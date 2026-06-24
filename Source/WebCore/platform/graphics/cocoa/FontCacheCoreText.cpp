/*
 * Copyright (C) 2015-2026 Apple Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE INC. AND ITS CONTRIBUTORS ``AS IS''
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL APPLE INC. OR ITS CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"
#include "FontCache.h"

#include "Color.h"
#include "Font.h"
#include "FontCascadeDescription.h"
#include "FontCreationContext.h"
#include "FontCustomPlatformData.h"
#include "FontDatabase.h"
#include "FontFamilySpecificationCoreText.h"
#include "FontInterrogation.h"
#include "FontMetricsNormalization.h"
#include "FontPaletteValues.h"
#include "Logging.h"
#include "StyleFontSizeFunctions.h"
#include "SystemFontDatabaseCoreText.h"
#include "UnrealizedCoreTextFont.h"
#include <CoreText/SFNTLayoutTypes.h>
#include <array>
#include <pal/spi/cf/CoreTextSPI.h>
#include <pal/spi/cocoa/AccessibilitySupportSPI.h>
#if PLATFORM(DRIFTSTACK)
#include <dirent.h>
#include <fcntl.h>
#include <string>
#include <unistd.h>
#include <sys/stat.h>
#endif
#include <wtf/HashSet.h>
#include <wtf/Lock.h>
#include <wtf/MainThread.h>
#include <wtf/MemoryPressureHandler.h>
#include <wtf/NeverDestroyed.h>
#include <wtf/RobinHoodHashMap.h>
#include <wtf/URLHash.h>
#include <wtf/cf/NotificationCenterCF.h>
#include <wtf/cf/TypeCastsCF.h>
#include <wtf/cf/VectorCF.h>
#include <wtf/cocoa/RuntimeApplicationChecksCocoa.h>

// Wave 29-499.58 — Forward declaration at file scope (extern "C" cannot
// appear inside a function body in C++; Wave 29-499.44 had it inside
// the eager-init block which failed C++ parse at UnifiedSource345
// compile). Function is defined in DriftstackArchetypeConfig.mm
// (@no-unify per SourcesCocoa.txt — Obj-C++ semantics preserved).
extern "C" void driftstackMetalPreWarm();

namespace WebCore {

bool fontNameIsSystemFont(CFStringRef fontName)
{
    return CFStringGetLength(fontName) > 0 && CFStringGetCharacterAtIndex(fontName, 0) == '.';
}

#if PLATFORM(DRIFTSTACK)
// Stage B Step 2/3: lazily-initialized map of lowercase iOS font-family-name
// -> file URL. Populated on first font lookup by walking DRIFTSTACK_FONTS_DIR
// and reading kCTFontFamilyNameAttribute from each font binary. Used by
// fontWithFamily on Driftstack to bypass CTFont's name-based lookup (which
// returns Mac's system font for "Helvetica" et al. even when iOS variants
// are also process-registered) and instead create a CTFont directly from
// the iOS file URL via CTFontManagerCreateFontDescriptorsFromURL. This is
// what makes iOS Helvetica's font metrics actually win over Mac's in
// canvas measureText output.
//
// FontCacheCoreText.cpp is plain C++ (not Obj-C++), so this function uses
// POSIX dirent + CoreFoundation C APIs only — no NSFileManager / @autoreleasepool.

static Lock driftstackIOSFontMapLock;

// V-086 Track 4 fix: nested map structure family → list of (style traits, URL).
// Each iOS font binary has a kCTFontStyleNameAttribute (Regular / Bold / Italic /
// Bold Italic / etc.) and kCTFontTraitsAttribute with weight + slant. We index
// every variant and pick the closest match at lookup time per the requested
// FontDescription's weight + italic.
struct DriftstackIOSFontVariant {
    RetainPtr<CFURLRef> url;
    float weight { 0.f };          // CTFontWeight: -1.0 (ultralight) … 0 (regular) … 1.0 (heavy)
    bool italic { false };
    String styleName;              // for diagnostics
};

static MemoryCompactRobinHoodHashMap<String, Vector<DriftstackIOSFontVariant>>& driftstackIOSFontMap() WTF_REQUIRES_LOCK(driftstackIOSFontMapLock)
{
    static NeverDestroyed<MemoryCompactRobinHoodHashMap<String, Vector<DriftstackIOSFontVariant>>> map;
    return map.get();
}

static bool driftstackIOSFontMapInitialized WTF_GUARDED_BY_LOCK(driftstackIOSFontMapLock) = false;

// W332 (#26b) — build {family-name → [all sibling family names of that face]}
// by reading the sfnt 'name' table DIRECTLY from a FONTS_DIR font file (TTF/OTF
// single or TTC collection), via bounded positioned reads. Every nameID=1 (and
// qualifying nameID=16) name of a face is cross-linked to all the others, so a
// descriptor matched on its English family resolves the localized/abbreviated
// siblings. WHY direct-from-binary: CTFontCreateWithFontDescriptor resolves a
// FONTS_DIR descriptor whose PostScript name collides with an already-
// registered Mac SYSTEM font (e.g. Hiragino) to the SYSTEM font, whose name
// table lacks the iOS localized records (ヒラギノ角ゴシック); and the descriptor
// array is NOT 1:1 with ttc face order, so we cannot index by it. Faces whose
// PostScript name is dot-prefixed (.AppleSystemUIFont / .PingFang UI …) are
// skipped entirely, so the hidden system UI font's localized names
// (Systeemlettertype / 系统字体 …) can never over-register. The CJK collections
// are 19-139 MB, so we pread only the header, table directory and name table.
// DRIFTSTACK #69: the 2 Savoye version-suffixed Full names + the 'Courier 10 Pitch'
// alias are detected by real iPhone Safari on browserleaks/fonts at <= 26.4 (256 fonts)
// but Apple STOPPED resolving them at Safari 26.5 (253). So the #69 exposure below must
// apply ONLY for archetypes at Safari <= 26.4 — a 26.5+ archetype correctly stays at 253
// (applying it there would OVER-detect by 3, the W321/W2368 invariant). Parses the
// "safariNN_M" token from DRIFTSTACK_ARCHETYPE; defaults to apply (launch = 26.4).
static bool driftstackBlfonts69ShouldApply()
{
    static const bool s_apply = []() -> bool {
        const char* arch = getenv("DRIFTSTACK_ARCHETYPE");
        if (!arch || !arch[0])
            return true;
        std::string_view sv(arch);
        auto pos = sv.find("safari");
        if (pos == std::string_view::npos)
            return true;
        pos += 6;
        int major = 0, minor = 0;
        while (pos < sv.size() && isASCIIDigit(sv[pos])) { major = major * 10 + (sv[pos] - '0'); ++pos; }
        if (pos < sv.size() && sv[pos] == '_') {
            ++pos;
            while (pos < sv.size() && isASCIIDigit(sv[pos])) { minor = minor * 10 + (sv[pos] - '0'); ++pos; }
        }
        if (major > 26)
            return false;          // Safari 27+ : Apple removed these (assume stays removed)
        if (major == 26 && minor >= 5)
            return false;          // Safari 26.5+ : verified real = 253 (not detected)
        return true;               // Safari <= 26.4 (incl Family-A 17/18/19) : verified/assumed 256
    }();
    return s_apply;
}

static void driftstackBuildLocalizedFamilyMap(const std::string& path, HashMap<String, Vector<String>>& out)
{
    int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0)
        return;
    auto readAt = [&](off_t off, size_t len) -> Vector<uint8_t> {
        Vector<uint8_t> buf(len);
        if (len) {
            ssize_t got = pread(fd, buf.mutableSpan().data(), len, off);
            if (got < 0 || static_cast<size_t>(got) != len)
                buf.clear();
        }
        return buf;
    };
    auto be16 = [](std::span<const uint8_t> s, size_t o) -> unsigned {
        return (static_cast<unsigned>(s[o]) << 8) | s[o + 1];
    };
    auto be32 = [](std::span<const uint8_t> s, size_t o) -> uint32_t {
        return (static_cast<uint32_t>(s[o]) << 24) | (static_cast<uint32_t>(s[o + 1]) << 16)
            | (static_cast<uint32_t>(s[o + 2]) << 8) | s[o + 3];
    };

    Vector<off_t> faceDirs;
    auto head = readAt(0, 12);
    if (head.size() < 12) {
        close(fd);
        return;
    }
    if (head[0] == 't' && head[1] == 't' && head[2] == 'c' && head[3] == 'f') {
        uint32_t numFonts = be32(head.span(), 8);
        if (numFonts > 1024)
            numFonts = 1024; // sanity
        auto offs = readAt(12, static_cast<size_t>(numFonts) * 4);
        if (offs.size() == static_cast<size_t>(numFonts) * 4) {
            for (uint32_t k = 0; k < numFonts; ++k)
                faceDirs.append(static_cast<off_t>(be32(offs.span(), static_cast<size_t>(k) * 4)));
        }
    } else
        faceDirs.append(0);

    for (off_t dirOffset : faceDirs) {
        auto dirHead = readAt(dirOffset, 12);
        if (dirHead.size() < 12)
            continue;
        unsigned numTables = be16(dirHead.span(), 4);
        auto tableDir = readAt(dirOffset + 12, static_cast<size_t>(numTables) * 16);
        if (tableDir.size() != static_cast<size_t>(numTables) * 16)
            continue;
        uint32_t nameOff = 0;
        uint32_t nameLen = 0;
        for (unsigned t = 0; t < numTables; ++t) {
            size_t e = static_cast<size_t>(t) * 16;
            if (tableDir[e] == 'n' && tableDir[e + 1] == 'a' && tableDir[e + 2] == 'm' && tableDir[e + 3] == 'e') {
                nameOff = be32(tableDir.span(), e + 8);
                nameLen = be32(tableDir.span(), e + 12);
                break;
            }
        }
        if (!nameLen || nameLen >= (1u << 24))
            continue;
        auto nameData = readAt(nameOff, nameLen);
        if (nameData.size() < 6)
            continue;
        auto ns = nameData.span();
        unsigned recCount = be16(ns, 2);
        size_t storageOffset = be16(ns, 4);
        String facePS;
        // Family names from this face. nameID=1 (Font Family) is always taken.
        // nameID=16 (Typographic Family) carries the BARE iOS family that the
        // weighted nameID=1 lacks ('ヒラギノ明朝 Pro' vs 'ヒラギノ明朝 Pro W3') — but
        // is taken ONLY when the SAME (platform,language) also has a nameID=1
        // record. That gate matches what iOS exposes: Hiragino has BOTH a JP
        // nameID=1 and a JP nameID=16 (lid 1041) → the bare JP name is exposed;
        // AppleSDGothicNeo has only an EN nameID=1 (pid=1) + a KO-only nameID=16
        // (lid 1042) → iOS does NOT expose 'Apple SD 산돌고딕 Neo', so we skip it.
        // Cross-linked: every kept name keys → all of them.
        Vector<String> names;
        Vector<uint32_t> id1Langs; // (platformID<<16 | languageID) of nameID=1 records
        struct TypoCand { String name; uint32_t lang; };
        Vector<TypoCand> id16Cands;
        // DRIFTSTACK #69 (W2557): set when a VERSION-SUFFIXED nameID=4 (Full name)
        // is found (e.g. "Savoye LET Plain:1.0"). Real iPhone Safari 26.4 exposes
        // these as resolvable families; some of their faces are hidden (dot-prefixed
        // PostScript name, e.g. ".SavoyeLetPlainCC"), so this also relaxes the
        // hidden-face skip below — but ONLY for the version-suffixed-full-name case.
        bool hasVersionSuffixedFullName = false;
        for (unsigned r = 0; r < recCount; ++r) {
            size_t recPos = 6 + static_cast<size_t>(r) * 12;
            if (recPos + 12 > nameData.size())
                break;
            unsigned nameID = be16(ns, recPos + 6);
            if (nameID != 1 && nameID != 6 && nameID != 16 && nameID != 4) // 1=Family, 6=PostScript, 16=Typographic Family, 4=Full name (version-suffixed only, #69)
                continue;
            unsigned platformID = be16(ns, recPos + 0);
            unsigned encodingID = be16(ns, recPos + 2);
            unsigned languageID = be16(ns, recPos + 4);
            // Mac platform (1) records: only Roman (eid=0) decodes correctly
            // as MacRoman; Mac-Japanese/Chinese/etc. (eid≠0) would be mojibake
            // (the real CJK names live in the pid=3 UTF-16 records).
            if (platformID == 1 && encodingID)
                continue;
            unsigned strLen = be16(ns, recPos + 8);
            size_t sPos = storageOffset + be16(ns, recPos + 10);
            if (!strLen || sPos + strLen > nameData.size())
                continue;
            CFStringEncoding enc = (platformID == 1) ? kCFStringEncodingMacRoman : kCFStringEncodingUTF16BE;
            auto sb = ns.subspan(sPos, strLen);
            RetainPtr<CFStringRef> cf = adoptCF(CFStringCreateWithBytes(kCFAllocatorDefault, sb.data(), sb.size(), enc, false));
            if (!cf)
                continue;
            String s = String(cf.get());
            if (s.isEmpty())
                continue;
            if (nameID == 6) {
                if (facePS.isEmpty())
                    facePS = s.convertToASCIILowercase();
                continue;
            }
            if (nameID == 4) {
                // DRIFTSTACK #69: expose the Full font name as a resolvable family ONLY for the
                // EXACT version-suffixed names the REAL iPhone (Safari 26.4, browserleaks/fonts)
                // resolves — an explicit allowlist, NOT a "any version-suffixed nameID=4" pattern.
                //   • A blanket nameID=4 add exposes every ordinary "Arial Bold" full name →
                //     over-detects ~200 fonts iOS does NOT report (reverted W2546).
                //   • Even a ":<digit>" version-suffix filter is too broad: the fork font set ALSO
                //     contains "Academy Engraved LET Plain:1.0" (AcademyEngraved.ttf, identical
                //     Family-Plain:1.0 structure) which browserleaks does NOT test and for which we
                //     have NO real-device evidence iOS resolves — exposing it risks a Mac-font
                //     OVER-detection (the W321/W2368 zero-over-detection invariant: over-detect is the
                //     real tell, under-detect the tolerated gap). So allowlist ONLY the proven 2.
                // (If a future real-device capture proves iOS resolves another version-suffixed Full
                //  name, add it here.) Verified W2557: fork blfonts 253→256, 0 over-detection.
                if (!driftstackBlfonts69ShouldApply())
                    continue; // Safari 26.5+ archetype: these are NOT detected (stay at 253)
                String lk4 = s.convertToASCIILowercase();
                if (lk4 != "savoye let plain:1.0"_s && lk4 != "savoye let plain cc.:1.0"_s)
                    continue;
                if (!names.contains(lk4)) {
                    names.append(lk4);
                    hasVersionSuffixedFullName = true;
                }
                continue;
            }
            if (s.startsWith('.'))
                continue;
            String lk = s.convertToASCIILowercase();
            if (lk.isEmpty())
                continue;
            uint32_t lang = (static_cast<uint32_t>(platformID) << 16) | languageID;
            if (nameID == 1) {
                if (!names.contains(lk))
                    names.append(lk);
                if (!id1Langs.contains(lang))
                    id1Langs.append(lang);
            } else // nameID == 16
                id16Cands.append(TypoCand { lk, lang });
        }
        for (const auto& cand : id16Cands) {
            if (id1Langs.contains(cand.lang) && !names.contains(cand.name))
                names.append(cand.name);
        }
        // Only non-hidden faces (PostScript name not dot-prefixed) — EXCEPT a face
        // carrying a version-suffixed nameID=4 Full name (#69: real Safari 26.4 exposes
        // e.g. "Savoye LET Plain CC.:1.0" even though its PostScript name is hidden
        // ".SavoyeLetPlainCC"). names.isEmpty() always skips.
        if (names.isEmpty())
            continue;
        if ((facePS.isEmpty() || facePS.startsWith('.')) && !hasVersionSuffixedFullName)
            continue;
        for (const String& key : names) {
            auto& vec = out.ensure(key, [] { return Vector<String> { }; }).iterator->value;
            for (const String& fam : names) {
                if (!vec.contains(fam))
                    vec.append(fam);
            }
        }
        // DRIFTSTACK #69: a HIDDEN face (dot-prefixed PostScript name) carrying a
        // version-suffixed nameID=4 Full name (e.g. ".SavoyeLetPlainCC" /
        // "Savoye LET Plain CC.:1.0") has NO English nameID=1 family, so the
        // resolution site — which looks up localizedByFamily by the descriptor's
        // family name — can't find these names. ALSO key them by the PostScript
        // name so the resolution site's postscript lookup (added there) registers
        // the version-suffixed Full name. Gated on hasVersionSuffixedFullName so
        // only these rare faces are PS-keyed (no broad hidden-face exposure).
        if (hasVersionSuffixedFullName && !facePS.isEmpty()) {
            auto& vec = out.ensure(facePS, [] { return Vector<String> { }; }).iterator->value;
            for (const String& fam : names) {
                if (!vec.contains(fam))
                    vec.append(fam);
            }
        }
    }
    close(fd);
}

static void driftstackWalkFontDir(const std::string& root, MemoryCompactRobinHoodHashMap<String, Vector<DriftstackIOSFontVariant>>& map, size_t& mappedCount, size_t& parseFailedCount, size_t& filesWalked, size_t& urlEmptyCount, size_t& dataRescuedCount)
{
    DIR* dir = opendir(root.c_str());
    if (!dir)
        return;

    // V-520.G (2026-05-08) — read all entries into a Vector + sort by name,
    // then iterate in sorted order. readdir() returns entries in filesystem
    // (inode) order on macOS APFS, which is NON-DETERMINISTIC across
    // processes. CTFontManagerRegisterFontsForURL() invocation order
    // affects subsequent text rendering — V-520.E/F empirically proved
    // text rasterization across two back-to-back fork processes was 0%
    // bit-identical with Stage B ON, vs 100% bit-identical with Stage B
    // OFF. Sorted enumeration → deterministic text rasterization across
    // processes → V-507 sha-keyed atlas dispatch reliable for text path.
    struct DirEntry { String name; bool isDir; };
    Vector<DirEntry> entries;
    while (struct dirent* entry = readdir(dir)) {
        if (entry->d_name[0] == '.')
            continue;
        String name = String::fromUTF8(unsafeSpan(entry->d_name));
        entries.append({ WTF::move(name), entry->d_type == DT_DIR });
    }
    std::sort(entries.begin(), entries.end(), [](const DirEntry& a, const DirEntry& b) {
        return codePointCompare(a.name, b.name) < 0;
    });

    for (const auto& entry : entries) {
        const String& name = entry.name;
        std::string fullPath = root + "/" + name.utf8().data();

        if (entry.isDir) {
            driftstackWalkFontDir(fullPath, map, mappedCount, parseFailedCount, filesWalked, urlEmptyCount, dataRescuedCount);
            continue;
        }

        if (!name.endsWithIgnoringASCIICase(".ttf"_s)
            && !name.endsWithIgnoringASCIICase(".ttc"_s)
            && !name.endsWithIgnoringASCIICase(".otf"_s))
            continue;

        ++filesWalked; // W2196 diag: count font files that actually reach the descriptor path.

        RetainPtr<CFStringRef> pathCF = adoptCF(CFStringCreateWithCString(kCFAllocatorDefault, fullPath.c_str(), kCFStringEncodingUTF8));
        RetainPtr<CFURLRef> fontURL = adoptCF(CFURLCreateWithFileSystemPath(kCFAllocatorDefault, pathCF.get(), kCFURLPOSIXPathStyle, false));
        if (!fontURL)
            continue;

        // Process-scope registration so CTFont creation paths can resolve the binary.
        CFErrorRef regError = nullptr;
        bool registered = CTFontManagerRegisterFontsForURL(fontURL.get(), kCTFontManagerScopeProcess, &regError);
        static const bool s_w2196Diag = std::getenv("DRIFTSTACK_TEXT_RUN_ATLAS_DIAG") != nullptr;
        if (regError) {
            if (s_w2196Diag) {
                RetainPtr<CFStringRef> ed = adoptCF(CFErrorCopyDescription(regError));
                WTFLogAlways("[Driftstack-W2196] %s: registerFonts FAILED: %s", fullPath.c_str(), ed ? String(ed.get()).utf8().data() : "?");
            }
            CFRelease(regError);
        }

        // Read all variants in the binary (.ttc collections may contain multiple).
        RetainPtr<CFArrayRef> descs = adoptCF(CTFontManagerCreateFontDescriptorsFromURL(fontURL.get()));
        CFIndex count = descs ? CFArrayGetCount(descs.get()) : 0;
        // W2196 (macOS 26.4 fleet): the URL-based descriptor API returns a non-null but EMPTY array for
        // these iOS fonts on 26.4 (parseFailed=0 + 0 families fits "walked, no parse error, 0 usable
        // descriptors"), so the override map stayed empty and the realize-fallbacks below never ran.
        // Fall back to reading the font bytes + CTFontManagerCreateFontDescriptorsFromData (URL/
        // registration-independent). Inert on 26.2 (the URL path already yields descriptors there).
        if (!count) {
            ++urlEmptyCount; // W2196 diag: the URL-descriptor API returned empty for this file (data-fallback territory).
            RetainPtr<CFDataRef> fontData;
            int ffd = ::open(fullPath.c_str(), O_RDONLY);
            if (ffd >= 0) {
                struct stat fst;
                if (::fstat(ffd, &fst) == 0 && fst.st_size > 0 && fst.st_size < (256LL << 20)) {
                    RetainPtr<CFMutableDataRef> md = adoptCF(CFDataCreateMutable(kCFAllocatorDefault, fst.st_size));
                    if (md) {
                        CFDataSetLength(md.get(), fst.st_size);
                        off_t total = 0;
                        WTF_ALLOW_UNSAFE_BUFFER_USAGE_BEGIN
                        uint8_t* buf = CFDataGetMutableBytePtr(md.get());
                        while (total < fst.st_size) {
                            ssize_t r = ::read(ffd, buf + total, fst.st_size - total);
                            if (r <= 0)
                                break;
                            total += r;
                        }
                        WTF_ALLOW_UNSAFE_BUFFER_USAGE_END
                        if (total == fst.st_size)
                            fontData = md;
                    }
                }
                ::close(ffd);
            }
            if (fontData) {
                descs = adoptCF(CTFontManagerCreateFontDescriptorsFromData(fontData.get()));
                count = descs ? CFArrayGetCount(descs.get()) : 0;
                if (count)
                    ++dataRescuedCount; // W2196 diag: data-fallback recovered descriptors the URL API missed.
            }
        }
        if (s_w2196Diag)
            WTFLogAlways("[Driftstack-W2196] %s: registered=%d descCount=%ld", fullPath.c_str(), registered ? 1 : 0, static_cast<long>(count));
        if (!count) {
            ++parseFailedCount;
            // V-487: log which font binary CTFontManager failed to parse.
            WTFLogAlways("[Driftstack-V487-PARSEFAIL] %s", fullPath.c_str());
            continue;
        }

        // W332 (#26b) — cross-linked family-name map for this binary's faces,
        // read DIRECTLY from its sfnt name tables (see
        // driftstackBuildLocalizedFamilyMap). Built once per file; looked up
        // per descriptor by family name below.
        HashMap<String, Vector<String>> localizedByFamily;
        driftstackBuildLocalizedFamilyMap(fullPath, localizedByFamily);

        for (CFIndex i = 0; i < count; ++i) {
            CTFontDescriptorRef desc = static_cast<CTFontDescriptorRef>(CFArrayGetValueAtIndex(descs.get(), i));
            RetainPtr<CFStringRef> familyCF = adoptCF(static_cast<CFStringRef>(CTFontDescriptorCopyAttribute(desc, kCTFontFamilyNameAttribute)));
            RetainPtr<CTFontDescriptorRef> realizedDesc; // keeps the realized descriptor alive if used below
            if (!familyCF) {
                // W2196 (A3 Mac-worker on-box repro, macOS 26.4): on fleet hosts running macOS 26.4+,
                // CTFontManagerCreateFontDescriptorsFromURL returns descriptors WITHOUT
                // kCTFontFamilyNameAttribute populated (it is lazy on 26.4; macOS 26.2 populated it
                // eagerly). With the attribute null, every iOS font was skipped here → the override map
                // mapped 0 families → ALL glyph/font/measureText surfaces fell back to Mac-native CoreText
                // on the fleet (glyphHash 777d587f instead of c587ed44). Realize the font from this
                // descriptor (which carries the file URL, so it resolves to THIS binary, not a name-
                // matched Mac system font) and read the family name off the realized CTFont. Inert on
                // 26.2 (the descriptor attribute is non-null there, so this branch never runs).
                RetainPtr<CTFontRef> realizedFont = adoptCF(CTFontCreateWithFontDescriptor(desc, 0.0, nullptr));
                if (realizedFont) {
                    familyCF = adoptCF(CTFontCopyFamilyName(realizedFont.get()));
                    // The descriptor's traits/style/PostScript attributes are lazy too on 26.4 — point
                    // all subsequent reads (weight/slant/style/PS below) at the REALIZED font's
                    // descriptor so face-variant selection is correct, not just the family.
                    realizedDesc = adoptCF(CTFontCopyFontDescriptor(realizedFont.get()));
                    if (realizedDesc)
                        desc = realizedDesc.get();
                }
                // W2196 one-shot diag (capped at 8): this branch runs ONLY when the descriptor's family
                // attribute was null — which on macOS 26.2 NEVER happens (the attr is eager there), so this
                // log is SILENT in production and fires only on the 26.4 fleet box. Since `mapped` can only
                // stay 0 (with count>0) if familyCF is null for EVERY descriptor (the family key is always
                // in aliasKeys downstream → an extracted family always increments mapped), this pins the
                // exact sub-step where extraction dies: realizeOk=0 → CTFontCreateWithFontDescriptor itself
                // fails on 26.4; realizeOk=1 + family=(null) → CTFontCopyFamilyName fails on the realized
                // font (→ fall back to the sfnt name table, which driftstackBuildLocalizedFamilyMap already
                // reads); realizeOk=1 + a real name → extraction worked, look further downstream.
                static unsigned s_w2196FamDiag = 0;
                if (s_w2196FamDiag < 8) {
                    ++s_w2196FamDiag;
                    WTFLogAlways("[Driftstack-W2196-fam] %s desc#%ld: attrFamilyNull=1 realizeOk=%d familyAfterRealize=%s",
                        fullPath.c_str(), static_cast<long>(i), realizedFont ? 1 : 0,
                        familyCF ? String(familyCF.get()).utf8().data() : "(null)");
                }
            }
            if (!familyCF)
                continue;
            String family = String(familyCF.get()).convertToASCIILowercase();
            if (family.isEmpty())
                continue;

            // Read weight + slant from kCTFontTraitsAttribute (NSDictionary).
            DriftstackIOSFontVariant variant;
            variant.url = fontURL;
            variant.weight = 0.f;
            variant.italic = false;

            RetainPtr<CFDictionaryRef> traits = adoptCF(static_cast<CFDictionaryRef>(CTFontDescriptorCopyAttribute(desc, kCTFontTraitsAttribute)));
            if (traits) {
                CFNumberRef weightNum = static_cast<CFNumberRef>(CFDictionaryGetValue(traits.get(), kCTFontWeightTrait));
                if (weightNum)
                    CFNumberGetValue(weightNum, kCFNumberFloatType, &variant.weight);
                CFNumberRef slantNum = static_cast<CFNumberRef>(CFDictionaryGetValue(traits.get(), kCTFontSlantTrait));
                if (slantNum) {
                    float slant = 0.f;
                    CFNumberGetValue(slantNum, kCFNumberFloatType, &slant);
                    variant.italic = slant > 0.01f;
                }
            }

            RetainPtr<CFStringRef> styleCF = adoptCF(static_cast<CFStringRef>(CTFontDescriptorCopyAttribute(desc, kCTFontStyleNameAttribute)));
            if (styleCF)
                variant.styleName = String(styleCF.get());

            // V-433.X (wave 29-195) + V-433.Y (wave 29-197) — register
            // under (family, full-PS-name, iPhone-canonical-face-name).
            // browserleaks /fonts probes ALL face-style names that iOS
            // exposes as discoverable CSS families: family ("Avenir"),
            // PS name ("AvenirNext-Heavy"), AND specific face variants
            // ("Avenir Heavy", "Hiragino Sans W3"). Auto-registering all
            // display names (CTFontDisplayName) over-exposes Bold/Italic/
            // Oblique faces iOS does NOT expose. Instead, register only
            // names that appear in the iPhone-canonical face-name list
            // for the launch archetype (BS v433y capture 2026-05-14).
            Vector<String> aliasKeys;
            aliasKeys.append(family);
            RetainPtr<CFStringRef> postscriptCF = adoptCF(static_cast<CFStringRef>(CTFontDescriptorCopyAttribute(desc, kCTFontNameAttribute)));
            if (postscriptCF) {
                String postscript = String(postscriptCF.get()).convertToASCIILowercase();
                if (!postscript.isEmpty() && postscript != family)
                    aliasKeys.append(postscript);
                // DRIFTSTACK #69: register version-suffixed Full names of HIDDEN faces
                // (".SavoyeLetPlainCC" → "Savoye LET Plain CC.:1.0"). The localizedByFamily
                // map (built above) keys these by the PostScript name for exactly this case,
                // since the hidden face has no English family name to match by.
                if (!postscript.isEmpty()) {
                    auto itPS = localizedByFamily.find(postscript);
                    if (itPS != localizedByFamily.end()) {
                        for (const String& a : itPS->value) {
                            if (!aliasKeys.contains(a))
                                aliasKeys.append(a);
                        }
                    }
                }
                // DRIFTSTACK #69: "Courier 10 Pitch" is a system-level alias the real iPhone
                // resolves to Courier (browserleaks/fonts detects it on Safari 26.4) but it lives
                // in NO fork font file's name table. Register it as an explicit alias on the
                // Courier face so font-family:"Courier 10 Pitch" resolves like the iPhone.
                if (driftstackBlfonts69ShouldApply() && (family == "courier"_s || postscript == "courier"_s)) {
                    if (!aliasKeys.contains("courier 10 pitch"_s))
                        aliasKeys.append("courier 10 pitch"_s);
                }
            }
            // iPhone-canonical face-name allowlist for archetype
            // iphone17_ios18_7_safari26_4. Derived from BS Automate
            // iPhone 17 / iOS 18.7 / Safari 26.4 v433y capture diff
            // (252 detected vs fork pre-fix 216 → 37 face variants
            // iPhone exposes that Mac CTFont descriptor parsing collapses
            // into the parent family). Lowercase, exact-match.
            static const std::array<const char*, 73> kIPhoneCanonicalFaceNames = {
                "avenir black", "avenir black oblique", "avenir book",
                "avenir heavy", "avenir light", "avenir medium",
                "avenir next condensed demi bold", "avenir next condensed heavy",
                "avenir next condensed medium", "avenir next condensed ultra light",
                "avenir next demi bold", "avenir next heavy",
                "avenir next medium", "avenir next ultra light",
                "charter black",
                "hiragino kaku gothic pro w3", "hiragino kaku gothic pro w6",
                "hiragino kaku gothic pron w3", "hiragino kaku gothic pron w6",
                "hiragino kaku gothic std w8", "hiragino kaku gothic stdn w8",
                "hiragino maru gothic pro w4", "hiragino maru gothic pron w4",
                "hiragino mincho pro w3", "hiragino mincho pro w6",
                "hiragino mincho pron w3", "hiragino mincho pron w6",
                "hiragino sans w3", "hiragino sans w4", "hiragino sans w5",
                "hiragino sans w6", "hiragino sans w7", "hiragino sans w8",
                "seravek extralight", "seravek light", "seravek medium",
                "signpainter-housescript",
                // W321 (2026-06-02) — the larger fontsfull test (3976: browserleaks
                // 3564 + all iOS name variants) vs a real iPhone 17 / Safari 26.4
                // capture revealed 36 MORE face names iOS exposes that the 37-name
                // v433y allowlist missed (browserleaks's partial 3564 list hid them).
                // All 36 are iOS-EXPOSED (real device detects them). VERIFIED build:
                // 18 resolve via the CTFontDisplayName match below (prod-fork 304->322,
                // 0 over-detection vs real). The other 18 (abbreviated Noto family
                // names "Noto Sans CanAborig"/etc. + "Fakt Slab Stencil Pro Med") have
                // a different CTFontDisplayName than these keys → they need an
                // ADDITIONAL source: the sfnt name-table id=1 family name (TODO #26,
                // follow-up). Kept here as documented targets (inert = harmless until
                // the name-table source lands; no over-detection).
                "druk bold", "druk heavy", "druk medium", "druk super",
                "druk text bold", "druk wide bold", "druk wide bold italic",
                "druk wide medium", "druk wide medium italic",
                "fakt slab stencil pro med", "journal sans new inline",
                "muktamahee bold", "muktamahee light", "muktamahee regular",
                "noto sans armenian light", "noto sans canaborig",
                "noto sans caucalban", "noto sans egypthiero",
                "noto sans hanifirohg", "noto sans imparamaic",
                "noto sans inspahlavi", "noto sans insparthi",
                "noto sans kannada light", "noto sans meeteimayek",
                "noto sans myanmar light", "noto sans newtailue",
                "noto sans oldhung", "noto sans oldnorarab",
                "noto sans oldpersian", "noto sans oldsouarab",
                "noto sans paucinhau", "noto sans psapahlavi",
                "noto sans sorasomp", "noto sans warangciti",
                "noto sans zawgyi light", "the hand serif semibold",
            };
            RetainPtr<CFStringRef> displayCF = adoptCF(static_cast<CFStringRef>(CTFontDescriptorCopyAttribute(desc, kCTFontDisplayNameAttribute)));
            if (displayCF) {
                String display = String(displayCF.get()).convertToASCIILowercase();
                for (const char* canonical : kIPhoneCanonicalFaceNames) {
                    if (display == String::fromUTF8(canonical)) {
                        if (!aliasKeys.contains(display))
                            aliasKeys.append(display);
                        break;
                    }
                }
            }

            // W330/W332 (#26/#26b) — register the localized + abbreviated family
            // names iOS CoreText exposes that Mac's kCTFontFamilyNameAttribute
            // collapses to the single pid=1 ASCII name. Read DIRECTLY from this
            // binary's sfnt name tables (localizedByFamily, built above) and
            // matched to this face by its English family name — NOT via
            // CTFontCopyTable on a CTFont-realized font, which CoreText resolves
            // to a same-PS-name Mac SYSTEM font (Hiragino) whose name table
            // lacks the iOS localized records. Empirically (FONTS_DIR name
            // tables): Damascus → 'دمشق'/'दमिश्कश'/'ڈیمسکس';
            // NotoSansCanadianAboriginal → 'Noto Sans CanAborig'; Hiragino →
            // 'ヒラギノ角ゴシック'…. Hidden system/UI faces (dot-prefixed PS) are
            // excluded at build time, so the system UI font's localized names
            // (Systeemlettertype / 系统字体 …) can never over-register. (PingFang's
            // 苹方-简… are blocked separately by its CTFontManager parse-fail —
            // founder-action-queue #26c.)
            if (!family.isEmpty() && !family.startsWith('.')) {
                auto it = localizedByFamily.find(family);
                if (it != localizedByFamily.end()) {
                    for (const String& alias : it->value) {
                        if (!aliasKeys.contains(alias))
                            aliasKeys.append(alias);
                    }
                }
            }

            for (const String& key : aliasKeys) {
                auto& variants = map.ensure(key, [] { return Vector<DriftstackIOSFontVariant> { }; }).iterator->value;
                // Avoid duplicates from the same .ttf being descriptor-walked
                // twice. V-091 fix: include styleName in dup-detection so .ttc
                // files with multiple faces sharing weight + italic but
                // differing in styleName (e.g., iOS Papyrus.ttc face 0
                // Condensed + face 1 Regular both at weight=0 italic=false)
                // all end up registered.
                bool dup = false;
                for (const auto& v : variants) {
                    if (CFEqual(v.url.get(), variant.url.get()) && v.italic == variant.italic
                        && std::abs(v.weight - variant.weight) < 0.01f
                        && v.styleName == variant.styleName) {
                        dup = true;
                        break;
                    }
                }
                if (!dup) {
                    DriftstackIOSFontVariant copy = variant;
                    variants.append(WTF::move(copy));
                    ++mappedCount;
                }
            }
        }
    }
    closedir(dir);
}

// V-090 Track 4 Phase 4.D: Apple's per-family CSS-weight → styleName mapping.
// Mac's reading of iOS .ttc font traits doesn't always match iPhone's
// per-CSS-weight font-face selection; for the 3 fonts where Mac picks a
// different face than iPhone at any CSS weight, encode the empirical
// iPhone mapping explicitly. Italic CSS requests reuse the upright face
// for these families (empirical: iPhone has no italic variant — italic CSS
// produces identical metrics).
static String preferredIOSStyleForFamily(const String& lowercaseFamily, int cssWeight)
{
    if (lowercaseFamily == "hiragino sans"_s) {
        if (cssWeight <= 300) return "W3"_s;
        if (cssWeight == 400) return "W4"_s;
        if (cssWeight == 500) return "W5"_s;
        if (cssWeight == 600) return "W6"_s;
        if (cssWeight == 700) return "W7"_s;
        return "W8"_s; // CSS 800 + 900 → W8 (heaviest available in HiraginoKakuGothic.ttc)
    }
    if (lowercaseFamily == "marker felt"_s)
        return cssWeight < 600 ? "Thin"_s : "Wide"_s;
    if (lowercaseFamily == "papyrus"_s)
        return cssWeight < 600 ? "Regular"_s : "Condensed"_s;
    return String();
}

static void initializeDriftstackIOSFontMapIfNeeded()
{
    Locker locker(driftstackIOSFontMapLock);
    if (driftstackIOSFontMapInitialized)
        return;
    driftstackIOSFontMapInitialized = true;

    const char* envDir = getenv("DRIFTSTACK_FONTS_DIR");
    // V-211: the dev-default fonts dir derives from the environment
    // (DRIFTSTACK_FONTS_ROOT, else $HOME/code/driftstack-fonts) instead of a
    // hardcoded build-machine home directory.
    std::string root;
    if (envDir)
        root = envDir;
    else {
        const char* fontsRoot = getenv("DRIFTSTACK_FONTS_ROOT");
        const char* home = getenv("HOME");
        root = (fontsRoot && *fontsRoot) ? std::string(fontsRoot) : std::string(home ? home : "") + "/code/driftstack-fonts";
        root += "/iphone16pro-ios26.4.1";
    }

    struct stat st;
    if (stat(root.c_str(), &st) != 0 || !S_ISDIR(st.st_mode)) {
        WTFLogAlways("[Driftstack] FontCache: iOS fonts dir not found at %s — skipping override map population", root.c_str());
        return;
    }

    size_t mapped = 0;
    size_t parseFailed = 0;
    size_t filesWalked = 0;
    size_t urlEmpty = 0;
    size_t dataRescued = 0;
    driftstackWalkFontDir(root, driftstackIOSFontMap(), mapped, parseFailed, filesWalked, urlEmpty, dataRescued);
    // W2196 (macOS 26.4 fleet font bug) — this summary line is UNCONDITIONAL and reaches the WebContent
    // process stderr on every run, unlike the per-file DRIFTSTACK_TEXT_RUN_ATLAS_DIAG-gated lines (the flag
    // was not reaching the sandboxed WebContent process, so those never fired on the box). The extra counters
    // decisively distinguish the candidate failure modes for "0 families mapped":
    //   filesWalked==0                              → no font files walked at all (path/recursion/extension)
    //   filesWalked>0, urlEmpty==0, mapped==0       → descriptors created (URL API non-empty) but family
    //                                                 extraction fails downstream on 26.4 (NOT the empty-array
    //                                                 hypothesis — parseFailed==0 already implied this)
    //   filesWalked>0, urlEmpty>0, dataRescued>0    → URL API empty but data-fallback recovered; mapped still 0 → downstream
    //   filesWalked>0, urlEmpty>0, dataRescued==0   → both descriptor APIs empty (deeper 26.4 font-data policy)
    WTFLogAlways("[Driftstack] FontCache: %zu families mapped to iOS font binaries (parseFailed=%zu, filesWalked=%zu, urlEmpty=%zu, dataRescued=%zu, dir=%s)", mapped, parseFailed, filesWalked, urlEmpty, dataRescued, root.c_str());

    // V-486 diagnostic: dump all registered family keys containing 'ping' (CJK
    // PingFang) to identify the actual lowercase form for Track 7 D candidates.
    {
        auto& map = driftstackIOSFontMap();
        for (auto it = map.begin(); it != map.end(); ++it) {
            const String& key = it->key;
            if (key.contains("ping"_s))
                WTFLogAlways("[Driftstack-V486-PINGFANG] registered family key='%s' variants=%zu", key.utf8().data(), it->value.size());
        }
    }

    // Wave 29-499.16 Task #79 follow-up — CoreText emoji shaper warmup.
    // canvas_emoji probe shows Mac fork first-call 48ms vs iPhone 20ms
    // (28ms detection signal). The cost is CoreText's emoji shaper init
    // on first emoji-codepoint render: AppleColorEmoji.ttc parse +
    // shaper table build + glyph cache prime. Pre-warm by invoking
    // CTFontCreateForString with an emoji codepoint at font-map init
    // (same gating as V510 atlas eager init — happens before first
    // canvas creation when DRIFTSTACK_EAGER_INIT_ATLAS=1).
    //
    // Per file 105 timing classification: shaper warmup is a Phase 1
    // build-time concern (binary already shipped with AppleColorEmoji
    // available); pre-warming at process startup matches iPhone's
    // post-warmup distribution from probe N=0.
    {
        const char* eager = getenv("DRIFTSTACK_EAGER_INIT_ATLAS");
        if (eager && eager[0] == '1') {
            RetainPtr<CFStringRef> emojiStr = adoptCF(CFStringCreateWithCString(kCFAllocatorDefault, "\xF0\x9F\x98\x80", kCFStringEncodingUTF8));
            if (emojiStr) {
                RetainPtr<CTFontRef> baseFont = adoptCF(CTFontCreateWithName(CFSTR("AppleColorEmoji"), 20.0, nullptr));
                if (baseFont) {
                    RetainPtr<CTFontRef> substitute = adoptCF(CTFontCreateForString(baseFont.get(), emojiStr.get(), CFRangeMake(0, 1)));
                    (void)substitute;
                    WTFLogAlways("[Driftstack-EG-WK-1.10/Task#79/EmojiWarmup] CoreText emoji shaper pre-warmed at font-map init — canvas_emoji 28ms cold-cache outlier eliminated for subsequent renders (DRIFTSTACK_EAGER_INIT_ATLAS=1)");
                }
            }
        }
    }

    // Wave 29-499.44 — Metal device pre-warm via @no-unify wrapper.
    // The function is defined in DriftstackArchetypeConfig.mm (which is
    // @no-unify per SourcesCocoa.txt, so its Obj-C++ semantics are
    // preserved). Calling it from here is safe because the forward
    // declaration is pure C linkage — no Metal headers leak into this
    // C++-compiled translation unit.
    //
    // History: Wave 29-499.38 attempted to inline the pre-warm in this
    // file, which broke under unified-source C++ compile mode on
    // `id<MTLDevice>` Obj-C type (reverted in Wave 29-499.40).
    {
        const char* eager = getenv("DRIFTSTACK_EAGER_INIT_ATLAS");
        if (eager && eager[0] == '1') {
            // Wave 29-499.58 — forward decl at file scope (see top of file).
            driftstackMetalPreWarm();
        }
    }

    // Wave 29-499.39 Task #79 follow-up — Latin-text shaper warmup.
    // font_offsetWidth probe shows Mac fork first-call 12ms vs iPhone
    // 4.67ms (7ms cold-cache delta). The cost is CoreText's first
    // CTLineCreateWithAttributedString on first text-with-font measure
    // (per CSS computed-style cascade → text shaping pipeline). Pre-
    // warm by creating a CTLine for a Latin string with common font;
    // shaper tables get built on first call, cached for subsequent
    // measureText / offsetWidth.
    //
    // Final outlier in Task #79 set: canvas_stripe + canvas_fpjs closed
    // .8, canvas_emoji .16, webgl_getParameter .38, font_offsetWidth
    // closed by THIS commit.
    {
        const char* eager = getenv("DRIFTSTACK_EAGER_INIT_ATLAS");
        if (eager && eager[0] == '1') {
            RetainPtr<CFStringRef> latinStr = adoptCF(CFStringCreateWithCString(kCFAllocatorDefault, "mmmmmmmmmmlli", kCFStringEncodingUTF8));
            if (latinStr) {
                // Use Helvetica 14pt — matches probe's font cascade default
                RetainPtr<CTFontRef> font = adoptCF(CTFontCreateWithName(CFSTR("Helvetica"), 14.0, nullptr));
                if (font) {
                    CFTypeRef keys[] = { kCTFontAttributeName };
                    CFTypeRef values[] = { font.get() };
                    RetainPtr<CFDictionaryRef> attrs = adoptCF(CFDictionaryCreate(kCFAllocatorDefault, keys, values, 1, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks));
                    if (attrs) {
                        RetainPtr<CFAttributedStringRef> attrString = adoptCF(CFAttributedStringCreate(kCFAllocatorDefault, latinStr.get(), attrs.get()));
                        if (attrString) {
                            RetainPtr<CTLineRef> line = adoptCF(CTLineCreateWithAttributedString(attrString.get()));
                            if (line) {
                                // Force the shaper to actually compute metrics
                                CGFloat ascent, descent, leading;
                                CTLineGetTypographicBounds(line.get(), &ascent, &descent, &leading);
                                (void)ascent; (void)descent; (void)leading;
                                WTFLogAlways("[Driftstack-EG-WK-1.10/Task#79/LatinShaperWarmup] CoreText Latin text shaper pre-warmed at font-map init — font_offsetWidth 7ms cold-cache outlier eliminated for first DOM text measurement (DRIFTSTACK_EAGER_INIT_ATLAS=1)");
                            }
                        }
                    }
                }
            }
        }
    }
}

static RetainPtr<CTFontRef> driftstackIOSFontWithFamily(const AtomString& family, const FontDescription& fontDescription, float size)
{
    if (family.isEmpty())
        return nullptr;
    initializeDriftstackIOSFontMapIfNeeded();

    String lowercase = family.string().convertToASCIILowercase();

    // V-088 Track 4 Pattern 2: redirect family names that aren't installed
    // on iOS to the iOS system fallback iPhone uses. Empirically verified
    // (V-085 capture data) iPhone falls back to Helvetica for these
    // family names (identical width=160.0625 / fBBA=14 / fBBD=4 metrics
    // when CSS asks for them on iPhone).
    //
    // W208: the 4 fonts below (Gujarati Sangam MN / Oriya Sangam MN / Plantagenet
    // Cherokee / Gurmukhi MN) are absent on EVERY real iPhone version (26.5, 18.6,
    // 17.1.1 — close-list §1) → genuine fork over-detection. Exclude them
    // UNCONDITIONALLY (was Family-A-only via s_isFamilyAArchetype, a stale gate from
    // when Family A was the launch; the launch is now Family B iphone17 26.4, which
    // skipped the gate → hit the helvetica alias below → rendered as a real font →
    // detected). Returning nullptr → a CSS `"Gujarati Sangam MN", monospace` request
    // falls back to the SPECIFIED fallback → matches the width-detection baseline →
    // not over-detected, matching a real iPhone.
    // W232: Kefa joins the nullptr exclusion. Kefa is a macOS-only font absent on a real
    // iPhone-17 (verified vs 5 real-device aio refs + BOTH font probes: browserleaks
    // fonts.detected had Kefa as the lone fork-only entry, 171 vs real 170; exhaustiveBitmap
    // Kefa present=fork-only). The OLD `kefa → helvetica` alias (below, now removed) resolved
    // Kefa to a REAL font even when an explicit fallback was specified, so the browserleaks
    // width-detection ("Kefa, monospace" vs "monospace") saw Kefa as PRESENT — a fork
    // over-detection tell. Returning nullptr makes Kefa genuinely absent: "Kefa, monospace"
    // falls to the specified monospace (not detected, matching iPhone), while a bare
    // measureText("Kefa") still falls to the canvas default (Helvetica, width 160.0625 ==
    // the real-device measureText value). Same mechanism as the 4 Indic fonts above.
    if (lowercase == "gujarati sangam mn"_s
        || lowercase == "oriya sangam mn"_s
        || lowercase == "plantagenet cherokee"_s
        || lowercase == "gurmukhi mn"_s
        || lowercase == "kefa"_s)
        return nullptr;
    // V-479 Times-family alias (V-442 TRIGGER C closure 2026-05-08):
    // iOS Stage B install ships TimesNewRoman.ttf, registered under
    // family 'times new roman'. Mac CSS and CT_FONT_NAME 'Times'
    // doesn't directly map to it. iPhone resolves CSS 'Times' to
    // TimesNewRoman.ttf via family alias; mirror that here so V-442
    // Stage B audit moves Times from MAC_DEFAULT_FAIL → STAGE_B_PASS.
    if (lowercase == "times"_s)
        lowercase = "times new roman"_s;
    // V-433.X (wave 29-195) — iOS legacy `* Sangam MN` family-name alias
    // to the modern Kohinoor families. iOS Safari resolves these CSS
    // names to the Kohinoor binaries internally; Mac CoreText also has
    // a "Bangla Sangam MN" font but with different metrics (width 633
    // vs Kohinoor's 680 at our test string). The other Sangam MN names
    // (Devanagari/Telugu/Tamil/Kannada) happen to match between Mac and
    // iOS without aliasing, so they are left alone.
    else if (lowercase == "bangla sangam mn"_s)
        lowercase = "kohinoor bangla"_s;
    // V-433.Y wave 29-197 — SignPainter-HouseScript: iOS exposes this
    // as a discoverable CSS family name (Preferred Family / name ID 16),
    // but Mac CTFontDescriptor only exposes the base family "SignPainter"
    // (name ID 1) when parsing SignPainter-Semibold.otf. Alias the iOS-
    // exposed name to the underlying SignPainter family so probe lookups
    // resolve correctly.
    else if (lowercase == "signpainter-housescript"_s)
        lowercase = "signpainter"_s;
    // V-433.Y wave 29-198 — variant-to-parent aliases for weight-suffixed
    // iOS-canonical face names. iPhone exposes these as discoverable CSS
    // family names (Preferred Family / name ID 16) BUT resolves them all
    // to the SAME parent-family Regular face (e.g., "Avenir Heavy",
    // "Avenir Light", "Avenir" all render width 4246 at the v433y test
    // string — iOS Safari ignores the weight suffix in family-name
    // lookup, uses CSS font-weight property instead). The display-name
    // allowlist in driftstackWalkFontDir registers them under the
    // weight-specific face; that's correct for FACE SELECTION but
    // produces wrong WIDTH metrics because Mac CT and iOS CT pick
    // different default faces from the same .ttc. Redirecting the
    // variant CSS family name to the parent family resolves to the
    // same canonical Regular face on fork, matching iPhone's tuple.
    else if (lowercase == "avenir black"_s
        || lowercase == "avenir black oblique"_s
        || lowercase == "avenir book"_s
        || lowercase == "avenir heavy"_s
        || lowercase == "avenir light"_s
        || lowercase == "avenir medium"_s)
        lowercase = "avenir"_s;
    else if (lowercase == "avenir next condensed demi bold"_s
        || lowercase == "avenir next condensed heavy"_s
        || lowercase == "avenir next condensed medium"_s
        || lowercase == "avenir next condensed ultra light"_s)
        lowercase = "avenir next condensed"_s;
    else if (lowercase == "avenir next demi bold"_s
        || lowercase == "avenir next heavy"_s
        || lowercase == "avenir next medium"_s
        || lowercase == "avenir next ultra light"_s)
        lowercase = "avenir next"_s;
    else if (lowercase == "charter black"_s)
        lowercase = "charter"_s;
    else if (lowercase == "hiragino sans w3"_s
        || lowercase == "hiragino sans w4"_s
        || lowercase == "hiragino sans w5"_s
        || lowercase == "hiragino sans w6"_s
        || lowercase == "hiragino sans w7"_s
        || lowercase == "hiragino sans w8"_s)
        lowercase = "hiragino sans"_s;
    else if (lowercase == "hiragino kaku gothic pro w3"_s
        || lowercase == "hiragino kaku gothic pro w6"_s)
        lowercase = "hiragino kaku gothic pro"_s;
    else if (lowercase == "hiragino kaku gothic pron w3"_s
        || lowercase == "hiragino kaku gothic pron w6"_s)
        lowercase = "hiragino kaku gothic pron"_s;
    else if (lowercase == "hiragino kaku gothic std w8"_s)
        lowercase = "hiragino kaku gothic std"_s;
    else if (lowercase == "hiragino kaku gothic stdn w8"_s)
        lowercase = "hiragino kaku gothic stdn"_s;
    else if (lowercase == "hiragino maru gothic pro w4"_s)
        lowercase = "hiragino maru gothic pro"_s;
    else if (lowercase == "hiragino maru gothic pron w4"_s)
        lowercase = "hiragino maru gothic pron"_s;
    else if (lowercase == "hiragino mincho pro w3"_s
        || lowercase == "hiragino mincho pro w6"_s)
        lowercase = "hiragino mincho pro"_s;
    else if (lowercase == "hiragino mincho pron w3"_s
        || lowercase == "hiragino mincho pron w6"_s)
        lowercase = "hiragino mincho pron"_s;
    else if (lowercase == "seravek extralight"_s
        || lowercase == "seravek light"_s
        || lowercase == "seravek medium"_s)
        lowercase = "seravek"_s;
    // V-521.A.2 (2026-05-08): Heiti SC/TC are legacy iOS CJK font families
    // that font-enumeration probe detects on iPhone (width 4292 for
    // 'mmmmmmmmlli' test string). They alias to PingFang SC/TC equivalents
    // on iPhone (Heiti was Apple's pre-PingFang Chinese system font;
    // CTFontManager resolves Heiti requests to PingFang fallback). Fork
    // mirrors that alias chain so /fonts probe detects Heiti SC/TC as
    // installed (any width != monospace base = "detected" boolean).
    else if (lowercase == "heiti sc"_s)
        lowercase = "pingfang sc"_s;
    else if (lowercase == "heiti tc"_s)
        lowercase = "pingfang tc"_s;
    // V-098 Track 8: iOS system font (SFUI.ttf) registers under family
    // ".SF UI" via CoreText's platform-0 Unicode name (preferred over
    // the platform-3 'System Font' name). Empirical (V-099 cumulative):
    // ONLY -apple-system + system-ui resolve to this iOS system font
    // on iPhone (width 163.73 for the rig test string). The others
    // (BlinkMacSystemFont, SF Pro Text, SF Pro Display) resolve to
    // Helvetica on iPhone (width 160.0625 — same as a CSS sans-serif
    // fallback). Don't redirect those — they match iPhone via the
    // existing MISS → CSS fallback path.
    // V-099 Track 8 finding: -apple-system / system-ui CSS pseudo-families
    // bypass driftstackIOSFontWithFamily entirely (proven empirically across
    // builds #9-#15). Diagnostic redirect to "helvetica" had ZERO effect on
    // measured -apple-system width — function not entered for these names.
    // The CSS resolution layer maps -apple-system to a system font directly
    // via WebKit's higher-level FontCascadeDescription / font-family
    // resolution path. Track 8 fix requires WebCore CSS-resolution layer
    // modification, not FontCache layer. Surfaced for founder review.
    // Telugu has its own iOS font (Kohinoor Telugu) — different metrics
    // than Helvetica (w=162.31 vs 160.06 in iPhone reference); redirect
    // to the actual iOS Telugu font.
    else if (lowercase == "telugu sangam mn"_s)
        lowercase = "kohinoor telugu"_s;

    DriftstackIOSFontVariant chosenVariant;
    bool found = false;
    {
        Locker locker(driftstackIOSFontMapLock);
        auto it = driftstackIOSFontMap().find(lowercase);
        if (it == driftstackIOSFontMap().end()) {
            static unsigned missCount = 0;
            if (++missCount <= 8)
                WTFLogAlways("[Driftstack] FontCache: lookup MISS for family '%s' (lowercase='%s')", family.string().utf8().data(), lowercase.utf8().data());
            return nullptr;
        }
        const auto& variants = it->value;
        const float requestedWeight = (static_cast<float>(fontDescription.weight()) - 400.f) / 400.f; // 100 → -0.75; 400 → 0; 700 → 0.75; 900 → 1.25 → clamp 1.0
        const bool requestedItalic = isItalic(fontDescription.fontStyleSlope());

        // V-090 Track 4 Phase 4.D: try explicit per-family styleName override first.
        const int cssWeight = static_cast<int>(static_cast<float>(fontDescription.weight()));
        String preferredStyle = preferredIOSStyleForFamily(lowercase, cssWeight);
        if (!preferredStyle.isEmpty()) {
            for (const auto& v : variants) {
                if (v.styleName == preferredStyle) {
                    chosenVariant = v;
                    found = true;
                    break;
                }
            }
        }

        if (!found) {
            // V-086 Track 4 fix: pick the variant whose (weight, italic)
            // is closest to the requested FontDescription. Convert the
            // request's weight/italic into CTFont's [-1, 1] weight scale
            // and slant boolean.
            float bestScore = std::numeric_limits<float>::infinity();
            for (const auto& v : variants) {
                float italicMismatch = (v.italic != requestedItalic) ? 1.0f : 0.0f;
                float weightDelta = std::abs(v.weight - requestedWeight);
                // Italic mismatch is a hard cost; weight delta is soft.
                float score = italicMismatch * 10.0f + weightDelta;
                if (score < bestScore) {
                    bestScore = score;
                    chosenVariant = v;
                    found = true;
                }
            }
        }
    }
    if (!found)
        return nullptr;

    static unsigned hitCount = 0;
    if (++hitCount <= 100 || family == AtomString("Papyrus"_s)) {
        char pathBuf[1024] = {};
        if (chosenVariant.url) {
            RetainPtr<CFStringRef> urlPath = CFURLGetString(chosenVariant.url.get());
            if (urlPath)
                CFStringGetCString(urlPath.get(), pathBuf, sizeof(pathBuf), kCFStringEncodingUTF8);
        }
        WTFLogAlways("[Driftstack] FontCache: lookup HIT family='%s' weight=%d italic=%d size=%.1f → style='%s' URL=%s",
            family.string().utf8().data(),
            static_cast<int>(static_cast<float>(fontDescription.weight())),
            static_cast<int>(isItalic(fontDescription.fontStyleSlope())),
            size,
            chosenVariant.styleName.utf8().data(),
            pathBuf);
    }

    RetainPtr<CFArrayRef> descs = adoptCF(CTFontManagerCreateFontDescriptorsFromURL(chosenVariant.url.get()));
    if (!descs || !CFArrayGetCount(descs.get()))
        return nullptr;
    // For .ttc collections containing multiple variants, find the descriptor
    // whose family-name matches the requested family exactly AND whose
    // italic + weight matches our chosen variant. Falls back to the first
    // descriptor if no match.
    CTFontDescriptorRef chosen = nullptr;
    RetainPtr<CTFontDescriptorRef> chosenHolder; // keeps a realized descriptor alive past the loop (macOS 26.4)
    CFIndex count = CFArrayGetCount(descs.get());
    for (CFIndex i = 0; i < count; ++i) {
        CTFontDescriptorRef d = static_cast<CTFontDescriptorRef>(CFArrayGetValueAtIndex(descs.get(), i));
        RetainPtr<CTFontDescriptorRef> realizedD;
        RetainPtr<CFStringRef> familyCF = adoptCF(static_cast<CFStringRef>(CTFontDescriptorCopyAttribute(d, kCTFontFamilyNameAttribute)));
        if (!familyCF) {
            // W2196 (macOS 26.4 fleet): CTFontManagerCreateFontDescriptorsFromURL leaves the descriptor
            // attrs (family/traits/style) lazy/null → this .ttc face-match would skip every descriptor
            // and fall to descriptor[0] = the WRONG face/weight for multi-face fonts (Hiragino W3/W6/W8,
            // Papyrus Regular/Condensed). Realize the font + match off the realized descriptor. Inert on
            // 26.2 (attr non-null there). Sibling of the override-map fix at line ~429.
            RetainPtr<CTFontRef> rf = adoptCF(CTFontCreateWithFontDescriptor(d, 0.0, nullptr));
            if (rf) {
                familyCF = adoptCF(CTFontCopyFamilyName(rf.get()));
                realizedD = adoptCF(CTFontCopyFontDescriptor(rf.get()));
                if (realizedD)
                    d = realizedD.get();
            }
        }
        if (!familyCF || String(familyCF.get()).convertToASCIILowercase() != lowercase)
            continue;
        // Match style by traits.
        RetainPtr<CFDictionaryRef> dTraits = adoptCF(static_cast<CFDictionaryRef>(CTFontDescriptorCopyAttribute(d, kCTFontTraitsAttribute)));
        float dWeight = 0.f; bool dItalic = false;
        if (dTraits) {
            CFNumberRef wn = static_cast<CFNumberRef>(CFDictionaryGetValue(dTraits.get(), kCTFontWeightTrait));
            if (wn) CFNumberGetValue(wn, kCFNumberFloatType, &dWeight);
            CFNumberRef sn = static_cast<CFNumberRef>(CFDictionaryGetValue(dTraits.get(), kCTFontSlantTrait));
            if (sn) {
                float s = 0.f;
                CFNumberGetValue(sn, kCFNumberFloatType, &s);
                dItalic = s > 0.01f;
            }
        }
        if (dItalic == chosenVariant.italic && std::abs(dWeight - chosenVariant.weight) < 0.01f) {
            // V-091 fix: also match by styleName when traits tie, so .ttc
            // files with multiple faces at identical (weight, italic) but
            // differing styleName (e.g., Papyrus.ttc Condensed/Regular)
            // resolve to the variant the override picked, not whichever
            // descriptor was enumerated first.
            RetainPtr<CFStringRef> styleCF = adoptCF(static_cast<CFStringRef>(CTFontDescriptorCopyAttribute(d, kCTFontStyleNameAttribute)));
            if (!styleCF || String(styleCF.get()) != chosenVariant.styleName)
                continue;
            chosen = d;
            chosenHolder = realizedD; // null on the 26.2 path (d points into descs, which outlives)
            break;
        }
    }
    if (!chosen)
        chosen = static_cast<CTFontDescriptorRef>(CFArrayGetValueAtIndex(descs.get(), 0));

    return adoptCF(CTFontCreateWithFontDescriptor(chosen, size, nullptr));
}
#endif // PLATFORM(DRIFTSTACK)

static RetainPtr<CFArrayRef> variationAxesWithNonLocalizedAxesNames(CTFontDescriptorRef fontDescriptor)
{
    // Reading kCTFontVariationAxesAttribute returns non localized axes names
    return adoptCF(static_cast<CFArrayRef>(CTFontDescriptorCopyAttribute(fontDescriptor, kCTFontVariationAxesAttribute)));
}

static RetainPtr<CFArrayRef> variationAxes(CTFontRef font, ShouldLocalizeAxisNames shouldLocalizeAxisNames)
{
    if (shouldLocalizeAxisNames == ShouldLocalizeAxisNames::Yes)
        return adoptCF(CTFontCopyVariationAxes(font));
    RetainPtr fontDescriptor = adoptCF(CTFontCopyFontDescriptor(font));
    return variationAxesWithNonLocalizedAxesNames(fontDescriptor.get());
}

VariationDefaultsMap defaultVariationValues(CTFontRef font, ShouldLocalizeAxisNames shouldLocalizeAxisNames)
{
    VariationDefaultsMap result;
    auto axes = variationAxes(font, shouldLocalizeAxisNames);
    if (!axes)
        return result;
    auto size = CFArrayGetCount(axes.get());
    for (CFIndex i = 0; i < size; ++i) {
        RetainPtr axis = static_cast<CFDictionaryRef>(CFArrayGetValueAtIndex(axes.get(), i));
        RetainPtr axisIdentifier = static_cast<CFNumberRef>(CFDictionaryGetValue(axis.get(), kCTFontVariationAxisIdentifierKey));
        String axisName = static_cast<CFStringRef>(CFDictionaryGetValue(axis.get(), kCTFontVariationAxisNameKey));
        RetainPtr defaultValue = static_cast<CFNumberRef>(CFDictionaryGetValue(axis.get(), kCTFontVariationAxisDefaultValueKey));
        RetainPtr minimumValue = static_cast<CFNumberRef>(CFDictionaryGetValue(axis.get(), kCTFontVariationAxisMinimumValueKey));
        RetainPtr maximumValue = static_cast<CFNumberRef>(CFDictionaryGetValue(axis.get(), kCTFontVariationAxisMaximumValueKey));
        uint32_t rawAxisIdentifier = 0;
        Boolean success = CFNumberGetValue(axisIdentifier.get(), kCFNumberSInt32Type, &rawAxisIdentifier);
        ASSERT_UNUSED(success, success);
        float rawDefaultValue = 0;
        float rawMinimumValue = 0;
        float rawMaximumValue = 0;
        CFNumberGetValue(defaultValue.get(), kCFNumberFloatType, &rawDefaultValue);
        CFNumberGetValue(minimumValue.get(), kCFNumberFloatType, &rawMinimumValue);
        CFNumberGetValue(maximumValue.get(), kCFNumberFloatType, &rawMaximumValue);

        if (rawMinimumValue > rawMaximumValue)
            std::swap(rawMinimumValue, rawMaximumValue);

        char b1 = rawAxisIdentifier >> 24;
        char b2 = (rawAxisIdentifier & 0xFF0000) >> 16;
        char b3 = (rawAxisIdentifier & 0xFF00) >> 8;
        char b4 = rawAxisIdentifier & 0xFF;
        FontTag resultKey = { { b1, b2, b3, b4 } };
        VariationDefaults resultValues = { axisName, rawDefaultValue, rawMinimumValue, rawMaximumValue };
        result.set(resultKey, resultValues);
    }
    return result;
}

static std::optional<bool>& NODELETE overrideEnhanceTextLegibility()
{
    static NeverDestroyed<std::optional<bool>> overrideEnhanceTextLegibility;
    return overrideEnhanceTextLegibility.get();
}

void setOverrideEnhanceTextLegibility(bool override)
{
    overrideEnhanceTextLegibility() = override;
}

static bool& platformShouldEnhanceTextLegibility()
{
    static NeverDestroyed<bool> shouldEnhanceTextLegibility = _AXSEnhanceTextLegibilityEnabled();
    return shouldEnhanceTextLegibility.get();
}

static inline bool shouldEnhanceTextLegibility()
{
    return overrideEnhanceTextLegibility().value_or(platformShouldEnhanceTextLegibility());
}

RetainPtr<CTFontRef> preparePlatformFont(UnrealizedCoreTextFont&& originalFont, const FontDescription& fontDescription, const FontCreationContext& fontCreationContext, FontTypeForPreparation fontTypeForPreparation, ApplyTraitsVariations applyTraitsVariations)
{
    originalFont.modifyFromContext(fontDescription, fontCreationContext, fontTypeForPreparation, applyTraitsVariations, shouldEnhanceTextLegibility());
    return originalFont.realize();
}

RefPtr<Font> FontCache::similarFont(const FontDescription& description, const String& family)
{
    // Attempt to find an appropriate font using a match based on the presence of keywords in
    // the requested names. For example, we'll match any name that contains "Arabic" to Geeza Pro.
    if (family.isEmpty())
        return nullptr;

#if PLATFORM(IOS_FAMILY) || PLATFORM(DRIFTSTACK)
    // V-683 (2026-05-11): extend to DRIFTSTACK. iOS substitutes Menlo/Monaco
    // → Courier and Lucida Grande → Verdana before CT font resolution. Without
    // this, Mac fork resolves the requested family directly via Mac CT,
    // returning Menlo (Mac's native monospace) for "menlo" / "monaco" requests
    // — different glyphs and metrics than iOS Courier.
    // Affects canvas fillText with monospace CSS family.
    // Substitute the default monospace font for well-known monospace fonts.
    if (equalLettersIgnoringASCIICase(family, "monaco"_s) || equalLettersIgnoringASCIICase(family, "menlo"_s))
        return fontForFamily(description, "courier"_s);

    // Substitute Verdana for Lucida Grande.
    if (equalLettersIgnoringASCIICase(family, "lucida grande"_s))
        return fontForFamily(description, "verdana"_s);
#endif

    static constexpr auto matchWords = std::to_array<ASCIILiteral>({ "Arabic"_s, "Pashto"_s, "Urdu"_s });
    auto familyMatcher = StringView(family);
    for (auto matchWord : matchWords) {
        if (equalIgnoringASCIICase(familyMatcher, matchWord))
            return fontForFamily(description, isFontWeightBold(description.weight()) ? "GeezaPro-Bold"_s : "GeezaPro"_s);
    }
    return nullptr;
}

static void fontCacheRegisteredFontsChangedNotificationCallback(CFNotificationCenterRef, void* observer, CFStringRef, const void *, CFDictionaryRef)
{
    ASSERT_UNUSED(observer, isMainThread() && observer == &FontCache::forCurrentThread());

    ensureOnMainThread([] {
        FontCache::invalidateAllFontCaches();
    });
}

void FontCache::platformInit()
{
    CFNotificationCenterAddObserver(CFNotificationCenterGetLocalCenterSingleton(), this, &fontCacheRegisteredFontsChangedNotificationCallback, kCTFontManagerRegisteredFontsChangedNotification, nullptr, CFNotificationSuspensionBehaviorDeliverImmediately);

#if PLATFORM(IOS_FAMILY)
    CFNotificationCenterAddObserver(CFNotificationCenterGetLocalCenterSingleton(), this, &fontCacheRegisteredFontsChangedNotificationCallback, protect(getUIContentSizeCategoryDidChangeNotificationName()).get(), nullptr, CFNotificationSuspensionBehaviorDeliverImmediately);
#endif

    CFNotificationCenterAddObserver(CFNotificationCenterGetLocalCenterSingleton(), this, &fontCacheRegisteredFontsChangedNotificationCallback, kAXSEnhanceTextLegibilityChangedNotification, nullptr, CFNotificationSuspensionBehaviorDeliverImmediately);

#if PLATFORM(MAC)
    CFNotificationCenterRef center = CFNotificationCenterGetLocalCenterSingleton();
    const CFStringRef notificationName = kCFLocaleCurrentLocaleDidChangeNotification;
#else
    CFNotificationCenterRef center = CFNotificationCenterGetDarwinNotifyCenterSingleton();
    const CFStringRef notificationName = CFSTR("com.apple.language.changed");
#endif
    CFNotificationCenterAddObserver(center, this, &fontCacheRegisteredFontsChangedNotificationCallback, notificationName, nullptr, CFNotificationSuspensionBehaviorDeliverImmediately);
}

Vector<String> FontCache::systemFontFamilies()
{
    Vector<String> fontFamilies;

    auto availableFontFamilies = adoptCF(CTFontManagerCopyAvailableFontFamilyNames());
    CFIndex count = CFArrayGetCount(availableFontFamilies.get());

#if PLATFORM(DRIFTSTACK)
    // V-230: filter Mac-system font enumeration to iOS-installed family
    // allowlist. Mac's CTFontManagerCopyAvailableFontFamilyNames returns
    // ~500 fonts (Mac system + Stage B-registered iOS); detection vendors
    // (font-enumeration probe, /canvasfont, fingerprint-library fontPreferences,
    // tracker-detector-suite native font enumeration) probe this list. iPhone Safari's
    // equivalent surface is ~99 family names. Mac-only fonts (Avenir Next,
    // Gill Sans, etc. that exist on Mac but not iOS — actually those ARE
    // on iOS; the Mac-only set is much smaller, ~30-50 families) leak
    // identification.
    //
    // Stage B's driftstackIOSFontMap (keyed lowercase) holds the iOS
    // family allowlist; filter Mac-returned list to include ONLY families
    // whose lowercase form is in the map. Net effect: all iOS-installed
    // fonts visible (whether Mac-shared or iOS-only); Mac-only fonts
    // hidden from JS-side enumeration. Phase 2 process-startup gate per
    // file 105 — driftstackIOSFontMap initialized once on first font lookup.
    initializeDriftstackIOSFontMapIfNeeded();
    Locker mapLocker(driftstackIOSFontMapLock);
    auto& iosFontMap = driftstackIOSFontMap();
    for (CFIndex i = 0; i < count; ++i) {
        RetainPtr fontName = dynamic_cf_cast<CFStringRef>(CFArrayGetValueAtIndex(availableFontFamilies.get(), i));
        if (!fontName) {
            ASSERT_NOT_REACHED();
            continue;
        }
        if (fontNameIsSystemFont(fontName.get()))
            continue;
        String name = fontName.get();
        if (iosFontMap.contains(name.convertToASCIILowercase()))
            fontFamilies.append(name);
    }
    return fontFamilies;
#else
    for (CFIndex i = 0; i < count; ++i) {
        RetainPtr fontName = dynamic_cf_cast<CFStringRef>(CFArrayGetValueAtIndex(availableFontFamilies.get(), i));
        if (!fontName) {
            ASSERT_NOT_REACHED();
            continue;
        }

        if (fontNameIsSystemFont(fontName.get()))
            continue;

        fontFamilies.append(fontName.get());
    }

    return fontFamilies;
#endif
}

static inline bool NODELETE isSystemFont(const String& family)
{
    // String's operator[] handles out-of-bounds by returning 0.
    return family[0] == '.';
}

bool FontCache::isSystemFontForbiddenForEditing(const String& fontFamily)
{
    return isSystemFont(fontFamily);
}

static CTFontSymbolicTraits NODELETE computeTraits(const FontDescription& fontDescription)
{
    CTFontSymbolicTraits traits = 0;
    if (fontDescription.fontStyleSlope())
        traits |= kCTFontTraitItalic;
    if (isFontWeightBold(fontDescription.weight()))
        traits |= kCTFontTraitBold;
    return traits;
}

SynthesisPair computeNecessarySynthesis(CTFontRef font, const FontDescription& fontDescription, OptionSet<FontLookupOptions> synthesisOptions, ShouldComputePhysicalTraits shouldComputePhysicalTraits, bool isPlatformFont)
{
    if (CTFontIsAppleColorEmoji(font))
        return SynthesisPair(false, false);

    if (isPlatformFont)
        return SynthesisPair(false, false);

    bool needsSyntheticBold = fontDescription.hasAutoFontSynthesisWeight()
        && !synthesisOptions.contains(FontLookupOptions::DisallowBoldSynthesis);
    bool needsSyntheticOblique = fontDescription.allowsItalicOrObliqueFontSynthesisStyle() && !synthesisOptions.contains(FontLookupOptions::DisallowObliqueSynthesis);

    if (!needsSyntheticBold && !needsSyntheticOblique)
        return SynthesisPair(false, false);

    CTFontSymbolicTraits desiredTraits = computeTraits(fontDescription);
    CTFontSymbolicTraits actualTraits = 0;
    if (isFontWeightBold(fontDescription.weight()) || isItalic(fontDescription.fontStyleSlope())) {
        if (shouldComputePhysicalTraits == ShouldComputePhysicalTraits::Yes)
            actualTraits = CTFontGetPhysicalSymbolicTraits(font);
        else
            actualTraits = CTFontGetSymbolicTraits(font);
    }

    needsSyntheticBold = needsSyntheticBold && (desiredTraits & kCTFontTraitBold) && !(actualTraits & kCTFontTraitBold);
    needsSyntheticOblique = needsSyntheticOblique && (desiredTraits & kCTFontTraitItalic) && !(actualTraits & kCTFontTraitItalic);

    return SynthesisPair(needsSyntheticBold, needsSyntheticOblique);
}

class FontCacheAllowlist {
public:
    static FontCacheAllowlist& NODELETE singleton() WTF_REQUIRES_LOCK(lock)
    {
        static NeverDestroyed<FontCacheAllowlist> allowlist;
        return allowlist;
    }

    void set(const Vector<String>& inputAllowlist) WTF_REQUIRES_LOCK(lock)
    {
        m_families.clear();
        for (auto& item : inputAllowlist)
            m_families.add(item);
    }

    bool allows(const AtomString& family) const WTF_REQUIRES_LOCK(lock)
    {
        return m_families.isEmpty() || m_families.contains(family);
    }

    static Lock lock;

private:
    HashSet<String, ASCIICaseInsensitiveHash> m_families;
};

Lock FontCacheAllowlist::lock;

void FontCache::setFontAllowlist(const Vector<String>& inputAllowlist)
{
    Locker locker { FontCacheAllowlist::lock };
    FontCacheAllowlist::singleton().set(inputAllowlist);
}

// Because this struct holds intermediate values which may be in the compressed -1 - 1 GX range, we don't want to use the relatively large
// quantization of FontSelectionValue. Instead, do this logic with floats.
struct MinMax {
    float minimum;
    float maximum;
};

struct VariationCapabilities {
    std::optional<MinMax> weight;
    std::optional<MinMax> width;
    std::optional<MinMax> slope;
};

static std::optional<MinMax> extractVariationBounds(CFDictionaryRef axis)
{
    RetainPtr minimumValue = static_cast<CFNumberRef>(CFDictionaryGetValue(axis, kCTFontVariationAxisMinimumValueKey));
    RetainPtr maximumValue = static_cast<CFNumberRef>(CFDictionaryGetValue(axis, kCTFontVariationAxisMaximumValueKey));
    float rawMinimumValue = 0;
    float rawMaximumValue = 0;
    CFNumberGetValue(minimumValue.get(), kCFNumberFloatType, &rawMinimumValue);
    CFNumberGetValue(maximumValue.get(), kCFNumberFloatType, &rawMaximumValue);
    if (rawMinimumValue < rawMaximumValue)
        return {{ rawMinimumValue, rawMaximumValue }};
    return std::nullopt;
}

static VariationCapabilities variationCapabilitiesForFontDescriptor(CTFontDescriptorRef fontDescriptor)
{
    VariationCapabilities result;

    if (!adoptCF(CTFontDescriptorCopyAttribute(fontDescriptor, kCTFontVariationAttribute)))
        return result;

    auto variations = variationAxesWithNonLocalizedAxesNames(fontDescriptor);
    if (!variations)
        return result;

    auto axisCount = CFArrayGetCount(variations.get());
    if (!axisCount)
        return result;

    for (CFIndex i = 0; i < axisCount; ++i) {
        RetainPtr axis = static_cast<CFDictionaryRef>(CFArrayGetValueAtIndex(variations.get(), i));
        RetainPtr axisIdentifier = static_cast<CFNumberRef>(CFDictionaryGetValue(axis.get(), kCTFontVariationAxisIdentifierKey));
        uint32_t rawAxisIdentifier = 0;
        Boolean success = CFNumberGetValue(axisIdentifier.get(), kCFNumberSInt32Type, &rawAxisIdentifier);
        ASSERT_UNUSED(success, success);
        if (rawAxisIdentifier == 0x77676874) // 'wght'
            result.weight = extractVariationBounds(axis.get());
        else if (rawAxisIdentifier == 0x77647468) // 'wdth'
            result.width = extractVariationBounds(axis.get());
        else if (rawAxisIdentifier == 0x736C6E74) // 'slnt'
            result.slope = extractVariationBounds(axis.get());
    }

    bool optOutFromGXNormalization = CTFontDescriptorIsSystemUIFont(fontDescriptor);

    auto variationType = [&] {
        // FIXME: https://bugs.webkit.org/show_bug.cgi?id=247987 Stop creating a whole CTFont here. Ideally we'd be able to do all the inspection we need to do without one.
        auto font = adoptCF(CTFontCreateWithFontDescriptor(fontDescriptor, 0, nullptr));
        return FontInterrogation(font.get()).variationType;
    }();
    if (variationType == FontInterrogation::VariationType::TrueTypeGX && !optOutFromGXNormalization) {
        if (result.weight)
            result.weight = { { normalizeGXWeight(result.weight.value().minimum), normalizeGXWeight(result.weight.value().maximum) } };
        if (result.width)
            result.width = { { normalizeVariationWidth(result.width.value().minimum), normalizeVariationWidth(result.width.value().maximum) } };
        if (result.slope)
            result.slope = { { normalizeSlope(result.slope.value().minimum), normalizeSlope(result.slope.value().maximum) } };
    }

    auto minimum = static_cast<float>(FontSelectionValue::minimumValue());
    auto maximum = static_cast<float>(FontSelectionValue::maximumValue());
    if (result.weight && (result.weight.value().minimum < minimum || result.weight.value().maximum > maximum))
        result.weight = { };
    if (result.width && (result.width.value().minimum < minimum || result.width.value().maximum > maximum))
        result.width = { };
    if (result.slope && (result.slope.value().minimum < minimum || result.slope.value().maximum > maximum))
        result.slope = { };

    return result;
}

static float getCSSAttribute(CTFontDescriptorRef fontDescriptor, const CFStringRef attribute, float fallback)
{
    auto number = adoptCF(static_cast<CFNumberRef>(CTFontDescriptorCopyAttribute(fontDescriptor, attribute)));
    if (!number)
        return fallback;
    float cssValue;
    auto success = CFNumberGetValue(number.get(), kCFNumberFloatType, &cssValue);
    ASSERT_UNUSED(success, success);
    return cssValue;
}

FontSelectionCapabilities capabilitiesForFontDescriptor(CTFontDescriptorRef fontDescriptor)
{
    if (!fontDescriptor)
        return { };

    VariationCapabilities variationCapabilities = variationCapabilitiesForFontDescriptor(fontDescriptor);

    if (!variationCapabilities.slope) {
        auto traits = adoptCF(static_cast<CFDictionaryRef>(CTFontDescriptorCopyAttribute(fontDescriptor, kCTFontTraitsAttribute)));
        if (traits) {
            if (!variationCapabilities.slope) {
                RetainPtr symbolicTraitsNumber = static_cast<CFNumberRef>(CFDictionaryGetValue(traits.get(), kCTFontSymbolicTrait));
                if (symbolicTraitsNumber) {
                    int32_t symbolicTraits;
                    auto success = CFNumberGetValue(symbolicTraitsNumber.get(), kCFNumberSInt32Type, &symbolicTraits);
                    ASSERT_UNUSED(success, success);
                    auto slopeValue = static_cast<float>(symbolicTraits & kCTFontTraitItalic ? italicValue() : normalItalicValue());
                    variationCapabilities.slope = {{ slopeValue, slopeValue }};
                } else
                    variationCapabilities.slope = {{ static_cast<float>(normalItalicValue()), static_cast<float>(normalItalicValue()) }};
            }
        }
    }

    if (!variationCapabilities.weight) {
        auto value = getCSSAttribute(fontDescriptor, kCTFontCSSWeightAttribute, static_cast<float>(normalWeightValue()));
        variationCapabilities.weight = {{ value, value }};
    }

    if (!variationCapabilities.width) {
        auto value = getCSSAttribute(fontDescriptor, kCTFontCSSWidthAttribute, static_cast<float>(normalWidthValue()));
        variationCapabilities.width = {{ value, value }};
    }

    FontSelectionCapabilities result = {{ FontSelectionValue(variationCapabilities.weight.value().minimum), FontSelectionValue(variationCapabilities.weight.value().maximum) },
        { FontSelectionValue(variationCapabilities.width.value().minimum), FontSelectionValue(variationCapabilities.width.value().maximum) },
        { FontSelectionValue(variationCapabilities.slope.value().minimum), FontSelectionValue(variationCapabilities.slope.value().maximum) }};
    ASSERT(result.weight.isValid());
    ASSERT(result.width.isValid());
    ASSERT(result.slope.isValid());
    return result;
}

static const FontDatabase::InstalledFont* findClosestFont(const FontDatabase::InstalledFontFamily& familyFonts, FontSelectionRequest fontSelectionRequest)
{
    auto capabilities = familyFonts.installedFonts.map([](auto& font) {
        return font.capabilities;
    });
    FontSelectionAlgorithm fontSelectionAlgorithm(fontSelectionRequest, WTF::move(capabilities), familyFonts.capabilities);
    auto index = fontSelectionAlgorithm.indexOfBestCapabilities();
    if (index == notFound)
        return nullptr;

    return &familyFonts.installedFonts[index];
}

FontDatabase& FontCache::database(AllowUserInstalledFonts allowUserInstalledFonts)
{
    return allowUserInstalledFonts == AllowUserInstalledFonts::Yes ? m_databaseAllowingUserInstalledFonts : m_databaseDisallowingUserInstalledFonts;
}

Vector<FontSelectionCapabilities> FontCache::getFontSelectionCapabilitiesInFamily(const AtomString& familyName, AllowUserInstalledFonts allowUserInstalledFonts)
{
    auto& fontDatabase = database(allowUserInstalledFonts);
    const auto& fonts = fontDatabase.collectionForFamily(familyName.string());
    return fonts.installedFonts.map([](auto& font) {
        return font.capabilities;
    });
}

struct FontLookup {
    RetainPtr<CTFontDescriptorRef> result;
    bool createdFromPostScriptName { false };
};

static bool isDotPrefixedForbiddenFont(const AtomString& family)
{
    if (linkedOnOrAfterSDKWithBehavior(SDKAlignedBehavior::ForbidsDotPrefixedFonts))
        return family.startsWith('.');
    return equalLettersIgnoringASCIICase(family, ".applesystemuifontserif"_s)
        || equalLettersIgnoringASCIICase(family, ".sf ns mono"_s)
        || equalLettersIgnoringASCIICase(family, ".sf ui mono"_s)
        || equalLettersIgnoringASCIICase(family, ".sf arabic"_s)
        || equalLettersIgnoringASCIICase(family, ".applesystemuifontrounded"_s);
}

static bool isAllowlistedFamily(const AtomString& family)
{
    if (isSystemFont(family.string()))
        return true;

    Locker locker { FontCacheAllowlist::lock };
    return FontCacheAllowlist::singleton().allows(family);
}

static FontLookup platformFontLookupWithFamily(FontDatabase& fontDatabase, const AtomString& family, FontSelectionRequest request, OptionSet<FontLookupOptions> options)
{
    if (!isAllowlistedFamily(family))
        return { nullptr };

    if (isDotPrefixedForbiddenFont(family)) {
        // If you want to use these fonts, use system-ui, ui-serif, ui-monospace, or ui-rounded.
        return { nullptr };
    }

    const auto& familyFonts = fontDatabase.collectionForFamily(family.string());
    if (familyFonts.isEmpty()) {
        // The CSS spec states that font-family only accepts a name of an actual font family. However, in WebKit, we claim to also
        // support supplying a PostScript name instead. However, this creates problems when the other properties (font-weight,
        // font-style) disagree with the traits of the PostScript-named font. The solution we have come up with is, when the default
        // values for font-weight and font-style are supplied, honor the PostScript name, but if font-weight specifies bold or
        // font-style specifies italic, then we run the regular matching algorithm on the family of the PostScript font. This way,
        // if content simply states "font-family: PostScriptName;" without specifying the other font properties, it will be honored,
        // but if a <b> appears as a descendent element, it will be honored too.
        const auto& postScriptFont = fontDatabase.fontForPostScriptName(family);
        if (!postScriptFont.fontDescriptor)
            return { nullptr };
        if (!options.contains(FontLookupOptions::ExactFamilyNameMatch)
            && ((isItalic(request.slope) && !isItalic(postScriptFont.capabilities.slope.maximum))
            || (isFontWeightBold(request.weight) && !isFontWeightBold(postScriptFont.capabilities.weight.maximum)))) {
            auto postScriptFamilyName = adoptCF(static_cast<CFStringRef>(CTFontDescriptorCopyAttribute(postScriptFont.fontDescriptor.get(), kCTFontFamilyNameAttribute)));
            if (!postScriptFamilyName)
                return { nullptr };
            const auto& familyFonts = fontDatabase.collectionForFamily(String(postScriptFamilyName.get()));
            if (familyFonts.isEmpty())
                return { nullptr };
            if (const auto* installedFont = findClosestFont(familyFonts, request)) {
                if (!installedFont->fontDescriptor)
                    return { nullptr };
                return { installedFont->fontDescriptor.get(), true };
            }
            return { nullptr };
        }
        return { postScriptFont.fontDescriptor.get(), true };
    }

    if (const auto* installedFont = findClosestFont(familyFonts, request))
        return { installedFont->fontDescriptor.get(), false };

    return { nullptr };
}

void FontCache::platformInvalidate()
{
    // FIXME: Workers need to access SystemFontDatabaseCoreText.
    m_fontFamilySpecificationCoreTextCache.clear();
    m_systemFontDatabaseCoreText.clear();

    platformShouldEnhanceTextLegibility() = _AXSEnhanceTextLegibilityEnabled();
}

struct SpecialCaseFontLookupResult {
    UnrealizedCoreTextFont unrealizedCoreTextFont;
    FontTypeForPreparation fontTypeForPreparation;
};

static std::optional<SpecialCaseFontLookupResult> fontDescriptorWithFamilySpecialCase(const AtomString& family, const FontDescription& fontDescription, float size, AllowUserInstalledFonts allowUserInstalledFonts)
{
    // FIXME: See comment in FontCascadeDescription::effectiveFamilyAt() in FontDescriptionCocoa.cpp
    std::optional<SystemFontKind> systemDesign;

    if (equalLettersIgnoringASCIICase(family, "ui-serif"_s))
        systemDesign = SystemFontKind::UISerif;
    else if (equalLettersIgnoringASCIICase(family, "ui-monospace"_s))
        systemDesign = SystemFontKind::UIMonospace;
    else if (equalLettersIgnoringASCIICase(family, "ui-rounded"_s))
        systemDesign = SystemFontKind::UIRounded;

    if (equalLettersIgnoringASCIICase(family, "-webkit-system-font"_s) || equalLettersIgnoringASCIICase(family, "-apple-system"_s) || equalLettersIgnoringASCIICase(family, "-apple-system-font"_s) || equalLettersIgnoringASCIICase(family, "system-ui"_s) || equalLettersIgnoringASCIICase(family, "ui-sans-serif"_s)) {
        ASSERT(!systemDesign);
        systemDesign = SystemFontKind::SystemUI;
    }

    if (systemDesign) {
        auto cascadeList = SystemFontDatabaseCoreText::forCurrentThread().cascadeList(fontDescription, family, *systemDesign, allowUserInstalledFonts);
        if (cascadeList.isEmpty())
            return std::nullopt;
        return { { RetainPtr { cascadeList[0] }, FontTypeForPreparation::SystemFont } };
    }

    if (family.startsWith("UICTFontTextStyle"_s)) {
        const auto& request = fontDescription.fontSelectionRequest();
        CTFontSymbolicTraits traits = (isFontWeightBold(request.weight) ? kCTFontTraitBold : 0) | (isItalic(request.slope) ? kCTFontTraitItalic : 0);
        auto descriptor = adoptCF(CTFontDescriptorCreateWithTextStyle(family.string().createCFString().get(), protect(contentSizeCategory()).get(), fontDescription.computedLocale().string().createCFString().get()));
        if (traits) {
            // FIXME: rdar://105369379 As far as I can tell, there's no modification to the attributes dictionary that has the same effect as CTFontDescriptorCreateCopyWithSymbolicTraits(),
            // because there doesn't seem to be a place to specify the bitmask. That's the reason we're creating the derived CTFontDescriptor here, rather than in UnrealizedCoreTextFont::realize().
            return { { adoptCF(CTFontDescriptorCreateCopyWithSymbolicTraits(descriptor.get(), traits, traits)), FontTypeForPreparation::SystemFont } };
        }
        return { { WTF::move(descriptor), FontTypeForPreparation::SystemFont } };
    }

    if (equalLettersIgnoringASCIICase(family, "-apple-menu"_s))
        return { { adoptCF(CTFontDescriptorCreateForUIType(kCTFontUIFontMenuItem, size, fontDescription.computedLocale().string().createCFString().get())), FontTypeForPreparation::SystemFont } };

    if (equalLettersIgnoringASCIICase(family, "-apple-status-bar"_s))
        return { { adoptCF(CTFontDescriptorCreateForUIType(kCTFontUIFontSystem, size, fontDescription.computedLocale().string().createCFString().get())), FontTypeForPreparation::SystemFont } };

    if (equalLettersIgnoringASCIICase(family, "lastresort"_s))
        return { { adoptCF(CTFontDescriptorCreateLastResort()), FontTypeForPreparation::NonSystemFont } };

    if (equalLettersIgnoringASCIICase(family, "-apple-system-monospaced-numbers"_s)) {
        auto systemFontDescriptor = UnrealizedCoreTextFont { adoptCF(CTFontDescriptorCreateForUIType(kCTFontUIFontSystem, size, nullptr)) };
        systemFontDescriptor.modify([](CFMutableDictionaryRef attributes) {
            int numberSpacingType = kNumberSpacingType;
            int monospacedNumbersSelector = kMonospacedNumbersSelector;
            auto numberSpacingNumber = adoptCF(CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &numberSpacingType));
            auto monospacedNumbersNumber = adoptCF(CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &monospacedNumbersSelector));
            CFTypeRef keys[] = { kCTFontFeatureTypeIdentifierKey, kCTFontFeatureSelectorIdentifierKey };
            CFTypeRef values[] = { numberSpacingNumber.get(), monospacedNumbersNumber.get() };
            ASSERT(std::size(keys) == std::size(values));
            auto settingsDictionary = adoptCF(CFDictionaryCreate(kCFAllocatorDefault, keys, values, std::size(keys), &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks));
            CFTypeRef entries[] = { settingsDictionary.get() };
            auto settingsArray = adoptCF(CFArrayCreate(kCFAllocatorDefault, entries, std::size(entries), &kCFTypeArrayCallBacks));
            CFDictionaryAddValue(attributes, kCTFontFeatureSettingsAttribute, settingsArray.get());
        });
        return { { systemFontDescriptor, FontTypeForPreparation::SystemFont } };
    }

    return std::nullopt;
}

static RetainPtr<CTFontRef> fontWithFamily(FontDatabase& fontDatabase, const AtomString& family, const FontDescription& fontDescription, const FontCreationContext& fontCreationContext, float size, OptionSet<FontLookupOptions> options)
{
    ASSERT(fontDatabase.allowUserInstalledFonts() == fontDescription.shouldAllowUserInstalledFonts());
#if PLATFORM(DRIFTSTACK)
    // V-433.Y wave 29-197 — universal Mac-font blocker eliminates the
    // need for platformFontLookupWithFamily below, leaving fontDatabase
    // and options unused on this platform.
    (void)fontDatabase;
    (void)options;
#endif

    if (family.isEmpty())
        return nullptr;

#if PLATFORM(DRIFTSTACK)
    // Stage B Step 3: prefer iOS-archetype fonts for any family name they
    // expose. This bypasses CTFont's name-based lookup which otherwise
    // returns Mac's system Helvetica/Arial/etc. variants — and prevents
    // canvas measureText from observing iPhone-specific font metrics.
    if (auto driftstackFont = driftstackIOSFontWithFamily(family, fontDescription, size))
        return driftstackFont;
#endif

    if (auto lookupResult = fontDescriptorWithFamilySpecialCase(family, fontDescription, size, fontDescription.shouldAllowUserInstalledFonts())) {
        lookupResult->unrealizedCoreTextFont.setSize(size);
        lookupResult->unrealizedCoreTextFont.modify([&](CFMutableDictionaryRef attributes) {
            addAttributesForInstalledFonts(attributes, fontDescription.shouldAllowUserInstalledFonts());
        });
        return preparePlatformFont(WTF::move(lookupResult->unrealizedCoreTextFont), fontDescription, fontCreationContext, lookupResult->fontTypeForPreparation);
    }

#if PLATFORM(DRIFTSTACK)
    // V-433.Y (wave 29-197, founder lock 2026-05-14 "pass any test which
    // might be doing different things") — universal Mac-font blocker
    // WITH iOS-canonical-shared-glyph exceptions.
    //
    // Any CSS family that wasn't matched by driftstackIOSFontWithFamily
    // (iOS binaries) above OR by fontDescriptorWithFamilySpecialCase
    // (-apple-system, system-ui, lastresort, etc.) is a Mac-installed
    // font that iPhone does NOT expose — EXCEPT for a narrow allow-list
    // of CJK families where Mac CTFont and iOS CTFont share the binary
    // glyph data byte-identically per V-679 (Mac's PingFangUI.ttc has
    // bit-identical cidg/hvgl/hmtx/OS_2 to iOS PingFang.ttc). For those
    // we let Mac CTFont resolve — the metric output matches iPhone.
    //
    // PingFang.ttc fails CTFontManagerCreateFontDescriptorsFromURL parse
    // on Mac (V-487 PARSEFAIL) so driftstackIOSFontWithFamily can't
    // resolve it; Mac's PingFangUI.ttc resolves the same name via Mac
    // CTFont. Allow that fallback only for these specific families.
    auto lowercaseFamily = family.string().convertToASCIILowercase();
    static const std::array<const char*, 11> kIOSCanonicalSharedGlyphFamilies = {
        "pingfang hk",
        "pingfang sc",
        "pingfang tc",
        "heiti sc",
        "heiti tc",
        "applesdgothicneo",
        // W335 (2026-06-02) — #26c PARTIAL: the localized PingFang family names
        // iOS exposes that Mac CTFont ALSO resolves to the bit-identical
        // PingFangUI.ttc (V-679). PingFang.ttc V-487-parse-fails so
        // driftstackIOSFontWithFamily can't load the iOS binary; these route
        // through the SAME Mac-CTFont shared-glyph fallback as Latin "pingfang
        // sc". Only the 4 script/region-MATCHED names resolve on Mac (verified
        // via CTFontCreateWithName: 苹方-简→PingFang SC, 蘋方-港→HK, 蘋方-澳→MO,
        // 蘋方-繁→TC). The 4 MISMATCHED (苹方-港/澳/繁, 蘋方-簡) fall back to
        // Helvetica on Mac, so they are NOT added — adding them would
        // over-detect as Helvetica (a tell). Those need the iOS binary loaded
        // directly (#26c residual; PingFang.ttc CTFontManager parse-fail).
        "苹方-简", "蘋方-港", "蘋方-澳", "蘋方-繁",
        // V-433.Y wave 29-197 — Snell Roundhand is iOS's CSS-cursive
        // default font. iPhone's "cursive" baseline tuple == Snell tuple
        // → Snell Roundhand probes return baseline → "not detected".
        // Mac CSS-cursive defaults to Apple Chancery (denied via denylist
        // → falls to monospace baseline), so without this exception the
        // probe sees Snell metrics distinct from cursive baseline →
        // false positive. Allowing Mac CTFont Snell Roundhand resolution
        // makes the cursive baseline equal Snell's metric tuple (within
        // sub-pixel CT rendering precision), restoring iPhone's logic.
        "snell roundhand",
    };
    bool isSharedGlyph = false;
    for (const char* canonical : kIOSCanonicalSharedGlyphFamilies) {
        if (lowercaseFamily == String::fromUTF8(canonical)) {
            isSharedGlyph = true;
            break;
        }
    }
    // V-433.Y wave 29-198 — Heiti SC/TC redirect: iPhone aliases Heiti
    // SC/TC → PingFang SC/TC internally (both render at PingFang's tuple
    // 4292,180). Mac has its OWN Heiti SC font binary with different
    // metrics (4482,130). Redirect the shared-glyph lookup to use
    // PingFang's name so platformFontLookupWithFamily resolves to Mac's
    // PingFangUI.ttc (which shares glyph data with iOS PingFang per
    // V-679) instead of Mac's separate Heiti SC.
    AtomString lookupFamily = family;
    if (lowercaseFamily == "heiti sc"_s) {
        lookupFamily = AtomString { "PingFang SC"_s };
        isSharedGlyph = true;
    } else if (lowercaseFamily == "heiti tc"_s) {
        lookupFamily = AtomString { "PingFang TC"_s };
        isSharedGlyph = true;
    } else if (lowercaseFamily == "pingfang mo"_s) {
        // W240 — PingFang MO (Macau variant): iOS exposes it, but Mac's PingFangUI.ttc
        // ships only HK/SC/TC faces (no MO). All PingFang regional variants share ONE
        // typeface — identical Latin metrics (width 163.26651, verified == fork's HK/SC/TC
        // which already match iOS exactly) — differing only in Chinese character coverage,
        // which the Latin width-detection never exercises. So redirect MO → the HK face via
        // the SAME shared-glyph mechanism as Heiti: this makes the fork DETECT PingFang MO
        // with the correct 163.26651 metric, matching a real iPhone (which has MO). NOTE:
        // W212's earlier attempt was a no-op because it aliased INSIDE driftstackIOSFontWithFamily
        // (which returns nullptr for non-map families → caller fell back to the original name);
        // this caller-level redirect is the working level (mirrors the Heiti redirect above).
        lookupFamily = AtomString { "PingFang HK"_s };
        isSharedGlyph = true;
    }
    if (!isSharedGlyph)
        return nullptr;

    // Fall through to Mac CTFont resolution for shared-glyph families.
    auto fontLookup = platformFontLookupWithFamily(fontDatabase, lookupFamily, fontDescription.fontSelectionRequest(), options);
    UnrealizedCoreTextFont unrealizedFont = { WTF::move(fontLookup.result) };
    unrealizedFont.setSize(size);
    ApplyTraitsVariations applyTraitsVariations = fontLookup.createdFromPostScriptName ? ApplyTraitsVariations::No : ApplyTraitsVariations::Yes;
    return preparePlatformFont(WTF::move(unrealizedFont), fontDescription, fontCreationContext, FontTypeForPreparation::NonSystemFont, applyTraitsVariations);
#else
    auto fontLookup = platformFontLookupWithFamily(fontDatabase, family, fontDescription.fontSelectionRequest(), options);
    UnrealizedCoreTextFont unrealizedFont = { WTF::move(fontLookup.result) };
    unrealizedFont.setSize(size);
    ApplyTraitsVariations applyTraitsVariations = fontLookup.createdFromPostScriptName ? ApplyTraitsVariations::No : ApplyTraitsVariations::Yes;
    return preparePlatformFont(WTF::move(unrealizedFont), fontDescription, fontCreationContext, FontTypeForPreparation::NonSystemFont, applyTraitsVariations);
#endif
}

#if PLATFORM(MAC)
bool FontCache::shouldAutoActivateFontIfNeeded(const AtomString& family)
{
    if (family.isEmpty())
        return false;

    static const unsigned maxCacheSize = 128;
    ASSERT(m_knownFamilies.size() <= maxCacheSize);
    if (m_knownFamilies.size() == maxCacheSize)
        m_knownFamilies.remove(m_knownFamilies.random());

    // Only attempt to auto-activate fonts once for performance reasons.
    return m_knownFamilies.add(family).isNewEntry;
}

static void autoActivateFont(const String& name, CGFloat size)
{
    auto fontName = name.createCFString();
    CFTypeRef keys[] = { kCTFontNameAttribute, kCTFontEnabledAttribute };
    CFTypeRef values[] = { fontName.get(), kCFBooleanTrue };
    auto attributes = adoptCF(CFDictionaryCreate(kCFAllocatorDefault, keys, values, std::size(keys), &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks));
    auto descriptor = adoptCF(CTFontDescriptorCreateWithAttributes(attributes.get()));
    auto newFont = adoptCF(CTFontCreateWithFontDescriptor(descriptor.get(), size, nullptr));
}
#endif

static void registerFontIfNeeded(const String& family) WTF_REQUIRES_LOCK(userInstalledFontMapLock())
{
    if (auto fontURL = userInstalledFontMap().getOptional(family)) {
        RELEASE_LOG_FORWARDABLE(Fonts, FontCacheCoreTextRegisterFont, family.utf8(), fontURL->string().utf8());
        RetainPtr cfURL = fontURL->createCFURL();

        CFErrorRef error = nullptr;
        if (!CTFontManagerRegisterFontsForURL(cfURL.get(), kCTFontManagerScopeProcess, &error)) {
            RetainPtr descriptionCF = adoptCF(CFErrorCopyDescription(error));
            String error(descriptionCF.get());
            RELEASE_LOG_FORWARDABLE(Fonts, FontCacheCoreTextRegisterError, family.utf8(), error.utf8());
        }

        userInstalledFontMap().removeIf([&](auto& keyAndValue) {
            return keyAndValue.value == fontURL;
        });
    }
}

static void registerFontsInFamilyIfNeeded(const String& family)
{
    Locker locker(userInstalledFontMapLock());
    if (!userInstalledFontMap().isEmpty()) {
        if (equalLettersIgnoringASCIICase(family, "helvetica"_s)) {
            // Helvetica is a system font with several variants, so we choose not to register additional fonts in this family.
            // This is because it can affect font matching. See rdar://172261885.
            return;
        }

        auto fontFamily = family.convertToASCIILowercase();

        registerFontIfNeeded(fontFamily);
        auto fontNames = userInstalledFontFamilyMap().find(fontFamily);
        if (fontNames != userInstalledFontFamilyMap().end()) {
            for (auto& fontName : fontNames->value)
                registerFontIfNeeded(fontName);
            userInstalledFontFamilyMap().remove(fontNames);
        }
    }
}

#if PLATFORM(DRIFTSTACK)
// V-237 / V-237.2 / V-253 — Mac-only font denylist (multi-archetype as
// of V-253). Per founder direction "100% match across everything …
// full iOS iphone bit identical". Returning nullptr for denied family
// names causes FontCascade to fall through to the next family or the
// monospace baseline → content-derived measureText probes report
// these fonts as "not installed", matching iPhone.
//
// V-253: per-archetype denylist moved to DriftstackFontsDenylist.h.
// iPhone iOS 18.6 has 22 Mac-only false-positives (V-237.2 derived);
// iPhone iOS 26.4 archetype empty pending founder iOS 26.4 fonts
// capture via V-242 URL.
#include "../DriftstackFontsDenylist.h"
#endif

std::unique_ptr<FontPlatformData> FontCache::createFontPlatformData(const FontDescription& fontDescription, const AtomString& family, const FontCreationContext& fontCreationContext, OptionSet<FontLookupOptions> options)
{
#if PLATFORM(DRIFTSTACK)
    // V-237 / V-253: Mac-only font denylist (multi-archetype lookup).
    // Reject family-name resolution for fonts in the current-archetype
    // denylist. Returning nullptr causes FontCascade to fall through to
    // the next family / monospace baseline → content-derived font
    // detection sees these as "not installed", matching real iPhone.
    if (driftstackFamilyDenylisted(family))
        return nullptr;
#endif
    registerFontsInFamilyIfNeeded(family);

    auto size = fontDescription.adjustedSizeForFontFace(fontCreationContext.sizeAdjust());
    auto& fontDatabase = database(fontDescription.shouldAllowUserInstalledFonts());
    auto font = fontWithFamily(fontDatabase, family, fontDescription, fontCreationContext, size, options);

#if PLATFORM(MAC)
    if (!font) {
        if (!shouldAutoActivateFontIfNeeded(family))
            return nullptr;

        // Auto activate the font before looking for it a second time.
        // Ignore the result because we want to use our own algorithm to actually find the font.
        autoActivateFont(family.string(), size);

        font = fontWithFamily(fontDatabase, family, fontDescription, fontCreationContext, size, options);
    }
#endif

    if (!font)
        return nullptr;

    if (fontDescription.shouldAllowUserInstalledFonts() == AllowUserInstalledFonts::No)
        m_seenFamiliesForPrewarming.add(FontCascadeDescription::foldedFamilyName(family));

#if PLATFORM(DRIFTSTACK)
    // V-405-B Phase 1 Stage B audit (founder Tier-2 ack 2026-05-07): when
    // DRIFTSTACK_FONT_AUDIT=1, log every (requested-family → resolved-CTFont)
    // mapping. Audit goal: verify V-405 fuzzer text probes hit Stage B iOS
    // fonts (e.g., /System/Library/PrivateFrameworks/.../Helvetica.ttc) vs
    // Mac default fonts (/System/Library/Fonts/...). Mismatch = font-loading
    // divergence at FontCache level → Stage B not winning against Mac defaults.
    static bool fontAuditEnabled = []() {
        return getenv("DRIFTSTACK_FONT_AUDIT") != nullptr;
    }();
    if (fontAuditEnabled) {
        auto url = adoptCF(static_cast<CFURLRef>(CTFontCopyAttribute(font.get(), kCTFontURLAttribute)));
        auto postScriptName = adoptCF(CTFontCopyPostScriptName(font.get()));
        auto urlString = url ? adoptCF(CFURLCopyPath(url.get())) : RetainPtr<CFStringRef>();
        WTFLogAlways("DRIFTSTACK_FONT_AUDIT requested='%s' size=%.1f weight=%.0f resolved_ps='%s' resolved_url='%s'",
            family.string().utf8().data(),
            static_cast<float>(size),
            static_cast<float>(fontDescription.weight()),
            postScriptName ? String(postScriptName.get()).utf8().data() : "null",
            urlString ? String(urlString.get()).utf8().data() : "null");
    }
#endif

    auto [syntheticBold, syntheticOblique] = computeNecessarySynthesis(font.get(), fontDescription, options).boldObliquePair();

    FontPlatformData platformData(font.get(), size, syntheticBold, syntheticOblique, fontDescription.orientation(), fontDescription.widthVariant(), fontDescription.textRenderingMode());

    platformData.updateSizeWithFontSizeAdjust(fontDescription.fontSizeAdjust(), fontDescription.computedSize());
    return makeUnique<FontPlatformData>(platformData);
}

void FontCache::platformPurgeInactiveFontData()
{
    Vector<CTFontRef> toRemove;
    for (auto& font : m_fallbackFonts) {
        if (CFGetRetainCount(font.get()) == 1)
            toRemove.append(font.get());
    }
    for (auto& font : toRemove)
        m_fallbackFonts.remove(font);

    m_databaseAllowingUserInstalledFonts.clear();
    m_databaseDisallowingUserInstalledFonts.clear();
}

#if PLATFORM(IOS_FAMILY) || PLATFORM(DRIFTSTACK)
// V-684: needed for DRIFTSTACK Arabic font replacement in lookupFallbackFont.
static inline bool isArabicCharacter(char16_t character)
{
    return character >= 0x0600 && character <= 0x06FF;
}
#endif

#if PLATFORM(DRIFTSTACK)
// V-709 (2026-05-11): CJK Han classification for lookupFallbackFont
// substitution. Mac CT picks Songti SC for many CJK codepoints where iOS
// picks PingFang SC. V-708 captured 740 Songti-SC calls across V-405 text
// fuzzer — substituting at this primary-cascade fallback layer is the
// V-484 candidate (a) closure path for V-405 atlas-OFF text positional
// drift.
static inline bool isCJKHanCharacter(char16_t character)
{
    return (character >= 0x3400 && character <= 0x4DBF)   // CJK Ext A
        || (character >= 0x4E00 && character <= 0x9FFF)   // CJK Unified
        || (character >= 0xF900 && character <= 0xFAFF);  // CJK Compat
}

// V-709: Devanagari classification. Mac CT picks ITF Devanagari for some
// codepoints where iOS picks Kohinoor / .SF Devanagari (172 calls in V-708).
static inline bool isDevanagariCharacter(char16_t character)
{
    return (character >= 0x0900 && character <= 0x097F)
        || (character >= 0xA8E0 && character <= 0xA8FF);
}
#endif

#if ASSERT_ENABLED
static bool isUserInstalledFont(CTFontRef font)
{
    return adoptCF(CTFontCopyAttribute(font, kCTFontUserInstalledAttribute)) == kCFBooleanTrue;
}
#endif

static RetainPtr<CTFontRef> lookupFallbackFont(CTFontRef font, FontSelectionValue fontWeight, const AtomString& locale, AllowUserInstalledFonts allowUserInstalledFonts, StringView characterCluster)
{
    ASSERT(characterCluster.length() > 0);

    RetainPtr<CFStringRef> localeString;
    if (!locale.isNull())
        localeString = locale.string().createCFString();

    CFIndex coveredLength = 0;
    auto upconvertedCharacters = characterCluster.upconvertedCharacters();
    auto fallbackOption = allowUserInstalledFonts == AllowUserInstalledFonts::No ? kCTFontFallbackOptionSystem : kCTFontFallbackOptionDefault;
    auto result = adoptCF(CTFontCreateForCharactersWithLanguageAndOption(font, reinterpret_cast<const UTF16Char*>(upconvertedCharacters.get()), characterCluster.length(), localeString.get(), fallbackOption, &coveredLength));
    ASSERT(!isUserInstalledFont(result.get()) || allowUserInstalledFonts == AllowUserInstalledFonts::Yes);

#if PLATFORM(IOS_FAMILY) || PLATFORM(DRIFTSTACK)
    // V-684 (2026-05-11): extend to DRIFTSTACK. This is the CT-level
    // character-cluster fallback used by canvas fillText shaping (via
    // CTLineCreateWithAttributedString → CTFontCreateForCharactersWithLanguageAndOption).
    // iOS replaces Times New Roman / Arial → GeezaPro for Arabic clusters.
    // V-682 patched the WebKit GlyphPage path but canvas fillText bypasses
    // GlyphPage; THIS path is what canvas fillText actually exercises.
    //
    // FIXME: This is so unfortunate. The reason this is here is that certain fonts which are early in the system font cascade list
    // (used to?) perform poorly. In order to speed up the browser, we block those fonts, and use other faster fonts instead.
    // However, this performance analysis was done, like, 10 years ago, and the probability that these fonts are still too slow
    // seems quite low. We should re-analyze performance to see if we can delete this code.
    char16_t firstCharacter = characterCluster[0];
    if (isArabicCharacter(firstCharacter)) {
        auto familyName = adoptCF(static_cast<CFStringRef>(CTFontCopyAttribute(result.get(), kCTFontFamilyNameAttribute)));
        if (fontFamilyShouldNotBeUsedForArabic(familyName.get())) {
            CFStringRef newFamilyName = isFontWeightBold(fontWeight) ? CFSTR("GeezaPro-Bold") : CFSTR("GeezaPro");
            CFTypeRef keys[] = { kCTFontNameAttribute };
            CFTypeRef values[] = { newFamilyName };
            auto attributes = adoptCF(CFDictionaryCreate(kCFAllocatorDefault, keys, values, std::size(keys), &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks));
            auto modification = adoptCF(CTFontDescriptorCreateWithAttributes(attributes.get()));
            result = adoptCF(CTFontCreateCopyWithAttributes(result.get(), CTFontGetSize(result.get()), nullptr, modification.get()));
        }
    }
#else
    UNUSED_PARAM(fontWeight);
#endif

#if PLATFORM(DRIFTSTACK)
    // V-709/V-712 (2026-05-11): Mac CT primary-cascade falls back to Songti
    // SC for CJK Han codepoints (740 calls / 4695 in V-708) and ITF
    // Devanagari for Devanagari (172 calls). iOS uses .AppleSimplified
    // ChineseFont (= iOS PingFang.ttc, byte-identical per V-679) and
    // .AppleIndicFont / .SF Devanagari respectively.
    //
    // V-709 (env-gated DRIFTSTACK_V709=1) substituted Songti SC → "PingFang
    // SC" via kCTFontNameAttribute but Mac CT resolved that to user-facing
    // /System/Library/Fonts/PingFang.ttc which DIFFERS from iOS PingFang
    // at head/hhea level — substitution mechanism fired (Songti 740→85,
    // PingFang SC 124→779) but no V-405 pass-rate movement.
    //
    // V-712 (env-gated DRIFTSTACK_V712=1) UPGRADED targeting: use
    // CTFontDescriptorCreateWithAttributes + kCTFontFamilyNameAttribute=
    // ".AppleSimplifiedChineseFont" to access Mac SPI internal PingFangUI.
    // Python ctypes probe confirmed this path returns family=.AppleSimplified
    // ChineseFont (postscript .AppleSimplifiedChineseFont-UltraLight) —
    // the V-679-byte-identical-to-iOS-PingFang internal font. Substitution
    // via this path should achieve true byte-level alignment with iOS.
    {
        char16_t firstChar = characterCluster[0];
        static const bool s_v709Enabled = []() {
            const char* env = getenv("DRIFTSTACK_V709");
            return env && env[0] == '1';
        }();
        static const bool s_v712Enabled = []() {
            const char* env = getenv("DRIFTSTACK_V712");
            return env && env[0] == '1';
        }();
        // Substitution targets: V-712 uses Mac SPI families (kCTFontFamilyName);
        // V-709 (fallback if V-712 disabled) uses user-facing names (kCTFontName).
        CFStringRef substituteFamily = nullptr; // V-712 path
        CFStringRef substituteName = nullptr;   // V-709 path
        if (s_v712Enabled || s_v709Enabled) {
            if (isCJKHanCharacter(firstChar)) {
                auto familyName = adoptCF(static_cast<CFStringRef>(CTFontCopyAttribute(result.get(), kCTFontFamilyNameAttribute)));
                if (familyName && CFStringCompare(familyName.get(), CFSTR("Songti SC"), 0) == kCFCompareEqualTo) {
                    if (s_v712Enabled)
                        substituteFamily = CFSTR(".AppleSimplifiedChineseFont");
                    else
                        substituteName = CFSTR("PingFang SC");
                }
            } else if (isDevanagariCharacter(firstChar)) {
                auto familyName = adoptCF(static_cast<CFStringRef>(CTFontCopyAttribute(result.get(), kCTFontFamilyNameAttribute)));
                if (familyName && CFStringCompare(familyName.get(), CFSTR("ITF Devanagari"), 0) == kCFCompareEqualTo) {
                    if (s_v712Enabled)
                        substituteFamily = CFSTR(".AppleIndicFont");
                    else
                        substituteName = CFSTR("Kohinoor Devanagari");
                }
            }
        }
        if (substituteFamily) {
            // V-712 path: family-name attribute to access Mac SPI internal.
            CFTypeRef keys[] = { kCTFontFamilyNameAttribute };
            CFTypeRef values[] = { substituteFamily };
            auto attributes = adoptCF(CFDictionaryCreate(kCFAllocatorDefault, keys, values, std::size(keys), &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks));
            auto descriptor = adoptCF(CTFontDescriptorCreateWithAttributes(attributes.get()));
            auto substituted = adoptCF(CTFontCreateWithFontDescriptor(descriptor.get(), CTFontGetSize(result.get()), nullptr));
            if (substituted)
                result = WTF::move(substituted);
        } else if (substituteName) {
            // V-709 fallback path: name attribute (user-facing).
            CFTypeRef keys[] = { kCTFontNameAttribute };
            CFTypeRef values[] = { substituteName };
            auto attributes = adoptCF(CFDictionaryCreate(kCFAllocatorDefault, keys, values, std::size(keys), &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks));
            auto modification = adoptCF(CTFontDescriptorCreateWithAttributes(attributes.get()));
            auto substituted = adoptCF(CTFontCreateCopyWithAttributes(result.get(), CTFontGetSize(result.get()), nullptr, modification.get()));
            if (substituted)
                result = WTF::move(substituted);
        }
    }
#endif

    return result;
}

#if PLATFORM(DRIFTSTACK)
// Track 9 (V-161 closure): Mac's lookupFallbackFont returns a different physical
// font for Korean Hangul characters than iOS does. Mac falls back via its own
// catalog (often AppleGothic or system-specific Hangul font); iOS uses
// AppleSDGothicNeo for ALL serif/sans-serif/system contexts. The 2 surfaces
// in V-157 (serif|hangul_jamo, serif|korean_hangul) and additional Hangul
// probes downstream all close when the fallback resolution returns iOS's
// AppleSDGothicNeo binary directly.
//
// Hangul Unicode ranges (per Unicode 15.x):
//   U+1100-U+11FF  Hangul Jamo
//   U+3130-U+318F  Hangul Compatibility Jamo
//   U+A960-U+A97F  Hangul Jamo Extended-A
//   U+AC00-U+D7AF  Hangul Syllables (precomposed; covers '한', '안녕', etc.)
//   U+D7B0-U+D7FF  Hangul Jamo Extended-B
//
// Returns nullptr if the cluster is not Hangul OR if AppleSDGothicNeo isn't
// in the Stage B installed font map (silent — does NOT log MISS like the
// Stage B path does for missing CSS family lookups).
// Helper: look up a font by family-name candidates in the Stage B map.
// Silent on miss; returns the variant matching requested weight/italic at size.
static RetainPtr<CTFontRef> driftstackLookupIOSFontByCandidates(std::span<const ASCIILiteral> candidates, const FontDescription& description, float size)
{
    initializeDriftstackIOSFontMapIfNeeded();
    Locker locker(driftstackIOSFontMapLock);
    auto& map = driftstackIOSFontMap();
    for (auto candidate : candidates) {
        auto it = map.find(String(candidate));
        // V-485 diagnostic: log every candidate lookup result.
        {
            static unsigned probeCount = 0;
            if (++probeCount <= 12) {
                WTFLogAlways("[Driftstack-V485-LOOKUP] candidate='%s' result=%s",
                    candidate.characters(), it == map.end() ? "MISS" : "HIT");
            }
        }
        if (it == map.end())
            continue;
        const auto& variants = it->value;
        if (variants.isEmpty())
            continue;
        const float requestedWeight = (static_cast<float>(description.weight()) - 400.f) / 400.f;
        const bool requestedItalic = isItalic(description.fontStyleSlope());
        DriftstackIOSFontVariant chosen = variants[0];
        float bestScore = std::numeric_limits<float>::infinity();
        for (const auto& v : variants) {
            float italicMismatch = (v.italic != requestedItalic) ? 1.0f : 0.0f;
            float weightDelta = std::abs(v.weight - requestedWeight);
            float score = italicMismatch * 10.0f + weightDelta;
            if (score < bestScore) {
                bestScore = score;
                chosen = v;
            }
        }
        RetainPtr<CFArrayRef> descs = adoptCF(CTFontManagerCreateFontDescriptorsFromURL(chosen.url.get()));
        if (!descs || !CFArrayGetCount(descs.get()))
            continue;
        // Wave 29-218 fix: for .ttc files containing multiple families (e.g.
        // SFIndia.ttc holds 9 .SF <Script> families), CTFontManagerCreate
        // FontDescriptorsFromURL returns ALL descriptors. Previously we always
        // used descs[0] (alphabetically first = ".SF Bangla" for SFIndia.ttc)
        // regardless of which candidate matched, so a `.sf devanagari` candidate
        // would return .SF Bangla — the wrong font with no U+1CDA coverage.
        // Now we scan descs[] for the descriptor whose family name matches the
        // current candidate, falling back to descs[0] if no match.
        CFIndex descCount = CFArrayGetCount(descs.get());
        CTFontDescriptorRef fd = nullptr;
        String candidateLower = String(candidate);
        for (CFIndex j = 0; j < descCount; ++j) {
            CTFontDescriptorRef candDesc = (CTFontDescriptorRef)CFArrayGetValueAtIndex(descs.get(), j);
            RetainPtr<CFStringRef> descFamilyCF = adoptCF(static_cast<CFStringRef>(CTFontDescriptorCopyAttribute(candDesc, kCTFontFamilyNameAttribute)));
            if (!descFamilyCF) {
                // W2196 (macOS 26.4): the family attr is lazy/null on URL-created descriptors, so this
                // multi-family .ttc match would skip every descriptor and fall to descs[0] (the
                // alphabetically-first family, e.g. .SF Bangla for a .sf-devanagari request → wrong
                // glyphs). Realize the font to read its family for the match decision. fd below stays the
                // array descriptor (CTFontCreateWithFontDescriptor realizes it). Inert on 26.2.
                RetainPtr<CTFontRef> rf = adoptCF(CTFontCreateWithFontDescriptor(candDesc, 0.0, nullptr));
                if (rf)
                    descFamilyCF = adoptCF(CTFontCopyFamilyName(rf.get()));
            }
            if (!descFamilyCF)
                continue;
            String descFamily = String(descFamilyCF.get()).convertToASCIILowercase();
            if (descFamily == candidateLower) {
                fd = candDesc;
                break;
            }
        }
        if (!fd)
            fd = (CTFontDescriptorRef)CFArrayGetValueAtIndex(descs.get(), 0);
        return adoptCF(CTFontCreateWithFontDescriptor(fd, size, nullptr));
    }
    return nullptr;
}

static RetainPtr<CTFontRef> driftstackIOSFallbackFontForHangulCluster(StringView cluster, const FontDescription& description, float size)
{
    if (cluster.isEmpty())
        return nullptr;
    char32_t cp = cluster[0];
    bool isHangul = (cp >= 0x1100 && cp <= 0x11FF)
                 || (cp >= 0x3130 && cp <= 0x318F)
                 || (cp >= 0xA960 && cp <= 0xA97F)
                 || (cp >= 0xAC00 && cp <= 0xD7AF)
                 || (cp >= 0xD7B0 && cp <= 0xD7FF);
    if (!isHangul)
        return nullptr;
    static const std::array<ASCIILiteral, 2> candidates {
        "apple sd gothic neo"_s,
        "applesdgothicneo"_s,
    };
    return driftstackLookupIOSFontByCandidates(candidates, description, size);
}

// Track 10 Hebrew (V-174 founder Tier-1 ack 2026-05-04 — re-enabled with
// per-context discrimination). V-165 wash was caused by SFHebrew override
// firing for BOTH serif AND sans-serif contexts; Mac native serif Hebrew
// already matches iPhone serif Hebrew, so forcing SFHebrew for serif breaks
// what was working. V-174 finding: originalFontData.platformData().familyName()
// at the systemFallbackForCharacterCluster call site is sufficient to
// discriminate sans-serif from serif (originating font name typically starts
// with "Helvetica" / "Arial" / "SF Pro" for sans-serif, "Times" for serif).
// This function fires SFHebrew override ONLY when the originating font name
// matches a sans-serif synonym list. Env-var-gated via
// DRIFTSTACK_TRACK10_HEBREW=1 (with __XPC_ mirror). Default-OFF until
// physical iPhone 16 Pro / iOS 26.4.1 cumulative-rig recapture validates
// post-recapture sans-serif|hebrew_* surfaces close.
static bool driftstackTrack10HebrewEnabled()
{
    static bool s_enabled = []() {
        const char* env = getenv("DRIFTSTACK_TRACK10_HEBREW");
        return env && env[0] == '1';
    }();
    return s_enabled;
}

static RetainPtr<CTFontRef> driftstackIOSFallbackFontForHebrewCluster(
    StringView cluster, const FontDescription& description,
    const String& originatingFamily, float size)
{
    if (!driftstackTrack10HebrewEnabled())
        return nullptr;
    if (cluster.isEmpty())
        return nullptr;
    char32_t cp = cluster[0];
    // Hebrew Unicode block + presentation forms.
    bool isHebrew = (cp >= 0x0590 && cp <= 0x05FF)
                 || (cp >= 0xFB1D && cp <= 0xFB4F);
    if (!isHebrew)
        return nullptr;
    // Per-context discrimination: only fire override for sans-serif requests.
    // Mac native serif Hebrew matches iPhone serif Hebrew per V-165 empirical;
    // overriding for serif would break what's already working.
    String lower = originatingFamily.convertToASCIILowercase();
    bool isSansSerifContext =
           lower.startsWith("helvetica"_s)
        || lower.startsWith("arial"_s)
        || lower.startsWith("sf pro"_s)
        || lower.startsWith("sfpro"_s)
        || lower.startsWith(".sf "_s)
        || lower.startsWith(".applesystemui"_s)
        || lower.contains("sans"_s);
    if (!isSansSerifContext)
        return nullptr;
    // V-490 ROLLBACK (V-491 empirical): adding `.sf hebrew` dot-prefix
    // candidate to the lookup made Hebrew dispatch fire with SFHebrew.ttf,
    // but its metrics regress sans-serif|hebrew ABBA (10.03 → 11.06; ref=10.015).
    // Mac's default fallback for sans-serif Hebrew (which fires when Hebrew
    // dispatch returns nullptr) is empirically closer to iPhone metrics than
    // SFHebrew. Restored original 3-candidate list; sans-serif Hebrew
    // remains 6/6 divergent but width/ABBA/ABBD deltas all SMALLER under
    // Mac default than under .sf hebrew dispatch. Future investigation:
    // identify which iOS font Safari ACTUALLY uses for sans-serif|Hebrew
    // (possibly SF Pro Text's Hebrew character set, not SFHebrew.ttf).
    static const std::array<ASCIILiteral, 3> candidates {
        "sfhebrew"_s, "sf hebrew"_s, "applegothic"_s,
    };
    return driftstackLookupIOSFontByCandidates(candidates, description, size);
}

// Track 7 candidate (d) (V-164 / V-166 — env-var-gated, default-OFF until
// physical iPhone 16 Pro / iOS 26.4.1 binary acquisition lands). When
// DRIFTSTACK_TRACK7_CANDIDATE_D=1 is set in the WebContent env, applies the
// Track 9 hook pattern to CJK + emoji codepoint ranges. Closes the 3
// unicodeRendering.value[*].h surfaces (cjk h=17.5/18, emoji + family h=18.5/18)
// once Stage B install includes:
//   /Core/PingFangSC.ttc     (Chinese fallback for serif/sans-serif/system)
//   /CoreAddition/AppleColorEmoji.ttc  (canonical multi-strike, NOT the
//     -160px-only file that's currently installed)
//
// Without those binaries in the Stage B map, the candidate-list lookup misses
// silently → fall through → behavior unchanged → no regression.
static bool driftstackTrack7CandidateDEnabled()
{
    static bool s_enabled = []() {
        const char* env = getenv("DRIFTSTACK_TRACK7_CANDIDATE_D");
        return env && env[0] == '1';
    }();
    return s_enabled;
}

// CJK Unified ranges — comprehensive coverage for Chinese/Japanese/Korean
// kanji/hanzi shared codepoint space:
//   U+3400-U+4DBF  CJK Unified Ideographs Extension A
//   U+4E00-U+9FFF  CJK Unified Ideographs (the main Han block)
//   U+F900-U+FAFF  CJK Compatibility Ideographs
//   U+20000-U+2A6DF  Extension B
//   U+2A700-U+2B73F  Extension C
//   U+2B740-U+2B81F  Extension D
//   U+2B820-U+2CEAF  Extension E
//   U+2CEB0-U+2EBEF  Extension F
//   U+30000-U+3134F  Extension G
//   U+31350-U+323AF  Extension H
//
// Note: This OVERRIDES Mac's CJK fallback for ALL CJK Unified codepoints.
// On iPhone, PingFang SC is the universal fallback regardless of CSS
// serif/sans-serif/system request (Apple does not ship a separate Chinese
// serif font on iOS). For Japanese kanji that would correctly fall back to
// Hiragino on iPhone, this hook still returns PingFang SC — but if the
// cluster also contains Hiragana/Katakana (Japanese-only ranges that this
// hook doesn't cover), Mac WebKit's per-character fallback splits the
// rendering across PingFang SC for kanji + Mac's Hiragino fallback for
// hiragana, which may diverge from iPhone. POST-Track-7 validation needs
// to confirm whether iPhone actually uses PingFang SC for mixed-Japanese
// content or if it picks Hiragino. If Hiragino: this hook needs to additionally
// check if the cluster contains Hiragana/Katakana → defer to Hiragino instead.
static RetainPtr<CTFontRef> driftstackIOSFallbackFontForCJKCluster(StringView cluster, const FontDescription& description, float size)
{
    // V-485 diagnostic probe — capture EVERY entry, especially CJK Han clusters
    // that V-482's probeCount<=3 limit may have hidden behind emoji surrogates.
    {
        static unsigned probeCount = 0;
        char32_t cp = cluster.isEmpty() ? 0u : (unsigned)cluster[0];
        // Always log if CJK Han range; otherwise sample first 5.
        bool isCJKHan = (cp >= 0x4E00 && cp <= 0x9FFF);
        if (isCJKHan || ++probeCount <= 5) {
            const char* env = getenv("DRIFTSTACK_TRACK7_CANDIDATE_D");
            WTFLogAlways("[Driftstack-V485-CJK-PROBE] entered cluster=U+%04X clusterLen=%u env='%s'%s",
                (unsigned)cp, (unsigned)cluster.length(), env ? env : "(null)", isCJKHan ? " HAN" : "");
        }
    }
    if (!driftstackTrack7CandidateDEnabled())
        return nullptr;
    if (cluster.isEmpty())
        return nullptr;
    char32_t cp = cluster[0];
    bool isCJK = (cp >= 0x3400 && cp <= 0x4DBF)
              || (cp >= 0x4E00 && cp <= 0x9FFF)
              || (cp >= 0xF900 && cp <= 0xFAFF)
              || (cp >= 0x20000 && cp <= 0x2A6DF)
              || (cp >= 0x2A700 && cp <= 0x2B73F)
              || (cp >= 0x2B740 && cp <= 0x2B81F)
              || (cp >= 0x2B820 && cp <= 0x2CEAF)
              || (cp >= 0x2CEB0 && cp <= 0x2EBEF)
              || (cp >= 0x30000 && cp <= 0x3134F)
              || (cp >= 0x31350 && cp <= 0x323AF);
    if (!isCJK)
        return nullptr;
    // V-486 (V-485 empirical finding): iOS PingFang.ttc registers under
    // dot-prefixed iOS-internal family names (kCTFontFamilyNameAttribute returns
    // ".PingFang SC", ".PingFang HK", etc. — confirmed via mdls
    // com_apple_ats_name_family attr on the .ttc file). Mac WebKit's public-name
    // requests for "PingFang SC" miss because the dot-prefix variant is what's
    // actually registered. List the dot-prefixed names first; non-dot variants
    // retained as defensive fallback in case future iOS versions normalize.
    static const std::array<ASCIILiteral, 6> candidates {
        ".pingfang sc"_s,
        ".pingfang"_s,
        "pingfang sc"_s,
        "pingfangsc"_s,
        "ping fang sc"_s,
        "pingfang"_s,
    };
    if (auto pingFang = driftstackLookupIOSFontByCandidates(candidates, description, size))
        return pingFang;

    // V-602 option 1 (2026-05-11, env-gated DRIFTSTACK_V602_SUBSTITUTE=1):
    // iOS PingFang.ttc cidg/hvgl outline tables prevent Mac CTFontManager from
    // parsing the binary (V-487 PARSEFAIL — only iOS Core font with this issue).
    // When the PingFang lookup chain fails, fall back to Mac's Hiragino Kaku
    // Gothic (which parses correctly and has ~6,746 CJK Unified Ideograph
    // coverage in font[0]). Tag the returned CTFont with a custom descriptor
    // attribute so Font::platformInit() can apply PingFang's hhea/OS-2 metric
    // overlay (data in DriftstackPingFangMetrics.h) at the metric extraction
    // layer. Net result: Mac fork CJK text canvas renders Hiragino glyphs
    // with PingFang's vertical metrics (line-spacing parity), closing the
    // Layer 1 + Layer 3 (metric) divergence. Layer 4 (glyph shape) parity is
    // a residual V-653 scope (Hiragino vs PingFang glyph shapes differ).
    //
    // Env-gated for safe rollout — default OFF until verified via V-652
    // Mac re-capture showing CJK canvasSha unique count > 1.
    static bool s_v602Enabled = []() {
        const char* env = getenv("DRIFTSTACK_V602_SUBSTITUTE");
        return env && env[0] == '1';
    }();
    if (s_v602Enabled) {
        // Mac Hiragino lookup. Identification by family name detection at
        // Font::platformInit() applies PingFang metric overlay (custom CTFont
        // descriptor attributes don't survive CTFontCreateWithFontDescriptor
        // round-trip — empirical 2026-05-11; family-name pattern is more
        // robust).
        static const std::array<ASCIILiteral, 4> hiraginoCandidates {
            "hiragino kaku gothic"_s,
            "hiraginokakugothic"_s,
            "hiragino sans"_s,
            "hiraginosans"_s,
        };
        if (auto hiragino = driftstackLookupIOSFontByCandidates(hiraginoCandidates, description, size)) {
            static unsigned hitCount = 0;
            if (++hitCount <= 5)
                WTFLogAlways("[Driftstack-V602] PingFang→Hiragino substitute fired (%u so far); cp=U+%04X size=%.1f",
                    hitCount, static_cast<unsigned>(cp), size);
            return hiragino;
        }
    }
    return nullptr;
}

// Emoji presentation ranges — covers the supplementary-plane emoji blocks +
// the BMP emoji-presentation-defaulted ranges. Apple's font cascade for
// emoji on iPhone uses the canonical multi-strike AppleColorEmoji.ttc
// regardless of context.
//   U+2600-U+26FF    Miscellaneous Symbols (some emoji-presentation defaulted)
//   U+2700-U+27BF    Dingbats (some emoji)
//   U+1F000-U+1F02F  Mahjong Tiles
//   U+1F0A0-U+1F0FF  Playing Cards
//   U+1F100-U+1F1FF  Enclosed Alphanumeric Supplement (regional indicators)
//   U+1F200-U+1F2FF  Enclosed Ideographic Supplement
//   U+1F300-U+1F5FF  Misc Symbols and Pictographs
//   U+1F600-U+1F64F  Emoticons
//   U+1F680-U+1F6FF  Transport
//   U+1F700-U+1F77F  Alchemical
//   U+1F780-U+1F7FF  Geometric Shapes Extended
//   U+1F800-U+1F8FF  Supplemental Arrows-C
//   U+1F900-U+1F9FF  Supplemental Symbols and Pictographs
//   U+1FA00-U+1FA6F  Chess Symbols
//   U+1FA70-U+1FAFF  Symbols and Pictographs Extended-A
//
// Note: This is BROADER than just "default emoji presentation" — characters
// like U+2622 (radioactive sign) get text presentation by default but
// U+2622 U+FE0F (with VS-16) gets emoji presentation. The cluster's first
// codepoint check here doesn't distinguish; the override fires for any
// character in the broad range. POST-Track-7 validation should confirm
// behavior matches iPhone for borderline cases (BMP symbol-vs-emoji
// presentation, regional indicators rendering as flag emoji vs text, etc.).
static RetainPtr<CTFontRef> driftstackIOSFallbackFontForEmojiCluster(StringView cluster, const FontDescription& description, float size)
{
    if (!driftstackTrack7CandidateDEnabled())
        return nullptr;
    if (cluster.isEmpty())
        return nullptr;
    char32_t cp = cluster[0];
    bool isEmoji = (cp >= 0x2600 && cp <= 0x27BF)
                || (cp >= 0x1F000 && cp <= 0x1F02F)
                || (cp >= 0x1F0A0 && cp <= 0x1F0FF)
                || (cp >= 0x1F100 && cp <= 0x1F1FF)
                || (cp >= 0x1F200 && cp <= 0x1F2FF)
                || (cp >= 0x1F300 && cp <= 0x1F5FF)
                || (cp >= 0x1F600 && cp <= 0x1F64F)
                || (cp >= 0x1F680 && cp <= 0x1F6FF)
                || (cp >= 0x1F700 && cp <= 0x1F77F)
                || (cp >= 0x1F780 && cp <= 0x1F7FF)
                || (cp >= 0x1F800 && cp <= 0x1F8FF)
                || (cp >= 0x1F900 && cp <= 0x1F9FF)
                || (cp >= 0x1FA00 && cp <= 0x1FA6F)
                || (cp >= 0x1FA70 && cp <= 0x1FAFF);
    if (!isEmoji)
        return nullptr;
    static const std::array<ASCIILiteral, 3> candidates {
        "apple color emoji"_s,
        "applecoloremoji"_s,
        "applecoloremoji-160px"_s,
    };
    return driftstackLookupIOSFontByCandidates(candidates, description, size);
}

// Track 10 (V-165 closure): Devanagari fallback. Mac's lookupFallbackFont
// returns macOS's native Devanagari font for U+0900-U+097F cluster; iOS uses
// Kohinoor Devanagari (in Stage B as Kohinoor.ttc) or DevanagariSangamMN.ttc.
// The 3 surfaces in V-159 (serif|devanagari) close when fallback returns
// iOS's Kohinoor binary. Devanagari Unicode range:
//   U+0900-U+097F  Devanagari
//   U+A8E0-U+A8FF  Devanagari Extended
static RetainPtr<CTFontRef> driftstackIOSFallbackFontForDevanagariCluster(StringView cluster, const FontDescription& description, float size)
{
    if (cluster.isEmpty())
        return nullptr;
    char32_t cp = cluster[0];
    bool isDevanagari = (cp >= 0x0900 && cp <= 0x097F)
                     || (cp >= 0xA8E0 && cp <= 0xA8FF);
    if (!isDevanagari)
        return nullptr;
    // Kohinoor Devanagari is iOS's primary modern Devanagari font (Stage B
    // file: LanguageSupport/Kohinoor.ttc). Try it first; fall back to legacy
    // Devanagari Sangam MN.
    static const std::array<ASCIILiteral, 3> candidates {
        "kohinoor devanagari"_s,
        "kohinoordevanagari"_s,
        "devanagari sangam mn"_s,
    };
    return driftstackLookupIOSFontByCandidates(candidates, description, size);
}

// V-433.Z wave 29-205: universal-symbol-cluster fallback override.
// Empirical Phase 2 unicode-glyphs test showed 10 codepoints diverge
// fork-vs-iPhone for ~ALL 713 fonts:
//
//   U+1CDA Vedic Sign Three Dots Above
//   U+17DD Khmer Sign Atthacan
//   U+302E Hangul Single Dot Tone Mark
//   U+2C7B Latin Letter Small Capital Turned E
//   U+10A0 Georgian Capital Letter An
//   U+A73D Latin Small Letter Av With Horizontal Bar
//   U+FFFD Replacement Character
//   U+21E4 Leftwards Arrow To Bar
//   U+20E3 Combining Enclosing Keycap
//   U+20B9 Indian Rupee Sign
//
// Root cause: Mac's CT fallback chain picks a DIFFERENT font than iOS's
// CT for these codepoints in Latin-script font contexts. iPhone routes
// to SF Pro (SFUI.ttf contains native glyphs for all these per `strings`
// inspection). Mac picks Apple Symbols or other, with different glyph
// widths.
//
// Fix: explicit override — for these specific codepoints, return iOS
// SF Pro font (.SF UI family from driftstackIOSFontMap). Universal —
// closes ~7000 of 7347 (95%) of Phase 2 diff measurements without
// per-page tuning.
static RetainPtr<CTFontRef> driftstackIOSFallbackFontForUniversalSymbolCluster(StringView cluster, const FontDescription& description, float size, bool baseFontIsMonospace = false, bool baseIsCursive = false, bool baseIsFantasy = false, bool baseIsSansSerif = false, double baseWeight = 0, bool baseIsSerif = false, StringView baseFamily = { })
{
    constexpr double kDriftstackHeavyBaseWeight = 0.35; // W2608: ≥ this -> weight-matched bold Latin/Indic fallback
    if (cluster.isEmpty())
        return nullptr;
    char32_t cp = cluster[0];
    // W2876b (2026-06-24): supplementary-plane cps (e.g. Enclosed Alphanumeric Supplement U+1F1xx emoji) arrive as
    // a UTF-16 surrogate PAIR — cluster[0] is the LEAD surrogate (0xD83C..), NOT the codepoint, so a `case 0x1F17F`
    // never matched (cp was 0xD83C). Decode the pair so the switch sees the real cp. Every prior case is BMP, so
    // this is the first supplementary case; BMP cps (lead not in D800..DBFF) are unaffected.
    if (cp >= 0xD800 && cp <= 0xDBFF && cluster.length() >= 2) {
        char32_t lo = cluster[1];
        if (lo >= 0xDC00 && lo <= 0xDFFF)
            cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
    }
    // P-#48 wave 29-314 diag trace: log entry + result for our 10 target cps.
    // Limited to first 30 fires per process to avoid log flood.
    static unsigned p48EntryCount = 0;
    bool p48ShouldLog = (cp == 0x1CDA || cp == 0x17DD || cp == 0x302E
        || cp == 0x2C7B || cp == 0x10A0 || cp == 0xA73D || cp == 0xFFFD
        || cp == 0x21E4 || cp == 0x20E3 || cp == 0x20B9) && (++p48EntryCount <= 30);
    if (p48ShouldLog)
        WTFLogAlways("[Driftstack-P48-Entry] cp=U+%04X size=%g (entry #%u)", (unsigned)cp, size, p48EntryCount);
    // V-433.Z wave 29-206: per-codepoint candidate routing derived from
    // iPhone 17 / iOS 18.7 / Safari 26.4 Phase 2 reference width modes.
    // Mac's `.SF UI` alone has incomplete coverage; each script's iOS
    // binary holds the actual glyph data.
    // V-433.Z wave 29-207: canonical iOS dot-prefixed family names verified
    // via `mdls kMDItemFonts` on iOS font binaries in DRIFTSTACK_FONTS_DIR.
    switch (cp) {
    case 0x10A0: { // Georgian Capital An — iPhone width 61 (UNIFORM 713 fonts)
        // Wave 29-219 fontTools cmap: U+10A0 in `.PhoneFallback` (Fallback.ttf)
        // + .LastResort. NOT in .SF Georgian (despite name suggesting Georgian
        // script coverage). .PhoneFallback is iOS internal fallback font.
        static const std::array<ASCIILiteral, 3> candidates {
            ".phonefallback"_s, ".sf georgian"_s, "geeza pro"_s,
        };
        return driftstackLookupIOSFontByCandidates(candidates, description, size);
    }
    case 0x1CDA: { // Vedic Sign Three Dots Above — iPhone width 27 (711/713)
        // Wave 29-317 empirical: prior wave 29-219 finding (NotoSansKannada has
        // U+1CDA cmap entry) was correct but INCOMPLETE — the glyph exists with
        // CTAdvance=0! Empirical from V-433Z-U1CDA-Diag log:
        //   "hook returned font family='Noto Sans Kannada' size=72 glyph=460 CTAdvance=0"
        // iPhone width=27 implies iPhone uses .PhoneFallback (per U+10A0 comment
        // wave 29-219). Reorder candidates to put .phonefallback FIRST.
        static const std::array<ASCIILiteral, 4> candidates {
            ".phonefallback"_s, "noto sans kannada"_s, ".sf devanagari"_s, "apple symbols"_s,
        };
        RetainPtr<CTFontRef> result = driftstackLookupIOSFontByCandidates(candidates, description, size);
        // Wave 29-218 diagnostic: log what font was actually returned for
        // U+1CDA to identify why DOM width still reports Arial's notdef=54
        // instead of the iPhone reference 27. Logs first 4 firings.
        if (result) {
            static unsigned u1cdaLogCount = 0;
            if (u1cdaLogCount++ < 4) {
                RetainPtr<CFStringRef> resultFamily = adoptCF(CTFontCopyFamilyName(result.get()));
                CGFloat resultAdv = 0;
                CGGlyph g[1] = { 0 };
                UniChar ch[1] = { 0x1CDA };
                if (CTFontGetGlyphsForCharacters(result.get(), ch, g, 1) && g[0]) {
                    CGSize advs[1] = { CGSizeZero };
                    CTFontGetAdvancesForGlyphs(result.get(), kCTFontOrientationHorizontal, g, advs, 1);
                    resultAdv = advs[0].width;
                }
                WTFLogAlways("[Driftstack-V433Z-U1CDA-Diag] hook returned font family='%s' size=%g glyph=%u CTAdvance=%g",
                    resultFamily ? String(resultFamily.get()).utf8().data() : "(null)",
                    size, (unsigned)g[0], resultAdv);
            }
        }
        return result;
    }
    case 0x20B9: { // Indian Rupee Sign
        // W2583 (Workflow wcc98yhwt, verified): the prior "carlito"-first pick gave the right
        // ADVANCE (DOM offsetWidth 9 @16px) but the WRONG line-box HEIGHT in the cursive generic
        // (fork 21 vs iOS 22). iOS resolves U+20B9 to Helvetica, whose ceil-ascent-16 lifts the
        // Snell-Roundhand cursive line box to 22 (carlito ascent 12 left it at 21). Verified vs the
        // iOS-26.5 sim: an explicit "helvetica" span reproduces the iOS target [9,21][9,20][9,21]
        // [9,20][9,22][9,26] EXACTLY across all 6 browserleaks generics (incl width 9). Reorder
        // "helvetica" first (carlito/chalkboard kept as fallbacks) — closes the cursive cell with no
        // regression to the already-matching default/sans/serif/mono cells. Canvas-SAFE (U+20B9 canvas
        // is atlas/override-served; this systemFallback pick affects only the DOM/FontCascade surface).
        // W2608: iOS weight-matches ₹ to the base font's weight — a HEAVY base (blfonts uniqueMetrics: DB LCD/DIN/
        // Bradley Hand/Hiragino-Kaku) resolves ₹ to Helvetica BOLD (70.81 @128px -> 71) not Helvetica (66.5 -> 67).
        // Generics + light bases (weight < 0.35) keep Helvetica (the glyphHash/symbol cells are weight 0 -> unchanged).
        if (baseWeight >= kDriftstackHeavyBaseWeight) {
            // driftstackLookupIOSFontByCandidates can't select a bold variant (it weight-normalizes to the CSS 400
            // base — W2598/W2608), so create Helvetica Bold DIRECTLY by its name. (ctadv: Helvetica-Bold ₹=71.)
            if (RetainPtr<CTFontRef> helveticaBold = adoptCF(CTFontCreateWithName(CFSTR("Helvetica-Bold"), size, nullptr)))
                return helveticaBold;
        }
        // W2829 (#96, cracked via the captures/v3/ct-cascade-probe.m iOS-26.5-sim cascade): the "AppleGothic" and
        // "Savoye LET" primaries route ₹ to KohinoorDevanagari-LIGHT on iOS (ctadv 59.008@128 = 46.10@100, byte-exact
        // vs the sim), NOT Helvetica (66.5 → fork served +8/+7 too WIDE — blfgcps AppleGothic Δ+8 / Savoye Δ+7). These
        // two primaries' iOS cascade lists prefer the narrow Indic ₹; the macOS-host natural cascade does not. Per-
        // primary render-fix (correct FONT). Other primaries keep Helvetica (already matched). glyphHash-SAFE (named
        // fonts, not one of the 6 generics). Light variant by exact PS name (driftstackLookupIOSFontByCandidates
        // weight-normalizes to CSS 400 so it can't select the Light cut).
        if (baseWeight < kDriftstackHeavyBaseWeight
            && (baseFamily.startsWith("AppleGothic"_s) || baseFamily.startsWith("Savoye"_s))) {
            if (RetainPtr<CTFontRef> kohLight = adoptCF(CTFontCreateWithName(CFSTR("KohinoorDevanagari-Light"), size, nullptr)))
                return kohLight;
        }
        static const std::array<ASCIILiteral, 5> candidates {
            "helvetica"_s, "carlito"_s, "chalkboard se"_s, ".sf ui"_s, "apple symbols"_s,
        };
        return driftstackLookupIOSFontByCandidates(candidates, description, size);
    }
    case 0x097F: { // ॿ Devanagari Letter Bba — W2608: iOS weight-matches the ॿ fallback. HEAVY base -> Kohinoor
        // Devanagari SEMIBOLD (74.50 @128px -> 75) via a semibold description copy; normal/light base -> nullptr
        // (the natural cascade gives Kohinoor Devanagari -> 73, which the generics already match).
        if (baseWeight >= kDriftstackHeavyBaseWeight) {
            if (RetainPtr<CTFontRef> kohinoorSemibold = adoptCF(CTFontCreateWithName(CFSTR("KohinoorDevanagari-Semibold"), size, nullptr)))
                return kohinoorSemibold;
        }
        // W2829 (#96, cracked via captures/v3/ct-cascade-probe.m + the in-fork [DS-097F-NAT] diagnostic): the
        // "AppleGothic" primary's NATURAL macOS cascade already resolves ॿ to Kohinoor-Devanagari-LIGHT (ctadv
        // 71.808@128 = 56.10@100, byte-exact vs the iOS-26.5 sim), but the Track10 Devanagari dispatcher below
        // (driftstackLookupIOSFontByCandidates is weight-normalized to CSS 400) was OVERRIDING that with Kohinoor-
        // REGULAR (72.576 → blfgcps AppleGothic ॿ +1). Pre-empt the dispatcher here so AppleGothic keeps its iOS-
        // correct LIGHT cut. (The other low-weight primaries — Chalkboard SE/Chalkduster/Noteworthy/Helvetica/Futura —
        // natural-resolve to Kohinoor-REGULAR which equals the dispatcher's Regular, so they need no route; their
        // remaining blfgcps Δ-16/-16/-10 is NOT a fallback-identity gap [the fork already picks the same Kohinoor-
        // Regular the sim's NATIVE CoreText cascade does] but a sim-Safari-WebKit-vs-native-cascade width residual —
        // needs the sim-Safari fallback identity to crack, parked.) glyphHash-SAFE (named font, not one of the 6 generics).
        if (baseFamily.startsWith("AppleGothic"_s)) {
            if (RetainPtr<CTFontRef> kohLight = adoptCF(CTFontCreateWithName(CFSTR("KohinoorDevanagari-Light"), size, nullptr)))
                return kohLight;
        }
        return nullptr;
    }
    case 0xFFFD:   // Replacement Character
    case 0x21E4: { // Leftwards Arrow To Bar
        // W2577: iOS CoreText resolves the U+FFFD/U+21E4 tofu fallback to MENLO, not "Apple Symbols".
        // Empirically (Mac CoreText vs iOS-26.5-sim 3090CE99, CTFontCreateForString + advances): iOS picks
        // Menlo (advance 9.6328 @16px → offsetWidth 10; 43.348 @72px → 43); the old "apple symbols" candidate
        // gives 13.30 @16px → width 14 (the glyphHash residual) and 59 @72px (verification-log:57741 "+16 WRONG").
        // Mac-native Menlo == iOS-sim Menlo BYTE-IDENTICAL for both glyphs, and the per-em advance is identical at
        // 16px AND 72px → closes both the glyphHash DOM surface and the fonts-full 72px canvas surface, size-
        // independent, general for any So/Sm symbol whose iOS tofu fallback is Menlo. Menlo first; keep the old
        // candidates as fallback.
        static const std::array<ASCIILiteral, 3> candidates {
            "menlo"_s, "apple symbols"_s, ".sf ui"_s,
        };
        return driftstackLookupIOSFontByCandidates(candidates, description, size);
    }
    case 0x20E3: { // Combining Enclosing Keycap — iOS renders as EMOJI, DOM offsetWidth 21
        // W2585: iOS resolves U+20E3 to Apple Color Emoji (advance 21.0 @16px -> offsetWidth 21), same as the
        // other emoji-presentation symbols, NOT ".SF UI Symbols" (which gave w13). Apple Color Emoji is a system
        // font (loads by name). (Prior ".sf ui symbols" route targeted a 72px surface; the DOM glyphHash @16px
        // wants the emoji.)
        static const std::array<ASCIILiteral, 3> candidates {
            "apple color emoji"_s, ".sf ui symbols"_s, "apple symbols"_s,
        };
        return driftstackLookupIOSFontByCandidates(candidates, description, size);
    }
    case 0x17DD: { // Khmer Sign Atthacan — iPhone width 36 (UNIFORM 713 fonts)
        // Wave 29-219 fontTools cmap: U+17DD in Khmer Sangam MN. Apple Symbols
        // does NOT have it. Route to khmer sangam mn directly.
        static const std::array<ASCIILiteral, 3> candidates {
            "khmer sangam mn"_s, "apple symbols"_s, ".sf ui"_s,
        };
        return driftstackLookupIOSFontByCandidates(candidates, description, size);
    }
    case 0x302E:   // Hangul Single Dot Tone Mark — iPhone widths 56/37
    case 0x2C7B:   // Latin Letter Small Capital Turned E — iPhone widths 56/37
    case 0xA73D: { // Latin Small Letter Av With Horizontal Bar — iPhone widths 56/37
        // Latin extended + Hangul tone; cascade .SF UI then Apple Symbols.
        static const std::array<ASCIILiteral, 3> candidates {
            ".sf ui"_s, "apple symbols"_s, "apple sd gothic neo"_s,
        };
        return driftstackLookupIOSFontByCandidates(candidates, description, size);
    }
    case 0x2B06: { // Upwards Black Arrow — iOS renders as EMOJI (Apple Color Emoji), DOM offsetWidth 21 / offsetHeight 27
        // W2585 (Mac CTFontCreateWithName candidate test): "Apple Color Emoji" has the glyph with advance 21.0
        // @16px (offsetWidth 21) and asc+desc 26.25 -> line-box offsetHeight 27 — EXACT iOS-26.5-sim match. The fork
        // raw cascade instead rendered a narrow text glyph (w16). Apple Color Emoji is a SYSTEM font (loads by name).
        static const std::array<ASCIILiteral, 1> candidates { "apple color emoji"_s };
        return driftstackLookupIOSFontByCandidates(candidates, description, size);
    }
    case 0x1F170: case 0x1F171: case 0x1F17E: case 0x1F17F: { // 🅰🅱🅾🅿 NEGATIVE SQUARED LATIN CAPITAL LETTERS (Enclosed Alphanumeric Supplement) — RGI emoji; all 4 sim-verified 21x27 @16px / 128x170 @128px
        // W2876 (2026-06-24): browserleaks /fonts has a SECOND fingerprint — "Unicode Glyphs" — that hashes DOM
        // offsetWidth/offsetHeight of special cps at LARGE size + default family (separate from the font-metrics
        // hash, #96). The macOS CT cascade resolves U+1F17F to Hiragino Sans (narrow text glyph, offsetWidth 16
        // @16px); a real iPhone renders it as Apple Color Emoji (advance 21 @16px -> offsetWidth 21, line-box 27).
        // Verified BOTH refs agree: iOS-26.5 sim = 21x27, and the W554 iOS-18.7 emoji curve @16px = 21 (version-
        // stable). U+1F17F is a standard RGI emoji (🅿 parking). The W2599 emoji-presentation sweep covered
        // U+2100-2B4F but NOT the Enclosed Alphanumeric Supplement (U+1F100-1F1FF). Same mechanism as U+2B06/U+20E3.
        static const std::array<ASCIILiteral, 1> candidates { "apple color emoji"_s };
        return driftstackLookupIOSFontByCandidates(candidates, description, size);
    }
    case 0x2581: { // Lower One Eighth Block
        // W2585: iOS resolves to Hiragino Sans (advance 16.0 @16px -> width 16; 128.0 @128px -> width 128) in
        // PROPORTIONAL generics (default/sans/serif/cursive/fantasy). asc 14.08 + desc 1.92 + LEAD 8.0 =
        // lineSpacing 24 -> line-box offsetHeight 25.
        // W2597: in a MONOSPACE base context (font-family:monospace -> Courier/Monaco, which lack the U+2581
        // glyph -> notdef), iOS does NOT fall to Hiragino — it falls to MENLO (advance 77.0625 @128px -> width
        // 78), matching the monospace fallback cascade. Empirical (iOS-26.5 sim vs fork): mono fork=128 (Hiragino)
        // vs iOS=78 (Menlo) — the +50px monospace blfonts uniqueMetrics divergence (Courier/Courier New/Monaco/
        // monospace, all +51 from this single char). Proportional generics already match (fork=iOS=128). The 16px
        // glyphHash is DOM-geometry-served in Element.cpp (size-gated to 16px/13px), so this 128px font pick does
        // not affect the glyphHash surface. Route monospace-base -> Menlo, proportional-base -> Hiragino Sans.
        if (baseFontIsMonospace) {
            static const std::array<ASCIILiteral, 3> candidates { "menlo"_s, "hiragino sans"_s, "hiraginosans"_s };
            return driftstackLookupIOSFontByCandidates(candidates, description, size);
        }
        static const std::array<ASCIILiteral, 2> candidates { "hiragino sans"_s, "hiraginosans"_s };
        return driftstackLookupIOSFontByCandidates(candidates, description, size);
    }
    case 0x3095: { // Hiragana Letter Small Ka — iOS DOM offsetWidth 16 / offsetHeight 25
        // W2585: iOS resolves to Hiragino Sans (advance 16.0 -> width 16; a+d 16 + lead 8 = lineSpacing 24 -> h25).
        // Fork was +1 (h26). Route to Hiragino Sans.
        static const std::array<ASCIILiteral, 2> candidates { "hiragino sans"_s, "hiraginosans"_s };
        return driftstackLookupIOSFontByCandidates(candidates, description, size);
    }
    case 0x20B0: { // German Penny Sign — iOS DOM offsetWidth 10
        // W2585: iOS uses Menlo (advance 9.633 -> width 10); fork picked a wide font (w15). Route to Menlo.
        static const std::array<ASCIILiteral, 3> candidates { "menlo"_s, "helvetica"_s, ".sf ui"_s };
        return driftstackLookupIOSFontByCandidates(candidates, description, size);
    }
    case 0x0D02: { // Malayalam Sign Anusvara — iOS DOM offsetWidth 7
        // W2585: iOS uses Malayalam Sangam MN (advance 6.164 -> width 7); fork was too tall (h24). Route there.
        static const std::array<ASCIILiteral, 2> candidates { "malayalam sangam mn"_s, ".sf malayalam"_s };
        return driftstackLookupIOSFontByCandidates(candidates, description, size);
    }
    case 0x05C6: { // Hebrew Punctuation Nun Hafukha — iOS DOM offsetWidth 6
        // W2585: iOS resolves to the SF Hebrew binary (Stage-B; advance 6.0625 -> width 6). The system-name
        // "Arial Hebrew" advances to width 6 (5.648) CONSISTENTLY; the Stage-B .SF Hebrew lookup gave inconsistent
        // 5/7 per generic (fell to Times in some). Route to Arial Hebrew first for the consistent w6.
        static const std::array<ASCIILiteral, 2> candidates { "arial hebrew"_s, ".sf hebrew"_s };
        return driftstackLookupIOSFontByCandidates(candidates, description, size);
    }
    // W2600: UNIFORM-all-6-generic symbol-advance overrides (symbol-advance fingerprint class). Each cp has the
    // SAME iOS advance in all 6 generics, and one system-loadable named font gives ceil(advance@16px)==that value
    // in every generic (adversarially confirmed via the symbol-advance-triage workflow's ctadv-by-name probing,
    // then build+sim-diff verified). Routed unconditionally (the override only fires where the primary font lacks
    // the glyph = the divergent generics; matching generics are untouched -> zero regression).
    case 0x2303: case 0x2325: case 0x2326: case 0x2327: case 0x232B: case 0x237D:
    case 0x233D: case 0x25B8: case 0x25BE: case 0x2641:
    case 0x21B5: case 0x21DE: case 0x21DF: case 0x21E5: case 0x21EA: { // -> Menlo (iOS width 10), uniform all 6
        // (U+233D: the workflow's "Arial Unicode MS" pick ctadv-matched 10 but is NOT loadable in the fork's font
        //  set -> driftstackLookupIOSFontByCandidates returned null -> stayed 16; Menlo has the glyph at 10 too.)
        // W2601 added U+21B5/21DE/21DF/21E5/21EA (arrows, iOS 10 all generics).
        static const std::array<ASCIILiteral, 1> candidates { "menlo"_s };
        return driftstackLookupIOSFontByCandidates(candidates, description, size);
    }
    case 0x2125: case 0x2137: case 0x2324: case 0x2108: { // -> Apple Symbols (iOS 10 / 8 / 9 / 11), uniform all 6
        static const std::array<ASCIILiteral, 1> candidates { "apple symbols"_s };
        return driftstackLookupIOSFontByCandidates(candidates, description, size);
    }
    case 0x2132: case 0x2141: case 0x2144: { // -> Helvetica (iOS 10 / 13 / 11)
        static const std::array<ASCIILiteral, 1> candidates { "helvetica"_s };
        return driftstackLookupIOSFontByCandidates(candidates, description, size);
    }
    case 0x2322: case 0x2323: { // -> Apple SD Gothic Neo (iOS 14)
        static const std::array<ASCIILiteral, 1> candidates { "apple sd gothic neo"_s };
        return driftstackLookupIOSFontByCandidates(candidates, description, size);
    }
    case 0x20BC: { // -> Helvetica Neue (iOS 9)
        static const std::array<ASCIILiteral, 2> candidates { "helvetica neue"_s, "helvetica"_s };
        return driftstackLookupIOSFontByCandidates(candidates, description, size);
    }
    case 0x2135: { // -> STIX Two Math (iOS 12)
        static const std::array<ASCIILiteral, 1> candidates { "stix two math"_s };
        return driftstackLookupIOSFontByCandidates(candidates, description, size);
    }
    // W2601: UNIFORM-EXCEPT-MONO symbol-advance overrides (symbol-advance-mono-triage workflow, adversarially
    // confirmed ctadv ok=1 + ceil==iOS non-mono target, then build+sim-diff verified). iOS is uniform across the
    // 5 PROPORTIONAL generics; the monospace generic ALREADY matches the fork -> route monospace-base to nullptr
    // (keep the natural cascade), proportional-base to the matched font. Uses the W2597 baseFontIsMonospace flag.
    case 0x21B0: case 0x21B1: case 0x21B2: case 0x21B3: case 0x21B4: case 0x21B6: case 0x21B7:
    case 0x21BC: case 0x21C0: case 0x21CD: case 0x21CF: case 0x21D1: case 0x21D3:
    case 0x21E0: case 0x21E1: case 0x21E2: case 0x21E3: case 0x21F0:
    case 0x2314: case 0x25A4: case 0x25A6: case 0x25A7: case 0x25A8: case 0x25A9: case 0x25AD:
    case 0x25B4: case 0x25B5: case 0x25B9: case 0x25BF: case 0x25C3: case 0x25C8:
    case 0x2609: case 0x260F: { // -> Apple SD Gothic Neo (iOS non-mono 14/15), mono natural
        if (baseFontIsMonospace)
            return nullptr;
        static const std::array<ASCIILiteral, 1> candidates { "apple sd gothic neo"_s };
        return driftstackLookupIOSFontByCandidates(candidates, description, size);
    }
    case 0x2100: case 0x2101: case 0x2106: case 0x2117: case 0x2120: case 0x2121:
    case 0x2129: case 0x213A: case 0x213B: case 0x214B: { // -> Helvetica (iOS non-mono 14/12/15/4/13/16/11), mono natural
        if (baseFontIsMonospace)
            return nullptr;
        static const std::array<ASCIILiteral, 1> candidates { "helvetica"_s };
        return driftstackLookupIOSFontByCandidates(candidates, description, size);
    }
    case 0x2305: case 0x2318: case 0x25C1: case 0x25C6: case 0x25C7: { // -> Hiragino Sans (iOS non-mono 11/14/16), mono natural
        if (baseFontIsMonospace)
            return nullptr;
        static const std::array<ASCIILiteral, 1> candidates { "hiragino sans"_s };
        return driftstackLookupIOSFontByCandidates(candidates, description, size);
    }
    case 0x25A3: case 0x25A5: { // -> Apple Symbols (iOS non-mono 14), mono natural
        if (baseFontIsMonospace)
            return nullptr;
        static const std::array<ASCIILiteral, 1> candidates { "apple symbols"_s };
        return driftstackLookupIOSFontByCandidates(candidates, description, size);
    }
    case 0x270E: case 0x2758: { // -> Zapf Dingbats (iOS non-mono 15/3), mono natural
        if (baseFontIsMonospace)
            return nullptr;
        static const std::array<ASCIILiteral, 2> candidates { "zapf dingbats"_s, "itc zapf dingbats"_s };
        return driftstackLookupIOSFontByCandidates(candidates, description, size);
    }
    // W2603: per-generic letterlike where iOS routes the PROPORTIONAL generics (default/serif/sans) to Helvetica
    // but the cursive/fantasy/monospace fallbacks ALREADY match a DIFFERENT iOS value -> route proportional to
    // Helvetica, leave cursive/fantasy/monospace natural (return nullptr). (Helvetica has real glyphs: ℃=18, ℉=17,
    // Å=11 = the iOS default/serif/sans target; the sans generic primary-renders so the override only fires in
    // default/serif/cursive where the primary lacks the glyph.)
    case 0x2103: { // ℃ Degree Celsius — iOS def/serif/sans/cursive=18 (Helvetica); fantasy=17, mono=10 already match
        if (baseFontIsMonospace || baseIsFantasy)
            return nullptr;
        static const std::array<ASCIILiteral, 1> candidates { "helvetica"_s };
        return driftstackLookupIOSFontByCandidates(candidates, description, size);
    }
    case 0x2109: case 0x212B: { // ℉ Degree Fahrenheit (iOS 17) / Å Angstrom (iOS 11) — def/serif/sans only; cursive/fantasy/mono already match
        if (baseFontIsMonospace || baseIsCursive || baseIsFantasy)
            return nullptr;
        static const std::array<ASCIILiteral, 1> candidates { "helvetica"_s };
        return driftstackLookupIOSFontByCandidates(candidates, description, size);
    }
    // W2604: per-generic arrows/geometric where default/serif primary-render (match) and ONLY the proportional
    // FALLBACK generics (sans/cursive/fantasy) diverge to a uniform iOS value; monospace already matches (10) so
    // gate it to nullptr. The override fires only where the primary lacks the glyph = the fallback generics.
    case 0x2191: case 0x2193: case 0x25A0: case 0x25A1: case 0x25CB: case 0x25E6: { // -> Hiragino Sans (iOS fallback-generic 16)
        if (baseFontIsMonospace)
            return nullptr;
        static const std::array<ASCIILiteral, 1> candidates { "hiragino sans"_s };
        return driftstackLookupIOSFontByCandidates(candidates, description, size);
    }
    case 0x2194: case 0x2195: case 0x25AA: case 0x25AB: case 0x263A: { // -> Apple Color Emoji (iOS fallback-generic 21)
        if (baseFontIsMonospace)
            return nullptr;
        static const std::array<ASCIILiteral, 1> candidates { "apple color emoji"_s };
        return driftstackLookupIOSFontByCandidates(candidates, description, size);
    }
    case 0x25BA: case 0x20AF: { // -> Menlo (iOS fallback-generic 10)
        if (baseFontIsMonospace)
            return nullptr;
        static const std::array<ASCIILiteral, 1> candidates { "menlo"_s };
        return driftstackLookupIOSFontByCandidates(candidates, description, size);
    }
    case 0x05BE: { // ־ Hebrew Maqaf (Po) — per-generic: default/serif=6, mono=10 (already match), sans/cursive/
        // fantasy=7. iOS uses Arial Hebrew (7) for the sans/cursive/fantasy fallback. Route those three; leave
        // default/serif (6) + monospace (10) natural. (Po/Lo orphan residual.)
        if (baseIsSansSerif || baseIsCursive || baseIsFantasy) {
            static const std::array<ASCIILiteral, 2> candidates { "arial hebrew"_s, ".sf hebrew"_s };
            return driftstackLookupIOSFontByCandidates(candidates, description, size);
        }
        return nullptr;
    }
    case 0x05C0: case 0x05C3: { // ׀ ׃ Hebrew Paseq / Sof Pasuq (Po) — W2612. sans-serif (Helvetica base) falls to
        // Lucida Grande (a Mac-only font, DOM line box 20) vs iOS 22; route sans-serif -> Arial Hebrew (its DOM line
        // box is 22, and advance 4.4/4.45 -> round 4 = iOS width 4, so 4x22 EXACT). The proven U+05BE Arial Hebrew
        // route confirms Arial Hebrew gives DOM height 22 in sans-serif. Only sans-serif diverges (serif/mono/cursive/
        // fantasy/system-ui already match iOS) so route baseIsSansSerif ONLY, leave the rest natural. (Po/Lo residual.)
        if (baseIsSansSerif) {
            static const std::array<ASCIILiteral, 2> candidates { "arial hebrew"_s, ".sf hebrew"_s };
            return driftstackLookupIOSFontByCandidates(candidates, description, size);
        }
        return nullptr;
    }
    case 0x0E32: case 0x0E33: { // ◌ Thai Sara Aa / Sara Am (Lo) — monospace (Courier lacks Thai -> fork notdef 10)
        // vs iOS 9/17. iOS uses Thonburi (U+0E32=9, U+0E33=17); proportional generics already match Thonburi's
        // value, so route unconditionally (Thonburi gives the iOS value in every generic). (Po/Lo orphan residual.)
        static const std::array<ASCIILiteral, 2> candidates { "thonburi"_s, "sathu"_s };
        return driftstackLookupIOSFontByCandidates(candidates, description, size);
    }
    case 0x20AA: { // ₪ New Sheqel Sign — iOS sans/cursive/fantasy=14 (Arial Hebrew); default/serif=13 + mono=10 already match
        if (baseFontIsMonospace)
            return nullptr;
        static const std::array<ASCIILiteral, 2> candidates { "arial hebrew"_s, ".sf hebrew"_s };
        return driftstackLookupIOSFontByCandidates(candidates, description, size);
    }
    // W2605: ◊ Lozenge U+25CA — cursive (Snell lacks it -> fork fallback 9) -> Helvetica (iOS 8). The monospace
    // divergence (Courier HAS ◊ at 8 but iOS=10) can't be reached by the cluster fallback (the primary renders it,
    // no fallback fires) -> handled by the DOM-geometry serve (Element.cpp). def/sans/serif/fantasy already match.
    case 0x25CA: {
        if (baseIsCursive) {
            static const std::array<ASCIILiteral, 1> candidates { "helvetica"_s };
            return driftstackLookupIOSFontByCandidates(candidates, description, size);
        }
        return nullptr;
    }
    // NOTE: the notdef-width currency U+20B6/20B7/20BB/20BF are NOT font-selectable (no Mac font reproduces iOS's
    // .LastResort per-cp tofu widths 10/12/14, and routing to a notdef font does NOT stick — WebKit continues the
    // cascade) -> served via the DOM-geometry serve (Element.cpp driftstackServeGlyphHashGeom).
    // W2602: BOX-DRAWING double-line + dark-shade (U+2551-256C, U+2593). iOS renders these at 12 in default/serif
    // (the system/Times primary HAS the glyph -> no fallback) and 10 in sans-serif/cursive/fantasy (Helvetica/
    // Snell/Papyrus LACK the glyph -> fallback). The fork's fallback picked a wide font (16). MENLO has the glyph
    // at 10 = iOS. The override only fires in the fallback generics (sans/cursive/fantasy); default/serif/mono are
    // primary-rendered and untouched. (Verified: .SF NS + Times have U+2551 ok=1 -> 12; Helvetica notdef.)
    case 0x2551: case 0x2552: case 0x2553: case 0x2554: case 0x2555: case 0x2556: case 0x2557:
    case 0x2558: case 0x2559: case 0x255A: case 0x255B: case 0x255C: case 0x255D: case 0x255F:
    case 0x2560: case 0x2562: case 0x2563: case 0x2564: case 0x2565: case 0x2566: case 0x2567:
    case 0x2568: case 0x2569: case 0x256B: case 0x256C: case 0x2593: { // -> Menlo (iOS fallback-generic width 10)
        static const std::array<ASCIILiteral, 1> candidates { "menlo"_s };
        return driftstackLookupIOSFontByCandidates(candidates, description, size);
    }
    // W2602b: CARD SUITS (U+2660/2663/2665/2666). iOS renders the proportional FALLBACK generics (sans/cursive/
    // fantasy, whose primary lacks the glyph) as COLOR EMOJI (advance 21); default/serif primary-render the text
    // glyph (9-11) and monospace stays 10 (Menlo). Route the fallback to Apple Color Emoji; monospace->nullptr.
    case 0x2660: case 0x2663: case 0x2665: case 0x2666: {
        if (baseFontIsMonospace)
            return nullptr;
        static const std::array<ASCIILiteral, 1> candidates { "apple color emoji"_s };
        return driftstackLookupIOSFontByCandidates(candidates, description, size);
    }
    // W2599: EMOJI-PRESENTATION symbol batch (symbol-advance fingerprint class, fork-vs-iOS-26.5-sim).
    // These 53 codepoints (arrows/weather/hands/religious/zodiac/tool/checkmark/heart symbols) are rendered
    // by a real iPhone as COLOR EMOJI — advance 21.0 @16px (Apple Color Emoji) — in the proportional generics
    // (default/sans-serif/serif/cursive/fantasy), where the fork's raw cascade picks a narrow TEXT glyph (11-16).
    // Same mechanism + font as the already-shipped U+2B06/U+20E3 (W2585). Apple Color Emoji is a system font
    // (loads by name); ctadv confirms ceil(advance@16)=21 for every one. The MONOSPACE generic already matches
    // iOS (both 10, the narrow mono fallback) for these — so route monospace-base to nullptr (keep the natural
    // cascade) and proportional-base to Apple Color Emoji. CANVAS pixels for these remain a #42-atlas follow-on;
    // this fixes the DOM/FontCascade advance (offsetWidth/measureText) which is what the symbol-sweep probes.
    case 0x2196: case 0x2197: case 0x2198: case 0x2199: case 0x21A9: case 0x21AA:
    case 0x2328: case 0x25B6: case 0x25C0: case 0x25FB: case 0x25FC:
    case 0x2600: case 0x2601: case 0x2602: case 0x2603: case 0x2604: case 0x260E:
    case 0x2611: case 0x2618: case 0x261D: case 0x2620: case 0x2622: case 0x2623:
    case 0x2626: case 0x262A: case 0x262E: case 0x262F: case 0x2638: case 0x265F:
    case 0x2668: case 0x267B: case 0x267E: case 0x2702: case 0x2708: case 0x2709:
    case 0x270C: case 0x270D: case 0x270F: case 0x2712: case 0x2714: case 0x2716:
    case 0x271D: case 0x2721: case 0x2733: case 0x2734: case 0x2744: case 0x2747:
    case 0x2763: case 0x2764: case 0x27A1: {
        if (baseFontIsMonospace)
            return nullptr;
        static const std::array<ASCIILiteral, 1> candidates { "apple color emoji"_s };
        return driftstackLookupIOSFontByCandidates(candidates, description, size);
    }
    // W2599b: the 3 emoji symbols iOS renders at 21 in ALL 6 generics INCLUDING monospace (uniform — the fork's
    // mono is also wrong here: U+2139 fork-mono 11, U+2B05/2B07 fork-mono 16). Route every generic to the emoji.
    case 0x2139: case 0x2B05: case 0x2B07: {
        static const std::array<ASCIILiteral, 1> candidates { "apple color emoji"_s };
        return driftstackLookupIOSFontByCandidates(candidates, description, size);
    }
    // W2633: exotic General Punctuation real-glyph cps (U+2023..U+205D — triangular bullet, primes/reversed
    // primes, reference/swung/asterism marks, quill brackets, interrobang family, tricolons). The serif/default
    // primary (Times / document default) LACKS these → the fork's notdef cascade resolves to LUCIDA GRANDE
    // (Mac-only, iOS lacks) at the wrong advance; a real iPhone renders them in HELVETICA. ctdirect/ctcascade-
    // confirmed: ceil(Helvetica advance@16) == the iOS-26.5-sim width for ALL 25 (e.g. U+203F 8→16, U+2050 8→16,
    // U+2023 8→6, U+2047 13→18), and the DOM line-box stays the base strut (serif 21 == iOS) because Helvetica's
    // box (16) is shorter and does not extend it — a clean COHERENT width-only fix (offsetWidth/measureText/canvas
    // all then use the Helvetica glyph, unlike the DOM-only Element.cpp serve). Fires only on the serif/default
    // notdef path: mono/cursive/fantasy/sans are excluded (they already match iOS — sans IS Helvetica so never
    // notdefs; system-ui's SF carries most of these glyphs natively so rarely reaches this fallback). U+2049/U+203C
    // are EXCLUDED (emoji-presentation per-generic split — their system-ui wants Apple Color Emoji). glyphHash-SAFE:
    // disjoint from the 5 glyphHash cps (U+1CDA/20E3/2581/05C6/2B06). After build + geomserve-table(DS_GEOM_SERVE=0)
    // sim-diff confirms natural==iOS for every generic, DELETE the W2614 serif rows from Element.cpp.
    case 0x2023: case 0x2031: case 0x2037: case 0x203D: case 0x2040: case 0x2041:
    case 0x2045: case 0x2046: case 0x204A: case 0x204B: case 0x204F: case 0x2050:
    case 0x2052: case 0x2053: case 0x2054: case 0x2057: {
        if (baseFontIsMonospace || baseIsCursive || baseIsFantasy || baseIsSansSerif)
            return nullptr;
        static const std::array<ASCIILiteral, 1> candidates { "helvetica"_s };
        return driftstackLookupIOSFontByCandidates(candidates, description, size);
    }
    // W2634: Small Form Variants (U+FE50..U+FE6B, excl. FE53/FE59/FE5A/FE67) — the NARROW CJK small-form
    // punctuation/ASCII variants. The fork's cascade resolves these to Songti SC / .CJK Symbols Fallback SC
    // rendered FULL-WIDTH (advance 16), but a real iPhone renders them in APPLE SYMBOLS at their true narrow
    // small-form width (FE50→6, FE52→5, FE5F→7, …). ctdirect-confirmed: ceil(Apple-Symbols advance@16) ==
    // the iOS-26.5-sim width for 24/28 cps × all generics (120/140 cells); the per-generic iOS values are
    // uniform so route every generic. EXCLUDED: FE53/FE67 (Apple Symbols lacks the glyph) + FE59/FE5A (small
    // parens, iOS=14 wide ≠ Apple-Symbols 5) — kept served. glyphHash-SAFE (disjoint from the 5 glyphHash cps).
    // After build + geomserve-table sim-diff verifies natural==iOS, DELETE the matching W2617 SmallForm rows.
    case 0xFE50: case 0xFE51: case 0xFE52: case 0xFE54: case 0xFE55: case 0xFE56:
    case 0xFE57: case 0xFE58: case 0xFE5B: case 0xFE5C: case 0xFE5D: case 0xFE5E:
    case 0xFE5F: case 0xFE60: case 0xFE61: case 0xFE62: case 0xFE63: case 0xFE64:
    case 0xFE65: case 0xFE66: case 0xFE68: case 0xFE69: case 0xFE6A: case 0xFE6B: {
        static const std::array<ASCIILiteral, 1> candidates { "apple symbols"_s };
        return driftstackLookupIOSFontByCandidates(candidates, description, size);
    }
    // W2635: CJK Symbols/Punctuation real-glyph cps — WIDTH already matches iOS (full-width 16); only the line-box
    // HEIGHT diverges, driven by the FALLBACK FONT (single inline glyph => the fallback's metrics ARE the line box).
    // U+3003/3005/3006/3007/3012/3013 (ditto/iteration/postal/geta marks): fork serif/cursive cascade picks Songti SC
    // (lineH 23) but a real iPhone uses HIRAGINO MINCHO ProN (lineH 25) → DOM height 25. U+301C (wave dash): fork picks
    // Hiragino Mincho (25) but iOS uses PINGFANG SC (lineH 23) → 23. Route ONLY the serif+cursive generics (default/
    // sans/mono already match iOS — their natural PingFang/Hiragino cascade gives the right value). Same mechanism +
    // height-via-fallback proven by case 0x3095 (Hiragino Sans -> DOM 25). glyphHash-SAFE (disjoint from the 5 glyphHash
    // cps). After build + REAL-iPhone geomserve-diff verifies height==iOS, DELETE the W2617 CJK rows for these cps.
    case 0x3003: case 0x3005: case 0x3006: case 0x3007: case 0x3012: case 0x3013: {
        if (!(baseIsSerif || baseIsCursive))
            return nullptr;
        static const std::array<ASCIILiteral, 2> candidates { "hiragino mincho pron"_s, "hiragino sans"_s };
        return driftstackLookupIOSFontByCandidates(candidates, description, size);
    }
    case 0x301C: {
        if (!(baseIsSerif || baseIsCursive))
            return nullptr;
        static const std::array<ASCIILiteral, 2> candidates { "pingfang sc"_s, "pingfangsc"_s };
        return driftstackLookupIOSFontByCandidates(candidates, description, size);
    }
    // W2636 NOTDEF CLASS: these cps are notdef in EVERY iOS font (no glyph anywhere). A real iPhone renders the
    // REQUESTING generic's missing-glyph box, whose advance + line-box is a per-generic CONSTANT (default/serif 13,20 /
    // sans 11,21 / mono 10,20 / cursive 8,21 / fantasy 8,26 / sysui 16,21). The fork's natural cascade instead finds a
    // MAC-ONLY font (Geneva / Arial Unicode MS — absent on iOS) that HAS a real glyph, rendering the wrong (generic-
    // uniform) advance. FIX: return ANY iOS font that also lacks the glyph → WebKit falls to the ORIGINAL requesting
    // font's missing-glyph box at the per-generic advance+line-box (the returned font's identity is irrelevant; it only
    // must lack the glyph — EMPIRICALLY PROVEN: returning "times new roman" for both default and system-ui yielded 13
    // vs 16, i.e. the box comes from the requesting font, not the returned one). Verified byte-exact vs the iOS-26.5 sim
    // for all 7 generics on U+2E1A. Routes each generic to its own primary (all lack these notdef cps): sans→Helvetica,
    // mono→Menlo, cursive→Snell, fantasy→Papyrus, default/serif/system-ui→Times. The 31 cps are EXACTLY those whose iOS
    // sim row equals the standard notdef signature; GCPS U+302E is EXCLUDED (glyphHash-load-bearing, handled separately).
    // Currency notdef (U+20B6..BF) has a DIFFERENT box signature → separate class. After build verifies natural==sim per
    // (cp,generic), DELETE the matching GEOM_SERVE rows. glyphHash-SAFE (all 31 disjoint from the 43 GCPS).
    case 0x2E1A: case 0x2E1B: case 0x2E1E: case 0x2E1F: case 0x2E20: case 0x2E21: case 0x2E22: case 0x2E23:
    case 0x2E24: case 0x2E25: case 0x2E26: case 0x2E27: case 0x2E2A: case 0x2E2B: case 0x2E2C: case 0x2E2D:
    case 0x2E2F: case 0x302A: case 0x302B: case 0x302C: case 0x302D: case 0x302F: case 0x3031: case 0x3032:
    case 0x3037: case 0x3038: case 0x3039: case 0x303A: case 0x303F: case 0xFE53: case 0xFE67: {
        if (baseIsSansSerif) { static const std::array<ASCIILiteral, 1> c { "helvetica"_s }; return driftstackLookupIOSFontByCandidates(c, description, size); }
        if (baseFontIsMonospace) { static const std::array<ASCIILiteral, 1> c { "menlo"_s }; return driftstackLookupIOSFontByCandidates(c, description, size); }
        if (baseIsCursive) { static const std::array<ASCIILiteral, 1> c { "snell roundhand"_s }; return driftstackLookupIOSFontByCandidates(c, description, size); }
        if (baseIsFantasy) { static const std::array<ASCIILiteral, 1> c { "papyrus"_s }; return driftstackLookupIOSFontByCandidates(c, description, size); }
        static const std::array<ASCIILiteral, 1> c { "times new roman"_s };
        return driftstackLookupIOSFontByCandidates(c, description, size);
    }
    // W2638: General Punctuation CURSIVE-cascade fix. The cursive generic (Snell Roundhand base) lacks these space/
    // dash/prime/mark/punctuation glyphs → the fork notdef-cascades to Geneva (Mac-only, iOS lacks) at the wrong
    // advance; a real iPhone renders the cursive fallback in HELVETICA NEUE. fontscan-confirmed ceil(Helvetica Neue
    // advance@16) == the iOS-26.5-sim CURSIVE width for every cp. Fires ONLY on cursive (the other 6 generics are
    // already fork-natural-correct, so non-cursive returns nullptr → unchanged). glyphHash-SAFE (disjoint from the 5
    // GCPS cps). After build + sim-diff confirms cursive==iOS, DELETE the cursive GEOM_SERVE rows for these cps.
    case 0x25CC: { // ◌ DOTTED CIRCLE — W2877: cursive base mis-cascades to Noto Nastaliq Urdu (Arabic, lineH 321 ->
        // probe 101x321) vs iOS Hiragino Mincho ProN (128x193 @128px / 16x25 @16px, ctcascade-verified == iOS-26.5
        // sim). Non-cursive already correct (default -> Hiragino Sans 149) so return nullptr to leave the cascade.
        if (!baseIsCursive)
            return nullptr;
        static const std::array<ASCIILiteral, 1> candidates { "hiragino mincho pron"_s };
        return driftstackLookupIOSFontByCandidates(candidates, description, size);
    }
    case 0x2002: case 0x2003: case 0x2004: case 0x2005: case 0x2006: case 0x2007:
    case 0x2009: case 0x200A: case 0x2012: case 0x2015: case 0x2016: case 0x2017:
    case 0x201B: case 0x201F: case 0x2025: case 0x2027: case 0x202F: case 0x2032:
    case 0x2033: case 0x2034: case 0x2035: case 0x203E: case 0x2044: case 0x204C:
    case 0x204D: {
        if (!baseIsCursive)
            return nullptr;
        static const std::array<ASCIILiteral, 1> candidates { "helvetica neue"_s };
        return driftstackLookupIOSFontByCandidates(candidates, description, size);
    }
    // W2638: the 9 General Punctuation cps that need BOTH serif/default→Helvetica (the W2633 width fix) AND
    // cursive→Helvetica Neue (the W2638 cursive fix). Split out of the W2633 block so cursive routes too.
    case 0x203B: case 0x203F: case 0x2042: case 0x2047: case 0x2048: case 0x204E:
    case 0x2051: case 0x205A: case 0x205D: {
        if (baseIsCursive) {
            static const std::array<ASCIILiteral, 1> candidates { "helvetica neue"_s };
            return driftstackLookupIOSFontByCandidates(candidates, description, size);
        }
        if (baseFontIsMonospace || baseIsFantasy || baseIsSansSerif)
            return nullptr;
        static const std::array<ASCIILiteral, 1> candidates { "helvetica"_s };
        return driftstackLookupIOSFontByCandidates(candidates, description, size);
    }
    // W2638: U+2028/2029 LINE/PARAGRAPH SEPARATOR — the monospace generic renders them at width 10 (MENLO); the other
    // generics are 0-width. Gate on monospace; the line-box height (17→20) rides the integer-inline-layout path (W2575).
    case 0x2028: case 0x2029: {
        if (!baseFontIsMonospace)
            return nullptr;
        static const std::array<ASCIILiteral, 1> candidates { "menlo"_s };
        return driftstackLookupIOSFontByCandidates(candidates, description, size);
    }
    // W2638: U+FE59/FE5A SMALL PARENTHESES — uniform width 14 across ALL generics via APPLE SD GOTHIC NEO (the iOS
    // small-form CJK font). W2634 kept these served because Apple Symbols gave the wrong width. Unconditional route.
    case 0xFE59: case 0xFE5A: {
        static const std::array<ASCIILiteral, 1> candidates { "apple sd gothic neo"_s };
        return driftstackLookupIOSFontByCandidates(candidates, description, size);
    }
    // W2639: rare currency symbols (U+20B6 Livre Tournois, U+20B7 Spesmilo, U+20BB Nordic Mark) — the iOS-26.5
    // simruntime font scan proves a real iPhone renders these in ROCKWELL (CoreUI/Rockwell.ttc, an iOS font hidden
    // from browserleaks detection — the workflow's iOS-set filter missed it). Verified 7/7 generics == iOS sim
    // (width 10/12/14, height 23/24/26 per-generic strut). glyphHash-SAFE (non-GCPS; GCPS currency 20B8/B9/BA/BD/B0
    // NOT here). U+20BF (Bitcoin) EXCLUDED — iOS renders it in SF UI (height 21, not Rockwell's 23); needs the iOS
    // SF font (Mac SF gives width 11≠10), kept served Class-B. After sim-diff, DELETE the 20B6/B7/BB serves.
    case 0x20B6: case 0x20B7: case 0x20BB: {
        static const std::array<ASCIILiteral, 1> candidates { "rockwell"_s };
        return driftstackLookupIOSFontByCandidates(candidates, description, size);
    }
    default:
        return nullptr;
    }
}
#endif // PLATFORM(DRIFTSTACK)

RefPtr<Font> FontCache::systemFallbackForCharacterCluster(const FontDescription& description, const Font& originalFontData, IsForPlatformFont isForPlatformFont, PreferColoredFont, StringView characterCluster)
{
    const FontPlatformData& platformData = originalFontData.platformData();
    RetainPtr ctFont = platformData.ctFont();

    auto fullName = String(adoptCF(CTFontCopyFullName(ctFont.get())).get());
    if (!fullName.isEmpty())
        m_fontNamesRequiringSystemFallbackForPrewarming.add(fullName);

    auto result = lookupFallbackFont(ctFont.get(), description.weight(), description.computedLocale(), description.shouldAllowUserInstalledFonts(), characterCluster);
#if PLATFORM(DRIFTSTACK)
    // V-433.Z wave 29-205: 10 universally-divergent codepoints route to SF Pro
    // FIRST (before script-specific overrides) so the explicit list always wins
    // even where script ranges (e.g. U+302E Hangul Tone Mark) would otherwise
    // match the Hangul or Devanagari hooks.
    // W2597: the base font's monospace trait disambiguates the U+2581 (and any future mono-vs-proportional)
    // fallback pick — iOS routes notdef block/symbol clusters down the monospace cascade (Menlo) for fixed-pitch
    // base fonts but the proportional cascade (Hiragino) otherwise.
    bool driftstackBaseFontIsMonospace = ctFont && (CTFontGetSymbolicTraits(ctFont.get()) & kCTFontTraitMonoSpace);
    // W2603: the CSS cursive/fantasy generics resolve to fixed iOS default fonts (Snell Roundhand / Papyrus). Some
    // symbol cps (℃/℉/Å, arrows, geometric) have a per-generic iOS advance where the cursive/fantasy fallback
    // ALREADY matches the fork but the proportional (default/serif) one does NOT — so the override must fire for
    // the proportional generics yet leave cursive/fantasy (and monospace) natural. Classify the base font by family.
    String driftstackBaseFamily = ctFont ? String(adoptCF(CTFontCopyFamilyName(ctFont.get())).get()) : String();
    bool driftstackBaseIsCursive = driftstackBaseFamily.startsWith("Snell"_s);
    bool driftstackBaseIsFantasy = equalLettersIgnoringASCIICase(driftstackBaseFamily, "papyrus"_s);
    // W2607: the sans-serif generic resolves to Helvetica; some cps (U+05BE) need the sans/cursive/fantasy
    // fallback DIFFERENT from default/serif, so distinguish the Helvetica (sans-serif) base too.
    bool driftstackBaseIsSansSerif = equalLettersIgnoringASCIICase(driftstackBaseFamily, "helvetica"_s);
    // W2635: the CSS serif generic resolves to Times New Roman; some CJK symbol cps need the serif (+cursive)
    // fallback DIFFERENT from default/sans/mono — so distinguish the Times (serif) base too.
    bool driftstackBaseIsSerif = driftstackBaseFamily.startsWith("Times"_s);
    // W2608: the base font's kCTFontWeightTrait (float -1..1) SURVIVES WebKit's font-build here (verified via the
    // DRIFTSTACK_LOG_FONT_RESOLVE diagnostic), unlike the symbolic kCTFontTraitBold which is stripped (W2598). iOS
    // weight-matches the Latin/Indic fallback for ₹/ॿ to the base font's weight: a HEAVY base (DB LCD 0.62, DIN/
    // Bradley Hand 0.40, Hiragino Kaku 0.62) resolves ₹ to Helvetica-Bold (71) + ॿ to Kohinoor-Semibold (75), where
    // a normal base (0.0, incl all the glyphHash/symbol-sweep generics) uses Helvetica (67) / Kohinoor (73). Read
    // the weight here and thread it. (Threshold 0.35 excludes Futura/Hiragino-Sans at 0.23 which want the normal 67.)
    double driftstackBaseWeight = 0;
    if (ctFont) {
        if (RetainPtr traits = adoptCF(CTFontCopyTraits(ctFont.get()))) {
            if (CFNumberRef n = static_cast<CFNumberRef>(CFDictionaryGetValue(traits.get(), kCTFontWeightTrait)))
                CFNumberGetValue(n, kCFNumberDoubleType, &driftstackBaseWeight);
        }
        if (getenv("DRIFTSTACK_LOG_FONT_RESOLVE") && characterCluster.length() && characterCluster[0] == 0x20B9) {
            static unsigned wcount = 0;
            if (wcount++ < 80)
                WTFLogAlways("[Driftstack-BaseWeight] U+20B9 base='%s' weightTrait=%.3f", driftstackBaseFamily.utf8().data(), driftstackBaseWeight);
        }
        // W2609: per-font special-case — the "Hiragino Sans" family (the modern iOS CJK gothic) gets the bold ₹/ॿ
        // fallback at ANY weight (iOS weight-matches to its heavier stroke), UNLIKE "Hiragino Kaku/Maru Gothic Pro"
        // (0.23) which want regular. A broad CJK prefix over-applies (REVERTED); narrowing to "Hiragino Sans" only
        // (exact-family, not "Hiragino Kaku") separates them. The heavy Hiragino Sans W6-W8 already weight-match.
        if (driftstackBaseWeight < 0.35 && driftstackBaseFamily.startsWith("Hiragino Sans"_s))
            driftstackBaseWeight = 0.5;
        // W2828 (#96, cracked via captures/v3/ct-cascade-probe.m sim-vs-Mac diff + the STABLE kCTFontWeightTrait):
        // "SignPainter" is the HouseScript-SEMIBOLD display script — its weight trait reads 0.30 (< the 0.35 heavy
        // threshold), so the fork served ₹/ॿ via the REGULAR fallback (Helvetica 67 / Kohinoor 73). But iOS
        // weight-matches SignPainter's ₹/ॿ to a BOLD fallback (Helvetica-Bold 71 / Kohinoor-Devanagari-Semibold 75 —
        // verified on the iOS-26.5 sim cascade), same as the heavy Hiragino Sans above. Force the heavy path so the
        // fork routes to iOS's bold-matched fallback (a render-fix — correct FONT, not answer-injection). glyphHash-
        // SAFE: SignPainter is a NAMED font, never one of the 6 glyphHash generics (Times/Helvetica/Snell/Papyrus/SF/
        // Menlo). (Impact at 0.62 already trips the threshold → W2608 fixed it; Futura at 0.00 wants regular → unchanged.)
        if (driftstackBaseWeight < 0.35 && driftstackBaseFamily.startsWith("SignPainter"_s))
            driftstackBaseWeight = 0.5;
    }
    if (auto driftstackUniversalFont = driftstackIOSFallbackFontForUniversalSymbolCluster(
            characterCluster, description, platformData.size(), driftstackBaseFontIsMonospace, driftstackBaseIsCursive, driftstackBaseIsFantasy, driftstackBaseIsSansSerif, driftstackBaseWeight, driftstackBaseIsSerif, driftstackBaseFamily)) {
        static unsigned hitCount = 0;
        if (++hitCount <= 8)
            WTFLogAlways("[Driftstack-V433Z-UniversalSymbol] Universal-symbol fallback override fired (%u so far); cluster first cp = U+%04X",
                hitCount, (unsigned)characterCluster[0]);
        result = WTF::move(driftstackUniversalFont);
    // Track 9 / V-161: short-circuit Mac's fallback resolution to prefer the
    // iOS Hangul font binary (AppleSDGothicNeo from Stage B). When the cluster
    // is Hangul and the override font loads, it replaces Mac's pick BEFORE
    // preparePlatformFont normalizes the result. If the cluster is not Hangul
    // OR AppleSDGothicNeo isn't installed, this is a no-op.
    } else if (auto driftstackHangulFont = driftstackIOSFallbackFontForHangulCluster(
            characterCluster, description, platformData.size())) {
        static unsigned hitCount = 0;
        if (++hitCount <= 8)
            WTFLogAlways("[Driftstack-Track9] Hangul fallback override fired (%u so far); cluster first cp = U+%04X",
                hitCount, (unsigned)characterCluster[0]);
        result = WTF::move(driftstackHangulFont);
    // Track 10 Hebrew dispatch removed post-V-165 validation (see comment block
    // above driftstackIOSFallbackFontForDevanagariCluster). Re-enable when
    // per-context (sans-serif vs serif) discrimination is plumbed through.
    } else if (auto driftstackDevanagariFont = driftstackIOSFallbackFontForDevanagariCluster(
            characterCluster, description, platformData.size())) {
        static unsigned hitCount = 0;
        if (++hitCount <= 8)
            WTFLogAlways("[Driftstack-Track10-Devanagari] Devanagari fallback override fired (%u so far); cluster first cp = U+%04X",
                hitCount, (unsigned)characterCluster[0]);
        result = WTF::move(driftstackDevanagariFont);
    } else if (auto driftstackHebrewFont = driftstackIOSFallbackFontForHebrewCluster(
            characterCluster, description, platformData.familyName(), platformData.size())) {
        // Env-var-gated: DRIFTSTACK_TRACK10_HEBREW=1 (V-174 / V-178). Per-context
        // discrimination via originatingFamily — only fires for sans-serif.
        static unsigned hitCount = 0;
        if (++hitCount <= 8)
            WTFLogAlways("[Driftstack-Track10-Hebrew] Hebrew fallback override fired (%u so far); cluster first cp = U+%04X originatingFamily=%s",
                hitCount, (unsigned)characterCluster[0], platformData.familyName().utf8().data());
        result = WTF::move(driftstackHebrewFont);
    } else if (auto driftstackCJKFont = driftstackIOSFallbackFontForCJKCluster(
            characterCluster, description, platformData.size())) {
        // Env-var-gated: DRIFTSTACK_TRACK7_CANDIDATE_D=1
        static unsigned hitCount = 0;
        if (++hitCount <= 8)
            WTFLogAlways("[Driftstack-Track7d-CJK] CJK fallback override fired (%u so far); cluster first cp = U+%04X",
                hitCount, (unsigned)characterCluster[0]);
        result = WTF::move(driftstackCJKFont);
    } else if (auto driftstackEmojiFont = driftstackIOSFallbackFontForEmojiCluster(
            characterCluster, description, platformData.size())) {
        // Env-var-gated: DRIFTSTACK_TRACK7_CANDIDATE_D=1
        static unsigned hitCount = 0;
        if (++hitCount <= 8)
            WTFLogAlways("[Driftstack-Track7d-Emoji] Emoji fallback override fired (%u so far); cluster first cp = U+%04X",
                hitCount, (unsigned)characterCluster[0]);
        result = WTF::move(driftstackEmojiFont);
    }
#endif
    result = preparePlatformFont(UnrealizedCoreTextFont { WTF::move(result) }, description, { });

    if (!result)
        return lastResortFallbackFont(description);

    // FontCascade::drawGlyphBuffer() requires that there are no duplicate Font objects which refer to the same thing. This is enforced in
    // FontCache::fontForPlatformData(), where our equality check is based on hashing the FontPlatformData, whose hash includes the raw CoreText
    // font pointer.
    RetainPtr substituteFont = m_fallbackFonts.add(result).iterator->get();

    auto [syntheticBold, syntheticOblique] = computeNecessarySynthesis(substituteFont.get(), description, { }, ShouldComputePhysicalTraits::No, isForPlatformFont == IsForPlatformFont::Yes).boldObliquePair();

    RefPtr<const FontCustomPlatformData> customPlatformData = nullptr;
    if (safeCFEqual(ctFont.get(), substituteFont.get()))
        customPlatformData = platformData.customPlatformData();
    FontPlatformData alternateFont(substituteFont.get(), platformData.size(), syntheticBold, syntheticOblique, platformData.orientation(), platformData.widthVariant(), platformData.textRenderingMode(), customPlatformData.get());

    return fontForPlatformData(alternateFont);
}

ASCIILiteral FontCache::platformAlternateFamilyName(const String& familyName)
{
    static const char16_t heitiString[] = { 0x9ed1, 0x4f53 };
    static const char16_t songtiString[] = { 0x5b8b, 0x4f53 };
    static const char16_t weiruanXinXiMingTi[] = { 0x5fae, 0x8edf, 0x65b0, 0x7d30, 0x660e, 0x9ad4 };
    static const char16_t weiruanYaHeiString[] = { 0x5fae, 0x8f6f, 0x96c5, 0x9ed1 };
    static const char16_t weiruanZhengHeitiString[] = { 0x5fae, 0x8edf, 0x6b63, 0x9ed1, 0x9ad4 };

    static constexpr ASCIILiteral songtiSC = "Songti SC"_s;
    static constexpr ASCIILiteral songtiTC = "Songti TC"_s;
    static constexpr ASCIILiteral heitiSCReplacement = "PingFang SC"_s;
    static constexpr ASCIILiteral heitiTCReplacement = "PingFang TC"_s;

    switch (familyName.length()) {
    case 2:
        if (equal(familyName, songtiString))
            return songtiSC;
        if (equal(familyName, heitiString))
            return heitiSCReplacement;
        break;
    case 4:
        if (equal(familyName, weiruanYaHeiString))
            return heitiSCReplacement;
        break;
    case 5:
        if (equal(familyName, weiruanZhengHeitiString))
            return heitiTCReplacement;
        break;
    case 6:
        if (equalLettersIgnoringASCIICase(familyName, "simsun"_s))
            return songtiSC;
        if (equal(familyName, weiruanXinXiMingTi))
            return songtiTC;
        break;
    case 10:
        if (equalLettersIgnoringASCIICase(familyName, "ms mingliu"_s))
            return songtiTC;
        if (equalIgnoringASCIICase(familyName, "\\5b8b\\4f53"_s))
            return songtiSC;
        break;
    case 18:
        if (equalLettersIgnoringASCIICase(familyName, "microsoft jhenghei"_s))
            return heitiTCReplacement;
        break;
    }

    return { };
}

void addAttributesForInstalledFonts(CFMutableDictionaryRef attributes, AllowUserInstalledFonts allowUserInstalledFonts)
{
    if (allowUserInstalledFonts == AllowUserInstalledFonts::No) {
        CFDictionaryAddValue(attributes, kCTFontUserInstalledAttribute, kCFBooleanFalse);
        CTFontFallbackOption fallbackOption = kCTFontFallbackOptionSystem;
        auto fallbackOptionNumber = adoptCF(CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt64Type, &fallbackOption));
        CFDictionaryAddValue(attributes, kCTFontFallbackOptionAttribute, fallbackOptionNumber.get());
    }
}

RetainPtr<CTFontRef> createFontForInstalledFonts(CTFontDescriptorRef fontDescriptor, CGFloat size, AllowUserInstalledFonts allowUserInstalledFonts)
{
    auto attributes = adoptCF(CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks));
    addAttributesForInstalledFonts(attributes.get(), allowUserInstalledFonts);
    if (CFDictionaryGetCount(attributes.get())) {
        auto resultFontDescriptor = adoptCF(CTFontDescriptorCreateCopyWithAttributes(fontDescriptor, attributes.get()));
        return adoptCF(CTFontCreateWithFontDescriptor(resultFontDescriptor.get(), size, nullptr));
    }
    return adoptCF(CTFontCreateWithFontDescriptor(fontDescriptor, size, nullptr));
}

static inline bool isFontMatchingUserInstalledFontFallback(CTFontRef font, AllowUserInstalledFonts allowUserInstalledFonts)
{
    bool willFallbackToSystemOnly = false;
    if (auto fontFallbackOptionAttributeRef = adoptCF(static_cast<CFNumberRef>(CTFontCopyAttribute(font, kCTFontFallbackOptionAttribute)))) {
        int64_t fontFallbackOptionAttribute;
        CFNumberGetValue(fontFallbackOptionAttributeRef.get(), kCFNumberSInt64Type, &fontFallbackOptionAttribute);
        willFallbackToSystemOnly = fontFallbackOptionAttribute == kCTFontFallbackOptionSystem;
    }

    bool shouldFallbackToSystemOnly = allowUserInstalledFonts == AllowUserInstalledFonts::No;
    return willFallbackToSystemOnly == shouldFallbackToSystemOnly;
}

RetainPtr<CTFontRef> createFontForInstalledFonts(CTFontRef font, AllowUserInstalledFonts allowUserInstalledFonts)
{
    if (isFontMatchingUserInstalledFontFallback(font, allowUserInstalledFonts))
        return font;

    auto attributes = adoptCF(CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks));
    addAttributesForInstalledFonts(attributes.get(), allowUserInstalledFonts);
    if (CFDictionaryGetCount(attributes.get())) {
        auto modification = adoptCF(CTFontDescriptorCreateWithAttributes(attributes.get()));
        return adoptCF(CTFontCreateCopyWithAttributes(font, CTFontGetSize(font), nullptr, modification.get()));
    }
    return font;
}

void addAttributesForWebFonts(CFMutableDictionaryRef attributes, AllowUserInstalledFonts allowUserInstalledFonts)
{
    if (allowUserInstalledFonts == AllowUserInstalledFonts::No) {
        CTFontFallbackOption fallbackOption = kCTFontFallbackOptionSystem;
        auto fallbackOptionNumber = adoptCF(CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt64Type, &fallbackOption));
        CFDictionaryAddValue(attributes, kCTFontFallbackOptionAttribute, fallbackOptionNumber.get());
    }
}

RetainPtr<CFSetRef> installedFontMandatoryAttributes(AllowUserInstalledFonts allowUserInstalledFonts)
{
    if (allowUserInstalledFonts == AllowUserInstalledFonts::No) {
        CFTypeRef mandatoryAttributesValues[] = { kCTFontFamilyNameAttribute, kCTFontPostScriptNameAttribute, kCTFontEnabledAttribute, kCTFontUserInstalledAttribute, kCTFontFallbackOptionAttribute };
        return adoptCF(CFSetCreate(kCFAllocatorDefault, mandatoryAttributesValues, std::size(mandatoryAttributesValues), &kCFTypeSetCallBacks));
    }
    return nullptr;
}

Ref<Font> FontCache::lastResortFallbackFont(const FontDescription& fontDescription)
{
    // FIXME: Would be even better to somehow get the user's default font here.  For now we'll pick
    // the default that the user would get without changing any prefs.
    if (auto result = fontForFamily(fontDescription, AtomString("Times"_s)))
        return *result;

    // LastResort is guaranteed to be non-null.
    auto fontDescriptor = adoptCF(CTFontDescriptorCreateLastResort());
    auto font = adoptCF(CTFontCreateWithFontDescriptor(fontDescriptor.get(), fontDescription.computedSize(), nullptr));
    auto [syntheticBold, syntheticOblique] = computeNecessarySynthesis(font.get(), fontDescription).boldObliquePair();
    FontPlatformData platformData(font.get(), fontDescription.computedSize(), syntheticBold, syntheticOblique, fontDescription.orientation(), fontDescription.widthVariant(), fontDescription.textRenderingMode());
    return fontForPlatformData(platformData);
}

FontCache::PrewarmInformation FontCache::collectPrewarmInformation() const
{
    return { copyToVector(m_seenFamiliesForPrewarming), copyToVector(m_fontNamesRequiringSystemFallbackForPrewarming) };
}

void FontCache::prewarm(PrewarmInformation&& prewarmInformation)
{
    if (prewarmInformation.isEmpty())
        return;

    if (!m_prewarmQueue)
        lazyInitialize(m_prewarmQueue, WorkQueue::create("WebKit font prewarm queue"_s));

    m_prewarmQueue->dispatch([&database = m_databaseDisallowingUserInstalledFonts, prewarmInformation = WTF::move(prewarmInformation).isolatedCopy()] {
        for (auto& family : prewarmInformation.seenFamilies)
            database.collectionForFamily(family);

        for (auto& fontName : prewarmInformation.fontNamesRequiringSystemFallback) {
            auto cfFontName = fontName.createCFString();
            if (auto warmingFont = adoptCF(CTFontCreateWithName(cfFontName.get(), 0, nullptr))) {
                // This is sufficient to warm CoreText caches for language and character specific fallbacks.
                CFIndex coveredLength = 0;
                UniChar character = ' ';

                auto fallbackWarmingFont = adoptCF(CTFontCreateForCharactersWithLanguageAndOption(warmingFont.get(), &character, 1, nullptr, kCTFontFallbackOptionSystem, &coveredLength));
            }
        }
    });
}

#if PLATFORM(DRIFTSTACK)
// W2625: a real iPhone has every system font loaded at boot, so its DOM geometry is deterministic.
// The fork's lazily-loaded fallback fonts (cursive/fantasy/CJK/Hebrew/Thai/Indic/combining-mark) warm
// only on first render, so a codepoint's COLD (first-render) advance/line-box can differ from its WARM
// value — a run-to-run non-determinism a real iPhone never shows (observed on Cyrillic-Ext-A combining
// marks: serif line box 22 cold vs 21 warm). On this platform the upstream prewarm is compiled out
// (HAVE(STATIC_FONT_REGISTRY)). So warm the full fork fallback set + the CoreText per-character system-
// fallback cache (the lazy/non-deterministic path used by systemFallbackForCharacterCluster) for a
// representative span of warming-sensitive codepoints at WebProcess startup, once — every later page
// render is then already warm = deterministic = iPhone-like. Cheap (~20 fonts x ~30 cps) and run-once.
static void driftstackPrewarmFonts()
{
    // Run-once via C++11 thread-safe function-local static init (no <mutex> — it conflicts in this TU).
    static bool warmed = [] {
        static constexpr std::array<ASCIILiteral, 24> families { {
            "Helvetica"_s, "Times New Roman"_s, "Courier"_s, "Courier New"_s, "Menlo"_s,
            "Snell Roundhand"_s, "Papyrus"_s, ".AppleSystemUIFont"_s, ".SF Hebrew"_s, "Arial Hebrew"_s,
            "Hiragino Sans"_s, "Hiragino Mincho ProN"_s, "Songti SC"_s, "PingFang SC"_s, "Thonburi"_s,
            "Apple Color Emoji"_s, "Apple Symbols"_s, "STIX Two Math"_s, "Noto Sans Kannada"_s,
            "Lucida Grande"_s, "Kohinoor Devanagari"_s, "Kohinoor Bangla"_s, "Mishafi"_s, "Kailasa"_s,
        } };
        // One representative codepoint per fallback-font class is enough (loading a font warms all its
        // glyphs): combining marks across scripts + exotic letters/ligatures + CJK/kana/bopomofo + symbols.
        static constexpr std::array<char32_t, 32> warmCps { {
            0x0300, 0x0301, 0x0653, 0x05B0, 0x064B, 0x0901, 0x093C, 0x0E31, 0x0E48, 0x0F39,
            0x1AB0, 0x1DC0, 0x20D0, 0x2DE0, 0x2DFF, 0x302A, 0xFE20, 0x1EFA, 0xFB00, 0xFB13,
            0x2C60, 0x4E00, 0x3041, 0x30A1, 0x3105, 0xA000, 0x2460, 0x2070, 0x2155, 0x2500,
            0x2E80, 0x25CA,
        } };
        for (auto family : families) {
            RetainPtr<CFStringRef> name = String(family).createCFString();
            RetainPtr<CTFontRef> base = adoptCF(CTFontCreateWithName(name.get(), 16, nullptr));
            if (!base)
                continue;
            for (char32_t cp : warmCps) {
                UniChar buf[2];
                CFIndex len = 0;
                if (cp > 0xFFFF) {
                    char32_t c = cp - 0x10000;
                    buf[0] = static_cast<UniChar>(0xD800 + (c >> 10));
                    buf[1] = static_cast<UniChar>(0xDC00 + (c & 0x3FF));
                    len = 2;
                } else {
                    buf[0] = static_cast<UniChar>(cp);
                    len = 1;
                }
                CFIndex covered = 0;
                // Warms CoreText's per-character system-fallback cache (the lazy/non-deterministic path).
                RetainPtr<CTFontRef> warmFallback = adoptCF(CTFontCreateForCharactersWithLanguageAndOption(base.get(), buf, len, nullptr, kCTFontFallbackOptionSystem, &covered));
                (void)warmFallback;
            }
        }
        return true;
    }();
    (void)warmed;
}
#endif

void FontCache::prewarmGlobally()
{
#if PLATFORM(DRIFTSTACK)
    driftstackPrewarmFonts();
#endif
#if !HAVE(STATIC_FONT_REGISTRY)
    if (MemoryPressureHandler::singleton().isUnderMemoryPressure())
        return;

    Vector<String> families {
#if PLATFORM(MAC) || PLATFORM(MACCATALYST)
        ".SF NS Text"_s,
        ".SF NS Display"_s,
#endif
        "Arial"_s,
        "Helvetica"_s,
        "Helvetica Neue"_s,
        "Lucida Grande"_s,
        "Times"_s,
        "Times New Roman"_s,
    };

    FontCache::PrewarmInformation prewarmInfo;
    prewarmInfo.seenFamilies = WTF::move(families);
    protect(FontCache::forCurrentThread())->prewarm(WTF::move(prewarmInfo));
#endif
}

void FontCache::platformReleaseNoncriticalMemory()
{
    // FIXME(https://bugs.webkit.org/show_bug.cgi?id=251560): We should be calling invalidate() on all platforms, but this causes a memory regression on iOS.
#if PLATFORM(MAC)
    invalidate();
#else
    m_systemFontDatabaseCoreText.clear();
    m_fontFamilySpecificationCoreTextCache.clear();
#endif
}

HashMap<String, URL>& userInstalledFontMap()
{
    static NeverDestroyed<HashMap<String, URL>> fontMap;
    return fontMap.get();
}

HashMap<String, Vector<String>>& userInstalledFontFamilyMap()
{
    static NeverDestroyed<HashMap<String, Vector<String>>> fontFamilyMap;
    return fontFamilyMap.get();
}

Lock& userInstalledFontMapLock()
{
    static Lock lock;
    return lock;
}

}
