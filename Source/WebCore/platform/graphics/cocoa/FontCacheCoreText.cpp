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
#include <string>
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

static void driftstackWalkFontDir(const std::string& root, MemoryCompactRobinHoodHashMap<String, Vector<DriftstackIOSFontVariant>>& map, size_t& mappedCount, size_t& parseFailedCount)
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
            driftstackWalkFontDir(fullPath, map, mappedCount, parseFailedCount);
            continue;
        }

        if (!name.endsWithIgnoringASCIICase(".ttf"_s)
            && !name.endsWithIgnoringASCIICase(".ttc"_s)
            && !name.endsWithIgnoringASCIICase(".otf"_s))
            continue;

        RetainPtr<CFStringRef> pathCF = adoptCF(CFStringCreateWithCString(kCFAllocatorDefault, fullPath.c_str(), kCFStringEncodingUTF8));
        RetainPtr<CFURLRef> fontURL = adoptCF(CFURLCreateWithFileSystemPath(kCFAllocatorDefault, pathCF.get(), kCFURLPOSIXPathStyle, false));
        if (!fontURL)
            continue;

        // Process-scope registration so CTFont creation paths can resolve the binary.
        CFErrorRef regError = nullptr;
        CTFontManagerRegisterFontsForURL(fontURL.get(), kCTFontManagerScopeProcess, &regError);
        if (regError)
            CFRelease(regError);

        // Read all variants in the binary (.ttc collections may contain multiple)
        // and add each (family, weight, italic) tuple into the map.
        RetainPtr<CFArrayRef> descs = adoptCF(CTFontManagerCreateFontDescriptorsFromURL(fontURL.get()));
        if (!descs) {
            ++parseFailedCount;
            // V-487: log which font binary CTFontManager failed to parse.
            WTFLogAlways("[Driftstack-V487-PARSEFAIL] %s", fullPath.c_str());
            continue;
        }
        CFIndex count = CFArrayGetCount(descs.get());
        for (CFIndex i = 0; i < count; ++i) {
            CTFontDescriptorRef desc = static_cast<CTFontDescriptorRef>(CFArrayGetValueAtIndex(descs.get(), i));
            RetainPtr<CFStringRef> familyCF = adoptCF(static_cast<CFStringRef>(CTFontDescriptorCopyAttribute(desc, kCTFontFamilyNameAttribute)));
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
            }
            // iPhone-canonical face-name allowlist for archetype
            // iphone17_ios18_7_safari26_4. Derived from BS Automate
            // iPhone 17 / iOS 18.7 / Safari 26.4 v433y capture diff
            // (252 detected vs fork pre-fix 216 → 37 face variants
            // iPhone exposes that Mac CTFont descriptor parsing collapses
            // into the parent family). Lowercase, exact-match.
            static const std::array<const char*, 37> kIPhoneCanonicalFaceNames = {
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
    std::string root = envDir ? envDir : "/Users/john/code/driftstack-fonts/iphone16pro-ios26.4.1";

    struct stat st;
    if (stat(root.c_str(), &st) != 0 || !S_ISDIR(st.st_mode)) {
        WTFLogAlways("[Driftstack] FontCache: iOS fonts dir not found at %s — skipping override map population", root.c_str());
        return;
    }

    size_t mapped = 0;
    size_t parseFailed = 0;
    driftstackWalkFontDir(root, driftstackIOSFontMap(), mapped, parseFailed);
    WTFLogAlways("[Driftstack] FontCache: %zu families mapped to iOS font binaries (parseFailed=%zu, dir=%s)", mapped, parseFailed, root.c_str());

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
    // Wave 29-407.7 (2026-05-20): family-of-archetype detection. Empirical
    // (BS Automate 5/5 captures) iPhone Safari 18.6 (Family A) does NOT
    // detect these 4 Indic-script fonts as present (per offsetWidth probe).
    // The Helvetica alias above PRODUCES a false positive on Family A
    // (Mac fork renders with Helvetica metrics ≠ monospace baseline, so
    // detection triggers as present). For Family A archetypes, return
    // nullptr instead so the natural cascade falls through to monospace
    // baseline (matches iPhone Safari 18.6).
    static const bool s_isFamilyAArchetype = []() {
        const char* archetype = getenv("DRIFTSTACK_ARCHETYPE");
        if (!archetype)
            return false;
        std::string_view sv(archetype);
        return sv.find("safari17_") != std::string_view::npos
            || sv.find("safari18_") != std::string_view::npos
            || sv.find("safari19_") != std::string_view::npos
            || sv.find("safari20_") != std::string_view::npos
            || sv.find("safari21_") != std::string_view::npos
            || sv.find("safari22_") != std::string_view::npos
            || sv.find("safari23_") != std::string_view::npos
            || sv.find("safari24_") != std::string_view::npos
            || sv.find("safari25_") != std::string_view::npos;
    }();
    if (s_isFamilyAArchetype) {
        if (lowercase == "gujarati sangam mn"_s
            || lowercase == "oriya sangam mn"_s
            || lowercase == "plantagenet cherokee"_s
            || lowercase == "gurmukhi mn"_s)
            return nullptr;
    }
    if (lowercase == "kefa"_s
        || lowercase == "gujarati sangam mn"_s
        || lowercase == "oriya sangam mn"_s
        || lowercase == "plantagenet cherokee"_s
        || lowercase == "gurmukhi mn"_s)
        lowercase = "helvetica"_s;
    // V-479 Times-family alias (V-442 TRIGGER C closure 2026-05-08):
    // iOS Stage B install ships TimesNewRoman.ttf, registered under
    // family 'times new roman'. Mac CSS and CT_FONT_NAME 'Times'
    // doesn't directly map to it. iPhone resolves CSS 'Times' to
    // TimesNewRoman.ttf via family alias; mirror that here so V-442
    // Stage B audit moves Times from MAC_DEFAULT_FAIL → STAGE_B_PASS.
    else if (lowercase == "times"_s)
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
    CFIndex count = CFArrayGetCount(descs.get());
    for (CFIndex i = 0; i < count; ++i) {
        CTFontDescriptorRef d = static_cast<CTFontDescriptorRef>(CFArrayGetValueAtIndex(descs.get(), i));
        RetainPtr<CFStringRef> familyCF = adoptCF(static_cast<CFStringRef>(CTFontDescriptorCopyAttribute(d, kCTFontFamilyNameAttribute)));
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
    static const std::array<const char*, 7> kIOSCanonicalSharedGlyphFamilies = {
        "pingfang hk",
        "pingfang sc",
        "pingfang tc",
        "heiti sc",
        "heiti tc",
        "applesdgothicneo",
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
static RetainPtr<CTFontRef> driftstackIOSFallbackFontForUniversalSymbolCluster(StringView cluster, const FontDescription& description, float size)
{
    if (cluster.isEmpty())
        return nullptr;
    char32_t cp = cluster[0];
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
    case 0x20B9: { // Indian Rupee Sign — iPhone width 37 (703/713)
        // Wave 29-219 fontTools cmap: U+20B9 in Carlito + Chalkboard SE.
        // Not in .SF UI as previously assumed.
        static const std::array<ASCIILiteral, 4> candidates {
            "carlito"_s, "chalkboard se"_s, ".sf ui"_s, "apple symbols"_s,
        };
        return driftstackLookupIOSFontByCandidates(candidates, description, size);
    }
    case 0xFFFD:   // Replacement Character — iPhone width 43 (710/713)
    case 0x21E4: { // Leftwards Arrow To Bar — iPhone width 43 (712/713)
        // Family in AppleSymbols.ttf: "Apple Symbols"
        static const std::array<ASCIILiteral, 2> candidates {
            "apple symbols"_s, ".sf ui"_s,
        };
        return driftstackLookupIOSFontByCandidates(candidates, description, size);
    }
    case 0x20E3: { // Combining Enclosing Keycap — iPhone width 72 (711/713)
        // Family in SFUISymbols-Regular.otf: ".SF UI Symbols"
        static const std::array<ASCIILiteral, 3> candidates {
            ".sf ui symbols"_s, "apple symbols"_s, ".sf ui"_s,
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
    if (auto driftstackUniversalFont = driftstackIOSFallbackFontForUniversalSymbolCluster(
            characterCluster, description, platformData.size())) {
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

void FontCache::prewarmGlobally()
{
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
