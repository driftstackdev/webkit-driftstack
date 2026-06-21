/*
 * V-770.A.1 — DriftstackTextRunAtlas scaffold impl.
 *
 * v1: empty atlas, lookup() always returns nullopt. Helpers compute
 * text-run hash + position class + font ID mapping.
 */
#include "config.h"
#include "DriftstackTextRunAtlas.h"

#if PLATFORM(DRIFTSTACK)

#include "Font.h"
#include "FloatPoint.h"
#include "FontPlatformData.h"
#include <CoreText/CoreText.h>
#include <wtf/FastMalloc.h>
#include <wtf/RetainPtr.h>
#include <wtf/NeverDestroyed.h>
#include <wtf/text/CString.h>
#include <wtf/text/StringHasher.h>
#include <wtf/text/StringView.h>
#include <wtf/ThreadSpecific.h>
#include <algorithm>
#include <atomic>
#include <cmath>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <sys/mman.h>
#include <cerrno>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <string>

namespace WebCore {

#if PLATFORM(DRIFTSTACK)
// V-211: the dev-default data path derives from the environment
// (DRIFTSTACK_DATA_ROOT, else $HOME/code/driftstack) instead of a hardcoded
// build-machine home directory. One-time strdup, process lifetime.
static const char* textRunAtlasDefaultPath(const char* relative)
{
    const char* root = std::getenv("DRIFTSTACK_DATA_ROOT");
    const char* home = std::getenv("HOME");
    std::string p = (root && *root) ? std::string(root) : std::string(home ? home : "") + "/code/driftstack";
    p += relative;
    return ::strdup(p.c_str());
}

// TD-V-NNN-J.1 (wave 29-222 founder-approved 2026-05-15): scan
// reference/ for archetype-suffixed atlas files and pick the matching
// one by runtime archetype.
//
// Naming convention: driftstack_text_run_atlas_<archetype-slug>_v<N>.bin
// Highest <N> wins per archetype.
//
// Selection priority:
//   1. DRIFTSTACK_TEXT_RUN_ATLAS_PATH env var (explicit override; tests)
//   2. Scan reference/ for files matching driftstack_text_run_atlas_<slug>_v*.bin
//      where <slug> = DRIFTSTACK_ARCHETYPE_SLUG env var
//   3. Legacy default: driftstack_text_run_atlas_v1.bin (back-compat)
//
// Returns full path of best-version atlas file matching runtime archetype,
// or empty string if no match.
static std::string resolveArchetypeAtlasPath()
{
    const char* slug = std::getenv("DRIFTSTACK_ARCHETYPE_SLUG");
    if (!slug || !*slug)
        return {};

    const char* dir = std::getenv("DRIFTSTACK_REFERENCE_DIR");
    if (!dir || !*dir) {
        static const char* defaultDir = textRunAtlasDefaultPath("/reference");
        dir = defaultDir;
    }

    DIR* d = ::opendir(dir);
    if (!d)
        return {};

    std::string prefix = std::string("driftstack_text_run_atlas_") + slug + "_v";
    std::string bestName;
    int bestVer = -1;

    while (struct dirent* e = ::readdir(d)) {
        std::string name(e->d_name);
        if (name.size() < prefix.size() + 4) continue;
        if (name.compare(0, prefix.size(), prefix) != 0) continue;
        if (name.compare(name.size() - 4, 4, ".bin") != 0) continue;
        std::string vs = name.substr(prefix.size(), name.size() - prefix.size() - 4);
        if (vs.empty()) continue;
        bool allDigits = true;
        int v = 0;
        for (char c : vs) {
            if (c < '0' || c > '9') { allDigits = false; break; }
            v = v * 10 + (c - '0');
        }
        if (!allDigits) continue;
        if (v > bestVer) { bestVer = v; bestName = name; }
    }
    ::closedir(d);

    if (bestVer < 0)
        return {};
    return std::string(dir) + "/" + bestName;
}
#endif

DriftstackTextRunAtlas& DriftstackTextRunAtlas::singleton()
{
    static DriftstackTextRunAtlas instance;
    // V-770.A.2: lazy auto-load on first access. Idempotent; failure is
    // soft (lookup() falls through to miss path, Mac CG renders natively).
    if (!instance.m_loaded)
        instance.loadFromFile(nullptr);
    return instance;
}

WTF_ALLOW_UNSAFE_BUFFER_USAGE_BEGIN
bool DriftstackTextRunAtlas::loadFromFile(const char* path)
{
    if (m_loaded)
        return true;

    // Direct-browse (human inspection) mode: skip the canvas-fingerprint text-run
    // atlas so page text renders natively (see DriftstackAsciiAtlas::mapAtlas for
    // rationale). Leaving m_loaded false keeps lookup() returning nullopt → native.
    const char* db = std::getenv("DRIFTSTACK_DIRECT_BROWSE");
    const char* bm = std::getenv("DRIFTSTACK_BROWSE");
    if ((db && db[0] == '1') || (bm && bm[0] == '1'))
        return false;

    const char* resolved = path;
    if (!resolved)
        resolved = std::getenv("DRIFTSTACK_TEXT_RUN_ATLAS_PATH");
    // TD-V-NNN-J.1: try archetype-suffixed file before legacy default.
    std::string archetypeOwned;
    if (!resolved) {
        archetypeOwned = resolveArchetypeAtlasPath();
        if (!archetypeOwned.empty()) resolved = archetypeOwned.c_str();
    }
    if (!resolved) {
        static const char* legacyDefault = textRunAtlasDefaultPath("/reference/driftstack_text_run_atlas_v1.bin");
        resolved = legacyDefault;
    }

    bool diag = std::getenv("DRIFTSTACK_TEXT_RUN_ATLAS_DIAG") != nullptr;
    int fd = ::open(resolved, O_RDONLY);
    if (fd < 0) {
        if (diag) WTFLogAlways("[Driftstack-V770A.LOAD] open('%s') failed errno=%d", resolved, errno);
        return false;
    }
    if (diag) WTFLogAlways("[Driftstack-V770A.LOAD] open('%s') fd=%d", resolved, fd);

    struct stat st;
    if (::fstat(fd, &st) != 0 || st.st_size < 16) {
        ::close(fd);
        return false;
    }

    void* base = ::mmap(nullptr, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    ::close(fd);
    if (base == MAP_FAILED)
        return false;

    const uint8_t* p = static_cast<const uint8_t*>(base);
    const uint8_t* end = p + st.st_size;

    // 1. Magic "DSCFA2"
    if (p + 6 > end || std::memcmp(p, "DSCFA2", 6) != 0) {
        ::munmap(base, st.st_size);
        return false;
    }
    p += 6;

    // 2. Header: version u16, archetype u16, iOS triplet u8×3
    if (p + 7 > end) { ::munmap(base, st.st_size); return false; }
    uint16_t version; std::memcpy(&version, p, 2); p += 2;
    if (version != 2) { ::munmap(base, st.st_size); return false; }
    uint16_t archetypeId; std::memcpy(&archetypeId, p, 2); p += 2;
    uint8_t iosMaj = *p; ++p;
    uint8_t iosMin = *p; ++p;
    uint8_t iosPat = *p; ++p;

    // 3. Font table — index into FontTableEntry array (V-770.A.3).
    if (p + 2 > end) { ::munmap(base, st.st_size); return false; }
    uint16_t nFonts; std::memcpy(&nFonts, p, 2); p += 2;
    if (nFonts > 0) {
        m_fontTable = static_cast<FontTableEntry*>(WTF::fastMalloc(sizeof(FontTableEntry) * nFonts));
        if (!m_fontTable) { ::munmap(base, st.st_size); return false; }
    }
    for (uint16_t i = 0; i < nFonts; ++i) {
        if (p + 3 > end) { ::munmap(base, st.st_size); return false; }
        uint16_t fid; std::memcpy(&fid, p, 2); p += 2;
        uint8_t nameLen = *p; p += 1;
        if (p + nameLen > end) { ::munmap(base, st.st_size); return false; }
        m_fontTable[i].fontId = fid;
        m_fontTable[i].nameBytes = reinterpret_cast<const char*>(p);
        m_fontTable[i].nameLen = nameLen;
        p += nameLen;
    }
    m_fontTableCount = nFonts;

    // 4. Text-run index
    if (p + 4 > end) { ::munmap(base, st.st_size); return false; }
    uint32_t nTextRun; std::memcpy(&nTextRun, p, 4); p += 4;

    constexpr size_t kTextRunStride = 2 + 2 + 1 + 8 + 4 + 4 + 4 * 5; // 39
    if (p + size_t(nTextRun) * kTextRunStride > end) {
        ::munmap(base, st.st_size); return false;
    }

    // Allocate parallel arrays for keys + entries.
    if (nTextRun > 0) {
        m_textRunKeys = static_cast<PackedKey*>(WTF::fastMalloc(sizeof(PackedKey) * nTextRun));
        m_textRunEntries = static_cast<TextRunEntry*>(WTF::fastMalloc(sizeof(TextRunEntry) * nTextRun));
        if (!m_textRunKeys || !m_textRunEntries) {
            if (m_textRunKeys) WTF::fastFree(m_textRunKeys);
            if (m_textRunEntries) WTF::fastFree(m_textRunEntries);
            m_textRunKeys = nullptr;
            m_textRunEntries = nullptr;
            ::munmap(base, st.st_size);
            return false;
        }
    }

    // Count per-bucket for prefix-sum layout (sorted-by-bucket arrays).
    uint32_t bucketCount[kBucketCount] {};
    const uint8_t* records = p;
    for (uint32_t i = 0; i < nTextRun; ++i) {
        const uint8_t* rec = records + size_t(i) * kTextRunStride;
        uint64_t hash; std::memcpy(&hash, rec + 5, 8);
        uint32_t bucket = static_cast<uint32_t>(hash) & kBucketMask;
        bucketCount[bucket]++;
    }
    // Prefix sums.
    uint32_t running = 0;
    for (size_t b = 0; b < kBucketCount; ++b) {
        m_buckets[b].first = running;
        m_buckets[b].count = bucketCount[b];
        running += bucketCount[b];
    }
    // Cursor per bucket for insertion.
    uint32_t bucketCursor[kBucketCount] {};
    for (uint32_t i = 0; i < nTextRun; ++i) {
        const uint8_t* rec = records + size_t(i) * kTextRunStride;
        uint16_t fontId; std::memcpy(&fontId, rec + 0, 2);
        uint16_t ptSize; std::memcpy(&ptSize, rec + 2, 2);
        uint8_t pos = *(rec + 4);
        uint64_t hash; std::memcpy(&hash, rec + 5, 8);
        uint32_t off; std::memcpy(&off, rec + 13, 4);
        uint32_t sz;  std::memcpy(&sz,  rec + 17, 4);
        float abbL, abbR, abbA, abbD, w;
        std::memcpy(&abbL, rec + 21, 4);
        std::memcpy(&abbR, rec + 25, 4);
        std::memcpy(&abbA, rec + 29, 4);
        std::memcpy(&abbD, rec + 33, 4);
        std::memcpy(&w,    rec + 37, 4);
        uint32_t bucket = static_cast<uint32_t>(hash) & kBucketMask;
        uint32_t slot = m_buckets[bucket].first + bucketCursor[bucket]++;
        m_textRunKeys[slot] = PackedKey { fontId, ptSize, pos, hash };
        m_textRunEntries[slot] = TextRunEntry { off, sz, abbL, abbR, abbA, abbD, w };
    }
    m_textRunEntryCount = nTextRun;
    p = records + size_t(nTextRun) * kTextRunStride;

    // 5. Skip per-glyph index (handled elsewhere by DriftstackTextGlyphAtlas).
    if (p + 4 > end) { ::munmap(base, st.st_size); return false; }
    uint32_t nPerGlyph; std::memcpy(&nPerGlyph, p, 4); p += 4;
    constexpr size_t kPerGlyphStride = 2 + 2 + 4 + 1 + 4 + 4 + 4 * 5; // 37
    p += size_t(nPerGlyph) * kPerGlyphStride;
    if (p > end) { ::munmap(base, st.st_size); return false; }

    // 6. Blob (rest of file). PNG bytes referenced by (offset, size).
    m_blobBase = p;
    m_blobSize = end - p;

    m_mmapBase = base;
    m_mmapSize = st.st_size;
    m_archetypeId = archetypeId;
    m_iosMajor = iosMaj;
    m_iosMinor = iosMin;
    m_iosPatch = iosPat;
    m_loaded = true;
    if (diag) WTFLogAlways("[Driftstack-V770A.LOAD] LOADED archetype_id=%u iOS=%u.%u.%u nTextRun=%u nFonts=%u nPerGlyph=%u",
        (unsigned)archetypeId, (unsigned)iosMaj, (unsigned)iosMin, (unsigned)iosPat,
        (unsigned)nTextRun, (unsigned)nFonts, (unsigned)nPerGlyph);
    return true;
}
WTF_ALLOW_UNSAFE_BUFFER_USAGE_END

WTF_ALLOW_UNSAFE_BUFFER_USAGE_BEGIN
std::optional<DriftstackTextRunAtlasEntry> DriftstackTextRunAtlas::lookup(
    uint16_t fontId,
    uint16_t ptSize,
    uint8_t positionClass,
    uint64_t textRunHash)
{
    m_lookupCount++;
    if (!m_loaded || !m_textRunKeys || m_textRunEntryCount == 0) {
        m_missCount++;
        return std::nullopt;
    }
    uint32_t bucket = static_cast<uint32_t>(textRunHash) & kBucketMask;
    const Bucket& b = m_buckets[bucket];
    // V-790.N (wave 29-154): two-pass lookup — first try exact pos_class
    // match, then fall back to pos_class=0. Atlas builders may only have
    // pos_class=0 entries (V-790.N V-405 text-run conversion), while
    // runtime computes a range of pos_classes from anchor sub-pixel.
    // For same (font, pt, text), the iPhone PNG is identical across
    // pos_classes; only sub-pixel AA at the edges differs. pos=0 fallback
    // gives ~95% pixel match for the sub-pixel-offset case.
    auto findExact = [&](uint8_t pc) -> std::optional<DriftstackTextRunAtlasEntry> {
        for (uint32_t i = 0; i < b.count; ++i) {
            const PackedKey& k = m_textRunKeys[b.first + i];
            if (k.textRunHash == textRunHash
                && k.fontId == fontId
                && k.ptSize == ptSize
                && k.positionClass == pc) {
                const TextRunEntry& e = m_textRunEntries[b.first + i];
                if (size_t(e.blobOffset) + size_t(e.blobSize) > m_blobSize)
                    return std::nullopt;
                DriftstackTextRunAtlasEntry result;
                result.pngData = m_blobBase + e.blobOffset;
                result.pngSize = e.blobSize;
                result.abbLeft = e.abbLeft;
                result.abbRight = e.abbRight;
                result.abbAscent = e.abbAscent;
                result.abbDescent = e.abbDescent;
                result.width = e.width;
                return result;
            }
        }
        return std::nullopt;
    };
    if (auto hit = findExact(positionClass)) {
        m_hitCount++;
        return hit;
    }
    if (positionClass != 0) {
        if (auto hit = findExact(0)) {
            m_hitCount++;
            return hit;
        }
    }
    m_missCount++;
    return std::nullopt;
}
WTF_ALLOW_UNSAFE_BUFFER_USAGE_END

WTF_ALLOW_UNSAFE_BUFFER_USAGE_BEGIN
uint64_t driftstackComputeTextRunHash(
    const Font& font,
    uint16_t ptSize,
    StringView textUtf8,
    std::span<const uint16_t> glyphs,
    std::span<const CGSize> advances)
{
    // V-771.B: FNV-1a 64-bit on (fontId, ptSize, UTF-8 text, weight, italic).
    // Platform-independent — iPhone capture and Mac fork hash to the same
    // value for the same (text, font, ptSize) tuple, enabling atlas-key
    // parity across the divergent CT glyph buffers (RTL, shaping, ligatures).
    //
    // Fallback path: when textUtf8 is empty (drawGlyphs callers outside
    // FontCascade::drawGlyphBuffer text path, e.g., DrawGlyphsRecorder
    // replay or text-decoration marks), hash on the platform glyph buffer.
    // Those callers won't have atlas entries anyway; the fallback only
    // exists to keep hash output stable per call site for telemetry.

    constexpr uint64_t FNV_OFFSET = 0xcbf29ce484222325ULL;
    constexpr uint64_t FNV_PRIME = 0x100000001b3ULL;

    uint64_t h = FNV_OFFSET;
    auto mixBytes = [&](const uint8_t* p, size_t n) {
        for (size_t i = 0; i < n; ++i) {
            h ^= p[i];
            h *= FNV_PRIME;
        }
    };

    // 1. Font family id (resolved via driftstackMapFontToId).
    uint16_t fontId = driftstackMapFontToId(font);
    mixBytes(reinterpret_cast<const uint8_t*>(&fontId), sizeof(fontId));

    // 2. Point size.
    mixBytes(reinterpret_cast<const uint8_t*>(&ptSize), sizeof(ptSize));

    // 3. UTF-8 text bytes (V-771.B primary identity).
    if (!textUtf8.isEmpty()) {
        auto utf8 = textUtf8.utf8();
        const uint8_t* utf8Bytes = reinterpret_cast<const uint8_t*>(utf8.data());
        mixBytes(utf8Bytes, utf8.length());
    } else {
        // V-770.A.1 fallback (platform-dependent — likely atlas-miss).
        if (!glyphs.empty())
            mixBytes(reinterpret_cast<const uint8_t*>(glyphs.data()), glyphs.size() * sizeof(uint16_t));
        if (!advances.empty())
            mixBytes(reinterpret_cast<const uint8_t*>(advances.data()), advances.size() * sizeof(CGSize));
    }

    // 4. Font weight (canonical bucket from FontDescription).
    uint16_t weight = static_cast<uint16_t>(font.platformData().size() * 0); // placeholder
    // FontPlatformData on Cocoa exposes weight via FontSelectionValue; the
    // builder-side capture uses the CSS weight (100..900). Until we wire the
    // canonical mapping, treat weight as 400 (regular) implicitly via fontId
    // — the atlas keys font_id per (family, weight, italic) tuple already.
    UNUSED_PARAM(weight);

    return h;
}
WTF_ALLOW_UNSAFE_BUFFER_USAGE_END

uint8_t driftstackComputePositionClass(CGContextRef cgContext, const FloatPoint& anchor)
{
    if (!cgContext)
        return 0;

    // 16x16 subpixel-offset grid: device-space (xFrac, yFrac) ∈ [0, 1)² → 8-bit class.
    CGAffineTransform ctm = CGContextGetCTM(cgContext);
    CGPoint device = CGPointApplyAffineTransform(CGPointMake(anchor.x(), anchor.y()), ctm);

    double xFrac = device.x - std::floor(device.x);
    double yFrac = device.y - std::floor(device.y);

    // Clamp to [0, 15] (handle xFrac == 1.0 edge case via std::min).
    int xBin = static_cast<int>(std::floor(xFrac * 16.0));
    int yBin = static_cast<int>(std::floor(yFrac * 16.0));
    if (xBin > 15) xBin = 15;
    if (yBin > 15) yBin = 15;
    if (xBin < 0) xBin = 0;
    if (yBin < 0) yBin = 0;

    return static_cast<uint8_t>((yBin << 4) | xBin);
}

WTF_ALLOW_UNSAFE_BUFFER_USAGE_BEGIN
uint16_t DriftstackTextRunAtlas::fontIdForName(const char* name, size_t len) const
{
    if (!m_fontTable || !name)
        return UINT16_MAX;
    for (uint16_t i = 0; i < m_fontTableCount; ++i) {
        const FontTableEntry& e = m_fontTable[i];
        if (e.nameLen == len && std::memcmp(e.nameBytes, name, len) == 0)
            return e.fontId;
    }
    return UINT16_MAX;
}
WTF_ALLOW_UNSAFE_BUFFER_USAGE_END

WTF_ALLOW_UNSAFE_BUFFER_USAGE_BEGIN
uint16_t driftstackMapFontToId(const Font& font)
{
    // V-770.A.3: resolve via atlas font table using the CT font's
    // PostScript name. Falls back to CSS family if the atlas table only
    // contains family aliases (the V-770.B builder accepts either).
    auto& atlas = DriftstackTextRunAtlas::singleton();
    if (!atlas.isLoaded())
        return UINT16_MAX; // sentinel: no font_id resolution possible

    CTFontRef ctFont = font.platformData().ctFont();
    if (!ctFont)
        return UINT16_MAX;

    char psBuf[256] = {};
    char familyBuf[256] = {};

    // Try PostScript name first.
    RetainPtr<CFStringRef> psName = adoptCF(CTFontCopyPostScriptName(ctFont));
    if (psName) {
        if (CFStringGetCString(psName.get(), psBuf, sizeof(psBuf), kCFStringEncodingUTF8)) {
            size_t bufLen = 0;
            while (bufLen < sizeof(psBuf) && psBuf[bufLen]) ++bufLen;
            uint16_t fid = atlas.fontIdForName(psBuf, bufLen);
            if (fid != UINT16_MAX)
                return fid;
        }
    }

    // Fallback: family name (CSS family alias like "-apple-system", "Arial").
    RetainPtr<CFStringRef> familyName = adoptCF(CTFontCopyFamilyName(ctFont));
    if (familyName) {
        if (CFStringGetCString(familyName.get(), familyBuf, sizeof(familyBuf), kCFStringEncodingUTF8)) {
            size_t bufLen = 0;
            while (bufLen < sizeof(familyBuf) && familyBuf[bufLen]) ++bufLen;
            uint16_t fid = atlas.fontIdForName(familyBuf, bufLen);
            if (fid != UINT16_MAX)
                return fid;
        }
    }

    // W1761: Asian system fallback fonts the Mac fleet's WebKit cascade resolves for
    // CJK/Kana/Hangul (not in the atlas font table — verified via the fork's V-583B/
    // V-770A diag, NOT macOS CTFontCreateForString which gives different names).
    // Mapped to dedicated font_ids so the V-790.L per-glyph atlas can key Asian
    // glyphs — the STORED pixels are the iOS glyph (sim-rendered == real iPhone per
    // W1509); this is only the lookup key. Additive (existing ids 0-21 untouched;
    // fires only after the atlas table already missed, i.e. previously UINT16_MAX).
    {
        auto eq = [](const char* a, const char* b) {
            while (*a && *a == *b) { ++a; ++b; }
            return *a == *b;
        };
        static const struct { const char* name; uint16_t id; } kAsianUiFonts[] = {
            { ".AppleSimplifiedChineseFont-Regular", 22 }, { ".AppleSimplifiedChineseFont", 22 },
            { ".AppleJapaneseFont-Regular", 23 },          { ".AppleJapaneseFont", 23 },
            { ".AppleKoreanFont-Regular", 24 },            { ".AppleKoreanFont", 24 },
            // W1770: world-script fallback fonts (fork WebKit-cascade names per V-583B
            // diag — NOT the native-CT .SF* names). Each → a dedicated font_id so the
            // per-glyph atlas can key + substitute the iOS glyph (closure pending capture).
            { ".SFArabic-Regular", 25 },          { ".SFHebrew-Regular", 26 },
            { ".SFArmenian-Regular", 27 },        { ".SFGeorgian-Regular", 28 },
            { "KohinoorDevanagari-Regular", 29 }, { "KohinoorGujarati-Regular", 30 },
            { "KohinoorTelugu-Regular", 31 },     { "MuktaMahee-Regular", 32 },
            { "TamilSangamMN", 33 },              { "NotoSansKannada-Regular", 34 },
            { "MalayalamSangamMN", 35 },          { "SinhalaSangamMN", 36 },
            { ".ThonburiUI-Regular", 37 },        { "LaoSangamMN", 38 },
            { "KhmerSangamMN", 39 },              { "NotoSansMyanmar-Regular", 40 },
            { "KefaIII-Regular", 41 },            { ".AppleIndicFont-Regular", 42 },
            // #79: Menlo (canvas monospace text) → font_id 12, matching the advance atlas
            // (DriftstackAdvanceAtlas monospace slot) + the #79 Western per-glyph color/coverage
            // atlas. Not in the text-run atlas name table, so resolve it here for the per-glyph
            // canvas serve (DriftstackTextGlyphAtlas::fontIdForFamily lacks the 'Menlo' literal).
            { "Menlo-Regular", 12 },              { "Menlo", 12 },
            // #79: Arial (PS name "ArialMT") + Verdana — NOT in the text-run atlas name table
            // (verified: advdiag never resolved fontId 1 → Arial canvas text fell to native Mac
            // render). The per-glyph atlas has Arial (font_id 1, incl twelfths sub-pixel) + Verdana
            // (8); resolve them here so the N>1 canvas serve engages (Mac Arial≈iOS but not exact —
            // the atlas + sidecar advance close fox text byte-exact). glyphHash is DOM (unaffected).
            { "ArialMT", 1 },                     { "Arial", 1 },
            { "Arial-BoldMT", 1 },                { "Verdana", 8 },
        };
        for (const auto& e : kAsianUiFonts) {
            if (eq(psBuf, e.name) || eq(familyBuf, e.name))
                return e.id;
        }
    }

    // V-770.A.14/.15: surface each distinct missing-font NAME once. A small
    // ring of seen names (kMaxDistinct=64 slots) avoids unbounded growth +
    // runaway log spam. Lookup is linear scan; expected steady-state distinct
    // count is small (single digits per session).
    if (std::getenv("DRIFTSTACK_TEXT_RUN_ATLAS_DIAG")) {
        struct SeenEntry { uint64_t hash; bool valid; };
        static constexpr size_t kMaxDistinct = 64;
        static SeenEntry s_seen[kMaxDistinct] {};
        static std::atomic<size_t> s_seenCount { 0 };

        // FNV-1a over (ps + '|' + family) as the dedup key.
        uint64_t k = 0xcbf29ce484222325ULL;
        for (const char* p = psBuf; *p; ++p) { k ^= (uint8_t)*p; k *= 0x100000001b3ULL; }
        k ^= '|'; k *= 0x100000001b3ULL;
        for (const char* p = familyBuf; *p; ++p) { k ^= (uint8_t)*p; k *= 0x100000001b3ULL; }
        if (!k) k = 1; // 0 reserved for empty slot

        size_t cnt = s_seenCount.load(std::memory_order_acquire);
        bool already = false;
        for (size_t i = 0; i < cnt && i < kMaxDistinct; ++i) {
            if (s_seen[i].valid && s_seen[i].hash == k) { already = true; break; }
        }
        if (!already && cnt < kMaxDistinct) {
            size_t slot = s_seenCount.fetch_add(1, std::memory_order_acq_rel);
            if (slot < kMaxDistinct) {
                s_seen[slot] = { k, true };
                WTFLogAlways("[Driftstack-V770A.UNKNOWN_FONT] ps='%s' family='%s' (slot=%u)",
                    psBuf[0] ? psBuf : "(none)",
                    familyBuf[0] ? familyBuf : "(none)",
                    (unsigned)slot);
            }
        }
    }

    return UINT16_MAX; // unknown — V-770.B.13 atlas builder should add the family
}
WTF_ALLOW_UNSAFE_BUFFER_USAGE_END

// V-771.B thread-local source text plumbing.
//
// Each WebContent thread that renders canvas text owns its own slot;
// drawGlyphBuffer pushes a StringView, drawGlyphs reads it during hash
// computation, the scope guard clears on return. Saved/restored via a
// stack-allocated previous-value field so nested drawGlyphBuffer calls
// (e.g., text-decoration mark draws) don't lose their parent context.
namespace {

struct TextSourceSlot {
    // W2538: owning copy of the source text for the CANVAS path. The per-glyph
    // platform hook (FontCascadeCoreText) reads this TLS source AFTER drawGlyphBuffer
    // returns the layout — by then the transient backing string of a non-owning
    // StringView is freed/recycled, so the view's length survives (sourceLen=1) but
    // its data dangles → the codepoint decodes as U+0000 and the per-glyph atlas
    // never hits (empirically 9/769). Capturing an owning String at scope entry
    // (while `source` is still a live param) keeps the bytes valid through the
    // deferred read. Page (non-canvas) text keeps the cheap non-owning view.
    String owned;
    StringView current;
};

static ThreadSpecific<TextSourceSlot>& textSourceSlot()
{
    static NeverDestroyed<ThreadSpecific<TextSourceSlot>> slot;
    return slot.get();
}

} // namespace

DriftstackCurrentTextSourceScope::DriftstackCurrentTextSourceScope(StringView source)
{
    auto& slot = *textSourceSlot();
    // #79: SAVE the previous source (own a copy) so the dtor RESTORES it. Nesting DID
    // appear: a multi-glyph canvas run (fox/Arial) triggers a nested empty-source
    // sub-draw whose dtor previously cleared the slot to empty, wiping the outer run's
    // source before its own drawGlyphs → the per-glyph N>1 serve saw length 0 != glyphs
    // → skipped → native render. On the non-nested hot path the previous source is empty
    // → this copy is a no-op (no alloc).
    m_savedSource = slot.current.toString();
    //
    // W2538: in the canvas-text-draw scope the per-glyph/platform hook reads this
    // source after the backing buffer may be gone, so own a copy there (current
    // then views the owned String, which lives until the dtor). Outside canvas
    // (on-screen page text — the hot path) keep the zero-alloc non-owning view.
    if (driftstackInCanvasTextDraw()) {
        slot.owned = source.toString();
        slot.current = slot.owned;
    } else {
        slot.owned = String { };
        slot.current = source;
    }
}

DriftstackCurrentTextSourceScope::~DriftstackCurrentTextSourceScope()
{
    auto& slot = *textSourceSlot();
    // #79: RESTORE the previous source (own it so the view stays valid), instead of
    // clearing to empty. Keeps the outer run's source live across nested sub-draws.
    slot.owned = std::move(m_savedSource);
    slot.current = slot.owned;
}

StringView driftstackCurrentTextSource()
{
    auto& slot = *textSourceSlot();
    return slot.current;
}

namespace {
// Per-thread canvas-text-draw nesting depth (W1092). >0 ⇒ the current
// drawGlyphs dispatch originates from CanvasRenderingContext2DBase text
// drawing (the fingerprint surface), so glyph pixel substitution applies.
struct CanvasTextDepthSlot {
    unsigned depth { 0 };
    bool nativeFallback { false };   // #79: set when a canvas-text glyph fell to native CT raster
};
ThreadSpecific<CanvasTextDepthSlot>& canvasTextDepthSlot()
{
    static NeverDestroyed<ThreadSpecific<CanvasTextDepthSlot>> slot;
    return slot.get();
}
} // namespace

void driftstackPushCanvasTextDraw()
{
    ++canvasTextDepthSlot()->depth;
}

void driftstackPopCanvasTextDraw()
{
    auto& slot = *canvasTextDepthSlot();
    if (slot.depth)
        --slot.depth;
}

bool driftstackInCanvasTextDraw()
{
    return canvasTextDepthSlot()->depth > 0;
}

void driftstackResetCanvasTextNativeFallback()
{
    canvasTextDepthSlot()->nativeFallback = false;
}

void driftstackMarkCanvasTextNativeFallback()
{
    canvasTextDepthSlot()->nativeFallback = true;
}

bool driftstackCanvasTextNativeFallbackOccurred()
{
    return canvasTextDepthSlot()->nativeFallback;
}

} // namespace WebCore

#endif // PLATFORM(DRIFTSTACK)
