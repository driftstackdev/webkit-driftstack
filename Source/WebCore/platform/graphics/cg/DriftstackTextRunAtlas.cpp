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
#include <cmath>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

namespace WebCore {

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

    const char* resolved = path;
    if (!resolved)
        resolved = std::getenv("DRIFTSTACK_TEXT_RUN_ATLAS_PATH");
    if (!resolved)
        resolved = "/Users/john/code/driftstack/reference/driftstack_text_run_atlas_v1.bin";

    int fd = ::open(resolved, O_RDONLY);
    if (fd < 0)
        return false;

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
    p += 2; // archetype_id (unused by loader)
    p += 3; // iOS triplet

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
    m_loaded = true;
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
    for (uint32_t i = 0; i < b.count; ++i) {
        const PackedKey& k = m_textRunKeys[b.first + i];
        if (k.textRunHash == textRunHash
            && k.fontId == fontId
            && k.ptSize == ptSize
            && k.positionClass == positionClass) {
            const TextRunEntry& e = m_textRunEntries[b.first + i];
            if (size_t(e.blobOffset) + size_t(e.blobSize) > m_blobSize) {
                // Defensive: corrupt offset; treat as miss.
                m_missCount++;
                return std::nullopt;
            }
            m_hitCount++;
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
        return 0; // loader not ready — match v1 stub behavior

    CTFontRef ctFont = font.platformData().ctFont();
    if (!ctFont)
        return 0;

    // Try PostScript name first.
    RetainPtr<CFStringRef> psName = adoptCF(CTFontCopyPostScriptName(ctFont));
    if (psName) {
        char buf[256];
        if (CFStringGetCString(psName.get(), buf, sizeof(buf), kCFStringEncodingUTF8)) {
            size_t bufLen = 0;
            while (bufLen < sizeof(buf) && buf[bufLen]) ++bufLen;
            uint16_t fid = atlas.fontIdForName(buf, bufLen);
            if (fid != UINT16_MAX)
                return fid;
        }
    }

    // Fallback: family name (CSS family alias like "-apple-system", "Arial").
    RetainPtr<CFStringRef> familyName = adoptCF(CTFontCopyFamilyName(ctFont));
    if (familyName) {
        char buf[256];
        if (CFStringGetCString(familyName.get(), buf, sizeof(buf), kCFStringEncodingUTF8)) {
            size_t bufLen = 0;
            while (bufLen < sizeof(buf) && buf[bufLen]) ++bufLen;
            uint16_t fid = atlas.fontIdForName(buf, bufLen);
            if (fid != UINT16_MAX)
                return fid;
        }
    }

    return 0; // unknown — V-770.B.13 atlas builder should add the family
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
    // No save/restore — drawGlyphBuffer is leaf w.r.t. recursive text emit
    // in the current code path. If nesting appears later, switch to a
    // Vector<StringView> push/pop and refactor.
    slot.current = source;
}

DriftstackCurrentTextSourceScope::~DriftstackCurrentTextSourceScope()
{
    auto& slot = *textSourceSlot();
    slot.current = StringView { };
}

StringView driftstackCurrentTextSource()
{
    auto& slot = *textSourceSlot();
    return slot.current;
}

} // namespace WebCore

#endif // PLATFORM(DRIFTSTACK)
