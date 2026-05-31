/*
 * DriftstackAsciiAtlas.mm — see header.
 */

#include "config.h"
#include "DriftstackAsciiAtlas.h"

#if PLATFORM(DRIFTSTACK)

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <wtf/Logging.h>

namespace WebCore {

// V-117 atlas binary path. Override at runtime via DRIFTSTACK_ASCII_ATLAS_PATH
// env var; default resolves to the captured atlas in dev environment.
// Anonymous namespace isolates these names from other Driftstack atlas .mm
// files (EmojiAtlas, CompositeAtlas) which the WebKit unify-build mechanism
// merges into the same translation unit.
namespace {
const char* kAsciiAtlasDefaultPath = "/Users/john/code/driftstack/reference/driftstack_ascii_atlas/driftstack-ascii-atlas.bin";
constexpr uint8_t kAsciiAtlasMagic[4] = { 'D', 'S', 'A', 'S' };
constexpr size_t kAsciiAtlasFontNameBytes = 64;
constexpr size_t kAsciiAtlasEntryBytes = 16;
}

DriftstackAsciiAtlas& DriftstackAsciiAtlas::singleton()
{
    static NeverDestroyed<DriftstackAsciiAtlas> instance;
    return instance.get();
}

DriftstackAsciiAtlas::DriftstackAsciiAtlas()
{
    mapAtlas();
}

DriftstackAsciiAtlas::~DriftstackAsciiAtlas()
{
    if (m_mmapBase && m_mmapSize)
        munmap(const_cast<uint8_t*>(m_mmapBase), m_mmapSize);
    if (m_fd >= 0)
        close(m_fd);
}

void DriftstackAsciiAtlas::mapAtlas()
{
    // Direct-browse (human inspection) mode: skip loading the canvas-fingerprint
    // glyph atlas so live web-page text renders natively from the iOS font
    // binaries. Atlas glyph substitution targets canvas-text bit-identity, but
    // applied to ordinary page-text glyph runs it emits solid boxes for any
    // (font,size,glyph) it doesn't cover. Empty atlas → every lookup misses →
    // native CT render (readable). Production capture mode (env unset) loads
    // normally so canvas fingerprint stays bit-identical.
    if (const char* db = getenv("DRIFTSTACK_DIRECT_BROWSE"); db && db[0] == '1') {
        WTFLogAlways("[Driftstack] AsciiAtlas: load suppressed (DRIFTSTACK_DIRECT_BROWSE=1) — native page-text render");
        return;
    }

    const char* envPath = getenv("DRIFTSTACK_ASCII_ATLAS_PATH");
    const char* path = envPath ? envPath : kAsciiAtlasDefaultPath;

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        WTFLogAlways("[Driftstack] AsciiAtlas: open failed for %s (errno=%d)", path, errno);
        return;
    }

    struct stat st;
    if (fstat(fd, &st) < 0 || st.st_size < 24) {
        WTFLogAlways("[Driftstack] AsciiAtlas: fstat failed or file too small (%lld bytes)", (long long)st.st_size);
        close(fd);
        return;
    }

    void* base = mmap(nullptr, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (base == MAP_FAILED) {
        WTFLogAlways("[Driftstack] AsciiAtlas: mmap failed (errno=%d)", errno);
        close(fd);
        return;
    }

    std::span<const uint8_t> bytesSpan = unsafeMakeSpan(static_cast<const uint8_t*>(base), static_cast<size_t>(st.st_size));

    if (bytesSpan.size() < 24
        || bytesSpan[0] != kAsciiAtlasMagic[0]
        || bytesSpan[1] != kAsciiAtlasMagic[1]
        || bytesSpan[2] != kAsciiAtlasMagic[2]
        || bytesSpan[3] != kAsciiAtlasMagic[3]) {
        WTFLogAlways("[Driftstack] AsciiAtlas: bad magic at start of %s", path);
        munmap(base, st.st_size);
        close(fd);
        return;
    }

    auto readU32 = [&bytesSpan](size_t off) -> uint32_t {
        return uint32_t(bytesSpan[off]) | (uint32_t(bytesSpan[off+1]) << 8)
             | (uint32_t(bytesSpan[off+2]) << 16) | (uint32_t(bytesSpan[off+3]) << 24);
    };

    // V-141: v3 header layout differs from v1/v2. v3 uses:
    //   4s magic, H version (offset 4-5), B subpixel (6), B color (7),
    //   I numFonts (8), I numColors (12), I numEntries (16),
    //   I indexOffset (20), I dataOffset (24), I reserved (28).
    // v1: H version is upper 16 bits of u32 at offset 4 (= 1).
    // v2: same (= 2). v3 uses just u16 here.
    // Read raw u16 version safely:
    uint16_t version = uint16_t(bytesSpan[4]) | (uint16_t(bytesSpan[5]) << 8);
    uint16_t versionUpper = uint16_t(bytesSpan[6]) | (uint16_t(bytesSpan[7]) << 8);

    uint32_t numFonts = 0;
    uint32_t numEntries = 0;
    uint32_t indexOffset = 0;
    uint32_t dataOffset = 0;
    uint32_t subpixelVariantCount = 1;
    uint32_t colorVariantCount = 1;
    size_t headerBytes = 24;
    size_t entryStride = 16;
    size_t colorTableOffset = 0;
    size_t colorTableBytes = 0;

    if (version == 3 && versionUpper != 0) {
        // V-141 v3 path: subpixel + color counts in upper bytes of position 4..7.
        subpixelVariantCount = bytesSpan[6];
        colorVariantCount = bytesSpan[7];
        if (bytesSpan.size() < 32) {
            WTFLogAlways("[Driftstack] AsciiAtlas: v3 header truncated (file %zu < 32)", bytesSpan.size());
            munmap(base, st.st_size); close(fd); return;
        }
        numFonts = readU32(8);
        uint32_t numColorsField = readU32(12);
        numEntries = readU32(16);
        indexOffset = readU32(20);
        dataOffset = readU32(24);
        // 28..31 reserved
        if (colorVariantCount == 0 || colorVariantCount > 16) {
            WTFLogAlways("[Driftstack] AsciiAtlas: v3 invalid colorVariantCount=%u", colorVariantCount);
            munmap(base, st.st_size); close(fd); return;
        }
        if (numColorsField != colorVariantCount) {
            WTFLogAlways("[Driftstack] AsciiAtlas: v3 numColors=%u != colorVariantCount=%u",
                numColorsField, colorVariantCount);
            munmap(base, st.st_size); close(fd); return;
        }
        if (subpixelVariantCount == 0 || subpixelVariantCount > 16) {
            // V-199: bound lifted from 4 → 16 for V-198 Path 2 V-127-16x atlas.
            // FontCascade.cpp dispatch quantizer extension (V-198 commit
            // f74276df77) handles variantCount=16 via roundf(fracX * 16.0f) & 15.
            WTFLogAlways("[Driftstack] AsciiAtlas: v3 invalid subpixelVariantCount=%u", subpixelVariantCount);
            munmap(base, st.st_size); close(fd); return;
        }
        headerBytes = 32;
        entryStride = 24;
        colorTableOffset = 32;
        colorTableBytes = colorVariantCount * 4;
    } else {
        // v1 / v2 legacy path: u32 version at offset 4.
        uint32_t legacyVersion = readU32(4);
        numFonts = readU32(8);
        numEntries = readU32(12);
        indexOffset = readU32(16);
        dataOffset = readU32(20);
        if (legacyVersion == 2) {
            if (bytesSpan.size() < 28) {
                WTFLogAlways("[Driftstack] AsciiAtlas: v2 header truncated (file size %zu < 28)", bytesSpan.size());
                munmap(base, st.st_size); close(fd); return;
            }
            subpixelVariantCount = readU32(24);
            headerBytes = 28;
            entryStride = 20;
            if (subpixelVariantCount == 0 || subpixelVariantCount > 16) {
                // V-199: bound lifted from 4 → 16 for V-198 Path 2 V-127-16x atlas
                // (matches v3 path; same FontCascade.cpp dispatch quantizer support).
                WTFLogAlways("[Driftstack] AsciiAtlas: v2 invalid subpixelVariantCount=%u", subpixelVariantCount);
                munmap(base, st.st_size); close(fd); return;
            }
            version = 2;
        } else if (legacyVersion == 1) {
            version = 1;
        } else {
            WTFLogAlways("[Driftstack] AsciiAtlas: unsupported version=%u", legacyVersion);
            munmap(base, st.st_size); close(fd); return;
        }
        // v1/v2: implicit single black slot, color table not present in file.
        colorVariantCount = 1;
        colorTableBytes = 0;
    }

    if (numFonts == 0 || numFonts > 64) {
        WTFLogAlways("[Driftstack] AsciiAtlas: invalid numFonts=%u", numFonts);
        munmap(base, st.st_size); close(fd); return;
    }

    // V-141: parse color table (v3 only; v1/v2 fall through with default
    // m_colorTable[0] = {0,0,0,255} from the in-class member initializer).
    if (version == 3) {
        if (bytesSpan.size() < colorTableOffset + colorTableBytes) {
            WTFLogAlways("[Driftstack] AsciiAtlas: v3 color table truncated");
            munmap(base, st.st_size); close(fd); return;
        }
        for (uint8_t i = 0; i < colorVariantCount; ++i) {
            m_colorTable[i].r = bytesSpan[colorTableOffset + i * 4 + 0];
            m_colorTable[i].g = bytesSpan[colorTableOffset + i * 4 + 1];
            m_colorTable[i].b = bytesSpan[colorTableOffset + i * 4 + 2];
            m_colorTable[i].a = bytesSpan[colorTableOffset + i * 4 + 3];
        }
    }

    // Font table follows (color table for v3, header for v1/v2).
    size_t fontTableOffset = (version == 3) ? (colorTableOffset + colorTableBytes) : headerBytes;

    // Parse font_table (64 bytes per entry, zero-padded UTF-8).
    m_fontNames.reserveInitialCapacity(numFonts);
    for (uint32_t i = 0; i < numFonts; ++i) {
        size_t off = fontTableOffset + i * kAsciiAtlasFontNameBytes;
        size_t len = 0;
        while (len < kAsciiAtlasFontNameBytes && bytesSpan[off + len] != 0)
            ++len;
        m_fontNames.append(String::fromUTF8(bytesSpan.subspan(off, len)));
    }

    if (indexOffset != fontTableOffset + numFonts * kAsciiAtlasFontNameBytes
        || dataOffset != indexOffset + numEntries * entryStride
        || dataOffset > bytesSpan.size()) {
        WTFLogAlways("[Driftstack] AsciiAtlas: header offsets invalid (version=%u indexOffset=%u dataOffset=%u fileSize=%zu)",
            version, indexOffset, dataOffset, bytesSpan.size());
        munmap(base, st.st_size); close(fd); return;
    }

    m_indexSpan = bytesSpan.subspan(indexOffset, numEntries * entryStride);
    m_dataPayloadSpan = bytesSpan.subspan(dataOffset);
    m_numEntries = numEntries;
    m_atlasVersion = version;
    m_subpixelVariantCount = static_cast<uint8_t>(subpixelVariantCount);
    m_colorVariantCount = static_cast<uint8_t>(colorVariantCount);
    m_entryStride = entryStride;

    m_fd = fd;
    m_mmapBase = static_cast<const uint8_t*>(base);
    m_mmapSize = st.st_size;

    WTFLogAlways("[Driftstack] AsciiAtlas: mapped %lld bytes from %s; v%u, %u entries × %u fonts × %u subpixel × %u color variants",
        (long long)st.st_size, path, version, numEntries, numFonts, subpixelVariantCount, colorVariantCount);
}

uint8_t DriftstackAsciiAtlas::colorIdxFor(uint8_t r, uint8_t g, uint8_t b, uint8_t a) const
{
    for (uint8_t i = 0; i < m_colorVariantCount; ++i) {
        const auto& c = m_colorTable[i];
        if (c.r == r && c.g == g && c.b == b && c.a == a)
            return i;
    }
    return 0xFF;
}

uint16_t DriftstackAsciiAtlas::fontIdFor(const String& fontCssName) const
{
    for (size_t i = 0; i < m_fontNames.size(); ++i) {
        if (m_fontNames[i] == fontCssName)
            return static_cast<uint16_t>(i);
    }
    return std::numeric_limits<uint16_t>::max();
}

// Read an IndexEntry from the byte span at logical entry index i. Stride
// depends on atlas version (v1: 16 bytes; v2: 20 bytes — added subpixelQuant;
// v3: 24 bytes — added colorIndex). Avoids unaligned struct access by
// reading byte-by-byte.
static DriftstackAsciiAtlas_IndexEntry readAsciiEntry(std::span<const uint8_t> indexSpan, size_t i, size_t stride)
{
    DriftstackAsciiAtlas_IndexEntry e { };
    auto entrySpan = indexSpan.subspan(i * stride, stride);
    e.fontId = uint16_t(entrySpan[0]) | (uint16_t(entrySpan[1]) << 8);
    e.sizePx = uint16_t(entrySpan[2]) | (uint16_t(entrySpan[3]) << 8);
    e.codepoint = uint32_t(entrySpan[4]) | (uint32_t(entrySpan[5]) << 8) | (uint32_t(entrySpan[6]) << 16) | (uint32_t(entrySpan[7]) << 24);
    if (stride == 24) {
        // v3: subpixelQuant at 8, colorIndex at 9, padding 10-11,
        //     dataOffset at 12, pngLen at 16, reserved 20-23.
        e.subpixelQuant = entrySpan[8];
        e.colorIndex = entrySpan[9];
        e.dataOffset = uint32_t(entrySpan[12]) | (uint32_t(entrySpan[13]) << 8) | (uint32_t(entrySpan[14]) << 16) | (uint32_t(entrySpan[15]) << 24);
        e.pngLen = uint32_t(entrySpan[16]) | (uint32_t(entrySpan[17]) << 8) | (uint32_t(entrySpan[18]) << 16) | (uint32_t(entrySpan[19]) << 24);
    } else if (stride == 20) {
        // v2: subpixelQuant at offset 8, 3 bytes padding, dataOffset at 12, pngLen at 16.
        e.subpixelQuant = entrySpan[8];
        e.colorIndex = 0; // implicit single black slot
        e.dataOffset = uint32_t(entrySpan[12]) | (uint32_t(entrySpan[13]) << 8) | (uint32_t(entrySpan[14]) << 16) | (uint32_t(entrySpan[15]) << 24);
        e.pngLen = uint32_t(entrySpan[16]) | (uint32_t(entrySpan[17]) << 8) | (uint32_t(entrySpan[18]) << 16) | (uint32_t(entrySpan[19]) << 24);
    } else {
        // v1: dataOffset at 8, pngLen at 12. subpixelQuant + colorIndex defaulted to 0.
        e.subpixelQuant = 0;
        e.colorIndex = 0;
        e.dataOffset = uint32_t(entrySpan[8]) | (uint32_t(entrySpan[9]) << 8) | (uint32_t(entrySpan[10]) << 16) | (uint32_t(entrySpan[11]) << 24);
        e.pngLen = uint32_t(entrySpan[12]) | (uint32_t(entrySpan[13]) << 8) | (uint32_t(entrySpan[14]) << 16) | (uint32_t(entrySpan[15]) << 24);
    }
    return e;
}

std::span<const uint8_t> DriftstackAsciiAtlas::entryFor(const String& fontCssName, uint16_t sizePx,
                                                       uint32_t codepoint, uint8_t subpixelQuant,
                                                       uint8_t colorIdx, uint8_t styleCode) const
{
    if (m_dataPayloadSpan.empty() || m_indexSpan.empty() || !m_numEntries)
        return { };

    uint16_t fontId = fontIdFor(fontCssName);
    if (fontId == std::numeric_limits<uint16_t>::max())
        return { };

    // Task #17: weight/italic variants are keyed as a fontId offset
    // (baseFontId + numFonts*styleCode). numFonts = base family count
    // (m_fontNames.size(), always 12 — the font table holds only the base
    // names; styled index entries carry fontIds 12..47). On a non-styled
    // atlas this pushes styleCode>0 past the populated fontId range, so the
    // search misses and the caller falls back to native CT.
    if (styleCode)
        fontId += static_cast<uint16_t>(m_fontNames.size()) * styleCode;

    // V-141: 5-key search (font_id, size_px, codepoint, subpixelQuant, colorIndex).
    // For v1/v2 atlases (entries have implicit colorIndex=0), only colorIdx==0
    // matches; callers should gate on colorVariantCount() > 1 to avoid passing
    // colorIdx > 0 to a legacy atlas.
    size_t lo = 0, hi = m_numEntries;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        auto e = readAsciiEntry(m_indexSpan, mid, m_entryStride);
        if (e.fontId < fontId) lo = mid + 1;
        else if (e.fontId > fontId) hi = mid;
        else if (e.sizePx < sizePx) lo = mid + 1;
        else if (e.sizePx > sizePx) hi = mid;
        else if (e.codepoint < codepoint) lo = mid + 1;
        else if (e.codepoint > codepoint) hi = mid;
        else if (e.subpixelQuant < subpixelQuant) lo = mid + 1;
        else if (e.subpixelQuant > subpixelQuant) hi = mid;
        else if (e.colorIndex < colorIdx) lo = mid + 1;
        else if (e.colorIndex > colorIdx) hi = mid;
        else
            return m_dataPayloadSpan.subspan(e.dataOffset, e.pngLen);
    }
    return { };
}

} // namespace WebCore

#endif // PLATFORM(DRIFTSTACK)
