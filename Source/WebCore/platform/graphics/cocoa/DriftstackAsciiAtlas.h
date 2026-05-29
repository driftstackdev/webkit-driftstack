/*
 * DriftstackAsciiAtlas.h — Per V-117 / Stage F root cause B
 *
 * mmap'd binary atlas of iPhone-rendered ASCII glyph bitmaps. Sibling
 * to DriftstackEmojiAtlas (single codepoint emoji) and
 * DriftstackCompositeAtlas (multi-codepoint emoji sequences).
 *
 * Used by FontCascade::drawGlyphBuffer on Driftstack to substitute
 * iPhone-equivalent ASCII glyph bitmaps for all glyphs whose codepoint
 * falls in the ASCII printable range (U+0020 .. U+007E) and whose
 * font + size match a captured atlas entry. Mac CT renders ASCII at
 * small sizes structurally differently from iOS CT (V-117: 0/196
 * non-space probes byte-match across 6 (font, size) cells); pre-captured
 * iPhone bitmaps are the only known closure path.
 *
 * Atlas format ('DSAS' magic — Driftstack ASCII):
 *   header[24]:
 *     -  4 B: magic 'DSAS'
 *     -  4 B: version (u32 LE) = 1
 *     -  4 B: numFonts (u32 LE)
 *     -  4 B: numEntries (u32 LE)
 *     -  4 B: indexOffset (u32 LE) = 24 + numFonts*64
 *     -  4 B: dataOffset (u32 LE) = indexOffset + numEntries*16
 *   font_table[numFonts * 64]:
 *     each = 64 B zero-padded UTF-8 CSS family name (e.g., "-apple-system")
 *   entries[numEntries * 16] (sorted by font_id, size_px, codepoint):
 *     -  2 B: font_id (u16 LE) — index into font_table
 *     -  2 B: size_px (u16 LE)
 *     -  4 B: codepoint (u32 LE)
 *     -  4 B: data_offset (u32 LE, relative to dataOffset)
 *     -  4 B: png_len (u32 LE)
 *   data[]: concatenated PNG byte streams
 *
 * Lookup: triple-key binary search on (font_id, size_px, codepoint).
 * Mac fork resolves CSS family name → font_id at startup via linear
 * scan over font_table (small N, ~10 fonts).
 *
 * Geometry contract (must match capture probe stage-f-ascii-rasterizer.html):
 *   canvas dim = 32 × 32
 *   glyph drawn at (4, size_px + 4) with textBaseline 'alphabetic'
 *   white background, black glyph color
 *
 * Substitution call site: FontCascade::drawGlyphBuffer iterates glyphs;
 * for each glyph at offset (originX, originY), atlas-hit emits the
 * decoded PNG via context.drawNativeImage at (originX - 4, originY - size_px - 4).
 */

#pragma once

#if PLATFORM(DRIFTSTACK)

#include <span>
#include <wtf/NeverDestroyed.h>
#include <wtf/Vector.h>
#include <wtf/text/WTFString.h>

namespace WebCore {

// Index entry struct exposed for the .mm-side reader.
// V-127 v2: 20 bytes (was 16 in v1; added subpixelQuant field).
// V-141 v3: 24 bytes (added colorIndex field).
struct DriftstackAsciiAtlas_IndexEntry {
    uint16_t fontId;
    uint16_t sizePx;
    uint32_t codepoint;
    uint8_t subpixelQuant;
    uint8_t colorIndex; // V-141: 0 for v1/v2 atlases (single implicit black/transparent slot)
    // 2 bytes implicit padding
    uint32_t dataOffset;
    uint32_t pngLen;
};

class DriftstackAsciiAtlas {
public:
    static DriftstackAsciiAtlas& singleton();

    // V-141: 5-key lookup with explicit colorIdx.
    // For v1/v2 atlases, only colorIdx == 0 returns entries (single slot).
    // Task #17: styleCode selects weight/italic variant (0=regular, 1=bold,
    // 2=italic, 3=bold-italic). Encoded as a fontId offset: effective
    // fontId = baseFontId + numFonts*styleCode. Regular (styleCode=0) is the
    // existing behavior; on a non-styled atlas, styleCode>0 misses → caller
    // falls back to native CT. Default 0 keeps all existing call sites intact.
    std::span<const uint8_t> entryFor(const String& fontCssName, uint16_t sizePx,
                                      uint32_t codepoint, uint8_t subpixelQuant,
                                      uint8_t colorIdx, uint8_t styleCode = 0) const;

    // V-127 4-key lookup (back-compat — defaults colorIdx to 0).
    std::span<const uint8_t> entryFor(const String& fontCssName, uint16_t sizePx,
                                      uint32_t codepoint, uint8_t subpixelQuant) const
    {
        return entryFor(fontCssName, sizePx, codepoint, subpixelQuant, 0);
    }

    // V-117 v1-compat: same as entryFor(..., 0, 0). For callers that don't
    // care about sub-pixel positioning (integer-aligned drawing).
    std::span<const uint8_t> entryFor(const String& fontCssName, uint16_t sizePx, uint32_t codepoint) const
    {
        return entryFor(fontCssName, sizePx, codepoint, 0, 0);
    }

    // V-127: subpixelVariantCount returns 1 for v1 atlas (no sub-pixel
    // variants captured), 1..4 for v2 atlas. Caller uses this to size
    // the quantizer.
    uint8_t subpixelVariantCount() const { return m_subpixelVariantCount; }

    // V-141: colorVariantCount returns 1 for v1/v2 (single implicit black slot),
    // 1..16 for v3. Dispatch uses this to gate color-aware lookup behavior.
    uint8_t colorVariantCount() const { return m_colorVariantCount; }

    // V-141: exact-match lookup for color slot. Returns 0xFF on miss.
    // Caller computes (r,g,b,a) from context.fillColor() bytes.
    // For v1/v2 atlases (colorVariantCount=1), this returns 0 only for
    // (0,0,0,255) — but callers should gate on colorVariantCount() > 1
    // to skip lookup entirely on legacy atlases.
    uint8_t colorIdxFor(uint8_t r, uint8_t g, uint8_t b, uint8_t a) const;

    struct ColorRGBA { uint8_t r, g, b, a; };
    ColorRGBA colorAt(uint8_t idx) const
    {
        if (idx >= m_colorVariantCount)
            return { 0, 0, 0, 0 };
        return m_colorTable[idx];
    }

    bool isAvailable() const { return !m_dataPayloadSpan.empty(); }
    const Vector<String>& fontNames() const { return m_fontNames; }

private:
    friend NeverDestroyed<DriftstackAsciiAtlas>;
    DriftstackAsciiAtlas();
    ~DriftstackAsciiAtlas();

    void mapAtlas();
    uint16_t fontIdFor(const String& fontCssName) const;

    int m_fd { -1 };
    const uint8_t* m_mmapBase { nullptr };
    size_t m_mmapSize { 0 };

    Vector<String> m_fontNames;
    std::span<const uint8_t> m_indexSpan;
    std::span<const uint8_t> m_dataPayloadSpan;
    size_t m_numEntries { 0 };
    // V-127 v2 metadata. v1 atlas → m_atlasVersion=1, m_subpixelVariantCount=1,
    // m_entryStride=16. v2 atlas → m_atlasVersion=2, count from header,
    // m_entryStride=20. v3 atlas → m_atlasVersion=3, m_entryStride=24,
    // m_colorVariantCount per header.
    uint32_t m_atlasVersion { 0 };
    uint8_t m_subpixelVariantCount { 1 };
    uint8_t m_colorVariantCount { 1 };
    size_t m_entryStride { 16 };
    // V-141: 16-element color table. For v1/v2 atlases:
    //   m_colorTable[0] = {0,0,0,255} (canonical black; the v1/v2 atlas
    //   always rendered black on transparent; stencil-and-tint applied
    //   the actual fill color at draw time). v3 atlases populate the
    //   real captured colors.
    std::array<ColorRGBA, 16> m_colorTable { { { 0, 0, 0, 255 } } };
};

} // namespace WebCore

#endif // PLATFORM(DRIFTSTACK)
