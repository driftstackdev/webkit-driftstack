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
struct DriftstackAsciiAtlas_IndexEntry {
    uint16_t fontId;
    uint16_t sizePx;
    uint32_t codepoint;
    uint8_t subpixelQuant;
    // 3 bytes implicit padding
    uint32_t dataOffset;
    uint32_t pngLen;
};

class DriftstackAsciiAtlas {
public:
    static DriftstackAsciiAtlas& singleton();

    // V-127 lookup with sub-pixel quantization. subpixelQuant ∈ [0, subpixelVariantCount()).
    std::span<const uint8_t> entryFor(const String& fontCssName, uint16_t sizePx,
                                      uint32_t codepoint, uint8_t subpixelQuant) const;

    // V-117 v1-compat: same as entryFor(..., 0). For callers that don't
    // care about sub-pixel positioning (integer-aligned drawing).
    std::span<const uint8_t> entryFor(const String& fontCssName, uint16_t sizePx, uint32_t codepoint) const
    {
        return entryFor(fontCssName, sizePx, codepoint, 0);
    }

    // V-127: subpixelVariantCount returns 1 for v1 atlas (no sub-pixel
    // variants captured), 1..4 for v2 atlas. Caller uses this to size
    // the quantizer.
    uint8_t subpixelVariantCount() const { return m_subpixelVariantCount; }

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
    // m_entryStride=20.
    uint32_t m_atlasVersion { 0 };
    uint8_t m_subpixelVariantCount { 1 };
    size_t m_entryStride { 16 };
};

} // namespace WebCore

#endif // PLATFORM(DRIFTSTACK)
