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

// Index entry struct exposed for the .mm-side reader. 16 bytes; not
// directly mapped over the mmap due to alignment + safe-buffer rules.
struct DriftstackAsciiAtlas_IndexEntry {
    uint16_t fontId;
    uint16_t sizePx;
    uint32_t codepoint;
    uint32_t dataOffset;
    uint32_t pngLen;
};

class DriftstackAsciiAtlas {
public:
    static DriftstackAsciiAtlas& singleton();

    // Returns PNG-encoded bytes for (fontCssName, sizePx, codepoint), or empty span if not found.
    // Caller decodes via WebKit's existing PNG infrastructure.
    std::span<const uint8_t> entryFor(const String& fontCssName, uint16_t sizePx, uint32_t codepoint) const;

    // True iff atlas binary was successfully loaded.
    bool isAvailable() const { return !m_dataPayloadSpan.empty(); }

    // Returns the list of CSS family names available in the atlas.
    // Used by callers that want to short-circuit lookup before doing
    // codepoint matching.
    const Vector<String>& fontNames() const { return m_fontNames; }

private:
    friend NeverDestroyed<DriftstackAsciiAtlas>;
    DriftstackAsciiAtlas();
    ~DriftstackAsciiAtlas();

    void mapAtlas();

    // Returns the font_id for a CSS family name, or std::numeric_limits<uint16_t>::max()
    // if the font is not in the atlas.
    uint16_t fontIdFor(const String& fontCssName) const;

    int m_fd { -1 };
    const uint8_t* m_mmapBase { nullptr };
    size_t m_mmapSize { 0 };

    Vector<String> m_fontNames;
    std::span<const uint8_t> m_indexSpan;
    std::span<const uint8_t> m_dataPayloadSpan;
    size_t m_numEntries { 0 };
};

} // namespace WebCore

#endif // PLATFORM(DRIFTSTACK)
