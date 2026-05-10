/*
 * DriftstackTextGlyphAtlas — per-codepoint PNG atlas for non-emoji glyphs.
 *
 * V-583.K-text Phase 3: extends V-583.B emoji atlas pattern to ASCII / CJK /
 * Arabic / Devanagari glyphs. Captures (font_id, ptSize, codepoint) → PNG bytes
 * from real iPhone via V-583.J + V-583.H BS Automate captures.
 *
 * Atlas binary loaded via mmap at WebProcess startup. Lookup is binary search
 * on sorted (font_id, ptSize, codepoint) index. Substituted at
 * FontCascadeCoreText::showGlyphsClampingToOrigin time, AFTER V-583.B emoji
 * dispatch, for non-color glyphs.
 *
 * Atlas file format (DTGA):
 *   magic: "DTGA" (4 bytes)
 *   version: uint16 (currently 1)
 *   font_count: uint16
 *   font_table: N × { id: uint16, name_len: uint8, name: bytes }
 *   glyph_count: uint32
 *   glyph_index: M × { font_id: uint16, ptSize: uint16, cp: uint32,
 *                      png_offset: uint32, png_size: uint32,
 *                      abbl: float, abbr: float, abba: float, abbd: float }
 *   png_blob: concatenated PNG bytes
 */

#pragma once

#if PLATFORM(DRIFTSTACK)

#include <cstdint>
#include <span>
#include <vector>
#include <wtf/text/WTFString.h>

namespace WebCore {

struct DriftstackTextGlyphEntry {
    uint16_t fontId;
    uint16_t ptSize;
    uint32_t codepoint;
    uint32_t pngOffset;
    uint32_t pngSize;
    float actualBoundingBoxLeft;
    float actualBoundingBoxRight;
    float actualBoundingBoxAscent;
    float actualBoundingBoxDescent;
} __attribute__((packed));

class DriftstackTextGlyphAtlas {
public:
    static DriftstackTextGlyphAtlas& singleton();

    bool isAvailable() const { return m_atlasData != nullptr; }

    // Returns PNG bytes for (font, ptSize, codepoint) or empty span on miss.
    std::span<const uint8_t> lookup(uint16_t fontId, uint16_t ptSize, uint32_t codepoint) const;

    // Looks up entry metadata (offset/size/anchors) without reading PNG.
    const DriftstackTextGlyphEntry* lookupEntry(uint16_t fontId, uint16_t ptSize, uint32_t codepoint) const;

    // Resolve CSS-name → font_id. Mirrors V-149 ASCII font enum.
    static uint16_t fontIdForFamily(const String& familyName);

    // Enumerate all codepoints present in atlas (used for reverse-map build).
    // Returns sorted unique set of codepoints.
    std::vector<uint32_t> allCodepoints() const;

    DriftstackTextGlyphAtlas();

private:
    ~DriftstackTextGlyphAtlas() = default;
    DriftstackTextGlyphAtlas(const DriftstackTextGlyphAtlas&) = delete;
    DriftstackTextGlyphAtlas& operator=(const DriftstackTextGlyphAtlas&) = delete;

    void loadAtlas();

    const uint8_t* m_atlasData { nullptr };
    size_t m_atlasSize { 0 };
    const DriftstackTextGlyphEntry* m_index { nullptr };
    uint32_t m_indexCount { 0 };
    const uint8_t* m_pngBlob { nullptr };
};

} // namespace WebCore

#endif // PLATFORM(DRIFTSTACK)
