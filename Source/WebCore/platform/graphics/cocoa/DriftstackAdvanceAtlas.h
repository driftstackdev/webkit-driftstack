/*
 * DriftstackAdvanceAtlas — per-codepoint glyph advance override atlas.
 *
 * V-689 (Wave 25): extends V-121 (ASCII constexpr table) + V-688 (non-ASCII
 * constexpr table) to a comprehensive mmap'd binary atlas covering 2.7M+
 * (font_id, sizePx, codepoint) → widthPx entries captured from real iPhone
 * via BS Automate v583k/v583j/v583h orchestrators.
 *
 * Constexpr-array approach (V-121 5700 entries, V-688 21996 entries) doesn't
 * scale to 2.7M entries (compile time + binary size). This class mirrors
 * DriftstackTextGlyphAtlas pattern: binary file mmap'd at WebProcess startup
 * with binary search lookup.
 *
 * Atlas file format (DAAA):
 *   magic: "DAAA" (4 bytes)
 *   version: uint16 (1)
 *   reserved: uint16 (0)
 *   font_count: uint32
 *   entry_count: uint32
 *   font_table: N × { id: uint16, name_len: uint16, name_bytes (padded to 4) }
 *   entries: M × { font_id: uint16, sizePx: uint16, codepoint: uint32,
 *                  widthPx: float32 } = 12 bytes each, sorted by
 *                  (font_id, sizePx, codepoint).
 *
 * Lookup: binary search on sorted (font_id, sizePx, codepoint).
 * Called from Font::platformWidthForGlyph after the existing constexpr-table
 * lookups (V-121, V-688) miss.
 */

#pragma once

#if PLATFORM(DRIFTSTACK)

#include <cstdint>
#include <wtf/text/WTFString.h>

namespace WebCore {

struct DriftstackAdvanceEntry {
    uint16_t fontId;
    uint16_t sizePx;
    uint32_t codepoint;
    float widthPx;
} __attribute__((packed));

class DriftstackAdvanceAtlas {
public:
    static DriftstackAdvanceAtlas& singleton();

    bool isAvailable() const { return m_atlasData != nullptr; }

    // Returns iPhone widthPx for (fontId, sizePx, codepoint) or -1 on miss.
    float lookup(uint16_t fontId, uint16_t sizePx, uint32_t codepoint) const;

    // Returns pointer to first entry for (fontId, sizePx) and count of consecutive
    // entries matching this (fontId, sizePx). Used by Font::platformWidthForGlyph
    // to build a glyph→codepoint reverse map for all atlas codepoints in the
    // active font's coverage. Returns nullptr if no entries match.
    const DriftstackAdvanceEntry* entriesForFontSize(uint16_t fontId, uint16_t sizePx, uint32_t* outCount) const;

    // CSS-name → font_id (matches V-149/V-688 font enum + .AppleSystemUIFont alias).
    static uint16_t fontIdForFamily(const String& familyName);

    uint32_t entryCount() const { return m_entryCount; }

    DriftstackAdvanceAtlas();

private:
    ~DriftstackAdvanceAtlas() = default;
    DriftstackAdvanceAtlas(const DriftstackAdvanceAtlas&) = delete;
    DriftstackAdvanceAtlas& operator=(const DriftstackAdvanceAtlas&) = delete;

    void loadAtlas();

    const uint8_t* m_atlasData { nullptr };
    size_t m_atlasSize { 0 };
    const DriftstackAdvanceEntry* m_entries { nullptr };
    uint32_t m_entryCount { 0 };
};

} // namespace WebCore

#endif // PLATFORM(DRIFTSTACK)
