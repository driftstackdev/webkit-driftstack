/*
 * V-790.L per-glyph exact-substitution atlas (Driftstack Path A2).
 *
 * Layer between V-770 text-run atlas (Layer A) and V-790.V Layer B
 * (Phase 3.B step 2 Mac+ML approximate substitution).
 *
 * Stores per-(font_id, pt_size_q4, codepoint, pos_class) → 64x64
 * uint8_t grayscale iPhone-canonical pixels. Atlas hit = bit-identical
 * sha256 output (no ML approximation). Atlas miss = fall through to
 * Layer B.
 *
 * Binary format (DSPGA1, little-endian):
 *   Header (16 bytes):
 *     magic        "DSPGA1\0\0"          8 bytes
 *     version      uint32_t              4 bytes
 *     entry_count  uint32_t              4 bytes
 *   Entries (each 4108 bytes, sorted by key):
 *     key:    (font_id u16, pt_size_q4 u16, codepoint u32, pos_class u32)
 *             = 12 bytes
 *     pixels: 64*64 uint8_t row-major   4096 bytes
 *
 * Runtime lookup: O(log N) binary search.
 *
 * See captures/v3/v790l-per-glyph-atlas-builder.py for the builder.
 */
#pragma once

#if PLATFORM(DRIFTSTACK)

#include <cstdint>
#include <optional>
#include <span>

namespace WebCore {

struct DriftstackPerGlyphAtlasEntry {
    // 64x64 grayscale iPhone-canonical pixels (row-major).
    // Backed by mmap; lifetime = atlas singleton lifetime.
    const uint8_t* pixels;
    // = 4096
    size_t pixelsSize;
};

class DriftstackPerGlyphAtlas {
public:
    static DriftstackPerGlyphAtlas& singleton();

    // Lazy auto-load on first access.
    bool loadFromFile(const char* path);

    bool isLoaded() const { return m_loaded; }
    size_t entryCount() const { return m_entryCount; }

    // Lookup. Returns nullopt on miss. Lookup key matches the encoding
    // used by FontCascadeCoreText.cpp Phase 3 hook:
    //   pt_size_q4 = static_cast<uint16_t>(ptSize * 16)
    std::optional<DriftstackPerGlyphAtlasEntry> lookup(
        uint16_t fontId,
        uint16_t ptSizeQ4,
        uint32_t codepoint,
        uint32_t posClass) const;

private:
    bool m_loaded { false };
    const uint8_t* m_mapBase { nullptr };
    size_t m_mapSize { 0 };
    size_t m_entryCount { 0 };
    // Offset to first entry's key (immediately after 16-byte header).
    const uint8_t* m_entriesBase { nullptr };
};

// #79 (2026-06-21): the arbitrary-canvas-text N>1 serve places glyph i at
// penX_i = anchor.x + Σ advance[0..i-1]. The FontCascade advances are iOS-correct
// for fonts the DriftstackAdvanceAtlas (V-689) covers densely (Menlo/Times/Helvetica)
// but UNCORRECTED (raw Mac) for the ones it leaves empty (Arial/Verdana=10 entries)
// → those glyphs land at the wrong sub-pixel frac → wrong pos_class → ±1 AA-edge diffs.
// This sidecar (DSWADV1, captured iOS canvas measureText widths) supplies the iOS
// advance for the Western canvas fonts WITHOUT touching the glyphHash-critical
// advance/measureText path. Returns nullopt on miss → caller falls back to the
// FontCascade advance. Lazy-loaded once from DRIFTSTACK_WESTERN_ADVANCE_SIDECAR_PATH
// (default reference/driftstack_western_advance_sidecar.bin).
std::optional<float> driftstackWesternAdvanceSidecar(uint16_t fontId, uint16_t sizePx, uint32_t codepoint);

} // namespace WebCore

#endif // PLATFORM(DRIFTSTACK)
