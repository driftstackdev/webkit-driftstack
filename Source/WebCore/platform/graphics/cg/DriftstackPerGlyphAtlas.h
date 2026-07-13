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
 *   Optional trailer (65808 bytes):
 *     complete DSGCMP1 fractional-alpha glyph-compositor response
 *   Optional destination trailer (458768 bytes, requires DSGCMP1):
 *     complete DSDCR1 opaque/text-backdrop source-over response
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

class AffineTransform;

struct DriftstackPerGlyphAtlasEntry {
    // 64x64 grayscale iPhone-canonical pixels (row-major).
    // Backed by mmap; lifetime = atlas singleton lifetime.
    const uint8_t* pixels;
    // = 4096
    size_t pixelsSize;
};

struct DriftstackGlyphCompositorPixel {
    uint8_t red;
    uint8_t green;
    uint8_t blue;
    uint8_t alpha;
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

    std::optional<DriftstackGlyphCompositorPixel> compositorPixel(
        uint8_t fillAlphaByte, uint8_t red, uint8_t green,
        uint8_t blue, uint8_t coverage) const;

    std::optional<DriftstackGlyphCompositorPixel> destinationPixel(
        uint8_t fillAlphaByte, uint8_t sourceRed, uint8_t sourceGreen,
        uint8_t sourceBlue, uint8_t coverage, uint8_t destinationRed,
        uint8_t destinationGreen, uint8_t destinationBlue,
        uint8_t destinationAlpha) const;

private:
    bool m_loaded { false };
    const uint8_t* m_mapBase { nullptr };
    size_t m_mapSize { 0 };
    size_t m_entryCount { 0 };
    // Offset to first entry's key (immediately after 16-byte header).
    const uint8_t* m_entriesBase { nullptr };
    uint8_t m_compositorFillAlphaByte { 0 };
    const uint8_t* m_compositorAlpha { nullptr };
    const uint8_t* m_compositorChannels { nullptr };
    const uint8_t* m_destinationOpaqueChannels { nullptr };
    const uint8_t* m_destinationTextBackdrop { nullptr };
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

// Map a glyph pen coordinate to the capture atlas's twelve horizontal
// position classes. Canvas coordinates and accumulated advance widths can
// arrive a few ulps below an exact k/12 boundary; tolerate only that numeric
// noise so a captured boundary remains in class k rather than class k - 1.
uint8_t driftstackTwelfthPositionClass(double coordinate);

// Atlas cells are captured without scale, rotation, or skew. Translation is
// safe because the captured mask is placed in user space and follows the
// canvas translation exactly; other linear transforms retain native drawing.
bool driftstackPerGlyphAtlasSupportsTransform(const AffineTransform&);

// Return a valid premultiplied backing byte whose local unpremultiplied
// readback is exactly the requested visible byte at this alpha.
WEBCORE_EXPORT std::optional<uint8_t> driftstackPremultipliedChannelForVisible(uint8_t visible, uint8_t alpha);

// Capture-derived iOS glyph-compositor response. The optional DSGCMP1 trailer
// in the per-glyph mmap maps
// (fill alpha byte, sRGB channel byte, opaque glyph coverage byte) to the
// unpremultiplied RGBA bytes returned by iOS canvas getImageData(). A missing
// trailer or an uncaptured fill-alpha byte returns nullopt so callers retain the
// existing compositor path; in particular, opaque rendering is unchanged.
std::optional<DriftstackGlyphCompositorPixel> driftstackGlyphCompositorPixel(
    uint8_t fillAlphaByte, uint8_t red, uint8_t green, uint8_t blue, uint8_t coverage);

// Capture-derived source-over response for destinations whose 8-bit visible
// state was exhaustively characterized. Opaque destinations are channel-
// separable for every sRGB byte; translucent #069 text backdrops are complete
// for every destination-alpha/source-coverage pair. Other destinations miss so
// the normal compositor remains authoritative.
std::optional<DriftstackGlyphCompositorPixel> driftstackGlyphDestinationPixel(
    uint8_t fillAlphaByte, uint8_t sourceRed, uint8_t sourceGreen,
    uint8_t sourceBlue, uint8_t coverage, uint8_t destinationRed,
    uint8_t destinationGreen, uint8_t destinationBlue,
    uint8_t destinationAlpha);

} // namespace WebCore

#endif // PLATFORM(DRIFTSTACK)
