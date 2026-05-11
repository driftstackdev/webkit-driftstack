/*
 * V-771.A0 — minimal text-run hashing + position-class utility.
 *
 * Used at V-771 drawGlyphsCoreText hook entry to compute Layer A atlas
 * lookup key. Free functions only; no I/O, no atlas dispatch yet.
 *
 * NOT YET INCLUDED IN BUILD GRAPH. V-771.A wires this into
 * FontCascadeCoreText.cpp drawGlyphsCoreText entry; V-820.A telemetry +
 * V-770.B atlas singleton + V-875 canary detector layer atop these
 * primitives.
 */

#pragma once

#if PLATFORM(DRIFTSTACK)

#include <CoreGraphics/CoreGraphics.h>
#include <cstdint>

namespace WebCore {

class Font;
class GraphicsContext;

// xxhash64 of (font postscript name, glyph indices, advances) — captures
// text-run identity from the rendered glyph buffer without needing the
// original string. Deterministic across processes for the same input.
uint64_t driftstackComputeTextRunHash(const Font& font,
                                      const CGGlyph* glyphs,
                                      const CGSize* advances,
                                      size_t count);

// 16×16 subpixel-offset grid: maps (x, y) anchor in user space through the
// current CTM, takes fractional part, bins to (yBin << 4) | xBin.
// Returns 8-bit position class for atlas key lookup.
uint8_t driftstackComputePositionClass(const GraphicsContext& context,
                                       double anchorX, double anchorY);

// Maps a Font instance to a stable font_id matching the DSCFA2 atlas font
// table (V-770.B emit). Returns 0xFFFF if font not in atlas vocabulary.
uint16_t driftstackMapFontToAtlasId(const Font& font);

} // namespace WebCore

#endif // PLATFORM(DRIFTSTACK)
