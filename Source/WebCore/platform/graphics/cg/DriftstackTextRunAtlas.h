/*
 * V-770.A.1 — DriftstackTextRunAtlas scaffold (Rule N v2 Layer A).
 *
 * Text-run-keyed atlas for canvas text rendering substitution. Hooked at
 * FontCascade::drawGlyphs entry. On atlas hit, iPhone canonical alpha mask
 * is composited onto the context, bypassing Mac CG rasterization. On miss,
 * pass through to default Mac CG path (Rule O v2 safety baseline).
 *
 * v1 implementation: STUB. lookup() always returns nullopt (empty atlas).
 * Wires the hook in place + emits V-820.A AtlasMiss telemetry on every
 * text run. When V-770.A text-run captures fire, atlas binary gets
 * populated and this lookup() returns hits without further hook code
 * changes.
 *
 * Atlas binary format: DSCFA2 text-run section (defined in
 * captures/v3/build-driftstack-text-run-atlas.py and
 * docs/architecture/wave-28-v770-atlas-builder-v2.md).
 */
#pragma once

#if PLATFORM(DRIFTSTACK)

#include <CoreGraphics/CoreGraphics.h>
#include <cstdint>
#include <optional>
#include <span>
#include <wtf/text/StringView.h>

namespace WebCore {

class Font;
class GraphicsContext;
class FloatPoint;

struct DriftstackTextRunAtlasEntry {
    // Atlas entry payload: alpha-mask PNG bytes + metrics.
    const uint8_t* pngData;
    size_t pngSize;
    float abbLeft;
    float abbRight;
    float abbAscent;
    float abbDescent;
    float width;
};

class DriftstackTextRunAtlas {
public:
    static DriftstackTextRunAtlas& singleton();

    // V-771 lookup entry. Returns hit if (font_id, ptSize, position_class,
    // text_run_hash) is in the atlas binary.
    //
    // v1: always returns nullopt (empty atlas / not yet loaded).
    std::optional<DriftstackTextRunAtlasEntry> lookup(
        uint16_t fontId,
        uint16_t ptSize,
        uint8_t positionClass,
        uint64_t textRunHash);

    // V-820.A integration: each lookup() call increments a counter for
    // telemetry. Telemetry emission is the caller's responsibility via
    // driftstackLogAtlasMiss.
    uint64_t lookupCount() const { return m_lookupCount; }
    uint64_t hitCount() const { return m_hitCount; }
    uint64_t missCount() const { return m_missCount; }

private:
    DriftstackTextRunAtlas() = default;

    uint64_t m_lookupCount { 0 };
    uint64_t m_hitCount { 0 };
    uint64_t m_missCount { 0 };
};

// Helpers (PLATFORM(DRIFTSTACK)-gated).
//
// V-771.B: hash on UTF-8 text bytes + font + ptSize for cross-platform
// parity. Falls back to glyph-buffer hash when textUtf8 is empty (e.g.,
// drawGlyphs call sites outside the FontCascade::drawGlyphBuffer text path).
uint64_t driftstackComputeTextRunHash(
    const Font& font,
    uint16_t ptSize,
    StringView textUtf8,                 // V-771.B primary identity
    std::span<const uint16_t> glyphs,    // CGGlyph == uint16_t (fallback)
    std::span<const CGSize> advances);   // fallback

uint8_t driftstackComputePositionClass(
    CGContextRef cgContext,
    const FloatPoint& anchor);

uint16_t driftstackMapFontToId(const Font& font);

// V-771.B thread-local source-text plumbing.
//
// FontCascade::drawGlyphBuffer receives the source StringView (via F.1.B-6
// plumbing from CanvasRenderingContext2D::fillText). It sets the current
// text source on its thread before invoking GraphicsContext::drawGlyphs,
// which dispatches to the platform Font::drawGlyphs (V-771 hook). The hook
// reads back the source for hash computation. RAII setter clears on exit.
class DriftstackCurrentTextSourceScope {
public:
    explicit DriftstackCurrentTextSourceScope(StringView source);
    ~DriftstackCurrentTextSourceScope();
    DriftstackCurrentTextSourceScope(const DriftstackCurrentTextSourceScope&) = delete;
    DriftstackCurrentTextSourceScope& operator=(const DriftstackCurrentTextSourceScope&) = delete;
};

StringView driftstackCurrentTextSource();

} // namespace WebCore

#endif // PLATFORM(DRIFTSTACK)
