/*
 * Driftstack: per-primary GCPS-char fallback-advance correction (browserleaks /fonts metricsHash).
 *
 * Mac CoreText applies a per-primary metric-compatible transform to the fallback advance of certain
 * GCPS probe characters (browserleaks /fonts uses ₹▁₺₸ẞॿ) that diverges from iOS for specific NAMED
 * primary fonts. The correction is keyed by (CSS-requested primary family, codepoint) -> the captured
 * iOS advance @128px (fork-vs-sim, gcps-allfonts-float probe), scaled to the run's primary size.
 *
 * Shared by BOTH text paths so a glyph's advance is identical whether it is measured through the
 * complex path (ComplexTextController, e.g. offsetWidth of a mixed-script string) or the simple path
 * (WidthIterator, e.g. canvas measureText of an all-Latin string) -- otherwise the two disagree, which
 * is itself a tell.
 *
 * Only verified-divergent, NON-SHAPING codepoints are listed: ẞ/U+1E9E is Latin (isolated advance ==
 * shaped advance, so the captured value is correct in any context). The Devanagari ॿ/U+097F SHAPES, so
 * its isolated capture != its shaped advance -- those corrections need shaped-context captures and are
 * intentionally NOT here yet (residual). Listing only the proven pairs leaves every other font and
 * codepoint untouched.
 */

#pragma once

#if PLATFORM(DRIFTSTACK)

#include "FontCascade.h"
#include <array>
#include <wtf/text/ASCIILiteral.h>
#include <wtf/text/WTFString.h>

namespace WebCore {

static inline bool driftstackLookupGcpsFallbackAdvance(const FontCascade& fontCascade, char32_t cp, float sizePx, float& outAdvance)
{
    if (cp != 0x1E9E) // ẞ (U+1E9E) -- the only currently-listed (non-shaping) GCPS codepoint
        return false;
    struct Entry { ASCIILiteral family; char32_t cp; float adv128; };
    static constexpr std::array<Entry, 1> kGcpsNamed { {
        { "Futura"_s, 0x1E9E, 86.9375f },  // ẞ -- closes the blfonts uniqueMetrics off-by-one (Futura↔Kailasa)
    } };
    // Scale by the PRIMARY's computed size (the requested font-size), NOT the fallback run font's size:
    // Mac CTLine metric-shrinks some fallbacks relative to the primary, which would mis-scale the @128px value.
    const float scale = sizePx / 128.0f;
    String fam = fontCascade.fontDescription().firstFamily().name.string();
    for (auto& e : kGcpsNamed) {
        if (e.cp == cp && fam == e.family) {
            outAdvance = e.adv128 * scale;
            return true;
        }
    }
    return false;
}

} // namespace WebCore

#endif // PLATFORM(DRIFTSTACK)
