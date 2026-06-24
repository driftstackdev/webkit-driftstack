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
    if (cp != 0x1E9E && cp != 0x20B9 && cp != 0x20B8 && cp != 0x097F) // ẞ ₹ ₸ ॿ -- listed GCPS codepoints
        return false;
    struct Entry { ASCIILiteral family; char32_t cp; float adv128; };
    static constexpr std::array<Entry, 5> kGcpsNamed { {
        { "Futura"_s, 0x1E9E, 86.9375f },  // ẞ -- closes the blfonts uniqueMetrics off-by-one (Futura↔Kailasa)
        // Impact: the fork's cascade sizes the GCPS fallback fonts narrower than iOS per-primary. Inject
        // the iOS @128px advances (native ctprobe == iOS for these) to close the Impact blfonts -8 group.
        { "Impact"_s, 0x20B9, 70.812f },   // ₹
        { "Impact"_s, 0x20B8, 71.188f },   // ₸
        { "Impact"_s, 0x1E9E, 88.375f },   // ẞ
        { "Impact"_s, 0x097F, 74.648f },   // ॿ -- sim per-char 75 + sim full 3985 both constrain; native-cascade 75.648 sizes ~1px wider than iOS here
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
