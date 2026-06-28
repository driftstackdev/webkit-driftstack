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

#include "DriftstackKefaAdvances.h" // driftstackKefaAdvancesActive() Family-A gate (Safari major<26)
#include "FontCascade.h"
#include <array>
#include <wtf/text/ASCIILiteral.h>
#include <wtf/text/WTFString.h>

namespace WebCore {

static inline bool driftstackLookupGcpsFallbackAdvance(const FontCascade& fontCascade, char32_t cp, float sizePx, float& outAdvance)
{
    if (cp != 0x1E9E && cp != 0x20B9 && cp != 0x20B8 && cp != 0x097F && cp != 0x2581 && cp != 0x20BA) // ẞ ₹ ₸ ॿ ▁ ₺ -- listed GCPS codepoints
        return false;
    struct Entry { ASCIILiteral family; char32_t cp; float adv128; };
    static constexpr std::array<Entry, 14> kGcpsNamed { {
        { "Futura"_s, 0x1E9E, 86.9375f },  // ẞ -- closes the blfonts uniqueMetrics off-by-one (Futura↔Kailasa)
        { "Savoye LET"_s, 0x097F, 71.808f },  // ॿ -- W2878: exact iOS-26.5-sim measureText FLOAT (71.80799865722656 == float 71.808f); prior 71.576f was Mac-native-tuned-to-group, not the real iOS per-char float (the founder's "actually-correct not tune-to-pass" — iOS's own group is computed WITH 71.808 so it satisfies both)
        // -apple-system / system-ui: ONLY ▁ (U+2581) diverges (sim measureText: fork 118.19 vs iOS 119.738);
        // the exact iOS float makes the fork's Σ == iOS's Σ -> group 4186->4187 == sim. ₹/₺/₸/ẞ/ॿ already match.
        { "-apple-system"_s, 0x2581, 119.73807525634766f },  // ▁ W2879: exact iOS-sim measureText float (was 119.738f=119.73799896, off at 7th digit)
        { "system-ui"_s, 0x2581, 119.73807525634766f },      // ▁ W2879: exact iOS-sim measureText float
        // Impact: the fork's cascade sizes the GCPS fallback fonts narrower than iOS per-primary. Inject
        // the iOS @128px advances (native ctprobe == iOS for these) to close the Impact blfonts -8 group.
        { "Impact"_s, 0x20B9, 70.8125f },   // ₹ W2879: exact iOS float (iOS=70.8125=1133/16; was 70.812f=70.81199646)
        { "Impact"_s, 0x20B8, 71.1875f },   // ₸ W2879: exact iOS float (iOS=71.1875=1139/16; was 71.188f=71.18800354)
        { "Impact"_s, 0x1E9E, 88.375f },   // ẞ
        { "Impact"_s, 0x097F, 74.496f },   // ॿ -- W2878: exact iOS-26.5-sim measureText FLOAT (74.49600219726562 == float 74.496f); prior 74.648f was native-cascade-tuned-to-group, not the real iOS per-char (offsetWidth 75 unchanged; iOS's group uses 74.496 so metricsHash holds)
        // 2026-06-27 Kefa Family-A GCPS fallback (blfonts metricsHash c6bdb116). Primary "Kefa" aliases to
        // the macOS "Kefa III" face; the GCPS chars have no Kefa glyph and route to Mac fallback fonts whose
        // advance differs from real iOS. Inject the real iOS @128px in-run advances (captured
        // blfonts-iPhone_16_Pro_Max-1782581084705.json kefaPerChar.floatPer, metricsHash c6bdb116
        // re-confirmed same capture) so the fork's Kefa metric group lands 4367,149. Latin glyphs are
        // corrected separately via DriftstackKefaAdvances.h on the Kefa III face.
        { "Kefa"_s, 0x20B9, 66.5f },       // ₹ INDIAN RUPEE SIGN
        { "Kefa"_s, 0x2581, 128.0f },      // ▁ LOWER ONE EIGHTH BLOCK
        { "Kefa"_s, 0x20BA, 71.1875f },    // ₺ TURKISH LIRA SIGN
        { "Kefa"_s, 0x20B8, 71.1875f },    // ₸ TENGE SIGN
        { "Kefa"_s, 0x1E9E, 86.9375f },    // ẞ LATIN CAPITAL LETTER SHARP S
        { "Kefa"_s, 0x097F, 72.576f },     // ॿ DEVANAGARI LETTER BBA
    } };
    // Scale by the PRIMARY's computed size (the requested font-size), NOT the fallback run font's size:
    // Mac CTLine metric-shrinks some fallbacks relative to the primary, which would mis-scale the @128px value.
    const float scale = sizePx / 128.0f;
    String fam = fontCascade.fontDescription().firstFamily().name.string();
    // Kefa is present ONLY on Safari<26 (Family-A); on 26.4+ a "Kefa"-primary request falls back
    // differently, so the iOS-18.6-Kefa GCPS advances are WRONG there. Gate the Kefa entries to
    // Family-A only. The 5 non-Kefa families (Futura/Savoye LET/-apple-system/system-ui/Impact) are
    // band-invariant iOS-correct and stay UNGATED.
    const bool kefaActive = driftstackKefaAdvancesActive();
    for (auto& e : kGcpsNamed) {
        if (e.family == "Kefa"_s && !kefaActive)
            continue;
        if (e.cp == cp && fam == e.family) {
            outAdvance = e.adv128 * scale;
            return true;
        }
    }
    return false;
}

} // namespace WebCore

#endif // PLATFORM(DRIFTSTACK)
