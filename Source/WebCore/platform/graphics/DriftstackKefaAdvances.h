/*
 * Driftstack: real-iOS Kefa per-glyph advance override (browserleaks /fonts metricsHash, Family-A).
 *
 * 2026-06-27. Kefa is PRESENT on real Safari 18.x (Family-A) and ABSENT on >=26 (FontCacheCoreText
 * driftstackKefaPresentForArchetype). On Safari<26 the fork aliases CSS family "Kefa" -> the macOS
 * face "Kefa III" (KefaIII.ttf nameID1) so blfonts sees Kefa PRESENT. BUT macOS "Kefa III" has
 * DIFFERENT per-glyph advances than real iOS "Kefa": for the browserleaks 1:1 probe string
 * (mmmMMMmmmlllmmmLLL + ₹▁₺₸ẞॿ + mmmiiimmmIIImmmwwwmmmWWW @128px) the macOS face lays out to
 * offsetWidth 4155, but real iOS Kefa lays out to 4367 -> the blfonts metric GROUP for Kefa is
 * "4367,149" on real device but "~4155,149" on the raw fork -> the grouped metricsHash diverges
 * (fork 796850ec vs real c6bdb116). The COUNT matches (Kefa detected); only the per-char advances
 * differ.
 *
 * Fix: override platformWidthForGlyph for the resolved "Kefa III" face, Family-A only, returning the
 * REAL iOS Kefa per-glyph advance (@128px, scaled by the run's px size). Values captured from a real
 * iPhone 16 Pro Max / iOS 18.6 / Safari 18.6 via the EXACT browserleaks 1:1 probe (offsetWidth
 * technique) whose metricsHash re-confirmed c6bdb116 in the same capture
 * (reference/realdevice-bs/blfonts-iPhone_16_Pro_Max-1782581084705.json, kefaPerChar.floatPer).
 * These are the genuine real-iOS Kefa glyph advances (not tuned-to-group); the fork runs the SAME
 * WebKit layout/rounding as iOS, so summing these per-glyph floats yields the SAME offsetWidth 4367.
 *
 * Only the probe-string codepoints are listed (the only ones that drive the blfonts metricsHash);
 * every other glyph of Kefa III is left at its native macOS advance. Miss -> caller keeps the Mac CT
 * advance.
 *
 * 2026-06-27 re-derivation (capture blfonts-iPhone_16_Pro_Max-1782581084705.json + A3 daemon-73890
 * fork-render): these LATIN advances are VERIFIED CORRECT and must NOT be lowered. The fork's WebKit
 * span layout rounds per contiguous N-glyph run: offsetWidth += ceil(Σ run-glyph-floats), then +25
 * whole-string inter-run. Under that model these genuine floats give fork-Latin == iOS-Latin == 3847
 * (per-run: m=2303(7×ceil(3·109.5625)=329), M=323, l=114, L=202, i=115, I=133, w=306, W=351 — byte-
 * identical to the captured iOS perChar advOw run subtotals). The +27 overshoot A3 saw (4394 vs iOS
 * 4367) is NOT in the Latin glyphs — it is the GCPS chars (₹/₺/₸): A3's render had the
 * DriftstackGcpsFallback.h Kefa entries INACTIVE (uncommitted), so ₹/₺/₸ used their raw Mac fallback
 * face (78/78/78) instead of the captured iOS in-run advances (₹66.5/₺71.1875/₸71.1875 → 67/72/72).
 * WITH those GcpsFallback Kefa entries active the fork lands ~4371 (residual +4 in ₺/₸ ceil-vs-iOS-
 * round); the remaining close-out is GCPS-side (DriftstackGcpsFallback.h), NOT here. Lowering these
 * Latin advances to absorb the GCPS error would corrupt the iOS-byte-exact Latin run subtotals (a
 * tune-to-pass that would fail any per-char/mutation gate). The height half (offsetHeight 149) is the
 * Kefa-III line-box, fixed in FontCoreText.cpp platformInit (NOT an advance).
 */

#pragma once

#if PLATFORM(DRIFTSTACK)

#include <wtf/ASCIICType.h>
#include <cstdlib>
#include <string_view>

namespace WebCore {

// Family-A gate: Kefa is present only on Safari major < 26 (mirrors FontCacheCoreText
// driftstackKefaPresentForArchetype — read DRIFTSTACK_ARCHETYPE LIVE, not a static cache,
// because the WebContent child is sandbox-denied the archetype-config JSON but getenv IS forwarded).
static inline bool driftstackKefaAdvancesActive()
{
    const char* arch = getenv("DRIFTSTACK_ARCHETYPE");
    if (!arch || !arch[0])
        return false;
    std::string_view sv(arch);
    auto pos = sv.find("safari");
    if (pos == std::string_view::npos)
        return false;
    pos += 6;
    int major = 0;
    while (pos < sv.size() && isASCIIDigit(sv[pos])) { major = major * 10 + (sv[pos] - '0'); ++pos; }
    return major > 0 && major < 26;
}

// Real iOS Kefa per-glyph advance @128px for the browserleaks 1:1 probe codepoints.
// 2026-06-27 (#4 matrix residual): A3 box-verified the Kefa group width is STILL 4394 (+27 over iOS
// 4367) even with DriftstackGcpsFallback.h's Kefa ₹/₺/₸ entries active. Root cause: macOS "Kefa III"
// HAS glyphs for ₹(U+20B9)/₺(U+20BA)/₸(U+20B8) IN ITS PRIMARY FACE (advance ~77.696 → ceil 78), so
// they NEVER route to a fallback run — the GcpsFallback hooks (ComplexTextController:794,
// FontCascade::widthForSimpleTextSlow) are FALLBACK-keyed and are bypassed. Real iOS "Kefa" LACKS
// ₹/₺/₸ → they fall to Helvetica (₹66.5, ₺/₸71.1875). To match, intercept the PRIMARY Kefa-III glyph
// here too: ₹/₺/₸ now live in this primary-face override (78→67/72/72, ≈ −27 → 4367). ẞ(U+1E9E) Kefa
// III HAS too (≈86.272 → 87) vs iOS Kefa 86.9375 (→87) — same ceil, no-op, included for correctness.
// ▁(U+2581)/ॿ(U+097F): Kefa III LACKS a glyph → they DO route to fallback → still handled by
// DriftstackGcpsFallback.h (do NOT add here). The Kefa ₹/₺/₸ entries in GcpsFallback are now
// redundant (never fire for Kefa) but harmless; left for documentation.
// Returns true + outAdvance (scaled to sizePx) when cp is a Kefa-face probe codepoint, else false.
static inline bool driftstackLookupKefaAdvance(char32_t cp, float sizePx, float& outAdvance)
{
    struct Entry { char32_t cp; float adv128; };
    // Captured: blfonts-iPhone_16_Pro_Max-1782581084705.json kefaPerChar.floatPer (x40-repeat /40,
    // getBoundingClientRect float) on real iOS 18.6 (metricsHash c6bdb116 re-confirmed same capture).
    static constexpr Entry kKefaProbeAdvances[] = {
        { 0x006D, 109.5625f },  // m  (×21 in the probe)
        { 0x004D, 107.625f },   // M
        { 0x006C, 37.75f },     // l
        { 0x004C, 67.3125f },   // L
        { 0x0069, 38.0625f },   // i
        { 0x0049, 44.25f },     // I
        { 0x0077, 101.8125f },  // w
        { 0x0057, 116.875f },   // W
        // GCPS chars that Kefa III renders in its PRIMARY face (so they bypass the fallback-keyed
        // GcpsFallback hook). Real iOS Kefa lacks these → Helvetica advances (@128px in-run floats):
        { 0x20B9, 66.5f },      // ₹ INDIAN RUPEE SIGN (iOS Helvetica; Kefa III primary ~77.696)
        { 0x20BA, 71.1875f },   // ₺ TURKISH LIRA SIGN  (iOS Helvetica; Kefa III primary ~77.696)
        { 0x20B8, 71.1875f },   // ₸ TENGE SIGN         (iOS Helvetica; Kefa III primary ~77.696)
        { 0x1E9E, 86.9375f },   // ẞ LATIN CAPITAL SHARP S (iOS Kefa 86.9375; Kefa III ~86.272 — both →ceil 87, no-op)
    };
    for (const auto& e : kKefaProbeAdvances) {
        if (e.cp == cp) {
            outAdvance = e.adv128 * (sizePx / 128.0f);
            return true;
        }
    }
    return false;
}

} // namespace WebCore

#endif // PLATFORM(DRIFTSTACK)
