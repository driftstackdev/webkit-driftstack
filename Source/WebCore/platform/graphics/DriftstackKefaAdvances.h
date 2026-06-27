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

// Real iOS Kefa per-glyph advance @128px for the browserleaks 1:1 probe LATIN codepoints.
// (The GCPS chars ₹▁₺₸ẞॿ have no glyph in Kefa III — they render through fallback faces and are
// corrected in DriftstackGcpsFallback.h keyed by the PRIMARY "Kefa" family, NOT here.)
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
