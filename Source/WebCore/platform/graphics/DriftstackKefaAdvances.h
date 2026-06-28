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
 * These are the genuine real-iOS Kefa glyph advances (not tuned-to-group).
 *
 * Only the probe-string codepoints are listed (the only ones that drive the blfonts metricsHash);
 * every other glyph of Kefa III is left at its native macOS advance. Miss -> caller keeps the Mac CT
 * advance.
 *
 * 2026-06-28 canonical-path trace (closes the prior speculation). The per-glyph floats here are
 * byte-exact to iOS (the kefaPerChar/x40 isolation path renders 4340,149 / bcr 4338.264 == iOS). BUT
 * the metricsHash GROUP target is the WHOLE-STRING single-shot inline-span offsetWidth = 4367,149, and
 * that +27 over the incremental value is a WHOLE-RUN measurement artifact present on iOS itself (same
 * capture yields BOTH 4367 group and 4339 incremental from these identical advances) — it is NOT a
 * per-glyph advance, so it CANNOT be closed from this table without breaking the (correct) x40 path.
 * See the detailed two-path ground-truth note above driftstackLookupKefaAdvance() and the residual note
 * in ComplexTextController.cpp (~line 797). DO NOT lower these Latin advances to chase the canonical
 * group: that corrupts the iOS-byte-exact x40 subtotals (a tune-to-pass that fails any per-char/mutation
 * gate). The height half (offsetHeight 149) is the Kefa-III line-box, fixed in FontCoreText.cpp
 * platformInit (NOT an advance).
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
// 2026-06-28 (#96 Kefa-18.6 WIDTH GROUP — the last matrix residual).
//
// ⭐ TWO GROUND-TRUTH NUMBERS, TWO MEASUREMENT PATHS — the metricsHash target is the GROUP, 4367,149:
//   • CANONICAL GROUP (the browserleaks metricsHash DRIVER) = "4367,149" / metricsHash c6bdb116.
//     This is the WHOLE-STRING inline `span.innerHTML="mmm…₹▁₺₸ẞॿ…"; span.style.fontFamily='Kefa'`
//     single-shot offsetWidth that browserleaks groups+hashes. Captured on a real iPhone 16 Pro
//     (aio-iPhone_16_Pro-1781706872739, the Family-A launch archetype iphone16pro_ios18_6) AND on a
//     16 Pro Max (blfonts-iPhone_16_Pro_Max-1782581084705 — same value 4367,149/c6bdb116).
//   • kefaPerChar.fullKefa (a SEPARATE bcr sub-probe, NOT hashed) = "4340,149", bcr float 4338.264.
//     This is the INCREMENTAL `appendChild(createTextNode(STR))` construction — a DIFFERENT DOM path
//     that yields a DIFFERENT offsetWidth on the SAME real device (kefaadv perChar_prefix sums 4339).
//   The earlier a96f0ba5 edit wrongly moved this header's "target" to 4340 (the kefaPerChar bcr field);
//   that is NOT the metricsHash target. The metricsHash group is 4367,149 — corrected back here.
//
// ⭐ THE +27 (4367 group vs 4340 incremental) IS A WHOLE-RUN MEASUREMENT ARTIFACT, NOT A PER-GLYPH
//   ADVANCE. It exists on iOS ITSELF (same capture, same device, same font, same string) and is
//   INVISIBLE in any per-char decomposition: the per-char prefix advOw and the isolated-x40 floats
//   (m 109.5625, ₹ 66.5, ₺/₸ 71.1875, …) BOTH sum to 4339 — never 4367. iOS produces both 4367 and
//   4339 from the IDENTICAL glyph advances. CONSEQUENCE: no entry in THIS table (or any per-glyph
//   advance edit anywhere) can make the canonical group land 4367 while keeping the incremental/x40
//   path at iOS's 4340 — closing one moves the other. The residual canonical +27 (fork 4394 vs iOS
//   4367, after removing the over-counting complex override — see ComplexTextController.cpp ~797) is a
//   whole-run single-shot offsetWidth artifact (fork over-adds ~+26 vs iOS in the complex layout) that
//   must be render-fixed in the layout/run-accumulation path, NOT via these advances. See the residual
//   note in ComplexTextController.cpp.
//
// WHAT THIS TABLE IS FOR (still correct + load-bearing): CSS "Kefa" aliases to macOS "Kefa III", whose
// per-glyph advances differ from real iOS Kefa for the probe. Verified from KefaIII.ttf hmtx @128px:
// Latin is LOWER (m 103.42 vs 109.5625, l 31.49 vs 37.75, w 96.13 vs 101.8125, …) and ₹/₺/₸ are HIGHER
// (77.696 vs iOS 66.5 / 71.1875 / 71.1875). Kefa III renders m/M/l/L/i/I/w/W and ₹/₺/₸/ẞ IN ITS PRIMARY
// FACE, so the simple/x40 path's Font::platformWidthForGlyph (FontCoreText:1160, gated on the resolved
// "Kefa III" face) consumes THIS table to land the iOS per-glyph values → measureText + the kefaPerChar
// incremental/isolation paths are byte-exact (4340/4338.264). The GCPS ₹/₺/₸/ẞ are ALSO corrected on
// every path by DriftstackGcpsFallback.h (keyed on CSS primary "Kefa" + cp, run-face-agnostic), so the
// complex/whole-run path needs no per-glyph Kefa hook (the prior one regressed canonical +9 and was
// removed). ▁(U+2581)/ॿ(U+097F): Kefa III LACKS the glyph → handled only by DriftstackGcpsFallback.h
// (do NOT add ▁/ॿ here). The Kefa ₹/₺/₸/ẞ entries in GcpsFallback override-equal these (same iOS source).
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
