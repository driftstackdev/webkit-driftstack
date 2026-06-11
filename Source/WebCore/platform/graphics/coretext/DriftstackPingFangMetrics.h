/*
 * Driftstack — PingFang per-weight metrics, extracted from iOS PingFang.ttc
 * via fontTools v4.62 (V-603, 2026-05-10). Used by V-602 option 1
 * (Hiragino base + PingFang metric overlay).
 *
 * Apple-proprietary cidg/hvgl outline tables prevent Mac CTFontManager
 * from parsing PingFang.ttc directly (V-487 PARSEFAIL). V-602 option 1
 * substitutes Mac Hiragino as the rendered font for CJK clusters and
 * overrides Mac Hiragino's metrics with PingFang values from this table.
 *
 * Data source: driftstack-fonts/iphone16pro-ios26.4.1/Core/PingFang.ttc  (sibling of the repo root)
 *               PingFang.ttc.NOTES (V-603 fontTools extraction)
 */

#pragma once

#if PLATFORM(DRIFTSTACK)

#include <array>
#include <cstdint>

namespace WebCore::Driftstack {

struct PingFangMetricEntry {
    // CSS font-weight bracket this entry applies to. CSS weight 100-900
    // resolves to the closest entry: e.g., weight=400 → Regular,
    // weight=700 → Bold.
    uint16_t weight;

    // OpenType design-units-per-em (unitsPerEm). Different per weight family
    // because PingFang's master-font set uses distinct EM-grids per weight.
    uint16_t unitsPerEm;

    // hhea-table metrics (signed font design units, NOT pixels).
    // Mac CT translates to pixels via (value / unitsPerEm) * pointSize.
    int16_t hheaAscent;
    int16_t hheaDescent;
    int16_t hheaLineGap;  // PingFang hhea lineGap is 0 across all weights

    // OS/2-table typo metrics (used when USE_TYPO_METRICS is set in OS/2 fsSelection).
    // PingFang has USE_TYPO_METRICS=0 BUT for layout consistency we provide
    // both metric pairs so the consumer can pick.
    int16_t typoAscent;
    int16_t typoDescent;
    int16_t typoLineGap;  // PingFang OS/2 lineGap is 400 across all weights

    // Human-readable weight family label. Useful for diagnostic logging.
    const char* label;
};

// Per-weight metric table for PingFang Standard (universal CJK fallback).
// PingFang TTC contains 32 sub-fonts spanning 7 weight families:
//
// Family             | Indices | unitsPerEm | hhea asc/desc/lg | typo asc/desc/lg
// PingFang TC Ultralight/Thin | 0-4   | 1028 | 884 / -144 / 0 | 860 / -140 / 400
// PingFang TC Light/Regular   | 5-9   | 1064 | 915 / -149 / 0 | 860 / -140 / 400
// PingFang TC Medium          | 10-14 | 1128 | 970 / -158 / 0 | 860 / -140 / 400
// PingFang TC Semibold        | 15-19 | 1144 | 984 / -160 / 0 | 860 / -140 / 400
// PingFang HK                 | 20-23 | 1000 | 1060 / -340 / 0| 860 / -140 / 400
// PingFang SC                 | 24-27 | 1000 | 860 / -140 / 0 | 860 / -140 / 400
// PingFang TC Bold/Black      | 28-31 | 1100 | 946 / -154 / 0 | 860 / -140 / 400
//
// All entries share typoAscent=860, typoDescent=-140, typoLineGap=400 in OS/2.
// This is the architecturally-correct vertical metric for canvas line-height
// computations independent of which specific weight resolves.
//
// Subset for initial launch: PingFang SC (the universal iPhone fallback
// regardless of CSS font-weight request). Resolution: any CSS font-weight
// maps to this single entry for v1. Multi-weight resolution is a follow-on
// once initial parity is verified.
inline constexpr std::array<PingFangMetricEntry, 7> kPingFangMetrics = {{
    // weight   uPM   hhea: asc / desc / lg    typo: asc / desc / lg    label
    {  100,  1028,    884,  -144,  0,           860, -140, 400, "PingFang TC Ultralight/Thin" },
    {  300,  1064,    915,  -149,  0,           860, -140, 400, "PingFang TC Light/Regular" },
    {  400,  1000,    860,  -140,  0,           860, -140, 400, "PingFang SC Regular (universal fallback)" },
    {  500,  1128,    970,  -158,  0,           860, -140, 400, "PingFang TC Medium" },
    {  600,  1144,    984,  -160,  0,           860, -140, 400, "PingFang TC Semibold" },
    {  700,  1100,    946,  -154,  0,           860, -140, 400, "PingFang TC Bold" },
    {  900,  1100,    946,  -154,  0,           860, -140, 400, "PingFang TC Black" },
}};

// Returns the PingFang metric entry closest to a given CSS font-weight.
// Used by Font::platformInit() V-602 substitute path to override Mac
// Hiragino metrics with PingFang values.
inline const PingFangMetricEntry& pingFangMetricForWeight(uint16_t cssWeight)
{
    // Bias toward the lighter weight on ties (matches Apple's
    // FontWeightSelectionAlgorithm for similar requests).
    const PingFangMetricEntry* best = &kPingFangMetrics[0];
    int bestDistance = std::abs(static_cast<int>(cssWeight) - static_cast<int>(kPingFangMetrics[0].weight));
    for (size_t i = 1; i < kPingFangMetrics.size(); ++i) {
        int distance = std::abs(static_cast<int>(cssWeight) - static_cast<int>(kPingFangMetrics[i].weight));
        if (distance < bestDistance) { best = &kPingFangMetrics[i]; bestDistance = distance; }
    }
    return *best;
}

} // namespace WebCore::Driftstack

#endif // PLATFORM(DRIFTSTACK)
