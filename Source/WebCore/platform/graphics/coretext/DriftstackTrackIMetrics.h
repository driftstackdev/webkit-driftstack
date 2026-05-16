/*
 * DriftstackTrackIMetrics.h — V-433 Track I per-font iOS metric overrides.
 *
 * Wave 29-239 — empirical iOS metric data captured from iPhone 17 / Safari 26.4
 * via Track I non-CJK BS orchestration mode (operations/scripts/v_track_i_non_cjk_fonts_probe.html
 * + bs-orchestrate.js trackINonCjkFonts MATRIX entry). 840-measurement session
 * captured 2026-05-16 ~09:15 UTC.
 *
 * Source: reference/trackI-captures/2026-05-16T09-15-04-230Z_*.json
 *
 * Per-font canonical metric (fontBoundingBoxAscent / fontBoundingBoxDescent
 * at size=16) → scale to em-units (1000-em) for ascent/descent override
 * application in FontCoreText.cpp Track I table.
 */

#pragma once

#if PLATFORM(DRIFTSTACK)

#include <cstdint>

namespace WebCore {
namespace Driftstack {

// Track I non-CJK fallback font metrics from iPhone 17 / Safari 26.4 (Family B).
// fbbA / fbbD captured at size=16; em scale = 16/unitsPerEm; typoAscent =
// fbbA * unitsPerEm / 16. Use unitsPerEm=1000 for these fonts unless otherwise
// specified.
struct TrackIFontMetric {
    const char* label;            // Mac family name (for matching)
    uint16_t unitsPerEm;
    int16_t typoAscent;            // positive: ascent above baseline
    int16_t typoDescent;           // positive: descent below baseline (will be negated in FontCoreText)
    int16_t typoLineGap;
};

// Empirically-derived from Track I BS burst 2026-05-16T09-15-04Z.
// Scaled from size=16 fbbA / fbbD with unitsPerEm=1000 (factor 62.5x).
inline const TrackIFontMetric kTrackIFontMetrics[] = {
    // Family                         unitsPerEm  typoAsc  typoDesc  typoLineGap
    { "Devanagari Sangam MN",          1000,      938,      438,      0 },  // fbbA=15 fbbD=7 at 16pt
    { "Geeza Pro",                     1000,      938,      375,      0 },  // fbbA=15 fbbD=6
    { "Hebrew",                        1000,      938,      250,      0 },  // fbbA=15 fbbD=4
    { "Khmer Sangam MN",               1000,     1125,      688,      0 },  // fbbA=18 fbbD=11
    { "Kohinoor Devanagari",           1000,     1063,      375,      0 },  // fbbA=17 fbbD=6
    { "Thonburi",                      1000,     1125,      250,      0 },  // fbbA=18 fbbD=4
};

// trackIMetricForFamily helper removed wave 29-240 r3: callers use
// kTrackIFontMetrics[N] direct indexing. Avoids -Wunsafe-buffer-usage
// errors on C-string parameters (WebKit requires std::span / std::string_view
// for buffer-aware APIs).

} // namespace Driftstack
} // namespace WebCore

#endif // PLATFORM(DRIFTSTACK)
