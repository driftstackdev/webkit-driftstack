/*
 * Copyright (C) 2026 Driftstack. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
 * OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#pragma once

#include <cmath>

// W3010: PURE math for the Driftstack iOS rubber-band over-scroll relaxation
// (the "behave exactly like iPhone" bounce when a drag/coast is pushed past the
// content's top/bottom boundary). The stateful engine lives in
// WebProcess/WebPage/WebPage.cpp (the m_driftstackRubberBand* state + the
// driftstackRubberBandTick timer + the boundary-clamp hook in the touch/coast
// scroll paths); the arithmetic it runs each ~60Hz tick is factored out HERE so it
// can be unit-tested in isolation (TestWebKitAPI/Tests/WebCore/DriftstackRubberBandMathTests.cpp),
// matching the testability bar of the momentum coast (DriftstackScrollCoastMath.h).
//
// These functions are PURE (no I/O, no WebKit types, deterministic): the live
// rubber-band and the test share ONE source of truth for the relaxation time-constant,
// the resistance model, and the rest threshold. Flipping the gate
// (DRIFTSTACK_RUBBERBAND_IOS) does not change the default-off behavior; this header
// is the locked SHAPE.
//
// ── Ground truth (BS real-iPhone capture ae547cfd, iOS 18.7 / Safari 26.4, 2026-06-28) ──
// The iOS ScrollElasticity over-scroll, measured as the excursion-beyond-boundary e(t):
//   • relaxation time-constant τ(peak/e) ≈ 191 ms  -- BIT-STABLE across drags,
//     VELOCITY-INDEPENDENT → it is an ENGINE CONSTANT (the thing we lock).
//   • ~650 ms perceptual decay-to-boundary, exponential ease-out.
//   • peak excursion (~215px in the capture) is OVER-PUSH-INPUT-DEPENDENT, NOT an
//     engine constant → we do NOT lock the absolute peak (file-110: no fake variance).
// So the law we reproduce is e(t) = e0 * exp(-t / τ) with τ = 0.191 s, where e0 is
// whatever the gesture pushed past the boundary. At t = τ the excursion is e0/e
// (≈0.368·e0 — the captured peak/e point), and the excursion is sub-pixel (≤1px for a
// ~215px peak) by ~t ≈ τ·ln(peak) ≈ 1.0s, with the bulk of the visible motion gone by
// ~650ms (e^-3.4 ≈ 0.033·peak ≈ 7px) — matching the captured exponential shape.

namespace WebKit {

namespace DriftstackRubberBand {

// iOS ScrollElasticity relaxation time-constant (seconds). The excursion past the
// boundary relaxes as e0*exp(-t/τ). LOCKED from the BS capture (τ(peak/e)≈191ms,
// velocity-independent). This is the behavioral TELL — do not tune it to a "feel".
constexpr double kTauSeconds = 0.191;

// Below this excursion (px) the rubber-band has visually settled to the boundary, so
// the relaxation stops and the offset snaps exactly to the edge (iOS settles to rest).
constexpr double kRestPx = 0.5;

// A degenerate / absurd tick interval (timer reschedule jitter, debugger pause) is
// capped to this many seconds so a long stall can never relax in one huge step.
constexpr double kMaxTickSeconds = 0.050; // 50 ms

// iOS over-scroll RESISTANCE (the "stretch") — as the finger drags past the boundary
// the content follows with diminishing return, not 1:1. AppKit/UIKit use a rubber-band
// curve where the visible stretch grows ~logarithmically with the raw over-drag. We
// model the incremental resistance as a simple linear damping on how much of an
// over-boundary drag delta is absorbed into the stretch: the more already stretched,
// the less each further px adds. kStretchDivisor matches the iOS feel (a ~constant the
// raw over-drag is divided by as the stretch grows); the absolute peak it produces is
// input-dependent (NOT locked) — only the RELAXATION τ/shape is the locked engine
// constant. resistedStretchIncrement returns the px the stretch grows for a raw
// over-boundary drag delta, given the CURRENT stretch and the viewport extent.
constexpr double kStretchDivisor = 0.55; // fraction of raw over-drag absorbed at zero stretch

// The additional stretch (px) produced by a raw over-boundary drag delta `rawDelta`
// (px the finger moved past the boundary this move) given the current stretch
// `currentStretch` (px) and the scrollable `extent` (px, the viewport dimension along
// the axis). Diminishing-return curve: the resistance grows with how far already
// stretched relative to the extent, so the stretch asymptotes rather than tracking the
// finger 1:1 — the iOS rubber-band feel. Returns >=0. extent<=0 falls back to a plain
// damped delta (no asymptote) so a degenerate extent can't divide-by-zero.
inline double resistedStretchIncrement(double rawDelta, double currentStretch, double extent)
{
    if (rawDelta <= 0.0)
        return 0.0;
    double damp = kStretchDivisor;
    if (extent > 0.0) {
        // As currentStretch approaches the extent, resistance → 1 (further drag barely
        // moves the content). Clamp the ratio to [0,1) so the factor stays in (0, kStretchDivisor].
        double ratio = currentStretch / extent;
        if (ratio < 0.0)
            ratio = 0.0;
        if (ratio > 0.95)
            ratio = 0.95;
        damp = kStretchDivisor * (1.0 - ratio);
    }
    return rawDelta * damp;
}

// The excursion (px) remaining after relaxing for tMs milliseconds from an initial
// excursion e0: the exact closed form e0*exp(-t/τ). Independent of tick granularity —
// the live tick loop samples this law at each frame.
inline double excursionAfterMs(double e0, double tMs)
{
    return e0 * std::exp(-(tMs / 1000.0) / kTauSeconds);
}

// The stretch (px) AFTER one relaxation tick of dtSeconds, given the stretch BEFORE the
// tick. Frame-rate-normalized via exp(-dt/τ) so a 16.7ms tick relaxes by exp(-0.0167/τ)
// and an occasional late tick relaxes proportionally (never a discontinuity). This is
// the per-tick analogue the engine applies: stretch *= relaxFactorForTick(dt).
inline double relaxFactorForTick(double dtSeconds)
{
    return std::exp(-dtSeconds / kTauSeconds);
}

// Cap a raw tick interval (seconds) to kMaxTickSeconds. A non-positive dt is left as-is
// for the caller to skip; this only bounds the upper end (the anti-lurch dt cap).
inline double clampTickSeconds(double dtSeconds)
{
    return dtSeconds > kMaxTickSeconds ? kMaxTickSeconds : dtSeconds;
}

// Has the rubber-band settled at this current excursion (px)? (Per-tick stop gate.)
inline bool isAtRest(double currentExcursion)
{
    return std::abs(currentExcursion) < kRestPx;
}

// The time (ms) at which an excursion starting at e0 decays to `target` px under the
// exp(-t/τ) law: t = τ*ln(e0/target)*1000. Used by the test to assert the captured
// τ(peak/e) and decay-to-boundary timings. e0<=target → 0.
inline double timeToReachMs(double e0, double target)
{
    if (e0 <= target || target <= 0.0)
        return 0.0;
    return kTauSeconds * std::log(e0 / target) * 1000.0;
}

} // namespace DriftstackRubberBand

} // namespace WebKit
