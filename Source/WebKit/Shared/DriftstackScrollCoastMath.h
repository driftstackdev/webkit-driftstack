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

// W2961 / W2995: PURE decay math for the Driftstack iOS scroll-momentum coast
// (the "slide like a new iPhone" Step-B kinetic glide). The stateful engine lives in
// WebProcess/WebPage/WebPage.cpp::driftstackScrollCoastTick (timer, hit-test, scroll
// dispatch); the arithmetic it runs each ~60Hz tick is factored out HERE so it can be
// unit-tested in isolation (TestWebKitAPI/Tests/WebCore/DriftstackScrollCoastMathTests.cpp),
// matching the testability bar of the GUI computeFlingPath. This header is self-contained
// (only <cmath>) so it is includable from both the WebProcess engine and the test target
// (Source/WebKit/Shared is on the TestWebKitAPI header search path, TestWebKitAPIBase.xcconfig).
//
// These functions are PURE (no I/O, no WebKit types, deterministic): the live coast and the
// test share ONE source of truth for the decay constant, the rest/lift-off thresholds, and the
// dt cap. Flipping the gate (DRIFTSTACK_SCROLL_MOMENTUM) stays separately gated on an A1
// BrowserStack post-lift capture re-validating the 0.998/ms decay constant — this header is
// testability PREP only and does not change the default-off behavior.

namespace WebKit {

namespace DriftstackScrollCoast {

// iOS UIScrollView.DecelerationRate.normal ~= 0.998 per millisecond. Anchored on Apple's
// published value; a behavioral TELL -- re-validate against a fresh multi-flick iOS capture
// before flipping DRIFTSTACK_SCROLL_MOMENTUM on (per project_perfect_scroll_stepB_design).
constexpr double kDecayPerMs = 0.998;

// Below this lift-off speed (px/s) the coast distance is sub-perceptible, so no coast is
// started -- iOS likewise does not fling a slow release.
constexpr double kMinLiftoffSpeed = 80; // px/s

// Once the coast slows below this speed (px/s) it stops and the velocity is zeroed -- iOS
// settling to rest.
constexpr double kRestSpeed = 30; // px/s

// A degenerate / absurd tick interval (timer reschedule jitter, debugger pause) is capped to
// this many seconds so a long stall can never lurch the page by one huge step.
constexpr double kMaxTickSeconds = 0.050; // 50 ms

// Per-tick velocity decay factor for a tick of dtMs milliseconds: pow(kDecayPerMs, dtMs).
// Frame-rate-normalized so a 16.7ms tick decays by ~0.998^16.7 and an occasional late tick
// decays proportionally (never a discontinuity).
inline double decayFactorForTickMs(double dtMs)
{
    return std::pow(kDecayPerMs, dtMs);
}

// Velocity (px/s) after coasting freely for tMs milliseconds from an initial v0: the exact
// closed form of the per-tick decay, v(t) = v0 * d^(t_ms). Independent of tick granularity.
inline double velocityAfterMs(double v0, double tMs)
{
    return v0 * std::pow(kDecayPerMs, tMs);
}

// Cap a raw tick interval (seconds) to kMaxTickSeconds. A non-positive dt is left as-is for
// the caller to skip; this only bounds the upper end (the anti-lurch dt cap).
inline double clampTickSeconds(double dtSeconds)
{
    return dtSeconds > kMaxTickSeconds ? kMaxTickSeconds : dtSeconds;
}

// Offset scrolled in one tick = velocity (px/s) * dt (seconds). Mirrors the engine's
// stepX/stepY = m_driftstackScrollVelocity * dt.seconds().
inline double offsetForTick(double velocity, double dtSeconds)
{
    return velocity * dtSeconds;
}

// Should a coast START for this lift-off speed? (TouchEnd gate.)
inline bool shouldStartCoast(double liftoffSpeed)
{
    return liftoffSpeed >= kMinLiftoffSpeed;
}

// Has the coast reached rest at this current speed? (Per-tick stop gate.)
inline bool isAtRest(double currentSpeed)
{
    return currentSpeed < kRestSpeed;
}

// Total offset scrolled while coasting CONTINUOUSLY for tMs milliseconds from v0 -- the
// closed-form integral of v0*d^(t) (the law the discrete tick loop approximates):
//   integral_0^T v0*d^(t_ms) dt   (t in seconds, t_ms = 1000*t)
//   = v0*(d^(T_ms) - 1) / ln(d) / 1000.
// The discrete ~60Hz tick loop (offsetForTick applied BEFORE decayFactorForTickMs each tick)
// is a left-endpoint Riemann sum of this integral and overshoots it slightly (granularity-
// bounded). Used as the reference law the test compares the simulated coast against.
inline double closedFormOffsetForMs(double v0, double tMs)
{
    return v0 * (std::pow(kDecayPerMs, tMs) - 1.0) / std::log(kDecayPerMs) / 1000.0;
}

} // namespace DriftstackScrollCoast

} // namespace WebKit
