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

// W2995: pure unit test for the Driftstack iOS scroll-momentum coast decay math
// (the "slide like a new iPhone" Step-B kinetic glide). The stateful engine lives in
// Source/WebKit/WebProcess/WebPage/WebPage.cpp::driftstackScrollCoastTick; its arithmetic is
// factored into the self-contained header Source/WebKit/Shared/DriftstackScrollCoastMath.h
// (reachable from this test via TestWebKitAPIBase.xcconfig's Source/WebKit/Shared search path).
// This is momentum-arc TESTABILITY PREP only -- the DRIFTSTACK_SCROLL_MOMENTUM gate stays gated
// on an A1 BrowserStack post-lift capture re-validating the 0.998/ms decay constant; this test
// does not flip it.

#include "config.h"

#include "DriftstackScrollCoastMath.h"
#include <cmath>

namespace TestWebKitAPI {

using namespace WebKit::DriftstackScrollCoast;

// (a) The simulated discrete ~60Hz coast offset matches the closed-form decay law
//     offset(T) = v0*(d^T_ms - 1)/ln(d)/1000 within a granularity tolerance. The discrete loop
//     (offset BEFORE decay each tick) is a left-endpoint Riemann sum of the integral and
//     overshoots it slightly, so we assert the relative error stays small and bounded.
TEST(DriftstackScrollCoastMath, DiscreteCoastMatchesClosedFormLaw)
{
    constexpr double v0 = 1000.0; // px/s lift-off
    constexpr double tickSeconds = 1.0 / 60.0;
    constexpr double tickMs = tickSeconds * 1000.0;

    double velocity = v0;
    double simulatedOffset = 0.0;
    double elapsedMs = 0.0;

    // Coast for ~500ms (30 ticks at 60Hz), comparing against the continuous law at each step.
    for (int i = 0; i < 30; ++i) {
        // Engine order: step uses the CURRENT velocity, THEN the velocity decays.
        simulatedOffset += offsetForTick(velocity, tickSeconds);
        velocity *= decayFactorForTickMs(tickMs);
        elapsedMs += tickMs;

        double closed = closedFormOffsetForMs(v0, elapsedMs);
        // Discrete left-endpoint sum overshoots the integral; the gap grows with elapsed time but
        // stays well under 3% for a 60Hz coast. Assert a tight relative bound (and that the sum
        // never UNDERSHOOTS -- a left sum of a decaying integrand is always >= the integral).
        double relativeError = (simulatedOffset - closed) / closed;
        EXPECT_GE(relativeError, 0.0);
        EXPECT_LT(relativeError, 0.03);
    }

    // The closed-form velocity law is exact (independent of tick granularity): after the same
    // elapsed time the analytic velocity must equal v0*d^t.
    EXPECT_NEAR(velocity, velocityAfterMs(v0, elapsedMs), 1e-6);
}

// (a') The per-tick decay factor is exactly pow(0.998, dtMs) and composes: applying two ticks of
//     dt is the same as one tick of 2*dt (frame-rate normalization -- a late tick decays
//     proportionally, never a discontinuity).
TEST(DriftstackScrollCoastMath, DecayFactorIsFrameRateNormalized)
{
    EXPECT_NEAR(decayFactorForTickMs(16.667), std::pow(0.998, 16.667), 1e-12);

    double oneStep = decayFactorForTickMs(33.334);
    double twoSteps = decayFactorForTickMs(16.667) * decayFactorForTickMs(16.667);
    EXPECT_NEAR(oneStep, twoSteps, 1e-9);

    // A zero-length tick must not decay (identity), and a longer tick decays strictly more.
    EXPECT_NEAR(decayFactorForTickMs(0.0), 1.0, 1e-12);
    EXPECT_LT(decayFactorForTickMs(50.0), decayFactorForTickMs(16.667));
}

// (b) The coast STOPS at the rest threshold (kRestSpeed = 30 px/s) -- it does not run forever.
//     Simulate the full discrete coast and assert it crosses below rest in a bounded number of
//     ticks, and that isAtRest() flips exactly at 30 px/s.
TEST(DriftstackScrollCoastMath, CoastStopsAtRestThreshold)
{
    EXPECT_DOUBLE_EQ(kRestSpeed, 30.0);

    // Just-below vs just-above the rest threshold.
    EXPECT_TRUE(isAtRest(29.999));
    EXPECT_FALSE(isAtRest(30.0));
    EXPECT_FALSE(isAtRest(30.001));

    constexpr double v0 = 2000.0; // a fast flick
    constexpr double tickSeconds = 1.0 / 60.0;
    constexpr double tickMs = tickSeconds * 1000.0;

    double velocity = v0;
    int ticks = 0;
    constexpr int kMaxTicks = 100000; // a runaway guard: must terminate WELL before this
    while (!isAtRest(std::fabs(velocity)) && ticks < kMaxTicks) {
        velocity *= decayFactorForTickMs(tickMs);
        ++ticks;
    }
    // From 2000 px/s, v0*d^t < 30 at t = ln(30/2000)/ln(0.998) ms ~= 2098ms ~= 126 ticks at 60Hz.
    EXPECT_LT(ticks, kMaxTicks);
    EXPECT_GT(ticks, 0);
    EXPECT_LT(ticks, 200);
    EXPECT_TRUE(isAtRest(std::fabs(velocity)));

    // Cross-check against the analytic time-to-rest.
    double analyticRestMs = std::log(kRestSpeed / v0) / std::log(kDecayPerMs);
    EXPECT_NEAR(ticks * tickMs, analyticRestMs, tickMs); // within one tick of the analytic crossing
}

// (c) A lift-off speed below kMinLiftoffSpeed (80 px/s) does NOT start a coast -- e.g. 50 < 80 is
//     rejected, while a flick at/above 80 starts one. iOS does not fling a slow release.
TEST(DriftstackScrollCoastMath, SubThresholdLiftoffDoesNotCoast)
{
    EXPECT_DOUBLE_EQ(kMinLiftoffSpeed, 80.0);

    EXPECT_FALSE(shouldStartCoast(50.0));  // the task's 50 < 80 case
    EXPECT_FALSE(shouldStartCoast(79.999));
    EXPECT_TRUE(shouldStartCoast(80.0));   // boundary: >= starts a coast
    EXPECT_TRUE(shouldStartCoast(80.001));
    EXPECT_TRUE(shouldStartCoast(2000.0));

    // A speed below the lift-off threshold is also below the rest threshold's larger gate, so even
    // if it somehow started it would immediately be at rest -- defense in depth on the boundaries.
    EXPECT_FALSE(shouldStartCoast(0.0));
}

// (d) The dt-cap prevents a lurch on a stalled tick: a 200ms gap is clamped to 50ms, so the step
//     scrolled and the decay applied are computed from 50ms, NOT 200ms.
TEST(DriftstackScrollCoastMath, DtCapPreventsLurchOnStalledTick)
{
    EXPECT_DOUBLE_EQ(kMaxTickSeconds, 0.050);

    constexpr double velocity = 1000.0; // px/s

    // A normal ~16.7ms tick is left untouched by the cap.
    EXPECT_NEAR(clampTickSeconds(0.016667), 0.016667, 1e-9);

    // A 200ms stalled tick is clamped to 50ms.
    double stalled = clampTickSeconds(0.200);
    EXPECT_DOUBLE_EQ(stalled, 0.050);

    // The offset for the clamped tick is the 50ms step (50px at 1000px/s), NOT the uncapped
    // 200ms step (200px) -- this is the anti-lurch guarantee.
    double cappedOffset = offsetForTick(velocity, stalled);
    double uncappedOffset = offsetForTick(velocity, 0.200);
    EXPECT_DOUBLE_EQ(cappedOffset, 50.0);
    EXPECT_DOUBLE_EQ(uncappedOffset, 200.0);
    EXPECT_LT(cappedOffset, uncappedOffset);

    // The decay for the clamped tick is likewise computed from 50ms, not 200ms (a capped tick
    // decelerates by at most pow(0.998, 50), never the much larger pow(0.998, 200) drop).
    double cappedDecay = decayFactorForTickMs(stalled * 1000.0);
    double uncappedDecay = decayFactorForTickMs(200.0);
    EXPECT_NEAR(cappedDecay, std::pow(0.998, 50.0), 1e-12);
    EXPECT_GT(cappedDecay, uncappedDecay); // capped retains MORE velocity (smaller decel)
}

} // namespace TestWebKitAPI
