/*
 * Copyright (C) 2016-2019 Apple Inc. All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY APPLE INC. ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL APPLE INC. OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. 
 */

#pragma once

#include <wtf/ClockType.h>
#include <wtf/GenericTimeMixin.h>
#include <wtf/Int128.h>
#include <cstdint>
#include <wtf/Noncopyable.h>

namespace WTF {

class MonotonicTime;
class PrintStream;

// The current time according to a wall clock (aka real time clock). This uses floating point
// internally so that you can reason about infinity and other things that arise in math. It's
// acceptable to use this to wrap NaN times, negative times, and infinite times, so long as they
// are relative to the same clock. Use this only if wall clock time is needed. For elapsed time
// measurement use MonotonicTime instead.
class WallTime final : public GenericTimeMixin<WallTime> {
public:
    static constexpr ClockType clockType = ClockType::Wall;
    
    // This is the epoch. So, x.secondsSinceEpoch() should be the same as x - WallTime().
    constexpr WallTime() = default;

    WTF_EXPORT_PRIVATE static WallTime now();
    
    WTF_EXPORT_PRIVATE void dump(PrintStream&) const;

private:
    friend class GenericTimeMixin<WallTime>;
    constexpr WallTime(double rawValue)
        : GenericTimeMixin<WallTime>(rawValue)
    {
    }
};
static_assert(sizeof(WallTime) == sizeof(double));

template<>
struct MarkableTraits<WallTime> {
    static bool isEmptyValue(WallTime time)
    {
        return time.isNaN();
    }

    static constexpr WallTime emptyValue()
    {
        return WallTime::nan();
    }
};

WTF_EXPORT_PRIVATE Int128 currentTimeInNanoseconds();

#if PLATFORM(DRIFTSTACK)
// W2882/#50 timing-fidelity virtual-clock skew: a thread-local Seconds offset added to performance.now()
// and Date.now() so per-operation timing matches the iPhone archetype. Both JSC (Date.now) and WebCore
// (Performance::now) read this. The accumulated offset CANCELS in deltas (a fingerprinter measures t1-t0);
// only the per-op charge applied between two reads survives -> measured delta == the op's iPhone cost.
// INERT until Phase-5 op-charging wires advanceDriftstackVirtualSkew() into the timed ops (skew stays 0).
// Defined in WallTime.cpp as a SINGLE exported symbol (NOT header-inline) so all of WTF/JavaScriptCore/
// WebCore share ONE thread-local across the dylib boundary; a header-inline static gives each dylib its own
// copy and cross-dylib charges (e.g. JSON.parse in JSC) become invisible to perf.now (WebCore).
WTF_EXPORT_PRIVATE Seconds driftstackVirtualSkew();
WTF_EXPORT_PRIVATE void advanceDriftstackVirtualSkew(Seconds delta);
WTF_EXPORT_PRIVATE void resetDriftstackVirtualClockSession();   // reset per-document cold flags + skew on navigation/teardown

// M8 virtual clock (engine + audit-corrected design notes in WallTime.cpp). INERT unless DRIFTSTACK_VIRTUAL_CLOCK=1.
// Samples per-archetype op costs (UNIMODAL cold + 0/1/2 warm multinomial + AR(1) thermal, crypto-random — no
// recoverable PRNG state) and charges modeled-minus-macActual into the shared skew ledger above. Declared here
// (not a separate header) because the Xcode build only compiles files registered in WTF.xcodeproj. Per-archetype
// params + spec: /Users/john/code/driftstack/docs/internal/timing-fidelity-variance-model.md.
enum class DriftstackTimedOp : uint8_t { ToDataURL, GetImageData, Render, MeasureText, WasmCompile, Count };

class DriftstackVirtualClock {
    WTF_MAKE_NONCOPYABLE(DriftstackVirtualClock);
public:
    WTF_EXPORT_PRIVATE static DriftstackVirtualClock& singleton();
    bool enabled() const { return m_enabled; }
    // Charge a timed op: samples the archetype cost for `op` (cold on its first charged call), updates the skew
    // ledger by (modeled - macActual). No-op unless enabled(). Caller measures macActual via a scope-exit.
    WTF_EXPORT_PRIVATE void chargeOp(DriftstackTimedOp, double pixels, Seconds macActual);
    WTF_EXPORT_PRIVATE Seconds currentSkew() const;            // == driftstackVirtualSkew()
    DriftstackVirtualClock();   // public so NeverDestroyed can build the singleton; copies blocked. Use singleton().
private:
    double sampleCostMs(DriftstackTimedOp, double pixels, bool isCold);
    uint64_t nextRandom(DriftstackTimedOp);
    bool m_enabled { false };
};
#endif

} // namespace WTF

using WTF::WallTime;
