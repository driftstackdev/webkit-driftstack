/*
 * Copyright (C) 2016 Apple Inc. All rights reserved.
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

#include "config.h"
#include <wtf/WallTime.h>

#include <wtf/MonotonicTime.h>
#include <wtf/PrintStream.h>

#if PLATFORM(DRIFTSTACK)
#include <array>
#include <cstdlib>
#include <wtf/CryptographicallyRandomNumber.h>
#include <wtf/NeverDestroyed.h>
#endif

namespace WTF {

void WallTime::dump(PrintStream& out) const
{
    out.print("Wall(", m_value, " sec)");
}

#if PLATFORM(DRIFTSTACK)
// M8 virtual-clock engine + skew LEDGER. INERT unless DRIFTSTACK_VIRTUAL_CLOCK=1. Implemented HERE, alongside
// the skew the now() read path reads, rather than a separate DriftstackVirtualClock.cpp — the WTF unified-source
// build did not re-configure for a new .cpp. Class declared in wtf/DriftstackVirtualClock.h. Spec + audit
// (wckmdkws4): /Users/john/code/driftstack/docs/internal/timing-fidelity-variance-model.md.

// Single shared thread-local skew (one instance in the WTF dylib; declared in WallTime.h). All of
// WTF/JavaScriptCore/WebCore link to these exported accessors so cross-dylib op-charges (JSON.parse in JSC,
// toDataURL in WebCore) all land on the SAME skew that performance.now()/Date.now() read.
// (Worker-thread coverage = an audit completeness item; thread_local main-thread coherence kept for v1.)
static thread_local Seconds g_driftstackVirtualSkew { };
Seconds driftstackVirtualSkew() { return g_driftstackVirtualSkew; }

// Skew (engine review wbj0htxb5 #2,#3): the fork can only ADD time — slow a measured op up to the slower iPhone
// cost — it CANNOT un-elapse the Mac's already-spent real time, so a negative charge (Mac already slower than
// the modeled iPhone cost: sub-quantum getImageData noise, or rarely a loaded Mac) is DROPPED, not banked. (A
// deficit ledger absorbed later positive charges -> collapsed the modeled per-op delta to ~0.) Soft-capped
// SMALL so the absolute offset stays within real-device NTP variance and never pins at an implausible constant
// (the old 250ms one-way climb was detectable vs external time). REFINEMENT: mean-revert/decay during idle so
// it never flat-lines at the cap. performance.now()/Date.now() share this skew.
void advanceDriftstackVirtualSkew(Seconds delta)
{
    // Apply EVERY charge directly: +delta slows a fork-faster op up to the iPhone cost; -delta SPENDS banked
    // skew to make a fork-slower op measure faster. This is monotonic from a fingerprinter's view — across an
    // op, measured = now(after)-now(before) = macActual + delta = modeled >= 0, so now() never rewinds even
    // when delta<0 (the skew decrease is always <= the real time the op spent). Symmetric small bound keeps
    // |skew| within real-device NTP variance with mean ~0 (no detectable one-way drift / flat-line).
    // [Re-corrects the earlier "drop negatives": the fork is NOT limited to adding time. The residual is only
    //  a SUSTAINED fork-slower op (e.g. 200 mutating toDataURL in a row) that drains the bound — that needs the
    //  op itself made faster (<= iPhone), not the clock; a real mixed workload banks skew from faster ops.]
    const Seconds kSkewBound = Seconds::fromMilliseconds(40);
    // Per-op cap: one anomalously slow op (e.g. the cold first toDataURL: fork ~144ms vs iPhone ~5ms) must NOT
    // drain the skew to the bound in a single charge — that would clamp the *following* warm ops and distort
    // their distribution. Cap each op's contribution; a genuinely-slow op stays a small residual on ITS own
    // sample without corrupting the steady-state warm stream that the chi-square gate measures.
    const Seconds kPerOpCap = Seconds::fromMilliseconds(6);
    if (delta > kPerOpCap)
        delta = kPerOpCap;
    else if (delta < -kPerOpCap)
        delta = -kPerOpCap;
    g_driftstackVirtualSkew = g_driftstackVirtualSkew + delta;
    if (g_driftstackVirtualSkew > kSkewBound)
        g_driftstackVirtualSkew = kSkewBound;
    else if (g_driftstackVirtualSkew < -kSkewBound)
        g_driftstackVirtualSkew = -kSkewBound;
}

// --- engine: per-archetype op-cost sampling (default = iPhone-17/A19, from reference/timing-params) ---
namespace {
struct DSArchetypeTimingParams {
    struct ColdDist { double mean; double jitter; };   // jitter <= mean so cold draws stay >= 0 (no clamp bias)
    std::array<ColdDist, static_cast<size_t>(DriftstackTimedOp::Count)> cold { {
        { 5.0, 1.0 },   // ToDataURL
        { 0.4, 0.4 },   // GetImageData
        { 3.6, 1.6 },   // Render
        { 0.1, 0.1 },   // MeasureText
        { 2.0, 1.0 },   // WasmCompile
    } };
    std::array<std::array<double, 3>, static_cast<size_t>(DriftstackTimedOp::Count)> warmP { {
        { { 0.23, 0.75, 0.02 } },   // ToDataURL
        { { 0.95, 0.05, 0.00 } },   // GetImageData
        { { 0.58, 0.42, 0.00 } },   // Render
        { { 0.98, 0.02, 0.00 } },   // MeasureText
        { { 0.00, 0.00, 0.00 } },   // WasmCompile
    } };
};
DSArchetypeTimingParams& dsParams() { static NeverDestroyed<DSArchetypeTimingParams> p; return p.get(); }
double dsRnd() { return cryptographicallyRandomNumber<uint32_t>() / (static_cast<double>(UINT32_MAX) + 1.0); }
// Cold-first-call flags: thread_local + reset via resetDriftstackVirtualClockSession() on navigation/teardown,
// so "cold" is PER-DOCUMENT (a re-navigated page re-incurs cold) - not first-call-ever-in-process, which would
// leak cold state across recycled WebProcesses = a cross-session correlation tell (review wbj0htxb5 #4). No AR(1)
// thermal in v1: the warm 0/1/2 multinomial IS the iPhone marginal; autocorrelation (a latent continuous cost
// perturbed before quantization) is a documented refinement, never a divisor on a probability (#1).
thread_local std::array<bool, static_cast<size_t>(DriftstackTimedOp::Count)> s_dsCharged { };
} // anonymous namespace

void resetDriftstackVirtualClockSession()
{
    g_driftstackVirtualSkew = 0_s;
    s_dsCharged = { };
}

DriftstackVirtualClock& DriftstackVirtualClock::singleton()
{
    static NeverDestroyed<DriftstackVirtualClock> clock;
    return clock.get();
}

Seconds DriftstackVirtualClock::currentSkew() const { return g_driftstackVirtualSkew; }

DriftstackVirtualClock::DriftstackVirtualClock()
{
    const char* v = getenv("DRIFTSTACK_VIRTUAL_CLOCK");
    if (!v) v = getenv("__XPC_DRIFTSTACK_VIRTUAL_CLOCK");
    m_enabled = v && v[0] == '1';
}

double DriftstackVirtualClock::sampleCostMs(DriftstackTimedOp op, double, bool isCold)
{
    auto i = static_cast<size_t>(op);
    if (i >= static_cast<size_t>(DriftstackTimedOp::Count))
        return 0;
    if (isCold) {
        auto& c = dsParams().cold[i];
        double j = c.jitter < c.mean ? c.jitter : c.mean;   // keep the draw >= 0 (no zero-clamp bias)
        return c.mean + (dsRnd() - 0.5) * 2.0 * j;
    }
    // warm: discrete 0/1/2 multinomial straight from the fitted proportions (NO thermal divisor)
    auto& p = dsParams().warmP[i];
    double u = dsRnd();
    if (u < p[0]) return 0.0;
    if (u < p[0] + p[1]) return 1.0;
    return 2.0;
}

uint64_t DriftstackVirtualClock::nextRandom(DriftstackTimedOp) { return cryptographicallyRandomNumber<uint64_t>(); }

void DriftstackVirtualClock::chargeOp(DriftstackTimedOp op, double pixels, Seconds macActual)
{
    if (!m_enabled)
        return;
    auto i = static_cast<size_t>(op);
    bool isCold = (i < s_dsCharged.size()) && !s_dsCharged[i];
    if (i < s_dsCharged.size())
        s_dsCharged[i] = true;
    double modeledMs = sampleCostMs(op, pixels, isCold);
    advanceDriftstackVirtualSkew(Seconds::fromMilliseconds(modeledMs) - macActual);
}
#endif

} // namespace WTF


