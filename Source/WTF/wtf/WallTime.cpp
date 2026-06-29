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
#include <cmath>
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
//
// M8 RE-FIT 2026-06-29 (param-table residual closure, grounded in all 71 BS iPhone-17-line timingraw captures —
// reference/timing-params/iphone17-warm-by-size-regime.json):
//   (1) toDataURL warm is STRONGLY SIZE-DEPENDENT (size 64 -> mostly 0ms, 256 -> ~mixed, 512 -> mostly 2+ms);
//       the previous single warm_p {0.207,0.726,0.066} was the REGIME-L @ size-256 cell only -> wrong at any
//       other size (a clock-on fork would emit the 256 mix at 64/512 = a tell). sampleCostMs now buckets
//       toDataURL by the `pixels` arg (sideLen = sqrt(px)) into the captured 64/256/512 warm rows.
//   (2) The captures are BIMODAL by a BS-pool TEMPORAL regime (verify-first: P0@256 ~0.20 before ~08:30 UTC,
//       ~0.52 after — a pool/device-assignment shift, NOT per-call variance and NOT a device model). A real
//       iPhone holds ONE regime for life (audit wckmdkws4 #5) -> pick the regime ONCE per session at reset
//       (CSPRNG) and hold it, so the per-call mix is internally consistent (never flips 0<->mode call-to-call).
//   getImageData/render are size- and regime-STABLE -> single warm row each (unchanged, already correct).
namespace {
enum class DSRegime : uint8_t { L = 0, H = 1, Count = 2 };
struct DSArchetypeTimingParams {
    struct ColdDist { double mean; double jitter; };   // jitter <= mean so cold draws stay >= 0 (no clamp bias)
    // Defaults fit to reference/timing-params/by-chip-generation.json (iPhone17-line_A19).
    std::array<ColdDist, static_cast<size_t>(DriftstackTimedOp::Count)> cold { {
        { 1.85, 0.88 },   // ToDataURL   (ref cold_mean 1.85, cold_sd 0.88)
        { 0.82, 0.51 },   // GetImageData (ref cold_mean 0.82, cold_sd 0.51)
        { 0.0,  0.0  },   // Render      (ref cold_mean 0)
        { 0.1,  0.1  },   // MeasureText
        { 2.0,  1.0  },   // WasmCompile
    } };
    // Render is size-stable (~99.8/0.2 at every size). MeasureText/WasmCompile kept for index alignment.
    std::array<std::array<double, 3>, static_cast<size_t>(DriftstackTimedOp::Count)> warmP { {
        { { 0.000, 0.000, 0.000 } },   // ToDataURL    — UNUSED (size+regime-bucketed below)
        { { 0.000, 0.000, 0.000 } },   // GetImageData — UNUSED (size-bucketed below)
        { { 0.998, 0.002, 0.000 } },   // Render       (size-stable; ref 99.8/0.2)
        { { 0.98,  0.02,  0.00  } },   // MeasureText
        { { 0.00,  0.00,  0.00  } },   // WasmCompile
    } };
    // toDataURL warm 0/1/2+ per [regime][sizeBucket]; sizeBucket 0=64, 1=256, 2=512 (clamped at the ends).
    // From iphone17-warm-by-size-regime.json (L: n=33 captures, H: n=38 captures). STRONGLY size-dependent.
    std::array<std::array<std::array<double, 3>, 3>, static_cast<size_t>(DSRegime::Count)> toDataURLWarm { {
        { {   // REGIME L
            { { 0.5145, 0.4533, 0.0322 } },   // 64
            { { 0.2034, 0.7276, 0.0690 } },   // 256
            { { 0.0000, 0.0295, 0.9705 } },   // 512
        } },
        { {   // REGIME H
            { { 0.8634, 0.1366, 0.0000 } },   // 64
            { { 0.5236, 0.4764, 0.0000 } },   // 256
            { { 0.0000, 0.4566, 0.5434 } },   // 512
        } },
    } };
    // getImageData warm 0/1/2+ per sizeBucket — also size-dependent (P0: 64~0.94, 256~0.82, 512~0.58), but
    // regime-INSENSITIVE (L~=H per size) -> one row per size, the L/H mean. From iphone17-warm-by-size-regime.json.
    std::array<std::array<double, 3>, 3> getImageDataWarm { {
        { { 0.9387, 0.0612, 0.0001 } },   // 64
        { { 0.8230, 0.1770, 0.0000 } },   // 256
        { { 0.5830, 0.4166, 0.0004 } },   // 512
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
// Per-session toDataURL warm regime (L/H). Picked ONCE at session reset, held for the session so the per-call
// mix is internally consistent (a real iPhone sits in one BS-pool regime for life — audit wckmdkws4 #5). The L/H
// split is the captured pool's two-mode prior; mid-point pick is unbiased (the two regimes are ~equal-weight in
// the capture set: L n=33, H n=38). NOT per-document (a single page must not flip regime across navigations).
thread_local DSRegime s_dsRegime { DSRegime::L };
thread_local bool s_dsRegimePicked { false };

DSRegime dsRegime()
{
    if (!s_dsRegimePicked) {
        s_dsRegime = dsRnd() < 0.5 ? DSRegime::L : DSRegime::H;
        s_dsRegimePicked = true;
    }
    return s_dsRegime;
}

// Map toDataURL pixel count -> the nearest captured size bucket (64/256/512). Boundaries at the geometric means
// (128, 362 px side) so 4096px->64, 65536px->256, 262144px->512; larger canvases clamp to 512.
size_t dsSizeBucket(double pixels)
{
    double side = pixels > 0 ? std::sqrt(pixels) : 0;
    if (side < 128.0) return 0;   // ~64
    if (side < 362.0) return 1;   // ~256
    return 2;                     // >=512
}
} // anonymous namespace

void resetDriftstackVirtualClockSession()
{
    g_driftstackVirtualSkew = 0_s;
    s_dsCharged = { };
    s_dsRegimePicked = false;   // re-pick the per-session regime on the next charged toDataURL (held thereafter)
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

double DriftstackVirtualClock::sampleCostMs(DriftstackTimedOp op, double pixels, bool isCold)
{
    auto i = static_cast<size_t>(op);
    if (i >= static_cast<size_t>(DriftstackTimedOp::Count))
        return 0;
    if (isCold) {
        auto& c = dsParams().cold[i];
        double j = c.jitter < c.mean ? c.jitter : c.mean;   // keep the draw >= 0 (no zero-clamp bias)
        return c.mean + (dsRnd() - 0.5) * 2.0 * j;
    }
    // warm: discrete 0/1/2+ multinomial from the fitted proportions (NO thermal divisor). toDataURL AND
    // getImageData are SIZE-dependent -> bucket by the canvas pixel count (toDataURL also per-session regime);
    // render/measureText are size-stable -> the single warmP row.
    const std::array<double, 3>* p;
    if (op == DriftstackTimedOp::ToDataURL)
        p = &dsParams().toDataURLWarm[static_cast<size_t>(dsRegime())][dsSizeBucket(pixels)];
    else if (op == DriftstackTimedOp::GetImageData)
        p = &dsParams().getImageDataWarm[dsSizeBucket(pixels)];
    else
        p = &dsParams().warmP[i];
    double u = dsRnd();
    if (u < (*p)[0]) return 0.0;
    if (u < (*p)[0] + (*p)[1]) return 1.0;
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


