/*
 * DriftstackVirtualClock — M8 timing fidelity (gated DRIFTSTACK_VIRTUAL_CLOCK, default-off / INERT).
 *
 * Makes a fingerprinter's MEASURED op durations + clock resolution statistically indistinguishable
 * from the session's iPhone ARCHETYPE. Per-archetype parameters are loaded from the archetype config
 * (reference/timing-params/<archetype>.json shape). Spec + the adversarial-audit corrections (wckmdkws4):
 * /Users/john/code/driftstack/docs/internal/timing-fidelity-variance-model.md.
 *
 * Design (audit-corrected — do NOT regress to the first-pass model):
 *  - SAMPLE per-call from the archetype's fitted distribution, never a deterministic modeledMs.
 *      COLD first-call: the per-session DEVICE-CHARACTERISTIC mode (low|high) is picked ONCE at process
 *        start (Phase-2, with the archetype's p_low) and held for the session — a real single iPhone sits
 *        in one mode for life; per-call mixture would flip 5↔17ms = a novel tell. Then jitter within the mode.
 *      WARM: a discrete 0/1/2 multinomial (warm is 1ms-quantized; a continuous lognormal re-quantized would
 *        not reproduce the observed mix).
 *  - AR(1) thermal latent: a slowly random-walking multiplier shared across ops so slow calls CLUSTER
 *    (real iPhone timings autocorrelate; IID marginal sampling is detectably too-clean).
 *  - Skew LEDGER (NOT a one-way monotonicity guard): carry negative deficits, amortize against positive
 *    charges so long-run mean skew ~= 0 and |skew| is capped — no monotonic upward drift tell. Date.now()
 *    and performance.now() share the ledger so dateNowVsPerf stays coherent. Apply skew BEFORE the 1ms floor.
 *  - CSPRNG-quality stream (SipHash counter-mode), seeded from a per-WebProcess pageNonce: session-stable,
 *    cross-session-varying, NOT state-recoverable (xoshiro is recoverable after ~1000 samples = synthetic-proof).
 *  - PRESENCE PARITY (separate from skew): the iPhone-17 has SharedArrayBuffer undefined + crossOriginIsolated
 *    false; the fork MUST match (a worker SAB clock would read true host time, bypassing this thread_local skew).
 *    Adding SAB is itself the divergence — enforced by verify-timing-fidelity.sh, not by this class.
 *
 * Charge sites (each: RAII scope-exit measuring macActual, behind if(enabled())):
 *   HTMLCanvasElement::toDataURL/toBlob, CanvasRenderingContext2D::getImageData, the 2D paint/render path,
 *   TextMetrics/offsetWidth layout, WebAssembly.compile first-call. Bucket-A: Performance::reduceTimeResolution.
 *   NOT audio.offlineRender (the first-pass histogram was FABRICATED — 0 supporting data; needs a real probe).
 */

#pragma once

#include <wtf/Seconds.h>

namespace WTF {

enum class DriftstackTimedOp : uint8_t {
    ToDataURL,
    GetImageData,
    Render,
    MeasureText,
    WasmCompile,
    Count
};

class DriftstackVirtualClock {
    WTF_MAKE_NONCOPYABLE(DriftstackVirtualClock);
public:
    WTF_EXPORT_PRIVATE static DriftstackVirtualClock& singleton();

    bool enabled() const { return m_enabled; }

    // Charge a timed op. Computes a modeled duration sampled from the archetype distribution for `op`
    // (cold on the op's first charged call this process, warm after), then updates the skew ledger by
    // (modeled - macActual). Caller measures macActual via a scope-exit. No-op unless enabled().
    WTF_EXPORT_PRIVATE void chargeOp(DriftstackTimedOp, double pixels, Seconds macActual);

    // The skew to ADD to a raw now() read, BEFORE the read's own 1ms floor is applied. Shared by
    // performance.now() and Date.now().
    Seconds currentSkew() const { return m_ledgerSkew; }

    // Bucket-A: the per-read nanosecond advance so a tight now()-polling loop crosses a 1ms boundary at
    // the archetype's observed rate (e.g. now.resolution {0:p0,1:p1}). No-op unless enabled().
    WTF_EXPORT_PRIVATE Seconds bucketAReadAdvance();

private:
    DriftstackVirtualClock();

    // Sample the modeled cost (ms) for op at `pixels`, cold on the first charged call. Pulls the cold
    // device-mode / warm-multinomial / size relationship from the loaded per-archetype param table and
    // applies the AR(1) thermal multiplier + CSPRNG jitter.
    double sampleCostMs(DriftstackTimedOp, double pixels, bool isCold);

    // CSPRNG (SipHash counter) stream per op — returns the next 64-bit draw; not state-recoverable.
    uint64_t nextRandom(DriftstackTimedOp);

    bool m_enabled { false };

    // Skew ledger.
    Seconds m_ledgerSkew { 0_s };      // current applied skew (what now() reads add)
    Seconds m_ledgerDeficit { 0_s };   // carried negative charge awaiting amortization
    // |skew| cap + the per-op callCount, the per-op CSPRNG counters, the AR(1) thermal state, the picked
    // per-session device-mode, the pageNonce seed, and the loaded archetype param table live in the .cpp
    // (opaque here to keep the WTF header light). See DriftstackVirtualClock.cpp.
};

// Back-compat shim: the existing HTMLCanvasElement toDataURL site calls this. It now routes through the
// ledger (was a raw thread_local add). Kept so existing call sites compile during the staged migration.
WTF_EXPORT_PRIVATE void advanceDriftstackVirtualSkew(Seconds delta);

} // namespace WTF

using WTF::DriftstackVirtualClock;
using WTF::DriftstackTimedOp;
