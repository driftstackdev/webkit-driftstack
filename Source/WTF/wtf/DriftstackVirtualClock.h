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
 *      COLD first-call: a UNIMODAL per-chip-generation distribution (mean + jitter). The apparent cold
 *        bimodality was PROVEN a BrowserStack pool/temporal artifact (same iPhone-17 hardware, Safari 26.0
 *        unimodal) — NOT a device property; so no per-session mode-pick. And the iPhone-17 line is
 *        timing-uniform (17 == Pro == Pro Max, verified 2026-06-25), so timing keys by CHIP-GENERATION.
 *      WARM: a discrete 0/1/2 multinomial (warm is 1ms-quantized; a continuous lognormal re-quantized would
 *        not reproduce the observed mix).
 *  - AR(1) thermal latent: a slowly random-walking multiplier shared across ops so slow calls CLUSTER
 *    (real iPhone timings autocorrelate; IID marginal sampling is detectably too-clean).
 *  - Skew LEDGER (NOT a one-way monotonicity guard): carry negative deficits, amortize against positive
 *    charges so long-run mean skew ~= 0 and |skew| is capped — no monotonic upward drift tell. Date.now()
 *    and performance.now() share the ledger so dateNowVsPerf stays coherent. Apply skew BEFORE the 1ms floor.
 *  - Random draws use cryptographicallyRandomNumber (crypto entropy, NO recoverable PRNG state) — the audit
 *    flagged xoshiro/xorshift as reconstructable after ~1000 samples (synthetic-proof). No seed to manage.
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

#include <cstdint>
#include <wtf/ExportMacros.h>
#include <wtf/Noncopyable.h>
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
    // performance.now() and Date.now(). (Ledger state is file-static in DriftstackVirtualClock.cpp.)
    WTF_EXPORT_PRIVATE Seconds currentSkew() const;

    // Bucket-A: the per-read nanosecond advance so a tight now()-polling loop crosses a 1ms boundary at
    // the archetype's observed rate (e.g. now.resolution {0:p0,1:p1}). No-op unless enabled().
    WTF_EXPORT_PRIVATE Seconds bucketAReadAdvance();

private:
    DriftstackVirtualClock();

    // Sample the modeled cost (ms) for op at `pixels`, cold on the first charged call. Pulls the cold
    // device-mode / warm-multinomial / size relationship from the loaded per-archetype param table and
    // applies the AR(1) thermal multiplier + CSPRNG jitter.
    double sampleCostMs(DriftstackTimedOp, double pixels, bool isCold);

    // A crypto-entropy draw (cryptographicallyRandomNumber) — not state-recoverable. No per-op seed/counter.
    uint64_t nextRandom(DriftstackTimedOp);

    bool m_enabled { false };
    // The skew ledger (s_ledgerSkew / s_ledgerDeficit), the AR(1) thermal latent, and the loaded archetype
    // param table are file-static in DriftstackVirtualClock.cpp — keeps this WTF header light and lets the
    // free function advanceDriftstackVirtualSkew() share the same ledger.
};

// Back-compat shim: the existing HTMLCanvasElement toDataURL site calls this. It now routes through the
// ledger (was a raw thread_local add). Kept so existing call sites compile during the staged migration.
WTF_EXPORT_PRIVATE void advanceDriftstackVirtualSkew(Seconds delta);

} // namespace WTF

using WTF::DriftstackVirtualClock;
using WTF::DriftstackTimedOp;
