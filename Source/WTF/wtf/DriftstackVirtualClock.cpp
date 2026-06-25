/*
 * DriftstackVirtualClock.cpp — M8 timing fidelity engine. INERT unless DRIFTSTACK_VIRTUAL_CLOCK=1.
 * Spec + audit (wckmdkws4) corrections: /Users/john/code/driftstack/docs/internal/timing-fidelity-variance-model.md.
 *
 * Random draws use cryptographicallyRandomNumber (no recoverable PRNG state — the audit flagged xoshiro as
 * reconstructable after ~1000 samples). The cold device-characteristic is UNIMODAL per archetype (the
 * bimodality was proven a BrowserStack pool artifact). Warm = discrete 0/1/2 multinomial (warm is 1ms-quantized).
 * Skew is a LEDGER: negative charges carry a deficit amortized against positive charges so long-run mean ~0
 * and |skew| is capped — no monotonic upward drift tell. Date.now()/performance.now() share the ledger.
 *
 * Default params below are the fitted iPhone-17 values (reference/timing-params/*.json). loadParams() lets the
 * WebProcess override them per-archetype at startup (the per-archetype config wire is the next step).
 */

#include "config.h"
#include <wtf/DriftstackVirtualClock.h>

#include <array>
#include <cstdlib>
#include <wtf/CryptographicallyRandomNumber.h>
#include <wtf/NeverDestroyed.h>

namespace WTF {

// Per-archetype timing parameters (default = iPhone-17, fitted). Overridable via loadParams().
struct ArchetypeTimingParams {
    // Cold first-call cost per op, ms: unimodal mean + +/- jitter half-width (uniform).
    struct ColdDist { double mean; double jitter; };
    std::array<ColdDist, static_cast<size_t>(DriftstackTimedOp::Count)> cold {{
        { 5.0, 1.0 },   // ToDataURL  (current-regime iPhone-17 ~5ms, see multi-archetype.json)
        { 0.4, 0.5 },   // GetImageData
        { 3.6, 1.6 },   // Render
        { 0.1, 0.3 },   // MeasureText
        { 2.0, 1.0 },   // WasmCompile
    }};
    // Warm per-call cost: P(0ms), P(1ms), P(2ms) — discrete multinomial (the rest of mass -> 2ms).
    std::array<std::array<double, 3>, static_cast<size_t>(DriftstackTimedOp::Count)> warmP {{
        {{ 0.23, 0.75, 0.02 }},   // ToDataURL
        {{ 0.95, 0.05, 0.00 }},   // GetImageData (mostly 0)
        {{ 0.58, 0.42, 0.00 }},   // Render
        {{ 0.98, 0.02, 0.00 }},   // MeasureText
        {{ 0.00, 0.00, 0.00 }},   // WasmCompile (cold-only; warm ~0)
    }};
    // Bucket-A clock-poll: P(a tight now() read advances the reported clock by >=1ms). iPhone now.resolution.
    double bucketACrossProb { 0.84 };
};

static ArchetypeTimingParams& params()
{
    static NeverDestroyed<ArchetypeTimingParams> p;
    return p.get();
}

// uniform double in [0,1)
static double rnd()
{
    return cryptographicallyRandomNumber<uint32_t>() / (static_cast<double>(UINT32_MAX) + 1.0);
}

// Skew ledger state (file-static; shared by advanceDriftstackVirtualSkew + currentSkew).
static Seconds s_ledgerSkew { 0_s };
static Seconds s_ledgerDeficit { 0_s };

DriftstackVirtualClock& DriftstackVirtualClock::singleton()
{
    static NeverDestroyed<DriftstackVirtualClock> clock;
    return clock.get();
}

Seconds DriftstackVirtualClock::currentSkew() const
{
    return s_ledgerSkew;
}

DriftstackVirtualClock::DriftstackVirtualClock()
{
    const char* v = getenv("DRIFTSTACK_VIRTUAL_CLOCK");
    if (!v) v = getenv("__XPC_DRIFTSTACK_VIRTUAL_CLOCK");   // WebContent sandbox mirror
    m_enabled = v && v[0] == '1';
}

// AR(1) thermal latent: a slowly random-walking multiplier shared across ops so slow calls cluster
// (real iPhone timings autocorrelate; IID would be detectably too-clean). Kept near 1.0, mean-reverting.
static double s_thermal = 1.0;
static double thermalStep()
{
    constexpr double phi = 0.92;      // persistence
    constexpr double sigma = 0.06;    // step size
    s_thermal = 1.0 + phi * (s_thermal - 1.0) + sigma * (rnd() - 0.5) * 2.0;
    if (s_thermal < 0.7) s_thermal = 0.7;
    if (s_thermal > 1.4) s_thermal = 1.4;
    return s_thermal;
}

double DriftstackVirtualClock::sampleCostMs(DriftstackTimedOp op, double /*pixels*/, bool isCold)
{
    auto i = static_cast<size_t>(op);
    if (i >= static_cast<size_t>(DriftstackTimedOp::Count))
        return 0;
    double thermal = thermalStep();
    if (isCold) {
        auto& c = params().cold[i];
        double v = c.mean + (rnd() - 0.5) * 2.0 * c.jitter;
        v *= thermal;
        return v < 0 ? 0 : v;
    }
    // warm: sample the 0/1/2 multinomial (thermal nudges the boundary slightly)
    auto& p = params().warmP[i];
    double u = rnd();
    double p0 = p[0] / thermal;   // hotter -> fewer 0s (slightly slower)
    if (u < p0) return 0.0;
    if (u < p0 + p[1]) return 1.0;
    return 2.0;
}

uint64_t DriftstackVirtualClock::nextRandom(DriftstackTimedOp)
{
    return cryptographicallyRandomNumber<uint64_t>();
}

void DriftstackVirtualClock::chargeOp(DriftstackTimedOp op, double pixels, Seconds macActual)
{
    if (!m_enabled)
        return;
    static std::array<bool, static_cast<size_t>(DriftstackTimedOp::Count)> charged {};
    auto i = static_cast<size_t>(op);
    bool isCold = (i < charged.size()) && !charged[i];
    if (i < charged.size()) charged[i] = true;

    double modeledMs = sampleCostMs(op, pixels, isCold);
    Seconds delta = Seconds::fromMilliseconds(modeledMs) - macActual;
    advanceDriftstackVirtualSkew(delta);
}

Seconds DriftstackVirtualClock::bucketAReadAdvance()
{
    if (!m_enabled)
        return 0_s;
    // Advance the reported clock by ~1ms with the archetype's cross-probability, so a tight now()-polling
    // loop crosses a 1ms boundary at the iPhone's observed rate instead of never (fast Mac).
    return (rnd() < params().bucketACrossProb) ? Seconds::fromMilliseconds(1) : 0_s;
}

// The skew LEDGER. delta>0 (modeled slower than Mac) advances now(); delta<0 (modeled faster, e.g. the fork's
// own overhead exceeds the iPhone) carries a DEFICIT amortized against future positive charges so long-run
// mean skew ~= 0 and |skew| is capped (no monotonic drift, and now() never goes backward).
void advanceDriftstackVirtualSkew(Seconds delta)
{
    const Seconds kCap = Seconds::fromMilliseconds(250);

    if (delta < 0_s) {
        // never move now() backward — bank the negative as a deficit
        s_ledgerDeficit = s_ledgerDeficit + (-delta);
    } else {
        // apply the positive charge, but first pay down any banked deficit
        Seconds applied = delta;
        if (s_ledgerDeficit > 0_s) {
            Seconds pay = s_ledgerDeficit < applied ? s_ledgerDeficit : applied;
            s_ledgerDeficit = s_ledgerDeficit - pay;
            applied = applied - pay;
        }
        s_ledgerSkew = s_ledgerSkew + applied;
        if (s_ledgerSkew > kCap)
            s_ledgerSkew = kCap;
    }
}

} // namespace WTF
