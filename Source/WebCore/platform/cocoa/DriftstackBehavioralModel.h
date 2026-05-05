/*
 * DriftstackBehavioralModel.h — AFP Layer 2 statistical model loader.
 *
 * Phase E.2 of /docs/architecture/afp-layer-design.md. Loads behavioral
 * distribution parameters from a JSON file at WebProcess init via the
 * DRIFTSTACK_BEHAVIORAL_MODEL_PATH env var. Exposes per-signal distribution
 * parameters to EventHandler synthesis code (Phase E.3 / PRIORITY 4) which
 * draws samples and dispatches synthetic events through the existing capture-
 * bubble dispatch tree.
 *
 * Per Tier-2 design lock 2026-05-05: hybrid JSON + binary appendix format.
 * This loader handles JSON-primary (always present); .behavioral-samples.bin
 * binary appendix support is deferred to a follow-up V-N entry.
 *
 * Singleton pattern matches DriftstackAsciiAtlas / DriftstackEmojiAtlas /
 * DriftstackWebGPUAtlas / DriftstackAudioAtlas precedent. Lazy-init on first
 * call; if env var unset OR file unreadable OR JSON malformed, instance
 * reports isAvailable() == false and synthesis code falls through to native
 * upstream behavior (= no behavioral synthesis fired).
 *
 * Default-OFF guarantee: when env var unset, instance loads zero state, every
 * lookup misses, EventHandler synthesis code emits no synthetic events. Phase 2
 * cumulative rig closure (diff=0) preserved.
 */

#pragma once

#if PLATFORM(DRIFTSTACK)

#include <array>
#include <memory>
#include <wtf/HashMap.h>
#include <wtf/NeverDestroyed.h>
#include <wtf/Vector.h>
#include <wtf/text/WTFString.h>

namespace WebCore {

// Distribution kinds per /captures/v3/behavioral-model-fitter/fitter.py
// SIGNAL_TAXONOMY constant. Keep in lockstep — adding a new kind requires
// updates here + in the Python fitter.
enum class DriftstackDistributionKind : uint8_t {
    Unknown = 0,
    Lognormal,            // params: mu, sigma. support [a, b].
    Gaussian,             // params: mean, variance.
    JointGaussian2D,      // params: mean[2], covariance[2][2].
    Beta,                 // params: alpha, beta. support [a, b] (commonly [0, 1]).
    Exponential,          // params: rate.
    EmpiricalHistogram,   // params: bins[N+1], counts[N].
    EmpiricalSamples,     // binary appendix; not implemented in scaffolding.
};

// Distribution parameter holder. Variant-shaped — only the fields matching
// `kind` are populated. Sampler dispatches on kind.
struct DriftstackDistributionParams {
    DriftstackDistributionKind kind { DriftstackDistributionKind::Unknown };

    // Univariate parametric (lognormal / gaussian / beta / exponential).
    double mu { 0.0 };
    double sigma { 0.0 };
    double mean { 0.0 };
    double variance { 0.0 };
    double alpha { 0.0 };
    double beta { 0.0 };
    double rate { 0.0 };
    double supportLo { 0.0 };
    double supportHi { 0.0 };

    // Bivariate joint Gaussian (mouseVelocity / mouseAcceleration).
    std::array<double, 2> mean2D { 0.0, 0.0 };
    std::array<std::array<double, 2>, 2> covariance2D { { { 0.0, 0.0 }, { 0.0, 0.0 } } };

    // Empirical histogram.
    Vector<double> histogramBins;
    Vector<uint32_t> histogramCounts;

    // Autocorrelation (per-signal, lag-1; future versions extend to lag-N vector).
    double autocorrelationLag1 { 0.0 };

    // Sample count from source captures (informational; sampler may skip
    // distributions with sampleCount < threshold).
    uint32_t sampleCount { 0 };
};

class DriftstackBehavioralModel {
public:
    static DriftstackBehavioralModel& singleton();

    bool isAvailable() const { return m_loaded; }
    const String& archetype() const { return m_archetype; }
    uint32_t schemaVersion() const { return m_schemaVersion; }

    // Lookup distribution params by signal name (matches SIGNAL_TAXONOMY in
    // fitter.py). Returns nullptr if signal not present in model OR model
    // not loaded.
    const DriftstackDistributionParams* distributionFor(const String& signalName) const;

    // Convenience: list of signals present in loaded model. Empty if not loaded.
    Vector<String> signalNames() const;

private:
    friend NeverDestroyed<DriftstackBehavioralModel>;
    DriftstackBehavioralModel();
    ~DriftstackBehavioralModel() = default;

    void loadFromEnv();
    bool parseJSON(const String& jsonText);
    static DriftstackDistributionKind kindFromString(const String&);

    bool m_loaded { false };
    String m_archetype;
    uint32_t m_schemaVersion { 0 };
    // Value wrapped in std::unique_ptr per HashTable rehash-size constraint
    // (WTF::KeyValuePair<String, DriftstackDistributionParams> exceeds the
    // 150-byte threshold for in-place HashMap storage; unique_ptr heaps it).
    HashMap<String, std::unique_ptr<DriftstackDistributionParams>> m_signals;
};

} // namespace WebCore

#endif // PLATFORM(DRIFTSTACK)
