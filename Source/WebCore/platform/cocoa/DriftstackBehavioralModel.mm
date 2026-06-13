/*
 * DriftstackBehavioralModel.mm — implementation for AFP Layer 2 model loader.
 * See header for design context.
 */

#include "config.h"
#include "DriftstackBehavioralModel.h"

#if PLATFORM(DRIFTSTACK)

#import <Foundation/Foundation.h>
#include <wtf/JSONValues.h>
#include <wtf/StdLibExtras.h>
#include <wtf/text/WTFString.h>

namespace WebCore {

DriftstackBehavioralModel& DriftstackBehavioralModel::singleton()
{
    static NeverDestroyed<DriftstackBehavioralModel> s_instance;
    return s_instance.get();
}

DriftstackBehavioralModel::DriftstackBehavioralModel()
{
    loadFromEnv();
}

void DriftstackBehavioralModel::loadFromEnv()
{
    const char* envPath = getenv("DRIFTSTACK_BEHAVIORAL_MODEL_PATH");
    if (!envPath || !envPath[0])
        return;

    NSString* nsPath = [NSString stringWithUTF8String:envPath];
    if (![[NSFileManager defaultManager] fileExistsAtPath:nsPath]) {
        NSLog(@"[Driftstack-BehavioralModel] file not found: %s", envPath);
        return;
    }

    NSError* error = nil;
    NSString* nsContents = [NSString stringWithContentsOfFile:nsPath encoding:NSUTF8StringEncoding error:&error];
    if (!nsContents) {
        NSLog(@"[Driftstack-BehavioralModel] read failed: %@", error.localizedDescription);
        return;
    }

    String jsonText { nsContents };
    if (!parseJSON(jsonText)) {
        NSLog(@"[Driftstack-BehavioralModel] JSON parse failed for %s", envPath);
        return;
    }

    m_loaded = true;
    NSLog(@"[Driftstack-BehavioralModel] loaded archetype=%s schema=%u signals=%u",
          m_archetype.utf8().data(), m_schemaVersion, static_cast<unsigned>(m_signals.size()));
}

DriftstackDistributionKind DriftstackBehavioralModel::kindFromString(const String& s)
{
    if (s == "lognormal"_s)             return DriftstackDistributionKind::Lognormal;
    if (s == "gaussian"_s)              return DriftstackDistributionKind::Gaussian;
    if (s == "joint_gaussian"_s)        return DriftstackDistributionKind::JointGaussian2D;
    if (s == "beta"_s)                  return DriftstackDistributionKind::Beta;
    if (s == "exponential"_s)           return DriftstackDistributionKind::Exponential;
    if (s == "empirical_histogram"_s)   return DriftstackDistributionKind::EmpiricalHistogram;
    if (s == "empirical_samples"_s)     return DriftstackDistributionKind::EmpiricalSamples;
    return DriftstackDistributionKind::Unknown;
}

bool DriftstackBehavioralModel::parseJSON(const String& jsonText)
{
    auto rootValue = JSON::Value::parseJSON(StringView { jsonText });
    if (!rootValue)
        return false;
    auto rootObject = rootValue->asObject();
    if (!rootObject)
        return false;

    auto schemaVersionOpt = rootObject->getInteger("schemaVersion"_s);
    if (!schemaVersionOpt)
        return false;
    m_schemaVersion = static_cast<uint32_t>(*schemaVersionOpt);

    m_archetype = rootObject->getString("archetype"_s);

    auto signalsObj = rootObject->getObject("signals"_s);
    if (!signalsObj)
        return false;

    for (const String& signalName : signalsObj->keys()) {
        auto signalRefValue = signalsObj->getValue(signalName);
        if (!signalRefValue)
            continue;
        auto signalObj = signalRefValue->asObject();
        if (!signalObj)
            continue;

        DriftstackDistributionParams params;
        String distStr = signalObj->getString("distribution"_s);
        params.kind = kindFromString(distStr);
        if (params.kind == DriftstackDistributionKind::Unknown)
            continue;

        if (auto sampleCount = signalObj->getInteger("sampleCount"_s))
            params.sampleCount = static_cast<uint32_t>(*sampleCount);
        if (auto autocorr = signalObj->getDouble("autocorrelation_lag1"_s))
            params.autocorrelationLag1 = *autocorr;

        auto paramsObj = signalObj->getObject("params"_s);
        if (!paramsObj)
            continue;

        switch (params.kind) {
        case DriftstackDistributionKind::Lognormal:
            if (auto v = paramsObj->getDouble("mu"_s))    params.mu    = *v;
            if (auto v = paramsObj->getDouble("sigma"_s)) params.sigma = *v;
            break;
        case DriftstackDistributionKind::Gaussian:
            if (auto v = paramsObj->getDouble("mean"_s))     params.mean     = *v;
            if (auto v = paramsObj->getDouble("variance"_s)) params.variance = *v;
            break;
        case DriftstackDistributionKind::JointGaussian2D: {
            auto meanArr = paramsObj->getArray("mean"_s);
            if (meanArr && meanArr->length() >= 2) {
                if (auto v = meanArr->get(0)->asDouble()) params.mean2D[0] = *v;
                if (auto v = meanArr->get(1)->asDouble()) params.mean2D[1] = *v;
            }
            auto covArr = paramsObj->getArray("covariance"_s);
            if (covArr && covArr->length() >= 2) {
                for (size_t i = 0; i < 2; ++i) {
                    auto row = covArr->get(i)->asArray();
                    if (!row || row->length() < 2)
                        continue;
                    if (auto v = row->get(0)->asDouble()) params.covariance2D[i][0] = *v;
                    if (auto v = row->get(1)->asDouble()) params.covariance2D[i][1] = *v;
                }
            }
            break;
        }
        case DriftstackDistributionKind::Beta:
            if (auto v = paramsObj->getDouble("alpha"_s)) params.alpha = *v;
            if (auto v = paramsObj->getDouble("beta"_s))  params.beta  = *v;
            break;
        case DriftstackDistributionKind::Exponential:
            if (auto v = paramsObj->getDouble("rate"_s)) params.rate = *v;
            break;
        case DriftstackDistributionKind::EmpiricalHistogram: {
            auto bins = paramsObj->getArray("bins"_s);
            if (bins) {
                for (size_t i = 0; i < bins->length(); ++i) {
                    if (auto v = bins->get(i)->asDouble())
                        params.histogramBins.append(*v);
                }
            }
            auto counts = paramsObj->getArray("counts"_s);
            if (counts) {
                for (size_t i = 0; i < counts->length(); ++i) {
                    if (auto v = counts->get(i)->asInteger())
                        params.histogramCounts.append(static_cast<uint32_t>(*v));
                }
            }
            break;
        }
        case DriftstackDistributionKind::EmpiricalSamples:
            // Binary appendix path; deferred to follow-up V-N.
            continue;
        default:
            continue;
        }

        // Optional support range (lognormal / beta).
        auto supportArr = signalObj->getArray("support"_s);
        if (supportArr && supportArr->length() >= 2) {
            if (auto v = supportArr->get(0)->asDouble()) params.supportLo = *v;
            if (auto v = supportArr->get(1)->asDouble()) params.supportHi = *v;
        }

        m_signals.set(signalName, std::make_unique<DriftstackDistributionParams>(std::move(params)));
    }

    return true;
}

const DriftstackDistributionParams* DriftstackBehavioralModel::distributionFor(const String& signalName) const
{
    if (!m_loaded)
        return nullptr;
    auto it = m_signals.find(signalName);
    if (it == m_signals.end())
        return nullptr;
    return it->value.get();
}

Vector<String> DriftstackBehavioralModel::signalNames() const
{
    Vector<String> names;
    if (!m_loaded)
        return names;
    names.reserveInitialCapacity(m_signals.size());
    for (const auto& entry : m_signals)
        names.append(entry.key);
    return names;
}

// V-197: AFP Layer 2 event injection scaffolding per
// /docs/architecture/afp-layer-design.md §3.3.4 LOCKED 2026-05-05
// (event injection point = Source/WebCore/page/EventHandler.cpp dispatch-up
// pattern). Implementation lives here in the same .mm as the model loader to
// avoid the cross-directory include path issue (EventHandler.cpp is at
// Source/WebCore/page/ and cannot include platform/cocoa/DriftstackBehavioralModel.h
// without xcodeproj header-search-path changes; co-locating the impl here
// sidesteps that).
//
// Phase E.3 of afp-layer-design.md §4. Default-OFF; gated on
// DRIFTSTACK_BEHAVIORAL_SYNTHESIS=1 env var. Synthesis only fires when harness
// commands a high-level intent. Per-call randomness comes from drawing fresh
// samples from the loaded distribution model.
//
// SCAFFOLDING (V-197): logs intent + skeleton dispatch logic. Actual event-
// emission (sampling from DriftstackDistributionParams + calling
// handleMousePressEvent / handleWheelEvent / dispatchTouchEvent / keyEvent /
// dispatchGestureEvent) is future V-N work. Default-OFF + log-only stub
// guarantees Phase 2 cumulative rig diff=0 unaffected.

} // namespace WebCore

#include "EventHandler.h"

namespace WebCore {

void EventHandler::driftstackSynthesizeBehavioralStream(DriftstackBehavioralIntent intent, double durationMs)
{
    static bool s_synthesisEnabled = []() {
        const char* env = getenv("DRIFTSTACK_BEHAVIORAL_SYNTHESIS");
        return env && env[0] == '1';
    }();
    if (!s_synthesisEnabled)
        return;

    const auto& model = DriftstackBehavioralModel::singleton();
    if (!model.isAvailable())
        return;

    const char* intentName = "unknown";
    const char* primarySignal = "n/a";
    switch (intent) {
    case DriftstackBehavioralIntent::IdleDwell:
        intentName = "IdleDwell";
        primarySignal = "(no events; passive duration)";
        break;
    case DriftstackBehavioralIntent::ScrollFreeForm:
        intentName = "ScrollFreeForm";
        primarySignal = "scrollWheelDelta + scrollIntervalMs";
        break;
    case DriftstackBehavioralIntent::TapSequence:
        intentName = "TapSequence";
        primarySignal = "touchPressure + touchDuration + mouseVelocity";
        break;
    case DriftstackBehavioralIntent::TypeText:
        intentName = "TypeText";
        primarySignal = "interKeyDelayMs + keyHoldDurationMs";
        break;
    case DriftstackBehavioralIntent::PinchRotate:
        intentName = "PinchRotate";
        primarySignal = "gestureScaleRate + gestureRotationRate";
        break;
    }

    auto interKeyParams = model.distributionFor("interKeyDelayMs"_s);
    WTFLogAlways("[Driftstack-BehavioralSynth] intent=%s durationMs=%.0f primarySignal=%s "
                 "model.archetype=%s model.signals=%u sampleCheck=interKeyDelayMs:%s",
        intentName, durationMs, primarySignal,
        model.archetype().utf8().data(),
        static_cast<unsigned>(model.signalNames().size()),
        interKeyParams ? "present" : "absent");

    // Phase E.3.5 (future): per-intent event-emission loop here.
    // Each handle*Event call dispatches up through the existing EventHandler
    // tree as if from native UI input. isTrusted: true via WebCore-internal
    // API (NOT JS dispatchEvent).
    //
    // W2465 audit note — when the EmpiricalHistogram sampler lands here, guard the
    // bins/counts pairing: the loader (loadSignals, EmpiricalHistogram case) appends
    // histogramBins and histogramCounts INDEPENDENTLY, so a malformed model can yield
    // bins.size() != counts.size(). The sampler MUST bound its index by
    // min(histogramBins.size(), histogramCounts.size()) (or reject the signal) — never
    // index counts[i] for i over bins.size() or vice versa. (Today: trusted shipped
    // model + this path is DRIFTSTACK_BEHAVIORAL_SYNTHESIS-gated default-off + a no-op
    // stub, so no live exposure; this is a build-ahead invariant for the wire-up.)
}

} // namespace WebCore

#endif // PLATFORM(DRIFTSTACK)
