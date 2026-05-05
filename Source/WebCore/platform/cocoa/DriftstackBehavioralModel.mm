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

} // namespace WebCore

#endif // PLATFORM(DRIFTSTACK)
