/*
 * V-820.A — Driftstack telemetry ring buffer implementation.
 *
 * Lock-free SPSC ring buffer per WebProcess. Producer = canvas hooks at
 * drawGlyphsCoreText / fillPath / drawPath. Consumer = UIProcess drain.
 *
 * NOT YET INCLUDED IN BUILD GRAPH. V-820.B wires xcconfig + caller sites.
 *
 * Wraparound semantics: head wraps via & (kRingCapacity - 1) since
 * kRingCapacity is a power of 2 (8192). When (head - tail) == kRingCapacity,
 * ring is full; push drops + increments droppedCount.
 */

#include "config.h"
#include "DriftstackTelemetry.h"

#if PLATFORM(DRIFTSTACK)

#include <cstdlib>
#include <wtf/Assertions.h>
#include <wtf/NeverDestroyed.h>
#include <wtf/RunLoop.h>
#include <wtf/Vector.h>

namespace WebCore {

DriftstackTelemetryRing::DriftstackTelemetryRing() = default;

bool DriftstackTelemetryRing::tryPush(const TelemetryEvent& event)
{
    uint32_t head = m_head.load(std::memory_order_relaxed);
    uint32_t tail = m_tail.load(std::memory_order_acquire);
    // Ring full if head - tail (modular) == capacity.
    if ((head - tail) >= kRingCapacity) {
        m_droppedCount.fetch_add(1, std::memory_order_relaxed);
        return false;
    }
    m_buf[head & (kRingCapacity - 1)] = event;
    m_head.store(head + 1, std::memory_order_release);
    m_pushedCount.fetch_add(1, std::memory_order_relaxed);
    return true;
}

WTF_ALLOW_UNSAFE_BUFFER_USAGE_BEGIN
size_t DriftstackTelemetryRing::drain(TelemetryEvent* out, size_t maxOut)
{
    if (!out || maxOut == 0)
        return 0;
    uint32_t tail = m_tail.load(std::memory_order_relaxed);
    uint32_t head = m_head.load(std::memory_order_acquire);
    size_t available = head - tail;
    size_t toRead = available < maxOut ? available : maxOut;
    for (size_t i = 0; i < toRead; ++i)
        out[i] = m_buf[(tail + i) & (kRingCapacity - 1)];
    m_tail.store(tail + toRead, std::memory_order_release);
    return toRead;
}
WTF_ALLOW_UNSAFE_BUFFER_USAGE_END

DriftstackTelemetryRing& driftstackTelemetryRing()
{
    static DriftstackTelemetryRing ring;
    return ring;
}

// V-820.B.1.a WebProcess drain timer (scaffold).
//
// Periodically drains the lock-free SPSC ring buffer and emits a one-line
// summary via WTFLogAlways. Production V-820.B.1.b will replace the log
// emission with WebPageProxy IPC → UIProcess → daemon HTTP POST. For now
// the scaffold gives visibility into hit-rate by surface (AtlasHit /
// AtlasMiss / etc.) without requiring full IPC wire-up.
//
// Gated by env var DRIFTSTACK_TELEMETRY_DRAIN=1; off by default so cumrig
// + production traffic isn't spammed.

class DriftstackTelemetryDrainTimer {
public:
    static DriftstackTelemetryDrainTimer& singleton()
    {
        static NeverDestroyed<DriftstackTelemetryDrainTimer> instance;
        return instance.get();
    }

    void start()
    {
        if (m_started)
            return;
        if (!std::getenv("DRIFTSTACK_TELEMETRY_DRAIN"))
            return;
        m_started = true;
        // Drain every 5 seconds; matches V-820.B.1 spec drain cadence.
        m_timer.startRepeating(Seconds { 5.0 });
    }

private:
    friend NeverDestroyed<DriftstackTelemetryDrainTimer>;

    DriftstackTelemetryDrainTimer()
        : m_timer(RunLoop::mainSingleton(), "DriftstackTelemetryDrainTimer"_s,
                  [this] { this->fire(); })
    {
    }

    void fire()
    {
        Vector<TelemetryEvent, 256> batch;
        batch.grow(256);
        size_t n = driftstackTelemetryRing().drain(batch.mutableSpan().data(), 256);
        if (!n)
            return;
        batch.shrink(n);

        unsigned atlasHit = 0, atlasMiss = 0, mlInf = 0, lat = 0, canary = 0;

        // V-820.B.1.b: structured JSONL emission per event. Each event line
        // is independently parseable by external aggregators (Python tail,
        // daemon ingest, log collectors). One-line summary at end mirrors
        // V-820.B.1.a aggregate stats. Env-gated separately by
        // DRIFTSTACK_TELEMETRY_JSONL=1 to avoid spamming the summary path
        // when only aggregate stats are wanted.
        bool jsonl = std::getenv("DRIFTSTACK_TELEMETRY_JSONL") != nullptr;

        for (const auto& ev : batch) {
            switch (ev.type) {
            case TelemetryEventType::AtlasHit: ++atlasHit; break;
            case TelemetryEventType::AtlasMiss: ++atlasMiss; break;
            case TelemetryEventType::MLInference: ++mlInf; break;
            case TelemetryEventType::Latency: ++lat; break;
            case TelemetryEventType::CanaryDetect: ++canary; break;
            }
            if (jsonl) {
                switch (ev.type) {
                case TelemetryEventType::AtlasHit:
                case TelemetryEventType::AtlasMiss: {
                    const auto& e = ev.data.atlasMiss;
                    WTFLogAlways("[Driftstack-V820B.JSONL] {\"type\":\"%s\",\"text_run_hash\":%llu,\"font_id\":%u,\"pt_size\":%u,\"position_class\":%u,\"archetype_id\":%u,\"ios_version_packed\":%u,\"timestamp_ms\":%llu}",
                        ev.type == TelemetryEventType::AtlasHit ? "AtlasHit" : "AtlasMiss",
                        (unsigned long long)e.text_run_hash,
                        (unsigned)e.font_id, (unsigned)e.pt_size, (unsigned)e.position_class,
                        (unsigned)e.archetype_id, (unsigned)e.ios_version_packed,
                        (unsigned long long)e.timestamp_ms);
                    break;
                }
                case TelemetryEventType::MLInference: {
                    const auto& e = ev.data.mlInference;
                    WTFLogAlways("[Driftstack-V820B.JSONL] {\"type\":\"MLInference\",\"text_run_hash\":%llu,\"font_id\":%u,\"pt_size\":%u,\"script_id\":%u,\"archetype_id\":%u,\"mean_confidence\":%.4f,\"max_uncertainty\":%.4f,\"inference_latency_us\":%u,\"flags\":%u}",
                        (unsigned long long)e.text_run_hash,
                        (unsigned)e.font_id, (unsigned)e.pt_size, (unsigned)e.script_id,
                        (unsigned)e.archetype_id, (double)e.mean_confidence, (double)e.max_uncertainty,
                        (unsigned)e.inference_latency_us, (unsigned)e.flags);
                    break;
                }
                case TelemetryEventType::Latency: {
                    const auto& e = ev.data.latency;
                    WTFLogAlways("[Driftstack-V820B.JSONL] {\"type\":\"Latency\",\"layer\":%u,\"per_call_us\":%u,\"cumulative_frame_us\":%u,\"flags\":%u,\"frame_id\":%llu}",
                        (unsigned)e.layer, (unsigned)e.per_call_us, (unsigned)e.cumulative_frame_us,
                        (unsigned)e.flags, (unsigned long long)e.frame_id);
                    break;
                }
                case TelemetryEventType::CanaryDetect: {
                    const auto& e = ev.data.canaryDetect;
                    WTFLogAlways("[Driftstack-V820B.JSONL] {\"type\":\"CanaryDetect\",\"canvas_op_pattern_hash\":%llu,\"canary_set_version\":%u,\"flags\":%u}",
                        (unsigned long long)e.canvas_op_pattern_hash,
                        (unsigned)e.canary_set_version, (unsigned)e.flags);
                    break;
                }
                }
            }
        }
        uint64_t pushed = driftstackTelemetryRing().pushedCount();
        uint64_t dropped = driftstackTelemetryRing().droppedCount();
        WTFLogAlways("[Driftstack-V820B] drain batch=%zu hit=%u miss=%u ml=%u lat=%u canary=%u (lifetime pushed=%llu dropped=%llu)",
            n, atlasHit, atlasMiss, mlInf, lat, canary,
            (unsigned long long)pushed, (unsigned long long)dropped);
    }

    RunLoop::Timer m_timer;
    bool m_started { false };
};

void driftstackTelemetryStartDrainTimer()
{
    DriftstackTelemetryDrainTimer::singleton().start();
}

} // namespace WebCore

#endif // PLATFORM(DRIFTSTACK)
