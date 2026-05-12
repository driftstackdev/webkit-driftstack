/*
 * V-820.A — Driftstack telemetry ring buffer + IPC scaffolding.
 *
 * Per Rule N v2 + V-820 design: privacy-safe atlas-miss + ML-inference +
 * latency + canary-detect events logged into a lock-free WebProcess ring
 * buffer; periodically drained via IPC to UIProcess; batched POST to
 * Driftstack harness daemon; aggregated to control plane (Agent 2 scope).
 *
 * THIS HEADER IS NOT YET INCLUDED IN THE BUILD GRAPH. V-820.B will add it
 * to the xcconfig + wire callers at:
 *   - drawGlyphsCoreText (atlas miss / ML inference / latency)
 *   - GraphicsContextCG::fillPath, drawPath, fillRect (canary detect via
 *     V-875 pattern match)
 *   - drawTextRunWithGlyphs (text-run hook V-771)
 *
 * For now this is a forward-compatible scaffold so V-820.B/.C/.D have a
 * fixed contract to wire into.
 */

#pragma once

#if PLATFORM(DRIFTSTACK)

#include <atomic>
#include <cstdint>
#include <cstddef>

namespace WebCore {

// V-820.A privacy-safe event types. Each is fixed-size (POD) and contains
// ONLY anonymized tuples (no URLs, no content, no PII).

struct AtlasMissEvent {
    uint64_t text_run_hash;
    uint16_t font_id;
    uint16_t pt_size;
    uint8_t position_class;
    uint8_t archetype_id;
    uint16_t ios_version_packed; // (major << 8) | minor
    uint64_t timestamp_ms;
};

struct MLInferenceEvent {
    uint64_t text_run_hash;
    uint16_t font_id;
    uint16_t pt_size;
    uint8_t script_id;
    uint8_t archetype_id;
    float mean_confidence;
    float max_uncertainty;
    uint16_t inference_latency_us;
    uint8_t flags; // bit 0=applied, bit 1=timeout_hit, bit 2=frame_budget_hit
    uint64_t timestamp_ms;
};

struct LatencyEvent {
    uint8_t layer; // 0=A atlas, 1=B ML, 2=fallback
    uint16_t per_call_us;
    uint16_t cumulative_frame_us;
    uint8_t flags; // bit 0=frame_budget_hit
    uint64_t frame_id;
    uint64_t timestamp_ms;
};

struct CanaryDetectEvent {
    uint64_t canvas_op_pattern_hash;
    uint8_t canary_set_version;
    uint8_t flags; // bit 0=matched_canary, bit 1=routed_atlas_only
    uint64_t timestamp_ms;
};

enum class TelemetryEventType : uint8_t {
    AtlasMiss = 1,
    MLInference = 2,
    Latency = 3,
    CanaryDetect = 4,
    // V-770.A.9: atlas-hit telemetry. Same POD as AtlasMissEvent for
    // IPC/serialization symmetry; daemon side distinguishes via type byte.
    // Emit-rate is high (one per atlas-hit drawGlyphBuffer call); daemon
    // should aggregate by (font_id, pt_size, position_class) before SQLite.
    AtlasHit = 5,
};

using AtlasHitEvent = AtlasMissEvent;

// Union-typed event for ring buffer storage.
struct TelemetryEvent {
    TelemetryEventType type;
    uint8_t _pad[7]; // 8-byte align
    union {
        AtlasMissEvent atlasMiss;
        MLInferenceEvent mlInference;
        LatencyEvent latency;
        CanaryDetectEvent canaryDetect;
    } data;
};

// Lock-free SPSC ring buffer for WebProcess-side event capture. UIProcess
// drains periodically via IPC; ring size 8K events (~256 KB) tolerates
// 5-second drain interval at 1600 events/s sustained.
class DriftstackTelemetryRing {
public:
    static constexpr size_t kRingCapacity = 8192;

    DriftstackTelemetryRing();
    ~DriftstackTelemetryRing() = default;

    // Producer (WebProcess hot path). Returns false if ring is full.
    // Non-blocking; drop-on-full is acceptable (telemetry is best-effort).
    bool tryPush(const TelemetryEvent& event);

    // Consumer (UIProcess drain path). Pops up to maxOut events into out.
    // Returns number popped.
    size_t drain(TelemetryEvent* out, size_t maxOut);

    // Atomic counters for monitoring.
    uint64_t pushedCount() const { return m_pushedCount.load(std::memory_order_acquire); }
    uint64_t droppedCount() const { return m_droppedCount.load(std::memory_order_acquire); }

private:
    TelemetryEvent m_buf[kRingCapacity];
    std::atomic<uint32_t> m_head { 0 }; // producer
    std::atomic<uint32_t> m_tail { 0 }; // consumer
    std::atomic<uint64_t> m_pushedCount { 0 };
    std::atomic<uint64_t> m_droppedCount { 0 };
};

// Singleton accessor (one ring per WebProcess).
DriftstackTelemetryRing& driftstackTelemetryRing();

// V-820.B.1.a: install a periodic RunLoop timer (5s cadence) that drains
// the ring and emits a one-line WTFLogAlways summary. Gated by env var
// DRIFTSTACK_TELEMETRY_DRAIN=1; off by default. Production V-820.B.1.b
// will replace the log emission with IPC → UIProcess → daemon HTTP POST.
// Must be called on a thread that has a RunLoop installed (e.g., main
// thread of WebContent process).
void driftstackTelemetryStartDrainTimer();

// Convenience producers. Hot-path callers use these instead of constructing
// TelemetryEvent manually.
inline void driftstackLogAtlasMiss(const AtlasMissEvent& e)
{
    TelemetryEvent te;
    te.type = TelemetryEventType::AtlasMiss;
    te.data.atlasMiss = e;
    driftstackTelemetryRing().tryPush(te);
}

inline void driftstackLogAtlasHit(const AtlasHitEvent& e)
{
    TelemetryEvent te;
    te.type = TelemetryEventType::AtlasHit;
    te.data.atlasMiss = e;
    driftstackTelemetryRing().tryPush(te);
}

inline void driftstackLogMLInference(const MLInferenceEvent& e)
{
    TelemetryEvent te;
    te.type = TelemetryEventType::MLInference;
    te.data.mlInference = e;
    driftstackTelemetryRing().tryPush(te);
}

inline void driftstackLogLatency(const LatencyEvent& e)
{
    TelemetryEvent te;
    te.type = TelemetryEventType::Latency;
    te.data.latency = e;
    driftstackTelemetryRing().tryPush(te);
}

inline void driftstackLogCanaryDetect(const CanaryDetectEvent& e)
{
    TelemetryEvent te;
    te.type = TelemetryEventType::CanaryDetect;
    te.data.canaryDetect = e;
    driftstackTelemetryRing().tryPush(te);
}

} // namespace WebCore

#endif // PLATFORM(DRIFTSTACK)
