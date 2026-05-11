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

DriftstackTelemetryRing& driftstackTelemetryRing()
{
    static DriftstackTelemetryRing ring;
    return ring;
}

} // namespace WebCore

#endif // PLATFORM(DRIFTSTACK)
