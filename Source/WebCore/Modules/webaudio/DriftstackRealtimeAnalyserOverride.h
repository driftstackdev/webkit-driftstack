/*
 * DriftstackRealtimeAnalyserOverride.h — V-374 (Gap 2 closure).
 *
 * Realtime audio-fp substitution table for AnalyserNode readback paths.
 * Companion to DriftstackAudioAtlas (DASA — OFFLINE path, V-216 Phase C);
 * V-374 closes the realtime path that FPJS open-source v3 / CreepJS
 * audio-fp / FPJS Pro tampering detection actually probe.
 *
 * Phase classification (file 105):
 *   - Phase 2 (process-startup, lazy): base64 decode + cache of iPhone-
 *     captured byte arrays per (sampleRate, fftSize) topology key
 *   - Phase 3 (per-call): substitution dispatch at the four
 *     RealtimeAnalyser readback functions (getFloat/ByteFrequencyData,
 *     getFloat/ByteTimeDomainData)
 *
 * Lookup contract:
 *   Each AnalyserNode has a (sampleRate, fftSize) tuple available at
 *   readback time. We dispatch on this tuple; the first matching row in
 *   the table wins. Vendors typically use distinct fftSize values
 *   (FPJS=1024, FPJS Pro=4096, CreepJS=8192, biquad=2048) so the
 *   collision domain is small. Future V-374-prime can refine the key
 *   with topology-walk hashing if collisions surface.
 *
 * Cross-codebase rationale (founder direction 2026-05-07):
 *   AnalyserNode FFT outputs are deterministic math (window function
 *   + FFT + linear→dB scaling) on input buffer state — not pipeline-
 *   rendered like canvas. Cross-codebase audio divergence less likely
 *   than canvas. iOS 18.6 BS Automate captures should substitute
 *   cleanly into fork's WebKit 625.x dispatch hook. If empirical
 *   verification shows divergence, surface as Tier-2 architectural
 *   for founder iPhone iOS 18.7 session.
 *
 * DO NOT EDIT BY HAND. Regenerate via:
 *   python3 /Users/john/code/driftstack/captures/v3/extract-v374-realtime-analyser-canonical.py
 */
#pragma once

#if PLATFORM(DRIFTSTACK)

#include <cstdint>
#include <span>

namespace WTF {
class String;
}

namespace WebCore {

struct RealtimeAnalyserOverrideEntry {
    const char* archetype;            // e.g. "iphone16pro_ios18_bs"
    const char* topologyKey;          // e.g. "fpjs_oss_v3_oscillator_compressor_analyser"
    uint32_t sampleRate;              // e.g. 44100
    uint32_t fftSize;                 // e.g. 1024
    uint32_t frequencyBinCount;       // = fftSize / 2
    const char* floatFreqBytesBase64; // Float32Array of frequencyBinCount entries (4 * count bytes)
    const char* byteFreqBytesBase64;  // Uint8Array of frequencyBinCount entries
    const char* floatTimeBytesBase64; // Float32Array of fftSize entries
    const char* byteTimeBytesBase64;  // Uint8Array of fftSize entries
};

// Auto-populated by codegen from BS Automate iOS 18.6 captures of
// /captures/v3/v374-analyser-graph-probe.html. The lookup function
// iterates this table via range-for; consumers should NOT index
// directly (-Wunsafe-buffer-usage forbids unbounded indexing).
namespace Driftstack {
std::span<const RealtimeAnalyserOverrideEntry> realtimeAnalyserOverrideTable();
}

namespace Driftstack {

// Process-startup gate. Reads DRIFTSTACK_REALTIME_ANALYSER_OVERRIDE env
// var once. Defaults off until founder explicitly authorizes via env.
bool isRealtimeAnalyserOverrideEnabled();

enum class AnalyserBufferKind : uint8_t {
    FloatFrequency = 0,
    ByteFrequency,
    FloatTimeDomain,
    ByteTimeDomain,
};

// V-374 entry: given an AnalyserNode's (sampleRate, fftSize) and the
// requested readback buffer kind, look up the matching iPhone-canonical
// row, lazy-decode its base64 byte array, and return the buffer span.
// Returns true on hit (outBytes populated with raw byte span; lifetime
// is the process). Returns false on miss (caller falls through to
// native compute).
bool getRealtimeAnalyserOverrideBytes(uint32_t sampleRate, uint32_t fftSize, AnalyserBufferKind kind, std::span<const uint8_t>& outBytes);

} // namespace Driftstack
} // namespace WebCore

#endif // PLATFORM(DRIFTSTACK)
