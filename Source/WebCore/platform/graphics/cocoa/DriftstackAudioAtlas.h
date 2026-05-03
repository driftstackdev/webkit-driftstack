/*
 * DriftstackAudioAtlas.h — Audio output substitution atlas (DASA v1)
 *
 * Per founder Tier-2 ack 2026-05-04 of DASA architectural pattern
 * (parallel to V-141 + DSWA). mmap'd binary atlas of iPhone-captured
 * OfflineAudioContext output bytes keyed by graph-config hash, used
 * to substitute iPhone-equivalent audio bytes at offline-render
 * completion for canonical fingerprint probes (cumulative-rig
 * audio.rawSamples + audio.offlineFingerprint10x + future canonical
 * vendor probes).
 *
 * Sibling to DriftstackAsciiAtlas (DSAS), DriftstackEmojiAtlas (DSEA),
 * DriftstackCompositeAtlas (DSEC), DriftstackWebGPUAtlas (DSWA). Same
 * locked layout discipline: little-endian, fixed offsets, no
 * compiler-dependent struct packing.
 *
 * Format ('DSAA' magic):
 *   header[32]:
 *     -  4 B: magic 'DSAA'
 *     -  2 B: version (u16 LE) = 1
 *     -  1 B: reserved
 *     -  1 B: keyHashAlgorithm — 1 = SHA-256 truncated to 16 bytes
 *     -  4 B: numEntries (u32 LE)
 *     -  4 B: indexOffset (u32 LE) = 32
 *     -  4 B: dataOffset (u32 LE)
 *     - 12 B: reserved (zeros)
 *   index[numEntries * 32 bytes] — sorted lexicographically by graphConfigHash:
 *     - 16 B: graphConfigHash (truncated SHA-256)
 *     -  4 B: sampleRate (u32 LE)
 *     -  4 B: channelCount (u32 LE)
 *     -  4 B: framesPerChannel (u32 LE)
 *     -  4 B: dataOffset (u32 LE) — relative to data section start
 *   data[]: concatenated interleaved Float32 sample bytes per entry.
 *           Per entry: framesPerChannel * channelCount * 4 bytes.
 *
 * Lookup contract (at OfflineAudioContext::handleAsyncRenderingComplete):
 *   1. Compute canonical graph-config hash from probe descriptor (or
 *      reconstructed graph state) — see docs/architecture/dasa-v1-design.md
 *      §"Graph hashing".
 *   2. Binary-search index for matching hash.
 *   3. If hit AND captured (channelCount, sampleRate, framesPerChannel)
 *      matches the actual rendered AudioBuffer: substitute bytes per
 *      channel (deinterleave from atlas data into Float32Array channel
 *      data). Log [Driftstack-DASA-HIT].
 *   4. If miss: log [Driftstack-DASA-MISS] (capped at 200) with hash
 *      + dimensions, fall through to native libm bytes.
 *   5. If shape mismatch on hit: log [Driftstack-DASA-SHAPE-MISMATCH],
 *      fall through.
 *
 * Default atlas binary path:
 *   <DRIFTSTACK_REPO_ROOT>/reference/driftstack_audio_atlas/driftstack-audio-atlas.bin
 * Override via DRIFTSTACK_AUDIO_ATLAS_PATH (with __XPC_ mirror for
 * WebContent XPC sandbox propagation).
 */

#pragma once

#if PLATFORM(DRIFTSTACK)

#include <array>
#include <span>
#include <wtf/NeverDestroyed.h>
#include <wtf/Vector.h>

namespace WebCore {

// Index entry struct exposed for the .mm-side reader.
// 32 bytes total to match DASA v1 indexEntryStride.
struct DriftstackAudioAtlas_IndexEntry {
    std::array<uint8_t, 16> graphConfigHash;
    uint32_t sampleRate;
    uint32_t channelCount;
    uint32_t framesPerChannel;
    uint32_t dataOffset; // relative to data section start
};

class DriftstackAudioAtlas {
public:
    static DriftstackAudioAtlas& singleton();

    // Lookup: returns the captured iPhone interleaved Float32 bytes
    // for the given graph-config hash + expected shape. Empty span on
    // miss OR on shape mismatch (caller MUST check span.size() before
    // memcpy'ing into the AudioBuffer's channel data).
    std::span<const uint8_t> entryFor(std::span<const uint8_t, 16> graphConfigHash,
                                      uint32_t expectedSampleRate,
                                      uint32_t expectedChannelCount,
                                      uint32_t expectedFramesPerChannel) const;

    // V1 fallback lookup: returns the FIRST atlas entry matching the
    // given (sampleRate, channelCount, framesPerChannel) shape. Used
    // by the v1 dispatch hook in OfflineAudioContext::finishedRendering
    // when canonical graph-config hashing isn't available (the v1
    // cumulative-rig has 1 canonical probe per shape, so shape lookup
    // is unambiguous). Returns empty span on no-match OR if multiple
    // entries match (ambiguous → fall through to native).
    std::span<const uint8_t> entryByShape(uint32_t sampleRate,
                                          uint32_t channelCount,
                                          uint32_t framesPerChannel) const;

    bool isAvailable() const { return !m_dataPayloadSpan.empty(); }
    size_t numEntries() const { return m_numEntries; }

private:
    friend NeverDestroyed<DriftstackAudioAtlas>;
    DriftstackAudioAtlas();
    ~DriftstackAudioAtlas();

    void mapAtlas();

    int m_fd { -1 };
    const uint8_t* m_mmapBase { nullptr };
    size_t m_mmapSize { 0 };

    std::span<const uint8_t> m_indexSpan;
    std::span<const uint8_t> m_dataPayloadSpan;
    size_t m_numEntries { 0 };
    uint32_t m_atlasVersion { 0 };
    uint32_t m_keyHashAlgorithm { 0 };
};

} // namespace WebCore

#endif // PLATFORM(DRIFTSTACK)
