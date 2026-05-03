/*
 * DriftstackWebGPUAtlas.h — WebGPU readback substitution atlas (DSWA v1)
 *
 * Per founder approval 2026-05-03 of WebGPU readback substitution
 * hybrid B+A strategy. mmap'd binary atlas of iPhone-captured WebGPU
 * pixel-readback bytes keyed by command-sequence hash, used to
 * substitute iPhone-equivalent bytes at GPUBuffer::getMappedRange()
 * for canonical fingerprint probes (CreepJS / FingerprintJS /
 * Hyperbeam test suite + the cumulative-rig webgpu.renderHash10x
 * pattern).
 *
 * Sibling to DriftstackAsciiAtlas (DSAS), DriftstackEmojiAtlas (DSEA),
 * DriftstackCompositeAtlas (DSEC). Same locked layout discipline:
 * little-endian, fixed offsets, no compiler-dependent struct packing.
 *
 * Format ('DSWA' magic):
 *   header[32]:
 *     -  4 B: magic 'DSWA'
 *     -  2 B: version (u16 LE) = 1
 *     -  2 B: reserved (zeros)
 *     -  4 B: numEntries (u32 LE)
 *     -  4 B: indexOffset (u32 LE)
 *     -  4 B: dataOffset (u32 LE)
 *     -  4 B: indexEntryStride (u32 LE) = 32 (locked at v1)
 *     -  4 B: keyHashAlgorithm (u32 LE) — 1 = SHA-256 truncated to 16 bytes
 *     -  4 B: reserved (zeros)
 *   index[numEntries * 32 bytes] — sorted lexicographically by commandSequenceHash:
 *     - 16 B: commandSequenceHash (truncated SHA-256)
 *     -  4 B: readbackByteCount (u32 LE)
 *     -  4 B: dataOffset (u32 LE) — relative to dataOffset header field
 *     -  4 B: reserved (zeros)
 *     -  4 B: metadataOffset (u32 LE) — informational only
 *   data[]: concatenated readback byte streams + metadata blobs
 *
 * Lookup contract (at GPUBuffer::getMappedRange):
 *   1. Compute canonical command-sequence hash from upstream pipeline
 *      state via Driftstack canonicalization function (see
 *      docs/architecture/dswa-v1-binary-format.md §"Command-sequence
 *      canonicalization").
 *   2. Binary-search index for matching hash.
 *   3. If hit AND captured readbackByteCount matches the actual
 *      buffer size: substitute bytes. Log [Driftstack-DSWA-HIT].
 *   4. If miss: log [Driftstack-DSWA-MISS] (capped at 200) with
 *      hash + size, fall through to native GPU bytes.
 *   5. If size mismatch on hit: log [Driftstack-DSWA-SIZE-MISMATCH],
 *      fall through (avoids substituting wrong-size data).
 *
 * Default atlas binary path:
 *   /Users/john/code/driftstack/reference/driftstack_webgpu_atlas/driftstack-webgpu-atlas.bin
 * Override via DRIFTSTACK_WEBGPU_ATLAS_PATH (with __XPC_ mirror for
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
// 32 bytes total to match DSWA v1 indexEntryStride.
struct DriftstackWebGPUAtlas_IndexEntry {
    std::array<uint8_t, 16> commandSequenceHash;
    uint32_t readbackByteCount;
    uint32_t dataOffset;
    uint32_t reserved; // = 0
    uint32_t metadataOffset; // informational only
};

class DriftstackWebGPUAtlas {
public:
    static DriftstackWebGPUAtlas& singleton();

    // Lookup: returns the captured iPhone bytes for the given
    // command-sequence hash + expected size. Empty span on miss
    // OR on size mismatch (caller MUST check span.size() before
    // memcpy'ing into a JS-visible ArrayBuffer).
    std::span<const uint8_t> entryFor(std::span<const uint8_t, 16> commandSequenceHash,
                                      uint32_t expectedByteCount) const;

    bool isAvailable() const { return !m_dataPayloadSpan.empty(); }
    size_t numEntries() const { return m_numEntries; }

private:
    friend NeverDestroyed<DriftstackWebGPUAtlas>;
    DriftstackWebGPUAtlas();
    ~DriftstackWebGPUAtlas();

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
