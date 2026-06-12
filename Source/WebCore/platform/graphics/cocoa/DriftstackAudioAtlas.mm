/*
 * DriftstackAudioAtlas.mm — see header.
 */

#include "config.h"
#include "DriftstackAudioAtlas.h"

#if PLATFORM(DRIFTSTACK)

#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <wtf/Logging.h>
#include <wtf/StdLibExtras.h>

namespace WebCore {

namespace {
// V-211: the dev-default data path derives from the environment
// (DRIFTSTACK_DATA_ROOT, else $HOME/code/driftstack) instead of a hardcoded
// build-machine home directory. One-time strdup, process lifetime.
const char* audioAtlasDefaultPath()
{
    static const char* path = [] {
        const char* root = std::getenv("DRIFTSTACK_DATA_ROOT");
        const char* home = std::getenv("HOME");
        std::string p = (root && *root) ? std::string(root) : std::string(home ? home : "") + "/code/driftstack";
        p += "/reference/driftstack_audio_atlas/driftstack-audio-atlas.bin";
        return ::strdup(p.c_str());
    }();
    return path;
}
constexpr uint8_t kAudioAtlasMagic[4] = { 'D', 'S', 'A', 'A' };
constexpr uint16_t kAudioAtlasVersion = 1;
constexpr size_t kAudioAtlasHeaderBytes = 32;
constexpr size_t kAudioAtlasIndexEntryStride = 32;
constexpr size_t kAudioAtlasHashBytes = 16;
}

DriftstackAudioAtlas& DriftstackAudioAtlas::singleton()
{
    static NeverDestroyed<DriftstackAudioAtlas> instance;
    return instance.get();
}

DriftstackAudioAtlas::DriftstackAudioAtlas()
{
    mapAtlas();
}

DriftstackAudioAtlas::~DriftstackAudioAtlas()
{
    if (m_mmapBase && m_mmapSize)
        munmap(const_cast<uint8_t*>(m_mmapBase), m_mmapSize);
    if (m_fd >= 0)
        close(m_fd);
}

void DriftstackAudioAtlas::mapAtlas()
{
    const char* envPath = getenv("DRIFTSTACK_AUDIO_ATLAS_PATH");
    const char* path = envPath ? envPath : audioAtlasDefaultPath();

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        // Not an error — atlas is optional. Customer Macs without
        // the captured iPhone bytes simply skip substitution.
        WTFLogAlways("[Driftstack] AudioAtlas: open failed for %s (errno=%d) — substitution disabled (expected pre-capture)",
            path, errno);
        return;
    }

    struct stat st;
    if (fstat(fd, &st) < 0 || st.st_size < static_cast<off_t>(kAudioAtlasHeaderBytes)) {
        WTFLogAlways("[Driftstack] AudioAtlas: fstat failed or file too small (%lld bytes < %zu)",
            (long long)st.st_size, kAudioAtlasHeaderBytes);
        close(fd);
        return;
    }

    void* base = mmap(nullptr, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (base == MAP_FAILED) {
        WTFLogAlways("[Driftstack] AudioAtlas: mmap failed (errno=%d)", errno);
        close(fd);
        return;
    }

    std::span<const uint8_t> bytesSpan = unsafeMakeSpan(static_cast<const uint8_t*>(base), static_cast<size_t>(st.st_size));

    // Magic check
    if (bytesSpan.size() < kAudioAtlasHeaderBytes
        || bytesSpan[0] != kAudioAtlasMagic[0]
        || bytesSpan[1] != kAudioAtlasMagic[1]
        || bytesSpan[2] != kAudioAtlasMagic[2]
        || bytesSpan[3] != kAudioAtlasMagic[3]) {
        WTFLogAlways("[Driftstack] AudioAtlas: bad magic at start of %s", path);
        munmap(base, st.st_size);
        close(fd);
        return;
    }

    auto readU16 = [&bytesSpan](size_t off) -> uint16_t {
        return uint16_t(bytesSpan[off]) | (uint16_t(bytesSpan[off+1]) << 8);
    };
    auto readU32 = [&bytesSpan](size_t off) -> uint32_t {
        return uint32_t(bytesSpan[off]) | (uint32_t(bytesSpan[off+1]) << 8)
             | (uint32_t(bytesSpan[off+2]) << 16) | (uint32_t(bytesSpan[off+3]) << 24);
    };

    uint16_t version = readU16(4);
    if (version != kAudioAtlasVersion) {
        WTFLogAlways("[Driftstack] AudioAtlas: unsupported version=%u (expected %u)",
            version, kAudioAtlasVersion);
        munmap(base, st.st_size); close(fd); return;
    }
    // byte 6 reserved
    uint8_t keyHashAlgorithm = bytesSpan[7];
    uint32_t numEntries = readU32(8);
    uint32_t indexOffset = readU32(12);
    uint32_t dataOffset = readU32(16);
    // bytes 20..31 reserved

    if (keyHashAlgorithm != 1) {
        WTFLogAlways("[Driftstack] AudioAtlas: unsupported keyHashAlgorithm=%u (expected 1=SHA-256-trunc16)",
            keyHashAlgorithm);
        munmap(base, st.st_size); close(fd); return;
    }

    // Validate offset arithmetic
    if (indexOffset < kAudioAtlasHeaderBytes
        || dataOffset != indexOffset + numEntries * kAudioAtlasIndexEntryStride
        || dataOffset > bytesSpan.size()) {
        WTFLogAlways("[Driftstack] AudioAtlas: header offsets invalid (numEntries=%u indexOffset=%u dataOffset=%u fileSize=%zu)",
            numEntries, indexOffset, dataOffset, bytesSpan.size());
        munmap(base, st.st_size); close(fd); return;
    }

    m_indexSpan = bytesSpan.subspan(indexOffset, numEntries * kAudioAtlasIndexEntryStride);
    m_dataPayloadSpan = bytesSpan.subspan(dataOffset);
    m_numEntries = numEntries;
    m_atlasVersion = version;
    m_keyHashAlgorithm = keyHashAlgorithm;

    m_fd = fd;
    m_mmapBase = static_cast<const uint8_t*>(base);
    m_mmapSize = st.st_size;

    WTFLogAlways("[Driftstack] AudioAtlas: mapped %lld bytes from %s; v%u, %u entries × %u-byte hash",
        (long long)st.st_size, path, version, numEntries, (unsigned)kAudioAtlasHashBytes);
}

// Anonymous namespace inside our cpp scope to avoid name collisions with
// other Driftstack*Atlas.mm files that get merged into the same unified
// translation unit by WebKit's build system.
namespace {

// Read a single DASA index entry. Hash bytes 0..15, sampleRate at 16,
// channelCount at 20, framesPerChannel at 24, dataOffset at 28.
DriftstackAudioAtlas_IndexEntry readAudioEntry(std::span<const uint8_t> indexSpan, size_t i)
{
    DriftstackAudioAtlas_IndexEntry e;
    auto entrySpan = indexSpan.subspan(i * kAudioAtlasIndexEntryStride, kAudioAtlasIndexEntryStride);
    for (size_t b = 0; b < kAudioAtlasHashBytes; ++b)
        e.graphConfigHash[b] = entrySpan[b];
    e.sampleRate = uint32_t(entrySpan[16]) | (uint32_t(entrySpan[17]) << 8)
                 | (uint32_t(entrySpan[18]) << 16) | (uint32_t(entrySpan[19]) << 24);
    e.channelCount = uint32_t(entrySpan[20]) | (uint32_t(entrySpan[21]) << 8)
                   | (uint32_t(entrySpan[22]) << 16) | (uint32_t(entrySpan[23]) << 24);
    e.framesPerChannel = uint32_t(entrySpan[24]) | (uint32_t(entrySpan[25]) << 8)
                       | (uint32_t(entrySpan[26]) << 16) | (uint32_t(entrySpan[27]) << 24);
    e.dataOffset = uint32_t(entrySpan[28]) | (uint32_t(entrySpan[29]) << 8)
                 | (uint32_t(entrySpan[30]) << 16) | (uint32_t(entrySpan[31]) << 24);
    return e;
}

// Lexicographic compare of 16-byte hash arrays.
// Returns -1 / 0 / +1 in the standard memcmp convention.
int compareAudioHash(const std::array<uint8_t, 16>& a, std::span<const uint8_t, 16> b)
{
    for (size_t i = 0; i < 16; ++i) {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return +1;
    }
    return 0;
}

// W2394 (hardening) — bounds-safe data-payload slice. The header validation in
// mapAtlas() bounds the INDEX region, but each entry carries its OWN dataOffset
// (byte 28) + size (framesPerChannel*channelCount*4) into the data payload, which
// were NOT checked before the subspan. A truncated/corrupt atlas (disk fault,
// partial R2 sync, interrupted download) with a valid header but an out-of-range
// entry → an OOB subspan that RELEASE_ASSERT-aborts WebContent (availability
// hazard on the multi-tenant fleet) or UB-reads past the mmap. Validate in 64-bit
// (the uint32 frames*channels*4 product can wrap) BEFORE subspan; on any out-of-
// range/degenerate entry return {} → caller falls through to native audio (safe).
// Mirrors the W2164 TextRunAtlas `blobOffset+blobSize > m_blobSize` check.
std::span<const uint8_t> boundedAudioPayload(std::span<const uint8_t> payload,
    uint32_t dataOffset, uint32_t framesPerChannel, uint32_t channelCount)
{
    uint64_t bytes = uint64_t(framesPerChannel) * channelCount * 4;
    if (!bytes || uint64_t(dataOffset) + bytes > payload.size())
        return { };
    return payload.subspan(dataOffset, static_cast<size_t>(bytes));
}

} // anonymous namespace

std::span<const uint8_t> DriftstackAudioAtlas::entryFor(std::span<const uint8_t, 16> graphConfigHash,
                                                       uint32_t expectedSampleRate,
                                                       uint32_t expectedChannelCount,
                                                       uint32_t expectedFramesPerChannel) const
{
    if (m_dataPayloadSpan.empty() || m_indexSpan.empty() || !m_numEntries)
        return { };

    // Binary search on the lexicographically-sorted index.
    size_t lo = 0, hi = m_numEntries;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        auto e = readAudioEntry(m_indexSpan, mid);
        int cmp = compareAudioHash(e.graphConfigHash, graphConfigHash);
        if (cmp < 0) lo = mid + 1;
        else if (cmp > 0) hi = mid;
        else {
            // W1652: key match at mid. The graph-hash excludes the OfflineAudioContext SHAPE
            // (sampleRate/frames), so the SAME graph can appear at MULTIPLE shapes (e.g. FPJS-classic
            // e24f21a1 rendered at 5000@44100, 8000@48000, AND 44100@44100). Entries are sorted by
            // (key, then shape), so same-key entries are contiguous — scan the block for the entry
            // whose shape matches the caller's buffer (was: single shape-check → only one shape/key).
            auto matchShape = [&](const auto& cand, size_t idx) -> std::span<const uint8_t> {
                if (cand.sampleRate != expectedSampleRate
                    || cand.channelCount != expectedChannelCount
                    || cand.framesPerChannel != expectedFramesPerChannel)
                    return { };
                auto pcm = boundedAudioPayload(m_dataPayloadSpan, cand.dataOffset, cand.framesPerChannel, cand.channelCount);
                if (pcm.empty()) {
                    static unsigned oob = 0;
                    if (++oob <= 50)
                        WTFLogAlways("[Driftstack-DASA-OOB] entry %zu of %zu out-of-range (dataOffset=%u frames=%u ch=%u vs payload=%zu) — skipping (corrupt/truncated atlas)",
                            idx, m_numEntries, cand.dataOffset, cand.framesPerChannel, cand.channelCount, m_dataPayloadSpan.size());
                    return { };
                }
                static unsigned hits = 0;
                if (++hits <= 50)
                    WTFLogAlways("[Driftstack-DASA-HIT] sr=%u ch=%u frames=%u bytes=%zu (entry %zu of %zu)",
                        cand.sampleRate, cand.channelCount, cand.framesPerChannel, pcm.size(), idx, m_numEntries);
                return pcm;
            };
            if (auto r = matchShape(e, mid); !r.empty())
                return r;
            for (size_t i = mid; i-- > 0; ) {
                auto cand = readAudioEntry(m_indexSpan, i);
                if (compareAudioHash(cand.graphConfigHash, graphConfigHash))
                    break;
                if (auto r = matchShape(cand, i); !r.empty())
                    return r;
            }
            for (size_t i = mid + 1; i < m_numEntries; ++i) {
                auto cand = readAudioEntry(m_indexSpan, i);
                if (compareAudioHash(cand.graphConfigHash, graphConfigHash))
                    break;
                if (auto r = matchShape(cand, i); !r.empty())
                    return r;
            }
            static unsigned shapeMismatch = 0;
            if (++shapeMismatch <= 50)
                WTFLogAlways("[Driftstack-DASA-SHAPE-MISMATCH] key matched but no same-key entry has shape sr=%u ch=%u frames=%u; falling through",
                    expectedSampleRate, expectedChannelCount, expectedFramesPerChannel);
            return { };
        }
    }

    return { };
}

std::span<const uint8_t> DriftstackAudioAtlas::entryByShape(uint32_t sampleRate,
                                                           uint32_t channelCount,
                                                           uint32_t framesPerChannel) const
{
    if (m_dataPayloadSpan.empty() || m_indexSpan.empty() || !m_numEntries)
        return { };

    // Linear scan — entries are sorted by hash, not shape, so no binary
    // search. v1 atlas has 1-2 entries; cost is trivial. v2 (when graph
    // hashing is plumbed) will use entryFor() exclusively and this method
    // can be removed.
    size_t firstMatch = static_cast<size_t>(-1);
    size_t matchCount = 0;
    for (size_t i = 0; i < m_numEntries; ++i) {
        auto e = readAudioEntry(m_indexSpan, i);
        if (e.sampleRate == sampleRate
            && e.channelCount == channelCount
            && e.framesPerChannel == framesPerChannel) {
            ++matchCount;
            if (firstMatch == static_cast<size_t>(-1))
                firstMatch = i;
        }
    }

    if (matchCount == 0)
        return { };

    if (matchCount > 1) {
        static unsigned ambig = 0;
        if (++ambig <= 50)
            WTFLogAlways("[Driftstack-DASA-SHAPE-AMBIGUOUS] %zu entries match shape sr=%u ch=%u frames=%u; falling through to native (graph-hash discrimination needed)",
                matchCount, sampleRate, channelCount, framesPerChannel);
        return { };
    }

    auto e = readAudioEntry(m_indexSpan, firstMatch);
    auto pcm = boundedAudioPayload(m_dataPayloadSpan, e.dataOffset, e.framesPerChannel, e.channelCount);
    if (pcm.empty()) {
        static unsigned oob = 0;
        if (++oob <= 50)
            WTFLogAlways("[Driftstack-DASA-OOB-by-shape] entry %zu of %zu out-of-range (dataOffset=%u frames=%u ch=%u vs payload=%zu) — skipping (corrupt/truncated atlas)",
                firstMatch, m_numEntries, e.dataOffset, e.framesPerChannel, e.channelCount, m_dataPayloadSpan.size());
        return { };
    }
    static unsigned hits = 0;
    if (++hits <= 50)
        WTFLogAlways("[Driftstack-DASA-HIT-by-shape] sr=%u ch=%u frames=%u bytes=%zu (entry %zu of %zu)",
            e.sampleRate, e.channelCount, e.framesPerChannel, pcm.size(), firstMatch, m_numEntries);
    return pcm;
}

} // namespace WebCore

#endif // PLATFORM(DRIFTSTACK)
