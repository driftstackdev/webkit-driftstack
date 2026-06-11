/*
 * DriftstackWebGPUAtlas.mm — see header.
 */

#include "config.h"
#include "DriftstackWebGPUAtlas.h"

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
const char* webgpuAtlasDefaultPath()
{
    static const char* path = [] {
        const char* root = std::getenv("DRIFTSTACK_DATA_ROOT");
        const char* home = std::getenv("HOME");
        std::string p = (root && *root) ? std::string(root) : std::string(home ? home : "") + "/code/driftstack";
        p += "/reference/driftstack_webgpu_atlas/driftstack-webgpu-atlas.bin";
        return ::strdup(p.c_str());
    }();
    return path;
}
constexpr uint8_t kWebGPUAtlasMagic[4] = { 'D', 'S', 'W', 'A' };
constexpr uint16_t kWebGPUAtlasVersion = 1;
constexpr size_t kWebGPUAtlasHeaderBytes = 32;
constexpr size_t kWebGPUAtlasIndexEntryStride = 32;
constexpr size_t kWebGPUAtlasHashBytes = 16;
}

DriftstackWebGPUAtlas& DriftstackWebGPUAtlas::singleton()
{
    static NeverDestroyed<DriftstackWebGPUAtlas> instance;
    return instance.get();
}

DriftstackWebGPUAtlas::DriftstackWebGPUAtlas()
{
    mapAtlas();
}

DriftstackWebGPUAtlas::~DriftstackWebGPUAtlas()
{
    if (m_mmapBase && m_mmapSize)
        munmap(const_cast<uint8_t*>(m_mmapBase), m_mmapSize);
    if (m_fd >= 0)
        close(m_fd);
}

void DriftstackWebGPUAtlas::mapAtlas()
{
    const char* envPath = getenv("DRIFTSTACK_WEBGPU_ATLAS_PATH");
    const char* path = envPath ? envPath : webgpuAtlasDefaultPath();

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        // Not an error — atlas is optional. Customer Macs without
        // the captured iPhone bytes simply skip substitution.
        // Logged for first-load visibility.
        WTFLogAlways("[Driftstack] WebGPUAtlas: open failed for %s (errno=%d) — substitution disabled (expected pre-capture)",
            path, errno);
        return;
    }

    struct stat st;
    if (fstat(fd, &st) < 0 || st.st_size < static_cast<off_t>(kWebGPUAtlasHeaderBytes)) {
        WTFLogAlways("[Driftstack] WebGPUAtlas: fstat failed or file too small (%lld bytes < %zu)",
            (long long)st.st_size, kWebGPUAtlasHeaderBytes);
        close(fd);
        return;
    }

    void* base = mmap(nullptr, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (base == MAP_FAILED) {
        WTFLogAlways("[Driftstack] WebGPUAtlas: mmap failed (errno=%d)", errno);
        close(fd);
        return;
    }

    std::span<const uint8_t> bytesSpan = unsafeMakeSpan(static_cast<const uint8_t*>(base), static_cast<size_t>(st.st_size));

    // Magic check
    if (bytesSpan.size() < kWebGPUAtlasHeaderBytes
        || bytesSpan[0] != kWebGPUAtlasMagic[0]
        || bytesSpan[1] != kWebGPUAtlasMagic[1]
        || bytesSpan[2] != kWebGPUAtlasMagic[2]
        || bytesSpan[3] != kWebGPUAtlasMagic[3]) {
        WTFLogAlways("[Driftstack] WebGPUAtlas: bad magic at start of %s", path);
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
    if (version != kWebGPUAtlasVersion) {
        WTFLogAlways("[Driftstack] WebGPUAtlas: unsupported version=%u (expected %u)",
            version, kWebGPUAtlasVersion);
        munmap(base, st.st_size); close(fd); return;
    }
    // bytes 6..7 reserved
    uint32_t numEntries = readU32(8);
    uint32_t indexOffset = readU32(12);
    uint32_t dataOffset = readU32(16);
    uint32_t indexEntryStride = readU32(20);
    uint32_t keyHashAlgorithm = readU32(24);
    // bytes 28..31 reserved

    if (indexEntryStride != kWebGPUAtlasIndexEntryStride) {
        WTFLogAlways("[Driftstack] WebGPUAtlas: unsupported indexEntryStride=%u (expected %zu)",
            indexEntryStride, kWebGPUAtlasIndexEntryStride);
        munmap(base, st.st_size); close(fd); return;
    }

    if (keyHashAlgorithm != 1) {
        WTFLogAlways("[Driftstack] WebGPUAtlas: unsupported keyHashAlgorithm=%u (expected 1=SHA-256-trunc16)",
            keyHashAlgorithm);
        munmap(base, st.st_size); close(fd); return;
    }

    // Validate offset arithmetic
    if (indexOffset < kWebGPUAtlasHeaderBytes
        || dataOffset != indexOffset + numEntries * indexEntryStride
        || dataOffset > bytesSpan.size()) {
        WTFLogAlways("[Driftstack] WebGPUAtlas: header offsets invalid (numEntries=%u indexOffset=%u dataOffset=%u fileSize=%zu)",
            numEntries, indexOffset, dataOffset, bytesSpan.size());
        munmap(base, st.st_size); close(fd); return;
    }

    m_indexSpan = bytesSpan.subspan(indexOffset, numEntries * indexEntryStride);
    m_dataPayloadSpan = bytesSpan.subspan(dataOffset);
    m_numEntries = numEntries;
    m_atlasVersion = version;
    m_keyHashAlgorithm = keyHashAlgorithm;

    m_fd = fd;
    m_mmapBase = static_cast<const uint8_t*>(base);
    m_mmapSize = st.st_size;

    WTFLogAlways("[Driftstack] WebGPUAtlas: mapped %lld bytes from %s; v%u, %u entries × %u-byte hash",
        (long long)st.st_size, path, version, numEntries, (unsigned)kWebGPUAtlasHashBytes);
}

// Anonymous namespace inside our cpp scope to avoid name collisions with
// other Driftstack*Atlas.mm files that get merged into the same unified
// translation unit by WebKit's build system. (DriftstackEmojiAtlas.mm
// also defines a `readEntry` / `compareHash` for its own format.)
namespace {

// Read a single DSWA index entry. Hash bytes 0..15, readbackByteCount at 16,
// dataOffset at 20, reserved at 24, metadataOffset at 28.
DriftstackWebGPUAtlas_IndexEntry readWebGPUEntry(std::span<const uint8_t> indexSpan, size_t i)
{
    DriftstackWebGPUAtlas_IndexEntry e;
    auto entrySpan = indexSpan.subspan(i * kWebGPUAtlasIndexEntryStride, kWebGPUAtlasIndexEntryStride);
    for (size_t b = 0; b < kWebGPUAtlasHashBytes; ++b)
        e.commandSequenceHash[b] = entrySpan[b];
    e.readbackByteCount = uint32_t(entrySpan[16]) | (uint32_t(entrySpan[17]) << 8)
                        | (uint32_t(entrySpan[18]) << 16) | (uint32_t(entrySpan[19]) << 24);
    e.dataOffset = uint32_t(entrySpan[20]) | (uint32_t(entrySpan[21]) << 8)
                 | (uint32_t(entrySpan[22]) << 16) | (uint32_t(entrySpan[23]) << 24);
    e.reserved = uint32_t(entrySpan[24]) | (uint32_t(entrySpan[25]) << 8)
               | (uint32_t(entrySpan[26]) << 16) | (uint32_t(entrySpan[27]) << 24);
    e.metadataOffset = uint32_t(entrySpan[28]) | (uint32_t(entrySpan[29]) << 8)
                     | (uint32_t(entrySpan[30]) << 16) | (uint32_t(entrySpan[31]) << 24);
    return e;
}

// Lexicographic compare of 16-byte hash arrays.
// Returns -1 / 0 / +1 in the standard memcmp convention.
int compareWebGPUHash(const std::array<uint8_t, 16>& a, std::span<const uint8_t, 16> b)
{
    for (size_t i = 0; i < 16; ++i) {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return +1;
    }
    return 0;
}

} // anonymous namespace

std::span<const uint8_t> DriftstackWebGPUAtlas::entryFor(std::span<const uint8_t, 16> commandSequenceHash,
                                                        uint32_t expectedByteCount) const
{
    if (m_dataPayloadSpan.empty() || m_indexSpan.empty() || !m_numEntries)
        return { };

    // Binary search on the lexicographically-sorted index.
    size_t lo = 0, hi = m_numEntries;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        auto e = readWebGPUEntry(m_indexSpan, mid);
        int cmp = compareWebGPUHash(e.commandSequenceHash, commandSequenceHash);
        if (cmp < 0) lo = mid + 1;
        else if (cmp > 0) hi = mid;
        else {
            // Hit! Verify byte count matches caller's buffer.
            if (e.readbackByteCount != expectedByteCount) {
                static unsigned sizeMismatch = 0;
                if (++sizeMismatch <= 50) {
                    WTFLogAlways("[Driftstack-DSWA-SIZE-MISMATCH] expected=%u captured=%u; falling through",
                        expectedByteCount, e.readbackByteCount);
                }
                return { };
            }
            static unsigned hits = 0;
            if (++hits <= 50)
                WTFLogAlways("[Driftstack-DSWA-HIT] bytes=%u (entry %zu of %zu)",
                    e.readbackByteCount, mid, m_numEntries);
            return m_dataPayloadSpan.subspan(e.dataOffset, e.readbackByteCount);
        }
    }

    // Miss: caller logs separately if it wants context (commandSequenceHash
    // may be one of many in a single render). We only log size-mismatch here
    // because that's a "would have hit but data shape is wrong" case, more
    // diagnostic-load-bearing than plain miss.
    return { };
}

std::span<const uint8_t> DriftstackWebGPUAtlas::entryByByteCount(uint32_t expectedByteCount) const
{
    if (m_dataPayloadSpan.empty() || m_indexSpan.empty() || !m_numEntries)
        return { };

    // Linear scan — entries are sorted by hash, not byte count. v1 atlas
    // has 1 entry; cost trivial. v2 (when graph hashing is plumbed) will
    // use entryFor() exclusively.
    size_t firstMatch = static_cast<size_t>(-1);
    size_t matchCount = 0;
    for (size_t i = 0; i < m_numEntries; ++i) {
        auto e = readWebGPUEntry(m_indexSpan, i);
        if (e.readbackByteCount == expectedByteCount) {
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
            WTFLogAlways("[Driftstack-DSWA-BYTECOUNT-AMBIGUOUS] %zu entries match byteCount=%u; falling through (canonical command-sequence hash discrimination needed)",
                matchCount, expectedByteCount);
        return { };
    }

    auto e = readWebGPUEntry(m_indexSpan, firstMatch);
    static unsigned hits = 0;
    if (++hits <= 50)
        WTFLogAlways("[Driftstack-DSWA-HIT-by-bytecount] bytes=%u (entry %zu of %zu)",
            e.readbackByteCount, firstMatch, m_numEntries);
    return m_dataPayloadSpan.subspan(e.dataOffset, e.readbackByteCount);
}

} // namespace WebCore

#endif // PLATFORM(DRIFTSTACK)
