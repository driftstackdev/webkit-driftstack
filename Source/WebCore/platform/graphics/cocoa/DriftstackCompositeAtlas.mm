/*
 * DriftstackCompositeAtlas.mm — see header.
 */

#include "config.h"
#include "DriftstackCompositeAtlas.h"

#if PLATFORM(DRIFTSTACK)

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <wtf/Logging.h>

namespace WebCore {

static const char* kDefaultCompositeAtlasPath = "/Users/john/code/driftstack/reference/driftstack_emoji_atlas/driftstack-composite-atlas.bin";

static constexpr uint8_t kCompositeAtlasMagic[4] = { 'D', 'S', 'E', 'C' };
static constexpr size_t kEntrySize = 80;          // 64 + 2 + 2 + 4 + 4 + 4
static constexpr size_t kSequenceBytes = 64;

DriftstackCompositeAtlas& DriftstackCompositeAtlas::singleton()
{
    static NeverDestroyed<DriftstackCompositeAtlas> instance;
    return instance.get();
}

DriftstackCompositeAtlas::DriftstackCompositeAtlas()
{
    mapAtlas();
}

DriftstackCompositeAtlas::~DriftstackCompositeAtlas()
{
    if (m_mmapBase && m_mmapSize)
        munmap(const_cast<uint8_t*>(m_mmapBase), m_mmapSize);
    if (m_fd >= 0)
        close(m_fd);
}

void DriftstackCompositeAtlas::mapAtlas()
{
    // Direct-browse (human inspection) mode: skip the canvas-fingerprint atlas so
    // page text renders natively (see DriftstackAsciiAtlas::mapAtlas for rationale).
    if (const char* db = getenv("DRIFTSTACK_DIRECT_BROWSE"); db && db[0] == '1') {
        WTFLogAlways("[Driftstack] CompositeAtlas: load suppressed (DRIFTSTACK_DIRECT_BROWSE=1) — native page-text render");
        return;
    }

    const char* envPath = getenv("DRIFTSTACK_COMPOSITE_ATLAS_PATH");
    const char* path = envPath ? envPath : kDefaultCompositeAtlasPath;

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        WTFLogAlways("[Driftstack] CompositeAtlas: open failed for %s (errno=%d)", path, errno);
        return;
    }

    struct stat st;
    if (fstat(fd, &st) < 0 || st.st_size < 24) {
        WTFLogAlways("[Driftstack] CompositeAtlas: fstat failed or file too small (%lld bytes)", (long long)st.st_size);
        close(fd);
        return;
    }

    void* base = mmap(nullptr, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (base == MAP_FAILED) {
        WTFLogAlways("[Driftstack] CompositeAtlas: mmap failed (errno=%d)", errno);
        close(fd);
        return;
    }

    std::span<const uint8_t> bytesSpan = unsafeMakeSpan(static_cast<const uint8_t*>(base), static_cast<size_t>(st.st_size));

    if (bytesSpan.size() < 24
        || bytesSpan[0] != kCompositeAtlasMagic[0]
        || bytesSpan[1] != kCompositeAtlasMagic[1]
        || bytesSpan[2] != kCompositeAtlasMagic[2]
        || bytesSpan[3] != kCompositeAtlasMagic[3]) {
        WTFLogAlways("[Driftstack] CompositeAtlas: bad magic at start of %s", path);
        munmap(base, st.st_size);
        close(fd);
        return;
    }

    auto readU32 = [&bytesSpan](size_t off) -> uint32_t {
        return uint32_t(bytesSpan[off]) | (uint32_t(bytesSpan[off+1]) << 8)
             | (uint32_t(bytesSpan[off+2]) << 16) | (uint32_t(bytesSpan[off+3]) << 24);
    };

    uint32_t version = readU32(4);
    uint32_t numStrikes = readU32(8);
    uint32_t numEntries = readU32(12);
    uint32_t indexOffset = readU32(16);
    uint32_t dataOffset = readU32(20);

    if (version != 1 || numStrikes == 0 || numStrikes > 16) {
        WTFLogAlways("[Driftstack] CompositeAtlas: invalid header version=%u numStrikes=%u", version, numStrikes);
        munmap(base, st.st_size);
        close(fd);
        return;
    }

    m_strikes.reserveInitialCapacity(numStrikes);
    for (uint32_t i = 0; i < numStrikes; ++i)
        m_strikes.append(readU32(24 + 4 * i));

    m_indexSpan = bytesSpan.subspan(indexOffset, numEntries * kEntrySize);
    m_dataPayloadSpan = bytesSpan.subspan(dataOffset);
    m_numEntries = numEntries;

    m_fd = fd;
    m_mmapBase = static_cast<const uint8_t*>(base);
    m_mmapSize = st.st_size;

    WTFLogAlways("[Driftstack] CompositeAtlas: mapped %lld bytes from %s; %u entries × %u strikes",
        (long long)st.st_size, path, numEntries, numStrikes);
}

// Read entry at index i (sequence + strikeIdx + offset + len).
struct CompositeIndexEntry {
    uint16_t sequenceLen;
    uint16_t strikeIdx;
    uint32_t offsetInPayload;
    uint32_t pngBytesLen;
    std::span<const uint8_t> sequenceBytes;
};

static CompositeIndexEntry readCompositeEntry(std::span<const uint8_t> indexSpan, size_t i)
{
    CompositeIndexEntry e;
    auto entrySpan = indexSpan.subspan(i * kEntrySize, kEntrySize);
    auto seqSpan = entrySpan.subspan(0, kSequenceBytes);
    e.sequenceLen = uint16_t(entrySpan[64]) | (uint16_t(entrySpan[65]) << 8);
    e.strikeIdx = uint16_t(entrySpan[66]) | (uint16_t(entrySpan[67]) << 8);
    // entry[68..72] reserved
    e.offsetInPayload = uint32_t(entrySpan[72]) | (uint32_t(entrySpan[73]) << 8) | (uint32_t(entrySpan[74]) << 16) | (uint32_t(entrySpan[75]) << 24);
    e.pngBytesLen = uint32_t(entrySpan[76]) | (uint32_t(entrySpan[77]) << 8) | (uint32_t(entrySpan[78]) << 16) | (uint32_t(entrySpan[79]) << 24);
    e.sequenceBytes = seqSpan.subspan(0, e.sequenceLen);
    return e;
}

// Compare two byte sequences lexically (memcmp equivalent).
static int compareBytes(std::span<const uint8_t> a, std::span<const uint8_t> b)
{
    size_t n = std::min(a.size(), b.size());
    for (size_t i = 0; i < n; ++i) {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return 1;
    }
    if (a.size() < b.size()) return -1;
    if (a.size() > b.size()) return 1;
    return 0;
}

std::span<const uint8_t> DriftstackCompositeAtlas::entryForSequenceAndStrike(std::span<const uint8_t> sequenceUtf8, uint32_t strikePPEM) const
{
    if (m_dataPayloadSpan.empty() || m_indexSpan.empty() || !m_numEntries)
        return { };
    if (sequenceUtf8.size() > kSequenceBytes)
        return { };

    // Find strike index.
    uint16_t strikeIdx = std::numeric_limits<uint16_t>::max();
    for (size_t i = 0; i < m_strikes.size(); ++i) {
        if (m_strikes[i] == strikePPEM) {
            strikeIdx = static_cast<uint16_t>(i);
            break;
        }
    }
    if (strikeIdx == std::numeric_limits<uint16_t>::max())
        return { };

    // Binary search by sequence (entries sorted by sequence_utf8 lex).
    size_t lo = 0, hi = m_numEntries;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        auto e = readCompositeEntry(m_indexSpan, mid);
        int cmp = compareBytes(e.sequenceBytes, sequenceUtf8);
        if (cmp < 0) lo = mid + 1;
        else if (cmp > 0) hi = mid;
        else {
            // Found a matching sequence; scan for the right strikeIdx.
            size_t start = mid;
            while (start > 0 && compareBytes(readCompositeEntry(m_indexSpan, start - 1).sequenceBytes, sequenceUtf8) == 0)
                --start;
            for (size_t i = start; i < m_numEntries; ++i) {
                auto ie = readCompositeEntry(m_indexSpan, i);
                if (compareBytes(ie.sequenceBytes, sequenceUtf8) != 0) break;
                if (ie.strikeIdx == strikeIdx)
                    return m_dataPayloadSpan.subspan(ie.offsetInPayload, ie.pngBytesLen);
            }
            return { };
        }
    }
    return { };
}

uint32_t DriftstackCompositeAtlas::pickStrikeForPointSize(float pointSize) const
{
    if (m_strikes.isEmpty())
        return 0;
    for (uint32_t s : m_strikes) {
        if (static_cast<float>(s) >= pointSize)
            return s;
    }
    return m_strikes.last();
}

} // namespace WebCore

#endif // PLATFORM(DRIFTSTACK)
