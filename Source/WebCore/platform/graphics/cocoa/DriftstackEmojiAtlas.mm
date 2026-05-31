/*
 * DriftstackEmojiAtlas.mm — see header.
 */

#include "config.h"
#include "DriftstackEmojiAtlas.h"

#if PLATFORM(DRIFTSTACK)

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <wtf/Logging.h>

namespace WebCore {

// V-088 atlas binary path. Override at runtime via DRIFTSTACK_EMOJI_ATLAS_PATH
// env var; default resolves to the captured atlas in dev environment.
static const char* kDefaultAtlasPath = "/Users/john/code/driftstack/reference/driftstack_emoji_atlas/driftstack-emoji-atlas.bin";

static constexpr uint8_t kAtlasMagic[4] = { 'D', 'S', 'E', 'A' };

DriftstackEmojiAtlas& DriftstackEmojiAtlas::singleton()
{
    static NeverDestroyed<DriftstackEmojiAtlas> instance;
    return instance.get();
}

DriftstackEmojiAtlas::DriftstackEmojiAtlas()
{
    mapAtlas();
}

DriftstackEmojiAtlas::~DriftstackEmojiAtlas()
{
    if (m_mmapBase && m_mmapSize)
        munmap(const_cast<uint8_t*>(m_mmapBase), m_mmapSize);
    if (m_fd >= 0)
        close(m_fd);
}

void DriftstackEmojiAtlas::mapAtlas()
{
    // Direct-browse (human inspection) mode: skip the canvas-fingerprint atlas so
    // page text renders natively (see DriftstackAsciiAtlas::mapAtlas for rationale).
    const char* db = getenv("DRIFTSTACK_DIRECT_BROWSE");
    const char* bm = getenv("DRIFTSTACK_BROWSE");
    if ((db && db[0] == '1') || (bm && bm[0] == '1')) {
        WTFLogAlways("[Driftstack] EmojiAtlas: load suppressed (browse render) — native page-text");
        return;
    }

    const char* envPath = getenv("DRIFTSTACK_EMOJI_ATLAS_PATH");
    const char* path = envPath ? envPath : kDefaultAtlasPath;

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        WTFLogAlways("[Driftstack] EmojiAtlas: open failed for %s (errno=%d, pid=%d, prog=%s)",
            path, errno, (int)getpid(), getprogname());
        return;
    }

    struct stat st;
    if (fstat(fd, &st) < 0 || st.st_size < 24) {
        WTFLogAlways("[Driftstack] EmojiAtlas: fstat failed or file too small (%lld bytes)", (long long)st.st_size);
        close(fd);
        return;
    }

    void* base = mmap(nullptr, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (base == MAP_FAILED) {
        WTFLogAlways("[Driftstack] EmojiAtlas: mmap failed (errno=%d)", errno);
        close(fd);
        return;
    }

    std::span<const uint8_t> bytesSpan = unsafeMakeSpan(static_cast<const uint8_t*>(base), static_cast<size_t>(st.st_size));

    // Verify magic.
    if (bytesSpan.size() < 24
        || bytesSpan[0] != kAtlasMagic[0]
        || bytesSpan[1] != kAtlasMagic[1]
        || bytesSpan[2] != kAtlasMagic[2]
        || bytesSpan[3] != kAtlasMagic[3]) {
        WTFLogAlways("[Driftstack] EmojiAtlas: bad magic at start of %s", path);
        munmap(base, st.st_size);
        close(fd);
        return;
    }

    // Parse header (LE).
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
        WTFLogAlways("[Driftstack] EmojiAtlas: invalid header version=%u numStrikes=%u", version, numStrikes);
        munmap(base, st.st_size);
        close(fd);
        return;
    }

    m_strikes.reserveInitialCapacity(numStrikes);
    for (uint32_t i = 0; i < numStrikes; ++i)
        m_strikes.append(readU32(24 + 4 * i));

    m_indexSpan = bytesSpan.subspan(indexOffset, numEntries * 16);
    m_dataPayloadSpan = bytesSpan.subspan(dataOffset);
    m_numEntries = numEntries;

    m_fd = fd;
    m_mmapBase = static_cast<const uint8_t*>(base);
    m_mmapSize = st.st_size;

    WTFLogAlways("[Driftstack] EmojiAtlas: mapped %lld bytes from %s; %u entries × %u strikes (pid=%d, prog=%s)",
        (long long)st.st_size, path, numEntries, numStrikes, (int)getpid(), getprogname());
}

// Read an IndexEntry from the byte span at logical entry index i.
// Avoids unaligned struct access by reading byte-by-byte.
static DriftstackEmojiAtlas_IndexEntry readEntry(std::span<const uint8_t> indexSpan, size_t i)
{
    DriftstackEmojiAtlas_IndexEntry e;
    auto entrySpan = indexSpan.subspan(i * 16, 16);
    e.codepoint = uint32_t(entrySpan[0]) | (uint32_t(entrySpan[1]) << 8) | (uint32_t(entrySpan[2]) << 16) | (uint32_t(entrySpan[3]) << 24);
    e.strikeIdx = uint16_t(entrySpan[4]) | (uint16_t(entrySpan[5]) << 8);
    e.reserved = uint16_t(entrySpan[6]) | (uint16_t(entrySpan[7]) << 8);
    e.offsetInPayload = uint32_t(entrySpan[8]) | (uint32_t(entrySpan[9]) << 8) | (uint32_t(entrySpan[10]) << 16) | (uint32_t(entrySpan[11]) << 24);
    e.pngBytesLen = uint32_t(entrySpan[12]) | (uint32_t(entrySpan[13]) << 8) | (uint32_t(entrySpan[14]) << 16) | (uint32_t(entrySpan[15]) << 24);
    return e;
}

std::span<const uint8_t> DriftstackEmojiAtlas::entryForCodepointAndStrike(uint32_t codepoint, uint32_t strikePPEM) const
{
    if (m_dataPayloadSpan.empty() || m_indexSpan.empty() || !m_numEntries)
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

    // Binary search by codepoint, then linear scan among that codepoint's strikes.
    size_t lo = 0, hi = m_numEntries;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        auto e = readEntry(m_indexSpan, mid);
        if (e.codepoint < codepoint) lo = mid + 1;
        else if (e.codepoint > codepoint) hi = mid;
        else {
            // Found a matching codepoint; scan forwards/backwards for the right strikeIdx.
            // Index is sorted by (codepoint, strikeIdx).
            size_t start = mid;
            while (start > 0 && readEntry(m_indexSpan, start - 1).codepoint == codepoint)
                --start;
            for (size_t i = start; i < m_numEntries; ++i) {
                auto ie = readEntry(m_indexSpan, i);
                if (ie.codepoint != codepoint) break;
                if (ie.strikeIdx == strikeIdx)
                    return m_dataPayloadSpan.subspan(ie.offsetInPayload, ie.pngBytesLen);
            }
            return { };
        }
    }
    return { };
}

uint32_t DriftstackEmojiAtlas::pickStrikeForPointSize(float pointSize) const
{
    if (m_strikes.isEmpty())
        return 0;
    // Smallest strike >= pointSize.
    for (uint32_t s : m_strikes) {
        if (static_cast<float>(s) >= pointSize)
            return s;
    }
    // pointSize larger than all strikes; return the largest.
    return m_strikes.last();
}

const Vector<uint32_t>& DriftstackEmojiAtlas::codepoints() const
{
    if (m_codepointsBuilt)
        return m_uniqueCodepoints;

    m_uniqueCodepoints.reserveInitialCapacity(m_numEntries / m_strikes.size());
    uint32_t lastSeen = std::numeric_limits<uint32_t>::max();
    for (size_t i = 0; i < m_numEntries; ++i) {
        auto e = readEntry(m_indexSpan, i);
        if (e.codepoint != lastSeen) {
            m_uniqueCodepoints.append(e.codepoint);
            lastSeen = e.codepoint;
        }
    }
    m_codepointsBuilt = true;
    return m_uniqueCodepoints;
}

} // namespace WebCore

#endif // PLATFORM(DRIFTSTACK)
