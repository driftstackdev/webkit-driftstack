/*
 * DriftstackAsciiAtlas.mm — see header.
 */

#include "config.h"
#include "DriftstackAsciiAtlas.h"

#if PLATFORM(DRIFTSTACK)

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <wtf/Logging.h>

namespace WebCore {

// V-117 atlas binary path. Override at runtime via DRIFTSTACK_ASCII_ATLAS_PATH
// env var; default resolves to the captured atlas in dev environment.
static const char* kDefaultAtlasPath = "/Users/john/code/driftstack/reference/driftstack_ascii_atlas/driftstack-ascii-atlas.bin";

static constexpr uint8_t kAtlasMagic[4] = { 'D', 'S', 'A', 'S' };
static constexpr size_t kFontNameBytes = 64;
static constexpr size_t kEntryBytes = 16;

DriftstackAsciiAtlas& DriftstackAsciiAtlas::singleton()
{
    static NeverDestroyed<DriftstackAsciiAtlas> instance;
    return instance.get();
}

DriftstackAsciiAtlas::DriftstackAsciiAtlas()
{
    mapAtlas();
}

DriftstackAsciiAtlas::~DriftstackAsciiAtlas()
{
    if (m_mmapBase && m_mmapSize)
        munmap(const_cast<uint8_t*>(m_mmapBase), m_mmapSize);
    if (m_fd >= 0)
        close(m_fd);
}

void DriftstackAsciiAtlas::mapAtlas()
{
    const char* envPath = getenv("DRIFTSTACK_ASCII_ATLAS_PATH");
    const char* path = envPath ? envPath : kDefaultAtlasPath;

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        WTFLogAlways("[Driftstack] AsciiAtlas: open failed for %s (errno=%d)", path, errno);
        return;
    }

    struct stat st;
    if (fstat(fd, &st) < 0 || st.st_size < 24) {
        WTFLogAlways("[Driftstack] AsciiAtlas: fstat failed or file too small (%lld bytes)", (long long)st.st_size);
        close(fd);
        return;
    }

    void* base = mmap(nullptr, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (base == MAP_FAILED) {
        WTFLogAlways("[Driftstack] AsciiAtlas: mmap failed (errno=%d)", errno);
        close(fd);
        return;
    }

    std::span<const uint8_t> bytesSpan = unsafeMakeSpan(static_cast<const uint8_t*>(base), static_cast<size_t>(st.st_size));

    if (bytesSpan.size() < 24
        || bytesSpan[0] != kAtlasMagic[0]
        || bytesSpan[1] != kAtlasMagic[1]
        || bytesSpan[2] != kAtlasMagic[2]
        || bytesSpan[3] != kAtlasMagic[3]) {
        WTFLogAlways("[Driftstack] AsciiAtlas: bad magic at start of %s", path);
        munmap(base, st.st_size);
        close(fd);
        return;
    }

    auto readU32 = [&bytesSpan](size_t off) -> uint32_t {
        return uint32_t(bytesSpan[off]) | (uint32_t(bytesSpan[off+1]) << 8)
             | (uint32_t(bytesSpan[off+2]) << 16) | (uint32_t(bytesSpan[off+3]) << 24);
    };

    uint32_t version = readU32(4);
    uint32_t numFonts = readU32(8);
    uint32_t numEntries = readU32(12);
    uint32_t indexOffset = readU32(16);
    uint32_t dataOffset = readU32(20);

    if (version != 1 || numFonts == 0 || numFonts > 64) {
        WTFLogAlways("[Driftstack] AsciiAtlas: invalid header version=%u numFonts=%u", version, numFonts);
        munmap(base, st.st_size);
        close(fd);
        return;
    }

    // Parse font_table (64 bytes per entry, zero-padded UTF-8).
    m_fontNames.reserveInitialCapacity(numFonts);
    for (uint32_t i = 0; i < numFonts; ++i) {
        size_t off = 24 + i * kFontNameBytes;
        // Find first NUL byte.
        size_t len = 0;
        while (len < kFontNameBytes && bytesSpan[off + len] != 0)
            ++len;
        m_fontNames.append(String::fromUTF8(unsafeMakeSpan(bytesSpan.data() + off, len)));
    }

    if (indexOffset != 24 + numFonts * kFontNameBytes
        || dataOffset != indexOffset + numEntries * kEntryBytes
        || dataOffset > bytesSpan.size()) {
        WTFLogAlways("[Driftstack] AsciiAtlas: header offsets invalid (indexOffset=%u dataOffset=%u fileSize=%zu)",
            indexOffset, dataOffset, bytesSpan.size());
        munmap(base, st.st_size);
        close(fd);
        return;
    }

    m_indexSpan = bytesSpan.subspan(indexOffset, numEntries * kEntryBytes);
    m_dataPayloadSpan = bytesSpan.subspan(dataOffset);
    m_numEntries = numEntries;

    m_fd = fd;
    m_mmapBase = static_cast<const uint8_t*>(base);
    m_mmapSize = st.st_size;

    WTFLogAlways("[Driftstack] AsciiAtlas: mapped %lld bytes from %s; %u entries × %u fonts",
        (long long)st.st_size, path, numEntries, numFonts);
}

uint16_t DriftstackAsciiAtlas::fontIdFor(const String& fontCssName) const
{
    for (size_t i = 0; i < m_fontNames.size(); ++i) {
        if (m_fontNames[i] == fontCssName)
            return static_cast<uint16_t>(i);
    }
    return std::numeric_limits<uint16_t>::max();
}

// Read an IndexEntry from the byte span at logical entry index i.
// Avoids unaligned struct access by reading byte-by-byte.
static DriftstackAsciiAtlas_IndexEntry readEntry(std::span<const uint8_t> indexSpan, size_t i)
{
    DriftstackAsciiAtlas_IndexEntry e;
    auto entrySpan = indexSpan.subspan(i * kEntryBytes, kEntryBytes);
    e.fontId = uint16_t(entrySpan[0]) | (uint16_t(entrySpan[1]) << 8);
    e.sizePx = uint16_t(entrySpan[2]) | (uint16_t(entrySpan[3]) << 8);
    e.codepoint = uint32_t(entrySpan[4]) | (uint32_t(entrySpan[5]) << 8) | (uint32_t(entrySpan[6]) << 16) | (uint32_t(entrySpan[7]) << 24);
    e.dataOffset = uint32_t(entrySpan[8]) | (uint32_t(entrySpan[9]) << 8) | (uint32_t(entrySpan[10]) << 16) | (uint32_t(entrySpan[11]) << 24);
    e.pngLen = uint32_t(entrySpan[12]) | (uint32_t(entrySpan[13]) << 8) | (uint32_t(entrySpan[14]) << 16) | (uint32_t(entrySpan[15]) << 24);
    return e;
}

std::span<const uint8_t> DriftstackAsciiAtlas::entryFor(const String& fontCssName, uint16_t sizePx, uint32_t codepoint) const
{
    if (m_dataPayloadSpan.empty() || m_indexSpan.empty() || !m_numEntries)
        return { };

    uint16_t fontId = fontIdFor(fontCssName);
    if (fontId == std::numeric_limits<uint16_t>::max())
        return { };

    // Triple-key binary search on (fontId, sizePx, codepoint), sorted in that order.
    size_t lo = 0, hi = m_numEntries;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        auto e = readEntry(m_indexSpan, mid);
        if (e.fontId < fontId) lo = mid + 1;
        else if (e.fontId > fontId) hi = mid;
        else if (e.sizePx < sizePx) lo = mid + 1;
        else if (e.sizePx > sizePx) hi = mid;
        else if (e.codepoint < codepoint) lo = mid + 1;
        else if (e.codepoint > codepoint) hi = mid;
        else
            return m_dataPayloadSpan.subspan(e.dataOffset, e.pngLen);
    }
    return { };
}

} // namespace WebCore

#endif // PLATFORM(DRIFTSTACK)
