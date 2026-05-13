/*
 * V-790.L per-glyph exact-substitution atlas implementation.
 *
 * mmap + binary search over the DSPGA1 atlas binary built by
 * captures/v3/v790l-per-glyph-atlas-builder.py.
 */
#include "config.h"
#include "DriftstackPerGlyphAtlas.h"

#if PLATFORM(DRIFTSTACK)

#include <algorithm>
#include <atomic>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <wtf/Assertions.h>
#include <wtf/NeverDestroyed.h>

namespace WebCore {

namespace {

constexpr size_t kHeaderSize = 16;
constexpr size_t kKeySize = 12;     // font_id u16 + pt_size_q4 u16 + cp u32 + pos u32
constexpr size_t kPixelsSize = 64 * 64;
constexpr size_t kEntrySize = kKeySize + kPixelsSize;
constexpr const char kMagic[8] = { 'D', 'S', 'P', 'G', 'A', '1', '\0', '\0' };

// Read little-endian u16 from byte ptr.
inline uint16_t leU16(const uint8_t* p)
{
    return static_cast<uint16_t>(p[0]) | (static_cast<uint16_t>(p[1]) << 8);
}

// Read little-endian u32 from byte ptr.
inline uint32_t leU32(const uint8_t* p)
{
    return static_cast<uint32_t>(p[0])
         | (static_cast<uint32_t>(p[1]) << 8)
         | (static_cast<uint32_t>(p[2]) << 16)
         | (static_cast<uint32_t>(p[3]) << 24);
}

// Pack a lookup key into 12 little-endian bytes (matching the on-disk
// format produced by the Python builder).
inline void packKey(uint8_t out[kKeySize], uint16_t fontId,
    uint16_t ptSizeQ4, uint32_t codepoint, uint32_t posClass)
{
    out[0] = static_cast<uint8_t>(fontId & 0xff);
    out[1] = static_cast<uint8_t>((fontId >> 8) & 0xff);
    out[2] = static_cast<uint8_t>(ptSizeQ4 & 0xff);
    out[3] = static_cast<uint8_t>((ptSizeQ4 >> 8) & 0xff);
    out[4] = static_cast<uint8_t>(codepoint & 0xff);
    out[5] = static_cast<uint8_t>((codepoint >> 8) & 0xff);
    out[6] = static_cast<uint8_t>((codepoint >> 16) & 0xff);
    out[7] = static_cast<uint8_t>((codepoint >> 24) & 0xff);
    out[8]  = static_cast<uint8_t>(posClass & 0xff);
    out[9]  = static_cast<uint8_t>((posClass >> 8) & 0xff);
    out[10] = static_cast<uint8_t>((posClass >> 16) & 0xff);
    out[11] = static_cast<uint8_t>((posClass >> 24) & 0xff);
}

// memcmp wrapper that treats keys as a 12-byte unsigned blob (same
// ordering used by the Python builder when sorting before write).
inline int cmpKey(const uint8_t* a, const uint8_t* b)
{
    return std::memcmp(a, b, kKeySize);
}

} // anonymous namespace

DriftstackPerGlyphAtlas& DriftstackPerGlyphAtlas::singleton()
{
    static NeverDestroyed<DriftstackPerGlyphAtlas> instance;
    if (!instance->m_loaded)
        instance->loadFromFile(nullptr);
    return instance.get();
}

bool DriftstackPerGlyphAtlas::loadFromFile(const char* path)
{
    if (m_loaded)
        return true;

    const char* resolved = path;
    if (!resolved)
        resolved = std::getenv("DRIFTSTACK_PER_GLYPH_ATLAS_PATH");
    if (!resolved)
        resolved = "/Users/john/code/driftstack/reference/driftstack_per_glyph_atlas.bin";

    bool diag = std::getenv("DRIFTSTACK_PER_GLYPH_ATLAS_DIAG") != nullptr;

    int fd = ::open(resolved, O_RDONLY);
    if (fd < 0) {
        if (diag) {
            WTFLogAlways("[V-790.L] per-glyph atlas open failed: %s "
                         "(errno=%d). Layer-A2 disabled.", resolved, errno);
        }
        return false;
    }

    struct stat st;
    if (::fstat(fd, &st) != 0 || st.st_size < static_cast<off_t>(kHeaderSize)) {
        if (diag) {
            WTFLogAlways("[V-790.L] per-glyph atlas stat failed or too "
                         "small: size=%lld", static_cast<long long>(st.st_size));
        }
        ::close(fd);
        return false;
    }

    void* base = ::mmap(nullptr, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    ::close(fd);
    if (base == MAP_FAILED) {
        if (diag)
            WTFLogAlways("[V-790.L] per-glyph atlas mmap failed");
        return false;
    }

    const uint8_t* bytes = static_cast<const uint8_t*>(base);

    if (std::memcmp(bytes, kMagic, 8) != 0) {
        WTFLogAlways("[V-790.L] per-glyph atlas magic mismatch — Layer-A2 disabled");
        ::munmap(base, st.st_size);
        return false;
    }

    uint32_t version = leU32(bytes + 8);
    uint32_t count = leU32(bytes + 12);
    if (version != 1) {
        WTFLogAlways("[V-790.L] per-glyph atlas version=%u unsupported — "
                     "Layer-A2 disabled", version);
        ::munmap(base, st.st_size);
        return false;
    }

    off_t expected = static_cast<off_t>(kHeaderSize) + static_cast<off_t>(count) * static_cast<off_t>(kEntrySize);
    if (st.st_size != expected) {
        WTFLogAlways("[V-790.L] per-glyph atlas size mismatch: got %lld "
                     "expected %lld (count=%u) — Layer-A2 disabled",
                     static_cast<long long>(st.st_size),
                     static_cast<long long>(expected), count);
        ::munmap(base, st.st_size);
        return false;
    }

    m_mapBase = bytes;
    m_mapSize = static_cast<size_t>(st.st_size);
    m_entryCount = count;
    m_entriesBase = bytes + kHeaderSize;
    m_loaded = true;

    WTFLogAlways("[V-790.L] per-glyph atlas loaded: %u entries from %s",
                 count, resolved);
    return true;
}

std::optional<DriftstackPerGlyphAtlasEntry> DriftstackPerGlyphAtlas::lookup(
    uint16_t fontId, uint16_t ptSizeQ4, uint32_t codepoint, uint32_t posClass) const
{
    if (!m_loaded || !m_entriesBase || !m_entryCount)
        return std::nullopt;

    uint8_t target[kKeySize];
    packKey(target, fontId, ptSizeQ4, codepoint, posClass);

    // Binary search over sorted entries.
    size_t lo = 0;
    size_t hi = m_entryCount;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        const uint8_t* midKey = m_entriesBase + mid * kEntrySize;
        int c = cmpKey(target, midKey);
        if (c == 0) {
            DriftstackPerGlyphAtlasEntry entry;
            entry.pixels = midKey + kKeySize;
            entry.pixelsSize = kPixelsSize;
            return entry;
        }
        if (c < 0)
            hi = mid;
        else
            lo = mid + 1;
    }
    return std::nullopt;
}

} // namespace WebCore

#endif // PLATFORM(DRIFTSTACK)
