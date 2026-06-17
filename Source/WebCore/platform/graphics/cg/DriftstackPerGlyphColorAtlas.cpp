/*
 * Per-glyph COLOR-emoji exact-substitution atlas implementation (#42 color residual, W2557).
 *
 * mmap + binary search over the DSPGCA1 atlas binary built by
 * captures/v3/build-perglyph-color-atlas.py. Mirrors DriftstackPerGlyphAtlas.cpp
 * (DSPGA1) byte-for-byte except the per-entry pixel payload is RGBA 16384 not 4096.
 */
#include "config.h"
#include "DriftstackPerGlyphColorAtlas.h"

#if PLATFORM(DRIFTSTACK)

#include "DriftstackTextRunAtlas.h"   // driftstackFnv1a32 (DSPGCA2 seq_hash keying)

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <string>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <wtf/Assertions.h>
#include <wtf/NeverDestroyed.h>

namespace WebCore {

namespace {

// NOTE: distinct names from DriftstackPerGlyphAtlas.cpp's anonymous-namespace helpers
// (kHeaderSize/kKeySize/leU32/packKey/cmpKey/...) — WebKit's UNIFIED build concatenates
// both .cpp into one TU, merging the anonymous namespaces; identical names would redefine.
constexpr size_t kColorHeaderSize = 16;
constexpr size_t kColorKeySize = 12;          // font_id u16 + pt_size_q4 u16 + cp u32 + pos u32
constexpr size_t kColorPixelsSize = 64 * 64 * 4;  // RGBA
constexpr size_t kColorEntrySize = kColorKeySize + kColorPixelsSize;
constexpr const char kColorMagic[8] = { 'D', 'S', 'P', 'G', 'C', 'A', '1', '\0' };
// DSPGCA2 (#42 multi-cp): identical layout; the u32 key field holds seq_hash=FNV-1a-32(utf8 of the
// codepoint sequence) instead of a bare codepoint (single cp = length-1 sequence → byte-identical).
constexpr const char kColorMagic2[8] = { 'D', 'S', 'P', 'G', 'C', 'A', '2', '\0' };

WTF_ALLOW_UNSAFE_BUFFER_USAGE_BEGIN

inline uint32_t leU32Color(const uint8_t* p)
{
    return static_cast<uint32_t>(p[0])
         | (static_cast<uint32_t>(p[1]) << 8)
         | (static_cast<uint32_t>(p[2]) << 16)
         | (static_cast<uint32_t>(p[3]) << 24);
}

inline void packKeyColor(uint8_t out[kColorKeySize], uint16_t fontId,
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

inline int cmpKeyColor(const uint8_t* a, const uint8_t* b)
{
    return std::memcmp(a, b, kColorKeySize);
}

WTF_ALLOW_UNSAFE_BUFFER_USAGE_END

} // anonymous namespace

DriftstackPerGlyphColorAtlas& DriftstackPerGlyphColorAtlas::singleton()
{
    static NeverDestroyed<DriftstackPerGlyphColorAtlas> instance;
    if (!instance->m_loaded)
        instance->loadFromFile(nullptr);
    return instance.get();
}

WTF_ALLOW_UNSAFE_BUFFER_USAGE_BEGIN

// V-211: dev-default path derives from the environment (DRIFTSTACK_DATA_ROOT,
// else $HOME/code/driftstack) — never a hardcoded build-machine home.
static const char* colorAtlasDefaultPath(const char* relative)
{
    const char* root = std::getenv("DRIFTSTACK_DATA_ROOT");
    const char* home = std::getenv("HOME");
    std::string p = (root && *root) ? std::string(root) : std::string(home ? home : "") + "/code/driftstack";
    p += relative;
    return ::strdup(p.c_str());
}

bool DriftstackPerGlyphColorAtlas::loadFromFile(const char* path)
{
    if (m_loaded)
        return true;

    const char* resolved = path;
    if (!resolved)
        resolved = std::getenv("DRIFTSTACK_PERGLYPH_COLOR_ATLAS_PATH");
    if (!resolved)
        resolved = colorAtlasDefaultPath("/reference/driftstack_emoji_atlas/driftstack-perglyph-color-atlas.bin");

    bool diag = std::getenv("DRIFTSTACK_PERGLYPH_COLOR_ATLAS_DIAG") != nullptr;

    int fd = ::open(resolved, O_RDONLY);
    if (fd < 0) {
        if (diag)
            WTFLogAlways("[V-COLOR] per-glyph color atlas open failed: %s (errno=%d)", resolved, errno);
        return false;
    }

    struct stat st;
    if (::fstat(fd, &st) != 0 || st.st_size < static_cast<off_t>(kColorHeaderSize)) {
        if (diag)
            WTFLogAlways("[V-COLOR] per-glyph color atlas stat failed/too small: size=%lld",
                static_cast<long long>(st.st_size));
        ::close(fd);
        return false;
    }

    void* base = ::mmap(nullptr, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    ::close(fd);
    if (base == MAP_FAILED) {
        if (diag)
            WTFLogAlways("[V-COLOR] per-glyph color atlas mmap failed");
        return false;
    }

    const uint8_t* bytes = static_cast<const uint8_t*>(base);

    bool isV2 = std::memcmp(bytes, kColorMagic2, 8) == 0;
    if (std::memcmp(bytes, kColorMagic, 8) != 0 && !isV2) {
        WTFLogAlways("[V-COLOR] per-glyph color atlas magic mismatch — disabled");
        ::munmap(base, st.st_size);
        return false;
    }

    uint32_t version = leU32Color(bytes + 8);
    uint32_t count = leU32Color(bytes + 12);
    if (version != 1 && version != 2) {
        WTFLogAlways("[V-COLOR] per-glyph color atlas version=%u unsupported — disabled", version);
        ::munmap(base, st.st_size);
        return false;
    }

    // off_t (64-bit signed) arithmetic — count cast to off_t BEFORE the multiply, so
    // the size check cannot integer-overflow on a malformed count (W2530 lesson).
    off_t expected = static_cast<off_t>(kColorHeaderSize) + static_cast<off_t>(count) * static_cast<off_t>(kColorEntrySize);
    if (st.st_size != expected) {
        WTFLogAlways("[V-COLOR] per-glyph color atlas size mismatch: got %lld expected %lld (count=%u) — disabled",
            static_cast<long long>(st.st_size), static_cast<long long>(expected), count);
        ::munmap(base, st.st_size);
        return false;
    }

    m_mapBase = bytes;
    m_mapSize = static_cast<size_t>(st.st_size);
    m_entryCount = count;
    m_entriesBase = bytes + kColorHeaderSize;
    m_version = version;   // DSPGCA2: the key u32 holds seq_hash, not a bare codepoint
    m_loaded = true;

    // Build the unique-codepoint index for hasCodepoint() (cp at key offset 4: after font_id u16 + ptSizeQ4 u16).
    m_codepoints.clear();
    m_codepoints.reserve(count);
    for (uint32_t i = 0; i < count; ++i)
        m_codepoints.push_back(leU32Color(m_entriesBase + static_cast<size_t>(i) * kColorEntrySize + 4));
    std::sort(m_codepoints.begin(), m_codepoints.end());
    m_codepoints.erase(std::unique(m_codepoints.begin(), m_codepoints.end()), m_codepoints.end());

    WTFLogAlways("[V-COLOR] per-glyph color atlas loaded: %u entries (%zu unique codepoints) from %s", count, m_codepoints.size(), resolved);
    return true;
}

std::optional<DriftstackPerGlyphColorAtlasEntry> DriftstackPerGlyphColorAtlas::lookup(
    uint16_t fontId, uint16_t ptSizeQ4, uint32_t codepoint, uint32_t posClass) const
{
    if (!m_loaded || !m_entriesBase || !m_entryCount)
        return std::nullopt;

    uint8_t target[kColorKeySize];
    packKeyColor(target, fontId, ptSizeQ4, codepoint, posClass);

    size_t lo = 0;
    size_t hi = m_entryCount;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        const uint8_t* midKey = m_entriesBase + mid * kColorEntrySize;
        int c = cmpKeyColor(target, midKey);
        if (c == 0) {
            DriftstackPerGlyphColorAtlasEntry entry;
            entry.pixels = midKey + kColorKeySize;
            entry.pixelsSize = kColorPixelsSize;
            return entry;
        }
        if (c < 0)
            hi = mid;
        else
            lo = mid + 1;
    }
    return std::nullopt;
}

bool DriftstackPerGlyphColorAtlas::hasCodepoint(uint32_t codepoint) const
{
    // For DSPGCA2 the m_codepoints index actually holds seq_hashes; a single codepoint is the
    // length-1 sequence, so search its seq_hash. For DSPGCA1 the index holds bare codepoints.
    uint32_t key = (m_version >= 2) ? driftstackSeqHashForCodepoint(static_cast<char32_t>(codepoint)) : codepoint;
    return std::binary_search(m_codepoints.begin(), m_codepoints.end(), key);
}

WTF_ALLOW_UNSAFE_BUFFER_USAGE_END

} // namespace WebCore

#endif // PLATFORM(DRIFTSTACK)
