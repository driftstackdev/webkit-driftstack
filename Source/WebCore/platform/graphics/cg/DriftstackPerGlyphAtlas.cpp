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
#include <string>
#include <vector>
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

WTF_ALLOW_UNSAFE_BUFFER_USAGE_BEGIN

// Read little-endian u16 from byte ptr. WebKit's
// -Wunsafe-buffer-usage flags raw-pointer arithmetic; wrapped in
// WTF_ALLOW_UNSAFE_BUFFER_USAGE for the mmap'd-byte access pattern.
inline uint16_t leU16(const uint8_t* p)
{
    return static_cast<uint16_t>(p[0]) | (static_cast<uint16_t>(p[1]) << 8);
}

inline uint32_t leU32(const uint8_t* p)
{
    return static_cast<uint32_t>(p[0])
         | (static_cast<uint32_t>(p[1]) << 8)
         | (static_cast<uint32_t>(p[2]) << 16)
         | (static_cast<uint32_t>(p[3]) << 24);
}

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

inline int cmpKey(const uint8_t* a, const uint8_t* b)
{
    return std::memcmp(a, b, kKeySize);
}

WTF_ALLOW_UNSAFE_BUFFER_USAGE_END

} // anonymous namespace

DriftstackPerGlyphAtlas& DriftstackPerGlyphAtlas::singleton()
{
    static NeverDestroyed<DriftstackPerGlyphAtlas> instance;
    if (!instance->m_loaded)
        instance->loadFromFile(nullptr);
    return instance.get();
}

WTF_ALLOW_UNSAFE_BUFFER_USAGE_BEGIN

// V-211: the dev-default data path derives from the environment
// (DRIFTSTACK_DATA_ROOT, else $HOME/code/driftstack) instead of a hardcoded
// build-machine home directory. One-time strdup, process lifetime.
static const char* perGlyphAtlasDefaultPath(const char* relative)
{
    const char* root = std::getenv("DRIFTSTACK_DATA_ROOT");
    const char* home = std::getenv("HOME");
    std::string p = (root && *root) ? std::string(root) : std::string(home ? home : "") + "/code/driftstack";
    p += relative;
    return ::strdup(p.c_str());
}

bool DriftstackPerGlyphAtlas::loadFromFile(const char* path)
{
    if (m_loaded)
        return true;

    const char* resolved = path;
    if (!resolved)
        resolved = std::getenv("DRIFTSTACK_PER_GLYPH_ATLAS_PATH");
    if (!resolved)
        resolved = perGlyphAtlasDefaultPath("/reference/driftstack_per_glyph_atlas.bin");

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

WTF_ALLOW_UNSAFE_BUFFER_USAGE_END

WTF_ALLOW_UNSAFE_BUFFER_USAGE_BEGIN

// #79 Western canvas-advance sidecar (DSWADV1). Lazy-loaded once into a sorted
// in-memory table (keys already sorted by (fontId,sizePx,cp) in the file → the
// packed-u64 key order matches → binary search). Process-lifetime leak by design.
std::optional<float> driftstackWesternAdvanceSidecar(uint16_t fontId, uint16_t sizePx, uint32_t codepoint)
{
    struct Sidecar {
        std::vector<uint64_t> keys;
        std::vector<float> widths;
    };
    static const Sidecar* s_sidecar = []() -> const Sidecar* {
        const char* resolved = std::getenv("DRIFTSTACK_WESTERN_ADVANCE_SIDECAR_PATH");
        if (!resolved)
            resolved = perGlyphAtlasDefaultPath("/reference/driftstack_western_advance_sidecar.bin");
        int fd = ::open(resolved, O_RDONLY);
        if (fd < 0) {
            WTFLogAlways("[Driftstack-#79-sidecar] open FAILED path=%s errno=%d", resolved, errno);
            return nullptr;
        }
        struct stat st;
        if (::fstat(fd, &st) != 0 || st.st_size < 16) { ::close(fd); return nullptr; }
        void* base = ::mmap(nullptr, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
        ::close(fd);
        if (base == MAP_FAILED)
            return nullptr;
        const uint8_t* b = static_cast<const uint8_t*>(base);
        static const char kSc[8] = { 'D', 'S', 'W', 'A', 'D', 'V', '1', '\0' };
        uint32_t version = leU32(b + 8);
        uint32_t count = leU32(b + 12);
        constexpr size_t kEnt = 12;
        if (std::memcmp(b, kSc, 8) != 0 || version != 1
            || static_cast<size_t>(st.st_size) != 16 + static_cast<size_t>(count) * kEnt) {
            ::munmap(base, st.st_size);
            return nullptr;
        }
        auto* sc = new Sidecar();
        sc->keys.reserve(count);
        sc->widths.reserve(count);
        for (uint32_t i = 0; i < count; ++i) {
            const uint8_t* e = b + 16 + static_cast<size_t>(i) * kEnt;
            uint64_t k = (static_cast<uint64_t>(leU16(e)) << 48)
                       | (static_cast<uint64_t>(leU16(e + 2)) << 32)
                       | leU32(e + 4);
            uint32_t wbits = leU32(e + 8);
            float w;
            std::memcpy(&w, &wbits, 4);
            sc->keys.push_back(k);
            sc->widths.push_back(w);
        }
        ::munmap(base, st.st_size);
        WTFLogAlways("[Driftstack-#79-sidecar] LOADED %u entries from %s", count, resolved);
        return sc;
    }();
    if (!s_sidecar)
        return std::nullopt;
    uint64_t key = (static_cast<uint64_t>(fontId) << 48)
                 | (static_cast<uint64_t>(sizePx) << 32) | codepoint;
    auto it = std::lower_bound(s_sidecar->keys.begin(), s_sidecar->keys.end(), key);
    if (it == s_sidecar->keys.end() || *it != key)
        return std::nullopt;
    return s_sidecar->widths[static_cast<size_t>(it - s_sidecar->keys.begin())];
}

WTF_ALLOW_UNSAFE_BUFFER_USAGE_END

} // namespace WebCore

#endif // PLATFORM(DRIFTSTACK)
