/*
 * DriftstackDOMGeomAtlas — see DriftstackDOMGeomAtlas.h. (W2619)
 */

#include "config.h"
#include "DriftstackDOMGeomAtlas.h"

#if PLATFORM(DRIFTSTACK)

#include "DriftstackArchetypeConfig.h"
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <wtf/Assertions.h>

namespace WebCore {

// Default launch archetype when neither env nor a loaded config names one.
static constexpr const char* kDefaultArchetypeSlug = "iphone17_ios18_7_safari26_4";

static std::string domGeomAtlasPath()
{
    if (const char* explicitPath = std::getenv("DRIFTSTACK_DOMGEOM_ATLAS_PATH"); explicitPath && *explicitPath)
        return std::string(explicitPath);

    // Archetype-keyed default: <data-root>/reference/domgeom-atlas/domgeom-<slug>.bin
    std::string slug;
    if (const char* envSlug = std::getenv("DRIFTSTACK_ARCHETYPE"); envSlug && *envSlug)
        slug = envSlug;
    else if (auto& cfg = DriftstackArchetypeConfig::singleton(); cfg.isValid() && !cfg.archetypeId().isEmpty())
        slug = cfg.archetypeId().utf8().data();
    else
        slug = kDefaultArchetypeSlug;

    const char* root = std::getenv("DRIFTSTACK_DATA_ROOT");
    const char* home = std::getenv("HOME");
    std::string base = (root && *root) ? std::string(root) : std::string(home ? home : "") + "/code/driftstack";
    return base + "/reference/domgeom-atlas/domgeom-" + slug + ".bin";
}

DriftstackDOMGeomAtlas& DriftstackDOMGeomAtlas::singleton()
{
    static DriftstackDOMGeomAtlas* instance = new DriftstackDOMGeomAtlas();
    return *instance;
}

DriftstackDOMGeomAtlas::DriftstackDOMGeomAtlas()
{
    loadAtlas();
}

void DriftstackDOMGeomAtlas::loadAtlas()
{
    std::string path = domGeomAtlasPath();

    int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0) {
        // Absent atlas is non-fatal: the hardcoded serve table still covers the verified blocks.
        WTFLogAlways("[Driftstack-W2619] DOM-geom atlas not loaded (open %s errno=%d) — table-only", path.c_str(), errno);
        return;
    }

    struct stat st;
    if (fstat(fd, &st) < 0 || st.st_size < 16) {
        close(fd);
        return;
    }

    void* p = mmap(nullptr, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (p == MAP_FAILED) {
        WTFLogAlways("[Driftstack-W2619] DOM-geom atlas mmap failed");
        return;
    }

    WTF_ALLOW_UNSAFE_BUFFER_USAGE_BEGIN
    auto* base = static_cast<const uint8_t*>(p);

    if (base[0] != 'D' || base[1] != 'D' || base[2] != 'G' || base[3] != 'A') {
        munmap(p, st.st_size);
        WTFLogAlways("[Driftstack-W2619] DOM-geom atlas bad magic");
        return;
    }

    size_t pos = 4;
    uint16_t version;
    memcpy(&version, base + pos, 2); pos += 2;
    pos += 2; // reserved
    if (version != 1) {
        munmap(p, st.st_size);
        WTFLogAlways("[Driftstack-W2619] DOM-geom atlas unsupported version %u", version);
        return;
    }

    uint16_t slugLen;
    memcpy(&slugLen, base + pos, 2); pos += 2;
    pos += slugLen;
    pos = (pos + 3) & ~static_cast<size_t>(3); // pad slug to 4-byte boundary

    uint32_t entryCount;
    if (pos + 4 > static_cast<size_t>(st.st_size)) {
        munmap(p, st.st_size);
        return;
    }
    memcpy(&entryCount, base + pos, 4); pos += 4;

    // Bounds-check the entry array (each entry is 10 packed bytes).
    if (static_cast<uint64_t>(pos) + static_cast<uint64_t>(entryCount) * sizeof(Entry) > static_cast<uint64_t>(st.st_size)) {
        munmap(p, st.st_size);
        WTFLogAlways("[Driftstack-W2619] DOM-geom atlas truncated (entryCount=%u)", entryCount);
        return;
    }

    m_atlasData = base;
    m_atlasSize = st.st_size;
    m_entries = reinterpret_cast<const Entry*>(base + pos);
    m_entryCount = entryCount;
    WTF_ALLOW_UNSAFE_BUFFER_USAGE_END

    WTFLogAlways("[Driftstack-W2619] DOM-geom atlas loaded: %u entries from %s", m_entryCount, path.c_str());
}

bool DriftstackDOMGeomAtlas::lookup(uint32_t cp, uint8_t generic, uint8_t sizePx, uint16_t& outW, uint16_t& outH) const
{
    if (!m_entries || !m_entryCount)
        return false;

    // Binary search on (cp, generic, sizePx) — entries are sorted in that order.
    uint32_t lo = 0;
    uint32_t hi = m_entryCount;
    WTF_ALLOW_UNSAFE_BUFFER_USAGE_BEGIN
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        const auto& e = m_entries[mid];
        if (e.cp < cp) lo = mid + 1;
        else if (e.cp > cp) hi = mid;
        else if (e.generic < generic) lo = mid + 1;
        else if (e.generic > generic) hi = mid;
        else if (e.sizePx < sizePx) lo = mid + 1;
        else if (e.sizePx > sizePx) hi = mid;
        else {
            outW = e.w;
            outH = e.h;
            return true;
        }
    }
    WTF_ALLOW_UNSAFE_BUFFER_USAGE_END
    return false;
}

} // namespace WebCore

#endif // PLATFORM(DRIFTSTACK)
