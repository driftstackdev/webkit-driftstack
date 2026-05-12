/*
 * DriftstackAdvanceAtlas — per-codepoint glyph advance override atlas.
 * V-689 (Wave 25).
 */

#include "config.h"
#include "DriftstackAdvanceAtlas.h"

#if PLATFORM(DRIFTSTACK)

#include <cerrno>
#include <cstdlib>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <wtf/Logging.h>
#include <wtf/NeverDestroyed.h>

namespace WebCore {

DriftstackAdvanceAtlas& DriftstackAdvanceAtlas::singleton()
{
    static NeverDestroyed<DriftstackAdvanceAtlas> instance;
    return instance.get();
}

DriftstackAdvanceAtlas::DriftstackAdvanceAtlas()
{
    loadAtlas();
}

void DriftstackAdvanceAtlas::loadAtlas()
{
    const char* atlasPath = std::getenv("DRIFTSTACK_ADVANCE_ATLAS_PATH");
    if (!atlasPath)
        atlasPath = "/Users/john/code/driftstack/reference/driftstack_advance_atlas.bin";

    int fd = open(atlasPath, O_RDONLY);
    if (fd < 0) {
        WTFLogAlways("[Driftstack-V689] advance atlas open failed at %s errno=%d pid=%d prog=%s",
            atlasPath, errno, (int)getpid(), getprogname());
        return;
    }

    struct stat st;
    if (fstat(fd, &st) < 0) {
        close(fd);
        return;
    }

    void* p = mmap(nullptr, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (p == MAP_FAILED) {
        WTFLogAlways("[Driftstack-V689] advance atlas mmap failed");
        return;
    }

    WTF_ALLOW_UNSAFE_BUFFER_USAGE_BEGIN
    auto* base = static_cast<const uint8_t*>(p);

    // Magic "DAAA"
    if (st.st_size < 16 || base[0] != 'D' || base[1] != 'A' || base[2] != 'A' || base[3] != 'A') {
        munmap(p, st.st_size);
        WTFLogAlways("[Driftstack-V689] advance atlas bad magic");
        return;
    }

    size_t pos = 4;
    uint16_t version;
    memcpy(&version, base + pos, 2); pos += 2;
    uint16_t reserved;
    memcpy(&reserved, base + pos, 2); pos += 2;
    (void)reserved;
    if (version != 1) {
        munmap(p, st.st_size);
        WTFLogAlways("[Driftstack-V689] advance atlas unsupported version %u", version);
        return;
    }

    uint32_t fontCount;
    memcpy(&fontCount, base + pos, 4); pos += 4;
    uint32_t entryCount;
    memcpy(&entryCount, base + pos, 4); pos += 4;

    // Skip font table: each entry is { id: uint16, name_len: uint16, name (padded to 4) }
    for (uint32_t i = 0; i < fontCount; ++i) {
        pos += 2; // id
        uint16_t nameLen;
        memcpy(&nameLen, base + pos, 2); pos += 2;
        size_t padded = (nameLen + 3) & ~3u;
        pos += padded;
    }

    if (pos + static_cast<size_t>(entryCount) * sizeof(DriftstackAdvanceEntry) > static_cast<size_t>(st.st_size)) {
        munmap(p, st.st_size);
        WTFLogAlways("[Driftstack-V689] advance atlas truncated (pos=%zu+entries=%u exceeds %zu)",
            pos, entryCount, static_cast<size_t>(st.st_size));
        return;
    }

    m_entries = reinterpret_cast<const DriftstackAdvanceEntry*>(base + pos);
    m_entryCount = entryCount;
    WTF_ALLOW_UNSAFE_BUFFER_USAGE_END

    m_atlasData = base;
    m_atlasSize = st.st_size;

    WTFLogAlways("[Driftstack-V689] advance atlas loaded: %u entries, %.1f MB",
        entryCount, static_cast<double>(st.st_size) / (1024 * 1024));
}

float DriftstackAdvanceAtlas::lookup(uint16_t fontId, uint16_t sizePx, uint32_t codepoint) const
{
    if (!m_entries || !m_entryCount)
        return -1.0f;

    // Binary search on (fontId, sizePx, codepoint) sorted index.
    uint32_t lo = 0;
    uint32_t hi = m_entryCount;
    WTF_ALLOW_UNSAFE_BUFFER_USAGE_BEGIN
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        const auto& e = m_entries[mid];
        if (e.fontId < fontId) lo = mid + 1;
        else if (e.fontId > fontId) hi = mid;
        else if (e.sizePx < sizePx) lo = mid + 1;
        else if (e.sizePx > sizePx) hi = mid;
        else if (e.codepoint < codepoint) lo = mid + 1;
        else if (e.codepoint > codepoint) hi = mid;
        else return e.widthPx;
    }
    WTF_ALLOW_UNSAFE_BUFFER_USAGE_END
    return -1.0f;
}

const DriftstackAdvanceEntry* DriftstackAdvanceAtlas::entriesForFontSize(uint16_t fontId, uint16_t sizePx, uint32_t* outCount) const
{
    if (outCount)
        *outCount = 0;
    if (!m_entries || !m_entryCount)
        return nullptr;

    const DriftstackAdvanceEntry* result = nullptr;
    uint32_t resultCount = 0;
    WTF_ALLOW_UNSAFE_BUFFER_USAGE_BEGIN
    // Binary-search for first entry with (fontId, sizePx, cp=0).
    uint32_t lo = 0;
    uint32_t hi = m_entryCount;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        const auto& e = m_entries[mid];
        if (e.fontId < fontId) lo = mid + 1;
        else if (e.fontId > fontId) hi = mid;
        else if (e.sizePx < sizePx) lo = mid + 1;
        else hi = mid;
    }
    if (lo < m_entryCount && m_entries[lo].fontId == fontId && m_entries[lo].sizePx == sizePx) {
        // Walk forward to count contiguous entries with same (fontId, sizePx).
        uint32_t end = lo;
        while (end < m_entryCount
            && m_entries[end].fontId == fontId
            && m_entries[end].sizePx == sizePx)
            ++end;
        resultCount = end - lo;
        result = &m_entries[lo];
    }
    WTF_ALLOW_UNSAFE_BUFFER_USAGE_END

    if (result && outCount)
        *outCount = resultCount;
    return result;
}

uint16_t DriftstackAdvanceAtlas::fontIdForFamily(const String& familyName)
{
    // Matches V-149/V-688 font enum + .AppleSystemUIFont alias.
    if (familyName == "-apple-system"_s || familyName == ".AppleSystemUIFont"_s) return 0;
    if (familyName == "Arial"_s) return 1;
    if (familyName == "Courier"_s || familyName == "Courier New"_s) return 2;
    if (familyName == "Georgia"_s) return 3;
    if (familyName == "Helvetica"_s) return 4;
    if (familyName == "Tahoma"_s) return 5;
    if (familyName == "Times New Roman"_s) return 6;
    if (familyName == "Trebuchet MS"_s) return 7;
    if (familyName == "Verdana"_s) return 8;
    if (familyName == "sans-serif"_s || familyName == "-webkit-sans-serif"_s) return 9;
    if (familyName == "serif"_s || familyName == "-webkit-serif"_s || familyName == "Times"_s || familyName == "Times Roman"_s) return 10;
    if (familyName == "system-ui"_s || familyName == "-webkit-system-font"_s) return 11;
    if (familyName == "monospace"_s || familyName == "-webkit-monospace"_s || familyName == "Menlo"_s) return 12;
    return UINT16_MAX;
}

} // namespace WebCore

#endif // PLATFORM(DRIFTSTACK)
