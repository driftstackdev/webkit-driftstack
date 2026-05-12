/*
 * DriftstackTextGlyphAtlas — per-codepoint PNG atlas for non-emoji glyphs.
 * V-583.K-text Phase 3.
 */

#include "config.h"
#include "DriftstackTextGlyphAtlas.h"

#if PLATFORM(DRIFTSTACK)

#include <algorithm>
#include <fcntl.h>
#include <span>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
// NOTE: Do NOT include wtf/Logging.h — leaks LOG_CHANNEL_PREFIX=WTFLog into
// unified bundle (FontCacheCoreText neighbor in UnifiedSource345 expects Log
// prefix). WTFLogAlways is in wtf/Assertions.h.
#include <wtf/Assertions.h>
#include <wtf/NeverDestroyed.h>

namespace WebCore {

DriftstackTextGlyphAtlas& DriftstackTextGlyphAtlas::singleton()
{
    static NeverDestroyed<DriftstackTextGlyphAtlas> instance;
    return instance.get();
}

DriftstackTextGlyphAtlas::DriftstackTextGlyphAtlas()
{
    loadAtlas();
}

void DriftstackTextGlyphAtlas::loadAtlas()
{
    const char* atlasPath = std::getenv("DRIFTSTACK_TEXT_GLYPH_ATLAS_PATH");
    if (!atlasPath)
        atlasPath = "/Users/john/code/driftstack/reference/driftstack_text_glyph_atlas.bin";

    int fd = open(atlasPath, O_RDONLY);
    if (fd < 0) {
        WTFLogAlways("[Driftstack-V583K-text] atlas missing at %s", atlasPath);
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
        WTFLogAlways("[Driftstack-V583K-text] atlas mmap failed");
        return;
    }

    WTF_ALLOW_UNSAFE_BUFFER_USAGE_BEGIN
    auto* base = static_cast<const uint8_t*>(p);

    // Magic check
    if (base[0] != 'D' || base[1] != 'T' || base[2] != 'G' || base[3] != 'A') {
        munmap(p, st.st_size);
        WTFLogAlways("[Driftstack-V583K-text] atlas bad magic");
        return;
    }

    size_t pos = 4;
    uint16_t version;
    memcpy(&version, base + pos, 2); pos += 2;
    if (version != 1) {
        munmap(p, st.st_size);
        WTFLogAlways("[Driftstack-V583K-text] atlas unsupported version %u", version);
        return;
    }

    uint16_t fontCount;
    memcpy(&fontCount, base + pos, 2); pos += 2;
    // Skip font table
    for (uint16_t i = 0; i < fontCount; ++i) {
        pos += 2; // id
        uint8_t nameLen = base[pos]; pos += 1;
        pos += nameLen;
    }

    uint32_t glyphCount;
    memcpy(&glyphCount, base + pos, 4); pos += 4;

    m_index = reinterpret_cast<const DriftstackTextGlyphEntry*>(base + pos);
    m_indexCount = glyphCount;
    pos += sizeof(DriftstackTextGlyphEntry) * glyphCount;

    m_pngBlob = base + pos;
    WTF_ALLOW_UNSAFE_BUFFER_USAGE_END

    m_atlasData = base;
    m_atlasSize = st.st_size;

    WTFLogAlways("[Driftstack-V583K-text] atlas loaded: %u entries, %.1f MB",
        glyphCount, static_cast<double>(st.st_size) / (1024 * 1024));
}

const DriftstackTextGlyphEntry* DriftstackTextGlyphAtlas::lookupEntry(uint16_t fontId, uint16_t ptSize, uint32_t codepoint) const
{
    if (!m_index || !m_indexCount)
        return nullptr;

    // Binary search on (font_id, ptSize, cp) sorted index.
    uint32_t lo = 0;
    uint32_t hi = m_indexCount;
    WTF_ALLOW_UNSAFE_BUFFER_USAGE_BEGIN
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        const auto& e = m_index[mid];
        // Compare (fontId, ptSize, codepoint) lexicographically
        if (e.fontId < fontId) lo = mid + 1;
        else if (e.fontId > fontId) hi = mid;
        else if (e.ptSize < ptSize) lo = mid + 1;
        else if (e.ptSize > ptSize) hi = mid;
        else if (e.codepoint < codepoint) lo = mid + 1;
        else if (e.codepoint > codepoint) hi = mid;
        else return &m_index[mid];
    }
    WTF_ALLOW_UNSAFE_BUFFER_USAGE_END
    return nullptr;
}

std::span<const uint8_t> DriftstackTextGlyphAtlas::lookup(uint16_t fontId, uint16_t ptSize, uint32_t codepoint) const
{
    const auto* entry = lookupEntry(fontId, ptSize, codepoint);
    if (!entry)
        return { };
    WTF_ALLOW_UNSAFE_BUFFER_USAGE_BEGIN
    return std::span<const uint8_t>(m_pngBlob + entry->pngOffset, entry->pngSize);
    WTF_ALLOW_UNSAFE_BUFFER_USAGE_END
}

std::vector<uint32_t> DriftstackTextGlyphAtlas::allCodepoints() const
{
    std::vector<uint32_t> cps;
    if (!m_index || !m_indexCount)
        return cps;

    cps.reserve(m_indexCount);
    WTF_ALLOW_UNSAFE_BUFFER_USAGE_BEGIN
    uint32_t lastCp = UINT32_MAX;
    for (uint32_t i = 0; i < m_indexCount; ++i) {
        uint32_t cp = m_index[i].codepoint;
        if (cp != lastCp) {
            cps.push_back(cp);
            lastCp = cp;
        }
    }
    WTF_ALLOW_UNSAFE_BUFFER_USAGE_END

    // Dedup (index sorted by font_id+ptSize+cp, so same cp may appear interleaved).
    std::sort(cps.begin(), cps.end());
    cps.erase(std::unique(cps.begin(), cps.end()), cps.end());
    return cps;
}

uint16_t DriftstackTextGlyphAtlas::fontIdForFamily(const String& familyName)
{
    // Mirrors V-149 ASCII font enum + adds Apple Color Emoji as 13.
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
    if (familyName == "monospace"_s || familyName == "-webkit-monospace"_s) return 12;
    if (familyName == "Apple Color Emoji"_s) return 13;

    // V-631: Mac script-fallback families → atlas fontId=0. macOS resolves
    // CJK / Arabic / Devanagari requests through its own fallback chain
    // (Hiragino Sans GB / Songti SC / Geeza Pro / Devanagari MT / etc.).
    // iPhone resolves the same script requests through PingFang SC /
    // Geeza Pro / Devanagari Sangam MN; the iPhone-captured PNGs in our
    // atlas under fontId=0 already encode those iOS-rasterized glyphs for
    // every script. By aliasing every Mac script-fallback family back to
    // fontId=0 we let the dispatch substitute Mac's CT-rendered fallback
    // pixels with iPhone's fallback pixels — bit-identical regardless of
    // which user-specified family triggered the script fallback.
    // Without this aliasing, V-405 text seeds (which use
    // rng.unicodeString over ['ASCII','CJK','Arabic','Devanagari','Emoji'])
    // exit fontIdForFamily with UINT16_MAX for every non-Latin glyph and
    // the dispatch falls through to vanilla Mac CT — text 0% pass rate.
    //
    // V-631.B: Mac script-fallback families empirically observed via fork
    // log on V-405 text seeds. macOS resolves CSS script-tagged glyph
    // requests through a private set of `.Apple{Script}Font` family names,
    // plus the public Hiragino / Songti / Geeza / Kohinoor / Devanagari MT
    // families. Map them all to atlas fontId=0 so iPhone-captured glyphs
    // (PingFang SC / Geeza Pro / Devanagari Sangam MN under iOS
    // -apple-system) substitute regardless of Mac's resolved family.
    //
    // CJK families on macOS:
    //   .AppleSimplifiedChineseFont — Simplified Chinese
    //   .AppleTraditionalChineseFont — Traditional Chinese
    //   .AppleJapaneseFont — Japanese
    //   .AppleKoreanFont — Korean
    //   .AppleHongKongChineseFont / .AppleMacaoChineseFont — regional CJK
    //   Hiragino Sans / Sans GB / Mincho ProN / Kaku Gothic Pro — public CJK
    //   Songti SC / STSong / STHeiti / PingFang SC|TC|HK — alternate CJK
    if (familyName == ".AppleSimplifiedChineseFont"_s
        || familyName == ".AppleTraditionalChineseFont"_s
        || familyName == ".AppleJapaneseFont"_s
        || familyName == ".AppleKoreanFont"_s
        || familyName == ".AppleHongKongChineseFont"_s
        || familyName == ".AppleMacaoChineseFont"_s
        || familyName == "Hiragino Sans GB"_s
        || familyName == "Hiragino Sans"_s
        || familyName == "Hiragino Kaku Gothic Pro"_s
        || familyName == "Hiragino Kaku Gothic ProN"_s
        || familyName == "Hiragino Mincho ProN"_s
        || familyName == "Hiragino Sans GB W3"_s
        || familyName == "Hiragino Sans GB W6"_s
        || familyName == "Songti SC"_s
        || familyName == "STSong"_s
        || familyName == "STHeiti"_s
        || familyName == "STHeitiSC-Medium"_s
        || familyName == "STHeitiTC-Medium"_s
        || familyName == "PingFang HK"_s
        || familyName == "PingFang SC"_s
        || familyName == "PingFang TC"_s)
        return 0;

    // Arabic family on macOS:
    //   .SF Arabic (system) / Geeza Pro / .AppleUrduFont / .DecoType Nastaleeq Urdu UI
    if (familyName == "Geeza Pro"_s
        || familyName == "GeezaPro"_s
        || familyName == ".SF Arabic"_s
        || familyName == ".AppleUrduFont"_s
        || familyName == ".DecoType Nastaleeq Urdu UI"_s)
        return 0;

    // Devanagari + Indic on macOS:
    //   .SF Devanagari / Kohinoor Devanagari / Devanagari MT / .AppleIndicFont
    //   / Devanagari Sangam MN
    if (familyName == "Devanagari MT"_s
        || familyName == "DevanagariMT"_s
        || familyName == "Devanagari Sangam MN"_s
        || familyName == "Kohinoor Devanagari"_s
        || familyName == ".SF Devanagari"_s
        || familyName == ".AppleIndicFont"_s)
        return 0;

    // Other script families observed empirically (Hebrew / Armenian /
    // Georgian / Apple Symbols Fallback) — currently no atlas coverage
    // for these scripts but route to fontId=0 so future expansion
    // captures get used immediately.
    if (familyName == ".SF Hebrew"_s
        || familyName == ".SF Armenian"_s
        || familyName == ".SF Georgian"_s
        || familyName == ".Apple Symbols Fallback"_s
        || familyName == ".AppleSystemFallback"_s
        || familyName == "Apple Symbols"_s)
        return 0;

    return UINT16_MAX;
}

} // namespace WebCore

#endif // PLATFORM(DRIFTSTACK)
