/*
 * DriftstackFontCanonicalAtlas.mm — implementation.
 */

#include "config.h"
#include "DriftstackFontCanonicalAtlas.h"

#if PLATFORM(DRIFTSTACK)

#import <CommonCrypto/CommonDigest.h>
#import <bit>
#import <fcntl.h>
#import <stdlib.h>
#import <sys/mman.h>
#import <sys/stat.h>
#import <unistd.h>
#import <wtf/Logging.h>
#import <wtf/NeverDestroyed.h>
#import <wtf/StdLibExtras.h>
#import <wtf/text/CString.h>
#import <wtf/text/StringBuilder.h>

namespace WebCore {

DriftstackFontCanonicalAtlas::DriftstackFontCanonicalAtlas() = default;

static constexpr const char* kDefaultPath = "/Users/john/code/driftstack/reference/driftstack_audio_atlas/v184-font-canonical-v1.bin";
static constexpr size_t kIndexEntryStride = 48;
static constexpr size_t kHashBytes = 16;
static constexpr size_t kHeaderSize = 32;

DriftstackFontCanonicalAtlas& DriftstackFontCanonicalAtlas::singleton()
{
    static NeverDestroyed<DriftstackFontCanonicalAtlas> instance;
    if (!instance.get().m_loaded)
        instance.get().loadOnce();
    return instance.get();
}

DriftstackFontCanonicalAtlas::~DriftstackFontCanonicalAtlas()
{
    if (m_mapped && m_mappedSize)
        ::munmap(m_mapped, m_mappedSize);
}

static inline uint16_t readU16(std::span<const uint8_t> s, size_t off)
{
    return uint16_t(s[off]) | (uint16_t(s[off + 1]) << 8);
}

static inline uint32_t readU32(std::span<const uint8_t> s, size_t off)
{
    return uint32_t(s[off])
         | (uint32_t(s[off + 1]) << 8)
         | (uint32_t(s[off + 2]) << 16)
         | (uint32_t(s[off + 3]) << 24);
}

static inline float readF32(std::span<const uint8_t> s, size_t off)
{
    uint32_t bits = readU32(s, off);
    return std::bit_cast<float>(bits);
}

void DriftstackFontCanonicalAtlas::loadOnce()
{
    if (m_loaded)
        return;
    m_loaded = true;

    const char* path = getenv("DRIFTSTACK_FONT_CANONICAL_PATH");
    if (!path || !*path)
        path = kDefaultPath;

    int fd = ::open(path, O_RDONLY);
    if (fd < 0) {
        WTFLogAlways("[Driftstack-V184-Canonical] open failed for %s (errno=%d) — disabled", path, errno);
        return;
    }

    struct stat st;
    if (::fstat(fd, &st) != 0 || st.st_size < (off_t)kHeaderSize) {
        ::close(fd);
        return;
    }

    void* base = ::mmap(nullptr, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    ::close(fd);
    if (base == MAP_FAILED)
        return;

    auto bytesSpan = unsafeMakeSpan(static_cast<const uint8_t*>(base), static_cast<size_t>(st.st_size));

    // Magic check 'DSCM'
    if (bytesSpan[0] != 'D' || bytesSpan[1] != 'S' || bytesSpan[2] != 'C' || bytesSpan[3] != 'M') {
        WTFLogAlways("[Driftstack-V184-Canonical] bad magic at %s", path);
        ::munmap(base, st.st_size);
        return;
    }
    uint16_t version = readU16(bytesSpan, 4);
    if (version != 1) {
        WTFLogAlways("[Driftstack-V184-Canonical] unsupported version=%u", version);
        ::munmap(base, st.st_size);
        return;
    }
    uint32_t numEntries = readU32(bytesSpan, 8);
    uint32_t indexOff = readU32(bytesSpan, 12);
    // dataOff = readU32(bytesSpan, 16); — no data section in DSCFM v1.

    if (indexOff != kHeaderSize) {
        ::munmap(base, st.st_size);
        return;
    }
    size_t indexBytes = static_cast<size_t>(numEntries) * kIndexEntryStride;
    if (kHeaderSize + indexBytes > bytesSpan.size()) {
        ::munmap(base, st.st_size);
        return;
    }

    m_mapped = base;
    m_mappedSize = static_cast<size_t>(st.st_size);
    m_numEntries = numEntries;
    m_indexSpan = bytesSpan.subspan(indexOff, indexBytes);

    WTFLogAlways("[Driftstack-V184-Canonical] loaded %u entries from %s (%zu bytes)",
        numEntries, path, m_mappedSize);
}

std::optional<DriftstackFontCanonicalEntry> DriftstackFontCanonicalAtlas::lookup(
    const String& family, const String& weight, const String& style,
    unsigned size, const String& text)
{
    if (!m_loaded || !m_numEntries)
        return std::nullopt;

    // Build canonical key string: "family|weight|style|size|text"
    // Matches build-v184-font-extension.py format.
    StringBuilder keyBuilder;
    keyBuilder.append(family);
    keyBuilder.append('|');
    keyBuilder.append(weight);
    keyBuilder.append('|');
    keyBuilder.append(style);
    keyBuilder.append('|');
    keyBuilder.append(String::number(size));
    keyBuilder.append('|');
    keyBuilder.append(text);
    String keyString = keyBuilder.toString();
    CString keyUtf8 = keyString.utf8();

    std::array<uint8_t, CC_SHA256_DIGEST_LENGTH> digest;
    CC_SHA256(keyUtf8.data(), static_cast<CC_LONG>(keyUtf8.length()), digest.data());
    auto digestSpan = std::span<const uint8_t> { digest }.first(kHashBytes);

    // Binary search over sorted index.
    size_t lo = 0, hi = m_numEntries;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        auto entrySpan = m_indexSpan.subspan(mid * kIndexEntryStride, kIndexEntryStride);
        auto keySpan = entrySpan.first(kHashBytes);
        int cmp = 0;
        for (size_t i = 0; i < kHashBytes; ++i) {
            if (keySpan[i] != digestSpan[i]) {
                cmp = (keySpan[i] < digestSpan[i]) ? -1 : 1;
                break;
            }
        }
        if (cmp < 0) {
            lo = mid + 1;
        } else if (cmp > 0) {
            hi = mid;
        } else {
            // Hit: read 7 f32 fields starting at offset 16 within entry.
            DriftstackFontCanonicalEntry entry;
            entry.mtWidth = readF32(entrySpan, kHashBytes + 0);
            entry.mtActualBoundingBoxAscent = readF32(entrySpan, kHashBytes + 4);
            entry.mtActualBoundingBoxDescent = readF32(entrySpan, kHashBytes + 8);
            entry.mtFontBoundingBoxAscent = readF32(entrySpan, kHashBytes + 12);
            entry.mtFontBoundingBoxDescent = readF32(entrySpan, kHashBytes + 16);
            entry.spanW = readF32(entrySpan, kHashBytes + 20);
            entry.spanH = readF32(entrySpan, kHashBytes + 24);
            return entry;
        }
    }
    return std::nullopt;
}

// Wave 29-284: cross-directory wrapper for Element::getBoundingClientRect
// (declared as extern free function in dom/Element.cpp). Returns span_w/h
// for V-405 Font full-surface closure.
extern bool driftstackLookupFontCanonicalSpan(const String&, const String&, const String&, unsigned, const String&, float&, float&);
bool driftstackLookupFontCanonicalSpan(const String& family, const String& weight,
    const String& style, unsigned size, const String& text,
    float& outSpanW, float& outSpanH)
{
    auto entry = DriftstackFontCanonicalAtlas::singleton().lookup(family, weight, style, size, text);
    if (!entry)
        return false;
    outSpanW = entry->spanW;
    outSpanH = entry->spanH;
    return true;
}

} // namespace WebCore

#endif // PLATFORM(DRIFTSTACK)
