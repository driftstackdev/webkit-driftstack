/*
 * V-790.L per-glyph exact-substitution atlas implementation.
 *
 * mmap + binary search over the DSPGA1 atlas binary built by
 * captures/v3/v790l-per-glyph-atlas-builder.py.
 */
#include "config.h"
#include "DriftstackPerGlyphAtlas.h"
#include "AffineTransform.h"
#include "GraphicsContext.h"
#include "PixelBufferConversion.h"

#if PLATFORM(DRIFTSTACK)

#include <algorithm>
#include <array>
#include <atomic>
#include <cmath>
#include <cstdlib>
#include <cstring>
#include <limits>
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
constexpr size_t kCompositorHeaderSize = 16;
constexpr size_t kCompositorAlphaSize = 256;
constexpr size_t kCompositorChannelSize = 256 * 256;
constexpr size_t kCompositorSize = kCompositorHeaderSize + kCompositorAlphaSize + kCompositorChannelSize;
constexpr const char kCompositorMagic[8] = { 'D', 'S', 'G', 'C', 'M', 'P', '1', '\0' };
constexpr size_t kDestinationHeaderSize = 16;
constexpr size_t kDestinationOpaqueSize = 3 * 256 * 256;
constexpr size_t kDestinationTextSize = 256 * 256 * 4;
constexpr size_t kDestinationSize = kDestinationHeaderSize + kDestinationOpaqueSize + kDestinationTextSize;
constexpr const char kDestinationMagic[8] = { 'D', 'S', 'D', 'C', 'R', '1', '\0', '\0' };

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

uint8_t driftstackTwelfthPositionClass(double coordinate)
{
    double fraction = coordinate - std::floor(coordinate);
    float roundedCoordinate = static_cast<float>(coordinate);
    double floatUlp = static_cast<double>(std::nextafter(
        roundedCoordinate, std::numeric_limits<float>::infinity())) - roundedCoordinate;
    // Keep the tolerance below half a class even for very large, off-canvas
    // coordinates where a float ulp can exceed the entire fractional range.
    double boundaryTolerance = std::min(floatUlp * 12.0, 0.5);
    double positionClass = std::floor(fraction * 12.0 + boundaryTolerance);
    return static_cast<uint8_t>(std::min(positionClass, 11.0));
}

bool driftstackPerGlyphAtlasSupportsTransform(const AffineTransform& transform)
{
    return transform.isIdentityOrTranslationOrFlipped();
}

std::optional<uint8_t> driftstackPremultipliedChannelForVisible(uint8_t visible, uint8_t alpha)
{
    struct PreimageTable {
        std::array<uint8_t, 256 * 256> value { };
        std::array<uint8_t, 256 * 256> present { };
    };
    static const PreimageTable table = [] {
        PreimageTable result;
        Vector<uint8_t> premultipliedCandidates(256 * 256 * 4);
        Vector<uint8_t> visibleCandidates(256 * 256 * 4);
        for (size_t candidateAlpha = 0; candidateAlpha < 256; ++candidateAlpha) {
            for (size_t channel = 0; channel < 256; ++channel) {
                size_t offset = (candidateAlpha * 256 + channel) * 4;
                premultipliedCandidates[offset] = static_cast<uint8_t>(channel);
                premultipliedCandidates[offset + 1] = static_cast<uint8_t>(channel);
                premultipliedCandidates[offset + 2] = static_cast<uint8_t>(channel);
                premultipliedCandidates[offset + 3] = static_cast<uint8_t>(candidateAlpha);
            }
        }
        auto srgb = DestinationColorSpace::SRGB();
        convertImagePixels(
            { { AlphaPremultiplication::Premultiplied, PixelFormat::RGBA8, srgb },
                1024, premultipliedCandidates.span() },
            { { AlphaPremultiplication::Unpremultiplied, PixelFormat::RGBA8, srgb },
                1024, visibleCandidates.mutableSpan() },
            { 256, 256 });
        for (size_t candidateAlpha = 0; candidateAlpha < 256; ++candidateAlpha) {
            for (size_t premultiplied = 0; premultiplied <= candidateAlpha; ++premultiplied) {
                size_t candidateOffset = (candidateAlpha * 256 + premultiplied) * 4;
                uint8_t candidateVisible = visibleCandidates[candidateOffset];
                size_t tableOffset = candidateAlpha * 256 + candidateVisible;
                if (!result.present[tableOffset]) {
                    result.value[tableOffset] = static_cast<uint8_t>(premultiplied);
                    result.present[tableOffset] = 1;
                }
            }
        }
        return result;
    }();
    size_t offset = static_cast<size_t>(alpha) * 256 + visible;
    if (!table.present[offset])
        return std::nullopt;
    return table.value[offset];
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

    off_t baseExpected = static_cast<off_t>(kHeaderSize) + static_cast<off_t>(count) * static_cast<off_t>(kEntrySize);
    off_t withCompositorExpected = baseExpected + static_cast<off_t>(kCompositorSize);
    off_t withDestinationExpected = withCompositorExpected + static_cast<off_t>(kDestinationSize);
    bool hasDestination = st.st_size == withDestinationExpected;
    bool hasCompositor = st.st_size == withCompositorExpected || hasDestination;
    if (st.st_size != baseExpected && !hasCompositor) {
        WTFLogAlways(
            "[V-790.L] per-glyph atlas size mismatch: got %lld "
            "expected %lld or %lld or %lld (count=%u) — Layer-A2 disabled",
            static_cast<long long>(st.st_size),
            static_cast<long long>(baseExpected),
            static_cast<long long>(withCompositorExpected),
            static_cast<long long>(withDestinationExpected), count);
        ::munmap(base, st.st_size);
        return false;
    }

    const uint8_t* compositor = hasCompositor ? bytes + baseExpected : nullptr;
    if (compositor) {
        uint32_t compositorVersion = leU32(compositor + 8);
        uint16_t capturedAlpha = leU16(compositor + 12);
        uint16_t reserved = leU16(compositor + 14);
        if (!equalSpans(unsafeMakeSpan(compositor, sizeof(kCompositorMagic)), asByteSpan(kCompositorMagic))
            || compositorVersion != 1 || capturedAlpha > 255 || reserved) {
            WTFLogAlways("[V-790.L] per-glyph compositor trailer invalid: version=%u alpha=%u reserved=%u — Layer-A2 disabled",
                compositorVersion, capturedAlpha, reserved);
            ::munmap(base, st.st_size);
            return false;
        }
        m_compositorFillAlphaByte = static_cast<uint8_t>(capturedAlpha);
        m_compositorAlpha = compositor + kCompositorHeaderSize;
        m_compositorChannels = m_compositorAlpha + kCompositorAlphaSize;
    }

    const uint8_t* destination = hasDestination ? bytes + withCompositorExpected : nullptr;
    if (destination) {
        uint32_t destinationVersion = leU32(destination + 8);
        uint16_t capturedAlpha = leU16(destination + 12);
        uint16_t reserved = leU16(destination + 14);
        if (!equalSpans(unsafeMakeSpan(destination, sizeof(kDestinationMagic)), asByteSpan(kDestinationMagic))
            || destinationVersion != 1 || capturedAlpha != m_compositorFillAlphaByte || reserved) {
            WTFLogAlways("[V-790.L] glyph-destination trailer invalid: version=%u alpha=%u reserved=%u — Layer-A2 disabled",
                destinationVersion, capturedAlpha, reserved);
            ::munmap(base, st.st_size);
            return false;
        }
        m_destinationOpaqueChannels = destination + kDestinationHeaderSize;
        m_destinationTextBackdrop = m_destinationOpaqueChannels + kDestinationOpaqueSize;
    }

    m_mapBase = bytes;
    m_mapSize = static_cast<size_t>(st.st_size);
    m_entryCount = count;
    m_entriesBase = bytes + kHeaderSize;
    m_loaded = true;

    WTFLogAlways("[V-790.L] per-glyph atlas loaded: %u entries from %s",
                 count, resolved);
    if (compositor)
        WTFLogAlways("[V-790.L] glyph-compositor trailer loaded: alpha=%u", m_compositorFillAlphaByte);
    if (destination)
        WTFLogAlways("[V-790.L] glyph-destination trailer loaded: alpha=%u", m_compositorFillAlphaByte);
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

std::optional<DriftstackGlyphCompositorPixel> DriftstackPerGlyphAtlas::compositorPixel(
    uint8_t fillAlphaByte, uint8_t red, uint8_t green, uint8_t blue, uint8_t coverage) const
{
    if (!m_loaded || !m_compositorAlpha || !m_compositorChannels
        || fillAlphaByte != m_compositorFillAlphaByte)
        return std::nullopt;
    auto channel = [&](uint8_t value) -> uint8_t {
        return m_compositorChannels[static_cast<size_t>(value) * 256 + coverage];
    };
    uint8_t alpha = m_compositorAlpha[coverage];
    return DriftstackGlyphCompositorPixel {
        channel(red), channel(green), channel(blue), alpha
    };
}

std::optional<DriftstackGlyphCompositorPixel> DriftstackPerGlyphAtlas::destinationPixel(
    uint8_t fillAlphaByte, uint8_t sourceRed, uint8_t sourceGreen,
    uint8_t sourceBlue, uint8_t coverage, uint8_t destinationRed,
    uint8_t destinationGreen, uint8_t destinationBlue,
    uint8_t destinationAlpha) const
{
    if (!m_loaded || !m_destinationOpaqueChannels || !m_destinationTextBackdrop
        || fillAlphaByte != m_compositorFillAlphaByte
        || sourceRed != 102 || sourceGreen != 204 || sourceBlue)
        return std::nullopt;
    if (destinationAlpha == 255) {
        auto channel = [&](size_t component, uint8_t value) -> uint8_t {
            return m_destinationOpaqueChannels[component * 256 * 256
                + static_cast<size_t>(value) * 256 + coverage];
        };
        return DriftstackGlyphCompositorPixel {
            channel(0, destinationRed), channel(1, destinationGreen),
            channel(2, destinationBlue), 255
        };
    }
    // RGB is semantically irrelevant at alpha zero, and the native overlap
    // validation proves that row against transparent text-edge destinations.
    if (destinationAlpha && (destinationRed || destinationGreen != 102 || destinationBlue != 153))
        return std::nullopt;
    size_t offset = (static_cast<size_t>(destinationAlpha) * 256 + coverage) * 4;
    return DriftstackGlyphCompositorPixel {
        m_destinationTextBackdrop[offset], m_destinationTextBackdrop[offset + 1],
        m_destinationTextBackdrop[offset + 2], m_destinationTextBackdrop[offset + 3]
    };
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

std::optional<DriftstackGlyphCompositorPixel> driftstackGlyphCompositorPixel(
    uint8_t fillAlphaByte, uint8_t red, uint8_t green, uint8_t blue, uint8_t coverage)
{
    return DriftstackPerGlyphAtlas::singleton().compositorPixel(
        fillAlphaByte, red, green, blue, coverage);
}

std::optional<DriftstackGlyphCompositorPixel> driftstackGlyphDestinationPixel(
    uint8_t fillAlphaByte, uint8_t sourceRed, uint8_t sourceGreen,
    uint8_t sourceBlue, uint8_t coverage, uint8_t destinationRed,
    uint8_t destinationGreen, uint8_t destinationBlue,
    uint8_t destinationAlpha)
{
    return DriftstackPerGlyphAtlas::singleton().destinationPixel(
        fillAlphaByte, sourceRed, sourceGreen, sourceBlue, coverage,
        destinationRed, destinationGreen,
        destinationBlue, destinationAlpha);
}

std::optional<uint32_t> driftstackGlyphDestinationPixelPacked(
    uint8_t fillAlphaByte, uint8_t sourceRed, uint8_t sourceGreen,
    uint8_t sourceBlue, uint8_t coverage, uint8_t destinationRed,
    uint8_t destinationGreen, uint8_t destinationBlue,
    uint8_t destinationAlpha)
{
    auto pixel = driftstackGlyphDestinationPixel(
        fillAlphaByte, sourceRed, sourceGreen, sourceBlue, coverage,
        destinationRed, destinationGreen, destinationBlue, destinationAlpha);
    if (!pixel)
        return std::nullopt;
    return static_cast<uint32_t>(pixel->red)
        | (static_cast<uint32_t>(pixel->green) << 8)
        | (static_cast<uint32_t>(pixel->blue) << 16)
        | (static_cast<uint32_t>(pixel->alpha) << 24);
}

} // namespace WebCore

#endif // PLATFORM(DRIFTSTACK)
