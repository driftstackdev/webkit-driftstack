/*
 * DriftstackCanvasFingerprint10xRGBA.mm — see header.
 */

#include "config.h"
#include "DriftstackCanvasFingerprint10xRGBA.h"

#if PLATFORM(DRIFTSTACK)

#include "DriftstackCanvasFingerprint10xOverride.h"

#import <CoreGraphics/CoreGraphics.h>
#import <ImageIO/ImageIO.h>
#include <array>
#include <cstdlib>
#include <wtf/FileSystem.h>
#include <wtf/HashMap.h>
#include <wtf/Lock.h>
#include <wtf/NeverDestroyed.h>
#include <wtf/RefCounted.h>
#include <wtf/RefPtr.h>
#include <wtf/RetainPtr.h>
#include <wtf/StdLibExtras.h>
#include <wtf/Vector.h>
#include <wtf/text/Base64.h>
#include <wtf/text/StringView.h>
#include <wtf/text/WTFString.h>

namespace WebCore {
namespace Driftstack {

namespace {

class DecodedRGBABuffer : public RefCounted<DecodedRGBABuffer> {
public:
    static Ref<DecodedRGBABuffer> create() { return adoptRef(*new DecodedRGBABuffer); }
    int width { 0 };
    int height { 0 };
    Vector<uint8_t> rgba; // unpremultiplied RGBA8, w*h*4 bytes
};

Lock& cacheLock()
{
    static NeverDestroyed<Lock> lock;
    return lock.get();
}

HashMap<const char*, RefPtr<DecodedRGBABuffer>>& cache()
{
    static NeverDestroyed<HashMap<const char*, RefPtr<DecodedRGBABuffer>>> map;
    return map.get();
}

// P1 (canvas-op-timing-audit): memo for the V-510 op-seq getImageData serve path
// (getV510AtlasRGBAForOpSeq). The sibling cache() is keyed on a stable static
// const char* (from lookupCanvasFp10xCanonicalWithText); the V-510 dataURL comes
// from a String (v510AtlasLookupPublic) whose utf8().data() pointer is NOT stable
// across calls, so it needs its OWN String-keyed memo. Keyed on opSeqSha (1:1 with
// the served dataURL). Shares cacheLock(). Same decodeOnce output, cached.
HashMap<String, RefPtr<DecodedRGBABuffer>>& v510OpSeqCache()
{
    static NeverDestroyed<HashMap<String, RefPtr<DecodedRGBABuffer>>> map;
    return map.get();
}

class RawOpSequenceAtlas {
public:
    bool lookup(const String&, int width, int height, Vector<uint8_t>&);

private:
    bool load();

    bool m_loadAttempted { false };
    bool m_valid { false };
    uint32_t m_count { 0 };
    size_t m_dataOffset { 0 };
    Vector<uint8_t> m_bytes;
};

RawOpSequenceAtlas& rawOpSequenceAtlas()
{
    static NeverDestroyed<RawOpSequenceAtlas> atlas;
    return atlas.get();
}

constexpr size_t rawAtlasHeaderSize = 24;
constexpr size_t rawAtlasIndexEntrySize = 28;
constexpr std::array<uint8_t, 8> rawAtlasMagic { 'D', 'S', 'C', 'R', 'A', 'W', '1', 0 };

uint16_t readLittleEndianU16(std::span<const uint8_t> bytes, size_t offset)
{
    return static_cast<uint16_t>(bytes[offset])
        | static_cast<uint16_t>(bytes[offset + 1]) << 8;
}

uint32_t readLittleEndianU32(std::span<const uint8_t> bytes, size_t offset)
{
    return static_cast<uint32_t>(bytes[offset])
        | static_cast<uint32_t>(bytes[offset + 1]) << 8
        | static_cast<uint32_t>(bytes[offset + 2]) << 16
        | static_cast<uint32_t>(bytes[offset + 3]) << 24;
}

int compareRawAtlasKeys(std::span<const uint8_t> left, std::span<const uint8_t> right)
{
    ASSERT(left.size() == 16);
    ASSERT(right.size() == 16);
    for (size_t index = 0; index < 16; ++index) {
        if (left[index] < right[index])
            return -1;
        if (left[index] > right[index])
            return 1;
    }
    return 0;
}

std::optional<std::array<uint8_t, 16>> rawAtlasKey(const String& sha256Hex)
{
    if (sha256Hex.length() < 32)
        return std::nullopt;
    std::array<uint8_t, 16> key;
    auto nibble = [](UChar character) -> int {
        if (character >= '0' && character <= '9')
            return character - '0';
        if (character >= 'a' && character <= 'f')
            return character - 'a' + 10;
        if (character >= 'A' && character <= 'F')
            return character - 'A' + 10;
        return -1;
    };
    for (size_t index = 0; index < key.size(); ++index) {
        int high = nibble(sha256Hex[index * 2]);
        int low = nibble(sha256Hex[index * 2 + 1]);
        if (high < 0 || low < 0)
            return std::nullopt;
        key[index] = static_cast<uint8_t>((high << 4) | low);
    }
    return key;
}

bool RawOpSequenceAtlas::load()
{
    if (m_loadAttempted)
        return m_valid;
    m_loadAttempted = true;

    const char* path = std::getenv("DRIFTSTACK_CANVAS_RAW_ATLAS_PATH");
    if (!path || !*path)
        return false;
    auto bytes = FileSystem::readEntireFile(String::fromUTF8(path));
    if (!bytes || bytes->size() < rawAtlasHeaderSize) {
        WTFLogAlways("[Driftstack canvas] raw op-sequence atlas unreadable or too small");
        return false;
    }
    m_bytes = WTF::move(*bytes);
    auto span = m_bytes.span();
    if (!equalSpans(span.first(rawAtlasMagic.size()), std::span(rawAtlasMagic))) {
        WTFLogAlways("[Driftstack canvas] raw op-sequence atlas magic mismatch");
        return false;
    }
    uint16_t version = readLittleEndianU16(span, 8);
    uint16_t entrySize = readLittleEndianU16(span, 10);
    uint32_t count = readLittleEndianU32(span, 12);
    uint32_t indexOffset = readLittleEndianU32(span, 16);
    uint32_t dataOffset = readLittleEndianU32(span, 20);
    uint64_t expectedDataOffset = rawAtlasHeaderSize + static_cast<uint64_t>(count) * rawAtlasIndexEntrySize;
    if (version != 1 || entrySize != rawAtlasIndexEntrySize || indexOffset != rawAtlasHeaderSize
        || expectedDataOffset != dataOffset || dataOffset > span.size()) {
        WTFLogAlways("[Driftstack canvas] raw op-sequence atlas header invalid");
        return false;
    }

    size_t expectedDataStart = 0;
    std::span<const uint8_t> previousKey;
    for (uint32_t index = 0; index < count; ++index) {
        size_t offset = rawAtlasHeaderSize + static_cast<size_t>(index) * rawAtlasIndexEntrySize;
        auto entry = span.subspan(offset, rawAtlasIndexEntrySize);
        auto key = entry.first(16);
        uint16_t width = readLittleEndianU16(entry, 16);
        uint16_t height = readLittleEndianU16(entry, 18);
        uint32_t dataStart = readLittleEndianU32(entry, 20);
        uint32_t dataLength = readLittleEndianU32(entry, 24);
        uint64_t expectedLength = static_cast<uint64_t>(width) * height * 4;
        uint64_t dataEnd = static_cast<uint64_t>(dataOffset) + dataStart + dataLength;
        if ((!previousKey.empty() && compareRawAtlasKeys(previousKey, key) >= 0)
            || !width || !height || expectedLength != dataLength || dataStart != expectedDataStart
            || dataEnd > span.size()) {
            WTFLogAlways("[Driftstack canvas] raw op-sequence atlas entry invalid");
            return false;
        }
        previousKey = key;
        expectedDataStart += dataLength;
    }
    if (static_cast<uint64_t>(dataOffset) + expectedDataStart != span.size()) {
        WTFLogAlways("[Driftstack canvas] raw op-sequence atlas size mismatch");
        return false;
    }
    m_count = count;
    m_dataOffset = dataOffset;
    m_valid = true;
    return true;
}

bool RawOpSequenceAtlas::lookup(const String& sha256Hex, int width, int height, Vector<uint8_t>& outRGBA)
{
    if (!load())
        return false;
    auto requestedKey = rawAtlasKey(sha256Hex);
    if (!requestedKey)
        return false;
    auto requestedKeySpan = std::span<const uint8_t>(*requestedKey);
    auto bytes = m_bytes.span();
    size_t low = 0;
    size_t high = m_count;
    while (low < high) {
        size_t middle = low + (high - low) / 2;
        auto entry = bytes.subspan(rawAtlasHeaderSize + middle * rawAtlasIndexEntrySize, rawAtlasIndexEntrySize);
        int comparison = compareRawAtlasKeys(entry.first(16), requestedKeySpan);
        if (comparison < 0)
            low = middle + 1;
        else
            high = middle;
    }
    if (low >= m_count)
        return false;
    auto entry = bytes.subspan(rawAtlasHeaderSize + low * rawAtlasIndexEntrySize, rawAtlasIndexEntrySize);
    if (compareRawAtlasKeys(entry.first(16), requestedKeySpan))
        return false;
    uint16_t entryWidth = readLittleEndianU16(entry, 16);
    uint16_t entryHeight = readLittleEndianU16(entry, 18);
    uint32_t dataStart = readLittleEndianU32(entry, 20);
    uint32_t dataLength = readLittleEndianU32(entry, 24);
    if (entryWidth != width || entryHeight != height
        || dataLength != static_cast<uint64_t>(width) * height * 4)
        return false;
    outRGBA = Vector<uint8_t>(bytes.subspan(m_dataOffset + dataStart, dataLength));
    return true;
}

bool rawOpSequenceAtlasLookup(const String& sha256Hex, int width, int height, Vector<uint8_t>& outRGBA)
{
    Locker locker(cacheLock());
    return rawOpSequenceAtlas().lookup(sha256Hex, width, height, outRGBA);
}

RefPtr<DecodedRGBABuffer> decodeOnce(const char* dataURL)
{
    static constexpr ASCIILiteral kPrefix = "data:image/png;base64,"_s;
    auto urlView = StringView::fromLatin1(dataURL);
    if (!urlView.startsWith(kPrefix))
        return nullptr;
    auto base64View = urlView.substring(kPrefix.length());

    auto pngBytes = base64Decode(base64View, { Base64DecodeOption::ValidatePadding });
    if (!pngBytes)
        return nullptr;
    const auto& bytes = pngBytes.value();
    if (bytes.isEmpty())
        return nullptr;

    auto cfData = adoptCF(CFDataCreate(nullptr, bytes.span().data(), static_cast<CFIndex>(bytes.size())));
    if (!cfData)
        return nullptr;
    auto src = adoptCF(CGImageSourceCreateWithData(cfData.get(), nullptr));
    if (!src)
        return nullptr;
    auto image = adoptCF(CGImageSourceCreateImageAtIndex(src.get(), 0, nullptr));
    if (!image)
        return nullptr;

    int w = static_cast<int>(CGImageGetWidth(image.get()));
    int h = static_cast<int>(CGImageGetHeight(image.get()));
    if (w <= 0 || h <= 0)
        return nullptr;

    auto buffer = DecodedRGBABuffer::create();
    buffer->width = w;
    buffer->height = h;
    buffer->rgba.grow(static_cast<size_t>(w) * h * 4);

    auto colorSpace = adoptCF(CGColorSpaceCreateWithName(kCGColorSpaceSRGB));
    if (!colorSpace)
        return nullptr;
    // Cast through uint32_t to satisfy -Wdeprecated-anon-enum-enum-conversion;
    // the union of CGImageAlphaInfo + kCGBitmapByteOrder* values is the
    // documented contract for CGBitmapContextCreate's bitmapInfo arg.
    uint32_t bitmapInfo = static_cast<uint32_t>(kCGImageAlphaPremultipliedLast)
                        | static_cast<uint32_t>(kCGBitmapByteOrder32Big);
    auto ctx = adoptCF(CGBitmapContextCreate(
        buffer->rgba.mutableSpan().data(),
        static_cast<size_t>(w),
        static_cast<size_t>(h),
        8,
        static_cast<size_t>(w) * 4,
        colorSpace.get(),
        bitmapInfo));
    if (!ctx)
        return nullptr;
    CGContextDrawImage(ctx.get(), CGRectMake(0, 0, w, h), image.get());

    // Unpremultiply: c' = (c * 255 + a/2) / a for a > 0; (0,0,0,0) for
    // a == 0; identity for a == 255. Matches the unpremultiply formula
    // WebKit uses elsewhere when reading a premultiplied buffer back as
    // unpremultiplied (see ImageBufferUtilities). Applying this to bytes
    // produced by CG's premultiplying decode gives the visible channel value,
    // but the mapping is not one-to-one for translucent pixels. Exact captured
    // getImageData bytes therefore use the raw op-sequence sidecar below.
    auto pixels = buffer->rgba.mutableSpan();
    const size_t pixelCount = static_cast<size_t>(w) * h;
    for (size_t i = 0; i < pixelCount; ++i) {
        uint8_t a = pixels[i * 4 + 3];
        if (!a) {
            pixels[i * 4 + 0] = 0;
            pixels[i * 4 + 1] = 0;
            pixels[i * 4 + 2] = 0;
            continue;
        }
        if (a == 255)
            continue;
        for (size_t c = 0; c < 3; ++c) {
            unsigned v = pixels[i * 4 + c];
            v = (v * 255u + a / 2u) / a;
            if (v > 255u)
                v = 255u;
            pixels[i * 4 + c] = static_cast<uint8_t>(v);
        }
    }
    return buffer;
}

bool decodeCanvasFp10xCanonicalToRGBA(const char* dataURL, std::span<const uint8_t>& outRGBA, int& outWidth, int& outHeight)
{
    if (!dataURL)
        return false;
    Locker locker(cacheLock());
    auto& map = cache();
    auto it = map.find(dataURL);
    if (it == map.end()) {
        auto decoded = decodeOnce(dataURL);
        if (!decoded)
            return false;
        it = map.set(dataURL, decoded.copyRef()).iterator;
    }
    if (!it->value)
        return false;
    const auto& buf = *it->value;
    outWidth = buf.width;
    outHeight = buf.height;
    outRGBA = buf.rgba.span();
    return true;
}

} // anonymous

bool isCanvasFp10xOverrideEnabled()
{
    static const bool enabled = []() {
        const char* env = std::getenv("DRIFTSTACK_CANVAS_FP10X_OVERRIDE");
        return env && env[0] == '1';
    }();
    return enabled;
}

bool getCanvasFp10xRGBAForCanvasState(int width, int height, const String& lastFillText, std::span<const uint8_t>& outRGBA)
{
    if (width <= 0 || height <= 0)
        return false;
    // Exact (dims + lastFillText) match ONLY. The old dimension-only fallback
    // (lookupCanvasFp10xCanonical(width,height)) substituted ANOTHER canvas's
    // canonical for any uncovered (width,height) state — i.e. it returned a 100%-
    // WRONG canvas (proven: a 200x100 'cumrig-cr2d-0' canvas got a black-bg
    // squiggle+circle from some other state). Under the bit-identical bar that's a
    // detectable defect; native rendering is device-exact for uncovered content, so
    // on a miss we now fall through (return false) to the native path instead.
    const char* canonical = WebCore::lookupCanvasFp10xCanonicalWithText(width, height, lastFillText);
    if (!canonical)
        return false;
    int decW = 0, decH = 0;
    std::span<const uint8_t> rgba;
    if (!decodeCanvasFp10xCanonicalToRGBA(canonical, rgba, decW, decH))
        return false;
    if (decW != width || decH != height)
        return false;
    if (rgba.size() != static_cast<size_t>(width) * height * 4)
        return false;
    outRGBA = rgba;
    return true;
}

bool getV510AtlasRGBAForOpSeq(const String& opSequenceSHA256Hex, int width, int height, Vector<uint8_t>& outRGBA)
{
    if (width <= 0 || height <= 0 || opSequenceSHA256Hex.length() < 32)
        return false;

    // getImageData is an unpremultiplied byte surface. Prefer capture-backed
    // bytes directly when the same complete operation key is present; decoding
    // the PNG atlas through CoreGraphics can lose the original edge preimage.
    if (rawOpSequenceAtlasLookup(opSequenceSHA256Hex, width, height, outRGBA))
        return true;

    // P1 (canvas-op-timing-audit): memoize the decode. The original ran the FULL
    // CG decode (base64→CGImageSource→CGBitmapContext draw→per-pixel unpremult)
    // on EVERY getImageData hit — the 4ms outlier source. Mirror the sibling
    // decodeCanvasFp10xCanonicalToRGBA HashMap+cacheLock() pattern: keyed on the
    // op-seq sha (1:1 with the served dataURL). Second+ call = HashMap hit + one
    // buffer copy. Same decodeOnce output, cached → byte-identical.
    {
        Locker locker(cacheLock());
        auto& map = v510OpSeqCache();
        auto it = map.find(opSequenceSHA256Hex);
        if (it != map.end()) {
            if (!it->value)
                return false; // negative cache: lookup/decode previously failed
            const auto& buf = *it->value;
            if (buf.width != width || buf.height != height)
                return false;
            if (buf.rgba.size() != static_cast<size_t>(width) * height * 4)
                return false;
            outRGBA = buf.rgba;
            return true;
        }
    }

    // V-510 atlas lookup (priority slot first, then main) keyed on op-seq sha.
    // Empty macForkDataURL: v3/v4 entries key on opSeqSha only (the §4 auto-learn
    // priority entries are v4). A hit returns the iPhone-canonical PNG dataURL.
    String hit = v510AtlasLookupPublic(String(), opSequenceSHA256Hex);
    if (hit.isEmpty()) {
        // Negative-cache the miss so repeat reads skip the atlas lookup too.
        Locker locker(cacheLock());
        v510OpSeqCache().set(opSequenceSHA256Hex, nullptr);
        return false;
    }
    auto utf8 = hit.utf8();
    // decodeOnce (file-local) decodes the PNG dataURL to non-premultiplied RGBA
    // with the same CG round-trip as the V-373 path; copy out (caller-owned).
    RefPtr<DecodedRGBABuffer> decoded = decodeOnce(utf8.data());
    {
        // Store decoded (or nullptr on decode failure) so we decode at most once
        // per op-seq, then copy out from the cached buffer below.
        Locker locker(cacheLock());
        v510OpSeqCache().set(opSequenceSHA256Hex, decoded);
    }
    if (!decoded)
        return false;
    if (decoded->width != width || decoded->height != height)
        return false;
    if (decoded->rgba.size() != static_cast<size_t>(width) * height * 4)
        return false;
    outRGBA = decoded->rgba;
    return true;
}

} // namespace Driftstack
} // namespace WebCore

#endif // PLATFORM(DRIFTSTACK)
