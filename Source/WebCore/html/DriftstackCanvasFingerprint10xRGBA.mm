/*
 * DriftstackCanvasFingerprint10xRGBA.mm — see header.
 */

#include "config.h"
#include "DriftstackCanvasFingerprint10xRGBA.h"

#if PLATFORM(DRIFTSTACK)

#include "DriftstackCanvasFingerprint10xOverride.h"

#import <CoreGraphics/CoreGraphics.h>
#import <ImageIO/ImageIO.h>
#include <cstdlib>
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
    // produced by CG's premultiplying decode round-trips losslessly to
    // the original PNG-encoded values.
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
    // V-510 atlas lookup (priority slot first, then main) keyed on op-seq sha.
    // Empty macForkDataURL: v3/v4 entries key on opSeqSha only (the §4 auto-learn
    // priority entries are v4). A hit returns the iPhone-canonical PNG dataURL.
    String hit = v510AtlasLookupPublic(String(), opSequenceSHA256Hex);
    if (hit.isEmpty())
        return false;
    auto utf8 = hit.utf8();
    // decodeOnce (file-local) decodes the PNG dataURL to non-premultiplied RGBA
    // with the same CG round-trip as the V-373 path; copy out (caller-owned).
    RefPtr<DecodedRGBABuffer> decoded = decodeOnce(utf8.data());
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
