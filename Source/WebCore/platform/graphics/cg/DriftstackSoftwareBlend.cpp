/*
 * Driftstack — software blend impl for CG-divergent blend modes (V-583.K).
 */

#include "config.h"
#include "DriftstackSoftwareBlend.h"

#if USE(CG) && PLATFORM(DRIFTSTACK)

#include "ColorSpace.h"
#include <algorithm>
#include <cmath>
#include <cstdint>

namespace WebCore {

namespace {

// Per-channel float blend formulas (W3C Compositing 1, §10).
// Inputs Cb (backdrop) and Cs (source) are in [0,1].
inline float blendChannelMultiply(float Cb, float Cs) { return Cb * Cs; }
inline float blendChannelScreen(float Cb, float Cs) { return Cb + Cs - Cb * Cs; }
inline float blendChannelHardLight(float Cb, float Cs)
{
    return Cs <= 0.5f ? blendChannelMultiply(Cb, 2.0f * Cs)
                      : blendChannelScreen(Cb, 2.0f * Cs - 1.0f);
}
inline float blendChannelSoftLight(float Cb, float Cs)
{
    if (Cs <= 0.5f)
        return Cb - (1.0f - 2.0f * Cs) * Cb * (1.0f - Cb);
    float D = (Cb <= 0.25f) ? ((16.0f * Cb - 12.0f) * Cb + 4.0f) * Cb : std::sqrt(Cb);
    return Cb + (2.0f * Cs - 1.0f) * (D - Cb);
}
inline float blendChannelColorBurn(float Cb, float Cs)
{
    if (Cb >= 1.0f) return 1.0f;
    if (Cs <= 0.0f) return 0.0f;
    return 1.0f - std::min(1.0f, (1.0f - Cb) / Cs);
}
inline float blendChannelExclusion(float Cb, float Cs) { return Cb + Cs - 2.0f * Cb * Cs; }

// Non-separable blends (operate on full RGB triplet).
inline float lum(float r, float g, float b) { return 0.3f * r + 0.59f * g + 0.11f * b; }

inline void clipColor(float& r, float& g, float& b)
{
    float l = lum(r, g, b);
    float n = std::min({ r, g, b });
    float x = std::max({ r, g, b });
    if (n < 0.0f) {
        float d = l - n;
        if (d < 1e-10f) d = 1e-10f;
        r = l + (((r - l) * l) / d);
        g = l + (((g - l) * l) / d);
        b = l + (((b - l) * l) / d);
    }
    if (x > 1.0f) {
        float d = x - l;
        if (d < 1e-10f) d = 1e-10f;
        r = l + (((r - l) * (1.0f - l)) / d);
        g = l + (((g - l) * (1.0f - l)) / d);
        b = l + (((b - l) * (1.0f - l)) / d);
    }
}

inline void setLum(float& r, float& g, float& b, float l)
{
    float d = l - lum(r, g, b);
    r += d; g += d; b += d;
    clipColor(r, g, b);
}

inline float sat(float r, float g, float b)
{
    return std::max({ r, g, b }) - std::min({ r, g, b });
}

inline void setSat(float& r, float& g, float& b, float s)
{
    // Sort channels so we can adjust min=0, mid=mid, max=s without losing identity of channels.
    float* mn = &r;
    float* md = &g;
    float* mx = &b;
    if (*mn > *md) std::swap(mn, md);
    if (*md > *mx) std::swap(md, mx);
    if (*mn > *md) std::swap(mn, md);
    if (*mx > *mn) {
        *md = ((*md - *mn) * s) / (*mx - *mn);
        *mx = s;
    } else {
        *md = 0.0f;
        *mx = 0.0f;
    }
    *mn = 0.0f;
}

inline void blendNonseparable(BlendMode mode,
    float Cbr, float Cbg, float Cbb,
    float Csr, float Csg, float Csb,
    float& or_, float& og, float& ob)
{
    // Default: copy backdrop (no-op), overwritten below.
    or_ = Cbr; og = Cbg; ob = Cbb;
    switch (mode) {
    case BlendMode::Hue: {
        // SetLum(SetSat(Cs, Sat(Cb)), Lum(Cb))
        float r = Csr, g = Csg, b = Csb;
        setSat(r, g, b, sat(Cbr, Cbg, Cbb));
        setLum(r, g, b, lum(Cbr, Cbg, Cbb));
        or_ = r; og = g; ob = b;
        break;
    }
    case BlendMode::Saturation: {
        // SetLum(SetSat(Cb, Sat(Cs)), Lum(Cb))
        float r = Cbr, g = Cbg, b = Cbb;
        setSat(r, g, b, sat(Csr, Csg, Csb));
        setLum(r, g, b, lum(Cbr, Cbg, Cbb));
        or_ = r; og = g; ob = b;
        break;
    }
    case BlendMode::Color: {
        // SetLum(Cs, Lum(Cb))
        float r = Csr, g = Csg, b = Csb;
        setLum(r, g, b, lum(Cbr, Cbg, Cbb));
        or_ = r; og = g; ob = b;
        break;
    }
    case BlendMode::Luminosity: {
        // SetLum(Cb, Lum(Cs))
        float r = Cbr, g = Cbg, b = Cbb;
        setLum(r, g, b, lum(Csr, Csg, Csb));
        or_ = r; og = g; ob = b;
        break;
    }
    default:
        break;
    }
}

inline uint8_t f2u8(float f)
{
    f = std::max(0.0f, std::min(1.0f, f));
    // Match Apple CG rounding: nearest, half-to-even is unstable here;
    // CG uses round-to-nearest-with-ties-to-positive (i.e. (int)(f*255+0.5)).
    return static_cast<uint8_t>(f * 255.0f + 0.5f);
}

} // anonymous namespace

bool driftstackSoftwareBlendFillRect(CGContextRef context, const FloatRect& rect, const Color& fillColor, float globalAlpha, BlendMode blendMode, CompositeOperator op)
{
    if (!context) return false;

    // Only apply to bitmap contexts where we have direct pixel access.
    void* data = CGBitmapContextGetData(context);
    if (!data) return false;

    size_t bw = CGBitmapContextGetWidth(context);
    size_t bh = CGBitmapContextGetHeight(context);
    size_t bpr = CGBitmapContextGetBytesPerRow(context);
    size_t bpp = CGBitmapContextGetBitsPerPixel(context) / 8;
    CGBitmapInfo info = CGBitmapContextGetBitmapInfo(context);
    CGImageAlphaInfo alphaInfo = static_cast<CGImageAlphaInfo>(info & kCGBitmapAlphaInfoMask);
    CGBitmapInfo byteOrder = info & kCGBitmapByteOrderMask;

    if (bpp != 4) return false; // 32-bit RGBA/BGRA only

    // Determine channel offsets. Canvas2D backing stores are typically
    // BGRA premultiplied on Apple platforms (kCGImageAlphaPremultipliedFirst
    // + byteOrder32Little). RGBA is also possible. Detect both.
    int rIdx, gIdx, bIdx, aIdx;
    bool premultiplied;
    bool alphaFirst = (alphaInfo == kCGImageAlphaPremultipliedFirst || alphaInfo == kCGImageAlphaFirst || alphaInfo == kCGImageAlphaNoneSkipFirst);
    bool alphaLast = (alphaInfo == kCGImageAlphaPremultipliedLast || alphaInfo == kCGImageAlphaLast || alphaInfo == kCGImageAlphaNoneSkipLast);
    bool littleEndian = (byteOrder == kCGBitmapByteOrder32Little);
    premultiplied = (alphaInfo == kCGImageAlphaPremultipliedFirst || alphaInfo == kCGImageAlphaPremultipliedLast);

    if (!alphaFirst && !alphaLast) return false;

    if (alphaFirst && littleEndian) {
        // BGRA: byte order [B G R A]
        bIdx = 0; gIdx = 1; rIdx = 2; aIdx = 3;
    } else if (alphaLast && !littleEndian) {
        // RGBA big-endian
        rIdx = 0; gIdx = 1; bIdx = 2; aIdx = 3;
    } else if (alphaFirst && !littleEndian) {
        // ARGB
        aIdx = 0; rIdx = 1; gIdx = 2; bIdx = 3;
    } else {
        // ABGR little-endian
        aIdx = 3; bIdx = 2; gIdx = 1; rIdx = 0;
    }

    // Map rect via current CTM to bitmap pixel coords.
    CGAffineTransform ctm = CGContextGetCTM(context);
    // CG bitmap coordinates are usually y-up from origin.
    CGRect deviceRect = CGRectApplyAffineTransform(rect, ctm);
    // CG y-axis: bitmap origin is bottom-left in CG; we want top-down pixel rows.
    // CGContextFillRect uses CGContextGetCTM — which already includes base flip
    // for y-down draws. So deviceRect after CTM is in bitmap coordinates with
    // CG's convention. We convert to row-major top-down by flipping Y.

    // Integer pixel bounds (inclusive-min, exclusive-max).
    int x0 = static_cast<int>(std::floor(deviceRect.origin.x));
    int y0 = static_cast<int>(std::floor(deviceRect.origin.y));
    int x1 = static_cast<int>(std::ceil(deviceRect.origin.x + deviceRect.size.width));
    int y1 = static_cast<int>(std::ceil(deviceRect.origin.y + deviceRect.size.height));

    // Flip Y to row-major top-down (bitmap row 0 = bottom in CG).
    int top = static_cast<int>(bh) - y1;
    int bot = static_cast<int>(bh) - y0;
    x0 = std::max(0, x0);
    x1 = std::min(static_cast<int>(bw), x1);
    top = std::max(0, top);
    bot = std::min(static_cast<int>(bh), bot);
    if (x0 >= x1 || top >= bot) return true; // empty intersection — silently consumed

    // Source color components in unpremultiplied [0,1].
    auto srgbComponents = fillColor.toResolvedColorComponentsInColorSpace(ColorSpace::SRGB);
    float Sr = srgbComponents[0];
    float Sg = srgbComponents[1];
    float Sb = srgbComponents[2];
    float Sa = srgbComponents[3] * globalAlpha;
    if (Sa <= 0.0f) return true; // nothing to draw

    // Clamp source [0,1].
    Sr = std::max(0.0f, std::min(1.0f, Sr));
    Sg = std::max(0.0f, std::min(1.0f, Sg));
    Sb = std::max(0.0f, std::min(1.0f, Sb));
    Sa = std::max(0.0f, std::min(1.0f, Sa));

    WTF_ALLOW_UNSAFE_BUFFER_USAGE_BEGIN // CG bitmap raw byte access
    uint8_t* base = static_cast<uint8_t*>(data);

    for (int y = top; y < bot; ++y) {
        uint8_t* row = base + y * bpr;
        for (int x = x0; x < x1; ++x) {
            uint8_t* px = row + x * bpp;
            // Read backdrop, unpremultiply if needed.
            float Br = px[rIdx] / 255.0f;
            float Bg = px[gIdx] / 255.0f;
            float Bb = px[bIdx] / 255.0f;
            float Ba = px[aIdx] / 255.0f;
            if (premultiplied && Ba > 0.0f) {
                Br /= Ba; Bg /= Ba; Bb /= Ba;
            }

            float Rr, Rg, Rb, Ra;

            if (op == CompositeOperator::XOR && blendMode == BlendMode::Normal) {
                // W3C XOR (Porter-Duff): co = αs*Cs*(1-αb) + αb*Cb*(1-αs)
                //                         αo = αs*(1-αb) + αb*(1-αs)
                Ra = Sa * (1.0f - Ba) + Ba * (1.0f - Sa);
                if (Ra > 0.0f) {
                    Rr = (Sa * Sr * (1.0f - Ba) + Ba * Br * (1.0f - Sa)) / Ra;
                    Rg = (Sa * Sg * (1.0f - Ba) + Ba * Bg * (1.0f - Sa)) / Ra;
                    Rb = (Sa * Sb * (1.0f - Ba) + Ba * Bb * (1.0f - Sa)) / Ra;
                } else {
                    Rr = Rg = Rb = 0.0f;
                }
            } else {
                // Generic blend + source-over composite.
                float blendR, blendG, blendB;
                switch (blendMode) {
                case BlendMode::ColorBurn:
                    blendR = blendChannelColorBurn(Br, Sr);
                    blendG = blendChannelColorBurn(Bg, Sg);
                    blendB = blendChannelColorBurn(Bb, Sb);
                    break;
                case BlendMode::HardLight:
                    blendR = blendChannelHardLight(Br, Sr);
                    blendG = blendChannelHardLight(Bg, Sg);
                    blendB = blendChannelHardLight(Bb, Sb);
                    break;
                case BlendMode::SoftLight:
                    blendR = blendChannelSoftLight(Br, Sr);
                    blendG = blendChannelSoftLight(Bg, Sg);
                    blendB = blendChannelSoftLight(Bb, Sb);
                    break;
                case BlendMode::Exclusion:
                    blendR = blendChannelExclusion(Br, Sr);
                    blendG = blendChannelExclusion(Bg, Sg);
                    blendB = blendChannelExclusion(Bb, Sb);
                    break;
                case BlendMode::Hue:
                case BlendMode::Saturation:
                case BlendMode::Color:
                case BlendMode::Luminosity:
                    blendNonseparable(blendMode, Br, Bg, Bb, Sr, Sg, Sb, blendR, blendG, blendB);
                    break;
                default:
                    return false; // unsupported — fall back
                }

                // W3C composite: Cs_compose = (1 - αb)*Cs + αb*B(Cb, Cs)
                // Then source-over: result = αs*Cs_compose + (1 - αs)*Cb
                float CsR = (1.0f - Ba) * Sr + Ba * blendR;
                float CsG = (1.0f - Ba) * Sg + Ba * blendG;
                float CsB = (1.0f - Ba) * Sb + Ba * blendB;
                Ra = Sa + Ba * (1.0f - Sa);
                if (Ra > 0.0f) {
                    Rr = (Sa * CsR + (1.0f - Sa) * Ba * Br) / Ra;
                    Rg = (Sa * CsG + (1.0f - Sa) * Ba * Bg) / Ra;
                    Rb = (Sa * CsB + (1.0f - Sa) * Ba * Bb) / Ra;
                } else {
                    Rr = Rg = Rb = 0.0f;
                }
            }

            // Write back, premultiply if needed.
            if (premultiplied) {
                px[rIdx] = f2u8(Rr * Ra);
                px[gIdx] = f2u8(Rg * Ra);
                px[bIdx] = f2u8(Rb * Ra);
            } else {
                px[rIdx] = f2u8(Rr);
                px[gIdx] = f2u8(Rg);
                px[bIdx] = f2u8(Rb);
            }
            px[aIdx] = f2u8(Ra);
        }
    }
    WTF_ALLOW_UNSAFE_BUFFER_USAGE_END

    return true;
}

} // namespace WebCore

#endif // USE(CG) && PLATFORM(DRIFTSTACK)
