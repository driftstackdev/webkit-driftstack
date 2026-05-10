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

// Per-channel double blend formulas (W3C Compositing 1, §10).
// Use double to match iPhone CG's internal precision (V-583.K-empirical:
// float gave systematic 1-LSB drift in G channel for non-separable hue).
inline double blendChannelMultiply(double Cb, double Cs) { return Cb * Cs; }
inline double blendChannelScreen(double Cb, double Cs) { return Cb + Cs - Cb * Cs; }
inline double blendChannelHardLight(double Cb, double Cs)
{
    return Cs <= 0.5 ? blendChannelMultiply(Cb, 2.0 * Cs)
                     : blendChannelScreen(Cb, 2.0 * Cs - 1.0);
}
inline double blendChannelSoftLight(double Cb, double Cs)
{
    if (Cs <= 0.5)
        return Cb - (1.0 - 2.0 * Cs) * Cb * (1.0 - Cb);
    double D = (Cb <= 0.25) ? ((16.0 * Cb - 12.0) * Cb + 4.0) * Cb : std::sqrt(Cb);
    return Cb + (2.0 * Cs - 1.0) * (D - Cb);
}
inline double blendChannelColorBurn(double Cb, double Cs)
{
    if (Cb >= 1.0) return 1.0;
    if (Cs <= 0.0) return 0.0;
    return 1.0 - std::min(1.0, (1.0 - Cb) / Cs);
}
inline double blendChannelExclusion(double Cb, double Cs) { return Cb + Cs - 2.0 * Cb * Cs; }

// Non-separable blends (operate on full RGB triplet).
inline double lum(double r, double g, double b) { return 0.3 * r + 0.59 * g + 0.11 * b; }

inline void clipColor(double& r, double& g, double& b)
{
    double l = lum(r, g, b);
    double n = std::min({ r, g, b });
    double x = std::max({ r, g, b });
    if (n < 0.0) {
        double d = l - n;
        if (d < 1e-15) d = 1e-15;
        r = l + (((r - l) * l) / d);
        g = l + (((g - l) * l) / d);
        b = l + (((b - l) * l) / d);
    }
    if (x > 1.0) {
        double d = x - l;
        if (d < 1e-15) d = 1e-15;
        r = l + (((r - l) * (1.0 - l)) / d);
        g = l + (((g - l) * (1.0 - l)) / d);
        b = l + (((b - l) * (1.0 - l)) / d);
    }
}

inline void setLum(double& r, double& g, double& b, double l)
{
    double d = l - lum(r, g, b);
    r += d; g += d; b += d;
    clipColor(r, g, b);
}

inline double sat(double r, double g, double b)
{
    return std::max({ r, g, b }) - std::min({ r, g, b });
}

inline void setSat(double& r, double& g, double& b, double s)
{
    // Sort channels so we can adjust min=0, mid=mid, max=s without losing identity of channels.
    double* mn = &r;
    double* md = &g;
    double* mx = &b;
    if (*mn > *md) std::swap(mn, md);
    if (*md > *mx) std::swap(md, mx);
    if (*mn > *md) std::swap(mn, md);
    if (*mx > *mn) {
        *md = ((*md - *mn) * s) / (*mx - *mn);
        *mx = s;
    } else {
        *md = 0.0;
        *mx = 0.0;
    }
    *mn = 0.0;
}

inline void blendNonseparable(BlendMode mode,
    double Cbr, double Cbg, double Cbb,
    double Csr, double Csg, double Csb,
    double& or_, double& og, double& ob)
{
    // Default: copy backdrop (no-op), overwritten below.
    or_ = Cbr; og = Cbg; ob = Cbb;
    switch (mode) {
    case BlendMode::Hue: {
        // SetLum(SetSat(Cs, Sat(Cb)), Lum(Cb))
        double r = Csr, g = Csg, b = Csb;
        setSat(r, g, b, sat(Cbr, Cbg, Cbb));
        setLum(r, g, b, lum(Cbr, Cbg, Cbb));
        or_ = r; og = g; ob = b;
        break;
    }
    case BlendMode::Saturation: {
        // SetLum(SetSat(Cb, Sat(Cs)), Lum(Cb))
        double r = Cbr, g = Cbg, b = Cbb;
        setSat(r, g, b, sat(Csr, Csg, Csb));
        setLum(r, g, b, lum(Cbr, Cbg, Cbb));
        or_ = r; og = g; ob = b;
        break;
    }
    case BlendMode::Color: {
        // SetLum(Cs, Lum(Cb))
        double r = Csr, g = Csg, b = Csb;
        setLum(r, g, b, lum(Cbr, Cbg, Cbb));
        or_ = r; og = g; ob = b;
        break;
    }
    case BlendMode::Luminosity: {
        // SetLum(Cb, Lum(Cs))
        double r = Cbr, g = Cbg, b = Cbb;
        setLum(r, g, b, lum(Csr, Csg, Csb));
        or_ = r; og = g; ob = b;
        break;
    }
    default:
        break;
    }
}

inline uint8_t f2u8(double f)
{
    f = std::max(0.0, std::min(1.0, f));
    // Match Apple CG rounding: nearest, half-to-even is unstable here;
    // CG uses round-to-nearest-with-ties-to-positive (i.e. (int)(f*255+0.5)).
    return static_cast<uint8_t>(f * 255.0 + 0.5);
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
    double Sr = srgbComponents[0];
    double Sg = srgbComponents[1];
    double Sb = srgbComponents[2];
    double Sa = static_cast<double>(srgbComponents[3]) * static_cast<double>(globalAlpha);
    if (Sa <= 0.0) return true; // nothing to draw

    // Clamp source [0,1].
    Sr = std::max(0.0, std::min(1.0, Sr));
    Sg = std::max(0.0, std::min(1.0, Sg));
    Sb = std::max(0.0, std::min(1.0, Sb));
    Sa = std::max(0.0, std::min(1.0, Sa));

    WTF_ALLOW_UNSAFE_BUFFER_USAGE_BEGIN // CG bitmap raw byte access
    uint8_t* base = static_cast<uint8_t*>(data);

    for (int y = top; y < bot; ++y) {
        uint8_t* row = base + y * bpr;
        for (int x = x0; x < x1; ++x) {
            uint8_t* px = row + x * bpp;
            // Read backdrop, unpremultiply if needed.
            double Br = px[rIdx] / 255.0;
            double Bg = px[gIdx] / 255.0;
            double Bb = px[bIdx] / 255.0;
            double Ba = px[aIdx] / 255.0;
            if (premultiplied && Ba > 0.0) {
                Br /= Ba; Bg /= Ba; Bb /= Ba;
            }

            double Rr, Rg, Rb, Ra;

            if (op == CompositeOperator::XOR && blendMode == BlendMode::Normal) {
                // W3C XOR (Porter-Duff): co = αs*Cs*(1-αb) + αb*Cb*(1-αs)
                //                         αo = αs*(1-αb) + αb*(1-αs)
                Ra = Sa * (1.0 - Ba) + Ba * (1.0 - Sa);
                if (Ra > 0.0) {
                    Rr = (Sa * Sr * (1.0 - Ba) + Ba * Br * (1.0 - Sa)) / Ra;
                    Rg = (Sa * Sg * (1.0 - Ba) + Ba * Bg * (1.0 - Sa)) / Ra;
                    Rb = (Sa * Sb * (1.0 - Ba) + Ba * Bb * (1.0 - Sa)) / Ra;
                } else {
                    Rr = Rg = Rb = 0.0;
                }
            } else {
                // Generic blend + source-over composite.
                double blendR, blendG, blendB;
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
                double CsR = (1.0 - Ba) * Sr + Ba * blendR;
                double CsG = (1.0 - Ba) * Sg + Ba * blendG;
                double CsB = (1.0 - Ba) * Sb + Ba * blendB;
                Ra = Sa + Ba * (1.0 - Sa);
                if (Ra > 0.0) {
                    Rr = (Sa * CsR + (1.0 - Sa) * Ba * Br) / Ra;
                    Rg = (Sa * CsG + (1.0 - Sa) * Ba * Bg) / Ra;
                    Rb = (Sa * CsB + (1.0 - Sa) * Ba * Bb) / Ra;
                } else {
                    Rr = Rg = Rb = 0.0;
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
