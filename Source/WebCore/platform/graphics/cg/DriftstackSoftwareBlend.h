/*
 * Driftstack — software blend impl for CG-divergent blend modes.
 *
 * V-583.K: Mac CG vs iPhone CG diverges by 1-LSB at certain pixel
 * boundaries for 8 specific blend modes (hue/color/saturation/
 * color-burn/hard-light/soft-light/exclusion/xor). To match iPhone
 * exactly we bypass CGContextFillRect for these modes and apply
 * W3C Compositing and Blending Level 1 spec in software per pixel.
 *
 * Empirical: max single-channel delta is always 1-2 (not algorithmic
 * divergence — sub-LSB rounding only). W3C reference impl matches
 * iPhone bit-exactly.
 */

#pragma once

#if USE(CG) && PLATFORM(DRIFTSTACK)

#include "Color.h"
#include "FloatRect.h"
#include "GraphicsTypes.h"
#include <CoreGraphics/CoreGraphics.h>

namespace WebCore {

// Returns true if the blend/composite combination diverges between Mac CG and
// iPhone CG by 1-LSB at certain pixel boundaries (V-583.K empirical).
inline bool driftstackSoftwareBlendApplies(CompositeOperator op, BlendMode blendMode)
{
    if (blendMode == BlendMode::Hue
        || blendMode == BlendMode::Color
        || blendMode == BlendMode::Saturation
        || blendMode == BlendMode::ColorBurn
        || blendMode == BlendMode::HardLight
        || blendMode == BlendMode::SoftLight
        || blendMode == BlendMode::Exclusion)
        return true;
    if (op == CompositeOperator::XOR && blendMode == BlendMode::Normal)
        return true;
    // V-590-revisit (founder verdict 2026-05-11 — Rule N locked): V-589
    // empirical enumeration identified destination-atop ×3 + lighter (PlusLighter)
    // ×2 + saturation ×1 across 6 mass-diff compositing seeds in V-405.
    // Saturation is already covered via the blendMode set above. destination-atop
    // and plus-lighter map to W3C composite operators (not blend modes), so
    // route them through the software path here where the Porter-Duff impl
    // matches iPhone CG bit-exactly.
    if (op == CompositeOperator::DestinationAtop && blendMode == BlendMode::Normal)
        return true;
    if (op == CompositeOperator::PlusLighter && blendMode == BlendMode::Normal)
        return true;
    return false;
}

// Software-blend a solid-color fillRect into a CG bitmap context per W3C spec.
// Returns true if the blend was performed. False means caller should fall back
// to standard CGContextFillRect (e.g. context is not a bitmap, or rect is empty
// after intersection with bitmap bounds).
//
// `globalAlpha` is the current GraphicsContext::alpha() value (canvas
// globalAlpha). The CGContext alpha state is opaque to public CG API.
//
// Caller is responsible for setting up CTM/clipping. This routine reads the
// CTM and uses it to map rect coordinates to pixel coordinates.
bool driftstackSoftwareBlendFillRect(CGContextRef context, const FloatRect& rect, const Color& fillColor, float globalAlpha, BlendMode blendMode, CompositeOperator op);

// V-749.A — extended software-blend with per-pixel coverage mask. Same
// composite/blend math as driftstackSoftwareBlendFillRect but each pixel's
// source alpha is multiplied by coverageMask[y * coverageRowStride + x] / 255.
// Enables V-749.B/C/D fillPath/drawEllipse/fillRoundedRect wiring.
//
// `deviceRect` is the path's device-space bounding rect (caller computed via
// CGContextGetCTM mapping). `coverage` array dims = (coverageWidth ×
// coverageHeight), row-major top-down. Caller responsibility:
//   1. Compute path device-space bounding rect.
//   2. CGBitmapContextCreate (alpha-only, dims = device rect rounded up).
//   3. CGContextSetFillColor(layerCtx, white); CGContextAddPath + fill the
//      path into the alpha bitmap (this produces the coverage mask).
//   4. Pass the bitmap data as `coverage`; call this function.
//
// Returns true if the blend was performed. False means non-bitmap context or
// empty intersection.
bool driftstackSoftwareBlendApplyMasked(
    CGContextRef context,
    const FloatRect& deviceRect,
    const uint8_t* coverage,
    int coverageWidth, int coverageHeight,
    size_t coverageRowStride,
    const Color& fillColor,
    float globalAlpha,
    BlendMode blendMode,
    CompositeOperator op);

} // namespace WebCore

#endif // USE(CG) && PLATFORM(DRIFTSTACK)
