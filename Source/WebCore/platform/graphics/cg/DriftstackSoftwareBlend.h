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

} // namespace WebCore

#endif // USE(CG) && PLATFORM(DRIFTSTACK)
