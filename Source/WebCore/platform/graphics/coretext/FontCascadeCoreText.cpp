/*
 * Copyright (C) 1999 Lars Knoll (knoll@kde.org)
 *           (C) 1999 Antti Koivisto (koivisto@kde.org)
 *           (C) 2000 Dirk Mueller (mueller@kde.org)
 * Copyright (C) 2003-2023 Apple Inc. All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public License
 * along with this library; see the file COPYING.LIB.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 */

#include "config.h"
#include "FontCascade.h"

#include "ComplexTextController.h"
#include "DashArray.h"
#include "Font.h"

#if PLATFORM(DRIFTSTACK)
#include "../cocoa/DriftstackEmojiAtlas.h"
#include "../cocoa/DriftstackTextGlyphAtlas.h"
#include "../cg/DriftstackPerGlyphAtlas.h"
#include "../cg/DriftstackTelemetry.h"
#include "../cg/DriftstackTextRunAtlas.h"
#include "Color.h"
#include <CoreGraphics/CoreGraphics.h>
#include <ImageIO/ImageIO.h>
#include <wtf/RetainPtr.h>
#endif
#include "FontCascadeFonts.h"
#include "FontCascadeInlines.h"
#include "FontInlines.h"
#include "GlyphBuffer.h"
#include "GraphicsContext.h"
#include "LayoutRect.h"
#include "Logging.h"
#include "RenderStyle+GettersInlines.h"
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <pal/spi/cg/CoreGraphicsSPI.h>
#include <wtf/MathExtras.h>
#include <wtf/RuntimeApplicationChecks.h>

#include <pal/spi/cf/CoreTextSPI.h>

namespace WebCore {

FontCascade::FontCascade(const FontPlatformData& fontData, FontSmoothingMode fontSmoothingMode)
    : m_fonts(FontCascadeFonts::createForPlatformFont(fontData))
    , m_enableKerning(computeEnableKerning())
    , m_requiresShaping(computeRequiresShaping())
{
    m_fontDescription.setFontSmoothing(fontSmoothingMode);
    RetainPtr ctFont = fontData.ctFont();

    m_fontDescription.setSpecifiedSize(CTFontGetSize(ctFont.get()));
    m_fontDescription.setComputedSize(CTFontGetSize(ctFont.get()));
    m_fontDescription.setIsItalic(CTFontGetSymbolicTraits(ctFont.get()) & kCTFontTraitItalic);
    m_fontDescription.setWeight((CTFontGetSymbolicTraits(ctFont.get()) & kCTFontTraitBold) ? boldWeightValue() : normalWeightValue());
}

static const AffineTransform& NODELETE rotateLeftTransform()
{
    static constexpr AffineTransform result(0, -1, 1, 0, 0, 0);
    return result;
}

AffineTransform NODELETE computeBaseOverallTextMatrix(const std::optional<AffineTransform>& syntheticOblique)
{
    AffineTransform result;

    // This is a Y-flip, because text's coordinate system is increasing-Y-goes-up,
    // but WebKit's coordinate system is increasing-Y-goes-down.
    result.setB(-result.b());
    result.setD(-result.d());

    if (syntheticOblique)
        result = *syntheticOblique * result;

    return result;
}

AffineTransform computeOverallTextMatrix(const Font& font)
{
    std::optional<AffineTransform> syntheticOblique;
    auto& platformData = font.platformData();
    if (platformData.syntheticOblique()) {
        static const float obliqueSkew = std::tanf(deg2rad(FontCascade::syntheticObliqueAngle()));
        if (platformData.orientation() == FontOrientation::Vertical) {
            if (font.isTextOrientationFallback())
                syntheticOblique = AffineTransform(1, obliqueSkew, 0, 1, 0, 0);
            else
                syntheticOblique = AffineTransform(1, -obliqueSkew, 0, 1, 0, 0);
        } else
            syntheticOblique = AffineTransform(1, 0, -obliqueSkew, 1, 0, 0);
    }

    return computeBaseOverallTextMatrix(syntheticOblique);
}

AffineTransform NODELETE computeBaseVerticalTextMatrix(const AffineTransform& previousTextMatrix)
{
    // The translation here ("e" and "f" fields) are irrelevant, because
    // this matrix is inverted in fillVectorWithVerticalGlyphPositions to place the glyphs in the CTM's coordinate system.
    // All we're trying to do here is rotate the text matrix so glyphs appear visually upright.
    // We have to include the previous text matrix because it includes things like synthetic oblique.
    //
    // Because this is a left-multiply, we're taking the points from user coordinates, which are increasing-Y-goes-down,
    // and we're rotating the points to the left in that coordinate system, to put them physically upright.
    return rotateLeftTransform() * previousTextMatrix;
}

AffineTransform NODELETE computeVerticalTextMatrix(const Font& font, const AffineTransform& previousTextMatrix)
{
    ASSERT_UNUSED(font, font.platformData().orientation() == FontOrientation::Vertical);
    return computeBaseVerticalTextMatrix(previousTextMatrix);
}

static void fillVectorWithHorizontalGlyphPositions(Vector<CGPoint, 256>& positions, CGContextRef context, std::span<const CGSize> advances, const FloatPoint& point)
{
    // Keep this in sync as the inverse of `DrawGlyphsRecorder::recordDrawGlyphs`.
    // The input positions are in the context's coordinate system, without the text matrix.
    // However, the positions that CT/CG accept are in the text matrix's coordinate system.
    // CGContextGetTextMatrix() gives us the matrix that maps from text's coordinate system to the context's (non-text) coordinate system.
    // We need to figure out what to deliver CT, inside the text's coordinate system, such that it ends up coincident with the input in the context's coordinate system.
    //
    // CTM * text matrix * positions we need to deliver to CT = CTM * input positions
    // Solving for the positions we need to deliver to CT, we get
    // positions we need to deliver to CT = inverse(text matrix) * input positions
    CGAffineTransform matrix = CGAffineTransformInvert(CGContextGetTextMatrix(context));
    positions[0] = CGPointApplyAffineTransform(point, matrix);
    for (size_t i = 1; i < advances.size(); ++i) {
        CGSize advance = CGSizeApplyAffineTransform(advances[i - 1], matrix);
        positions[i].x = positions[i - 1].x + advance.width;
        positions[i].y = positions[i - 1].y + advance.height;
    }
}

static void fillVectorWithVerticalGlyphPositions(Vector<CGPoint, 256>& positions, std::span<const CGSize> translations, std::span<const CGSize> advances, const FloatPoint& point, float ascentDelta, CGAffineTransform textMatrix)
{
    // Keep this function in sync as the inverse of `DrawGlyphsRecorder::recordDrawGlyphs`.

    // It's important to realize we're dealing with 4 coordinate systems here:
    // 1. Physical coordinate system. This is what the user sees.
    // 2. User coordinate system. This is the coordinate system of just the CTM. For vertical text, this is just like the normal WebKit increasing-Y-down
    //        coordinate system, except we're rotated right, so logical right is physical down. (We do this so logical inline progression proceeds in the
    //        logically increasing-X dimension, just as it would if we weren't doing vertical stuff.)
    // 3. Text coordinate system. This is the coordinate of the text matrix concatenated with the CTM. For vertical text, this is rotated such that
    //        increasing Y goes physically up, and increasing X goes physically right. The control points in font contours are authored according to this
    //        increasing-Y-up coordinate system.
    // 4. Synthetic-oblique-less text coordinate system. This would be identical to the text coordinate system if synthetic oblique was not in effect. This
    //        is useful because, when we're moving glyphs around, we usually don't want to consider synthetic oblique. Instead, synthetic oblique is just
    //        a rasterization-time effect, and not used for glyph positioning/layout.
    //        FIXME: Does this mean that synthetic oblique should always be applied on the result of rotateLeftTransform() in computeVerticalTextMatrix(),
    //        rather than the other way around?

    // Imagine an vertical upright glyph:
    // +--------------------------+
    // |      ___       ___       |
    // |      \  \     /  /       |
    // |       \  \   /  /        |
    // |        \  \ /  /         |
    // |         \  V  /          |
    // |          \   /           |
    // |          |   |           |
    // |          |   |           |
    // |          |   |           |
    // |          |   |           |
    // |          |___|           |
    // |                          |
    // +--------------------------+
    //
    // The ideographic baseline lies in the center of the glyph, and the alphabetic baseline lies to the left of it:
    //     |        |
    // +---|--------|-------------+
    // |   |  ___   |   ___       |
    // |   |  \  \  |  /  /       |
    // |   |   \  \ | /  /        |
    // |   |    \  \|/  /         |
    // |   |     \  |  /          |
    // |   |      \ | /           |
    // |   |      | | |           |
    // |   |      | | |           |
    // |   |      | | |           |
    // |   |      | | |           |
    // |   |      |_|_|           |
    // |   |        |             |
    // +---|--------|-------------+
    //     |        | <== ideographic baseline
    //     | <== alphabetic baseline
    //
    // The glyph itself has a local origin, which is the position sent to Core Text. The control points of the contours are defined relative to this point.
    // +--------------------------+
    // |      ___       ___       |
    // |      \  \     /  /       |
    // |       \  \   /  /        |
    // |        \  \ /  /         |
    // |         \  V  /          |
    // |          \   /           |
    // |          |   |           |
    // |          |   |           |
    // |          |   |           |
    // * <= here  |   |           |
    // |          |___|           |
    // |                          |
    // +--------------------------+
    //
    // Now, for horizontal text, we can do the simple thing of just:
    // 1. Place the pen at a position. Record this position as the local origin of the first glyph
    // 2. Move the pen according to the glyph's advance
    // 3. Record a new position as the local origin of the next glyph
    // 4. Go to 2
    // However, for vertical text, we can't get away with this because the glyph origins are not on the baseline.
    // This is what the "vertical translation for a glyph" is for. It contains this vector:
    // +---A--------B-------------+
    // |           /              |
    // |          /               |
    // |        --                |
    // |       /                  |
    // |      /                   |
    // |    --                    |
    // |   /                      |
    // |  /                       |
    // ||_                        |
    // C                          |
    // |                          |
    // |                          |
    // +--------------------------+
    // It points from the pen position on the ideographic baseline to the glyph's local origin. This is (usually) physically
    // down-and-to-the-left. Core Text gives us these vectors in the text coordinate system, and so therefore these vectors (usually) have
    // both X and Y components negative.

    // The goal of this function is to produce glyph origins in the text coordinate system, because that's what Core Text expects. The "advances"
    // and "point" parameters to this function are in the user coordinate system. The "translations" parameter is in the "synthetic-oblique-less
    // text coordinate system."

    // CGContextGetTextMatrix() transforms points from text coordinates to user coordinates. However, we're trying to produce text coordinates from
    // user coordinates, so we invert it.
    CGAffineTransform transform = CGAffineTransformInvert(textMatrix);

    // Because the "vertical translation for a glyph" vector starts at the ideographic baseline (the point B in the above diagram), we have to
    // adjust the pen position to start there. WebKit's text routines start out using the alphabetic baseline (point A in the diagram above) so we
    // adjust the start position here, which has the effect of shifting the whole run altogether.
    //
    // ascentDelta is (usually) a negative number, and represents the distance between the ideographic baseline to the alphabetic baseline.
    // In user coordinates, we want to adjust the Y component to make a horizontal physical change. And, because the user coordinate system is
    // logically increasing-Y-down, we add the value, which is negative, to move us logically up, which is physically to the right. Now our position
    // is at the point labeled B in the above diagram, in user coordinates.
    auto position = CGPointMake(point.x(), point.y() + ascentDelta);

    static const auto constantSyntheticTextMatrixOmittingOblique = computeBaseVerticalTextMatrix(computeBaseOverallTextMatrix(std::nullopt)); // See fillVectorWithVerticalGlyphPositions(), which describes what this is.

    for (unsigned i = 0; i < translations.size(); ++i) {
        // The "translations" parameter is in the "synthetic-oblique-less text coordinate system" and we want to add it to the position in the user
        // coordinate system. Luckily, the text matrix (or, at least the version of the text matrix that doesn't include synthetic oblique) does exactly
        // this. So, we just create the synthetic-oblique-less text matrix, and run the translation through it. This gives us the translation in user
        // coordinates.
        auto translationInUserCoordinates = CGSizeApplyAffineTransform(translations[i], constantSyntheticTextMatrixOmittingOblique);

        // Now we can add the position in user coordinates with the translation in user coordinates.
        auto positionInUserCoordinates = CGPointMake(position.x + translationInUserCoordinates.width, position.y + translationInUserCoordinates.height);

        // And then put it back in font coordinates for submission to Core Text. Yay!
        positions[i] = CGPointApplyAffineTransform(positionInUserCoordinates, transform);

        // Advance the position to the next position in user coordinates. Both the advances and position are in user coordinates.
        position.x += advances[i].width;
        position.y += advances[i].height;
    }
}

static void showGlyphsWithAdvances(const FloatPoint& point, const Font& font, CGContextRef context, std::span<const CGGlyph> glyphs, std::span<const CGSize> advances, const AffineTransform& textMatrix)
{
    if (glyphs.empty())
        return;

    const FontPlatformData& platformData = font.platformData();
#if PLATFORM(DRIFTSTACK)
    // V-602 LAYER-4 DIAG (env-gated DRIFTSTACK_V602_DIAG=1): log the CTFont
    // family name + first 5 glyph IDs + notdef count to characterize the
    // empty-pixel rasterization gap for CJK / Arabic / Devanagari clusters.
    // Per V-602 verify: Hiragino is selected for CJK but glyphs emit 0 pixels.
    // This diagnostic reveals whether the issue is .notdef glyph IDs (cluster
    // shaped against a font that doesn't have those glyphs) or whether real
    // glyph IDs are passed but rasterization fails.
    static bool s_v602Diag = []() {
        const char* env = getenv("DRIFTSTACK_V602_DIAG");
        return env && env[0] == '1';
    }();
    if (s_v602Diag) {
        // V-708 (2026-05-11): rate limit raised to 5000 (was 30) so V-405
        // atlas-OFF text fuzzer's full 250-seed trace captures cleanly.
        // Per-process cap retained to bound log size for cumrig + rig
        // runs that drive thousands of fillText calls.
        static unsigned diagFireCount = 0;
        if (++diagFireCount <= 5000) {
            RetainPtr<CFStringRef> familyName = adoptCF(CTFontCopyFamilyName(platformData.ctFont()));
            char nameBuf[256] = {0};
            if (familyName)
                CFStringGetCString(familyName.get(), nameBuf, sizeof(nameBuf), kCFStringEncodingUTF8);
            unsigned notdefCount = 0;
            for (size_t i = 0; i < glyphs.size(); ++i)
                if (glyphs[i] == 0) ++notdefCount;
            float advanceSum = 0.f;
            for (size_t i = 0; i < advances.size(); ++i)
                advanceSum += advances[i].width;
            // V-708: include CTFont ascent/descent/leading at point-size,
            // unitsPerEm for cross-checking V-679 binary identity → metric
            // identity hypothesis. Per-call ascent reveals if font binary
            // metrics on Mac for SPI fonts match expected iOS values.
            CGFloat ascent = CTFontGetAscent(platformData.ctFont());
            CGFloat descent = CTFontGetDescent(platformData.ctFont());
            CGFloat leading = CTFontGetLeading(platformData.ctFont());
            unsigned upm = CTFontGetUnitsPerEm(platformData.ctFont());
            WTFLogAlways("[Driftstack-V602-DIAG] font='%s' size=%.1f upm=%u asc=%.3f desc=%.3f lead=%.3f advSum=%.3f nGlyphs=%zu notdef=%u g0..4={%u,%u,%u,%u,%u}",
                nameBuf, platformData.size(), upm,
                static_cast<double>(ascent), static_cast<double>(descent),
                static_cast<double>(leading), static_cast<double>(advanceSum),
                glyphs.size(), notdefCount,
                glyphs.size() > 0 ? glyphs[0] : 0u,
                glyphs.size() > 1 ? glyphs[1] : 0u,
                glyphs.size() > 2 ? glyphs[2] : 0u,
                glyphs.size() > 3 ? glyphs[3] : 0u,
                glyphs.size() > 4 ? glyphs[4] : 0u);
        }
    }
#endif
    Vector<CGPoint, 256> positions(glyphs.size());
    if (platformData.orientation() == FontOrientation::Vertical) {
        ScopedTextMatrix savedMatrix(computeVerticalTextMatrix(font, textMatrix), context);

        Vector<CGSize, 256> translations(glyphs.size());
        RetainPtr ctFont = platformData.ctFont();
        CTFontGetVerticalTranslationsForGlyphs(ctFont.get(), glyphs.data(), translations.mutableSpan().data(), glyphs.size());

        auto ascentDelta = font.fontMetrics().ascent(FontBaseline::Ideographic) - font.fontMetrics().ascent();
        fillVectorWithVerticalGlyphPositions(positions, translations, advances, point, ascentDelta, CGContextGetTextMatrix(context));
        CTFontDrawGlyphs(ctFont.get(), glyphs.data(), positions.span().data(), glyphs.size(), context);
    } else {
        fillVectorWithHorizontalGlyphPositions(positions, context, advances, point);
        // V-CANVAS-GLYPH-AS-PATH (2026-05-29): tested rendering glyphs as filled
        // outline paths (CTFontCreatePathForGlyph) instead of CTFontDrawGlyphs —
        // hypothesis that CG path-fill (which matches iPhone bit-identical for
        // geometry) would also match iPhone's glyph edge-AA. DISPROVEN: ascii text
        // went 121px→151px vs iPhone (worse). iPhone's glyph edge-AA is the font
        // rasterizer's (hinted), NOT path-fill. So glyph edge-AA is the genuine
        // macOS-CT≠iOS-CT rasterizer difference; closed via the per-glyph atlas, not native.
        CTFontDrawGlyphs(RetainPtr { platformData.ctFont() }.get(), glyphs.data(), positions.span().data(), glyphs.size(), context);
    }
}

static void setCGFontRenderingMode(GraphicsContext& context)
{
    RetainPtr<CGContextRef> cgContext = context.platformContext();
    CGContextSetShouldAntialiasFonts(cgContext.get(), true);

    CGAffineTransform contextTransform = CGContextGetCTM(cgContext.get());
    bool isTranslationOrIntegralScale = WTF::isIntegral(contextTransform.a) && WTF::isIntegral(contextTransform.d) && contextTransform.b == 0.f && contextTransform.c == 0.f;
    bool isRotated = ((contextTransform.b || contextTransform.c) && (contextTransform.a || contextTransform.d));
    bool doSubpixelQuantization = isTranslationOrIntegralScale || (!isRotated && context.shouldSubpixelQuantizeFonts());

    CGContextSetShouldSubpixelPositionFonts(cgContext.get(), true);
    CGContextSetShouldSubpixelQuantizeFonts(cgContext.get(), doSubpixelQuantization);
    // V-102 empirical: disabling subpixel positioning on Driftstack does
    // NOT reduce byte-diff vs iPhone (tested: F.3 stayed at 2.27% byte-diff).
    // The ~2% byte-diff at AA edges is NOT from subpixel quantization but
    // from another factor (font hinting / AA gamma curve / color space /
    // CG private flags). Subpixel state restored to upstream behavior.
#if PLATFORM(DRIFTSTACK)
    // V-104 hypothesis: iOS sets CGFontAntialiasingStyle explicitly via
    // FontAntialiasingStateSaver (Source/WebCore/platform/graphics/ios/
    // FontAntialiasingStateSaver.h:64) — portrait → kCGFontAntialiasingStyle
    // Unfiltered (= 0), landscape → kCGFontAntialiasingStyleFilterLight.
    // Mac default is kCGFontAntialiasingStyleUnfilteredCustomDilation
    // (= 8 << 7 = 1024) which applies Mac-specific CustomDilation. The two
    // produce different AA pixel patterns at glyph edges. iPhone 16 Pro
    // archetype is portrait, so set Unfiltered. If this resolves V-097's
    // ~2% byte-diff, F.2-F.7 root cause is the CG AA style flag.
    CGContextSetFontAntialiasingStyle(cgContext.get(), kCGFontAntialiasingStyleUnfiltered);
    // V-653 (2026-05-11): iOS Safari doesn't apply LCD subpixel font
    // smoothing (it's a Mac-only concept tied to LCD/RGB subpixel layout
    // on desktop displays). Fresh CGBitmapContextCreate'd canvas on Mac
    // inherits the system default of shouldSmoothFonts=true /
    // allowsFontSmoothing=true. The state propagation in
    // FontCascadeCoreText::drawGlyphs marks shouldSmoothFonts UNUSED for
    // DRIFTSTACK, so the Mac default leaks through to CTFontDrawGlyphs
    // → CT applies LCD smoothing → text pixels diverge from iPhone's
    // grayscale-AA pixels. Force-disable both Allows + Should so every
    // drawGlyphs path uses non-smoothed glyph rasterization. V-102 tested
    // subpixel-position OFF (no effect) and V-104 locked antialiasing-
    // style; this is the remaining CG flag delta. CGContextSetAllowsFont
    // Smoothing is a CG SPI declared in pal/spi/cg/CoreGraphicsSPI.h.
    CGContextSetAllowsFontSmoothing(cgContext.get(), false);
    CGContextSetShouldSmoothFonts(cgContext.get(), false);
#endif
}

#if PLATFORM(DRIFTSTACK)
// V-666 (2026-05-11): pre-tint an alpha-mask CGImage with the active fill
// color in a CPU bitmap context, then return a tinted CGImage suitable for
// plain CGContextDrawImage onto the canvas backing.
//
// Why V-666 instead of V-633.D (ClipToMask + FillRect) or V-627.B
// (TransparencyLayer + DestinationIn + DrawImage)? Empirical V-660 +
// V-665 showed both V-633.D and V-627.B produce visible pixels but
// diverge from iPhone reference bytes (V-667 characterization: 83%
// precision-drift profile). V-090 emoji's plain DrawImage path produces
// iPhone-bit-identical pixels on GPU canvas — so the V-666 strategy is
// to do the alpha-mask + fill-color composition in a CPU bitmap context
// (where pixel arithmetic is bit-exact) and then blit the result via
// the same plain-DrawImage path V-090 uses.
//
// Algorithm:
//   1. Create CPU bitmap context (sRGB, 8-bit, premultipliedLast)
//   2. Fill with active fill color (premultiplied RGB × alpha is
//      computed exactly in 8-bit)
//   3. DestinationIn blend with the alpha-mask CGImage (keeps fill
//      where mask alpha > 0, clears elsewhere)
//   4. Return CGBitmapContextCreateImage as the tinted CGImage
static RetainPtr<CGImageRef> createTintedAlphaMaskImage(
    CGImageRef alphaMaskImage,
    float fillR, float fillG, float fillB, float fillA,
    size_t width, size_t height)
{
    if (!alphaMaskImage || !width || !height)
        return { };
    auto colorSpace = adoptCF(CGColorSpaceCreateWithName(kCGColorSpaceSRGB));
    if (!colorSpace)
        return { };
    // V-675 (2026-05-11): use ByteOrder32Host + AlphaPremultipliedFirst to
    // match the canvas backing format. Canvas creates contexts with
    // kCGImageAlphaPremultipliedFirst | kCGBitmapByteOrder32Host (per
    // ImageBufferCGBitmapBackend.cpp:74). Avoiding byte-swap during
    // CGContextDrawImage may prevent pixel-conversion precision loss
    // between Mac CG and iOS CG.
    auto ctx = adoptCF(CGBitmapContextCreate(
        nullptr, width, height, 8, width * 4, colorSpace.get(),
        static_cast<uint32_t>(kCGImageAlphaPremultipliedFirst) | static_cast<uint32_t>(kCGBitmapByteOrder32Host)));
    if (!ctx)
        return { };
    CGContextSetRGBFillColor(ctx.get(),
        std::clamp(fillR, 0.f, 1.f),
        std::clamp(fillG, 0.f, 1.f),
        std::clamp(fillB, 0.f, 1.f),
        std::clamp(fillA, 0.f, 1.f));
    CGContextFillRect(ctx.get(), CGRectMake(0, 0, width, height));
    CGContextSetBlendMode(ctx.get(), kCGBlendModeDestinationIn);
    CGContextDrawImage(ctx.get(), CGRectMake(0, 0, width, height), alphaMaskImage);
    return adoptCF(CGBitmapContextCreateImage(ctx.get()));
}
#endif

void FontCascade::drawGlyphs(GraphicsContext& context, const Font& font, std::span<const GlyphBufferGlyph> glyphs, std::span<const GlyphBufferAdvance> advances, const FloatPoint& anchorPoint, FontSmoothingMode smoothingMode)
{
    const auto& platformData = font.platformData();
    if (!platformData.size())
        return;

    if (isInGPUProcess() && font.hasAnyComplexColorFormatGlyphs(glyphs)) {
        ASSERT_NOT_REACHED();
        return;
    }

#if PLATFORM(DRIFTSTACK)
    // V-583.B-DIAG: opt-in glyph trace via DRIFTSTACK_GLYPH_DIAG env var.
    // Off by default; for advance-mismatch root-cause analysis only.
    if (std::getenv("DRIFTSTACK_GLYPH_DIAG")) {
        char psName[256] = {};
        unsigned symTraits = 0;
        if (CTFontRef ctf = platformData.ctFont()) {
            if (RetainPtr<CFStringRef> ps = adoptCF(CTFontCopyPostScriptName(ctf)))
                CFStringGetCString(ps.get(), psName, sizeof(psName), kCFStringEncodingUTF8);
            symTraits = CTFontGetSymbolicTraits(ctf);
        }
        WTFLogAlways("[Driftstack-V583B-DIAG] drawGlyphs anchor=(%.3f,%.3f) ptSize=%.2f n=%zu g0=%u adv0=%.3f adv1=%.3f ps='%s' symTraits=0x%x bold=%d italic=%d synthBold=%.2f",
            (double)anchorPoint.x(), (double)anchorPoint.y(),
            (double)platformData.size(), glyphs.size(),
            glyphs.size() ? static_cast<unsigned>(glyphs[0]) : 0u,
            glyphs.size() ? (double)advances[0].width : 0.0,
            glyphs.size() > 1 ? (double)advances[1].width : 0.0,
            psName, symTraits,
            (symTraits & kCTFontTraitBold) ? 1 : 0,
            (symTraits & kCTFontTraitItalic) ? 1 : 0,
            (double)font.syntheticBoldOffset());
    }

    // V-583.E: ComplexTextController.draw bypasses Font::widthForGlyph (it uses
    // CTRunGetAdvances directly). Result: V-149 ASCII advance overrides + V-094
    // Track 5 emoji-color-glyph overrides + V-143 Apple-Color-Emoji-space-glyph
    // overrides ONLY apply to canvas.measureText, NOT to fillText cursor
    // positioning. To close that gap: at this drawGlyphs entry, replace each
    // advance[i] with the iPhone-canonical value from Font::platformWidthForGlyph
    // (which routes through all existing per-glyph override layers). Subsequent
    // showGlyphsWithAdvances calls + V-582 composite-path position computation
    // use the corrected advances. (Empirical V-405 seed=250 vs iPhone reference:
    // Mac fork's CT cursor reaches emoji 0.6 px later than iPhone's at fontSize=16
    // -apple-system multi-script text — closes when overrides fire here.)
    Vector<GlyphBufferAdvance, 256> driftstackAdvances;
    if (advances.size() == glyphs.size()) {
        driftstackAdvances.reserveInitialCapacity(glyphs.size());
        for (size_t i = 0; i < glyphs.size(); ++i) {
            float iphoneWidth = font.widthForGlyph(glyphs[i], Font::SyntheticBoldInclusion::Exclude);
            // platformWidthForGlyph returns iPhone advance via overrides, OR Mac
            // native advance if no override matches. If the override returned
            // something different from input advance.width, prefer the override.
            // Otherwise keep input (which may include synthetic-bold + other
            // adjustments not in platformWidthForGlyph).
            if (std::abs(iphoneWidth - advances[i].width) > 0.001f) {
                driftstackAdvances.append(GlyphBufferAdvance{ iphoneWidth, advances[i].height });
            } else {
                driftstackAdvances.append(advances[i]);
            }
        }
        // Reassign the span to point at our local vector. Local Vector outlives
        // this function scope so the span is valid for the rest of drawGlyphs.
        advances = driftstackAdvances.span();
    }

    // V-771 / V-770.A.1 — text-run atlas lookup (Rule N v2 Layer A entry).
    // Stub atlas (v1) always misses; emits V-820.A AtlasMiss telemetry.
    // When V-770.A captures fire + atlas binary loads (V-770.A.2 next slice),
    // lookup hits will substitute iPhone canonical alpha directly here.
    {
        // Glyph buffer reinterpretation: GlyphBufferGlyph is a typedef to
        // uint16_t on platforms using CGGlyph; cast safely via WTF helper.
        const auto glyphsU16 = unsafeMakeSpan(
            reinterpret_cast<const uint16_t*>(glyphs.data()), glyphs.size());
        // GlyphBufferAdvance is CGSize on Cocoa platform (GlyphBufferMembers.h);
        // reinterpret the span directly without copying.
        const auto advancesCGSize = unsafeMakeSpan(
            reinterpret_cast<const CGSize*>(advances.data()), advances.size());

        uint16_t fontId = driftstackMapFontToId(font);
        uint16_t ptSize = static_cast<uint16_t>(platformData.size());
        // V-771.B: read source UTF-8 text from thread-local slot set by
        // FontCascade::drawGlyphBuffer. Empty when drawGlyphs is invoked
        // outside the canvas text path (DrawGlyphsRecorder replay, etc.) —
        // hash falls back to glyph-buffer mode.
        StringView sourceText = driftstackCurrentTextSource();
        uint64_t textRunHash = driftstackComputeTextRunHash(
            font, ptSize, sourceText, glyphsU16, advancesCGSize);
        uint8_t positionClass = driftstackComputePositionClass(
            context.platformContext(), anchorPoint);

        // W1092: glyph PIXEL substitution (atlas blit below + the V-790.L
        // per-glyph path) is a CANVAS-fingerprint concern only. drawGlyphs is
        // ALSO the on-screen HTML text path, so substituting there paints
        // canonical glyph images over the visible page → black boxes when
        // browsing real sites (founder report 2026-06-05). Gate both pixel
        // paths on the canvas text-draw scope: outside a canvas draw, the text
        // falls through to native CTFontDrawGlyphs (readable). Canvas reads
        // (getImageData/toDataURL) keep full substitution → fingerprint
        // bit-identity preserved. The advance overrides above stay unconditional
        // (they affect cursor metrics, never pixels, so cause no boxes).
        const bool driftstackCanvasCtx = driftstackInCanvasTextDraw();

        auto& atlas = DriftstackTextRunAtlas::singleton();
        auto atlasResult = atlas.lookup(
            fontId, ptSize, positionClass, textRunHash);
        if (!driftstackCanvasCtx)
            atlasResult.reset(); // on-screen text: never blit atlas pixels

        // V-770.A.5 diag: opt-in trace for synthetic atlas hit verification.
        if (std::getenv("DRIFTSTACK_TEXT_RUN_ATLAS_DIAG")) {
            WTFLogAlways("[Driftstack-V770A] drawGlyphs entry: fontId=%u pt=%u pos=0x%02x hash=0x%016llx text=%.*s sourceLen=%u loaded=%d entries=%u => %s",
                (unsigned)fontId, (unsigned)ptSize, (unsigned)positionClass,
                (unsigned long long)textRunHash,
                (int)std::min<size_t>(64, sourceText.length()),
                sourceText.is8Bit() ? (const char*)sourceText.span8().data() : "(16bit)",
                (unsigned)sourceText.length(),
                atlas.isLoaded() ? 1 : 0, (unsigned)atlas.entryCount(),
                atlasResult.has_value() ? "HIT" : "miss");
        }

        if (atlasResult.has_value()) {
            // V-770.A.4 atlas hit blit: decode the iPhone-canonical PNG
            // alpha mask from the mmap blob (zero-copy) and CGContextDrawImage
            // onto the current cgContext at the anchor point. Return early so
            // the platform CT draw beneath is skipped.
            const auto& entry = atlasResult.value();
            CGContextRef cg = context.platformContext();
            if (cg && entry.pngData && entry.pngSize > 0) {
                RetainPtr<CFDataRef> cfData = adoptCF(CFDataCreateWithBytesNoCopy(
                    kCFAllocatorDefault,
                    entry.pngData,
                    static_cast<CFIndex>(entry.pngSize),
                    kCFAllocatorNull));
                if (cfData) {
                    RetainPtr<CGImageSourceRef> cgSource = adoptCF(
                        CGImageSourceCreateWithData(cfData.get(), nullptr));
                    if (cgSource && CGImageSourceGetCount(cgSource.get()) > 0) {
                        RetainPtr<CGImageRef> cgImage = adoptCF(
                            CGImageSourceCreateImageAtIndex(cgSource.get(), 0, nullptr));
                        if (cgImage) {
                            // Atlas entry is the rendered text run at its
                            // captured canvas dimensions. Composite at the
                            // anchor point in CT's drawing coordinates,
                            // flipping Y because PNG origin is top-left but
                            // canvas anchor is the baseline.
                            const CGFloat imgW = CGImageGetWidth(cgImage.get());
                            const CGFloat imgH = CGImageGetHeight(cgImage.get());
                            // Capture page anchors text at y = round(canvasH*0.75);
                            // atlas top-left == (anchor.x - canvasX_offset, anchor.y - canvasY_offset).
                            // For v1 we approximate: snap to integer pixel,
                            // place top-left at (floor(anchorX) - abbLeft, floor(anchorY) - abbAscent).
                            const float dx = std::floor(anchorPoint.x()) - entry.abbLeft;
                            const float dy = std::floor(anchorPoint.y()) - entry.abbAscent;

                            CGContextSaveGState(cg);
                            // Y-flip: WebKit canvas CGContext is typically top-left
                            // origin (after RenderingMode flip), but for native
                            // pixel-aligned bitmap blit we draw in unflipped
                            // device space. Use CGContextDrawImage with explicit
                            // CGAffineTransform identity (no extra transform).
                            CGContextDrawImage(cg, CGRectMake(dx, dy, imgW, imgH), cgImage.get());
                            CGContextRestoreGState(cg);
                            // Return early — atlas hit completes the draw.
                            return;
                        }
                    }
                }
            }
            // Decode failure: fall through to default Mac CG path (safe).
        } else {
            // Atlas miss: emit V-820.A telemetry.
            AtlasMissEvent e{};
            e.text_run_hash = textRunHash;
            e.font_id = fontId;
            e.pt_size = ptSize;
            e.position_class = positionClass;
            e.archetype_id = 1; // iphone16pro_ios18_bs default
            e.ios_version_packed = (18 << 8) | 6;
            e.timestamp_ms = 0; // V-820.A producer not yet wired to real clock
            driftstackLogAtlasMiss(e);

            // V-790.L per-glyph exact-substitution atlas lookup (Path A2
            // wave 29-141). Sits BEFORE Phase 3 Layer B hook in the
            // pipeline: if atlas hits, use exact iPhone pixels (sha256
            // bit-identical), skip Layer B entirely. Atlas miss → fall
            // through to Layer B Phase 3.B step 2 approximate.
            //
            // Selective-by-N: only N=1 case (single-glyph drawGlyphs
            // calls). Codepoint extracted from sourceText (set by
            // FontCascade::drawGlyphBuffer via driftstackCurrentTextSource()).
            // For N>1 or empty sourceText, atlas lookup is skipped.
            if (driftstackCanvasCtx && glyphs.size() == 1 && sourceText.length() >= 1) {
                // W1092: per-glyph pixel substitution gated to canvas only
                // (same rationale as the atlas blit above — no boxes on-screen).
                // Extract first codepoint from sourceText.
                //
                // Empirical (wave 29-143 diag): sourceText is UTF-8
                // encoded bytes packed into an 8-bit StringView buffer
                // for non-ASCII text. So is8Bit()=true and a single CJK
                // char appears as 3 bytes. We must decode UTF-8.
                //
                // For 16-bit StringView (rare in this codepath), the
                // first u16 is either a codepoint or a high surrogate.
                // We use the first u16 directly (BMP only; surrogate
                // pairs not handled in v1).
                uint32_t cp = 0;
                if (sourceText.is8Bit()) {
                    auto bytes = sourceText.span8();
                    uint8_t b0 = bytes[0];
                    if (b0 < 0x80) {
                        cp = b0; // ASCII
                    } else if ((b0 & 0xE0) == 0xC0 && sourceText.length() >= 2) {
                        // 2-byte UTF-8: 110xxxxx 10xxxxxx
                        cp = (static_cast<uint32_t>(b0 & 0x1F) << 6)
                           | (static_cast<uint32_t>(bytes[1] & 0x3F));
                    } else if ((b0 & 0xF0) == 0xE0 && sourceText.length() >= 3) {
                        // 3-byte UTF-8: 1110xxxx 10xxxxxx 10xxxxxx
                        cp = (static_cast<uint32_t>(b0 & 0x0F) << 12)
                           | (static_cast<uint32_t>(bytes[1] & 0x3F) << 6)
                           | (static_cast<uint32_t>(bytes[2] & 0x3F));
                    } else if ((b0 & 0xF8) == 0xF0 && sourceText.length() >= 4) {
                        // 4-byte UTF-8: 11110xxx 10xxxxxx 10xxxxxx 10xxxxxx
                        cp = (static_cast<uint32_t>(b0 & 0x07) << 18)
                           | (static_cast<uint32_t>(bytes[1] & 0x3F) << 12)
                           | (static_cast<uint32_t>(bytes[2] & 0x3F) << 6)
                           | (static_cast<uint32_t>(bytes[3] & 0x3F));
                    } else {
                        // Malformed or unsupported encoding — skip atlas
                        cp = 0;
                    }
                } else {
                    // V-790.L surrogate pair decode (wave 29-204): 16-bit
                    // StringView may contain UTF-16. Supplementary plane
                    // characters (emoji U+10000..U+10FFFF) encode as
                    // high+low surrogate pairs. Without decoding, lookup
                    // keys on the high surrogate (U+D800..U+DBFF) which
                    // is never in atlas → atlas miss for every emoji.
                    auto span = sourceText.span16();
                    uint16_t u0 = span[0];
                    if (u0 >= 0xD800 && u0 <= 0xDBFF && span.size() >= 2) {
                        uint16_t u1 = span[1];
                        if (u1 >= 0xDC00 && u1 <= 0xDFFF) {
                            cp = 0x10000
                               + ((static_cast<uint32_t>(u0) - 0xD800) << 10)
                               + (static_cast<uint32_t>(u1) - 0xDC00);
                        } else {
                            cp = u0; // malformed; use lead surrogate
                        }
                    } else {
                        cp = u0;
                    }
                }

                if (std::getenv("DRIFTSTACK_PER_GLYPH_ATLAS_DIAG")) {
                    WTFLogAlways("[V-790.L] per-glyph atlas LOOKUP "
                                 "font_id=%u pt_size_q4=%u cp=U+%04x pos=%u "
                                 "(sourceLen=%u, 8bit=%d)",
                                 static_cast<unsigned>(fontId),
                                 static_cast<unsigned>(ptSize * 16),
                                 static_cast<unsigned>(cp),
                                 static_cast<unsigned>(positionClass),
                                 static_cast<unsigned>(sourceText.length()),
                                 sourceText.is8Bit() ? 1 : 0);
                }

                auto& pglyphAtlas = DriftstackPerGlyphAtlas::singleton();
                auto hit = pglyphAtlas.lookup(
                    fontId,
                    static_cast<uint16_t>(ptSize * 16),
                    cp,
                    static_cast<uint32_t>(positionClass));

                // V-790.L proof-of-concept: when exact pos_class missing,
                // fall back to pos_class=0 entry. For (font_id, ptSize, cp)
                // the central glyph rasterization is identical; only
                // sub-pixel AA at the edges differs across pos_classes.
                // pos_class=0 fallback gives ~95% pixel match (vs exact
                // 100% for matching pos_class). v1 atlas only has
                // pos_class=0 entries; later captures will expand.
                if (!hit && positionClass != 0) {
                    hit = pglyphAtlas.lookup(
                        fontId,
                        static_cast<uint16_t>(ptSize * 16),
                        cp,
                        0u);
                    if (hit && std::getenv("DRIFTSTACK_PER_GLYPH_ATLAS_DIAG")) {
                        WTFLogAlways("[V-790.L] per-glyph atlas pos-fallback "
                                     "(actual_pos=%u, used pos=0)",
                                     static_cast<unsigned>(positionClass));
                    }
                }
                // V-790.L-N1 alpha-mask blit (wave 29-203): atlas stores
                // white-bg + black-text grayscale per V-790.L capture pages
                // (ctx.fillStyle='white'; fillRect; ctx.fillStyle='black';
                // fillText). The earlier kCGImageAlphaNone CGContextDrawImage
                // approach overpainted the canvas because it treated atlas as
                // opaque grayscale.
                //
                // Fix: invert atlas pixels (alpha_mask = 255 - atlas_pixel) →
                // CGImage with alpha channel → CGContextClipToMask + fill
                // rect with current fillStyle color. After the mask clip, the
                // canvas's actual fill color paints through the iPhone-
                // canonical alpha-mask shape, producing bit-identical iPhone
                // glyph rasterization on top of arbitrary canvas backgrounds.
                //
                // Env-gate retained (DRIFTSTACK_V790L_N1_SUB=1) for staged
                // rollout. Default OFF; production validation flips ON.
                static const bool v790lN1SubEnabled = std::getenv("DRIFTSTACK_V790L_N1_SUB")
                    && std::getenv("DRIFTSTACK_V790L_N1_SUB")[0] == '1';
                if (hit && v790lN1SubEnabled) {
                    // Invert atlas pixels into a mask buffer. The atlas is
                    // 64x64 grayscale (1 byte per pixel, row-major, row
                    // stride 64). After inversion: pixel=0 means glyph fully
                    // opaque, pixel=255 means background fully transparent —
                    // matches CGContextClipToMask alpha semantics.
                    std::array<uint8_t, 64 * 64> maskBuf;
                    auto atlasPx = unsafeMakeSpan(hit->pixels, 64 * 64);
                    auto maskSpan = unsafeMakeSpan(maskBuf.data(), 64 * 64);
                    for (size_t i = 0; i < 64 * 64; ++i)
                        maskSpan[i] = static_cast<uint8_t>(255 - atlasPx[i]);

                    // Create a CGImage from the mask buffer. Per Apple docs,
                    // CGContextClipToMask accepts either an alpha-only mask
                    // image OR a grayscale image (treated as alpha).
                    RetainPtr<CFDataRef> maskData = adoptCF(CFDataCreate(
                        kCFAllocatorDefault, maskBuf.data(),
                        64 * 64));
                    RetainPtr<CGDataProviderRef> dataProvider = adoptCF(
                        CGDataProviderCreateWithCFData(maskData.get()));
                    RetainPtr<CGImageRef> maskImg = adoptCF(CGImageMaskCreate(
                        64, 64, 8, 8, 64,
                        dataProvider.get(),
                        nullptr, false));
                    if (maskImg) {
                        CGContextRef destCG = context.platformContext();
                        CGContextSaveGState(destCG);
                        // CGContextClipToMask applies mask in current
                        // transform coordinates. Anchor at glyph position
                        // (top-left of 64x64 box).
                        CGRect dstRect = CGRectMake(
                            anchorPoint.x() - 32.0,
                            anchorPoint.y() - 32.0 + static_cast<CGFloat>(ptSize) / 2.0,
                            64, 64);
                        CGContextClipToMask(destCG, dstRect, maskImg.get());
                        // Fill the rect with current fillStyle color. This
                        // paints through the mask: where mask=0 (former
                        // atlas pixel=255=white-bg) → no paint; where mask=
                        // 255 (former atlas pixel=0=black-text) → paint.
                        CGContextFillRect(destCG, dstRect);
                        CGContextRestoreGState(destCG);
                        WTFLogAlways("[V-790.L] per-glyph atlas HIT "
                                     "font_id=%u pt=%u cp=U+%04x pos=%u "
                                     "— alpha-mask iPhone substitution",
                                     static_cast<unsigned>(fontId),
                                     static_cast<unsigned>(ptSize),
                                     static_cast<unsigned>(cp),
                                     static_cast<unsigned>(positionClass));
                        return; // skip Layer B + platform CT raster
                    }
                }
            }

            // V-790.L Phase 3.C N=2+ multi-glyph extension (wave 29-174).
            // Iterates per-glyph atlas lookup using UTF-8 sourceText decode +
            // cumulative advance positioning. All-hits substitute all glyphs
            // via per-glyph blit and return early. Partial-hits or no-hits
            // fall through to existing V-655 / V-583K-text / Mac CT dispatch.
            //
            // Multi-glyph dispatch is gated on glyphs.size() >= 2 to avoid
            // re-firing for the N=1 case already handled above. Same
            // pos_class fallback to 0 applies per-glyph.
            if (glyphs.size() >= 2 && sourceText.length() >= 1) {
                struct V790LPlan {
                    bool hit;
                    uint32_t cp;
                    const uint8_t* pixels; // raw 64x64 atlas pixels, mmap-stable
                };
                Vector<V790LPlan, 256> v790lPlans;
                v790lPlans.reserveInitialCapacity(glyphs.size());

                // UTF-8 decode iterator over sourceText
                size_t srcIdx = 0;
                auto decodeNextCp = [&]() -> uint32_t {
                    uint32_t cp = 0;
                    if (sourceText.is8Bit()) {
                        auto bytes = sourceText.span8();
                        if (srcIdx >= bytes.size())
                            return 0;
                        uint8_t b0 = bytes[srcIdx];
                        if (b0 < 0x80) {
                            cp = b0;
                            srcIdx += 1;
                        } else if ((b0 & 0xE0) == 0xC0 && srcIdx + 1 < bytes.size()) {
                            cp = (static_cast<uint32_t>(b0 & 0x1F) << 6)
                               | (static_cast<uint32_t>(bytes[srcIdx + 1] & 0x3F));
                            srcIdx += 2;
                        } else if ((b0 & 0xF0) == 0xE0 && srcIdx + 2 < bytes.size()) {
                            cp = (static_cast<uint32_t>(b0 & 0x0F) << 12)
                               | (static_cast<uint32_t>(bytes[srcIdx + 1] & 0x3F) << 6)
                               | (static_cast<uint32_t>(bytes[srcIdx + 2] & 0x3F));
                            srcIdx += 3;
                        } else if ((b0 & 0xF8) == 0xF0 && srcIdx + 3 < bytes.size()) {
                            cp = (static_cast<uint32_t>(b0 & 0x07) << 18)
                               | (static_cast<uint32_t>(bytes[srcIdx + 1] & 0x3F) << 12)
                               | (static_cast<uint32_t>(bytes[srcIdx + 2] & 0x3F) << 6)
                               | (static_cast<uint32_t>(bytes[srcIdx + 3] & 0x3F));
                            srcIdx += 4;
                        } else {
                            cp = 0;
                            srcIdx += 1;
                        }
                    } else {
                        auto u16 = sourceText.span16();
                        if (srcIdx >= u16.size())
                            return 0;
                        cp = static_cast<uint32_t>(u16[srcIdx]);
                        srcIdx += 1;
                    }
                    return cp;
                };

                auto& v790lPglyphAtlas = DriftstackPerGlyphAtlas::singleton();
                unsigned v790lHits = 0;
                // V-790.L Task #16: PER-GLYPH sub-pixel phase. Each glyph in the run
                // sits at a DIFFERENT cursor position → different sub-pixel phase, so
                // look up each at its OWN cursor's THIRDS phase (xBin=floor(xfrac*3) at
                // 1/3,2/3; yBin=integer-vs-fractional) rather than the per-run anchor
                // phase. The anchor-phase-for-all bug (+ pos=0-only atlas) is why the
                // wave-29-175 N≥2 substitution worsened byte-delta and was disabled;
                // composition is proven EXACT (compose==run, iPhone+fork) with the
                // correct per-glyph phase. Self-contained to this loop; the substitution
                // stays gated behind DRIFTSTACK_V790L_MULTI_SUB (default OFF).
                CGAffineTransform v790lCtm = CGContextGetCTM(context.platformContext());
                FloatPoint v790lCursor = anchorPoint;
                auto v790lPhaseAt = [&](const FloatPoint& pt) -> uint32_t {
                    CGPoint dev = CGPointApplyAffineTransform(CGPointMake(pt.x(), pt.y()), v790lCtm);
                    double xf = dev.x - std::floor(dev.x), yf = dev.y - std::floor(dev.y);
                    int xb = static_cast<int>(std::floor(std::min(xf, 0.99999) * 3.0)); // thirds: 0,1,2
                    int yb = (yf > 1e-4) ? 1 : 0;                                        // integer-y vs fractional-y
                    return static_cast<uint32_t>((yb << 4) | xb);
                };
                for (size_t i = 0; i < glyphs.size(); ++i) {
                    V790LPlan p { false, 0, nullptr };
                    p.cp = decodeNextCp();
                    uint32_t pgPos = v790lPhaseAt(v790lCursor);
                    if (p.cp > 0) {
                        auto hit = v790lPglyphAtlas.lookup(
                            fontId,
                            static_cast<uint16_t>(ptSize * 16),
                            p.cp,
                            pgPos);
                        if (!hit && pgPos != 0) {
                            hit = v790lPglyphAtlas.lookup(
                                fontId,
                                static_cast<uint16_t>(ptSize * 16),
                                p.cp,
                                0u);
                        }
                        if (hit) {
                            p.hit = true;
                            p.pixels = hit->pixels;
                            ++v790lHits;
                        }
                    }
                    v790lPlans.append(p);
                    v790lCursor.move(advances[i].width, advances[i].height);
                }

                static unsigned v790lMultiLog = 0;
                if (++v790lMultiLog <= 20) {
                    WTFLogAlways("[Driftstack-V790L-MULTI] fontId=%u pt=%u n=%zu hits=%u",
                        static_cast<unsigned>(fontId),
                        static_cast<unsigned>(ptSize),
                        glyphs.size(), v790lHits);
                }

                // Substitute IFF all glyphs hit. Partial-hit case is more complex
                // (need to render misses via Mac CT at correct positions); leaving
                // partial fall-through to existing V-655/V-583K-text dispatch.
                //
                // V-790.L atlas pixels: 64x64 8-bit gray, 0=black-text 255=white-bg
                // (per v790l-cjk-fullrange-capture.html: ctx.fillStyle='white';
                // fillRect; fillStyle='black'; fillText). To substitute correctly
                // on V-405's colored canvas:
                //   alpha[y,x] = 255 - pixel[y,x]   (text=opaque, bg=transparent)
                //   draw alpha mask, fill with V-405's current fillStyle color.
                //
                // V-790.L-DISABLED (wave 29-175): empirical findings:
                // - alpha-mask substitution at corrected positioning produces
                //   AVG byte delta 1267 (worse than 200-500 baseline without
                //   Phase 3.C). Likely subpixel AA / glyph shaping divergence
                //   between Mac CT and iPhone CT (V-705 territory).
                // - Substitution OFF restores 397/500 → 400/500 baseline.
                // - Phase 3.C dispatch + logging remain (proves infrastructure).
                static const bool v790lMultiSubEnabled = std::getenv("DRIFTSTACK_V790L_MULTI_SUB")
                    && std::getenv("DRIFTSTACK_V790L_MULTI_SUB")[0] == '1';
                if (driftstackCanvasCtx && v790lMultiSubEnabled && v790lHits == glyphs.size()) {
                    CGContextRef destCG = context.platformContext();

                    // V-790.L probe positioning (v790l-cjk-fullrange-capture.html):
                    //   canvas 64×64; ctx.fillText(ch, 32 - ptSize/2 + xFrac, 40 + yFrac)
                    // → glyph LEFT edge at x = 32 - ptSize/2
                    // → glyph BASELINE at y = 40
                    // To align with fork's cursor (baseline origin):
                    //   PNG.x = cursor.x() - (32 - ptSize/2)
                    //   PNG.y = cursor.y() - 40
                    const CGFloat anchorXOffset = 32.0 - static_cast<CGFloat>(ptSize) / 2.0;
                    const CGFloat anchorYOffset = 40.0;

                    FloatPoint cursor = anchorPoint;
                    for (size_t i = 0; i < glyphs.size(); ++i) {
                        std::array<uint8_t, 64 * 64> alphaMask;
                        auto src = unsafeMakeSpan(v790lPlans[i].pixels, 64 * 64);
                        for (size_t k = 0; k < 64 * 64; ++k)
                            alphaMask[k] = 255 - src[k];

                        RetainPtr<CGContextRef> maskCtx = adoptCF(
                            CGBitmapContextCreate(
                                alphaMask.data(),
                                64, 64, 8, 64,
                                nullptr,
                                kCGImageAlphaOnly));
                        if (!maskCtx) {
                            cursor.move(advances[i].width, advances[i].height);
                            continue;
                        }
                        RetainPtr<CGImageRef> maskImg = adoptCF(
                            CGBitmapContextCreateImage(maskCtx.get()));
                        if (!maskImg) {
                            cursor.move(advances[i].width, advances[i].height);
                            continue;
                        }

                        // Position PNG top-left at (cursor.x - anchorXOffset, cursor.y - anchorYOffset)
                        // Use V-655 mask-tint pattern: translate + Y-flip + clip + fill.
                        const CGFloat drawX = cursor.x() - anchorXOffset;
                        const CGFloat drawY = cursor.y() - anchorYOffset;
                        CGContextSaveGState(destCG);
                        CGContextTranslateCTM(destCG, drawX, drawY);
                        CGContextTranslateCTM(destCG, 0.f, 64.f);
                        CGContextScaleCTM(destCG, 1.f, -1.f);
                        CGContextClipToMask(destCG,
                            CGRectMake(0.f, 0.f, 64.f, 64.f), maskImg.get());
                        CGContextFillRect(destCG,
                            CGRectMake(0.f, 0.f, 64.f, 64.f));
                        CGContextRestoreGState(destCG);

                        cursor.move(advances[i].width, advances[i].height);
                    }
                    static unsigned v790lMultiSubLog = 0;
                    if (++v790lMultiSubLog <= 20) {
                        WTFLogAlways("[Driftstack-V790L-MULTI-SUB] all %zu glyphs substituted via alpha-mask (fontId=%u pt=%u)",
                            glyphs.size(),
                            static_cast<unsigned>(fontId),
                            static_cast<unsigned>(ptSize));
                    }
                    return; // skip Layer B + platform CT raster
                }
            }

            // Layer B v1 per-glyph ML delta predictor REMOVED 2026-05-29 (founder:
            // "drop the ML"). Superseded by the finite-phase text atlas (V-790.L above
            // + the thirds-keyed run atlas); BS-confirmed the sub-pixel phase space is
            // finite, so an exact phase-keyed atlas replaces approximate ML inference.
        }
    }
#endif

    RetainPtr<CGContextRef> cgContext = context.platformContext();

    if (!font.allowsAntialiasing())
        smoothingMode = FontSmoothingMode::None;

    bool shouldAntialias = true;
    bool shouldSmoothFonts = true;

    switch (smoothingMode) {
    case FontSmoothingMode::Antialiased:
        shouldSmoothFonts = false;
        break;
    case FontSmoothingMode::Auto:
    case FontSmoothingMode::SubpixelAntialiased:
        break;
    case FontSmoothingMode::None:
        shouldAntialias = false;
        shouldSmoothFonts = false;
        break;
    }

#if PLATFORM(IOS_FAMILY) || PLATFORM(DRIFTSTACK)
    UNUSED_VARIABLE(shouldSmoothFonts);
#else
    bool originalShouldUseFontSmoothing = CGContextGetShouldSmoothFonts(cgContext.get());
    if (shouldSmoothFonts != originalShouldUseFontSmoothing)
        CGContextSetShouldSmoothFonts(cgContext.get(), shouldSmoothFonts);
#endif

    bool originalShouldAntialias = CGContextGetShouldAntialias(cgContext.get());
    if (shouldAntialias != originalShouldAntialias)
        CGContextSetShouldAntialias(cgContext.get(), shouldAntialias);

    FloatPoint point = anchorPoint;

    auto textMatrix = computeOverallTextMatrix(font);
    ScopedTextMatrix restorer(textMatrix, cgContext.get());

    setCGFontRenderingMode(context);
    CGContextSetFontSize(cgContext.get(), platformData.size());

    auto shadow = context.dropShadow();

    AffineTransform contextCTM = context.getCTM();
    float syntheticBoldOffset = font.syntheticBoldOffset();
    if (syntheticBoldOffset && !contextCTM.isIdentityOrTranslationOrFlipped()) {
        FloatSize horizontalUnitSizeInDevicePixels = contextCTM.mapSize(FloatSize(1, 0));
        float horizontalUnitLengthInDevicePixels = sqrtf(horizontalUnitSizeInDevicePixels.width() * horizontalUnitSizeInDevicePixels.width() + horizontalUnitSizeInDevicePixels.height() * horizontalUnitSizeInDevicePixels.height());
        if (horizontalUnitLengthInDevicePixels) {
            // Make sure that a scaled down context won't blow up the gap between the glyphs.
            syntheticBoldOffset = std::min(syntheticBoldOffset, syntheticBoldOffset / horizontalUnitLengthInDevicePixels);
        }
    };

    bool hasSimpleShadow = context.textDrawingMode() == TextDrawingMode::Fill && shadow && shadow->color.isValid() && !shadow->radius && !platformData.isColorBitmapFont() && (!context.shadowsIgnoreTransforms() || contextCTM.isIdentityOrTranslationOrFlipped()) && !context.isInTransparencyLayer();
    if (hasSimpleShadow) {
        // Paint simple shadows ourselves instead of relying on CG shadows, to avoid losing subpixel antialiasing.
        context.clearDropShadow();
        Color fillColor = context.fillColor();
        Color shadowFillColor = shadow->color.colorWithAlphaMultipliedBy(fillColor.alphaAsFloat());
        context.setFillColor(shadowFillColor);
        auto shadowTextOffset = point + context.platformShadowOffset(shadow->offset);
        showGlyphsWithAdvances(shadowTextOffset, font, cgContext.get(), glyphs, advances, textMatrix);
        if (syntheticBoldOffset) {
            shadowTextOffset.move(syntheticBoldOffset, 0);
            showGlyphsWithAdvances(shadowTextOffset, font, cgContext.get(), glyphs, advances, textMatrix);
        }
        context.setFillColor(fillColor);
    }

#if PLATFORM(DRIFTSTACK)
    // V-090 / Phase F.1.B-2: composite atlas-rendered emoji bitmaps in
    // place of CT-rendered color glyphs. V-655 (2026-05-11) extends this
    // block to ALSO dispatch text-atlas substitutions when a mixed
    // text+emoji run has any emoji-atlas hit (V-632 coexistence gap fix).
    // Classification per glyph: EMOJI_HIT | TEXT_HIT | PASSTHROUGH. The
    // standalone V-583.K-text block below still serves the emoji-free
    // case so this refactor is incremental.
    bool didCompositePath = false;
    // W1092: the emoji/text glyph-atlas composite dispatch substitutes iPhone
    // glyph pixels — a CANVAS-fingerprint concern only. Gate on the canvas
    // text-draw scope so on-screen HTML text skips it and renders natively
    // (no black boxes); canvas reads still composite → bit-identity preserved.
    if (driftstackInCanvasTextDraw()) {
        auto& emojiAtlas = DriftstackEmojiAtlas::singleton();
        // V-655: text-atlas state available for unified dispatch.
        static const bool v655TextAtlasEnabled = std::getenv("DRIFTSTACK_TEXT_ATLAS")
            && std::getenv("DRIFTSTACK_TEXT_ATLAS")[0] == '1';
        auto& v655TextAtlas = DriftstackTextGlyphAtlas::singleton();
        const bool v655UseText = v655TextAtlasEnabled && v655TextAtlas.isAvailable();
        // V-CANVAS-EMOJI-CG (2026-05-29): the standalone per-glyph DriftstackEmojiAtlas
        // is DEPRECATED + DISABLED by default. Its captured PNGs have OPAQUE WHITE
        // backgrounds (not transparent) and the glyph fills the whole 2*strike+8 canvas,
        // so the composite draws an oversized emoji inside a white box (empirically
        // 2060px divergence vs real iPhone, ~1.5x oversize + white halo). Letting CG
        // render the emoji natively from the iOS AppleColorEmoji font is the CORRECT
        // size/design (bbox within 1px of iPhone, 805px residual = color-glyph bitmap
        // downscale AA — the same class as the text-AA limit). True bit-identical emoji
        // comes from the op-seq whole-canvas auto-learn atlas (V-510), exactly like text
        // and the rest of canvas — not this brittle per-glyph subsystem. Re-enable the
        // legacy path with DRIFTSTACK_PERGLYPH_EMOJI=1 only if the atlas is re-captured
        // with transparent backgrounds + correct glyph metrics.
        static const bool s_perGlyphEmojiEnabled = std::getenv("DRIFTSTACK_PERGLYPH_EMOJI")
            && std::getenv("DRIFTSTACK_PERGLYPH_EMOJI")[0] == '1';
        if (emojiAtlas.isAvailable() && (s_perGlyphEmojiEnabled || v655UseText)) {
            const float ptSize = font.platformData().size();
            const uint32_t strike = emojiAtlas.pickStrikeForPointSize(ptSize);
            const uint16_t ptSizeRound = static_cast<uint16_t>(std::round(ptSize));
            const uint16_t v655FontId = v655UseText
                ? DriftstackTextGlyphAtlas::fontIdForFamily(font.platformData().familyName())
                : UINT16_MAX;

            // Pass 1: classify each glyph (emoji-atlas-hit | text-atlas-hit | passthrough).
            // perGlyphStrike: V-583.B per-ptSize override path uses strike==ptSize
            // (no downscale). Default strike from pickStrikeForPointSize otherwise.
            // V-655: textHit + textCp + textBytes for text-atlas substitution.
            struct GlyphPlan {
                bool atlasHit; // emoji
                uint32_t cp;
                std::span<const uint8_t> pngBytes;
                uint32_t perGlyphStrike;
                bool textHit;
                uint32_t textCp;
                std::span<const uint8_t> textPngBytes;
            };
            Vector<GlyphPlan, 256> plans;
            plans.reserveInitialCapacity(glyphs.size());
            bool anyAtlasHit = false; // any emoji hit — gates dispatch
            unsigned v655TextHitCount = 0;
            for (size_t i = 0; i < glyphs.size(); ++i) {
                GlyphPlan p { false, 0, { }, strike, false, 0, { } };
                Glyph g = glyphs[i];
                if (font.colorGlyphType(g) == ColorGlyphType::Color) {
                    char32_t cp = font.driftstackCodepointForColorGlyph(g);
                    // V-106: Per Unicode TR51, all BMP emoji codepoints
                    // (≤ U+FFFF) have Emoji_Presentation=False — they default
                    // to TEXT presentation and require VS-16 (U+FE0F) to
                    // render as color. iPhone Safari respects this: bare
                    // U+2764 renders monochrome text-heart. Mac CT, when
                    // sans-serif primary font lacks the glyph, falls back to
                    // Apple Color Emoji which returns a Color glyph for the
                    // same bare codepoint — F.1.B-2 then substitutes via
                    // atlas, producing a color heart that diverges from
                    // iPhone (V-095 U+2764 ❤ failure). Skipping BMP entries
                    // here lets CT's fallback render via showGlyphsWithAdvances
                    // (text or color, whatever CT shaped) — matches iPhone for
                    // bare-codepoint case. BMP+VS-16 sequences are routed
                    // through the composite atlas (F.1.B-5/6), not this path.
                    if (s_perGlyphEmojiEnabled && cp > 0xFFFF) {
                        auto entry = emojiAtlas.entryForCodepointAndStrike(static_cast<uint32_t>(cp), strike);
                        if (!entry.empty()) {
                            p.atlasHit = true;
                            p.cp = static_cast<uint32_t>(cp);
                            p.pngBytes = entry;
                            anyAtlasHit = true;
                        }
                    }
                }
                // V-655: if not emoji-atlas-hit, check text atlas.
                if (!p.atlasHit && v655UseText && v655FontId != UINT16_MAX) {
                    char32_t tcp = font.driftstackCodepointForTextGlyph(g);
                    if (tcp) {
                        auto bytes = v655TextAtlas.lookup(v655FontId, ptSizeRound, static_cast<uint32_t>(tcp));
                        if (!bytes.empty()) {
                            p.textHit = true;
                            p.textCp = static_cast<uint32_t>(tcp);
                            p.textPngBytes = bytes;
                            ++v655TextHitCount;
                        }
                    }
                }
                plans.append(p);
            }

            if (anyAtlasHit) {
                didCompositePath = true;
                int hitCount = 0;
                for (auto& p : plans) if (p.atlasHit) ++hitCount;
                WTFLogAlways("[Driftstack-V582] EmojiAtlas dispatch fired: %d/%zu emoji + %u/%zu text atlas-HIT (pid=%d, prog=%s, ptSize=%.1f, strike=%u)",
                    hitCount, glyphs.size(), v655TextHitCount, glyphs.size(), (int)getpid(), getprogname(), (double)ptSize, strike);
                // Compute glyph positions in CTM coords (no text-matrix flip).
                Vector<CGPoint, 256> positions;
                positions.reserveInitialCapacity(glyphs.size());
                FloatPoint cursor = point;
                for (size_t i = 0; i < glyphs.size(); ++i) {
                    positions.append(CGPointMake(cursor.x(), cursor.y()));
                    // GlyphBufferAdvance is CGSize on cocoa; .width/.height are fields, not methods.
                    cursor.move(advances[i].width, advances[i].height);
                }

                // Pass 2: emit non-atlas glyphs via showGlyphsWithAdvances in
                // contiguous CT runs; atlas-hit glyphs via CGContextDrawImage.
                Vector<GlyphBufferGlyph, 64> ctRunGlyphs;
                Vector<GlyphBufferAdvance, 64> ctRunAdvances;
                FloatPoint ctRunStart = point;

                auto flushCTRun = [&]() {
                    if (ctRunGlyphs.isEmpty())
                        return;
                    showGlyphsWithAdvances(ctRunStart, font, cgContext.get(),
                        ctRunGlyphs.span(), ctRunAdvances.span(), textMatrix);
                    ctRunGlyphs.clear();
                    ctRunAdvances.clear();
                };

                // V-655: text-atlas mask-tint constants (mirror V-583.K-text block).
                static bool v655s_v633dEnabled = []() {
                    const char* env = getenv("DRIFTSTACK_V633D");
                    return env && env[0] == '1';
                }();
                const float v655CanvasW = ptSize * 4.0f;
                const float v655CanvasH = ptSize * 3.0f;
                const float v655BearingX = ptSize * 0.5f;
                const float v655BaselineY = ptSize * 2.0f;

                for (size_t i = 0; i < glyphs.size(); ++i) {
                    if (!plans[i].atlasHit && !plans[i].textHit) {
                        if (ctRunGlyphs.isEmpty())
                            ctRunStart = FloatPoint(positions[i].x, positions[i].y);
                        ctRunGlyphs.append(glyphs[i]);
                        ctRunAdvances.append(advances[i]);
                        continue;
                    }
                    flushCTRun();
                    if (plans[i].atlasHit) {
                        // Emoji-atlas path (V-090 original).
                        // Atlas image: canvas dim = 2*strike + 8 (per atlas capture spec).
                        // Glyph drawn at (4, strike + 2) within canvas. Scale strike → ptSize.
                        // V-583.B: per-glyph strike (== ptSize for override entries → scale=1.0).
                        const uint32_t glyphStrike = plans[i].perGlyphStrike;
                        RetainPtr<CGImageRef> image = font.driftstackAtlasImageForCodepoint(plans[i].cp, glyphStrike, plans[i].pngBytes);
                        if (!image)
                            continue;
                        const float canvasDim = 2.0f * static_cast<float>(glyphStrike) + 8.0f;
                        const float scale = ptSize / static_cast<float>(glyphStrike);
                        const float imageDim = canvasDim * scale;
                        const float originXOffset = -4.0f * scale;
                        const float originYOffset = -(static_cast<float>(glyphStrike) + 2.0f) * scale;
                        // WebKit canonical "draw image right-side-up in Y-down CTM" pattern,
                        // mirroring GraphicsContextCG::drawNativeImage (lines 415-433).
                        CGContextSaveGState(cgContext.get());
                        CGContextTranslateCTM(cgContext.get(),
                            positions[i].x + originXOffset,
                            positions[i].y + originYOffset);
                        CGContextTranslateCTM(cgContext.get(), 0.f, imageDim);
                        CGContextScaleCTM(cgContext.get(), 1.f, -1.f);
                        CGContextDrawImage(cgContext.get(), CGRectMake(0.f, 0.f, imageDim, imageDim), image.get());
                        CGContextRestoreGState(cgContext.get());
                    } else {
                        // V-655: text-atlas mask-tint path (mirror V-583.K-text block).
                        RetainPtr<CGImageRef> image = font.driftstackTextAtlasImageForCodepoint(
                            plans[i].textCp, ptSizeRound, plans[i].textPngBytes);
                        if (!image)
                            continue;
                        float drawX = positions[i].x - v655BearingX;
                        float drawY = positions[i].y - v655BaselineY;
                        // V-666 (2026-05-11, env-gated DRIFTSTACK_V666=1):
                        // pre-tint alpha-mask in CPU bitmap context to bit-
                        // exact RGBA8 premultiplied, then plain DrawImage
                        // (V-090 emoji proven flush path on GPU canvas).
                        static bool v655UseV666 = []() {
                            // V-TEXT-BLACKCORNERS (2026-05-28): V-666 is the only composition that
                            // masks the alpha correctly — the V-627.B DestinationIn default and the
                            // V-633.D ClipToMask alternative both fill the whole glyph rect (solid
                            // fill, empirically 2486 vs 5 opaque). So V-666 is default-ON; opt OUT
                            // with DRIFTSTACK_V666=0. (Whole path is gated on DRIFTSTACK_TEXT_ATLAS,
                            // OFF in prod, so this cannot affect the atlas-OFF 1690/0 baseline.)
                            const char* env = getenv("DRIFTSTACK_V666");
                            return !env || env[0] != '0';
                        }();
                        CGContextSaveGState(cgContext.get());
                        CGContextTranslateCTM(cgContext.get(), drawX, drawY);
                        CGContextTranslateCTM(cgContext.get(), 0.f, v655CanvasH);
                        CGContextScaleCTM(cgContext.get(), 1.f, -1.f);
                        if (v655UseV666) {
                            auto [fr, fg, fb, fa] = context.fillColor()
                                .toResolvedColorComponentsInColorSpace(ColorSpace::SRGB);
                            RetainPtr<CGImageRef> tinted = createTintedAlphaMaskImage(
                                image.get(), fr, fg, fb, fa,
                                static_cast<size_t>(v655CanvasW),
                                static_cast<size_t>(v655CanvasH));
                            if (tinted) {
                                CGContextDrawImage(cgContext.get(),
                                    CGRectMake(0.f, 0.f, v655CanvasW, v655CanvasH),
                                    tinted.get());
                            }
                        } else if (v655s_v633dEnabled) {
                            CGContextClipToMask(cgContext.get(),
                                CGRectMake(0.f, 0.f, v655CanvasW, v655CanvasH), image.get());
                            CGContextFillRect(cgContext.get(),
                                CGRectMake(0.f, 0.f, v655CanvasW, v655CanvasH));
                        } else {
                            CGContextBeginTransparencyLayer(cgContext.get(), nullptr);
                            CGContextFillRect(cgContext.get(),
                                CGRectMake(0.f, 0.f, v655CanvasW, v655CanvasH));
                            CGContextSetBlendMode(cgContext.get(), kCGBlendModeDestinationIn);
                            CGContextDrawImage(cgContext.get(),
                                CGRectMake(0.f, 0.f, v655CanvasW, v655CanvasH), image.get());
                            CGContextEndTransparencyLayer(cgContext.get());
                        }
                        CGContextRestoreGState(cgContext.get());
                    }
                }
                flushCTRun();
            }
        }
    }
    // V-583.K-text Phase 3c: PNG substitution dispatch for text glyphs.
    // For each atlas-hit glyph, decode captured PNG → CGImage → draw at glyph
    // anchor (baseline-aligned via per-glyph metrics in atlas index). Misses
    // (codepoint not in atlas) fall through to CT.
    //
    // Captured canvas convention (v583k-comprehensive-glyph.html):
    //   canvasW = ptSize * 4, canvasH = ptSize * 3
    //   text drawn at (ptSize * 0.5, ptSize * 2), textBaseline='alphabetic'
    // Anchor: PNG top-left at (px - ptSize*0.5, py - ptSize*2) where (px, py)
    // is WebKit glyph baseline position.
    bool didTextAtlasPath = false;
    // V-583.K-text Phase 3c dispatch is OPT-IN via DRIFTSTACK_TEXT_ATLAS=1.
    // HISTORY: early captured PNGs encoded an OPAQUE white background, so
    // stamping each PNG over a non-white canvas overpainted the surrounding
    // pattern with white (atlas-ON L1 distance -166% to -5938% vs atlas-OFF on
    // V-405 text seeds) — the "black/filled corners" artifact.
    // RESOLVED 2026-05-28: every current atlas .bin is now a transparent-bg
    // anti-aliased coverage mask — empirically decoded (per-glyph + all 3
    // text-run atlases: alpha 0..216, zero white-opaque px; see V-TEXT-
    // BLACKCORNERS RESOLVED in operations/verification-log.md). The white-bg
    // defect no longer exists in the data. Dispatch nonetheless stays default-
    // OFF pending a fresh atlas-ON cumrig re-score (to confirm the
    // -166%..-5938% divergence is gone now that the data is alpha-correct) plus
    // founder sign-off on the V-405 Text-surface closure. Do NOT flip this gate
    // without that re-score.
    static const bool textAtlasEnabled = std::getenv("DRIFTSTACK_TEXT_ATLAS")
        && std::getenv("DRIFTSTACK_TEXT_ATLAS")[0] == '1';
    // W1092: standalone text glyph-atlas substitution is canvas-only (same
    // rationale as the composite block above — no boxes on on-screen HTML text).
    if (driftstackInCanvasTextDraw() && !didCompositePath && textAtlasEnabled) {
        auto& textAtlas = DriftstackTextGlyphAtlas::singleton();
        if (textAtlas.isAvailable() && glyphs.size() > 0) {
            const String& familyName = font.platformData().familyName();
            uint16_t fontId = DriftstackTextGlyphAtlas::fontIdForFamily(familyName);
            const float ptSize = font.platformData().size();
            const uint16_t ptSizeRound = static_cast<uint16_t>(std::round(ptSize));
            if (fontId != UINT16_MAX) {
                // Classify each glyph.
                struct TextPlan {
                    bool atlasHit;
                    char32_t codepoint;
                    std::span<const uint8_t> pngBytes;
                };
                Vector<TextPlan, 256> textPlans;
                textPlans.reserveInitialCapacity(glyphs.size());
                unsigned hits = 0;
                for (auto g : glyphs) {
                    TextPlan tp { false, 0, { } };
                    char32_t cp = font.driftstackCodepointForTextGlyph(g);
                    if (cp) {
                        tp.codepoint = cp;
                        auto bytes = textAtlas.lookup(fontId, ptSizeRound, static_cast<uint32_t>(cp));
                        if (!bytes.empty()) {
                            tp.atlasHit = true;
                            tp.pngBytes = bytes;
                            ++hits;
                        }
                    }
                    textPlans.append(tp);
                }
                if (hits > 0) {
                    didTextAtlasPath = true;
                    static unsigned logCount = 0;
                    if (++logCount <= 20) {
                        WTFLogAlways("[Driftstack-V583K-text] PNG-substitute family='%s' fontId=%u ptSize=%u hits=%u/%zu",
                            familyName.utf8().data(), fontId, ptSizeRound, hits, glyphs.size());
                    }
                    // Compute per-glyph positions.
                    Vector<CGPoint, 256> textPositions;
                    textPositions.reserveInitialCapacity(glyphs.size());
                    FloatPoint cursor = point;
                    for (size_t i = 0; i < glyphs.size(); ++i) {
                        textPositions.append(CGPointMake(cursor.x(), cursor.y()));
                        cursor.move(advances[i].width, advances[i].height);
                    }
                    // Two-pass: flush CT runs between atlas hits.
                    Vector<GlyphBufferGlyph, 64> textCTRunGlyphs;
                    Vector<GlyphBufferAdvance, 64> textCTRunAdvances;
                    FloatPoint textCTRunStart = point;
                    auto flushTextCTRun = [&]() {
                        if (textCTRunGlyphs.isEmpty())
                            return;
                        showGlyphsWithAdvances(textCTRunStart, font, cgContext.get(),
                            textCTRunGlyphs.span(), textCTRunAdvances.span(), textMatrix);
                        textCTRunGlyphs.clear();
                        textCTRunAdvances.clear();
                    };
                    const float canvasW = ptSize * 4.0f;
                    const float canvasH = ptSize * 3.0f;
                    const float bearingX = ptSize * 0.5f;
                    const float baselineY = ptSize * 2.0f;
                    for (size_t i = 0; i < glyphs.size(); ++i) {
                        if (!textPlans[i].atlasHit) {
                            if (textCTRunGlyphs.isEmpty())
                                textCTRunStart = FloatPoint(textPositions[i].x, textPositions[i].y);
                            textCTRunGlyphs.append(glyphs[i]);
                            textCTRunAdvances.append(advances[i]);
                            continue;
                        }
                        flushTextCTRun();
                        // V-583.K-text Phase 3d: cache decoded PNG → CGImage.
                        RetainPtr<CGImageRef> image = font.driftstackTextAtlasImageForCodepoint(
                            static_cast<uint32_t>(textPlans[i].codepoint), ptSizeRound, textPlans[i].pngBytes);
                        // V-633.A diagnostic — confirm image-decode success rate;
                        // cap at 30 lines per process to avoid log flood.
                        {
                            static unsigned diagCount = 0;
                            if (++diagCount <= 30) {
                                WTFLogAlways("[Driftstack-V633A] image=%p cp=U+%04x ptSize=%u pngBytes=%zu",
                                    image.get(), static_cast<unsigned>(textPlans[i].codepoint),
                                    static_cast<unsigned>(ptSizeRound), textPlans[i].pngBytes.size());
                            }
                        }
                        if (!image)
                            continue;
                        // Draw at baseline-aligned anchor.
                        float drawX = textPositions[i].x - bearingX;
                        float drawY = textPositions[i].y - baselineY;
                        // V-627.B: tint alpha-mask atlas image with active fill
                        // color via transparency layer. Atlas PNGs encode alpha
                        // only (RGB=(0,0,0); alpha = glyph coverage, per V-627.A
                        // post-process). Pipeline:
                        //   1. begin transparency layer (isolated compositing)
                        //   2. fillRect with cgContext's current fill color —
                        //      paints the user's fillStyle across the canvasW ×
                        //      canvasH glyph rect inside the layer.
                        //   3. setBlendMode(DestinationIn): subsequent draws
                        //      use src alpha to mask dest pixels.
                        //   4. drawImage(alpha-mask): keeps fill-color pixels
                        //      where mask alpha > 0; everywhere else, layer
                        //      pixels alpha→0 → composited as transparent.
                        //   5. end transparency layer → composite onto canvas.
                        // Result: user-colored, alpha-blended glyph painted
                        // ONLY where mask is non-zero. Surrounding canvas
                        // pixels are preserved (no white overpaint).
                        CGContextSaveGState(cgContext.get());
                        CGContextTranslateCTM(cgContext.get(), drawX, drawY);
                        CGContextTranslateCTM(cgContext.get(), 0.f, canvasH);
                        CGContextScaleCTM(cgContext.get(), 1.f, -1.f);
                        // V-633.D (2026-05-11, env-gated DRIFTSTACK_V633D=1):
                        // GPU-honoring tint via CGContextClipToMask + FillRect.
                        // Unlike V-627.B's BeginTransparencyLayer + DestinationIn
                        // (which uses an isolated compositing buffer that GPU
                        // readback paths don't honor — V-633.A finding: bits=0x0
                        // on every dispatch sample), ClipToMask + FillRect is a
                        // single composite op that writes directly to the canvas
                        // backing on both CPU and GPU contexts.
                        static bool s_v633dEnabled = []() {
                            const char* env = getenv("DRIFTSTACK_V633D");
                            return env && env[0] == '1';
                        }();
                        // V-666 (2026-05-11, env-gated DRIFTSTACK_V666=1):
                        // pre-tint alpha-mask in CPU bitmap context, then
                        // plain DrawImage. See helper comment.
                        static bool s_v666Enabled = []() {
                            // V-TEXT-BLACKCORNERS (2026-05-28): V-666 is the only composition that
                            // masks the alpha correctly — the V-627.B DestinationIn default and the
                            // V-633.D ClipToMask alternative both fill the whole glyph rect (solid
                            // fill, empirically 2486 vs 5 opaque). So V-666 is default-ON; opt OUT
                            // with DRIFTSTACK_V666=0. (Whole path is gated on DRIFTSTACK_TEXT_ATLAS,
                            // OFF in prod, so this cannot affect the atlas-OFF 1690/0 baseline.)
                            const char* env = getenv("DRIFTSTACK_V666");
                            return !env || env[0] != '0';
                        }();
                        if (s_v666Enabled) {
                            auto [fr, fg, fb, fa] = context.fillColor()
                                .toResolvedColorComponentsInColorSpace(ColorSpace::SRGB);
                            RetainPtr<CGImageRef> tinted = createTintedAlphaMaskImage(
                                image.get(), fr, fg, fb, fa,
                                static_cast<size_t>(canvasW),
                                static_cast<size_t>(canvasH));
                            if (tinted) {
                                CGContextDrawImage(cgContext.get(),
                                    CGRectMake(0.f, 0.f, canvasW, canvasH),
                                    tinted.get());
                            }
                        } else if (s_v633dEnabled) {
                            CGContextClipToMask(cgContext.get(),
                                CGRectMake(0.f, 0.f, canvasW, canvasH), image.get());
                            CGContextFillRect(cgContext.get(),
                                CGRectMake(0.f, 0.f, canvasW, canvasH));
                        } else {
                            // V-627.B legacy (default): transparency-layer + DestinationIn.
                            CGContextBeginTransparencyLayer(cgContext.get(), nullptr);
                            CGContextFillRect(cgContext.get(),
                                CGRectMake(0.f, 0.f, canvasW, canvasH));
                            CGContextSetBlendMode(cgContext.get(), kCGBlendModeDestinationIn);
                            CGContextDrawImage(cgContext.get(),
                                CGRectMake(0.f, 0.f, canvasW, canvasH), image.get());
                            CGContextEndTransparencyLayer(cgContext.get());
                        }
                        CGContextRestoreGState(cgContext.get());
                        // V-633.A diagnostic — report bitmap context availability.
                        // CGBitmapContextGetData returns nullptr when the
                        // CGContext is GPUProcess-accelerated (IOSurface-backed);
                        // in that case our CG draws may target a different
                        // backing buffer than the one toDataURL serializes,
                        // which would explain pixels appearing unchanged.
                        {
                            static unsigned pixDiagCount = 0;
                            if (++pixDiagCount <= 5) {
                                void* bits = CGBitmapContextGetData(cgContext.get());
                                size_t bpr = CGBitmapContextGetBytesPerRow(cgContext.get());
                                size_t width = CGBitmapContextGetWidth(cgContext.get());
                                size_t height = CGBitmapContextGetHeight(cgContext.get());
                                WTFLogAlways("[Driftstack-V633A-CTX] post-substitute cp=U+%04x bits=%p bpr=%zu bmp=%zux%zu — %s",
                                    static_cast<unsigned>(textPlans[i].codepoint),
                                    bits, bpr, width, height,
                                    bits ? "bitmap-backed" : "GPU/IOSurface-backed (CGBitmapContextGetData NULL — pixel-readback gap)");
                            }
                        }
                    }
                    flushTextCTRun();
                }
            }
        }
    }
    // V-654 fix (2026-05-11): the fallback CT draw was nested inside the
    // `if (!didCompositePath && textAtlasEnabled)` block above, which meant
    // atlas-OFF runs never reached showGlyphsWithAdvances and canvas text
    // rendered ONLY at V-121 override sizes {14,16,18,20,24} via a side
    // effect path. Moved to top-level so non-atlas, non-emoji-composite
    // draws hit the standard CT pipeline unconditionally.
    if (!didCompositePath && !didTextAtlasPath)
        showGlyphsWithAdvances(point, font, cgContext.get(), glyphs, advances, textMatrix);
#else
    showGlyphsWithAdvances(point, font, cgContext.get(), glyphs, advances, textMatrix);
#endif

    if (syntheticBoldOffset)
        showGlyphsWithAdvances(FloatPoint(point.x() + syntheticBoldOffset, point.y()), font, cgContext.get(), glyphs, advances, textMatrix);

    if (hasSimpleShadow)
        context.setDropShadow(*shadow);

#if !PLATFORM(IOS_FAMILY) && !PLATFORM(DRIFTSTACK)
    if (shouldSmoothFonts != originalShouldUseFontSmoothing)
        CGContextSetShouldSmoothFonts(cgContext.get(), originalShouldUseFontSmoothing);
#endif

    if (shouldAntialias != originalShouldAntialias)
        CGContextSetShouldAntialias(cgContext.get(), originalShouldAntialias);
}

bool FontCascade::primaryFontIsSystemFont() const
{
    Ref fontData = primaryFont();
    return isSystemFont(RetainPtr { fontData->ctFont() }.get());
}

RefPtr<const Font> FontCascade::fontForCombiningCharacterSequence(StringView stringView) const
{
    auto codePoints = stringView.codePoints();
    auto codePointsIterator = codePoints.begin();

    ASSERT(!stringView.isEmpty());
    char32_t baseCharacter = *codePointsIterator;
    ++codePointsIterator;
    bool isOnlySingleCodePoint = codePointsIterator == codePoints.end();

    GlyphData baseCharacterGlyphData = glyphDataForCharacter(baseCharacter, false, FontVariant::Normal);

    if (!baseCharacterGlyphData.glyph)
        return nullptr;

    if (isOnlySingleCodePoint)
        return baseCharacterGlyphData.font.get();

    bool triedBaseCharacterFont = false;

    for (unsigned i = 0; !fallbackRangesAt(i).isNull(); ++i) {
        auto& fontRanges = fallbackRangesAt(i);
        if (fontRanges.isGenericFontFamily() && isPrivateUseAreaCharacter(baseCharacter))
            continue;
        RefPtr font = fontRanges.fontForCharacter(baseCharacter);
        if (!font)
            continue;
#if PLATFORM(IOS_FAMILY) || PLATFORM(DRIFTSTACK)
        // V-682 (2026-05-11): extend to DRIFTSTACK. Skip Times New Roman / Arial
        // in Arabic combining-character fallback so combining clusters route
        // to SF Arabic / Geeza Pro instead of Times — matches iOS behavior.
        if (baseCharacter >= 0x0600 && baseCharacter <= 0x06ff && font->shouldNotBeUsedForArabic())
            continue;
#endif
        if (font->platformData().orientation() == FontOrientation::Vertical) {
            if (isCJKIdeographOrSymbol(baseCharacter)) {
                if (!font->hasVerticalGlyphs())
                    font = font->brokenIdeographFont();
            } else if (m_fontDescription.nonCJKGlyphOrientation() == NonCJKGlyphOrientation::Mixed) {
                Ref verticalRightFont = font->verticalRightOrientationFont();
                Glyph verticalRightGlyph = verticalRightFont->glyphForCharacter(baseCharacter);
                if (verticalRightGlyph == baseCharacterGlyphData.glyph)
                    font = verticalRightFont.ptr();
            } else {
                Ref uprightFont = font->uprightOrientationFont();
                Glyph uprightGlyph = uprightFont->glyphForCharacter(baseCharacter);
                if (uprightGlyph != baseCharacterGlyphData.glyph)
                    font = uprightFont.ptr();
            }
        }

        if (font == baseCharacterGlyphData.font.get())
            triedBaseCharacterFont = true;

        if (font->canRenderCombiningCharacterSequence(stringView))
            return font;
    }

    if (!triedBaseCharacterFont) {
        RefPtr font = baseCharacterGlyphData.font.get();
        if (font && font->canRenderCombiningCharacterSequence(stringView))
            return font;
    }

    return Font::createSystemFallbackFontPlaceholder();
}

ResolvedEmojiPolicy FontCascade::resolveEmojiPolicy(FontVariantEmoji fontVariantEmoji, char32_t character)
{
    // You may think that this function should be different between macOS and iOS. And you may even be right!
    //
    // For "unqualified" characters on https://unicode.org/Public/emoji/latest/emoji-test.txt the apparent behavior
    // of macOS and iOS is different. Both OSes cascade through the default cascade list, but on macOS,
    // STIXTwo is ahead of AppleColorEmoji in the list. On iOS, however, AppleColorEmoji is really early in the list
    // (it appears before almost everything else). So the observed effect is that a lot of these "unqualified"
    // characters will be emoji style on iOS whereas they will be text style on macOS.
    //
    // On the other hand, when Unicode says that a character is Emoji_Presentation, then it needs to be rendered a
    // emoji style, regardless of which OS you're on. Them's the rules.
    //
    // The fact that this function is the same on macOS and iOS is a somewhat-intentional choice. We *could* gather up
    // all the characters that apparently render differently on macOS and iOS, and force them to maintain those
    // differences here. However, that has 2 downsides:
    // 1. Having a big list of characters in WebKit source code is unmaintanable. And generating it at build time is a
    //        bit of a science project, given Apple's internal build system.
    // 2. More importantly, it probably isn't what authors want. If authors have their own font-family fallback list,
    //        they probably don't want us to sidestep _most_ of it in search of an emoji font, just because of the
    //        particular order of Core Text's native cascade list for native apps.
    //
    // So, where we end up here is a situation where these characters will get platform-specific rendering, but only if
    // the author is using `font-family: system-ui` or we end up falling off the end of the fallback list altogether.
    // Otherwise, we honor the author's given font-family list. This is probably the best of both words:
    // 1. If we have a positive signal from Unicode that a character has gotta be rendered in emoji style, then we'll
    //        honor that,
    // 2. In all other cases we'll honor the author's fallback list...
    // 3. Unless the author has (intentionally or unintentionally) asked us to perform a platform-specific fallback
    //        (via either asking for system-ui or by falling off the end of the list).

    switch (fontVariantEmoji) {
    case FontVariantEmoji::Normal:
    case FontVariantEmoji::Unicode:
        // https://www.unicode.org/reports/tr51/#Presentation_Style
        // There had been no clear line for implementers between three categories of Unicode characters:
        // 1. emoji-default: those expected to have an emoji presentation by default, but can also have a text presentation
        // 2. text-default: those expected to have a text presentation by default, but could also have an emoji presentation
        // 3. text-only: those that should only have a text presentation
        // These categories can be distinguished using properties listed in Annex A: Emoji Properties and Data Files.
        // The first category are characters with Emoji=Yes and Emoji_Presentation=Yes.
        // The second category are characters with Emoji=Yes and Emoji_Presentation=No.
        // The third category are characters with Emoji=No.
        if (isEmojiWithPresentationByDefault(character))
            return ResolvedEmojiPolicy::RequireEmoji;
        return ResolvedEmojiPolicy::NoPreference;
    case FontVariantEmoji::Text:
        return ResolvedEmojiPolicy::RequireText;
    case FontVariantEmoji::Emoji:
        return ResolvedEmojiPolicy::RequireEmoji;
    }
}

bool FontCascade::canUseGlyphDisplayList(const RenderStyle& style)
{
    // CoreText won't call the drawImage delegate for glyphs that are invisible, even if they have an associated shadow applied to its graphic context. This would result in a glyph display list without the invisible glyph which is drawn as image and we would not draw its associated shadow. Therefore, we won't use a display list for runs that are invisible and have an associated shadow.
    return !(!style.textShadow().isNone() && !style.color().isVisible());
}

} // namespace WebCore
