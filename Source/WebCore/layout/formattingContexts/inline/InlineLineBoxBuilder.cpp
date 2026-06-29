/*
 * Copyright (C) 2021 Apple Inc. All rights reserved.
 * Copyright (C) 2025 Samuel Weinig <sam@webkit.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE INC. AND ITS CONTRIBUTORS ``AS IS''
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL APPLE INC. OR ITS CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"
#include "InlineLineBoxBuilder.h"

#include "InlineLevelBoxInlines.h"
#include "InlineLineBoxVerticalAligner.h"
#include "InlineLineBuilder.h"
#include "LayoutBoxGeometry.h"
#include "RenderStyle+GettersInlines.h"
#include "RubyFormattingContext.h"
#include "StyleWebKitLineBoxContain.h"

namespace WebCore {
namespace Layout {

LineBoxBuilder::LineBoxBuilder(const InlineFormattingContext& inlineFormattingContext, LineLayoutResult& lineLayoutResult)
    : m_inlineFormattingContext(inlineFormattingContext)
    , m_lineLayoutResult(lineLayoutResult)
{
}

LineBox LineBoxBuilder::build(size_t lineIndex)
{
    auto& lineLayoutResult = this->lineLayoutResult();
    // FIXME: The overflowing hanging content should be part of the ink overflow.
    auto contentLogicalWidth = [&] {
        if (lineLayoutResult.directionality.inlineBaseDirection == TextDirection::LTR)
            return lineLayoutResult.contentGeometry.logicalWidth - lineLayoutResult.hangingContent.logicalWidth;
        // FIXME: Currently clients of the inline iterator interface (editing, selection, DOM etc) can't deal with
        // hanging content offsets when they affect the rest of the content.
        // In left-to-right inline direction, hanging content is always trailing hence the width does not impose offset on the rest of the content
        // while with right-to-left, the hanging content is visually leading (left side of the content) and it does offset the rest of the line.
        // What's missing is a way to tell that while the content starts at the left side of the (visually leading) hanging content
        // the root inline box has an offset, the width of the hanging content (essentially decoupling the content and the root inline box visual left).
        // For now just include the hanging content in the root inline box as if it was not hanging (this is how legacy line layout works).
        return lineLayoutResult.contentGeometry.logicalWidth;
    };
    auto lineBox = LineBox { rootBox(), lineLayoutResult.contentGeometry.logicalLeft, contentLogicalWidth(), lineIndex, isFirstFormattedLine(), lineLayoutResult.nonSpanningInlineLevelBoxCount };
    if (lineLayoutResult.isBlockContent())
        constructBlockContent(lineBox);
    else {
        constructInlineLevelBoxes(lineBox);
        if (lineLayoutResult.hasContentfulInlineContent()) {
            adjustIdeographicBaselineIfApplicable(lineBox);
            adjustInlineBoxHeightsForLineBoxContainIfApplicable(lineBox);
        } else {
            // Collapse all inline boxes (they are supposed to be empty as well).
            for (auto& inlineBox : lineBox.nonRootInlineLevelBoxes()) {
                if (!inlineBox.isInlineBox()) {
                    ASSERT(inlineBox.layoutBox().isWordBreakOpportunity());
                    ASSERT(!inlineBox.logicalHeight());
                    continue;
                }
                ASSERT(!inlineBox.hasContent());
                inlineBox.setLogicalHeight({ });
            }
        }
        if (m_lineHasNonLineSpanningRubyContent)
            RubyFormattingContext::applyAnnotationContributionToLayoutBounds(lineBox, formattingContext());
        computeLineBoxGeometry(lineBox);
        adjustOutsideListMarkersPosition(lineBox);

        if (auto adjustment = formattingContext().quirks().adjustmentForLineGridLineSnap(lineBox))
            expandAboveRootInlineBox(lineBox, *adjustment);
    }

    return lineBox;
}

LineBox LineBoxBuilder::buildForRootInlineBoxOnly(size_t lineIndex)
{
    auto& lineLayoutResult = this->lineLayoutResult();
    ASSERT(lineLayoutResult.hasContentfulInlineContent());

    auto lineBox = LineBox { rootBox(), lineLayoutResult.contentGeometry.logicalLeft, lineLayoutResult.contentGeometry.logicalWidth - lineLayoutResult.hangingContent.logicalWidth, lineIndex, isFirstFormattedLine(), lineLayoutResult.nonSpanningInlineLevelBoxCount };
    auto& rootInlineBox = lineBox.rootInlineBox();
    setVerticalPropertiesForInlineLevelBox(lineBox, rootInlineBox);
    rootInlineBox.setLogicalTop(rootInlineBox.layoutBounds().ascent - rootInlineBox.ascent());
    auto lineBoxLogicalHeight = applyTextBoxTrimOnLineBoxIfNeeded(rootInlineBox.layoutBounds().height(), lineBox);
    lineBox.setLogicalRect({ lineLayoutResult.lineGeometry.logicalTopLeft, lineLayoutResult.lineGeometry.logicalWidth, lineBoxLogicalHeight });
    return lineBox;
}

TextUtil::FallbackFontList LineBoxBuilder::collectFallbackFonts(const InlineLevelBox& parentInlineBox, const Line::Run& run, const RenderStyle& style)
{
    ASSERT(parentInlineBox.isInlineBox());
    auto& inlineTextBox = downcast<InlineTextBox>(run.layoutBox());
    if (inlineTextBox.canUseSimplifiedContentMeasuring()) {
        // Simplified text measuring works with primary font only.
        return { };
    }
    auto& text = run.textContent();
    auto fallbackFonts = TextUtil::fallbackFontsForText(StringView(inlineTextBox.content()).substring(text.start, text.length), style, text.needsHyphen ? TextUtil::IncludeHyphen::Yes : TextUtil::IncludeHyphen::No);
    if (fallbackFonts.isEmptyIgnoringNullReferences())
        return { };

    auto fallbackFontsForInlineBoxes = m_fallbackFontsForInlineBoxes.get(&parentInlineBox);
    auto numberOfFallbackFontsForInlineBox = fallbackFontsForInlineBoxes.computeSize();
    for (Ref font : fallbackFonts) {
        fallbackFontsForInlineBoxes.add(font.ptr());
        m_fallbackFontRequiresIdeographicBaseline = m_fallbackFontRequiresIdeographicBaseline || font->hasVerticalGlyphs();
    }
    if (fallbackFontsForInlineBoxes.computeSize() != numberOfFallbackFontsForInlineBox)
        m_fallbackFontsForInlineBoxes.set(&parentInlineBox, fallbackFontsForInlineBoxes);
    return fallbackFonts;
}

static InlineLevelBox::AscentAndDescent NODELETE primaryFontMetricsForInlineBox(const InlineLevelBox& inlineBox, FontBaseline fontBaseline = FontBaseline::Alphabetic)
{
    ASSERT(inlineBox.isInlineBox());
    auto& fontMetrics = inlineBox.primarymetricsOfPrimaryFont();
    auto ascent = InlineFormattingUtils::ascent(fontMetrics, fontBaseline, inlineBox);
    auto descent = InlineFormattingUtils::descent(fontMetrics, fontBaseline, inlineBox);
    return { ascent, descent };
}

static bool NODELETE isLineFitEdgeLeading(const InlineLevelBox& inlineBox)
{
    ASSERT(inlineBox.isInlineBox());
    return inlineBox.lineFitEdge().isLeading();
}

#if PLATFORM(DRIFTSTACK)
// W2980e (#120 glyph-1600 cluster B): is the inline box's PRIMARY font the SF system font (the CSS
// `default`/-apple-system base)? On a real iPhone the -apple-system line-box strut is glyph-INDEPENDENT —
// it stays the SF-Pro strut (1910 @1600px) even when a TALL fallback glyph (CJK / block element / CJK
// ideograph) is rendered into the box. The faithful 1600px Unicode-Glyphs grid proves this exactly: for the
// default generic, EVERY cp whose SF-Pro cascade falls to a taller fallback (U+2581/U+3095/U+532D → a
// 2240-2400-tall face) STILL reads 1910, while the explicit generics (sans=Helvetica / serif=Times / etc.)
// DO stretch to the fallback enclosure (2400/2240) and the fork already matches those. So the strut
// suppression must be scoped to the SF default base ONLY — a blanket suppress would collapse the
// explicit-generic 2400 cells back to 1910 (REGRESSION). Cps where SF-Pro carries the glyph NATIVELY at a
// tall line-box (e.g. U+097F default 2400 = SF-Pro's own Devanagari strut, no fallback) are unaffected:
// there is no fallback font, so the suppressed branch never runs for them. Matches CTFontCopyFamilyName's
// SF system-font names (the same set FontCoreText.cpp shouldUseSfProConstantOnePixelAdjustment pins).
static bool NODELETE driftstackPrimaryFontIsSfSystemBase(const InlineLevelBox& inlineBox)
{
    auto& primaryFont = inlineBox.layoutBox().style().fontCascade().primaryFont();
    auto family = primaryFont.platformData().familyName();
    return family == ".AppleSystemUIFont"_s
        || family == ".SF NS"_s
        || family == ".SF NS Display"_s
        || family == ".SF NS Text"_s
        || family == "SF Pro"_s
        || family == "SF Pro Display"_s
        || family == "SF Pro Text"_s;
}
#endif

static InlineLevelBox::AscentAndDescent layoutBoundstWithEdgeAdjustmentForInlineBox(const InlineLevelBox& inlineBox, const FontMetrics& fontMetrics, FontBaseline fontBaseline)
{
    ASSERT(inlineBox.isInlineBox());

    if (inlineBox.isRootInlineBox())
        return { InlineFormattingUtils::ascent(fontMetrics, fontBaseline, inlineBox), InlineFormattingUtils::descent(fontMetrics, fontBaseline, inlineBox) };

    auto ascent = [&] -> InlineLayoutUnit {
        return WTF::switchOn(inlineBox.lineFitEdge(),
            [&](CSS::Keyword::Leading) -> InlineLayoutUnit {
                return InlineFormattingUtils::ascent(fontMetrics, fontBaseline, inlineBox);
            },
            [&](Style::TextEdgePair edgePair) -> InlineLayoutUnit {
                switch (edgePair.over) {
                case TextEdgeOver::Text:
                    return InlineFormattingUtils::ascent(fontMetrics, fontBaseline, inlineBox);
                case TextEdgeOver::Cap:
                    return InlineFormattingUtils::snapToInt(fontMetrics.capHeight().value_or(0.f), inlineBox);
                case TextEdgeOver::Ex:
                    return InlineFormattingUtils::snapToInt(fontMetrics.xHeight().value_or(0.f), inlineBox);
                case TextEdgeOver::Ideographic:
                    return InlineFormattingUtils::ascent(fontMetrics, FontBaseline::Ideographic, inlineBox);
                case TextEdgeOver::IdeographicInk:
                    ASSERT_NOT_IMPLEMENTED_YET();
                    return InlineFormattingUtils::ascent(fontMetrics, FontBaseline::Ideographic, inlineBox);
                }
                RELEASE_ASSERT_NOT_REACHED();
            }
        );
    };

    auto descent = [&] -> InlineLayoutUnit {
        return WTF::switchOn(inlineBox.lineFitEdge(),
            [&](CSS::Keyword::Leading) -> InlineLayoutUnit {
                return InlineFormattingUtils::descent(fontMetrics, fontBaseline, inlineBox);
            },
            [&](Style::TextEdgePair edgePair) -> InlineLayoutUnit {
                switch (edgePair.under) {
                case TextEdgeUnder::Text:
                    return InlineFormattingUtils::descent(fontMetrics, fontBaseline, inlineBox);
                case TextEdgeUnder::Alphabetic:
                    return 0.f;
                case TextEdgeUnder::Ideographic:
                    return InlineFormattingUtils::descent(fontMetrics, FontBaseline::Ideographic, inlineBox);
                case TextEdgeUnder::IdeographicInk:
                    ASSERT_NOT_IMPLEMENTED_YET();
                    return InlineFormattingUtils::descent(fontMetrics, FontBaseline::Ideographic, inlineBox);
                }
                RELEASE_ASSERT_NOT_REACHED();
            }
        );
    };
    return { ascent(), descent() };
}

static InlineLevelBox::AscentAndDescent textBoxAdjustedInlineBoxHeight(const InlineLevelBox& inlineBox, const FontMetrics& fontMetrics, FontBaseline fontBaseline)
{
    ASSERT(inlineBox.isInlineBox());

    if (inlineBox.isRootInlineBox())
        return { InlineFormattingUtils::ascent(fontMetrics, fontBaseline, inlineBox), InlineFormattingUtils::descent(fontMetrics, fontBaseline, inlineBox) };

    auto inlineBoxTextBoxTrim = inlineBox.textBoxTrim();
    auto ascent = [&] -> InlineLayoutUnit {
        auto textBoxEdge = inlineBoxTextBoxTrim == TextBoxTrim::TrimStart || inlineBoxTextBoxTrim == TextBoxTrim::TrimBoth ? inlineBox.textBoxEdge().tryTextEdgePair() : std::nullopt;
        if (!textBoxEdge)
            return InlineFormattingUtils::ascent(fontMetrics, fontBaseline, inlineBox);

        switch (textBoxEdge->over) {
        case TextEdgeOver::Text:
            return InlineFormattingUtils::ascent(fontMetrics, fontBaseline, inlineBox);
        case TextEdgeOver::Cap:
            return InlineFormattingUtils::snapToInt(fontMetrics.capHeight().value_or(0.f), inlineBox);
        case TextEdgeOver::Ex:
            return InlineFormattingUtils::snapToInt(fontMetrics.xHeight().value_or(0.f), inlineBox);
        case TextEdgeOver::Ideographic:
            return InlineFormattingUtils::ascent(fontMetrics, FontBaseline::Ideographic, inlineBox);
        case TextEdgeOver::IdeographicInk:
            ASSERT_NOT_IMPLEMENTED_YET();
            return InlineFormattingUtils::ascent(fontMetrics, FontBaseline::Ideographic, inlineBox);
        }
        RELEASE_ASSERT_NOT_REACHED();
    };

    auto descent = [&] -> InlineLayoutUnit {
        auto textBoxEdge = inlineBoxTextBoxTrim == TextBoxTrim::TrimEnd || inlineBoxTextBoxTrim == TextBoxTrim::TrimBoth ? inlineBox.textBoxEdge().tryTextEdgePair() : std::nullopt;
        if (!textBoxEdge)
            return InlineFormattingUtils::descent(fontMetrics, fontBaseline, inlineBox);

        switch (textBoxEdge->under) {
        case TextEdgeUnder::Text:
            return InlineFormattingUtils::descent(fontMetrics, fontBaseline, inlineBox);
        case TextEdgeUnder::Alphabetic:
            return 0.f;
        case TextEdgeUnder::Ideographic:
            return InlineFormattingUtils::descent(fontMetrics, FontBaseline::Ideographic, inlineBox);
        case TextEdgeUnder::IdeographicInk:
            ASSERT_NOT_IMPLEMENTED_YET();
            return InlineFormattingUtils::descent(fontMetrics, FontBaseline::Ideographic, inlineBox);
        }
        RELEASE_ASSERT_NOT_REACHED();
    };
    return { ascent(), descent() };
}

InlineLevelBox::AscentAndDescent LineBoxBuilder::enclosingAscentDescentWithFallbackFonts(const InlineLevelBox& inlineBox, const TextUtil::FallbackFontList& fallbackFontsForContent, FontBaseline fontBaseline) const
{
    ASSERT(!fallbackFontsForContent.isEmptyIgnoringNullReferences());
    ASSERT(inlineBox.isInlineBox());

    // https://www.w3.org/TR/css-inline-3/#inline-height
    // When the computed line-height is normal, the layout bounds of an inline box encloses all its glyphs, going from the highest A to the deepest D. 
    auto maxAscent = InlineLayoutUnit { };
    auto maxDescent = InlineLayoutUnit { };
    // If line-height computes to normal and either line-fit-edge is leading or this is the root inline box,
    // the font's line gap metric may also be incorporated into A and D by adding half to each side as half-leading.
    auto shouldUseLineGapToAdjustAscentDescent = (inlineBox.isRootInlineBox() || isLineFitEdgeLeading(inlineBox)) && !rootBox().isRubyAnnotationBox();
    for (Ref font : fallbackFontsForContent) {
        auto& fontMetrics = font->fontMetrics();
        auto [ascent, descent] = textBoxAdjustedInlineBoxHeight(inlineBox, fontMetrics, fontBaseline);
        if (shouldUseLineGapToAdjustAscentDescent) {
            auto halfLeading = (InlineFormattingUtils::snapToInt(fontMetrics.lineSpacing(), inlineBox) - (ascent + descent)) / 2;
            ascent += halfLeading;
            descent += halfLeading;
        }
#if PLATFORM(DRIFTSTACK)
        if (getenv("DRIFTSTACK_LOG_LINE_BOX_HEIGHT")) {
            auto famName = font->platformData().familyName();
            WTFLogAlways("[Driftstack-W2588-FBFONT] family='%s' rawAsc=%.3f rawDesc=%.3f lineSpacing=%.3f -> adjAsc=%.3f adjDesc=%.3f",
                famName.utf8().data(), (double)fontMetrics.ascent(), (double)fontMetrics.descent(), (double)fontMetrics.lineSpacing(), (double)ascent, (double)descent);
        }
#endif
        maxAscent = std::max(maxAscent, ascent);
        maxDescent = std::max(maxDescent, descent);
    }
    // We need floor/ceil to match legacy layout integral positioning.
    return { InlineFormattingUtils::snapToInt(maxAscent, inlineBox, InlineFormattingUtils::SnapDirection::Floor), InlineFormattingUtils::snapToInt(maxDescent, inlineBox, InlineFormattingUtils::SnapDirection::Ceil) };
}

void LineBoxBuilder::setLayoutBoundsForInlineBox(InlineLevelBox& inlineBox, FontBaseline fontBaseline) const
{
    ASSERT(inlineBox.isInlineBox());

    auto layoutBounds = [&]() -> InlineLevelBox::AscentAndDescent {
        auto [ascent, descent] = layoutBoundstWithEdgeAdjustmentForInlineBox(inlineBox, inlineBox.primarymetricsOfPrimaryFont(), fontBaseline);

#if PLATFORM(DRIFTSTACK)
        // V-433.Z P-track #46 +1px Δh probe — half-leading source layer
        // (wave 29-223 slice 3). Logs ascent / descent / preferredLineHeight
        // / halfLeading on the BOTH branches (font-metrics-based vs
        // computed-line-height). v433y context measures fonts at varying
        // sizes via canvas; this site IS in the canvas measureText layout
        // path. Env-gate DRIFTSTACK_LOG_LINE_BOX_HEIGHT=1.
        {
            static bool s_logLBH = []() {
                const char* env = getenv("DRIFTSTACK_LOG_LINE_BOX_HEIGHT");
                return env && env[0] == '1';
            }();
            if (s_logLBH) {
                float preferred = inlineBox.preferredLineHeight();
                bool metricsBased = inlineBox.isPreferredLineHeightFontMetricsBased();
                WTFLogAlways("[Driftstack-P46-SLBIB] isRoot=%d ascent_in=%.6f descent_in=%.6f prefLH=%.6f metricsBased=%d sum=%.6f",
                    inlineBox.isRootInlineBox() ? 1 : 0,
                    static_cast<double>(ascent),
                    static_cast<double>(descent),
                    static_cast<double>(preferred),
                    metricsBased ? 1 : 0,
                    static_cast<double>(ascent + descent));
            }
        }
#endif

        // FIXME: Annotation root should not have any impact here with the proper annotation box handling (dedicated IFC line for annotations and line-height is 1).
        if (rootBox().isRubyAnnotationBox())
            return { ascent, descent };

        if (!inlineBox.isPreferredLineHeightFontMetricsBased()) {
            // https://www.w3.org/TR/css-inline-3/#inline-height
            // When computed line-height is not normal, calculate the leading L as L = line-height - (A + D).
            // Half the leading (its half-leading) is added above A, and the other half below D,
            // giving an effective ascent above the baseline of A′ = A + L/2, and an effective descent of D′ = D + L/2.
            auto halfLeading = (InlineFormattingUtils::snapToInt(inlineBox.preferredLineHeight(), inlineBox, InlineFormattingUtils::SnapDirection::Floor) - (ascent + descent)) / 2;
            if (!isLineFitEdgeLeading(inlineBox) && !inlineBox.isRootInlineBox()) {
                // However, if text-box-edge is not leading and this is not the root inline box, if the half-leading is positive, treat it as zero.
                halfLeading = std::min(halfLeading, 0.f);
            }
            ascent += halfLeading;
            descent += halfLeading;
        } else {
            // https://www.w3.org/TR/css-inline-3/#inline-height
            // If line-height computes to normal and either line-fit-edge is leading or this is the root inline box,
            // the font’s line gap metric may also be incorporated into A and D by adding half to each side as half-leading.
            auto shouldIncorporateHalfLeading = inlineBox.isRootInlineBox() || isLineFitEdgeLeading(inlineBox);
            if (shouldIncorporateHalfLeading) {
                auto lineGap = InlineFormattingUtils::snapToInt(inlineBox.primarymetricsOfPrimaryFont().lineSpacing(), inlineBox);
                auto halfLeading = (lineGap - (ascent + descent)) / 2;
#if PLATFORM(DRIFTSTACK)
                // Wave 29-257 / P-track #46 empirical exploration: ceil(halfLeading)
                // closes cjk h=17.5→18 but breaks emoji/family h=18.5→19, flag h=18.0→18.5.
                // iPhone reference: cjk=18, arabic=19, emoji=18, family=18, flag=18.
                // Per-script-target rounding requires font-cascade-aware logic
                // beyond simple ceil/round. Kept as env-gated diagnostic:
                // DRIFTSTACK_HALFLEADING_ROUND=ceil applies std::ceil,
                // DRIFTSTACK_HALFLEADING_ROUND=round applies std::round,
                // unset = no-op (default).
                if (const char* env = getenv("DRIFTSTACK_HALFLEADING_ROUND")) {
                    if (env[0] == 'c' || env[0] == 'C')
                        halfLeading = std::ceil(halfLeading);
                    else if (env[0] == 'r' || env[0] == 'R')
                        halfLeading = std::round(halfLeading);
                    else if (env[0] == '1')
                        halfLeading = std::round(halfLeading);
                    else if (env[0] == 'e' || env[0] == 'E') {
                        // W336: round-half-to-EVEN (banker's rounding). The P-track
                        // #46 iOS targets are exactly this — cjk 17.5→18, emoji
                        // 18.5→18, family 18.5→18, flag 18.0→18 — which ceil/round
                        // (away-from-zero: 18.5→19) miss but half-to-even matches.
                        halfLeading = std::nearbyint(halfLeading);
                    }
                }
#endif
                ascent += halfLeading;
                descent += halfLeading;
            }
        }
#if PLATFORM(DRIFTSTACK)
        // W2573: log the OUTPUT layoutBounds (post-half-leading) to pin where the glyphHash block +1
        // enters (the font METRICS are iOS-identical per W2573, so the +1 is in this layout assembly).
        // Correlate with the [P46-SLBIB] input line via ascent_in/descent_in (which identify the font).
        if (getenv("DRIFTSTACK_LOG_LINE_BOX_HEIGHT"))
            WTFLogAlways("[Driftstack-W2573-OUT] isRoot=%d out_ascent=%.6f out_descent=%.6f out_sum=%.6f",
                inlineBox.isRootInlineBox() ? 1 : 0, static_cast<double>(ascent), static_cast<double>(descent),
                static_cast<double>(ascent + descent));
#endif
        return { ascent, descent };
    }();

    auto inflateWithMarginBorderAndPaddingIfApplicable = [&] {
        if (isLineFitEdgeLeading(inlineBox) || inlineBox.isRootInlineBox())
            return;
        // Additionally, when line-fit-edge is not leading, the layout bounds are inflated by the sum of the margin,
        // border, and padding on each side.
        ASSERT(!inlineBox.isRootInlineBox());
        auto& inlineBoxGeometry = formattingContext().geometryForBox(inlineBox.layoutBox());
        layoutBounds.ascent += inlineBoxGeometry.marginBorderAndPaddingBefore();
        layoutBounds.descent += inlineBoxGeometry.marginBorderAndPaddingAfter();
    };
    inflateWithMarginBorderAndPaddingIfApplicable();

    layoutBounds = { InlineFormattingUtils::snapToInt(layoutBounds.ascent, inlineBox, InlineFormattingUtils::SnapDirection::Floor), InlineFormattingUtils::snapToInt(layoutBounds.descent, inlineBox, InlineFormattingUtils::SnapDirection::Ceil) };
    inlineBox.setLayoutBounds(layoutBounds);
}

void LineBoxBuilder::setVerticalPropertiesForInlineLevelBox(const LineBox& lineBox, InlineLevelBox& inlineLevelBox) const
{
    auto setVerticalProperties = [&] (InlineLevelBox::AscentAndDescent ascentAndDescent, bool applyLegacyRounding = true) {
        if (applyLegacyRounding)
            ascentAndDescent = { InlineFormattingUtils::snapToInt(ascentAndDescent.ascent, inlineLevelBox, InlineFormattingUtils::SnapDirection::Floor), InlineFormattingUtils::snapToInt(ascentAndDescent.descent, inlineLevelBox, InlineFormattingUtils::SnapDirection::Ceil) };
        inlineLevelBox.setAscentAndDescent(ascentAndDescent);
        inlineLevelBox.setLayoutBounds(ascentAndDescent);
        inlineLevelBox.setLogicalHeight(ascentAndDescent.height());
    };

    if (inlineLevelBox.isInlineBox()) {
        auto ascentAndDescent = [&]() -> InlineLevelBox::AscentAndDescent {
            auto fontBaseline = lineBox.baselineType();
            if (inlineLevelBox.isRootInlineBox())
                return primaryFontMetricsForInlineBox(inlineLevelBox, fontBaseline);

            auto& fontMetrics = inlineLevelBox.primarymetricsOfPrimaryFont();
            auto [ascent, descent] = textBoxAdjustedInlineBoxHeight(inlineLevelBox, fontMetrics, fontBaseline);
            return { ascent, descent };
        }();

        setVerticalProperties(ascentAndDescent);
        // Override default layout bounds.
        setLayoutBoundsForInlineBox(inlineLevelBox, lineBox.baselineType());

        // With text-box-trim, the inline box top is not always where the content starts.
        auto fontMetricBasedAscent = primaryFontMetricsForInlineBox(inlineLevelBox, lineBox.baselineType()).ascent;
        inlineLevelBox.setInlineBoxContentOffsetForTextBoxTrim(fontMetricBasedAscent - ascentAndDescent.ascent);
        return;
    }
    if (inlineLevelBox.isLineBreakBox()) {
        auto ascentAndDescent = primaryFontMetricsForInlineBox(lineBox.parentInlineBox(inlineLevelBox), lineBox.baselineType());
        setVerticalProperties(ascentAndDescent);
        if (!inlineLevelBox.isPreferredLineHeightFontMetricsBased()) {
            // When the BR has an explicit line-height, apply the same half-leading model as setLayoutBoundsForInlineBox.
            auto halfLeading = (InlineFormattingUtils::snapToInt(inlineLevelBox.preferredLineHeight(), inlineLevelBox, InlineFormattingUtils::SnapDirection::Floor) - ascentAndDescent.height()) / 2;
            inlineLevelBox.setLayoutBounds({ ascentAndDescent.ascent + halfLeading, ascentAndDescent.descent + halfLeading });
        }
        return;
    }
    if (inlineLevelBox.isListMarker()) {
        auto& layoutBox = downcast<ElementBox>(inlineLevelBox.layoutBox());
        auto& listMarkerBoxGeometry = formattingContext().geometryForBox(layoutBox);
        auto marginBoxHeight = listMarkerBoxGeometry.marginBoxHeight();

        if (lineBox.baselineType() == FontBaseline::Ideographic) {
            // FIXME: We should rely on the integration baseline.
            setVerticalProperties(primaryFontMetricsForInlineBox(lineBox.parentInlineBox(inlineLevelBox), lineBox.baselineType()));
            inlineLevelBox.setLogicalHeight(marginBoxHeight);
            return;
        }
        if (auto ascent = layoutBox.baselineForIntegration()) {
            if (layoutBox.isListMarkerImage())
                return setVerticalProperties({ *ascent, marginBoxHeight - *ascent });
            // Special list marker handling. Text driven list markers behave as text when it comes to layout bounds/ascent descent.
            // This needs to consult the list marker's style (and not the root) because we don't follow the DOM insertion point in case like this:
            // <li><div>content</div></li>
            // where the list marker ends up inside the <div> and the <div>'s style != <li>'s style.
            auto listMarkerLayoutBounds = layoutBox.layoutBoundsForListMarker();
            inlineLevelBox.setLayoutBounds({ InlineLayoutUnit(listMarkerLayoutBounds.first), InlineLayoutUnit(listMarkerLayoutBounds.second) });

            auto& fontMetrics = inlineLevelBox.primarymetricsOfPrimaryFont();
            auto fontBaseline = lineBox.baselineType();
            inlineLevelBox.setAscentAndDescent({ InlineFormattingUtils::ascent(fontMetrics, fontBaseline, inlineLevelBox), InlineFormattingUtils::descent(fontMetrics, fontBaseline, inlineLevelBox) });

            inlineLevelBox.setLogicalHeight(marginBoxHeight);
            return;
        }
        setVerticalProperties({ marginBoxHeight, { } });
        return;
    }
    if (inlineLevelBox.isAtomicInlineBox()) {
        auto& layoutBox = inlineLevelBox.layoutBox();
        auto& inlineLevelBoxGeometry = formattingContext().geometryForBox(layoutBox);
        auto marginBoxHeight = inlineLevelBoxGeometry.marginBoxHeight();
        auto ascent = [&]() -> InlineLayoutUnit {
            if (layoutState().shouldNotSynthesizeInlineBlockBaseline())
                return downcast<ElementBox>(layoutBox).baselineForIntegration().value_or(marginBoxHeight);

            if (layoutBox.isInlineBlockBox()) {
                // The baseline of an 'inline-block' is the baseline of its last line box in the normal flow, unless it has either no in-flow line boxes or
                // if its 'overflow' property has a computed value other than 'visible', in which case the baseline is the bottom margin edge.
                auto synthesizeBaseline = !layoutBox.establishesInlineFormattingContext() || !layoutBox.style().isOverflowVisible();
                if (synthesizeBaseline)
                    return marginBoxHeight;

                // FIXME: Grab the first/last baseline off of the inline formatting context (display content).
                ASSERT_NOT_IMPLEMENTED_YET();
            }
            return marginBoxHeight;
        }();
        setVerticalProperties({ ascent, marginBoxHeight - ascent }, false);
        return;
    }
    ASSERT_NOT_REACHED();
}

void LineBoxBuilder::constructInlineLevelBoxes(LineBox& lineBox)
{
    auto& formattingContext = this->formattingContext();
    auto& rootInlineBox = lineBox.rootInlineBox();
    setVerticalPropertiesForInlineLevelBox(lineBox, rootInlineBox);

    auto styleToUse = [&] (const auto& layoutBox) -> const RenderStyle& {
        return isFirstFormattedLine() ? layoutBox.firstLineStyle() : layoutBox.style();
    };

    auto& inlineContent = lineLayoutResult().runs;
    for (size_t index = 0; index < inlineContent.size(); ++index) {
        auto& run = inlineContent[index];
        auto& layoutBox = run.layoutBox();
        auto& style = styleToUse(layoutBox);
        auto logicalLeft = rootInlineBox.logicalLeft() + run.logicalLeft();

        if (run.isText()) {
            auto& parentInlineBox = lineBox.parentInlineBox(run);
            parentInlineBox.setHasContent();
            if (auto fallbackFonts = collectFallbackFonts(parentInlineBox, run, style); !fallbackFonts.isEmptyIgnoringNullReferences()) {
                // Adjust non-empty inline box height when glyphs from the non-primary font stretch the box.
                if (parentInlineBox.isPreferredLineHeightFontMetricsBased()) {
#if PLATFORM(DRIFTSTACK)
                    // W2980 (#117): on the iPhone-emulation build, the line-box strut must stay
                    // pinned to the PRIMARY (first-available) font of the element, glyph-INDEPENDENT,
                    // matching real-iPhone Safari. browserleaks /fonts measures div.offsetHeight of a
                    // single exotic codepoint at 128px for 43 cps x 6 generics; a real iPhone returns a
                    // PERFECTLY UNIFORM per-generic line-box height for ALL codepoints (verified live:
                    // default 192 / sans 193 / serif 194 / mono 193 / cursive 198 / fantasy 214 @128px;
                    // 24/24/25/25/26/28 @16px) — i.e. the strut is the primary font's, never stretched
                    // by whichever fallback font renders a given glyph. Upstream WebKit (CSS-inline-3
                    // "enclose all glyphs from highest A to deepest D") stretches the strut to the MAX of
                    // the primary and each per-glyph FALLBACK font's metrics. On iOS the fallback fonts'
                    // metrics happen to fit within the primary strut, so the strut stays uniform; on the
                    // Mac the fork selects Mac-only fallback fonts (Hiragino / Noto / Apple Color Emoji /
                    // .LastResort, etc.) whose ascent+descent EXCEED the primary strut, scattering
                    // div.offsetHeight per-glyph (149/150/129/162/199/256 ...) and diverging the live
                    // Unicode-Glyphs fingerprint (fork BAA41872 vs real iPhone 5D474692 @128px).
                    //
                    // This is the CORRECT, SIZE-GENERAL CSS mechanism (the strut is set by the element's
                    // first-available font, uniform regardless of which fallback renders a glyph) — it is
                    // correct at 16px AND 128px AND any size, not a per-cell or per-size serve. Widths are
                    // unaffected (the fallback advances are correct and drive the width column 1:1). The
                    // 16px glyphHash surface stays intact because the strut already equals the primary
                    // font's strut there too; suppressing only the FALLBACK over-stretch leaves the
                    // primary-font strut (set by setLayoutBoundsForInlineBox above) as the sole height.
                    static const bool s_primaryFontStrut = [] {
                        const char* e = getenv("DRIFTSTACK_PRIMARY_FONT_STRUT");
                        return e && e[0] == '1';
                    }();
                    if (s_primaryFontStrut) {
                        if (getenv("DRIFTSTACK_LOG_LINE_BOX_HEIGHT")) {
                            auto lb = parentInlineBox.layoutBounds();
                            WTFLogAlways("[Driftstack-W2980-STRUT] primary-font strut pinned: ascent=%.3f descent=%.3f (fallback stretch suppressed, %u fallback fonts)",
                                (double)lb.ascent, (double)lb.descent, (unsigned)fallbackFonts.computeSize());
                        }
                        // Leave the strut at the primary font's layout bounds (uniform per generic, any size).
                    } else
#endif
                    {
                    auto enclosingAscentAndDescent = enclosingAscentDescentWithFallbackFonts(parentInlineBox, fallbackFonts, FontBaseline::Alphabetic);
                    auto layoutBounds = parentInlineBox.layoutBounds();
                    parentInlineBox.setLayoutBounds({ std::max(layoutBounds.ascent, enclosingAscentAndDescent.ascent), std::max(layoutBounds.descent, enclosingAscentAndDescent.descent) });
                    }
                }
            }
            continue;
        }
        if (run.isSoftLineBreak()) {
            lineBox.parentInlineBox(run).setHasContent();
            continue;
        }
        if (run.isHardLineBreak()) {
            auto lineBreakBox = InlineLevelBox::createLineBreakBox(layoutBox, style, logicalLeft);
            setVerticalPropertiesForInlineLevelBox(lineBox, lineBreakBox);
            lineBox.addInlineLevelBox(WTF::move(lineBreakBox));

            if (layoutState().inStandardsMode() || InlineQuirks::lineBreakBoxAffectsParentInlineBox(lineBox))
                lineBox.parentInlineBox(run).setHasContent();
            continue;
        }
        if (run.isAtomicInlineBox()) {
            auto& inlineLevelBoxGeometry = formattingContext.geometryForBox(layoutBox);
            logicalLeft += std::max(0_lu, inlineLevelBoxGeometry.marginStart());
            auto atomicInlineBox = InlineLevelBox::createAtomicInlineBox(layoutBox, style, logicalLeft, inlineLevelBoxGeometry.borderBoxWidth());
            setVerticalPropertiesForInlineLevelBox(lineBox, atomicInlineBox);
            lineBox.addInlineLevelBox(WTF::move(atomicInlineBox));
            continue;
        }
        if (run.isInlineBoxStart() || run.isLineSpanningInlineBoxStart()) {
            auto marginStart = run.isInlineBoxStart() || style.boxDecorationBreak() == BoxDecorationBreak::Clone ? formattingContext.geometryForBox(layoutBox).marginStart() : LayoutUnit();
            // At this point we don't know yet how wide this inline box is. Let's assume it's as long as the line is
            // and adjust it later if we come across an inlineBoxEnd run (see below).
            // Inline box run is based on margin box. Let's convert it to border box.
            logicalLeft += std::max(0_lu, marginStart);
            auto initialLogicalWidth = [&] {
                auto logicalWidth = rootInlineBox.logicalRight() - logicalLeft;
                // We (editing, DOM etc) can't yet handle RTL hanging content (see contentLogicalWidth in LineBoxBuilder::build).
                if (lineLayoutResult().directionality.inlineBaseDirection == TextDirection::LTR)
                    logicalWidth += lineLayoutResult().hangingContent.logicalWidth;
                return logicalWidth;
            }();
            initialLogicalWidth = std::max(initialLogicalWidth, 0.f);
            auto inlineBox = InlineLevelBox::createInlineBox(layoutBox, style, logicalLeft, initialLogicalWidth, run.isInlineBoxStart() ? InlineLevelBox::LineSpanningInlineBox::No : InlineLevelBox::LineSpanningInlineBox::Yes);
            inlineBox.setTextEmphasis(InlineFormattingUtils::textEmphasisForInlineBox(layoutBox, rootBox()));
            setVerticalPropertiesForInlineLevelBox(lineBox, inlineBox);
            if (run.isInlineBoxStart()) {
                inlineBox.setIsFirstBox();
                m_lineHasNonLineSpanningRubyContent = m_lineHasNonLineSpanningRubyContent || layoutBox.isRubyBase();
            }
            lineBox.addInlineLevelBox(WTF::move(inlineBox));
            continue;
        }
        if (run.isInlineBoxEnd()) {
            // Adjust the logical width when the inline box closes on this line.
            // Note that margin end does not affect the logical width (e.g. positive margin right does not make the run wider).
            auto& inlineBox = lineBox.inlineLevelBoxFor(run);
            ASSERT(inlineBox.isInlineBox());
            // Inline box run is based on margin box. Let's convert it to border box.
            // Negative margin end makes the run have negative width.
            auto marginEndAdjustemnt = -formattingContext.geometryForBox(layoutBox).marginEnd();
            auto logicalWidth = run.logicalWidth() + marginEndAdjustemnt;
            auto inlineBoxLogicalRight = logicalLeft + logicalWidth;
            // When the content pulls the </span> to the logical left direction (e.g. negative letter space)
            // make sure we don't end up with negative logical width on the inline box.
            inlineBox.setLogicalWidth(std::max(0.f, inlineBoxLogicalRight - inlineBox.logicalLeft()));
            inlineBox.setIsLastBox();
            continue;
        }
        if (run.isListMarker()) {
            auto& listMarkerBox = downcast<ElementBox>(layoutBox);
            if (!listMarkerBox.isListMarkerImage()) {
                // Non-image type of list markers make their parent inline boxes (e.g. root inline box) contentful (and stretch them vertically).
                lineBox.parentInlineBox(run).setHasContent();
            }

            if (run.isListMarkerOutside())
                m_outsideListMarkers.append(index);

            auto atomicInlineBox = InlineLevelBox::createAtomicInlineBox(listMarkerBox, style, logicalLeft, formattingContext.geometryForBox(listMarkerBox).borderBoxWidth());
            setVerticalPropertiesForInlineLevelBox(lineBox, atomicInlineBox);
            lineBox.addInlineLevelBox(WTF::move(atomicInlineBox));
            continue;
        }
        if (run.isWordBreakOpportunity()) {
            lineBox.addInlineLevelBox(InlineLevelBox::createGenericInlineLevelBox(layoutBox, style, logicalLeft));
            continue;
        }
        ASSERT(run.isOutOfFlow());
    }
}

void LineBoxBuilder::constructBlockContent(LineBox& lineBox)
{
    auto& lineLayoutResult = this->lineLayoutResult();
    auto& runs = lineLayoutResult.runs;
    if (runs.isEmpty() || !runs.last().isBlock()) {
        ASSERT_NOT_REACHED();
        return;
    }

    // Since we don't need to position and align block content inside the line, we don't need to create any boxes for this block content.
    auto& blockRun = runs.last();
    ASSERT(blockRun.isBlock());
    auto& blockGeometry = formattingContext().geometryForBox(blockRun.layoutBox());
    for (size_t index = 0;  index < runs.size() - 1; ++index) {
        auto& run = runs[index];
        if (run.isLineSpanningInlineBoxStart()) {
            auto inlineBoxWidth = blockRun.logicalWidth() ? lineLayoutResult.lineGeometry.logicalWidth : 0.f;
            auto lineSpanningInlineBox = InlineLevelBox::createInlineBox(run.layoutBox(), run.layoutBox().style(), lineLayoutResult.contentGeometry.logicalLeft, inlineBoxWidth, InlineLevelBox::LineSpanningInlineBox::Yes);
            setVerticalPropertiesForInlineLevelBox(lineBox, lineSpanningInlineBox);
            lineSpanningInlineBox.setLogicalTop(blockGeometry.marginBefore());
            lineSpanningInlineBox.setLogicalHeight(InlineLayoutUnit(blockGeometry.borderBoxHeight()));
            lineBox.addInlineLevelBox(WTF::move(lineSpanningInlineBox));
            continue;
        }
        ASSERT_NOT_REACHED();
    }

    auto blockLineLogicalTopLeft = InlineLayoutPoint { lineLayoutResult.lineGeometry.initialLogicalTopLeft.x(), lineLayoutResult.lineGeometry.logicalTopLeft.y() };
    lineBox.setLogicalRect({ blockLineLogicalTopLeft, lineLayoutResult.lineGeometry.logicalWidth, blockGeometry.marginBoxHeight() });
    setVerticalPropertiesForInlineLevelBox(lineBox, lineBox.rootInlineBox());
}

void LineBoxBuilder::adjustInlineBoxHeightsForLineBoxContainIfApplicable(LineBox& lineBox)
{
    // While line-box-contain normally tells whether a certain type of content should be included when computing the line box height,
    // font and Glyphs values affect the "size" of the associated inline boxes (which then affect the line box height).
    auto lineBoxContain = rootBox().style().lineBoxContain();
    // Collect layout bounds based on the contain property and set them on the inline boxes when they are applicable.
    HashMap<InlineLevelBox*, TextUtil::EnclosingAscentDescent> inlineBoxBoundsMap;

    if (lineBoxContain.contains(Style::WebkitLineBoxContainValue::InlineBox)) {
        for (auto& inlineLevelBox : lineBox.nonRootInlineLevelBoxes()) {
            if (!inlineLevelBox.isInlineBox())
                continue;
            auto& inlineBoxGeometry = formattingContext().geometryForBox(inlineLevelBox.layoutBox());
            auto ascent = inlineLevelBox.ascent() + inlineBoxGeometry.marginBorderAndPaddingBefore();
            auto descent = inlineLevelBox.descent() + inlineBoxGeometry.marginBorderAndPaddingAfter();
            inlineBoxBoundsMap.set(&inlineLevelBox, TextUtil::EnclosingAscentDescent { ascent, descent });
        }
    }

    if (lineBoxContain.contains(Style::WebkitLineBoxContainValue::Font)) {
        // Assign font based layout bounds to all inline boxes.
        auto ensureFontMetricsBasedHeight = [&] (auto& inlineBox) {
            ASSERT(inlineBox.isInlineBox());
            auto [ascent, descent] = primaryFontMetricsForInlineBox(inlineBox, lineBox.baselineType());
            auto lineGap = InlineFormattingUtils::snapToInt(inlineBox.primarymetricsOfPrimaryFont().lineSpacing(), inlineBox);
            auto halfLeading = !rootBox().isRubyAnnotationBox() ? (lineGap - (ascent + descent)) / 2 : 0.f;
            ascent += halfLeading;
            descent += halfLeading;
            if (auto fallbackFonts = m_fallbackFontsForInlineBoxes.get(&inlineBox); !fallbackFonts.isEmptyIgnoringNullReferences()) {
                auto enclosingAscentAndDescent = enclosingAscentDescentWithFallbackFonts(inlineBox, fallbackFonts, lineBox.baselineType());
#if PLATFORM(DRIFTSTACK)
                // W2980e (#120 glyph-1600 cluster B — the +23 default-strut, the UNGUARDED site the
                // browserleaks <div><span> block-default probe hits). This is the `lineBoxContain=Font`
                // (ensureFontMetricsBasedHeight) path; the W2980 guard at the Alphabetic/Ideographic sites
                // (559/847) never covered it, so the fork stretched the default-generic strut to a MARGINALLY
                // taller fallback enclosure (U+2581/U+2B06/U+21E4/U+20B0/U+3095/U+532D default 1933) where a
                // real iPhone keeps the primary SF-Pro strut (1910) — the 6 "+23" cells. On iOS the -apple-
                // system cascade routes these CJK-symbol/arrow cps to a fallback whose metrics FIT WITHIN the
                // SF-Pro strut (the .Hiragino Kaku Gothic Interface / CJK-symbols-fallback cut, lineH within
                // SF-Pro's box on iOS), so no stretch; the Mac host cascade picks Hiragino-Sans-W3 (lineH
                // 2401) whose enclosure marginally exceeds 1910 → spurious +23.
                //
                // SCOPED PRECISELY (the grid is the ground truth — a blanket SF-default suppress would REGRESS
                // ~14 genuinely-tall default cells the fork already matches, e.g. U+17DD 3179 / U+A830 2660 /
                // U+0700 2302 that iOS DOES stretch): suppress ONLY when (a) the primary is the SF default
                // base AND (b) the fallback enclosure is only MARGINALLY above the primary strut
                // (< kSfDefaultStrutKeepBelow). The 6 +23 cells land at exactly 1933 (Δ23 over 1910); the
                // next-tallest KEEP cell is U+08E4/U+2425 at 1988 — so a 1960 cutoff cleanly separates them
                // (the marginal Hiragino-W3-vs-Interface +23 is suppressed; the genuinely-tall scripts keep
                // their iOS-matching stretch). Width is UNTOUCHED (this only caps height; U+21E4/20B0/2B06/20E3
                // default WIDTH is a separate default-base-coverage problem handled in FontCacheCoreText).
                //
                // 16px-SAFE: at 16px every generic column is a flat per-generic constant (24/24/25/25/26/28 —
                // the body line-height:1.5 floor dominates, the font strut is hidden), so changing the 1600px
                // line-box strut is structurally invisible at 16px → glyphHash c587ed44 cannot move.
                // Large-size gate (matches the cluster-A pointSize>=100 discipline): fires only at the 1600px
                // probe band, NEVER the 16/13px glyphHash sizes — double-guarding 16px-safety even though the
                // line-height:1.5 floor already hides the strut there.
                constexpr float kSfDefaultStrutKeepBelow = 1960.f;
                bool driftstackSuppressFallbackStretch = inlineBox.fontSize() >= 100.f
                    && driftstackPrimaryFontIsSfSystemBase(inlineBox)
                    && (enclosingAscentAndDescent.ascent + enclosingAscentAndDescent.descent) < kSfDefaultStrutKeepBelow
                    && (enclosingAscentAndDescent.ascent + enclosingAscentAndDescent.descent) > (ascent + descent);
                if (!driftstackSuppressFallbackStretch)
#endif
                {
                ascent = std::max(ascent, enclosingAscentAndDescent.ascent);
                descent = std::max(descent, enclosingAscentAndDescent.descent);
                }
            }
            inlineBoxBoundsMap.set(&inlineBox, TextUtil::EnclosingAscentDescent { ascent, descent });
        };

        ensureFontMetricsBasedHeight(lineBox.rootInlineBox());
        for (auto& inlineLevelBox : lineBox.nonRootInlineLevelBoxes()) {
            if (!inlineLevelBox.isInlineBox())
                continue;
            ensureFontMetricsBasedHeight(inlineLevelBox);
        }
    }

    if (lineBoxContain.contains(Style::WebkitLineBoxContainValue::Glyphs)) {
        // Compute text content (glyphs) hugging inline box layout bounds.
        for (auto run : lineLayoutResult().runs) {
            if (!run.isText())
                continue;

            auto& textBox = downcast<InlineTextBox>(run.layoutBox());
            auto& textContent = run.textContent();
            auto& style = isFirstFormattedLine() ? textBox.firstLineStyle() : textBox.style();
            auto enclosingAscentDescentForRun = TextUtil::enclosingGlyphBoundsForText(StringView(textBox.content()).substring(textContent.start, textContent.length), style, textBox.shouldUseSimpleGlyphOverflowCodePath() ? TextUtil::ShouldUseSimpleGlyphOverflowCodePath::Yes : TextUtil::ShouldUseSimpleGlyphOverflowCodePath::No);

            auto& parentInlineBox = lineBox.parentInlineBox(run);
            auto enclosingAscentDescentForInlineBox = inlineBoxBoundsMap.get(&parentInlineBox);
            enclosingAscentDescentForInlineBox.ascent = std::max(enclosingAscentDescentForInlineBox.ascent, -enclosingAscentDescentForRun.ascent);
            enclosingAscentDescentForInlineBox.descent = std::max(enclosingAscentDescentForInlineBox.descent, enclosingAscentDescentForRun.descent);

            inlineBoxBoundsMap.set(&parentInlineBox, enclosingAscentDescentForInlineBox);
        }
    }

    if (lineBoxContain.contains(Style::WebkitLineBoxContainValue::InitialLetter)) {
        // Initial letter contain is based on the font metrics cap geometry and we hug descent.
        auto& rootInlineBox = lineBox.rootInlineBox();
        auto& fontMetrics = rootInlineBox.primarymetricsOfPrimaryFont();
        auto initialLetterAscent = InlineFormattingUtils::snapToInt(fontMetrics.capHeight().value_or(0.f), rootInlineBox);
        auto initialLetterDescent = InlineLayoutUnit { };

        for (auto run : lineLayoutResult().runs) {
            // We really should only have one text run for initial letter.
            if (!run.isText())
                continue;

            auto& textBox = downcast<InlineTextBox>(run.layoutBox());
            auto& textContent = run.textContent();
            auto& style = isFirstFormattedLine() ? textBox.firstLineStyle() : textBox.style();
            auto ascentAndDescent = TextUtil::enclosingGlyphBoundsForText(StringView(textBox.content()).substring(textContent.start, textContent.length), style, textBox.shouldUseSimpleGlyphOverflowCodePath() ? TextUtil::ShouldUseSimpleGlyphOverflowCodePath::Yes : TextUtil::ShouldUseSimpleGlyphOverflowCodePath::No);

            initialLetterDescent = ascentAndDescent.descent;
            if (lineBox.baselineType() != FontBaseline::Alphabetic)
                initialLetterAscent = -ascentAndDescent.ascent;
            break;
        }
        inlineBoxBoundsMap.set(&rootInlineBox, TextUtil::EnclosingAscentDescent { initialLetterAscent, initialLetterDescent });
    }

    for (auto entry : inlineBoxBoundsMap) {
        auto* inlineBox = entry.key;
        auto enclosingAscentDescentForInlineBox = entry.value;
        auto inlineBoxLayoutBounds = inlineBox->layoutBounds();

        // "line-box-container: block" The extended block progression dimension of the root inline box must fit within the line box.
        auto mayShrinkLineBox = inlineBox->isRootInlineBox() ? !lineBoxContain.contains(Style::WebkitLineBoxContainValue::Block) : true;
        auto ascent = mayShrinkLineBox ? enclosingAscentDescentForInlineBox.ascent : std::max(enclosingAscentDescentForInlineBox.ascent, inlineBoxLayoutBounds.ascent);
        auto descent = mayShrinkLineBox ? enclosingAscentDescentForInlineBox.descent : std::max(enclosingAscentDescentForInlineBox.descent, inlineBoxLayoutBounds.descent);
        inlineBox->setLayoutBounds({ InlineFormattingUtils::snapToInt(ascent, *inlineBox, InlineFormattingUtils::SnapDirection::Ceil), InlineFormattingUtils::snapToInt(descent, *inlineBox, InlineFormattingUtils::SnapDirection::Ceil) });
    }
}

void LineBoxBuilder::adjustIdeographicBaselineIfApplicable(LineBox& lineBox)
{
    // Re-compute the ascent/descent values for the inline boxes on the line (including the root inline box)
    // when the style/content needs ideographic baseline setup in vertical writing mode.
    auto& rootInlineBox = lineBox.rootInlineBox();

    auto lineNeedsIdeographicBaseline = [&] {
        auto styleToUse = [&] (auto& inlineLevelBox) -> const RenderStyle& {
            return isFirstFormattedLine() ? inlineLevelBox.layoutBox().firstLineStyle() : inlineLevelBox.layoutBox().style();
        };
        auto& rootInlineBoxStyle = styleToUse(rootInlineBox);
        if (rootInlineBoxStyle.writingMode().isHorizontal())
            return false;

        auto primaryFontRequiresIdeographicBaseline = [&] (auto& style) {
            return style.fontDescription().orientation() == FontOrientation::Vertical || style.fontCascade().primaryFont().hasVerticalGlyphs();
        };

        if (m_fallbackFontRequiresIdeographicBaseline || primaryFontRequiresIdeographicBaseline(rootInlineBoxStyle))
            return true;
        for (auto& inlineLevelBox : lineBox.nonRootInlineLevelBoxes()) {
            if (inlineLevelBox.isInlineBox() && primaryFontRequiresIdeographicBaseline(styleToUse(inlineLevelBox)))
                return true;
        }
        return false;
    };

    if (!lineNeedsIdeographicBaseline())
        return;

    lineBox.setBaselineType(FontBaseline::Ideographic);

    auto adjustLayoutBoundsWithIdeographicBaseline = [&] (auto& inlineLevelBox) {
        auto initiatesLayoutBoundsChange = inlineLevelBox.isInlineBox() || inlineLevelBox.isAtomicInlineBox() || inlineLevelBox.isLineBreakBox();
        if (!initiatesLayoutBoundsChange)
            return;

        if (inlineLevelBox.isInlineBox() || inlineLevelBox.isLineBreakBox() || (inlineLevelBox.isListMarker() && !downcast<ElementBox>(inlineLevelBox.layoutBox()).isListMarkerImage()))
            setVerticalPropertiesForInlineLevelBox(lineBox, inlineLevelBox);
        else if (inlineLevelBox.isAtomicInlineBox()) {
            auto inlineLevelBoxHeight = inlineLevelBox.logicalHeight();
            InlineLayoutUnit ideographicBaseline = roundToInt(inlineLevelBoxHeight / 2);
            // Move the baseline position but keep the same logical height.
            inlineLevelBox.setAscentAndDescent({ ideographicBaseline, inlineLevelBoxHeight - ideographicBaseline });
            inlineLevelBox.setLayoutBounds({ ideographicBaseline, inlineLevelBoxHeight - ideographicBaseline });
        }

        auto needsFontFallbackAdjustment = inlineLevelBox.isInlineBox();
        if (needsFontFallbackAdjustment) {
#if PLATFORM(DRIFTSTACK)
            // W2980 (#117): same primary-font-strut pin as the Alphabetic-baseline path above, for the
            // ideographic-baseline (vertical/CJK) variant — keep the strut on the primary font so the
            // line-box height is glyph-independent (uniform per generic, any size) like a real iPhone.
            static const bool s_primaryFontStrutI = [] {
                const char* e = getenv("DRIFTSTACK_PRIMARY_FONT_STRUT");
                return e && e[0] == '1';
            }();
            if (s_primaryFontStrutI) {
                // Leave the strut at the primary font's layout bounds (no fallback over-stretch).
            } else
#endif
            if (auto fallbackFonts = m_fallbackFontsForInlineBoxes.get(&inlineLevelBox); !fallbackFonts.isEmptyIgnoringNullReferences() && inlineLevelBox.isPreferredLineHeightFontMetricsBased()) {
                auto enclosingAscentAndDescent = enclosingAscentDescentWithFallbackFonts(inlineLevelBox, fallbackFonts, FontBaseline::Ideographic);
                auto layoutBounds = inlineLevelBox.layoutBounds();
                inlineLevelBox.setLayoutBounds({ std::max(layoutBounds.ascent, enclosingAscentAndDescent.ascent), std::max(layoutBounds.descent, enclosingAscentAndDescent.descent) });
            }
        }
    };

    adjustLayoutBoundsWithIdeographicBaseline(rootInlineBox);
    for (auto& inlineLevelBox : lineBox.nonRootInlineLevelBoxes()) {
        if (inlineLevelBox.isAtomicInlineBox()) {
            auto& layoutBox = inlineLevelBox.layoutBox();
            if (layoutBox.isInlineTableBox()) {
                // This is the integration codepath where inline table boxes are represented as atomic inline boxes.
                // Integration codepath sets ideographic baseline by default for non-horizontal content.
                continue;
            }
            auto isInlineBlockWithNonSyntheticBaseline = layoutBox.isInlineBlockBox() && downcast<ElementBox>(layoutBox).baselineForIntegration().has_value();
            if (isInlineBlockWithNonSyntheticBaseline && !layoutBox.writingMode().isHorizontal())
                continue;
        }
        adjustLayoutBoundsWithIdeographicBaseline(inlineLevelBox);
    }
}

static Style::TextEdgePair effectiveTextBoxEdge(const InlineLevelBox& rootInlineBox, const BlockLayoutState& blockLayoutState)
{
    // TextBoxEdge property specifies the metrics to use for text-box-trim effects. Values have the same meanings as for line-fit-edge;
    // the auto keyword uses the value of line-fit-edge on the root inline of the the affected line box,
    // interpreting leading (the initial value) as text.
    // https://drafts.csswg.org/css-inline-3/#text-box-edge
    return WTF::switchOn(blockLayoutState.textBoxEdge(),
        [&](Style::TextEdgePair edgePair) {
            return edgePair;
        },
        [&](CSS::Keyword::Auto) {
            return WTF::switchOn(rootInlineBox.lineFitEdge(),
                [&](Style::TextEdgePair edgePair) {
                    return edgePair;
                },
                [&](CSS::Keyword::Leading) {
                    return Style::TextEdgePair { TextEdgeOver::Text, TextEdgeUnder::Text };
                }
            );
        }
    );
}

InlineLayoutUnit LineBoxBuilder::applyTextBoxTrimOnLineBoxIfNeeded(InlineLayoutUnit lineBoxLogicalHeight, LineBox& lineBox) const
{
    auto& rootInlineBox = lineBox.rootInlineBox();
    auto textBoxTrim = blockLayoutState().textBoxTrim();
    auto textBoxEdge = effectiveTextBoxEdge(rootInlineBox, blockLayoutState());
    auto shouldTrimBlockStartOfLineBox = isFirstFormattedLine() && textBoxTrim.contains(BlockLayoutState::TextBoxTrimSide::Start);
    auto shouldTrimBlockEndOfLineBox = isLastLine() && textBoxTrim.contains(BlockLayoutState::TextBoxTrimSide::End);
    if (!shouldTrimBlockStartOfLineBox && !shouldTrimBlockEndOfLineBox)
        return lineBoxLogicalHeight;

    auto& primaryFontMetrics = rootInlineBox.primarymetricsOfPrimaryFont();
    if (shouldTrimBlockEndOfLineBox) {
        auto textBoxEdgeUnderForRootInlineBox = [&] -> InlineLayoutUnit {
            switch (textBoxEdge.under) {
            case TextEdgeUnder::Text:
                return 0.f;
            case TextEdgeUnder::Alphabetic:
                return InlineFormattingUtils::descent(primaryFontMetrics, FontBaseline::Alphabetic, rootInlineBox);
            case TextEdgeUnder::Ideographic:
            case TextEdgeUnder::IdeographicInk:
                ASSERT_NOT_IMPLEMENTED_YET();
                return 0.f;
            }
            RELEASE_ASSERT_NOT_REACHED();
        }();
        auto needToTrimThisMuch = std::max(0.f, (lineBoxLogicalHeight - rootInlineBox.logicalBottom()) + textBoxEdgeUnderForRootInlineBox);
        lineBoxLogicalHeight -= needToTrimThisMuch;
    }
    if (shouldTrimBlockStartOfLineBox) {
        auto textBoxEdgeOverForRootInlineBox = [&] -> InlineLayoutUnit {
            switch (textBoxEdge.over) {
            case TextEdgeOver::Text:
                return 0.f;
            case TextEdgeOver::Cap:
                return InlineFormattingUtils::ascent(primaryFontMetrics, FontBaseline::Alphabetic, rootInlineBox) - InlineFormattingUtils::snapToInt(primaryFontMetrics.capHeight().value_or(0.f), rootInlineBox);
            case TextEdgeOver::Ex:
                return InlineFormattingUtils::ascent(primaryFontMetrics, FontBaseline::Alphabetic, rootInlineBox) - InlineFormattingUtils::snapToInt(primaryFontMetrics.xHeight().value_or(0.f), rootInlineBox);
            case TextEdgeOver::Ideographic:
            case TextEdgeOver::IdeographicInk:
                ASSERT_NOT_IMPLEMENTED_YET();
                return 0.f;
            }
            RELEASE_ASSERT_NOT_REACHED();
        };
        auto needToTrimThisMuch = std::max(0.f, lineLayoutResult().lineGeometry.initialLetterClearGap.value_or(0_lu) + rootInlineBox.logicalTop() + textBoxEdgeOverForRootInlineBox());
        lineBoxLogicalHeight -= needToTrimThisMuch;

        auto adjustRootInlineAndBottomAlignedBoxes = [&] {
            // When trimming makes the line box move up, bottom aligned boxes has to follow the root inline box.
            // All other boxes can keep their vertical positions relative to the line box top.
            for (auto& inlineLevelBox : lineBox.nonRootInlineLevelBoxes()) {
                if (!WTF::holdsAlternative<CSS::Keyword::Bottom>(inlineLevelBox.verticalAlign()))
                    continue;
                inlineLevelBox.setLogicalTop(inlineLevelBox.logicalTop() - needToTrimThisMuch);
            }
            rootInlineBox.setLogicalTop(rootInlineBox.logicalTop() - needToTrimThisMuch);
        };
        adjustRootInlineAndBottomAlignedBoxes();
        m_lineLayoutResult.firstLineStartTrim = needToTrimThisMuch;
    }
    return lineBoxLogicalHeight;
}

void LineBoxBuilder::computeLineBoxGeometry(LineBox& lineBox) const
{
    auto lineBoxLogicalHeight = applyTextBoxTrimOnLineBoxIfNeeded(LineBoxVerticalAligner { formattingContext() }.computeLogicalHeightAndAlign(lineBox, lineLayoutResult().hasContentfulInlineContent()), lineBox);
    if (formattingContext().quirks().shouldCollapseLineBoxHeight(lineLayoutResult().runs, m_outsideListMarkers.size()))
        lineBoxLogicalHeight = { };
    lineBox.setLogicalRect({ lineLayoutResult().lineGeometry.logicalTopLeft, lineLayoutResult().lineGeometry.logicalWidth, lineBoxLogicalHeight });
}

void LineBoxBuilder::adjustOutsideListMarkersPosition(LineBox& lineBox)
{
    auto lineBoxRect = lineBox.logicalRect();
    auto floatConstraints = formattingContext().floatingContext().constraints(LayoutUnit { lineBoxRect.top() }, LayoutUnit { lineBoxRect.bottom() }, FloatingContext::MayBeAboveLastFloat::No);

    auto lineBoxOffset = lineBoxRect.left() - (lineLayoutResult().lineGeometry.initialLogicalTopLeft.x() + lineLayoutResult().lineGeometry.intrusiveFloatsOffset);
    auto rootInlineBoxLogicalLeft = lineBox.logicalRectForRootInlineBox().left();
    auto rootInlineBoxOffsetFromContentBoxOrIntrusiveFloat = lineBoxOffset + rootInlineBoxLogicalLeft;
    for (auto listMarkerBoxIndex : m_outsideListMarkers) {
        auto& listMarkerRun = lineLayoutResult().runs[listMarkerBoxIndex];
        ASSERT(listMarkerRun.isListMarkerOutside());
        auto& listMarkerBox = downcast<ElementBox>(listMarkerRun.layoutBox());
        auto& listMarkerInlineLevelBox = lineBox.inlineLevelBoxFor(listMarkerRun);
        // Move it to the logical left of the line box (from the logical left of the root inline box).
        auto listMarkerInitialOffsetFromRootInlineBox = listMarkerInlineLevelBox.logicalLeft() - rootInlineBoxOffsetFromContentBoxOrIntrusiveFloat;
        auto logicalLeft = listMarkerInitialOffsetFromRootInlineBox;
        auto nestedListMarkerMarginStart = [&] {
            auto nestedOffset = layoutState().nestedListMarkerOffset(listMarkerBox);
            if (nestedOffset == LayoutUnit::min())
                return 0_lu;
            // Nested list markers (in standards mode) share the same line and have offsets as if they had dedicated lines.
            // <!DOCTYPE html>
            // <ul><li><ul><li>markers on the same line in standards mode
            // vs.
            // <ul><li><ul><li>markers with dedicated lines in quirks mode
            // or
            // <!DOCTYPE html>
            // <ul><li>markers<ul><li>with dedicated lines
            // While a float may not constrain the line, it could constrain the nested list marker (being it outside of the line box to the logical left).  
            // FIXME: We may need to do this in a post-process task after the line box geometry is computed.
            return floatConstraints.start ? std::min(0_lu, std::max(floatConstraints.start->x, nestedOffset)) : nestedOffset;
        }();
        adjustMarginStartForListMarker(listMarkerBox, nestedListMarkerMarginStart, rootInlineBoxOffsetFromContentBoxOrIntrusiveFloat);
        logicalLeft += nestedListMarkerMarginStart;
        listMarkerInlineLevelBox.setLogicalLeft(logicalLeft);
    }
}

void LineBoxBuilder::adjustMarginStartForListMarker(const ElementBox& listMarkerBox, LayoutUnit nestedListMarkerMarginStart, InlineLayoutUnit rootInlineBoxOffset) const
{
    if (!nestedListMarkerMarginStart && !rootInlineBoxOffset)
        return;
    auto& listMarkerGeometry = const_cast<InlineFormattingContext&>(formattingContext()).geometryForBox(listMarkerBox);
    // Make sure that the line content does not get pulled in to logical left direction due to
    // the large negative margin (i.e. this ensures that logical left of the list content stays at the line start)
    listMarkerGeometry.setHorizontalMargin({ listMarkerGeometry.marginStart() + nestedListMarkerMarginStart - LayoutUnit { rootInlineBoxOffset }, listMarkerGeometry.marginEnd() - nestedListMarkerMarginStart + LayoutUnit { rootInlineBoxOffset } });
}

void LineBoxBuilder::expandAboveRootInlineBox(LineBox& lineBox, InlineLayoutUnit expansion) const
{
    lineBox.rootInlineBox().setLogicalTop(lineBox.rootInlineBox().logicalTop() + expansion);
    auto lineBoxRect = lineBox.logicalRect();
    lineBoxRect.expandVertically(expansion);
    lineBox.setLogicalRect(lineBoxRect);
}

}
}

