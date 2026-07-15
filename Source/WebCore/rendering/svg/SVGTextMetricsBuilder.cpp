/*
 * Copyright (C) Research In Motion Limited 2010-2012. All rights reserved.
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
#include "SVGTextMetricsBuilder.h"

#include "ComplexTextController.h"
#include "FontCascadeCache.h"
#include "FontCascadeInlines.h"
#include "RenderChildIterator.h"
#include "RenderSVGInline.h"
#include "RenderSVGInlineText.h"
#include "RenderSVGText.h"
#include "RenderStyle+GettersInlines.h"
#include "WidthIterator.h"
#include <wtf/WeakPtr.h>
#if PLATFORM(DRIFTSTACK)
#include <wtf/text/CharacterProperties.h>
#endif

namespace WebCore {

SVGTextMetricsBuilder::SVGTextMetricsBuilder()
    : m_run(StringView())
    , m_textPosition(0)
    , m_isComplexText(false)
    , m_totalWidth(0)
{
}

inline bool SVGTextMetricsBuilder::currentCharacterStartsSurrogatePair() const
{
    return U16_IS_LEAD(m_run[m_textPosition]) && (m_textPosition + 1) < m_run.length() && U16_IS_TRAIL(m_run[m_textPosition + 1]);
}

template<typename Iterator>
bool SVGTextMetricsBuilder::advance(Iterator& iterator)
{
    m_textPosition += m_currentMetrics.length();
    if (m_textPosition >= m_run.length())
        return false;

    advanceIterator(iterator);
    return m_currentMetrics.length() > 0;
}

void SVGTextMetricsBuilder::advanceIterator(WidthIterator& simpleWidthIterator)
{
    GlyphBuffer glyphBuffer;
    auto before = simpleWidthIterator.currentCharacterIndex();
    simpleWidthIterator.advance(m_textPosition + 1, glyphBuffer);
    auto after = simpleWidthIterator.currentCharacterIndex();
    if (before == after) {
        m_currentMetrics = SVGTextMetrics();
        return;
    }

    float currentWidth = simpleWidthIterator.runWidthSoFar() - m_totalWidth;
    m_totalWidth = simpleWidthIterator.runWidthSoFar();

    m_currentMetrics = SVGTextMetrics(*m_text, after - before, currentWidth);
}

void SVGTextMetricsBuilder::advanceIterator(ComplexTextController& complexTextController)
{
    unsigned metricsLength = currentCharacterStartsSurrogatePair() ? 2 : 1;
    float beforeWidth = 0;
    float afterWidth = 0;

    complexTextController.advance(m_textPosition, nullptr);
    beforeWidth = complexTextController.runWidthSoFar();

    complexTextController.advance(m_textPosition + metricsLength, nullptr);
    afterWidth = complexTextController.runWidthSoFar();

    m_currentMetrics = SVGTextMetrics(*m_text, metricsLength, afterWidth - beforeWidth);
    m_complexStartToCurrentMetrics = SVGTextMetrics(*m_text, m_textPosition + metricsLength, afterWidth);

    ASSERT(m_currentMetrics.length() == metricsLength);

    // Frequent case for Arabic text: when measuring a single character the arabic isolated form is taken
    // when rendering the glyph "in context" (with it's surrounding characters) it changes due to shaping.
    // So whenever currentWidth != currentMetrics.width(), we are processing a text run whose length is
    // not equal to the sum of the individual lengths of the glyphs, when measuring them isolated.
    float currentWidth = m_complexStartToCurrentMetrics.width() - m_totalWidth;
    if (currentWidth != m_currentMetrics.width())
        m_currentMetrics.setWidth(currentWidth);

    m_totalWidth = m_complexStartToCurrentMetrics.width();
}

#if PLATFORM(DRIFTSTACK)
// svgrect launch tell (real iPhone 17 / Safari 26.4, creepjsdomrect svgrectEmoji): iOS reports EVERY
// color-emoji grapheme cluster's SVG getComputedTextLength at a uniform cell of 1.0006670379638672 *
// fontSize (== 200.13340759 @200px), whereas canvas measureText reports exactly fontSize (the W554
// FontCoreText color-glyph override, byte-correct FOR CANVAS — real iPhone canvas emoji == fontSize). iOS
// itself differs between the two surfaces for color emoji; the fork routes both through W554, so its SVG
// total is fontSize (200) and diverges from iOS SVG (200.133). The fork additionally distributes a
// cluster's advance across its component glyphs (incl. visible joiners for un-ligated ZWJ sequences), so
// the correction must be per grapheme-CLUSTER, not per character.
//
// Post-pass: group this renderer's run into emoji grapheme clusters (a cluster extends across ZWJ /
// variation selectors / Fitzpatrick modifiers / tag chars / the codepoint following a ZWJ / the 2nd
// regional indicator). For each cluster whose BASE resolves to a COLOR glyph (colorGlyphType == Color —
// the exact discriminator: the gender signs ♀/♂ that iOS keeps at 200 are Outline; the text-rendered
// candidates ©/®/™/U+2049/U+2639/U+2695 and all CJK / other text are Outline too), scale that cluster's
// per-character metric widths so the cluster total equals the iOS cell. NON-color clusters are untouched,
// so a run with no color-emoji base is a strict no-op — pure-text SVG (incl. the separate #160 latin arc)
// is provably unaffected. Single per-color-glyph cell ratio, NOT a per-probe table (Rule 5).
// glyphHash-isolated: the glyph-unicode-fp probe has zero color emoji and measures canvas/DOM, never SVG.
void SVGTextMetricsBuilder::applyDriftstackSVGEmojiClusterCells()
{
    if (!m_text)
        return;
    float scalingFactor = m_text->scalingFactor();
    if (scalingFactor <= 0)
        return;
    const FontCascade& scaledFont = m_text->scaledFont();
    float logicalEm = scaledFont.size() / scalingFactor;
    if (logicalEm <= 0)
        return;
    auto* attributes = m_text->layoutAttributes();
    if (!attributes)
        return;
    auto& metrics = attributes->textMetricsValues();
    if (metrics.isEmpty())
        return;

    // Double-precision then cast so the em==200 probe lands on the EXACT real-iPhone float 200.13340759.
    const float cellWidth = static_cast<float>(1.0006670379638672 * static_cast<double>(logicalEm));
    StringView runText = m_run.text();
    unsigned runLength = runText.length();

    // Perf early-out: color emoji live at/above U+2000 (symbols/dingbats/pictographs; surrogate leads are
    // >= 0xD800). Pure Latin/Latin-ext SVG text is entirely below U+2000, so it never touches the per-cluster
    // glyph resolution below — this keeps the common case a cheap scan. (© U+00A9 / ® U+00AE are below the
    // threshold but are Outline glyphs that never need scaling, so skipping them is correct.)
    bool hasSymbolRange = false;
    for (unsigned p = 0; p < runLength; ++p) {
        if (runText[p] >= 0x2000) {
            hasSymbolRange = true;
            break;
        }
    }
    if (!hasSymbolRange)
        return;

    auto codePointAt = [&](unsigned pos) -> char32_t {
        char16_t c = runText[pos];
        if (U16_IS_LEAD(c) && pos + 1 < runLength && U16_IS_TRAIL(runText[pos + 1]))
            return U16_GET_SUPPLEMENTARY(c, runText[pos + 1]);
        return c;
    };
    auto isClusterContinuation = [](char32_t cp) -> bool {
        return cp == 0x200D                     // ZERO WIDTH JOINER
            || (cp >= 0xFE00 && cp <= 0xFE0F)   // variation selectors
            || (cp >= 0x1F3FB && cp <= 0x1F3FF) // Fitzpatrick skin-tone modifiers
            || (cp >= 0xE0020 && cp <= 0xE007F) // emoji tag sequence tags
            || (cp >= 0x1F1E6 && cp <= 0x1F1FF); // regional indicators (2nd of a flag pair)
    };
    auto colorProbe = [&](char32_t cp, FontVariant variant, std::optional<ResolvedEmojiPolicy> policy) -> bool {
        auto glyphData = scaledFont.glyphDataForCharacter(cp, false, variant, policy);
        return glyphData.font && glyphData.colorGlyphType == ColorGlyphType::Color;
    };
    auto baseIsColorEmoji = [&](char32_t cp) -> bool {
        // BMP: the live font resolution is reliable AND necessary — 2668/2139/arrows are text-default yet
        // render color in Apple Color Emoji, while ♀/♂ (2640/2642) and ©/®/™ are Outline and must be kept.
        if (colorProbe(cp, FontVariant::Auto, std::nullopt)
            || colorProbe(cp, FontVariant::Auto, ResolvedEmojiPolicy::RequireEmoji)
            || colorProbe(cp, FontVariant::Normal, ResolvedEmojiPolicy::RequireEmoji))
            return true;
        // Supplementary emoji: glyphDataForCharacter is unreliable here (the SVG complex measurement
        // invalidates the FontCascadeCache mid-pass, so it inconsistently reports Outline for 1F600/1F469/
        // 1F935/…). Every supplementary codepoint in the emoji blocks renders as a color cell, and the
        // keep-at-non-cell candidates (♀/♂/©/®/™/⁉/☹/⚕) are all BMP — so intrinsic emoji-ness is a safe
        // fallback above the BMP plane only.
        return cp > 0xFFFF && (isEmojiGroupCandidate(cp) || isEmojiWithPresentationByDefault(cp));
    };

    bool diag = std::getenv("DRIFTSTACK_SVGEMOJI_DIAG");
    unsigned charPos = 0;
    size_t i = 0;
    while (i < metrics.size() && charPos < runLength) {
        char32_t baseCharacter = codePointAt(charPos);
        size_t clusterStart = i;
        double clusterSum = metrics[i].width();
        unsigned len = metrics[i].length();
        unsigned nextPos = charPos + (len ? len : 1);
        bool prevWasZWJ = baseCharacter == 0x200D;
        ++i;
        // Extend the cluster across continuation codepoints (and the codepoint right after a ZWJ).
        while (i < metrics.size() && nextPos < runLength) {
            char32_t nextCharacter = codePointAt(nextPos);
            if (!prevWasZWJ && !isClusterContinuation(nextCharacter))
                break;
            clusterSum += metrics[i].width();
            unsigned nlen = metrics[i].length();
            prevWasZWJ = nextCharacter == 0x200D;
            nextPos += (nlen ? nlen : 1);
            ++i;
        }
        bool isColor = clusterSum > 0.0 && baseIsColorEmoji(baseCharacter);
        if (isColor) {
            // Assign the whole cell to the first metric and zero the continuations, so the cluster total
            // is EXACTLY the iOS cell (per-metric float scaling would leave a sub-ULP residue on multi-glyph
            // ZWJ clusters). Preserve corrected-minus-natural on every changed metric so substring queries
            // can add only this SVG-specific correction after their normal isolated-range measurement.
            // getComputedTextLength still sums the corrected cluster metrics -> exactly cellWidth.
            auto setCorrectedWidth = [&](size_t index, float correctedWidth) {
                auto& metric = metrics[index];
                metric.setDriftstackSVGEmojiWidthAdjustment(correctedWidth - metric.width());
                metric.setWidth(correctedWidth);
            };
            setCorrectedWidth(clusterStart, cellWidth);
            for (size_t k = clusterStart + 1; k < i; ++k)
                setCorrectedWidth(k, 0);
        }
        if (diag)
            WTFLogAlways("[DS-SVGEMOJI] base=U+%05X chars=%zu sum=%.6f color=%d -> %s",
                static_cast<unsigned>(baseCharacter), i - clusterStart, clusterSum, isColor ? 1 : 0,
                isColor ? "cell" : "kept");
        charPos = nextPos;
    }
}
#endif

static inline bool NODELETE shouldUseComplexTextController(FontCascade::CodePath codePathToUse, const FontCascade& scaledFont)
{
#if PLATFORM(GTK) || PLATFORM(WPE)
    if (codePathToUse != FontCascade::CodePath::Complex && scaledFont.shouldUseComplexTextControllerForSimpleText())
        return true;
#else
    UNUSED_PARAM(scaledFont);
#endif
    return codePathToUse == FontCascade::CodePath::Complex;
}

void SVGTextMetricsBuilder::initializeMeasurementWithTextRenderer(RenderSVGInlineText& text)
{
    m_text = text;
    m_textPosition = 0;
    m_currentMetrics = SVGTextMetrics();
    m_complexStartToCurrentMetrics = SVGTextMetrics();
    m_totalWidth = 0;

    const FontCascade& scaledFont = text.scaledFont();
    m_run = SVGTextMetrics::constructTextRun(text);
    m_isComplexText = shouldUseComplexTextController(scaledFont.codePath(m_run), scaledFont);

    if (m_isComplexText)
        FontCascadeCache::forCurrentThread().invalidate();

    m_canUseSimplifiedTextMeasuring = false;
    if (!m_isComplexText) {
        if (auto cachedValue = text.canUseSimplifiedTextMeasuring())
            m_canUseSimplifiedTextMeasuring = cachedValue.value();
        else {
            // Currently SVG implementation does not support first-line, so we always pass nullptr for firstLineStyle.
            // When supporting first-line, we also need to update firstLineStyle's FontCascade to be aligned with scaledFont in RenderSVGInlineText.
            m_canUseSimplifiedTextMeasuring = Layout::TextUtil::canUseSimplifiedTextMeasuring(m_run.text(), scaledFont, text.style().collapseWhiteSpace(), nullptr);
            text.setCanUseSimplifiedTextMeasuring(m_canUseSimplifiedTextMeasuring);
        }
    }
}

struct MeasureTextData {
    MeasureTextData(SVGCharacterDataMap* characterDataMap)
        : allCharactersMap(characterDataMap)
    {
    }

    SVGCharacterDataMap* allCharactersMap;
    bool processRenderer { false };
};

std::tuple<unsigned, char16_t> SVGTextMetricsBuilder::measureTextRenderer(RenderSVGInlineText& text, const MeasureTextData& data, std::tuple<unsigned, char16_t> state)
{
    SVGTextLayoutAttributes* attributes = text.layoutAttributes();
    ASSERT(attributes);
    Vector<SVGTextMetrics>& textMetricsValues = attributes->textMetricsValues();
    if (data.processRenderer) {
        if (data.allCharactersMap)
            attributes->clear();
        else
            textMetricsValues.shrink(0);
    }

    initializeMeasurementWithTextRenderer(text);

    auto& scaledFont = text.scaledFont();
    if (m_canUseSimplifiedTextMeasuring && data.processRenderer) {
        // If we are not specifying specific configuration for characters, data.allCharactersMap has only 1 entry for default case.
        // This is extremely common, and that's why we crafted a fast path here.
        // FIXME: For any cases, we are handling one character by one character in SVGTextMetrics. But many texts do not have
        // characterDataMap. We should handle multiple characters in one SVGTextMetrics. This also makes RTL work.
        // FIXME: This function is called even though width information is not changed at all. RenderSVGText / RenderSVGInlineText
        // should track the potential changes to width etc. and invoke this function only when it is actually changed.
        if (data.allCharactersMap && m_run.direction() == TextDirection::LTR && data.allCharactersMap->size() == 1) {
            constexpr unsigned defaultPosition = 1;
            ASSERT(data.allCharactersMap->contains(defaultPosition)); // "1" is the default value and always exists.
            auto characterData = data.allCharactersMap->get(defaultPosition);

            auto [valueListPosition, lastCharacter] = state;
            bool preserveWhiteSpace = text.style().whiteSpaceCollapse() == WhiteSpaceCollapse::Preserve;
            auto view = m_run.text();
            unsigned length = view.length();
            unsigned skippedCharacters = 0;
            float scalingFactor = text.scalingFactor();
            ASSERT(scalingFactor);
            float scaledHeight = scaledFont.metricsOfPrimaryFont().height() / scalingFactor;

            // m_canUseSimplifiedTextMeasuring ensures that this does not include surrogate pairs. So we do not need to consider about them.
            for (unsigned i = 0; i < length; ++i) {
                char16_t currentCharacter = view.codeUnitAt(i);
                ASSERT(!U16_IS_LEAD(currentCharacter));
                if (currentCharacter == space && !preserveWhiteSpace && (!lastCharacter || lastCharacter == space)) {
                    if (data.processRenderer)
                        textMetricsValues.append(SVGTextMetrics(SVGTextMetrics::SkippedSpaceMetrics));
                    ++skippedCharacters;
                    continue;
                }

                if ((valueListPosition + i - skippedCharacters + 1) == defaultPosition)
                    attributes->characterDataMap().set(i + 1, characterData);

                float width = scaledFont.widthForTextUsingSimplifiedMeasuring(view.substring(i, 1), TextDirection::LTR);
                float scaledWidth = width / scalingFactor;
                textMetricsValues.append(SVGTextMetrics(1, scaledWidth, scaledHeight));
                lastCharacter = currentCharacter;
            }

#if PLATFORM(DRIFTSTACK)
            applyDriftstackSVGEmojiClusterCells();
#endif
            return std::tuple { valueListPosition + length - skippedCharacters, lastCharacter };
        }
    }

    if (m_isComplexText) {
        ComplexTextController iterator(scaledFont, m_run, true);
        return measureTextRendererWithIterator(iterator, text, data, state);
    }

    WidthIterator iterator(scaledFont, m_run);
    return measureTextRendererWithIterator(iterator, text, data, state);
}

template<typename Iterator>
std::tuple<unsigned, char16_t> SVGTextMetricsBuilder::measureTextRendererWithIterator(Iterator& iterator, RenderSVGInlineText& text, const MeasureTextData& data, std::tuple<unsigned, char16_t> state)
{
    auto [valueListPosition, lastCharacter] = state;
    bool preserveWhiteSpace = text.style().whiteSpaceCollapse() == WhiteSpaceCollapse::Preserve;
    auto* attributes = text.layoutAttributes();
    auto& textMetricsValues = attributes->textMetricsValues();
    int surrogatePairCharacters = 0;
    unsigned skippedCharacters = 0;
    while (advance(iterator)) {
        char16_t currentCharacter = m_run[m_textPosition];
        if (currentCharacter == space && !preserveWhiteSpace && (!lastCharacter || lastCharacter == space)) {
            if (data.processRenderer)
                textMetricsValues.append(SVGTextMetrics(SVGTextMetrics::SkippedSpaceMetrics));
            skippedCharacters += m_currentMetrics.length();
            continue;
        }

        if (data.processRenderer) {
            if (data.allCharactersMap) {
                auto it = data.allCharactersMap->find(valueListPosition + m_textPosition - skippedCharacters - surrogatePairCharacters + 1);
                if (it != data.allCharactersMap->end())
                    attributes->characterDataMap().set(m_textPosition + 1, it->value);
            }
            textMetricsValues.append(m_currentMetrics);
        }

        if (data.allCharactersMap && currentCharacterStartsSurrogatePair())
            surrogatePairCharacters++;

        lastCharacter = currentCharacter;
    }

#if PLATFORM(DRIFTSTACK)
    if (data.processRenderer)
        applyDriftstackSVGEmojiClusterCells();
#endif
    return std::tuple { valueListPosition + m_textPosition - skippedCharacters, lastCharacter };
}

void SVGTextMetricsBuilder::walkTree(RenderElement& start, RenderSVGInlineText* stopAtLeaf, MeasureTextData& data)
{
    unsigned valueListPosition = 0;
    char16_t lastCharacter = 0;
    CheckedPtr child = start.firstChild();
    while (child) {
        if (auto* text = dynamicDowncast<RenderSVGInlineText>(*child)) {
            data.processRenderer = !stopAtLeaf || stopAtLeaf == text;
            std::tie(valueListPosition, lastCharacter) = measureTextRenderer(*text, data, std::tuple { valueListPosition, lastCharacter });
            if (stopAtLeaf && stopAtLeaf == text)
                return;
        } else if (auto* renderer = dynamicDowncast<RenderSVGInline>(*child)) {
            // Visit children of text content elements.
            if (auto* inlineChild = renderer->firstChild()) {
                child = inlineChild;
                continue;
            }
        }
        child = child->nextInPreOrderAfterChildren(&start);
    }
}

void SVGTextMetricsBuilder::measureTextRenderer(RenderSVGText& textRoot, RenderSVGInlineText* stopAtLeaf)
{
    MeasureTextData data(nullptr);
    walkTree(textRoot, stopAtLeaf, data);
}

void SVGTextMetricsBuilder::buildMetricsAndLayoutAttributes(RenderSVGText& textRoot, RenderSVGInlineText* stopAtLeaf, SVGCharacterDataMap& allCharactersMap)
{
    MeasureTextData data(&allCharactersMap);
    walkTree(textRoot, stopAtLeaf, data);
}

}
