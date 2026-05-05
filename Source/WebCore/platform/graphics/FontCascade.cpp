/*
 * Copyright (C) 1999 Lars Knoll (knoll@kde.org)
 *           (C) 1999 Antti Koivisto (koivisto@kde.org)
 *           (C) 2000 Dirk Mueller (mueller@kde.org)
 * Copyright (C) 2003-2025 Apple Inc. All rights reserved.
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
 *
 */

#include "config.h"
#include "FontCascade.h"

#include "ComplexTextController.h"
#include "DisplayList.h"
#include "DisplayListRecorderImpl.h"
#include "FloatRect.h"
#include "FontCache.h"
#include "FontCascadeInlines.h"
#include "FontInlines.h"
#include "GlyphBuffer.h"
#include "GraphicsContext.h"
#include "LayoutRect.h"
#include "TextRun.h"
#include "TextShapingResultAndDisplayList.h"
#include "WidthIterator.h"
#if PLATFORM(DRIFTSTACK)
#include "cocoa/DriftstackAsciiAtlas.h"
#include "cocoa/DriftstackCompositeAtlas.h"
#include "NativeImage.h"
#include <CoreGraphics/CoreGraphics.h>
#include <ImageIO/ImageIO.h>
#include <wtf/RetainPtr.h>
#endif
#include <ranges>
#include <wtf/MainThread.h>
#include <wtf/MathExtras.h>
#include <wtf/NeverDestroyed.h>
#include <wtf/RobinHoodHashSet.h>
#include <wtf/SortedArrayMap.h>
#include <wtf/TZoneMallocInlines.h>
#include <wtf/text/AtomStringHash.h>
#include <wtf/text/StringBuilder.h>
#include <wtf/text/TextStream.h>

namespace WebCore {

WTF_MAKE_TZONE_ALLOCATED_IMPL(FontCascade);

using namespace WTF::Unicode;

TextShapingContext::TextShapingContext(const FontCascade& fontCascade)
    : hasKerningOrLigatures(fontCascade.enableKerning() || fontCascade.requiresShaping())
    , hasWordSpacingOrLetterSpacing(fontCascade.wordSpacing() || fontCascade.letterSpacing())
    , hasTextSpacing(!fontCascade.textAutospace().isNoAutospace())
{
}

Markable<FontCascade::CodePath> FontCascade::s_forcedCodePath = std::nullopt;

static std::atomic<unsigned> lastFontCascadeGeneration { 0 };

// ============================================================================================
// FontCascade Implementation (Cross-Platform Portion)
// ============================================================================================

FontCascade::FontCascade() = default;

FontCascade::FontCascade(FontCascadeDescription&& description)
    : m_fontDescription(WTF::move(description))
    , m_generation(++lastFontCascadeGeneration)
    , m_useBackslashAsYenSymbol(computeUseBackslashAsYenSymbol())
    , m_enableKerning(computeEnableKerning())
    , m_requiresShaping(computeRequiresShaping())
{
    m_fontDescription.setShouldDisableLigaturesForSpacing(false);
}

FontCascade::FontCascade(FontCascadeDescription&& description, const FontCascade& other)
    : m_fontDescription(WTF::move(description))
    , m_spacing(other.m_spacing)
    , m_generation(++lastFontCascadeGeneration)
    , m_useBackslashAsYenSymbol(computeUseBackslashAsYenSymbol())
    , m_enableKerning(computeEnableKerning())
    , m_requiresShaping(computeRequiresShaping())
{
}

FontCascade::FontCascade(const FontCascade& other)
    : CanMakeWeakPtr<FontCascade>()
    , CanMakeCheckedPtr<FontCascade, WTF::DefaultedOperatorEqual::No, WTF::CheckedPtrDeleteCheckException::Yes>()
    , m_fontDescription(other.m_fontDescription)
    , m_spacing(other.m_spacing)
    , m_fonts(other.m_fonts)
    , m_fontSelector(other.m_fontSelector)
    , m_generation(other.m_generation)
    , m_useBackslashAsYenSymbol(other.m_useBackslashAsYenSymbol)
    , m_enableKerning(other.m_enableKerning)
    , m_requiresShaping(other.m_requiresShaping)
{
}

FontCascade::~FontCascade() = default;

FontCascade& FontCascade::operator=(const FontCascade& other)
{
    m_fontDescription = other.m_fontDescription;
    m_fonts = other.m_fonts;
    m_spacing = other.m_spacing;
    m_generation = other.m_generation;
    m_useBackslashAsYenSymbol = other.m_useBackslashAsYenSymbol;
    m_enableKerning = other.m_enableKerning;
    m_requiresShaping = other.m_requiresShaping;
    m_fontSelector = other.m_fontSelector;
    return *this;
}

bool FontCascade::operator==(const FontCascade& other) const
{
    if (m_fontDescription != other.m_fontDescription || m_spacing != other.m_spacing)
        return false;

    if (m_fonts != other.m_fonts)
        return false;

    if (!m_fonts)
        return true;

    if (fontSelector() != other.fontSelector())
        return false;

    // Can these cases actually somehow occur? All fonts should get wiped out by full style recalc.
    if (fontSelectorVersion() != other.fontSelectorVersion())
        return false;

    if (m_fonts->generation() != other.m_fonts->generation())
        return false;

    return true;
}

bool FontCascade::isCurrent(const FontSelector& fontSelector) const
{
    if (!m_fonts)
        return false;
    if (m_fonts->generation() != FontCache::forCurrentThread().generation())
        return false;
    if (fontSelectorVersion() != fontSelector.version())
        return false;

    return true;
}

unsigned FontCascade::fontSelectorVersion() const
{
    return m_fontSelector ? Ref { *m_fontSelector }->version() : 0;
}

void FontCascade::updateFonts(Ref<FontCascadeFonts>&& fonts) const
{
    // FIXME: Ideally we'd only update m_generation if the fonts changed.
    m_fonts = WTF::move(fonts);
    m_generation = ++lastFontCascadeGeneration;
}

void FontCascade::update(RefPtr<FontSelector>&& fontSelector) const
{
    m_fontSelector = WTF::move(fontSelector);
    protect(FontCache::forCurrentThread())->updateFontCascade(*this);
}

TextShapingResult FontCascade::layoutText(CodePath codePathToUse, const TextRun& run, unsigned from, unsigned to, ForTextEmphasis forTextEmphasis) const
{
    if (RefPtr fonts = this->fonts()) {
        if (auto* cached = fonts->getOrCreateCachedShapedText(run, *this, from, to, forTextEmphasis))
            return cached->textShapingResult;
    }

    if (shouldUseComplexTextController(codePathToUse))
        return layoutComplexText(run, from, to, forTextEmphasis);

    return layoutSimpleText(run, from, to, forTextEmphasis);
}

FloatSize FontCascade::drawText(GraphicsContext& context, const TextRun& run, const FloatPoint& point, unsigned from, std::optional<unsigned> to, CustomFontNotReadyAction customFontNotReadyAction) const
{
    unsigned destination = to.value_or(run.length());
    auto glyphBuffer = layoutText(codePath(run, from, to), run, from, destination).glyphBuffer;
    glyphBuffer.flatten();

    if (glyphBuffer.isEmpty())
        return FloatSize();

    FloatPoint startPoint = point + WebCore::size(glyphBuffer.initialAdvance());
    drawGlyphBuffer(context, glyphBuffer, startPoint, customFontNotReadyAction, run.text());
    return startPoint - point;
}

void FontCascade::drawEmphasisMarks(GraphicsContext& context, const TextRun& run, const AtomString& mark, const FloatPoint& point, unsigned from, std::optional<unsigned> to) const
{
    if (isLoadingCustomFonts())
        return;

    unsigned destination = to.value_or(run.length());

    auto glyphBuffer = layoutText(codePath(run, from, to), run, from, destination, ForTextEmphasis::Yes).glyphBuffer;
    glyphBuffer.flatten();

    if (glyphBuffer.isEmpty())
        return;

    FloatPoint startPoint = point + WebCore::size(glyphBuffer.initialAdvance());
    drawEmphasisMarks(context, glyphBuffer, mark, startPoint);
}

RefPtr<const DisplayList::DisplayList> FontCascade::displayListForTextRun(GraphicsContext& context, const TextRun& run, unsigned from, std::optional<unsigned> to, CustomFontNotReadyAction customFontNotReadyAction) const
{
    ASSERT(!context.paintingDisabled());
    unsigned destination = to.value_or(run.length());

    // FIXME: Use the fast code path once it handles partial runs with kerning and ligatures. See http://webkit.org/b/100050
    CodePath codePathToUse = codePath(run);
    if (codePathToUse != CodePath::Complex && !canHandleRunAsSimpleText(run, from, destination))
        codePathToUse = CodePath::Complex;

    auto glyphBuffer = layoutText(codePathToUse, run, from, destination).glyphBuffer;
    glyphBuffer.flatten();

    return displayListForGlyphBuffer(context, glyphBuffer, customFontNotReadyAction);
}

RefPtr<const DisplayList::DisplayList> FontCascade::displayListForGlyphBuffer(GraphicsContext& context, const GlyphBuffer& glyphBuffer,  CustomFontNotReadyAction customFontNotReadyAction) const
{
    ASSERT(!context.paintingDisabled());

    if (glyphBuffer.isEmpty())
        return nullptr;

#if USE(SKIA)
    const auto drawGlyphsMode = context.hasPlatformContext() ? DisplayList::Recorder::DrawGlyphsMode::TextBlob : DisplayList::Recorder::DrawGlyphsMode::Normal;
#else
    constexpr auto drawGlyphsMode = DisplayList::Recorder::DrawGlyphsMode::Deconstruct;
#endif

    DisplayList::RecorderImpl recordingContext(context.state().clone(GraphicsContextState::Purpose::Initial), { },
        context.getCTM(GraphicsContext::DefinitelyIncludeDeviceScale), context.colorSpace(), drawGlyphsMode);

    FloatPoint startPoint = toFloatPoint(WebCore::size(glyphBuffer.initialAdvance()));
    drawGlyphBuffer(recordingContext, glyphBuffer, startPoint, customFontNotReadyAction);

    return recordingContext.takeDisplayList();
}

#if PLATFORM(DRIFTSTACK)
// V-147: thread-local primary font family for V-143 emoji-fallback +1 px
// override. Set at FontCascade::widthOfTextRange entry; read in
// Font::platformWidthForGlyph (FontCoreText.cpp). Stored as raw const
// char* to avoid AtomString global destructor (Werror gates exit-time
// destructors on globals).
namespace Driftstack {
thread_local const char* g_currentPrimaryFamilyCStr = nullptr;
struct ScopedPrimaryFamily {
    const char* prev;
    CString owned;
    ScopedPrimaryFamily(const AtomString& s) {
        prev = g_currentPrimaryFamilyCStr;
        owned = s.string().utf8();
        g_currentPrimaryFamilyCStr = owned.data();
    }
    ~ScopedPrimaryFamily() { g_currentPrimaryFamilyCStr = prev; }
};
}
#endif

float FontCascade::widthOfTextRange(const TextRun& run, unsigned from, unsigned to, float& outWidthBeforeRange, float& outWidthAfterRange) const
{
    ASSERT(from <= to);
    ASSERT(to <= run.length());

    if (!run.length())
        return 0;

#if PLATFORM(DRIFTSTACK)
    // V-147: capture primary family for emoji-fallback +1 override.
    Driftstack::ScopedPrimaryFamily _scopedPrimary(m_fontDescription.firstFamily().name);
#endif

    float offsetBeforeRange = 0;
    float offsetAfterRange = 0;
    float totalWidth = 0;

    if (shouldUseComplexTextController(codePath(run))) {
        ComplexTextController complexIterator(*this, run);
        complexIterator.advance(from, nullptr, GlyphIterationStyle::IncludePartialGlyphs, nullptr);
        offsetBeforeRange = complexIterator.runWidthSoFar();
        complexIterator.advance(to, nullptr, GlyphIterationStyle::IncludePartialGlyphs, nullptr);
        offsetAfterRange = complexIterator.runWidthSoFar();
        complexIterator.advance(run.length(), nullptr, GlyphIterationStyle::IncludePartialGlyphs, nullptr);
        totalWidth = complexIterator.runWidthSoFar();
    } else {
        WidthIterator simpleIterator(*this, run);
        GlyphBuffer glyphBuffer;
        simpleIterator.advance(from, glyphBuffer);
        offsetBeforeRange = simpleIterator.runWidthSoFar();
        simpleIterator.advance(to, glyphBuffer);
        offsetAfterRange = simpleIterator.runWidthSoFar();
        simpleIterator.advance(run.length(), glyphBuffer);
        totalWidth = simpleIterator.runWidthSoFar();
        simpleIterator.finalize(glyphBuffer);
        // FIXME: Finalizing the WidthIterator can affect the total width.
        // We might need to adjust the various widths we've measured to account for that.
    }

    outWidthBeforeRange = offsetBeforeRange;
    outWidthAfterRange = totalWidth - offsetAfterRange;
    return offsetAfterRange - offsetBeforeRange;
}

float FontCascade::width(StringView text) const
{
    TextRun run { text };
    return width (run);
}

float FontCascade::width(const TextRun& run, SingleThreadWeakHashSet<const Font>* fallbackFonts, GlyphOverflow* glyphOverflow) const
{
    if (!run.length())
        return 0;

#if PLATFORM(DRIFTSTACK)
    // V-147: capture primary family for emoji-fallback +1 override.
    Driftstack::ScopedPrimaryFamily _scopedPrimary(m_fontDescription.firstFamily().name);
#endif

    CodePath codePathToUse = codePath(run);
    if (codePathToUse != CodePath::Complex) {
        // The complex path is more restrictive about returning fallback fonts than the simple path, so we need an explicit test to make their behaviors match.
        if constexpr (!canReturnFallbackFontsForComplexText())
            fallbackFonts = nullptr;
        // The simple path can optimize the case where glyph overflow is not observable.
        if (codePathToUse != CodePath::SimpleWithGlyphOverflow && (glyphOverflow && !glyphOverflow->computeBounds))
            glyphOverflow = nullptr;
    }

    auto* cacheEntry = fonts()->glyphGeometryCache().add(run, { }, TextShapingContext { *this });

    if (cacheEntry && cacheEntry->width) {
        if (!glyphOverflow)
            return *cacheEntry->width;
        if (cacheEntry->glyphOverflow && cacheEntry->glyphOverflow->computeBounds == glyphOverflow->computeBounds) {
            *glyphOverflow = *cacheEntry->glyphOverflow;
            return *cacheEntry->width;
        }
    }

    SingleThreadWeakHashSet<const Font> localFallbackFonts;
    if (!fallbackFonts)
        fallbackFonts = &localFallbackFonts;

    float result = width(codePathToUse, run, fallbackFonts, glyphOverflow);
    if (cacheEntry && fallbackFonts->isEmptyIgnoringNullReferences()) {
        cacheEntry->width = result;
        if (glyphOverflow)
            cacheEntry->glyphOverflow = *glyphOverflow;
    }
    return result;
}

float FontCascade::width(CodePath codePathToUse, const TextRun& run, SingleThreadWeakHashSet<const Font>* fallbackFonts, GlyphOverflow* glyphOverflow) const
{
    if (shouldUseComplexTextController(codePathToUse)) {
        ComplexTextController controller(*this, run, true, fallbackFonts);
        if (glyphOverflow) {
            glyphOverflow->top = std::max<double>(glyphOverflow->top, -controller.minGlyphBoundingBoxY() - (glyphOverflow->computeBounds ? 0 : metricsOfPrimaryFont().ascent()));
            glyphOverflow->bottom = std::max<double>(glyphOverflow->bottom, controller.maxGlyphBoundingBoxY() - (glyphOverflow->computeBounds ? 0 : metricsOfPrimaryFont().descent()));
            glyphOverflow->left = std::max<double>(0, -controller.minGlyphBoundingBoxX());
            glyphOverflow->right = std::max<double>(0, controller.maxGlyphBoundingBoxX() - controller.totalAdvance().width());
        }
        return controller.totalAdvance().width();
    }

    WidthIterator it(*this, run, fallbackFonts, glyphOverflow);
    GlyphBuffer glyphBuffer;
    it.advance(run.length(), glyphBuffer);
    it.finalize(glyphBuffer);
    if (glyphOverflow) {
        glyphOverflow->top = std::max<double>(glyphOverflow->top, -it.minGlyphBoundingBoxY() - (glyphOverflow->computeBounds ? 0 : metricsOfPrimaryFont().ascent()));
        glyphOverflow->bottom = std::max<double>(glyphOverflow->bottom, it.maxGlyphBoundingBoxY() - (glyphOverflow->computeBounds ? 0 : metricsOfPrimaryFont().descent()));
        glyphOverflow->left = it.firstGlyphOverflowX();
        glyphOverflow->right = it.lastGlyphOverflowX();
    }
    return it.runWidthSoFar();
}

NEVER_INLINE float FontCascade::widthForSimpleTextSlow(StringView text, TextDirection textDirection, GlyphGeometryCacheEntry* cacheEntry) const
{
#if PLATFORM(GTK) || PLATFORM(WPE)
    TextRun run { text, 0, 0, ExpansionBehavior::defaultBehavior(), textDirection, false, false };
    float result = width(CodePath::Simple, run);
#else
    GlyphBuffer glyphBuffer;
    Ref font = primaryFont();
    ASSERT(!font->syntheticBoldOffset()); // This function should only be called when RenderText::computeCanUseSimplifiedTextMeasuring() returns true, and that function requires no synthetic bold.

    auto addGlyphsFromText = [&](GlyphBuffer& glyphBuffer, const Font& font, auto characters) {
        for (size_t i = 0; i < characters.size(); ++i) {
            auto glyph = font.glyphForCharacter(characters[i]);
            glyphBuffer.add(glyph, font, font.widthForGlyph(glyph), i);
        }
    };

    if (text.is8Bit())
        addGlyphsFromText(glyphBuffer, font, text.span8());
    else
        addGlyphsFromText(glyphBuffer, font, text.span16());

    auto initialAdvance = font->applyTransforms(glyphBuffer, 0, 0, enableKerning(), requiresShaping(), fontDescription().computedLocale(), text, textDirection);
    auto result = 0.f;
    for (size_t i = 0; i < glyphBuffer.size(); ++i)
        result += WebCore::width(glyphBuffer.advanceAt(i));
    result += WebCore::width(initialAdvance);
#endif
    if (cacheEntry)
        cacheEntry->width = result;
    return result;
}

float FontCascade::widthForSimpleTextWithFixedPitch(StringView text, bool whitespaceIsCollapsed) const
{
    if (text.isEmpty())
        return 0;

    auto monospaceCharacterWidth = primaryFont().spaceWidth();
    if (whitespaceIsCollapsed)
        return text.length() * monospaceCharacterWidth;

    auto* cacheEntry = fonts()->glyphGeometryCache().add(text, { });
    if (cacheEntry && cacheEntry->width)
        return *cacheEntry->width;

    auto width = 0.f;
    for (unsigned index = 0; index < text.length(); ++index) {
        auto character = text[index];
        ASSERT(character != tabCharacter); // canUseSimplifiedTextMeasuring will return false for tab character with !whitespaceIsCollapsed.
        if (character == newlineCharacter || character == lineSeparator || character == paragraphSeparator) {
            // Zero width.
        } else if (character >= space)
            width += monospaceCharacterWidth;
        if (index && character == space)
            width += wordSpacing();
    }

    if (cacheEntry)
        cacheEntry->width = width;
    return width;
}

float FontCascade::zeroWidth() const
{
    // This represents the advance measure of the glyph 0 (zero, the Unicode character U+0030)
    // in the element's font. In cases where it is impossible or impractical to determine the measure of the 0 glyph,
    // it must be assumed to be 0.5em
    auto defaultZeroWidthValue = fontDescription().computedSize() / 2;
    if (!metricsOfPrimaryFont().zeroWidth())
        return defaultZeroWidthValue;

    auto glyphData = glyphDataForCharacter('0', false);
    if (!glyphData.isValid())
        return defaultZeroWidthValue;
    return glyphData.font->fontMetrics().zeroWidth().value_or(defaultZeroWidthValue);
}

GlyphData FontCascade::glyphDataForCharacter(char32_t c, bool mirror, FontVariant variant, std::optional<ResolvedEmojiPolicy> resolvedEmojiPolicy) const
{
    if (variant == FontVariant::Auto) {
        if (m_fontDescription.variantCaps() == FontVariantCaps::Small) {
            char32_t upperC = u_toupper(c);
            if (upperC != c) {
                c = upperC;
                variant = FontVariant::SmallCaps;
            } else
                variant = FontVariant::Normal;
        } else
            variant = FontVariant::Normal;
    }

    if (mirror)
        c = mirrorCharacterIfNeeded(c);

    auto emojiPolicy = resolvedEmojiPolicy.value_or(resolveEmojiPolicy(m_fontDescription.variantEmoji(), c));

    return protect(fonts())->glyphDataForCharacter(c, m_fontDescription, protect(fontSelector()).get(), variant, emojiPolicy);
}


bool FontCascade::canUseSimplifiedTextMeasuring(char32_t character, FontVariant fontVariant, bool whitespaceIsCollapsed, const Font& primaryFont) const
{
    if (character == tabCharacter && !whitespaceIsCollapsed)
        return false;

    // We cache whitespaceIsCollapsed = true result. false case is handled above.
    whitespaceIsCollapsed = true;
    bool isCacheable = fontVariant == FontVariant::Auto && isLatin1(character);
    size_t baseIndex = static_cast<size_t>(character) * bitsPerCharacterInCanUseSimplifiedTextMeasuringForAutoVariantCache;
    if (isCacheable) {
        static_assert(0 < bitsPerCharacterInCanUseSimplifiedTextMeasuringForAutoVariantCache);
        static_assert(1 < bitsPerCharacterInCanUseSimplifiedTextMeasuringForAutoVariantCache);
        if (m_canUseSimplifiedTextMeasuringForAutoVariantCache.get(baseIndex))
            return m_canUseSimplifiedTextMeasuringForAutoVariantCache.get(baseIndex + 1);
    }

    bool result = WidthIterator::characterCanUseSimplifiedTextMeasuring(character, whitespaceIsCollapsed);
    if (result) {
        constexpr bool mirror = false;
        auto glyphData = glyphDataForCharacter(character, mirror, fontVariant);
        result = glyphData.isValid() && glyphData.font == &primaryFont;
    }

    if (isCacheable) {
        m_canUseSimplifiedTextMeasuringForAutoVariantCache.set(baseIndex, true);
        m_canUseSimplifiedTextMeasuringForAutoVariantCache.set(baseIndex + 1, result);
    }
    return result;
}

// For font families where any of the fonts don't have a valid entry in the OS/2 table
// for avgCharWidth, fallback to the legacy webkit behavior of getting the avgCharWidth
// from the width of a '0'. This only seems to apply to a fixed number of Mac fonts,
// but, in order to get similar rendering across platforms, we do this check for
// all platforms.
bool FontCascade::hasValidAverageCharWidth() const
{
    ASSERT(isMainThread());

    const auto& family = firstFamily().name;
    if (family.isEmpty())
        return false;

#if PLATFORM(COCOA)
    // Internal fonts on macOS and iOS also have an invalid entry in the table for avgCharWidth.
    if (primaryFontIsSystemFont())
        return false;
#endif

    static constexpr SortedArraySet set { std::to_array<ComparableASCIILiteral>({
        "#GungSeo"_s,
        "#HeadLineA"_s,
        "#PCMyungjo"_s,
        "#PilGi"_s,
        "American Typewriter"_s,
        "Apple Braille"_s,
        "Apple LiGothic"_s,
        "Apple LiSung"_s,
        "Apple Symbols"_s,
        "AppleGothic"_s,
        "AppleMyungjo"_s,
        "Arial Hebrew"_s,
        "Chalkboard"_s,
        "Cochin"_s,
        "Corsiva Hebrew"_s,
        "Courier"_s,
        "Euphemia UCAS"_s,
        "Geneva"_s,
        "Gill Sans"_s,
        "Hei"_s,
        "Helvetica"_s,
        "Hoefler Text"_s,
        "InaiMathi"_s,
        "Kai"_s,
        "Lucida Grande"_s,
        "Marker Felt"_s,
        "Monaco"_s,
        "Mshtakan"_s,
        "New Peninim MT"_s,
        "Osaka"_s,
        "Raanana"_s,
        "STHeiti"_s,
        "Symbol"_s,
        "Times"_s,
    }) };
    return !set.contains(family);
}

bool FontCascade::fastAverageCharWidthIfAvailable(float& width) const
{
    bool success = hasValidAverageCharWidth();
    if (success)
        width = roundf(primaryFont().avgCharWidth()); // FIXME: primaryFont() might not correspond to firstFamily().
    return success;
}

Vector<LayoutRect> FontCascade::characterSelectionRectsForText(const TextRun& run, const LayoutRect& selectionRect, unsigned from, std::optional<unsigned> toOrEndOfRun) const
{
    unsigned to = toOrEndOfRun.value_or(run.length());
    ASSERT(from <= to);

    bool rtl = run.rtl();

    // FIXME: We could further optimize this by using the simple text codepath when applicable.
    ComplexTextController controller(*this, run);
    controller.advance(from);

    return Vector<LayoutRect>(to - from, [&](size_t i) {
        auto current = from + i + 1;
        auto characterRect = selectionRect;
        auto beforeWidth = controller.runWidthSoFar();

        controller.advance(current);
        auto afterWidth = controller.runWidthSoFar();

        characterRect.move(rtl ? controller.totalAdvance().width() - afterWidth : beforeWidth, 0);
        characterRect.setWidth(LayoutUnit::fromFloatCeil(afterWidth - beforeWidth));
        return characterRect;
    });
}

void FontCascade::adjustSelectionRectForText(bool canUseSimplifiedTextMeasuring, const TextRun& run, LayoutRect& selectionRect, unsigned from, std::optional<unsigned> to) const
{
    unsigned destination = to.value_or(run.length());

    // FIXME: Use the fast code path once it handles partial runs with kerning and ligatures. See http://webkit.org/b/100050
    CodePath codePathToUse = codePath(run);
    if (codePathToUse != CodePath::Complex) {
        if (canUseSimplifiedTextMeasuring && canTakeFixedPitchFastContentMeasuring())
            return adjustSelectionRectForSimpleTextWithFixedPitch(run, selectionRect, from, destination);

        if (!canHandleRunAsSimpleText(run, from, destination))
            codePathToUse = CodePath::Complex;
    }

    if (shouldUseComplexTextController(codePathToUse))
        return adjustSelectionRectForComplexText(run, selectionRect, from, destination);

    return adjustSelectionRectForSimpleText(run, selectionRect, from, destination);
}

int FontCascade::offsetForPosition(const TextRun& run, float x, bool includePartialGlyphs) const
{
    if (shouldUseComplexTextController(codePath(run, x)))
        return offsetForPositionForComplexText(run, x, includePartialGlyphs);

    return offsetForPositionForSimpleText(run, x, includePartialGlyphs);
}

template <typename CharacterType>
static inline String normalizeSpacesInternal(std::span<const CharacterType> characters)
{
    StringBuilder normalized;
    normalized.reserveCapacity(characters.size());

    for (auto character : characters)
        normalized.append(FontCascade::normalizeSpaces(character));

    return normalized.toString();
}

String FontCascade::normalizeSpaces(std::span<const Latin1Character> characters)
{
    return normalizeSpacesInternal(characters);
}

String FontCascade::normalizeSpaces(std::span<const char16_t> characters)
{
    return normalizeSpacesInternal(characters);
}

String FontCascade::normalizeSpaces(StringView stringView)
{
    if (stringView.is8Bit())
        return normalizeSpacesInternal(stringView.span8());
    return normalizeSpacesInternal(stringView.span16());
}

static std::atomic<bool> disableFontSubpixelAntialiasingForTesting = false;

void FontCascade::setDisableFontSubpixelAntialiasingForTesting(bool disable)
{
    ASSERT(isMainThread());
    disableFontSubpixelAntialiasingForTesting = disable;
}

bool FontCascade::shouldDisableFontSubpixelAntialiasingForTesting()
{
    return disableFontSubpixelAntialiasingForTesting;
}

bool FontCascade::canHandleRunAsSimpleText(const TextRun& run, unsigned from, unsigned to) const
{
#if !PLATFORM(GTK) && !PLATFORM(WPE) && !USE(FREETYPE)
    // FIXME: Use the fast code path once it handles partial runs with kerning and ligatures. See http://webkit.org/b/100050
    return !((enableKerning() || requiresShaping()) && (from || to != run.length()));
#else
    UNUSED_PARAM(run);
    UNUSED_PARAM(from);
    UNUSED_PARAM(to);
    return true;
#endif
}

#if PLATFORM(GTK) || PLATFORM(WPE)
bool FontCascade::shouldUseComplexTextControllerForSimpleText() const
{
    // For ports that doesn't implement Font::applyTransforms, we can only use WidthIterator when we know for sure
    // that Font::applyTransforms is not actually needed.
    if (fontDescription().variantCaps() != FontVariantCaps::Normal || fontDescription().variantEmoji() == FontVariantEmoji::Emoji)
        return true;

    return enableKerning() || requiresShaping();
}
#endif

void FontCascade::setForcedCodePath(Markable<CodePath> p)
{
    s_forcedCodePath = p;
}

Markable<FontCascade::CodePath> FontCascade::forcedCodePath()
{
    return s_forcedCodePath;
}

FontCascade::CodePath FontCascade::codePath(const TextRun& run, std::optional<unsigned> from, std::optional<unsigned> to) const
{
    if (s_forcedCodePath)
        return *s_forcedCodePath;

    if (!canHandleRunAsSimpleText(run, from.value_or(0), to.value_or(run.length())))
        return CodePath::Complex;

    // FIXME: https://bugs.webkit.org/show_bug.cgi?id=150791: @font-face features should also cause this to be complex.

#if !USE(FONT_VARIANT_VIA_FEATURES) && !USE(FREETYPE)
    if (run.length() > 1 && (enableKerning() || requiresShaping()))
        return CodePath::Complex;
#endif

    if (!run.characterScanForCodePath())
        return CodePath::Simple;

    if (run.is8Bit())
        return CodePath::Simple;

    // Start from 0 since drawing and highlighting also measure the characters before run->from.
    return characterRangeCodePath(run.span16());
}

FontCascade::CodePath FontCascade::characterRangeCodePath(std::span<const char16_t> span)
{
    // FIXME: Should use a UnicodeSet in ports where ICU is used. Note that we 
    // can't simply use UnicodeCharacter Property/class because some characters
    // are not 'combining', but still need to go to the complex path.
    // Alternatively, we may as well consider binary search over a sorted
    // list of ranges.
    CodePath result = CodePath::Simple;
    bool previousCharacterIsEmojiGroupCandidate = false;
    size_t size = span.size();
    for (size_t i = 0; i < size; ++i) {
        auto c = span[i];
        if (c == zeroWidthJoiner && previousCharacterIsEmojiGroupCandidate)
            return CodePath::Complex;
        
        previousCharacterIsEmojiGroupCandidate = false;
        if (c < 0x2E5) // U+02E5 through U+02E9 (Modifier Letters : Tone letters)  
            continue;
        if (c <= 0x2E9) 
            return CodePath::Complex;

        if (c < 0x300) // U+0300 through U+036F Combining diacritical marks
            continue;
        if (c <= 0x36F)
            return CodePath::Complex;

        if (c < 0x0591 || c == 0x05BE) // U+0591 through U+05CF excluding U+05BE Hebrew combining marks, Hebrew punctuation Paseq, Sof Pasuq and Nun Hafukha
            continue;
        if (c <= 0x05CF)
            return CodePath::Complex;

        // U+0600 through U+109F Arabic, Syriac, Thaana, NKo, Samaritan, Mandaic,
        // Devanagari, Bengali, Gurmukhi, Gujarati, Oriya, Tamil, Telugu, Kannada, 
        // Malayalam, Sinhala, Thai, Lao, Tibetan, Myanmar
        if (c < 0x0600) 
            continue;
        if (c <= 0x109F)
            return CodePath::Complex;

        // U+1100 through U+11FF Hangul Jamo (only Ancient Korean should be left here if you precompose;
        // Modern Korean will be precomposed as a result of step A)
        if (c < 0x1100)
            continue;
        if (c <= 0x11FF)
            return CodePath::Complex;

        if (c < 0x135D) // U+135D through U+135F Ethiopic combining marks
            continue;
        if (c <= 0x135F)
            return CodePath::Complex;

        if (c < 0x1700) // U+1780 through U+18AF Tagalog, Hanunoo, Buhid, Taghanwa,Khmer, Mongolian
            continue;
        if (c <= 0x18AF)
            return CodePath::Complex;

        if (c < 0x1900) // U+1900 through U+194F Limbu (Unicode 4.0)
            continue;
        if (c <= 0x194F)
            return CodePath::Complex;

        if (c < 0x1980) // U+1980 through U+19DF New Tai Lue
            continue;
        if (c <= 0x19DF)
            return CodePath::Complex;

        if (c < 0x1A00) // U+1A00 through U+1CFF Buginese, Tai Tham, Balinese, Batak, Lepcha, Vedic
            continue;
        if (c <= 0x1CFF)
            return CodePath::Complex;

        if (c < 0x1DC0) // U+1DC0 through U+1DFF Comining diacritical mark supplement
            continue;
        if (c <= 0x1DFF)
            return CodePath::Complex;

        // U+1E00 through U+2000 characters with diacritics and stacked diacritics
        if (c <= 0x2000) {
            result = CodePath::SimpleWithGlyphOverflow;
            continue;
        }

        if (c < 0x20D0) // U+20D0 through U+20FF Combining marks for symbols
            continue;
        if (c <= 0x20FF)
            return CodePath::Complex;

        if (c < 0x26F9)
            continue;
        if (c < 0x26FA)
            return CodePath::Complex;

        if (c < 0x2CEF) // U+2CEF through U+2CF1 Combining marks for Coptic
            continue;
        if (c <= 0x2CF1)
            return CodePath::Complex;

        if (c < 0x302A) // U+302A through U+302F Ideographic and Hangul Tone marks
            continue;
        if (c <= 0x302F)
            return CodePath::Complex;

        if (c < 0x3099)
            continue;
        if (c < 0x309D)
            return CodePath::Complex; // KATAKANA-HIRAGANA (SEMI-)VOICED SOUND MARKS require character composition

        if (c < 0xA67C) // U+A67C through U+A67D Combining marks for old Cyrillic
            continue;
        if (c <= 0xA67D)
            return CodePath::Complex;

        if (c < 0xA6F0) // U+A6F0 through U+A6F1 Combining mark for Bamum
            continue;
        if (c <= 0xA6F1)
            return CodePath::Complex;

        // U+A800 through U+ABFF Nagri, Phags-pa, Saurashtra, Devanagari Extended,
        // Hangul Jamo Ext. A, Javanese, Myanmar Extended A, Tai Viet, Meetei Mayek,
        if (c < 0xA800) 
            continue;
        if (c <= 0xABFF)
            return CodePath::Complex;

        if (c < 0xD7B0) // U+D7B0 through U+D7FF Hangul Jamo Ext. B
            continue;
        if (c <= 0xD7FF)
            return CodePath::Complex;

        if (c <= 0xDBFF) {
            // High surrogate

            if (i + 1 == size)
                continue;

            char16_t next = span[++i];
            if (!U16_IS_TRAIL(next))
                continue;

            char32_t supplementaryCharacter = U16_GET_SUPPLEMENTARY(c, next);

            if (supplementaryCharacter < 0x10A00)
                continue;
            if (supplementaryCharacter < 0x10A60) // Kharoshthi
                return CodePath::Complex;
            if (supplementaryCharacter < 0x11000)
                continue;
            if (supplementaryCharacter < 0x11080) // Brahmi
                return CodePath::Complex;
            if (supplementaryCharacter < 0x110D0) // Kaithi
                return CodePath::Complex;
            if (supplementaryCharacter < 0x11100)
                continue;
            if (supplementaryCharacter < 0x11150) // Chakma
                return CodePath::Complex;
            if (supplementaryCharacter < 0x11180) // Mahajani
                return CodePath::Complex;
            if (supplementaryCharacter < 0x111E0) // Sharada
                return CodePath::Complex;
            if (supplementaryCharacter < 0x11200)
                continue;
            if (supplementaryCharacter < 0x11250) // Khojki
                return CodePath::Complex;
            if (supplementaryCharacter < 0x112B0)
                continue;
            if (supplementaryCharacter < 0x11300) // Khudawadi
                return CodePath::Complex;
            if (supplementaryCharacter < 0x11380) // Grantha
                return CodePath::Complex;
            if (supplementaryCharacter < 0x11400)
                continue;
            if (supplementaryCharacter < 0x11480) // Newa
                return CodePath::Complex;
            if (supplementaryCharacter < 0x114E0) // Tirhuta
                return CodePath::Complex;
            if (supplementaryCharacter < 0x11580)
                continue;
            if (supplementaryCharacter < 0x11600) // Siddham
                return CodePath::Complex;
            if (supplementaryCharacter < 0x11660) // Modi
                return CodePath::Complex;
            if (supplementaryCharacter < 0x11680)
                continue;
            if (supplementaryCharacter < 0x116D0) // Takri
                return CodePath::Complex;
            if (supplementaryCharacter < 0x11700)
                continue;
            if (supplementaryCharacter < 0x11C00) // Ahom, Dogra, Dives Akuru, Nandinagari, Zanabazar Square, Soyombo, Warang Citi, Pau Cin Hau
                return CodePath::Complex;
            if (supplementaryCharacter < 0x11C70) // Bhaiksuki
                return CodePath::Complex;
            if (supplementaryCharacter < 0x11CC0) // Marchen
                return CodePath::Complex;
            if (supplementaryCharacter < 0x1E900)
                continue;
            if (supplementaryCharacter < 0x1E960) // Adlam
                return CodePath::Complex;
            if (supplementaryCharacter < 0x1F1E6) // U+1F1E6 through U+1F1FF Regional Indicator Symbols
                continue;
            if (supplementaryCharacter <= 0x1F1FF)
                return CodePath::Complex;

            if (isEmojiFitzpatrickModifier(supplementaryCharacter))
                return CodePath::Complex;
            if (isEmojiGroupCandidate(supplementaryCharacter)) {
                previousCharacterIsEmojiGroupCandidate = true;
                continue;
            }

            if (supplementaryCharacter < 0xE0000)
                continue;
            if (supplementaryCharacter < 0xE0080) // Tags
                return CodePath::Complex;
            if (supplementaryCharacter < 0xE0100) // U+E0100 through U+E01EF Unicode variation selectors.
                continue;
            if (supplementaryCharacter <= 0xE01EF)
                return CodePath::Complex;

            // FIXME: Check for Brahmi (U+11000 block), Kaithi (U+11080 block) and other complex scripts
            // in plane 1 or higher.

            continue;
        }

        if (c < 0xFE00) // U+FE00 through U+FE0F Unicode variation selectors
            continue;
        if (c <= 0xFE0F)
            return CodePath::Complex;

        if (c < 0xFE20) // U+FE20 through U+FE2F Combining half marks
            continue;
        if (c <= 0xFE2F)
            return CodePath::Complex;
    }
    return result;
}

bool FontCascade::isCJKIdeograph(char32_t c)
{
    // The basic CJK Unified Ideographs block.
    if (c >= 0x4E00 && c <= 0x9FFF)
        return true;
    
    // CJK Unified Ideographs Extension A.
    if (c >= 0x3400 && c <= 0x4DBF)
        return true;
    
    // CJK Radicals Supplement.
    if (c >= 0x2E80 && c <= 0x2EFF)
        return true;
    
    // Kangxi Radicals.
    if (c >= 0x2F00 && c <= 0x2FDF)
        return true;
    
    // CJK Strokes.
    if (c >= 0x31C0 && c <= 0x31EF)
        return true;
    
    // CJK Compatibility Ideographs.
    if (c >= 0xF900 && c <= 0xFAFF)
        return true;

    // CJK Unified Ideographs Extension B.
    if (c >= 0x20000 && c <= 0x2A6DF)
        return true;

    // CJK Unified Ideographs Extension C.
    if (c >= 0x2A700 && c <= 0x2B73F)
        return true;
    
    // CJK Unified Ideographs Extension D.
    if (c >= 0x2B740 && c <= 0x2B81F)
        return true;
    
    // CJK Compatibility Ideographs Supplement.
    if (c >= 0x2F800 && c <= 0x2FA1F)
        return true;

    return false;
}

bool FontCascade::isCJKIdeographOrSymbol(char32_t c)
{
    // 0x2C7 Caron, Mandarin Chinese 3rd Tone
    // 0x2CA Modifier Letter Acute Accent, Mandarin Chinese 2nd Tone
    // 0x2CB Modifier Letter Grave Access, Mandarin Chinese 4th Tone
    // 0x2D9 Dot Above, Mandarin Chinese 5th Tone
    // 0x2EA Modifier Letter Yin Departing Tone Mark
    // 0x2EB Modifier Letter Yang Departing Tone Mark
    if ((c == 0x2C7) || (c == 0x2CA) || (c == 0x2CB) || (c == 0x2D9) || (c == 0x2EA) || (c == 0x2EB))
        return true;

    if ((c == 0x2020) || (c == 0x2021) || (c == 0x2030) || (c == 0x203B) || (c == 0x203C)
        || (c == 0x2042) || (c == 0x2047) || (c == 0x2048) || (c == 0x2049) || (c == 0x2051)
        || (c == 0x20DD) || (c == 0x20DE) || (c == 0x2100) || (c == 0x2103) || (c == 0x2105)
        || (c == 0x2109) || (c == 0x210A) || (c == 0x2113) || (c == 0x2116) || (c == 0x2121)
        || (c == 0x212B) || (c == 0x213B) || (c == 0x2150) || (c == 0x2151) || (c == 0x2152))
        return true;

    if (c >= 0x2156 && c <= 0x215A)
        return true;

    if (c >= 0x2160 && c <= 0x216B)
        return true;

    if (c >= 0x2170 && c <= 0x217B)
        return true;

    if ((c == 0x217F) || (c == 0x2189) || (c == 0x2307) || (c == 0x2312) || (c == 0x23BE) || (c == 0x23BF))
        return true;

    if (c >= 0x23C0 && c <= 0x23CC)
        return true;

    if ((c == 0x23CE) || (c == 0x2423))
        return true;

    if (c >= 0x2460 && c <= 0x2492)
        return true;

    if (c >= 0x249C && c <= 0x24FF)
        return true;

    if ((c == 0x25A0) || (c == 0x25A1) || (c == 0x25A2) || (c == 0x25AA) || (c == 0x25AB))
        return true;

    if ((c == 0x25B1) || (c == 0x25B2) || (c == 0x25B3) || (c == 0x25B6) || (c == 0x25B7) || (c == 0x25BC) || (c == 0x25BD))
        return true;
    
    if ((c == 0x25C0) || (c == 0x25C1) || (c == 0x25C6) || (c == 0x25C7) || (c == 0x25C9) || (c == 0x25CB) || (c == 0x25CC))
        return true;

    if (c >= 0x25CE && c <= 0x25D3)
        return true;

    if (c >= 0x25E2 && c <= 0x25E6)
        return true;

    if (c == 0x25EF)
        return true;

    if (c >= 0x2600 && c <= 0x2603)
        return true;

    if ((c == 0x2605) || (c == 0x2606) || (c == 0x260E) || (c == 0x2616) || (c == 0x2617) || (c == 0x2640) || (c == 0x2642))
        return true;

    if (c >= 0x2660 && c <= 0x266F)
        return true;

    if (c >= 0x2672 && c <= 0x267D)
        return true;

    if ((c == 0x26A0) || (c == 0x26BD) || (c == 0x26BE) || (c == 0x2713) || (c == 0x271A) || (c == 0x273F) || (c == 0x2740) || (c == 0x2756))
        return true;

    if (c >= 0x2776 && c <= 0x277F)
        return true;

    if (c == 0x2B1A)
        return true;

    // Ideographic Description Characters.
    if (c >= 0x2FF0 && c <= 0x2FFF)
        return true;

    // CJK Symbols and Punctuation, excluding 0x3030.
    if (c >= 0x3000 && c < 0x3030)
        return true;

    if (c > 0x3030 && c <= 0x303F)
        return true;

    // Hiragana
    if (c >= 0x3040 && c <= 0x309F)
        return true;

    // Katakana 
    if (c >= 0x30A0 && c <= 0x30FF)
        return true;

    // Bopomofo
    if (c >= 0x3100 && c <= 0x312F)
        return true;

    if (c >= 0x3190 && c <= 0x319F)
        return true;

    // Bopomofo Extended
    if (c >= 0x31A0 && c <= 0x31BF)
        return true;

    // Enclosed CJK Letters and Months.
    if (c >= 0x3200 && c <= 0x32FF)
        return true;
    
    // CJK Compatibility.
    if (c >= 0x3300 && c <= 0x33FF)
        return true;

    if (c >= 0xF860 && c <= 0xF862)
        return true;

    // CJK Compatibility Forms.
    if (c >= 0xFE30 && c <= 0xFE4F)
        return true;

    if ((c == 0xFE10) || (c == 0xFE11) || (c == 0xFE12) || (c == 0xFE19))
        return true;

    if ((c == 0xFF0D) || (c == 0xFF1B) || (c == 0xFF1C) || (c == 0xFF1E))
        return false;

    // Halfwidth and Fullwidth Forms
    // Usually only used in CJK
    if (c >= 0xFF00 && c <= 0xFFEF)
        return true;

    // Emoji.
    if (c == 0x1F100)
        return true;

    if (c >= 0x1F110 && c <= 0x1F129)
        return true;

    if (c >= 0x1F130 && c <= 0x1F149)
        return true;

    if (c >= 0x1F150 && c <= 0x1F169)
        return true;

    if (c >= 0x1F170 && c <= 0x1F189)
        return true;

    if (c >= 0x1F200 && c <= 0x1F6C5)
        return true;

    return isCJKIdeograph(c);
}

std::pair<unsigned, bool> FontCascade::expansionOpportunityCountInternal(std::span<const Latin1Character> characters, TextDirection direction, ExpansionBehavior expansionBehavior)
{
    unsigned count = 0;
    bool isAfterExpansion = expansionBehavior.left == ExpansionBehavior::Behavior::Forbid;
    if (expansionBehavior.left == ExpansionBehavior::Behavior::Force) {
        ++count;
        isAfterExpansion = true;
    }
    auto handleExpansionsForCharacters = [&](const auto& range) {
        for (auto character : range) {
            if (treatAsSpace(character)) {
                ++count;
                isAfterExpansion = true;
            } else
                isAfterExpansion = false;
        }
    };

    if (direction == TextDirection::LTR)
        handleExpansionsForCharacters(characters);
    else
        handleExpansionsForCharacters(characters | std::views::reverse);

    if (!isAfterExpansion && expansionBehavior.right == ExpansionBehavior::Behavior::Force) {
        ++count;
        isAfterExpansion = true;
    } else if (isAfterExpansion && expansionBehavior.right == ExpansionBehavior::Behavior::Forbid) {
        ASSERT(count);
        --count;
        isAfterExpansion = false;
    }
    return std::make_pair(count, isAfterExpansion);
}

std::pair<unsigned, bool> FontCascade::expansionOpportunityCountInternal(std::span<const char16_t> characters, TextDirection direction, ExpansionBehavior expansionBehavior)
{
    unsigned count = 0;
    bool isAfterExpansion = expansionBehavior.left == ExpansionBehavior::Behavior::Forbid;
    if (expansionBehavior.left == ExpansionBehavior::Behavior::Force) {
        ++count;
        isAfterExpansion = true;
    }
    if (direction == TextDirection::LTR) {
        for (size_t i = 0; i < characters.size(); ++i) {
            char32_t character = characters[i];
            if (treatAsSpace(character)) {
                ++count;
                isAfterExpansion = true;
                continue;
            }
            if (U16_IS_LEAD(character) && i + 1 < characters.size() && U16_IS_TRAIL(characters[i + 1])) {
                character = U16_GET_SUPPLEMENTARY(character, characters[i + 1]);
                ++i;
            }
            if (canExpandAroundIdeographsInComplexText() && isCJKIdeographOrSymbol(character)) {
                if (!isAfterExpansion)
                    ++count;
                ++count;
                isAfterExpansion = true;
                continue;
            }
            isAfterExpansion = false;
        }
    } else {
        for (size_t i = characters.size(); i > 0; --i) {
            char32_t character = characters[i - 1];
            if (treatAsSpace(character)) {
                ++count;
                isAfterExpansion = true;
                continue;
            }
            if (U16_IS_TRAIL(character) && i > 1 && U16_IS_LEAD(characters[i - 2])) {
                character = U16_GET_SUPPLEMENTARY(characters[i - 2], character);
                --i;
            }
            if (canExpandAroundIdeographsInComplexText() && isCJKIdeographOrSymbol(character)) {
                if (!isAfterExpansion)
                    ++count;
                ++count;
                isAfterExpansion = true;
                continue;
            }
            isAfterExpansion = false;
        }
    }
    if (!isAfterExpansion && expansionBehavior.right == ExpansionBehavior::Behavior::Force) {
        ++count;
        isAfterExpansion = true;
    } else if (isAfterExpansion && expansionBehavior.right == ExpansionBehavior::Behavior::Forbid) {
        ASSERT(count);
        --count;
        isAfterExpansion = false;
    }
    return std::make_pair(count, isAfterExpansion);
}

std::pair<unsigned, bool> FontCascade::expansionOpportunityCount(StringView stringView, TextDirection direction, ExpansionBehavior expansionBehavior)
{
    // For each character, iterating from left to right:
    //   If it is recognized as a space, insert an opportunity after it
    //   If it is an ideograph, insert one opportunity before it and one opportunity after it
    // Do this such a way so that there are not two opportunities next to each other.
    if (stringView.is8Bit())
        return expansionOpportunityCountInternal(stringView.span8(), direction, expansionBehavior);
    return expansionOpportunityCountInternal(stringView.span16(), direction, expansionBehavior);
}

bool FontCascade::leftExpansionOpportunity(StringView stringView, TextDirection direction)
{
    if (!stringView.length())
        return false;

    char32_t initialCharacter;
    if (direction == TextDirection::LTR) {
        initialCharacter = stringView[0];
        if (U16_IS_LEAD(initialCharacter) && stringView.length() > 1 && U16_IS_TRAIL(stringView[1]))
            initialCharacter = U16_GET_SUPPLEMENTARY(initialCharacter, stringView[1]);
    } else {
        initialCharacter = stringView[stringView.length() - 1];
        if (U16_IS_TRAIL(initialCharacter) && stringView.length() > 1 && U16_IS_LEAD(stringView[stringView.length() - 2]))
            initialCharacter = U16_GET_SUPPLEMENTARY(stringView[stringView.length() - 2], initialCharacter);
    }

    return canExpandAroundIdeographsInComplexText() && isCJKIdeographOrSymbol(initialCharacter);
}

bool FontCascade::rightExpansionOpportunity(StringView stringView, TextDirection direction)
{
    if (!stringView.length())
        return false;

    char32_t finalCharacter;
    if (direction == TextDirection::LTR) {
        finalCharacter = stringView[stringView.length() - 1];
        if (U16_IS_TRAIL(finalCharacter) && stringView.length() > 1 && U16_IS_LEAD(stringView[stringView.length() - 2]))
            finalCharacter = U16_GET_SUPPLEMENTARY(stringView[stringView.length() - 2], finalCharacter);
    } else {
        finalCharacter = stringView[0];
        if (U16_IS_LEAD(finalCharacter) && stringView.length() > 1 && U16_IS_TRAIL(stringView[1]))
            finalCharacter = U16_GET_SUPPLEMENTARY(finalCharacter, stringView[1]);
    }

    return treatAsSpace(finalCharacter) || (canExpandAroundIdeographsInComplexText() && isCJKIdeographOrSymbol(finalCharacter));
}

// https://www.w3.org/TR/css-text-decor-3/#text-emphasis-style-property
bool FontCascade::canReceiveTextEmphasis(char32_t c)
{
    auto mask = U_GET_GC_MASK(c);
    if (mask & (U_GC_Z_MASK | U_GC_CN_MASK | U_GC_CC_MASK | U_GC_CF_MASK))
        return false;

    // Additional word-separator characters listed in CSS Text Level 3 Editor's Draft 3 November 2010.
    // https://www.w3.org/TR/css-text-3/#word-separator
    if (c == ethiopicWordspace || c == aegeanWordSeparatorLine || c == aegeanWordSeparatorDot
        || c == ugariticWordDivider || c == tibetanMarkIntersyllabicTsheg || c == tibetanMarkDelimiterTshegBstar)
        return false;

    if (mask & U_GC_P_MASK) {
        return c == '#' || c == '%' || c == '&' || c == '@'
            || c == arabicIndicPerMilleSign
            || c == arabicIndicPerTenThousandSign
            || c == arabicPercentSign
            || c == fullwidthAmpersand
            || c == fullwidthCommercialAt
            || c == fullwidthNumberSign
            || c == fullwidthPercentSign
            || c == partAlternationMark
            || c == perMilleSign
            || c == perTenThousandSign
            || c == pilcrowSign
            || c == reversedPilcrowSign
            || c == sectionSign
            || c == smallAmpersand
            || c == smallCommercialAt
            || c == smallNumberSign
            || c == smallPercentSign
            || c == swungDash
            || c == tironianSignEt;
    }

    return true;
}

bool FontCascade::isLoadingCustomFonts() const
{
    RefPtr fonts = m_fonts;
    return fonts && fonts->isLoadingCustomFonts();
}

bool FontCascade::computeUseBackslashAsYenSymbol() const
{
    return protect(FontCache::forCurrentThread())->useBackslashAsYenSignForFamily(m_fontDescription.firstFamily().name);
}

enum class GlyphUnderlineType : uint8_t {
    SkipDescenders,
    SkipGlyph,
    DrawOverGlyph
};
    
static GlyphUnderlineType computeUnderlineType(const TextRun& textRun, const GlyphBuffer& glyphBuffer, unsigned index)
{
    // In general, we want to skip descenders. However, skipping descenders on CJK characters leads to undesirable renderings,
    // so we want to draw through CJK characters (on a character-by-character basis).
    // FIXME: The CSS spec says this should instead be done by the user-agent stylesheet using the lang= attribute.
    char32_t baseCharacter;
    auto offsetInString = glyphBuffer.checkedStringOffsetAt(index, textRun.length());
    if (!offsetInString)
        return GlyphUnderlineType::SkipDescenders;
    
    if (textRun.is8Bit())
        baseCharacter = textRun.span8()[offsetInString.value()];
    else {
        auto characters = textRun.span16();
        U16_GET(characters, 0, static_cast<unsigned>(offsetInString.value()), characters.size(), baseCharacter);
    }
    // u_getIntPropertyValue with UCHAR_IDEOGRAPHIC doesn't return true for Japanese or Korean codepoints.
    // Instead, we can use the "Unicode allocation block" for the character.
    UBlockCode blockCode = ublock_getCode(baseCharacter);
    switch (blockCode) {
    case UBLOCK_CJK_RADICALS_SUPPLEMENT:
    case UBLOCK_CJK_SYMBOLS_AND_PUNCTUATION:
    case UBLOCK_ENCLOSED_CJK_LETTERS_AND_MONTHS:
    case UBLOCK_CJK_COMPATIBILITY:
    case UBLOCK_CJK_UNIFIED_IDEOGRAPHS_EXTENSION_A:
    case UBLOCK_CJK_UNIFIED_IDEOGRAPHS:
    case UBLOCK_CJK_COMPATIBILITY_IDEOGRAPHS:
    case UBLOCK_CJK_COMPATIBILITY_FORMS:
    case UBLOCK_CJK_UNIFIED_IDEOGRAPHS_EXTENSION_B:
    case UBLOCK_CJK_COMPATIBILITY_IDEOGRAPHS_SUPPLEMENT:
    case UBLOCK_CJK_STROKES:
    case UBLOCK_CJK_UNIFIED_IDEOGRAPHS_EXTENSION_C:
    case UBLOCK_CJK_UNIFIED_IDEOGRAPHS_EXTENSION_D:
    case UBLOCK_IDEOGRAPHIC_DESCRIPTION_CHARACTERS:
    case UBLOCK_LINEAR_B_IDEOGRAMS:
    case UBLOCK_ENCLOSED_IDEOGRAPHIC_SUPPLEMENT:
    case UBLOCK_HIRAGANA:
    case UBLOCK_KATAKANA:
    case UBLOCK_BOPOMOFO:
    case UBLOCK_BOPOMOFO_EXTENDED:
    case UBLOCK_HANGUL_JAMO:
    case UBLOCK_HANGUL_COMPATIBILITY_JAMO:
    case UBLOCK_HANGUL_SYLLABLES:
    case UBLOCK_HANGUL_JAMO_EXTENDED_A:
    case UBLOCK_HANGUL_JAMO_EXTENDED_B:
        return GlyphUnderlineType::DrawOverGlyph;
    default:
        return GlyphUnderlineType::SkipDescenders;
    }
}

// FIXME: This function may not work if the emphasis mark uses a complex script, but none of the
// standard emphasis marks do so.
std::optional<GlyphData> FontCascade::getEmphasisMarkGlyphData(const AtomString& mark) const
{
    if (mark.isEmpty())
        return std::nullopt;

    char32_t character;
    if (!mark.is8Bit()) {
        size_t i = 0;
        auto span = mark.span16();
        U16_NEXT(span, i, span.size(), character);
        ASSERT(U16_IS_SINGLE(character)); // The CSS parser replaces unpaired surrogates with the object replacement character.
    } else
        character = mark[0];

    std::optional<GlyphData> glyphData(glyphDataForCharacter(character, false, FontVariant::EmphasisMark));
    return glyphData.value().isValid() ? glyphData : std::nullopt;
}

int FontCascade::emphasisMarkAscent(const AtomString& mark) const
{
    std::optional<GlyphData> markGlyphData = getEmphasisMarkGlyphData(mark);
    if (!markGlyphData)
        return 0;

    RefPtr markFontData = markGlyphData.value().font.get();
    ASSERT(markFontData);
    if (!markFontData)
        return 0;

    return markFontData->fontMetrics().intAscent();
}

int FontCascade::emphasisMarkDescent(const AtomString& mark) const
{
    std::optional<GlyphData> markGlyphData = getEmphasisMarkGlyphData(mark);
    if (!markGlyphData)
        return 0;

    RefPtr markFontData = markGlyphData.value().font.get();
    ASSERT(markFontData);
    if (!markFontData)
        return 0;

    return markFontData->fontMetrics().intDescent();
}

const Font* FontCascade::fontForEmphasisMark(const AtomString& mark) const
{
    auto markGlyphData = getEmphasisMarkGlyphData(mark);
    if (!markGlyphData)
        return { };

    ASSERT(markGlyphData->font);
    return markGlyphData->font.get();
}

float FontCascade::floatEmphasisMarkHeight(const AtomString& mark) const
{
    if (RefPtr font = fontForEmphasisMark(mark))
        return font->fontMetrics().height();
    return { };
}

TextShapingResult FontCascade::layoutSimpleText(const TextRun& run, unsigned from, unsigned to, ForTextEmphasis forTextEmphasis) const
{
    TextShapingResult result;

    WidthIterator it(*this, run, 0, false, forTextEmphasis == ForTextEmphasis::Yes);
    // FIXME: Using separate glyph buffers for the prefix and the suffix is incorrect when kerning or
    // ligatures are enabled.
    GlyphBuffer localGlyphBuffer;
    it.advance(from, localGlyphBuffer);
    float beforeWidth = it.runWidthSoFar();
    it.advance(to, result.glyphBuffer);

    if (result.glyphBuffer.isEmpty())
        return result;

    float afterWidth = it.runWidthSoFar();
    result.width = afterWidth - beforeWidth;

    float initialAdvance = 0;
    if (run.rtl()) {
        it.advance(run.length(), localGlyphBuffer);
        it.finalize(localGlyphBuffer);
        initialAdvance = it.runWidthSoFar() - afterWidth;
    } else {
        it.finalize(localGlyphBuffer);
        initialAdvance = beforeWidth;
    }
    result.glyphBuffer.expandInitialAdvance(initialAdvance);

    // The glyph buffer is currently in logical order,
    // but we need to return the results in visual order.
    if (run.rtl())
        result.glyphBuffer.reverse(0, result.glyphBuffer.size());

    return result;
}

TextShapingResult FontCascade::layoutComplexText(const TextRun& run, unsigned from, unsigned to, ForTextEmphasis forTextEmphasis) const
{
    TextShapingResult result;

    ComplexTextController controller(*this, run, false, 0, forTextEmphasis == ForTextEmphasis::Yes);
    GlyphBuffer glyphBufferForStartingIndex;
    controller.advance(from, &glyphBufferForStartingIndex);
    float widthBeforeSegment = controller.totalAdvance().width();
    controller.advance(to, &result.glyphBuffer);

    if (result.glyphBuffer.isEmpty())
        return result;

    result.width = controller.totalAdvance().width() - widthBeforeSegment;

    if (run.rtl()) {
        // Exploit the fact that the sum of the paint advances is equal to
        // the sum of the layout advances.
        FloatSize initialAdvance = controller.totalAdvance();
        for (unsigned i = 0; i < glyphBufferForStartingIndex.size(); ++i)
            initialAdvance -= WebCore::size(glyphBufferForStartingIndex.advanceAt(i));
        for (unsigned i = 0; i < result.glyphBuffer.size(); ++i)
            initialAdvance -= WebCore::size(result.glyphBuffer.advanceAt(i));
        // FIXME: Shouldn't we subtract the other initial advance?
        result.glyphBuffer.reverse(0, result.glyphBuffer.size());
        result.glyphBuffer.setInitialAdvance(makeGlyphBufferAdvance(initialAdvance));
    } else {
        FloatSize initialAdvance = WebCore::size(glyphBufferForStartingIndex.initialAdvance());
        for (unsigned i = 0; i < glyphBufferForStartingIndex.size(); ++i)
            initialAdvance += WebCore::size(glyphBufferForStartingIndex.advanceAt(i));
        // FIXME: Shouldn't we add the other initial advance?
        result.glyphBuffer.setInitialAdvance(makeGlyphBufferAdvance(initialAdvance));
    }

    return result;
}

inline bool NODELETE shouldDrawIfLoading(const Font& font, FontCascade::CustomFontNotReadyAction customFontNotReadyAction)
{
    // Don't draw anything while we are using custom fonts that are in the process of loading,
    // except if the 'customFontNotReadyAction' argument is set to UseFallbackIfFontNotReady
    // (in which case "font" will be a fallback font).
    return !font.isInterstitial() || font.visibility() == Font::Visibility::Visible || customFontNotReadyAction == FontCascade::CustomFontNotReadyAction::UseFallbackIfFontNotReady;
}

#if PLATFORM(DRIFTSTACK)
// V-171 Option A (founder Tier-2 ack 2026-05-04): per-glyph dispatch gate.
// When `DRIFTSTACK_DISPATCH_PER_GLYPH=1` is set in the WebContent env (with
// __XPC_DRIFTSTACK_DISPATCH_PER_GLYPH=1 mirror per launchd convention),
// the V-131 mixed-dispatch outer gate is bypassed: V-141 ASCII atlas is
// attempted per-glyph (inner loop already filters cp < 0x20 || cp > 0x7E),
// non-ASCII glyphs fall through to native CT, which routes color emoji
// through DriftstackEmojiAtlas dispatch in FontCascadeCoreText.cpp
// drawGlyphsWithAdvances (V-090 / F.1.B-2 — empirically operational per
// V-173 atlas-binary read confirming 😃+🍕 entries at all 4 strikes).
// Result: ASCII glyphs substitute as iPhone bytes, color-emoji glyphs
// substitute as iPhone bytes — the composite hash matches iPhone's
// pure-CT-iPhone canvas-fp output without the V-131 hybrid concern.
// Default-OFF until cumulative-rig + scoreboard.py validate clean.
static bool driftstackDispatchPerGlyphEnabled()
{
    static bool s_enabled = []() {
        const char* env = getenv("DRIFTSTACK_DISPATCH_PER_GLYPH");
        return env && env[0] == '1';
    }();
    return s_enabled;
}
#endif

// This function assumes the GlyphBuffer's initial advance has already been incorporated into the start point.
void FontCascade::drawGlyphBuffer(GraphicsContext& context, const GlyphBuffer& glyphBuffer, FloatPoint& point, CustomFontNotReadyAction customFontNotReadyAction, StringView source) const
{
    ASSERT(glyphBuffer.isFlattened());

#if PLATFORM(DRIFTSTACK)
    // F.1.B-6 Phase 3: composite emoji atlas substitution via CGContextDrawImage.
    // Per founder direction Approach 1 (source-text iteration). TR51-simplified
    // sequence boundary detection (ZWJ chains, regional flag pairs, keycap,
    // skin-tone, VS-16 forced) → DriftstackCompositeAtlas lookup → PNG decode
    // → drawNativeImage at cluster origin. Atlas-hit glyphs skipped from
    // platform drawGlyphs path; non-hit text runs forwarded as normal.
    enum class AtlasHitKind { Composite, Ascii };
    struct AtlasHit {
        AtlasHitKind kind { AtlasHitKind::Composite };
        size_t glyphStart; // first glyph index in cluster
        size_t glyphEnd;   // one past last glyph index
        // Composite: pngBytes pre-resolved at pre-flight; strikeOrSize = strike.
        // Ascii (V-127): pngBytes left empty at pre-flight; draw-time resolves
        // by (asciiCssFamily, strikeOrSize=sizePx, asciiCodepoint, subpixelQuant)
        // where subpixelQuant is computed from origin.x() fractional part.
        std::span<const uint8_t> pngBytes;
        uint32_t strikeOrSize; // strike (Composite) or sizePx (Ascii)
        String asciiCssFamily; // V-127: empty for Composite
        uint32_t asciiCodepoint; // V-127: 0 for Composite
        // V-141: color slot resolved at pre-flight time from context.fillColor().
        // 0 for v1/v2 atlases (single implicit black slot) or for Composite hits.
        // Threaded to draw-time entryFor lookup so the matching pre-tinted glyph
        // is selected; also gates the stencil-and-tint pipeline.
        uint8_t colorIdx { 0 };
    };
    Vector<AtlasHit, 8> atlasHits;
    if (!source.isEmpty() && glyphBuffer.size()) {
        auto codePointAt = [&](unsigned i) -> std::pair<char32_t, unsigned> {
            if (i >= source.length())
                return { 0, 0 };
            if (source.is8Bit())
                return { static_cast<char32_t>(source[i]), 1 };
            UChar ch = source[i];
            if (ch >= 0xD800 && ch <= 0xDBFF && i + 1 < source.length()) {
                UChar low = source[i + 1];
                if (low >= 0xDC00 && low <= 0xDFFF)
                    return { static_cast<char32_t>(0x10000 + ((ch - 0xD800) << 10) + (low - 0xDC00)), 2 };
            }
            return { static_cast<char32_t>(ch), 1 };
        };
        auto detectSequence = [&](unsigned start) -> unsigned {
            auto [cp, cpSize] = codePointAt(start);
            if (!cpSize)
                return start;
            bool maybeEmoji = (cp >= 0x1F000 && cp <= 0x1FFFF)
                || (cp >= 0x2600 && cp <= 0x27BF)
                || (cp >= 0x2300 && cp <= 0x23FF)
                || (cp >= 0x2000 && cp <= 0x21FF)
                || (cp >= 0x1F1E6 && cp <= 0x1F1FF)
                || ((cp >= '0' && cp <= '9') || cp == '#' || cp == '*');
            if (!maybeEmoji)
                return start;
            unsigned end = start + cpSize;
            for (;;) {
                auto [zwj, zwjSize] = codePointAt(end);
                if (!zwjSize || zwj != 0x200D)
                    break;
                auto [next, nextSize] = codePointAt(end + zwjSize);
                if (!nextSize)
                    break;
                end += zwjSize + nextSize;
            }
            auto [tone, toneSize] = codePointAt(end);
            if (toneSize && tone >= 0x1F3FB && tone <= 0x1F3FF)
                end += toneSize;
            auto [vs, vsSize] = codePointAt(end);
            if (vsSize && vs == 0xFE0F)
                end += vsSize;
            if (cp >= 0x1F1E6 && cp <= 0x1F1FF) {
                auto [pair, pairSize] = codePointAt(start + cpSize);
                if (pairSize && pair >= 0x1F1E6 && pair <= 0x1F1FF)
                    end = std::max(end, start + cpSize + pairSize);
            }
            if ((cp >= '0' && cp <= '9') || cp == '#' || cp == '*') {
                auto [a, aSize] = codePointAt(start + cpSize);
                auto [b, bSize] = codePointAt(start + cpSize + aSize);
                if (aSize && bSize && a == 0xFE0F && b == 0x20E3)
                    end = std::max(end, start + cpSize + aSize + bSize);
            }
            return end > start + cpSize ? end : start;
        };

        // Build sorted unique source-text offsets the GlyphBuffer references.
        Vector<unsigned, 32> rawOffsets;
        rawOffsets.reserveInitialCapacity(glyphBuffer.size());
        for (size_t i = 0; i < glyphBuffer.size(); ++i)
            rawOffsets.append(static_cast<unsigned>(glyphBuffer.uncheckedStringOffsetAt(i)));
        std::sort(rawOffsets.begin(), rawOffsets.end());
        Vector<unsigned, 32> offsets;
        offsets.reserveInitialCapacity(rawOffsets.size());
        for (unsigned v : rawOffsets) {
            if (offsets.isEmpty() || offsets.last() != v)
                offsets.append(v);
        }

        auto& atlas = DriftstackCompositeAtlas::singleton();
        const float ptSize = primaryFont().platformData().size();
        const uint32_t strike = atlas.isAvailable() ? atlas.pickStrikeForPointSize(ptSize) : 0;

        if (atlas.isAvailable()) {
            for (unsigned off : offsets) {
                unsigned compositeEnd = detectSequence(off);
                bool isComposite = compositeEnd > off + 1
                    || (compositeEnd > off && [&]() { auto [cp, sz] = codePointAt(off); return sz > 0; }());
                if (!isComposite)
                    continue;
                String sub = source.substring(off, compositeEnd - off).toString();
                auto utf8 = sub.utf8();
                std::span<const uint8_t> seqBytes = unsafeMakeSpan(reinterpret_cast<const uint8_t*>(utf8.data()), utf8.length());
                auto entry = atlas.entryForSequenceAndStrike(seqBytes, strike);
                if (entry.empty())
                    continue;
                // Map source-text [off, compositeEnd) to glyph index range.
                size_t gStart = glyphBuffer.size();
                size_t gEnd = 0;
                for (size_t i = 0; i < glyphBuffer.size(); ++i) {
                    unsigned gOff = static_cast<unsigned>(glyphBuffer.uncheckedStringOffsetAt(i));
                    if (gOff >= off && gOff < compositeEnd) {
                        if (i < gStart) gStart = i;
                        if (i + 1 > gEnd) gEnd = i + 1;
                    }
                }
                if (gStart < gEnd)
                    atlasHits.append({ AtlasHitKind::Composite, gStart, gEnd, entry, strike, String(), 0u });
            }
            // Sort by glyphStart so the drawing loop can advance through them.
            std::sort(atlasHits.begin(), atlasHits.end(),
                [](const AtlasHit& a, const AtlasHit& b) { return a.glyphStart < b.glyphStart; });
        }
    }

    // V-117: Stage F root cause B — DriftstackAsciiAtlas substitution for
    // ASCII printable codepoints (U+0020 .. U+007E). Per V-117 empirical:
    // 0/196 non-space ASCII probes byte-match between Mac CT and iOS CT
    // across 6 (font, size) cells; only iPhone-rendered atlas substitution
    // closes this. Per-glyph dispatch (one hit per ASCII glyph), no source-
    // text iteration needed beyond reading codepoint at glyph's stringOffset.
    if (!source.isEmpty() && glyphBuffer.size()) {
        auto& asciiAtlas = DriftstackAsciiAtlas::singleton();
        // V-131 path 2 (CTM gate) was REVERTED in V-135. Empirical finding:
        // canvas's CTM is always non-identity (DPR-scaled by 2 or 3), so
        // the gate blocked 100% of canvas dispatches, leaving transparent
        // -background canvases with NO visible text (V-127 stencil-and-tint
        // was the only mechanism producing glyphs in that path; native CT
        // alone produced empty output). Per V-135 cumulative-rig: 1250/1253
        // unchanged vs V-136; canvas-fp 7/14 unchanged but with VISIBLE
        // text on all probes (was hash-stable garbage before).
        //
        // V-146 shadow-context gate: skip atlas dispatch when context has a
        // drop shadow. The atlas captures only the glyph shape (no shadow);
        // dispatching for shadow_text canvases would draw glyph WITHOUT
        // shadow, missing the canvas's shadow rendering. Native CT path
        // handles shadow correctly via setShadow() in CG context.
        if (asciiAtlas.isAvailable() && !context.hasDropShadow()) {
            const auto& firstFamily = m_fontDescription.firstFamily();
            const String cssFamily = firstFamily.name;
            const float ptSize = primaryFont().platformData().size();
            const uint16_t sizePx = static_cast<uint16_t>(roundf(ptSize));

            // V-141: color-aware dispatch. For v3 atlas (colorVariantCount > 1),
            // resolve context.fillColor() to a colorIdx; on miss (color not in
            // captured set), abandon atlas dispatch so native CT renders and
            // the diagnostic log surfaces the missing color value (POC pass
            // criterion #5 — bounded miss rate). For v1/v2 atlases
            // (colorVariantCount == 1), preserve existing behavior: dispatch
            // with implicit colorIdx=0 + stencil-and-tint to arbitrary fill
            // colors at draw time.
            uint8_t resolvedColorIdx = 0;
            bool skipAsciiDispatch = false;
            const bool atlasIsColorAware = (asciiAtlas.colorVariantCount() > 1);
            if (atlasIsColorAware) {
                Color tint = context.fillColor();
                auto [tr, tg, tb, ta] = tint.toResolvedColorComponentsInColorSpace(ColorSpace::SRGB);
                uint8_t r = static_cast<uint8_t>(std::clamp(roundf(tr * 255.0f), 0.0f, 255.0f));
                uint8_t g = static_cast<uint8_t>(std::clamp(roundf(tg * 255.0f), 0.0f, 255.0f));
                uint8_t b = static_cast<uint8_t>(std::clamp(roundf(tb * 255.0f), 0.0f, 255.0f));
                uint8_t a = static_cast<uint8_t>(std::clamp(roundf(ta * 255.0f), 0.0f, 255.0f));
                resolvedColorIdx = asciiAtlas.colorIdxFor(r, g, b, a);
                if (resolvedColorIdx == 0xFF) {
                    // POC pass criterion #5: log every miss with the missing
                    // color value. Surfaces what colors real probes need that
                    // the captured 16-color set lacks. Capped at 200 lines to
                    // avoid log explosion on uncovered probes.
                    static unsigned colorMisses = 0;
                    if (++colorMisses <= 200) {
                        WTFLogAlways("[Driftstack-V141] color MISS r=%u g=%u b=%u a=%u (atlas has %u colors); native CT fallback",
                            r, g, b, a, asciiAtlas.colorVariantCount());
                    }
                    skipAsciiDispatch = true;
                }
            }
            // V-122 founder Tier-2 ack: when the resolved primary family is a
            // Generic-kind family (CSS sans-serif/serif/etc. resolved to Mac's
            // per-page-settings default), atlas may not have an entry for the
            // resolved name (e.g., "Helvetica") but DOES have one for the
            // CSS keyword. Build a fallback name list to try in order. The
            // resolved-name list ("Helvetica" / "Times" / "Courier" / etc.)
            // is Mac WebKit's documented per-page-settings default for the
            // five CSS generic families.
            Vector<String, 4> familyKeysToTry;
            familyKeysToTry.append(cssFamily);
            // V-135 finding: Mac fork resolves CSS sans-serif/serif/etc. to
            // internal "-webkit-sans-serif" / "-webkit-serif" names (NOT
            // "Helvetica" as V-122 assumed). Add explicit fallbacks for
            // these canonical webkit-internal names.
            if (cssFamily == "-webkit-sans-serif"_s) familyKeysToTry.append("sans-serif"_s);
            else if (cssFamily == "-webkit-serif"_s) familyKeysToTry.append("serif"_s);
            else if (cssFamily == "-webkit-monospace"_s) familyKeysToTry.append("monospace"_s);
            else if (cssFamily == "-webkit-cursive"_s) familyKeysToTry.append("cursive"_s);
            else if (cssFamily == "-webkit-fantasy"_s) familyKeysToTry.append("fantasy"_s);
            if (firstFamily.kind == FontFamilyKind::Generic) {
                if (cssFamily == "Helvetica"_s) {
                    familyKeysToTry.append("sans-serif"_s);
                } else if (cssFamily == "Times"_s) {
                    familyKeysToTry.append("serif"_s);
                } else if (cssFamily == "Courier"_s) {
                    familyKeysToTry.append("monospace"_s);
                } else if (cssFamily == "Apple Chancery"_s) {
                    familyKeysToTry.append("cursive"_s);
                } else if (cssFamily == "Papyrus"_s) {
                    familyKeysToTry.append("fantasy"_s);
                }
            }

            // Recover codepoint at a source offset (UTF-16 surrogate pair aware).
            auto codePointAtOffset = [&](unsigned i) -> char32_t {
                if (i >= source.length())
                    return 0;
                if (source.is8Bit())
                    return static_cast<char32_t>(source[i]);
                UChar ch = source[i];
                if (ch >= 0xD800 && ch <= 0xDBFF && i + 1 < source.length()) {
                    UChar low = source[i + 1];
                    if (low >= 0xDC00 && low <= 0xDFFF)
                        return static_cast<char32_t>(0x10000 + ((ch - 0xD800) << 10) + (low - 0xDC00));
                }
                return static_cast<char32_t>(ch);
            };

            // V-131 closure path 1: mixed-dispatch fallthrough. If source
            // contains BOTH ASCII (0x20..0x7E) and non-ASCII (>= 0x80)
            // codepoints, atlas substitution would produce a hybrid render
            // (iPhone-atlas ASCII + Mac-CT non-ASCII) that cannot byte-
            // match iPhone's pure-CT render. Abandon atlas dispatch for
            // the entire run; fall through to native CT path. The pre-flight
            // for-loop below stays gated on the !mixed condition.
            //
            // V-171 Option A (founder Tier-2 ack 2026-05-04): when
            // DRIFTSTACK_DISPATCH_PER_GLYPH=1 is set, the mixedDispatch
            // outer-gate is bypassed (per-glyph dispatch). Inner loop
            // already filters non-ASCII codepoints (cp < 0x20 || cp > 0x7E
            // continue), so ASCII glyphs go to V-141 atlas + non-ASCII
            // glyphs fall through to native CT (which routes color emoji
            // via DriftstackEmojiAtlas in FontCascadeCoreText.cpp drawGlyphs
            // WithAdvances). Both halves substitute to iPhone bytes; V-131's
            // hybrid concern doesn't apply when the non-ASCII side is
            // covered by an iPhone-byte atlas too. See V-171 / V-173 / V-175.
            bool hasAscii = false;
            bool hasNonAscii = false;
            for (size_t i = 0; i < glyphBuffer.size(); ++i) {
                unsigned offset = static_cast<unsigned>(glyphBuffer.uncheckedStringOffsetAt(i));
                char32_t cp = codePointAtOffset(offset);
                if (cp >= 0x20 && cp <= 0x7E)
                    hasAscii = true;
                else if (cp >= 0x80)
                    hasNonAscii = true;
                if (hasAscii && hasNonAscii)
                    break;
            }
            const bool mixedDispatch = hasAscii && hasNonAscii;
            const bool perGlyphDispatch = driftstackDispatchPerGlyphEnabled();
            const bool dispatchAllowed = (!mixedDispatch || perGlyphDispatch) && !skipAsciiDispatch;
            if (dispatchAllowed) {
                for (size_t i = 0; i < glyphBuffer.size(); ++i) {
                    // Skip glyphs already covered by a composite atlas hit.
                    bool alreadyHit = false;
                    for (const auto& h : atlasHits) {
                        if (i >= h.glyphStart && i < h.glyphEnd) {
                            alreadyHit = true;
                            break;
                        }
                    }
                    if (alreadyHit)
                        continue;
                    unsigned offset = static_cast<unsigned>(glyphBuffer.uncheckedStringOffsetAt(i));
                    char32_t cp = codePointAtOffset(offset);
                    if (cp < 0x20 || cp > 0x7E)
                        continue;
                    // V-127: probe atlas at quant=0 to verify (font, size, cp) is
                    // covered. If yes, store the WINNING key in the AtlasHit;
                    // draw-time lookup re-queries with the subpixelQuant from
                    // the layout fractional X.
                    // V-141: probe at the resolved colorIdx (0 for v1/v2 atlas).
                    String winningKey;
                    for (const auto& key : familyKeysToTry) {
                        auto entry = asciiAtlas.entryFor(key, sizePx, static_cast<uint32_t>(cp), 0, resolvedColorIdx);
                        if (!entry.empty()) {
                            winningKey = key;
                            break;
                        }
                    }
                    if (winningKey.isEmpty())
                        continue;
                    AtlasHit h;
                    h.kind = AtlasHitKind::Ascii;
                    h.glyphStart = i;
                    h.glyphEnd = i + 1;
                    h.strikeOrSize = static_cast<uint32_t>(sizePx);
                    h.asciiCssFamily = winningKey;
                    h.asciiCodepoint = static_cast<uint32_t>(cp);
                    h.colorIdx = resolvedColorIdx; // V-141
                    atlasHits.append(std::move(h));
                }
                std::sort(atlasHits.begin(), atlasHits.end(),
                    [](const AtlasHit& a, const AtlasHit& b) { return a.glyphStart < b.glyphStart; });
            }
        }
    }

    // V-127 sub-pixel quantizer. Concretized per V-128 spot-check pattern
    // (variants=3): 0.0 ≡ 0.25 (snap to integer) ≠ 0.5 ≠ 0.75. Verified
    // empirically on 9/10 codepoints in batch 0 of the V-127 capture.
    // Founder-required full-capture verification step before this commit.
    auto quantizeSubpixel = [](float fracX, uint8_t variantCount) -> uint8_t {
        if (variantCount <= 1)
            return 0;
        if (variantCount == 4) {
            int q = static_cast<int>(roundf(fracX * 4.0f)) & 3;
            return static_cast<uint8_t>(q);
        }
        if (variantCount == 3) {
            // 0.0..0.4 → 0 (covers 0.0 + 0.25); 0.4..0.625 → 1 (0.5);
            // 0.625..1.0 → 2 (0.75)
            if (fracX < 0.4f) return 0;
            if (fracX < 0.625f) return 1;
            return 2;
        }
        if (variantCount == 2)
            return fracX < 0.5f ? 0 : 1;
        if (variantCount == 16) {
            // V-198: V-127 Path 2 root closure — 16-bucket sub-pixel
            // quantization matching iPhone CT. Per platform-precision-
            // rules.md §2.1 round-half-away-from-zero (roundf semantics).
            int q = static_cast<int>(roundf(fracX * 16.0f)) & 15;
            return static_cast<uint8_t>(q);
        }
        return 0;
    };

    auto drawCompositeAtImageOrigin = [&](const AtlasHit& hit, FloatPoint origin) {
        // V-127: for Ascii hits, resolve atlas entry at draw time using
        // the layout fractional X to pick the matching sub-pixel variant.
        // Composite hits use pre-resolved pngBytes from pre-flight.
        std::span<const uint8_t> pngBytes = hit.pngBytes;
        // V-140: fracX visible to draw code so destRect can pick floor vs
        // ceil to match the variant the atlas entry was captured for.
        float fracX = 0.0f;
        uint8_t quant = 0;
        if (hit.kind == AtlasHitKind::Ascii) {
            auto& asciiAtlas = DriftstackAsciiAtlas::singleton();
            fracX = origin.x() - floorf(origin.x());
            if (fracX < 0.0f) fracX += 1.0f;
            quant = quantizeSubpixel(fracX, asciiAtlas.subpixelVariantCount());
            // V-141: thread the colorIdx resolved at pre-flight (0 for v1/v2).
            pngBytes = asciiAtlas.entryFor(hit.asciiCssFamily, static_cast<uint16_t>(hit.strikeOrSize),
                                            hit.asciiCodepoint, quant, hit.colorIdx);
            if (pngBytes.empty()) {
                // Fall back to subpixel-0 if the specific quant has no
                // entry (atlas v1 or pre-V-127 atlas missing higher
                // quants). Same colorIdx (don't fall back to color 0
                // for v3 — that would draw black where caller asked for
                // a different color).
                pngBytes = asciiAtlas.entryFor(hit.asciiCssFamily, static_cast<uint16_t>(hit.strikeOrSize),
                                                hit.asciiCodepoint, 0, hit.colorIdx);
            }
        }
        WTFLogAlways("[Driftstack-Atlas] draw start kind=%s hit=[%zu,%zu) origin=(%.2f,%.2f) pngBytes=%zu strikeOrSize=%u",
            hit.kind == AtlasHitKind::Composite ? "composite" : "ascii",
            hit.glyphStart, hit.glyphEnd, (float)origin.x(), (float)origin.y(), pngBytes.size(), hit.strikeOrSize);
        if (pngBytes.empty()) return;
        // Decode PNG → CGImage.
        RetainPtr cfData = adoptCF(CFDataCreate(kCFAllocatorDefault, pngBytes.data(), pngBytes.size()));
        if (!cfData) { WTFLogAlways("[Driftstack-Atlas] NULL cfData"); return; }
        RetainPtr cgSource = adoptCF(CGImageSourceCreateWithData(cfData.get(), nullptr));
        if (!cgSource || !CGImageSourceGetCount(cgSource.get())) { WTFLogAlways("[Driftstack-Atlas] NULL cgSource or empty"); return; }
        RetainPtr cgImage = adoptCF(CGImageSourceCreateImageAtIndex(cgSource.get(), 0, nullptr));
        if (!cgImage) { WTFLogAlways("[Driftstack-Atlas] NULL cgImage"); return; }
        WTFLogAlways("[Driftstack-Atlas] cgImage decoded %zux%zu",
            CGImageGetWidth(cgImage.get()), CGImageGetHeight(cgImage.get()));

        // V-117 ASCII branch: atlas image is 32×32 with glyph drawn at internal
        // (4, sizePx + 4) on transparent background. Glyph PNG is black RGB +
        // alpha-coverage. Stencil-and-tint via transparency layer so the glyph
        // takes the current GraphicsContext fillColor (matching CT's behavior
        // where fillText paints in the current fillStyle), and so the
        // substitution composes correctly over any canvas background.
        if (hit.kind == AtlasHitKind::Ascii) {
            const float sizePx = static_cast<float>(hit.strikeOrSize);
            const float canvasDim = 32.0f;
            // V-127: destRect.x snaps to integer-pixel-aligned position so the
            // atlas variant's captured sub-pixel offset reproduces the original
            // layout without further fractional resampling at drawNativeImage.
            //
            // V-140 fix: when quant==0 was selected via wraparound
            // (fracX > 0.5), the atlas variant represents the NEXT integer's
            // pixel boundary, not the current's. Use ceil instead of floor in
            // that case. Per V-135 empirical: 16% of canvas-fp t01 glyphs hit
            // the wrap case (fracX in [0.875, 1.0]), so floor placed them
            // 1 px left of where iPhone CT would.
            const float snapX = (quant == 0 && fracX > 0.5f) ? ceilf(origin.x()) : floorf(origin.x());
            FloatRect destRect(snapX - 4.0f, origin.y() - sizePx - 4.0f, canvasDim, canvasDim);
            FloatRect srcRect(0, 0, canvasDim, canvasDim);
            RefPtr nativeImg = NativeImage::create(WTF::move(cgImage));
            if (!nativeImg) { WTFLogAlways("[Driftstack-Atlas] Ascii nativeImg NULL"); return; }

            // V-141: stencil-and-tint inversion. v1/v2 atlas entries are
            // BLACK glyphs on TRANSPARENT — must be tinted at draw time to
            // match the context's fillColor. v3 atlas entries are PRE-TINTED
            // in iPhone's exact rendering of the matched colorIdx — drawing
            // them via stencil-and-tint would RE-tint already-tinted pixels
            // (compounding the wrong color). For v3, draw the bitmap
            // directly via SourceOver; for v1/v2, keep the existing
            // stencil-and-tint pipeline.
            auto& asciiAtlasForDraw = DriftstackAsciiAtlas::singleton();
            if (asciiAtlasForDraw.colorVariantCount() > 1) {
                // v3: pre-tinted; direct draw.
                //
                // V-171 Option C (V-182 founder Tier-2 ack 2026-05-04): atlas
                // images are pixel-perfect captures of iPhone CT output (each
                // pixel's RGBA is iPhone-canonical). Default CGContextDrawImage
                // applies interpolation when destRect doesn't pixel-align with
                // device pixels — this resamples iPhone's pixel-perfect atlas
                // and produces AA-edge mixing that diverges from iPhone's
                // pure native render. V-182 empirical: 79% exact match + 21%
                // distributed RGB diff is consistent with interpolation re-
                // sampling (each glyph edge has 2-4 px of mixed-color pixels).
                // Fix: snap destRect to integer pixel coords (origin already
                // floored/ceiled per V-127/V-140; round size dims too) AND
                // set CGContext interpolation quality to None for this blit
                // so atlas pixels copy 1:1 to dest pixels without resampling.
                CGContextRef cgCtx = context.platformContext();
                CGInterpolationQuality savedQuality = CGContextGetInterpolationQuality(cgCtx);
                CGContextSetInterpolationQuality(cgCtx, kCGInterpolationNone);
                bool savedAA = context.shouldAntialias();
                context.setShouldAntialias(false);
                context.drawNativeImage(*nativeImg, destRect, srcRect, { CompositeOperator::SourceOver });
                context.setShouldAntialias(savedAA);
                CGContextSetInterpolationQuality(cgCtx, savedQuality);
            } else {
                // v1/v2: stencil-and-tint with context fillColor.
                Color tint = context.fillColor();
                context.beginTransparencyLayer(1.0f);
                context.fillRect(destRect, tint);
                context.drawNativeImage(*nativeImg, destRect, srcRect, { CompositeOperator::DestinationIn });
                context.endTransparencyLayer();
            }
            WTFLogAlways("[Driftstack-Atlas] Ascii draw COMPLETE dest=%.1fx%.1f at %.1f,%.1f colorIdx=%u",
                (float)destRect.width(), (float)destRect.height(), (float)destRect.x(), (float)destRect.y(), (unsigned)hit.colorIdx);
            return;
        }

        // Composite emoji geometry: atlas canvas dim = 2*strike + 8; glyph drawn
        // at (4, strike+2) within atlas canvas. Scale strike → ptSize; place
        // atlas origin so glyph baseline lands at `origin` (matching where CT
        // would place glyphs).
        const float ptSize = primaryFont().platformData().size();
        const float canvasDim = 2.0f * static_cast<float>(hit.strikeOrSize) + 8.0f;
        const float scale = ptSize / static_cast<float>(hit.strikeOrSize);
        const float imageDim = canvasDim * scale;
        const float originXOffset = -4.0f * scale;
        const float originYOffset = -(static_cast<float>(hit.strikeOrSize) + 2.0f) * scale;

        CGContextRef cgContext = context.platformContext();
        if (!cgContext) {
            WTFLogAlways("[Driftstack-F1B6] Phase3 NULL cgContext (hasPlatformContext=%d). Falling back to GraphicsContext::drawNativeImage path.", context.hasPlatformContext() ? 1 : 0);
            // Fallback: use GraphicsContext::drawNativeImage which works for both
            // direct CG contexts AND recorder contexts (records draw into display list).
            RefPtr nativeImg = NativeImage::create(WTF::move(cgImage));
            if (!nativeImg) { WTFLogAlways("[Driftstack-F1B6] Phase3 nativeImg NULL"); return; }
            FloatRect destRect(origin.x() + originXOffset, origin.y() + originYOffset, imageDim, imageDim);
            FloatRect srcRect(0, 0, CGImageGetWidth(nativeImg->platformImage().get()), CGImageGetHeight(nativeImg->platformImage().get()));
            context.drawNativeImage(*nativeImg, destRect, srcRect);
            WTFLogAlways("[Driftstack-F1B6] Phase3 drawNativeImage fallback complete (dest=%.1fx%.1f at %.1f,%.1f)",
                (float)destRect.width(), (float)destRect.height(), (float)destRect.x(), (float)destRect.y());
            return;
        }
        WTFLogAlways("[Driftstack-F1B6] Phase3 drawing: ptSize=%.2f canvasDim=%.2f scale=%.2f imageDim=%.2f origin=(%.2f,%.2f) offsets=(%.2f,%.2f)",
            ptSize, canvasDim, scale, imageDim, (float)origin.x(), (float)origin.y(), originXOffset, originYOffset);
        CGContextSaveGState(cgContext);
        CGContextTranslateCTM(cgContext, origin.x() + originXOffset, origin.y() + originYOffset);
        CGContextTranslateCTM(cgContext, 0.f, imageDim);
        CGContextScaleCTM(cgContext, 1.f, -1.f);
        CGContextDrawImage(cgContext, CGRectMake(0.f, 0.f, imageDim, imageDim), cgImage.get());
        CGContextRestoreGState(cgContext);
        WTFLogAlways("[Driftstack-F1B6] Phase3 draw COMPLETE");
    };
#else
    UNUSED_PARAM(source);
#endif

    RefPtr fontData = glyphBuffer.fontAt(0);
    FloatPoint startPoint = point;
    float nextX = startPoint.x() + WebCore::width(glyphBuffer.advanceAt(0));
    float nextY = startPoint.y() + height(glyphBuffer.advanceAt(0));
    unsigned lastFrom = 0;
    unsigned nextGlyph = 1;
#if PLATFORM(DRIFTSTACK)
    size_t hitIdx = 0;
    auto flushTextRun = [&](size_t from, size_t to, FloatPoint runStart) {
        if (from >= to)
            return;
        if (!shouldDrawIfLoading(*fontData, customFontNotReadyAction))
            return;
        size_t glyphCount = to - from;
        context.drawGlyphs(*fontData, glyphBuffer.glyphs(from, glyphCount), glyphBuffer.advances(from, glyphCount), runStart, m_fontDescription.usedFontSmoothing());
    };
    // First glyph special-case: if 0 is start of an atlas hit, flush nothing,
    // emit composite, advance past hit.
    if (!atlasHits.isEmpty() && atlasHits[0].glyphStart == 0) {
        const AtlasHit& hit = atlasHits[0];
        drawCompositeAtImageOrigin(hit, point);
        // Advance position by sum of advances for all skipped glyphs.
        float skipX = 0.f, skipY = 0.f;
        for (size_t i = hit.glyphStart; i < hit.glyphEnd; ++i) {
            skipX += WebCore::width(glyphBuffer.advanceAt(i));
            skipY += height(glyphBuffer.advanceAt(i));
        }
        startPoint.setX(point.x() + skipX);
        startPoint.setY(point.y() + skipY);
        nextX = startPoint.x();
        nextY = startPoint.y();
        if (hit.glyphEnd > 0)
            fontData = glyphBuffer.fontAt(hit.glyphEnd - 1); // approximate; refined below
        lastFrom = hit.glyphEnd;
        nextGlyph = hit.glyphEnd;
        if (lastFrom < glyphBuffer.size())
            fontData = glyphBuffer.fontAt(lastFrom);
        ++hitIdx;
    }
#endif
    while (nextGlyph < glyphBuffer.size()) {
        RefPtr nextFontData = glyphBuffer.fontAt(nextGlyph);
#if PLATFORM(DRIFTSTACK)
        // Check if entering an atlas hit boundary.
        if (hitIdx < atlasHits.size() && nextGlyph == atlasHits[hitIdx].glyphStart) {
            // Flush current run up to but not including this glyph.
            flushTextRun(lastFrom, nextGlyph, startPoint);
            // Draw composite at current draw position (nextX, nextY but actually need to track advance from startPoint).
            // The current cursor position in text-flow coords is (nextX, nextY).
            drawCompositeAtImageOrigin(atlasHits[hitIdx], FloatPoint(nextX, nextY));
            const AtlasHit& hit = atlasHits[hitIdx];
            // Advance cursor by sum of skipped glyph advances.
            float skipX = 0.f, skipY = 0.f;
            for (size_t i = hit.glyphStart; i < hit.glyphEnd; ++i) {
                skipX += WebCore::width(glyphBuffer.advanceAt(i));
                skipY += height(glyphBuffer.advanceAt(i));
            }
            nextX += skipX;
            nextY += skipY;
            lastFrom = hit.glyphEnd;
            nextGlyph = hit.glyphEnd;
            startPoint.setX(nextX);
            startPoint.setY(nextY);
            if (lastFrom < glyphBuffer.size())
                fontData = glyphBuffer.fontAt(lastFrom);
            ++hitIdx;
            continue;
        }
#endif

        if (nextFontData != fontData) {
            if (shouldDrawIfLoading(*fontData, customFontNotReadyAction)) {
                size_t glyphCount = nextGlyph - lastFrom;
                context.drawGlyphs(*fontData, glyphBuffer.glyphs(lastFrom, glyphCount), glyphBuffer.advances(lastFrom, glyphCount), startPoint, m_fontDescription.usedFontSmoothing());
            }
            lastFrom = nextGlyph;
            fontData = WTF::move(nextFontData);
            startPoint.setX(nextX);
            startPoint.setY(nextY);
        }
        nextX += WebCore::width(glyphBuffer.advanceAt(nextGlyph));
        nextY += height(glyphBuffer.advanceAt(nextGlyph));
        nextGlyph++;
    }

    if (lastFrom < glyphBuffer.size() && shouldDrawIfLoading(*fontData, customFontNotReadyAction)) {
        size_t glyphCount = nextGlyph - lastFrom;
        context.drawGlyphs(*fontData, glyphBuffer.glyphs(lastFrom, glyphCount), glyphBuffer.advances(lastFrom, glyphCount), startPoint, m_fontDescription.usedFontSmoothing());
    }
    point.setX(nextX);
}

inline static float offsetToMiddleOfGlyph(const Font& fontData, Glyph glyph)
{
    if (fontData.platformData().orientation() == FontOrientation::Horizontal) {
        FloatRect bounds = fontData.boundsForGlyph(glyph);
        return bounds.x() + bounds.width() / 2;
    }
    // FIXME: Use glyph bounds once they make sense for vertical fonts.
    return fontData.widthForGlyph(glyph) / 2;
}

inline static float offsetToMiddleOfGlyphAtIndex(const GlyphBuffer& glyphBuffer, unsigned i)
{
    return offsetToMiddleOfGlyph(protect(glyphBuffer.fontAt(i)), glyphBuffer.glyphAt(i));
}

void FontCascade::drawEmphasisMarks(GraphicsContext& context, const GlyphBuffer& glyphBuffer, const AtomString& mark, const FloatPoint& point) const
{
    ASSERT(glyphBuffer.isFlattened());
    std::optional<GlyphData> markGlyphData = getEmphasisMarkGlyphData(mark);
    if (!markGlyphData)
        return;

    RefPtr markFontData = markGlyphData.value().font.get();
    ASSERT(markFontData);
    if (!markFontData)
        return;

    Glyph markGlyph = markGlyphData.value().glyph;
    Glyph spaceGlyph = markFontData->spaceGlyph();

    // FIXME: This needs to take the initial advance into account.
    // The problem might actually be harder for complex text, though.
    // Putting a mark over every glyph probably isn't great in complex scripts.
    float middleOfLastGlyph = offsetToMiddleOfGlyphAtIndex(glyphBuffer, 0);
    FloatPoint startPoint(point.x() + middleOfLastGlyph - offsetToMiddleOfGlyph(*markFontData, markGlyph), point.y());

    GlyphBuffer markBuffer;
    auto glyphForMarker = [&](unsigned index) {
        auto glyph = glyphBuffer.glyphAt(index);
        return (glyph && glyph != deletedGlyph) ? markGlyph : spaceGlyph;
    };

    for (unsigned i = 0; i + 1 < glyphBuffer.size(); ++i) {
        float middleOfNextGlyph = offsetToMiddleOfGlyphAtIndex(glyphBuffer, i + 1);
        float advance = WebCore::width(glyphBuffer.advanceAt(i)) - middleOfLastGlyph + middleOfNextGlyph;
        markBuffer.add(glyphForMarker(i), *markFontData, advance);
        middleOfLastGlyph = middleOfNextGlyph;
    }
    markBuffer.add(glyphForMarker(glyphBuffer.size() - 1), *markFontData, 0);

    drawGlyphBuffer(context, markBuffer, startPoint, CustomFontNotReadyAction::DoNotPaintIfFontNotReady);
}

void FontCascade::adjustSelectionRectForSimpleText(const TextRun& run, LayoutRect& selectionRect, unsigned from, unsigned to) const
{
    GlyphBuffer glyphBuffer;
    WidthIterator it(*this, run);
    it.advance(from, glyphBuffer);
    float beforeWidth = it.runWidthSoFar();
    it.advance(to, glyphBuffer);
    float afterWidth = it.runWidthSoFar();

    if (run.rtl()) {
        it.advance(run.length(), glyphBuffer);
        it.finalize(glyphBuffer);
        float totalWidth = it.runWidthSoFar();
        selectionRect.move(totalWidth - afterWidth, 0);
    } else {
        it.finalize(glyphBuffer);
        selectionRect.move(beforeWidth, 0);
    }
    selectionRect.setWidth(LayoutUnit::fromFloatCeil(afterWidth - beforeWidth));
}

void FontCascade::adjustSelectionRectForComplexText(const TextRun& run, LayoutRect& selectionRect, unsigned from, unsigned to) const
{
    ComplexTextController controller(*this, run);
    controller.advance(from);
    float beforeWidth = controller.runWidthSoFar();
    controller.advance(to);
    float afterWidth = controller.runWidthSoFar();

    if (run.rtl())
        selectionRect.move(controller.totalAdvance().width() - afterWidth, 0);
    else
        selectionRect.move(beforeWidth, 0);
    selectionRect.setWidth(LayoutUnit::fromFloatCeil(afterWidth - beforeWidth));
}

void FontCascade::adjustSelectionRectForSimpleTextWithFixedPitch(const TextRun& run, LayoutRect& selectionRect, unsigned from, unsigned to) const
{
    bool whitespaceIsCollapsed = !run.allowTabs();
    float beforeWidth = widthForSimpleTextWithFixedPitch(run.text().left(from), whitespaceIsCollapsed);
    float afterWidth = widthForSimpleTextWithFixedPitch(run.text().left(to), whitespaceIsCollapsed);
    if (run.rtl()) {
        float totalWidth = widthForSimpleTextWithFixedPitch(run.text(), whitespaceIsCollapsed);
        selectionRect.move(totalWidth - afterWidth, 0);
    } else
        selectionRect.move(beforeWidth, 0);
    selectionRect.setWidth(LayoutUnit::fromFloatCeil(afterWidth - beforeWidth));
}

int FontCascade::offsetForPositionForSimpleText(const TextRun& run, float x, bool includePartialGlyphs) const
{
    float delta = x;

    WidthIterator it(*this, run);
    GlyphBuffer localGlyphBuffer;
    unsigned offset;
    if (run.rtl()) {
        delta -= width(CodePath::Simple, run);
        while (1) {
            offset = it.currentCharacterIndex();
            float w;
            if (!it.advanceOneCharacter(w, localGlyphBuffer))
                break;
            delta += w;
            if (includePartialGlyphs) {
                if (delta - w / 2 >= 0)
                    break;
            } else {
                if (delta >= 0)
                    break;
            }
        }
    } else {
        while (1) {
            offset = it.currentCharacterIndex();
            float w;
            if (!it.advanceOneCharacter(w, localGlyphBuffer))
                break;
            delta -= w;
            if (includePartialGlyphs) {
                if (delta + w / 2 <= 0)
                    break;
            } else {
                if (delta <= 0)
                    break;
            }
        }
    }

    it.finalize(localGlyphBuffer);
    return offset;
}

int FontCascade::offsetForPositionForComplexText(const TextRun& run, float x, bool includePartialGlyphs) const
{
    ComplexTextController controller(*this, run);
    return controller.offsetForPosition(x, includePartialGlyphs);
}

#if !PLATFORM(COCOA) && !USE(HARFBUZZ)
// FIXME: Unify this with the macOS and iOS implementation.
RefPtr<const Font> FontCascade::fontForCombiningCharacterSequence(StringView stringView) const
{
    ASSERT(stringView.length() > 0);
    char32_t baseCharacter = *stringView.codePoints().begin();
    GlyphData baseCharacterGlyphData = glyphDataForCharacter(baseCharacter, false, FontVariant::Normal);

    if (!baseCharacterGlyphData.isValid())
        return nullptr;
    return baseCharacterGlyphData.font.get();
}
#endif

struct GlyphIterationState {
    FloatPoint startingPoint;
    FloatPoint currentPoint;
    float y1;
    float y2;
    float minX;
    float maxX;
};

static std::optional<float> NODELETE findIntersectionPoint(float y, FloatPoint p1, FloatPoint p2)
{
    if ((p1.y() < y && p2.y() > y) || (p1.y() > y && p2.y() < y))
        return p1.x() + (y - p1.y()) * (p2.x() - p1.x()) / (p2.y() - p1.y());
    return std::nullopt;
}

static void updateX(GlyphIterationState& state, float x)
{
    state.minX = std::min(state.minX, x);
    state.maxX = std::max(state.maxX, x);
}

// This function is called by CGPathApply and is therefore invoked for each
// contour in a glyph. This function models each contours as a straight line
// and calculates the intersections between each pseudo-contour and
// two horizontal lines (the upper and lower bounds of an underline) found in
// GlyphIterationState::y1 and GlyphIterationState::y2. It keeps track of the
// leftmost and rightmost intersection in GlyphIterationState::minX and
// GlyphIterationState::maxX.
static void findPathIntersections(GlyphIterationState& state, const PathElement& element)
{
    bool doIntersection = false;
    FloatPoint point = FloatPoint();
    switch (element.type) {
    case PathElement::Type::MoveToPoint:
        state.startingPoint = element.points[0];
        state.currentPoint = element.points[0];
        break;
    case PathElement::Type::AddLineToPoint:
        doIntersection = true;
        point = element.points[0];
        break;
    case PathElement::Type::AddQuadCurveToPoint:
        doIntersection = true;
        point = element.points[1];
        break;
    case PathElement::Type::AddCurveToPoint:
        doIntersection = true;
        point = element.points[2];
        break;
    case PathElement::Type::CloseSubpath:
        doIntersection = true;
        point = state.startingPoint;
        break;
    }
    if (!doIntersection)
        return;
    if (auto intersectionPoint = findIntersectionPoint(state.y1, state.currentPoint, point))
        updateX(state, *intersectionPoint);
    if (auto intersectionPoint = findIntersectionPoint(state.y2, state.currentPoint, point))
        updateX(state, *intersectionPoint);
    if ((state.currentPoint.y() >= state.y1 && state.currentPoint.y() <= state.y2)
        || (state.currentPoint.y() <= state.y1 && state.currentPoint.y() >= state.y2))
        updateX(state, state.currentPoint.x());
    state.currentPoint = point;
}

class GlyphToPathTranslator {
public:
    GlyphToPathTranslator(const TextRun& textRun, const GlyphBuffer& glyphBuffer, const FloatPoint& textOrigin)
        : m_textRun(textRun)
        , m_glyphBuffer(glyphBuffer)
        , m_fontData(glyphBuffer.fontAt(m_index))
        , m_translation(AffineTransform::makeTranslation(toFloatSize(textOrigin)))
    {
#if USE(CG)
        m_translation.flipY();
#endif
    }

    bool NODELETE containsMorePaths() { return m_index != m_glyphBuffer.size(); }
    Path path();
    std::pair<float, float> extents();
    GlyphUnderlineType underlineType();
    void advance();

private:
    unsigned m_index { 0 };
    CheckedRef<const TextRun> m_textRun;
    const GlyphBuffer& m_glyphBuffer;
    Ref<const Font> m_fontData;
    AffineTransform m_translation;
};

Path GlyphToPathTranslator::path()
{
    // Upright glyphs in vertical text need per-glyph translations from CoreText that we don't have here.
    if (m_fontData->platformData().orientation() == FontOrientation::Vertical)
        return { };
    Path path = Ref { m_fontData }->pathForGlyph(m_glyphBuffer.glyphAt(m_index));
    path.transform(m_translation);
    return path;
}

std::pair<float, float> GlyphToPathTranslator::extents()
{
    auto beginning = m_translation.mapPoint(FloatPoint(0, 0));
    auto advance = m_glyphBuffer.advanceAt(m_index);
    auto end = m_translation.mapSize(size(advance));
    return std::make_pair(beginning.x(), beginning.x() + end.width());
}

auto GlyphToPathTranslator::underlineType() -> GlyphUnderlineType
{
    return computeUnderlineType(m_textRun, m_glyphBuffer, m_index);
}

void GlyphToPathTranslator::advance()
{
    GlyphBufferAdvance advance = m_glyphBuffer.advanceAt(m_index);
    m_translation.translate(size(advance));
    ++m_index;
    if (m_index < m_glyphBuffer.size())
        m_fontData = m_glyphBuffer.fontAt(m_index);
}

Vector<FloatSegment> FontCascade::lineSegmentsForIntersectionsWithRect(const TextRun& run, const FloatPoint& textOrigin, const FloatRect& lineExtents) const
{
    Vector<FloatSegment> result;
    if (isLoadingCustomFonts())
        return result;

    auto glyphBuffer = layoutText(codePath(run), run, 0, run.length()).glyphBuffer;
    if (!glyphBuffer.size())
        return result;

    FloatPoint origin = textOrigin + WebCore::size(glyphBuffer.initialAdvance());
    GlyphToPathTranslator translator(run, glyphBuffer, origin);
    for (; translator.containsMorePaths(); translator.advance()) {
        GlyphIterationState info = { FloatPoint(0, 0), FloatPoint(0, 0), lineExtents.y(), lineExtents.y() + lineExtents.height(), lineExtents.x() + lineExtents.width(), lineExtents.x() };
        switch (translator.underlineType()) {
        case GlyphUnderlineType::SkipDescenders: {
            Path path = translator.path();
            path.applyElements([&](const PathElement& element) {
                findPathIntersections(info, element);
            });
            if (info.minX < info.maxX)
                result.append({ info.minX - lineExtents.x(), info.maxX - lineExtents.x() });
            break;
        }
        case GlyphUnderlineType::SkipGlyph: {
            std::pair<float, float> extents = translator.extents();
            result.append({ extents.first - lineExtents.x(), extents.second - lineExtents.x() });
            break;
        }
        case GlyphUnderlineType::DrawOverGlyph:
            // Nothing to do
            break;
        }
    }
    return result;
}

bool shouldSynthesizeSmallCaps(bool dontSynthesizeSmallCaps, const Font* nextFont, char32_t baseCharacter, std::optional<char32_t> capitalizedBase, FontVariantCaps fontVariantCaps, bool engageAllSmallCapsProcessing)
{
    if (fontVariantCaps == FontVariantCaps::Normal)
        return false;

    if (dontSynthesizeSmallCaps)
        return false;
    if (!nextFont || nextFont->isSystemFontFallbackPlaceholder())
        return false;
    if (engageAllSmallCapsProcessing && isUnicodeCompatibleASCIIWhitespace(baseCharacter))
        return false;
    if (!engageAllSmallCapsProcessing && !capitalizedBase)
        return false;
    return !nextFont->variantCapsSupportedForSynthesis(fontVariantCaps);
}

// FIXME: Capitalization is language-dependent and context-dependent and should operate on grapheme clusters instead of codepoints.
std::optional<char32_t> capitalized(char32_t baseCharacter)
{
    if (U_GET_GC_MASK(baseCharacter) & U_GC_M_MASK)
        return std::nullopt;

    char32_t uppercaseCharacter = u_toupper(baseCharacter);
    ASSERT(uppercaseCharacter == baseCharacter || (U_IS_BMP(baseCharacter) == U_IS_BMP(uppercaseCharacter)));
    if (uppercaseCharacter != baseCharacter)
        return uppercaseCharacter;
    return std::nullopt;
}

TextStream& operator<<(TextStream& ts, const FontCascade& fontCascade)
{
    ts << fontCascade.fontDescription();

    if (fontCascade.fontSelector())
        ts << ", font selector "_s << fontCascade.fontSelector();

    if (fontCascade.fonts())
        ts << ", generation "_s << fontCascade.fonts()->generation();

    return ts;
}

} // namespace WebCore
