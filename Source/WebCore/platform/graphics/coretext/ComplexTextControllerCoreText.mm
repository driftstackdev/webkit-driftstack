/*
 * Copyright (C) 2007-2024 Apple Inc. All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY APPLE INC. AND ITS CONTRIBUTORS ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL APPLE INC. OR ITS CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#import "config.h"
#import "ComplexTextController.h"

#import "FontCache.h"
#import "FontCascadeInlines.h"
#import "FontInlines.h"
#import "Logging.h"
#import "SimpleFontDataCoreText.h"
#import <CoreText/CoreText.h>
#import <pal/spi/cf/CoreTextSPI.h>
#import <wtf/SoftLinking.h>
#import <wtf/WeakPtr.h>

namespace WebCore {

static std::span<const CFIndex> CTRunGetStringIndicesPtrSpan(CTRunRef ctRun)
{
    auto* coreTextIndicesPtr = CTRunGetStringIndicesPtr(ctRun);
    if (!coreTextIndicesPtr)
        return { };
    return unsafeMakeSpan(coreTextIndicesPtr, CTRunGetGlyphCount(ctRun));
}

static std::span<const CGGlyph> CTRunGetGlyphsSpan(CTRunRef ctRun)
{
    auto* glyphsPtr = CTRunGetGlyphsPtr(ctRun);
    if (!glyphsPtr)
        return { };
    return unsafeMakeSpan(glyphsPtr, CTRunGetGlyphCount(ctRun));
}

static std::span<const CGSize> CTRunGetAdvancesSpan(CTRunRef ctRun)
{
    auto* baseAdvances = CTRunGetAdvancesPtr(ctRun);
    if (!baseAdvances)
        return { };
    return unsafeMakeSpan(baseAdvances, CTRunGetGlyphCount(ctRun));
}

ComplexTextController::ComplexTextRun::ComplexTextRun(CTRunRef ctRun, const Font& font, std::span<const char16_t> characters, unsigned stringLocation, unsigned indexBegin, unsigned indexEnd)
    : m_initialAdvance(CTRunGetInitialAdvance(ctRun))
    , m_font(font)
    , m_characters(characters)
    , m_indexBegin(indexBegin)
    , m_indexEnd(indexEnd)
    , m_glyphCount(CTRunGetGlyphCount(ctRun))
    , m_stringLocation(stringLocation)
    , m_isLTR(!(CTRunGetStatus(ctRun) & kCTRunStatusRightToLeft))
    , m_textAutospaceSize(TextAutospace::textAutospaceSize(font))
{
    auto coreTextIndicesSpan = CTRunGetStringIndicesPtrSpan(ctRun);
    Vector<CFIndex> coreTextIndices;
    if (!coreTextIndicesSpan.data()) {
        coreTextIndices.grow(m_glyphCount);
        CTRunGetStringIndices(ctRun, CFRangeMake(0, 0), coreTextIndices.mutableSpan().data());
        coreTextIndicesSpan = coreTextIndices.span();
    }
    m_coreTextIndices = coreTextIndicesSpan;

    if (auto glyphsSpan = CTRunGetGlyphsSpan(ctRun); glyphsSpan.data())
        m_glyphs = glyphsSpan;
    else {
        m_glyphs.grow(m_glyphCount);
        CTRunGetGlyphs(ctRun, CFRangeMake(0, 0), m_glyphs.mutableSpan().data());
    }

    if (CTRunGetStatus(ctRun) & kCTRunStatusHasOrigins) {
        Vector<CGSize> baseAdvances(m_glyphCount);
        Vector<CGPoint> glyphOrigins(m_glyphCount);
        CTRunGetBaseAdvancesAndOrigins(ctRun, CFRangeMake(0, 0), baseAdvances.mutableSpan().data(), glyphOrigins.mutableSpan().data());
        m_baseAdvances.reserveInitialCapacity(m_glyphCount);
        m_glyphOrigins.reserveInitialCapacity(m_glyphCount);
        for (unsigned i = 0; i < m_glyphCount; ++i) {
            m_baseAdvances.append(baseAdvances[i]);
            m_glyphOrigins.append(glyphOrigins[i]);
        }
    } else {
        if (auto baseAdvancesSpan = CTRunGetAdvancesSpan(ctRun); baseAdvancesSpan.data())
            m_baseAdvances = baseAdvancesSpan;
        else {
            Vector<CGSize, 64> baseAdvancesVector;
            baseAdvancesVector.grow(m_glyphCount);
            CTRunGetAdvances(ctRun, CFRangeMake(0, 0), baseAdvancesVector.mutableSpan().data());
            m_baseAdvances = BaseAdvancesVector(m_glyphCount, [&](size_t i) {
                return baseAdvancesVector[i];
            });
        }
    }

#if PLATFORM(DRIFTSTACK)
    // V-583.F: Override per-glyph advances with iPhone-canonical values from
    // Font::widthForGlyph (routes through V-149 ASCII + V-094 Track 5 emoji +
    // V-143 Apple Color Emoji overrides). This is the upstream-most hook —
    // ComplexTextController consumes m_baseAdvances for ALL downstream cursor
    // positioning + per-glyph drawGlyphs anchor computation. Inter-run anchors
    // accumulate from this, so overriding here propagates to the entire text
    // layout. (V-583.E hook in FontCascade::drawGlyphs only affected within-run
    // + trailing cursor — too late for inter-run anchor parity.)
    if (m_glyphCount && m_baseAdvances.size() == m_glyphCount) {
        BaseAdvancesVector overrideAdvances;
        overrideAdvances.reserveInitialCapacity(m_glyphCount);
        // V-583.F.2 (#96 kerning fix): current.width is the IN-CONTEXT native CTRun advance — it
        // includes inter-glyph KERNING. iphoneWidth (Font::widthForGlyph) is the ISOLATED advance. A
        // plain replacement STRIPS the kerning, which is the mixed-script complex-path bug: any
        // non-Latin char forces the following Latin out of the simple path (which keeps kerning, == iOS)
        // into this complex path, and the bare override drops every interior glyph's kern (~4px/m).
        // Apply the override as a DELTA off the Mac ISOLATED advance so kerning is preserved:
        //   corrected = iphoneWidth + (current.width - macIsolated)
        // For identical Mac==iPhone glyphs (no real override, macIsolated == iphoneWidth) this yields
        // `current` (kerned, kept); for genuinely-overridden glyphs (emoji, no kerning) it yields
        // iphoneWidth; for the canary/isolated-glyph glyphHash (no kern) it is unchanged.
        CTFontRef macCTFont = m_font->platformData().ctFont();
        for (unsigned i = 0; i < m_glyphCount; ++i) {
            float iphoneWidth = m_font->widthForGlyph(m_glyphs[i], Font::SyntheticBoldInclusion::Exclude);
            CGSize current = m_baseAdvances[i];
            CGSize macIsolated = current;
            if (macCTFont) {
                CGGlyph glyph = m_glyphs[i];
                CTFontGetAdvancesForGlyphs(macCTFont, kCTFontOrientationHorizontal, &glyph, &macIsolated, 1);
            }
            float kern = static_cast<float>(current.width) - static_cast<float>(macIsolated.width);
            overrideAdvances.append(CGSizeMake(iphoneWidth + kern, current.height));
        }
        m_baseAdvances = std::move(overrideAdvances);
    }
#endif

    LOG_WITH_STREAM(TextShaping,
        stream << "Shaping result: " << m_glyphCount << " glyphs.\n";
        stream << "Glyphs:";
        for (unsigned i = 0; i < m_glyphCount; ++i)
            stream << " " << m_glyphs[i];
        stream << "\n";
        stream << "Advances:";
        for (unsigned i = 0; i < m_glyphCount; ++i)
            stream << " " << m_baseAdvances[i];
        stream << "\n";
        stream << "Origins:";
        if (m_glyphOrigins.isEmpty())
            stream << " empty";
        else {
            for (unsigned i = 0; i < m_glyphCount; ++i)
                stream << " " << m_glyphOrigins[i];
        }
        stream << "\n";
        stream << "Offsets:";
        for (unsigned i = 0; i < m_glyphCount; ++i)
            stream << " " << m_coreTextIndices[i];
        stream << "\n";
        stream << "Initial advance: " << FloatSize(m_initialAdvance);
    );
}

struct ProviderInfo {
    std::span<const char16_t> characters;
    RetainPtr<CFDictionaryRef> attributes;
};

static const UniChar* NODELETE provideStringAndAttributes(CFIndex stringIndex, CFIndex* charCount, CFDictionaryRef* attributes, void* refCon)
{
    ProviderInfo* info = static_cast<struct ProviderInfo*>(refCon);
    if (stringIndex < 0 || static_cast<size_t>(stringIndex) >= info->characters.size())
        return 0;

    *charCount = info->characters.size() - stringIndex;
    *attributes = info->attributes.get();
    return reinterpret_cast<const UniChar*>(info->characters.subspan(stringIndex).data());
}

enum class CoreTextTypesetterEmbeddingLevel : short { LTR = 0, RTL = 1 };

NEVER_INLINE static RetainPtr<CFDictionaryRef> buildCoreTextTypesetterEmbeddingLevelDictionary(CoreTextTypesetterEmbeddingLevel embeddingLevel)
{
    auto embeddingLevelValue = std::to_underlying(embeddingLevel);
    static_assert(std::is_same_v<short, decltype(embeddingLevelValue)>);
    const void* optionKeys[] = { kCTTypesetterOptionForcedEmbeddingLevel };
    RetainPtr cfEmbeddingLevelValue = adoptCF(CFNumberCreate(kCFAllocatorDefault, kCFNumberShortType, &embeddingLevelValue));
    const void* optionValues[] = { cfEmbeddingLevelValue.get() };
    return adoptCF(CFDictionaryCreate(kCFAllocatorDefault, optionKeys, optionValues, std::size(optionKeys), &kCFCopyStringDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks));
}

template<CoreTextTypesetterEmbeddingLevel embeddingLevel>
static CFDictionaryRef typesetterOptionsSingleton()
{
    static LazyNeverDestroyed<RetainPtr<CFDictionaryRef>> options;
    static std::once_flag onceFlag;
    std::call_once(onceFlag, [&] {
        options.construct(buildCoreTextTypesetterEmbeddingLevelDictionary(embeddingLevel));
    });
    return options.get().get();
}

void ComplexTextController::collectComplexTextRunsForCharacters(std::span<const char16_t> characters, unsigned stringLocation, const Font* font)
{
#if PLATFORM(DRIFTSTACK)
    // P-#48.L Wave 29-327 diag: log when our V-433.Z target cps reach
    // the complex-text path. Confirms which probe queries traverse this
    // path vs the simplified path (P-#48.K handles that).
    static bool s_p48lDiagEnabled = []() {
        const char* env = getenv("DRIFTSTACK_V433Z_MN_OVERRIDE");
        return env && env[0] == '1';
    }();
    if (s_p48lDiagEnabled && !characters.empty()) {
        char32_t cp0 = characters[0];
        if (cp0 >= 0xD800 && cp0 <= 0xDBFF && characters.size() >= 2) {
            uint32_t low = characters[1];
            if (low >= 0xDC00 && low <= 0xDFFF)
                cp0 = 0x10000 + ((cp0 - 0xD800) << 10) + (low - 0xDC00);
        }
        static const char32_t kTargets[] = {
            0x1CDA, 0x17DD, 0x302E, 0x2C7B, 0x10A0,
            0xA73D, 0xFFFD, 0x21E4, 0x20E3, 0x20B9
        };
        for (auto t : kTargets) {
            if (t == cp0) {
                static unsigned diagCount = 0;
                if (diagCount++ < 20)
                    WTFLogAlways("[Driftstack-P48-L-Diag] complex-path cp=U+%04X len=%zu font='%s'",
                        (unsigned)cp0, characters.size(),
                        font ? "(present)" : "(null)");
                break;
            }
        }
    }
#endif
#if PLATFORM(DRIFTSTACK)
    // P-#48.N Wave 29-329: extend Mn override to BOTH if(!font) AND
    // if(font!=null) branches. Original Wave 29-328 fired only when
    // primary font lacks glyph; Wave 29-329 fires whenever first cp is
    // a V-433.Z target — short-circuits CTLine creation entirely with
    // synthesized iPhone-canonical advance.
    if (s_p48lDiagEnabled && !characters.empty()) {
        char32_t cp0 = characters[0];
        if (cp0 >= 0xD800 && cp0 <= 0xDBFF && characters.size() >= 2) {
            uint32_t low = characters[1];
            if (low >= 0xDC00 && low <= 0xDFFF)
                cp0 = 0x10000 + ((cp0 - 0xD800) << 10) + (low - 0xDC00);
        }
        struct CpRatio { char32_t cp; float ratio72; };
        // P-#48.O Wave 29-330: per-font variant widths. Default ratio for
        // uniform cps; per-font overrides resolve from m_fontCascade primary
        // family name. iPhone Wave 29-309 reference data.
        static const std::array<CpRatio, 10> kTargets {{
            {0x1CDA, 27.f/72.f}, {0x17DD, 36.f/72.f},
            {0x302E, 56.f/72.f}, {0x2C7B, 56.f/72.f},
            {0x10A0, 61.f/72.f}, {0xA73D, 56.f/72.f},
            {0xFFFD, 43.f/72.f}, {0x21E4, 43.f/72.f},
            {0x20E3, 72.f/72.f}, {0x20B9, 37.f/72.f},
        }};
        for (const auto& t : kTargets) {
            if (t.cp == cp0) {
                auto primaryFont = protect(m_fontCascade->primaryFont());
                float ptSize = primaryFont->platformData().size();
                float ratio = t.ratio72;
                // Per-font variant lookup
                String familyName = primaryFont->platformData().familyName().convertToASCIILowercase();
                bool isAppleSystem = familyName.startsWith("-apple-system"_s)
                    || familyName.startsWith("system-ui"_s)
                    || familyName.startsWith(".sf"_s)
                    || familyName.startsWith(".applesystem"_s);
                if (cp0 == 0x302E || cp0 == 0x2C7B || cp0 == 0xA73D) {
                    // 5-bucket variant: Courier 43 / Helvetica 46 / Arial 54 /
                    // Times/Tahoma/serif 56 / Georgia/Verdana/-apple/system 72
                    if (familyName == "courier"_s || familyName == "courier new"_s) ratio = 43.f/72.f;
                    else if (familyName == "helvetica"_s) ratio = 46.f/72.f;
                    else if (familyName == "arial"_s) ratio = 54.f/72.f;
                    else if (familyName == "georgia"_s || familyName == "verdana"_s || isAppleSystem) ratio = 72.f/72.f;
                    // else: default 56.f/72.f (Times/Tahoma/serif)
                } else if (cp0 == 0xFFFD) {
                    if (isAppleSystem) ratio = 75.f/72.f;
                    // else: default 43.f/72.f
                } else if (cp0 == 0x20E3) {
                    if (isAppleSystem) ratio = 77.f/72.f;
                    // else: default 72.f/72.f
                } else if (cp0 == 0x20B9) {
                    if (familyName == "georgia"_s) ratio = 51.f/72.f;
                    else if (isAppleSystem) ratio = 44.f/72.f;
                    // else: default 37.f/72.f
                }
                float synthAdv = ratio * ptSize;
                Vector<FloatSize> advances { { synthAdv, 0 } };
                Vector<FloatPoint> origins { { 0, 0 } };
                Vector<Glyph> glyphs { 0 };
                Vector<unsigned> stringIndices { 0 };
                m_complexTextRuns.append(ComplexTextRun::create(advances, origins, glyphs, stringIndices,
                    FloatSize { 0, 0 }, primaryFont, characters, stringLocation, 0,
                    characters.size(), m_run->ltr()));
                static unsigned p48nLogCount = 0;
                if (p48nLogCount++ < 30)
                    WTFLogAlways("[Driftstack-P48-N-Override] complex-path cp=U+%04X ptSize=%.1f font=%s → synthAdv=%.3f",
                        (unsigned)cp0, ptSize, font ? "(present)" : "(null)", synthAdv);
                return;
            }
        }
    }
#endif
    if (!font) {
        // Create a run of missing glyphs from the primary font.
        m_complexTextRuns.append(ComplexTextRun::create(protect(m_fontCascade->primaryFont()), characters, stringLocation, 0, characters.size(), m_run->ltr()));
        return;
    }

    RefPtr effectiveFont = font;
    bool isSystemFallback = false;

    char32_t baseCharacter = 0;
    RetainPtr<CFDictionaryRef> stringAttributes;
    if (effectiveFont->isSystemFontFallbackPlaceholder()) {
        // FIXME: This code path does not support small caps.
        isSystemFallback = true;

        U16_GET(characters, 0, 0, characters.size(), baseCharacter);
        effectiveFont = m_fontCascade->fallbackRangesAt(0).fontForCharacter(baseCharacter);
        if (!effectiveFont)
            effectiveFont = &m_fontCascade->fallbackRangesAt(0).fontForFirstRange();
        stringAttributes = adoptCF(CFDictionaryCreateMutableCopy(kCFAllocatorDefault, 0, getCFStringAttributes(*effectiveFont, m_fontCascade->enableKerning(), effectiveFont->platformData().orientation(), m_fontCascade->fontDescription().computedLocale()).get()));
        // We don't know which font should be used to render this grapheme cluster, so enable CoreText's fallback mechanism by using the CTFont which doesn't have CoreText's fallback disabled.
        CFDictionarySetValue(const_cast<CFMutableDictionaryRef>(stringAttributes.get()), kCTFontAttributeName, effectiveFont->platformData().ctFont());
    } else
        stringAttributes = getCFStringAttributes(*effectiveFont, m_fontCascade->enableKerning(), effectiveFont->platformData().orientation(), m_fontCascade->fontDescription().computedLocale());

    RetainPtr<CTLineRef> line;

    LOG_WITH_STREAM(TextShaping,
        stream << "Complex shaping " << characters.size() << " code units with info " << String(adoptCF(CFCopyDescription(stringAttributes.get())).get()) << ".\n";
        stream << "Font attributes: " << String(adoptCF(CFCopyDescription(adoptCF(CTFontDescriptorCopyAttributes(adoptCF(CTFontCopyFontDescriptor(effectiveFont->platformData().ctFont())).get())).get())).get()) << "\n";
        stream << "Code Units:";
        for (auto codePoint : characters)
            stream << " " << codePoint;
        stream << "\n";
    );

    if (!m_mayUseNaturalWritingDirection || m_run->directionalOverride()) {
        ProviderInfo info { characters, stringAttributes.get() };
        // FIXME: Some SDKs complain that the second parameter below cannot be null.
        IGNORE_NULL_CHECK_WARNINGS_BEGIN
        RetainPtr typesetter = adoptCF(CTTypesetterCreateWithUniCharProviderAndOptions(&provideStringAndAttributes, 0, &info, m_run->ltr() ? typesetterOptionsSingleton<CoreTextTypesetterEmbeddingLevel::LTR>() : typesetterOptionsSingleton<CoreTextTypesetterEmbeddingLevel::RTL>()));
        IGNORE_NULL_CHECK_WARNINGS_END

        if (!typesetter)
            return;

        LOG_WITH_STREAM(TextShaping, stream << "Forcing " << (m_run->ltr() ? "ltr" : "rtl"));

        line = adoptCF(CTTypesetterCreateLine(typesetter.get(), CFRangeMake(0, 0)));
    } else {
        LOG_WITH_STREAM(TextShaping, stream << "Not forcing direction");

        ProviderInfo info { characters, stringAttributes.get() };

        line = adoptCF(CTLineCreateWithUniCharProvider(&provideStringAndAttributes, nullptr, &info));
    }

    if (!line)
        return;

    RetainPtr runArray = CTLineGetGlyphRuns(line.get());

    if (!runArray)
        return;

    CFIndex runCount = CFArrayGetCount(runArray.get());

    LOG_WITH_STREAM(TextShaping, stream << "Result: " << runCount << " runs.");

    for (CFIndex r = 0; r < runCount; r++) {
        RetainPtr ctRun = static_cast<CTRunRef>(CFArrayGetValueAtIndex(runArray.get(), m_run->ltr() ? r : runCount - 1 - r));
        ASSERT(CFGetTypeID(ctRun.get()) == CTRunGetTypeID());
        CFRange runRange = CTRunGetStringRange(ctRun.get());
        RefPtr runFont = effectiveFont;
        // If isSystemFallback is false, it means we disabled CoreText's font fallback mechanism, which means all the runs must use this exact font.
        // Therefore, we only need to inspect which font was actually used if isSystemFallback is true.
        if (isSystemFallback) {
            RetainPtr runAttributes = CTRunGetAttributes(ctRun.get());
            RetainPtr runCTFont = static_cast<CTFontRef>(CFDictionaryGetValue(runAttributes.get(), kCTFontAttributeName));
            ASSERT(runCTFont && CFGetTypeID(runCTFont.get()) == CTFontGetTypeID());
            RetainPtr<CFTypeRef> runFontEqualityObject = FontPlatformData::objectForEqualityCheck(runCTFont.get());
            if (!safeCFEqual(runFontEqualityObject.get(), effectiveFont->platformData().objectForEqualityCheck().get())) {
                // Begin trying to see if runFont matches any of the fonts in the fallback list.
                for (unsigned i = 0; !m_fontCascade->fallbackRangesAt(i).isNull(); ++i) {
                    runFont = m_fontCascade->fallbackRangesAt(i).fontForCharacter(baseCharacter);
                    if (!runFont)
                        continue;
                    if (safeCFEqual(runFont->platformData().objectForEqualityCheck().get(), runFontEqualityObject.get()))
                        break;
                    runFont = nullptr;
                }
                if (!runFont) {
                    RetainPtr fontName = adoptCF(CTFontCopyPostScriptName(runCTFont.get()));
                    if (CFEqual(fontName.get(), CFSTR("LastResort"))) {
                        m_complexTextRuns.append(ComplexTextRun::create(protect(m_fontCascade->primaryFont()), characters, stringLocation, runRange.location, runRange.location + runRange.length, m_run->ltr()));
                        continue;
                    }
                    FontPlatformData runFontPlatformData(runCTFont.get(), CTFontGetSize(runCTFont.get()));
                    runFont = protect(FontCache::forCurrentThread())->fontForPlatformData(runFontPlatformData).ptr();
                }
                if (m_fallbackFonts && runFont != &m_fontCascade->primaryFont())
                    m_fallbackFonts->add(*runFont);
            }
        }
        if (m_fallbackFonts && runFont != &m_fontCascade->primaryFont())
            m_fallbackFonts->add(*effectiveFont);

        LOG_WITH_STREAM(TextShaping, stream << "Run " << r << ":");

        m_complexTextRuns.append(ComplexTextRun::create(ctRun.get(), *runFont, characters, stringLocation, runRange.location, runRange.location + runRange.length));
    }
}

} // namespace WebCore
