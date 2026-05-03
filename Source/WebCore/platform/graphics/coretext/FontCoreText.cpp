/*
 * Copyright (C) 2005-2025 Apple Inc. All rights reserved.
 * Copyright (C) 2006 Alexey Proskuryakov
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
#include "Font.h"

#if PLATFORM(DRIFTSTACK)
#include "../cocoa/DriftstackAsciiAdvanceTable.h"
#include "../cocoa/DriftstackEmojiAtlas.h"
#include "DriftstackKerningTable.h"
#include <unordered_map>
#include <unordered_set>
#include <wtf/Lock.h>
#include <wtf/NeverDestroyed.h>
#include <wtf/text/AtomString.h>
namespace WebCore::Driftstack {
extern thread_local const char* g_currentPrimaryFamilyCStr;
}
#endif

#include "Color.h"
#include "DoublePoint.h"
#include "FloatRect.h"
#include "FontCache.h"
#include "FontCascade.h"
#include "FontCustomPlatformData.h"
#include "FontDescription.h"
#include "LocaleCocoa.h"
#include "Logging.h"
#include "OpenTypeCG.h"
#include "PathCG.h"
#include "SharedBuffer.h"
#include <CoreText/CoreText.h>
#include <float.h>
#include <pal/cf/CoreTextSoftLink.h>
#include <pal/spi/cf/CoreTextSPI.h>
#include <pal/spi/cg/CoreGraphicsSPI.h>
#include <unicode/uchar.h>
#include <wtf/Assertions.h>
#include <wtf/HexNumber.h>
#include <wtf/MathExtras.h>
#include <wtf/RetainPtr.h>
#include <wtf/StdLibExtras.h>
#include <wtf/cf/VectorCF.h>

#if ENABLE(MULTI_REPRESENTATION_HEIC)
#include "MultiRepresentationHEICMetrics.h"
#endif

#include <pal/cf/CoreTextSoftLink.h>

namespace WebCore {

static inline bool caseInsensitiveCompare(CFStringRef a, CFStringRef b)
{
    return a && CFStringCompare(a, b, kCFCompareCaseInsensitive) == kCFCompareEqualTo;
}

static bool fontHasVerticalGlyphs(CTFontRef font)
{
    return fontHasEitherTable(font, kCTFontTableVhea, kCTFontTableVORG);
}

#if PLATFORM(IOS_FAMILY) || PLATFORM(DRIFTSTACK)
bool fontFamilyShouldNotBeUsedForArabic(CFStringRef fontFamilyName)
{
    if (!fontFamilyName)
        return false;

    // Times New Roman and Arial are not performant enough to use. <rdar://problem/21333326>
    // FIXME <rdar://problem/12096835> remove this function once the above bug is fixed.
    return (CFStringCompare(CFSTR("Times New Roman"), fontFamilyName, 0) == kCFCompareEqualTo)
        || (CFStringCompare(CFSTR("Arial"), fontFamilyName, 0) == kCFCompareEqualTo);
}

static const float kLineHeightAdjustment = 0.15f;

static bool shouldUseAdjustment(CTFontRef font)
{
    RetainPtr<CFStringRef> familyName = adoptCF(CTFontCopyFamilyName(font));

    if (!familyName || !CFStringGetLength(familyName.get()))
        return false;

    return caseInsensitiveCompare(familyName.get(), CFSTR("Times"))
        || caseInsensitiveCompare(familyName.get(), CFSTR("Helvetica"))
        || caseInsensitiveCompare(familyName.get(), CFSTR(".Helvetica NeueUI"));
}

#else

static bool needsAscentAdjustment(CFStringRef familyName)
{
    return familyName && (caseInsensitiveCompare(familyName, CFSTR("Times"))
        || caseInsensitiveCompare(familyName, CFSTR("Helvetica"))
        || caseInsensitiveCompare(familyName, CFSTR("Courier")));
}

#endif

static bool isAhemFont(CFStringRef familyName)
{
    return familyName && caseInsensitiveCompare(familyName, CFSTR("Ahem"));
}

bool fontHasEitherTable(CTFontRef ctFont, unsigned tableTag1, unsigned tableTag2)
{
    return CTFontHasTable(ctFont, tableTag1) || CTFontHasTable(ctFont, tableTag2);
}

void Font::platformInit()
{
    auto constexpr syntheticBoldScaleFactor = 36.0f;
    m_syntheticBoldOffset = m_platformData.syntheticBold() ? (m_platformData.size() / syntheticBoldScaleFactor) : 0.f;

    RetainPtr ctFont = this->ctFont();
    unsigned unitsPerEm = CTFontGetUnitsPerEm(ctFont.get());
    float pointSize = m_platformData.size();
    CGFloat capHeight = pointSize ? CTFontGetCapHeight(ctFont.get()) : 0;
    CGFloat lineGap = pointSize ? CTFontGetLeading(ctFont.get()) : 0;
    CGFloat ascent = pointSize ? CTFontGetAscent(ctFont.get()) : 0;
    CGFloat descent = pointSize ? CTFontGetDescent(ctFont.get()) : 0;

    // The Open Font Format describes the OS/2 USE_TYPO_METRICS flag as follows:
    // "If set, it is strongly recommended to use OS/2.sTypoAscender - OS/2.sTypoDescender+ OS/2.sTypoLineGap as a value for default line spacing for this font."
    // On macOS, we only apply this rule in the important case of fonts with a MATH table.
    if (CTFontHasTable(ctFont.get(), kCTFontTableMATH)) {
        short typoAscent, typoDescent, typoLineGap;
        if (OpenType::tryGetTypoMetrics(ctFont.get(), typoAscent, typoDescent, typoLineGap)) {
            ascent = scaleEmToUnits(typoAscent, unitsPerEm) * pointSize;
            descent = -scaleEmToUnits(typoDescent, unitsPerEm) * pointSize;
            lineGap = scaleEmToUnits(typoLineGap, unitsPerEm) * pointSize;
        }
    }

    auto familyName = adoptCF(CTFontCopyFamilyName(ctFont.get()));

    // Disable antialiasing when rendering with Ahem because many tests require this.
    if (isAhemFont(familyName.get()))
        m_allowsAntialiasing = false;

#if PLATFORM(MAC) && !PLATFORM(DRIFTSTACK)
    // We need to adjust Times, Helvetica, and Courier to closely match the
    // vertical metrics of their Microsoft counterparts that are the de facto
    // web standard. The AppKit adjustment of 20% is too big and is
    // incorrectly added to line spacing, so we use a 15% adjustment instead
    // and add it to the ascent.
    if (origin() == Origin::Local && needsAscentAdjustment(familyName.get()))
        ascent += std::round((ascent + descent) * 0.15f);
#endif

    if (isAhemFont(familyName.get())) {
        auto tolerance = [&] (auto a, auto b) {
            auto toleranceInPixel = 0.01f;
            return toleranceInPixel / std::max(std::abs(a), std::abs(b)) * 100.f;
        };
        auto roundedAscent = std::round(ascent);
        if (WTF::areEssentiallyEqual(ascent, roundedAscent, tolerance(ascent, roundedAscent))) {
            ascent = roundedAscent;
            descent = std::round(descent);
        }
    }

    // Compute line spacing before the line metrics hacks are applied.
#if !PLATFORM(IOS_FAMILY) && !PLATFORM(DRIFTSTACK)
    float lineSpacing = std::lround(ascent) + std::lround(descent) + std::lround(lineGap);
#endif

#if PLATFORM(MAC) && !PLATFORM(DRIFTSTACK)
    // Hack Hiragino line metrics to allow room for marked text underlines.
    // <rdar://problem/5386183>
    if (descent < 3 && lineGap >= 3 && familyName && CFStringHasPrefix(familyName.get(), CFSTR("Hiragino"))) {
        lineGap -= 3 - descent;
        descent = 3;
    }
#endif

    if (platformData().orientation() == FontOrientation::Vertical && !isTextOrientationFallback())
        m_hasVerticalGlyphs = fontHasVerticalGlyphs(ctFont.get());

#if PLATFORM(IOS_FAMILY) || PLATFORM(DRIFTSTACK)
    CGFloat adjustment = shouldUseAdjustment(ctFont.get()) ? ceil((ascent + descent) * kLineHeightAdjustment) : 0;

    lineGap = ceilf(lineGap);
    float lineSpacing = std::ceil(ascent) + adjustment + std::ceil(descent) + lineGap;
    ascent = ceilf(ascent + adjustment);
    descent = ceilf(descent);

#if PLATFORM(DRIFTSTACK)
    // V-081 Stage D-2 Track 1: iPhone reports a different per-size
    // fontBoundingBox{Ascent,Descent} for Apple Color Emoji than Mac's
    // CoreText returns from the same iOS font binary. Captured per-size
    // empirically (Stage D-3 Set A, sizes [8..96]). Override here so
    // m_fontMetrics.intAscent() / .intDescent() (which feed
    // fontBoundingBox* in TextMetrics) match iPhone exactly.
    if (CTFontGetSymbolicTraits(ctFont.get()) & kCTFontTraitColorGlyphs) {
        struct DriftstackEmojiFontMetricsEntry { float size; float ascent; float descent; };
        static constexpr std::array<DriftstackEmojiFontMetricsEntry, 89> driftstackEmojiFontMetricsTable = {{
            {  8.f, 10.f,  4.f }, {  9.f, 12.f,  4.f }, { 10.f, 13.f,  4.f }, { 11.f, 14.f,  5.f },
            { 12.f, 15.f,  5.f }, { 13.f, 17.f,  6.f }, { 14.f, 18.f,  6.f }, { 15.f, 19.f,  6.f },
            { 16.f, 20.f,  7.f }, { 17.f, 21.f,  7.f }, { 18.f, 21.f,  7.f }, { 19.f, 22.f,  7.f },
            { 20.f, 22.f,  7.f }, { 21.f, 23.f,  8.f }, { 22.f, 23.f,  8.f }, { 23.f, 24.f,  8.f },
            { 24.f, 25.f,  8.f }, { 25.f, 26.f,  8.f }, { 26.f, 27.f,  9.f }, { 27.f, 28.f,  9.f },
            { 28.f, 29.f,  9.f }, { 29.f, 30.f, 10.f }, { 30.f, 31.f, 10.f }, { 31.f, 32.f, 10.f },
            { 32.f, 33.f, 11.f }, { 33.f, 34.f, 11.f }, { 34.f, 35.f, 11.f }, { 35.f, 36.f, 11.f },
            { 36.f, 37.f, 12.f }, { 37.f, 38.f, 12.f }, { 38.f, 39.f, 12.f }, { 39.f, 40.f, 13.f },
            { 40.f, 41.f, 13.f }, { 41.f, 42.f, 13.f }, { 42.f, 43.f, 14.f }, { 43.f, 44.f, 14.f },
            { 44.f, 45.f, 14.f }, { 45.f, 46.f, 15.f }, { 46.f, 47.f, 15.f }, { 47.f, 48.f, 15.f },
            { 48.f, 49.f, 16.f }, { 49.f, 50.f, 16.f }, { 50.f, 51.f, 16.f }, { 51.f, 52.f, 16.f },
            { 52.f, 53.f, 17.f }, { 53.f, 54.f, 17.f }, { 54.f, 55.f, 17.f }, { 55.f, 56.f, 18.f },
            { 56.f, 57.f, 18.f }, { 57.f, 58.f, 18.f }, { 58.f, 59.f, 19.f }, { 59.f, 60.f, 19.f },
            { 60.f, 61.f, 19.f }, { 61.f, 62.f, 20.f }, { 62.f, 63.f, 20.f }, { 63.f, 64.f, 20.f },
            { 64.f, 65.f, 21.f }, { 65.f, 66.f, 21.f }, { 66.f, 67.f, 21.f }, { 67.f, 68.f, 21.f },
            { 68.f, 69.f, 22.f }, { 69.f, 70.f, 22.f }, { 70.f, 71.f, 22.f }, { 71.f, 72.f, 23.f },
            { 72.f, 73.f, 23.f }, { 73.f, 74.f, 23.f }, { 74.f, 75.f, 24.f }, { 75.f, 76.f, 24.f },
            { 76.f, 77.f, 24.f }, { 77.f, 78.f, 25.f }, { 78.f, 79.f, 25.f }, { 79.f, 80.f, 25.f },
            { 80.f, 81.f, 26.f }, { 81.f, 82.f, 26.f }, { 82.f, 83.f, 26.f }, { 83.f, 84.f, 26.f },
            { 84.f, 85.f, 27.f }, { 85.f, 86.f, 27.f }, { 86.f, 87.f, 27.f }, { 87.f, 88.f, 28.f },
            { 88.f, 89.f, 28.f }, { 89.f, 90.f, 28.f }, { 90.f, 91.f, 29.f }, { 91.f, 92.f, 29.f },
            { 92.f, 93.f, 29.f }, { 93.f, 94.f, 30.f }, { 94.f, 95.f, 30.f }, { 95.f, 96.f, 30.f },
            { 96.f, 97.f, 31.f }
        }};
        const float emojiSize = m_platformData.size();
        if (emojiSize <= driftstackEmojiFontMetricsTable.front().size) {
            ascent = driftstackEmojiFontMetricsTable.front().ascent;
            descent = driftstackEmojiFontMetricsTable.front().descent;
        } else if (emojiSize >= driftstackEmojiFontMetricsTable.back().size) {
            ascent = driftstackEmojiFontMetricsTable.back().ascent;
            descent = driftstackEmojiFontMetricsTable.back().descent;
        } else {
            DriftstackEmojiFontMetricsEntry a = driftstackEmojiFontMetricsTable.front();
            for (const auto& b : driftstackEmojiFontMetricsTable) {
                if (emojiSize >= a.size && emojiSize <= b.size && a.size != b.size) {
                    float t = (emojiSize - a.size) / (b.size - a.size);
                    ascent  = a.ascent  + t * (b.ascent  - a.ascent);
                    descent = a.descent + t * (b.descent - a.descent);
                    break;
                }
                a = b;
            }
        }
    }

    // V-083 Track 3: per-size fontBoundingBox{Ascent,Descent} overrides
    // for non-emoji fonts where Mac CoreText returns metrics that diverge
    // from iPhone's. Captured per-size via Track 3 BS Automate run
    // (track3-non-emoji-fonts.html), 6 fonts × 89 sizes = 534 reference
    // probes. Of the 6 fonts, 3 (Gujarati Sangam MN / Oriya Sangam MN /
    // Plantagenet Cherokee) share identical metrics → one shared table.
    {
        struct DriftstackTrack3Entry { float size; float ascent; float descent; };
        static constexpr std::array<DriftstackTrack3Entry, 89> track3TimesTable = {{
            {   8.f,   8.f,   2.f }, {   9.f,   9.f,   2.f }, {  10.f,   9.f,   3.f }, {  11.f,  10.f,   3.f },
            {  12.f,  11.f,   3.f }, {  13.f,  12.f,   3.f }, {  14.f,  13.f,   4.f }, {  15.f,  14.f,   4.f },
            {  16.f,  15.f,   4.f }, {  17.f,  16.f,   4.f }, {  18.f,  17.f,   4.f }, {  19.f,  17.f,   5.f },
            {  20.f,  18.f,   5.f }, {  21.f,  19.f,   5.f }, {  22.f,  20.f,   5.f }, {  23.f,  21.f,   5.f },
            {  24.f,  22.f,   6.f }, {  25.f,  23.f,   6.f }, {  26.f,  24.f,   6.f }, {  27.f,  25.f,   6.f },
            {  28.f,  25.f,   7.f }, {  29.f,  26.f,   7.f }, {  30.f,  27.f,   7.f }, {  31.f,  28.f,   7.f },
            {  32.f,  29.f,   7.f }, {  33.f,  30.f,   8.f }, {  34.f,  31.f,   8.f }, {  35.f,  32.f,   8.f },
            {  36.f,  33.f,   8.f }, {  37.f,  33.f,   9.f }, {  38.f,  34.f,   9.f }, {  39.f,  35.f,   9.f },
            {  40.f,  36.f,   9.f }, {  41.f,  37.f,   9.f }, {  42.f,  38.f,  10.f }, {  43.f,  39.f,  10.f },
            {  44.f,  40.f,  10.f }, {  45.f,  41.f,  10.f }, {  46.f,  41.f,  10.f }, {  47.f,  42.f,  11.f },
            {  48.f,  43.f,  11.f }, {  49.f,  44.f,  11.f }, {  50.f,  45.f,  11.f }, {  51.f,  46.f,  12.f },
            {  52.f,  47.f,  12.f }, {  53.f,  48.f,  12.f }, {  54.f,  49.f,  12.f }, {  55.f,  50.f,  12.f },
            {  56.f,  50.f,  13.f }, {  57.f,  51.f,  13.f }, {  58.f,  52.f,  13.f }, {  59.f,  53.f,  13.f },
            {  60.f,  54.f,  13.f }, {  61.f,  55.f,  14.f }, {  62.f,  56.f,  14.f }, {  63.f,  57.f,  14.f },
            {  64.f,  58.f,  14.f }, {  65.f,  58.f,  15.f }, {  66.f,  59.f,  15.f }, {  67.f,  60.f,  15.f },
            {  68.f,  61.f,  15.f }, {  69.f,  62.f,  15.f }, {  70.f,  63.f,  16.f }, {  71.f,  64.f,  16.f },
            {  72.f,  65.f,  16.f }, {  73.f,  66.f,  16.f }, {  74.f,  66.f,  17.f }, {  75.f,  67.f,  17.f },
            {  76.f,  68.f,  17.f }, {  77.f,  69.f,  17.f }, {  78.f,  70.f,  17.f }, {  79.f,  71.f,  18.f },
            {  80.f,  72.f,  18.f }, {  81.f,  73.f,  18.f }, {  82.f,  74.f,  18.f }, {  83.f,  74.f,  18.f },
            {  84.f,  75.f,  19.f }, {  85.f,  76.f,  19.f }, {  86.f,  77.f,  19.f }, {  87.f,  78.f,  19.f },
            {  88.f,  79.f,  20.f }, {  89.f,  80.f,  20.f }, {  90.f,  81.f,  20.f }, {  91.f,  82.f,  20.f },
            {  92.f,  82.f,  20.f }, {  93.f,  83.f,  21.f }, {  94.f,  84.f,  21.f }, {  95.f,  85.f,  21.f },
            {  96.f,  86.f,  21.f }
        }};
        static constexpr std::array<DriftstackTrack3Entry, 89> track3AppleSystemTable = {{
            {   8.f,   8.f,   2.f }, {   9.f,   9.f,   3.f }, {  10.f,  10.f,   3.f }, {  11.f,  11.f,   3.f },
            {  12.f,  12.f,   3.f }, {  13.f,  13.f,   4.f }, {  14.f,  14.f,   4.f }, {  15.f,  15.f,   4.f },
            {  16.f,  16.f,   4.f }, {  17.f,  17.f,   5.f }, {  18.f,  18.f,   5.f }, {  19.f,  19.f,   5.f },
            {  20.f,  20.f,   5.f }, {  21.f,  20.f,   6.f }, {  22.f,  21.f,   6.f }, {  23.f,  22.f,   6.f },
            {  24.f,  23.f,   6.f }, {  25.f,  24.f,   7.f }, {  26.f,  25.f,   7.f }, {  27.f,  26.f,   7.f },
            {  28.f,  27.f,   7.f }, {  29.f,  28.f,   7.f }, {  30.f,  29.f,   8.f }, {  31.f,  30.f,   8.f },
            {  32.f,  31.f,   8.f }, {  33.f,  32.f,   8.f }, {  34.f,  33.f,   9.f }, {  35.f,  34.f,   9.f },
            {  36.f,  35.f,   9.f }, {  37.f,  36.f,   9.f }, {  38.f,  37.f,  10.f }, {  39.f,  38.f,  10.f },
            {  40.f,  39.f,  10.f }, {  41.f,  40.f,  10.f }, {  42.f,  40.f,  11.f }, {  43.f,  41.f,  11.f },
            {  44.f,  42.f,  11.f }, {  45.f,  43.f,  11.f }, {  46.f,  44.f,  12.f }, {  47.f,  45.f,  12.f },
            {  48.f,  46.f,  12.f }, {  49.f,  47.f,  12.f }, {  50.f,  48.f,  13.f }, {  51.f,  49.f,  13.f },
            {  52.f,  50.f,  13.f }, {  53.f,  51.f,  13.f }, {  54.f,  52.f,  14.f }, {  55.f,  53.f,  14.f },
            {  56.f,  54.f,  14.f }, {  57.f,  55.f,  14.f }, {  58.f,  56.f,  14.f }, {  59.f,  57.f,  15.f },
            {  60.f,  58.f,  15.f }, {  61.f,  59.f,  15.f }, {  62.f,  60.f,  15.f }, {  63.f,  60.f,  16.f },
            {  64.f,  61.f,  16.f }, {  65.f,  62.f,  16.f }, {  66.f,  63.f,  16.f }, {  67.f,  64.f,  17.f },
            {  68.f,  65.f,  17.f }, {  69.f,  66.f,  17.f }, {  70.f,  67.f,  17.f }, {  71.f,  68.f,  18.f },
            {  72.f,  69.f,  18.f }, {  73.f,  70.f,  18.f }, {  74.f,  71.f,  18.f }, {  75.f,  72.f,  19.f },
            {  76.f,  73.f,  19.f }, {  77.f,  74.f,  19.f }, {  78.f,  75.f,  19.f }, {  79.f,  76.f,  20.f },
            {  80.f,  77.f,  20.f }, {  81.f,  78.f,  20.f }, {  82.f,  79.f,  20.f }, {  83.f,  80.f,  21.f },
            {  84.f,  80.f,  21.f }, {  85.f,  81.f,  21.f }, {  86.f,  82.f,  21.f }, {  87.f,  83.f,  21.f },
            {  88.f,  84.f,  22.f }, {  89.f,  85.f,  22.f }, {  90.f,  86.f,  22.f }, {  91.f,  87.f,  22.f },
            {  92.f,  88.f,  23.f }, {  93.f,  89.f,  23.f }, {  94.f,  90.f,  23.f }, {  95.f,  91.f,  23.f },
            {  96.f,  92.f,  24.f }
        }};
        static constexpr std::array<DriftstackTrack3Entry, 89> track3IndicSharedTable = {{
            {   8.f,   9.f,   2.f }, {   9.f,   9.f,   3.f }, {  10.f,  10.f,   3.f }, {  11.f,  11.f,   3.f },
            {  12.f,  12.f,   3.f }, {  13.f,  13.f,   3.f }, {  14.f,  14.f,   4.f }, {  15.f,  15.f,   4.f },
            {  16.f,  16.f,   4.f }, {  17.f,  17.f,   4.f }, {  18.f,  17.f,   5.f }, {  19.f,  18.f,   5.f },
            {  20.f,  20.f,   5.f }, {  21.f,  21.f,   5.f }, {  22.f,  21.f,   6.f }, {  23.f,  22.f,   6.f },
            {  24.f,  23.f,   6.f }, {  25.f,  24.f,   6.f }, {  26.f,  25.f,   6.f }, {  27.f,  26.f,   7.f },
            {  28.f,  27.f,   7.f }, {  29.f,  28.f,   7.f }, {  30.f,  29.f,   7.f }, {  31.f,  29.f,   8.f },
            {  32.f,  30.f,   8.f }, {  33.f,  31.f,   8.f }, {  34.f,  33.f,   8.f }, {  35.f,  33.f,   9.f },
            {  36.f,  34.f,   9.f }, {  37.f,  35.f,   9.f }, {  38.f,  36.f,   9.f }, {  39.f,  37.f,   9.f },
            {  40.f,  38.f,  10.f }, {  41.f,  39.f,  10.f }, {  42.f,  40.f,  10.f }, {  43.f,  41.f,  10.f },
            {  44.f,  41.f,  11.f }, {  45.f,  42.f,  11.f }, {  46.f,  43.f,  11.f }, {  47.f,  45.f,  11.f },
            {  48.f,  45.f,  12.f }, {  49.f,  46.f,  12.f }, {  50.f,  47.f,  12.f }, {  51.f,  48.f,  12.f },
            {  52.f,  49.f,  12.f }, {  53.f,  49.f,  13.f }, {  54.f,  51.f,  13.f }, {  55.f,  52.f,  13.f },
            {  56.f,  53.f,  13.f }, {  57.f,  53.f,  14.f }, {  58.f,  54.f,  14.f }, {  59.f,  55.f,  14.f },
            {  60.f,  57.f,  14.f }, {  61.f,  57.f,  15.f }, {  62.f,  58.f,  15.f }, {  63.f,  59.f,  15.f },
            {  64.f,  60.f,  15.f }, {  65.f,  61.f,  15.f }, {  66.f,  61.f,  16.f }, {  67.f,  63.f,  16.f },
            {  68.f,  64.f,  16.f }, {  69.f,  65.f,  16.f }, {  70.f,  65.f,  17.f }, {  71.f,  66.f,  17.f },
            {  72.f,  67.f,  17.f }, {  73.f,  68.f,  17.f }, {  74.f,  69.f,  18.f }, {  75.f,  70.f,  18.f },
            {  76.f,  71.f,  18.f }, {  77.f,  72.f,  18.f }, {  78.f,  73.f,  18.f }, {  79.f,  73.f,  19.f },
            {  80.f,  75.f,  19.f }, {  81.f,  76.f,  19.f }, {  82.f,  77.f,  19.f }, {  83.f,  77.f,  20.f },
            {  84.f,  78.f,  20.f }, {  85.f,  79.f,  20.f }, {  86.f,  80.f,  20.f }, {  87.f,  81.f,  21.f },
            {  88.f,  82.f,  21.f }, {  89.f,  83.f,  21.f }, {  90.f,  84.f,  21.f }, {  91.f,  85.f,  21.f },
            {  92.f,  85.f,  22.f }, {  93.f,  86.f,  22.f }, {  94.f,  88.f,  22.f }, {  95.f,  89.f,  22.f },
            {  96.f,  89.f,  23.f }
        }};
        static constexpr std::array<DriftstackTrack3Entry, 89> track3TeluguSangamTable = {{
            {   8.f,   9.f,   3.f }, {   9.f,  10.f,   4.f }, {  10.f,  11.f,   4.f }, {  11.f,  12.f,   4.f },
            {  12.f,  13.f,   5.f }, {  13.f,  14.f,   5.f }, {  14.f,  15.f,   5.f }, {  15.f,  16.f,   6.f },
            {  16.f,  17.f,   6.f }, {  17.f,  18.f,   6.f }, {  18.f,  19.f,   7.f }, {  19.f,  20.f,   7.f },
            {  20.f,  21.f,   7.f }, {  21.f,  23.f,   8.f }, {  22.f,  24.f,   8.f }, {  23.f,  25.f,   9.f },
            {  24.f,  26.f,   9.f }, {  25.f,  27.f,   9.f }, {  26.f,  28.f,  10.f }, {  27.f,  29.f,  10.f },
            {  28.f,  30.f,  10.f }, {  29.f,  31.f,  11.f }, {  30.f,  32.f,  11.f }, {  31.f,  33.f,  11.f },
            {  32.f,  34.f,  12.f }, {  33.f,  35.f,  12.f }, {  34.f,  36.f,  12.f }, {  35.f,  37.f,  13.f },
            {  36.f,  38.f,  13.f }, {  37.f,  39.f,  13.f }, {  38.f,  40.f,  14.f }, {  39.f,  41.f,  14.f },
            {  40.f,  42.f,  14.f }, {  41.f,  44.f,  15.f }, {  42.f,  45.f,  15.f }, {  43.f,  46.f,  16.f },
            {  44.f,  47.f,  16.f }, {  45.f,  48.f,  16.f }, {  46.f,  49.f,  17.f }, {  47.f,  50.f,  17.f },
            {  48.f,  51.f,  17.f }, {  49.f,  52.f,  18.f }, {  50.f,  53.f,  18.f }, {  51.f,  54.f,  18.f },
            {  52.f,  55.f,  19.f }, {  53.f,  56.f,  19.f }, {  54.f,  57.f,  19.f }, {  55.f,  58.f,  20.f },
            {  56.f,  59.f,  20.f }, {  57.f,  60.f,  20.f }, {  58.f,  61.f,  21.f }, {  59.f,  62.f,  21.f },
            {  60.f,  63.f,  21.f }, {  61.f,  65.f,  22.f }, {  62.f,  66.f,  22.f }, {  63.f,  67.f,  23.f },
            {  64.f,  68.f,  23.f }, {  65.f,  69.f,  23.f }, {  66.f,  70.f,  24.f }, {  67.f,  71.f,  24.f },
            {  68.f,  72.f,  24.f }, {  69.f,  73.f,  25.f }, {  70.f,  74.f,  25.f }, {  71.f,  75.f,  25.f },
            {  72.f,  76.f,  26.f }, {  73.f,  77.f,  26.f }, {  74.f,  78.f,  26.f }, {  75.f,  79.f,  27.f },
            {  76.f,  80.f,  27.f }, {  77.f,  81.f,  27.f }, {  78.f,  82.f,  28.f }, {  79.f,  83.f,  28.f },
            {  80.f,  84.f,  28.f }, {  81.f,  86.f,  29.f }, {  82.f,  87.f,  29.f }, {  83.f,  88.f,  30.f },
            {  84.f,  89.f,  30.f }, {  85.f,  90.f,  30.f }, {  86.f,  91.f,  31.f }, {  87.f,  92.f,  31.f },
            {  88.f,  93.f,  31.f }, {  89.f,  94.f,  32.f }, {  90.f,  95.f,  32.f }, {  91.f,  96.f,  32.f },
            {  92.f,  97.f,  33.f }, {  93.f,  98.f,  33.f }, {  94.f,  99.f,  33.f }, {  95.f, 100.f,  34.f },
            {  96.f, 101.f,  34.f }
        }};

        // Match family by lowercased name. The 6 fonts collapse into 4
        // tables (Gujarati/Oriya/Plantagenet share the indic table).
        const std::span<const DriftstackTrack3Entry> matchedTable = [&]() -> std::span<const DriftstackTrack3Entry> {
            if (!familyName)
                return { };
            String fn = String(familyName.get()).convertToASCIILowercase();
            if (fn == "times"_s)
                return std::span<const DriftstackTrack3Entry>(track3TimesTable);
            if (fn == ".applesystemuifont"_s || fn == "applesystemuifont"_s || fn == "-apple-system"_s)
                return std::span<const DriftstackTrack3Entry>(track3AppleSystemTable);
            if (fn == "gujarati sangam mn"_s || fn == "oriya sangam mn"_s || fn == "plantagenet cherokee"_s)
                return std::span<const DriftstackTrack3Entry>(track3IndicSharedTable);
            if (fn == "telugu sangam mn"_s)
                return std::span<const DriftstackTrack3Entry>(track3TeluguSangamTable);
            return { };
        }();

        if (!matchedTable.empty()) {
            const float track3Size = m_platformData.size();
            if (track3Size <= matchedTable.front().size) {
                ascent = matchedTable.front().ascent;
                descent = matchedTable.front().descent;
            } else if (track3Size >= matchedTable.back().size) {
                ascent = matchedTable.back().ascent;
                descent = matchedTable.back().descent;
            } else {
                DriftstackTrack3Entry a = matchedTable.front();
                for (const auto& b : matchedTable) {
                    if (track3Size >= a.size && track3Size <= b.size && a.size != b.size) {
                        float t = (track3Size - a.size) / (b.size - a.size);
                        ascent  = a.ascent  + t * (b.ascent  - a.ascent);
                        descent = a.descent + t * (b.descent - a.descent);
                        break;
                    }
                    a = b;
                }
            }
        }
    }
#endif

    m_shouldNotBeUsedForArabic = fontFamilyShouldNotBeUsedForArabic(familyName.get());
#endif

    CGFloat xHeight = 0;
    if (m_platformData.size()) {
        if (platformData().orientation() == FontOrientation::Horizontal) {
            // Measure the actual character "x", since it's possible for it to extend below the baseline, and we need the
            // reported x-height to only include the portion of the glyph that is above the baseline.
            Glyph xGlyph = glyphForCharacter('x');
            if (xGlyph)
                xHeight = -CGRectGetMinY(platformBoundsForGlyph(xGlyph));
            else
                xHeight = CTFontGetXHeight(ctFont.get());
        } else
            xHeight = verticalRightOrientationFont().fontMetrics().xHeight().value_or(0);
    }

    if (CTFontGetSymbolicTraits(ctFont.get()) & kCTFontTraitColorGlyphs) {
        if (RetainPtr cfBitVector = adoptCF(CTFontCopyColorGlyphCoverage(ctFont.get())))
            m_emojiType = SomeEmojiGlyphs { BitVector(cfBitVector.get()) };
        else
            m_emojiType = NoEmojiGlyphs { };
    } else
        m_emojiType = NoEmojiGlyphs { };

    m_fontMetrics.setUnitsPerEm(unitsPerEm);
    m_fontMetrics.setAscent(ascent);
    m_fontMetrics.setDescent(descent);
    m_fontMetrics.setCapHeight(capHeight);
    m_fontMetrics.setLineGap(lineGap);
    m_fontMetrics.setXHeight(xHeight);
    m_fontMetrics.setLineSpacing(lineSpacing);
    m_fontMetrics.setUnderlinePosition(-CTFontGetUnderlinePosition(ctFont.get()));
    m_fontMetrics.setUnderlineThickness(CTFontGetUnderlineThickness(ctFont.get()));
}

void Font::platformCharWidthInit()
{
    m_avgCharWidth = 0;
    m_maxCharWidth = 0;

    RetainPtr ctFont = this->ctFont();
    auto os2Table = adoptCF(CTFontCopyTable(ctFont.get(), kCTFontTableOS2, kCTFontTableOptionNoOptions));
    if (os2Table && CFDataGetLength(os2Table.get()) >= 4) {
        auto os2 = span(os2Table.get());
        SInt16 os2AvgCharWidth = os2[2] * 256 + os2[3];
        m_avgCharWidth = scaleEmToUnits(os2AvgCharWidth, m_fontMetrics.unitsPerEm()) * m_platformData.size();
    }

    auto headTable = adoptCF(CTFontCopyTable(ctFont.get(), kCTFontTableHead, kCTFontTableOptionNoOptions));
    if (headTable && CFDataGetLength(headTable.get()) >= 42) {
        auto head = span(headTable.get());
        unsigned uxMin = head[36] * 256 + head[37];
        unsigned uxMax = head[40] * 256 + head[41];
        SInt16 xMin = static_cast<SInt16>(uxMin);
        SInt16 xMax = static_cast<SInt16>(uxMax);
        float diff = static_cast<float>(xMax - xMin);
        m_maxCharWidth = scaleEmToUnits(diff, m_fontMetrics.unitsPerEm()) * m_platformData.size();
    }

    // Fallback to a cross-platform estimate, which will populate these values if they are non-positive.
    initCharWidths();
}

bool Font::variantCapsSupportedForSynthesis(FontVariantCaps fontVariantCaps) const
{
    switch (fontVariantCaps) {
    case FontVariantCaps::Small:
        return supportsSmallCaps();
    case FontVariantCaps::Petite:
        return supportsPetiteCaps();
    case FontVariantCaps::AllSmall:
        return supportsAllSmallCaps();
    case FontVariantCaps::AllPetite:
        return supportsAllPetiteCaps();
    default:
        // Synthesis only supports the variant-caps values listed above.
        return true;
    }
}

static RetainPtr<CFDictionaryRef> smallCapsOpenTypeDictionary(CFStringRef key, int rawValue)
{
    RetainPtr<CFNumberRef> value = adoptCF(CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &rawValue));
    CFTypeRef keys[] = { kCTFontOpenTypeFeatureTag, kCTFontOpenTypeFeatureValue };
    CFTypeRef values[] = { key, value.get() };
    return adoptCF(CFDictionaryCreate(kCFAllocatorDefault, keys, values, std::size(keys), &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks));
}

static RetainPtr<CFDictionaryRef> smallCapsTrueTypeDictionary(int rawKey, int rawValue)
{
    RetainPtr<CFNumberRef> key = adoptCF(CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &rawKey));
    RetainPtr<CFNumberRef> value = adoptCF(CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &rawValue));
    CFTypeRef keys[] = { kCTFontFeatureTypeIdentifierKey, kCTFontFeatureSelectorIdentifierKey };
    CFTypeRef values[] = { key.get(), value.get() };
    return adoptCF(CFDictionaryCreate(kCFAllocatorDefault, keys, values, std::size(keys), &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks));
}

static void unionBitVectors(BitVector& result, CFBitVectorRef source)
{
    CFIndex length = CFBitVectorGetCount(source);
    result.ensureSize(length);
    CFIndex min = 0;
    while (min < length) {
        CFIndex nextIndex = CFBitVectorGetFirstIndexOfBit(source, CFRangeMake(min, length - min), 1);
        if (nextIndex == kCFNotFound)
            break;
        result.set(nextIndex, true);
        min = nextIndex + 1;
    }
}

static void injectOpenTypeCoverage(CFStringRef feature, CTFontRef font, BitVector& result)
{
    RetainPtr<CFBitVectorRef> source = adoptCF(CTFontCopyGlyphCoverageForFeature(font, smallCapsOpenTypeDictionary(feature, 1).get()));
    unionBitVectors(result, source.get());
}

static void injectTrueTypeCoverage(int type, int selector, CTFontRef font, BitVector& result)
{
    RetainPtr<CFBitVectorRef> source = adoptCF(CTFontCopyGlyphCoverageForFeature(font, smallCapsTrueTypeDictionary(type, selector).get()));
    unionBitVectors(result, source.get());
}

bool Font::supportsOpenTypeAlternateHalfWidths() const
{
    if (m_supportsOpenTypeAlternateHalfWidths == SupportsFeature::Unknown)
        m_supportsOpenTypeAlternateHalfWidths = supportsOpenTypeFeature(protect(ctFont()).get(), CFSTR("halt")) ? SupportsFeature::Yes : SupportsFeature::No;
    return m_supportsOpenTypeAlternateHalfWidths == SupportsFeature::Yes;
}

bool Font::supportsSmallCaps() const
{
    if (m_supportsSmallCaps == SupportsFeature::Unknown) {
        BitVector glyphsSupportedBySmallCaps;
        RetainPtr ctFont = this->ctFont();
        injectOpenTypeCoverage(CFSTR("smcp"), ctFont.get(), glyphsSupportedBySmallCaps);
        injectTrueTypeCoverage(kLowerCaseType, kLowerCaseSmallCapsSelector, ctFont.get(), glyphsSupportedBySmallCaps);
        m_supportsSmallCaps = glyphsSupportedBySmallCaps.isEmpty() ? SupportsFeature::No : SupportsFeature::Yes;
    }
    return m_supportsSmallCaps == SupportsFeature::Yes;
}

bool Font::supportsAllSmallCaps() const
{
    if (m_supportsAllSmallCaps == SupportsFeature::Unknown) {
        BitVector glyphsSupportedByAllSmallCaps;
        RetainPtr ctFont = this->ctFont();
        injectOpenTypeCoverage(CFSTR("smcp"), ctFont.get(), glyphsSupportedByAllSmallCaps);
        injectOpenTypeCoverage(CFSTR("c2sc"), ctFont.get(), glyphsSupportedByAllSmallCaps);
        injectTrueTypeCoverage(kLowerCaseType, kLowerCaseSmallCapsSelector, ctFont.get(), glyphsSupportedByAllSmallCaps);
        injectTrueTypeCoverage(kUpperCaseType, kUpperCaseSmallCapsSelector, ctFont.get(), glyphsSupportedByAllSmallCaps);
        m_supportsAllSmallCaps = glyphsSupportedByAllSmallCaps.isEmpty() ? SupportsFeature::No : SupportsFeature::Yes;
    }
    return m_supportsAllSmallCaps == SupportsFeature::Yes;
}

bool Font::supportsPetiteCaps() const
{
    if (m_supportsPetiteCaps == SupportsFeature::Unknown) {
        BitVector glyphsSupportedByPetiteCaps;
        RetainPtr ctFont = this->ctFont();
        injectOpenTypeCoverage(CFSTR("pcap"), ctFont.get(), glyphsSupportedByPetiteCaps);
        injectTrueTypeCoverage(kLowerCaseType, kLowerCasePetiteCapsSelector, ctFont.get(), glyphsSupportedByPetiteCaps);
        m_supportsPetiteCaps = glyphsSupportedByPetiteCaps.isEmpty() ? SupportsFeature::No : SupportsFeature::Yes;
    }
    return m_supportsPetiteCaps == SupportsFeature::Yes;
}

bool Font::supportsAllPetiteCaps() const
{
    if (m_supportsAllPetiteCaps == SupportsFeature::Unknown) {
        BitVector glyphsSupportedByAllPetiteCaps;
        RetainPtr ctFont = this->ctFont();
        injectOpenTypeCoverage(CFSTR("pcap"), ctFont.get(), glyphsSupportedByAllPetiteCaps);
        injectOpenTypeCoverage(CFSTR("c2pc"), ctFont.get(), glyphsSupportedByAllPetiteCaps);
        injectTrueTypeCoverage(kLowerCaseType, kLowerCasePetiteCapsSelector, ctFont.get(), glyphsSupportedByAllPetiteCaps);
        injectTrueTypeCoverage(kUpperCaseType, kUpperCasePetiteCapsSelector, ctFont.get(), glyphsSupportedByAllPetiteCaps);
        m_supportsAllPetiteCaps = glyphsSupportedByAllPetiteCaps.isEmpty() ? SupportsFeature::No : SupportsFeature::Yes;
    }
    return m_supportsAllPetiteCaps == SupportsFeature::Yes;
}

static RefPtr<Font> createDerivativeFont(CTFontRef font, float size, FontOrientation orientation, CTFontSymbolicTraits fontTraits, bool syntheticBold, bool syntheticItalic, FontWidthVariant fontWidthVariant, TextRenderingMode textRenderingMode, const FontCustomPlatformData* customPlatformData)
{
    if (!font)
        return nullptr;

    if (syntheticBold)
        fontTraits |= kCTFontBoldTrait;
    if (syntheticItalic)
        fontTraits |= kCTFontItalicTrait;

    CTFontSymbolicTraits scaledFontTraits = CTFontGetSymbolicTraits(font);

    bool usedSyntheticBold = (fontTraits & kCTFontBoldTrait) && !(scaledFontTraits & kCTFontTraitBold);
    bool usedSyntheticOblique = (fontTraits & kCTFontItalicTrait) && !(scaledFontTraits & kCTFontTraitItalic);
    FontPlatformData scaledFontData(font, size, usedSyntheticBold, usedSyntheticOblique, orientation, fontWidthVariant, textRenderingMode, customPlatformData);

    return Font::create(scaledFontData);
}

static inline bool isOpenTypeFeature(CFDictionaryRef feature)
{
    return CFDictionaryContainsKey(feature, kCTFontOpenTypeFeatureTag) && CFDictionaryContainsKey(feature, kCTFontOpenTypeFeatureValue);
}

static inline bool isTrueTypeFeature(CFDictionaryRef feature)
{
    return CFDictionaryContainsKey(feature, kCTFontFeatureTypeIdentifierKey) && CFDictionaryContainsKey(feature, kCTFontFeatureSelectorIdentifierKey);
}

static inline std::optional<CFStringRef> openTypeFeature(CFDictionaryRef feature)
{
    ASSERT(isOpenTypeFeature(feature));
    RetainPtr tag = static_cast<CFStringRef>(CFDictionaryGetValue(feature, kCTFontOpenTypeFeatureTag));
    int rawValue;
    RetainPtr value = static_cast<CFNumberRef>(CFDictionaryGetValue(feature, kCTFontOpenTypeFeatureValue));
    auto success = CFNumberGetValue(value.get(), kCFNumberIntType, &rawValue);
    ASSERT_UNUSED(success, success);
    return rawValue ? std::optional<CFStringRef>(tag.get()) : std::nullopt;
}

static inline std::pair<int, int> trueTypeFeature(CFDictionaryRef feature)
{
    ASSERT(isTrueTypeFeature(feature));
    int rawType;
    RetainPtr type = static_cast<CFNumberRef>(CFDictionaryGetValue(feature, kCTFontFeatureTypeIdentifierKey));
    auto success = CFNumberGetValue(type.get(), kCFNumberIntType, &rawType);
    ASSERT_UNUSED(success, success);
    int rawSelector;
    RetainPtr selector = static_cast<CFNumberRef>(CFDictionaryGetValue(feature, kCTFontFeatureSelectorIdentifierKey));
    success = CFNumberGetValue(selector.get(), kCFNumberIntType, &rawSelector);
    ASSERT_UNUSED(success, success);
    return std::make_pair(rawType, rawSelector);
}

static inline CFNumberRef defaultSelectorForTrueTypeFeature(int key, CTFontRef font)
{
    RetainPtr<CFArrayRef> features = adoptCF(CTFontCopyFeatures(font));
    CFIndex featureCount = CFArrayGetCount(features.get());
    for (CFIndex i = 0; i < featureCount; ++i) {
        RetainPtr featureType = static_cast<CFDictionaryRef>(CFArrayGetValueAtIndex(features.get(), i));
        RetainPtr featureKey = static_cast<CFNumberRef>(CFDictionaryGetValue(featureType.get(), kCTFontFeatureTypeIdentifierKey));
        if (!featureKey)
            continue;
        int rawFeatureKey;
        CFNumberGetValue(featureKey.get(), kCFNumberIntType, &rawFeatureKey);
        if (rawFeatureKey != key)
            continue;

        RetainPtr featureSelectors = static_cast<CFArrayRef>(CFDictionaryGetValue(featureType.get(), kCTFontFeatureTypeSelectorsKey));
        if (!featureSelectors)
            continue;
        CFIndex selectorsCount = CFArrayGetCount(featureSelectors.get());
        for (CFIndex j = 0; j < selectorsCount; ++j) {
            RetainPtr featureSelector = static_cast<CFDictionaryRef>(CFArrayGetValueAtIndex(featureSelectors.get(), j));
            RetainPtr isDefault = static_cast<CFNumberRef>(CFDictionaryGetValue(featureSelector.get(), kCTFontFeatureSelectorDefaultKey));
            if (!isDefault)
                continue;
            int rawIsDefault;
            CFNumberGetValue(isDefault.get(), kCFNumberIntType, &rawIsDefault);
            if (!rawIsDefault)
                continue;
            return static_cast<CFNumberRef>(CFDictionaryGetValue(featureSelector.get(), kCTFontFeatureSelectorIdentifierKey));
        }
    }
    return nullptr;
}

static inline RetainPtr<CFDictionaryRef> removedFeature(CFDictionaryRef feature, CTFontRef font)
{
    bool isOpenType = isOpenTypeFeature(feature);
    bool isTrueType = isTrueTypeFeature(feature);
    if (!isOpenType && !isTrueType)
        return feature; // We don't understand this font format.
    RetainPtr<CFMutableDictionaryRef> result = adoptCF(CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks));
    if (isOpenType) {
        auto featureTag = openTypeFeature(feature);
        if (featureTag && (CFEqual(featureTag.value(), CFSTR("smcp"))
            || CFEqual(featureTag.value(), CFSTR("c2sc"))
            || CFEqual(featureTag.value(), CFSTR("pcap"))
            || CFEqual(featureTag.value(), CFSTR("c2pc")))) {
            int rawZero = 0;
            RetainPtr<CFNumberRef> zero = adoptCF(CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &rawZero));
            CFDictionaryAddValue(result.get(), kCTFontOpenTypeFeatureTag, featureTag.value());
            CFDictionaryAddValue(result.get(), kCTFontOpenTypeFeatureValue, zero.get());
        } else {
            CFDictionaryAddValue(result.get(), kCTFontOpenTypeFeatureTag, CFDictionaryGetValue(feature, kCTFontOpenTypeFeatureTag));
            CFDictionaryAddValue(result.get(), kCTFontOpenTypeFeatureValue, CFDictionaryGetValue(feature, kCTFontOpenTypeFeatureValue));
        }
    }
    if (isTrueType) {
        auto trueTypeFeaturePair = trueTypeFeature(feature);
        if (trueTypeFeaturePair.first == kLowerCaseType && (trueTypeFeaturePair.second == kLowerCaseSmallCapsSelector || trueTypeFeaturePair.second == kLowerCasePetiteCapsSelector)) {
            CFDictionaryAddValue(result.get(), kCTFontFeatureTypeIdentifierKey, CFDictionaryGetValue(feature, kCTFontFeatureTypeIdentifierKey));
            if (RetainPtr defaultSelector = defaultSelectorForTrueTypeFeature(kLowerCaseType, font))
                CFDictionaryAddValue(result.get(), kCTFontFeatureSelectorIdentifierKey, defaultSelector.get());
            else
                CFDictionaryAddValue(result.get(), kCTFontFeatureSelectorIdentifierKey, CFDictionaryGetValue(feature, kCTFontFeatureSelectorIdentifierKey));
        } else if (trueTypeFeaturePair.first == kUpperCaseType && (trueTypeFeaturePair.second == kUpperCaseSmallCapsSelector || trueTypeFeaturePair.second == kUpperCasePetiteCapsSelector)) {
            CFDictionaryAddValue(result.get(), kCTFontFeatureTypeIdentifierKey, CFDictionaryGetValue(feature, kCTFontFeatureTypeIdentifierKey));
            if (RetainPtr defaultSelector = defaultSelectorForTrueTypeFeature(kUpperCaseType, font))
                CFDictionaryAddValue(result.get(), kCTFontFeatureSelectorIdentifierKey, defaultSelector.get());
            else
                CFDictionaryAddValue(result.get(), kCTFontFeatureSelectorIdentifierKey, CFDictionaryGetValue(feature, kCTFontFeatureSelectorIdentifierKey));
        } else {
            CFDictionaryAddValue(result.get(), kCTFontFeatureTypeIdentifierKey, CFDictionaryGetValue(feature, kCTFontFeatureTypeIdentifierKey));
            CFDictionaryAddValue(result.get(), kCTFontFeatureSelectorIdentifierKey, CFDictionaryGetValue(feature, kCTFontFeatureSelectorIdentifierKey));
        }
    }
    return result;
}

static RetainPtr<CTFontRef> createCTFontWithoutSynthesizableFeatures(CTFontRef font)
{
    RetainPtr<CFArrayRef> features = adoptCF(static_cast<CFArrayRef>(CTFontCopyAttribute(font, kCTFontFeatureSettingsAttribute)));
    if (!features)
        return font;
    CFIndex featureCount = CFArrayGetCount(features.get());
    RetainPtr<CFMutableArrayRef> newFeatures = adoptCF(CFArrayCreateMutable(kCFAllocatorDefault, featureCount, &kCFTypeArrayCallBacks));
    for (CFIndex i = 0; i < featureCount; ++i) {
        RetainPtr feature = static_cast<CFDictionaryRef>(CFArrayGetValueAtIndex(features.get(), i));
        CFArrayAppendValue(newFeatures.get(), removedFeature(feature.get(), font).get());
    }
    CFTypeRef keys[] = { kCTFontFeatureSettingsAttribute };
    CFTypeRef values[] = { newFeatures.get() };
    RetainPtr<CFDictionaryRef> attributes = adoptCF(CFDictionaryCreate(kCFAllocatorDefault, keys, values, std::size(keys), &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks));
    RetainPtr<CTFontDescriptorRef> newDescriptor = adoptCF(CTFontDescriptorCreateWithAttributes(attributes.get()));
    return adoptCF(CTFontCreateCopyWithAttributes(font, CTFontGetSize(font), nullptr, newDescriptor.get()));
}

RefPtr<Font> Font::createFontWithoutSynthesizableFeatures() const
{
    float size = m_platformData.size();
    RetainPtr ctFont = this->ctFont();
    CTFontSymbolicTraits fontTraits = CTFontGetSymbolicTraits(ctFont.get());
    RetainPtr newCTFont = createCTFontWithoutSynthesizableFeatures(ctFont.get());
    return createDerivativeFont(newCTFont.get(), size, m_platformData.orientation(), fontTraits, m_platformData.syntheticBold(), m_platformData.syntheticOblique(), m_platformData.widthVariant(), m_platformData.textRenderingMode(), protect(m_platformData.customPlatformData()).get());
}

RefPtr<Font> Font::platformCreateScaledFont(const FontDescription&, float scaleFactor) const
{
    float size = m_platformData.size() * scaleFactor;
    RetainPtr ctFont = this->ctFont();
    CTFontSymbolicTraits fontTraits = CTFontGetSymbolicTraits(ctFont.get());
    RetainPtr<CTFontDescriptorRef> fontDescriptor = adoptCF(CTFontCopyFontDescriptor(ctFont.get()));
    RetainPtr<CTFontRef> scaledFont = adoptCF(CTFontCreateWithFontDescriptor(fontDescriptor.get(), size, nullptr));

    return createDerivativeFont(scaledFont.get(), size, m_platformData.orientation(), fontTraits, m_platformData.syntheticBold(), m_platformData.syntheticOblique(), m_platformData.widthVariant(), m_platformData.textRenderingMode(), protect(m_platformData.customPlatformData()).get());
}

bool supportsOpenTypeFeature(CTFontRef font, CFStringRef featureTag)
{
    RetainPtr<CFArrayRef> features = adoptCF(CTFontCopyFeatures(font));
    CFIndex featureCount = CFArrayGetCount(features.get());
    for (CFIndex featureIndex = 0; featureIndex < featureCount; ++featureIndex) {
        RetainPtr feature = static_cast<CFDictionaryRef>(CFArrayGetValueAtIndex(features.get(), featureIndex));
        RetainPtr featureTypeIdentifier = static_cast<CFNumberRef>(CFDictionaryGetValue(feature.get(), kCTFontFeatureTypeIdentifierKey));
        if (!featureTypeIdentifier)
            continue;

        int rawFeatureTypeIdentifier;
        CFNumberGetValue(featureTypeIdentifier.get(), kCFNumberIntType, &rawFeatureTypeIdentifier);
        if (rawFeatureTypeIdentifier != kTextSpacingType)
            continue;

        RetainPtr featureSelectors = static_cast<CFArrayRef>(CFDictionaryGetValue(feature.get(), kCTFontFeatureTypeSelectorsKey));
        if (!featureSelectors)
            continue;
        auto selectorsCount = CFArrayGetCount(featureSelectors.get());
        for (CFIndex selectorIndex = 0; selectorIndex < selectorsCount; ++selectorIndex) {
            RetainPtr featureSelector = static_cast<CFDictionaryRef>(CFArrayGetValueAtIndex(featureSelectors.get(), selectorIndex));
            RetainPtr openTypeTag = static_cast<CFStringRef>(CFDictionaryGetValue(featureSelector.get(), kCTFontOpenTypeFeatureTag));
            if (!openTypeTag)
                continue;
            if (CFStringCompare(openTypeTag.get(), featureTag, 0) == kCFCompareEqualTo)
                return true;
        }
    }
    return false;
}

RefPtr<Font> Font::platformCreateHalfWidthFont() const
{
    if (!supportsOpenTypeAlternateHalfWidths())
        return nullptr;

    RetainPtr ctFont = this->ctFont();
    RetainPtr<CTFontDescriptorRef> fontDescriptor = adoptCF(CTFontCopyFontDescriptor(ctFont.get()));
    auto size = m_platformData.size();
    auto fontTraits = CTFontGetSymbolicTraits(ctFont.get());
    int enableHaltValue = 1;
    auto featureName = CFSTR("halt");
    auto featureValue = adoptCF(CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &enableHaltValue));

    const void* featureValues[] = { featureName, featureValue.get() };
    auto fontFeatureSettings = adoptCF(CFArrayCreate(kCFAllocatorDefault, featureValues, std::size(featureValues), &kCFTypeArrayCallBacks));

    CFTypeRef fontDescriptorKeys[] = { kCTFontFeatureSettingsAttribute };
    CFTypeRef fontDescriptorValues[] = { fontFeatureSettings.get() };
    auto attributes = adoptCF(CFDictionaryCreate(kCFAllocatorDefault, fontDescriptorKeys, fontDescriptorValues, std::size(fontDescriptorValues), &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks));

    auto attributesDescriptor = adoptCF(CTFontDescriptorCreateWithAttributes(attributes.get()));
    auto halfWidthFont = adoptCF(CTFontCreateCopyWithAttributes(ctFont.get(), size, nullptr, attributesDescriptor.get()));

    return createDerivativeFont(halfWidthFont.get(), size, m_platformData.orientation(), fontTraits, m_platformData.syntheticBold(), m_platformData.syntheticOblique(), m_platformData.widthVariant(), m_platformData.textRenderingMode(), protect(m_platformData.customPlatformData()).get());
}

float Font::platformWidthForGlyph(Glyph glyph) const
{
    CGSize advance = CGSizeZero;

    if (platformData().size()) {
        bool horizontal = platformData().orientation() == FontOrientation::Horizontal;
        CTFontOrientation orientation = horizontal || m_isBrokenIdeographFallback ? kCTFontOrientationHorizontal : kCTFontOrientationVertical;
        CTFontGetAdvancesForGlyphs(protect(ctFont()).get(), orientation, &glyph, &advance, 1);
    }
#if PLATFORM(DRIFTSTACK)
    // V-094 Track 5: iPhone Apple Color Emoji advance is constant per
    // ptSize across all emoji codepoints. Empirical (Track 5 capture
    // 159 probes / 53 codepoints / 3 sizes):
    //   ptSize 14 → advance 19
    //   ptSize 24 → advance 25
    //   ptSize 48 → advance 48
    // Override Mac CTFontGetAdvancesForGlyphs result for color glyphs
    // so canvas.measureText returns iPhone-equivalent widths.
    if (platformData().size() > 0.f && colorGlyphType(glyph) == ColorGlyphType::Color) {
        const float ptSize = platformData().size();
        float iphoneAdvance;
        if (ptSize <= 14.f)
            iphoneAdvance = 19.f * (ptSize / 14.f);
        else if (ptSize >= 48.f)
            iphoneAdvance = ptSize;
        else if (ptSize <= 24.f)
            iphoneAdvance = 19.f + (ptSize - 14.f) * (25.f - 19.f) / (24.f - 14.f);
        else
            iphoneAdvance = 25.f + (ptSize - 24.f) * (48.f - 25.f) / (48.f - 24.f);
        // V-147 / V-143 Option A: when primary font is NOT Apple Color Emoji
        // (i.e., emoji is rendered via fallback), iPhone CT adds +1 px to
        // the natural emoji width. Per stage-f-emoji-advances capture:
        //   "14px Apple Color Emoji" 😃/🍕 = 19 (primary)
        //   "14px -apple-system" 😃/🍕 = 20 (fallback +1)
        //   "14px sans-serif" 😃/🍕 = 19 (fallback +0 — only -apple-system gets +1)
        // So the +1 only applies when primary is -apple-system (or system-ui
        // which resolves to .AppleSystemUIFont same as -apple-system).
        const char* primary = Driftstack::g_currentPrimaryFamilyCStr;
        if (primary && (std::string_view(primary) == "-apple-system" || std::string_view(primary) == "system-ui"))
            iphoneAdvance += 1.f;
        return iphoneAdvance;
    }

    // V-145: Apple Color Emoji has a SPACE glyph (U+0020) at width 19/21/22/23/25
    // for sizes 14/16/18/20/24 (per stage-f-emoji-ascii capture). Mac CT
    // returns ~3.89 (Helvetica fallback width) which causes the cumulative-rig
    // Apple Color Emoji probe 5px diff. Override Apple Color Emoji's space
    // glyph specifically.
    if (platformData().size() > 0.f) {
        const auto& familyName = m_platformData.familyName();
        if (familyName == "Apple Color Emoji"_s || familyName == ".Apple Color Emoji UI"_s) {
            // Determine if this glyph is the space character.
            UniChar ch = 0x20;
            CGGlyph spaceGlyph = 0;
            CTFontGetGlyphsForCharacters(protect(ctFont()).get(), &ch, &spaceGlyph, 1);
            if (spaceGlyph && glyph == spaceGlyph) {
                const uint16_t sizePx = static_cast<uint16_t>(roundf(platformData().size()));
                switch (sizePx) {
                    case 14: return 19.f;
                    case 16: return 21.f;
                    case 18: return 22.f;
                    case 20: return 23.f;
                    case 24: return 25.f;
                    default: break;
                }
            }
        }
    }

    // V-121 closure: per-glyph ASCII advance override at the configured
    // (font, size, codepoint) combinations. iPhone reference data captured
    // via stage-f-ascii-advances probe (1900 entries × 4 fonts × 5 sizes ×
    // 95 codepoints). Mac CT advance differs from iPhone CT advance by ~0.18 px/char
    // for -apple-system + ~0.45 px/char for sans-serif fallback, accumulating
    // to the cumulative-rig measureText.fonts.value.{-apple-system,Apple Color
    // Emoji}.width residuals (V-120/V-121). This override aligns advances to
    // iPhone reference, which closes the residual + helps the canvas-fp t02
    // multi-glyph composition match.
    if (platformData().size() > 0.f) {
        const float ptSize = platformData().size();
        const uint16_t sizePx = static_cast<uint16_t>(roundf(ptSize));
        if (sizePx == 14 || sizePx == 16 || sizePx == 18 || sizePx == 20 || sizePx == 24) {
            // Map resolved family name → atlas-table key. Direct CSS-name
            // matches first (Arial, Helvetica, Times New Roman, Courier,
            // Tahoma, Verdana, Georgia, Trebuchet MS — priority D coverage).
            // Then generic-resolution aliases (Mac per-page-settings defaults
            // for sans-serif/serif/etc. → V-122 multi-key pattern).
            const String& familyName = m_platformData.familyName();
            const char* atlasKey = nullptr;
            if (familyName == "Arial"_s) atlasKey = "Arial";
            else if (familyName == "Tahoma"_s) atlasKey = "Tahoma";
            else if (familyName == "Times New Roman"_s) atlasKey = "Times New Roman";
            else if (familyName == "Courier"_s || familyName == "Courier New"_s) atlasKey = "Courier";
            else if (familyName == "Verdana"_s) atlasKey = "Verdana";
            else if (familyName == "Georgia"_s) atlasKey = "Georgia";
            else if (familyName == "Trebuchet MS"_s) atlasKey = "Trebuchet MS";
            else if (familyName == "Helvetica"_s) atlasKey = "Helvetica";
            else if (familyName == ".AppleSystemUIFont"_s) atlasKey = "-apple-system";
            else if (familyName == "Times"_s || familyName == "Times Roman"_s) atlasKey = "serif";
            // V-144: Mac resolves CSS generic keywords to internal -webkit-*
            // names (per V-138 instrumentation). Add fallbacks.
            else if (familyName == "-webkit-sans-serif"_s) atlasKey = "sans-serif";
            else if (familyName == "-webkit-serif"_s) atlasKey = "serif";
            else if (familyName == "-webkit-system-font"_s) atlasKey = "system-ui";
            // V-145 diagnostic: log every (familyName, atlasKey) resolution.
            WTFLogAlways("[Driftstack-V145] resolve family='%s' → atlasKey='%s' size=%.1f",
                familyName.utf8().data(), atlasKey ? atlasKey : "(null)", ptSize);
            if (atlasKey) {
                // Build glyph→codepoint reverse map for ASCII range on first use.
                if (!m_driftstackAsciiReverseMapBuilt) {
                    RetainPtr font = ctFont();
                    if (font) {
                        for (UChar cp = 0x20; cp <= 0x7E; ++cp) {
                            UniChar ch[1] = { cp };
                            CGGlyph glyphs[1] = { 0 };
                            if (CTFontGetGlyphsForCharacters(font.get(), ch, glyphs, 1) && glyphs[0])
                                m_driftstackAsciiReverseMap.set(glyphs[0], static_cast<char32_t>(cp));
                        }
                    }
                    m_driftstackAsciiReverseMapBuilt = true;
                    WTFLogAlways("[Driftstack-V121] ascii reverse map built for family='%s' atlasKey='%s' size=%.1f entries=%u",
                        familyName.utf8().data(), atlasKey, ptSize, static_cast<unsigned>(m_driftstackAsciiReverseMap.size()));
                }
                auto it = m_driftstackAsciiReverseMap.find(glyph);
                if (it != m_driftstackAsciiReverseMap.end()) {
                    char32_t cp = it->value;
                    // Find atlasKey font_id in kDriftstackAsciiAdvanceFonts.
                    uint16_t fontId = 0xFFFF;
                    for (uint16_t i = 0; i < std::size(kDriftstackAsciiAdvanceFonts); ++i) {
                        if (kDriftstackAsciiAdvanceFonts[i] == atlasKey) {
                            fontId = i;
                            break;
                        }
                    }
                    if (fontId != 0xFFFF) {
                        // Linear scan of the table (sorted by font_id+size+cp).
                        for (const auto& e : kDriftstackAsciiAdvanceTable) {
                            if (e.fontId > fontId)
                                break;
                            if (e.fontId == fontId && e.sizePx == sizePx && e.codepoint == static_cast<uint32_t>(cp)) {
                                // V-145 diagnostic: log all HITs (was capped at 5)
                                WTFLogAlways("[Driftstack-V121] HIT family='%s' resolved='%s' size=%u cp=U+%04X mac=%.4f → ios=%.4f",
                                    atlasKey, familyName.utf8().data(), sizePx, static_cast<uint32_t>(cp), advance.width, e.widthPx);
                                return e.widthPx;
                            }
                        }
                        static unsigned misses = 0;
                        if (++misses <= 5)
                            WTFLogAlways("[Driftstack-V121] MISS family='%s' fontId=%u size=%u cp=U+%04X (table_len=%zu)",
                                atlasKey, fontId, sizePx, static_cast<uint32_t>(cp), kDriftstackAsciiAdvanceTable.size());
                    } else {
                        static unsigned noFontId = 0;
                        if (++noFontId <= 5)
                            WTFLogAlways("[Driftstack-V121] no fontId for atlasKey='%s' (font_table_len=%zu)",
                                atlasKey, kDriftstackAsciiAdvanceFonts.size());
                    }
                }
            }
        }
    }
#endif
    return advance.width;
}

#if PLATFORM(DRIFTSTACK)
// V-090 / Phase F.1.B-1: glyph→codepoint reverse map for the
// DriftstackEmojiAtlas. Built lazily on first access. Iterates the
// atlas's known codepoints, queries CTFont for the glyph each
// resolves to, stores reverse mapping. Cost: ~1426 CTFontGetGlyphsForCharacters
// calls per color-emoji font; one-time at first lookup.
char32_t Font::driftstackCodepointForColorGlyph(Glyph glyph) const
{
    if (!m_driftstackEmojiReverseMapBuilt) {
        const auto& atlas = DriftstackEmojiAtlas::singleton();
        if (!atlas.isAvailable()) {
            m_driftstackEmojiReverseMapBuilt = true;
            return 0;
        }

        RetainPtr<CTFontRef> font = ctFont();
        const auto& codepoints = atlas.codepoints();
        for (uint32_t cp : codepoints) {
            std::array<UniChar, 2> codeUnits {};
            std::array<CGGlyph, 2> glyphs {};
            CFIndex len;
            if (cp > 0xFFFFu) {
                uint32_t scalar = cp - 0x10000u;
                codeUnits[0] = 0xD800u | (scalar >> 10);
                codeUnits[1] = 0xDC00u | (scalar & 0x3FFu);
                len = 2;
            } else {
                codeUnits[0] = static_cast<UniChar>(cp);
                len = 1;
            }
            if (CTFontGetGlyphsForCharacters(font.get(), codeUnits.data(), glyphs.data(), len)) {
                if (glyphs[0])
                    m_driftstackEmojiReverseMap.set(glyphs[0], static_cast<char32_t>(cp));
            }
        }
        m_driftstackEmojiReverseMapBuilt = true;
        WTFLogAlways("[Driftstack] Font::driftstackCodepointForColorGlyph: built reverse map for color-emoji font, %u entries", static_cast<unsigned>(m_driftstackEmojiReverseMap.size()));
    }

    auto it = m_driftstackEmojiReverseMap.find(glyph);
    return it != m_driftstackEmojiReverseMap.end() ? it->value : 0;
}

// V-090 / Phase F.1.B-2: decode atlas PNG bytes into a CGImageRef and
// cache per (codepoint, strikePPEM). Cache key encodes both as
// (codepoint << 32) | strikePPEM. The provider holds a CFData wrapper
// around the mmap'd atlas region; both the data and provider are
// process-lifetime stable since the atlas singleton is NeverDestroyed.
RetainPtr<CGImageRef> Font::driftstackAtlasImageForCodepoint(uint32_t codepoint, uint32_t strikePPEM, std::span<const uint8_t> pngBytes) const
{
    const uint64_t key = (static_cast<uint64_t>(codepoint) << 32) | strikePPEM;
    Locker locker(m_driftstackAtlasImageCacheLock);
    auto it = m_driftstackAtlasImageCache.find(key);
    if (it != m_driftstackAtlasImageCache.end())
        return it->value;
    RetainPtr<CFDataRef> data = adoptCF(CFDataCreate(kCFAllocatorDefault, pngBytes.data(), static_cast<CFIndex>(pngBytes.size())));
    if (!data)
        return { };
    RetainPtr<CGDataProviderRef> provider = adoptCF(CGDataProviderCreateWithCFData(data.get()));
    if (!provider)
        return { };
    RetainPtr<CGImageRef> image = adoptCF(CGImageCreateWithPNGDataProvider(provider.get(), nullptr, false, kCGRenderingIntentDefault));
    if (image)
        m_driftstackAtlasImageCache.add(key, image);
    return image;
}
#endif

#if PLATFORM(DRIFTSTACK)
namespace {

using namespace DriftstackKerning;

static uint16_t resolveKerningFontId(const String& familyName)
{
    auto utf8 = familyName.utf8();
    auto utf8sv = std::string_view(utf8.data(), utf8.length());
    for (size_t i = 0; i < kKerningFonts.size(); ++i) {
        if (utf8sv == kKerningFonts[i])
            return static_cast<uint16_t>(i);
    }
    // V-138 fallback: Mac CT resolves CSS keywords to internal names.
    // Map them back to the analyzer's CSS-keyword ids.
    if (familyName == ".AppleSystemUIFont"_s || familyName == ".SF NS"_s) {
        for (size_t i = 0; i < kKerningFonts.size(); ++i)
            if (std::string_view(kKerningFonts[i]) == "-apple-system")
                return static_cast<uint16_t>(i);
    }
    if (familyName == "-webkit-sans-serif"_s || familyName == "Helvetica"_s) {
        for (size_t i = 0; i < kKerningFonts.size(); ++i)
            if (std::string_view(kKerningFonts[i]) == "sans-serif")
                return static_cast<uint16_t>(i);
    }
    if (familyName == "-webkit-serif"_s || familyName == "Times"_s) {
        for (size_t i = 0; i < kKerningFonts.size(); ++i)
            if (std::string_view(kKerningFonts[i]) == "serif")
                return static_cast<uint16_t>(i);
    }
    return 0xFFFF;
}

static const KerningCell* findKerningCell(uint16_t fontId, uint16_t sizePx)
{
    size_t lo = 0, hi = kKerningCells.size();
    while (lo < hi) {
        size_t mid = (lo + hi) / 2;
        const auto& c = kKerningCells[mid];
        if (c.fontId < fontId || (c.fontId == fontId && c.sizePx < sizePx))
            lo = mid + 1;
        else if (c.fontId > fontId || (c.fontId == fontId && c.sizePx > sizePx))
            hi = mid;
        else
            return &c;
    }
    return nullptr;
}

static const KerningPair* findKerningPair(std::span<const KerningPair> pairs, uint8_t left, uint8_t right)
{
    size_t lo = 0, hi = pairs.size();
    while (lo < hi) {
        size_t mid = (lo + hi) / 2;
        const auto& p = pairs[mid];
        if (p.leftCp < left || (p.leftCp == left && p.rightCp < right))
            lo = mid + 1;
        else if (p.leftCp > left || (p.leftCp == left && p.rightCp > right))
            hi = mid;
        else
            return &p;
    }
    return nullptr;
}

struct MacKerningCache {
    std::unordered_map<uint64_t, float> values;
    std::unordered_set<uint64_t> populatedCells;
    Lock mutex;
};

static MacKerningCache& macKerningCache()
{
    static NeverDestroyed<MacKerningCache> cache;
    return cache.get();
}

// V-138 v4: get the natural (un-kerned) advance for a single glyph via
// CTFontGetAdvancesForGlyphs. The CALLER computes mac kerning at the
// dispatch site as: (current shaped advance from glyphBuffer) - (this).
// Avoids the V-138 v1-v3 bug where CTFontShapeGlyphs(2-glyph, …) returns
// zero advances.
static float naturalAdvanceForGlyph(CTFontRef ctFont, uint8_t left)
{
    UniChar ch = static_cast<UniChar>(left);
    CGGlyph glyph = 0;
    CTFontGetGlyphsForCharacters(ctFont, &ch, &glyph, 1);
    if (!glyph)
        return 0.0f;
    CGSize adv = CGSizeZero;
    CTFontGetAdvancesForGlyphs(ctFont, kCTFontOrientationHorizontal, &glyph, &adv, 1);
    return static_cast<float>(adv.width);
}

// Legacy stub — kept so the cache + populate signature still compiles; the
// V-138 v4 path uses the per-glyph naturalAdvanceForGlyph + per-call shaped
// advance subtraction.
static float computeMacPairKerningOnce(CTFontRef, uint8_t, uint8_t)
{
    return 0.0f;
}

static void populateMacKerningCellOnce(uint16_t fontId, uint16_t sizePx,
    CTFontRef ctFont, std::span<const KerningPair> iPhonePairs)
{
    auto& cache = macKerningCache();
    Locker locker { cache.mutex };
    uint64_t cellKey = (static_cast<uint64_t>(fontId) << 16) | sizePx;
    if (cache.populatedCells.contains(cellKey))
        return;
    for (const auto& p : iPhonePairs) {
        uint64_t key = (cellKey << 16) | (static_cast<uint64_t>(p.leftCp) << 8) | p.rightCp;
        cache.values[key] = computeMacPairKerningOnce(ctFont, p.leftCp, p.rightCp);
    }
    cache.populatedCells.insert(cellKey);
}

static float lookupMacPairKerning(uint16_t fontId, uint16_t sizePx, uint8_t left, uint8_t right)
{
    auto& cache = macKerningCache();
    Locker locker { cache.mutex };
    uint64_t cellKey = (static_cast<uint64_t>(fontId) << 16) | sizePx;
    uint64_t key = (cellKey << 16) | (static_cast<uint64_t>(left) << 8) | right;
    auto it = cache.values.find(key);
    return it == cache.values.end() ? 0.0f : it->second;
}

static char32_t recoverCodepointFromGlyph(const GlyphBuffer& gb, unsigned glyphIdx,
    StringView source, unsigned beginningStringIndex)
{
    unsigned offset = static_cast<unsigned>(gb.uncheckedStringOffsetAt(glyphIdx)) + beginningStringIndex;
    if (offset >= source.length())
        return 0;
    if (source.is8Bit())
        return static_cast<char32_t>(source[offset]);
    UChar ch = source[offset];
    if (ch >= 0xD800 && ch <= 0xDBFF && offset + 1 < source.length()) {
        UChar low = source[offset + 1];
        if (low >= 0xDC00 && low <= 0xDFFF)
            return static_cast<char32_t>(0x10000 + ((ch - 0xD800) << 10) + (low - 0xDC00));
    }
    return static_cast<char32_t>(ch);
}

static void applyDriftstackPairKerningOverride(GlyphBuffer& glyphBuffer,
    unsigned beginningGlyphIndex, unsigned beginningStringIndex,
    bool enableKerning, CTFontRef ctFont, const String& familyName,
    float ptSize, StringView text)
{
    if (!enableKerning)
        return;
    if (glyphBuffer.size() <= beginningGlyphIndex + 1)
        return;
    uint16_t fontId = resolveKerningFontId(familyName);
    if (fontId == 0xFFFF)
        return;
    uint16_t sizePx = static_cast<uint16_t>(roundf(ptSize));
    const KerningCell* cell = findKerningCell(fontId, sizePx);
    if (!cell)
        return;
    auto pairs = std::span<const KerningPair> { kKerningPairs }.subspan(cell->pairsOffset, cell->pairsCount);

    // V-138 v4: at each glyph, natural advance (no kerning) is queried
    // via CTFontGetAdvancesForGlyphs. Mac kerning = shaped_advance -
    // natural. Then delta = iphone_kerning - mac_kerning. This bypasses
    // the v1-v3 CTFontShapeGlyphs-returns-zero bug.
    for (unsigned i = beginningGlyphIndex; i + 1 < glyphBuffer.size(); ++i) {
        char32_t leftCp = recoverCodepointFromGlyph(glyphBuffer, i, text, beginningStringIndex);
        char32_t rightCp = recoverCodepointFromGlyph(glyphBuffer, i + 1, text, beginningStringIndex);
        if (leftCp < 0x20 || leftCp > 0x7E || rightCp < 0x20 || rightCp > 0x7E)
            continue;
        const KerningPair* p = findKerningPair(pairs,
            static_cast<uint8_t>(leftCp), static_cast<uint8_t>(rightCp));
        if (!p)
            continue;
        float iphoneKerning = static_cast<float>(p->kerningQ8) / 256.0f;
        float natural = naturalAdvanceForGlyph(ctFont, static_cast<uint8_t>(leftCp));
        float shaped = WebCore::width(glyphBuffer.advanceAt(i));
        float macKerning = shaped - natural;
        float delta = iphoneKerning - macKerning;
        // V-148: removed 0.001 threshold; ULP-level pair deltas accumulate
        // to bridge measureText residuals. Emoji-containing canvas.measureText
        // uses Complex path which bypasses this hook — deferred follow-up
        // for ComplexTextController integration.
        if (delta == 0.0f)
            continue;
        glyphBuffer.expandAdvance(i, delta);
    }
    (void)populateMacKerningCellOnce; (void)lookupMacPairKerning; // unused in v4
}

} // anonymous namespace
#endif // PLATFORM(DRIFTSTACK)

GlyphBufferAdvance Font::applyTransforms(GlyphBuffer& glyphBuffer, unsigned beginningGlyphIndex, unsigned beginningStringIndex, bool enableKerning, bool requiresShaping, const AtomString& locale, StringView text, TextDirection textDirection) const
{
    UNUSED_PARAM(requiresShaping);

    if (!platformData().size())
        return makeGlyphBufferAdvance();

    auto handler = ^(CFRange range, CGGlyph** newGlyphsPointer, CGSize** newAdvancesPointer, CGPoint** newOffsetsPointer, CFIndex** newIndicesPointer)
    {
        range.location = std::min(std::max(range.location, static_cast<CFIndex>(0)), static_cast<CFIndex>(glyphBuffer.size()));
        if (range.length < 0) {
            range.length = std::min(range.location, -range.length);
            range.location = range.location - range.length;
            glyphBuffer.remove(beginningGlyphIndex + range.location, range.length);
            LOG_WITH_STREAM(TextShaping, stream << "Callback called to remove at location " << range.location << " and length " << range.length);
        } else {
            glyphBuffer.makeHole(beginningGlyphIndex + range.location, range.length, this);
            LOG_WITH_STREAM(TextShaping, stream << "Callback called to insert hole at location " << range.location << " and length " << range.length);
        }

        *newGlyphsPointer = glyphBuffer.glyphs(beginningGlyphIndex).data();
        *newAdvancesPointer = glyphBuffer.advances(beginningGlyphIndex).data();
        *newOffsetsPointer = glyphBuffer.origins(beginningGlyphIndex).data();
        *newIndicesPointer = glyphBuffer.offsetsInString(beginningGlyphIndex).data();
    };

    auto substring = text.substring(beginningStringIndex);
    constexpr unsigned bufferSize = 256;
    auto upconvertedCharacters = substring.upconvertedCharacters<bufferSize>();
    auto localeString = locale.isNull() ? nullptr : LocaleCocoa::canonicalLanguageIdentifierFromString(locale);
    auto numberOfInputGlyphs = glyphBuffer.size() - beginningGlyphIndex;
    // FIXME: Enable kerning for single glyphs when rdar://82195405 is fixed
    CTFontShapeOptions options = kCTFontShapeWithClusterComposition
        | (enableKerning && numberOfInputGlyphs ? kCTFontShapeWithKerning : 0)
        | (textDirection == TextDirection::RTL ? kCTFontShapeRightToLeft : 0);

    // FIXME: This shouldn't actually be necessary, if we pass in a pointer to the base of the string.
    for (unsigned i = 0; i < glyphBuffer.size() - beginningGlyphIndex; ++i)
        glyphBuffer.offsetsInString(beginningGlyphIndex)[i] -= beginningStringIndex;

    RetainPtr ctFont = this->ctFont();
    LOG_WITH_STREAM(TextShaping,
        stream << "Simple shaping " << numberOfInputGlyphs << " glyphs in font " << String(adoptCF(CTFontCopyPostScriptName(ctFont.get())).get()) << ".\n";
        stream << "Font attributes: " << String(adoptCF(CFCopyDescription(adoptCF(CTFontDescriptorCopyAttributes(adoptCF(CTFontCopyFontDescriptor(ctFont.get())).get())).get())).get()) << "\n";
        stream << "Locale: " << String(localeString.get()) << "\n";
        stream << "Options: " << options << "\n";
        auto glyphs = glyphBuffer.glyphs(beginningGlyphIndex);
        stream << "Glyphs:";
        for (auto& glyph : glyphs)
            stream << " " << glyph;
        stream << "\n";
        auto advances = glyphBuffer.advances(beginningGlyphIndex);
        stream << "Advances:";
        for (auto& advance : advances)
            stream << " " << FloatSize(advance);
        stream << "\n";
        auto origins = glyphBuffer.origins(beginningGlyphIndex);
        stream << "Origins:";
        for (auto& origin : origins)
            stream << " " << FloatPoint(origin);
        stream << "\n";
        auto offsets = glyphBuffer.offsetsInString(beginningGlyphIndex);
        stream << "Offsets:";
        for (auto& offset : offsets)
            stream << " " << offset;
        stream << "\n";
        auto codeUnits = upconvertedCharacters.span();
        stream << "Code Units:";
        for (unsigned i = 0; i < numberOfInputGlyphs; ++i)
            stream << " U+" << hex(codeUnits[i], 4);
    );

    auto initialAdvance = CTFontShapeGlyphs(
        ctFont.get(),
        glyphBuffer.glyphs(beginningGlyphIndex).data(),
        glyphBuffer.advances(beginningGlyphIndex).data(),
        glyphBuffer.origins(beginningGlyphIndex).data(),
        glyphBuffer.offsetsInString(beginningGlyphIndex).data(),
        reinterpret_cast<const UniChar*>(upconvertedCharacters.get()),
        numberOfInputGlyphs,
        options,
        localeString.get(),
        handler);

    LOG_WITH_STREAM(TextShaping,
        stream << "Shaping result: " << glyphBuffer.size() - beginningGlyphIndex << " glyphs.\n";
        auto glyphs = glyphBuffer.glyphs(beginningGlyphIndex);
        stream << "Glyphs:";
        for (auto& glyph : glyphs)
            stream << " " << glyph;
        stream << "\n";
        auto advances = glyphBuffer.advances(beginningGlyphIndex);
        stream << "Advances:";
        for (auto& advance : advances)
            stream << " " << FloatSize(advance);
        stream << "\n";
        auto origins = glyphBuffer.origins(beginningGlyphIndex);
        stream << "Origins:";
        for (auto& origin : origins)
            stream << " " << FloatPoint(origin);
        stream << "\n";
        auto offsets = glyphBuffer.offsetsInString(beginningGlyphIndex);
        stream << "Offsets:";
        for (auto& offset : offsets)
            stream << " " << offset;
        stream << "\n";
        stream << "Initial advance: " << FloatSize(initialAdvance);
    );

    ASSERT(numberOfInputGlyphs || glyphBuffer.size() == beginningGlyphIndex);
    ASSERT(numberOfInputGlyphs || (!initialAdvance.width && !initialAdvance.height));

#if PLATFORM(DRIFTSTACK)
    // V-126 closure: Mac CT and iOS CT apply different per-pair kerning.
    // After CTFontShapeGlyphs has applied Mac kerning, replace those
    // contributions with iPhone-equivalent kerning (delta-adjustment).
    // See /docs/architecture/v126-kerning-override-design.md.
    applyDriftstackPairKerningOverride(glyphBuffer, beginningGlyphIndex,
        beginningStringIndex, enableKerning, ctFont.get(),
        m_platformData.familyName(), m_platformData.size(), text);
#endif

    for (unsigned i = 0; i < glyphBuffer.size() - beginningGlyphIndex; ++i)
        glyphBuffer.offsetsInString(beginningGlyphIndex)[i] += beginningStringIndex;

    if (textDirection == TextDirection::RTL)
        glyphBuffer.reverse(beginningGlyphIndex, glyphBuffer.size() - beginningGlyphIndex);

    return initialAdvance;
}

static int extractNumber(CFNumberRef number)
{
    int result = 0;
    if (number)
        CFNumberGetValue(number, kCFNumberIntType, &result);
    return result;
}

static bool extractBoolean(CFBooleanRef value)
{
    if (value)
        return CFBooleanGetValue(value);
    return false;
}

void Font::determinePitch()
{
    RetainPtr ctFont = this->ctFont();
    ASSERT(ctFont);

    // Special case Osaka-Mono.
    // According to <rdar://problem/3999467>, we should treat Osaka-Mono as fixed pitch.
    // Note that the AppKit does not report Osaka-Mono as fixed pitch.

    // Special case MS-PGothic.
    // According to <rdar://problem/4032938>, we should not treat MS-PGothic as fixed pitch.
    // Note that AppKit does report MS-PGothic as fixed pitch.

    // Special case MonotypeCorsiva
    // According to <rdar://problem/5454704>, we should not treat MonotypeCorsiva as fixed pitch.
    // Note that AppKit does report MonotypeCorsiva as fixed pitch.

    auto fullName = adoptCF(CTFontCopyFullName(ctFont.get()));
    auto familyName = adoptCF(CTFontCopyFamilyName(ctFont.get()));

    int fixedPitch = extractNumber(adoptCF(static_cast<CFNumberRef>(CTFontCopyAttribute(ctFont.get(), kCTFontFixedAdvanceAttribute))).get());
    bool userInstalled = extractBoolean(adoptCF(static_cast<CFBooleanRef>(CTFontCopyAttribute(ctFont.get(), kCTFontUserInstalledAttribute))).get());
    m_treatAsFixedPitch = (CTFontGetSymbolicTraits(ctFont.get()) & kCTFontMonoSpaceTrait) || fixedPitch || (caseInsensitiveCompare(fullName.get(), CFSTR("Osaka-Mono")) || caseInsensitiveCompare(fullName.get(), CFSTR("MS-PGothic")) || caseInsensitiveCompare(fullName.get(), CFSTR("MonotypeCorsiva")));
    if (familyName && caseInsensitiveCompare(familyName.get(), CFSTR("Courier New"))) {
#if PLATFORM(IOS_FAMILY) || PLATFORM(DRIFTSTACK)
        // Special case Courier New to not be treated as fixed pitch, as this will make use of a hacked space width which is undesireable for iPhone (see rdar://6269783).
        m_treatAsFixedPitch = false;
#endif
        // "Courier New" has many special case characters which does not have widths (u0181, u0182 etc.). Thus we disable fast content measuring for monospace fonts.
        m_canTakeFixedPitchFastContentMeasuring = false;
    } else
        m_canTakeFixedPitchFastContentMeasuring = m_treatAsFixedPitch && !userInstalled;
}

#if PLATFORM(DRIFTSTACK)
// V-080 / V-081 Stage D-2 Track 2: iPhone normalizes ALL color-emoji glyph
// bboxes to a per-size canonical value, INDEPENDENT of glyph codepoint AND
// of the rendering font. Captured empirically (Stage D-3 emoji matrix,
// 2026-05-01: 15 distinct emoji × 89 sizes × 2 fonts → identical
// (width, ABA, ABD) per size). Mac CoreText returns smaller per-glyph
// bboxes from the same iOS font binary; clamp to iPhone canonical
// values whenever the queried glyph is a color glyph.
//
// Table: per-size (width, ascent, descent) tuples for sizes [8..96].
// Ascent / descent are FloatRect-coordinate values (positive ascent
// becomes -y in the WebKit-local convention; positive descent becomes
// +maxY). Width is the glyph's advance-width-equivalent bbox horizontal
// extent.
struct DriftstackEmojiBboxEntry { float size; float width; float ascent; float descent; };
// All values are exact 1/64-px multiples (LayoutUnit precision).
// Formatted as decimal-representable-as-float fractions to avoid
// rounding noise (the iPhone-canonical 13.640625 = 873/64).
static constexpr std::array<DriftstackEmojiBboxEntry, 89> driftstackEmojiBboxTable = {{
    {   8.f,  11.f,        7.796875f,    2.1875f },     {   9.f,  12.f,        8.765625f,    2.46875f },
    {  10.f,  13.f,        9.75f,        2.75f },       {  11.f,  15.f,       10.71875f,     3.015625f },
    {  12.f,  16.f,       11.6875f,      3.296875f },   {  13.f,  17.f,       12.671875f,    3.5625f },
    {  14.f,  19.f,       13.640625f,    3.84375f },    {  15.f,  20.f,       14.625f,       4.125f },
    {  16.f,  21.f,       15.59375f,     4.390625f },   {  17.f,  22.f,       16.1875f,      4.296875f },
    {  18.f,  22.f,       16.796875f,    4.1875f },     {  19.f,  23.f,       17.390625f,    4.09375f },
    {  20.f,  23.f,       18.f,          4.f },         {  21.f,  23.f,       18.59375f,     3.890625f },
    {  22.f,  24.f,       19.1875f,      3.796875f },   {  23.f,  24.f,       19.796875f,    3.6875f },
    {  24.f,  25.f,       20.390625f,    3.59375f },    {  25.f,  26.f,       21.25f,        3.75f },
    {  26.f,  26.f,       22.09375f,     3.890625f },   {  27.f,  27.f,       22.9375f,      4.046875f },
    {  28.f,  28.f,       23.796875f,    4.1875f },     {  29.f,  29.f,       24.640625f,    4.34375f },
    {  30.f,  30.f,       25.5f,         4.5f },        {  31.f,  31.f,       26.34375f,     4.640625f },
    {  32.f,  32.f,       27.1875f,      4.796875f },   {  33.f,  33.f,       28.046875f,    4.9375f },
    {  34.f,  34.f,       28.890625f,    5.09375f },    {  35.f,  35.f,       29.75f,        5.25f },
    {  36.f,  36.f,       30.59375f,     5.390625f },   {  37.f,  37.f,       31.4375f,      5.546875f },
    {  38.f,  38.f,       32.296875f,    5.6875f },     {  39.f,  39.f,       33.140625f,    5.84375f },
    {  40.f,  40.f,       34.f,          6.f },         {  41.f,  41.f,       34.84375f,     6.140625f },
    {  42.f,  42.f,       35.6875f,      6.296875f },   {  43.f,  43.f,       36.546875f,    6.4375f },
    {  44.f,  44.f,       37.390625f,    6.59375f },    {  45.f,  45.f,       38.25f,        6.75f },
    {  46.f,  46.f,       39.09375f,     6.890625f },   {  47.f,  47.f,       39.9375f,      7.046875f },
    {  48.f,  48.f,       40.796875f,    7.1875f },     {  49.f,  49.f,       41.640625f,    7.34375f },
    {  50.f,  50.f,       42.5f,         7.5f },        {  51.f,  51.f,       43.34375f,     7.640625f },
    {  52.f,  52.f,       44.1875f,      7.796875f },   {  53.f,  53.f,       45.046875f,    7.9375f },
    {  54.f,  54.f,       45.890625f,    8.09375f },    {  55.f,  55.f,       46.75f,        8.25f },
    {  56.f,  56.f,       47.59375f,     8.390625f },   {  57.f,  57.f,       48.4375f,      8.546875f },
    {  58.f,  58.f,       49.296875f,    8.6875f },     {  59.f,  59.f,       50.140625f,    8.84375f },
    {  60.f,  60.f,       51.f,          9.f },         {  61.f,  61.f,       51.84375f,     9.140625f },
    {  62.f,  62.f,       52.6875f,      9.296875f },   {  63.f,  63.f,       53.546875f,    9.4375f },
    {  64.f,  64.f,       54.390625f,    9.59375f },    {  65.f,  65.f,       55.25f,        9.75f },
    {  66.f,  66.f,       56.09375f,     9.890625f },   {  67.f,  67.f,       56.9375f,     10.046875f },
    {  68.f,  68.f,       57.796875f,   10.1875f },     {  69.f,  69.f,       58.640625f,   10.34375f },
    {  70.f,  70.f,       59.5f,        10.5f },        {  71.f,  71.f,       60.34375f,    10.640625f },
    {  72.f,  72.f,       61.1875f,     10.796875f },   {  73.f,  73.f,       62.046875f,   10.9375f },
    {  74.f,  74.f,       62.890625f,   11.09375f },    {  75.f,  75.f,       63.75f,       11.25f },
    {  76.f,  76.f,       64.59375f,    11.390625f },   {  77.f,  77.f,       65.4375f,     11.546875f },
    {  78.f,  78.f,       66.296875f,   11.6875f },     {  79.f,  79.f,       67.140625f,   11.84375f },
    {  80.f,  80.f,       68.f,         12.f },         {  81.f,  81.f,       68.84375f,    12.140625f },
    {  82.f,  82.f,       69.6875f,     12.296875f },   {  83.f,  83.f,       70.546875f,   12.4375f },
    {  84.f,  84.f,       71.390625f,   12.59375f },    {  85.f,  85.f,       72.25f,       12.75f },
    {  86.f,  86.f,       73.09375f,    12.890625f },   {  87.f,  87.f,       73.9375f,     13.046875f },
    {  88.f,  88.f,       74.796875f,   13.1875f },     {  89.f,  89.f,       75.640625f,   13.34375f },
    {  90.f,  90.f,       76.5f,        13.5f },        {  91.f,  91.f,       77.34375f,    13.640625f },
    {  92.f,  92.f,       78.1875f,     13.796875f },   {  93.f,  93.f,       79.046875f,   13.9375f },
    {  94.f,  94.f,       79.890625f,   14.09375f },    {  95.f,  95.f,       80.75f,       14.25f },
    {  96.f,  96.f,       81.59375f,    14.390625f }
}};

// Linear-interp lookup. Sizes outside [8, 96] clamp to nearest endpoint.
// Most canvas sizes are integer points so the interp branch rarely fires.
static FloatRect driftstackEmojiBboxForSize(float size)
{
    if (size <= driftstackEmojiBboxTable.front().size) {
        const auto& e = driftstackEmojiBboxTable.front();
        return FloatRect(0, -e.ascent, e.width, e.ascent + e.descent);
    }
    if (size >= driftstackEmojiBboxTable.back().size) {
        const auto& e = driftstackEmojiBboxTable.back();
        return FloatRect(0, -e.ascent, e.width, e.ascent + e.descent);
    }
    DriftstackEmojiBboxEntry a = driftstackEmojiBboxTable.front();
    for (const auto& b : driftstackEmojiBboxTable) {
        if (size >= a.size && size <= b.size && a.size != b.size) {
            float t = (size - a.size) / (b.size - a.size);
            float w = a.width   + t * (b.width   - a.width);
            float ascent  = a.ascent  + t * (b.ascent  - a.ascent);
            float descent = a.descent + t * (b.descent - a.descent);
            return FloatRect(0, -ascent, w, ascent + descent);
        }
        a = b;
    }
    // Unreachable: above branches cover all cases.
    return FloatRect();
}
#endif

FloatRect Font::platformBoundsForGlyph(Glyph glyph) const
{
    FloatRect boundingBox;
    CGRect ignoredRect = { };
    boundingBox = CTFontGetBoundingRectsForGlyphs(protect(ctFont()).get(), platformData().orientation() == FontOrientation::Vertical ? kCTFontOrientationVertical : kCTFontOrientationHorizontal, &glyph, &ignoredRect, 1);
    boundingBox.setY(-boundingBox.maxY());
    boundingBox.setWidth(boundingBox.width() + m_syntheticBoldOffset);

#if PLATFORM(DRIFTSTACK)
    if (colorGlyphType(glyph) == ColorGlyphType::Color)
        return driftstackEmojiBboxForSize(m_platformData.size());
#endif

    return boundingBox;
}

Vector<FloatRect, Font::inlineGlyphRunCapacity> Font::platformBoundsForGlyphs(const Vector<Glyph, inlineGlyphRunCapacity>& glyphs) const
{
    Vector<CGRect, inlineGlyphRunCapacity> rectsForGlyphs(glyphs.size());
    CTFontGetBoundingRectsForGlyphs(protect(ctFont()).get(), platformData().orientation() == FontOrientation::Vertical ? kCTFontOrientationVertical : kCTFontOrientationHorizontal, glyphs.span().data(), rectsForGlyphs.mutableSpan().data(), rectsForGlyphs.size());

#if PLATFORM(DRIFTSTACK)
    Vector<FloatRect, Font::inlineGlyphRunCapacity> result;
    result.reserveInitialCapacity(glyphs.size());
    const float fontSize = m_platformData.size();
    for (size_t i = 0; i < glyphs.size(); ++i) {
        if (colorGlyphType(glyphs[i]) == ColorGlyphType::Color) {
            result.append(driftstackEmojiBboxForSize(fontSize));
            continue;
        }
        FloatRect boundingBox(rectsForGlyphs[i]);
        boundingBox.setY(-boundingBox.maxY());
        boundingBox.setWidth(boundingBox.width() + m_syntheticBoldOffset);
        result.append(boundingBox);
    }
    return result;
#else
    return rectsForGlyphs.map<Vector<FloatRect, inlineGlyphRunCapacity>>([&](const auto& rect) -> auto {
        FloatRect boundingBox(rect);
        boundingBox.setY(-boundingBox.maxY());
        boundingBox.setWidth(boundingBox.width() + m_syntheticBoldOffset);
        return boundingBox;
    });
#endif
}

Path Font::platformPathForGlyph(Glyph glyph) const
{
    auto result = adoptCF(CTFontCreatePathForGlyph(protect(ctFont()).get(), glyph, nullptr));
    if (!result)
        return { };

    auto syntheticBoldOffset = this->syntheticBoldOffset();
    if (syntheticBoldOffset) {
        auto newPath = adoptCF(CGPathCreateMutable());
        CGPathAddPath(newPath.get(), nullptr, result.get());
        auto translation = CGAffineTransformMakeTranslation(syntheticBoldOffset, 0);
        CGPathAddPath(newPath.get(), &translation, result.get());
        return { PathCG::create(WTF::move(newPath)) };
    }

    return { PathCG::create(adoptCF(CGPathCreateMutableCopy(result.get()))) };
}

bool Font::platformSupportsCodePoint(char32_t character, std::optional<char32_t> variation) const
{
    if (variation)
        return false;

    std::array<UniChar, 2> codeUnits;
    std::array<CGGlyph, 2> glyphs;
    CFIndex count = 0;
    U16_APPEND_UNSAFE(codeUnits, count, character);
    return CTFontGetGlyphsForCharacters(protect(ctFont()).get(), codeUnits.data(), glyphs.data(), count);
}

static bool hasGlyphsForCharacterRange(CTFontRef font, UniChar firstCharacter, UniChar lastCharacter, bool expectValidGlyphsForAllCharacters)
{
    const unsigned numberOfCharacters = lastCharacter - firstCharacter + 1;
    Vector<CGGlyph> glyphs(FillWith { }, numberOfCharacters, 0);
    CTFontGetGlyphsForCharacterRange(font, glyphs.begin(), CFRangeMake(firstCharacter, numberOfCharacters));
    glyphs.removeAll(0);

    if (glyphs.isEmpty())
        return false;

    Vector<CGRect> boundingRects(FillWith { }, glyphs.size(), CGRectZero);
    CTFontGetBoundingRectsForGlyphs(font, kCTFontOrientationDefault, glyphs.begin(), boundingRects.begin(), glyphs.size());

    unsigned validGlyphsCount = 0;
    for (auto& rect : boundingRects) {
        if (!CGRectIsEmpty(rect))
            ++validGlyphsCount;
    }

    if (expectValidGlyphsForAllCharacters)
        return validGlyphsCount == glyphs.size();

    return validGlyphsCount;
}

bool Font::isProbablyOnlyUsedToRenderIcons() const
{
    RetainPtr platformFont = ctFont();
    if (!platformFont)
        return false;

    // Allow most non-icon fonts to bail early here by testing a single character 'a', without iterating over all basic latin characters.
    UniChar lowercaseACharacter = 'a';
    CGGlyph lowercaseAGlyph;
    if (CTFontGetGlyphsForCharacters(platformFont.get(), &lowercaseACharacter, &lowercaseAGlyph, 1)) {
        CGRect ignoredRect = { };
        if (!CGRectIsEmpty(CTFontGetBoundingRectsForGlyphs(platformFont.get(), kCTFontOrientationDefault, &lowercaseAGlyph, &ignoredRect, 1)))
            return false;
    }

    auto supportedCharacters = adoptCF(CTFontCopyCharacterSet(platformFont.get()));
    if (CFCharacterSetHasMemberInPlane(supportedCharacters.get(), 1) || CFCharacterSetHasMemberInPlane(supportedCharacters.get(), 2))
        return false;

    return !hasGlyphsForCharacterRange(platformFont.get(), ' ', '~', false) && !hasGlyphsForCharacterRange(platformFont.get(), 0x0600, 0x06FF, true);
}

const PAL::OTSVGTable& Font::otSVGTable() const
{
    if (!m_otSVGTable) {
        if (auto tableData = adoptCF(CTFontCopyTable(protect(ctFont()).get(), kCTFontTableSVG, kCTFontTableOptionNoOptions)))
            m_otSVGTable = PAL::OTSVGTable(tableData.get(), fontMetrics().unitsPerEm(), platformData().size());
        else
            m_otSVGTable = {{ }};
    }
    return m_otSVGTable.value();
}

Font::ComplexColorFormatGlyphs Font::ComplexColorFormatGlyphs::createWithNoRelevantTables()
{
    return { false, 0 };
}

Font::ComplexColorFormatGlyphs Font::ComplexColorFormatGlyphs::createWithRelevantTablesAndGlyphCount(unsigned glyphCount)
{
    return { true, glyphCount };
}

bool NODELETE Font::ComplexColorFormatGlyphs::hasValueFor(Glyph glyph) const
{
    return m_bits.contains(bitForInitialized(glyph));
}

bool NODELETE Font::ComplexColorFormatGlyphs::get(Glyph glyph) const
{
    ASSERT(hasValueFor(glyph));
    return m_bits.contains(bitForValue(glyph));
}

void Font::ComplexColorFormatGlyphs::set(Glyph glyph, bool value)
{
    ASSERT(m_hasRelevantTables);
    ASSERT(!hasValueFor(glyph));
    m_bits.set(bitForInitialized(glyph));
    if (value)
        m_bits.set(bitForValue(glyph));
}

bool Font::hasComplexColorFormatTables() const
{
    if (otSVGTable().table)
        return true;

#if HAVE(CORE_TEXT_SBIX_IMAGE_SIZE_FUNCTIONS)
    if (auto sbixTableData = adoptCF(CTFontCopyTable(protect(ctFont()).get(), kCTFontTableSbix, kCTFontTableOptionNoOptions)))
        return true;
#endif

    return false;
}

Font::ComplexColorFormatGlyphs& Font::glyphsWithComplexColorFormat() const
{
    if (!m_glyphsWithComplexColorFormat) {
        if (hasComplexColorFormatTables()) {
            CFIndex glyphCount = CTFontGetGlyphCount(protect(ctFont()).get());
            if (glyphCount >= 0) {
                m_glyphsWithComplexColorFormat = ComplexColorFormatGlyphs::createWithRelevantTablesAndGlyphCount(glyphCount);
                return m_glyphsWithComplexColorFormat.value();
            }
        }
        m_glyphsWithComplexColorFormat = ComplexColorFormatGlyphs::createWithNoRelevantTables();
    }
    return m_glyphsWithComplexColorFormat.value();
}

bool Font::glyphHasComplexColorFormat(Glyph glyphID) const
{
#if HAVE(CORE_TEXT_GLYPHHASCOMPLEXCOLOR_FUNCTION)
    if (PAL::canLoad_CoreText_CTFontHasComplexColorFormatForGlyph())
        return PAL::softLink_CoreText_CTFontHasComplexColorFormatForGlyph(protect(ctFont()).get(), glyphID);
#endif

    if (auto svgTable = otSVGTable().table) {
        if (PAL::softLinkOTSVGOTSVGTableGetDocumentIndexForGlyph(svgTable, glyphID) != kCFNotFound)
            return true;
    }

#if HAVE(CORE_TEXT_SBIX_IMAGE_SIZE_FUNCTIONS)
    // There's no function to directly look up the sbix table, so use the fact that this one returns a non-zero value iff there's an sbix entry.
    if (CTFontGetSbixImageSizeForGlyphAndContentsScale(protect(ctFont()).get(), glyphID, 0))
        return true;
#endif

    return false;
}

std::optional<BitVector> Font::findOTSVGGlyphs(std::span<const GlyphBufferGlyph> glyphs) const
{
    auto table = otSVGTable().table;
    if (!table)
        return { };

    std::optional<BitVector> result;
    for (size_t i = 0; i < glyphs.size(); ++i) {
        if (PAL::softLinkOTSVGOTSVGTableGetDocumentIndexForGlyph(table, glyphs[i]) != kCFNotFound) {
            if (!result)
                result = BitVector(glyphs.size());
            result.value().quickSet(i);
        }
    }
    return result;
}

bool Font::hasAnyComplexColorFormatGlyphs(std::span<const GlyphBufferGlyph> glyphs) const
{
    auto& complexGlyphs = glyphsWithComplexColorFormat();
    if (!complexGlyphs.hasRelevantTables())
        return false;

    for (auto glyph : glyphs) {
        if (!complexGlyphs.hasValueFor(glyph))
            complexGlyphs.set(glyph, glyphHasComplexColorFormat(glyph));

        if (complexGlyphs.get(glyph))
            return true;
    }
    return false;
}

std::optional<Ref<Font>> Font::fromIPCData(IPCFontData&& data)
{
    return WTF::switchOn(WTF::move(data),
        [] (InstalledFont&& installedFont) -> std::optional<Ref<Font>> {
            return installedFont.toFont();
        },
        [] (CustomFontCreationData&& creationData) -> std::optional<Ref<Font>> {
            Ref fontFaceData = SharedBuffer::create(WTF::move(creationData.fontFaceData));
            RefPtr<FontCustomPlatformData> customPlatformData = FontCustomPlatformData::create(fontFaceData, creationData.itemInCollection);
            if (!customPlatformData)
                return std::nullopt;

            RetainPtr baseFontDescriptor = customPlatformData->fontDescriptor.get();
            if (!baseFontDescriptor)
                return std::nullopt;

            RetainPtr<CFDictionaryRef> attributesDictionary = creationData.attributes ? creationData.attributes->toCFDictionary() : nullptr;
            RetainPtr fontDescriptor = adoptCF(CTFontDescriptorCreateCopyWithAttributes(baseFontDescriptor.get(), attributesDictionary.get()));

            RetainPtr font = adoptCF(CTFontCreateWithFontDescriptor(fontDescriptor.get(), creationData.metadata.pointSize, nullptr));

            return Font::create(FontPlatformData(creationData.metadata.pointSize, FontOrientation(creationData.metadata.orientation), FontWidthVariant(creationData.metadata.widthVariant), TextRenderingMode(creationData.metadata.textRenderingMode), creationData.metadata.syntheticBold, creationData.metadata.syntheticOblique, WTF::move(font), WTF::move(customPlatformData)));
        }
    );
}

std::optional<InstalledFont> Font::toSerializableInstalledFont() const
{
    RetainPtr ctFont = this->ctFont();
    if (!ctFont || m_platformData.creationData())
        return std::nullopt;

    FontMetadata fontData = {
        CTFontGetSize(ctFont.get()),
        platformData().orientation(),
        platformData().widthVariant(),
        platformData().textRenderingMode(),
        platformData().syntheticBold(),
        platformData().syntheticOblique()
    };

    SystemUIFontType fontType = CTFontGetUIFontType(ctFont.get());
    if (fontType != SystemUIFontTypeNone) {
        return InstalledFont {
            InstalledFont::SystemUIFont {
                fontType,
                adoptCF(checked_cf_cast<CFStringRef>(CTFontCopyAttribute(ctFont.get(), kCTFontDescriptorLanguageAttribute))).get()
            },
            fontData
        };
    }

    RetainPtr fontDescriptor = adoptCF(CTFontCopyFontDescriptor(ctFont.get()));
    RetainPtr attributes = adoptCF(CTFontDescriptorCopyAttributes(fontDescriptor.get()));
    return InstalledFont {
        InstalledFont::PostScriptFont {
            String(adoptCF(CTFontCopyPostScriptName(ctFont.get())).get()),
            CTFontDescriptorGetOptions(fontDescriptor.get()),
            FontPlatformSerializedAttributes::fromCF(attributes.get())
        },
        fontData
    };
}

IPCFontData Font::toSerializableFont() const
{
    std::optional<InstalledFont> installedFont = toSerializableInstalledFont();
    if (installedFont)
        return { *installedFont };

    RetainPtr font = ctFont();
    RetainPtr fontDescriptor = adoptCF(CTFontCopyFontDescriptor(font.get()));
    RetainPtr attributes = adoptCF(CTFontDescriptorCopyAttributes(fontDescriptor.get()));

    const auto& data = m_platformData.creationData();
    FontMetadata fontData = {
        CTFontGetSize(font.get()),
        m_platformData.orientation(),
        m_platformData.widthVariant(),
        m_platformData.textRenderingMode(),
        m_platformData.syntheticBold(),
        m_platformData.syntheticOblique()
    };

    return { CustomFontCreationData { fontData, { data->fontFaceData->span() }, FontPlatformSerializedAttributes::fromCF(attributes.get()), data->itemInCollection } };
}

#if ENABLE(MULTI_REPRESENTATION_HEIC)

MultiRepresentationHEICMetrics Font::metricsForMultiRepresentationHEIC() const
{
    CGRect bounds = CTFontGetTypographicBoundsForAdaptiveImageProvider(ctFont(), nullptr);

    MultiRepresentationHEICMetrics metrics;
    metrics.ascent = CGRectGetMaxY(bounds);
    metrics.descent = -CGRectGetMinY(bounds);
    metrics.width = CGRectGetMaxX(bounds);
    return metrics;
}

#endif

} // namespace WebCore
