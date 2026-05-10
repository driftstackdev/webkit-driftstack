/*
 * Copyright (C) 2006-2025 Apple Inc. All rights reserved.
 * Copyright (C) 2007-2008 Torch Mobile, Inc.
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

#pragma once

#include <WebCore/FloatRect.h>
#include <WebCore/FontMetrics.h>
#include <WebCore/FontPlatformData.h>
#include <WebCore/GlyphBuffer.h>
#include <WebCore/GlyphMetricsMap.h>
#include <WebCore/RenderingResourceIdentifier.h>
#include <WebCore/TrustedFonts.h>
#include <wtf/BitVector.h>
#include <wtf/Lock.h>
#include <wtf/Platform.h>
#include <wtf/RetainPtr.h>
#include <wtf/WeakPtr.h>

#if PLATFORM(COCOA)
#include <pal/cf/OTSVGTable.h>
#endif

#if PLATFORM(WIN)
#include <usp10.h>
#endif

#if USE(SKIA)
WTF_IGNORE_WARNINGS_IN_THIRD_PARTY_CODE_BEGIN
#include <skia/core/SkTextBlob.h>
WTF_IGNORE_WARNINGS_IN_THIRD_PARTY_CODE_END
#endif

namespace WTF {
class TextStream;
}

namespace WebCore {

class FontCache;
class FontDescription;
class GlyphPage;
#if ENABLE(MATHML)
class OpenTypeMathData;
#endif
#if ENABLE(OPENTYPE_VERTICAL)
class OpenTypeVerticalData;
#endif

struct GlyphData;
#if ENABLE(MULTI_REPRESENTATION_HEIC)
struct MultiRepresentationHEICMetrics;
#endif

enum class FontVariant : uint8_t { Auto, Normal, SmallCaps, EmphasisMark, BrokenIdeograph };
enum class PitchType : uint8_t { Unknown, Fixed, Variable };
enum class IsForPlatformFont : bool { No, Yes };

// Used to create platform fonts.
enum class FontOrigin : bool { Remote, Local };
enum class FontIsInterstitial : bool { No, Yes };
enum class FontVisibility : bool { Visible, Invisible };
enum class FontIsOrientationFallback : bool { No, Yes };

#if USE(CORE_TEXT)
using IPCFontData = Variant<WebCore::InstalledFont, WebCore::CustomFontCreationData>;

bool fontHasEitherTable(CTFontRef, unsigned tableTag1, unsigned tableTag2);
bool supportsOpenTypeFeature(CTFontRef, CFStringRef featureTag);
#endif

struct FontInternalAttributes {
    WEBCORE_EXPORT RenderingResourceIdentifier ensureRenderingResourceIdentifier() const;

    mutable std::optional<RenderingResourceIdentifier> renderingResourceIdentifier;
    FontOrigin origin : 1;
    FontIsInterstitial isInterstitial : 1;
    FontVisibility visibility : 1;
    FontIsOrientationFallback isTextOrientationFallback : 1;
};

DECLARE_ALLOCATOR_WITH_HEAP_IDENTIFIER(Font);
class Font : public RefCounted<Font>, public CanMakeSingleThreadWeakPtr<Font> {
    WTF_DEPRECATED_MAKE_FAST_ALLOCATED_WITH_HEAP_IDENTIFIER(Font, Font);
public:
    using Origin = FontOrigin;
    using IsInterstitial = FontIsInterstitial;
    using Visibility = FontVisibility;
    using IsOrientationFallback = FontIsOrientationFallback;

    WEBCORE_EXPORT static Ref<Font> create(const FontPlatformData&, Origin = Origin::Local, IsInterstitial = IsInterstitial::No, Visibility = Visibility::Visible, IsOrientationFallback = IsOrientationFallback::No, std::optional<RenderingResourceIdentifier> = std::nullopt);
    WEBCORE_EXPORT static Ref<Font> create(Ref<SharedBuffer>&& fontFaceData, Font::Origin, float fontSize, bool syntheticBold, bool syntheticItalic, DownloadableBinaryFontTrustedTypes);
    WEBCORE_EXPORT static Ref<Font> create(WebCore::FontInternalAttributes&&, WebCore::FontPlatformData&&);

    WEBCORE_EXPORT ~Font();

    static Ref<Font> createSystemFallbackFontPlaceholder() { return adoptRef(*new Font(IsSystemFallbackFontPlaceholder::Yes)); }
    bool isSystemFontFallbackPlaceholder() const { return m_isSystemFontFallbackPlaceholder; }
    const FontPlatformData& platformData() const LIFETIME_BOUND { return m_platformData; }
#if ENABLE(MATHML)
    const OpenTypeMathData* mathData() const;
#endif
#if ENABLE(OPENTYPE_VERTICAL)
    inline const OpenTypeVerticalData* verticalData() const;
#endif

    WEBCORE_EXPORT RenderingResourceIdentifier renderingResourceIdentifier() const;

    const Font* smallCapsFont(const FontDescription&) const;
    const Font& noSynthesizableFeaturesFont() const;
    const Font* emphasisMarkFont(const FontDescription&) const;
    const Font& brokenIdeographFont() const;
    const RefPtr<Font> halfWidthFont() const;

    bool isProbablyOnlyUsedToRenderIcons() const;

    const Font* variantFont(const FontDescription& description, FontVariant variant) const
    {
        switch (variant) {
        case FontVariant::SmallCaps:
            return smallCapsFont(description);
        case FontVariant::EmphasisMark:
            return emphasisMarkFont(description);
        case FontVariant::BrokenIdeograph:
            return &brokenIdeographFont();
        case FontVariant::Auto:
        case FontVariant::Normal:
            break;
        }
        ASSERT_NOT_REACHED();
        return const_cast<Font*>(this);
    }

    bool variantCapsSupportedForSynthesis(FontVariantCaps) const;

    const Font& verticalRightOrientationFont() const;
    const Font& uprightOrientationFont() const;
    const Font& invisibleFont() const;

    bool hasVerticalGlyphs() const { return m_hasVerticalGlyphs; }
    bool isTextOrientationFallback() const { return m_attributes.isTextOrientationFallback == IsOrientationFallback::Yes; }

    const FontMetrics& fontMetrics() const LIFETIME_BOUND { return m_fontMetrics; }
    float sizePerUnit() const { return platformData().size() / (fontMetrics().unitsPerEm() ? fontMetrics().unitsPerEm() : 1); }

    float maxCharWidth() const { return m_maxCharWidth; }
    void setMaxCharWidth(float maxCharWidth) { m_maxCharWidth = maxCharWidth; }

    float avgCharWidth() const { return m_avgCharWidth; }
    void setAvgCharWidth(float avgCharWidth) { m_avgCharWidth = avgCharWidth; }

    FloatRect boundsForGlyph(Glyph) const;
#if USE(CORE_TEXT) || USE(SKIA)
    static constexpr size_t inlineGlyphRunCapacity = 256;
    Vector<FloatRect, inlineGlyphRunCapacity> boundsForGlyphs(std::span<const Glyph>) const;
#endif

    // Should the result of this function include the results of synthetic bold?
    enum class SyntheticBoldInclusion {
        Incorporate,
        Exclude
    };

    enum class IsSystemFallbackFontPlaceholder : bool {
        No,
        Yes
    };

    float widthForGlyph(Glyph, SyntheticBoldInclusion = SyntheticBoldInclusion::Incorporate) const;

    Path pathForGlyph(Glyph) const;

    float NODELETE spaceWidth(SyntheticBoldInclusion SyntheticBoldInclusion = SyntheticBoldInclusion::Incorporate) const
    {
        return m_spaceWidth + (SyntheticBoldInclusion == SyntheticBoldInclusion::Incorporate ? syntheticBoldOffset() : 0);
    }

    float syntheticBoldOffset() const { return m_syntheticBoldOffset; }

    Glyph spaceGlyph() const { return m_spaceGlyph; }
    Glyph zeroWidthSpaceGlyph() const { return m_zeroWidthSpaceGlyph; }
    bool isZeroWidthSpaceGlyph(Glyph glyph) const { return glyph == m_zeroWidthSpaceGlyph && glyph; }

    GlyphData glyphDataForCharacter(char32_t) const;
    Glyph glyphForCharacter(char32_t) const;
    bool supportsCodePoint(char32_t) const;
    bool platformSupportsCodePoint(char32_t, std::optional<char32_t> variation = std::nullopt) const;

    RefPtr<Font> systemFallbackFontForCharacterCluster(StringView, const FontDescription&, ResolvedEmojiPolicy, IsForPlatformFont) const;

    const GlyphPage* glyphPage(unsigned pageNumber) const;

    void determinePitch();
    PitchType pitch() const { return m_treatAsFixedPitch ? PitchType::Fixed : PitchType::Variable; }
    bool canTakeFixedPitchFastContentMeasuring() const { return m_canTakeFixedPitchFastContentMeasuring; }

    Origin origin() const { return m_attributes.origin; }
    bool isInterstitial() const { return m_attributes.isInterstitial == IsInterstitial::Yes; }
    Visibility visibility() const { return m_attributes.visibility; }
    bool allowsAntialiasing() const { return m_allowsAntialiasing; }

#if !LOG_DISABLED
    String description() const;
#endif

#if PLATFORM(IOS_FAMILY) || PLATFORM(DRIFTSTACK)
    bool shouldNotBeUsedForArabic() const { return m_shouldNotBeUsedForArabic; };
#endif
#if USE(CORE_TEXT)
    CTFontRef ctFont() const { return m_platformData.ctFont(); }
    bool supportsSmallCaps() const;
    bool supportsAllSmallCaps() const;
    bool supportsPetiteCaps() const;
    bool supportsAllPetiteCaps() const;
    bool supportsOpenTypeAlternateHalfWidths() const;
#if ENABLE(MULTI_REPRESENTATION_HEIC)
    MultiRepresentationHEICMetrics metricsForMultiRepresentationHEIC() const;
#endif
#endif

#if USE(SKIA)
    sk_sp<SkTextBlob> buildTextBlob(std::span<const GlyphBufferGlyph>, std::span<const GlyphBufferAdvance>, FontSmoothingMode) const;
    bool enableAntialiasing(FontSmoothingMode) const;
#endif

    bool canRenderCombiningCharacterSequence(StringView) const;
    GlyphBufferAdvance applyTransforms(GlyphBuffer&, unsigned beginningGlyphIndex, unsigned beginningStringIndex, bool enableKerning, bool requiresShaping, const AtomString& locale, StringView text, TextDirection) const;

    // Returns nullopt if none of the glyphs are OT-SVG glyphs.
    std::optional<BitVector> findOTSVGGlyphs(std::span<const GlyphBufferGlyph>) const;

    bool hasAnyComplexColorFormatGlyphs(std::span<const GlyphBufferGlyph>) const;
#if USE(CORE_TEXT)
    WEBCORE_EXPORT static std::optional<Ref<Font>> fromIPCData(IPCFontData&&);
    WEBCORE_EXPORT IPCFontData toSerializableFont() const;
    WEBCORE_EXPORT std::optional<InstalledFont> toSerializableInstalledFont() const;
#endif
#if PLATFORM(WIN)
    SCRIPT_CACHE* scriptCache() const LIFETIME_BOUND { return &m_scriptCache; }
#endif

    void setIsUsedInSystemFallbackFontCache() { m_isUsedInSystemFallbackFontCache = true; }
    bool isUsedInSystemFallbackFontCache() const { return m_isUsedInSystemFallbackFontCache; }

    using Attributes = FontInternalAttributes;
    const Attributes& attributes() const LIFETIME_BOUND { return m_attributes; }

    ColorGlyphType colorGlyphType(Glyph) const;

#if PLATFORM(DRIFTSTACK)
    // V-090 / Phase F.1.B-1: glyph→codepoint reverse lookup for color
    // emoji atlas. Built at platformInit by walking the
    // DriftstackEmojiAtlas's codepoint list and querying the CTFont's
    // forward glyph map for each. Returns 0 if glyph is not a known
    // single-codepoint color emoji.
    char32_t driftstackCodepointForColorGlyph(Glyph) const;
    // V-583.K-text Phase 3b: glyph→codepoint resolution for atlas substitution.
    // Returns 0 if glyph is not in atlas reverse-map. Lazy-builds reverse map
    // from DriftstackTextGlyphAtlas codepoint enumeration on first call.
    char32_t driftstackCodepointForTextGlyph(Glyph) const;
    // V-090 / Phase F.1.B-2: decoded atlas PNG → CGImageRef cache lookup.
    // pngBytes must remain valid for the lifetime of the returned image
    // (atlas mmap'd region — singleton lifetime is process lifetime).
    RetainPtr<CGImageRef> driftstackAtlasImageForCodepoint(uint32_t codepoint, uint32_t strikePPEM, std::span<const uint8_t> pngBytes) const;
    // V-583.K-text Phase 3d: decoded text-atlas PNG → CGImageRef cache lookup.
    // Same pattern as driftstackAtlasImageForCodepoint but keyed on (ptSize, cp)
    // for the text glyph atlas. Avoids repeated PNG decode on repeated glyph
    // renders (canvas fingerprint workloads invoke same glyph many times).
    RetainPtr<CGImageRef> driftstackTextAtlasImageForCodepoint(uint32_t codepoint, uint32_t ptSize, std::span<const uint8_t> pngBytes) const;
    // V-148-Complex: per-pair iphone-vs-mac kerning delta to apply to the
    // LEFT glyph's advance. Returns 0 if (font, size, leftCp, rightCp) not
    // in V-138 table, or if both kerning values match. Mac kerning is
    // computed via natural-vs-shaped using CTFontGetAdvancesForGlyphs.
    float driftstackPairKerningDelta(uint8_t leftCp, uint8_t rightCp, float macShapedAdvanceL) const;
#endif

private:
    WEBCORE_EXPORT Font(const FontPlatformData&, Origin, IsInterstitial, Visibility, IsOrientationFallback, std::optional<RenderingResourceIdentifier>);
    Font(IsSystemFallbackFontPlaceholder);

    void platformInit();
    void platformGlyphInit();
    void platformCharWidthInit();
    void NODELETE platformDestroy();

    void initCharWidths();

    RefPtr<Font> createFontWithoutSynthesizableFeatures() const;
    RefPtr<Font> createScaledFont(const FontDescription&, float scaleFactor) const;
    RefPtr<Font> platformCreateScaledFont(const FontDescription&, float scaleFactor) const;
    RefPtr<Font> createHalfWidthFont() const;
    RefPtr<Font> platformCreateHalfWidthFont() const;

    struct DerivedFonts;
    DerivedFonts& ensureDerivedFontData() const;

    FloatRect platformBoundsForGlyph(Glyph) const;
#if USE(CORE_TEXT) || USE(SKIA)
    Vector<FloatRect, inlineGlyphRunCapacity> platformBoundsForGlyphs(const Vector<Glyph, inlineGlyphRunCapacity>&) const;
#endif
    float platformWidthForGlyph(Glyph) const;
    Path platformPathForGlyph(Glyph) const;

#if PLATFORM(COCOA)
    class ComplexColorFormatGlyphs {
    public:
        static ComplexColorFormatGlyphs createWithNoRelevantTables();
        static ComplexColorFormatGlyphs createWithRelevantTablesAndGlyphCount(unsigned glyphCount);

        bool hasValueFor(Glyph) const;
        bool get(Glyph) const;
        void set(Glyph, bool value);

        bool hasRelevantTables() const { return m_hasRelevantTables; }

    private:
        static constexpr size_t bitForInitialized(Glyph glyphID) { return static_cast<size_t>(glyphID) * 2; }
        static constexpr size_t bitForValue(Glyph glyphID) { return static_cast<size_t>(glyphID) * 2 + 1; }
        static constexpr size_t bitsRequiredForGlyphCount(unsigned glyphCount) { return glyphCount * 2; }

        ComplexColorFormatGlyphs(bool hasRelevantTables, unsigned glyphCount)
            : m_hasRelevantTables(hasRelevantTables)
            , m_bits(bitsRequiredForGlyphCount(glyphCount))
        { }

        bool m_hasRelevantTables;
        BitVector m_bits; // pairs of (initialized, value) bits
    };

    const PAL::OTSVGTable& otSVGTable() const;
    bool glyphHasComplexColorFormat(Glyph) const;
    bool hasComplexColorFormatTables() const;
    ComplexColorFormatGlyphs& glyphsWithComplexColorFormat() const;
#endif

    FontMetrics m_fontMetrics;
    float m_maxCharWidth { -1 };
    float m_avgCharWidth { -1 };

    const FontPlatformData m_platformData;

    mutable HashMap<unsigned, RefPtr<GlyphPage>, IntHash<unsigned>, WTF::UnsignedWithZeroKeyHashTraits<unsigned>> m_glyphPages;
    mutable GlyphMetricsMap<float> m_glyphToWidthMap;
    mutable std::unique_ptr<GlyphMetricsMap<FloatRect>> m_glyphToBoundsMap;
    // FIXME: Find a more efficient way to represent std::optional<Path>.
    mutable std::unique_ptr<GlyphMetricsMap<std::optional<Path>>> m_glyphPathMap;
    mutable BitVector m_codePointSupport;

#if ENABLE(MATHML)
    mutable RefPtr<OpenTypeMathData> m_mathData;
#endif
#if ENABLE(OPENTYPE_VERTICAL)
    RefPtr<OpenTypeVerticalData> m_verticalData;
#endif

    Attributes m_attributes;

    struct DerivedFonts {
        WTF_DEPRECATED_MAKE_STRUCT_FAST_ALLOCATED(DerivedFonts);
    public:

        RefPtr<Font> smallCapsFont;
        RefPtr<Font> noSynthesizableFeaturesFont;
        RefPtr<Font> emphasisMarkFont;
        RefPtr<Font> brokenIdeographFont;
        RefPtr<Font> verticalRightOrientationFont;
        RefPtr<Font> uprightOrientationFont;
        RefPtr<Font> invisibleFont;
        RefPtr<Font> halfWidthFont;
    };

    mutable std::unique_ptr<DerivedFonts> m_derivedFontData;

    struct NoEmojiGlyphs { };
#if USE(SKIA)
    struct AllEmojiGlyphs { };
#endif
    struct SomeEmojiGlyphs {
        BitVector colorGlyphs;
    };
#if USE(SKIA)
    using EmojiType = Variant<NoEmojiGlyphs, AllEmojiGlyphs, SomeEmojiGlyphs>;
#else
    using EmojiType = Variant<NoEmojiGlyphs, SomeEmojiGlyphs>;
#endif
    EmojiType m_emojiType { NoEmojiGlyphs { } };

#if PLATFORM(DRIFTSTACK)
    // V-090 / Phase F.1.B-1: glyph→codepoint reverse map for the subset
    // of color glyphs covered by DriftstackEmojiAtlas. Populated lazily.
    mutable HashMap<unsigned, char32_t, IntHash<unsigned>, WTF::UnsignedWithZeroKeyHashTraits<unsigned>> m_driftstackEmojiReverseMap;
    mutable bool m_driftstackEmojiReverseMapBuilt { false };
    // V-090 / Phase F.1.B-2: per-(codepoint, strike) decoded PNG → CGImage cache.
    // Key encoding: (uint64_t)codepoint << 32 | strikePPEM. WTF::Lock-protected.
    mutable HashMap<uint64_t, RetainPtr<CGImageRef>, IntHash<uint64_t>, WTF::UnsignedWithZeroKeyHashTraits<uint64_t>> m_driftstackAtlasImageCache;
    mutable Lock m_driftstackAtlasImageCacheLock;
    // V-583.K-text Phase 3d: per-(ptSize, codepoint) decoded text-atlas PNG → CGImage cache.
    // Key encoding: (uint64_t)ptSize << 32 | codepoint. WTF::Lock-protected.
    // Disjoint key space from emoji atlas cache (text atlas covers
    // ASCII/CJK/Arabic/Devanagari, emoji atlas covers color emoji codepoints).
    mutable HashMap<uint64_t, RetainPtr<CGImageRef>, IntHash<uint64_t>, WTF::UnsignedWithZeroKeyHashTraits<uint64_t>> m_driftstackTextAtlasImageCache;
    mutable Lock m_driftstackTextAtlasImageCacheLock;
    // V-121 closure: glyph→ASCII-codepoint reverse map for the subset of glyphs
    // in U+0020..U+007E. Used by Font::platformWidthForGlyph to look up
    // iPhone reference widths from DriftstackAsciiAdvanceTable. Populated
    // lazily; ~95 entries per font, one CTFontGetGlyphsForCharacters call
    // per codepoint at first use.
    mutable HashMap<unsigned, char32_t, IntHash<unsigned>, WTF::UnsignedWithZeroKeyHashTraits<unsigned>> m_driftstackAsciiReverseMap;
    mutable bool m_driftstackAsciiReverseMapBuilt { false };
    // V-583.K-text Phase 3b: glyph→codepoint reverse map for all codepoints
    // covered by DriftstackTextGlyphAtlas (ASCII + CJK + Arabic + Devanagari).
    // Populated lazily on first text-render-with-atlas access; iterates atlas's
    // codepoint set and queries CTFont for glyph mapping.
    mutable HashMap<unsigned, char32_t, IntHash<unsigned>, WTF::UnsignedWithZeroKeyHashTraits<unsigned>> m_driftstackTextGlyphReverseMap;
    mutable bool m_driftstackTextGlyphReverseMapBuilt { false };
#endif

#if PLATFORM(COCOA)
    mutable std::optional<PAL::OTSVGTable> m_otSVGTable;
    mutable std::optional<ComplexColorFormatGlyphs> m_glyphsWithComplexColorFormat; // SVG and sbix

    enum class SupportsFeature : uint8_t {
        No,
        Yes,
        Unknown
    };
    mutable SupportsFeature m_supportsSmallCaps { SupportsFeature::Unknown };
    mutable SupportsFeature m_supportsAllSmallCaps { SupportsFeature::Unknown };
    mutable SupportsFeature m_supportsPetiteCaps { SupportsFeature::Unknown };
    mutable SupportsFeature m_supportsAllPetiteCaps { SupportsFeature::Unknown };
    mutable SupportsFeature m_supportsOpenTypeAlternateHalfWidths { SupportsFeature::Unknown };
#endif

#if PLATFORM(WIN)
    mutable SCRIPT_CACHE m_scriptCache { 0 };
#endif

    Glyph m_spaceGlyph { 0 };
    Glyph m_zeroWidthSpaceGlyph { 0 };

    float m_spaceWidth { 0 };
    float m_syntheticBoldOffset { 0 };

    unsigned m_treatAsFixedPitch : 1;
    unsigned m_canTakeFixedPitchFastContentMeasuring : 1 { false };
    unsigned m_isBrokenIdeographFallback : 1;
    unsigned m_hasVerticalGlyphs : 1;

    unsigned m_isUsedInSystemFallbackFontCache : 1;
    
    unsigned m_allowsAntialiasing : 1;

    unsigned m_isSystemFontFallbackPlaceholder : 1 { false };

#if PLATFORM(IOS_FAMILY) || PLATFORM(DRIFTSTACK)
    unsigned m_shouldNotBeUsedForArabic : 1;
#endif

    // Adding any non-derived information to Font needs a parallel change in WebCoreArgumentCoders.cpp.
};

#if PLATFORM(IOS_FAMILY) || PLATFORM(DRIFTSTACK)
bool fontFamilyShouldNotBeUsedForArabic(CFStringRef);
#endif

#if !LOG_DISABLED
WEBCORE_EXPORT TextStream& operator<<(TextStream&, const Font&);
TextStream& operator<<(TextStream&, const GlyphBuffer&);
#endif

} // namespace WebCore
