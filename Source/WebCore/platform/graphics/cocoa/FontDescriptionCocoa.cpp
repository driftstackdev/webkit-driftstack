/*
 * Copyright (C) 2017-2025 Apple Inc. All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY APPLE INC. ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL APPLE INC. OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"
#include "FontCascadeDescription.h"
#include "Logging.h"
#include "SystemFontDatabaseCoreText.h"

#if PLATFORM(DRIFTSTACK)
#include <cstdlib>
#include <string_view>
#endif

namespace WebCore {

#if PLATFORM(DRIFTSTACK)
static bool driftstackUsesLegacyCJKDisplayCascade(const FontCascadeDescription& description, const AtomString& cssFamily, bool isPrimaryFamily)
{
    const char* enabled = getenv("DRIFTSTACK_TRACK7_CANDIDATE_D");
    if (!enabled || std::string_view(enabled) != "1"
        || !isPrimaryFamily
        || cssFamily != "-apple-system"_s
        || description.familyCount() < 1
        || description.firstFamily().name != "-apple-system"_s
        || description.weight() != normalWeightValue()
        || description.width() != normalWidthValue()
        || description.fontStyleSlope()
        || description.fontStyleAxis() != FontStyleAxis::normal
        || !description.featureSettings().isEmpty()
        || !description.variationSettings().isEmpty()
        || !description.variantSettings().isAllNormal()
        || description.shouldDisableLigaturesForSpacing()
        || description.textRenderingMode() != TextRenderingMode::Auto
        || description.fontPalette().type != FontPalette::Type::Normal
        || description.opticalSizing() != FontOpticalSizing::Auto
        || !description.fontSizeAdjust().isNone())
        return false;

    const char* archetype = getenv("DRIFTSTACK_ARCHETYPE");
    if (!archetype || !archetype[0])
        return false;
    std::string_view value(archetype);
    constexpr std::string_view safariMarker = "_safari";
    auto position = value.rfind(safariMarker);
    if (position == std::string_view::npos)
        return false;
    position += safariMarker.size();
    auto majorStart = position;
    int major = 0;
    while (position < value.size() && value[position] >= '0' && value[position] <= '9') {
        if (major <= 25)
            major = major * 10 + value[position] - '0';
        ++position;
    }
    if (position == majorStart || position >= value.size() || value[position++] != '_')
        return false;
    auto minorStart = position;
    while (position < value.size() && value[position] >= '0' && value[position] <= '9')
        ++position;
    if (position == minorStart || position != value.size())
        return false;
    return major > 0 && major < 26;
}

static bool driftstackIsLegacyCJKDisplayFontForCascadeInsertion(CTFontRef font)
{
    if (!font)
        return false;
    RetainPtr family = adoptCF(CTFontCopyFamilyName(font));
    if (!family || CFStringCompare(family.get(), CFSTR(".PingFang UI SC"), 0) != kCFCompareEqualTo)
        return false;
    RetainPtr postScriptName = adoptCF(CTFontCopyPostScriptName(font));
    return postScriptName && String(postScriptName.get()).startsWith(".PingFangUIDisplaySC-"_s);
}

static RetainPtr<CTFontDescriptorRef> driftstackLegacyCJKDisplayDescriptor(const FontCascadeDescription& description, AllowUserInstalledFonts allowUserInstalledFonts, RetainPtr<CGFontRef>& physicalFace)
{
    RetainPtr<CFStringRef> localeString;
    if (!description.computedLocale().isEmpty())
        localeString = description.computedLocale().string().createCFString();
    RetainPtr systemFont = adoptCF(CTFontCreateUIFontForLanguage(kCTFontUIFontSystem, 20, localeString.get()));
    if (!systemFont)
        return nullptr;

    constexpr UTF16Char representativeHanCharacter = 0x4E2D;
    CFIndex coveredLength = 0;
    auto fallbackOption = allowUserInstalledFonts == AllowUserInstalledFonts::No ? kCTFontFallbackOptionSystem : kCTFontFallbackOptionDefault;
    RetainPtr displayAt20 = adoptCF(CTFontCreateForCharactersWithLanguageAndOption(systemFont.get(), &representativeHanCharacter, 1, localeString.get(), fallbackOption, &coveredLength));
    if (coveredLength != 1 || !driftstackIsLegacyCJKDisplayFontForCascadeInsertion(displayAt20.get()))
        return nullptr;

    // CoreText's policy descriptor reselects PingFang Text when realized below
    // 20px. Hold the capture-proven physical face instead, and recreate the
    // requested size from its CGFont so optical policy cannot change the face.
    RetainPtr displayPhysicalFace = adoptCF(CTFontCopyGraphicsFont(displayAt20.get(), nullptr));
    if (!displayPhysicalFace)
        return nullptr;
    RetainPtr displayAtTargetSize = adoptCF(CTFontCreateWithGraphicsFont(displayPhysicalFace.get(), description.computedSize(), nullptr, nullptr));
    if (!driftstackIsLegacyCJKDisplayFontForCascadeInsertion(displayAtTargetSize.get()))
        return nullptr;
    if (allowUserInstalledFonts == AllowUserInstalledFonts::No) {
        RetainPtr userInstalled = adoptCF(CTFontCopyAttribute(displayAtTargetSize.get(), kCTFontUserInstalledAttribute));
        if (userInstalled.get() == kCFBooleanTrue)
            return nullptr;
    }
    RetainPtr descriptor = adoptCF(CTFontCopyFontDescriptor(displayAtTargetSize.get()));
    if (!descriptor)
        return nullptr;
    physicalFace = WTF::move(displayPhysicalFace);
    return descriptor;
}
#endif

struct SystemFontCascadeList {
    Vector<RetainPtr<CTFontDescriptorRef>> descriptors;
#if PLATFORM(DRIFTSTACK)
    bool hasLegacyCJKDisplayDescriptor { false };
    unsigned legacyCJKDisplayDescriptorIndex { 0 };
    RetainPtr<CGFontRef> legacyCJKDisplayPhysicalFace;
#endif
};

static inline SystemFontCascadeList systemFontCascadeList(const FontCascadeDescription& description, const AtomString& cssFamily, SystemFontKind systemFontKind, AllowUserInstalledFonts allowUserInstalledFonts, bool isPrimaryFamily)
{
    SystemFontCascadeList result;
    result.descriptors = SystemFontDatabaseCoreText::forCurrentThread().cascadeList(description, cssFamily, systemFontKind, allowUserInstalledFonts);
#if PLATFORM(DRIFTSTACK)
    if (!driftstackUsesLegacyCJKDisplayCascade(description, cssFamily, isPrimaryFamily))
        return result;

    // Put the physical Display face immediately after the primary system font,
    // ahead of CoreText's policy descriptors. The ordinary simplified-Chinese
    // descriptor can be sourced from Display at 20px yet reselect Text when it
    // is realized below 20px; retaining the physical face prevents that switch.
    if (!result.descriptors.isEmpty()) {
        RetainPtr<CGFontRef> physicalFace;
        if (auto descriptor = driftstackLegacyCJKDisplayDescriptor(description, allowUserInstalledFonts, physicalFace)) {
            result.descriptors.insert(1, WTF::move(descriptor));
            result.hasLegacyCJKDisplayDescriptor = true;
            result.legacyCJKDisplayDescriptorIndex = 1;
            result.legacyCJKDisplayPhysicalFace = WTF::move(physicalFace);
        }
    }
#endif
    UNUSED_PARAM(isPrimaryFamily);
    return result;
}

unsigned FontCascadeDescription::effectiveFamilyCount() const
{
    // FIXME: Move all the other system font keywords from fontDescriptorWithFamilySpecialCase() to here.
    unsigned result = 0;
    for (unsigned i = 0; i < familyCount(); ++i) {
        const auto& family = familyAt(i);
        if (auto use = SystemFontDatabaseCoreText::forCurrentThread().matchSystemFontUse(family.name))
            result += systemFontCascadeList(*this, family.name, *use, shouldAllowUserInstalledFonts(), !i).descriptors.size();
        else
            ++result;
    }
    return result;
}

FontFamilySpecification FontCascadeDescription::effectiveFamilyAt(unsigned index) const
{
    // The special cases in this function need to match the behavior in FontCacheCoreText.cpp. This code
    // is used for regular (element style) lookups, and the code in FontDescriptionCocoa.cpp is used when
    // src:local(special-cased-name) is specified inside an @font-face block.
    // FIXME: Currently, an @font-face block corresponds to a single item in the font-family: fallback list, which
    // means that "src:local(system-ui)" can't follow the Core Text cascade list (the way it does for regular lookups).
    // These two behaviors should be unified, which would hopefully allow us to delete this duplicate code.
    for (unsigned i = 0; i < familyCount(); ++i) {
        const auto& family = familyAt(i);
        if (auto use = SystemFontDatabaseCoreText::forCurrentThread().matchSystemFontUse(family.name)) {
            auto cascadeList = systemFontCascadeList(*this, family.name, *use, shouldAllowUserInstalledFonts(), !i);
            if (index < cascadeList.descriptors.size()) {
#if PLATFORM(DRIFTSTACK)
                bool isLegacyCJKDisplayCascadeDescriptor = cascadeList.hasLegacyCJKDisplayDescriptor && index == cascadeList.legacyCJKDisplayDescriptorIndex;
                return FontFamilySpecification(FontFamilySpecificationCoreText(cascadeList.descriptors[index].get(), isLegacyCJKDisplayCascadeDescriptor ? cascadeList.legacyCJKDisplayPhysicalFace.get() : nullptr));
#else
                return FontFamilySpecification(cascadeList.descriptors[index].get());
#endif
            }
            index -= cascadeList.descriptors.size();
        }
        else if (!index)
            return family;
        else
            --index;
    }
    ASSERT_NOT_REACHED();
    return FontFamily { nullAtom(), FontFamilyKind::Specified };
}

AtomString FontDescription::platformResolveGenericFamily(UScriptCode script, const AtomString& locale, const AtomString& familyName)
{
    ASSERT((locale.isNull() && script == USCRIPT_COMMON) || !locale.isNull());
    if (script == USCRIPT_COMMON)
        return nullAtom();

    String result;
    // FIXME: Use the system font database to handle standardFamily
    if (familyName == serifFamily)
        result = SystemFontDatabaseCoreText::forCurrentThread().serifFamily(locale.string());
    else if (familyName == sansSerifFamily)
        result = SystemFontDatabaseCoreText::forCurrentThread().sansSerifFamily(locale.string());
    else if (familyName == cursiveFamily)
        result = SystemFontDatabaseCoreText::forCurrentThread().cursiveFamily(locale.string());
    else if (familyName == fantasyFamily)
        result = SystemFontDatabaseCoreText::forCurrentThread().fantasyFamily(locale.string());
    else if (familyName == monospaceFamily)
        result = SystemFontDatabaseCoreText::forCurrentThread().monospaceFamily(locale.string());
    else
        return nullAtom();

    // Per CTFont.h: "Any font name beginning with a '.' is reserved for the system" and should be
    // created using CTFontCreateUIFontForLanguage() or similar APIs, not through standard font lookup.
    // CoreText sometimes returns these system-internal font names (e.g., ".Times Fallback") when
    // resolving CSS generic families for certain locales (rdar://139338599). Since WebKit's font
    // lookup cannot properly handle these reserved names, we reject them and fall back to
    // settings-based resolution instead.
    auto isValidFontName = [](const String& fontName) {
        if (fontName.isEmpty())
            return false;
        if (fontName.startsWith('.')) {
            LOG(Fonts, "CoreText returned reserved font name '%s'; using settings-based font resolution instead", fontName.utf8().data());
            return false;
        }
        return true;
    };

    if (!isValidFontName(result))
        return nullAtom();

    return AtomString { result };
}

}
