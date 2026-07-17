/*
 * Copyright (C) 2017-2023 Apple Inc. All rights reserved.
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
#include "FontFamilySpecificationCoreText.h"

#include "FontCache.h"
#include "FontCascadeDescription.h"
#include "FontFamilySpecificationCoreTextCache.h"
#include "FontSelector.h"
#include "StyleFontSizeFunctions.h"
#include "UnrealizedCoreTextFont.h"
#include <pal/spi/cf/CoreTextSPI.h>
#include <wtf/HashFunctions.h>
#include <wtf/HashMap.h>

#include <CoreText/CoreText.h>

namespace WebCore {

#if PLATFORM(DRIFTSTACK)
static bool driftstackIsLegacyCJKDisplayFont(CTFontRef font)
{
    if (!font)
        return false;
    RetainPtr family = adoptCF(CTFontCopyFamilyName(font));
    if (!family || CFStringCompare(family.get(), CFSTR(".PingFang UI SC"), 0) != kCFCompareEqualTo)
        return false;
    RetainPtr postScriptName = adoptCF(CTFontCopyPostScriptName(font));
    return postScriptName && String(postScriptName.get()).startsWith(".PingFangUIDisplaySC-"_s);
}

static RetainPtr<CTFontRef> driftstackLegacyCJKDisplayFont(CGFontRef physicalFace, const FontCascadeDescription& description, CGFloat size)
{
    RetainPtr cascadeFont = adoptCF(CTFontCreateWithGraphicsFont(physicalFace, size, nullptr, nullptr));
    if (!driftstackIsLegacyCJKDisplayFont(cascadeFont.get()))
        return nullptr;
    if (description.shouldAllowUserInstalledFonts() == AllowUserInstalledFonts::No) {
        RetainPtr userInstalled = adoptCF(CTFontCopyAttribute(cascadeFont.get(), kCTFontUserInstalledAttribute));
        if (userInstalled.get() == kCFBooleanTrue)
            return nullptr;
    }
    return cascadeFont;
}
#endif

FontFamilySpecificationCoreText::FontFamilySpecificationCoreText(CTFontDescriptorRef fontDescriptor)
    : m_fontDescriptor(fontDescriptor)
{
}

#if PLATFORM(DRIFTSTACK)
FontFamilySpecificationCoreText::FontFamilySpecificationCoreText(CTFontDescriptorRef fontDescriptor, CGFontRef legacyCJKDisplayPhysicalFace)
    : m_fontDescriptor(fontDescriptor)
    , m_legacyCJKDisplayPhysicalFace(legacyCJKDisplayPhysicalFace)
{
}
#endif

FontFamilySpecificationCoreText::~FontFamilySpecificationCoreText() = default;

FontRanges FontFamilySpecificationCoreText::fontRanges(const FontCascadeDescription& fontDescription) const
{
    auto size = fontDescription.computedSize();
#if PLATFORM(DRIFTSTACK)
    if (m_legacyCJKDisplayPhysicalFace) {
        // This physical face was explicitly injected for the primary legacy
        // -apple-system cascade. Keep it out of the shared specification cache:
        // an equivalent descriptor can occur naturally in a later CSS family,
        // where ordinary optical-size preparation must remain intact.
        if (auto font = driftstackLegacyCJKDisplayFont(m_legacyCJKDisplayPhysicalFace.get(), fontDescription, size)) {
            static unsigned hitCount = 0;
            if (++hitCount <= 8)
                WTFLogAlways("[Driftstack-CJK-Display] Legacy system CJK Display cascade selected (%u so far); size=%.1f", hitCount, size);
            auto [syntheticBold, syntheticOblique] = computeNecessarySynthesis(font.get(), fontDescription, { }, ShouldComputePhysicalTraits::Yes).boldObliquePair();
            FontPlatformData platformData(font.get(), size, false, syntheticOblique, fontDescription.orientation(), fontDescription.widthVariant(), fontDescription.textRenderingMode());
            platformData.updateSizeWithFontSizeAdjust(fontDescription.fontSizeAdjust(), fontDescription.computedSize());
            return FontRanges(protect(FontCache::forCurrentThread())->fontForPlatformData(platformData));
        }
    }
#endif
    auto& originalPlatformData = FontFamilySpecificationCoreTextCache::forCurrentThread().ensure(FontFamilySpecificationKey(m_fontDescriptor.get(), fontDescription), [&]() {
        // FIXME: Stop creating this unnecessary CTFont once rdar://problem/105508842 is fixed.
        UnrealizedCoreTextFont unrealizedFont = { adoptCF(CTFontCreateWithFontDescriptor(m_fontDescriptor.get(), size, nullptr)) };
        unrealizedFont.setSize(size);

        auto font = preparePlatformFont(WTF::move(unrealizedFont), fontDescription, { }, FontTypeForPreparation::SystemFont);

        auto [syntheticBold, syntheticOblique] = computeNecessarySynthesis(font.get(), fontDescription, { }, ShouldComputePhysicalTraits::Yes).boldObliquePair();

        auto platformData = makeUnique<FontPlatformData>(font.get(), size, false, syntheticOblique, fontDescription.orientation(), fontDescription.widthVariant(), fontDescription.textRenderingMode());
        platformData->updateSizeWithFontSizeAdjust(fontDescription.fontSizeAdjust(), fontDescription.computedSize());
        return platformData;
    });

    return FontRanges(protect(FontCache::forCurrentThread())->fontForPlatformData(originalPlatformData));
}

}
