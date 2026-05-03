/*
 * Copyright (C) 2015-2026 Apple Inc. All rights reserved.
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
#include "FontCache.h"

#include "Color.h"
#include "Font.h"
#include "FontCascadeDescription.h"
#include "FontCreationContext.h"
#include "FontCustomPlatformData.h"
#include "FontDatabase.h"
#include "FontFamilySpecificationCoreText.h"
#include "FontInterrogation.h"
#include "FontMetricsNormalization.h"
#include "FontPaletteValues.h"
#include "Logging.h"
#include "StyleFontSizeFunctions.h"
#include "SystemFontDatabaseCoreText.h"
#include "UnrealizedCoreTextFont.h"
#include <CoreText/SFNTLayoutTypes.h>
#include <array>
#include <pal/spi/cf/CoreTextSPI.h>
#include <pal/spi/cocoa/AccessibilitySupportSPI.h>
#if PLATFORM(DRIFTSTACK)
#include <dirent.h>
#include <string>
#include <sys/stat.h>
#endif
#include <wtf/HashSet.h>
#include <wtf/Lock.h>
#include <wtf/MainThread.h>
#include <wtf/MemoryPressureHandler.h>
#include <wtf/NeverDestroyed.h>
#include <wtf/RobinHoodHashMap.h>
#include <wtf/URLHash.h>
#include <wtf/cf/NotificationCenterCF.h>
#include <wtf/cf/TypeCastsCF.h>
#include <wtf/cocoa/RuntimeApplicationChecksCocoa.h>

namespace WebCore {

bool fontNameIsSystemFont(CFStringRef fontName)
{
    return CFStringGetLength(fontName) > 0 && CFStringGetCharacterAtIndex(fontName, 0) == '.';
}

#if PLATFORM(DRIFTSTACK)
// Stage B Step 2/3: lazily-initialized map of lowercase iOS font-family-name
// -> file URL. Populated on first font lookup by walking DRIFTSTACK_FONTS_DIR
// and reading kCTFontFamilyNameAttribute from each font binary. Used by
// fontWithFamily on Driftstack to bypass CTFont's name-based lookup (which
// returns Mac's system font for "Helvetica" et al. even when iOS variants
// are also process-registered) and instead create a CTFont directly from
// the iOS file URL via CTFontManagerCreateFontDescriptorsFromURL. This is
// what makes iOS Helvetica's font metrics actually win over Mac's in
// canvas measureText output.
//
// FontCacheCoreText.cpp is plain C++ (not Obj-C++), so this function uses
// POSIX dirent + CoreFoundation C APIs only — no NSFileManager / @autoreleasepool.

static Lock driftstackIOSFontMapLock;

// V-086 Track 4 fix: nested map structure family → list of (style traits, URL).
// Each iOS font binary has a kCTFontStyleNameAttribute (Regular / Bold / Italic /
// Bold Italic / etc.) and kCTFontTraitsAttribute with weight + slant. We index
// every variant and pick the closest match at lookup time per the requested
// FontDescription's weight + italic.
struct DriftstackIOSFontVariant {
    RetainPtr<CFURLRef> url;
    float weight { 0.f };          // CTFontWeight: -1.0 (ultralight) … 0 (regular) … 1.0 (heavy)
    bool italic { false };
    String styleName;              // for diagnostics
};

static MemoryCompactRobinHoodHashMap<String, Vector<DriftstackIOSFontVariant>>& driftstackIOSFontMap() WTF_REQUIRES_LOCK(driftstackIOSFontMapLock)
{
    static NeverDestroyed<MemoryCompactRobinHoodHashMap<String, Vector<DriftstackIOSFontVariant>>> map;
    return map.get();
}

static bool driftstackIOSFontMapInitialized WTF_GUARDED_BY_LOCK(driftstackIOSFontMapLock) = false;

static void driftstackWalkFontDir(const std::string& root, MemoryCompactRobinHoodHashMap<String, Vector<DriftstackIOSFontVariant>>& map, size_t& mappedCount, size_t& parseFailedCount)
{
    DIR* dir = opendir(root.c_str());
    if (!dir)
        return;

    while (struct dirent* entry = readdir(dir)) {
        if (entry->d_name[0] == '.')
            continue;
        // Use WTF::String for safe extension comparison (avoids -Wunsafe-buffer-usage
        // -in-libc-call from strlen/strcasecmp/etc.).
        String name = String::fromUTF8(unsafeSpan(entry->d_name));
        std::string fullPath = root + "/" + name.utf8().data();

        if (entry->d_type == DT_DIR) {
            driftstackWalkFontDir(fullPath, map, mappedCount, parseFailedCount);
            continue;
        }

        if (!name.endsWithIgnoringASCIICase(".ttf"_s)
            && !name.endsWithIgnoringASCIICase(".ttc"_s)
            && !name.endsWithIgnoringASCIICase(".otf"_s))
            continue;

        RetainPtr<CFStringRef> pathCF = adoptCF(CFStringCreateWithCString(kCFAllocatorDefault, fullPath.c_str(), kCFStringEncodingUTF8));
        RetainPtr<CFURLRef> fontURL = adoptCF(CFURLCreateWithFileSystemPath(kCFAllocatorDefault, pathCF.get(), kCFURLPOSIXPathStyle, false));
        if (!fontURL)
            continue;

        // Process-scope registration so CTFont creation paths can resolve the binary.
        CFErrorRef regError = nullptr;
        CTFontManagerRegisterFontsForURL(fontURL.get(), kCTFontManagerScopeProcess, &regError);
        if (regError)
            CFRelease(regError);

        // Read all variants in the binary (.ttc collections may contain multiple)
        // and add each (family, weight, italic) tuple into the map.
        RetainPtr<CFArrayRef> descs = adoptCF(CTFontManagerCreateFontDescriptorsFromURL(fontURL.get()));
        if (!descs) {
            ++parseFailedCount;
            continue;
        }
        CFIndex count = CFArrayGetCount(descs.get());
        for (CFIndex i = 0; i < count; ++i) {
            CTFontDescriptorRef desc = static_cast<CTFontDescriptorRef>(CFArrayGetValueAtIndex(descs.get(), i));
            RetainPtr<CFStringRef> familyCF = adoptCF(static_cast<CFStringRef>(CTFontDescriptorCopyAttribute(desc, kCTFontFamilyNameAttribute)));
            if (!familyCF)
                continue;
            String family = String(familyCF.get()).convertToASCIILowercase();
            if (family.isEmpty())
                continue;

            // Read weight + slant from kCTFontTraitsAttribute (NSDictionary).
            DriftstackIOSFontVariant variant;
            variant.url = fontURL;
            variant.weight = 0.f;
            variant.italic = false;

            RetainPtr<CFDictionaryRef> traits = adoptCF(static_cast<CFDictionaryRef>(CTFontDescriptorCopyAttribute(desc, kCTFontTraitsAttribute)));
            if (traits) {
                CFNumberRef weightNum = static_cast<CFNumberRef>(CFDictionaryGetValue(traits.get(), kCTFontWeightTrait));
                if (weightNum)
                    CFNumberGetValue(weightNum, kCFNumberFloatType, &variant.weight);
                CFNumberRef slantNum = static_cast<CFNumberRef>(CFDictionaryGetValue(traits.get(), kCTFontSlantTrait));
                if (slantNum) {
                    float slant = 0.f;
                    CFNumberGetValue(slantNum, kCFNumberFloatType, &slant);
                    variant.italic = slant > 0.01f;
                }
            }

            RetainPtr<CFStringRef> styleCF = adoptCF(static_cast<CFStringRef>(CTFontDescriptorCopyAttribute(desc, kCTFontStyleNameAttribute)));
            if (styleCF)
                variant.styleName = String(styleCF.get());

            auto& variants = map.ensure(family, [] { return Vector<DriftstackIOSFontVariant> { }; }).iterator->value;
            // Avoid duplicates from the same .ttf being descriptor-walked twice.
            // V-091 fix: include styleName in dup-detection so .ttc files with
            // multiple faces sharing weight + italic but differing in styleName
            // (e.g., iOS Papyrus.ttc face 0 Condensed + face 1 Regular both at
            // weight=0 italic=false) all end up registered.
            bool dup = false;
            for (const auto& v : variants) {
                if (CFEqual(v.url.get(), variant.url.get()) && v.italic == variant.italic
                    && std::abs(v.weight - variant.weight) < 0.01f
                    && v.styleName == variant.styleName) {
                    dup = true;
                    break;
                }
            }
            if (!dup) {
                variants.append(WTF::move(variant));
                ++mappedCount;
            }
        }
    }
    closedir(dir);
}

// V-090 Track 4 Phase 4.D: Apple's per-family CSS-weight → styleName mapping.
// Mac's reading of iOS .ttc font traits doesn't always match iPhone's
// per-CSS-weight font-face selection; for the 3 fonts where Mac picks a
// different face than iPhone at any CSS weight, encode the empirical
// iPhone mapping explicitly. Italic CSS requests reuse the upright face
// for these families (empirical: iPhone has no italic variant — italic CSS
// produces identical metrics).
static String preferredIOSStyleForFamily(const String& lowercaseFamily, int cssWeight)
{
    if (lowercaseFamily == "hiragino sans"_s) {
        if (cssWeight <= 300) return "W3"_s;
        if (cssWeight == 400) return "W4"_s;
        if (cssWeight == 500) return "W5"_s;
        if (cssWeight == 600) return "W6"_s;
        if (cssWeight == 700) return "W7"_s;
        return "W8"_s; // CSS 800 + 900 → W8 (heaviest available in HiraginoKakuGothic.ttc)
    }
    if (lowercaseFamily == "marker felt"_s)
        return cssWeight < 600 ? "Thin"_s : "Wide"_s;
    if (lowercaseFamily == "papyrus"_s)
        return cssWeight < 600 ? "Regular"_s : "Condensed"_s;
    return String();
}

static void initializeDriftstackIOSFontMapIfNeeded()
{
    Locker locker(driftstackIOSFontMapLock);
    if (driftstackIOSFontMapInitialized)
        return;
    driftstackIOSFontMapInitialized = true;

    const char* envDir = getenv("DRIFTSTACK_FONTS_DIR");
    std::string root = envDir ? envDir : "/Users/john/code/driftstack-fonts/iphone16pro-ios26.4.1";

    struct stat st;
    if (stat(root.c_str(), &st) != 0 || !S_ISDIR(st.st_mode)) {
        WTFLogAlways("[Driftstack] FontCache: iOS fonts dir not found at %s — skipping override map population", root.c_str());
        return;
    }

    size_t mapped = 0;
    size_t parseFailed = 0;
    driftstackWalkFontDir(root, driftstackIOSFontMap(), mapped, parseFailed);
    WTFLogAlways("[Driftstack] FontCache: %zu families mapped to iOS font binaries (parseFailed=%zu, dir=%s)", mapped, parseFailed, root.c_str());
}

static RetainPtr<CTFontRef> driftstackIOSFontWithFamily(const AtomString& family, const FontDescription& fontDescription, float size)
{
    if (family.isEmpty())
        return nullptr;
    initializeDriftstackIOSFontMapIfNeeded();

    String lowercase = family.string().convertToASCIILowercase();

    // V-088 Track 4 Pattern 2: redirect family names that aren't installed
    // on iOS to the iOS system fallback iPhone uses. Empirically verified
    // (V-085 capture data) iPhone falls back to Helvetica for these
    // family names (identical width=160.0625 / fBBA=14 / fBBD=4 metrics
    // when CSS asks for them on iPhone).
    if (lowercase == "kefa"_s
        || lowercase == "gujarati sangam mn"_s
        || lowercase == "oriya sangam mn"_s
        || lowercase == "plantagenet cherokee"_s
        || lowercase == "gurmukhi mn"_s)
        lowercase = "helvetica"_s;
    // V-098 Track 8: iOS system font (SFUI.ttf) registers under family
    // ".SF UI" via CoreText's platform-0 Unicode name (preferred over
    // the platform-3 'System Font' name). Empirical (V-099 cumulative):
    // ONLY -apple-system + system-ui resolve to this iOS system font
    // on iPhone (width 163.73 for the rig test string). The others
    // (BlinkMacSystemFont, SF Pro Text, SF Pro Display) resolve to
    // Helvetica on iPhone (width 160.0625 — same as a CSS sans-serif
    // fallback). Don't redirect those — they match iPhone via the
    // existing MISS → CSS fallback path.
    // V-099 Track 8 finding: -apple-system / system-ui CSS pseudo-families
    // bypass driftstackIOSFontWithFamily entirely (proven empirically across
    // builds #9-#15). Diagnostic redirect to "helvetica" had ZERO effect on
    // measured -apple-system width — function not entered for these names.
    // The CSS resolution layer maps -apple-system to a system font directly
    // via WebKit's higher-level FontCascadeDescription / font-family
    // resolution path. Track 8 fix requires WebCore CSS-resolution layer
    // modification, not FontCache layer. Surfaced for founder review.
    // Telugu has its own iOS font (Kohinoor Telugu) — different metrics
    // than Helvetica (w=162.31 vs 160.06 in iPhone reference); redirect
    // to the actual iOS Telugu font.
    else if (lowercase == "telugu sangam mn"_s)
        lowercase = "kohinoor telugu"_s;

    DriftstackIOSFontVariant chosenVariant;
    bool found = false;
    {
        Locker locker(driftstackIOSFontMapLock);
        auto it = driftstackIOSFontMap().find(lowercase);
        if (it == driftstackIOSFontMap().end()) {
            static unsigned missCount = 0;
            if (++missCount <= 8)
                WTFLogAlways("[Driftstack] FontCache: lookup MISS for family '%s' (lowercase='%s')", family.string().utf8().data(), lowercase.utf8().data());
            return nullptr;
        }
        const auto& variants = it->value;
        const float requestedWeight = (static_cast<float>(fontDescription.weight()) - 400.f) / 400.f; // 100 → -0.75; 400 → 0; 700 → 0.75; 900 → 1.25 → clamp 1.0
        const bool requestedItalic = isItalic(fontDescription.fontStyleSlope());

        // V-090 Track 4 Phase 4.D: try explicit per-family styleName override first.
        const int cssWeight = static_cast<int>(static_cast<float>(fontDescription.weight()));
        String preferredStyle = preferredIOSStyleForFamily(lowercase, cssWeight);
        if (!preferredStyle.isEmpty()) {
            for (const auto& v : variants) {
                if (v.styleName == preferredStyle) {
                    chosenVariant = v;
                    found = true;
                    break;
                }
            }
        }

        if (!found) {
            // V-086 Track 4 fix: pick the variant whose (weight, italic)
            // is closest to the requested FontDescription. Convert the
            // request's weight/italic into CTFont's [-1, 1] weight scale
            // and slant boolean.
            float bestScore = std::numeric_limits<float>::infinity();
            for (const auto& v : variants) {
                float italicMismatch = (v.italic != requestedItalic) ? 1.0f : 0.0f;
                float weightDelta = std::abs(v.weight - requestedWeight);
                // Italic mismatch is a hard cost; weight delta is soft.
                float score = italicMismatch * 10.0f + weightDelta;
                if (score < bestScore) {
                    bestScore = score;
                    chosenVariant = v;
                    found = true;
                }
            }
        }
    }
    if (!found)
        return nullptr;

    static unsigned hitCount = 0;
    if (++hitCount <= 100 || family == AtomString("Papyrus"_s)) {
        char pathBuf[1024] = {};
        if (chosenVariant.url) {
            RetainPtr<CFStringRef> urlPath = CFURLGetString(chosenVariant.url.get());
            if (urlPath)
                CFStringGetCString(urlPath.get(), pathBuf, sizeof(pathBuf), kCFStringEncodingUTF8);
        }
        WTFLogAlways("[Driftstack] FontCache: lookup HIT family='%s' weight=%d italic=%d size=%.1f → style='%s' URL=%s",
            family.string().utf8().data(),
            static_cast<int>(static_cast<float>(fontDescription.weight())),
            static_cast<int>(isItalic(fontDescription.fontStyleSlope())),
            size,
            chosenVariant.styleName.utf8().data(),
            pathBuf);
    }

    RetainPtr<CFArrayRef> descs = adoptCF(CTFontManagerCreateFontDescriptorsFromURL(chosenVariant.url.get()));
    if (!descs || !CFArrayGetCount(descs.get()))
        return nullptr;
    // For .ttc collections containing multiple variants, find the descriptor
    // whose family-name matches the requested family exactly AND whose
    // italic + weight matches our chosen variant. Falls back to the first
    // descriptor if no match.
    CTFontDescriptorRef chosen = nullptr;
    CFIndex count = CFArrayGetCount(descs.get());
    for (CFIndex i = 0; i < count; ++i) {
        CTFontDescriptorRef d = static_cast<CTFontDescriptorRef>(CFArrayGetValueAtIndex(descs.get(), i));
        RetainPtr<CFStringRef> familyCF = adoptCF(static_cast<CFStringRef>(CTFontDescriptorCopyAttribute(d, kCTFontFamilyNameAttribute)));
        if (!familyCF || String(familyCF.get()).convertToASCIILowercase() != lowercase)
            continue;
        // Match style by traits.
        RetainPtr<CFDictionaryRef> dTraits = adoptCF(static_cast<CFDictionaryRef>(CTFontDescriptorCopyAttribute(d, kCTFontTraitsAttribute)));
        float dWeight = 0.f; bool dItalic = false;
        if (dTraits) {
            CFNumberRef wn = static_cast<CFNumberRef>(CFDictionaryGetValue(dTraits.get(), kCTFontWeightTrait));
            if (wn) CFNumberGetValue(wn, kCFNumberFloatType, &dWeight);
            CFNumberRef sn = static_cast<CFNumberRef>(CFDictionaryGetValue(dTraits.get(), kCTFontSlantTrait));
            if (sn) {
                float s = 0.f;
                CFNumberGetValue(sn, kCFNumberFloatType, &s);
                dItalic = s > 0.01f;
            }
        }
        if (dItalic == chosenVariant.italic && std::abs(dWeight - chosenVariant.weight) < 0.01f) {
            // V-091 fix: also match by styleName when traits tie, so .ttc
            // files with multiple faces at identical (weight, italic) but
            // differing styleName (e.g., Papyrus.ttc Condensed/Regular)
            // resolve to the variant the override picked, not whichever
            // descriptor was enumerated first.
            RetainPtr<CFStringRef> styleCF = adoptCF(static_cast<CFStringRef>(CTFontDescriptorCopyAttribute(d, kCTFontStyleNameAttribute)));
            if (!styleCF || String(styleCF.get()) != chosenVariant.styleName)
                continue;
            chosen = d;
            break;
        }
    }
    if (!chosen)
        chosen = static_cast<CTFontDescriptorRef>(CFArrayGetValueAtIndex(descs.get(), 0));

    return adoptCF(CTFontCreateWithFontDescriptor(chosen, size, nullptr));
}
#endif // PLATFORM(DRIFTSTACK)

static RetainPtr<CFArrayRef> variationAxesWithNonLocalizedAxesNames(CTFontDescriptorRef fontDescriptor)
{
    // Reading kCTFontVariationAxesAttribute returns non localized axes names
    return adoptCF(static_cast<CFArrayRef>(CTFontDescriptorCopyAttribute(fontDescriptor, kCTFontVariationAxesAttribute)));
}

static RetainPtr<CFArrayRef> variationAxes(CTFontRef font, ShouldLocalizeAxisNames shouldLocalizeAxisNames)
{
    if (shouldLocalizeAxisNames == ShouldLocalizeAxisNames::Yes)
        return adoptCF(CTFontCopyVariationAxes(font));
    RetainPtr fontDescriptor = adoptCF(CTFontCopyFontDescriptor(font));
    return variationAxesWithNonLocalizedAxesNames(fontDescriptor.get());
}

VariationDefaultsMap defaultVariationValues(CTFontRef font, ShouldLocalizeAxisNames shouldLocalizeAxisNames)
{
    VariationDefaultsMap result;
    auto axes = variationAxes(font, shouldLocalizeAxisNames);
    if (!axes)
        return result;
    auto size = CFArrayGetCount(axes.get());
    for (CFIndex i = 0; i < size; ++i) {
        RetainPtr axis = static_cast<CFDictionaryRef>(CFArrayGetValueAtIndex(axes.get(), i));
        RetainPtr axisIdentifier = static_cast<CFNumberRef>(CFDictionaryGetValue(axis.get(), kCTFontVariationAxisIdentifierKey));
        String axisName = static_cast<CFStringRef>(CFDictionaryGetValue(axis.get(), kCTFontVariationAxisNameKey));
        RetainPtr defaultValue = static_cast<CFNumberRef>(CFDictionaryGetValue(axis.get(), kCTFontVariationAxisDefaultValueKey));
        RetainPtr minimumValue = static_cast<CFNumberRef>(CFDictionaryGetValue(axis.get(), kCTFontVariationAxisMinimumValueKey));
        RetainPtr maximumValue = static_cast<CFNumberRef>(CFDictionaryGetValue(axis.get(), kCTFontVariationAxisMaximumValueKey));
        uint32_t rawAxisIdentifier = 0;
        Boolean success = CFNumberGetValue(axisIdentifier.get(), kCFNumberSInt32Type, &rawAxisIdentifier);
        ASSERT_UNUSED(success, success);
        float rawDefaultValue = 0;
        float rawMinimumValue = 0;
        float rawMaximumValue = 0;
        CFNumberGetValue(defaultValue.get(), kCFNumberFloatType, &rawDefaultValue);
        CFNumberGetValue(minimumValue.get(), kCFNumberFloatType, &rawMinimumValue);
        CFNumberGetValue(maximumValue.get(), kCFNumberFloatType, &rawMaximumValue);

        if (rawMinimumValue > rawMaximumValue)
            std::swap(rawMinimumValue, rawMaximumValue);

        char b1 = rawAxisIdentifier >> 24;
        char b2 = (rawAxisIdentifier & 0xFF0000) >> 16;
        char b3 = (rawAxisIdentifier & 0xFF00) >> 8;
        char b4 = rawAxisIdentifier & 0xFF;
        FontTag resultKey = { { b1, b2, b3, b4 } };
        VariationDefaults resultValues = { axisName, rawDefaultValue, rawMinimumValue, rawMaximumValue };
        result.set(resultKey, resultValues);
    }
    return result;
}

static std::optional<bool>& NODELETE overrideEnhanceTextLegibility()
{
    static NeverDestroyed<std::optional<bool>> overrideEnhanceTextLegibility;
    return overrideEnhanceTextLegibility.get();
}

void setOverrideEnhanceTextLegibility(bool override)
{
    overrideEnhanceTextLegibility() = override;
}

static bool& platformShouldEnhanceTextLegibility()
{
    static NeverDestroyed<bool> shouldEnhanceTextLegibility = _AXSEnhanceTextLegibilityEnabled();
    return shouldEnhanceTextLegibility.get();
}

static inline bool shouldEnhanceTextLegibility()
{
    return overrideEnhanceTextLegibility().value_or(platformShouldEnhanceTextLegibility());
}

RetainPtr<CTFontRef> preparePlatformFont(UnrealizedCoreTextFont&& originalFont, const FontDescription& fontDescription, const FontCreationContext& fontCreationContext, FontTypeForPreparation fontTypeForPreparation, ApplyTraitsVariations applyTraitsVariations)
{
    originalFont.modifyFromContext(fontDescription, fontCreationContext, fontTypeForPreparation, applyTraitsVariations, shouldEnhanceTextLegibility());
    return originalFont.realize();
}

RefPtr<Font> FontCache::similarFont(const FontDescription& description, const String& family)
{
    // Attempt to find an appropriate font using a match based on the presence of keywords in
    // the requested names. For example, we'll match any name that contains "Arabic" to Geeza Pro.
    if (family.isEmpty())
        return nullptr;

#if PLATFORM(IOS_FAMILY)
    // Substitute the default monospace font for well-known monospace fonts.
    if (equalLettersIgnoringASCIICase(family, "monaco"_s) || equalLettersIgnoringASCIICase(family, "menlo"_s))
        return fontForFamily(description, "courier"_s);

    // Substitute Verdana for Lucida Grande.
    if (equalLettersIgnoringASCIICase(family, "lucida grande"_s))
        return fontForFamily(description, "verdana"_s);
#endif

    static constexpr auto matchWords = std::to_array<ASCIILiteral>({ "Arabic"_s, "Pashto"_s, "Urdu"_s });
    auto familyMatcher = StringView(family);
    for (auto matchWord : matchWords) {
        if (equalIgnoringASCIICase(familyMatcher, matchWord))
            return fontForFamily(description, isFontWeightBold(description.weight()) ? "GeezaPro-Bold"_s : "GeezaPro"_s);
    }
    return nullptr;
}

static void fontCacheRegisteredFontsChangedNotificationCallback(CFNotificationCenterRef, void* observer, CFStringRef, const void *, CFDictionaryRef)
{
    ASSERT_UNUSED(observer, isMainThread() && observer == &FontCache::forCurrentThread());

    ensureOnMainThread([] {
        FontCache::invalidateAllFontCaches();
    });
}

void FontCache::platformInit()
{
    CFNotificationCenterAddObserver(CFNotificationCenterGetLocalCenterSingleton(), this, &fontCacheRegisteredFontsChangedNotificationCallback, kCTFontManagerRegisteredFontsChangedNotification, nullptr, CFNotificationSuspensionBehaviorDeliverImmediately);

#if PLATFORM(IOS_FAMILY)
    CFNotificationCenterAddObserver(CFNotificationCenterGetLocalCenterSingleton(), this, &fontCacheRegisteredFontsChangedNotificationCallback, protect(getUIContentSizeCategoryDidChangeNotificationName()).get(), nullptr, CFNotificationSuspensionBehaviorDeliverImmediately);
#endif

    CFNotificationCenterAddObserver(CFNotificationCenterGetLocalCenterSingleton(), this, &fontCacheRegisteredFontsChangedNotificationCallback, kAXSEnhanceTextLegibilityChangedNotification, nullptr, CFNotificationSuspensionBehaviorDeliverImmediately);

#if PLATFORM(MAC)
    CFNotificationCenterRef center = CFNotificationCenterGetLocalCenterSingleton();
    const CFStringRef notificationName = kCFLocaleCurrentLocaleDidChangeNotification;
#else
    CFNotificationCenterRef center = CFNotificationCenterGetDarwinNotifyCenterSingleton();
    const CFStringRef notificationName = CFSTR("com.apple.language.changed");
#endif
    CFNotificationCenterAddObserver(center, this, &fontCacheRegisteredFontsChangedNotificationCallback, notificationName, nullptr, CFNotificationSuspensionBehaviorDeliverImmediately);
}

Vector<String> FontCache::systemFontFamilies()
{
    Vector<String> fontFamilies;

    auto availableFontFamilies = adoptCF(CTFontManagerCopyAvailableFontFamilyNames());
    CFIndex count = CFArrayGetCount(availableFontFamilies.get());
    for (CFIndex i = 0; i < count; ++i) {
        RetainPtr fontName = dynamic_cf_cast<CFStringRef>(CFArrayGetValueAtIndex(availableFontFamilies.get(), i));
        if (!fontName) {
            ASSERT_NOT_REACHED();
            continue;
        }

        if (fontNameIsSystemFont(fontName.get()))
            continue;

        fontFamilies.append(fontName.get());
    }

    return fontFamilies;
}

static inline bool NODELETE isSystemFont(const String& family)
{
    // String's operator[] handles out-of-bounds by returning 0.
    return family[0] == '.';
}

bool FontCache::isSystemFontForbiddenForEditing(const String& fontFamily)
{
    return isSystemFont(fontFamily);
}

static CTFontSymbolicTraits NODELETE computeTraits(const FontDescription& fontDescription)
{
    CTFontSymbolicTraits traits = 0;
    if (fontDescription.fontStyleSlope())
        traits |= kCTFontTraitItalic;
    if (isFontWeightBold(fontDescription.weight()))
        traits |= kCTFontTraitBold;
    return traits;
}

SynthesisPair computeNecessarySynthesis(CTFontRef font, const FontDescription& fontDescription, OptionSet<FontLookupOptions> synthesisOptions, ShouldComputePhysicalTraits shouldComputePhysicalTraits, bool isPlatformFont)
{
    if (CTFontIsAppleColorEmoji(font))
        return SynthesisPair(false, false);

    if (isPlatformFont)
        return SynthesisPair(false, false);

    bool needsSyntheticBold = fontDescription.hasAutoFontSynthesisWeight()
        && !synthesisOptions.contains(FontLookupOptions::DisallowBoldSynthesis);
    bool needsSyntheticOblique = fontDescription.allowsItalicOrObliqueFontSynthesisStyle() && !synthesisOptions.contains(FontLookupOptions::DisallowObliqueSynthesis);

    if (!needsSyntheticBold && !needsSyntheticOblique)
        return SynthesisPair(false, false);

    CTFontSymbolicTraits desiredTraits = computeTraits(fontDescription);
    CTFontSymbolicTraits actualTraits = 0;
    if (isFontWeightBold(fontDescription.weight()) || isItalic(fontDescription.fontStyleSlope())) {
        if (shouldComputePhysicalTraits == ShouldComputePhysicalTraits::Yes)
            actualTraits = CTFontGetPhysicalSymbolicTraits(font);
        else
            actualTraits = CTFontGetSymbolicTraits(font);
    }

    needsSyntheticBold = needsSyntheticBold && (desiredTraits & kCTFontTraitBold) && !(actualTraits & kCTFontTraitBold);
    needsSyntheticOblique = needsSyntheticOblique && (desiredTraits & kCTFontTraitItalic) && !(actualTraits & kCTFontTraitItalic);

    return SynthesisPair(needsSyntheticBold, needsSyntheticOblique);
}

class FontCacheAllowlist {
public:
    static FontCacheAllowlist& NODELETE singleton() WTF_REQUIRES_LOCK(lock)
    {
        static NeverDestroyed<FontCacheAllowlist> allowlist;
        return allowlist;
    }

    void set(const Vector<String>& inputAllowlist) WTF_REQUIRES_LOCK(lock)
    {
        m_families.clear();
        for (auto& item : inputAllowlist)
            m_families.add(item);
    }

    bool allows(const AtomString& family) const WTF_REQUIRES_LOCK(lock)
    {
        return m_families.isEmpty() || m_families.contains(family);
    }

    static Lock lock;

private:
    HashSet<String, ASCIICaseInsensitiveHash> m_families;
};

Lock FontCacheAllowlist::lock;

void FontCache::setFontAllowlist(const Vector<String>& inputAllowlist)
{
    Locker locker { FontCacheAllowlist::lock };
    FontCacheAllowlist::singleton().set(inputAllowlist);
}

// Because this struct holds intermediate values which may be in the compressed -1 - 1 GX range, we don't want to use the relatively large
// quantization of FontSelectionValue. Instead, do this logic with floats.
struct MinMax {
    float minimum;
    float maximum;
};

struct VariationCapabilities {
    std::optional<MinMax> weight;
    std::optional<MinMax> width;
    std::optional<MinMax> slope;
};

static std::optional<MinMax> extractVariationBounds(CFDictionaryRef axis)
{
    RetainPtr minimumValue = static_cast<CFNumberRef>(CFDictionaryGetValue(axis, kCTFontVariationAxisMinimumValueKey));
    RetainPtr maximumValue = static_cast<CFNumberRef>(CFDictionaryGetValue(axis, kCTFontVariationAxisMaximumValueKey));
    float rawMinimumValue = 0;
    float rawMaximumValue = 0;
    CFNumberGetValue(minimumValue.get(), kCFNumberFloatType, &rawMinimumValue);
    CFNumberGetValue(maximumValue.get(), kCFNumberFloatType, &rawMaximumValue);
    if (rawMinimumValue < rawMaximumValue)
        return {{ rawMinimumValue, rawMaximumValue }};
    return std::nullopt;
}

static VariationCapabilities variationCapabilitiesForFontDescriptor(CTFontDescriptorRef fontDescriptor)
{
    VariationCapabilities result;

    if (!adoptCF(CTFontDescriptorCopyAttribute(fontDescriptor, kCTFontVariationAttribute)))
        return result;

    auto variations = variationAxesWithNonLocalizedAxesNames(fontDescriptor);
    if (!variations)
        return result;

    auto axisCount = CFArrayGetCount(variations.get());
    if (!axisCount)
        return result;

    for (CFIndex i = 0; i < axisCount; ++i) {
        RetainPtr axis = static_cast<CFDictionaryRef>(CFArrayGetValueAtIndex(variations.get(), i));
        RetainPtr axisIdentifier = static_cast<CFNumberRef>(CFDictionaryGetValue(axis.get(), kCTFontVariationAxisIdentifierKey));
        uint32_t rawAxisIdentifier = 0;
        Boolean success = CFNumberGetValue(axisIdentifier.get(), kCFNumberSInt32Type, &rawAxisIdentifier);
        ASSERT_UNUSED(success, success);
        if (rawAxisIdentifier == 0x77676874) // 'wght'
            result.weight = extractVariationBounds(axis.get());
        else if (rawAxisIdentifier == 0x77647468) // 'wdth'
            result.width = extractVariationBounds(axis.get());
        else if (rawAxisIdentifier == 0x736C6E74) // 'slnt'
            result.slope = extractVariationBounds(axis.get());
    }

    bool optOutFromGXNormalization = CTFontDescriptorIsSystemUIFont(fontDescriptor);

    auto variationType = [&] {
        // FIXME: https://bugs.webkit.org/show_bug.cgi?id=247987 Stop creating a whole CTFont here. Ideally we'd be able to do all the inspection we need to do without one.
        auto font = adoptCF(CTFontCreateWithFontDescriptor(fontDescriptor, 0, nullptr));
        return FontInterrogation(font.get()).variationType;
    }();
    if (variationType == FontInterrogation::VariationType::TrueTypeGX && !optOutFromGXNormalization) {
        if (result.weight)
            result.weight = { { normalizeGXWeight(result.weight.value().minimum), normalizeGXWeight(result.weight.value().maximum) } };
        if (result.width)
            result.width = { { normalizeVariationWidth(result.width.value().minimum), normalizeVariationWidth(result.width.value().maximum) } };
        if (result.slope)
            result.slope = { { normalizeSlope(result.slope.value().minimum), normalizeSlope(result.slope.value().maximum) } };
    }

    auto minimum = static_cast<float>(FontSelectionValue::minimumValue());
    auto maximum = static_cast<float>(FontSelectionValue::maximumValue());
    if (result.weight && (result.weight.value().minimum < minimum || result.weight.value().maximum > maximum))
        result.weight = { };
    if (result.width && (result.width.value().minimum < minimum || result.width.value().maximum > maximum))
        result.width = { };
    if (result.slope && (result.slope.value().minimum < minimum || result.slope.value().maximum > maximum))
        result.slope = { };

    return result;
}

static float getCSSAttribute(CTFontDescriptorRef fontDescriptor, const CFStringRef attribute, float fallback)
{
    auto number = adoptCF(static_cast<CFNumberRef>(CTFontDescriptorCopyAttribute(fontDescriptor, attribute)));
    if (!number)
        return fallback;
    float cssValue;
    auto success = CFNumberGetValue(number.get(), kCFNumberFloatType, &cssValue);
    ASSERT_UNUSED(success, success);
    return cssValue;
}

FontSelectionCapabilities capabilitiesForFontDescriptor(CTFontDescriptorRef fontDescriptor)
{
    if (!fontDescriptor)
        return { };

    VariationCapabilities variationCapabilities = variationCapabilitiesForFontDescriptor(fontDescriptor);

    if (!variationCapabilities.slope) {
        auto traits = adoptCF(static_cast<CFDictionaryRef>(CTFontDescriptorCopyAttribute(fontDescriptor, kCTFontTraitsAttribute)));
        if (traits) {
            if (!variationCapabilities.slope) {
                RetainPtr symbolicTraitsNumber = static_cast<CFNumberRef>(CFDictionaryGetValue(traits.get(), kCTFontSymbolicTrait));
                if (symbolicTraitsNumber) {
                    int32_t symbolicTraits;
                    auto success = CFNumberGetValue(symbolicTraitsNumber.get(), kCFNumberSInt32Type, &symbolicTraits);
                    ASSERT_UNUSED(success, success);
                    auto slopeValue = static_cast<float>(symbolicTraits & kCTFontTraitItalic ? italicValue() : normalItalicValue());
                    variationCapabilities.slope = {{ slopeValue, slopeValue }};
                } else
                    variationCapabilities.slope = {{ static_cast<float>(normalItalicValue()), static_cast<float>(normalItalicValue()) }};
            }
        }
    }

    if (!variationCapabilities.weight) {
        auto value = getCSSAttribute(fontDescriptor, kCTFontCSSWeightAttribute, static_cast<float>(normalWeightValue()));
        variationCapabilities.weight = {{ value, value }};
    }

    if (!variationCapabilities.width) {
        auto value = getCSSAttribute(fontDescriptor, kCTFontCSSWidthAttribute, static_cast<float>(normalWidthValue()));
        variationCapabilities.width = {{ value, value }};
    }

    FontSelectionCapabilities result = {{ FontSelectionValue(variationCapabilities.weight.value().minimum), FontSelectionValue(variationCapabilities.weight.value().maximum) },
        { FontSelectionValue(variationCapabilities.width.value().minimum), FontSelectionValue(variationCapabilities.width.value().maximum) },
        { FontSelectionValue(variationCapabilities.slope.value().minimum), FontSelectionValue(variationCapabilities.slope.value().maximum) }};
    ASSERT(result.weight.isValid());
    ASSERT(result.width.isValid());
    ASSERT(result.slope.isValid());
    return result;
}

static const FontDatabase::InstalledFont* findClosestFont(const FontDatabase::InstalledFontFamily& familyFonts, FontSelectionRequest fontSelectionRequest)
{
    auto capabilities = familyFonts.installedFonts.map([](auto& font) {
        return font.capabilities;
    });
    FontSelectionAlgorithm fontSelectionAlgorithm(fontSelectionRequest, WTF::move(capabilities), familyFonts.capabilities);
    auto index = fontSelectionAlgorithm.indexOfBestCapabilities();
    if (index == notFound)
        return nullptr;

    return &familyFonts.installedFonts[index];
}

FontDatabase& FontCache::database(AllowUserInstalledFonts allowUserInstalledFonts)
{
    return allowUserInstalledFonts == AllowUserInstalledFonts::Yes ? m_databaseAllowingUserInstalledFonts : m_databaseDisallowingUserInstalledFonts;
}

Vector<FontSelectionCapabilities> FontCache::getFontSelectionCapabilitiesInFamily(const AtomString& familyName, AllowUserInstalledFonts allowUserInstalledFonts)
{
    auto& fontDatabase = database(allowUserInstalledFonts);
    const auto& fonts = fontDatabase.collectionForFamily(familyName.string());
    return fonts.installedFonts.map([](auto& font) {
        return font.capabilities;
    });
}

struct FontLookup {
    RetainPtr<CTFontDescriptorRef> result;
    bool createdFromPostScriptName { false };
};

static bool isDotPrefixedForbiddenFont(const AtomString& family)
{
    if (linkedOnOrAfterSDKWithBehavior(SDKAlignedBehavior::ForbidsDotPrefixedFonts))
        return family.startsWith('.');
    return equalLettersIgnoringASCIICase(family, ".applesystemuifontserif"_s)
        || equalLettersIgnoringASCIICase(family, ".sf ns mono"_s)
        || equalLettersIgnoringASCIICase(family, ".sf ui mono"_s)
        || equalLettersIgnoringASCIICase(family, ".sf arabic"_s)
        || equalLettersIgnoringASCIICase(family, ".applesystemuifontrounded"_s);
}

static bool isAllowlistedFamily(const AtomString& family)
{
    if (isSystemFont(family.string()))
        return true;

    Locker locker { FontCacheAllowlist::lock };
    return FontCacheAllowlist::singleton().allows(family);
}

static FontLookup platformFontLookupWithFamily(FontDatabase& fontDatabase, const AtomString& family, FontSelectionRequest request, OptionSet<FontLookupOptions> options)
{
    if (!isAllowlistedFamily(family))
        return { nullptr };

    if (isDotPrefixedForbiddenFont(family)) {
        // If you want to use these fonts, use system-ui, ui-serif, ui-monospace, or ui-rounded.
        return { nullptr };
    }

    const auto& familyFonts = fontDatabase.collectionForFamily(family.string());
    if (familyFonts.isEmpty()) {
        // The CSS spec states that font-family only accepts a name of an actual font family. However, in WebKit, we claim to also
        // support supplying a PostScript name instead. However, this creates problems when the other properties (font-weight,
        // font-style) disagree with the traits of the PostScript-named font. The solution we have come up with is, when the default
        // values for font-weight and font-style are supplied, honor the PostScript name, but if font-weight specifies bold or
        // font-style specifies italic, then we run the regular matching algorithm on the family of the PostScript font. This way,
        // if content simply states "font-family: PostScriptName;" without specifying the other font properties, it will be honored,
        // but if a <b> appears as a descendent element, it will be honored too.
        const auto& postScriptFont = fontDatabase.fontForPostScriptName(family);
        if (!postScriptFont.fontDescriptor)
            return { nullptr };
        if (!options.contains(FontLookupOptions::ExactFamilyNameMatch)
            && ((isItalic(request.slope) && !isItalic(postScriptFont.capabilities.slope.maximum))
            || (isFontWeightBold(request.weight) && !isFontWeightBold(postScriptFont.capabilities.weight.maximum)))) {
            auto postScriptFamilyName = adoptCF(static_cast<CFStringRef>(CTFontDescriptorCopyAttribute(postScriptFont.fontDescriptor.get(), kCTFontFamilyNameAttribute)));
            if (!postScriptFamilyName)
                return { nullptr };
            const auto& familyFonts = fontDatabase.collectionForFamily(String(postScriptFamilyName.get()));
            if (familyFonts.isEmpty())
                return { nullptr };
            if (const auto* installedFont = findClosestFont(familyFonts, request)) {
                if (!installedFont->fontDescriptor)
                    return { nullptr };
                return { installedFont->fontDescriptor.get(), true };
            }
            return { nullptr };
        }
        return { postScriptFont.fontDescriptor.get(), true };
    }

    if (const auto* installedFont = findClosestFont(familyFonts, request))
        return { installedFont->fontDescriptor.get(), false };

    return { nullptr };
}

void FontCache::platformInvalidate()
{
    // FIXME: Workers need to access SystemFontDatabaseCoreText.
    m_fontFamilySpecificationCoreTextCache.clear();
    m_systemFontDatabaseCoreText.clear();

    platformShouldEnhanceTextLegibility() = _AXSEnhanceTextLegibilityEnabled();
}

struct SpecialCaseFontLookupResult {
    UnrealizedCoreTextFont unrealizedCoreTextFont;
    FontTypeForPreparation fontTypeForPreparation;
};

static std::optional<SpecialCaseFontLookupResult> fontDescriptorWithFamilySpecialCase(const AtomString& family, const FontDescription& fontDescription, float size, AllowUserInstalledFonts allowUserInstalledFonts)
{
    // FIXME: See comment in FontCascadeDescription::effectiveFamilyAt() in FontDescriptionCocoa.cpp
    std::optional<SystemFontKind> systemDesign;

    if (equalLettersIgnoringASCIICase(family, "ui-serif"_s))
        systemDesign = SystemFontKind::UISerif;
    else if (equalLettersIgnoringASCIICase(family, "ui-monospace"_s))
        systemDesign = SystemFontKind::UIMonospace;
    else if (equalLettersIgnoringASCIICase(family, "ui-rounded"_s))
        systemDesign = SystemFontKind::UIRounded;

    if (equalLettersIgnoringASCIICase(family, "-webkit-system-font"_s) || equalLettersIgnoringASCIICase(family, "-apple-system"_s) || equalLettersIgnoringASCIICase(family, "-apple-system-font"_s) || equalLettersIgnoringASCIICase(family, "system-ui"_s) || equalLettersIgnoringASCIICase(family, "ui-sans-serif"_s)) {
        ASSERT(!systemDesign);
        systemDesign = SystemFontKind::SystemUI;
    }

    if (systemDesign) {
        auto cascadeList = SystemFontDatabaseCoreText::forCurrentThread().cascadeList(fontDescription, family, *systemDesign, allowUserInstalledFonts);
        if (cascadeList.isEmpty())
            return std::nullopt;
        return { { RetainPtr { cascadeList[0] }, FontTypeForPreparation::SystemFont } };
    }

    if (family.startsWith("UICTFontTextStyle"_s)) {
        const auto& request = fontDescription.fontSelectionRequest();
        CTFontSymbolicTraits traits = (isFontWeightBold(request.weight) ? kCTFontTraitBold : 0) | (isItalic(request.slope) ? kCTFontTraitItalic : 0);
        auto descriptor = adoptCF(CTFontDescriptorCreateWithTextStyle(family.string().createCFString().get(), protect(contentSizeCategory()).get(), fontDescription.computedLocale().string().createCFString().get()));
        if (traits) {
            // FIXME: rdar://105369379 As far as I can tell, there's no modification to the attributes dictionary that has the same effect as CTFontDescriptorCreateCopyWithSymbolicTraits(),
            // because there doesn't seem to be a place to specify the bitmask. That's the reason we're creating the derived CTFontDescriptor here, rather than in UnrealizedCoreTextFont::realize().
            return { { adoptCF(CTFontDescriptorCreateCopyWithSymbolicTraits(descriptor.get(), traits, traits)), FontTypeForPreparation::SystemFont } };
        }
        return { { WTF::move(descriptor), FontTypeForPreparation::SystemFont } };
    }

    if (equalLettersIgnoringASCIICase(family, "-apple-menu"_s))
        return { { adoptCF(CTFontDescriptorCreateForUIType(kCTFontUIFontMenuItem, size, fontDescription.computedLocale().string().createCFString().get())), FontTypeForPreparation::SystemFont } };

    if (equalLettersIgnoringASCIICase(family, "-apple-status-bar"_s))
        return { { adoptCF(CTFontDescriptorCreateForUIType(kCTFontUIFontSystem, size, fontDescription.computedLocale().string().createCFString().get())), FontTypeForPreparation::SystemFont } };

    if (equalLettersIgnoringASCIICase(family, "lastresort"_s))
        return { { adoptCF(CTFontDescriptorCreateLastResort()), FontTypeForPreparation::NonSystemFont } };

    if (equalLettersIgnoringASCIICase(family, "-apple-system-monospaced-numbers"_s)) {
        auto systemFontDescriptor = UnrealizedCoreTextFont { adoptCF(CTFontDescriptorCreateForUIType(kCTFontUIFontSystem, size, nullptr)) };
        systemFontDescriptor.modify([](CFMutableDictionaryRef attributes) {
            int numberSpacingType = kNumberSpacingType;
            int monospacedNumbersSelector = kMonospacedNumbersSelector;
            auto numberSpacingNumber = adoptCF(CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &numberSpacingType));
            auto monospacedNumbersNumber = adoptCF(CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &monospacedNumbersSelector));
            CFTypeRef keys[] = { kCTFontFeatureTypeIdentifierKey, kCTFontFeatureSelectorIdentifierKey };
            CFTypeRef values[] = { numberSpacingNumber.get(), monospacedNumbersNumber.get() };
            ASSERT(std::size(keys) == std::size(values));
            auto settingsDictionary = adoptCF(CFDictionaryCreate(kCFAllocatorDefault, keys, values, std::size(keys), &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks));
            CFTypeRef entries[] = { settingsDictionary.get() };
            auto settingsArray = adoptCF(CFArrayCreate(kCFAllocatorDefault, entries, std::size(entries), &kCFTypeArrayCallBacks));
            CFDictionaryAddValue(attributes, kCTFontFeatureSettingsAttribute, settingsArray.get());
        });
        return { { systemFontDescriptor, FontTypeForPreparation::SystemFont } };
    }

    return std::nullopt;
}

static RetainPtr<CTFontRef> fontWithFamily(FontDatabase& fontDatabase, const AtomString& family, const FontDescription& fontDescription, const FontCreationContext& fontCreationContext, float size, OptionSet<FontLookupOptions> options)
{
    ASSERT(fontDatabase.allowUserInstalledFonts() == fontDescription.shouldAllowUserInstalledFonts());

    if (family.isEmpty())
        return nullptr;

#if PLATFORM(DRIFTSTACK)
    // Stage B Step 3: prefer iOS-archetype fonts for any family name they
    // expose. This bypasses CTFont's name-based lookup which otherwise
    // returns Mac's system Helvetica/Arial/etc. variants — and prevents
    // canvas measureText from observing iPhone-specific font metrics.
    if (auto driftstackFont = driftstackIOSFontWithFamily(family, fontDescription, size))
        return driftstackFont;
#endif

    if (auto lookupResult = fontDescriptorWithFamilySpecialCase(family, fontDescription, size, fontDescription.shouldAllowUserInstalledFonts())) {
        lookupResult->unrealizedCoreTextFont.setSize(size);
        lookupResult->unrealizedCoreTextFont.modify([&](CFMutableDictionaryRef attributes) {
            addAttributesForInstalledFonts(attributes, fontDescription.shouldAllowUserInstalledFonts());
        });
        return preparePlatformFont(WTF::move(lookupResult->unrealizedCoreTextFont), fontDescription, fontCreationContext, lookupResult->fontTypeForPreparation);
    }
    auto fontLookup = platformFontLookupWithFamily(fontDatabase, family, fontDescription.fontSelectionRequest(), options);
    UnrealizedCoreTextFont unrealizedFont = { WTF::move(fontLookup.result) };
    unrealizedFont.setSize(size);
    ApplyTraitsVariations applyTraitsVariations = fontLookup.createdFromPostScriptName ? ApplyTraitsVariations::No : ApplyTraitsVariations::Yes;
    return preparePlatformFont(WTF::move(unrealizedFont), fontDescription, fontCreationContext, FontTypeForPreparation::NonSystemFont, applyTraitsVariations);
}

#if PLATFORM(MAC)
bool FontCache::shouldAutoActivateFontIfNeeded(const AtomString& family)
{
    if (family.isEmpty())
        return false;

    static const unsigned maxCacheSize = 128;
    ASSERT(m_knownFamilies.size() <= maxCacheSize);
    if (m_knownFamilies.size() == maxCacheSize)
        m_knownFamilies.remove(m_knownFamilies.random());

    // Only attempt to auto-activate fonts once for performance reasons.
    return m_knownFamilies.add(family).isNewEntry;
}

static void autoActivateFont(const String& name, CGFloat size)
{
    auto fontName = name.createCFString();
    CFTypeRef keys[] = { kCTFontNameAttribute, kCTFontEnabledAttribute };
    CFTypeRef values[] = { fontName.get(), kCFBooleanTrue };
    auto attributes = adoptCF(CFDictionaryCreate(kCFAllocatorDefault, keys, values, std::size(keys), &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks));
    auto descriptor = adoptCF(CTFontDescriptorCreateWithAttributes(attributes.get()));
    auto newFont = adoptCF(CTFontCreateWithFontDescriptor(descriptor.get(), size, nullptr));
}
#endif

static void registerFontIfNeeded(const String& family) WTF_REQUIRES_LOCK(userInstalledFontMapLock())
{
    if (auto fontURL = userInstalledFontMap().getOptional(family)) {
        RELEASE_LOG_FORWARDABLE(Fonts, FontCacheCoreTextRegisterFont, family.utf8(), fontURL->string().utf8());
        RetainPtr cfURL = fontURL->createCFURL();

        CFErrorRef error = nullptr;
        if (!CTFontManagerRegisterFontsForURL(cfURL.get(), kCTFontManagerScopeProcess, &error)) {
            RetainPtr descriptionCF = adoptCF(CFErrorCopyDescription(error));
            String error(descriptionCF.get());
            RELEASE_LOG_FORWARDABLE(Fonts, FontCacheCoreTextRegisterError, family.utf8(), error.utf8());
        }

        userInstalledFontMap().removeIf([&](auto& keyAndValue) {
            return keyAndValue.value == fontURL;
        });
    }
}

static void registerFontsInFamilyIfNeeded(const String& family)
{
    Locker locker(userInstalledFontMapLock());
    if (!userInstalledFontMap().isEmpty()) {
        if (equalLettersIgnoringASCIICase(family, "helvetica"_s)) {
            // Helvetica is a system font with several variants, so we choose not to register additional fonts in this family.
            // This is because it can affect font matching. See rdar://172261885.
            return;
        }

        auto fontFamily = family.convertToASCIILowercase();

        registerFontIfNeeded(fontFamily);
        auto fontNames = userInstalledFontFamilyMap().find(fontFamily);
        if (fontNames != userInstalledFontFamilyMap().end()) {
            for (auto& fontName : fontNames->value)
                registerFontIfNeeded(fontName);
            userInstalledFontFamilyMap().remove(fontNames);
        }
    }
}

std::unique_ptr<FontPlatformData> FontCache::createFontPlatformData(const FontDescription& fontDescription, const AtomString& family, const FontCreationContext& fontCreationContext, OptionSet<FontLookupOptions> options)
{
    registerFontsInFamilyIfNeeded(family);

    auto size = fontDescription.adjustedSizeForFontFace(fontCreationContext.sizeAdjust());
    auto& fontDatabase = database(fontDescription.shouldAllowUserInstalledFonts());
    auto font = fontWithFamily(fontDatabase, family, fontDescription, fontCreationContext, size, options);

#if PLATFORM(MAC)
    if (!font) {
        if (!shouldAutoActivateFontIfNeeded(family))
            return nullptr;

        // Auto activate the font before looking for it a second time.
        // Ignore the result because we want to use our own algorithm to actually find the font.
        autoActivateFont(family.string(), size);

        font = fontWithFamily(fontDatabase, family, fontDescription, fontCreationContext, size, options);
    }
#endif

    if (!font)
        return nullptr;

    if (fontDescription.shouldAllowUserInstalledFonts() == AllowUserInstalledFonts::No)
        m_seenFamiliesForPrewarming.add(FontCascadeDescription::foldedFamilyName(family));

    auto [syntheticBold, syntheticOblique] = computeNecessarySynthesis(font.get(), fontDescription, options).boldObliquePair();

    FontPlatformData platformData(font.get(), size, syntheticBold, syntheticOblique, fontDescription.orientation(), fontDescription.widthVariant(), fontDescription.textRenderingMode());

    platformData.updateSizeWithFontSizeAdjust(fontDescription.fontSizeAdjust(), fontDescription.computedSize());
    return makeUnique<FontPlatformData>(platformData);
}

void FontCache::platformPurgeInactiveFontData()
{
    Vector<CTFontRef> toRemove;
    for (auto& font : m_fallbackFonts) {
        if (CFGetRetainCount(font.get()) == 1)
            toRemove.append(font.get());
    }
    for (auto& font : toRemove)
        m_fallbackFonts.remove(font);

    m_databaseAllowingUserInstalledFonts.clear();
    m_databaseDisallowingUserInstalledFonts.clear();
}

#if PLATFORM(IOS_FAMILY)
static inline bool isArabicCharacter(char16_t character)
{
    return character >= 0x0600 && character <= 0x06FF;
}
#endif

#if ASSERT_ENABLED
static bool isUserInstalledFont(CTFontRef font)
{
    return adoptCF(CTFontCopyAttribute(font, kCTFontUserInstalledAttribute)) == kCFBooleanTrue;
}
#endif

static RetainPtr<CTFontRef> lookupFallbackFont(CTFontRef font, FontSelectionValue fontWeight, const AtomString& locale, AllowUserInstalledFonts allowUserInstalledFonts, StringView characterCluster)
{
    ASSERT(characterCluster.length() > 0);

    RetainPtr<CFStringRef> localeString;
    if (!locale.isNull())
        localeString = locale.string().createCFString();

    CFIndex coveredLength = 0;
    auto upconvertedCharacters = characterCluster.upconvertedCharacters();
    auto fallbackOption = allowUserInstalledFonts == AllowUserInstalledFonts::No ? kCTFontFallbackOptionSystem : kCTFontFallbackOptionDefault;
    auto result = adoptCF(CTFontCreateForCharactersWithLanguageAndOption(font, reinterpret_cast<const UTF16Char*>(upconvertedCharacters.get()), characterCluster.length(), localeString.get(), fallbackOption, &coveredLength));
    ASSERT(!isUserInstalledFont(result.get()) || allowUserInstalledFonts == AllowUserInstalledFonts::Yes);

#if PLATFORM(IOS_FAMILY)
    // FIXME: This is so unfortunate. The reason this is here is that certain fonts which are early in the system font cascade list
    // (used to?) perform poorly. In order to speed up the browser, we block those fonts, and use other faster fonts instead.
    // However, this performance analysis was done, like, 10 years ago, and the probability that these fonts are still too slow
    // seems quite low. We should re-analyze performance to see if we can delete this code.
    char16_t firstCharacter = characterCluster[0];
    if (isArabicCharacter(firstCharacter)) {
        auto familyName = adoptCF(static_cast<CFStringRef>(CTFontCopyAttribute(result.get(), kCTFontFamilyNameAttribute)));
        if (fontFamilyShouldNotBeUsedForArabic(familyName.get())) {
            CFStringRef newFamilyName = isFontWeightBold(fontWeight) ? CFSTR("GeezaPro-Bold") : CFSTR("GeezaPro");
            CFTypeRef keys[] = { kCTFontNameAttribute };
            CFTypeRef values[] = { newFamilyName };
            auto attributes = adoptCF(CFDictionaryCreate(kCFAllocatorDefault, keys, values, std::size(keys), &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks));
            auto modification = adoptCF(CTFontDescriptorCreateWithAttributes(attributes.get()));
            result = adoptCF(CTFontCreateCopyWithAttributes(result.get(), CTFontGetSize(result.get()), nullptr, modification.get()));
        }
    }
#else
    UNUSED_PARAM(fontWeight);
#endif

    return result;
}

#if PLATFORM(DRIFTSTACK)
// Track 9 (V-161 closure): Mac's lookupFallbackFont returns a different physical
// font for Korean Hangul characters than iOS does. Mac falls back via its own
// catalog (often AppleGothic or system-specific Hangul font); iOS uses
// AppleSDGothicNeo for ALL serif/sans-serif/system contexts. The 2 surfaces
// in V-157 (serif|hangul_jamo, serif|korean_hangul) and additional Hangul
// probes downstream all close when the fallback resolution returns iOS's
// AppleSDGothicNeo binary directly.
//
// Hangul Unicode ranges (per Unicode 15.x):
//   U+1100-U+11FF  Hangul Jamo
//   U+3130-U+318F  Hangul Compatibility Jamo
//   U+A960-U+A97F  Hangul Jamo Extended-A
//   U+AC00-U+D7AF  Hangul Syllables (precomposed; covers '한', '안녕', etc.)
//   U+D7B0-U+D7FF  Hangul Jamo Extended-B
//
// Returns nullptr if the cluster is not Hangul OR if AppleSDGothicNeo isn't
// in the Stage B installed font map (silent — does NOT log MISS like the
// Stage B path does for missing CSS family lookups).
// Helper: look up a font by family-name candidates in the Stage B map.
// Silent on miss; returns the variant matching requested weight/italic at size.
static RetainPtr<CTFontRef> driftstackLookupIOSFontByCandidates(std::span<const ASCIILiteral> candidates, const FontDescription& description, float size)
{
    initializeDriftstackIOSFontMapIfNeeded();
    Locker locker(driftstackIOSFontMapLock);
    auto& map = driftstackIOSFontMap();
    for (auto candidate : candidates) {
        auto it = map.find(String(candidate));
        if (it == map.end())
            continue;
        const auto& variants = it->value;
        if (variants.isEmpty())
            continue;
        const float requestedWeight = (static_cast<float>(description.weight()) - 400.f) / 400.f;
        const bool requestedItalic = isItalic(description.fontStyleSlope());
        DriftstackIOSFontVariant chosen = variants[0];
        float bestScore = std::numeric_limits<float>::infinity();
        for (const auto& v : variants) {
            float italicMismatch = (v.italic != requestedItalic) ? 1.0f : 0.0f;
            float weightDelta = std::abs(v.weight - requestedWeight);
            float score = italicMismatch * 10.0f + weightDelta;
            if (score < bestScore) {
                bestScore = score;
                chosen = v;
            }
        }
        RetainPtr<CFArrayRef> descs = adoptCF(CTFontManagerCreateFontDescriptorsFromURL(chosen.url.get()));
        if (!descs || !CFArrayGetCount(descs.get()))
            continue;
        CTFontDescriptorRef fd = (CTFontDescriptorRef)CFArrayGetValueAtIndex(descs.get(), 0);
        return adoptCF(CTFontCreateWithFontDescriptor(fd, size, nullptr));
    }
    return nullptr;
}

static RetainPtr<CTFontRef> driftstackIOSFallbackFontForHangulCluster(StringView cluster, const FontDescription& description, float size)
{
    if (cluster.isEmpty())
        return nullptr;
    char32_t cp = cluster[0];
    bool isHangul = (cp >= 0x1100 && cp <= 0x11FF)
                 || (cp >= 0x3130 && cp <= 0x318F)
                 || (cp >= 0xA960 && cp <= 0xA97F)
                 || (cp >= 0xAC00 && cp <= 0xD7AF)
                 || (cp >= 0xD7B0 && cp <= 0xD7FF);
    if (!isHangul)
        return nullptr;
    static const std::array<ASCIILiteral, 2> candidates {
        "apple sd gothic neo"_s,
        "applesdgothicneo"_s,
    };
    return driftstackLookupIOSFontByCandidates(candidates, description, size);
}

// Track 10 Hebrew: REMOVED post-V-165 validation. Empirical result was a wash:
// the SFHebrew override closed 3 sans-serif|hebrew surfaces but BROKE 3
// serif|hebrew surfaces (Mac's native serif Hebrew was already matching iPhone;
// the override forced SFHebrew for both serif AND sans-serif contexts, which
// matches iPhone for sans-serif but diverges for serif). Per-context font
// discrimination (sans-serif vs serif vs system in the originating CSS request)
// is not available at the systemFallbackForCharacterCluster call site without
// additional plumbing. Hebrew override is deferred until that discrimination
// is available, OR until empirical capture of iPhone's serif|hebrew font
// identifies the specific iOS font binary so we can override per-context.

// Track 10 (V-165 closure): Devanagari fallback. Mac's lookupFallbackFont
// returns macOS's native Devanagari font for U+0900-U+097F cluster; iOS uses
// Kohinoor Devanagari (in Stage B as Kohinoor.ttc) or DevanagariSangamMN.ttc.
// The 3 surfaces in V-159 (serif|devanagari) close when fallback returns
// iOS's Kohinoor binary. Devanagari Unicode range:
//   U+0900-U+097F  Devanagari
//   U+A8E0-U+A8FF  Devanagari Extended
static RetainPtr<CTFontRef> driftstackIOSFallbackFontForDevanagariCluster(StringView cluster, const FontDescription& description, float size)
{
    if (cluster.isEmpty())
        return nullptr;
    char32_t cp = cluster[0];
    bool isDevanagari = (cp >= 0x0900 && cp <= 0x097F)
                     || (cp >= 0xA8E0 && cp <= 0xA8FF);
    if (!isDevanagari)
        return nullptr;
    // Kohinoor Devanagari is iOS's primary modern Devanagari font (Stage B
    // file: LanguageSupport/Kohinoor.ttc). Try it first; fall back to legacy
    // Devanagari Sangam MN.
    static const std::array<ASCIILiteral, 3> candidates {
        "kohinoor devanagari"_s,
        "kohinoordevanagari"_s,
        "devanagari sangam mn"_s,
    };
    return driftstackLookupIOSFontByCandidates(candidates, description, size);
}
#endif // PLATFORM(DRIFTSTACK)

RefPtr<Font> FontCache::systemFallbackForCharacterCluster(const FontDescription& description, const Font& originalFontData, IsForPlatformFont isForPlatformFont, PreferColoredFont, StringView characterCluster)
{
    const FontPlatformData& platformData = originalFontData.platformData();
    RetainPtr ctFont = platformData.ctFont();

    auto fullName = String(adoptCF(CTFontCopyFullName(ctFont.get())).get());
    if (!fullName.isEmpty())
        m_fontNamesRequiringSystemFallbackForPrewarming.add(fullName);

    auto result = lookupFallbackFont(ctFont.get(), description.weight(), description.computedLocale(), description.shouldAllowUserInstalledFonts(), characterCluster);
#if PLATFORM(DRIFTSTACK)
    // Track 9 / V-161: short-circuit Mac's fallback resolution to prefer the
    // iOS Hangul font binary (AppleSDGothicNeo from Stage B). When the cluster
    // is Hangul and the override font loads, it replaces Mac's pick BEFORE
    // preparePlatformFont normalizes the result. If the cluster is not Hangul
    // OR AppleSDGothicNeo isn't installed, this is a no-op.
    if (auto driftstackHangulFont = driftstackIOSFallbackFontForHangulCluster(
            characterCluster, description, platformData.size())) {
        static unsigned hitCount = 0;
        if (++hitCount <= 8)
            WTFLogAlways("[Driftstack-Track9] Hangul fallback override fired (%u so far); cluster first cp = U+%04X",
                hitCount, (unsigned)characterCluster[0]);
        result = WTF::move(driftstackHangulFont);
    // Track 10 Hebrew dispatch removed post-V-165 validation (see comment block
    // above driftstackIOSFallbackFontForDevanagariCluster). Re-enable when
    // per-context (sans-serif vs serif) discrimination is plumbed through.
    } else if (auto driftstackDevanagariFont = driftstackIOSFallbackFontForDevanagariCluster(
            characterCluster, description, platformData.size())) {
        static unsigned hitCount = 0;
        if (++hitCount <= 8)
            WTFLogAlways("[Driftstack-Track10-Devanagari] Devanagari fallback override fired (%u so far); cluster first cp = U+%04X",
                hitCount, (unsigned)characterCluster[0]);
        result = WTF::move(driftstackDevanagariFont);
    }
#endif
    result = preparePlatformFont(UnrealizedCoreTextFont { WTF::move(result) }, description, { });

    if (!result)
        return lastResortFallbackFont(description);

    // FontCascade::drawGlyphBuffer() requires that there are no duplicate Font objects which refer to the same thing. This is enforced in
    // FontCache::fontForPlatformData(), where our equality check is based on hashing the FontPlatformData, whose hash includes the raw CoreText
    // font pointer.
    RetainPtr substituteFont = m_fallbackFonts.add(result).iterator->get();

    auto [syntheticBold, syntheticOblique] = computeNecessarySynthesis(substituteFont.get(), description, { }, ShouldComputePhysicalTraits::No, isForPlatformFont == IsForPlatformFont::Yes).boldObliquePair();

    RefPtr<const FontCustomPlatformData> customPlatformData = nullptr;
    if (safeCFEqual(ctFont.get(), substituteFont.get()))
        customPlatformData = platformData.customPlatformData();
    FontPlatformData alternateFont(substituteFont.get(), platformData.size(), syntheticBold, syntheticOblique, platformData.orientation(), platformData.widthVariant(), platformData.textRenderingMode(), customPlatformData.get());

    return fontForPlatformData(alternateFont);
}

ASCIILiteral FontCache::platformAlternateFamilyName(const String& familyName)
{
    static const char16_t heitiString[] = { 0x9ed1, 0x4f53 };
    static const char16_t songtiString[] = { 0x5b8b, 0x4f53 };
    static const char16_t weiruanXinXiMingTi[] = { 0x5fae, 0x8edf, 0x65b0, 0x7d30, 0x660e, 0x9ad4 };
    static const char16_t weiruanYaHeiString[] = { 0x5fae, 0x8f6f, 0x96c5, 0x9ed1 };
    static const char16_t weiruanZhengHeitiString[] = { 0x5fae, 0x8edf, 0x6b63, 0x9ed1, 0x9ad4 };

    static constexpr ASCIILiteral songtiSC = "Songti SC"_s;
    static constexpr ASCIILiteral songtiTC = "Songti TC"_s;
    static constexpr ASCIILiteral heitiSCReplacement = "PingFang SC"_s;
    static constexpr ASCIILiteral heitiTCReplacement = "PingFang TC"_s;

    switch (familyName.length()) {
    case 2:
        if (equal(familyName, songtiString))
            return songtiSC;
        if (equal(familyName, heitiString))
            return heitiSCReplacement;
        break;
    case 4:
        if (equal(familyName, weiruanYaHeiString))
            return heitiSCReplacement;
        break;
    case 5:
        if (equal(familyName, weiruanZhengHeitiString))
            return heitiTCReplacement;
        break;
    case 6:
        if (equalLettersIgnoringASCIICase(familyName, "simsun"_s))
            return songtiSC;
        if (equal(familyName, weiruanXinXiMingTi))
            return songtiTC;
        break;
    case 10:
        if (equalLettersIgnoringASCIICase(familyName, "ms mingliu"_s))
            return songtiTC;
        if (equalIgnoringASCIICase(familyName, "\\5b8b\\4f53"_s))
            return songtiSC;
        break;
    case 18:
        if (equalLettersIgnoringASCIICase(familyName, "microsoft jhenghei"_s))
            return heitiTCReplacement;
        break;
    }

    return { };
}

void addAttributesForInstalledFonts(CFMutableDictionaryRef attributes, AllowUserInstalledFonts allowUserInstalledFonts)
{
    if (allowUserInstalledFonts == AllowUserInstalledFonts::No) {
        CFDictionaryAddValue(attributes, kCTFontUserInstalledAttribute, kCFBooleanFalse);
        CTFontFallbackOption fallbackOption = kCTFontFallbackOptionSystem;
        auto fallbackOptionNumber = adoptCF(CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt64Type, &fallbackOption));
        CFDictionaryAddValue(attributes, kCTFontFallbackOptionAttribute, fallbackOptionNumber.get());
    }
}

RetainPtr<CTFontRef> createFontForInstalledFonts(CTFontDescriptorRef fontDescriptor, CGFloat size, AllowUserInstalledFonts allowUserInstalledFonts)
{
    auto attributes = adoptCF(CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks));
    addAttributesForInstalledFonts(attributes.get(), allowUserInstalledFonts);
    if (CFDictionaryGetCount(attributes.get())) {
        auto resultFontDescriptor = adoptCF(CTFontDescriptorCreateCopyWithAttributes(fontDescriptor, attributes.get()));
        return adoptCF(CTFontCreateWithFontDescriptor(resultFontDescriptor.get(), size, nullptr));
    }
    return adoptCF(CTFontCreateWithFontDescriptor(fontDescriptor, size, nullptr));
}

static inline bool isFontMatchingUserInstalledFontFallback(CTFontRef font, AllowUserInstalledFonts allowUserInstalledFonts)
{
    bool willFallbackToSystemOnly = false;
    if (auto fontFallbackOptionAttributeRef = adoptCF(static_cast<CFNumberRef>(CTFontCopyAttribute(font, kCTFontFallbackOptionAttribute)))) {
        int64_t fontFallbackOptionAttribute;
        CFNumberGetValue(fontFallbackOptionAttributeRef.get(), kCFNumberSInt64Type, &fontFallbackOptionAttribute);
        willFallbackToSystemOnly = fontFallbackOptionAttribute == kCTFontFallbackOptionSystem;
    }

    bool shouldFallbackToSystemOnly = allowUserInstalledFonts == AllowUserInstalledFonts::No;
    return willFallbackToSystemOnly == shouldFallbackToSystemOnly;
}

RetainPtr<CTFontRef> createFontForInstalledFonts(CTFontRef font, AllowUserInstalledFonts allowUserInstalledFonts)
{
    if (isFontMatchingUserInstalledFontFallback(font, allowUserInstalledFonts))
        return font;

    auto attributes = adoptCF(CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks));
    addAttributesForInstalledFonts(attributes.get(), allowUserInstalledFonts);
    if (CFDictionaryGetCount(attributes.get())) {
        auto modification = adoptCF(CTFontDescriptorCreateWithAttributes(attributes.get()));
        return adoptCF(CTFontCreateCopyWithAttributes(font, CTFontGetSize(font), nullptr, modification.get()));
    }
    return font;
}

void addAttributesForWebFonts(CFMutableDictionaryRef attributes, AllowUserInstalledFonts allowUserInstalledFonts)
{
    if (allowUserInstalledFonts == AllowUserInstalledFonts::No) {
        CTFontFallbackOption fallbackOption = kCTFontFallbackOptionSystem;
        auto fallbackOptionNumber = adoptCF(CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt64Type, &fallbackOption));
        CFDictionaryAddValue(attributes, kCTFontFallbackOptionAttribute, fallbackOptionNumber.get());
    }
}

RetainPtr<CFSetRef> installedFontMandatoryAttributes(AllowUserInstalledFonts allowUserInstalledFonts)
{
    if (allowUserInstalledFonts == AllowUserInstalledFonts::No) {
        CFTypeRef mandatoryAttributesValues[] = { kCTFontFamilyNameAttribute, kCTFontPostScriptNameAttribute, kCTFontEnabledAttribute, kCTFontUserInstalledAttribute, kCTFontFallbackOptionAttribute };
        return adoptCF(CFSetCreate(kCFAllocatorDefault, mandatoryAttributesValues, std::size(mandatoryAttributesValues), &kCFTypeSetCallBacks));
    }
    return nullptr;
}

Ref<Font> FontCache::lastResortFallbackFont(const FontDescription& fontDescription)
{
    // FIXME: Would be even better to somehow get the user's default font here.  For now we'll pick
    // the default that the user would get without changing any prefs.
    if (auto result = fontForFamily(fontDescription, AtomString("Times"_s)))
        return *result;

    // LastResort is guaranteed to be non-null.
    auto fontDescriptor = adoptCF(CTFontDescriptorCreateLastResort());
    auto font = adoptCF(CTFontCreateWithFontDescriptor(fontDescriptor.get(), fontDescription.computedSize(), nullptr));
    auto [syntheticBold, syntheticOblique] = computeNecessarySynthesis(font.get(), fontDescription).boldObliquePair();
    FontPlatformData platformData(font.get(), fontDescription.computedSize(), syntheticBold, syntheticOblique, fontDescription.orientation(), fontDescription.widthVariant(), fontDescription.textRenderingMode());
    return fontForPlatformData(platformData);
}

FontCache::PrewarmInformation FontCache::collectPrewarmInformation() const
{
    return { copyToVector(m_seenFamiliesForPrewarming), copyToVector(m_fontNamesRequiringSystemFallbackForPrewarming) };
}

void FontCache::prewarm(PrewarmInformation&& prewarmInformation)
{
    if (prewarmInformation.isEmpty())
        return;

    if (!m_prewarmQueue)
        lazyInitialize(m_prewarmQueue, WorkQueue::create("WebKit font prewarm queue"_s));

    m_prewarmQueue->dispatch([&database = m_databaseDisallowingUserInstalledFonts, prewarmInformation = WTF::move(prewarmInformation).isolatedCopy()] {
        for (auto& family : prewarmInformation.seenFamilies)
            database.collectionForFamily(family);

        for (auto& fontName : prewarmInformation.fontNamesRequiringSystemFallback) {
            auto cfFontName = fontName.createCFString();
            if (auto warmingFont = adoptCF(CTFontCreateWithName(cfFontName.get(), 0, nullptr))) {
                // This is sufficient to warm CoreText caches for language and character specific fallbacks.
                CFIndex coveredLength = 0;
                UniChar character = ' ';

                auto fallbackWarmingFont = adoptCF(CTFontCreateForCharactersWithLanguageAndOption(warmingFont.get(), &character, 1, nullptr, kCTFontFallbackOptionSystem, &coveredLength));
            }
        }
    });
}

void FontCache::prewarmGlobally()
{
#if !HAVE(STATIC_FONT_REGISTRY)
    if (MemoryPressureHandler::singleton().isUnderMemoryPressure())
        return;

    Vector<String> families {
#if PLATFORM(MAC) || PLATFORM(MACCATALYST)
        ".SF NS Text"_s,
        ".SF NS Display"_s,
#endif
        "Arial"_s,
        "Helvetica"_s,
        "Helvetica Neue"_s,
        "Lucida Grande"_s,
        "Times"_s,
        "Times New Roman"_s,
    };

    FontCache::PrewarmInformation prewarmInfo;
    prewarmInfo.seenFamilies = WTF::move(families);
    protect(FontCache::forCurrentThread())->prewarm(WTF::move(prewarmInfo));
#endif
}

void FontCache::platformReleaseNoncriticalMemory()
{
    // FIXME(https://bugs.webkit.org/show_bug.cgi?id=251560): We should be calling invalidate() on all platforms, but this causes a memory regression on iOS.
#if PLATFORM(MAC)
    invalidate();
#else
    m_systemFontDatabaseCoreText.clear();
    m_fontFamilySpecificationCoreTextCache.clear();
#endif
}

HashMap<String, URL>& userInstalledFontMap()
{
    static NeverDestroyed<HashMap<String, URL>> fontMap;
    return fontMap.get();
}

HashMap<String, Vector<String>>& userInstalledFontFamilyMap()
{
    static NeverDestroyed<HashMap<String, Vector<String>>> fontFamilyMap;
    return fontFamilyMap.get();
}

Lock& userInstalledFontMapLock()
{
    static Lock lock;
    return lock;
}

}
