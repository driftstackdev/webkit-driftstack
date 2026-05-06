// V-253 (overnight 2026-05-06) multi-archetype fonts denylist.
// Per-archetype list of Mac-only font families to reject in
// FontCache::cachedFontPlatformData / FontCache::createFontPlatformData
// so that browserleaks-style measureText probes report these as
// "not installed" (matching real iPhone behavior).
//
// Currently derived from V-237.2 BS Automate iPhone 16 Pro / iOS 18.6
// browserleaks-fonts probe (171 detected on iPhone vs 193 detected on
// fork pre-V-237 → 22 Mac-only false-positives).
//
// For iOS 26.4 archetype: denylist will be derived analogously after
// founder iOS 26.4 fonts capture lands (V-242 founder URL fires
// /captures/v3/founder-ios26-bundled-capture.html which captures the
// iOS 26.4 fonts list). Codegen TODO: extract-fonts-denylist.py.
//
// Runtime archetype selector reads the `DRIFTSTACK_ARCHETYPE` env var
// (parallel to canvas table V-245). Default = iphone16pro_ios18_6.

// IMPLEMENTATION NOTE: this header is included from inside
// `namespace WebCore { ... }` blocks (FontCache.cpp:59+,
// FontCacheCoreText.cpp same). It does NOT open its own namespace.

#pragma once
#include <string_view>
#include <wtf/text/AtomString.h>
#include <wtf/text/WTFString.h>

struct DriftstackFontsDenylistEntry {
    const char* archetype;
    const char* familyLowercase;
};

static constexpr DriftstackFontsDenylistEntry kDriftstackFontsDenylist[] = {
    // iphone16pro_ios18_6 archetype — V-237.2 BS Automate iOS 18.6
    // capture identified these 22 Mac fonts as fork-detected but
    // iPhone-iOS-18.6-undetected (browserleaks-style measureText).
    { "iphone16pro_ios18_6", "al bayan" },
    { "iphone16pro_ios18_6", "al tarikh" },
    { "iphone16pro_ios18_6", "andale mono" },
    { "iphone16pro_ios18_6", "arial black" },
    { "iphone16pro_ios18_6", "arial narrow" },
    { "iphone16pro_ios18_6", "brush script mt" },
    { "iphone16pro_ios18_6", "comic sans ms" },
    { "iphone16pro_ios18_6", "geneva" },
    { "iphone16pro_ios18_6", "gujarati sangam mn" },
    { "iphone16pro_ios18_6", "gurmukhi mn" },
    { "iphone16pro_ios18_6", "kannada sangam mn" },
    { "iphone16pro_ios18_6", "lucida grande" },
    { "iphone16pro_ios18_6", "microsoft sans serif" },
    { "iphone16pro_ios18_6", "oriya sangam mn" },
    { "iphone16pro_ios18_6", "plantagenet cherokee" },
    { "iphone16pro_ios18_6", "simsun" },
    { "iphone16pro_ios18_6", "tahoma" },
    { "iphone16pro_ios18_6", "trattatello" },
    { "iphone16pro_ios18_6", "webdings" },
    { "iphone16pro_ios18_6", "wingdings" },
    { "iphone16pro_ios18_6", "wingdings 2" },
    { "iphone16pro_ios18_6", "wingdings 3" },

    // iphone16pro_ios26_4_1 archetype — empty pending founder iOS 26.4
    // fonts capture (V-242 URL). Until populated, iOS 26.4 archetype
    // runs without font denying.
};

// Locally inlined archetype helpers (parallel to V-245 canvas-table
// inlines; kept here to avoid header coupling). std::string_view used
// for safe string compare (WebKit forbids strcmp + raw pointer
// arithmetic under -Werror,-Wunsafe-buffer-*).
inline const char* driftstackFontsCurrentArchetypeCStr()
{
    static const char* archetype = []() {
        const char* env = getenv("DRIFTSTACK_ARCHETYPE");
        return env && env[0] ? env : "iphone16pro_ios18_6";
    }();
    return archetype;
}

inline bool driftstackFontsArchetypeEq(const char* a, const char* b)
{
    return std::string_view(a) == std::string_view(b);
}

inline bool driftstackFamilyDenylistedForArchetype(const char* archetype, const WTF::AtomString& family)
{
    if (family.isEmpty())
        return false;
    auto folded = family.string().convertToASCIILowercase();
    for (const auto& entry : kDriftstackFontsDenylist) {
        if (!driftstackFontsArchetypeEq(entry.archetype, archetype))
            continue;
        if (folded == WTF::String::fromUTF8(entry.familyLowercase))
            return true;
    }
    return false;
}

// Convenience overload — uses the runtime archetype selector.
inline bool driftstackFamilyDenylisted(const WTF::AtomString& family)
{
    return driftstackFamilyDenylistedForArchetype(driftstackFontsCurrentArchetypeCStr(), family);
}
