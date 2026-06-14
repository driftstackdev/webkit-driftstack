// V-253 (overnight 2026-05-06) multi-archetype fonts denylist.
// Per-archetype list of Mac-only font families to reject in
// FontCache::cachedFontPlatformData / FontCache::createFontPlatformData
// so that content-derived measureText probes report these as
// "not installed" (matching real iPhone behavior).
//
// Currently derived from V-237.2 BS Automate iPhone 16 Pro / iOS 18.6
// tracker-probe-fonts probe (171 detected on iPhone vs 193 detected on
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
    // iPhone-iOS-18.6-undetected (content-derived measureText).
    { "iphone16pro_ios18_6", "al bayan" },
    { "iphone16pro_ios18_6", "al tarikh" },
    { "iphone16pro_ios18_6", "andale mono" },
    { "iphone16pro_ios18_6", "arial black" },
    { "iphone16pro_ios18_6", "arial narrow" },
    { "iphone16pro_ios18_6", "arial unicode ms" },
    { "iphone16pro_ios18_6", "brush script mt" },
    { "iphone16pro_ios18_6", "comic sans ms" },
    { "iphone16pro_ios18_6", "geneva" },
    { "iphone16pro_ios18_6", "gujarati sangam mn" },
    { "iphone16pro_ios18_6", "gurmukhi mn" },
    { "iphone16pro_ios18_6", "kannada sangam mn" },
    { "iphone16pro_ios18_6", "lucida grande" },
    { "iphone16pro_ios18_6", "microsoft sans serif" },
    { "iphone16pro_ios18_6", "monaco" },
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

    // iphone17_ios18_7_safari26_4 archetype (launch archetype) — wave
    // 29-194/195 v433x-exhaustive (511 fonts × measureText vs monospace
    // baseline). Diff: fork detected 141 vs BS iPhone16Pro/iOS18.7/Safari26.4
    // detected 109 → 36 Mac-only false positives below. Wave 29-195 add
    // (v404 probe @ 128px + currency-bearing sample text): al bayan, al
    // tarikh, arial black, arial narrow, arial unicode ms, trattatello —
    // detected by v404 conditions but not v433x's (Mac/iPhone width-equals-
    // monospace coincidence at v433x params). Per V-237.2 empirical iOS
    // 18.6 capture these are Mac-only. Lowercase, sorted.
    { "iphone17_ios18_7_safari26_4", "al bayan" },
    { "iphone17_ios18_7_safari26_4", "al tarikh" },
    { "iphone17_ios18_7_safari26_4", "andale mono" },
    { "iphone17_ios18_7_safari26_4", "apple chancery" },
    { "iphone17_ios18_7_safari26_4", "applemyungjo" },
    { "iphone17_ios18_7_safari26_4", "arial black" },
    { "iphone17_ios18_7_safari26_4", "baghdad" },
    { "iphone17_ios18_7_safari26_4", "beirut" },
    { "iphone17_ios18_7_safari26_4", "arial narrow" },
    { "iphone17_ios18_7_safari26_4", "arial unicode ms" },
    { "iphone17_ios18_7_safari26_4", "big caslon" },
    { "iphone17_ios18_7_safari26_4", "brush script mt" },
    { "iphone17_ios18_7_safari26_4", "comic sans ms" },
    { "iphone17_ios18_7_safari26_4", "diwan kufi" },
    { "iphone17_ios18_7_safari26_4", "diwan thuluth" },
    { "iphone17_ios18_7_safari26_4", "farisi" },
    { "iphone17_ios18_7_safari26_4", "geneva" },
    { "iphone17_ios18_7_safari26_4", "gujarati sangam mn" },
    { "iphone17_ios18_7_safari26_4", "gurmukhi mn" },
    { "iphone17_ios18_7_safari26_4", "gurmukhi sangam mn" },
    { "iphone17_ios18_7_safari26_4", "herculanum" },
    { "iphone17_ios18_7_safari26_4", "inaimathi" },
    { "iphone17_ios18_7_safari26_4", "kannada mn" },
    { "iphone17_ios18_7_safari26_4", "kannada sangam mn" },
    { "iphone17_ios18_7_safari26_4", "kefa" },
    { "iphone17_ios18_7_safari26_4", "kufistandardgk" },
    { "iphone17_ios18_7_safari26_4", "lucida grande" },
    { "iphone17_ios18_7_safari26_4", "luminari" },
    { "iphone17_ios18_7_safari26_4", "microsoft sans serif" },
    { "iphone17_ios18_7_safari26_4", "monaco" },
    { "iphone17_ios18_7_safari26_4", "muna" },
    { "iphone17_ios18_7_safari26_4", "nadeem" },
    { "iphone17_ios18_7_safari26_4", "oriya sangam mn" },
    { "iphone17_ios18_7_safari26_4", "pt mono" },
    { "iphone17_ios18_7_safari26_4", "pt sans" },
    { "iphone17_ios18_7_safari26_4", "pt serif" },
    { "iphone17_ios18_7_safari26_4", "plantagenet cherokee" },
    { "iphone17_ios18_7_safari26_4", "sana" },
    { "iphone17_ios18_7_safari26_4", "songti sc" },
    { "iphone17_ios18_7_safari26_4", "songti tc" },
    { "iphone17_ios18_7_safari26_4", "stixtwomath" },
    { "iphone17_ios18_7_safari26_4", "shree devanagari 714" },
    { "iphone17_ios18_7_safari26_4", "simsun" },
    { "iphone17_ios18_7_safari26_4", "sinhala mn" },
    { "iphone17_ios18_7_safari26_4", "skia" },
    { "iphone17_ios18_7_safari26_4", "tahoma" },
    { "iphone17_ios18_7_safari26_4", "tamil mn" },
    { "iphone17_ios18_7_safari26_4", "telugu mn" },
    { "iphone17_ios18_7_safari26_4", "trattatello" },
    { "iphone17_ios18_7_safari26_4", "waseem" },
    { "iphone17_ios18_7_safari26_4", "webdings" },
    { "iphone17_ios18_7_safari26_4", "wingdings" },
    { "iphone17_ios18_7_safari26_4", "wingdings 2" },
    { "iphone17_ios18_7_safari26_4", "wingdings 3" },
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

// W2556 (config-coherence audit #5): the Mac-only-font denylist reflects iOS FONT AVAILABILITY
// (which font files exist on the device) — MODEL-INDEPENDENT, keyed only by iOS version. It was
// keyed by the EXACT slug, so only the launch slug iphone17_ios18_7_safari26_4 ever matched and
// EVERY other archetype got an EMPTY denylist (Mac-only fonts a real iPhone hides stayed visible =
// a per-model font-detection tell). Match by iOS version instead: every model on iOS 18.7 → the
// iphone17 (18.7) set, every model on iOS 18.6 → the iphone16pro (18.6) set. The 2 entry keys
// (iphone16pro_ios18_6, iphone17_ios18_7_safari26_4) are the only iOS versions in the 81-archetype
// matrix, so every archetype maps to exactly one set.
inline std::string_view driftstackFontsIosKey(std::string_view slug)
{
    auto p = slug.find("_ios");
    if (p == std::string_view::npos)
        return slug; // unkeyed: fall back to whole-slug compare
    auto rest = slug.substr(p + 4);          // e.g. "18_7_safari26_4" or "18_6"
    auto u1 = rest.find('_');                // end of "18"
    auto u2 = (u1 == std::string_view::npos) ? std::string_view::npos : rest.find('_', u1 + 1);
    return rest.substr(0, u2 == std::string_view::npos ? rest.size() : u2); // "18_7" | "18_6"
}

inline bool driftstackFontsArchetypeEq(const char* a, const char* b)
{
    return driftstackFontsIosKey(std::string_view(a)) == driftstackFontsIosKey(std::string_view(b));
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
