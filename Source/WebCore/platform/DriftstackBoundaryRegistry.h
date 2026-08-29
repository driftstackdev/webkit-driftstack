// DriftstackBoundaryRegistry.h — GENERATED, DO NOT EDIT BY HAND.
//
// Source of truth: operations/boundary-registry.json
// Generator:       operations/scripts/build-boundary-header.py
// Regenerate:      python3 operations/scripts/build-boundary-header.py
//
// WHY THIS FILE EXISTS (CLAUDE.md Rule 7): the fork had ~120+ hand-rolled version/model/family
// boundary-parse sites, each re-deriving a boundary the boundary-registry already declares. That
// duplication is the ROOT of the canvas Family-A/B conflation (one lambda hand-rolled "pre-Safari-26"
// = safari17_..25_ and WRONGLY dropped 26.0-26.3 into Family-B, while the canvas file a few over had
// the correct <=26.3 cutoff). Here every boundary is emitted ONCE from the registry, so a registry
// edit shifts every consuming site together. Migrate the hand-rolled lambdas to call these accessors
// (see docs/internal/M2-LAMBDA-MIGRATION-PLAN.md) — do not add a 121st hand-roll.
//
// PHASE/THREADING: each accessor parses DRIFTSTACK_ARCHETYPE EXACTLY ONCE via a function-local
// `static const bool` (C++11 thread-safe one-time init), through the shared driftstackParseArchetype()
// helper. Unset env returns the launch default (Family B / Safari 26.4 / Kefa absent), matching every
// current fork lambda's `if (!archetype) return ...` guardrail.
//
// Surfaces emitted from the registry: canvas_2d_pixel, webgpu_exposed, av1_canplaytype, canvas_avif_toblob_boundary, vp9_mse_istypesupported_boundary (+ driftstackKefaPresent, pending a registry surface).

#pragma once

#include <cstdlib>
#include <string_view>

namespace WebCore {

// Parsed view of DRIFTSTACK_ARCHETYPE. The slug grammar is
//   <model>_ios<MAJ>_<MIN>_safari<MAJ>_<MIN>   e.g. "iphone17_ios18_7_safari26_4"
//                                                    "iphone16pro_ios18_6_safari18_6"
// modelSlug is the leading token up to the first "_ios"; safariMajor/Minor are parsed from the
// "safari<MAJ>_<MIN>" token. `present` is false iff the env var is unset/empty (=> launch default).
struct DriftstackArchetype {
    bool present { false };
    std::string_view modelSlug {};   // e.g. "iphone17", "iphone16pro" (leading run up to "_ios")
    int safariMajor { 0 };
    int safariMinor { 0 };
};

// Parse an archetype SLUG. Pure of side effects.
// Split out of driftstackParseArchetype() so the same parse can classify a slug that is NOT this
// process's own archetype: the cross-archetype canvas fallback in
// DriftstackCanvasFingerprint10xOverride.h classifies a DONOR archetype, and an env-reading function
// structurally cannot answer that — which is why that file hand-rolls its own rfind("_safari").
inline DriftstackArchetype driftstackParseArchetypeSlug(const char* slug)
{
    DriftstackArchetype out;
    if (!slug || !slug[0])
        return out;  // present stays false => launch default
    out.present = true;
    std::string_view sv(slug);

    // modelSlug = leading run up to "_ios" (fallback: up to first '_').
    auto iosPos = sv.find("_ios");
    out.modelSlug = (iosPos != std::string_view::npos) ? sv.substr(0, iosPos)
                                                       : sv.substr(0, sv.find('_'));

    // safariMajor/Minor from the "safari<MAJ>_<MIN>" token.
    auto sfPos = sv.find("safari");
    if (sfPos != std::string_view::npos) {
        size_t i = sfPos + 6;  // len("safari")
        int major = 0;
        while (i < sv.size() && sv[i] >= '0' && sv[i] <= '9') {
            major = major * 10 + (sv[i] - '0');
            ++i;
        }
        out.safariMajor = major;
        if (i < sv.size() && sv[i] == '_') {
            ++i;
            int minor = 0;
            while (i < sv.size() && sv[i] >= '0' && sv[i] <= '9') {
                minor = minor * 10 + (sv[i] - '0');
                ++i;
            }
            out.safariMinor = minor;
        }
    }
    return out;
}

// Parse DRIFTSTACK_ARCHETYPE once. Pure of side effects; callers should cache in a static.
inline DriftstackArchetype driftstackParseArchetype()
{
    return driftstackParseArchetypeSlug(std::getenv("DRIFTSTACK_ARCHETYPE"));
}

// The canvas family question is THREE-valued, and every bool form of it loses a value. A slug with no
// "safari<MAJ>_<MIN>" token — a chrome-on-iOS archetype, or a legacy slug like iphone16pro_ios18_6 —
// carries no family information at all, and the two existing predicates collapse that in OPPOSITE
// directions: driftstackCanvasFamilyA() returns false ("not A", read downstream as B) while the
// hand-rolled driftstackArchetypeIsFamilyB(slug) returns false ("not B", i.e. A). Same input, opposite
// conclusion, and neither answer is B — both are really "unknown". Callers that must tell "not A" from
// "no information" use this form and decide for themselves what Unknown means.
enum class DriftstackCanvasFamily { Unknown, A, B };

// derived from: registry surface "canvas_2d_pixel"
inline DriftstackCanvasFamily driftstackCanvasFamilyForSlug(const char* slug)
{
    const DriftstackArchetype a = driftstackParseArchetypeSlug(slug);
    if (!a.present)
        return DriftstackCanvasFamily::Unknown;  // unset/empty => launch default, not a family
    if (a.safariMajor <= 0)
        return DriftstackCanvasFamily::Unknown;  // no safari<N>_ token => NO INFORMATION
    if (a.safariMajor < 26)
        return DriftstackCanvasFamily::A;        // any pre-26 Safari is Family A
    if (a.safariMajor > 26)
        return DriftstackCanvasFamily::B;
    return a.safariMinor <= 3 ? DriftstackCanvasFamily::A : DriftstackCanvasFamily::B;
}

// Canvas Family-A iff Safari minor <= 26.3 (registry canvas_2d_pixel families.A "<=26.3"). Replaces s_isFamilyAArchetype + the 14 canvas/CSS/webauthn hand-rolls. A => target 61b7a151, B => 57186fab.
// derived from: registry surface "canvas_2d_pixel" (status: BOUNDARY-CONFIRMED, per-family target VERIFY-on-real-device)
inline bool driftstackCanvasFamilyA()
{
    return [&]() -> bool {
        const DriftstackArchetype a = driftstackParseArchetype();
        if (!a.present)
            return false;  // unset env = launch default
        if (a.safariMajor <= 0)
            return false;  // slug carries no safari<N>_ token (e.g. a
                           // chrome-on-iOS archetype) => NO INFORMATION, take the launch default
        if (a.safariMajor < 26)
            return true;   // any pre-26 Safari is Family A
        if (a.safariMajor > 26)
            return false;
        return a.safariMinor <= 3;  // within major 26: Family A iff minor <= 3
    }();
}

// navigator.gpu exposed iff model is A16+ (registry webgpu_exposed families.exposed) AND Safari major >= 26. Replaces the 3-copy WebPage/Navigator/WorkerNavigator gate. exposed => true, hidden => false.
// derived from: registry surface "webgpu_exposed" (status: VERIFIED VERSION-KEYED (Safari>=26 PRESENT all-chips incl A15, <26 ABSENT all-chips) real-device 2026-06-28 (a4222a80/#119): A15 flips on version axis (18.3.1 ABSENT -> 26.4 PRESENT), A17Pro/A18Pro PRESENT. Fork matches every captured cell. A15@26.0/26.1 sub-cell = BS-POOL PHYSICAL BOUND (proven 2026-06-29, see closure-analysis note): the BS iOS-26 pool floats to 26.2-26.4 (>7 iPhone-14 attempts incl 4 fresh never landed 26.0/26.1; no BS minor-pin). A18-non-Pro@26 sibling cell = BS HARD-REJECTS iPhone 16 @ os 26. DECISION PENDING (founder/A3): version-key the fork A15 cutoff to 26.0 to match the config (drafted in scratchpad A15-WEBGPU-MINOR-FIX-DRAFT.md; gate webgpu-a15-minor-boundary-gate.sh); else fork stays conservative-26.2 (config/fork incoherent at iphone14_..._safari26_0).)
inline bool driftstackWebGPUExposed()
{
    return [&]() -> bool {
        const DriftstackArchetype a = driftstackParseArchetype();
        if (!a.present)
            return true;  // unset env = launch default (A16+ launch model)
        const bool a16Plus = a.modelSlug.starts_with("iphone17") || a.modelSlug.starts_with("iphone16") || a.modelSlug.starts_with("iphone15") || a.modelSlug.starts_with("iphone14pro");
        if (a16Plus)
            return a.safariMajor >= 26;
        // registry families.exposed second clause: A15-non-Pro from 26.2 onward
        const bool secondary = a.modelSlug.starts_with("iphone13") || a.modelSlug.starts_with("iphone14") || a.modelSlug.starts_with("iphone14plus");
        if (!secondary)
            return false;
        if (a.safariMajor > 26)
            return true;
        return a.safariMajor == 26 && a.safariMinor >= 2;
    }();
}

// Silicon tier: true iff the model is A17Pro or newer (registry av1_canplaytype families.A17Pro_plus). Version-INVARIANT — the SAME split backs av01 canPlayType, HEVC decode-level ceiling, webrtc video-pt and the webgl trig scene, at every Safari major measured. Migrate the hand-rolled `find("iphone15pro")==0 || …` chip lists in HEVCUtilitiesCocoa.mm / DriftstackArchetypeConfig.mm / Adapter.mm to this.
// derived from: registry surface "av1_canplaytype" (status: CLOSED 2026-06-30 — BOUNDARY-CONFIRMED real-device (A15/A16 av01='' ; A17Pro+ av01='probably') AND REVERSE-render CLOSED 2026-06-30 daemon 70461 (HEAD f22cc48e0c, box=M2Pro-Mac14,12-devbox [chip confirmed 2026-07-08 — NOT the M3-Ultra fleet the label assumed; this surface is host-INDEPENDENT so the closure holds on any chip]): iphone17(A19) canPlayType.av01='probably' + iphone14(A15) '' + webcodecs false ; av1-canplaytype-perchip-gate.sh exit 0, boundary pair mutation-verified. decodingInfo matrix by av1-decinfo-matrix-gate.sh. Was — 'committed; A3 build-pending'.)
inline bool driftstackIsA17ProOrNewer()
{
    return [&]() -> bool {
        const DriftstackArchetype a = driftstackParseArchetype();
        if (!a.present)
            return true;  // unset env = launch default
        return a.modelSlug.starts_with("iphone15pro") || a.modelSlug.starts_with("iphone15promax") || a.modelSlug.starts_with("iphone16") || a.modelSlug.starts_with("iphone17");
    }();
}

// toBlob/convertToBlob normalizes image/avif to image/png iff Safari MAJOR < 26 (registry canvas_avif_toblob_boundary families.A "<26"). ⚠️ This is a MAJOR cutoff and is NOT the same boundary as driftstackCanvasFamilyA (MINOR <=26.3): 26.0-26.3 are Family-A for canvas PIXELS and Family-B here (they return avif natively, capture-confirmed over 213 aio captures). Conflating the two is the original Family-A/B bug. Migrate the safari17_..25_ enumerations in HTMLCanvasElement.cpp (main toBlob) and OffscreenCanvas.cpp (worker convertToBlob) to this.
// derived from: registry surface "canvas_avif_toblob_boundary" (status: n/a)
inline bool driftstackAvifToBlobNormalizesToPng()
{
    return [&]() -> bool {
        const DriftstackArchetype a = driftstackParseArchetype();
        if (!a.present)
            return false;  // unset env = launch default
        return a.safariMajor > 0 && a.safariMajor < 26;
    }();
}

// ManagedMediaSource.isTypeSupported(video/mp4; codecs="vp09.*") is FALSE iff Safari MAJOR < 26 (registry vp9_mse_istypesupported_boundary families.A "<26"). Chip-INDEPENDENT. Migrate DriftstackArchetypeConfig.mm driftstackFamilyAVP9MSEUnsupported() to this; both asserting gates (vp9-decinfo-container-split, mse-changetype-istypesupported-coherence) currently re-derive it from literals with no registry reference.
// derived from: registry surface "vp9_mse_istypesupported_boundary" (status: n/a)
inline bool driftstackVP9MSEUnsupported()
{
    return [&]() -> bool {
        const DriftstackArchetype a = driftstackParseArchetype();
        if (!a.present)
            return false;  // unset env = launch default
        return a.safariMajor > 0 && a.safariMajor < 26;
    }();
}

// Kefa font present iff Safari major < 26 (FontCacheCoreText.cpp 2026-06-27 split). No dedicated registry surface yet — boundary is the documented Safari-major cutoff.
// derived from: no registry surface yet (status: n/a)
inline bool driftstackKefaPresent()
{
    return [&]() -> bool {
        const DriftstackArchetype a = driftstackParseArchetype();
        if (!a.present)
            return false;  // unset env = launch default
        return a.safariMajor > 0 && a.safariMajor < 26;
    }();
}

} // namespace WebCore
