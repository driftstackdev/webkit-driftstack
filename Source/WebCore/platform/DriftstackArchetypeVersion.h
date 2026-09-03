// DriftstackArchetypeVersion.h — the ONE per-archetype Safari-version predicate.
//
// driftstackArchetypeSafariAtLeast(major, minor) answers "is this process's archetype Safari >= major.minor?"
// from DRIFTSTACK_ARCHETYPE. Every band-keyed site in WebCore and WebKit calls this; do not add a file-local
// copy (six of them drifted apart: five treated an unset env as TRUE, one as FALSE, and only that one accepted
// '.' between major and minor).
//
// Parse: driftstackParseArchetype() from the generated DriftstackBoundaryRegistry.h — the same parser every
// registry accessor uses, so the "safari<MAJ>_<MIN>" / "safari<MAJ>.<MIN>" grammar lives in exactly one place.
//
// Unset / empty / no "safari<N>" token => the LAUNCH archetype (Safari 26.4). This is the convention every
// registry accessor's launch default and the JSC Asuncion gate (dsMajor == 0 => newest band) already follow.
// So at the shipped unset default the predicate is TRUE for every boundary <= 26.4 and FALSE for boundaries
// above it (26.5+): the unset default never hides a launch feature and never exposes a post-launch one.
//
// Read LIVE on every call, never cached in a function-local static: the per-band env can be applied after
// early process init, and a static would freeze the launch default for every archetype (gate silently inert).

#pragma once

#include "DriftstackBoundaryRegistry.h"

namespace WebCore {

// The launch archetype's Safari version. Every unset / unparseable DRIFTSTACK_ARCHETYPE resolves here.
inline constexpr int driftstackLaunchSafariMajor = 26;
inline constexpr int driftstackLaunchSafariMinor = 4;

inline bool driftstackArchetypeSafariAtLeast(int wantMajor, int wantMinor)
{
    const DriftstackArchetype archetype = driftstackParseArchetype();
    const bool parsed = archetype.present && archetype.safariMajor > 0;
    const int major = parsed ? archetype.safariMajor : driftstackLaunchSafariMajor;
    const int minor = parsed ? archetype.safariMinor : driftstackLaunchSafariMinor;
    return major > wantMajor || (major == wantMajor && minor >= wantMinor);
}

} // namespace WebCore
