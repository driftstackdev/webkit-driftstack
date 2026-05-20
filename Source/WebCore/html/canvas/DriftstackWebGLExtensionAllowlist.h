/*
 * Driftstack — WebGL getSupportedExtensions allowlist (§11.D, Task #89).
 *
 * Empirical canonical (V-2026-05-20-W11D-WEBGL-EXTENSIONS-CANONICAL,
 * extended r2): 51-element set identical across Family A (iPhone 16 Pro
 * / Safari 18.6) and Family B (iPhone 17 / Safari 26.4). Initial 50 from
 * v2-fingerprint captures; +1 (NV_shader_noperspective_interpolation)
 * added from cumrig REF 2026-05-04T19-24-11Z_real-iphone-recapture.json
 * which is the authoritative full-real-iPhone baseline.  No archetype-
 * dependent variation for this surface, so a single allowlist constant
 * suffices.
 *
 * The post-filter is safe-by-construction: it only REMOVES entries the
 * Mac fork's natural getSupportedExtensions() would emit that iPhone does
 * not.  If Mac is missing a name that iPhone has, this filter cannot add
 * it; that case becomes a separate stub-implement task at the extension
 * class level.  Verification of the Mac-vs-iPhone diff happens on the
 * next cumrig build cycle (webgl1.parameters.extensions +
 * webgl2.parameters.extensions probes at captures/v1/index.html:588+629).
 */

#pragma once

#if PLATFORM(DRIFTSTACK)

#include <wtf/Forward.h>
#include <wtf/Vector.h>
#include <wtf/text/WTFString.h>

namespace WebCore {
namespace Driftstack {

WEBCORE_EXPORT bool isWebGLExtensionInIphoneCanonical(const String&);

WEBCORE_EXPORT void filterWebGLExtensionsToIphoneCanonical(Vector<String>& extensions);

} // namespace Driftstack
} // namespace WebCore

#endif // PLATFORM(DRIFTSTACK)
