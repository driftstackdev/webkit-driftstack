# Driftstack WebKit Fork — Modifications Index

Per-patch list of Driftstack-specific changes from upstream WebKit.

Per-patch format:
- **Patch ID** — internal identifier (matches V-062 wave numbering
  in main Driftstack repo).
- **Files** — files modified.
- **Surface** — fingerprint surface affected.
- **Source citation** — V-044 / V-047 entry in main Driftstack
  repo's `/experiments/layer1/`.
- **V-log** — corresponding entry in main Driftstack repo's
  `/operations/verification-log.md`.
- **Description** — what the patch does.

## Scaffolding

### scaffold-1: PLATFORM(DRIFTSTACK) compile-time gate

- **Patch ID:** `scaffold-1`
- **Files:** `Source/WTF/wtf/Platform.h` (+5 lines)
- **Description:** Adds `#define WTF_PLATFORM_DRIFTSTACK 1` to
  Platform.h. Per WebKit's `PLATFORM()` macro convention defined
  in `PlatformLegacy.h` line 38: `#define PLATFORM(WTF_FEATURE)
  (defined WTF_PLATFORM_##WTF_FEATURE && WTF_PLATFORM_##WTF_FEATURE)`.
  Defining `WTF_PLATFORM_DRIFTSTACK 1` makes `PLATFORM(DRIFTSTACK)`
  evaluate to true everywhere in this fork's compilation.
- **Status:** `driftstack-main` branch landing.

## Wave 1 — Configuration overrides at session boot

V-062 Wave 1 patches. Each surface gets the iPhone-archetype
default hardcoded inside `#if PLATFORM(DRIFTSTACK)`. The existing
upstream override hooks (e.g., `Page::setCustomNavigatorPlatform`)
remain intact for future per-archetype harness configuration.

### wave-1-1: navigator.platform → "iPhone"

- **Files:** `Source/WebCore/page/NavigatorBase.cpp` (+5 lines)
- **Surface:** `navigator.platform`
- **Source citation:** V-044 surface #1
- **Description:** `#if PLATFORM(DRIFTSTACK) return "iPhone"_s;`
  branch atop the OS-conditional cascade in `NavigatorBase::platform()`.

### wave-1-2: navigator.userAgent → iPhone iOS 26.4.1 launch UA

- **Files:** `Source/WebCore/page/Navigator.cpp` (+~10 lines)
- **Surface:** `navigator.userAgent` + derived `navigator.appVersion`
- **Source citation:** V-047 surfaces #1 + #2
- **Description:** `#if PLATFORM(DRIFTSTACK)` early-return in
  `Navigator::userAgent()` returning the launch-archetype UA per
  V-024 + D-2026-04-29-07. `navigator.appVersion` derives.

### wave-1-3: screen.width / height / availWidth / availHeight → 402×874

- **Files:** `Source/WebCore/page/Screen.cpp` (+~16 lines across 4 functions)
- **Surface:** `screen.{width, height, availWidth, availHeight}`
- **Source citation:** V-047 surface #3 group
- **Description:** `#if PLATFORM(DRIFTSTACK)` early-return with
  iPhone 16 Pro launch-archetype dimensions in the four `Screen::`
  size accessors.

### wave-1-4: window.devicePixelRatio → 3.0

- **Files:** `Source/WebCore/page/LocalDOMWindow.cpp` (+~4 lines)
- **Surface:** `window.devicePixelRatio`
- **Source citation:** V-044 surface #4
- **Description:** `#if PLATFORM(DRIFTSTACK)` early-return in
  `LocalDOMWindow::devicePixelRatio()` with iPhone 16 Pro DPR
  (3.0) multiplied by frame scale + page zoom factors.

### wave-1-5: screen.orientation.type → "portrait-primary"

- **Files:** `Source/WebCore/page/ScreenOrientation.cpp` (+~3 lines),
  `Source/WebCore/platform/PlatformScreen.{h,cpp}` (+~3 lines)
- **Surface:** `screen.orientation.type` + `.angle`
- **Source citation:** V-044 surface #5
- **Description:** `#if PLATFORM(DRIFTSTACK)` early-return in
  `ScreenOrientation::type()` and parallel patch in
  `naturalScreenOrientationType()` for `angle()` cross-coherence.

### wave-1-6: navigator.hardwareConcurrency → 4

- **Files:** `Source/WebCore/page/NavigatorBase.cpp` (+~3 lines)
- **Surface:** `navigator.hardwareConcurrency`
- **Source citation:** V-044 surface #3
- **Description:** `#if PLATFORM(DRIFTSTACK) return 4;` after
  the AFP-tracker check in `NavigatorBase::hardwareConcurrency()`.
  AFP path (1..64 random in tracker contexts per V-021) unchanged.

### wave-1-7: permissions.notifications default → "denied"

- **Files:** `Source/WebCore/Modules/notifications/Notification.cpp`
  (+~5 lines)
- **Surface:** `Notification.permission` +
  `permissions.queryAll.notifications`
- **Source citation:** V-044 surface #7
- **Description:** `#if PLATFORM(DRIFTSTACK) return Permission::Denied;`
  in `Notification::permission()` per iOS Safari default for
  non-PWA contexts.

### wave-1-8: Intl.locale + Intl.timeZone via env vars

- **Patch ID:** `wave-1-8` (no fork patch — wrapper-script-driven)
- **Surface:** `Intl.locale`, `Intl.timeZone`
- **Source citation:** V-047 surfaces #10 + #11
- **Description:** No WebKit C++ patch. Wrapper script at
  [driftstack/captures/v1/run-driftstack-safari.sh](https://github.com/driftstackdev/driftstack/blob/main/captures/v1/run-driftstack-safari.sh)
  sets `LANG`, `LC_ALL`, `TZ` env vars before launching Safari.
  ICU + WTF respect them.

## Wave 2 — Source patches (V-062 + V-066 reorganization)

### wave-2-1: navigator.maxTouchPoints → 5

- **Files:** `Source/WebCore/page/Navigator.cpp` (+~3 lines)
- **Surface:** `navigator.maxTouchPoints`
- **Source citation:** V-044 surface #2
- **Description:** `#if PLATFORM(DRIFTSTACK) return 5;` at top
  of `Navigator::maxTouchPoints()` body. Respects the existing
  `needsZeroMaxTouchPointsQuirk` per-document quirk.

### Stage A patches (Wave 2.2 – 2.10) — canvas-text rendering

Per [main repo Option B Stage A patch index](https://github.com/driftstackdev/driftstack/blob/main/docs/architecture/option-b-stage-a-patches.md).
Stage A is the WebKit/CGContext configuration matching tier of
the Option B 4-stage hybrid (D-2026-04-30-14 + D-15). Patches
land metrics-first (V-068 finding: font-metric divergences are
more load-bearing than smoothing for canvas-text bit-exactness).

### wave-2-2: FontCascade::drawGlyphs() font-smoothing toggle parity

- **Files:** `Source/WebCore/platform/graphics/coretext/FontCascadeCoreText.cpp`
  (+~4 lines across 2 sites)
- **Surface:** canvas-text rendering
- **Source citation:** V-067
- **Description:** Extends iOS-only block at lines 337-343 +
  394-397 to `#if PLATFORM(IOS_FAMILY) || PLATFORM(DRIFTSTACK)`.

### wave-2-3: CanvasRenderingContext2DBase forces sRGB on Driftstack

- **Files:** `Source/WebCore/html/canvas/CanvasRenderingContext2DBase.cpp`
- **Surface:** canvas color-managed output
- **Source citation:** V-067 + file 54
- **Description:** `defaultColorSpace()` returns
  `PredefinedColorSpace::SRGB` on Driftstack builds.

### wave-2-4: Driftstack font-smoothing-style at CGContext setup (empirical)

- **Files:** TBD (`FontCascadeCoreText.cpp` near `setCGFontRenderingMode`)
- **Surface:** font-smoothing intensity / gamma
- **Source citation:** V-067
- **Description:** `CGContextSetFontSmoothingStyle()` to
  iOS-equivalent integer. Initial value empirically determined
  in Stage A first 60 days; M3 decision-gate informs final value.
  If iOS uses a private CGContext SPI value not exposable here,
  this may need to live deeper (Stage D).

### wave-2-5: GraphicsContextCG drawImage iOS-equivalent

- **Files:** `Source/WebCore/platform/graphics/cg/GraphicsContextCG.cpp`
  (+~4 lines across 2 sites at lines 383 + 437)
- **Surface:** canvas image drawing
- **Source citation:** V-067
- **Description:** Extends iOS-only blocks for drawImage AA-off +
  pixel-alignment to also apply on Driftstack.

### wave-2-6: GraphicsContextCG dotted/dashed line stroke iOS-equivalent

- **Files:** `Source/WebCore/platform/graphics/cg/GraphicsContextCG.cpp`
  line 620
- **Surface:** canvas dotted/dashed line stroke AA
- **Source citation:** V-067

### wave-2-7: FontCoreText.cpp lineSpacing computation parity (HIGHEST IMPACT)

- **Files:** `Source/WebCore/platform/graphics/coretext/FontCoreText.cpp`
  (+~12 lines across multiple sites; helper-function gate also
  extended)
- **Surface:** font ascent / descent / lineSpacing → canvas text
  vertical positioning
- **Source citation:** V-068 (highest-impact font-metric finding)
- **Description:** Extends iOS branch (line 190) to
  `#if PLATFORM(IOS_FAMILY) || PLATFORM(DRIFTSTACK)` and gates
  macOS branch (line 174) with `&& !PLATFORM(DRIFTSTACK)`.
  Driftstack uses iOS-style ceil()-based rounding +
  `kLineHeightAdjustment = 0.15f` for Times/Helvetica/.Helvetica
  NeueUI.

### wave-2-8: FontCoreText.cpp suppress macOS Times/Helvetica/Courier ascent +15%

- **Files:** `Source/WebCore/platform/graphics/coretext/FontCoreText.cpp`
  lines 151-159
- **Surface:** Times/Helvetica/Courier ascent metric
- **Source citation:** V-068

### wave-2-9: FontCoreText.cpp suppress Hiragino metrics hack

- **Files:** `Source/WebCore/platform/graphics/coretext/FontCoreText.cpp`
  lines 178-185
- **Surface:** Hiragino font line metrics
- **Source citation:** V-068

### wave-2-10: FontCoreText.cpp Courier New fixed-pitch parity

- **Files:** `Source/WebCore/platform/graphics/coretext/FontCoreText.cpp`
  lines 779-782
- **Surface:** Courier New `measureText` width / fixed-pitch
- **Source citation:** V-068

## Wave 3 — Filtered passthroughs at WebKit layer

WebGL / WebGPU / codec / payment / scroll / dimensions filtering
where Mac fleet's underlying driver or system returns Mac-specific
values; WebKit-layer filter substitutes iPhone-archetype values.
Per-patch detail; commit hashes resolve via `git log driftstack-main`.

### wave-3-1: GPU adapter buffer-size limits clamp to iPhone values

- **Commit:** `194ac487`
- **Files:** `Source/WebCore/Modules/WebGPU/GPUSupportedLimits.cpp`
- **Surface:** `navigator.gpu.requestAdapter().limits.{maxBufferSize, maxStorageBufferBindingSize, maxUniformBufferBindingSize}`
- **Description:** Clamp three buffer-size limits to iPhone 16 Pro values via `std::min<uint64_t>(m_backing->maxBufferSize(), 1073741824ULL)` etc.

### wave-3-2 / 3-2-extension / 3-2-extension-2 / 3-2-fix: matchMedia hover/pointer/orientation

- **Commits:** various; ends `fded66ef`, `6ed27b3d`, `65f42a72`
- **Files:** `Source/WebCore/css/query/MediaQueryFeatures.cpp`
- **Surface:** `matchMedia('(hover: hover)')`, `(pointer: coarse)`, `(any-hover: none)`, `(any-pointer: coarse)`, `(orientation: portrait)`, `(device-width: 402px)`, `(device-height: 874px)`
- **Description:** Override 7 CSS media-feature evaluators on Driftstack to return iPhone-touch-only / iPhone-portrait / iPhone-archetype-dimensions values.

### wave-3-3: GPU adapter maxInterStageShaderVariables → 124

- **Commit:** `bb918088`
- **Files:** `Source/WebCore/Modules/WebGPU/GPUSupportedLimits.cpp`
- **Surface:** `navigator.gpu.requestAdapter().limits.maxInterStageShaderVariables`
- **Description:** Returns 124 (iPhone) instead of Mac's higher value.

### wave-3-4: WebAuthn UVPA + conditionalMediation availability → true

- **Commit:** `27ddaaf4`
- **Files:** `Source/WebCore/Modules/webauthn/AuthenticatorCoordinator.cpp`
- **Surface:** `PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()`, `PublicKeyCredential.isConditionalMediationAvailable()`
- **Description:** Force-return true on Driftstack to match iPhone Touch ID/Face ID availability.

### wave-3-5: GPU adapter features filter — drop clip-distances

- **Commit:** `d688bc55`
- **Files:** `Source/WebCore/Modules/WebGPU/GPUSupportedFeatures.cpp`
- **Surface:** `navigator.gpu.requestAdapter().features` set
- **Description:** Filter out `clip-distances` feature on Driftstack — iPhone 16 Pro doesn't expose it.

### wave-3-6: WebGL2 getParameter filter — 6 limit values

- **Commit:** `c7cab7e8`
- **Files:** `Source/WebCore/html/canvas/WebGL2RenderingContext.cpp`
- **Surface:** `gl.getParameter(MAX_*)` for 6 specific PNAMEs
- **Description:** Clamp / substitute MAX_VERTEX_UNIFORM_COMPONENTS, MAX_FRAGMENT_UNIFORM_COMPONENTS, MAX_VARYING_COMPONENTS, etc. to iPhone values.

### wave-3-7: WebGL1 MAX_VARYING_VECTORS → 31

- **Commit:** `4efbaa5a`
- **Files:** `Source/WebCore/html/canvas/WebGLRenderingContextBase.cpp`
- **Surface:** `gl.getParameter(MAX_VARYING_VECTORS)`
- **Description:** Returns 31 (iPhone 16 Pro) instead of Mac higher value.

### wave-3-8 + wave-3-8-extension: storage.estimate quota / usage

- **Commits:** `fe771d7e`, `6f50ecc3`
- **Files:** `Source/WebCore/Modules/storage/StorageManager.cpp`
- **Surface:** `navigator.storage.estimate()` quota + usage
- **Description:** quota /= 2 (approximate iPhone tier); usage = 0.

### wave-3-9 → wave-3-9-revert: TOUCH_EVENTS extension attempt

- **Commits:** `89ef9b37` → `8f051fcb`
- **Status:** REVERTED — enabling TOUCH_EVENTS exposed missing source files in WebCore.xcodeproj. PlatformTouchEvent.h is gated on `PLATFORM(IOS_FAMILY) && USE(APPLE_INTERNAL_SDK)`. Touch/TouchEvent/TouchList compilation needs Apple-internal SDK or stub-class approach. Tracked as future work.

### wave-3-10: accept self-signed certs for localhost in MiniBrowser

- **Commit:** `8d744684`
- **Files:** `Tools/MiniBrowser/mac/WK2BrowserWindowController.m`
- **Surface:** N/A (rig infrastructure — enables HTTPS rig variant)
- **Description:** `didReceiveAuthenticationChallenge` accepts self-signed certs for `localhost`/`127.0.0.1` on Driftstack so the HTTPS-only rig (ApplePaySession surfaces, secure-context APIs) can run without cert installation.

### wave-3-11 + wave-3-11-fix: AES-KW generateKey errors

- **Commits:** `017ccf62`, `57ca6127`
- **Files:** `Source/WebCore/crypto/algorithms/CryptoAlgorithmAESKW.cpp`
- **Surface:** `crypto.subtle.generateKey({name:'AES-KW',length:128},...)` error message
- **Description:** Reject AES-KW generateKey with `ExceptionCode::SyntaxError` (text "A required parameter was missing or out-of-range") to match iPhone behavior.

### wave-3-12: ApplePaySession status constants iOS legacy naming

- **Commit:** `d77576c6`
- **Files:** `Source/WebCore/Modules/applepay/ApplePaySession.idl` + `ApplePaySession.h`
- **Surface:** `ApplePaySession.STATUS_INVALID_BILLING_ADDRESS` + `STATUS_INVALID_SHIPPING_ADDRESS`
- **Description:** Rename IDL constant names from POSTAL_ADDRESS variants to non-POSTAL (iPhone Safari ships the legacy names). H-file aliases preserve enum values.

### wave-3-13: window/visualViewport dimensions match iPhone archetype

- **Commit:** `4d530988`
- **Files:** `Source/WebCore/page/LocalDOMWindow.cpp` + `VisualViewport.cpp`
- **Surface:** `window.{innerWidth,innerHeight,outerWidth,outerHeight,screenX,screenY}` + `visualViewport.{width,height,pageTop}`
- **Description:** Hardcode iPhone 16 Pro values: 402×714 inner, 402×874 outer, 0/0 screen. Bypasses upstream layout-derived computation so the value is constant regardless of MiniBrowser's actual NSWindow geometry.

### wave-3-14: speech.voices Samantha identifier compact tier

- **Commit:** `dfbda840`
- **Files:** `Source/WebCore/platform/cocoa/PlatformSpeechSynthesizerCocoa.mm`
- **Surface:** `speechSynthesis.getVoices()[*].voiceURI` for Samantha
- **Description:** Substitute `com.apple.voice.super-compact.en-US.Samantha` → `com.apple.voice.compact.en-US.Samantha` in voice list construction. iPhone Safari ships Samantha at the higher-quality "compact" tier; only this 1 voice URI differs across the 68-voice list.

### wave-1-7-extension: Permissions API notifications + push → denied

- **Commit:** `fb0090e4`
- **Files:** `Source/WebCore/Modules/permissions/Permissions.cpp`
- **Surface:** `navigator.permissions.query({name:'notifications'})` + `'push'`
- **Description:** Both return `Permission::Denied` to match iPhone non-PWA defaults.

### wave-1-8-fix → wave-1-8-fix-4: TZ + LANG + LC_ALL env-var propagation chain

- **Commits:** `2c6910ef` → `79c52234` → `88c3461b` → `016a47ad`
- **Files:** `Source/WebKit/UIProcess/Launcher/cocoa/ProcessLauncherCocoa.mm` + `Source/WebKit/Shared/EntryPointUtilities/Cocoa/XPCService/XPCServiceMain.mm`
- **Surface:** `Date.toString()` timezone, `Intl.DateTimeFormat().resolvedOptions().timeZone`, `Date.getTimezoneOffset()`
- **Description:** Forwards TZ/LANG/LC_ALL env vars from UIProcess to WebContent XPC service via `xpc_dictionary_set_string("ContainerEnvironmentVariables", …)`. fix-4 found and resolved root cause: outer gate at line 379 was `#if PLATFORM(IOS_FAMILY)` only, excluding Driftstack from compiling the entire block. Extended to `IOS_FAMILY || DRIFTSTACK`. Also calls `WTF::setTimeZoneOverride()` in XPCServiceMain so JSC's DateCache picks up the value before any Date code runs.

### wave-2-2-prefs-fix-2: MiniBrowser don't force-enable Notification/Push

- **Commit:** `5ba46417`
- **Files:** `Tools/MiniBrowser/mac/AppDelegate.m`
- **Surface:** `Notification` + `PushManager` global presence
- **Description:** Removed unconditional force-enables; the YAML default (NotificationsEnabled=false on Driftstack) now takes effect.

### wave-2-4-prefs-fix: disable FEATURE_DEFAULT_VALIDATION

- **Commit:** `6a47775e`
- **Files:** `Source/WTF/wtf/PlatformEnable.h`
- **Surface:** N/A (build infrastructure)
- **Description:** Gates off the `static_assert` validation of stable-feature defaults on Driftstack so wave-2-* prefs YAML overrides compile without firing the assert.

### wave-2-5-prefs / wave-2-6-prefs: PaymentRequest + ApplePay enabled

- **Commits:** `f1d629ad`, `8a373b29`
- **Files:** `Source/WebCore/page/Settings.yaml`, `Source/WTF/Scripts/Preferences/UnifiedWebPreferences.yaml`
- **Surface:** PaymentRequest + ApplePaySession constructors exposed
- **Description:** Both default true on Driftstack.

### scaffold-1-fix: define WTF_PLATFORM_DRIFTSTACK before PlatformEnable.h

- **Commit:** `27a46e43`
- **Files:** `Source/WTF/wtf/Platform.h`
- **Surface:** N/A (foundational fix)
- **Description:** Originally placed after Platform*.h includes. With the wrong order, `!PLATFORM(DRIFTSTACK)` gates evaluated as if DRIFTSTACK was undefined, breaking wave-2-4-prefs-fix's static_assert gating. Reorder fixes the cascade.

### stage-a-2-3: screenColorSpace returns SRGB on Driftstack

- **Commit:** `1f8efe77`
- **Files:** `Source/WebCore/platform/mac/PlatformScreenMac.mm`
- **Surface:** `screenColorSpace()` for Driftstack ViewTransitions
- **Description:** Returns `DestinationColorSpace::SRGB()` unconditionally on Driftstack, bypassing Mac's `screenProperties(widget)->colorSpace` which returns DisplayP3 for HDR-capable Macs. Note: zero rig impact since canvas pipeline uses `PredefinedColorSpace::SRGB()` by default; this only matters for the ViewTransition.cpp path. Patch is correct but doesn't move the rig needle.

### wave-3-9-revert: TOUCH_EVENTS extension reverted

- **Commit:** `8f051fcb`
- **Status:** Documented above under wave-3-9.

## Phase 2.5 — Option B Stages B + C + D

(Stages B = iOS font binary install + cache filter; C = ICU/CLDR
rebuild; D = targeted CoreText residual reverse engineering. Land
here as Phase 2.5 work proceeds.)

## Cross-references

- [V-062 Phase 2 Implementation Order](https://github.com/driftstackdev/driftstack/blob/main/docs/experiments/phase-2-implementation-order.md)
- [V-044 Source Citations (cross-platform-different surfaces)](https://github.com/driftstackdev/driftstack/blob/main/experiments/layer1/source-citations.md)
- [V-047 Source Citations (RUNTIME surfaces)](https://github.com/driftstackdev/driftstack/blob/main/experiments/layer1/runtime-source-citations.md)
- [Option B Proposal](https://github.com/driftstackdev/driftstack/blob/main/docs/architecture/option-b-proposal.md)
- [Option B Stage A Patch Index](https://github.com/driftstackdev/driftstack/blob/main/docs/architecture/option-b-stage-a-patches.md)
- [WebKit Build Setup](https://github.com/driftstackdev/driftstack/blob/main/docs/architecture/webkit-build-setup.md)

## Update protocol

Append a new patch entry when each commit lands. Include patch ID,
files modified, surface, source citation, V-log entry, and
description.

When upstream rebase changes a patch's target (file moved,
function refactored), update the entry with the new file path /
line range and note the rebase.
