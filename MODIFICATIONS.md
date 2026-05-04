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

## Wave 4 — Substitution atlases (V-141 / Stage F.1 / DSWA / DASA / Track 7-9-10)

The Wave 4 family addresses fingerprint surfaces where Mac and iPhone produce structurally divergent bytes that cannot be closed by per-field overrides — only byte-level substitution against a captured iPhone reference works. The pattern: capture iPhone canonical output → store as a binary atlas in `/reference/` → wire a dispatch hook in WebKit that intercepts the relevant call, looks up the entry by content-derived key, and substitutes the iPhone bytes. Default-OFF env-var gating where the atlas isn't yet locked-archetype-specific.

### wave-4-1: V-141 ASCII atlas substitution (DriftstackAsciiAtlas)

- **Commits:** `af4ca0ca97` (V-127 multi-subpixel dispatch), `3d536ac7d0` (V-131 closure paths 1+2), `14947a9a6a` (V-135 revert V-131 path 2), `74c4c742f9` (V-141 color-aware dispatch), `c462a1c775` (DSAS v3 multicolor reader), `86249ee70b` (V-140 wraparound destRect fix), additional V-138/V-143/V-144/V-145/V-146/V-147 incremental fixes
- **Files:** `Source/WebCore/platform/graphics/cocoa/DriftstackAsciiAtlas.{h,mm}` (new) + dispatch in `Source/WebCore/platform/graphics/FontCascade.cpp` lines 1737-1900+
- **Surface:** ASCII glyph rendering in `<canvas>` 2D `fillText` — iPhone CT vs Mac CT produce non-byte-matching pixel output for printable ASCII (U+0020 .. U+007E)
- **Description:** Per-glyph atlas substitution at FontCascade dispatch. Atlas binary at `/reference/driftstack_ascii_atlas/` (DSAS v3 format: magic `DSAS` + version 3 + multi-color variants). Currently 5-font partial atlas; POC v2 capture (autopilot-running 2026-05-04) builds the full 13-font × 16-color atlas. V-131 mixed-dispatch gate at line 1845-1864 abandons dispatch when source has BOTH ASCII + non-ASCII codepoints — see V-171 for the gate-bypass mechanism (env-var-gated, default-OFF).

### wave-4-2: Composite atlas (ZWJ emoji sequences) — DriftstackCompositeAtlas

- **Files:** `Source/WebCore/platform/graphics/cocoa/DriftstackCompositeAtlas.{h,mm}` (new) + dispatch in `FontCascade.cpp` line 1701
- **Surface:** ZWJ-joined emoji sequences (e.g., 👨‍👩‍👧‍👦 family-of-four) — iPhone CT renders as a single composite glyph, Mac CT renders as separate glyphs side-by-side
- **Description:** Atlas keyed on ZWJ-sequence codepoint tuple, binary at `/reference/driftstack_emoji_atlas/driftstack-composite-atlas.bin` (504 entries × 4 strikes, 5.7 MiB). Dispatch reads the cluster's RGI (Recommended-for-General-Interchange) sequence, looks up an entry, draws via CGContextDrawImage. Companion to wave-4-3 single-emoji atlas.

### wave-4-3: Stage F.1 single-emoji atlas — DriftstackEmojiAtlas

- **Files:** `Source/WebCore/platform/graphics/cocoa/DriftstackEmojiAtlas.{h,mm}` (new) + dispatch in `Source/WebCore/platform/graphics/coretext/FontCascadeCoreText.cpp` line 414 (inside `drawGlyphsWithAdvances`)
- **Surface:** Single-codepoint color emoji rendering (😃 🍕 etc.) — pixel-level Mac/iPhone divergence per F.1.B-2 V-090 finding
- **Description:** Per-glyph image substitution. Atlas binary at `/reference/driftstack_emoji_atlas/driftstack-emoji-atlas.bin` (DSEA v1 format: magic `DSEA` + 4 strikes 40/64/96/160 PPEM × 5704 codepoints, 70.6 MiB). Dispatch fires for color glyphs with codepoint > U+FFFF (V-106 BMP exclusion to preserve text-vs-emoji-presentation behavior). Default-on; no env var.

### wave-4-4: V-153 Float16 quantization (REFUTED — env-var-gated dead code)

- **Commit:** `fb68074b43`
- **Files:** `Source/WebCore/Modules/webaudio/OfflineAudioContext.cpp` lines ~286-330
- **Surface:** `audio.offlineFingerprint10x` (was hypothesized to close via Float16 round-trip)
- **Status:** **REFUTED per V-160.** When enabled (`DRIFTSTACK_AUDIO_FLOAT16=1` + `__XPC_` mirror), Float16 quantization fires correctly but audio hash still diverges from iPhone reference (libm divergence is the actual cause; Float16 doesn't address it). Patch retained behind env var as default-OFF; no production purpose. Will be removed in a hygiene pass or superseded by DASA (wave-4-9).

### wave-4-5: Track 9 — Hangul fallback override (V-162)

- **Commit:** `81721b367b`
- **Files:** `Source/WebCore/platform/graphics/cocoa/FontCacheCoreText.cpp` (function `driftstackIOSFallbackFontForHangulCluster`) + dispatch in `systemFallbackForCharacterCluster`
- **Surface:** `serif|*hangul*` measureText surfaces in `canvas.measureText.complexScripts`
- **Description:** When the cluster's first codepoint is in U+1100..U+11FF / U+3130..U+318F / U+A960..U+A97F / U+AC00..U+D7AF / U+D7B0..U+D7FF (Hangul ranges), substitute the iOS-shipped Apple SD Gothic Neo font from the Stage B `$DRIFTSTACK_FONTS_DIR/iphone16pro-ios26.4.1/` install (canonical: `/var/lib/driftstack/fonts/...`). Default-on (no env var). Validated against td016: 6/6 Hangul probes match iPhone (was 4/2 before); locked-archetype validation pending recapture.

### wave-4-6: Track 10 — Devanagari fallback override (V-165)

- **Commit:** `d8a75147bf`
- **Files:** `Source/WebCore/platform/graphics/cocoa/FontCacheCoreText.cpp` (function `driftstackIOSFallbackFontForDevanagariCluster`)
- **Surface:** `*|devanagari` measureText surfaces
- **Description:** Cluster-codepoint-in-Devanagari-range → substitute Kohinoor Devanagari (iOS canonical). Companion was Hebrew (Track 10 candidate B) — DROPPED post-validation (Mac native serif Hebrew already matches iPhone serif Hebrew; SFHebrew override would close sans-serif but break serif). Re-enable after per-context discrimination plumbed through. Default-on for Devanagari only.

### wave-4-7: Track 7 candidate (d) — CJK + Emoji fallback (V-164 / V-166)

- **Commit:** `c9cc1a57c9`
- **Files:** `Source/WebCore/platform/graphics/cocoa/FontCacheCoreText.cpp` (functions `driftstackIOSFallbackFontForCJKCluster` + `driftstackIOSFallbackFontForEmojiCluster` + `driftstackTrack7CandidateDEnabled`)
- **Surface:** `unicodeRendering.value[0,2,3].h` (CJK + emoji-presentation height)
- **Description:** **Env-var-gated** (`DRIFTSTACK_TRACK7_CANDIDATE_D=1` + `__XPC_` mirror). CJK cluster (U+3400-U+4DBF, U+4E00-U+9FFF, etc.) → PingFang SC; emoji-presentation cluster → Apple Color Emoji canonical .ttc. Requires Stage B font install: `$DRIFTSTACK_FONTS_DIR/iphone16pro-ios26.4.1/Core/PingFangSC.ttc` + `/Core/AppleColorEmoji.ttc` (canonical: `/var/lib/driftstack/fonts/...`). Default-OFF until physical iPhone session lands binaries (cap_only-recapture-manifest deliverable #2).

### wave-4-8: DSWA — WebGPU readback substitution (V-169 / V-170)

- **Commits:** `82da005d22` (reader), `cf8ff2312e` (dispatch hook)
- **Files:** `Source/WebCore/platform/graphics/cocoa/DriftstackWebGPUAtlas.{h,mm}` (new) + dispatch in `Source/WebCore/Modules/WebGPU/GPUBuffer.cpp` line ~200 (inside `getMappedRange` callback)
- **Surface:** `webgpu.renderHash10x` (10 surfaces) — WebGPU readback bytes vary across GPU classes
- **Description:** **Env-var-gated** (`DRIFTSTACK_WEBGPU_ATLAS=1` + `__XPC_` mirror). Atlas keyed on byte-count (v1 fallback; v2 will hash on shader+inputs). Atlas binary at `/reference/driftstack_webgpu_atlas/driftstack-webgpu-atlas.bin` (DSWA v1 format). **CRITICAL CAVEAT (V-170):** current atlas was captured from BS pool iPhone 17 Pro / iOS 26.x via Stage G — same Apple Silicon GPU class as Mac fork → atlas data hash is byte-identical to Mac fork's WebGPU output → substitution is functionally correct but a NO-OP against the locked iPhone 16 Pro / iOS 26.4.1 archetype. Resolution: physical iPhone 16 Pro Stage G recapture (cap_only-recapture-manifest deliverable #3) → DSWA atlas v2 with iPhone 16 Pro bytes → 10 webgpu surfaces close.

### wave-4-9: DASA — Audio output substitution (V-169)

- **Commit:** `70a12604b8`
- **Files:** `Source/WebCore/platform/graphics/cocoa/DriftstackAudioAtlas.{h,mm}` (new) + dispatch in `Source/WebCore/Modules/webaudio/OfflineAudioContext.cpp` `finishedRendering()` (after V-153 Float16 block)
- **Surface:** `audio.offlineFingerprint10x` (10 surfaces) — iPhone vs Mac libm divergence (V-163 root cause)
- **Description:** **Env-var-gated** (`DRIFTSTACK_AUDIO_ATLAS=1` + `__XPC_` mirror). Atlas keyed on (sampleRate, channelCount, framesPerChannel) shape (v1 fallback; v2 will key on graph-config SHA-256). Atlas binary at `/reference/driftstack_audio_atlas/driftstack-audio-atlas.bin` (DASA v1 format). Atlas not yet built; needs Stage H capture (cap_only-recapture-manifest deliverable #4) on physical iPhone 16 Pro. Same cross-archetype risk as wave-4-8: if iPhone 17 Pro audio is bit-identical to Mac fork audio (libm convergence), Stage H must fire on physical iPhone 16 Pro to produce closure-relevant bytes.

### wave-4-10: Sandbox extension for atlas + Stage B font paths (V-167)

- **Commit:** `f2de1a53c5`
- **Files:** `Source/WebKit/WebProcess/com.apple.WebProcess.sb.in`
- **Surface:** N/A (sandbox infrastructure)
- **Description:** Extends WebContent process file-read allow-list to cover atlas binaries (founder dev-machine: `$HOME/code/driftstack/reference/driftstack_*_atlas/`), Stage B font binaries (`$HOME/code/driftstack-fonts/`), and `/var/lib/driftstack/` (canonical production-equivalent path; gated on Phase 3 sudo creation per `path-hygiene-plan.md`). All paths configurable via env vars per individual atlas reader. Hygiene gap noted in `phase-2-closure-status.md` known-limitations: founder-dev-machine paths still in profile; needs `/var/lib/driftstack/` sudo creation + rig env-var-rigging coordination before production.

### wave-4-11: Hygiene comment-only sanitization (V-167)

- **Commit:** `5082671ecf`
- **Files:** 3 .mm header comments in `DriftstackAsciiAtlas.mm` + `DriftstackCompositeAtlas.mm` + `DriftstackEmojiAtlas.mm`
- **Surface:** N/A (source-comment cleanup)
- **Description:** Removed founder-dev-machine path references from header comment blocks (replaced with abstract path descriptions). Code-default fallback paths (`kDefaultAtlasPath = "<founder-dev-machine path under $HOME/code/driftstack/reference/..."`) remain — those are guarded by env-var override and only active during dev; production deployment uses `DRIFTSTACK_*_ATLAS_PATH` env vars to point at `/var/lib/driftstack/atlases/` paths per `path-hygiene-plan.md`.

### wave-4-12: V-171 Option A — V-131 per-glyph dispatch gate (env-var-gated)

- **Commit:** `ce49c92dd3`
- **Files:** `Source/WebCore/platform/graphics/FontCascade.cpp` (helper at top of `drawGlyphBuffer` + gate logic at lines ~1845-1864)
- **Surface:** `canvas.fingerprint10x.{hashes, sampleDataUrls}` (13 surfaces) — formerly entirely V-131-blocked when text contains both ASCII and non-ASCII codepoints
- **Description:** **Env-var-gated** (`DRIFTSTACK_DISPATCH_PER_GLYPH=1` + `__XPC_` mirror; default-OFF). When enabled, the V-131 mixed-dispatch outer gate at FontCascade.cpp:1864 is bypassed (`dispatchAllowed = (!mixedDispatch || perGlyphDispatch) && !skipAsciiDispatch`). Inner per-glyph loop already filters non-ASCII codepoints; ASCII glyphs go to V-141 atlas, non-ASCII glyphs fall through to native CT (which routes color emoji via DriftstackEmojiAtlas in FontCascadeCoreText.cpp `drawGlyphsWithAdvances` — confirmed operational per V-090 / F.1.B-2 / V-173 atlas-binary read showing 😃 + 🍕 at all 4 strikes).
- **Empirical post-build (V-178):** canvas-fp pixel diff 38.4%→20.9% RGB / 37.8%→4.9% alpha (45.6% RGB / 87% alpha reduction). 870 atlas-hit log lines vs 0 pre-V-171. Scoreboard hashes still differ because residual ~21% pixel diff persists; needs follow-up sub-pixel positioning / AA-edge-mixing investigation. Default-OFF until residual closes.

### wave-4-13: V-174 Track 10 Hebrew per-context dispatch (env-var-gated)

- **Commit:** `8dd5d03521`
- **Files:** `Source/WebCore/platform/graphics/cocoa/FontCacheCoreText.cpp` (function `driftstackIOSFallbackFontForHebrewCluster` + `driftstackTrack10HebrewEnabled` + dispatch in `systemFallbackForCharacterCluster`)
- **Surface:** `canvas.measureText.complexScripts.value.sans-serif|hebrew_*` (3-4 surfaces post-iPhone-recapture)
- **Description:** **Env-var-gated** (`DRIFTSTACK_TRACK10_HEBREW=1` + `__XPC_` mirror; default-OFF). Re-enables V-165's Hebrew override that was deactivated because forcing SFHebrew for both serif AND sans-serif contexts broke serif|hebrew (Mac native already matched iPhone serif Hebrew). Per-context discrimination via `originalFontData.platformData().familyName()` at the dispatch site: only fire override when originating family matches sans-serif synonyms (Helvetica / Arial / SF Pro / .SF / .AppleSystemUI / *sans*).
- **Empirical post-V-179 (with env var enabled):** dispatch fires correctly (5+ Hebrew clusters logged, originatingFamily=Helvetica). However, sans-serif|hebrew_* measureText surfaces still differ from iPhone — Mac CoreText shaping of SFHebrew.ttf produces different metrics than iPhone CoreText shaping of the same binary (width 31.78 vs 28.04 = ~13% diff). Investigation pending — likely needs additional measureText override layer specifically for Hebrew scripts.

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
