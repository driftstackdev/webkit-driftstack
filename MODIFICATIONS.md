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

(Patches land here as Phase 2 progresses. WebGL / WebGPU / codec
filtering for surfaces where Mac fleet's underlying driver
returns Mac-specific values; WebKit-layer filter substitutes
iPhone-archetype values.)

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
