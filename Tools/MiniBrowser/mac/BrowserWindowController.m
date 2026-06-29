/*
 * Copyright (C) 2012 Apple Inc. All rights reserved.
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

#import "BrowserWindowController.h"

#import "AppDelegate.h"
#import "SettingsController.h"

#import <objc/runtime.h>

// Driftstack (W1371): a window that always DRAWS with active (key+main) appearance regardless of
// real focus, so the chrome NEVER greys/dims when the user focuses another window (the founder's
// W1370 priority: "window greyed-out/dark when not activated — not user-friendly"). It overrides
// only the APPEARANCE getters (`hasKeyAppearance`/`hasMainAppearance`) — NOT `isKeyWindow`/
// `isMainWindow` — so the window's REAL key/main status (focus, first responder, menu routing,
// text-field editing) is completely UNCHANGED; only the dimming-vs-active DRAWING is forced active.
// Retrofitted onto the existing nib-loaded window via `object_setClass` (the subclass adds NO ivars,
// so the object layout is unchanged → a layout-safe isa swap), gated by DRIFTSTACK_SAFARI_CHROME.
@interface DriftstackAlwaysActiveWindow : NSWindow
@end
@implementation DriftstackAlwaysActiveWindow
- (BOOL)hasKeyAppearance { return YES; }
- (BOOL)hasMainAppearance { return YES; }
@end

@interface BrowserWindowController () <NSSharingServicePickerDelegate, NSSharingServiceDelegate> {
    NSTimer *_mainThreadStallTimer;
}
// W2972: content-only-mode predicate (DRIFTSTACK_SAFARI_CHROME_HIDDEN) — forward-declared so
// windowDidLoad (above the definition) can call it without an undeclared-selector warning.
- (BOOL)driftSafariChromeHidden;
// W2990: the layout-viewport height-correction body (W1421/W2972), extracted so windowDidLoad can
// invoke it SYNCHRONOUSLY for the content-only path + on the deferred fallback for chrome-shown.
// Forward-declared (defined below windowDidLoad) to avoid an undeclared-selector warning.
- (void)driftApplyLayoutViewportHeight:(int)layoutViewportHeight screenWidth:(int)screenWidth;
@end

@implementation BrowserWindowController

@synthesize editable = _editable;

- (id)initWithWindow:(NSWindow *)window
{
    self = [super initWithWindow:window];
    return self;
}

- (void)windowDidLoad
{
    // FIXME: We should probably adopt the default unified style, but we'd need
    // somewhere to put the window/page title.
    self.window.toolbarStyle = NSWindowToolbarStyleExpanded;

    // Enable tabbing - group regular windows together
    self.window.tabbingIdentifier = @"MiniBrowserMainWindow";

    // W2837 (founder white-band, A2-A3 W2824/W2825): the WHOLE window is captured into the session stream
    // (SCContentFilter desktopIndependentWindow). Where no WEB content covers it — the hidden-chrome-bar
    // reserve band (DRIFTSTACK_SAFARI_CHROME_HIDDEN hides the bar but leaves the web-view inset by barH) +
    // any title/letterbox edge — the bare window background shows. macOS defaults that to a LIGHT
    // (windowBackgroundColor) fill → a WHITE band baked into the published frame (the founder's recurring
    // "white space"; the GUI masks most of it but a geometry-dependent sliver peeks past the fixed mask).
    // Paint the window BLACK so every non-web band reads as the device bezel — GEOMETRY-INDEPENDENTLY, so no
    // px-perfect mask-matching is needed. Capture-appearance ONLY: the page never sees the window chrome
    // color, and this is NOT a dark NSAppearance (so it does NOT flip prefers-color-scheme) → zero
    // fingerprint surface. (Only backgroundColor — NOT `opaque`, to avoid the W2229 opaque-KVO interaction
    // with the iOS-26 bottom-bar NSHostingView's `opaque` observer.)
    self.window.backgroundColor = NSColor.blackColor;

    // Driftstack iOS-Safari chrome (W1369) — ENV-GATED `DRIFTSTACK_SAFARI_CHROME`, default OFF so the
    // production session host stays byte-identical until the custom chrome is fully built + verified.
    // The whole window is captured into the session stream (SCContentFilter desktopIndependentWindow),
    // so the macOS title-bar furniture (traffic lights + title text) both looks nothing like iOS Safari
    // AND greys out when the window isn't key (the founder-reported symptom). Phase-1 foundation: drop
    // that native furniture. The custom always-active Safari toolbar that fully replaces the (still-
    // greying) native URL toolbar is the next increment behind this same gate. The window-size /
    // layout-viewport math below is DYNAMIC (measures the actual chrome at runtime) so it self-corrects
    // to the new chrome height — clientHeight==innerHeight stays correct (the file-99 fingerprint).
    // W1434b: VALUE check, not a bare presence check — a non-empty FALSY value ("0"/"false"/"no"/"off")
    // must DISABLE the chrome (the operator sets =0 meaning OFF). The harness already normalizes the
    // forwarded value to "1"/omitted (BrowserProcess.envFlagEnabled, W1434), so production is footgun-free;
    // this matches that for the BARE-fork path (a direct MiniBrowser launch / the chrome-render-check
    // oracle, whose CHROME=0 previously ran chrome-ON via the old presence check).
    const char* driftChromeRaw = getenv("DRIFTSTACK_SAFARI_CHROME");
    NSString *driftChromeVal = driftChromeRaw
        ? [[NSString stringWithUTF8String:driftChromeRaw] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]].lowercaseString
        : nil;
    BOOL driftSafariChromeOn = driftChromeVal.length > 0
        && ![driftChromeVal isEqualToString:@"0"] && ![driftChromeVal isEqualToString:@"false"]
        && ![driftChromeVal isEqualToString:@"no"] && ![driftChromeVal isEqualToString:@"off"];
    if (driftSafariChromeOn) {
        // W1375: do NOT make the titlebar transparent yet — verified by screenshot (W1375) that a
        // transparent titlebar lets the web content show THROUGH under the floating toolbar (the page
        // top overlaps the controls). Keep the titlebar OPAQUE; W1371's always-active appearance already
        // stops the greying, so an opaque always-active titlebar = no grey + no overlap + no traffic
        // lights. The translucent Safari-26 GLASS look (which wants transparency) needs proper
        // web-content insetting below the bar — deferred to the glass-styling phase.
        self.window.titleVisibility = NSWindowTitleHidden;
        [self.window standardWindowButton:NSWindowCloseButton].hidden = YES;
        [self.window standardWindowButton:NSWindowMiniaturizeButton].hidden = YES;
        [self.window standardWindowButton:NSWindowZoomButton].hidden = YES;
        // W1371: stop the chrome greying when the window isn't focused (founder W1370). Force
        // always-active DRAWING via the appearance-only window subclass (real focus/responder
        // status untouched).
        // W2229 (A3): force the always-active appearance via CLASS-METHOD replacement, NOT object_setClass.
        // object_setClass changes the window's isa, which clobbers KVO's isa bookkeeping: the iOS-26 bottom-bar
        // NSHostingView observes the window's `opaque` key path, so KVO isa-swizzles the window to a
        // NSKVONotifying_… subclass; object_setClass overwrites that isa → the `opaque` observer removal later
        // fails ("Cannot remove an observer ... not registered") → NSRangeException → SIGABRT on EVERY
        // SAFARI_CHROME=1 launch via the AppKit window-setup/reopen path (verified: a clean launch with zero
        // saved state still crashed). Replacing -hasKeyAppearance/-hasMainAppearance on the window's class to
        // return YES gives the identical always-active drawing with NO isa change → KVO untouched → no crash.
        // The fork hosts a single session window, so class-scoping the override is fine. (Was object_setClass
        // → DriftstackAlwaysActiveWindow; that subclass is now unused but left for reference.)
        static dispatch_once_t driftActiveOnce;
        dispatch_once(&driftActiveOnce, ^{
            Class wc = [self.window class];
            IMP yesImp = imp_implementationWithBlock(^BOOL(__unused id _self){ return YES; });
            class_replaceMethod(wc, @selector(hasKeyAppearance), yesImp, "B@:");
            class_replaceMethod(wc, @selector(hasMainAppearance), yesImp, "B@:");
        });
        // W1378 (founder: "fancier iOS 26 look, url bar at BOTTOM like Safari, tabs"): build the
        // iOS-26 Safari-style BOTTOM toolbar (translucent glass, always-active). Deferred to the next
        // runloop so the nib's containerView + the WK2 subclass's webView are created/laid out first.
        dispatch_async(dispatch_get_main_queue(), ^{ [self installDriftSafariBottomBar]; });
    }

    // Driftstack: size the window content to the ACTIVE ARCHETYPE's viewport so
    // the physical render (and screenshots/streams) match the chosen device, and
    // the CSS layout viewport agrees with the JS-reported screen/inner dims.
    // NOT hardcoded — multi-device by design (iPhone 17 / 16 Pro / Pro Max / various
    // iOS). The launch wrapper exports DRIFTSTACK_VIEWPORT_WIDTH/HEIGHT from the
    // active archetype config (operations/archetypes/<archetype>.json screen dims);
    // if unset, the nib default is kept. frameAutosaveName was removed from the nib
    // so a previously user-resized frame can no longer override this.
    const char* vpw = getenv("DRIFTSTACK_VIEWPORT_WIDTH");
    const char* vph = getenv("DRIFTSTACK_VIEWPORT_HEIGHT");
    if (vpw && vph) {
        int w = atoi(vpw);
        int h = atoi(vph);
        if (w > 0 && h > 0) {
            NSSize vpSize = NSMakeSize(w, h);
            // Disable AppKit window state restoration (it restores a previously
            // displayed frame DURING window display, after windowDidLoad, which
            // would override this). Re-assert the size on the next runloop turn
            // (after display) so the archetype viewport always wins.
            self.window.restorable = NO;
            __weak typeof(self) weakSelf = self;
            // Lock the window to the archetype viewport: a real iPhone cannot be
            // resized or maximized, and a larger/maximized window would leak the
            // host viewport (CSS layout viewport, matchMedia, getBoundingClientRect
            // all follow the real content size, not just the JS-overridden
            // window.inner* values). Drop the resizable style so the size is fixed
            // and the green button can't zoom/maximize.
            self.window.styleMask &= ~NSWindowStyleMaskResizable;
            NSButton *zoomButton = [self.window standardWindowButton:NSWindowZoomButton];
            if (zoomButton)
                zoomButton.enabled = NO;
            [self.window setContentSize:vpSize];
            __weak NSWindow *weakWindow = self.window;
            // The web content view (mainContentView) sits below the URL bar, so
            // its height = window-content-height - chrome. A real iPhone reports
            // documentElement.clientHeight == window.innerHeight (the layout
            // viewport, e.g. 714 for iPhone 16/17). If the webView height does
            // not equal that, clientHeight/matchMedia leak the wrong value even
            // though window.innerHeight is JS-overridden. When
            // DRIFTSTACK_LAYOUT_VIEWPORT_HEIGHT is set, resize the window so the
            // webView height == the layout viewport (measure the chrome, add it).
            const char* lvhEnv = getenv("DRIFTSTACK_LAYOUT_VIEWPORT_HEIGHT");
            int layoutViewportHeight = lvhEnv ? atoi(lvhEnv) : 0;
            // W2990 (A3 render-investigation a57228b6 — height-settle fidelity polish): in the PRODUCTION
            // content-only / chrome-HIDDEN path the final window-content height is DETERMINISTIC up front.
            // chromeHidden forces barH=0 (the bar is invisible; its reserve is dropped per W2972) and
            // titleInset=0 (NSFullSizeContentView + transparent titlebar extends content under the ~32px
            // title band), so targetContent == layoutViewportHeight EXACTLY — with NO dependency on any
            // value that only settles after the window displays (contentView height / contentLayoutRect /
            // the web-view's origin.y). Both the web container (containerView) and the web view
            // (mainContentView == _webView) are already created + parented by awakeFromNib, which runs
            // BEFORE windowDidLoad. So commit the final size SYNCHRONOUSLY here — before AppDelegate's
            // makeKeyAndOrderFront + loadURLString run (same runloop turn) — so the page lays out at the
            // FINAL height from first paint, with no late one-time vertical resize nudging the layout
            // ~0.4s in (real Safari lays out at the final size from first paint; the old dispatch_after
            // 0.4s deferral caused a late height-reflow if the page painted inside that window). The WIDTH
            // was already committed synchronously above (setContentSize:vpSize). This changes ONLY WHEN the
            // already-correct HEIGHT is applied — never the VALUE (DRIFTSTACK_LAYOUT_VIEWPORT_HEIGHT is A1's
            // fingerprint). Chrome-SHOWN keeps the 0.4s deferral FALLBACK below (its inset is a real visible
            // bar, NOT deterministic until display).
            BOOL chromeHiddenAtLoad = [self driftSafariChromeHidden];
            if (layoutViewportHeight > 0 && chromeHiddenAtLoad)
                [self driftApplyLayoutViewportHeight:layoutViewportHeight screenWidth:w];
            dispatch_async(dispatch_get_main_queue(), ^{
                [weakWindow setContentSize:vpSize];
                if (layoutViewportHeight > 0) {
                    typeof(self) strongSelfAsync = weakSelf;
                    // Content-only path: already pinned SYNCHRONOUSLY in windowDidLoad above. The display
                    // path re-asserted vpSize (the [weakWindow setContentSize:vpSize] just above), so
                    // re-apply the deterministic final height ONCE more here (cheap + idempotent — same
                    // constants, no measurement) to win that race, then SKIP the 0.4s deferral entirely
                    // (no late reflow). The web-view stays pinned to the layout viewport throughout.
                    if (strongSelfAsync && [strongSelfAsync driftSafariChromeHidden]) {
                        [strongSelfAsync driftApplyLayoutViewportHeight:layoutViewportHeight screenWidth:w];
                        return;
                    }
                    // Chrome-SHOWN FALLBACK (dev/visual only — production sets SAFARI_CHROME_HIDDEN=1, the
                    // synchronous path above): the bar IS a real visible inset, so barH (the web-view's
                    // origin.y) + the title-band inset are NOT deterministic until the window displays +
                    // lays out several runloop turns later. Keep the short deferral: measure the real
                    // chrome, derive the inset, resize so the web view == the layout viewport
                    // (clientHeight == innerHeight).
                    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.4 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                        typeof(self) strongSelf = weakSelf;
                        if (!strongSelf || !weakWindow)
                            return;
                        [strongSelf driftApplyLayoutViewportHeight:layoutViewportHeight screenWidth:w];
                    });
                }
            });
        }
    }

    [share sendActionOn:NSEventMaskLeftMouseDown];
    [super windowDidLoad];
}

// W2990 (A3 render-investigation a57228b6): the layout-viewport height correction, extracted from
// windowDidLoad's deferred block so it can run SYNCHRONOUSLY (content-only / chrome-hidden — the
// production path, where the final size is deterministic up front) OR on the 0.4s deferral
// (chrome-SHOWN fallback, where the real bar inset only settles after the window displays). It is
// IDEMPOTENT: the same constants in → the same final frame out, so re-invoking it (sync + the async
// re-assert) is harmless. Operates on self/self.window directly; the callers guard lifetime.
- (void)driftApplyLayoutViewportHeight:(int)layoutViewportHeight screenWidth:(int)screenWidth
{
    NSWindow *win = self.window;
    if (!win || layoutViewportHeight <= 0)
        return;
    int w = screenWidth;
    // W1421 (fingerprint FIX): documentElement.clientHeight == the WEB VIEW's
    // FRAME height (the layout viewport), so the window must be sized so the
    // web view == layoutViewportHeight exactly. The OLD measure
    // (contentView.height - contentLayoutRect.height) saw ONLY the title-bar
    // band (~32px) — it was BLIND to the Driftstack bottom bar, which insets
    // the web container (containerView) by barH (92px) under DRIFTSTACK_SAFARI_CHROME.
    // Result, proven empirically: clientHeight = layoutViewport - 92 (782 vs 874)
    // = a file-99 tell whenever the chrome is on. Fix: derive the chrome from the
    // ACTUAL web view (its origin.y == the bottom-bar height, 0 when chrome off)
    // PLUS the title-bar band, then DETERMINISTICALLY pin the web-view frame to
    // the layout viewport — do NOT rely on autoresize propagating the resize
    // (empirically it did not; the window is non-resizable so an explicit frame
    // sticks).
    CGFloat contentH = win.contentView.frame.size.height;
    NSView *web = containerView ?: self.mainContentView;
    CGFloat barH = web ? web.frame.origin.y : 0;                       // bottom-bar height (0 = chrome off)
    CGFloat titleInset = contentH - win.contentLayoutRect.size.height; // title-bar band
    if (barH < 0) barH = 0;
    if (titleInset < 0) titleInset = 0;
    // W2972 (founder "black space at the bottom, browser only ~70%" + A2 W2957/W2971
    // per-archetype-size bug): in content-only mode the web-view must FILL the captured
    // frame so (1) there is no black band to mask, and (2) the window aspect == the
    // per-archetype capture profile aspect → SCStream scalesToFit becomes a no-op (no
    // anamorphic scale, no letterbox). So:
    //   - DROP the 92px hidden-bar reserve (barH→0; the bar is invisible, reserving it
    //     only bakes a black void — the dominant ~12% bottom band the founder reports).
    //   - DROP the macOS title-band inset too: extend the web content under the title bar
    //     (NSFullSizeContentView + transparent titlebar) so the window content == the
    //     layout viewport EXACTLY and the web-view fills it edge-to-edge. The W1375
    //     page-shows-through-the-toolbar risk does NOT apply here: there is NO visible
    //     toolbar in content-only mode (the GUI Browser-mode supplies the URL bar), so
    //     nothing overlaps the page.
    // The web-view height stays == layoutViewportHeight (inner_height, e.g. 714/693/796),
    // so documentElement.clientHeight == window.innerHeight remains iPhone-exact (the
    // file-99 layout-viewport signal is UNCHANGED). The window WIDTH is the per-archetype
    // screen_width `w` (DRIFTSTACK_VIEWPORT_WIDTH: 390/402/430...) — already correct.
    // Chrome-SHOWN keeps the old barH + titleInset behavior (the bar is real chrome).
    // W2990: in content-only mode this whole computation is constant (barH=0, titleInset=0 →
    // targetContent == layoutViewportHeight) — which is why windowDidLoad can call it SYNCHRONOUSLY
    // (before first paint), eliminating the late height-reflow. The measured contentH / origin.y /
    // contentLayoutRect feed ONLY the chrome-SHOWN fallback branch.
    BOOL chromeHidden = [self driftSafariChromeHidden];
    if (chromeHidden) {
        // Extend content under the title bar so its 32px band stops insetting the web-view.
        win.titlebarAppearsTransparent = YES;
        win.styleMask |= NSWindowStyleMaskFullSizeContentView;
        barH = 0;
        titleInset = 0;
    }
    CGFloat targetContent = layoutViewportHeight + barH + titleInset;
    [win setContentSize:NSMakeSize(w, targetContent)];
    // Pin the web view to EXACTLY the layout viewport, above the bottom bar (origin.y
    // == barH; barH == 0 in content-only mode → the web-view fills the full content).
    // W3011 (#1 TOP black band): the web container was BOTTOM-anchored at origin.y == barH
    // (0 in content-only mode). When the live window's contentView is taller than the freshly
    // -committed layoutViewportHeight for a turn (the [setContentSize:] / display race), a
    // residual macOS title strut sits ABOVE the web-view and is captured BLACK at the top of
    // the frame. TOP-ANCHOR the container so any residual slack falls BELOW the web-view (it is
    // already covered by the bottom-bar / off-frame), never above it. The web-view HEIGHT stays
    // EXACTLY layoutViewportHeight — only origin.y moves, so clientHeight == innerHeight (the
    // file-99 layout-viewport signal) is UNCHANGED (fingerprint-safe). Chrome-SHOWN keeps the
    // bottom-anchored barH origin (the bar is real visible chrome below the page).
    if (containerView) {
        containerView.autoresizingMask = NSViewNotSizable;
        CGFloat contentNow = win.contentView.frame.size.height;
        CGFloat originY = chromeHidden ? MAX(0.0, contentNow - layoutViewportHeight) : barH;
        containerView.frame = NSMakeRect(0, originY, w, layoutViewportHeight);
        if (self.mainContentView)
            self.mainContentView.frame = containerView.bounds;
    }
    NSLog(@"[Driftstack-WindowSize] content=%.0f bar=%.0f title=%.0f hidden=%d -> window content=%.0f web-view=%d (target viewport=%d, screen-w=%d)",
        contentH, barH, titleInset, (int)chromeHidden, (double)targetContent, layoutViewportHeight, layoutViewportHeight, w);
}

// W1378: the iOS-26 Safari BOTTOM bar. Re-homes the existing controls (IBOutlets = the real control
// views; their target/action wiring to the WK2 controller stays intact) into a translucent always-
// active glass bar pinned to the window BOTTOM, and shrinks the web content to sit ABOVE it — the
// defining iOS-Safari layout (address bar at the bottom). Gated by DRIFTSTACK_SAFARI_CHROME.
// NOTE (fingerprint): the bar height becomes the chrome; the web-content height (== layout viewport,
// clientHeight==innerHeight, file-99) must be cumrig-verified before enabling for sessions. First cut
// — visual layout iterates via the screenshot loop; tabs + scroll-minimize + final glass polish next.
// W2972: content-only mode predicate — DRIFTSTACK_SAFARI_CHROME_HIDDEN truthy (the GUI Browser-mode
// supplies its own URL bar, so the fork's rendered iOS bar is hidden AND its reserve band is dropped).
// Shared by installDriftSafariBottomBar (web-container inset) + windowDidLoad's resize block (window-
// content height / web-view frame) so they agree on whether the barH reserve exists.
- (BOOL)driftSafariChromeHidden
{
    const char *raw = getenv("DRIFTSTACK_SAFARI_CHROME_HIDDEN");
    return raw && (raw[0] == '1' || raw[0] == 't' || raw[0] == 'T' || raw[0] == 'y' || raw[0] == 'Y');
}

- (void)installDriftSafariBottomBar
{
    NSView *content = self.window.contentView;
    if (!content)
        return;
    const CGFloat barH = 92.0;   // iOS-26 Safari bottom bar: URL-pill row + toolbar-icon row
    NSRect cb = content.bounds;
    // W2972: in content-only mode (DRIFTSTACK_SAFARI_CHROME_HIDDEN) the rendered bar is invisible, so
    // RESERVING its barH band below the web container only bakes a black void into the captured frame
    // (the founder's "black space at the bottom" — the web-view filled ~70% of the frame). When hidden,
    // do NOT inset the web container by barH: the web-view fills from y=0 (the windowDidLoad resize block
    // then sizes the window content to layoutViewport so the web-view == the full content height, and
    // clientHeight == innerHeight stays exact). Chrome-SHOWN keeps the barH inset (the bar IS visible).
    BOOL driftChromeHidden = [self driftSafariChromeHidden];
    const CGFloat reservedBarH = driftChromeHidden ? 0.0 : barH;

    // Drop the native top toolbar (its controls are re-homed below).
    self.window.toolbar = nil;

    // Translucent always-active glass bar pinned to the bottom (never greys: state = Active).
    NSVisualEffectView *bar = [[NSVisualEffectView alloc] initWithFrame:NSMakeRect(0, 0, cb.size.width, barH)];
    bar.material = NSVisualEffectMaterialMenu;                       // W1385: more translucent (Liquid-Glass-er)
    bar.blendingMode = NSVisualEffectBlendingModeWithinWindow;
    bar.state = NSVisualEffectStateActive;
    bar.autoresizingMask = NSViewWidthSizable | NSViewMaxYMargin;   // stretch width, pin to bottom
    [content addSubview:bar positioned:NSWindowAbove relativeTo:nil];
    // W2718 (founder directive via A2 — the GUI Browser-mode URL bar replaces the rendered iOS bar):
    // when DRIFTSTACK_SAFARI_CHROME_HIDDEN is set, HIDE this rendered bar (+ all its re-homed controls,
    // which are subviews of `bar` → a hidden parent hides them too) WITHOUT touching the web-view inset.
    // The web-view stays pinned to the 714 layout viewport (set in windowDidLoad's size logic), so the
    // SITE still measures innerHeight == 714 (iPhone-exact) — the bar is merely invisible. Default OFF →
    // zero behavior change. The GUI overlays/crops the now-empty bar band on its side (A2).
    if (driftChromeHidden)
        bar.hidden = YES;
    // W1385: a subtle top hairline separating the bar from the page (iOS toolbars have one).
    NSView *hairline = [[NSView alloc] initWithFrame:NSMakeRect(0, barH - 0.5, cb.size.width, 0.5)];
    hairline.wantsLayer = YES;
    hairline.layer.backgroundColor = NSColor.separatorColor.CGColor;
    hairline.autoresizingMask = NSViewWidthSizable | NSViewMinYMargin;
    [bar addSubview:hairline];

    CGFloat W = cb.size.width;
    // Row 1 (top of bar): the URL "pill" with the lock at its left + reload at its right.
    // W1402 (founder): the standalone lock button is removed — its meaning ("HTTPS") wasn't clear and
    // iOS Safari doesn't show a separate lock control. The URL pill takes the freed width.
    if (urlText) {
        // W1385: a clean iOS-Safari URL "pill" — borderless, centered, a soft rounded translucent fill.
        urlText.frame = NSMakeRect(14, barH - 44, W - 58, 34);   // W1402: lock removed → pill starts at the left edge
        urlText.bordered = NO;
        urlText.bezeled = NO;
        urlText.drawsBackground = NO;
        urlText.alignment = NSTextAlignmentCenter;
        urlText.font = [NSFont systemFontOfSize:13];
        urlText.wantsLayer = YES;
        urlText.layer.cornerRadius = 17;
        urlText.layer.backgroundColor = [NSColor.secondaryLabelColor colorWithAlphaComponent:0.12].CGColor;
        [bar addSubview:urlText];
    }
    if (reloadButton) { reloadButton.frame = NSMakeRect(W - 38, barH - 40, 28, 28); [bar addSubview:reloadButton]; }
    // Row 2 (bottom of bar): back / forward on the left, share on the right (iOS toolbar row).
    if (backButton) { backButton.frame = NSMakeRect(18, 10, 34, 34); [bar addSubview:backButton]; }
    if (forwardButton) { forwardButton.frame = NSMakeRect(64, 10, 34, 34); [bar addSubview:forwardButton]; }
    // W1402 (founder): Share button removed — not needed for the session browser; the tabs button is
    // now the lone right-edge control on the toolbar row (right margin matches back's left margin).
    // W1397: iOS Safari TABS button (far-right of the toolbar row) → toggles the custom tab overview.
    // Only shown when this controller implements the overview (the WK2 controller); NSSelectorFromString
    // avoids an undeclared-selector warning in this base file (the action lives in WK2BrowserWindowController).
    SEL tabsSel = NSSelectorFromString(@"driftToggleTabOverview:");
    if ([self respondsToSelector:tabsSel]) {
        NSButton *tabsButton = [NSButton buttonWithImage:([NSImage imageWithSystemSymbolName:@"square.on.square" accessibilityDescription:@"Tabs"]
                                                            ?: [NSImage imageNamed:NSImageNameListViewTemplate])
                                                  target:self action:tabsSel];
        tabsButton.frame = NSMakeRect(W - 52, 10, 34, 34);
        tabsButton.autoresizingMask = NSViewMinXMargin | NSViewMaxYMargin;
        tabsButton.bordered = NO;
        tabsButton.image.template = YES;
        tabsButton.contentTintColor = [NSColor colorWithSRGBRed:114.0/255.0 green:47.0/255.0 blue:55.0/255.0 alpha:1.0];
        // W2079: label the button for accessibility + UI automation. The NSImage's accessibilityDescription
        // does NOT propagate to the button's AXDescription, so the tabs control was unlabeled (a11y gap +
        // un-scriptable). Set the button's own label so VoiceOver announces it AND System Events can target
        // it (`button whose description is "Tabs"`) to open the overview headlessly for visual self-checks.
        tabsButton.accessibilityLabel = @"Tabs";
        [bar addSubview:tabsButton];
    }
    // W2073 (founder "the loading thing is kinda small, make it better"): replace the 24px corner spinner
    // with a full-width iOS-style DETERMINATE progress bar pinned to the TOP edge of the bottom bar (where
    // iOS-26 Safari shows load progress). The xib switched it to style=bar; it stays bound to the webView's
    // estimatedProgress (0..1, maxValue=1) + hidden-when-not-loading, so it fills left→right as the page loads
    // and disappears on completion. Purely a chrome overlay — does NOT resize the web view, so the
    // clientHeight==inner_height(714) layout-viewport signal (W2072/W2564) is unaffected.
    if (progressIndicator) {
        progressIndicator.frame = NSMakeRect(0, barH - 5, W, 5);
        progressIndicator.autoresizingMask = NSViewWidthSizable | NSViewMinYMargin;   // full width, pinned to the bar's top edge
        [bar addSubview:progressIndicator];
    }

    // Shrink the web content to sit ABOVE the bar (the nib's containerView is the webView's parent).
    // W2972: reservedBarH == 0 in content-only mode → the web container fills the FULL window content
    // (no freed-bar black band), == barH when the bar is drawn.
    // W3011 (#1 TOP black band): in content-only mode do NOT stretch the container to the full
    // contentView height (cb.size.height) — that bottom-anchors it at y=0 and, when the live
    // contentView is momentarily taller than the layout viewport (the windowDidLoad size race), a
    // residual macOS title strut sits ABOVE the web-view and is captured BLACK. Pin a FIXED-height
    // (layoutViewportHeight) container, TOP-ANCHORED, so any residual slack falls BELOW it (covered /
    // off-frame), never above. The web-view height stays EXACTLY layoutViewportHeight, so
    // clientHeight == innerHeight (file-99) is UNCHANGED. layoutViewportHeight is read the same way
    // windowDidLoad reads it (DRIFTSTACK_LAYOUT_VIEWPORT_HEIGHT); <= 0 → fall back to the prior
    // full-content stretch (no behavior change). Chrome-SHOWN keeps the barH bottom inset (real bar).
    if (containerView) {
        const char* lvhEnvBar = getenv("DRIFTSTACK_LAYOUT_VIEWPORT_HEIGHT");
        int layoutViewportHeightBar = lvhEnvBar ? atoi(lvhEnvBar) : 0;
        if (driftChromeHidden && layoutViewportHeightBar > 0) {
            CGFloat lvh = (CGFloat)layoutViewportHeightBar;
            containerView.frame = NSMakeRect(0, MAX(0.0, cb.size.height - lvh), W, lvh);
        } else {
            containerView.frame = NSMakeRect(0, reservedBarH, W, cb.size.height - reservedBarH);
        }
        containerView.autoresizingMask = NSViewWidthSizable | NSViewHeightSizable;
    }
    if (self.mainContentView && containerView) {
        self.mainContentView.frame = containerView.bounds;
        self.mainContentView.autoresizingMask = NSViewWidthSizable | NSViewHeightSizable;
    }

    // W1385: Driftstack "Drift touch" — tint the ACTION glyphs Oxblood #722F37 (A2 brand spec, the
    // SOLE accent, reserved for actions/active states — not large fills, so the bar/pill stay neutral;
    // matches the simulator-toolbar DriftMark for brand coherence). contentTintColor on nil is a no-op.
    NSColor *oxblood = [NSColor colorWithSRGBRed:114.0/255.0 green:47.0/255.0 blue:55.0/255.0 alpha:1.0];
    for (NSButton *b in @[backButton ?: [NSButton new], forwardButton ?: [NSButton new], reloadButton ?: [NSButton new]]) {
        b.image.template = YES;            // contentTintColor only tints TEMPLATE images
        b.contentTintColor = oxblood;
        b.bordered = NO;                   // ensure the glyph (not a bezel) shows the tint
    }
}

- (void)newWindowForTab:(id)sender
{
    [[NSApp browserAppDelegate] newTab:sender];
}

- (IBAction)openLocation:(id)sender
{
    [[self window] makeFirstResponder:urlText];
}

- (void)loadURLString:(NSString *)urlString
{
}

- (void)loadHTMLString:(NSString *)HTMLString
{
}

- (NSString *)addProtocolIfNecessary:(NSString *)address
{
    if ([address rangeOfString:@"://"].length > 0)
        return address;

    if ([address hasPrefix:@"data:"])
        return address;

    if ([address hasPrefix:@"about:"])
        return address;

    if ([address hasPrefix:@"javascript:"])
        return address;

    return [@"http://" stringByAppendingString:address];
}

- (IBAction)share:(id)sender
{
    NSSharingServicePicker *picker = [[NSSharingServicePicker alloc] initWithItems:@[ self.currentURL ]];
    picker.delegate = self;
    [picker showRelativeToRect:NSZeroRect ofView:sender preferredEdge:NSRectEdgeMinY];
}

- (IBAction)fetch:(id)sender
{
    [self doesNotRecognizeSelector:_cmd];
}

- (IBAction)reload:(id)sender
{
    [self doesNotRecognizeSelector:_cmd];
}

- (IBAction)showCertificate:(id)sender
{
    [self doesNotRecognizeSelector:_cmd];
}

- (IBAction)forceRepaint:(id)sender
{
    [self doesNotRecognizeSelector:_cmd];
}

- (IBAction)cloneSiteIsolatedWindow:(id)sender
{
    [self doesNotRecognizeSelector:_cmd];
}

- (IBAction)cloneNonIsolatedWindow:(id)sender
{
    [self doesNotRecognizeSelector:_cmd];
}

- (IBAction)saveAsPDF:(id)sender
{
    [self doesNotRecognizeSelector:_cmd];
}

- (IBAction)saveAsImage:(id)sender
{
    [self doesNotRecognizeSelector:_cmd];
}

- (IBAction)saveAsWebArchive:(id)sender
{
    [self doesNotRecognizeSelector:_cmd];
}

- (IBAction)saveAsCompleteWebPage:(id)sender
{
    [self doesNotRecognizeSelector:_cmd];
}

- (IBAction)goBack:(id)sender
{
    [self doesNotRecognizeSelector:_cmd];
}

- (IBAction)goForward:(id)sender
{
    [self doesNotRecognizeSelector:_cmd];
}

- (IBAction)showHideWebView:(id)sender
{
    self.mainContentView.hidden = !self.mainContentView.isHidden;
}

- (IBAction)removeReinsertWebView:(id)sender
{
    if (self.mainContentView.window)
        [self.mainContentView removeFromSuperview];
    else
        [containerView addSubview:self.mainContentView];
}

- (IBAction)toggleFullWindowWebView:(id)sender
{
    BOOL newFillWindow = ![self webViewFillsWindow];
    [self setWebViewFillsWindow:newFillWindow];

    SettingsController *settings = [[NSApplication sharedApplication] browserAppDelegate].settingsController;
    settings.webViewFillsWindow = newFillWindow;
}

- (BOOL)webViewFillsWindow
{
    return NSEqualRects(containerView.bounds, self.mainContentView.frame);
}

- (void)setWebViewFillsWindow:(BOOL)fillWindow
{
    if (fillWindow)
        [self.mainContentView setFrame:containerView.bounds];
    else {
        const CGFloat viewInset = 100.0f;
        NSRect viewRect = NSInsetRect(containerView.bounds, viewInset, viewInset);
        // Make it not vertically centered, to reveal y-flipping bugs.
        viewRect = NSOffsetRect(viewRect, 0, -25);
        [self.mainContentView setFrame:viewRect];
    }
}

- (IBAction)zoomIn:(id)sender
{
    [self doesNotRecognizeSelector:_cmd];
}

- (IBAction)zoomOut:(id)sender
{
    [self doesNotRecognizeSelector:_cmd];
}

- (IBAction)resetZoom:(id)sender
{
    [self doesNotRecognizeSelector:_cmd];
}

- (BOOL)canZoomIn
{
    [self doesNotRecognizeSelector:_cmd];
    return NO;
}

- (BOOL)canZoomOut
{
    [self doesNotRecognizeSelector:_cmd];
    return NO;
}

- (BOOL)canResetZoom
{
    [self doesNotRecognizeSelector:_cmd];
    return NO;
}

- (IBAction)toggleZoomMode:(id)sender
{
    [self doesNotRecognizeSelector:_cmd];
}

- (CGFloat)pageScaleForMenuItemTag:(NSInteger)tag
{
    if (tag == 1)
        return 1;
    if (tag == 2)
        return 1.25;
    if (tag == 3)
        return 1.5;
    if (tag == 4)
        return 2.0;

    return 1;
}

- (IBAction)setPageScale:(id)sender
{
    [self doesNotRecognizeSelector:_cmd];
}

- (IBAction)setViewScale:(id)sender
{
    [self doesNotRecognizeSelector:_cmd];
}

- (IBAction)toggleShrinkToFit:(id)sender
{
    [self doesNotRecognizeSelector:_cmd];
}

- (IBAction)dumpSourceToConsole:(id)sender
{
    [self doesNotRecognizeSelector:_cmd];
}

- (IBAction)showHideWebInspector:(id)sender
{
    [self doesNotRecognizeSelector:_cmd];
}

- (IBAction)togglePictureInPicture:(id)sender
{
    [self doesNotRecognizeSelector:_cmd];
}

- (IBAction)toggleInWindowFullscreen:(id)sender
{
    [self doesNotRecognizeSelector:_cmd];
}

- (void)didChangeSettings
{
    [self doesNotRecognizeSelector:_cmd];
}

- (NSURL *)currentURL
{
    [self doesNotRecognizeSelector:_cmd];
    return nil;
}

- (NSView *)mainContentView
{
    [self doesNotRecognizeSelector:_cmd];
    return nil;
}

- (IBAction)toggleEditable:(id)sender
{
    self.editable = !self.isEditable;
}

- (IBAction)toggleMainThreadStalls:(id)sender
{
    if (_mainThreadStallTimer) {
        [_mainThreadStallTimer invalidate];
        _mainThreadStallTimer = nil;
        return;
    }

    const NSTimeInterval stallTimerRepeatInterval = 0.2;
    _mainThreadStallTimer = [NSTimer scheduledTimerWithTimeInterval:stallTimerRepeatInterval repeats:YES block:^(NSTimer * _Nonnull timer) {
        const NSTimeInterval stallDuration = 0.2;
        usleep(stallDuration * USEC_PER_SEC);
    }];
}

- (BOOL)mainThreadStallsEnabled
{
    return !!_mainThreadStallTimer;
}

- (NSImage *)windowSnapshotInRect:(CGRect)rect
{
    [self doesNotRecognizeSelector:_cmd];
    return nil;
}

#pragma mark -
#pragma mark NSSharingServicePickerDelegate

- (NSArray *)sharingServicePicker:(NSSharingServicePicker *)sharingServicePicker sharingServicesForItems:(NSArray *)items proposedSharingServices:(NSArray *)proposedServices
{
    return proposedServices;
}

- (id <NSSharingServiceDelegate>)sharingServicePicker:(NSSharingServicePicker *)sharingServicePicker delegateForSharingService:(NSSharingService *)sharingService
{
    return self;
}

- (void)sharingServicePicker:(NSSharingServicePicker *)sharingServicePicker didChooseSharingService:(NSSharingService *)service
{
}

#pragma mark -
#pragma mark NSSharingServiceDelegate

- (NSRect)sharingService:(NSSharingService *)sharingService sourceFrameOnScreenForShareItem:(id)item
{
    NSRect rect = [self.window convertRectToScreen:self.mainContentView.bounds];
    
    return rect;
}

static CGRect coreGraphicsScreenRectForAppKitScreenRect(NSRect rect)
{
    NSScreen *firstScreen = [NSScreen screens][0];
    return CGRectMake(NSMinX(rect), NSHeight(firstScreen.frame) - NSMinY(rect) - NSHeight(rect), NSWidth(rect), NSHeight(rect));
}

- (NSImage *)sharingService:(NSSharingService *)sharingService transitionImageForShareItem:(id)item contentRect:(NSRect *)contentRect
{
    NSRect contentFrame = [self.window convertRectToScreen:self.mainContentView.bounds];
    CGRect frame = coreGraphicsScreenRectForAppKitScreenRect(contentFrame);
    return [self windowSnapshotInRect:frame];
}

- (NSWindow *)sharingService:(NSSharingService *)sharingService sourceWindowForShareItems:(NSArray *)items sharingContentScope:(NSSharingContentScope *)sharingContentScope
{
    *sharingContentScope = NSSharingContentScopeFull;
    return self.window;
}

- (void)updateTitleForBadgeChange
{
    // Only implemented in WebKit2
}

@end
