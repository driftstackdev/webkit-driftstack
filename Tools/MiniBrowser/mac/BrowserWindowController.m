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

    // Driftstack iOS-Safari chrome (W1369) — ENV-GATED `DRIFTSTACK_SAFARI_CHROME`, default OFF so the
    // production session host stays byte-identical until the custom chrome is fully built + verified.
    // The whole window is captured into the session stream (SCContentFilter desktopIndependentWindow),
    // so the macOS title-bar furniture (traffic lights + title text) both looks nothing like iOS Safari
    // AND greys out when the window isn't key (the founder-reported symptom). Phase-1 foundation: drop
    // that native furniture. The custom always-active Safari toolbar that fully replaces the (still-
    // greying) native URL toolbar is the next increment behind this same gate. The window-size /
    // layout-viewport math below is DYNAMIC (measures the actual chrome at runtime) so it self-corrects
    // to the new chrome height — clientHeight==innerHeight stays correct (the file-99 fingerprint).
    if (getenv("DRIFTSTACK_SAFARI_CHROME")) {
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
        // status untouched). isa-swap is layout-safe (subclass adds no ivars).
        object_setClass(self.window, [DriftstackAlwaysActiveWindow class]);
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
            dispatch_async(dispatch_get_main_queue(), ^{
                [weakWindow setContentSize:vpSize];
                if (layoutViewportHeight > 0) {
                    // The webView's final height (content - URL-bar chrome) only
                    // settles after the window displays + lays out, several
                    // runloop turns later. Correct on a short delay: measure the
                    // real webView height, derive the chrome, and resize so the
                    // webView == the layout viewport (clientHeight == innerHeight).
                    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.4 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                        // The web layout viewport (documentElement.clientHeight) is
                        // the contentView area NOT obscured by the title bar/toolbar
                        // (the WKWebView frame fills the whole content but the web
                        // content is inset). That obscured band = contentView.height
                        // - contentLayoutRect.height. Size the window so the
                        // unobscured area == the iPhone layout viewport.
                        CGFloat contentH = weakWindow.contentView.frame.size.height;
                        CGFloat unobscuredH = weakWindow.contentLayoutRect.size.height;
                        CGFloat chrome = contentH - unobscuredH;
                        if (chrome < 0)
                            chrome = 0;
                        NSLog(@"[Driftstack-WindowSize] content=%.0f unobscured=%.0f chrome=%.0f -> window content=%.0f (target viewport=%d)",
                            contentH, unobscuredH, chrome, (double)(layoutViewportHeight + chrome), layoutViewportHeight);
                        [weakWindow setContentSize:NSMakeSize(w, layoutViewportHeight + chrome)];
                    });
                }
            });
        }
    }

    [share sendActionOn:NSEventMaskLeftMouseDown];
    [super windowDidLoad];
}

// W1378: the iOS-26 Safari BOTTOM bar. Re-homes the existing controls (IBOutlets = the real control
// views; their target/action wiring to the WK2 controller stays intact) into a translucent always-
// active glass bar pinned to the window BOTTOM, and shrinks the web content to sit ABOVE it — the
// defining iOS-Safari layout (address bar at the bottom). Gated by DRIFTSTACK_SAFARI_CHROME.
// NOTE (fingerprint): the bar height becomes the chrome; the web-content height (== layout viewport,
// clientHeight==innerHeight, file-99) must be cumrig-verified before enabling for sessions. First cut
// — visual layout iterates via the screenshot loop; tabs + scroll-minimize + final glass polish next.
- (void)installDriftSafariBottomBar
{
    NSView *content = self.window.contentView;
    if (!content)
        return;
    const CGFloat barH = 92.0;   // iOS-26 Safari bottom bar: URL-pill row + toolbar-icon row
    NSRect cb = content.bounds;

    // Drop the native top toolbar (its controls are re-homed below).
    self.window.toolbar = nil;

    // Translucent always-active glass bar pinned to the bottom (never greys: state = Active).
    NSVisualEffectView *bar = [[NSVisualEffectView alloc] initWithFrame:NSMakeRect(0, 0, cb.size.width, barH)];
    bar.material = NSVisualEffectMaterialMenu;                       // W1385: more translucent (Liquid-Glass-er)
    bar.blendingMode = NSVisualEffectBlendingModeWithinWindow;
    bar.state = NSVisualEffectStateActive;
    bar.autoresizingMask = NSViewWidthSizable | NSViewMaxYMargin;   // stretch width, pin to bottom
    [content addSubview:bar positioned:NSWindowAbove relativeTo:nil];
    // W1385: a subtle top hairline separating the bar from the page (iOS toolbars have one).
    NSView *hairline = [[NSView alloc] initWithFrame:NSMakeRect(0, barH - 0.5, cb.size.width, 0.5)];
    hairline.wantsLayer = YES;
    hairline.layer.backgroundColor = NSColor.separatorColor.CGColor;
    hairline.autoresizingMask = NSViewWidthSizable | NSViewMinYMargin;
    [bar addSubview:hairline];

    CGFloat W = cb.size.width;
    // Row 1 (top of bar): the URL "pill" with the lock at its left + reload at its right.
    if (lockButton) { lockButton.frame = NSMakeRect(12, barH - 40, 28, 28); [bar addSubview:lockButton]; }
    if (urlText) {
        // W1385: a clean iOS-Safari URL "pill" — borderless, centered, a soft rounded translucent fill.
        urlText.frame = NSMakeRect(44, barH - 44, W - 88, 34);
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
    if (share) { share.frame = NSMakeRect(W - 98, 10, 34, 34); [bar addSubview:share]; }
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
        [bar addSubview:tabsButton];
    }
    if (progressIndicator) { progressIndicator.frame = NSMakeRect(W/2 - 12, 12, 24, 24); [bar addSubview:progressIndicator]; }

    // Shrink the web content to sit ABOVE the bar (the nib's containerView is the webView's parent).
    if (containerView) {
        containerView.frame = NSMakeRect(0, barH, W, cb.size.height - barH);
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
    for (NSButton *b in @[backButton ?: [NSButton new], forwardButton ?: [NSButton new], reloadButton ?: [NSButton new], lockButton ?: [NSButton new], share ?: [NSButton new]]) {
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
