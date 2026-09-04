/*
 * Copyright (C) 2010-2016 Apple Inc. All rights reserved.
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

#import "WK2BrowserWindowController.h"

#import "AppDelegate.h"
#import "SettingsController.h"
#import <wtf/Platform.h> // for PLATFORM(DRIFTSTACK) launch-security guard (preprocessor-only, .m-safe)
#import <PDFKit/PDFDocument.h>
#import <QuartzCore/CATextLayer.h>
#import <QuartzCore/CAAnimation.h>
#import <SecurityInterface/SFCertificateTrustPanel.h>
#import <UniformTypeIdentifiers/UniformTypeIdentifiers.h>
#import <WebKit/WKFrameInfo.h>
#import <WebKit/WKNavigationActionPrivate.h>
#import <WebKit/WKNavigationDelegate.h>
#import <WebKit/WKOpenPanelParametersPrivate.h>
#import <WebKit/WKPreferencesPrivate.h>
#import <WebKit/WKUIDelegate.h>
#import <WebKit/WKUIDelegatePrivate.h>
#import <WebKit/WKWebViewConfigurationPrivate.h>
#import <WebKit/WKWebViewPrivate.h>
#import <WebKit/WKWebViewPrivateForTesting.h>
#import <WebKit/WKWebpagePreferences.h>
#import <WebKit/WKWebpagePreferencesPrivate.h>
#import <WebKit/WKWebsiteDataStorePrivate.h>
#import <WebKit/WebNSURLExtras.h>
#import <WebKit/_WKArchiveConfiguration.h>
#import <WebKit/_WKFindDelegate.h>
#import <WebKit/_WKFindOptions.h>
#import <WebKit/_WKIconLoadingDelegate.h>
#import <WebKit/_WKInspector.h>
#import <WebKit/_WKLinkIconParameters.h>
#import <objc/runtime.h>   // W2078: associate the per-tab favicon with its WKWebView for the tab overview
#import <WebKit/_WKUserInitiatedAction.h>

static void* keyValueObservingContext = &keyValueObservingContext;
static const int testHeaderBannerHeight = 42;
static const int testFooterBannerHeight = 58;

#if PLATFORM(DRIFTSTACK)
// Warm-tabs fix (2026-07-11): the page-load stall watchdog (W2857) must be PER-TAB. A single per-controller
// NSTimer both (a) got clobbered when any other tab started a navigation and (b) on fire acted on _webView —
// the CURRENTLY visible tab — instead of the tab that armed it, so a background tab's stall surfaced a spurious
// "page took too long" error page on the tab the user was actually looking at. Key the timer to the navigating
// WKWebView via an associated object; fire on THAT webView only if it is still loading.
static char kDriftstackNavWatchdogKey;
static inline void driftstackDisarmNavWatchdog(WKWebView *webView)
{
    NSTimer *watchdog = objc_getAssociatedObject(webView, &kDriftstackNavWatchdogKey);
    [watchdog invalidate];
    objc_setAssociatedObject(webView, &kDriftstackNavWatchdogKey, nil, OBJC_ASSOCIATION_RETAIN);
}
#endif

// Driftstack (W2649): make a FAILED customer load VISIBLE. When a navigation genuinely fails
// (DNS/connect/cert/timeout/proxy error) the customer browser window otherwise shows a blank white
// page with no indication of what went wrong — founder report. We render a neutral, Safari-like
// "can't open the page" error page IN the webView so it streams to the customer. This is MiniBrowser
// HARNESS chrome (Tools/MiniBrowser) ONLY — it does NOT touch any WebContent/fork render or font path,
// so glyphHash / the fingerprint surface is UNAFFECTED (it appears only on failure, when no site is
// loaded, so it is not a fingerprint surface).

// Escape a string for safe interpolation into HTML text/attribute context (avoid injection from the
// failing URL or the NSError reason). & must be replaced first.
static NSString *driftstackHTMLEscape(NSString *raw)
{
    if (!raw.length)
        return @"";
    NSMutableString *s = [raw mutableCopy];
    [s replaceOccurrencesOfString:@"&" withString:@"&amp;" options:0 range:NSMakeRange(0, s.length)];
    [s replaceOccurrencesOfString:@"<" withString:@"&lt;" options:0 range:NSMakeRange(0, s.length)];
    [s replaceOccurrencesOfString:@">" withString:@"&gt;" options:0 range:NSMakeRange(0, s.length)];
    [s replaceOccurrencesOfString:@"\"" withString:@"&quot;" options:0 range:NSMakeRange(0, s.length)];
    [s replaceOccurrencesOfString:@"'" withString:@"&#39;" options:0 range:NSMakeRange(0, s.length)];
    return s;
}

// Render the on-screen error page for a genuine load failure. Skips the benign cancellation/supersede
// (NSURLErrorCancelled / -999) — that is a normal navigation supersede and must NOT show an error page.
static void driftstackShowLoadFailurePage(WKWebView *webView, NSError *error)
{
    if (!webView || !error)
        return;
    // A superseded/cancelled navigation (-999) is normal (e.g. a new load started). Do not surface it.
    if ([error.domain isEqualToString:NSURLErrorDomain] && error.code == NSURLErrorCancelled)
        return;

    // Prefer the explicit failing URL from the error; fall back to the webView's current URL.
    // (NSURLErrorFailingURLStringErrorKey is deprecated as of macOS 15.4 — use the NSURL key.)
    NSURL *failingURL = error.userInfo[NSURLErrorFailingURLErrorKey];
    NSString *failingURLString = failingURL.absoluteString;
    if (!failingURLString.length)
        failingURLString = webView.URL.absoluteString;
    if (!failingURLString.length)
        failingURLString = @"";

    NSString *reason = error.localizedDescription.length ? error.localizedDescription : @"The load failed.";
    NSString *escURL = driftstackHTMLEscape(failingURLString);
    NSString *escReason = driftstackHTMLEscape(reason);
    NSString *escDomain = driftstackHTMLEscape(error.domain ?: @"");

    NSString *html = [NSString stringWithFormat:@""
        "<!DOCTYPE html><html><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
        "<title>This page could not be loaded</title>"
        "<style>"
        "html,body{margin:0;height:100%%;background:#f2f2f7;"
        "font-family:-apple-system,'SF Pro Text','Helvetica Neue',sans-serif;color:#1c1c1e;}"
        ".wrap{box-sizing:border-box;min-height:100%%;display:flex;flex-direction:column;"
        "align-items:center;justify-content:center;text-align:center;padding:48px 28px;}"
        "h1{font-size:22px;font-weight:600;margin:0 0 12px;}"
        ".reason{font-size:16px;line-height:1.45;color:#3a3a3c;margin:0 0 18px;max-width:34em;}"
        ".url{font-size:13px;color:#6c6c70;word-break:break-all;max-width:36em;margin:0 0 6px;}"
        ".code{font-size:12px;color:#8e8e93;margin-top:18px;}"
        "</style></head><body><div class=\"wrap\">"
        "<h1>This page could not be loaded</h1>"
        "<p class=\"reason\">%@</p>"
        "<p class=\"url\">%@</p>"
        "<p class=\"code\">%@ &middot; error %ld</p>"
        "</div></body></html>",
        escReason, escURL, escDomain, (long)error.code];

    NSURL *unreachableURL = failingURLString.length ? [NSURL URLWithString:failingURLString] : nil;

    // Keep the failed URL in the address bar WITHOUT adding a history entry. _loadAlternateHTMLString
    // is WK SPI (declared in WKWebViewPrivate.h, already imported); fall back to loadHTMLString if the
    // unreachable URL could not be parsed.
    if (unreachableURL && [webView respondsToSelector:@selector(_loadAlternateHTMLString:baseURL:forUnreachableURL:)])
        [webView _loadAlternateHTMLString:html baseURL:unreachableURL forUnreachableURL:unreachableURL];
    else
        [webView loadHTMLString:html baseURL:unreachableURL];
}

@interface MiniBrowserNSTextFinder : NSTextFinder

@property (nonatomic, copy) dispatch_block_t hideInterfaceCallback;

@end

@implementation MiniBrowserNSTextFinder

- (void)performAction:(NSTextFinderAction)op
{
    [super performAction:op];

    if (op == NSTextFinderActionHideFindInterface && _hideInterfaceCallback)
        _hideInterfaceCallback();
}

@end

@interface FindBarFieldEditor : NSTextView
@end

@implementation FindBarFieldEditor

- (void)performTextFinderAction:(id)sender
{
    [self.window.windowController performTextFinderAction:sender];
}

- (BOOL)validateMenuItem:(NSMenuItem *)menuItem
{
    if (menuItem.action == @selector(performTextFinderAction:))
        return YES;
    return [super validateMenuItem:menuItem];
}

@end

@interface WK2BrowserWindowController () <NSTextFinderBarContainer, _WKFindDelegate, NSSearchFieldDelegate, WKNavigationDelegate, WKUIDelegate, WKUIDelegatePrivate, _WKIconLoadingDelegate>
- (void)driftActivateWebView:(WKWebView *)webView;
- (void)driftRunTabsSelfTest;
- (void)driftToggleTabOverview:(id)sender;
- (void)driftSelectTab:(NSButton *)sender;
- (void)driftCloseTab:(NSButton *)sender;
- (void)driftOverviewNewTab:(id)sender;
- (void)driftNoteWarmTabActive:(WKWebView *)webView;
- (void)driftEvictWarmTabsBeyondN;
- (void)driftEvictAllWarmToActive;
- (void)driftEnsureWarmTabMemoryPressureSource;
@end

// Driftstack: multi-tab MODEL for the iOS-26 chrome (gated DRIFTSTACK_SAFARI_CHROME) — the (B)
// approach: real per-tab WKWebViews in ONE window, not macOS window-tabs. Pure index model: it
// holds the session's WKWebViews + the active index and nothing else; the CONTROLLER owns webview
// creation, the KVO/binding/delegate wiring, and visibility (see -driftActivateWebView:), so this
// stays trivially correct + crash-free (no WebKit state touched here). The controller keeps its
// single `_webView` pointer aimed at -activeWebView, so every existing `_webView` reference (nav,
// urlText, find bar, mainContentView, …) acts on the active tab with no change. Never empties:
// -closeActiveTab refuses to remove the last tab. Indices are NSInteger + bounds-checked so a bad
// index returns nil/-1 rather than trapping (a reusable model fed runtime UI events must not crash).
@interface DriftstackTabManager : NSObject
@property (nonatomic, readonly) NSUInteger count;
@property (nonatomic, readonly) NSInteger activeIndex;
@property (nonatomic, readonly, nullable) WKWebView *activeWebView;
- (void)addTab:(WKWebView *)webView;                     // append + make active
- (nullable WKWebView *)switchToIndex:(NSInteger)index;  // bounds-checked; nil if out of range
- (NSInteger)closeActiveTab;                             // remove active + pick neighbor; -1 if it would empty
- (NSInteger)closeTabAtIndex:(NSInteger)index;           // remove tab i, fix activeIndex; -1 if OOB / would empty
- (nullable WKWebView *)webViewAtIndex:(NSInteger)index;
@end

@implementation DriftstackTabManager {
    NSMutableArray<WKWebView *> *_tabs;
    NSInteger _activeIndex;
}
- (instancetype)init
{
    if ((self = [super init])) {
        _tabs = [NSMutableArray array];
        _activeIndex = -1;
    }
    return self;
}
- (NSUInteger)count { return _tabs.count; }
- (NSInteger)activeIndex { return _activeIndex; }
- (WKWebView *)activeWebView
{
    return (_activeIndex >= 0 && _activeIndex < (NSInteger)_tabs.count) ? _tabs[_activeIndex] : nil;
}
- (WKWebView *)webViewAtIndex:(NSInteger)index
{
    return (index >= 0 && index < (NSInteger)_tabs.count) ? _tabs[index] : nil;
}
- (void)addTab:(WKWebView *)webView
{
    if (!webView)
        return;
    [_tabs addObject:webView];
    _activeIndex = (NSInteger)_tabs.count - 1;
}
- (WKWebView *)switchToIndex:(NSInteger)index
{
    if (index < 0 || index >= (NSInteger)_tabs.count)
        return nil;
    _activeIndex = index;
    return _tabs[index];
}
- (NSInteger)closeActiveTab
{
    return [self closeTabAtIndex:_activeIndex];
}
- (NSInteger)closeTabAtIndex:(NSInteger)index
{
    if (_tabs.count <= 1 || index < 0 || index >= (NSInteger)_tabs.count)
        return -1;   // never empty; out-of-range = no-op
    [_tabs removeObjectAtIndex:index];
    if (index < _activeIndex)
        _activeIndex -= 1;                            // a tab BEFORE the active one closed → shift the active left
    else if (index == _activeIndex && _activeIndex >= (NSInteger)_tabs.count)
        _activeIndex = (NSInteger)_tabs.count - 1;    // closed the active AND it was last → previous neighbor
    // (index == _activeIndex but not last: _activeIndex now points at the next tab — correct, no change)
    return _activeIndex;
}
@end

// Driftstack: iOS-Simulator-style touch presentation. A passthrough overlay that
// (a) hides the Mac arrow cursor over the web view and (b) flashes a translucent
// tap ring at each click point — so the browser looks like an iPhone (a tap, no
// cursor) rather than a Mac. Gated behind DRIFTSTACK_IOS_CURSOR.
@interface DriftstackTapOverlayView : NSView
- (void)driftstackFlashTapAt:(NSPoint)point;
@end

@implementation DriftstackTapOverlayView {
    NSTrackingArea *_trackingArea;
}
- (NSView *)hitTest:(NSPoint)point { return nil; } // events pass through to the WKWebView below
- (void)updateTrackingAreas
{
    [super updateTrackingAreas];
    if (_trackingArea)
        [self removeTrackingArea:_trackingArea];
    _trackingArea = [[NSTrackingArea alloc] initWithRect:NSZeroRect
        options:(NSTrackingMouseEnteredAndExited | NSTrackingActiveInKeyWindow | NSTrackingInVisibleRect)
        owner:self userInfo:nil];
    [self addTrackingArea:_trackingArea];
}
- (void)mouseEntered:(NSEvent *)event { [NSCursor hide]; }
- (void)mouseExited:(NSEvent *)event { [NSCursor unhide]; }
- (void)driftstackFlashTapAt:(NSPoint)point
{
    CGFloat radius = 21.0;
    CALayer *ring = [CALayer layer];
    ring.frame = CGRectMake(point.x - radius, point.y - radius, radius * 2, radius * 2);
    ring.cornerRadius = radius;
    ring.backgroundColor = [[NSColor colorWithCalibratedWhite:0.5 alpha:0.40] CGColor];
    ring.borderColor = [[NSColor colorWithCalibratedWhite:0.35 alpha:0.75] CGColor];
    ring.borderWidth = 1.5;
    [self.layer addSublayer:ring];
    CABasicAnimation *scale = [CABasicAnimation animationWithKeyPath:@"transform.scale"];
    scale.fromValue = @0.5;
    scale.toValue = @1.25;
    CABasicAnimation *fade = [CABasicAnimation animationWithKeyPath:@"opacity"];
    fade.fromValue = @1.0;
    fade.toValue = @0.0;
    CAAnimationGroup *group = [CAAnimationGroup animation];
    group.animations = @[scale, fade];
    group.duration = 0.34;
    [ring addAnimation:group forKey:@"driftstackTap"];
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.34 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        [ring removeFromSuperlayer];
    });
}
@end

#if PLATFORM(DRIFTSTACK)
// Driftstack warm-tabs (doc 151 §2.3): N = 1 active + (N-1) warm live tabs. Default 2 (the common "switch back
// to where I just was" case, comfortably under the 1800 MB overuse ceiling); overridable via
// DRIFTSTACK_WARM_TABS_N for the N=3 promotion experiment (behind the RSS-ceiling-vs-N coupling, §2.3). Never
// below 1 — the active tab is never evictable. Read live (process-stable but cheap; can't go stale).
static NSInteger driftstackWarmTabsN(void)
{
    const char *raw = getenv("DRIFTSTACK_WARM_TABS_N");
    NSInteger n = raw ? (NSInteger)atol(raw) : 2;
    return n < 1 ? 1 : n;
}
#endif

@implementation WK2BrowserWindowController {
    WKWebViewConfiguration *_configuration;
    WKWebView *_webView;                  // ALWAYS the active tab (DriftstackTabManager keeps it aimed here)
    DriftstackTabManager *_tabManager;    // Driftstack iOS-26 chrome multi-tab model (gated)
    NSMutableArray<WKWebView *> *_warmTabLRU; // Driftstack warm-tabs (doc 151): live tabs, most-recently-active first
    dispatch_source_t _warmTabMemoryPressureSource; // Driftstack warm-tabs (doc 151 §5): pressure -> evict-to-active
    __weak WKWebView *_driftWiredWebView; // the tab currently carrying the shared chrome wiring (KVO/bindings/delegates)
    NSView *_driftTabOverlay;             // the iOS-style tab-overview overlay (nil when closed)
    BOOL _zoomTextOnly;
    BOOL _isPrivateBrowsingWindow;
    // W2857 page-load STALL watchdog is now PER-TAB (associated object kDriftstackNavWatchdogKey), not a controller ivar.

    BOOL _useShrinkToFit;

    MiniBrowserNSTextFinder *_textFinder;
    NSView *_textFindBarView;

    NSView *_findBar;
    NSSearchField *_findSearchField;
    NSTextField *_findMatchCountLabel;
    FindBarFieldEditor *_findBarFieldEditor;
    id _findBarClickMonitor;
    id _tapOverlayClickMonitor;   // Driftstack DRIFTSTACK_IOS_CURSOR tap-ring local event monitor (removed in dealloc; was leaked per window)

    BOOL _findBarVisible;
    BOOL _usingFindDelegate;

    CATextLayer *_pointerLockBanner;
}

// Driftstack: make `webView` the ACTIVE tab. Moves the SHARED, single-instance chrome — the lone
// progressIndicator binding, the title/URL/lock/gpu KVO observers, and the nav/UI delegates — off the
// outgoing tab and onto this one, hides the old + shows the new, then refreshes the URL/title/lock
// chrome immediately (KVO only fires on CHANGE). Keeping those shared resources on the ACTIVE tab only
// means a backgrounded tab can neither drive the chrome nor fire delegate callbacks, and tearing its
// observers down before it can be released avoids the classic KVO-still-registered crash. Idempotent:
// re-activating the current tab is a no-op (guards against double-registering observers/bindings). For
// the single-tab (chrome-off / no extra tab) case the very first call is behaviour-identical to the
// original inline awakeFromNib wiring — same binding/observers/delegates, just applied via this seam.
- (void)driftActivateWebView:(WKWebView *)webView
{
    if (!webView || webView == _driftWiredWebView)
        return;

    WKWebView *previous = _driftWiredWebView;
    if (previous) {
        [progressIndicator unbind:NSHiddenBinding];
        [progressIndicator unbind:NSValueBinding];
        @try {
            [previous removeObserver:self forKeyPath:@"title" context:keyValueObservingContext];
            [previous removeObserver:self forKeyPath:@"URL" context:keyValueObservingContext];
            [previous removeObserver:self forKeyPath:@"hasOnlySecureContent" context:keyValueObservingContext];
            [previous removeObserver:self forKeyPath:@"_gpuProcessIdentifier" context:keyValueObservingContext];
        } @catch (NSException *exception) {
            NSLog(@"[Driftstack/MiniBrowser] tab switch: observer teardown skipped (%@)", exception.name);
        }
        previous.navigationDelegate = nil;
        previous.UIDelegate = nil;
        previous.hidden = YES;
    }

    _webView = webView;
    _driftWiredWebView = webView;
    webView.hidden = NO;

    [progressIndicator bind:NSHiddenBinding toObject:webView withKeyPath:@"loading" options:@{ NSValueTransformerNameBindingOption : NSNegateBooleanTransformerName }];
    [progressIndicator bind:NSValueBinding toObject:webView withKeyPath:@"estimatedProgress" options:nil];

    [webView addObserver:self forKeyPath:@"title" options:0 context:keyValueObservingContext];
    [webView addObserver:self forKeyPath:@"URL" options:0 context:keyValueObservingContext];
    [webView addObserver:self forKeyPath:@"hasOnlySecureContent" options:0 context:keyValueObservingContext];
    [webView addObserver:self forKeyPath:@"_gpuProcessIdentifier" options:0 context:keyValueObservingContext];

    webView.navigationDelegate = self;
    webView.UIDelegate = self;

    [self updateTextFieldFromURL:webView.URL];
    [self updateTitle:webView.title];
    [self updateLockButtonIcon:webView.hasOnlySecureContent];

    // W1397: re-point the text finder at the active tab — find-on-page must search the VISIBLE tab,
    // not whichever tab was active when the finder was first created (W1391 follow-gap). No-op until
    // the find bar is first used (`_textFinder` lazily created in `_showFindBar`).
    if (_textFinder)
        _textFinder.client = webView;
}

// Driftstack: the iOS-style TAB OVERVIEW (B2) — toggled by the bottom-bar tabs button. A full-content
// glass overlay listing the open tabs as cards (title + URL), tap a card to switch, "+ New Tab" to open
// one. Gated DRIFTSTACK_SAFARI_CHROME (the bar that hosts the button is too). Cards show text now;
// snapshot thumbnails are a later polish. All tab state comes from the DriftstackTabManager; switching
// reuses -driftActivateWebView: (the W1390 engine), so the chrome + content follow correctly.
- (void)driftToggleTabOverview:(id)sender
{
    if (_driftTabOverlay) {            // toggle closed
        [_driftTabOverlay removeFromSuperview];
        _driftTabOverlay = nil;
        return;
    }
    NSView *content = self.window.contentView;
    if (!content || !_tabManager)
        return;

    NSVisualEffectView *overlay = [[NSVisualEffectView alloc] initWithFrame:content.bounds];
    overlay.material = NSVisualEffectMaterialHUDWindow;
    overlay.state = NSVisualEffectStateActive;                       // never greys (same always-active rule as the bar)
    overlay.blendingMode = NSVisualEffectBlendingModeWithinWindow;
    overlay.autoresizingMask = NSViewWidthSizable | NSViewHeightSizable;

    CGFloat W = content.bounds.size.width, H = content.bounds.size.height;
    NSTextField *titleLabel = [NSTextField labelWithString:[NSString stringWithFormat:@"%lu Tab%@",
                                                            (unsigned long)_tabManager.count,
                                                            _tabManager.count == 1 ? @"" : @"s"]];
    titleLabel.font = [NSFont boldSystemFontOfSize:20];
    titleLabel.alignment = NSTextAlignmentCenter;
    titleLabel.frame = NSMakeRect(0, H - 56, W, 28);
    titleLabel.autoresizingMask = NSViewWidthSizable | NSViewMinYMargin;
    [overlay addSubview:titleLabel];

    NSColor *oxblood = [NSColor colorWithSRGBRed:114.0/255.0 green:47.0/255.0 blue:55.0/255.0 alpha:1.0];
    const CGFloat cardH = 60, gap = 12, sideMargin = 24;
    CGFloat y = H - 56 - 24 - cardH;
    for (NSInteger i = 0; i < (NSInteger)_tabManager.count; i++) {
        WKWebView *wv = [_tabManager webViewAtIndex:i];
        NSString *t = wv.title.length ? wv.title : (wv.URL.absoluteString.length ? wv.URL.absoluteString : @"New Tab");
        NSButton *card = [NSButton buttonWithTitle:t target:self action:@selector(driftSelectTab:)];
        card.tag = i;
        // W2078: show the tab's FAVICON on the card (iOS-26 tab switcher look), left of the title. NSButton
        // lays out image+title for us (NSImageLeading). Falls back to title-only if the tab has no icon yet.
        NSImage *favicon = objc_getAssociatedObject(wv, &kDriftFaviconKey);
        if (favicon) {
            NSImage *small = [favicon copy];
            small.size = NSMakeSize(24, 24);
            card.image = small;
            card.imagePosition = NSImageLeading;
            card.imageHugsTitle = YES;
        }
        card.bezelStyle = NSBezelStyleRegularSquare;
        card.frame = NSMakeRect(sideMargin, y, W - 2 * sideMargin, cardH);
        card.autoresizingMask = NSViewWidthSizable | NSViewMinYMargin;
        card.wantsLayer = YES;
        card.layer.cornerRadius = 12;
        card.layer.borderWidth = (i == _tabManager.activeIndex) ? 2.0 : 0.0;   // highlight the active tab
        card.layer.borderColor = oxblood.CGColor;
        card.contentTintColor = (i == _tabManager.activeIndex) ? oxblood : nil;
        [overlay addSubview:card];
        // Per-card CLOSE (×) — iOS overview lets you close a tab from here. Added AFTER the card so it
        // sits on top at the right edge (a click on the × closes; elsewhere on the card switches).
        // Hidden when only one tab remains (closeTabAtIndex refuses to empty — never a dead-end ×).
        if (_tabManager.count > 1) {
            NSButton *closeBtn = [NSButton buttonWithTitle:@"✕" target:self action:@selector(driftCloseTab:)];
            closeBtn.tag = i;
            closeBtn.bordered = NO;
            closeBtn.frame = NSMakeRect(W - sideMargin - 40, y + (cardH - 28) / 2, 28, 28);
            closeBtn.autoresizingMask = NSViewMinXMargin | NSViewMinYMargin;
            [overlay addSubview:closeBtn];
        }
        y -= (cardH + gap);
    }

    NSButton *plus = [NSButton buttonWithTitle:@"+  New Tab" target:self action:@selector(driftOverviewNewTab:)];
    plus.frame = NSMakeRect(sideMargin, 28, W - 2 * sideMargin, 44);
    plus.autoresizingMask = NSViewWidthSizable | NSViewMaxYMargin;
    plus.contentTintColor = oxblood;
    [overlay addSubview:plus];

    [content addSubview:overlay positioned:NSWindowAbove relativeTo:nil];
    _driftTabOverlay = overlay;
}

- (void)driftSelectTab:(NSButton *)sender
{
    WKWebView *wv = [_tabManager switchToIndex:sender.tag];
    if (wv)
        [self driftActivateWebView:wv];
    [self driftToggleTabOverview:nil];   // dismiss the overview
}

- (void)driftCloseTab:(NSButton *)sender
{
    WKWebView *closing = [_tabManager webViewAtIndex:sender.tag];
    NSInteger newActive = [_tabManager closeTabAtIndex:sender.tag];
    if (newActive < 0)
        return;                              // refused (last tab) — nothing to do
    // Warm-tabs fix (2026-07-11): drop the closed tab from the warm LRU too. _warmTabLRU is a controller ivar
    // that closeTabAtIndex: (a DriftstackTabManager method) cannot touch, so a closed automation tab used to
    // linger in the LRU — leaking its WKWebView + WebContent, and (worse) stalling eviction: a later
    // driftEvictWarmTabsBeyondN picks the stale entry as victim, fails to find its index (idx<0), and breaks,
    // so the warm set can grow past N.
    [_warmTabLRU removeObject:closing];
    [closing removeFromSuperview];           // drop the closed tab's webview from the container
    WKWebView *active = [_tabManager activeWebView];
    if (active)
        [self driftActivateWebView:active];  // no-op if the active tab didn't change (idempotent guard)
    // Rebuild the overview to reflect the new tab set (close → reopen).
    [self driftToggleTabOverview:nil];
    [self driftToggleTabOverview:nil];
}

- (void)driftOverviewNewTab:(id)sender
{
    WKWebView *wv = [[WKWebView alloc] initWithFrame:[containerView bounds] configuration:_configuration];
    [wv setAutoresizingMask:(NSViewWidthSizable | NSViewHeightSizable)];
    wv.hidden = YES;
    // W1446 (W1390 increment-2 z-order): a new tab's webView added with the default (topmost) z-order
    // would cover the iOS tap-ring overlay (DRIFTSTACK_IOS_CURSOR, added above _webView) once this tab
    // is activated → the tap-ring vanishes. Insert BELOW the overlay if present so the ring stays on top.
    DriftstackTapOverlayView *existingOverlay = nil;
    for (NSView *sub in containerView.subviews) {
        if ([sub isKindOfClass:[DriftstackTapOverlayView class]]) { existingOverlay = (DriftstackTapOverlayView *)sub; break; }
    }
    if (existingOverlay)
        [containerView addSubview:wv positioned:NSWindowBelow relativeTo:existingOverlay];
    else
        [containerView addSubview:wv];
    [_tabManager addTab:wv];
    [self driftActivateWebView:wv];
    [wv loadRequest:[NSURLRequest requestWithURL:[NSURL URLWithString:@"about:blank"]]];
    [self driftToggleTabOverview:nil];   // dismiss → reveal the fresh tab
}

#if PLATFORM(DRIFTSTACK)
// Driftstack warm-tabs (doc 151 §7.1): the automation-path new-tab. Same live-tab creation as
// -driftOverviewNewTab: (shares _configuration → same store/fingerprint; z-ordered below the tap overlay;
// added to _tabManager; activated via the -driftActivateWebView: engine which hides the previous tab) but
// WITHOUT the about:blank load (the harness navigates it) and WITHOUT the overview-UI toggle. Returns the new
// WKWebView so the automation delegate can hand it back + mark it controlledByAutomation. See header.
- (WKWebView *)driftCreateAndActivateAutomationTab
{
    if (!containerView || !_tabManager)
        return nil;
    [self driftEnsureWarmTabMemoryPressureSource];   // arm the pressure safety-valve on first warm tab
    // First automation tab: REUSE the pristine initial tab (awakeFromNib registers tab 0) rather than
    // orphaning it. Otherwise tab0 stays a live-but-unused hidden WebContent that occupies a warm slot (so
    // N=2 would leave 0 real warm tabs) and can never be evicted (it's never entered the LRU). Detect the
    // pristine-initial state as exactly one tab with an empty LRU (nothing automation-claimed yet); claim it
    // into the LRU + hand it back so requestNewWebViewWithOptions marks IT controlledByAutomation.
    if (_tabManager.count == 1 && (!_warmTabLRU || _warmTabLRU.count == 0)) {
        WKWebView *initial = _tabManager.activeWebView;
        if (initial) {
            [self driftNoteWarmTabActive:initial];
            return initial;
        }
    }
    WKWebView *wv = [[WKWebView alloc] initWithFrame:[containerView bounds] configuration:_configuration];
    [wv setAutoresizingMask:(NSViewWidthSizable | NSViewHeightSizable)];
    wv.hidden = YES;
    DriftstackTapOverlayView *existingOverlay = nil;
    for (NSView *sub in containerView.subviews) {
        if ([sub isKindOfClass:[DriftstackTapOverlayView class]]) { existingOverlay = (DriftstackTapOverlayView *)sub; break; }
    }
    if (existingOverlay)
        [containerView addSubview:wv positioned:NSWindowBelow relativeTo:existingOverlay];
    else
        [containerView addSubview:wv];
    [_tabManager addTab:wv];
    [self driftActivateWebView:wv];
    [self driftNoteWarmTabActive:wv];      // LRU: the new tab is now most-recently-active
    [self driftEvictWarmTabsBeyondN];      // bound the warm set to N (evict the LRU non-active tab, never active/last)
    return wv;
}

// Driftstack warm-tabs (doc 151 §7.1): the automation-path tab switch (W3C POST /window). If `webView` is one
// of this window's live tabs, make it active + visible via the -driftActivateWebView: engine (which hides the
// previous tab, moves the shared chrome/KVO, and is idempotent so switching to the already-active tab is a
// no-op). Returns YES if handled, NO if `webView` is not a tab here. This is the WARM fast-path — a live
// bring-to-front with NO reload/navigate. See header.
- (BOOL)driftSwitchToAutomationWebView:(WKWebView *)webView
{
    if (!webView || !_tabManager)
        return NO;
    for (NSInteger i = 0; i < (NSInteger)_tabManager.count; i++) {
        if ([_tabManager webViewAtIndex:i] == webView) {
            WKWebView *wv = [_tabManager switchToIndex:i];
            if (wv) {
                [self driftActivateWebView:wv];   // idempotent — no-op if already the active/wired tab
                [self driftNoteWarmTabActive:wv]; // LRU: switched-to tab is now most-recently-active
            }
            return YES;
        }
    }
    return NO;
}

// Driftstack warm-tabs (doc 151 §5): mark `webView` most-recently-active in the LRU (create + switch both call
// this). The warm set = the N most-recently-active live tabs.
- (void)driftNoteWarmTabActive:(WKWebView *)webView
{
    if (!webView)
        return;
    if (!_warmTabLRU)
        _warmTabLRU = [NSMutableArray array];
    [_warmTabLRU removeObject:webView];
    [_warmTabLRU insertObject:webView atIndex:0];   // most-recently-active first
}

// Driftstack warm-tabs (doc 151 §5, eviction trigger #1): while the live tab count exceeds N, evict the
// least-recently-active tab that is NOT the active one — closeTabAtIndex: (which refuses to empty the list) +
// drop it from the LRU + removeFromSuperview so the backing WebContent terminates on dealloc. Never evicts the
// active/last tab; the evicted tab's {url,scrollY,title} stays in the harness's logical tab set (a later switch
// to it is a cold reload — iOS-faithful). A warm-but-inactive tab was already unwired by -driftActivateWebView:
// when it lost focus, so there is no KVO/delegate teardown to do here.
- (void)driftEvictWarmTabsBeyondN
{
    NSInteger n = driftstackWarmTabsN();
    while ((NSInteger)_tabManager.count > n) {
        WKWebView *active = _tabManager.activeWebView;
        WKWebView *victim = nil;
        for (WKWebView *wv in [_warmTabLRU reverseObjectEnumerator]) {   // least-recently-active first
            if (wv != active) { victim = wv; break; }
        }
        if (!victim)
            break;   // nothing evictable — only the active/last tab remains
        NSInteger idx = -1;
        for (NSInteger i = 0; i < (NSInteger)_tabManager.count; i++) {
            if ([_tabManager webViewAtIndex:i] == victim) { idx = i; break; }
        }
        if (idx < 0 || [_tabManager closeTabAtIndex:idx] < 0)
            break;   // couldn't close (out-of-range / would empty) — stop
        [_warmTabLRU removeObject:victim];
        [victim removeFromSuperview];   // drop the view-hierarchy strong ref → WebContent terminates on dealloc
    }
}

// Driftstack warm-tabs (doc 151 §5, eviction trigger #2 — the REQUIRED safety valve, §2.3 guardrail 2): under
// real memory pressure, drop ALL warm-but-inactive tabs to active-only, regardless of N. Mirrors iOS (Safari
// unloads background tabs under pressure) and keeps warm-tabs from ever tripping the per-session RSS overuse
// ceiling before the host-level guard fires.
- (void)driftEvictAllWarmToActive
{
    WKWebView *active = _tabManager.activeWebView;
    while ((NSInteger)_tabManager.count > 1) {
        NSInteger idx = -1;
        for (NSInteger i = 0; i < (NSInteger)_tabManager.count; i++) {
            if ([_tabManager webViewAtIndex:i] != active) { idx = i; break; }
        }
        if (idx < 0)
            break;   // only the active tab remains
        WKWebView *victim = [_tabManager webViewAtIndex:idx];
        if ([_tabManager closeTabAtIndex:idx] < 0)
            break;
        [_warmTabLRU removeObject:victim];
        [victim removeFromSuperview];
    }
}

// Lazily arm a main-queue memory-pressure source the first time warm-tabs opens a tab (so it's only active when
// the feature is). WARN|CRITICAL → -driftEvictAllWarmToActive. A dispatch source is the ObjC-native mechanism
// for this UI process (the WTF MemoryPressureHandler is C++ / WebContent-side, not usable from a .m). Torn down
// in -dealloc.
- (void)driftEnsureWarmTabMemoryPressureSource
{
    if (_warmTabMemoryPressureSource)
        return;
    dispatch_source_t src = dispatch_source_create(DISPATCH_SOURCE_TYPE_MEMORYPRESSURE, 0,
        DISPATCH_MEMORYPRESSURE_WARN | DISPATCH_MEMORYPRESSURE_CRITICAL, dispatch_get_main_queue());
    if (!src)
        return;
    __weak WK2BrowserWindowController *weakSelf = self;
    dispatch_source_set_event_handler(src, ^{
        [weakSelf driftEvictAllWarmToActive];
    });
    dispatch_resume(src);
    _warmTabMemoryPressureSource = src;
}
#endif

// Driftstack (gated DRIFTSTACK_TABS_SELFTEST): deterministic, screenshot-verifiable exercise of the
// tab ENGINE with NO clicks/keystrokes — open a 2nd tab + activate it (proves the bind→new path), then
// switch back to tab 0 (proves the unbind-old/rebind-new switch path + that the chrome follows). Each
// phase is observable by the focus-safe capture loop (scripts/screenshot-minibrowser-chrome.sh). Debug
// only; compiled in but inert unless the env var is set (and the whole chrome is itself gated).
- (void)driftRunTabsSelfTest
{
    NSView *container = containerView;   // capture the ivar outside the block (avoid -Wimplicit-retain-self)
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        WKWebView *tabB = [[WKWebView alloc] initWithFrame:[container bounds] configuration:self->_configuration];
        [tabB setAutoresizingMask:(NSViewWidthSizable | NSViewHeightSizable)];
        tabB.hidden = YES;
        [container addSubview:tabB];
        [self->_tabManager addTab:tabB];
        [self driftActivateWebView:tabB];
        [tabB loadHTMLString:@"<html><body style=\"font:48px -apple-system;padding:40px;color:#722F37\">DRIFTSTACK TAB B</body></html>" baseURL:[NSURL URLWithString:@"https://tab-b.driftstack.test/"]];
        NSLog(@"[Driftstack/MiniBrowser] tabs self-test: opened+activated tab B (count=%lu, active=%ld)", (unsigned long)self->_tabManager.count, (long)self->_tabManager.activeIndex);

        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            WKWebView *tab0 = [self->_tabManager switchToIndex:0];
            if (tab0)
                [self driftActivateWebView:tab0];
            NSLog(@"[Driftstack/MiniBrowser] tabs self-test: switched back to tab 0 (active=%ld)", (long)self->_tabManager.activeIndex);

            // Phase 3 (W1397): open the tab OVERVIEW so its card grid is screenshot-verifiable
            // WITHOUT a click (focus/z-order-independent — the W1390 self-test pattern). Opened ~5s in
            // (well before a standalone MiniBrowser's ~8s self-exit) so a capture lands while it's up.
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                [self driftToggleTabOverview:nil];
                NSLog(@"[Driftstack/MiniBrowser] tabs self-test: opened tab overview (tabs=%lu)", (unsigned long)self->_tabManager.count);
            });
        });
    });
}

- (void)awakeFromNib
{
    _webView = [[WKWebView alloc] initWithFrame:[containerView bounds] configuration:_configuration];
    _webView.inspectable = YES;
    [self didChangeSettings];

    _webView.allowsMagnification = YES;
    _webView.allowsBackForwardNavigationGestures = YES;
    _webView._editable = self.isEditable;

    [_webView setAutoresizingMask:(NSViewWidthSizable | NSViewHeightSizable)];
    [containerView addSubview:_webView];

    // Driftstack: install the iOS-Simulator-style tap overlay (Mac cursor hidden +
    // a tap ring flashed on each click) when DRIFTSTACK_IOS_CURSOR is set. The
    // overlay is hitTest-transparent, so every click still reaches the WKWebView
    // (and the fork's native touch synthesis) unchanged.
    // W1446: VALUE check, not bare presence (same footgun class as SAFARI_CHROME W1434b) — a non-empty
    // FALSY value ("0"/"false"/"no"/"off") must DISABLE the tap ring, not enable it. (This env is
    // bare-fork/dev-only — the harness never forwards it — but keep the gate semantics consistent.)
    const char* iosCursorRaw = getenv("DRIFTSTACK_IOS_CURSOR");
    NSString *iosCursorVal = iosCursorRaw
        ? [[NSString stringWithUTF8String:iosCursorRaw] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]].lowercaseString
        : nil;
    BOOL iosCursorOn = iosCursorVal.length > 0
        && ![iosCursorVal isEqualToString:@"0"] && ![iosCursorVal isEqualToString:@"false"]
        && ![iosCursorVal isEqualToString:@"no"] && ![iosCursorVal isEqualToString:@"off"];
    if (iosCursorOn) {
        DriftstackTapOverlayView *tapOverlay = [[DriftstackTapOverlayView alloc] initWithFrame:[containerView bounds]];
        tapOverlay.wantsLayer = YES;
        [tapOverlay setAutoresizingMask:(NSViewWidthSizable | NSViewHeightSizable)];
        [containerView addSubview:tapOverlay positioned:NSWindowAbove relativeTo:_webView];
        __weak DriftstackTapOverlayView *weakTapOverlay = tapOverlay;
        _tapOverlayClickMonitor = [NSEvent addLocalMonitorForEventsMatchingMask:NSEventMaskLeftMouseDown handler:^NSEvent *(NSEvent *event) {
            DriftstackTapOverlayView *overlay = weakTapOverlay;
            if (overlay && event.window == overlay.window) {
                NSPoint point = [overlay convertPoint:event.locationInWindow fromView:nil];
                if (NSPointInRect(point, [overlay bounds]))
                    [overlay driftstackFlashTapAt:point];
            }
            return event;
        }];
    }

    // Driftstack: register tab 0 with the multi-tab manager and route the shared chrome (the lone
    // progressIndicator binding + the title/URL/lock/gpu KVO observers + the nav/UI delegates) through
    // -driftActivateWebView: so it can MOVE between tabs. _webView stays the single active-tab pointer.
    // Behaviour-identical to the original inline wiring for the single-tab case (same binding/observers/
    // delegates) — the seam only matters once a 2nd tab exists (iOS-26 chrome, gated).
    _tabManager = [[DriftstackTabManager alloc] init];
    [_tabManager addTab:_webView];
    [self driftActivateWebView:_webView];

    SettingsController *settingsController = [[NSApplication sharedApplication] browserAppDelegate].settingsController;
    // This setting installs the new WK2 Icon Loading Delegate and tests that mechanism by
    // telling WebKit to load every icon referenced by the page.
    if (settingsController.loadsAllSiteIcons)
        _webView._iconLoadingDelegate = self;
    
    _webView._observedRenderingProgressEvents = _WKRenderingProgressEventFirstLayout
        | _WKRenderingProgressEventFirstVisuallyNonEmptyLayout
        | _WKRenderingProgressEventFirstPaintWithSignificantArea
        | _WKRenderingProgressEventFirstLayoutAfterSuppressedIncrementalRendering
        | _WKRenderingProgressEventFirstPaintAfterSuppressedIncrementalRendering;


    if (settingsController.customUserAgent)
        _webView.customUserAgent = settingsController.customUserAgent;

    _webView._usePlatformFindUI = NO;

    _zoomTextOnly = NO;

    // Driftstack (gated DRIFTSTACK_TABS_SELFTEST): screenshot-verifiable tab-engine self-test (B1).
    if (getenv("DRIFTSTACK_TABS_SELFTEST"))
        [self driftRunTabsSelfTest];
}

- (id)windowWillReturnFieldEditor:(NSWindow *)sender toObject:(id)client
{
    if (client == _findSearchField) {
        if (!_findBarFieldEditor) {
            _findBarFieldEditor = [[FindBarFieldEditor alloc] init];
            _findBarFieldEditor.fieldEditor = YES;
        }
        return _findBarFieldEditor;
    }
    return nil;
}

- (instancetype)initWithConfiguration:(WKWebViewConfiguration *)configuration
{
    if (!(self = [super initWithWindowNibName:@"BrowserWindow"]))
        return nil;

    _configuration = [configuration copy];
    _isPrivateBrowsingWindow = !_configuration.websiteDataStore.isPersistent;

    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(userAgentDidChange:) name:kUserAgentChangedNotificationName object:nil];
    return self;
}

- (void)dealloc
{
    if (_warmTabMemoryPressureSource) {   // Driftstack warm-tabs: tear down the memory-pressure source
        dispatch_source_cancel(_warmTabMemoryPressureSource);
        _warmTabMemoryPressureSource = nil;
    }
    [[NSNotificationCenter defaultCenter] removeObserver:self];
    if (_findBarClickMonitor)
        [NSEvent removeMonitor:_findBarClickMonitor];
    if (_tapOverlayClickMonitor)
        [NSEvent removeMonitor:_tapOverlayClickMonitor];
    _webView._findDelegate = nil;
    _textFinder.client = nil;
    _textFinder.findBarContainer = nil;
    [_webView removeObserver:self forKeyPath:@"title"];
    [_webView removeObserver:self forKeyPath:@"URL"];
    [_webView removeObserver:self forKeyPath:@"hasOnlySecureContent"];
    [_webView removeObserver:self forKeyPath:@"_gpuProcessIdentifier"];

    [progressIndicator unbind:NSHiddenBinding];
    [progressIndicator unbind:NSValueBinding];
}

- (void)windowDidLoad
{
    [super windowDidLoad];

    // Private windows get separate identifier so they can't merge with regular windows
    if (_isPrivateBrowsingWindow)
        self.window.tabbingIdentifier = @"MiniBrowserPrivateWindow";
}

- (void)userAgentDidChange:(NSNotification *)notification
{
    SettingsController *settingsController = [[NSApplication sharedApplication] browserAppDelegate].settingsController;
    _webView.customUserAgent = settingsController.customUserAgent;
    [_webView reload];
}

- (IBAction)fetch:(id)sender
{
    [urlText setStringValue:[self addProtocolIfNecessary:urlText.stringValue]];
    NSURL *url = [NSURL _webkit_URLWithUserTypedString:urlText.stringValue];
    [_webView loadURL:url];
}

- (IBAction)setPageScale:(id)sender
{
    CGFloat scale = [self pageScaleForMenuItemTag:[sender tag]];
    [_webView _setPageScale:scale withOrigin:CGPointZero];
}

- (CGFloat)viewScaleForMenuItemTag:(NSInteger)tag
{
    if (tag == 1)
        return 1;
    if (tag == 2)
        return 0.75;
    if (tag == 3)
        return 0.5;
    if (tag == 4)
        return 0.25;

    return 1;
}

- (IBAction)togglePictureInPicture:(id)sender
{
    [_webView _togglePictureInPicture];
}

- (IBAction)toggleInWindowFullscreen:(id)sender
{
    [_webView _toggleInWindow];
}

// T-11 (Driftstack 2026-09-03): geolocation PERMISSION. WebKit asks the client here
// (UIDelegate.mm decidePolicyForGeolocationPermissionRequest) and, with no answer, DENIES —
// instantly, before the DRIFTSTACK_GEO_* position override in WebGeolocationManagerProxy.cpp
// ever runs. Measured on the box: getCurrentPosition -> PERMISSION_DENIED in 0 ms (that run
// was the no-override control; the render harness sets no GEO env). Grant iff the SAME inputs the
// position override needs are present — BOTH latitude and longitude — so the permission cannot be
// granted for a session the override will then fail to answer; otherwise leave WebKit's default
// untouched so an un-overridden session is byte-identical.
// ⚠️ This predicate is deliberately a SUBSET of the override's (WebGeolocationManagerProxy.cpp also
// requires each value to parse as a double). A superset here — the first version keyed on LAT alone —
// would grant permission and then deliver POSITION_UNAVAILABLE, a coherence tell no real device shows.
static BOOL driftstackGeoEnvPresent(const char *name, const char *xpcName)
{
    const char *v = getenv(name);
    if (!v || !v[0])
        v = getenv(xpcName);
    return v && v[0];
}

static BOOL driftstackHasSpoofedLocation(void)
{
    return driftstackGeoEnvPresent("DRIFTSTACK_GEO_LAT", "__XPC_DRIFTSTACK_GEO_LAT")
        && driftstackGeoEnvPresent("DRIFTSTACK_GEO_LON", "__XPC_DRIFTSTACK_GEO_LON");
}

- (void)_webView:(WKWebView *)webView requestGeolocationPermissionForOrigin:(WKSecurityOrigin *)origin initiatedByFrame:(WKFrameInfo *)frame decisionHandler:(void (^)(WKPermissionDecision decision))decisionHandler
{
    if (driftstackHasSpoofedLocation()) {
        decisionHandler(WKPermissionDecisionGrant);
        return;
    }
    // Deny, not Prompt. Before this delegate existed WebKit's path returned with the request
    // unanswered, which the caller treats as an instant deny (measured: PERMISSION_DENIED in 0 ms).
    // Prompt is NOT that default: UIDelegate.mm routes it to alertForPermission — a modal sheet —
    // and a headless session without a location then hangs on it (measured: the no-override
    // control render produced no capture in 60 s). Deny reproduces the pre-patch behaviour exactly.
    decisionHandler(WKPermissionDecisionDeny);
}

// Sibling SPI with the older shape; WebKit uses whichever the delegate responds to. Both are
// implemented so the answer does not depend on which selector this WebKit build prefers.
- (void)_webView:(WKWebView *)webView requestGeolocationPermissionForFrame:(WKFrameInfo *)frame decisionHandler:(void (^)(BOOL allowed))decisionHandler
{
    decisionHandler(driftstackHasSpoofedLocation());
}

// No _webView:queryPermission:forOrigin:completionHandler: on purpose. permissions.query() for
// geolocation is forced to "prompt" in the WebProcess (Permissions.cpp, §A row 13: a real iPhone
// page never sees it auto-granted, 27/27 captures), and after a granted request the Geolocation
// object reports "granted" on its own — measured here as before=prompt, after=granted, which is
// the real-device first-visit sequence. A grant answered from this delegate would be overridden
// there, so a hook here could only ever claim a behaviour it does not produce.

- (void)_webView:(WKWebView *)webView requestNotificationPermissionForSecurityOrigin:(WKSecurityOrigin *)securityOrigin decisionHandler:(void (^)(BOOL))decisionHandler
{
    NSDictionary *permissions = [[NSUserDefaults standardUserDefaults] dictionaryForKey:@"NotificationPermissions"];
    NSString *originString = [NSString stringWithFormat:@"%@://%@", securityOrigin.protocol, securityOrigin.host];
    id value = [permissions valueForKey:originString];
    if (value) {
        decisionHandler([(NSNumber *)value boolValue]);
        return;
    }

    NSAlert* alert = [[NSAlert alloc] init];

    [alert setMessageText:[NSString stringWithFormat:@"Allow notification permissions for %@?", originString]];
    [alert addButtonWithTitle:@"Deny"];
    [alert addButtonWithTitle:@"Allow"];

    [alert beginSheetModalForWindow:self.window completionHandler:^void (NSModalResponse response) {
        BOOL granted = response == NSAlertSecondButtonReturn;

        NSMutableDictionary *permissions = [[[NSUserDefaults standardUserDefaults] dictionaryForKey:@"NotificationPermissions"] mutableCopy];
        if (!permissions)
            permissions = [NSMutableDictionary dictionaryWithCapacity:1];
        [permissions setValue:@(granted) forKey:originString];
        [[NSUserDefaults standardUserDefaults] setObject:permissions forKey:@"NotificationPermissions"];

        decisionHandler(granted);
    }];
}

- (IBAction)setViewScale:(id)sender
{
    CGFloat scale = [self viewScaleForMenuItemTag:[sender tag]];
    CGFloat oldScale = [_webView _viewScale];

    if (scale == oldScale)
        return;

    [_webView _setLayoutMode:_WKLayoutModeDynamicSizeComputedFromViewScale];

    NSRect oldFrame = self.window.frame;
    NSSize newFrameSize = NSMakeSize(oldFrame.size.width * (scale / oldScale), oldFrame.size.height * (scale / oldScale));
    [self.window setFrame:NSMakeRect(oldFrame.origin.x, oldFrame.origin.y - (newFrameSize.height - oldFrame.size.height), newFrameSize.width, newFrameSize.height) display:NO animate:NO];

    [_webView _setViewScale:scale];
}

static BOOL areEssentiallyEqual(double a, double b)
{
    double tolerance = 0.001;
    return (fabs(a - b) <= tolerance);
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-implementations"
- (BOOL)validateMenuItem:(NSMenuItem *)menuItem
#pragma GCC diagnostic pop
{
    SEL action = menuItem.action;

    if (action == @selector(cloneSiteIsolatedWindow:))
        return YES;
    if (action == @selector(cloneNonIsolatedWindow:))
        return YES;
    if (action == @selector(saveAsPDF:))
        return YES;
    if (action == @selector(saveAsImage:))
        return YES;
    if (action == @selector(saveAsWebArchive:))
        return YES;
    if (action == @selector(saveAsCompleteWebPage:))
        return YES;

    if (action == @selector(zoomIn:))
        return [self canZoomIn];
    if (action == @selector(zoomOut:))
        return [self canZoomOut];
    if (action == @selector(resetZoom:))
        return [self canResetZoom];
    
    // Disabled until missing WK2 functionality is exposed via API/SPI.
    if (action == @selector(dumpSourceToConsole:)
        || action == @selector(forceRepaint:))
        return NO;
    
    if (action == @selector(showHideWebView:))
        [menuItem setTitle:[_webView isHidden] ? @"Show Web View" : @"Hide Web View"];
    else if (action == @selector(removeReinsertWebView:))
        [menuItem setTitle:[_webView window] ? @"Remove Web View" : @"Insert Web View"];
    else if (action == @selector(toggleFullWindowWebView:))
        [menuItem setTitle:[self webViewFillsWindow] ? @"Inset Web View" : @"Fit Web View to Window"];
    else if (action == @selector(toggleZoomMode:))
        [menuItem setState:_zoomTextOnly ? NSControlStateValueOn : NSControlStateValueOff];
    else if (action == @selector(toggleEditable:))
        [menuItem setState:self.isEditable ? NSControlStateValueOn : NSControlStateValueOff];
    else if (action == @selector(showHideWebInspector:))
        [menuItem setTitle:_webView._inspector.isVisible ? @"Close Web Inspector" : @"Show Web Inspector"];
    else if (action == @selector(toggleAlwaysShowsHorizontalScroller:))
        menuItem.state = _webView._alwaysShowsHorizontalScroller ? NSControlStateValueOn : NSControlStateValueOff;
    else if (action == @selector(toggleAlwaysShowsVerticalScroller:))
        menuItem.state = _webView._alwaysShowsVerticalScroller ? NSControlStateValueOn : NSControlStateValueOff;
    else if (action == @selector(toggleMainThreadStalls:))
        menuItem.state = self.mainThreadStallsEnabled ? NSControlStateValueOn : NSControlStateValueOff;

    [_webView _updateMediaPlaybackControlsManager];
    if (action == @selector(togglePictureInPicture:)) {
        menuItem.state = _webView._isPictureInPictureActive ? NSControlStateValueOn : NSControlStateValueOff;
        return _webView._canTogglePictureInPicture;
    }

    if (action == @selector(toggleInWindowFullscreen:)) {
        menuItem.state = _webView._isInWindowActive ? NSControlStateValueOn : NSControlStateValueOff;
        return _webView._canToggleInWindow;
    }

    if (action == @selector(setPageScale:))
        [menuItem setState:areEssentiallyEqual([_webView _pageScale], [self pageScaleForMenuItemTag:[menuItem tag]])];

    if (action == @selector(setViewScale:))
        [menuItem setState:areEssentiallyEqual([_webView _viewScale], [self viewScaleForMenuItemTag:[menuItem tag]])];

    return YES;
}

- (IBAction)reload:(id)sender
{
    [_webView reload];
}

- (IBAction)showCertificate:(id)sender
{
    if (_webView.serverTrust)
        [[SFCertificateTrustPanel sharedCertificateTrustPanel] beginSheetForWindow:self.window modalDelegate:nil didEndSelector:nil contextInfo:NULL trust:_webView.serverTrust message:@"TLS Certificate Details"];
}

- (IBAction)logAccessibilityTrees:(id)sender
{
    NSSavePanel *panel = [NSSavePanel savePanel];
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    panel.allowedFileTypes = @[ @"axtree" ];
#pragma clang diagnostic pop
    [panel beginSheetModalForWindow:self.window completionHandler:^(NSInteger result) {
        if (result == NSModalResponseOK) {
            [self->_webView _retrieveAccessibilityTreeData:^(NSData *data, NSError *error) {
                [data writeToURL:[panel URL] options:0 error:nil];
            }];
        }
    }];
}

- (IBAction)forceRepaint:(id)sender
{
    // FIXME: This doesn't actually force a repaint.
    [_webView setNeedsDisplay:YES];
}

- (IBAction)goBack:(id)sender
{
    [_webView goBack];
}

- (IBAction)goForward:(id)sender
{
    [_webView goForward];
}

- (IBAction)toggleZoomMode:(id)sender
{
    if (_zoomTextOnly) {
        _zoomTextOnly = NO;
        double currentTextZoom = _webView._textZoomFactor;
        _webView._textZoomFactor = 1;
        _webView.pageZoom = currentTextZoom;
    } else {
        _zoomTextOnly = YES;
        double currentPageZoom = _webView._pageZoomFactor;
        _webView._textZoomFactor = currentPageZoom;
        _webView.pageZoom = 1;
    }
}

- (IBAction)resetZoom:(id)sender
{
    if (![self canResetZoom])
        return;

    if (_zoomTextOnly)
        _webView._textZoomFactor = 1;
    else {
        _webView.pageZoom = 1;
        _webView.magnification = 1;
    }
}

- (BOOL)canResetZoom
{
    return _zoomTextOnly ? (_webView._textZoomFactor != 1) : (_webView.pageZoom != 1);
}

- (IBAction)toggleShrinkToFit:(id)sender
{
    _useShrinkToFit = !_useShrinkToFit;
    toggleUseShrinkToFitButton.image = _useShrinkToFit ? [NSImage imageNamed:@"NSExitFullScreenTemplate"] : [NSImage imageNamed:@"NSEnterFullScreenTemplate"];
    [_webView _setLayoutMode:_useShrinkToFit ? _WKLayoutModeDynamicSizeComputedFromMinimumDocumentSize : _WKLayoutModeViewSize];
}

- (IBAction)dumpSourceToConsole:(id)sender
{
}

- (IBAction)showHideWebInspector:(id)sender
{
    _WKInspector *inspector = _webView._inspector;
    if (inspector.isVisible)
        [inspector hide];
    else
        [inspector show];
}

- (IBAction)toggleAlwaysShowsHorizontalScroller:(id)sender
{
    _webView._alwaysShowsHorizontalScroller = !_webView._alwaysShowsHorizontalScroller;
}

- (IBAction)toggleAlwaysShowsVerticalScroller:(id)sender
{
    _webView._alwaysShowsVerticalScroller = !_webView._alwaysShowsVerticalScroller;
}

- (NSURL *)currentURL
{
    return _webView.URL;
}

- (NSView *)mainContentView
{
    return _webView;
}

- (void)setEditable:(BOOL)editable
{
    [super setEditable:editable];
    _webView._editable = editable;
}

- (BOOL)validateUserInterfaceItem:(id <NSValidatedUserInterfaceItem>)item
{
    SEL action = item.action;

    if (action == @selector(goBack:) || action == @selector(goForward:))
        return [_webView validateUserInterfaceItem:item];

    if (action == @selector(showCertificate:))
        return _webView.serverTrust != nil;

    return YES;
}

- (void)validateToolbar
{
    [toolbar validateVisibleItems];
}

- (BOOL)windowShouldClose:(id)sender
{
    return YES;
}

- (void)windowWillClose:(NSNotification *)notification
{
    [[[NSApplication sharedApplication] browserAppDelegate] browserWindowWillClose:self.window];
}

#define DefaultMinimumZoomFactor (.5)
#define DefaultMaximumZoomFactor (3.0)
#define DefaultZoomFactorRatio (1.2)

- (CGFloat)currentZoomFactor
{
    return _zoomTextOnly ? _webView._textZoomFactor : _webView.pageZoom;
}

- (void)setCurrentZoomFactor:(CGFloat)factor
{
    if (_zoomTextOnly)
        _webView._textZoomFactor = factor;
    else
        _webView.pageZoom = factor;
}

- (BOOL)canZoomIn
{
    return self.currentZoomFactor * DefaultZoomFactorRatio < DefaultMaximumZoomFactor;
}

- (void)zoomIn:(id)sender
{
    if (!self.canZoomIn)
        return;

    self.currentZoomFactor *= DefaultZoomFactorRatio;
}

- (BOOL)canZoomOut
{
    return self.currentZoomFactor / DefaultZoomFactorRatio > DefaultMinimumZoomFactor;
}

- (void)zoomOut:(id)sender
{
    if (!self.canZoomOut)
        return;

    self.currentZoomFactor /= DefaultZoomFactorRatio;
}

- (void)didChangeSettings
{
    SettingsController *settings = [[NSApplication sharedApplication] browserAppDelegate].settingsController;
    WKPreferences *preferences = _webView.configuration.preferences;

    _webView._useSystemAppearance = settings.useSystemAppearance;

    preferences._tiledScrollingIndicatorVisible = settings.tiledScrollingIndicatorVisible;
    preferences._compositingBordersVisible = settings.layerBordersVisible;
    preferences._compositingRepaintCountersVisible = settings.layerBordersVisible;
    preferences._legacyLineLayoutVisualCoverageEnabled = settings.legacyLineLayoutVisualCoverageEnabled;
    preferences._acceleratedDrawingEnabled = settings.acceleratedDrawingEnabled;
    preferences._resourceUsageOverlayVisible = settings.resourceUsageOverlayVisible;
    preferences._largeImageAsyncDecodingEnabled = settings.largeImageAsyncDecodingEnabled;
    preferences._animatedImageAsyncDecodingEnabled = settings.animatedImageAsyncDecodingEnabled;
    preferences._colorFilterEnabled = settings.appleColorFilterEnabled;
    preferences.siteSpecificQuirksModeEnabled = settings.siteSpecificQuirksModeEnabled;
    preferences._punchOutWhiteBackgroundsInDarkMode = settings.punchOutWhiteBackgroundsInDarkMode;
    preferences._mockCaptureDevicesEnabled = settings.useMockCaptureDevices;
    preferences.tabFocusesLinks = settings.tabFocusesLinksEnabled;

    preferences._serviceControlsEnabled = settings.dataDetectorsEnabled;
    preferences._telephoneNumberDetectionIsEnabled = settings.dataDetectorsEnabled;

    // Wave 29-499.326 — guard a header-declared-but-unimplemented SPI. In this
    // fork build WKWebpagePreferences.securityRestrictionMode (macOS 26.4) is
    // declared in the headers MiniBrowser compiles against but its setter is not
    // implemented in WKWebpagePreferences.mm. Calling it threw
    // "-[WKWebpagePreferences setSecurityRestrictionMode:]: unrecognized selector"
    // inside awakeFromNib; AppKit swallowed the exception, so the browser window
    // was never created — the app launched with no window and no crash/error.
    // respondsToSelector keeps window creation alive and reports the missing SPI
    // loudly instead of failing silently.
    WKWebpagePreferences *defaultWebpagePreferences = _webView.configuration.defaultWebpagePreferences;
    if ([defaultWebpagePreferences respondsToSelector:@selector(setSecurityRestrictionMode:)])
        defaultWebpagePreferences.securityRestrictionMode = settings.enhancedSecurityEnabled ? WKSecurityRestrictionModeMaximizeCompatibility : WKSecurityRestrictionModeNone;
    else
        NSLog(@"[Driftstack/MiniBrowser] WKWebpagePreferences has no -setSecurityRestrictionMode: in this WebKit build; skipping the enhancedSecurity setting so the window still opens. Implement it in WKWebpagePreferences.mm to restore the setting.");
    _webView.configuration.websiteDataStore._resourceLoadStatisticsEnabled = settings.resourceLoadStatisticsEnabled;

    [self setWebViewFillsWindow:settings.webViewFillsWindow];

    BOOL useTransparentWindows = settings.useTransparentWindows;
    if (useTransparentWindows != !_webView._drawsBackground) {
        [self.window setOpaque:!useTransparentWindows];
        [self.window setBackgroundColor:[NSColor clearColor]];
        [self.window setHasShadow:!useTransparentWindows];

        _webView._drawsBackground = !useTransparentWindows;

        [self.window display];
    }

    BOOL usePaginatedMode = settings.usePaginatedMode;
    if (usePaginatedMode != (_webView._paginationMode != _WKPaginationModeUnpaginated)) {
        if (usePaginatedMode) {
            _webView._paginationMode = _WKPaginationModeLeftToRight;
            _webView._pageLength = _webView.bounds.size.width / 2;
            _webView._gapBetweenPages = 10;
        } else
            _webView._paginationMode = _WKPaginationModeUnpaginated;
    }
    
    NSUInteger visibleOverlayRegions = 0;
    if (settings.nonFastScrollableRegionOverlayVisible)
        visibleOverlayRegions |= _WKNonFastScrollableRegion;
    if (settings.wheelEventHandlerRegionOverlayVisible)
        visibleOverlayRegions |= _WKWheelEventHandlerRegion;
    if (settings.interactionRegionOverlayVisible)
        visibleOverlayRegions |= _WKInteractionRegion;
    if (settings.enhancedSecurityOverlayVisible)
        visibleOverlayRegions |= _WKEnhancedSecurityRegion;

    preferences._visibleDebugOverlayRegions = visibleOverlayRegions;

    int headerBannerHeight = [settings isSpaceReservedForBanners] ? testHeaderBannerHeight : 0;
    if (!headerBannerHeight)
        [_webView _setHeaderBannerLayer:nil];
    else {
        CALayer *headerBannerLayer = [[CALayer alloc] init];
        [headerBannerLayer setBounds:CGRectMake(0, 0, 0, headerBannerHeight)];
        [headerBannerLayer setAnchorPoint:CGPointZero];
        [headerBannerLayer setBackgroundColor:[NSColor colorWithSRGBRed:172. / 255. green:221 / 255. blue:222. / 255. alpha:1].CGColor];
        [_webView _setHeaderBannerLayer:headerBannerLayer];
    }

    int footerBannerHeight = [settings isSpaceReservedForBanners] ? testFooterBannerHeight : 0;
    if (!footerBannerHeight)
        [_webView _setFooterBannerLayer:nil];
    else {
        CALayer *footerBannerLayer = [[CALayer alloc] init];
        [footerBannerLayer setBounds:CGRectMake(0, 0, 0, footerBannerHeight)];
        [footerBannerLayer setAnchorPoint:CGPointZero];
        [footerBannerLayer setBackgroundColor:[NSColor colorWithSRGBRed:116. / 255. green:187. / 255. blue:251. / 255. alpha:1].CGColor];
        [_webView _setFooterBannerLayer:footerBannerLayer];
    }

    [self updateTitle:_webView.title];
}

- (void)updateTitleForBadgeChange
{
    [self updateTitle:_webView.title];
}

- (void)updateTitle:(NSString *)title
{
    if (!title.length) {
        NSURL *url = _webView.URL;
        title = url.lastPathComponent ?: url._web_userVisibleString;
    }

    if (!title.length)
        title = @"MiniBrowser";

    if (BrowserAppDelegate.currentBadge)
        title = [title stringByAppendingFormat:@" (%@)", BrowserAppDelegate.currentBadge];

    SettingsController *settings = [[NSApp browserAppDelegate] settingsController];
    pid_t webPID = _webView._webProcessIdentifier;
    if (settings.showWebProcessIdentifierInTitle && webPID)
        title = [title stringByAppendingFormat:@" [%d]", webPID];

    self.window.title = title;

    NSMutableString *subtitle = [@"[WK2" mutableCopy];
    __auto_type appendProcessIdentifier = ^(NSString *name, pid_t processIdentifier) {
        if (!processIdentifier)
            return;
        [subtitle appendFormat:@" %@:%d", name, processIdentifier];
    };

    appendProcessIdentifier(@"web", _webView._webProcessIdentifier);
    appendProcessIdentifier(@"net", _webView.configuration.websiteDataStore._networkProcessIdentifier);
    appendProcessIdentifier(@"gpu", _webView._gpuProcessIdentifier);

    [subtitle appendString:@"]"];

    if (_isPrivateBrowsingWindow)
        [subtitle appendString:@" 🙈"];

    if (_webView._editable)
        [subtitle appendString:@" ✏️"];

    if (_webView.configuration.preferences._siteIsolationEnabled)
        [subtitle appendString:@" (Site Isolated)"];

    self.window.subtitle = subtitle;
}

- (void)observeValueForKeyPath:(NSString *)keyPath ofObject:(id)object change:(NSDictionary *)change context:(void *)context
{
    if (context != keyValueObservingContext || object != _webView)
        return;

    if ([keyPath isEqualToString:@"title"])
        [self updateTitle:_webView.title];
    else if ([keyPath isEqualToString:@"URL"])
        [self updateTextFieldFromURL:_webView.URL];
    else if ([keyPath isEqualToString:@"hasOnlySecureContent"])
        [self updateLockButtonIcon:_webView.hasOnlySecureContent];
    else if ([keyPath isEqualToString:@"_gpuProcessIdentifier"])
        [self updateTitle:_webView.title];
}

- (nullable WKWebView *)webView:(WKWebView *)webView createWebViewWithConfiguration:(WKWebViewConfiguration *)configuration forNavigationAction:(WKNavigationAction *)navigationAction windowFeatures:(WKWindowFeatures *)windowFeatures
{
    WK2BrowserWindowController *controller = [[WK2BrowserWindowController alloc] initWithConfiguration:configuration];
    [controller.window makeKeyAndOrderFront:self];
    
    [[[NSApplication sharedApplication] browserAppDelegate] didCreateBrowserWindowController:controller];

    return controller->_webView;
}

- (void)webView:(WKWebView *)webView runJavaScriptAlertPanelWithMessage:(NSString *)message initiatedByFrame:(WKFrameInfo *)frame completionHandler:(void (^)(void))completionHandler
{
    NSAlert* alert = [[NSAlert alloc] init];

    [alert setMessageText:[NSString stringWithFormat:@"JavaScript alert dialog from %@.", [frame.request.URL absoluteString]]];
    [alert setInformativeText:message];
    [alert addButtonWithTitle:@"OK"];

    [alert beginSheetModalForWindow:self.window completionHandler:^void (NSModalResponse response) {
        completionHandler();
    }];
}

- (void)webView:(WKWebView *)webView runJavaScriptConfirmPanelWithMessage:(NSString *)message initiatedByFrame:(WKFrameInfo *)frame completionHandler:(void (^)(BOOL result))completionHandler
{
    NSAlert* alert = [[NSAlert alloc] init];

    [alert setMessageText:[NSString stringWithFormat:@"JavaScript confirm dialog from %@.", [frame.request.URL  absoluteString]]];
    [alert setInformativeText:message];
    
    [alert addButtonWithTitle:@"OK"];
    [alert addButtonWithTitle:@"Cancel"];

    [alert beginSheetModalForWindow:self.window completionHandler:^void (NSModalResponse response) {
        completionHandler(response == NSAlertFirstButtonReturn);
    }];
}

- (void)webView:(WKWebView *)webView runJavaScriptTextInputPanelWithPrompt:(NSString *)prompt defaultText:(NSString *)defaultText initiatedByFrame:(WKFrameInfo *)frame completionHandler:(void (^)(NSString *result))completionHandler
{
    NSAlert* alert = [[NSAlert alloc] init];

    [alert setMessageText:[NSString stringWithFormat:@"JavaScript prompt dialog from %@.", [frame.request.URL absoluteString]]];
    [alert setInformativeText:prompt];
    
    [alert addButtonWithTitle:@"OK"];
    [alert addButtonWithTitle:@"Cancel"];
    
    NSTextField* input = [[NSTextField alloc] initWithFrame:NSMakeRect(0, 0, 200, 24)];
    [input setStringValue:defaultText];
    [alert setAccessoryView:input];
    
    [alert beginSheetModalForWindow:self.window completionHandler:^void (NSModalResponse response) {
        [input validateEditing];
        completionHandler(response == NSAlertFirstButtonReturn ? [input stringValue] : nil);
    }];
}

- (void)webView:(WKWebView *)webView runOpenPanelWithParameters:(WKOpenPanelParameters *)parameters initiatedByFrame:(WKFrameInfo *)frame completionHandler:(void (^)(NSArray<NSURL *> * URLs))completionHandler
{
#if PLATFORM(DRIFTSTACK)
    // LAUNCH-SECURITY (isolation audit wi8z2sdot / planning 146, founder file-control; W2849/W2850): a customer
    // session's <input type=file> must NEVER browse the SHARED Mac worker's /Users. Instead of an NSOpenPanel
    // rooted at the worker filesystem (or the arbitrary-path DRIFTSTACK_AUTO_FILE_PICK — both gone from prod),
    // answer the chooser with files from the per-session 0o700 upload JAIL (DRIFTSTACK_UPLOAD_DIR) — the customer
    // pushed them there via the file-control API. Each path is realpath-canonicalized + prefix-checked against the
    // canonical jail so a symlink/.. inside the jail can't escape it. No jail / no files → iPhone-faithful "user
    // cancelled" (nil). Precise per-file selection is the WD upload-drive (handle.id→jailed path); this chooser
    // funnel is the jail-confined fallback for pages that open the picker directly.
    NSMutableArray<NSURL *> *jailURLs = [NSMutableArray array];
    const char* jailEnv = getenv("DRIFTSTACK_UPLOAD_DIR");
    if (jailEnv && jailEnv[0]) {
        char jailReal[PATH_MAX];
        if (realpath(jailEnv, jailReal)) {
            NSString *jailPrefix = [[NSString stringWithUTF8String:jailReal] stringByAppendingString:@"/"];
            NSDirectoryEnumerator<NSURL *> *en = [[NSFileManager defaultManager]
                enumeratorAtURL:[NSURL fileURLWithPath:[NSString stringWithUTF8String:jailReal]]
                includingPropertiesForKeys:@[NSURLIsRegularFileKey, NSURLContentModificationDateKey]
                options:0 errorHandler:nil];
            for (NSURL *url in en) {
                NSNumber *isRegular = nil;
                if (![url getResourceValue:&isRegular forKey:NSURLIsRegularFileKey error:nil] || !isRegular.boolValue)
                    continue;
                char fileReal[PATH_MAX];
                if (!realpath(url.path.fileSystemRepresentation, fileReal))
                    continue;
                NSString *fileCanon = [NSString stringWithUTF8String:fileReal];
                if (![fileCanon hasPrefix:jailPrefix])
                    continue;   // realpath landed outside the jail (symlink/.. escape) — refuse
                [jailURLs addObject:[NSURL fileURLWithPath:fileCanon]];
            }
            // most-recent upload first → deterministic choice for a single-file <input>
            [jailURLs sortUsingComparator:^NSComparisonResult(NSURL *a, NSURL *b) {
                NSDate *da = nil, *db = nil;
                [a getResourceValue:&da forKey:NSURLContentModificationDateKey error:nil];
                [b getResourceValue:&db forKey:NSURLContentModificationDateKey error:nil];
                return [db compare:da];
            }];
        }
    }
    if (!parameters.allowsMultipleSelection && jailURLs.count > 1)
        jailURLs = [NSMutableArray arrayWithObject:jailURLs[0]];
    completionHandler(jailURLs.count ? jailURLs : nil);
    return;
#else
    // Wave 29-499.348 — headless file-pick for the PathB v2 upload functional
    // test. DRIFTSTACK_AUTO_FILE_PICK=<path> answers any <input type=file>
    // open-panel with that file, no dialog — lets the automated harness drive a
    // real disk-backed multipart upload through the network stack.
    const char* autoPick = getenv("DRIFTSTACK_AUTO_FILE_PICK");
    if (autoPick && autoPick[0]) {
        NSString *path = [NSString stringWithUTF8String:autoPick];
        if ([[NSFileManager defaultManager] fileExistsAtPath:path]) {
            completionHandler(@[[NSURL fileURLWithPath:path]]);
            return;
        }
        completionHandler(nil);
        return;
    }

    NSOpenPanel *openPanel = [NSOpenPanel openPanel];

    openPanel.allowsMultipleSelection = parameters.allowsMultipleSelection;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    [openPanel setAllowedFileTypes:parameters._allowedFileExtensions];
#pragma clang diagnostic pop

    [openPanel beginSheetModalForWindow:webView.window completionHandler:^(NSInteger result) {
        if (result == NSModalResponseOK)
            completionHandler(openPanel.URLs);
        else
            completionHandler(nil);
    }];
#endif
}

- (void)_webView:(WebView *)sender runBeforeUnloadConfirmPanelWithMessage:(NSString *)message initiatedByFrame:(WKFrameInfo *)frame completionHandler:(void (^)(BOOL result))completionHandler
{
    NSAlert *alert = [[NSAlert alloc] init];

    alert.messageText = [NSString stringWithFormat:@"JavaScript before unload dialog from %@.", [frame.request.URL absoluteString]];
    alert.informativeText = message;

    [alert addButtonWithTitle:@"Leave Page"];
    [alert addButtonWithTitle:@"Stay On Page"];

    [alert beginSheetModalForWindow:self.window completionHandler:^void (NSModalResponse response) {
        completionHandler(response == NSAlertFirstButtonReturn);
    }];
}

- (WKDragDestinationAction)_webView:(WKWebView *)webView dragDestinationActionMaskForDraggingInfo:(id)draggingInfo
{
    return WKDragDestinationActionAny;
}

- (void)_webView:(WKWebView *)webView printFrame:(_WKFrameHandle *)frame pdfFirstPageSize:(CGSize)size completionHandler:(void (^)(void))completionHandler
{
    [[_webView printOperationWithPrintInfo:[NSPrintInfo sharedPrintInfo]] runOperationModalForWindow:self.window delegate:nil didRunSelector:nil contextInfo:nil];
    completionHandler();
}

// W2076: is the iOS-26 Safari chrome active? (value-check, matches BrowserWindowController.m:86-92 —
// a non-empty value that isn't "0"/"false"/"no"/"off"). Used to switch the address bar between the
// iOS collapsed-domain look (chrome on) and the full dev URL (chrome off).
static BOOL driftSafariChromeEnabled(void)
{
    const char *raw = getenv("DRIFTSTACK_SAFARI_CHROME");
    if (!raw)
        return NO;
    NSString *v = [[NSString stringWithUTF8String:raw] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]].lowercaseString;
    return v.length > 0 && ![v isEqualToString:@"0"] && ![v isEqualToString:@"false"] && ![v isEqualToString:@"no"] && ![v isEqualToString:@"off"];
}

- (void)updateTextFieldFromURL:(NSURL *)URL
{
    if (!URL)
        return;

    if (!URL.absoluteString.length)
        return;

    // W2076 (founder "more modern / more iOS"): in the iOS-26 chrome the collapsed address bar shows the
    // DOMAIN (host minus a leading "www."), like iOS-26 Safari — not the full scheme://host/path. The full
    // URL returns on tap-to-edit (controlTextDidBeginEditing). Chrome-only, and the page CANNOT read the
    // address bar → fp-NEUTRAL. The bare/dev MiniBrowser (chrome off) keeps the full user-visible URL.
    NSString *host = URL.host;
    if (driftSafariChromeEnabled() && host.length) {
        if ([host hasPrefix:@"www."])
            host = [host substringFromIndex:4];
        urlText.stringValue = host;
    } else
        urlText.stringValue = [URL _web_userVisibleString];
}

// W2076: while the user is editing the address bar, show the FULL URL so they can see/edit the whole
// address (iOS-26 expands the collapsed domain to the full URL on tap); restore the collapsed domain
// when editing ends. Gated on the chrome — the dev/bare browser already shows the full URL.
- (void)controlTextDidBeginEditing:(NSNotification *)notification
{
    if (notification.object == urlText && driftSafariChromeEnabled()) {
        NSURL *u = self.currentURL;
        if (u.absoluteString.length)
            urlText.stringValue = [u _web_userVisibleString];
    }
}

- (void)controlTextDidEndEditing:(NSNotification *)notification
{
    if (notification.object == urlText)
        [self updateTextFieldFromURL:self.currentURL];
}

- (void)updateLockButtonIcon:(BOOL)hasOnlySecureContent
{
    if (hasOnlySecureContent)
        [lockButton setImage:[NSImage imageWithSystemSymbolName:@"lock" accessibilityDescription:nil]];
    else
        [lockButton setImage:[NSImage imageWithSystemSymbolName:@"lock.open" accessibilityDescription:nil]];
}

- (void)loadURLString:(NSString *)urlString
{
    // FIXME: We shouldn't have to set the url text here.
    [urlText setStringValue:urlString];
    [self fetch:nil];
}

- (void)loadHTMLString:(NSString *)HTMLString
{
    [_webView loadHTMLString:HTMLString baseURL:nil];
}

static NSSet *dataTypes(void)
{
    return [WKWebsiteDataStore allWebsiteDataTypes];
}

- (IBAction)fetchWebsiteData:(id)sender
{
    [_configuration.websiteDataStore _fetchDataRecordsOfTypes:dataTypes() withOptions:_WKWebsiteDataStoreFetchOptionComputeSizes completionHandler:^(NSArray *websiteDataRecords) {
        NSLog(@"did fetch website data %@.", websiteDataRecords);
    }];
}

- (IBAction)fetchAndClearWebsiteData:(id)sender
{
    [_configuration.websiteDataStore fetchDataRecordsOfTypes:dataTypes() completionHandler:^(NSArray *websiteDataRecords) {
        [self->_configuration.websiteDataStore removeDataOfTypes:dataTypes() forDataRecords:websiteDataRecords completionHandler:^{
            [self->_configuration.websiteDataStore fetchDataRecordsOfTypes:dataTypes() completionHandler:^(NSArray *websiteDataRecords) {
                NSLog(@"did clear website data, after clearing data is %@.", websiteDataRecords);
            }];
        }];
    }];
}

- (IBAction)clearWebsiteData:(id)sender
{
    [_configuration.websiteDataStore removeDataOfTypes:dataTypes() modifiedSince:[NSDate distantPast] completionHandler:^{
        NSLog(@"Did clear website data.");
    }];
}

- (IBAction)printWebView:(id)sender
{
    [[_webView printOperationWithPrintInfo:[NSPrintInfo sharedPrintInfo]] runOperationModalForWindow:self.window delegate:nil didRunSelector:nil contextInfo:nil];
}

// __attribute__((unused)): under PLATFORM(DRIFTSTACK) the sole caller (the NSWorkspace openURL branch in
// decidePolicyForNavigationAction) is gated out by launch-security guard #1, leaving this static unused.
static BOOL isJavaScriptURL(NSURL *url) __attribute__((unused));
static BOOL isJavaScriptURL(NSURL *url)
{
    return [url.scheme isEqualToString:@"javascript"];
}

#pragma mark WKNavigationDelegate

- (void)webView:(WKWebView *)webView decidePolicyForNavigationAction:(WKNavigationAction *)navigationAction preferences:(WKWebpagePreferences *)preferences decisionHandler:(void (^)(WKNavigationActionPolicy, WKWebpagePreferences *))decisionHandler
{
    LOG(@"decidePolicyForNavigationAction");

    preferences._networkConnectionIntegrityPolicy = ^{
        if (!NSApplication.sharedApplication.browserAppDelegate.settingsController.advancedPrivacyProtectionsEnabled)
            return _WKWebsiteNetworkConnectionIntegrityPolicyNone;

        return _WKWebsiteNetworkConnectionIntegrityPolicyEnabled
            | _WKWebsiteNetworkConnectionIntegrityPolicyEnhancedTelemetry
            | _WKWebsiteNetworkConnectionIntegrityPolicyRequestValidation
            | _WKWebsiteNetworkConnectionIntegrityPolicySanitizeLookalikeCharacters;
    }();

    preferences.allowsContentJavaScript = NSApplication.sharedApplication.browserAppDelegate.settingsController.allowsContentJavascript;

    if (navigationAction._canHandleRequest) {
        decisionHandler(WKNavigationActionPolicyAllow, preferences);
        return;
    }

    NSURL *url = navigationAction.request.URL;
    
#if PLATFORM(DRIFTSTACK)
    // LAUNCH-SECURITY guard #1 (A3 #50, founder's exact ask): a customer session must NEVER launch a
    // Mac app on the SHARED WORKER. The upstream branch hands any non-WebKit-handleable scheme
    // (mailto:/facetime:///messages:///instagram:///fb:///itms-apps:///maps:// …) to NSWorkspace openURL →
    // which LAUNCHES the worker's Mail/Messages/FaceTime/App Store/etc., binding a third-party scheme to
    // the worker's real accounts. On a real iPhone an unhandleable scheme with no installed app is a SILENT
    // no-op — the navigation simply cancels. So: cancel, never openURL.
    (void)url;
#else
    if (!isJavaScriptURL(url) && navigationAction._userInitiatedAction && !navigationAction._userInitiatedAction.isConsumed) {
        [navigationAction._userInitiatedAction consume];
        [[NSWorkspace sharedWorkspace] openURL:url];
    }
#endif

    decisionHandler(WKNavigationActionPolicyCancel, preferences);
    [self validateToolbar];
}

- (void)webView:(WKWebView *)webView decidePolicyForNavigationResponse:(WKNavigationResponse *)navigationResponse decisionHandler:(void (^)(WKNavigationResponsePolicy))decisionHandler
{
    LOG(@"decidePolicyForNavigationResponse");
    decisionHandler(WKNavigationResponsePolicyAllow);
    [self validateToolbar];
}

- (void)webView:(WKWebView *)webView didStartProvisionalNavigation:(WKNavigation *)navigation
{
    LOG(@"didStartProvisionalNavigation: %@", navigation);
#if PLATFORM(DRIFTSTACK)
    // W2857 (founder 2026-06-24, page-load STALL reporting): a navigation that never COMMITS (the request
    // hangs — no response + no error: a blocked site, an unreachable/half-open proxy, an h3/QUIC stall)
    // otherwise shows an endless blank spinner ("loading then nothing"). Arm a watchdog; if no didCommit /
    // didFinish / didFailProvisional fires within the window, surface a timeout error page (W2649) so the
    // stall is VISIBLE in the stream + stop the hung load. Disarmed the moment the load commits/finishes/fails.
    driftstackDisarmNavWatchdog(webView);
    double watchdogSecs = 45.0;
    const char *watchdogEnv = getenv("DRIFTSTACK_NAV_WATCHDOG_SEC");
    if (watchdogEnv && watchdogEnv[0]) { double v = atof(watchdogEnv); if (v > 0) watchdogSecs = v; }
    __weak WK2BrowserWindowController *weakSelf = self;
    __weak WKWebView *weakWebView = webView;
    NSTimer *watchdog = [NSTimer scheduledTimerWithTimeInterval:watchdogSecs repeats:NO block:^(NSTimer *timer) {
        WK2BrowserWindowController *strongSelf = weakSelf;
        WKWebView *strongWebView = weakWebView;
        if (!strongSelf || !strongWebView || !strongWebView.loading)
            return;   // the tab that armed this watchdog is gone, or already stopped loading — never touch _webView
        objc_setAssociatedObject(strongWebView, &kDriftstackNavWatchdogKey, nil, OBJC_ASSOCIATION_RETAIN);
        NSError *timeoutError = [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorTimedOut userInfo:@{
            NSLocalizedDescriptionKey: [NSString stringWithFormat:@"The page took too long to respond (no response within %.0f seconds). It may be blocked, or the proxy / network is unreachable.", watchdogSecs] }];
        [strongWebView stopLoading];
        driftstackShowLoadFailurePage(strongWebView, timeoutError);
    }];
    objc_setAssociatedObject(webView, &kDriftstackNavWatchdogKey, watchdog, OBJC_ASSOCIATION_RETAIN);
#endif
    [self validateToolbar];
}

- (void)webView:(WKWebView *)webView didReceiveServerRedirectForProvisionalNavigation:(WKNavigation *)navigation
{
    LOG(@"didReceiveServerRedirectForProvisionalNavigation: %@", navigation);
}

- (void)webView:(WKWebView *)webView didFailProvisionalNavigation:(WKNavigation *)navigation withError:(NSError *)error
{
    LOG(@"didFailProvisionalNavigation: %@navigation, error: %@", navigation, error);
#if PLATFORM(DRIFTSTACK)
    driftstackDisarmNavWatchdog(webView);  // W2857: real failure fired — disarm this tab's stall watchdog (W2649 handles it)
#endif
    // Driftstack (W2649): show an on-screen error page so a failed customer load is VISIBLE in the
    // stream (not a blank white page). Skips the -999/cancelled supersede inside the helper.
    driftstackShowLoadFailurePage(webView, error);
}

- (void)webView:(WKWebView *)webView didCommitNavigation:(WKNavigation *)navigation
{
    LOG(@"didCommitNavigation: %@", navigation);
#if PLATFORM(DRIFTSTACK)
    driftstackDisarmNavWatchdog(webView);  // W2857: response committed (page rendering) — disarm this tab's stall watchdog
#endif
    [self updateTitle:nil];
}

- (void)webView:(WKWebView *)webView didFinishNavigation:(WKNavigation *)navigation
{
    LOG(@"didFinishNavigation: %@", navigation);
#if PLATFORM(DRIFTSTACK)
    driftstackDisarmNavWatchdog(webView);  // W2857: load finished — disarm this tab's stall watchdog
#endif
    // Dev-only network-fingerprint capture: DRIFTSTACK_DUMP_BODY_TEXT=<file> → after load,
    // write document.body.innerText to <file>. Used to extract the rendered JSON of a top-level
    // navigation to tls.peet.ws/api/all (CORS-clean since it is a navigation, not a cross-origin
    // fetch) so the fork's live on-the-wire JA3/JA4 + raw HTTP/2 frames can be diffed vs real iOS.
    {
        const char* _dumpPath = getenv("DRIFTSTACK_DUMP_BODY_TEXT");
        if (_dumpPath && _dumpPath[0]) {
            NSString *_dp = [NSString stringWithUTF8String:_dumpPath];
            [webView evaluateJavaScript:@"(document.body?document.body.innerText:'')"
                      completionHandler:^(id result, NSError *error) {
                NSString *_txt = [result isKindOfClass:[NSString class]] ? (NSString*)result : @"";
                [_txt writeToFile:_dp atomically:YES encoding:NSUTF8StringEncoding error:nil];
            }];
        }
    }
    // Fork-test: DRIFTSTACK_AUTOTAP=1 → after load, tap the probe's tapZone center (read live from the
    // page via window.__dsTapZoneCenter, robust to layout) so it fires a native touchstart into A3's oracle.
    // No #if ENABLE(): MiniBrowser is a framework client (ENABLE is undefined here); the runtime env guard
    // + the SPI being a no-op-without-impl on non-DRIFTSTACK builds suffices.
    // ⛔ A BARE getenv() PRESENCE CHECK MEANS `=0` TURNS THE FLAG ON (A1 2026-09-04). This read
    // `if (getenv("DRIFTSTACK_AUTOTAP"))`, so DRIFTSTACK_AUTOTAP=0 — the spelling anyone would reach for
    // to disable it — ENABLED the auto-tap, which then injects a named `window.__dsNT` global into the
    // page's main world. A default-off flag that is not actually off is the same shape this file already
    // fixed for DRIFTSTACK_IOS_CURSOR a few hundred lines up, whose comment states the rule outright:
    // a FALSY value ("0"/"false"/"no"/"off") must DISABLE the feature, not enable it. Same semantics here,
    // deliberately copied rather than re-invented so the two gates cannot drift apart.
    const char* autoTapRaw = getenv("DRIFTSTACK_AUTOTAP");
    NSString *autoTapVal = autoTapRaw
        ? [[NSString stringWithUTF8String:autoTapRaw] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]].lowercaseString
        : nil;
    BOOL autoTapOn = autoTapVal.length > 0
        && ![autoTapVal isEqualToString:@"0"] && ![autoTapVal isEqualToString:@"false"]
        && ![autoTapVal isEqualToString:@"no"] && ![autoTapVal isEqualToString:@"off"];
    if (autoTapOn) {
        // The iPhone viewport override (innerWidth -> ~402) applies late after didFinishNavigation, so
        // reading __dsTapZoneCenter too early gets the transient window-width layout and the tap misses the
        // reflowed tapZone. Poll innerWidth until it is stable across 2 reads (settled), then read center + tap.
        __block int _attempts = 0;
        __block double _lastW = -1.0;
        __block void (^_pollTap)(void) = nil;
        // Recursive self-referencing block (re-dispatches until settled); leaks once per page load, dev-only tool.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-retain-cycles"
        _pollTap = ^{
            [webView evaluateJavaScript:@"(function(){var c=window.__dsTapZoneCenter;return [window.innerWidth, c?c.x:0, c?c.y:0];})()"
                      completionHandler:^(id result, NSError *error) {
                _attempts++;
                if (![result isKindOfClass:[NSArray class]] || [result count] < 3)
                    return;
                double w = [result[0] doubleValue], cx = [result[1] doubleValue], cy = [result[2] doubleValue];
                BOOL settled = (w == _lastW && w > 0);
                _lastW = w;
                if (settled || _attempts >= 15) {
                    // The native touch point is in WINDOW coordinates but cx/cy are web-content coordinates;
                    // the window chrome (title bar/toolbar) adds a Y offset, so a content-space tap lands too
                    // high and misses the tapZone. Calibrate empirically: a capture-phase document recorder
                    // catches the calibration tap's landed clientY, offset = cy - landedY, then re-tap corrected.
                    [webView evaluateJavaScript:@"(function(){window.__dsNT=null;document.addEventListener('touchstart',function(e){var t=(e.touches&&e.touches[0])||(e.changedTouches&&e.changedTouches[0])||{};window.__dsNT={y:t.clientY};},true);return 0;})()"
                              completionHandler:^(id ir, NSError *ie){
                        [webView _dsSimulateTouchDownUpAtPoint:CGPointMake(cx, cy)];
                        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.3 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                            [webView evaluateJavaScript:@"window.__dsNT" completionHandler:^(id cal, NSError *ce){
                                double landedY = [cal isKindOfClass:[NSDictionary class]] ? [cal[@"y"] doubleValue] : cy;
                                double cyCorr = cy + (cy - landedY);   // add the measured window-chrome Y offset
                                [webView _dsSimulateTouchDownUpAtPoint:CGPointMake(cx, cyCorr)];
                            }];
                        });
                    }];
                } else {
                    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.3 * NSEC_PER_SEC)), dispatch_get_main_queue(), _pollTap);
                }
            }];
        };
#pragma clang diagnostic pop
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.3 * NSEC_PER_SEC)), dispatch_get_main_queue(), _pollTap);
    }
}

- (void)webView:(WKWebView *)webView didReceiveAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition disposition, NSURLCredential *__nullable credential))completionHandler
{
    LOG(@"didReceiveAuthenticationChallenge: %@", challenge);
    // Driftstack fork: accept self-signed certs for localhost so the
    // cumulative-rig HTTPS variant works without requiring system
    // keychain trust setup. Limited to localhost so ordinary browsing
    // still validates real certificates correctly.
    if ([challenge.protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust]) {
        NSString* host = challenge.protectionSpace.host;
        if ([host isEqualToString:@"localhost"] || [host isEqualToString:@"127.0.0.1"] || [host isEqualToString:@"::1"]) {
            NSURLCredential* cred = [NSURLCredential credentialForTrust:challenge.protectionSpace.serverTrust];
            completionHandler(NSURLSessionAuthChallengeUseCredential, cred);
            return;
        }
    }
    if ([challenge.protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodHTTPBasic]) {
        NSAlert *alert = [[NSAlert alloc] init];
        NSView *container = [[NSView alloc] initWithFrame:NSMakeRect(0, 0, 200, 48)];
        NSTextField *userInput = [[NSTextField alloc] initWithFrame:NSMakeRect(0, 24, 200, 24)];
        NSTextField *passwordInput = [[NSSecureTextField alloc] initWithFrame:NSMakeRect(0, 0, 200, 24)];
        
        [alert setMessageText:[NSString stringWithFormat:@"Log in to %@:%lu.", challenge.protectionSpace.host, challenge.protectionSpace.port]];
        [alert addButtonWithTitle:@"Log in"];
        [alert addButtonWithTitle:@"Cancel"];
        [container addSubview:userInput];
        [container addSubview:passwordInput];
        [alert setAccessoryView:container];
        [userInput setNextKeyView:passwordInput];
        [alert.window setInitialFirstResponder:userInput];
        
        [alert beginSheetModalForWindow:self.window completionHandler:^(NSModalResponse response) {
            [userInput validateEditing];
            if (response == NSAlertFirstButtonReturn)
                completionHandler(NSURLSessionAuthChallengeUseCredential, [[NSURLCredential alloc] initWithUser:[userInput stringValue] password:[passwordInput stringValue] persistence:NSURLCredentialPersistenceForSession]);
            else
                completionHandler(NSURLSessionAuthChallengeRejectProtectionSpace, nil);
        }];
        return;
    }
    completionHandler(NSURLSessionAuthChallengeRejectProtectionSpace, nil);
}

- (void)webView:(WKWebView *)webView didFailNavigation:(WKNavigation *)navigation withError:(NSError *)error
{
    LOG(@"didFailNavigation: %@, error %@", navigation, error);
    // Driftstack (W2649): a committed-then-failed load also leaves a partial/blank page — surface the
    // same on-screen error page. Skips the -999/cancelled supersede inside the helper.
    driftstackShowLoadFailurePage(webView, error);
}

- (void)webViewWebContentProcessDidTerminate:(WKWebView *)webView
{
    // W2825 (A3 fork-lifecycle audit #1 / A1-A3 bus #25): emit a deterministic stderr marker the
    // harness greps in BrowserProcess.drainPipe to reap a dead-renderer session WITHOUT polling or
    // false-positives — WebKit tells us exactly when WebContent dies. Symmetric with the paint-ready
    // marker. PID is best-effort (the process is already gone, so it may read 0). Stderr-only ⇒ zero
    // fingerprint surface. Keep this BEFORE the reload so the marker fires even if reload throws.
    NSLog(@"[Driftstack-WebContentTerminated] pid=%d", (int)webView._webProcessIdentifier);
    NSLog(@"WebContent process crashed; reloading");
    [self reload:nil];
}

- (void)_webView:(WKWebView *)webView renderingProgressDidChange:(_WKRenderingProgressEvents)progressEvents
{
    if (progressEvents & _WKRenderingProgressEventFirstLayout)
        LOG(@"renderingProgressDidChange: %@", @"first layout");

    if (progressEvents & _WKRenderingProgressEventFirstVisuallyNonEmptyLayout)
        LOG(@"renderingProgressDidChange: %@", @"first visually non-empty layout");

    if (progressEvents & _WKRenderingProgressEventFirstPaintWithSignificantArea)
        LOG(@"renderingProgressDidChange: %@", @"first paint with significant area");

    if (progressEvents & _WKRenderingProgressEventFirstLayoutAfterSuppressedIncrementalRendering)
        LOG(@"renderingProgressDidChange: %@", @"first layout after suppressed incremental rendering");

    if (progressEvents & _WKRenderingProgressEventFirstPaintAfterSuppressedIncrementalRendering)
        LOG(@"renderingProgressDidChange: %@", @"first paint after suppressed incremental rendering");
}

// W2078: associated-object key — stash each tab's favicon ON its WKWebView so the iOS-26 tab overview
// renders it per card (iPhone shows favicons in the tab switcher, not the address bar).
static char kDriftFaviconKey;

- (void)webView:(WKWebView *)webView shouldLoadIconWithParameters:(_WKLinkIconParameters *)parameters completionHandler:(void (^)(void (^)(NSData*)))completionHandler
{
    completionHandler(^void (NSData *data) {
        // W2078: the icon was already being FETCHED here (then only logged) — now keep it on the tab's
        // webView for the overview cards. Decode off the data; nil-safe (a bad/empty icon just isn't stored).
        if (data.length) {
            NSImage *icon = [[NSImage alloc] initWithData:data];
            if (icon)
                objc_setAssociatedObject(webView, &kDriftFaviconKey, icon, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        }
        LOG(@"Icon URL %@ received icon data of length %u", parameters.url, (unsigned)data.length);
    });
}

#pragma mark Find in Page

static const NSUInteger findMaxMatchCount = 1000;

- (BOOL)_shouldUseFindDelegate
{
    SettingsController *settings = [[NSApplication sharedApplication] browserAppDelegate].settingsController;
    return settings.useFindDelegate;
}

- (void)_ensureFindDelegateSetup
{
    if (_findBar)
        return;
    _webView._findDelegate = self;
    [self _buildFindBar];
}

- (void)_ensureTextFinderSetup
{
    if (_textFinder)
        return;
    _textFinder = [[MiniBrowserNSTextFinder alloc] init];
    _textFinder.incrementalSearchingEnabled = YES;
    _textFinder.incrementalSearchingShouldDimContentView = NO;
    _textFinder.client = _webView;
    _textFinder.findBarContainer = self;
    __weak WKWebView *weakWebView = _webView;
    _textFinder.hideInterfaceCallback = ^{
        [weakWebView _hideFindUI];
    };
}

- (void)_buildFindBar
{
    NSVisualEffectView *bar = [[NSVisualEffectView alloc] init];
    bar.translatesAutoresizingMaskIntoConstraints = NO;
    bar.material = NSVisualEffectMaterialTitlebar;
    bar.blendingMode = NSVisualEffectBlendingModeWithinWindow;
    _findBar = bar;

    _findSearchField = [[NSSearchField alloc] init];
    _findSearchField.translatesAutoresizingMaskIntoConstraints = NO;
    _findSearchField.placeholderString = @"Find in Page";
    _findSearchField.delegate = self;
    [_findBar addSubview:_findSearchField];

    NSButton *prevButton = [NSButton buttonWithTitle:@"<" target:self action:@selector(_findPrevious:)];
    prevButton.translatesAutoresizingMaskIntoConstraints = NO;
    prevButton.bezelStyle = NSBezelStyleRounded;
    [_findBar addSubview:prevButton];

    NSButton *nextButton = [NSButton buttonWithTitle:@">" target:self action:@selector(_findNext:)];
    nextButton.translatesAutoresizingMaskIntoConstraints = NO;
    nextButton.bezelStyle = NSBezelStyleRounded;
    [_findBar addSubview:nextButton];

    NSButton *doneButton = [NSButton buttonWithTitle:@"Done" target:self action:@selector(_hideFindBar:)];
    doneButton.translatesAutoresizingMaskIntoConstraints = NO;
    doneButton.bezelStyle = NSBezelStyleRounded;
    [_findBar addSubview:doneButton];

    _findMatchCountLabel = [NSTextField labelWithString:@""];
    _findMatchCountLabel.translatesAutoresizingMaskIntoConstraints = NO;
    _findMatchCountLabel.font = [NSFont systemFontOfSize:11];
    _findMatchCountLabel.textColor = [NSColor secondaryLabelColor];
    _findMatchCountLabel.lineBreakMode = NSLineBreakByTruncatingTail;
    [_findMatchCountLabel setContentCompressionResistancePriority:NSLayoutPriorityDefaultLow forOrientation:NSLayoutConstraintOrientationHorizontal];
    [_findBar addSubview:_findMatchCountLabel];

    [NSLayoutConstraint activateConstraints:@[
        [_findSearchField.leadingAnchor constraintEqualToAnchor:_findBar.leadingAnchor constant:4],
        [_findSearchField.centerYAnchor constraintEqualToAnchor:_findBar.centerYAnchor],
        [prevButton.leadingAnchor constraintEqualToAnchor:_findSearchField.trailingAnchor constant:4],
        [prevButton.centerYAnchor constraintEqualToAnchor:_findBar.centerYAnchor],
        [prevButton.widthAnchor constraintEqualToConstant:30],
        [nextButton.leadingAnchor constraintEqualToAnchor:prevButton.trailingAnchor constant:2],
        [nextButton.centerYAnchor constraintEqualToAnchor:_findBar.centerYAnchor],
        [nextButton.widthAnchor constraintEqualToConstant:30],
        [doneButton.leadingAnchor constraintEqualToAnchor:nextButton.trailingAnchor constant:2],
        [doneButton.centerYAnchor constraintEqualToAnchor:_findBar.centerYAnchor],
        [_findMatchCountLabel.leadingAnchor constraintEqualToAnchor:doneButton.trailingAnchor constant:4],
        [_findMatchCountLabel.centerYAnchor constraintEqualToAnchor:_findBar.centerYAnchor],
        [_findMatchCountLabel.trailingAnchor constraintLessThanOrEqualToAnchor:_findBar.trailingAnchor constant:-4],
    ]];
}

- (void)_showFindBar
{
    if (!_findBarVisible) {
        _findBarVisible = YES;

        [containerView addSubview:_findBar];
        [NSLayoutConstraint activateConstraints:@[
            [_findBar.topAnchor constraintEqualToAnchor:containerView.safeAreaLayoutGuide.topAnchor],
            [_findBar.leadingAnchor constraintEqualToAnchor:containerView.leadingAnchor],
            [_findBar.trailingAnchor constraintEqualToAnchor:containerView.trailingAnchor],
            [_findBar.heightAnchor constraintEqualToConstant:30],
        ]];

        __weak WK2BrowserWindowController *weakSelf = self;
        _findBarClickMonitor = [NSEvent addLocalMonitorForEventsMatchingMask:NSEventMaskLeftMouseDown handler:^NSEvent *(NSEvent *event) {
            WK2BrowserWindowController *strongSelf = weakSelf;
            if (!strongSelf)
                return event;
            NSPoint locationInBar = [strongSelf->_findBar convertPoint:event.locationInWindow fromView:nil];
            if (![strongSelf->_findBar mouse:locationInBar inRect:strongSelf->_findBar.bounds])
                [strongSelf _hideFindBarAndUI];
            return event;
        }];
    }

    [self.window makeFirstResponder:_findSearchField];
    [_findSearchField selectText:nil];
}

- (void)_hideFindBarAndUI
{
    if (!_findBarVisible)
        return;

    _findBarVisible = NO;
    [NSEvent removeMonitor:_findBarClickMonitor];
    _findBarClickMonitor = nil;
    [_findBar removeFromSuperview];
    _findMatchCountLabel.stringValue = @"";
    [_webView _hideFindUI];
    [self.window makeFirstResponder:_webView];
}

- (void)_findStringInDirection:(BOOL)backward
{
    NSString *searchString = _findSearchField.stringValue;
    if (!searchString.length)
        return;

    _WKFindOptions options = _WKFindOptionsCaseInsensitive | _WKFindOptionsWrapAround | _WKFindOptionsShowFindIndicator | _WKFindOptionsShowOverlay | _WKFindOptionsDetermineMatchIndex;
    if (backward)
        options |= _WKFindOptionsBackwards;

    [_webView _findString:searchString options:options maxCount:findMaxMatchCount];
    [_findSearchField selectText:nil];
}

- (IBAction)performTextFinderAction:(id)sender
{
    NSInteger tag = [sender tag];

    if (tag == NSTextFinderActionShowFindInterface) {
        BOOL shouldUseFindDelegate = [self _shouldUseFindDelegate];

        if (_findBarVisible && shouldUseFindDelegate != _usingFindDelegate) {
            if (_usingFindDelegate)
                [self _hideFindBarAndUI];
            else {
                [_textFinder performAction:NSTextFinderActionHideFindInterface];
                _findBarVisible = NO;
                [_textFindBarView removeFromSuperview];
                [_webView _hideFindUI];
            }
        }

        _usingFindDelegate = shouldUseFindDelegate;

        if (_usingFindDelegate) {
            [self _ensureFindDelegateSetup];
            [self _showFindBar];
        } else {
            [self _ensureTextFinderSetup];
            [_textFinder performAction:NSTextFinderActionShowFindInterface];
        }
        return;
    }

    if (_usingFindDelegate) {
        switch (tag) {
        case NSTextFinderActionNextMatch:
            [self _findStringInDirection:NO];
            break;
        case NSTextFinderActionPreviousMatch:
            [self _findStringInDirection:YES];
            break;
        case NSTextFinderActionHideFindInterface:
            [self _hideFindBarAndUI];
            break;
        default:
            break;
        }
    } else {
        [self _ensureTextFinderSetup];
        [_textFinder performAction:tag];
    }
}

- (void)_findNext:(id)sender
{
    [self _findStringInDirection:NO];
}

- (void)_findPrevious:(id)sender
{
    [self _findStringInDirection:YES];
}

- (void)_hideFindBar:(id)sender
{
    [self _hideFindBarAndUI];
}

- (void)cancelOperation:(id)sender
{
    if (_findBarVisible) {
        if (_usingFindDelegate)
            [self _hideFindBarAndUI];
        else
            [_textFinder performAction:NSTextFinderActionHideFindInterface];
    }
}

- (BOOL)control:(NSControl *)control textView:(NSTextView *)textView doCommandBySelector:(SEL)commandSelector
{
    if (!_usingFindDelegate || control != _findSearchField)
        return NO;

    if (commandSelector == @selector(insertNewline:)) {
        BOOL shiftDown = !!([NSEvent modifierFlags] & NSEventModifierFlagShift);
        [self _findStringInDirection:shiftDown];
        return YES;
    }

    if (commandSelector == @selector(cancelOperation:)) {
        [self _hideFindBarAndUI];
        return YES;
    }

    return NO;
}

#pragma mark NSSearchFieldDelegate

- (void)controlTextDidChange:(NSNotification *)notification
{
    if (!_usingFindDelegate)
        return;

    NSString *searchString = _findSearchField.stringValue;
    if (!searchString.length) {
        _findMatchCountLabel.stringValue = @"";
        [_webView _hideFindUI];
        return;
    }

    [_webView _findString:searchString options:_WKFindOptionsCaseInsensitive | _WKFindOptionsWrapAround | _WKFindOptionsShowFindIndicator | _WKFindOptionsShowOverlay | _WKFindOptionsDetermineMatchIndex maxCount:findMaxMatchCount];
}

#pragma mark _WKFindDelegate

- (void)_updateDisplayedMatchCount:(NSUInteger)matchCount matchIndex:(NSInteger)matchIndex
{
    if (!matchCount)
        _findMatchCountLabel.stringValue = @"Not found";
    else if (matchCount == 1)
        _findMatchCountLabel.stringValue = @"1 match";
    else if (matchCount > findMaxMatchCount)
        _findMatchCountLabel.stringValue = [NSString stringWithFormat:@"More than %lu matches", (unsigned long)findMaxMatchCount];
    else if (matchIndex != NSNotFound && matchIndex >= 0)
        _findMatchCountLabel.stringValue = [NSString stringWithFormat:@"%lu of %lu", (unsigned long)(matchIndex % matchCount + 1), (unsigned long)matchCount];
    else
        _findMatchCountLabel.stringValue = [NSString stringWithFormat:@"%lu matches", (unsigned long)matchCount];
}

- (void)_webView:(WKWebView *)webView didCountMatches:(NSUInteger)matches forString:(NSString *)string
{
    [self _updateDisplayedMatchCount:matches matchIndex:NSNotFound];
}

- (void)_webView:(WKWebView *)webView didFindMatches:(NSUInteger)matches forString:(NSString *)string withMatchIndex:(NSInteger)matchIndex
{
    [self _updateDisplayedMatchCount:matches matchIndex:matchIndex];
}

- (void)_webView:(WKWebView *)webView didFailToFindString:(NSString *)string
{
    [self _updateDisplayedMatchCount:0 matchIndex:NSNotFound];
}

#pragma mark NSTextFinderBarContainer

- (NSView *)findBarView
{
    return _textFindBarView;
}

- (void)setFindBarView:(NSView *)findBarView
{
    _textFindBarView = findBarView;
    _textFindBarView.autoresizingMask = NSViewMaxYMargin | NSViewWidthSizable;
    _textFindBarView.frame = NSMakeRect(0, 0, containerView.bounds.size.width, _textFindBarView.frame.size.height);
    _findBarVisible = YES;
}

- (BOOL)isFindBarVisible
{
    return _findBarVisible;
}

- (void)setFindBarVisible:(BOOL)findBarVisible
{
    _findBarVisible = findBarVisible;
    if (findBarVisible)
        [containerView addSubview:_textFindBarView];
    else
        [_textFindBarView removeFromSuperview];
}

- (NSView *)contentView
{
    return _webView;
}

- (void)findBarViewDidChangeHeight
{
}

- (void)_cloneWindowSiteIsolated:(BOOL)siteIsolated
{
    _WKSessionState *sessionState = [_webView _sessionState];

    WKWebViewConfiguration *configuration = _webView.configuration;
    _configuration.preferences._siteIsolationEnabled = siteIsolated;

    WK2BrowserWindowController *controller = [[WK2BrowserWindowController alloc] initWithConfiguration:configuration];
    [controller.window makeKeyAndOrderFront:self];

    [[[NSApplication sharedApplication] browserAppDelegate] didCreateBrowserWindowController:controller];

    [controller->_webView _restoreSessionState:sessionState andNavigate:YES];
}

- (IBAction)cloneSiteIsolatedWindow:(id)sender
{
    [self _cloneWindowSiteIsolated:YES];
}

- (IBAction)cloneNonIsolatedWindow:(id)sender
{
    [self _cloneWindowSiteIsolated:NO];
}

- (IBAction)saveAsPDF:(id)sender
{
    NSSavePanel *panel = [NSSavePanel savePanel];
    panel.allowedContentTypes = @[ UTTypePDF ];

    [panel beginSheetModalForWindow:self.window completionHandler:^(NSInteger result) {
        if (result != NSModalResponseOK)
            return;
        [self->_webView createPDFWithConfiguration:nil completionHandler:^(NSData *pdfSnapshotData, NSError *error) {
            PDFDocument *pdfDocument = [[PDFDocument alloc] initWithData:pdfSnapshotData];
            [pdfDocument writeToURL:[panel URL]];
        }];
    }];
}

- (IBAction)saveAsImage:(id)sender
{
    NSSavePanel *panel = [NSSavePanel savePanel];
    panel.allowedContentTypes = @[ UTTypeTIFF ];

    [panel beginSheetModalForWindow:self.window completionHandler:^(NSInteger result) {
        if (result != NSModalResponseOK)
            return;
        [self->_webView takeSnapshotWithConfiguration:nil completionHandler:^(NSImage *snapshot, NSError *error) {
            [snapshot.TIFFRepresentation writeToURL:[panel URL] options:0 error:nil];
        }];
    }];
}

- (IBAction)saveAsWebArchive:(id)sender
{
    NSSavePanel *panel = [NSSavePanel savePanel];
    panel.allowedContentTypes = @[ UTTypeWebArchive ];

    [panel beginSheetModalForWindow:self.window completionHandler:^(NSInteger result) {
        if (result != NSModalResponseOK)
            return;
        [self->_webView createWebArchiveDataWithCompletionHandler:^(NSData *archiveData, NSError *error) {
            [archiveData writeToURL:[panel URL] options:0 error:nil];
        }];
    }];
}

- (IBAction)saveAsCompleteWebPage:(id)sender
{
    NSSavePanel *panel = [NSSavePanel savePanel];
    panel.allowedContentTypes = @[ UTTypeDirectory ];

    [panel beginSheetModalForWindow:self.window completionHandler:^(NSInteger result) {
        if (result != NSModalResponseOK)
            return;

        _WKArchiveConfiguration *archiveConfiguration = [[_WKArchiveConfiguration alloc] init];
        archiveConfiguration.directory = [panel URL];
        archiveConfiguration.suggestedFileName = @"index.html";

        [self->_webView _archiveWithConfiguration:archiveConfiguration completionHandler:^(NSError *error) {
            if (error)
                NSLog(@"Saving complete web page to '%@' failed", [[panel URL] absoluteString]);
        }];
    }];
}

- (void)_webViewDidRequestPointerLock:(WKWebView *)webView completionHandler:(void (^)(BOOL))completionHandler
{
    if (!_pointerLockBanner) {
        _pointerLockBanner = [[CATextLayer alloc] init];
        [_pointerLockBanner setString:[[NSAttributedString alloc] initWithString:@"Your mouse pointer is hidden. Press Esc (Escape) once to reveal your mouse pointer." attributes:@{ NSFontAttributeName:[NSFont systemFontOfSize:16], NSForegroundColorAttributeName:NSColor.blackColor }]];
        [_pointerLockBanner setBackgroundColor:NSColor.lightGrayColor.CGColor];
        [_pointerLockBanner setWrapped:YES];
        [_pointerLockBanner setFrame:CGRectMake(0, 0, 0, testHeaderBannerHeight)];
        [_pointerLockBanner setContentsScale:[NSScreen mainScreen].backingScaleFactor];
    }
    [webView _setHeaderBannerLayer:_pointerLockBanner];
    completionHandler(YES);
}

- (void)_webViewDidLosePointerLock:(WKWebView *)webView
{
    [webView _setHeaderBannerLayer:nil];
}

- (NSImage *)windowSnapshotInRect:(CGRect)rect
{
    return [_webView _windowSnapshotInRect:rect withOptions:kCGWindowImageBoundsIgnoreFraming];
}

@end
