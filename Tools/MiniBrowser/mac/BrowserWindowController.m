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
        self.window.titlebarAppearsTransparent = YES;
        self.window.titleVisibility = NSWindowTitleHidden;
        [self.window standardWindowButton:NSWindowCloseButton].hidden = YES;
        [self.window standardWindowButton:NSWindowMiniaturizeButton].hidden = YES;
        [self.window standardWindowButton:NSWindowZoomButton].hidden = YES;
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
