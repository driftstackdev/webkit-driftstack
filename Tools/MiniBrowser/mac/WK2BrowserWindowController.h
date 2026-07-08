/*
 * Copyright (C) 2010 Apple Inc. All rights reserved.
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

#import <WebKit/WebKit.h>
#import "BrowserWindowController.h"

@interface WK2BrowserWindowController : BrowserWindowController

@property (readonly) WKWebView *webView;

// Driftstack warm-tabs (doc 151, runtime-gated DRIFTSTACK_WARM_TABS): create a real new live tab in THIS
// window — a genuine background WKWebView sharing the session configuration (same store / cookie jar /
// fingerprint) — add it to the tab manager, activate it (moves the shared chrome + KVO via
// -driftActivateWebView:, hides the previous tab), and return its WKWebView. Used by the automation
// delegate's requestNewWebViewWithOptions (W3C POST /window/new) so a warm tab is a live page, not a reload.
// Returns nil if the window has no content container yet. Does NOT navigate (the harness loads the URL).
// (Declared unconditionally — this .h is imported before <WebKit> defines PLATFORM(); the impl is
// #if PLATFORM(DRIFTSTACK)-guarded in the .m.)
- (WKWebView *)driftCreateAndActivateAutomationTab;

- (instancetype)initWithConfiguration:(WKWebViewConfiguration *)configuration;

@end
