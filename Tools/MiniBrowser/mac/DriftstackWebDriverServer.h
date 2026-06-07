/*
 * DriftstackWebDriverServer.h — Driftstack item-9 in-process WebDriver entry.
 *
 * Callable from plain ObjC (MiniBrowser AppDelegate.m). Starts the in-process
 * W3C-WebDriver server bound to `session` on a free localhost port and writes
 * /tmp/driftstack-webdriver-<sessionID>.port so the harness can discover it.
 */

#pragma once

#import <Foundation/Foundation.h>

@class _WKAutomationSession;

#ifdef __cplusplus
extern "C" {
#endif

// Start the in-process WebDriver server. Call ONCE, after the automation session is
// created and installed on the process pool. No-op on bad args / if already started /
// if it cannot bind. Safe to call from the main thread at app launch.
void DriftstackStartWebDriverServer(NSString *sessionID, _WKAutomationSession *session);

#ifdef __cplusplus
}
#endif
