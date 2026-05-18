/*
 * Copyright (C) 2026 Driftstack BV. All rights reserved.
 *
 * Wave 29-397 H3.exec.5.B.2 — Driftstack JS-bridge message handler.
 *
 * Receives postMessage payloads from window.driftstack JS namespace
 * (defined by bridge.js, injected via WKUserScript at
 * WKUserScriptInjectionTimeAtDocumentStart into the "driftstack-bridge"
 * WKContentWorld), forwards each call to the harness Swift side via the
 * per-session unix socket at /tmp/driftstack-js-bridge-<sessionId>.sock.
 *
 * Handler lives in an isolated content world so page-scope JS (and the
 * detection scripts in it) cannot enumerate the message handler name
 * or the window.driftstack namespace. Matches the
 * real-iPhone-with-content-script architecture exactly (page sees no
 * extension symbols).
 *
 * Per CLAUDE.md production-zero-JS-fingerprint rule: bridge.js DOES NOT
 * modify any built-in object / prototype / global; only DEFINES the
 * window.driftstack namespace in the isolated world. Page-scope sees
 * no Driftstack symbols.
 */

#import <Foundation/Foundation.h>
#import <WebKit/WKScriptMessageHandler.h>

#if PLATFORM(DRIFTSTACK)

NS_ASSUME_NONNULL_BEGIN

@class WKScriptMessage;
@class WKUserContentController;

WK_SWIFT_UI_ACTOR
@interface DriftstackJSBridgeMessageHandler : NSObject <WKScriptMessageHandler>

/*! Per-session id. Used to locate the harness-side unix socket at
 *  /tmp/driftstack-js-bridge-<sessionId>.sock.
 *  Resolved at -init from the DRIFTSTACK_ARCHETYPE_SESSION_ID env
 *  variable (set by harness BrowserProcess.spawn).
 */
@property (nonatomic, readonly, copy) NSString *sessionId;

/*! Path to the unix socket. Defaults to
 *  /tmp/driftstack-js-bridge-<sessionId>.sock. Override via the env
 *  DRIFTSTACK_JS_BRIDGE_SOCKET_PATH for tests.
 */
@property (nonatomic, readonly, copy) NSString *socketPath;

- (instancetype)init;
- (instancetype)initWithSessionId:(NSString *)sessionId
                       socketPath:(nullable NSString *)socketPath NS_DESIGNATED_INITIALIZER;

/*! WKScriptMessageHandler protocol. Invoked on the main thread by the
 *  WKUserContentController when bridge.js calls
 *  window.webkit.messageHandlers.driftstackBridge.postMessage(...).
 *  message.body is the JS object (NSDictionary / NSArray / NSString /
 *  NSNumber / NSDate / NSNull).
 */
- (void)userContentController:(WKUserContentController *)userContentController
      didReceiveScriptMessage:(WKScriptMessage *)message;

NS_ASSUME_NONNULL_END
@end

#endif /* PLATFORM(DRIFTSTACK) */
