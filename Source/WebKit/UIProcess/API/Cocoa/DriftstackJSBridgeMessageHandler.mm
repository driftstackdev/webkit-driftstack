/*
 * Copyright (C) 2026 Driftstack BV. All rights reserved.
 *
 * Wave 29-397 H3.exec.5.B.2 — Driftstack JS-bridge message handler.
 *
 * Per DriftstackJSBridgeMessageHandler.h header for full design notes.
 */

#import "config.h"
#import "DriftstackJSBridgeMessageHandler.h"

#if PLATFORM(DRIFTSTACK)

#import <Foundation/Foundation.h>
#import <WebKit/WKScriptMessage.h>
#import <WebKit/WKFrameInfo.h>
#import <sys/socket.h>
#import <sys/time.h>
#import <sys/un.h>
#import <unistd.h>

@implementation DriftstackJSBridgeMessageHandler {
    NSString *_sessionId;
    NSString *_socketPath;
    dispatch_queue_t _ioQueue;
}

- (instancetype)init {
    NSDictionary *env = [[NSProcessInfo processInfo] environment];
    NSString *sid = env[@"DRIFTSTACK_ARCHETYPE_SESSION_ID"] ?: env[@"__XPC_DRIFTSTACK_ARCHETYPE_SESSION_ID"] ?: @"default";
    NSString *override = env[@"DRIFTSTACK_JS_BRIDGE_SOCKET_PATH"];
    return [self initWithSessionId:sid socketPath:override];
}

- (instancetype)initWithSessionId:(NSString *)sessionId socketPath:(NSString *)socketPath {
    self = [super init];
    if (!self) return nil;
    _sessionId = [sessionId copy];
    _socketPath = [(socketPath ?: [NSString stringWithFormat:@"/tmp/driftstack-js-bridge-%@.sock", sessionId]) copy];
    _ioQueue = dispatch_queue_create("dev.driftstack.jsbridge.io", DISPATCH_QUEUE_SERIAL);
    return self;
}

- (NSString *)sessionId { return _sessionId; }
- (NSString *)socketPath { return _socketPath; }

- (void)userContentController:(WKUserContentController *)userContentController
      didReceiveScriptMessage:(WKScriptMessage *)message {
    // Marshal the JS payload to a top-level JSON object that the harness
    // can parse: {"session": <sid>, "name": <message.name>,
    //              "frame": <main/sub>, "body": <body>}.
    NSDictionary *envelope = @{
        @"session": _sessionId,
        @"name": message.name ?: @"",
        @"frame": message.frameInfo.isMainFrame ? @"main" : @"sub",
        @"body": message.body ?: [NSNull null],
    };

    NSError *jsonError = nil;
    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:envelope options:0 error:&jsonError];
    if (!jsonData) {
        NSLog(@"[DriftstackJSBridge] JSON encode failed for session=%@ name=%@: %@",
              _sessionId, message.name, jsonError);
        return;
    }
    // Append newline so harness can frame on '\n'.
    NSMutableData *withNL = [jsonData mutableCopy];
    [withNL appendBytes:"\n" length:1];

    // Async send on _ioQueue so we don't block the WebContent main thread.
    NSString *path = _socketPath;
    dispatch_async(_ioQueue, ^{
        int fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd < 0) {
            NSLog(@"[DriftstackJSBridge] socket() failed: errno=%d", errno);
            return;
        }
        // Wave 29-499.361 (hardening) — two standard unix-socket-client guards this
        // handler omitted:
        //  (1) SO_NOSIGPIPE — on macOS, send() to a peer that closed the connection
        //      mid-write raises SIGPIPE, whose default disposition TERMINATES the
        //      process. If the harness JSBridgeSocketServer accepts then closes/dies
        //      while we're sending, an unguarded send() could crash this UIProcess.
        //      (Foundation usually ignores SIGPIPE process-wide, but per-socket
        //      SO_NOSIGPIPE makes THIS socket correct regardless of global state.)
        //  (2) SO_SNDTIMEO — the send() below is blocking and _ioQueue is SERIAL, so
        //      a harness that accepts but stops draining (hung/overloaded) would block
        //      send() on a full socket buffer indefinitely → the serial queue stalls →
        //      every subsequent bridge message backs up unbounded (the W2314 blocking-
        //      syscall-with-no-timeout class). A 2s cap makes a stuck send fail (the
        //      while-loop breaks, message dropped, fd closed) so the queue drains.
        int one = 1;
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
        struct timeval sndTimeout = { .tv_sec = 2, .tv_usec = 0 };
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &sndTimeout, sizeof(sndTimeout));
        struct sockaddr_un addr;
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, [path UTF8String], sizeof(addr.sun_path) - 1);

        if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            // Harness not yet listening or socket missing — non-fatal,
            // log + drop. The bridge.js side will see no callback
            // response + Promise will reject after its own timeout.
            close(fd);
            return;
        }
        const uint8_t *bytes = (const uint8_t *)[withNL bytes];
        NSUInteger remaining = [withNL length];
        while (remaining > 0) {
            ssize_t written = send(fd, bytes, remaining, 0);
            if (written <= 0) break;
            remaining -= (NSUInteger)written;
            bytes += written;
        }
        close(fd);
    });
}

@end

#endif /* PLATFORM(DRIFTSTACK) */
