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
