/*
 * WKDriftstackSocks5URLProtocol.mm — Wave 29-386 Phase A scaffold stub.
 *
 * See WKDriftstackSocks5URLProtocol.h for design + Phase B plan.
 *
 * Phase A: +canInitWithRequest returns NO unconditionally — the protocol
 * is class-registered but never matches any request. Acts as a placeholder
 * + signals that the integration scaffold is in place.
 */

#import "config.h"
#import "DriftstackSocks5URLProtocol.h"

#if PLATFORM(DRIFTSTACK)

#import "DriftstackSocks5Client.h"
#import <stdlib.h>
#import <string.h>
#import <wtf/Assertions.h>
#import <wtf/text/WTFString.h>

namespace WebKit {
// Wave 29-396 sub-slice 1.6: global dispatch flag definition.
std::atomic<bool> g_driftstackCustomSocks5Active { false };
} // namespace WebKit

// Wave 29-396 sub-slice 1.7.2.d: lifetime management via ivars.
// DriftstackSocks5Client + CFStream pair must outlive -startLoading
// return; stored as ivars released in -stopLoading.
@interface WKDriftstackSocks5URLProtocol () {
    std::unique_ptr<WebKit::DriftstackSocks5Client> _socks5Client;
    CFReadStreamRef _readStream;
    CFWriteStreamRef _writeStream;
}
@end

@implementation WKDriftstackSocks5URLProtocol

+ (BOOL)canInitWithRequest:(NSURLRequest *)request
{
    // Wave 29-396 sub-slice 1.6: Phase B dispatch gate.
    // Returns YES iff:
    //   1. WebKit::g_driftstackCustomSocks5Active flag set by
    //      NetworkSessionCocoa (when DRIFTSTACK_CUSTOM_SOCKS5=1 + SOCKS5
    //      active for session), AND
    //   2. Request URL scheme is http or https (skip ws/wss/file/etc.)
    //
    // -startLoading still TODO sub-slices 1.7-1.8 (HTTP/HTTPS driving
    // through DriftstackSocks5Client established TCP socket). Until those
    // land, this gate returns NO unconditionally because the flag is
    // never set in dev/cumrig (only when explicit DRIFTSTACK_CUSTOM_SOCKS5=1
    // env is wired through to NetworkSessionCocoa).
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        WTFLogAlways("[Driftstack-EG-WK-1.8/SOCK5-URLPROTOCOL] WKDriftstackSocks5URLProtocol class loaded — gate set on g_driftstackCustomSocks5Active flag (Wave 29-396 sub-slice 1.6).");
    });

    if (!WebKit::g_driftstackCustomSocks5Active.load(std::memory_order_relaxed))
        return NO;

    // Only intercept HTTP/HTTPS. WebSocket (ws/wss) has its own
    // NSURLProtocol subclass; file/data/blob schemes don't need SOCKS5.
    NSURL *url = request.URL;
    NSString *scheme = url.scheme.lowercaseString;
    if (![scheme isEqualToString:@"http"] && ![scheme isEqualToString:@"https"])
        return NO;

    // Currently startLoading returns error → setting return YES here
    // would break HTTPS requests when env-gate set. Keep gate dormant
    // (return NO) until -startLoading impl lands sub-slices 1.7-1.8.
    // The flag-check itself is the wiring scaffold being verified this slice.
    return NO;
}

+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)request
{
    return request;
}

- (void)startLoading
{
    // Wave 29-396 sub-slice 1.7.1: DriftstackSocks5Client construction +
    // performHandshake + tcpConnect. Future sub-slices land:
    //   1.7.2: CFStream pair wrap + HTTP/1.1 driving
    //   1.8:   TLS for HTTPS
    //   1.9:   protocolClasses registration + CFNetwork SOCKS5 disable
    NSURL *url = self.request.URL;
    NSString *host = url.host ?: @"";
    NSNumber *port = url.port;
    NSString *scheme = url.scheme.lowercaseString ?: @"";
    int defaultPort = [scheme isEqualToString:@"https"] ? 443 : 80;
    int actualPort = port ? port.intValue : defaultPort;

    // Read SOCKS5 proxy from env var (EG-WK-1.1 path). Per-session
    // proxy_configuration plumb-through is a future sub-slice; for
    // Phase B v1 we use the env-fallback proxy as the SOCKS5 target.
    const char* proxyEnv = getenv("DRIFTSTACK_SOCKS5_PROXY");
    if (!proxyEnv || !proxyEnv[0]) {
        WTFLogAlways("[Driftstack-EG-WK-1.8/SOCK5-URLPROTOCOL] startLoading: DRIFTSTACK_SOCKS5_PROXY not set — cannot route through SOCKS5. Returning error.");
        [[self client] URLProtocol:self didFailWithError:[NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorBadServerResponse userInfo:@{
            NSLocalizedDescriptionKey: @"DRIFTSTACK_SOCKS5_PROXY env var required for custom SOCKS5 dispatch",
        }]];
        return;
    }

    // Parse "host:port" from env var
    NSString *proxySpec = [NSString stringWithUTF8String:proxyEnv];
    NSArray<NSString *> *parts = [proxySpec componentsSeparatedByString:@":"];
    if (parts.count != 2) {
        WTFLogAlways("[Driftstack-EG-WK-1.8/SOCK5-URLPROTOCOL] startLoading: DRIFTSTACK_SOCKS5_PROXY malformed '%s' (need host:port)", proxyEnv);
        [[self client] URLProtocol:self didFailWithError:[NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorBadServerResponse userInfo:nil]];
        return;
    }

    WebKit::Socks5Endpoint proxy;
    proxy.host = WTF::String::fromUTF8([parts[0] UTF8String]);
    proxy.port = static_cast<uint16_t>([parts[1] intValue]);

    WebKit::Socks5Credentials creds;
    // No auth for v1.0 (RFC 1928 §3 NO_AUTH method); user/pass support
    // when DRIFTSTACK_SOCKS5_USER + DRIFTSTACK_SOCKS5_PASS env vars set
    // (future sub-slice).

    _socks5Client = std::make_unique<WebKit::DriftstackSocks5Client>(proxy, creds);
    auto& client = _socks5Client;
    auto handshakeResult = client->performHandshake();
    if (handshakeResult != WebKit::Socks5Result::Success) {
        WTFLogAlways("[Driftstack-EG-WK-1.8/SOCK5-URLPROTOCOL] startLoading: handshake failed (%d) against proxy %s:%u",
            int(handshakeResult), proxy.host.utf8().data(), unsigned(proxy.port));
        [[self client] URLProtocol:self didFailWithError:[NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorCannotConnectToHost userInfo:@{
            NSLocalizedDescriptionKey: @"SOCKS5 handshake failed",
        }]];
        return;
    }

    WebKit::Socks5Endpoint dest;
    dest.host = WTF::String::fromUTF8([host UTF8String]);
    dest.port = static_cast<uint16_t>(actualPort);

    WebKit::Socks5Endpoint bnd;
    auto connectResult = client->tcpConnect(dest, bnd);
    if (connectResult != WebKit::Socks5Result::Success) {
        WTFLogAlways("[Driftstack-EG-WK-1.8/SOCK5-URLPROTOCOL] startLoading: tcpConnect failed (%d) for %s:%d via proxy",
            int(connectResult), [host UTF8String], actualPort);
        [[self client] URLProtocol:self didFailWithError:[NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorCannotConnectToHost userInfo:@{
            NSLocalizedDescriptionKey: @"SOCKS5 tcpConnect failed",
        }]];
        return;
    }

    // Sub-slice 1.7.2.b: wrap established socket FD into CFStream pair.
    int fd = client->socketFileDescriptor();
    if (fd < 0) {
        WTFLogAlways("[Driftstack-EG-WK-1.8/SOCK5-URLPROTOCOL] sub-1.7.2.b: socketFileDescriptor() returned -1 (no successful tcpConnect)");
        [[self client] URLProtocol:self didFailWithError:[NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorCannotConnectToHost userInfo:nil]];
        return;
    }

    CFReadStreamRef readStreamRef = NULL;
    CFWriteStreamRef writeStreamRef = NULL;
    CFStreamCreatePairWithSocket(kCFAllocatorDefault, static_cast<CFSocketNativeHandle>(fd), &readStreamRef, &writeStreamRef);
    if (!readStreamRef || !writeStreamRef) {
        WTFLogAlways("[Driftstack-EG-WK-1.8/SOCK5-URLPROTOCOL] sub-1.7.2.b: CFStreamCreatePairWithSocket failed for fd=%d", fd);
        if (readStreamRef) CFRelease(readStreamRef);
        if (writeStreamRef) CFRelease(writeStreamRef);
        [[self client] URLProtocol:self didFailWithError:[NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorCannotConnectToHost userInfo:nil]];
        return;
    }

    // Don't let CFStream close the socket on dispose — DriftstackSocks5Client
    // owns the FD via its Impl destructor.
    CFReadStreamSetProperty(readStreamRef, kCFStreamPropertyShouldCloseNativeSocket, kCFBooleanFalse);
    CFWriteStreamSetProperty(writeStreamRef, kCFStreamPropertyShouldCloseNativeSocket, kCFBooleanFalse);

    // Sub-slice 1.7.2.b stops here. Streams are constructed but not yet
    // opened/driven. Sub-slice 1.7.2.c serializes HTTP/1.1 request bytes
    // + writes to writeStream + reads response from readStream. Sub-slice
    // 1.7.2.d adds lifetime management via class ivars so the
    // DriftstackSocks5Client outlives this function call.
    // Sub-slice 1.7.2.d: store streams in ivars for lifetime past startLoading.
    _readStream = readStreamRef;
    _writeStream = writeStreamRef;

    WTFLogAlways("[Driftstack-EG-WK-1.8/SOCK5-URLPROTOCOL] sub-1.7.2.d SUCCESS — CFStream pair stored in ivars (fd=%d, read=%p, write=%p) for %s:%d via SOCKS5 proxy. HTTP/1.1 driving pending sub-slice 1.7.2.c.",
        fd, (void*)_readStream, (void*)_writeStream, [host UTF8String], actualPort);

    [[self client] URLProtocol:self didFailWithError:[NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorUnsupportedURL userInfo:@{
        NSLocalizedDescriptionKey: @"Phase B sub-slice 1.7.2.d — ivars stored; HTTP/1.1 driving pending sub-slice 1.7.2.c",
    }]];
}

- (void)stopLoading
{
    // Wave 29-396 sub-slice 1.7.2.d: tear down lifetime-managed resources.
    // -stopLoading is called by NSURLProtocolClient when the protocol
    // task is canceled OR after URLProtocolDidFinishLoading. Release ivar
    // resources to prevent leaks.
    if (_readStream) {
        CFReadStreamClose(_readStream);
        CFRelease(_readStream);
        _readStream = NULL;
    }
    if (_writeStream) {
        CFWriteStreamClose(_writeStream);
        CFRelease(_writeStream);
        _writeStream = NULL;
    }
    _socks5Client.reset();  // closes BSD socket FD via Impl destructor
}

@end

#endif // PLATFORM(DRIFTSTACK)
