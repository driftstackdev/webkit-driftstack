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

#import <wtf/Assertions.h>

namespace WebKit {
// Wave 29-396 sub-slice 1.6: global dispatch flag definition.
std::atomic<bool> g_driftstackCustomSocks5Active { false };
} // namespace WebKit

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
    // Phase B will implement: parse host/port from self.request.URL.host:port,
    // call DriftstackSocks5Client::tcpConnect(dest, &bnd), then drive HTTP/
    // HTTPS over the established TCP socket. For HTTPS, do TLS handshake first
    // (NSStream + SSL or CFStream with SSL settings).
    //
    // For now: this is dead code since canInitWithRequest returns NO.
    WTFLogAlways("[Driftstack-EG-WK-1.8/SOCK5-URLPROTOCOL] startLoading called unexpectedly — should be dormant per Phase A canInitWithRequest=NO. Likely production misconfiguration.");
    [[self client] URLProtocol:self didFailWithError:[NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorUnsupportedURL userInfo:nil]];
}

- (void)stopLoading
{
    // No-op until Phase B has an active connection to tear down.
}

@end

#endif // PLATFORM(DRIFTSTACK)
