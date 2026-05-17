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

@implementation WKDriftstackSocks5URLProtocol

+ (BOOL)canInitWithRequest:(NSURLRequest *)request
{
    // Phase A: dispatch dormant. Wave 29-387+ Phase B will return YES when
    // DRIFTSTACK_CUSTOM_SOCKS5=1 + SOCKS5 config active. For now: leave the
    // CFNetwork SOCKS5 path (Wave 29-366) as the actual transport.
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        WTFLogAlways("[Driftstack-EG-WK-1.8/SOCK5-URLPROTOCOL] WKDriftstackSocks5URLProtocol class loaded — Phase A scaffold (canInitWithRequest always NO). Phase B impl pending Wave 29-387+.");
    });
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
