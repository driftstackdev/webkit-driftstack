/*
 * WKDriftstackSocks5URLProtocol — NSURLProtocol subclass that routes
 * NSURLSession HTTP/HTTPS requests through DriftstackSocks5Client.
 *
 * Wave 29-386 Phase A scaffold. Phase B (the actual HTTP-over-SOCKS5
 * driving + TLS upgrade for HTTPS) lands in a subsequent slice.
 *
 * Why this exists:
 *   CFNetwork's built-in SOCKS5 (kCFNetworkProxiesSOCKSEnable) pre-resolves
 *   destination hostnames via getaddrinfo() locally and sends ATYP=0x01
 *   (pre-resolved IPv4) over the wire. This LEAKS the destination hostname
 *   to the Mac fleet's ISP DNS — defeats the whole point of having
 *   customer SOCKS5 in the first place.
 *
 *   The remedy is DriftstackSocks5Client (Wave 29-368/29-375/29-379) which
 *   speaks RFC 1928 with ATYP=0x03 (DOMAINNAME). The proxy resolves the
 *   destination hostname remotely; zero local DNS.
 *
 *   To get NSURLSession to USE DriftstackSocks5Client instead of CFNetwork's
 *   built-in, we need an NSURLProtocol subclass that intercepts requests +
 *   routes them through our client.
 *
 * Phase A scope (this scaffold):
 *   - Class declaration + +canInitWithRequest: returning NO unconditionally
 *     (so the protocol is registered but never matches)
 *   - WTFLogAlways diagnostics for every NSURLProtocol callback that
 *     fires before canInitWithRequest gates them off
 *   - Tells production logs "scaffold installed, dispatch dormant"
 *
 * Phase B (Wave 29-387+):
 *   - +canInitWithRequest: returns YES when DRIFTSTACK_CUSTOM_SOCKS5=1
 *     + SOCKS5 config active for this NSURLSession
 *   - -startLoading: extract host/port from self.request.URL, call
 *     DriftstackSocks5Client::tcpConnect, then write HTTP request bytes
 *     to socket + read response. For HTTPS, do TLS handshake first.
 *   - Caller code in NetworkSessionCocoa.mm registers the class on
 *     NSURLSessionConfiguration.protocolClasses when env-gate set
 */

#pragma once

#if PLATFORM(DRIFTSTACK)

#import <Foundation/Foundation.h>
#include <atomic>

NS_ASSUME_NONNULL_BEGIN

namespace WebKit {

// Wave 29-396 sub-slice 1.6: global dispatch flag set by
// NetworkSessionCocoa::NetworkSessionCocoa() when both
// DRIFTSTACK_CUSTOM_SOCKS5=1 AND SOCKS5 is active for ANY session in
// the NetworkProcess. WKDriftstackSocks5URLProtocol::+canInitWithRequest
// reads this flag to gate dispatch.
//
// Approach A (coarse global, v1.0 acceptable per Phase B impl plan
// Wave 29-388.B Slice B.1): single-customer NetworkProcess deployment
// means coarseness doesn't matter — when ANY session has env-gate set,
// ALL HTTP/HTTPS requests in the process get intercepted.
extern std::atomic<bool> g_driftstackCustomSocks5Active;

} // namespace WebKit

@interface WKDriftstackSocks5URLProtocol : NSURLProtocol
@end

NS_ASSUME_NONNULL_END

#endif // PLATFORM(DRIFTSTACK)
