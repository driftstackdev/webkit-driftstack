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
#import "DriftstackHttp3.h"
#import <stdlib.h>
#import <string.h>
#import <wtf/Assertions.h>
#import <wtf/HashSet.h>
#import <wtf/Lock.h>
#import <wtf/NeverDestroyed.h>
#import <wtf/text/WTFString.h>

namespace WebKit {
// Wave 29-396 sub-slice 1.6: global dispatch flag definition.
std::atomic<bool> g_driftstackCustomSocks5Active { false };
} // namespace WebKit

// Wave 29-499.321 — Alt-Svc-based HTTP/3 discovery. Real Safari does NOT speak
// h3 to an origin until that origin has advertised it via an `Alt-Svc: h3=...`
// response header (RFC 7838). Without this, we'd attempt a full QUIC handshake
// (up to ~12s budget) on every https request to an h2-only origin before
// falling back — making general browsing unusable. So: the first request to a
// host goes over TCP h1/h2, we learn h3 support from its Alt-Svc header, and
// only subsequent requests to that host take the QUIC fast-path. The
// DRIFTSTACK_PATHB_V2_H3_FORCE=1 escape hatch attempts h3 unconditionally (for
// the cloudflare-quic.com / browserleaks first-contact verification path).
static Lock& driftstackH3HostsLock()
{
    static NeverDestroyed<Lock> lock;
    return lock.get();
}
static HashSet<String>& driftstackH3Hosts()
{
    static NeverDestroyed<HashSet<String>> hosts;
    return hosts.get();
}
static String driftstackH3HostKey(NSString* host, int port)
{
    return WTF::String::fromUTF8([[NSString stringWithFormat:@"%@:%d", host, port] UTF8String]);
}
static bool driftstackHostKnownH3(NSString* host, int port)
{
    Locker locker { driftstackH3HostsLock() };
    return driftstackH3Hosts().contains(driftstackH3HostKey(host, port));
}
static void driftstackRememberH3Host(NSString* host, int port)
{
    Locker locker { driftstackH3HostsLock() };
    driftstackH3Hosts().add(driftstackH3HostKey(host, port));
}

// Wave 29-396 sub-slice 1.7.2.c helper: write all bytes to CFWriteStream.
// WTF_ALLOW_UNSAFE_BUFFER_USAGE at function scope per WebKit precedent
// (pragma push/pop can't balance inside conditional branches).
WTF_ALLOW_UNSAFE_BUFFER_USAGE_BEGIN
static CFIndex writeAllToCFStream(CFWriteStreamRef stream, NSData *data)
{
    const uint8_t *bytes = (const uint8_t *)data.bytes;
    CFIndex offset = 0;
    CFIndex total = data.length;
    while (offset < total) {
        CFIndex n = CFWriteStreamWrite(stream, bytes + offset, total - offset);
        if (n <= 0)
            return -1;
        offset += n;
    }
    return total;
}
WTF_ALLOW_UNSAFE_BUFFER_USAGE_END

// Wave 29-396 sub-slice 1.7.2.e helper: read until headers complete OR EOF.
// Returns: total bytes read into outBuffer (which is the complete response —
// caller splits headers vs body at "\r\n\r\n"). -1 on stream error.
// Uses blocking read on CFReadStream (background thread context OK).
WTF_ALLOW_UNSAFE_BUFFER_USAGE_BEGIN
static NSData* readAllFromCFStream(CFReadStreamRef stream)
{
    NSMutableData *out = [NSMutableData data];
    uint8_t chunk[4096];
    while (true) {
        if (CFReadStreamGetStatus(stream) == kCFStreamStatusAtEnd)
            break;
        if (CFReadStreamGetStatus(stream) == kCFStreamStatusError)
            return nil;
        CFIndex n = CFReadStreamRead(stream, chunk, sizeof(chunk));
        if (n < 0)
            return nil;
        if (n == 0)
            break;  // EOF
        [out appendBytes:chunk length:n];
    }
    return out;
}
WTF_ALLOW_UNSAFE_BUFFER_USAGE_END

// Wave 29-499.321 — HTTP/3 fast-path. For https requests (when
// DRIFTSTACK_PATHB_V2_H3=1), attempt a real QUIC/HTTP-3 request through the
// SOCKS5 §7 UDP relay via the DriftstackHttp3 ngtcp2/nghttp3 engine. CFNetwork
// will not negotiate h3 when a proxy is configured (it abandons the QUIC
// connection below the interceptable layer), so this is the only way the
// browser actually speaks QUIC through the customer proxy. On success the
// response is delivered to the URL-loading client and YES is returned; on any
// failure we return NO and the caller falls through to the TCP h1/h2 path
// (mirrors Safari's h3→h2 fallback for non-h3 origins).
WTF_ALLOW_UNSAFE_BUFFER_USAGE_BEGIN
static BOOL driftstackTryHttp3(NSURLProtocol* proto, NSURL* url, NSString* host, int actualPort)
{
    const char* h3env = getenv("DRIFTSTACK_PATHB_V2_H3");
    if (!h3env || h3env[0] != '1')
        return NO;

    // Alt-Svc gating: only attempt h3 for origins that advertised it (learned
    // from a prior TCP response's Alt-Svc header), unless FORCE is set. This
    // keeps first-contact + h2-only origins on the fast TCP path.
    const char* forceEnv = getenv("DRIFTSTACK_PATHB_V2_H3_FORCE");
    bool force = forceEnv && forceEnv[0] == '1';
    if (!force && !driftstackHostKnownH3(host, actualPort)) {
        WTFLogAlways("[Wave29-499.321/URLPROTOCOL] %s:%d not yet known h3-capable (no Alt-Svc seen) — using TCP h1/h2",
            [host UTF8String], actualPort);
        return NO;
    }

    WebKit::DriftstackHttp3Request req;
    req.method = WTF::String::fromUTF8([(proto.request.HTTPMethod ?: @"GET") UTF8String]);
    req.scheme = "https"_s;
    req.authority = WTF::String::fromUTF8([[NSString stringWithFormat:@"%@:%d", host, actualPort] UTF8String]);
    NSString* path = url.path.length ? url.path : @"/";
    if (url.query.length > 0)
        path = [NSString stringWithFormat:@"%@?%@", path, url.query];
    req.path = WTF::String::fromUTF8([path UTF8String]);
    NSDictionary* hdrs = proto.request.allHTTPHeaderFields ?: @{};
    for (NSString* key in hdrs) {
        NSString* lk = key.lowercaseString;
        if ([lk isEqualToString:@"host"] || [lk isEqualToString:@"connection"])
            continue;
        req.extraHeaders.append({ WTF::String::fromUTF8([key UTF8String]), WTF::String::fromUTF8([hdrs[key] UTF8String]) });
    }
    NSData* body = proto.request.HTTPBody;
    if (body.length > 0)
        req.body.append(std::span<const uint8_t> { static_cast<const uint8_t*>(body.bytes), static_cast<size_t>(body.length) });

    WTFLogAlways("[Wave29-499.321/URLPROTOCOL] attempting HTTP/3 for https://%s:%d%s via SOCKS5 §7",
        [host UTF8String], actualPort, [path UTF8String]);
    WebKit::DriftstackHttp3Response resp = WebKit::driftstackHttp3Execute(nullptr, req);
    if (resp.failed || resp.statusCode == 0) {
        WTFLogAlways("[Wave29-499.321/URLPROTOCOL] HTTP/3 attempt failed (%s) — falling back to TCP h1/h2",
            resp.errorMessage.utf8().data());
        return NO;
    }

    NSMutableDictionary<NSString*, NSString*>* respHeaders = [NSMutableDictionary dictionary];
    for (auto& kv : resp.headers) {
        NSString* k = [NSString stringWithUTF8String:kv.first.utf8().data()];
        NSString* v = [NSString stringWithUTF8String:kv.second.utf8().data()];
        if (k && v && ![k hasPrefix:@":"])  // skip :status / pseudo-headers
            respHeaders[k] = v;
    }
    NSHTTPURLResponse* nsResp = [[NSHTTPURLResponse alloc] initWithURL:url
        statusCode:resp.statusCode HTTPVersion:@"HTTP/3.0" headerFields:respHeaders];
    [[proto client] URLProtocol:proto didReceiveResponse:nsResp cacheStoragePolicy:NSURLCacheStorageNotAllowed];
    if (!resp.body.isEmpty()) {
        NSData* bodyData = [NSData dataWithBytes:resp.body.span().data() length:resp.body.size()];
        [[proto client] URLProtocol:proto didLoadData:bodyData];
    }
    [[proto client] URLProtocolDidFinishLoading:proto];
    WTFLogAlways("[Wave29-499.321/URLPROTOCOL] HTTP/3 SUCCESS — status=%d bodyLen=%zu delivered via QUIC over SOCKS5 §7",
        resp.statusCode, resp.body.size());
    return YES;
}
WTF_ALLOW_UNSAFE_BUFFER_USAGE_END

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

    // Wave .321 diagnostic — is canInitWithRequest even called for real page loads?
    {
        NSURL* u = request.URL;
        WTFLogAlways("[Wave29-499.321/canInit] called for %s://%s%s flagActive=%d",
            [(u.scheme ?: @"?") UTF8String], [(u.host ?: @"?") UTF8String],
            [(u.path ?: @"") UTF8String], WebKit::g_driftstackCustomSocks5Active.load(std::memory_order_relaxed));
    }

    if (!WebKit::g_driftstackCustomSocks5Active.load(std::memory_order_relaxed))
        return NO;

    // Only intercept HTTP/HTTPS. WebSocket (ws/wss) has its own
    // NSURLProtocol subclass; file/data/blob schemes don't need SOCKS5.
    NSURL *url = request.URL;
    NSString *scheme = url.scheme.lowercaseString;
    if (![scheme isEqualToString:@"http"] && ![scheme isEqualToString:@"https"])
        return NO;

    // Wave 29-397 Slice 16.4.b.7.b: HTTPS-skip toggle for QUIC interpose
    // empirical testing. When DRIFTSTACK_URLPROTOCOL_HTTPS_SKIP=1, this
    // gate declines HTTPS requests so they flow through CFNetwork's
    // normal NSURLSession stack — which can attempt h3 ALPN negotiation
    // and trigger the DriftstackQuicInterpose dylib (Slice 16.4.b.5/.6).
    //
    // Known trade-off: when HTTPS-skip is active, TCP-only HTTPS
    // requests (no h3 ALPN from server) flow direct via CFNetwork, with
    // CFNetwork SOCKS5 disarmed (Wave 29-396 sub-1.9.c, to prevent
    // double-routing). NOTE (W2309): this is NOT an IP leak — the W2277
    // egress fail-closed (the mDNSResponder mach-lookup DENY in the
    // NetworkProcess sandbox) makes EVERY direct CFNetwork/nw_connection
    // egress FAIL, even by literal IP, so a disarmed-SOCKS5 direct request
    // cannot reach the network at all. The residual is FUNCTIONAL, not a
    // privacy leak: with HTTPS-skip on, TCP-only HTTPS servers (no h3) get
    // a failed request rather than proxy routing. Future Slice 16.4.b.7.c
    // re-arms CFNetwork SOCKS5 when HTTPS-skip is set so TCP-only HTTPS
    // routes through the proxy (h3 via interpose, TCP via CFNetwork SOCKS5).
    // Until then keep HTTPS-skip OFF in production (default); the
    // np-env-forwarding-guard flags it if added to the prod launch-env.
    //
    // Default OFF — URLProtocol keeps Wave 29-396 sub-1.9.a behavior.
    if ([scheme isEqualToString:@"https"]) {
        const char* httpsSkip = getenv("DRIFTSTACK_URLPROTOCOL_HTTPS_SKIP");
        if (httpsSkip && httpsSkip[0] == '1') {
            static bool loggedOnce = false;
            if (!loggedOnce) {
                loggedOnce = true;
                WTFLogAlways("[Driftstack-EG-WK-1.8/SOCK5-URLPROTOCOL] HTTPS-skip ACTIVE — DRIFTSTACK_URLPROTOCOL_HTTPS_SKIP=1; HTTPS deferred to CFNetwork for h3 interpose path");
            }
            return NO;
        }
    }

    // Wave 29-499.273 — bypass SOCKS5 for loopback + private-network
    // hostnames. Local test harnesses (sink-server on 127.0.0.1, dev
    // containers on 10/172.16/192.168) can't be reached via an internet
    // SOCKS5 proxy (proxy returns REP=0x03 'Network unreachable').
    // Matches iPhone Safari behavior — iOS bypasses VPN/proxy for
    // private-RFC1918 + loopback by default.
    NSString *host = url.host.lowercaseString;
    if ([host isEqualToString:@"localhost"]
        || [host hasPrefix:@"127."]
        || [host isEqualToString:@"::1"]
        || [host hasPrefix:@"10."]
        || [host hasPrefix:@"192.168."]
        || ([host hasPrefix:@"172."]
            && ({
                NSArray *parts = [host componentsSeparatedByString:@"."];
                BOOL is172 = NO;
                if (parts.count == 4) {
                    int second = [parts[1] intValue];
                    is172 = (second >= 16 && second <= 31);
                }
                is172;
            }))) {
        static bool loggedLoopbackOnce = false;
        if (!loggedLoopbackOnce) {
            loggedLoopbackOnce = true;
            WTFLogAlways("[Driftstack-EG-WK-1.8/Wave29-499.273] bypass SOCKS5 for loopback/private host '%s' (direct via CFNetwork)",
                host.UTF8String);
        }
        return NO;
    }

    // Wave 29-396 sub-slice 1.9.b: ACTIVATE — claim the request for
    // SOCKS5 transport via DriftstackSocks5Client.
    return YES;
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

    // Wave 29-499.321 — HTTP/3 fast-path for https origins. If the QUIC/h3
    // request through the SOCKS5 §7 relay succeeds, the response is delivered
    // here and we're done; otherwise fall through to the TCP h1/h2 path below.
    if ([scheme isEqualToString:@"https"] && driftstackTryHttp3(self, url, host, actualPort))
        return;

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
    // Wave 29-396 sub-slice 1.7.3: RFC 1929 §2 user/pass via env vars.
    // DRIFTSTACK_SOCKS5_USER + DRIFTSTACK_SOCKS5_PASS populate creds.
    // Empty → NO_AUTH method (RFC 1928 §3 method 0x00). Set → triggers
    // USERNAME_PASSWORD method (0x02) negotiation in performHandshake().
    const char* userEnv = getenv("DRIFTSTACK_SOCKS5_USER");
    const char* passEnv = getenv("DRIFTSTACK_SOCKS5_PASS");
    if (userEnv && userEnv[0] && passEnv) {
        creds.username = WTF::String::fromUTF8(userEnv);
        creds.password = WTF::String::fromUTF8(passEnv);
        // W1921: redact the username VALUE from the log (a credential-half identifying the
        // customer proxy account) — log only its length, matching the password (pass-len).
        WTFLogAlways("[Driftstack-EG-WK-1.8/SOCK5-URLPROTOCOL] sub-1.7.3: RFC 1929 user/pass creds set (user-len=%u, pass-len=%u)",
            unsigned(creds.username.utf8().length()), unsigned(creds.password.utf8().length()));
    }

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

    // Wave 29-396 sub-slice 1.8: enable TLS for HTTPS scheme via CFStream
    // SSL settings dict. SNI populated from URL host. Cert validation ON
    // (v1.0 default — fail loud on bad certs, customer can disable per-
    // session via future DRIFTSTACK_TLS_INSECURE env if needed).
    if ([scheme isEqualToString:@"https"]) {
        NSDictionary *sslSettings = @{
            (NSString *)kCFStreamSSLLevel: (NSString *)kCFStreamSocketSecurityLevelNegotiatedSSL,
            (NSString *)kCFStreamSSLPeerName: host,
            (NSString *)kCFStreamSSLValidatesCertificateChain: @YES,
        };
        if (!CFReadStreamSetProperty(readStreamRef, kCFStreamPropertySSLSettings, (CFTypeRef)sslSettings)
            || !CFWriteStreamSetProperty(writeStreamRef, kCFStreamPropertySSLSettings, (CFTypeRef)sslSettings)) {
            WTFLogAlways("[Driftstack-EG-WK-1.8/SOCK5-URLPROTOCOL] sub-1.8: CFStreamSetProperty SSL settings failed for %s", [host UTF8String]);
            CFRelease(readStreamRef);
            CFRelease(writeStreamRef);
            [[self client] URLProtocol:self didFailWithError:[NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorSecureConnectionFailed userInfo:nil]];
            return;
        }
        WTFLogAlways("[Driftstack-EG-WK-1.8/SOCK5-URLPROTOCOL] sub-1.8: TLS enabled for HTTPS %s (SNI + cert validate)", [host UTF8String]);
    }

    // Sub-slice 1.7.2.b stops here. Streams are constructed but not yet
    // opened/driven. Sub-slice 1.7.2.c serializes HTTP/1.1 request bytes
    // + writes to writeStream + reads response from readStream. Sub-slice
    // 1.7.2.d adds lifetime management via class ivars so the
    // DriftstackSocks5Client outlives this function call.
    // Sub-slice 1.7.2.d: store streams in ivars for lifetime past startLoading.
    _readStream = readStreamRef;
    _writeStream = writeStreamRef;

    // Sub-slice 1.7.2.c: HTTP/1.1 request serialization + write.
    if (!CFWriteStreamOpen(_writeStream) || !CFReadStreamOpen(_readStream)) {
        WTFLogAlways("[Driftstack-EG-WK-1.8/SOCK5-URLPROTOCOL] sub-1.7.2.c: CFStream open failed");
        [[self client] URLProtocol:self didFailWithError:[NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorCannotConnectToHost userInfo:nil]];
        return;
    }

    // Wait for write stream to enter Open state. Background thread,
    // synchronous spin is acceptable for connect-handshake duration.
    for (int i = 0; i < 50; i++) {  // ~5s max
        if (CFWriteStreamGetStatus(_writeStream) == kCFStreamStatusOpen)
            break;
        [NSThread sleepForTimeInterval:0.1];
    }
    if (CFWriteStreamGetStatus(_writeStream) != kCFStreamStatusOpen) {
        WTFLogAlways("[Driftstack-EG-WK-1.8/SOCK5-URLPROTOCOL] sub-1.7.2.c: write stream not Open after 5s; status=%ld",
            CFWriteStreamGetStatus(_writeStream));
        [[self client] URLProtocol:self didFailWithError:[NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorTimedOut userInfo:nil]];
        return;
    }

    // Build HTTP/1.1 request bytes.
    NSString *method = self.request.HTTPMethod ?: @"GET";
    NSString *path = url.path;
    if (path.length == 0) path = @"/";
    if (url.query.length > 0) path = [NSString stringWithFormat:@"%@?%@", path, url.query];

    NSMutableString *requestStr = [NSMutableString stringWithFormat:@"%@ %@ HTTP/1.1\r\n", method, path];
    [requestStr appendFormat:@"Host: %@\r\n", host];
    [requestStr appendString:@"Connection: close\r\n"];  // simplest: one request per connection
    NSDictionary *headers = self.request.allHTTPHeaderFields ?: @{};
    for (NSString *key in headers) {
        // Skip Host (already added) + Connection (overridden)
        NSString *lowerKey = key.lowercaseString;
        if ([lowerKey isEqualToString:@"host"] || [lowerKey isEqualToString:@"connection"])
            continue;
        [requestStr appendFormat:@"%@: %@\r\n", key, headers[key]];
    }
    [requestStr appendString:@"\r\n"];

    NSData *requestData = [requestStr dataUsingEncoding:NSUTF8StringEncoding];
    NSData *body = self.request.HTTPBody;
    if (body.length > 0) {
        NSMutableData *combined = [NSMutableData dataWithData:requestData];
        [combined appendData:body];
        requestData = combined;
    }

    // Write request bytes via helper (handles WTF_ALLOW_UNSAFE_BUFFER_USAGE).
    CFIndex written = writeAllToCFStream(_writeStream, requestData);
    if (written < 0) {
        WTFLogAlways("[Driftstack-EG-WK-1.8/SOCK5-URLPROTOCOL] sub-1.7.2.c: writeAllToCFStream failed");
        [[self client] URLProtocol:self didFailWithError:[NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorNetworkConnectionLost userInfo:nil]];
        return;
    }

    WTFLogAlways("[Driftstack-EG-WK-1.8/SOCK5-URLPROTOCOL] sub-1.7.2.c: wrote %lu HTTP request bytes for %@ %s:%d via SOCKS5. Reading response...",
        (unsigned long)requestData.length, method, [host UTF8String], actualPort);

    // Sub-slice 1.7.2.e: read response from CFReadStream + parse + notify.
    NSData *responseBytes = readAllFromCFStream(_readStream);
    if (!responseBytes || responseBytes.length == 0) {
        WTFLogAlways("[Driftstack-EG-WK-1.8/SOCK5-URLPROTOCOL] sub-1.7.2.e: empty response or read error");
        [[self client] URLProtocol:self didFailWithError:[NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorNetworkConnectionLost userInfo:nil]];
        return;
    }

    // Find \r\n\r\n header/body boundary
    NSData *boundary = [@"\r\n\r\n" dataUsingEncoding:NSUTF8StringEncoding];
    NSRange boundaryRange = [responseBytes rangeOfData:boundary options:0 range:NSMakeRange(0, responseBytes.length)];
    if (boundaryRange.location == NSNotFound) {
        WTFLogAlways("[Driftstack-EG-WK-1.8/SOCK5-URLPROTOCOL] sub-1.7.2.e: no \\r\\n\\r\\n header boundary in %lu bytes", (unsigned long)responseBytes.length);
        [[self client] URLProtocol:self didFailWithError:[NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorCannotParseResponse userInfo:nil]];
        return;
    }

    NSData *headerBytes = [responseBytes subdataWithRange:NSMakeRange(0, boundaryRange.location)];
    NSUInteger bodyOffset = boundaryRange.location + boundaryRange.length;
    NSData *bodyBytes = [responseBytes subdataWithRange:NSMakeRange(bodyOffset, responseBytes.length - bodyOffset)];
    NSString *headerStr = [[NSString alloc] initWithData:headerBytes encoding:NSUTF8StringEncoding];

    NSArray<NSString *> *headerLines = [headerStr componentsSeparatedByString:@"\r\n"];
    if (headerLines.count < 1) {
        [[self client] URLProtocol:self didFailWithError:[NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorCannotParseResponse userInfo:nil]];
        return;
    }

    // Parse status line: HTTP/1.1 200 OK
    NSString *statusLine = headerLines[0];
    NSArray<NSString *> *statusParts = [statusLine componentsSeparatedByString:@" "];
    NSInteger statusCode = (statusParts.count >= 2) ? statusParts[1].integerValue : 0;
    NSString *httpVersion = (statusParts.count >= 1) ? statusParts[0] : @"HTTP/1.1";

    // Parse response headers (different variable name to avoid shadowing
    // request `headers` from sub-slice 1.7.2.c)
    NSMutableDictionary<NSString *, NSString *> *respHeaders = [NSMutableDictionary dictionary];
    for (NSUInteger i = 1; i < headerLines.count; i++) {
        NSString *line = headerLines[i];
        NSRange colon = [line rangeOfString:@":"];
        if (colon.location == NSNotFound) continue;
        NSString *key = [line substringToIndex:colon.location];
        NSString *val = [[line substringFromIndex:colon.location + 1] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
        respHeaders[key] = val;
        // Wave 29-499.321 — learn h3 support from Alt-Svc (RFC 7838). If this
        // https origin advertises h3, remember it so subsequent requests take
        // the QUIC fast-path. We only need to detect the "h3" token; the
        // authority/port advertised is assumed to be the same origin (the
        // common case for h3=":443").
        if ([key.lowercaseString isEqualToString:@"alt-svc"]
            && [scheme isEqualToString:@"https"]
            && [val rangeOfString:@"h3"].location != NSNotFound) {
            driftstackRememberH3Host(host, actualPort);
            WTFLogAlways("[Wave29-499.321/URLPROTOCOL] learned h3 for %s:%d via Alt-Svc: %s",
                [host UTF8String], actualPort, [val UTF8String]);
        }
    }

    NSHTTPURLResponse *response = [[NSHTTPURLResponse alloc] initWithURL:url statusCode:statusCode HTTPVersion:httpVersion headerFields:respHeaders];

    WTFLogAlways("[Driftstack-EG-WK-1.8/SOCK5-URLPROTOCOL] sub-1.7.2.e SUCCESS — %s %s:%d via SOCKS5 → HTTP %ld, %lu body bytes",
        [method UTF8String], [host UTF8String], actualPort, (long)statusCode, (unsigned long)bodyBytes.length);

    [[self client] URLProtocol:self didReceiveResponse:response cacheStoragePolicy:NSURLCacheStorageNotAllowed];
    if (bodyBytes.length > 0)
        [[self client] URLProtocol:self didLoadData:bodyBytes];
    [[self client] URLProtocolDidFinishLoading:self];
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
