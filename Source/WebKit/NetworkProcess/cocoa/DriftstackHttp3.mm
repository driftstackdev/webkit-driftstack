/*
 * DriftstackHttp3.mm — Wave 29-499.142 (Task #104 Phase 3)
 *
 * Phase 3 scaffold. driftstackHttp3Execute is a stub returning failure
 * until ngtcp2 integration is wired up. The function exists so callers
 * (DriftstackNetworkLoader) can dispatch to it when ALPN selects "h3"
 * — the call will return failed=true and trigger fallback to h2.
 *
 * Full Phase 3 implementation tracked in:
 *   1. ngtcp2 dlopen + dlsym resolution (mirror Phase 1.5b BoringSSL pattern)
 *   2. Wire BoringSSL QUIC API (SSL_set_quic_method, etc.)
 *   3. SOCKS5 UDP_ASSOCIATE setup + §7 framing for QUIC packets
 *   4. ngtcp2 event loop integration
 *   5. HTTP/3 framing + QPACK encoder
 *   6. QPACK decoder for response headers
 *   7. iPhone QUIC transport params capture + injection
 */

#import "config.h"
#import "DriftstackHttp3.h"

#if PLATFORM(DRIFTSTACK)

#import <stdlib.h>
#import <wtf/Assertions.h>

namespace WebKit {

DriftstackHttp3Response driftstackHttp3Execute(void* /*socks5UdpRelay*/, const DriftstackHttp3Request& /*request*/)
{
    DriftstackHttp3Response resp;
    resp.failed = true;
    resp.errorMessage = "HTTP/3 not yet implemented; falling back to h2/h1"_s;

    static bool loggedOnce = false;
    if (!loggedOnce) {
        loggedOnce = true;
        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.142] HTTP/3 scaffold — full ngtcp2 + BoringSSL QUIC + iPhone params + QPACK pending implementation. Returning failed; caller falls back to h2.");
    }
    return resp;
}

bool driftstackHttp3Enabled()
{
    const char* env = getenv("DRIFTSTACK_PATHB_V2_H3");
    return env && env[0] == '1';
}

} // namespace WebKit

#endif // PLATFORM(DRIFTSTACK)
