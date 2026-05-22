/*
 * DriftstackHttp2.h — Wave 29-499.140 (Task #104 Phase 2)
 *
 * Minimal RFC 7540 HTTP/2 client on top of an SSL* connection (from
 * BoringSSL TLS 1.3 layer via DriftstackNetworkLoader). Implements:
 *
 *  - Connection preface (24-byte PRI sequence)
 *  - Frame send/receive (9-byte header + payload)
 *  - SETTINGS frame with iPhone Safari 26.0 values:
 *      ENABLE_PUSH = 0
 *      INITIAL_WINDOW_SIZE = 4194304
 *      MAX_CONCURRENT_STREAMS = 100
 *      NO_RFC7540_PRIORITIES = 1
 *  - WINDOW_UPDATE increment = 10485760 (iPhone reference)
 *  - HEADERS frame with iPhone pseudo-header order (m,s,p,a)
 *  - DATA frames (request body, response body)
 *  - HPACK header encoding (RFC 7541) with static table only initially
 *
 * Akamai fingerprint target (from real iPhone capture via tls.peet.ws):
 *   2:0;4:4194304;3:100;9:1|10485760|0|m,s,p,a
 *
 * Used by DriftstackNetworkLoader when ALPN selects "h2". Provides
 * iPhone-Safari-bit-identical HTTP/2 wire fingerprint.
 *
 * Phase 2 scope: single request/response per connection (one stream).
 * Phase 2.5: multi-stream connection reuse, stream multiplexing.
 */

#pragma once

#if PLATFORM(DRIFTSTACK)

#include <stdint.h>
#include <wtf/Forward.h>
#include <wtf/Vector.h>
#include <wtf/text/WTFString.h>

namespace WebKit {

struct DriftstackHttp2Request {
    String method;         // "GET", "POST", etc.
    String scheme;         // "https"
    String authority;      // "host:port" or just "host"
    String path;           // "/" or "/api?x=1"
    Vector<std::pair<String, String>> extraHeaders;  // Non-pseudo headers
    Vector<uint8_t> body;  // Empty for GET; encoded for POST
};

struct DriftstackHttp2Response {
    int statusCode { 0 };
    Vector<std::pair<String, String>> headers;
    Vector<uint8_t> body;
    bool failed { false };
    String errorMessage;
};

// Execute one HTTP/2 request over an SSL-wrapped fd. The SSL connection
// must already be established and have negotiated "h2" via ALPN. Caller
// is responsible for SSL_shutdown + SSL_free.
//
// boringSSL parameter is a void* SSL* (typed as void* to avoid header
// pollution; cast back internally to SSL* via the dlsym table).
//
// Returns DriftstackHttp2Response with body + headers. On failure,
// response.failed=true and errorMessage describes the issue.
DriftstackHttp2Response driftstackHttp2Execute(void* boringSSL, const DriftstackHttp2Request& request);

} // namespace WebKit

#endif // PLATFORM(DRIFTSTACK)
