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

#include <memory>
#include <stdint.h>
#include <wtf/Condition.h>
#include <wtf/Forward.h>
#include <wtf/HashMap.h>
#include <wtf/Lock.h>
#include <wtf/ThreadSafeRefCounted.h>
#include <wtf/Threading.h>
#include <wtf/Vector.h>
#include <wtf/text/WTFString.h>

namespace WebKit {

class DriftstackTLS13Client;
class DriftstackSocks5Client;

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

// Wave 29-499.193 — pluggable transport overload. Caller provides
// read/write callbacks; HTTP/2 runs over LibreSSL OR our DriftstackTLS13Client.
struct DriftstackHttp2Transport {
    void* ctx { nullptr };
    int (*readFn)(void* ctx, uint8_t* buf, size_t n) { nullptr };
    int (*writeFn)(void* ctx, const uint8_t* buf, size_t n) { nullptr };
};
DriftstackHttp2Response driftstackHttp2ExecuteVia(const DriftstackHttp2Transport& transport,
                                                  const DriftstackHttp2Request& request);

// Wave 29-499.331 — decode Content-Encoding (gzip/deflate/br) in body IN-PLACE and strip the
// content-encoding/content-length headers. Idempotent: a no-op when there's no content-encoding
// header (so it's safe to call again after an engine path already decoded). Exposed so the loader
// can run it at the single delivery chokepoint, guaranteeing NO raw-compressed body ever reaches
// WebKit regardless of which h2/h3 path produced the response (the Twilio controllers.js/directives.js
// "" gzip-magic SyntaxError came from a path that skipped decode).
void driftstackDecodeContentEncoding(Vector<uint8_t>& body, Vector<std::pair<String, String>>& headers);

// Wave 29-499.321 (Phase 2.5) — PERSISTENT, MULTIPLEXED HTTP/2 session for
// connection pooling. One session per origin owns the established h2 transport
// (preface + SETTINGS sent once) and a background reader thread that demuxes
// frames to per-stream buffers. execute() is thread-safe + concurrent: many
// loader threads submit requests on the SAME connection, each on its own h2
// stream — exactly like a real browser (no per-request handshake). Used by the
// connection pool in DriftstackNetworkLoader when ALPN selects "h2".
class DriftstackHttp2Session : public ThreadSafeRefCounted<DriftstackHttp2Session> {
public:
    // Create over an established, h2-ALPN-negotiated TLS connection. The session
    // takes OWNERSHIP of the TLS + SOCKS5 clients so the connection lives exactly
    // as long as the session is referenced (pool entry + any in-flight execute) —
    // makes pooling lifetime-safe. Sends preface+SETTINGS+WINDOW_UPDATE and starts
    // the reader thread. Returns nullptr on setup failure.
    static RefPtr<DriftstackHttp2Session> create(std::unique_ptr<DriftstackTLS13Client>&&,
        std::unique_ptr<DriftstackSocks5Client>&&);
    ~DriftstackHttp2Session();

    // Submit one request on a new stream; blocks the caller until the response
    // completes (or error / timeout). Thread-safe; concurrent calls multiplex.
    DriftstackHttp2Response execute(const DriftstackHttp2Request&);

    // True while the connection is healthy + accepting new streams (no GOAWAY /
    // transport error / max-stream-id exhaustion).
    bool isAlive();

private:
    DriftstackHttp2Session(std::unique_ptr<DriftstackTLS13Client>&&, std::unique_ptr<DriftstackSocks5Client>&&);
    bool sendPrefaceAndSettings();
    void readerLoop();

    struct Stream {
        DriftstackHttp2Response resp;
        bool complete { false };
        bool failed { false };
    };

    std::unique_ptr<DriftstackTLS13Client> m_tls;       // owned; outlives the reader
    std::unique_ptr<DriftstackSocks5Client> m_socks5;   // owned; holds the proxy fd
    DriftstackHttp2Transport m_transport;               // ctx = m_tls.get()
    Lock m_writeLock;   // serializes transport writes (HEADERS/DATA/ACKs)
    Lock m_lock;        // guards m_streams + m_alive + m_nextStreamId
    Condition m_cond;   // signals a stream completing/failing
    HashMap<uint32_t, std::unique_ptr<Stream>> m_streams WTF_GUARDED_BY_LOCK(m_lock);
    uint32_t m_nextStreamId WTF_GUARDED_BY_LOCK(m_lock) { 1 };
    bool m_alive WTF_GUARDED_BY_LOCK(m_lock) { true };
    RefPtr<Thread> m_readerThread;
};

} // namespace WebKit

#endif // PLATFORM(DRIFTSTACK)
