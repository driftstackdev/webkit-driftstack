/*
 * DriftstackHttp2.h — Wave 29-499.140 (Task #104 Phase 2)
 *
 * Minimal RFC 7540 HTTP/2 client on top of an SSL* connection (from
 * BoringSSL TLS 1.3 layer via DriftstackNetworkLoader). Implements:
 *
 *  - Connection preface (24-byte PRI sequence)
 *  - Frame send/receive (9-byte header + payload)
 *  - SETTINGS frame with iPhone 17 / Safari 26.4 values + order (BS capture
 *    Wave .323; emit order is 2,3,4,9 — MAX_CONCURRENT before INITIAL_WINDOW):
 *      ENABLE_PUSH = 0            (id 2)
 *      MAX_CONCURRENT_STREAMS = 100   (id 3)
 *      INITIAL_WINDOW_SIZE = 2097152  (id 4 — 2MB, NOT 4194304; that was stale)
 *      NO_RFC7540_PRIORITIES = 1  (id 9)
 *  - WINDOW_UPDATE increment = 10420225 (= target 10485760 - default 65535)
 *  - HEADERS frame with iPhone pseudo-header order (m,s,a,p — authority BEFORE path)
 *  - DATA frames (request body, response body)
 *  - HPACK header encoding (RFC 7541) with static table only initially
 *
 * Akamai fingerprint target (real iPhone 17 capture via tls.peet.ws; W95/BS .323;
 * hash c52879e43202aeb92740be6e8c86ea96):
 *   2:0;3:100;4:2097152;9:1|10420225|0|m,s,a,p
 *
 * Used by DriftstackNetworkLoader when ALPN selects "h2". Provides
 * iPhone-Safari-bit-identical HTTP/2 wire fingerprint.
 *
 * Phase 2 scope: single request/response per connection (one stream).
 * Phase 2.5: multi-stream connection reuse, stream multiplexing.
 */

#pragma once

#if PLATFORM(DRIFTSTACK)

#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <stdint.h>
#include <wtf/Condition.h>
#include <wtf/Forward.h>
#include <wtf/HashMap.h>
#include <wtf/Lock.h>
#include <wtf/MonotonicTime.h>
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

    // Wave 29-499.350 — optional INCREMENTAL delivery (Server-Sent Events /
    // EventSource). When onBodyChunk is set, the one-shot execute does NOT
    // accumulate resp.body; it fires onHeaders once when the response HEADERS
    // arrive, then onBodyChunk per DATA frame, running until the stream ends or
    // a callback returns false (cancellation). This lets PathB v2 carry an
    // infinite text/event-stream over the iPhone TLS path instead of bypassing
    // to CFNetwork (Mac JA4). Unset (the default) = the buffer-all behavior.
    // Streaming is used ONLY on the one-shot path (the pooled session ignores
    // these — SSE always takes a dedicated connection).
    std::function<bool(int statusCode, const Vector<std::pair<String, String>>&)> onHeaders;
    std::function<bool(std::span<const uint8_t>)> onBodyChunk;
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

// Wave 29-499.352 — RFC 8441 WebSocket-over-HTTP/2 (Extended CONNECT). Opens a
// single long-lived h2 stream with :method=CONNECT + :protocol=websocket and
// tunnels arbitrary bytes (the caller layers RFC 6455 framing on top — same
// framing as the h1.1 path, only the handshake differs). Reuses the engine's
// HPACK + frame helpers. The connection (TLS, h2-ALPN) is owned by the caller and
// supplied via the transport read/write fns.
struct DriftstackHttp2ConnectRequest {
    String authority;   // "host:port"
    String path;        // "/chat?x=1"
    String protocol;    // "websocket"
    Vector<std::pair<String, String>> extraHeaders;  // sec-websocket-version, origin, sec-websocket-protocol, cookie…
};

class DriftstackHttp2ConnectStream {
public:
    explicit DriftstackHttp2ConnectStream(const DriftstackHttp2Transport&);
    ~DriftstackHttp2ConnectStream();

    // Sends preface+SETTINGS+WINDOW_UPDATE + the CONNECT HEADERS, then reads
    // frames until the response HEADERS. Returns the :status (200 = WS tunnel
    // open) or -1 on transport/RST/GOAWAY error. Records whether the server
    // advertised SETTINGS_ENABLE_CONNECT_PROTOCOL.
    int open(const DriftstackHttp2ConnectRequest&);
    bool serverEnabledConnectProtocol() const { return m_serverEnabledConnectProtocol; }
    const Vector<std::pair<String, String>>& responseHeaders() const { return m_responseHeaders; }

    // Tunnel read: returns the next inbound DATA payload bytes (≤ maxLen), 0 on
    // clean stream end, -1 on error. Processes SETTINGS/PING/WINDOW_UPDATE inline
    // and replenishes our receive window so long streams don't stall.
    int readData(uint8_t* buf, size_t maxLen);
    // Tunnel write: sends bytes as an h2 DATA frame on the stream, chunked to the
    // peer max-frame-size and blocking on the send window (RFC 7540 §6.9).
    bool sendData(const uint8_t* data, size_t len);
    // Sends END_STREAM (empty DATA) to close the tunnel write side.
    void close();

private:
    DriftstackHttp2Transport m_transport;
    Lock m_writeLock;
    Condition m_windowCond;            // signals send-window growth
    int64_t m_sendWindow { 65535 };    // our stream send window (guarded by m_writeLock)
    uint32_t m_peerInitialWindow { 65535 };
    uint64_t m_recvSinceUpdate { 0 };      // bytes received since our last STREAM WINDOW_UPDATE (toward window/4)
    uint64_t m_connRecvSinceUpdate { 0 };  // bytes received since our last CONNECTION WINDOW_UPDATE (toward window/2)
    Vector<uint8_t> m_dataLeftover;    // inbound DATA decoded but not yet returned by readData
    Vector<std::pair<String, String>> m_responseHeaders;  // CONNECT response headers (non-pseudo)
    bool m_serverEnabledConnectProtocol { false };
    bool m_streamEnded { false };
    bool m_closed { false };
    static constexpr uint32_t kStreamId = 1;
};

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

    // a74622fc Phase 1 — async-delivery restructure (root cause of the westernunion/
    // facebook heavy-multi-origin-page hang over a non-UDP proxy: execute() pins a GCD
    // worker thread for the ENTIRE response, which self-starves the shared blocking-I/O
    // worker pool once enough slow/many-origin streams are in flight simultaneously —
    // "NO real-iOS analog" since NSURLSession is event-driven and never pins a thread
    // per in-flight request). submitAsync sends the SAME HEADERS(+DATA) bytes as
    // execute() (factored via sendRequestFrames — byte-identical wire order, zero
    // fingerprint risk) and returns IMMEDIATELY, freeing the calling worker thread.
    // Delivery happens via callbacks invoked from the session's existing reader thread
    // (no new threads) at the same 3 mutate points readerLoop already has. Additive:
    // execute() is completely unchanged; only used when DRIFTSTACK_EGRESS_ASYNC_DELIVERY=1.
    struct AsyncStreamCallbacks {
        std::function<void(int statusCode, const Vector<std::pair<String, String>>&)> onHeaders;
        std::function<void(const uint8_t* data, size_t length)> onData;
        // failed=true + a non-empty errorMessage on any failure path (RST_STREAM, GOAWAY of
        // an unprocessed stream, dead connection, idle timeout); failed=false + empty on a
        // clean END_STREAM. Called EXACTLY once, terminally — safe to release/destroy state.
        std::function<void(bool failed, const String& errorMessage)> onComplete;
    };
    // Returns the allocated stream id (0 on immediate send failure — onComplete is invoked
    // synchronously with failed=true before returning in that case, never left silent).
    uint32_t submitAsync(const DriftstackHttp2Request&, AsyncStreamCallbacks&&);
    // Removes the callback stream + sends RST_STREAM (CANCEL); safe to call at most once,
    // safe to call after the stream already completed (no-op then).
    void cancelStream(uint32_t streamId);

    // True while the connection is healthy + accepting new streams (no GOAWAY /
    // transport error / max-stream-id exhaustion).
    bool isAlive();

private:
    DriftstackHttp2Session(std::unique_ptr<DriftstackTLS13Client>&&, std::unique_ptr<DriftstackSocks5Client>&&);
    bool sendPrefaceAndSettings();
    void readerLoop();
    // Shared by execute() and submitAsync(): allocates the next stream id and writes
    // HEADERS(+DATA) UNDER m_writeLock+m_lock atomically (Wave 29-499.357 ordering
    // invariant — MUST stay identical for both callers). Returns 0 + sets resp.failed
    // on a send failure (session already marked !alive by the time it returns false).
    uint32_t sendRequestFrames(const DriftstackHttp2Request&, DriftstackHttp2Response& outFailureResp);

    struct Stream {
        DriftstackHttp2Response resp;
        bool complete { false };
        bool failed { false };
        // Unset (default) for the execute()-blocking path — completely inert, zero behavior
        // change. Set for submitAsync() streams: the READER thread (not a caller) owns
        // removal from m_streams once onComplete fires (execute() streams are removed by
        // the blocking caller instead, as today).
        std::optional<AsyncStreamCallbacks> asyncCallbacks;
        // onHeaders is delivered as soon as the HEADERS frame arrives (not deferred to
        // completion, so WebCore can start as early as a real network stack would); every
        // later finish path (DATA-end, RST, GOAWAY, dead-connection) must check this before
        // calling onHeaders again — it may fire on a completion path that races ahead of, or
        // instead of, the dedicated HEADERS-block delivery.
        bool asyncHeadersDelivered { false };
        // a74622fc risk (d): submitAsync has no caller-side wait loop to extend/enforce the
        // idle-progress deadline, so the reader ports it here — updated on every HEADERS/DATA
        // notify point, swept opportunistically each time the reader processes a frame.
        MonotonicTime idleDeadline;
        // egress audit wxzzaphvp #10 — per-stream bytes consumed since this stream's last
        // WINDOW_UPDATE, for the iOS-faithful batched cadence (replenish at window/4). The
        // one-shot/ConnectStream readers already batch; the pooled reader used to emit a WU
        // per DATA frame (a non-Safari wire tell) — this tracks the stream accumulator so the
        // pooled path matches. Guarded by m_lock (only touched in the reader's DATA handler).
        uint64_t recvSinceWU { 0 };
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
    // egress audit wxzzaphvp #10 — connection-level bytes consumed since the last CONNECTION
    // WINDOW_UPDATE (stream 0), summed across ALL multiplexed streams, for the iOS-faithful
    // batched cadence (replenish at window/2). Guarded by m_lock (accumulated in the reader's
    // DATA handler alongside m_streams).
    uint64_t m_connRecvSinceWU WTF_GUARDED_BY_LOCK(m_lock) { 0 };
    RefPtr<Thread> m_readerThread;
};

} // namespace WebKit

#endif // PLATFORM(DRIFTSTACK)
