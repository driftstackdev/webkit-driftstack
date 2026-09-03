/*
 * DriftstackHttp3.h — Wave 29-499.142 (Task #104 Phase 3)
 *
 * HTTP/3 + QUIC client for Driftstack SOCKS5 customer-proxy mode.
 * Provides iPhone-Safari-bit-identical QUIC + HTTP/3 wire fingerprint.
 *
 * Architecture:
 *   ngtcp2 (libngtcp2.dylib /opt/homebrew/lib) — QUIC state machine
 *   BoringSSL via dlsym (from libwebrtc.dylib) — TLS within QUIC
 *   SOCKS5 UDP_ASSOCIATE relay (existing Wave 29-499.99-106 infra) — transport
 *   HTTP/3 framing (RFC 9114) + QPACK headers (RFC 9204) — application
 *
 * Flow:
 *   1. SOCKS5 UDP_ASSOCIATE to get UDP relay endpoint (BND.ADDR:BND.PORT)
 *   2. ngtcp2_conn_client_new — create QUIC connection state
 *   3. SSL_set_quic_method — wire BoringSSL TLS to ngtcp2 callbacks
 *   4. Configure iPhone-matched transport parameters:
 *      - initial_max_data, initial_max_stream_data_bidi_local/remote,
 *      - initial_max_streams_bidi/uni
 *      - max_idle_timeout, max_udp_payload_size
 *      - ack_delay_exponent, max_ack_delay
 *      - active_connection_id_limit
 *   5. ALPN: "h3" — required for HTTP/3 negotiation
 *   6. Event loop:
 *      - ngtcp2_conn_write_pkt → generate QUIC packets
 *      - Wrap with SOCKS5 §7 UDP framing
 *      - sendto() to SOCKS5 UDP relay endpoint
 *      - recvfrom() → unwrap §7 → ngtcp2_conn_read_pkt
 *      - Process stream data → HTTP/3 frame parser
 *   7. HTTP/3 request:
 *      - QPACK encode HEADERS frame on bidi stream (id 0, 4, 8, ...)
 *      - Read DATA frames from peer-initiated unidi streams + bidi
 *   8. Close: ngtcp2_conn_handle_expiry + ngtcp2_conn_writev_stream
 *
 * Phase 3 scope: single h3 request over QUIC. Phase 3.5 adds multi-
 * stream multiplexing + 0-RTT resumption.
 *
 * iPhone Safari 26.0 QUIC transport params (TODO: capture from real
 * iPhone via tls.peet.ws/api/all with --http3 flag, or pcap analysis).
 */

#pragma once

#if PLATFORM(DRIFTSTACK)

#include <memory>
#include <stdint.h>
#include <wtf/Forward.h>
#include <wtf/Lock.h>
#include <wtf/ThreadSafeRefCounted.h>
#include <wtf/Vector.h>
#include <wtf/text/WTFString.h>

namespace WebKit {

struct DriftstackHttp3Request {
    String method;
    String scheme;         // "https" (h3 requires TLS)
    String authority;      // host:port or host
    String path;
    Vector<std::pair<String, String>> extraHeaders;
    Vector<uint8_t> body;
};

struct DriftstackHttp3Response {
    int statusCode { 0 };
    Vector<std::pair<String, String>> headers;
    Vector<uint8_t> body;
    bool failed { false };
    String errorMessage;
};

// Execute one HTTP/3 request via QUIC over SOCKS5 UDP_ASSOCIATE.
//
// Parameters:
//   socks5UdpRelay: void* opaque handle returned by SOCKS5 UDP_ASSOCIATE
//                    setup (existing infra from Wave 29-499.99-106).
//                    Caller owns + closes after.
//   request: full HTTP/3 request data.
//
// Returns DriftstackHttp3Response with body + headers. On failure,
// response.failed=true and errorMessage describes the issue.
DriftstackHttp3Response driftstackHttp3Execute(void* socks5UdpRelay, const DriftstackHttp3Request& request);

// Phase 3 gate: returns true if Phase 3 (HTTP/3) is enabled via
// DRIFTSTACK_PATHB_V2_H3=1 env. Default false until Phase 3 impl complete.
bool driftstackHttp3Enabled();

// T-5 — a COMPLETED QUIC handshake, recorded in the engine and drained by the integrated loader, which
// forwards it to the UI process. The NetworkProcess's own stderr goes to launchd, not to the daemon's
// pipe, so a marker logged here would never be observed (A3 measured 0 of 20 kept logs carrying any NP
// line, including one that fires unconditionally). Presence of the UI-process marker means MEASURED.
void driftstackHttp3RecordHandshakeObserved(const String& sni);
bool driftstackHttp3TakeHandshakeObservation(String& sniOut, uint64_t& idOut);

// Wave 29-499.321 — query the DNS HTTPS resource record (RFC 9460 type 65) for
// `host` THROUGH the SOCKS5 §7 relay (no local leak), and return true if it
// advertises HTTP/3 (alpn contains "h3"). This is how real Safari discovers h3
// for FIRST contact (before any Alt-Svc response header). Result cached per host.
bool driftstackHostAdvertisesH3ViaDns(const WTF::String& host);

// W2648 (founder no-UDP white-screen, audit udp-1/3/5) — the shared "the SOCKS5 proxy
// does NOT relay UDP" latch. Set once a genuine UDP_ASSOCIATE refusal/timeout is observed
// (NOT a TCP/auth/parse error — see the tri-state in driftstackQuicRawSocks5Associate);
// thereafter EVERY h3 entry point (DNS-RR gate, the Alt-Svc known-h3 gate in the loader,
// the request-path execute/session-create associates, and setAssumesHTTP3Capable) must
// consult it and choose h2/TCP — so a no-UDP proxy never re-incurs the ~4s associate stall
// that wedged the page (white screen, no error). UDP-capable proxies never set it → h3 path
// is byte-unchanged (founder's "do NOT mess with UDP proxies"). Exported for the cross-TU
// gates in DriftstackNetworkLoader.mm + NetworkDataTaskCocoa.mm.
bool driftstackUdpRelayKnownDown();
void driftstackMarkUdpRelayDown();
// W2752: an ASYNC UDP_ASSOCIATE probe that CONFIRMS a genuine relay clears the latch → the custom h3 path
// lights up for SUBSEQUENT connections (the first page already loaded conservatively on TCP, no ~3s stall).
void driftstackClearUdpRelayDown();

// Wave 29-499.322 (Phase 3.5) — PERSISTENT HTTP/3 session for connection pooling.
// Like real Safari, ONE QUIC connection per origin is established once (handshake
// + nghttp3 setup) and REUSED for every request to that origin, instead of a fresh
// QUIC handshake per request (what one-shot driftstackHttp3Execute does — N
// handshakes for an N-resource page). MVP scope is SERIALIZED reuse: one request
// at a time on the live connection (the DriftstackQuicConn response model is
// single-request), which still removes the per-request handshake (the dominant
// cost). Concurrent stream multiplexing + a background servicing thread is a later
// phase. Gated by DRIFTSTACK_H3_POOL (default off).
class DriftstackHttp3Session : public ThreadSafeRefCounted<DriftstackHttp3Session> {
public:
    // Establish a QUIC+h3 connection to `authority` (host[:port]) over a fresh
    // SOCKS5 UDP_ASSOCIATE relay (proxy + creds from env, same path as
    // driftstackHttp3Execute). Returns nullptr on setup/handshake failure.
    static RefPtr<DriftstackHttp3Session> create(const String& authority);
    ~DriftstackHttp3Session();

    // Submit one request on a new bidi stream of the live connection; blocks until
    // the response completes (or error / timeout). NOT concurrent in the MVP —
    // callers serialize via the pool claim (the lock enforces it regardless).
    DriftstackHttp3Response execute(const DriftstackHttp3Request&);

    // True while the QUIC connection is healthy + usable for new requests.
    bool isAlive();

private:
    DriftstackHttp3Session(void* qc, void* ssl);
    void runPump();                       // background owner-thread loop (.mm)

    Lock m_lock;                          // guards m_pumpState queue/inflight + m_alive
    void* m_qc { nullptr };                // owned DriftstackQuicConn* (opaque here;
                                           // real type is .mm-internal, anon namespace)
    void* m_ssl { nullptr };               // SSL* (owned; freed at session close)
    void* m_pumpState { nullptr };         // owned H3PumpState* (.mm) — background pump
                                           // thread + request queue + per-request slots
                                           // for CONCURRENT multiplexing; nullptr = none
    bool m_alive { true };
};

// Gate: true if h3 connection pooling is enabled via DRIFTSTACK_H3_POOL=1.
bool driftstackHttp3PoolEnabled();

// W2890 (#37 DNS-leak fail-closed invariant) — DEFAULT-ON. When true (the default), the QUIC/h3
// path NEVER falls back to a LOCAL getaddrinfo on a §7 proxy-resolve failure: it aborts the h3
// attempt so the loader falls through to h2/TCP (proxy-resolved, no leak), matching a real iPhone's
// UDP-blocked → h2 behaviour. DRIFTSTACK_H3_DNS_FAIL_CLOSED=0 restores the legacy (leaking) fallback.
bool driftstackH3DnsFailClosed();

// W2890 — privacy/fingerprint INVARIANT: count of LOCAL getaddrinfo calls reached on the QUIC/h3
// path under DRIFTSTACK_CUSTOM_SOCKS5=1. MUST be 0 in production (non-zero = DNS-leak regression).
uint64_t driftstackH3LocalGetaddrinfoCount();

// W2890 — hard guard for a would-be LOCAL getaddrinfo on the QUIC/h3 path. Returns true ONLY if the
// legacy local fallback is permitted (fail-closed disabled); callers MUST treat false as "abort the
// h3 attempt, do NOT getaddrinfo". Asserts + counts on the (escape-hatch-only) leaking path. Shared
// with the §7 framer sites in DriftstackQuicSocks5Bridge.mm.
bool driftstackH3LocalResolveAllowed(const char* site, const char* host);

} // namespace WebKit

#endif // PLATFORM(DRIFTSTACK)
