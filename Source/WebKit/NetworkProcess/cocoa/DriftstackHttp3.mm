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

#import <dlfcn.h>
#import <stdlib.h>
#import <sys/socket.h>
#import <wtf/Assertions.h>

WTF_ALLOW_UNSAFE_BUFFER_USAGE_BEGIN

namespace WebKit {

namespace {

// Wave 29-499.147 — ngtcp2 dlsym wrapper. Mirrors BoringSSL pattern in
// DriftstackNetworkLoader.mm. Allows runtime resolution from
// /opt/homebrew/lib/libngtcp2.dylib (development) or bundled location
// (production — Phase 3.x packaging work).

typedef struct ngtcp2_conn ngtcp2_conn;
typedef struct ngtcp2_settings ngtcp2_settings;
typedef struct ngtcp2_transport_params ngtcp2_transport_params;
typedef struct ngtcp2_callbacks ngtcp2_callbacks;
typedef struct ngtcp2_cid ngtcp2_cid;
typedef struct ngtcp2_path ngtcp2_path;
typedef struct ngtcp2_pkt_info ngtcp2_pkt_info;
typedef struct ngtcp2_vec ngtcp2_vec;
typedef struct ngtcp2_addr ngtcp2_addr;
typedef struct ngtcp2_ccerr ngtcp2_ccerr;
typedef int64_t ngtcp2_tstamp;

struct Ngtcp2Fns {
    void (*settings_default)(ngtcp2_settings*) = nullptr;
    void (*transport_params_default)(ngtcp2_transport_params*) = nullptr;
    int (*conn_client_new_versioned)(ngtcp2_conn**, const ngtcp2_cid*, const ngtcp2_cid*,
        const ngtcp2_path*, uint32_t, int, const ngtcp2_callbacks*,
        const ngtcp2_settings*, const ngtcp2_transport_params*, void*, void*) = nullptr;
    void (*conn_del)(ngtcp2_conn*) = nullptr;
    int (*conn_open_bidi_stream)(ngtcp2_conn*, int64_t*, void*) = nullptr;
    ngtcp2_tstamp (*conn_get_expiry)(ngtcp2_conn*) = nullptr;
    int (*conn_handle_expiry)(ngtcp2_conn*, ngtcp2_tstamp) = nullptr;
    void (*addr_init)(ngtcp2_addr*, const struct sockaddr*, size_t) = nullptr;
    void (*cid_init)(ngtcp2_cid*, const uint8_t*, size_t) = nullptr;
    void (*ccerr_default)(ngtcp2_ccerr*) = nullptr;

    // Wave 29-499.223 — packet I/O + key install bindings. Needed to wire
    // BoringSSL QUIC TLS callbacks (SSL_set_quic_method) to ngtcp2's packet
    // protection. ngtcp2 handles the QUIC transport (RFC 9000); BoringSSL
    // handles the TLS handshake messages exchanged via crypto frames
    // (RFC 9001). The dlsym-resolved symbols below let us drive both.
    ssize_t (*conn_read_pkt_versioned)(ngtcp2_conn*, const ngtcp2_path*,
        const ngtcp2_pkt_info*, const uint8_t*, size_t, ngtcp2_tstamp) = nullptr;
    ssize_t (*conn_write_pkt_versioned)(ngtcp2_conn*, ngtcp2_path*,
        ngtcp2_pkt_info*, uint8_t*, size_t, ngtcp2_tstamp) = nullptr;
    ssize_t (*conn_writev_stream_versioned)(ngtcp2_conn*, ngtcp2_path*,
        ngtcp2_pkt_info*, uint8_t*, size_t, int64_t*, uint32_t, int64_t,
        const ngtcp2_vec*, size_t, ngtcp2_tstamp) = nullptr;
    int (*conn_install_initial_key)(ngtcp2_conn*, const void*, const void*,
        const void*, const void*, const void*, const void*, size_t) = nullptr;
    int (*conn_install_rx_handshake_key)(ngtcp2_conn*, const void*, const void*,
        const void*, size_t) = nullptr;
    int (*conn_install_tx_handshake_key)(ngtcp2_conn*, const void*, const void*,
        const void*, size_t) = nullptr;
    int (*conn_install_rx_key)(ngtcp2_conn*, const void*, size_t, const void*,
        const void*, size_t) = nullptr;
    int (*conn_install_tx_key)(ngtcp2_conn*, const void*, size_t, const void*,
        const void*, size_t) = nullptr;
    int (*conn_submit_crypto_data)(ngtcp2_conn*, uint32_t, const uint8_t*, size_t) = nullptr;
    int (*conn_handshake_completed)(ngtcp2_conn*) = nullptr;
    bool ready = false;
};

// Wave 29-499.223 — BoringSSL QUIC TLS API (re-exported via libwebrtc.dylib
// per Wave 29-499.222 / libwebrtc.exp). These callbacks let ngtcp2 ask
// BoringSSL to produce/consume handshake messages, and BoringSSL emits
// derived keys for each cryptographic level (Initial/Handshake/1-RTT).
//
// ssl_encryption_level_t (BoringSSL):
//   ssl_encryption_initial = 0
//   ssl_encryption_early_data = 1
//   ssl_encryption_handshake = 2
//   ssl_encryption_application = 3
enum ssl_encryption_level_t : int {
    ssl_encryption_initial = 0,
    ssl_encryption_early_data = 1,
    ssl_encryption_handshake = 2,
    ssl_encryption_application = 3,
};

struct ssl_quic_method_st {
    int (*set_read_secret)(void* ssl, ssl_encryption_level_t level,
        const void* cipher, const uint8_t* secret, size_t secret_len);
    int (*set_write_secret)(void* ssl, ssl_encryption_level_t level,
        const void* cipher, const uint8_t* secret, size_t secret_len);
    int (*add_handshake_data)(void* ssl, ssl_encryption_level_t level,
        const uint8_t* data, size_t len);
    int (*flush_flight)(void* ssl);
    int (*send_alert)(void* ssl, ssl_encryption_level_t level, uint8_t alert);
};

struct BoringSslQuicFns {
    int (*SSL_set_quic_method)(void* ssl, const ssl_quic_method_st* quic_method) = nullptr;
    int (*SSL_provide_quic_data)(void* ssl, ssl_encryption_level_t level,
        const uint8_t* data, size_t len) = nullptr;
    int (*SSL_process_quic_post_handshake)(void* ssl) = nullptr;
    int (*SSL_set_quic_transport_params)(void* ssl, const uint8_t* params, size_t params_len) = nullptr;
    void (*SSL_get_peer_quic_transport_params)(void* ssl, const uint8_t** out_params,
        size_t* out_params_len) = nullptr;
    bool ready = false;
};

static BoringSslQuicFns& boringSslQuicFns()
{
    static BoringSslQuicFns s;
    return s;
}

// Resolve BoringSSL QUIC API from libwebrtc.dylib (already loaded as
// a framework dependency of WebKit; RTLD_DEFAULT finds it). Mirrors
// the LibreSSL dlsym pattern in DriftstackCrypto.mm but targets the
// libwebrtc-bundled BoringSSL re-exports added in Wave 29-499.222.
static bool resolveBoringSslQuic()
{
    auto& f = boringSslQuicFns();
    if (f.ready) return true;
#define RESOLVE_BQ(field, sym) f.field = reinterpret_cast<decltype(f.field)>(dlsym(RTLD_DEFAULT, sym))
    RESOLVE_BQ(SSL_set_quic_method, "SSL_set_quic_method");
    RESOLVE_BQ(SSL_provide_quic_data, "SSL_provide_quic_data");
    RESOLVE_BQ(SSL_process_quic_post_handshake, "SSL_process_quic_post_handshake");
    RESOLVE_BQ(SSL_set_quic_transport_params, "SSL_set_quic_transport_params");
    RESOLVE_BQ(SSL_get_peer_quic_transport_params, "SSL_get_peer_quic_transport_params");
#undef RESOLVE_BQ
    f.ready = f.SSL_set_quic_method && f.SSL_provide_quic_data
        && f.SSL_process_quic_post_handshake;
    WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.223] BoringSSL QUIC dlsym ready=%d (set_quic_method=%p provide_quic_data=%p process_post_handshake=%p)",
        f.ready, reinterpret_cast<void*>(f.SSL_set_quic_method),
        reinterpret_cast<void*>(f.SSL_provide_quic_data),
        reinterpret_cast<void*>(f.SSL_process_quic_post_handshake));
    return f.ready;
}

static Ngtcp2Fns& ngtcp2Fns()
{
    static Ngtcp2Fns s;
    return s;
}

static bool resolveNgtcp2()
{
    auto& f = ngtcp2Fns();
    if (f.ready) return true;

    // Try multiple candidate paths
    const char* candidates[] = {
        "libngtcp2.dylib",
        "/opt/homebrew/lib/libngtcp2.dylib",  // dev install via Homebrew
        "@executable_path/../Frameworks/libngtcp2.dylib",  // future bundled
        nullptr,
    };
    void* handle = nullptr;
    for (int i = 0; candidates[i]; ++i) {
        handle = dlopen(candidates[i], RTLD_NOW | RTLD_GLOBAL);
        if (handle) {
            WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.147] dlopen ngtcp2 OK at '%s'", candidates[i]);
            break;
        }
    }
    if (!handle) {
        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.147] dlopen ngtcp2 failed (HTTP/3 disabled). Tried: libngtcp2.dylib, /opt/homebrew/lib/libngtcp2.dylib, @executable_path");
        return false;
    }

#define RESOLVE(field, sym) f.field = reinterpret_cast<decltype(f.field)>(dlsym(RTLD_DEFAULT, sym))
    RESOLVE(settings_default, "ngtcp2_settings_default");
    RESOLVE(transport_params_default, "ngtcp2_transport_params_default");
    RESOLVE(conn_client_new_versioned, "ngtcp2_conn_client_new_versioned");
    RESOLVE(conn_del, "ngtcp2_conn_del");
    RESOLVE(conn_open_bidi_stream, "ngtcp2_conn_open_bidi_stream");
    RESOLVE(conn_get_expiry, "ngtcp2_conn_get_expiry");
    RESOLVE(conn_handle_expiry, "ngtcp2_conn_handle_expiry");
    RESOLVE(addr_init, "ngtcp2_addr_init");
    RESOLVE(cid_init, "ngtcp2_cid_init");
    RESOLVE(ccerr_default, "ngtcp2_ccerr_default");
    // Wave 29-499.223 — packet I/O + key install
    RESOLVE(conn_read_pkt_versioned, "ngtcp2_conn_read_pkt_versioned");
    RESOLVE(conn_write_pkt_versioned, "ngtcp2_conn_write_pkt_versioned");
    RESOLVE(conn_writev_stream_versioned, "ngtcp2_conn_writev_stream_versioned");
    RESOLVE(conn_install_initial_key, "ngtcp2_conn_install_initial_key");
    RESOLVE(conn_install_rx_handshake_key, "ngtcp2_conn_install_rx_handshake_key");
    RESOLVE(conn_install_tx_handshake_key, "ngtcp2_conn_install_tx_handshake_key");
    RESOLVE(conn_install_rx_key, "ngtcp2_conn_install_rx_key");
    RESOLVE(conn_install_tx_key, "ngtcp2_conn_install_tx_key");
    RESOLVE(conn_submit_crypto_data, "ngtcp2_conn_submit_crypto_data");
    RESOLVE(conn_handshake_completed, "ngtcp2_conn_handshake_completed");
#undef RESOLVE

    bool required = f.settings_default && f.transport_params_default
        && f.conn_client_new_versioned && f.conn_del && f.conn_open_bidi_stream
        && f.conn_get_expiry && f.conn_handle_expiry
        && f.addr_init && f.cid_init && f.ccerr_default
        && f.conn_read_pkt_versioned && f.conn_write_pkt_versioned
        && f.conn_writev_stream_versioned
        && f.conn_install_initial_key && f.conn_install_rx_handshake_key
        && f.conn_install_tx_handshake_key && f.conn_install_rx_key
        && f.conn_install_tx_key && f.conn_submit_crypto_data
        && f.conn_handshake_completed;
    f.ready = required;
    WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.147] ngtcp2 dlsym ready=%d", required);
    return required;
}

} // anonymous namespace

DriftstackHttp3Response driftstackHttp3Execute(void* /*socks5UdpRelay*/, const DriftstackHttp3Request& /*request*/)
{
    DriftstackHttp3Response resp;

    if (!resolveNgtcp2()) {
        resp.failed = true;
        resp.errorMessage = "ngtcp2 unavailable (dlopen libngtcp2.dylib failed)"_s;
        return resp;
    }

    if (!resolveBoringSslQuic()) {
        resp.failed = true;
        resp.errorMessage = "BoringSSL QUIC TLS API unavailable from libwebrtc.dylib (was Wave 29-499.222 export wired correctly?)"_s;
        return resp;
    }

    // Wave 29-499.223 — verification gate: both transport (ngtcp2) and
    // crypto (BoringSSL QUIC TLS API via libwebrtc.dylib) layers are now
    // resolvable. The remaining Phase 3 work is:
    //   a) Allocate dcid (8-20 random bytes) + scid (8 random bytes) via
    //      ngtcp2_cid_init
    //   b) Configure iPhone-matched transport_params: initial_max_data,
    //      max_streams_bidi/uni, max_idle_timeout, max_udp_payload_size,
    //      ack_delay_exponent, max_ack_delay, active_connection_id_limit
    //   c) Configure ngtcp2_callbacks with:
    //      - get_new_connection_id
    //      - update_key (1-RTT key update)
    //      - rand
    //      - recv_crypto_data → SSL_provide_quic_data
    //      - encrypt / decrypt (use libwebrtc AEAD as Wave 29-499.190 does)
    //      - hp_mask (header protection — AES-128-ECB or ChaCha20)
    //   d) Build ssl_quic_method_st callbacks:
    //      - set_read_secret → derive ngtcp2 rx keys via HKDF-Expand-Label,
    //                          then conn_install_rx_*_key
    //      - set_write_secret → analogous tx
    //      - add_handshake_data → conn_submit_crypto_data
    //      - flush_flight → no-op (ngtcp2 batches packet writes)
    //      - send_alert → submit alert via crypto stream
    //   e) Wire BoringSSL SSL_CTX from DriftstackCustomTLS (already built
    //      for HTTP/2; reuse with SSL_set_quic_method)
    //   f) Configure iPhone-exact ClientHello via DriftstackCustomTLS
    //      (reuse buildClientHello + Wave 29-499.219 hybrid keyshare)
    //   g) ALPN: "h3" instead of "h2"
    //   h) Event loop:
    //      - conn_write_pkt → SOCKS5 §7 wrap → sendto relay
    //      - recvfrom relay → §7 unwrap → conn_read_pkt
    //      - On stream data event: nghttp3 frame parse → HTTP/3 RESPONSE
    //   i) HTTP/3 request emission:
    //      - nghttp3 QPACK encode HEADERS frame on stream id 0
    //      - DATA frames for body
    //
    // Estimated effort: ~1500 LOC + multi-day debugging. Each piece
    // (a..i) is well-defined RFC-spec work, not architecturally novel.

    static bool loggedFullStackOnce = false;
    if (!loggedFullStackOnce) {
        loggedFullStackOnce = true;
        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.223] HTTP/3 stack VERIFIED RESOLVABLE — ngtcp2 (transport, 20 syms) + BoringSSL QUIC TLS (5 syms via libwebrtc re-export) both ready. Next: wire ssl_quic_method_st callbacks + ngtcp2 conn setup + iPhone transport params + h3 ALPN.");
    }

    // Phase 3 implementation TODO:
    // 1. Allocate dcid + scid via ngtcp2_cid_init
    // 2. Configure iPhone-matched transport params (capture from real iPhone)
    // 3. Wire BoringSSL QUIC API via ngtcp2_callbacks
    // 4. SOCKS5 UDP_ASSOCIATE setup
    // 5. ngtcp2_conn_client_new_versioned
    // 6. Event loop: write_pkt → SOCKS5 §7 wrap → sendto, recvfrom → unwrap → read_pkt
    // 7. HTTP/3 framing on bidi stream 0
    // 8. QPACK encode + decode
    //
    // For Phase 3 scaffold today: return failed so caller falls back to h2.
    resp.failed = true;
    resp.errorMessage = "Phase 3 HTTP/3 wiring incomplete; ngtcp2 dlsym ready but conn setup TODO"_s;

    static bool loggedOnce = false;
    if (!loggedOnce) {
        loggedOnce = true;
        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.147] HTTP/3 scaffold: ngtcp2 dlsym working but ngtcp2_conn setup + BoringSSL QUIC binding + UDP_ASSOCIATE relay event loop are Phase 3.x work-items. Falling back to h2.");
    }
    return resp;
}

bool driftstackHttp3Enabled()
{
    const char* env = getenv("DRIFTSTACK_PATHB_V2_H3");
    return env && env[0] == '1';
}

} // namespace WebKit

WTF_ALLOW_UNSAFE_BUFFER_USAGE_END

#endif // PLATFORM(DRIFTSTACK)
