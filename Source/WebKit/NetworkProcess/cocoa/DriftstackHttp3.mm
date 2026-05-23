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
#import "DriftstackCrypto.h"
// Wave 29-499.238 — pull in SOCKS5 §7 wrap/unwrap helpers + relay channel
// establishment. Reuses the same DriftstackRTC infrastructure that already
// works for WebRTC (Wave 29-499.99-106) per the V-2026-05-23-W29-499.221
// STUN verification.
#import "DriftstackRTCSocks5Bridge.h"
#import "DriftstackSocks5Framing.h"

#if PLATFORM(DRIFTSTACK)

#import <arpa/inet.h>
#import <dlfcn.h>
#import <netinet/in.h>
#import <stdlib.h>
#import <string.h>
#import <sys/socket.h>
#import <wtf/Assertions.h>

// Wave 29-499.228 — ngtcp2 header inclusion. Provides real struct layouts
// for ngtcp2_settings, ngtcp2_transport_params, ngtcp2_cid, ngtcp2_callbacks,
// etc. The functions are still dlsym-resolved at runtime (Wave 29-499.147)
// to avoid hard link dependency on libngtcp2.dylib at WebKit load time —
// HTTP/3 path is opt-in via DRIFTSTACK_PATHB_V2_H3=1.
// Header guards prevent re-declaration conflicts with the existing forward
// declarations in Ngtcp2Fns below.
#define DRIFTSTACK_HAS_NGTCP2_HEADERS 1
#include <ngtcp2/ngtcp2.h>

WTF_ALLOW_UNSAFE_BUFFER_USAGE_BEGIN

namespace WebKit {

namespace {

// Wave 29-499.147 — ngtcp2 dlsym wrapper. Mirrors BoringSSL pattern in
// DriftstackNetworkLoader.mm. Allows runtime resolution from
// /opt/homebrew/lib/libngtcp2.dylib (development) or bundled location
// (production — Phase 3.x packaging work).

// Wave 29-499.228 — types now come from <ngtcp2/ngtcp2.h>. Forward decls
// removed (replaced by real struct definitions from the header).

struct Ngtcp2Fns {
    // Wave 29-499.243 — versioned symbol signatures matching ngtcp2 1.22 ABI.
    // Headers wrap these in macros that prepend a version int; we resolve
    // the raw _versioned symbol via dlsym and pass NGTCP2_SETTINGS_VERSION /
    // NGTCP2_TRANSPORT_PARAMS_VERSION explicitly.
    void (*settings_default_versioned)(int version, ngtcp2_settings*) = nullptr;
    void (*transport_params_default_versioned)(int version, ngtcp2_transport_params*) = nullptr;
    // Wave 29-499.247e — corrected signature per ngtcp2.h:
    // (pconn, dcid, scid, path, client_chosen_version,
    //  callbacks_version, callbacks,
    //  settings_version, settings,
    //  transport_params_version, params,
    //  mem, user_data) — 13 args
    int (*conn_client_new_versioned)(ngtcp2_conn**, const ngtcp2_cid*, const ngtcp2_cid*,
        const ngtcp2_path*, uint32_t,
        int, const ngtcp2_callbacks*,
        int, const ngtcp2_settings*,
        int, const ngtcp2_transport_params*,
        const void*, void*) = nullptr;
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
    // Wave 29-499.254 — corrected signatures with pkt_info_version arg.
    // Real signature inserts int pkt_info_version between path and pi.
    // writev_stream also uses ngtcp2_ssize* (signed) not int64_t* for pdatalen.
    ngtcp2_ssize (*conn_read_pkt_versioned)(ngtcp2_conn*, const ngtcp2_path*,
        int, const ngtcp2_pkt_info*, const uint8_t*, size_t, ngtcp2_tstamp) = nullptr;
    ngtcp2_ssize (*conn_write_pkt_versioned)(ngtcp2_conn*, ngtcp2_path*,
        int, ngtcp2_pkt_info*, uint8_t*, size_t, ngtcp2_tstamp) = nullptr;
    ngtcp2_ssize (*conn_writev_stream_versioned)(ngtcp2_conn*, ngtcp2_path*,
        int, ngtcp2_pkt_info*, uint8_t*, size_t, ngtcp2_ssize*, uint32_t, int64_t,
        const ngtcp2_vec*, size_t, ngtcp2_tstamp) = nullptr;
    // Wave 29-499.234 — install_initial_key signature matches real ngtcp2.h.
    // The handshake / 1-RTT install_*_key keep void* signatures for now;
    // their .225 call sites pass raw uint8_t* and converting them requires
    // wrapping in DriftstackQuicAeadCtx / DriftstackQuicHpCtx structs at
    // those sites — deferred to Wave 29-499.235 to avoid expanding scope
    // mid-iteration. The void*+pointer reinterpret_cast preserves the
    // pointer values that ngtcp2 ultimately dereferences via its actual
    // typed signature.
    int (*conn_install_initial_key)(ngtcp2_conn*,
        const ngtcp2_crypto_aead_ctx*, const uint8_t*,
        const ngtcp2_crypto_cipher_ctx*,
        const ngtcp2_crypto_aead_ctx*, const uint8_t*,
        const ngtcp2_crypto_cipher_ctx*, size_t) = nullptr;
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
    // Wave 29-499.224 — ex_data slot APIs for SSL→QuicConn linkage.
    void* (*SSL_get_ex_data)(const void* ssl, int idx) = nullptr;
    int (*SSL_set_ex_data)(void* ssl, int idx, void* arg) = nullptr;
    int (*SSL_get_ex_new_index)(long argl, void* argp, void* new_func,
        void* dup_func, void* free_func) = nullptr;
    // Wave 29-499.225 — SSL_CIPHER introspection for QUIC key length
    // selection per cipher: 0x1301 AES-128-GCM-SHA256 → key=16, hp=16, hash=SHA256;
    // 0x1302 AES-256-GCM-SHA384 → key=32, hp=32, hash=SHA384;
    // 0x1303 CHACHA20-POLY1305-SHA256 → key=32, hp=32, hash=SHA256.
    uint16_t (*SSL_CIPHER_get_protocol_id)(const void* cipher) = nullptr;
    const char* (*SSL_CIPHER_get_name)(const void* cipher) = nullptr;
    // Wave 29-499.236 — SSL context + handshake driver. Used by
    // driftstackHttp3Execute to set up a client SSL with h3 ALPN, then
    // drive handshake via SSL_do_handshake (which fires the quic_method
    // callbacks to install keys + submit crypto frames).
    void* (*SSL_CTX_new)(const void* method) = nullptr;
    void (*SSL_CTX_free)(void* ctx) = nullptr;
    int (*SSL_CTX_set_min_proto_version)(void* ctx, int version) = nullptr;
    int (*SSL_CTX_set_max_proto_version)(void* ctx, int version) = nullptr;
    int (*SSL_CTX_set_alpn_protos)(void* ctx, const uint8_t* protos, size_t len) = nullptr;
    const void* (*TLS_client_method)(void) = nullptr;
    void* (*SSL_new)(void* ctx) = nullptr;
    void (*SSL_free)(void* ssl) = nullptr;
    int (*SSL_set_tlsext_host_name)(void* ssl, const char* name) = nullptr;
    int (*SSL_do_handshake)(void* ssl) = nullptr;
    void (*SSL_set_connect_state)(void* ssl) = nullptr;
    int (*SSL_get_error)(const void* ssl, int rv) = nullptr;
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
    // Wave 29-499.245 — dlopen libwebrtc explicitly + use that specific
    // handle for all SSL_* dlsym. Without this RTLD_DEFAULT may return
    // Apple LibreSSL's SSL_CTX_new (different ABI from BoringSSL's
    // TLS_client_method) causing silent crash inside SSL_CTX_new.
    static void* libwebrtcHandle = nullptr;
    if (!libwebrtcHandle) {
        const char* libwebrtcCandidates[] = {
            "libwebrtc.dylib",
            "/Users/john/code/webkit-driftstack/WebKitBuild/Release/libwebrtc.dylib",
            "@executable_path/../Frameworks/libwebrtc.dylib",
            nullptr,
        };
        for (int i = 0; libwebrtcCandidates[i]; ++i) {
            libwebrtcHandle = dlopen(libwebrtcCandidates[i], RTLD_NOW | RTLD_GLOBAL);
            if (libwebrtcHandle) {
                WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.245] dlopen libwebrtc OK at '%s' handle=%p", libwebrtcCandidates[i], libwebrtcHandle);
                break;
            }
        }
        if (!libwebrtcHandle) {
            WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.245] dlopen libwebrtc FAILED — BoringSSL QUIC unavailable");
            return false;
        }
    }
#define RESOLVE_BQ(field, sym) f.field = reinterpret_cast<decltype(f.field)>(dlsym(libwebrtcHandle, sym))
    RESOLVE_BQ(SSL_set_quic_method, "SSL_set_quic_method");
    RESOLVE_BQ(SSL_provide_quic_data, "SSL_provide_quic_data");
    RESOLVE_BQ(SSL_process_quic_post_handshake, "SSL_process_quic_post_handshake");
    RESOLVE_BQ(SSL_set_quic_transport_params, "SSL_set_quic_transport_params");
    RESOLVE_BQ(SSL_get_peer_quic_transport_params, "SSL_get_peer_quic_transport_params");
    RESOLVE_BQ(SSL_get_ex_data, "SSL_get_ex_data");
    RESOLVE_BQ(SSL_set_ex_data, "SSL_set_ex_data");
    RESOLVE_BQ(SSL_get_ex_new_index, "SSL_get_ex_new_index");
    RESOLVE_BQ(SSL_CIPHER_get_protocol_id, "SSL_CIPHER_get_protocol_id");
    RESOLVE_BQ(SSL_CIPHER_get_name, "SSL_CIPHER_get_name");
    // Wave 29-499.236 — SSL context + handshake driver.
    RESOLVE_BQ(SSL_CTX_new, "SSL_CTX_new");
    RESOLVE_BQ(SSL_CTX_free, "SSL_CTX_free");
    RESOLVE_BQ(SSL_CTX_set_min_proto_version, "SSL_CTX_set_min_proto_version");
    RESOLVE_BQ(SSL_CTX_set_max_proto_version, "SSL_CTX_set_max_proto_version");
    RESOLVE_BQ(SSL_CTX_set_alpn_protos, "SSL_CTX_set_alpn_protos");
    RESOLVE_BQ(TLS_client_method, "TLS_client_method");
    RESOLVE_BQ(SSL_new, "SSL_new");
    RESOLVE_BQ(SSL_free, "SSL_free");
    RESOLVE_BQ(SSL_set_tlsext_host_name, "SSL_set_tlsext_host_name");
    RESOLVE_BQ(SSL_do_handshake, "SSL_do_handshake");
    RESOLVE_BQ(SSL_set_connect_state, "SSL_set_connect_state");
    RESOLVE_BQ(SSL_get_error, "SSL_get_error");
#undef RESOLVE_BQ
    f.ready = f.SSL_set_quic_method && f.SSL_provide_quic_data
        && f.SSL_process_quic_post_handshake
        && f.SSL_get_ex_data && f.SSL_set_ex_data && f.SSL_get_ex_new_index
        && f.SSL_CTX_new && f.SSL_new && f.SSL_free && f.SSL_CTX_free
        && f.TLS_client_method && f.SSL_do_handshake
        && f.SSL_CTX_set_alpn_protos;
    WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.223] BoringSSL QUIC dlsym ready=%d (set_quic_method=%p provide_quic_data=%p process_post_handshake=%p)",
        f.ready, reinterpret_cast<void*>(f.SSL_set_quic_method),
        reinterpret_cast<void*>(f.SSL_provide_quic_data),
        reinterpret_cast<void*>(f.SSL_process_quic_post_handshake));
    // Wave 29-499.245b — per-symbol diagnostic for libwebrtc dlsym.
    WTFLogAlways("[Wave29-499.245b] BoringSslQuicFns: SSL_get_ex_data=%p SSL_set_ex_data=%p SSL_get_ex_new_index=%p SSL_CIPHER_get_protocol_id=%p SSL_CIPHER_get_name=%p SSL_CTX_new=%p SSL_CTX_free=%p min_pv=%p max_pv=%p set_alpn=%p TLS_client_method=%p SSL_new=%p SSL_free=%p set_sni=%p do_handshake=%p set_connect=%p get_error=%p",
        (void*)f.SSL_get_ex_data, (void*)f.SSL_set_ex_data,
        (void*)f.SSL_get_ex_new_index, (void*)f.SSL_CIPHER_get_protocol_id,
        (void*)f.SSL_CIPHER_get_name, (void*)f.SSL_CTX_new,
        (void*)f.SSL_CTX_free, (void*)f.SSL_CTX_set_min_proto_version,
        (void*)f.SSL_CTX_set_max_proto_version, (void*)f.SSL_CTX_set_alpn_protos,
        (void*)f.TLS_client_method, (void*)f.SSL_new,
        (void*)f.SSL_free, (void*)f.SSL_set_tlsext_host_name,
        (void*)f.SSL_do_handshake, (void*)f.SSL_set_connect_state,
        (void*)f.SSL_get_error);
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

    // Try multiple candidate paths. NetworkProcess sandbox + SIP strip
    // DYLD_LIBRARY_PATH; absolute paths to WebKitBuild/Release work because
    // that's where WebKit framework loads from at runtime, and dyld
    // permits dlopen from sibling locations of the loaded framework.
    const char* candidates[] = {
        "libngtcp2.dylib",
        "/Users/john/code/webkit-driftstack/WebKitBuild/Release/libngtcp2.dylib",  // dev: rewritten @rpath dylib next to WebKit framework
        "/opt/homebrew/lib/libngtcp2.dylib",  // dev install via Homebrew (sandbox often blocks)
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

// Wave 29-499.244 — use the dlopen handle directly (RTLD_DEFAULT fails in
// NetworkProcess sandbox even though RTLD_GLOBAL is set on dlopen).
#define RESOLVE(field, sym) f.field = reinterpret_cast<decltype(f.field)>(dlsym(handle, sym))
    RESOLVE(settings_default_versioned, "ngtcp2_settings_default_versioned");
    RESOLVE(transport_params_default_versioned, "ngtcp2_transport_params_default_versioned");
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
    RESOLVE(conn_handshake_completed, "ngtcp2_conn_get_handshake_completed");
#undef RESOLVE

    bool required = f.settings_default_versioned && f.transport_params_default_versioned
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
    // Wave 29-499.244b — detailed per-symbol diagnostic to identify what's missing.
    WTFLogAlways("[Wave29-499.244b] ngtcp2 sym resolve: settings_default_v=%p tp_default_v=%p conn_client_new_v=%p conn_del=%p open_bidi=%p get_expiry=%p handle_expiry=%p addr_init=%p cid_init=%p ccerr=%p read_pkt_v=%p write_pkt_v=%p writev_stream_v=%p install_initial_key=%p install_rx_hs_key=%p install_tx_hs_key=%p install_rx_key=%p install_tx_key=%p submit_crypto=%p handshake_completed=%p",
        (void*)f.settings_default_versioned, (void*)f.transport_params_default_versioned,
        (void*)f.conn_client_new_versioned, (void*)f.conn_del,
        (void*)f.conn_open_bidi_stream, (void*)f.conn_get_expiry,
        (void*)f.conn_handle_expiry, (void*)f.addr_init,
        (void*)f.cid_init, (void*)f.ccerr_default,
        (void*)f.conn_read_pkt_versioned, (void*)f.conn_write_pkt_versioned,
        (void*)f.conn_writev_stream_versioned, (void*)f.conn_install_initial_key,
        (void*)f.conn_install_rx_handshake_key, (void*)f.conn_install_tx_handshake_key,
        (void*)f.conn_install_rx_key, (void*)f.conn_install_tx_key,
        (void*)f.conn_submit_crypto_data, (void*)f.conn_handshake_completed);
    return required;
}

// Wave 29-499.224 — DriftstackQuicConn ties an SSL pointer to its ngtcp2
// connection state. Stored via SSL_set_ex_data; the 5 ssl_quic_method_st
// callbacks recover it via SSL_get_ex_data at each invocation. Lifetime
// equals the QUIC connection; freed when SSL_free is called (via the
// ex_data free callback registered with SSL_get_ex_new_index).
struct DriftstackQuicConn {
    ngtcp2_conn* conn { nullptr };
    void* ssl { nullptr };
    bool handshakeCompleted { false };
    // Persisted secrets for HKDF-Expand-Label key derivation across
    // set_*_secret callbacks. Length depends on negotiated cipher
    // (32 for SHA-256, 48 for SHA-384). Initial=0, Handshake=2, App=3.
    Vector<uint8_t> rxSecret[4];
    Vector<uint8_t> txSecret[4];
};

[[maybe_unused]] static int& quicConnExDataIndex()
{
    static int s_idx = -1;
    return s_idx;
}

[[maybe_unused]] static DriftstackQuicConn* quicConnFromSsl(void* ssl)
{
    auto& f = boringSslQuicFns();
    if (!f.ready || quicConnExDataIndex() < 0)
        return nullptr;
    return static_cast<DriftstackQuicConn*>(f.SSL_get_ex_data(ssl, quicConnExDataIndex()));
}

// Wave 29-499.225 — RFC 9001 §5.1 QUIC key derivation. Each TLS level
// secret (Initial/Handshake/1-RTT) derives three pieces of keying material:
//   key = HKDF-Expand-Label(secret, "quic key", "", key_len)
//   iv  = HKDF-Expand-Label(secret, "quic iv",  "", 12)
//   hp  = HKDF-Expand-Label(secret, "quic hp",  "", key_len)
//
// Cipher-aware lengths (per RFC 9001 §5.2 + RFC 8446):
//   AES-128-GCM-SHA256  (0x1301): key=16, hp=16, hash=SHA-256, secret_len=32
//   AES-256-GCM-SHA384  (0x1302): key=32, hp=32, hash=SHA-384, secret_len=48
//   CHACHA20-POLY1305   (0x1303): key=32, hp=32, hash=SHA-256, secret_len=32
//
// QUIC Initial uses AES-128-GCM-SHA256 always (RFC 9001 §5.2). Handshake
// + 1-RTT use the negotiated cipher.
struct QuicAeadParams {
    size_t keyLen { 0 };
    size_t hpLen { 0 };
    bool useSha384 { false };  // false = SHA-256, true = SHA-384
    bool valid { false };
};

static QuicAeadParams aeadParamsForCipher(const void* cipher, size_t secret_len)
{
    QuicAeadParams p;
    auto& f = boringSslQuicFns();
    if (cipher && f.SSL_CIPHER_get_protocol_id) {
        uint16_t id = f.SSL_CIPHER_get_protocol_id(cipher);
        switch (id) {
        case 0x1301: p.keyLen = 16; p.hpLen = 16; p.useSha384 = false; p.valid = true; break;
        case 0x1302: p.keyLen = 32; p.hpLen = 32; p.useSha384 = true;  p.valid = true; break;
        case 0x1303: p.keyLen = 32; p.hpLen = 32; p.useSha384 = false; p.valid = true; break;
        }
    }
    // Fallback: if cipher pointer is null (some BoringSSL paths) infer from
    // secret_len. secret_len=48 → SHA-384 → AES-256-GCM (key=32); else assume
    // AES-128-GCM (Initial level always; most common 1-RTT cipher).
    if (!p.valid) {
        if (secret_len == 48) {
            p.keyLen = 32; p.hpLen = 32; p.useSha384 = true; p.valid = true;
        } else if (secret_len == 32) {
            p.keyLen = 16; p.hpLen = 16; p.useSha384 = false; p.valid = true;
        }
    }
    return p;
}

static bool deriveQuicKeyMaterial(const uint8_t* secret, size_t secret_len,
    const void* cipher,
    Vector<uint8_t>& outKey, Vector<uint8_t>& outIV, Vector<uint8_t>& outHp)
{
    auto params = aeadParamsForCipher(cipher, secret_len);
    if (!params.valid) {
        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.225] deriveQuicKeyMaterial: unsupported cipher / secret_len=%zu (must be 32 or 48)", secret_len);
        return false;
    }
    Vector<uint8_t> secretVec(secret_len);
    memcpy(secretVec.mutableSpan().data(), secret, secret_len);
    Vector<uint8_t> emptyCtx;
    if (params.useSha384) {
        outKey = WebKit::driftstackHkdfExpandLabelSha384(secretVec, "quic key", emptyCtx, params.keyLen);
        outIV  = WebKit::driftstackHkdfExpandLabelSha384(secretVec, "quic iv",  emptyCtx, 12);
        outHp  = WebKit::driftstackHkdfExpandLabelSha384(secretVec, "quic hp",  emptyCtx, params.hpLen);
    } else {
        outKey = WebKit::driftstackHkdfExpandLabelSha256(secretVec, "quic key", emptyCtx, params.keyLen);
        outIV  = WebKit::driftstackHkdfExpandLabelSha256(secretVec, "quic iv",  emptyCtx, 12);
        outHp  = WebKit::driftstackHkdfExpandLabelSha256(secretVec, "quic hp",  emptyCtx, params.hpLen);
    }
    bool ok = !outKey.isEmpty() && outIV.size() == 12 && !outHp.isEmpty();
    return ok;
}

// Wave 29-499.224 — ssl_quic_method_st callbacks (5 total per BoringSSL ABI).
// These bridge BoringSSL's TLS state machine to ngtcp2's QUIC packet protection.
//
// RFC 9001 §4.1: TLS handshake messages travel via QUIC CRYPTO frames at
// the cryptographic level matching the TLS handshake phase (Initial,
// Handshake, Application/1-RTT). set_read_secret / set_write_secret
// announce that a level's traffic secrets are available; we derive the
// AEAD keys + IVs + header-protection keys via HKDF-Expand-Label and
// install them in ngtcp2 so it can encrypt/decrypt packets at that level.

[[maybe_unused]] static int driftstackQuicSetReadSecret(void* ssl, ssl_encryption_level_t level,
    const void* cipher, const uint8_t* secret, size_t secret_len)
{
    DriftstackQuicConn* qc = quicConnFromSsl(ssl);
    if (!qc || !qc->conn) return 0;
    if (level < 4) {
        qc->rxSecret[level].resize(secret_len);
        memcpy(qc->rxSecret[level].mutableSpan().data(), secret, secret_len);
    }
    Vector<uint8_t> key, iv, hp;
    if (!deriveQuicKeyMaterial(secret, secret_len, cipher, key, iv, hp)) {
        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.225] QuicSetReadSecret: key derivation FAILED level=%d", static_cast<int>(level));
        return 0;
    }
    auto& nf = ngtcp2Fns();
    int rv = -1;
    switch (level) {
    case ssl_encryption_handshake:
        rv = nf.conn_install_rx_handshake_key(qc->conn,
            key.span().data(), iv.span().data(), hp.span().data(), key.size());
        break;
    case ssl_encryption_application:
        rv = nf.conn_install_rx_key(qc->conn,
            secret, secret_len,
            key.span().data(), iv.span().data(), key.size());
        break;
    case ssl_encryption_initial:
    case ssl_encryption_early_data:
    default:
        // Initial keys are installed via ngtcp2_conn_install_initial_key
        // separately (during conn setup, before any TLS messages). 0-RTT
        // is post-launch scope.
        rv = 0;
        break;
    }
    WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.225] QuicSetReadSecret level=%d secret_len=%zu key_len=%zu hp_len=%zu install_rv=%d",
        static_cast<int>(level), secret_len, key.size(), hp.size(), rv);
    return rv == 0 ? 1 : 0;
}

[[maybe_unused]] static int driftstackQuicSetWriteSecret(void* ssl, ssl_encryption_level_t level,
    const void* cipher, const uint8_t* secret, size_t secret_len)
{
    DriftstackQuicConn* qc = quicConnFromSsl(ssl);
    if (!qc || !qc->conn) return 0;
    if (level < 4) {
        qc->txSecret[level].resize(secret_len);
        memcpy(qc->txSecret[level].mutableSpan().data(), secret, secret_len);
    }
    Vector<uint8_t> key, iv, hp;
    if (!deriveQuicKeyMaterial(secret, secret_len, cipher, key, iv, hp)) {
        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.225] QuicSetWriteSecret: key derivation FAILED level=%d", static_cast<int>(level));
        return 0;
    }
    auto& nf = ngtcp2Fns();
    int rv = -1;
    switch (level) {
    case ssl_encryption_handshake:
        rv = nf.conn_install_tx_handshake_key(qc->conn,
            key.span().data(), iv.span().data(), hp.span().data(), key.size());
        break;
    case ssl_encryption_application:
        rv = nf.conn_install_tx_key(qc->conn,
            secret, secret_len,
            key.span().data(), iv.span().data(), key.size());
        break;
    case ssl_encryption_initial:
    case ssl_encryption_early_data:
    default:
        rv = 0;
        break;
    }
    WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.225] QuicSetWriteSecret level=%d secret_len=%zu key_len=%zu hp_len=%zu install_rv=%d",
        static_cast<int>(level), secret_len, key.size(), hp.size(), rv);
    return rv == 0 ? 1 : 0;
}

[[maybe_unused]] static int driftstackQuicAddHandshakeData(void* ssl, ssl_encryption_level_t level,
    const uint8_t* data, size_t len)
{
    DriftstackQuicConn* qc = quicConnFromSsl(ssl);
    if (!qc || !qc->conn) return 0;
    auto& nf = ngtcp2Fns();
    // Map ssl level → ngtcp2 encryption level (same enum values, but
    // ngtcp2 uses ngtcp2_encryption_level_t — identical 0..3 layout).
    uint32_t ngtcp2Level = static_cast<uint32_t>(level);
    int rv = nf.conn_submit_crypto_data(qc->conn, ngtcp2Level, data, len);
    if (rv != 0) {
        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.224] QuicAddHandshakeData FAILED rv=%d level=%d len=%zu",
            rv, static_cast<int>(level), len);
        return 0;
    }
    static unsigned s_firstCount = 0;
    if (s_firstCount++ < 5) {
        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.224] QuicAddHandshakeData OK level=%d len=%zu (submitted to ngtcp2 crypto frame at level=%u)",
            static_cast<int>(level), len, ngtcp2Level);
    }
    return 1;
}

[[maybe_unused]] static int driftstackQuicFlushFlight(void* /*ssl*/)
{
    // ngtcp2 batches packet writes via conn_writev_stream during event loop.
    // No explicit flush needed here; the event loop polls ngtcp2 on schedule.
    return 1;
}

[[maybe_unused]] static int driftstackQuicSendAlert(void* ssl, ssl_encryption_level_t level, uint8_t alert)
{
    WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.224] QuicSendAlert level=%d alert=0x%02x (TLS alert raised; will close QUIC connection with TRANSPORT_ERROR + CRYPTO_ERROR base + alert code per RFC 9001 §4.8)",
        static_cast<int>(level), alert);
    DriftstackQuicConn* qc = quicConnFromSsl(ssl);
    if (qc)
        qc->handshakeCompleted = false;
    return 1;
}


// Wave 29-499.226 — QUIC variable-length integer encoder per RFC 9000 §16.
// Encodes value into a 1/2/4/8-byte big-endian varint with the top two bits
// indicating length (00=1B/6b, 01=2B/14b, 10=4B/30b, 11=8B/62b).
[[maybe_unused]] static void encodeQuicVarint(Vector<uint8_t>& out, uint64_t value)
{
    if (value < 0x40ULL) {
        out.append(static_cast<uint8_t>(value));
    } else if (value < 0x4000ULL) {
        out.append(static_cast<uint8_t>(0x40 | (value >> 8)));
        out.append(static_cast<uint8_t>(value & 0xFF));
    } else if (value < 0x40000000ULL) {
        out.append(static_cast<uint8_t>(0x80 | (value >> 24)));
        out.append(static_cast<uint8_t>((value >> 16) & 0xFF));
        out.append(static_cast<uint8_t>((value >> 8) & 0xFF));
        out.append(static_cast<uint8_t>(value & 0xFF));
    } else {
        out.append(static_cast<uint8_t>(0xC0 | (value >> 56)));
        out.append(static_cast<uint8_t>((value >> 48) & 0xFF));
        out.append(static_cast<uint8_t>((value >> 40) & 0xFF));
        out.append(static_cast<uint8_t>((value >> 32) & 0xFF));
        out.append(static_cast<uint8_t>((value >> 24) & 0xFF));
        out.append(static_cast<uint8_t>((value >> 16) & 0xFF));
        out.append(static_cast<uint8_t>((value >> 8) & 0xFF));
        out.append(static_cast<uint8_t>(value & 0xFF));
    }
}

// Wave 29-499.226 — emit one transport parameter (RFC 9000 §18): varint id +
// varint length + value bytes. For integer-valued params, value is itself a
// varint.
[[maybe_unused]] static void emitQuicTpInt(Vector<uint8_t>& out, uint64_t id, uint64_t value)
{
    encodeQuicVarint(out, id);
    Vector<uint8_t> valueBytes;
    encodeQuicVarint(valueBytes, value);
    encodeQuicVarint(out, valueBytes.size());
    out.append(valueBytes.span());
}

[[maybe_unused]] static void emitQuicTpBytes(Vector<uint8_t>& out, uint64_t id, std::span<const uint8_t> data)
{
    encodeQuicVarint(out, id);
    encodeQuicVarint(out, data.size());
    out.append(data);
}

[[maybe_unused]] static void emitQuicTpEmpty(Vector<uint8_t>& out, uint64_t id)
{
    encodeQuicVarint(out, id);
    out.append(static_cast<uint8_t>(0));  // length=0
}

// Wave 29-499.226 — iPhone Safari 26 QUIC client transport parameters.
// On-wire byte sequence ready for SSL_set_quic_transport_params(ssl, ..., ...).
//
// Values chosen to match observed iPhone Safari behavior over QUIC:
//   max_idle_timeout = 30000 ms (Apple default per nw_quic configuration)
//   max_udp_payload_size = 1452 (Ethernet MTU - IPv4/UDP/QUIC overhead)
//   initial_max_data = 12582912 (~12 MB connection flow control window)
//   initial_max_stream_data_bidi_{local,remote} = 6291456 (~6 MB stream)
//   initial_max_stream_data_uni = 1048576 (~1 MB)
//   initial_max_streams_bidi = 100 (typical h3 needs)
//   initial_max_streams_uni = 100
//   ack_delay_exponent = 3 (default)
//   max_ack_delay = 25 ms (default)
//   disable_active_migration = presence (Apple disables migration by default)
//   active_connection_id_limit = 4
//   initial_source_connection_id = scid (caller supplies)
//
// TODO Wave 29-499.227: capture real iPhone Safari QUIC connection via mitm
// or pcap; refine transport params to byte-identical match.
[[maybe_unused]] static Vector<uint8_t> buildIphoneQuicTransportParams(std::span<const uint8_t> initialScid)
{
    Vector<uint8_t> tp;
    emitQuicTpInt(tp, 0x01, 30000);          // max_idle_timeout (ms)
    emitQuicTpInt(tp, 0x03, 1452);           // max_udp_payload_size
    emitQuicTpInt(tp, 0x04, 12582912);       // initial_max_data
    emitQuicTpInt(tp, 0x05, 6291456);        // initial_max_stream_data_bidi_local
    emitQuicTpInt(tp, 0x06, 6291456);        // initial_max_stream_data_bidi_remote
    emitQuicTpInt(tp, 0x07, 1048576);        // initial_max_stream_data_uni
    emitQuicTpInt(tp, 0x08, 100);            // initial_max_streams_bidi
    emitQuicTpInt(tp, 0x09, 100);            // initial_max_streams_uni
    emitQuicTpInt(tp, 0x0A, 3);              // ack_delay_exponent
    emitQuicTpInt(tp, 0x0B, 25);             // max_ack_delay
    emitQuicTpEmpty(tp, 0x0C);               // disable_active_migration (presence)
    emitQuicTpInt(tp, 0x0E, 4);              // active_connection_id_limit
    emitQuicTpBytes(tp, 0x0F, initialScid);  // initial_source_connection_id
    return tp;
}

// Wave 29-499.230 — ngtcp2_callbacks stubs. RFC 9000 §17.4 / ngtcp2 API:
// these are invoked by ngtcp2 during conn lifecycle. Mandatory for client:
//   recv_crypto_data, encrypt, decrypt, hp_mask, rand, get_new_connection_id.
// Optional but useful: handshake_completed, recv_stream_data, update_key,
// acked_stream_data_offset, stream_open, stream_close.
//
// Each callback receives ngtcp2_conn* + a user_data pointer (we register
// DriftstackQuicConn* there in conn_client_new_versioned). The user_data
// recovery is symmetric to the SSL_get_ex_data pattern in Wave 29-499.224
// but for ngtcp2's own user_data slot.

// client_initial: invoked when ngtcp2_conn_client_new_versioned finishes
// initial setup. Client must call ngtcp2_conn_submit_crypto_data with
// the first CRYPTO frame (ClientHello) — but we drive TLS via
// SSL_do_handshake from driftstackHttp3Execute which fires our
// add_handshake_data quic_method callback → ngtcp2_conn_submit_crypto_data.
// So this callback returns 0 immediately; the actual ClientHello flows
// through the BoringSSL → ssl_quic_method bridge.
[[maybe_unused]] static int driftstackNgtcp2ClientInitial(ngtcp2_conn* /*conn*/, void* /*user_data*/)
{
    static bool loggedOnce = false;
    if (!loggedOnce) {
        loggedOnce = true;
        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.249] client_initial callback fired — BoringSSL TLS path drives ClientHello via add_handshake_data");
    }
    return 0;
}

// Wave 29-499.252 — recv_retry: mandatory for client (assertion at
// ngtcp2_conn.c:1227). Invoked when server sends Retry packet asking
// the client to repeat the Initial with a token. Production code would
// re-derive Initial keys with the new dcid + retry packet's data, then
// continue. Stub returns 0 (no retry handling in scaffold; production
// path adds retry-token retransmit logic).
[[maybe_unused]] static int driftstackNgtcp2RecvRetry(ngtcp2_conn* /*conn*/,
    const void* /*hd*/, void* /*user_data*/)
{
    WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.252] recv_retry fired — server requested Retry; production scaffold would re-key + retransmit. Returning 0 (drop).");
    return 0;
}

// Wave 29-499.253 — remaining mandatory client callbacks. ngtcp2 asserts
// each on conn_new. Stubs that do the minimum to satisfy the contract:
//   update_key: key update for 1-RTT (RFC 9001 §6). Caller derives new
//     traffic secrets via HKDF-Expand-Label "quic ku" + key/iv from those.
//   delete_crypto_aead_ctx / delete_crypto_cipher_ctx: free the
//     DriftstackQuicAeadCtx/HpCtx we heap-allocated.
//   get_path_challenge_data: 8 random bytes for PATH_CHALLENGE frames.
[[maybe_unused]] static int driftstackNgtcp2UpdateKey(ngtcp2_conn* /*conn*/,
    uint8_t* /*rx_secret*/, uint8_t* /*tx_secret*/,
    void* /*rx_aead_ctx*/, uint8_t* /*rx_iv*/,
    void* /*tx_aead_ctx*/, uint8_t* /*tx_iv*/,
    const uint8_t* /*current_rx_secret*/, const uint8_t* /*current_tx_secret*/,
    size_t /*secretlen*/, void* /*user_data*/)
{
    // Production: HKDF-Expand-Label(current_rx_secret, "quic ku", "", secretlen)
    // → new rx_secret; same for tx. Then derive new aead key+iv. Stub
    // returns 0 to allow handshake to complete; 1-RTT key updates won't
    // happen without this — that's OK for the smoke (handshake only).
    return 0;
}

// TODO Wave 29-499.254: structs DriftstackQuicAeadCtx/HpCtx are defined
// later in the file (near encrypt callbacks .231-.232). C++ delete with
// only forward declaration is UB. For the scaffold, leak — ngtcp2 only
// asks for delete at conn destruction time which is fine for our
// short-lived smoke test. Production layout: move struct defs earlier
// OR move delete impls later. Stub uses no-op delete.
[[maybe_unused]] static void driftstackNgtcp2DeleteCryptoAeadCtx(ngtcp2_conn* /*conn*/,
    void* /*aead_ctx_native*/, void* /*user_data*/)
{
    // Intentional leak — see TODO above.
}

[[maybe_unused]] static void driftstackNgtcp2DeleteCryptoCipherCtx(ngtcp2_conn* /*conn*/,
    void* /*cipher_ctx_native*/, void* /*user_data*/)
{
    // Intentional leak — see TODO above.
}

[[maybe_unused]] static int driftstackNgtcp2GetPathChallengeData(ngtcp2_conn* /*conn*/,
    uint8_t* data, void* /*user_data*/)
{
    arc4random_buf(data, 8);  // NGTCP2_PATH_CHALLENGE_DATALEN = 8
    return 0;
}

[[maybe_unused]] static int driftstackNgtcp2VersionNegotiation(ngtcp2_conn* /*conn*/,
    uint32_t /*version*/, const ngtcp2_cid* /*client_dcid*/, void* /*user_data*/)
{
    return 0;
}

// recv_crypto_data: ngtcp2 delivers a CRYPTO frame's payload. Hand to
// BoringSSL via SSL_provide_quic_data so the TLS state machine processes
// it (which in turn triggers our ssl_quic_method_st callbacks for keys +
// outbound handshake data).
[[maybe_unused]] static int driftstackNgtcp2RecvCryptoData(ngtcp2_conn* /*conn*/,
    ngtcp2_encryption_level level, uint64_t /*offset*/,
    const uint8_t* data, size_t datalen, void* user_data)
{
    DriftstackQuicConn* qc = static_cast<DriftstackQuicConn*>(user_data);
    if (!qc || !qc->ssl) return -1;
    auto& f = boringSslQuicFns();
    ssl_encryption_level_t sslLevel = static_cast<ssl_encryption_level_t>(level);
    int rv = f.SSL_provide_quic_data(qc->ssl, sslLevel, data, datalen);
    if (rv != 1) {
        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.230] RecvCryptoData: SSL_provide_quic_data FAILED level=%d datalen=%zu rv=%d",
            static_cast<int>(level), datalen, rv);
        return -1;
    }
    return 0;
}

// rand: ngtcp2 needs random bytes for CIDs + retry tokens. Use arc4random_buf
// which is cryptographically secure on macOS (libsystem-provided).
[[maybe_unused]] static void driftstackNgtcp2Rand(uint8_t* dest, size_t destlen,
    const ngtcp2_rand_ctx* /*rand_ctx*/)
{
    arc4random_buf(dest, destlen);
}

// get_new_connection_id: generate fresh CID with stateless reset token.
// Called when ngtcp2 wants to issue a new connection ID.
[[maybe_unused]] static int driftstackNgtcp2GetNewConnectionId(ngtcp2_conn* /*conn*/,
    ngtcp2_cid* cid, uint8_t* token, size_t cidlen, void* /*user_data*/)
{
    arc4random_buf(cid->data, cidlen);
    cid->datalen = cidlen;
    arc4random_buf(token, NGTCP2_STATELESS_RESET_TOKENLEN);
    return 0;
}

// handshake_completed: optional, but useful for state tracking.
[[maybe_unused]] static int driftstackNgtcp2HandshakeCompleted(ngtcp2_conn* /*conn*/, void* user_data)
{
    DriftstackQuicConn* qc = static_cast<DriftstackQuicConn*>(user_data);
    if (qc) qc->handshakeCompleted = true;
    WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.230] QUIC handshake COMPLETED (BoringSSL TLS 1.3 over ngtcp2 reached 1-RTT keys)");
    return 0;
}

// encrypt / decrypt: per-packet AEAD per RFC 9001 §5.3. Each QUIC packet's
// payload is AEAD-protected with key/iv installed via Wave 29-499.225.
// ngtcp2 calls these with (key, nonce, plaintext, aad). We use LibreSSL's
// EVP_AEAD (already wired in DriftstackCrypto.mm for TLS 1.3 record layer).
//
// TODO Wave 29-499.231: wire to driftstackAESGCMEncrypt / Decrypt helpers
// (similar to DriftstackCrypto's existing TLS 1.3 path; reuse the same
// EVP_AEAD_CTX construction).
// Wave 29-499.231 — AEAD callbacks wired to DriftstackCrypto's existing
// LibreSSL EVP_AEAD helpers (the same ones powering PathB v2 TLS 1.3 record
// encryption per Waves .190-.219). ngtcp2 passes an opaque
// ngtcp2_crypto_aead_ctx whose native_handle we populate with our own
// DriftstackQuicAeadCtx { key, key_len, is_aes256, is_chacha20 } at
// install-key time (Wave .232 will wire the install path).
struct DriftstackQuicAeadCtx {
    Vector<uint8_t> key;
    bool isAes256 { false };       // 0x1302 (32-byte key)
    bool isChacha20 { false };     // 0x1303 (32-byte key)
};

[[maybe_unused]] static int driftstackNgtcp2Encrypt(uint8_t* dest,
    const ngtcp2_crypto_aead* /*aead*/,
    const ngtcp2_crypto_aead_ctx* aead_ctx,
    const uint8_t* plaintext, size_t plaintextlen,
    const uint8_t* nonce, size_t noncelen,
    const uint8_t* aad, size_t aadlen)
{
    if (!aead_ctx || !aead_ctx->native_handle)
        return -1;
    auto* ctx = static_cast<DriftstackQuicAeadCtx*>(aead_ctx->native_handle);

    Vector<uint8_t> nonceVec(noncelen);
    memcpy(nonceVec.mutableSpan().data(), nonce, noncelen);
    Vector<uint8_t> ptVec(plaintextlen);
    if (plaintextlen) memcpy(ptVec.mutableSpan().data(), plaintext, plaintextlen);
    Vector<uint8_t> aadVec(aadlen);
    if (aadlen) memcpy(aadVec.mutableSpan().data(), aad, aadlen);

    Vector<uint8_t> result;
    if (ctx->isAes256)
        result = WebKit::driftstackAes256GcmEncrypt(ctx->key, nonceVec, ptVec, aadVec);
    else
        result = WebKit::driftstackAes128GcmEncrypt(ctx->key, nonceVec, ptVec, aadVec);
    // ChaCha20-Poly1305 (0x1303): TODO Wave .232 - LibreSSL has it via
    // EVP_aead_chacha20_poly1305; needs same dlsym wrapping.

    if (result.size() != plaintextlen + 16) // GCM tag is 16 bytes
        return -1;
    memcpy(dest, result.span().data(), result.size());
    return 0;
}

[[maybe_unused]] static int driftstackNgtcp2Decrypt(uint8_t* dest,
    const ngtcp2_crypto_aead* /*aead*/,
    const ngtcp2_crypto_aead_ctx* aead_ctx,
    const uint8_t* ciphertext, size_t ciphertextlen,
    const uint8_t* nonce, size_t noncelen,
    const uint8_t* aad, size_t aadlen)
{
    if (!aead_ctx || !aead_ctx->native_handle)
        return -1;
    auto* ctx = static_cast<DriftstackQuicAeadCtx*>(aead_ctx->native_handle);

    Vector<uint8_t> nonceVec(noncelen);
    memcpy(nonceVec.mutableSpan().data(), nonce, noncelen);
    Vector<uint8_t> ctVec(ciphertextlen);
    if (ciphertextlen) memcpy(ctVec.mutableSpan().data(), ciphertext, ciphertextlen);
    Vector<uint8_t> aadVec(aadlen);
    if (aadlen) memcpy(aadVec.mutableSpan().data(), aad, aadlen);

    Vector<uint8_t> result;
    if (ctx->isAes256)
        result = WebKit::driftstackAes256GcmDecrypt(ctx->key, nonceVec, ctVec, aadVec);
    else
        result = WebKit::driftstackAes128GcmDecrypt(ctx->key, nonceVec, ctVec, aadVec);

    if (result.isEmpty())
        return -1;  // AEAD verification failed
    memcpy(dest, result.span().data(), result.size());
    return 0;
}

// Wave 29-499.232 — header protection per RFC 9001 §5.4. Single-block
// AES-ECB encrypt of the 16-byte sample with the hp_key produces a 16-byte
// mask used to XOR header bytes for packet-number-length + reserved bits
// obfuscation.
//
// DriftstackQuicHpCtx wraps the hp_key bytes (we stash this struct in
// ngtcp2_crypto_cipher_ctx::native_handle at install time).
struct DriftstackQuicHpCtx {
    Vector<uint8_t> key;
    bool isAes256 { false };
    bool isChacha20 { false };
};

// AES-128-ECB single-block via LibreSSL AES_encrypt + AES_set_encrypt_key.
// These are stable symbols across LibreSSL / OpenSSL / BoringSSL ABIs.
// AES_KEY layout = struct { uint32_t rd_key[60]; int rounds; } = 244 bytes
// — we allocate a 256-byte buffer to be safe.
struct DriftstackAesEncryptFns {
    int (*set_encrypt_key)(const uint8_t* userKey, const int bits, void* key) = nullptr;
    void (*encrypt)(const uint8_t* in, uint8_t* out, const void* key) = nullptr;
    bool ready = false;
};

static DriftstackAesEncryptFns& aesEncryptFns()
{
    static DriftstackAesEncryptFns s;
    return s;
}

static bool resolveAesEncryptFns()
{
    auto& f = aesEncryptFns();
    if (f.ready) return true;
    f.set_encrypt_key = reinterpret_cast<decltype(f.set_encrypt_key)>(dlsym(RTLD_DEFAULT, "AES_set_encrypt_key"));
    f.encrypt = reinterpret_cast<decltype(f.encrypt)>(dlsym(RTLD_DEFAULT, "AES_encrypt"));
    f.ready = f.set_encrypt_key && f.encrypt;
    if (!f.ready) {
        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.232] resolveAesEncryptFns: AES_set_encrypt_key=%p AES_encrypt=%p — header protection will fail",
            reinterpret_cast<void*>(f.set_encrypt_key), reinterpret_cast<void*>(f.encrypt));
    }
    return f.ready;
}

[[maybe_unused]] static int driftstackNgtcp2HpMask(uint8_t* dest,
    const ngtcp2_crypto_cipher* /*hp*/,
    const ngtcp2_crypto_cipher_ctx* hp_ctx,
    const uint8_t* sample)
{
    if (!hp_ctx || !hp_ctx->native_handle)
        return -1;
    if (!resolveAesEncryptFns())
        return -1;

    auto* ctx = static_cast<DriftstackQuicHpCtx*>(hp_ctx->native_handle);
    auto& f = aesEncryptFns();

    if (ctx->isChacha20) {
        // RFC 9001 §5.4.4: ChaCha20 header protection.
        // mask = ChaCha20(hp_key, counter=sample[0..4], nonce=sample[4..16], zero[5])
        // TODO Wave .233: wire ChaCha20 helper. AES-GCM path covers 99% of
        // QUIC handshakes; ChaCha20 is fallback for older mobile clients.
        return -1;
    }

    uint8_t aesKeyBuf[256] = { };
    int bits = ctx->isAes256 ? 256 : 128;
    if (f.set_encrypt_key(ctx->key.span().data(), bits, aesKeyBuf) != 0)
        return -1;
    f.encrypt(sample, dest, aesKeyBuf);
    return 0;
}

[[maybe_unused]] static void initDriftstackNgtcp2Callbacks(ngtcp2_callbacks* cb)
{
    memset(cb, 0, sizeof(*cb));
    // Wave 29-499.249 — client_initial is MANDATORY per ngtcp2 docs for
    // client-side conn. Without it ngtcp2_conn_client_new_versioned hits
    // NULL ptr in its init path → Translation fault.
    cb->client_initial = driftstackNgtcp2ClientInitial;
    cb->recv_retry = reinterpret_cast<decltype(cb->recv_retry)>(driftstackNgtcp2RecvRetry);
    cb->update_key = reinterpret_cast<decltype(cb->update_key)>(driftstackNgtcp2UpdateKey);
    cb->delete_crypto_aead_ctx = reinterpret_cast<decltype(cb->delete_crypto_aead_ctx)>(driftstackNgtcp2DeleteCryptoAeadCtx);
    cb->delete_crypto_cipher_ctx = reinterpret_cast<decltype(cb->delete_crypto_cipher_ctx)>(driftstackNgtcp2DeleteCryptoCipherCtx);
    cb->get_path_challenge_data = driftstackNgtcp2GetPathChallengeData;
    cb->version_negotiation = reinterpret_cast<decltype(cb->version_negotiation)>(driftstackNgtcp2VersionNegotiation);
    cb->recv_crypto_data = driftstackNgtcp2RecvCryptoData;
    cb->handshake_completed = driftstackNgtcp2HandshakeCompleted;
    cb->encrypt = driftstackNgtcp2Encrypt;
    cb->decrypt = driftstackNgtcp2Decrypt;
    cb->hp_mask = driftstackNgtcp2HpMask;
    cb->rand = driftstackNgtcp2Rand;
    cb->get_new_connection_id = driftstackNgtcp2GetNewConnectionId;
    // recv_stream_data, acked_stream_data_offset, stream_open, stream_close,
    // update_key, recv_version_negotiation, recv_token, send_token,
    // remove_connection_id, path_validation: optional callbacks added on
    // demand in subsequent waves (.231+).
}

// Wave 29-499.229 — iPhone-matched ngtcp2_settings + ngtcp2_transport_params
// initializers. Uses real ngtcp2_settings_default + ngtcp2_transport_params_default
// (dlsym'd at runtime) to zero-init structs to library-recommended baseline,
// then overlays iPhone-Safari-typical values.
//
// ngtcp2_duration is uint64_t nanoseconds. RFC 9000 wire transport_params
// encodes max_idle_timeout / max_ack_delay as milliseconds (varint); ngtcp2
// internally translates from its nanosecond struct field.
[[maybe_unused]] static void initIphoneNgtcp2Settings(ngtcp2_settings* settings, ngtcp2_tstamp initialTs)
{
    auto& f = ngtcp2Fns();
    f.settings_default_versioned(NGTCP2_SETTINGS_VERSION, settings);
    settings->initial_ts = initialTs;
    // Defaults are otherwise reasonable; iPhone-specific overrides go here
    // (e.g., congestion control algorithm) after pcap capture per Wave .227.
}

[[maybe_unused]] static void initIphoneNgtcp2TransportParams(ngtcp2_transport_params* params,
    std::span<const uint8_t> initialScid)
{
    auto& f = ngtcp2Fns();
    f.transport_params_default_versioned(NGTCP2_TRANSPORT_PARAMS_VERSION, params);
    // Override to match values targeted in Wave 29-499.226's wire-format builder.
    params->max_idle_timeout = 30ULL * NGTCP2_SECONDS;
    params->max_udp_payload_size = 1452;
    params->initial_max_data = 12582912;
    params->initial_max_stream_data_bidi_local = 6291456;
    params->initial_max_stream_data_bidi_remote = 6291456;
    params->initial_max_stream_data_uni = 1048576;
    params->initial_max_streams_bidi = 100;
    params->initial_max_streams_uni = 100;
    params->ack_delay_exponent = 3;
    params->max_ack_delay = 25 * NGTCP2_MILLISECONDS;
    params->disable_active_migration = 1;  // presence flag
    params->active_connection_id_limit = 4;
    // Wave 29-499.251 — initial_source_connection_id is SERVER-only per
    // ngtcp2 assertion (ngtcp2_conn.c:1215 "!params->initial_scid_present").
    // Client must NOT set it; the server learns the client's scid from the
    // Initial packet header field. Leaving these fields zeroed satisfies the
    // assertion + matches RFC 9000 §18.2 (initial_source_connection_id is
    // a server-set transport_param).
    (void)initialScid;  // mark used (parameter kept for API stability)
}

[[maybe_unused]] static const ssl_quic_method_st& driftstackQuicMethod()
{
    static const ssl_quic_method_st s_method = {
        driftstackQuicSetReadSecret,
        driftstackQuicSetWriteSecret,
        driftstackQuicAddHandshakeData,
        driftstackQuicFlushFlight,
        driftstackQuicSendAlert,
    };
    return s_method;
}

// Wave 29-499.233 — ngtcp2_conn client allocation + initial-key install.
//
// Pulls together .224-.232 pieces into a single helper. Caller provides:
//   - ssl: pointer from SSL_new (we'll wire SSL_set_quic_method + ex_data)
//   - localSock / remoteSock: bound BSD sockets for QUIC packet I/O. Local
//     should be a fresh UDP socket; remote is the address of the destination
//     (or the SOCKS5 relay endpoint).
//
// Returns a heap-allocated DriftstackQuicConn whose ownership transfers
// to the caller; freed via destroyDriftstackQuicConn.
[[maybe_unused]] static void destroyDriftstackQuicConn(DriftstackQuicConn* qc)
{
    if (!qc) return;
    if (qc->conn) {
        auto& nf = ngtcp2Fns();
        if (nf.conn_del) nf.conn_del(qc->conn);
    }
    delete qc;
}

[[maybe_unused]] static DriftstackQuicConn* connectQuic(void* ssl,
    const struct sockaddr* localAddr, socklen_t localAddrLen,
    const struct sockaddr* remoteAddr, socklen_t remoteAddrLen)
{
    auto& nf = ngtcp2Fns();
    auto& bsf = boringSslQuicFns();
    if (!nf.ready || !bsf.ready) {
        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.233] connectQuic: ngtcp2 (%d) or BoringSSL QUIC (%d) not resolved",
            nf.ready, bsf.ready);
        return nullptr;
    }

    auto* qc = new DriftstackQuicConn { };
    qc->ssl = ssl;
    WTFLogAlways("[Wave29-499.247c] connectQuic entered; before cid_init");

    // 1. Allocate dcid (8-20 random bytes per RFC 9000 §17.2) + scid (8 random
    //    bytes is customary client choice; Apple Safari uses 8).
    // Wave 29-499.247d — generate random bytes FIRST then pass to cid_init
    // (passing nullptr+datalen=8 caused cid_init to memcpy from NULL → crash).
    uint8_t dcidBytes[8], scidBytes[8];
    arc4random_buf(dcidBytes, 8);
    arc4random_buf(scidBytes, 8);
    ngtcp2_cid dcid { }, scid { };
    nf.cid_init(&dcid, dcidBytes, 8);
    nf.cid_init(&scid, scidBytes, 8);
    WTFLogAlways("[Wave29-499.247c] cid_init done (dcid.datalen=%zu scid.datalen=%zu)", dcid.datalen, scid.datalen);

    // 2. Initialize settings + transport_params via .229 helpers.
    ngtcp2_settings settings { };
    initIphoneNgtcp2Settings(&settings, /*initialTs=*/0);
    WTFLogAlways("[Wave29-499.247c] settings init done");

    ngtcp2_transport_params tp { };
    std::span<const uint8_t> scidSpan = unsafeMakeSpan(scid.data, scid.datalen);
    initIphoneNgtcp2TransportParams(&tp, scidSpan);
    WTFLogAlways("[Wave29-499.247c] transport_params init done");

    // 3. Populate callbacks via .230-.232.
    ngtcp2_callbacks cb { };
    initDriftstackNgtcp2Callbacks(&cb);

    // 4. Build ngtcp2_path from sockaddrs.
    ngtcp2_path path { };
    nf.addr_init(&path.local, localAddr, localAddrLen);
    nf.addr_init(&path.remote, remoteAddr, remoteAddrLen);

    // 5. Allocate the conn. QUIC v1 (RFC 9000) version constant is provided
    // by ngtcp2.h (NGTCP2_PROTO_VER_V1 = 0x00000001U).
    WTFLogAlways("[Wave29-499.247c] before conn_client_new_versioned");
    int rv = nf.conn_client_new_versioned(&qc->conn, &dcid, &scid, &path,
        NGTCP2_PROTO_VER_V1,
        NGTCP2_CALLBACKS_VERSION, &cb,
        NGTCP2_SETTINGS_VERSION, &settings,
        NGTCP2_TRANSPORT_PARAMS_VERSION, &tp,
        nullptr, /*user_data=*/qc);
    WTFLogAlways("[Wave29-499.247c] conn_client_new_versioned returned rv=%d conn=%p", rv, qc->conn);
    if (rv != 0) {
        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.233] conn_client_new_versioned FAILED rv=%d", rv);
        destroyDriftstackQuicConn(qc);
        return nullptr;
    }

    // 6. Wire BoringSSL → DriftstackQuicConn linkage:
    //    a) SSL_set_quic_method(ssl, &driftstackQuicMethod) — TLS handshake
    //       messages now flow through our 5 ssl_quic_method_st callbacks.
    //    b) SSL_set_ex_data(ssl, idx, qc) — qc reachable from the callbacks
    //       via SSL_get_ex_data.
    if (bsf.SSL_set_quic_method(ssl, &driftstackQuicMethod()) != 1) {
        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.233] SSL_set_quic_method FAILED");
        destroyDriftstackQuicConn(qc);
        return nullptr;
    }
    if (quicConnExDataIndex() < 0)
        quicConnExDataIndex() = bsf.SSL_get_ex_new_index(0, nullptr, nullptr, nullptr, nullptr);
    if (quicConnExDataIndex() >= 0)
        bsf.SSL_set_ex_data(ssl, quicConnExDataIndex(), qc);

    // 7. Encode iPhone transport_params for SSL_set_quic_transport_params.
    //    These travel in the ClientHello's quic_transport_parameters extension
    //    and are bound to the TLS transcript per RFC 9001 §8.2.
    Vector<uint8_t> tpBytes = buildIphoneQuicTransportParams(scidSpan);
    if (bsf.SSL_set_quic_transport_params(ssl, tpBytes.span().data(), tpBytes.size()) != 1) {
        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.233] SSL_set_quic_transport_params FAILED (tpBytes=%zu)", tpBytes.size());
        destroyDriftstackQuicConn(qc);
        return nullptr;
    }

    // 8. RFC 9001 §5.2: derive Initial keys from dcid + install. QUIC v1
    // initial_salt = 0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a (20 bytes).
    static const uint8_t kQuicV1InitialSalt[20] = {
        0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
        0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a
    };
    Vector<uint8_t> saltVec(20);
    memcpy(saltVec.mutableSpan().data(), kQuicV1InitialSalt, 20);
    Vector<uint8_t> dcidVec(dcid.datalen);
    memcpy(dcidVec.mutableSpan().data(), dcid.data, dcid.datalen);

    Vector<uint8_t> initialSecret = WebKit::driftstackHkdfExtractSha256(saltVec, dcidVec);
    if (initialSecret.size() != 32) {
        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.234] HKDF-Extract initial_secret FAILED (got %zu bytes)", initialSecret.size());
        destroyDriftstackQuicConn(qc);
        return nullptr;
    }

    Vector<uint8_t> emptyCtx;
    Vector<uint8_t> clientInitialSecret = WebKit::driftstackHkdfExpandLabelSha256(initialSecret, "client in", emptyCtx, 32);
    Vector<uint8_t> serverInitialSecret = WebKit::driftstackHkdfExpandLabelSha256(initialSecret, "server in", emptyCtx, 32);
    if (clientInitialSecret.size() != 32 || serverInitialSecret.size() != 32) {
        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.234] HKDF-Expand-Label client/server in FAILED (sizes %zu/%zu)",
            clientInitialSecret.size(), serverInitialSecret.size());
        destroyDriftstackQuicConn(qc);
        return nullptr;
    }

    // Derive {key,iv,hp} for both directions via .225 helper. cipher=nullptr
    // forces secret_len=32 fallback → AES-128-GCM-SHA256 (QUIC Initial cipher).
    Vector<uint8_t> txKey, txIV, txHp, rxKey, rxIV, rxHp;
    if (!deriveQuicKeyMaterial(clientInitialSecret.span().data(), 32, /*cipher=*/nullptr, txKey, txIV, txHp)
        || !deriveQuicKeyMaterial(serverInitialSecret.span().data(), 32, /*cipher=*/nullptr, rxKey, rxIV, rxHp)) {
        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.234] Initial key material derivation FAILED");
        destroyDriftstackQuicConn(qc);
        return nullptr;
    }

    // Heap-allocate aead_ctx + hp_ctx innards (ngtcp2 holds pointers for the
    // life of the conn). Leak intentionally — they're freed when qc is freed
    // via the explicit deletes below if install fails.
    auto* tx_aead = new DriftstackQuicAeadCtx { txKey, false, false };
    auto* rx_aead = new DriftstackQuicAeadCtx { rxKey, false, false };
    auto* tx_hp_inner = new DriftstackQuicHpCtx { txHp, false, false };
    auto* rx_hp_inner = new DriftstackQuicHpCtx { rxHp, false, false };

    ngtcp2_crypto_aead_ctx tx_aead_ctx { tx_aead };
    ngtcp2_crypto_aead_ctx rx_aead_ctx { rx_aead };
    ngtcp2_crypto_cipher_ctx tx_hp_ctx { tx_hp_inner };
    ngtcp2_crypto_cipher_ctx rx_hp_ctx { rx_hp_inner };

    int kv = nf.conn_install_initial_key(qc->conn,
        &rx_aead_ctx, rxIV.span().data(), &rx_hp_ctx,
        &tx_aead_ctx, txIV.span().data(), &tx_hp_ctx,
        12);  // ivlen
    if (kv != 0) {
        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.234] conn_install_initial_key FAILED rv=%d", kv);
        delete tx_aead; delete rx_aead; delete tx_hp_inner; delete rx_hp_inner;
        destroyDriftstackQuicConn(qc);
        return nullptr;
    }

    WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.234] connectQuic: COMPLETE — ngtcp2_conn allocated + BoringSSL QUIC method wired + iPhone transport_params set + RFC 9001 §5.2 Initial keys installed (client+server, AES-128-GCM-SHA256 derived from dcid via QUIC v1 salt). dcid_len=%zu scid_len=%zu tpBytes_len=%zu. Ready for handshake event loop (Wave .235).",
        dcid.datalen, scid.datalen, tpBytes.size());
    return qc;
}

// Wave 29-499.235 — event loop primitives. The caller drives the QUIC
// handshake via writePacket/readPacket; SOCKS5 §7 wrap/unwrap happens at
// the call site between these and the wire (sendto/recvfrom).
//
// Monotonic timestamp (nanoseconds since boot). ngtcp2 uses this for
// pacing, packet number generation, RTT estimation.
[[maybe_unused]] static ngtcp2_tstamp driftstackQuicTimestampNow()
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<ngtcp2_tstamp>(ts.tv_sec) * 1000000000ULL
        + static_cast<ngtcp2_tstamp>(ts.tv_nsec);
}

// Produce the next outbound QUIC packet (or 0 if nothing to send right
// now). The returned bytes are the raw QUIC packet — caller must SOCKS5
// §7 wrap (with destination = the QUIC peer endpoint, NOT the proxy) and
// sendto the relay socket. Returns -1 on conn-level error.
[[maybe_unused]] static ssize_t driftstackQuicWritePacket(DriftstackQuicConn* qc,
    uint8_t* buf, size_t buflen)
{
    if (!qc || !qc->conn) return -1;
    auto& nf = ngtcp2Fns();
    ngtcp2_pkt_info pi { };
    // Use writev_stream with stream_id=-1 + datav=NULL for handshake-only
    // packets (no application data yet). After handshake completes, use
    // stream_id=0 + nghttp3-produced datav for HTTP/3 request emission.
    ngtcp2_ssize n = nf.conn_writev_stream_versioned(qc->conn, /*path=*/nullptr,
        NGTCP2_PKT_INFO_VERSION, &pi, buf, buflen, /*pdatalen=*/nullptr,
        /*flags=*/0, /*stream_id=*/-1,
        /*datav=*/nullptr, /*datavcnt=*/0,
        driftstackQuicTimestampNow());
    return n;
}

// Feed an inbound QUIC packet (post-§7-unwrap, raw QUIC bytes from peer)
// into the conn. ngtcp2 decrypts via our encrypt/decrypt callbacks,
// dispatches CRYPTO frames to BoringSSL via recv_crypto_data, and updates
// internal state. Returns 0 on success, -1 on protocol/auth error.
[[maybe_unused]] static int driftstackQuicReadPacket(DriftstackQuicConn* qc,
    const uint8_t* buf, size_t buflen,
    const struct sockaddr* peerAddr, socklen_t peerAddrLen,
    const struct sockaddr* localAddr, socklen_t localAddrLen)
{
    if (!qc || !qc->conn) return -1;
    auto& nf = ngtcp2Fns();
    ngtcp2_path path { };
    nf.addr_init(&path.local, localAddr, localAddrLen);
    nf.addr_init(&path.remote, peerAddr, peerAddrLen);
    ngtcp2_pkt_info pi { };
    return static_cast<int>(nf.conn_read_pkt_versioned(qc->conn, &path,
        NGTCP2_PKT_INFO_VERSION, &pi, buf, buflen, driftstackQuicTimestampNow()));
}

// Sketch of caller-side event loop (Wave .236 will wire this into
// driftstackHttp3Execute):
//
//   DriftstackQuicConn* qc = connectQuic(ssl, &local, llen, &peer, plen);
//   uint8_t buf[1500];
//   while (!qc->handshakeCompleted) {
//       // Produce outbound packet(s)
//       for (;;) {
//           ssize_t n = driftstackQuicWritePacket(qc, buf, sizeof(buf));
//           if (n <= 0) break;
//           // §7 wrap with destination = peer (the actual QUIC server)
//           Vector<uint8_t> framed = socks5Framing::wrap(peer, {buf, n});
//           sendto(relayFd, framed.data(), framed.size(), 0, &relay, rlen);
//       }
//       // Wait for inbound (with timeout per ngtcp2 expiry)
//       ssize_t r = recvfrom(relayFd, buf, sizeof(buf), 0, ...);
//       if (r > 0) {
//           // §7 unwrap
//           Socks5Framing::Endpoint src; Vector<uint8_t> payload;
//           Socks5Framing::unwrap({buf, r}, src, payload);
//           // Feed to ngtcp2
//           driftstackQuicReadPacket(qc, payload.data(), payload.size(),
//               (sockaddr*)&peerSa, peerSaLen, (sockaddr*)&localSa, localSaLen);
//       }
//   }
//   // qc->handshakeCompleted = true → install nghttp3 + emit h3 HEADERS

} // anonymous namespace

DriftstackHttp3Response driftstackHttp3Execute(void* /*socks5UdpRelay*/, const DriftstackHttp3Request& request)
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

    // Wave 29-499.236 — wire connectQuic() entry path. This sets up:
    //   - SSL_CTX with TLS 1.3 + ALPN "h3" + DriftstackCustomTLS path
    //   - SSL_new + SSL_set_tlsext_host_name(host) + SSL_set_connect_state
    //   - connectQuic() — ngtcp2 conn + initial keys
    //   - SSL_do_handshake — triggers BoringSSL TLS state machine which
    //     invokes our ssl_quic_method_st callbacks (Wave .224-.225)
    //
    // The full event loop (write_pkt → SOCKS5 §7 → sendto + recvfrom →
    // §7 unwrap → read_pkt with retransmit timer) is wired in Wave .237;
    // this iteration verifies the SSL bring-up + first conn_write_pkt
    // returns a valid Initial packet.
    auto& bsf = boringSslQuicFns();
    WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.244c] Calling TLS_client_method()...");
    const void* method = bsf.TLS_client_method();
    WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.244c] TLS_client_method()=%p — calling SSL_CTX_new...", method);
    void* ctx = bsf.SSL_CTX_new(method);
    WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.244c] SSL_CTX_new returned ctx=%p", ctx);
    if (!ctx) {
        resp.failed = true;
        resp.errorMessage = "SSL_CTX_new returned nullptr"_s;
        return resp;
    }
    // TLS 1.3 only (RFC 9001 §4.2 requirement for QUIC).
    constexpr int TLS1_3_VERSION = 0x0304;
    WTFLogAlways("[Wave29-499.246] before SSL_CTX_set_min_proto_version");
    bsf.SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    WTFLogAlways("[Wave29-499.246] before SSL_CTX_set_max_proto_version");
    bsf.SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);

    // ALPN "h3" — single 2-byte protocol per RFC 7301 wire format
    // (length-prefixed: 0x02 'h' '3').
    static const uint8_t alpnH3[] = { 0x02, 'h', '3' };
    WTFLogAlways("[Wave29-499.246] before SSL_CTX_set_alpn_protos");
    bsf.SSL_CTX_set_alpn_protos(ctx, alpnH3, sizeof(alpnH3));
    WTFLogAlways("[Wave29-499.246] before SSL_new");
    void* ssl = bsf.SSL_new(ctx);
    WTFLogAlways("[Wave29-499.246] SSL_new returned ssl=%p", ssl);
    if (!ssl) {
        bsf.SSL_CTX_free(ctx);
        resp.failed = true;
        resp.errorMessage = "SSL_new returned nullptr"_s;
        return resp;
    }
    bsf.SSL_set_connect_state(ssl);

    // SNI hostname from request
    CString hostUtf8 = request.authority.utf8();
    if (!hostUtf8.isNull()) {
        // Strip :port suffix for SNI
        const char* hostStr = hostUtf8.data();
        const char* colon = strchr(hostStr, ':');
        if (colon) {
            String hostOnly = String::fromUTF8(std::span<const char> { hostStr, static_cast<size_t>(colon - hostStr) });
            bsf.SSL_set_tlsext_host_name(ssl, hostOnly.utf8().data());
        } else {
            bsf.SSL_set_tlsext_host_name(ssl, hostStr);
        }
    }

    // Wave 29-499.238 — establish SOCKS5 UDP_ASSOCIATE relay (same shared
    // channel as WebRTC + WebTransport per Wave .102/.221 architecture).
    DriftstackRTC::RelayChannel relayChannel;
    DriftstackRTC::BridgeResult relayResult = DriftstackRTC::establishRelayChannel(relayChannel);
    if (relayResult != DriftstackRTC::BridgeResult::Success) {
        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.238] establishRelayChannel FAILED (result=%d) — h3 falls back to h2",
            static_cast<int>(relayResult));
        bsf.SSL_free(ssl);
        bsf.SSL_CTX_free(ctx);
        resp.failed = true;
        resp.errorMessage = "SOCKS5 UDP_ASSOCIATE failed for HTTP/3 transport"_s;
        return resp;
    }

    // Create + bind local UDP socket for receiving §7-wrapped responses
    // from the relay. The socket connects to the relayHost:relayPort so
    // sendto/recvfrom address the relay (which forwards to peer via §7
    // destination header).
    int udpFd = socket(AF_INET, SOCK_DGRAM, 0);
    if (udpFd < 0) {
        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.238] UDP socket() failed errno=%d", errno);
        bsf.SSL_free(ssl);
        bsf.SSL_CTX_free(ctx);
        resp.failed = true;
        resp.errorMessage = "UDP socket creation failed"_s;
        return resp;
    }
    struct sockaddr_in localBind { };
    localBind.sin_family = AF_INET;
    localBind.sin_addr.s_addr = htonl(INADDR_ANY);
    localBind.sin_port = 0;
    if (bind(udpFd, reinterpret_cast<struct sockaddr*>(&localBind), sizeof(localBind)) < 0) {
        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.238] UDP bind() failed errno=%d", errno);
        ::close(udpFd);
        bsf.SSL_free(ssl);
        bsf.SSL_CTX_free(ctx);
        resp.failed = true;
        resp.errorMessage = "UDP bind failed"_s;
        return resp;
    }
    // Read back the bound port (OS picked an ephemeral one).
    socklen_t localLen = sizeof(localBind);
    getsockname(udpFd, reinterpret_cast<struct sockaddr*>(&localBind), &localLen);
    uint16_t boundPort = ntohs(localBind.sin_port);

    // Build relay endpoint sockaddr for sendto/recvfrom target.
    struct sockaddr_in relaySa { };
    relaySa.sin_family = AF_INET;
    relaySa.sin_port = htons(relayChannel.relayPort);
    auto relayHostUtf8 = relayChannel.relayHost.utf8();
    inet_pton(AF_INET, relayHostUtf8.data(), &relaySa.sin_addr);

    // Peer addr for connectQuic. For this scaffold: cloudflare-quic.com
    // (1.1.1.1:443) — a known h3 server. Wave .239 wires request.authority
    // resolution via hardcodedSTUNHostnameLookup (and adds h3-specific
    // hostname → IPv4 mappings since the .94 map is STUN-focused).
    struct sockaddr_in local { };
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_ANY);
    local.sin_port = htons(boundPort);
    struct sockaddr_in peer { };
    peer.sin_family = AF_INET;
    peer.sin_addr.s_addr = htonl(0xA29F8760);  // 162.159.135.96 cloudflare-quic.com (Wave .256)
    peer.sin_port = htons(443);

    WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.238] UDP socket fd=%d localPort=%u, relay=%s:%u, peer=1.1.1.1:443. Ready for handshake event loop (Wave .239 wires sendto+recvfrom + timeout).",
        udpFd, boundPort, relayHostUtf8.data(), relayChannel.relayPort);

    WTFLogAlways("[Wave29-499.247] before connectQuic call");
    DriftstackQuicConn* qc = connectQuic(ssl,
        reinterpret_cast<const struct sockaddr*>(&local), sizeof(local),
        reinterpret_cast<const struct sockaddr*>(&peer), sizeof(peer));
    if (!qc) {
        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.237] connectQuic returned nullptr");
        bsf.SSL_free(ssl);
        bsf.SSL_CTX_free(ctx);
        resp.failed = true;
        resp.errorMessage = "connectQuic returned nullptr"_s;
        return resp;
    }

    // Wave 29-499.254 — removed standalone SSL_do_handshake + writePacket
    // (was for .237 scaffold verification; consumed the ClientHello before
    // the event loop could §7-wrap+sendto it, leading to packetsSent=0).
    // Event loop below does the full SSL_do_handshake + writePacket + §7
    // wrap + sendto inside iter 1.

    // Wave 29-499.239 — handshake event loop.
    // Each iteration: SSL_do_handshake → write_pkt → §7 wrap → sendto relay,
    // recvfrom (with timeout) → §7 unwrap → read_pkt. Repeat until
    // qc->handshakeCompleted or 5s wall-clock budget exhausted.
    Socks5Framing::Endpoint peerEp { "cloudflare-quic.com"_s, 443 };  // Wave .256
    constexpr int kMaxIterations = 20;
    constexpr int kPerRecvTimeoutMs = 250;
    int iters = 0;
    int packetsSent = 0;
    int packetsReceived = 0;
    while (iters < kMaxIterations && !qc->handshakeCompleted) {
        ++iters;
        // Drive TLS state machine. May fire quic_method.set_*_secret +
        // add_handshake_data → ngtcp2_conn_submit_crypto_data.
        bsf.SSL_do_handshake(ssl);

        // Drain all packets ngtcp2 wants to send right now.
        for (;;) {
            uint8_t pkt[1500];
            ssize_t n = driftstackQuicWritePacket(qc, pkt, sizeof(pkt));
            if (n <= 0) break;
            Vector<uint8_t> framed;
            if (!Socks5Framing::wrap(peerEp, std::span<const uint8_t> { pkt, static_cast<size_t>(n) }, framed))
                break;
            ssize_t s = sendto(udpFd, framed.span().data(), framed.size(), 0,
                reinterpret_cast<struct sockaddr*>(&relaySa), sizeof(relaySa));
            if (s > 0) ++packetsSent;
            static bool loggedFirstSendOnce = false;
            if (!loggedFirstSendOnce) {
                loggedFirstSendOnce = true;
                // Wave 29-499.257 — hex dump first 64 bytes of pre-§7 QUIC
                // packet to inspect Initial packet structure:
                //   byte 0:    long header flags (0xC0=fixed+long, +0x00=initial, +0x03=PN len-1)
                //   bytes 1-4: version (0x00000001 for QUIC v1)
                //   byte 5:    dcid length (8)
                //   bytes 6-13: dcid
                //   byte 14:   scid length (8)
                //   bytes 15-22: scid
                //   byte 23+: varint token len, token, varint length, packet number, encrypted payload
                auto b = [&](size_t i) -> unsigned { return i < static_cast<size_t>(n) ? pkt[i] : 0; };
                WTFLogAlways("[Wave29-499.257] FIRST 64 bytes of QUIC Initial pkt (pre-§7): %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
                    b(0), b(1), b(2), b(3), b(4), b(5), b(6), b(7),
                    b(8), b(9), b(10), b(11), b(12), b(13), b(14), b(15),
                    b(16), b(17), b(18), b(19), b(20), b(21), b(22), b(23),
                    b(24), b(25), b(26), b(27), b(28), b(29), b(30), b(31),
                    b(32), b(33), b(34), b(35), b(36), b(37), b(38), b(39),
                    b(40), b(41), b(42), b(43), b(44), b(45), b(46), b(47),
                    b(48), b(49), b(50), b(51), b(52), b(53), b(54), b(55),
                    b(56), b(57), b(58), b(59), b(60), b(61), b(62), b(63));
                WTFLogAlways("[Wave29-499.255] FIRST QUIC sendto: pkt=%zd framed=%zu sent=%zd errno=%d peer=cloudflare-quic.com:443 via relay",
                    n, framed.size(), s, s < 0 ? errno : 0);
            }
        }

        // Wait for inbound with a short per-iteration timeout.
        struct timeval tv { 0, kPerRecvTimeoutMs * 1000 };
        fd_set rs;
        FD_ZERO(&rs);
        FD_SET(udpFd, &rs);
        int sel = select(udpFd + 1, &rs, nullptr, nullptr, &tv);
        if (sel <= 0) continue;

        uint8_t inbound[2048];
        struct sockaddr_in from { };
        socklen_t fromLen = sizeof(from);
        ssize_t r = recvfrom(udpFd, inbound, sizeof(inbound), 0,
            reinterpret_cast<struct sockaddr*>(&from), &fromLen);
        if (r <= 0) continue;
        ++packetsReceived;
        static bool loggedFirstRecvOnce = false;
        if (!loggedFirstRecvOnce) {
            loggedFirstRecvOnce = true;
            WTFLogAlways("[Wave29-499.255] FIRST QUIC recvfrom: %zd bytes from %s:%u",
                r, inet_ntoa(from.sin_addr), ntohs(from.sin_port));
        }

        Socks5Framing::Endpoint src;
        Vector<uint8_t> payload;
        if (!Socks5Framing::unwrap(std::span<const uint8_t> { inbound, static_cast<size_t>(r) }, src, payload))
            continue;

        driftstackQuicReadPacket(qc, payload.span().data(), payload.size(),
            reinterpret_cast<struct sockaddr*>(&peer), sizeof(peer),
            reinterpret_cast<struct sockaddr*>(&local), sizeof(local));
    }

    WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.239] handshake event loop: iters=%d packetsSent=%d packetsReceived=%d handshakeCompleted=%d",
        iters, packetsSent, packetsReceived, qc->handshakeCompleted);

    ::close(udpFd);
    destroyDriftstackQuicConn(qc);
    bsf.SSL_free(ssl);
    bsf.SSL_CTX_free(ctx);

    resp.failed = true;
    resp.errorMessage = "Phase 3 HTTP/3 handshake scaffold: SOCKS5 §7-wrapped Initial packet sent; recv loop pending Wave .239"_s;
    return resp;
}

// Wave 29-499.240 — C-linkage smoke trigger callable from
// DriftstackQuicInterposeMain.mm at first nw_connection_create (which
// is when WebKit framework loaded + Driftstack symbols visible). Avoids
// the -no_inits linker restriction that blocked the static-constructor
// approach in .240b. Double-gated (DRIFTSTACK_PATHB_V2_H3=1 +
// DRIFTSTACK_PATHB_V2_H3_SMOKE=1) so production traffic is unaffected.
extern "C" void driftstackHttp3FireSmoke(void);
extern "C" void driftstackHttp3FireSmoke()
{
    const char* h3 = getenv("DRIFTSTACK_PATHB_V2_H3");
    const char* sm = getenv("DRIFTSTACK_PATHB_V2_H3_SMOKE");
    if (!h3 || h3[0] != '1' || !sm || sm[0] != '1')
        return;
    WebKit::driftstackHttp3Enabled();
}

bool driftstackHttp3Enabled()
{
    const char* env = getenv("DRIFTSTACK_PATHB_V2_H3");
    bool enabled = env && env[0] == '1';

    // Wave 29-499.240 — one-shot smoke test of the QUIC stack scaffolded
    // across .222-.239 when DRIFTSTACK_PATHB_V2_H3_SMOKE=1. Drives
    // driftstackHttp3Execute against 1.1.1.1:443 (Cloudflare h3) through
    // the SOCKS5 §7 relay, logs every step. Fires once per process.
    if (enabled) {
        static bool didSmoke = false;
        const char* smokeEnv = getenv("DRIFTSTACK_PATHB_V2_H3_SMOKE");
        if (!didSmoke && smokeEnv && smokeEnv[0] == '1') {
            didSmoke = true;
            WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.240] H3 smoke test: invoking driftstackHttp3Execute against 1.1.1.1:443");
            DriftstackHttp3Request req;
            req.method = "GET"_s;
            req.scheme = "https"_s;
            req.authority = "cloudflare-quic.com:443"_s;  // Wave .256: proper SNI
            req.path = "/"_s;
            DriftstackHttp3Response resp = driftstackHttp3Execute(nullptr, req);
            WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.240] H3 smoke test RESULT: failed=%d errorMessage='%s' status=%d body_bytes=%zu",
                resp.failed, resp.errorMessage.utf8().data(),
                resp.statusCode, resp.body.size());
        }
    }
    return enabled;
}

} // namespace WebKit

WTF_ALLOW_UNSAFE_BUFFER_USAGE_END

#endif // PLATFORM(DRIFTSTACK)
