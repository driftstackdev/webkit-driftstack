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
#import <mutex>  // Wave 29-499.291 — std::once_flag for RFC 9001 §A.1 self-test
#import <sys/socket.h>
#import <wtf/Assertions.h>
#import <wtf/Condition.h>
#import <wtf/HashMap.h>
#import <wtf/HashSet.h>
#import <wtf/Lock.h>
#import <wtf/MonotonicTime.h>
#import <wtf/NeverDestroyed.h>
#import <wtf/Threading.h>
#import <wtf/text/StringHash.h>

// Wave 29-499.228 — ngtcp2 header inclusion. Provides real struct layouts
// for ngtcp2_settings, ngtcp2_transport_params, ngtcp2_cid, ngtcp2_callbacks,
// etc. The functions are still dlsym-resolved at runtime (Wave 29-499.147)
// to avoid hard link dependency on libngtcp2.dylib at WebKit load time —
// HTTP/3 path is opt-in via DRIFTSTACK_PATHB_V2_H3=1.
// Header guards prevent re-declaration conflicts with the existing forward
// declarations in Ngtcp2Fns below.
#define DRIFTSTACK_HAS_NGTCP2_HEADERS 1
#include <ngtcp2/ngtcp2.h>
// Wave 29-499.321 — real nghttp3 types for the HTTP/3 client layer. Functions
// are dlsym-resolved at runtime (like ngtcp2); only the struct layouts come
// from the header.
#include <nghttp3/nghttp3.h>

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
    int (*conn_open_uni_stream)(ngtcp2_conn*, int64_t*, void*) = nullptr;  // Wave .321 — nghttp3 control+qpack streams
    int (*conn_extend_max_stream_offset)(ngtcp2_conn*, int64_t, uint64_t) = nullptr;  // Wave .321 — per-stream flow control
    void (*conn_extend_max_offset)(ngtcp2_conn*, uint64_t) = nullptr;  // Wave .321 — connection flow control
    int (*conn_decode_and_set_remote_transport_params)(ngtcp2_conn*, const uint8_t*, size_t) = nullptr;  // Wave .321 — apply server's TP (stream limits)
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
    // Wave 29-499.312 — REAL ngtcp2 signatures (were wrong void* placeholders
    // that crashed: ngtcp2 read raw key bytes as a ngtcp2_crypto_aead_ctx
    // struct → garbage native_handle → memmove SIGSEGV in install_tx_handshake).
    int (*conn_install_rx_handshake_key)(ngtcp2_conn*, const ngtcp2_crypto_aead_ctx*,
        const uint8_t* iv, size_t ivlen, const ngtcp2_crypto_cipher_ctx*) = nullptr;
    int (*conn_install_tx_handshake_key)(ngtcp2_conn*, const ngtcp2_crypto_aead_ctx*,
        const uint8_t* iv, size_t ivlen, const ngtcp2_crypto_cipher_ctx*) = nullptr;
    int (*conn_install_rx_key)(ngtcp2_conn*, const uint8_t* secret, size_t secretlen,
        const ngtcp2_crypto_aead_ctx*, const uint8_t* iv, size_t ivlen,
        const ngtcp2_crypto_cipher_ctx*) = nullptr;
    int (*conn_install_tx_key)(ngtcp2_conn*, const uint8_t* secret, size_t secretlen,
        const ngtcp2_crypto_aead_ctx*, const uint8_t* iv, size_t ivlen,
        const ngtcp2_crypto_cipher_ctx*) = nullptr;
    int (*conn_submit_crypto_data)(ngtcp2_conn*, uint32_t, const uint8_t*, size_t) = nullptr;
    int (*conn_handshake_completed)(ngtcp2_conn*) = nullptr;
    // Wave 29-499.308 — set Initial crypto ctx so ngtcp2 knows AEAD tag
    // overhead (16 bytes) and reserves packet space for it.
    void (*conn_set_initial_crypto_ctx)(ngtcp2_conn*, const ngtcp2_crypto_ctx*) = nullptr;
    // Wave 29-499.316 — tell ngtcp2 TLS completed (hand-rolled integration must
    // call this; the ngtcp2_crypto helper does it automatically).
    void (*conn_tls_handshake_completed)(ngtcp2_conn*) = nullptr;
    // Wave 29-499.318 — set Handshake/1-RTT crypto ctx (AEAD overhead) too;
    // set_initial_crypto_ctx only covers Initial. Without this, ngtcp2 reserves
    // 0 tag bytes for handshake/1-RTT packets → ngtcp2_ppe_final assert (SIGABRT).
    void (*conn_set_crypto_ctx)(ngtcp2_conn*, const ngtcp2_crypto_ctx*) = nullptr;
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

// Wave 29-499.314 — CRITICAL: ngtcp2's ngtcp2_encryption_level enum DIFFERS
// from BoringSSL's ssl_encryption_level_t:
//   ngtcp2:    INITIAL=0, HANDSHAKE=1, 0RTT=2,        1RTT=3
//   BoringSSL: initial=0, early_data=1, handshake=2,  application=3
// A raw cast mislabels Handshake data as 0-RTT → SSL_provide_quic_data rejects
// the server's EncryptedExtensions/Certificate/Finished → handshake stalls.
// These map between the two encodings.
static inline ssl_encryption_level_t ngtcp2LevelToSsl(int ngtcp2Level)
{
    switch (ngtcp2Level) {
    case 0: return ssl_encryption_initial;      // INITIAL
    case 1: return ssl_encryption_handshake;    // HANDSHAKE
    case 2: return ssl_encryption_early_data;   // 0RTT
    case 3: return ssl_encryption_application;  // 1RTT
    default: return ssl_encryption_initial;
    }
}
static inline uint32_t sslLevelToNgtcp2(ssl_encryption_level_t sslLevel)
{
    switch (sslLevel) {
    case ssl_encryption_initial:     return 0;  // INITIAL
    case ssl_encryption_handshake:   return 1;  // HANDSHAKE
    case ssl_encryption_early_data:  return 2;  // 0RTT
    case ssl_encryption_application: return 3;  // 1RTT
    default: return 0;
    }
}

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
    RESOLVE(conn_open_uni_stream, "ngtcp2_conn_open_uni_stream");  // Wave .321
    RESOLVE(conn_extend_max_stream_offset, "ngtcp2_conn_extend_max_stream_offset");  // Wave .321
    RESOLVE(conn_extend_max_offset, "ngtcp2_conn_extend_max_offset");  // Wave .321
    RESOLVE(conn_decode_and_set_remote_transport_params, "ngtcp2_conn_decode_and_set_remote_transport_params");  // Wave .321
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
    RESOLVE(conn_set_initial_crypto_ctx, "ngtcp2_conn_set_initial_crypto_ctx");  // Wave .308
    RESOLVE(conn_tls_handshake_completed, "ngtcp2_conn_tls_handshake_completed");  // Wave .316
    RESOLVE(conn_set_crypto_ctx, "ngtcp2_conn_set_crypto_ctx");  // Wave .318
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

// Wave 29-499.321 — nghttp3 (HTTP/3 framing + QPACK) dlsym layer. Resolves the
// ~11 functions the client needs from libnghttp3.9.dylib. nghttp3 sits ON TOP
// of ngtcp2: ngtcp2 owns the QUIC transport (streams + crypto), nghttp3 owns
// the HTTP/3 mapping (HEADERS via QPACK + DATA frames). After the QUIC
// handshake completes we create an nghttp3_conn, bind its control + QPACK
// uni-streams, open a client bidi stream, submit a GET, then shuttle bytes
// between ngtcp2 streams and nghttp3 until the response is complete.
struct NgHttp3Fns {
    void (*settings_default_versioned)(int, nghttp3_settings*) = nullptr;
    int (*conn_client_new_versioned)(nghttp3_conn**, int, const nghttp3_callbacks*,
        int, const nghttp3_settings*, const nghttp3_mem*, void*) = nullptr;
    void (*conn_del)(nghttp3_conn*) = nullptr;
    int (*conn_bind_control_stream)(nghttp3_conn*, int64_t) = nullptr;
    int (*conn_bind_qpack_streams)(nghttp3_conn*, int64_t, int64_t) = nullptr;
    int (*conn_submit_request)(nghttp3_conn*, int64_t, const nghttp3_nv*, size_t,
        const nghttp3_data_reader*, void*) = nullptr;
    nghttp3_ssize (*conn_read_stream)(nghttp3_conn*, int64_t, const uint8_t*, size_t, int) = nullptr;
    nghttp3_ssize (*conn_writev_stream)(nghttp3_conn*, int64_t*, int*, nghttp3_vec*, size_t) = nullptr;
    int (*conn_add_write_offset)(nghttp3_conn*, int64_t, size_t) = nullptr;
    int (*conn_add_ack_offset)(nghttp3_conn*, int64_t, uint64_t) = nullptr;
    int (*conn_close_stream)(nghttp3_conn*, int64_t, uint64_t) = nullptr;
    int (*conn_set_stream_user_data)(nghttp3_conn*, int64_t, void*) = nullptr;
    nghttp3_vec (*rcbuf_get_buf)(const nghttp3_rcbuf*) = nullptr;
    bool ready = false;
};

static NgHttp3Fns& ngHttp3Fns()
{
    static NgHttp3Fns s;
    return s;
}

static bool resolveNgHttp3()
{
    auto& f = ngHttp3Fns();
    if (f.ready) return true;
    const char* candidates[] = {
        "libnghttp3.dylib",
        "libnghttp3.9.dylib",
        "/Users/john/code/webkit-driftstack/WebKitBuild/Release/libnghttp3.dylib",  // copy beside WebKit framework (matches ngtcp2 layout)
        "/Users/john/code/webkit-driftstack/WebKitBuild/Release/libnghttp3.9.dylib",
        "/opt/homebrew/opt/libnghttp3/lib/libnghttp3.9.dylib",
        "/opt/homebrew/lib/libnghttp3.dylib",
        "@executable_path/../Frameworks/libnghttp3.9.dylib",
        nullptr,
    };
    void* handle = nullptr;
    for (int i = 0; candidates[i]; ++i) {
        handle = dlopen(candidates[i], RTLD_NOW | RTLD_GLOBAL);
        if (handle) {
            WTFLogAlways("[Wave29-499.321] dlopen nghttp3 OK at '%s'", candidates[i]);
            break;
        }
    }
    if (!handle) {
        WTFLogAlways("[Wave29-499.321] dlopen nghttp3 FAILED (HTTP/3 request layer disabled)");
        return false;
    }
#define RESOLVE3(field, sym) f.field = reinterpret_cast<decltype(f.field)>(dlsym(handle, sym))
    RESOLVE3(settings_default_versioned, "nghttp3_settings_default_versioned");
    RESOLVE3(conn_client_new_versioned, "nghttp3_conn_client_new_versioned");
    RESOLVE3(conn_del, "nghttp3_conn_del");
    RESOLVE3(conn_bind_control_stream, "nghttp3_conn_bind_control_stream");
    RESOLVE3(conn_bind_qpack_streams, "nghttp3_conn_bind_qpack_streams");
    RESOLVE3(conn_submit_request, "nghttp3_conn_submit_request");
    RESOLVE3(conn_read_stream, "nghttp3_conn_read_stream");
    RESOLVE3(conn_writev_stream, "nghttp3_conn_writev_stream");
    RESOLVE3(conn_add_write_offset, "nghttp3_conn_add_write_offset");
    RESOLVE3(conn_add_ack_offset, "nghttp3_conn_add_ack_offset");
    RESOLVE3(conn_close_stream, "nghttp3_conn_close_stream");
    RESOLVE3(conn_set_stream_user_data, "nghttp3_conn_set_stream_user_data");
    RESOLVE3(rcbuf_get_buf, "nghttp3_rcbuf_get_buf");
#undef RESOLVE3
    bool required = f.settings_default_versioned && f.conn_client_new_versioned
        && f.conn_del && f.conn_bind_control_stream && f.conn_bind_qpack_streams
        && f.conn_submit_request && f.conn_read_stream && f.conn_writev_stream
        && f.conn_add_write_offset && f.conn_add_ack_offset && f.conn_close_stream
        && f.rcbuf_get_buf;
    f.ready = required;
    WTFLogAlways("[Wave29-499.321] nghttp3 dlsym ready=%d (settings=%p new=%p bind_ctrl=%p bind_qpack=%p submit=%p read=%p writev=%p add_write=%p add_ack=%p close=%p rcbuf=%p)",
        required, (void*)f.settings_default_versioned, (void*)f.conn_client_new_versioned,
        (void*)f.conn_bind_control_stream, (void*)f.conn_bind_qpack_streams,
        (void*)f.conn_submit_request, (void*)f.conn_read_stream, (void*)f.conn_writev_stream,
        (void*)f.conn_add_write_offset, (void*)f.conn_add_ack_offset,
        (void*)f.conn_close_stream, (void*)f.rcbuf_get_buf);
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

    // Wave 29-499.321 — HTTP/3 (nghttp3) client state. Populated after the
    // QUIC handshake completes: nghttp3_conn drives QPACK + HEADERS/DATA frames
    // over QUIC streams. This turns the smoke harness into a real request/
    // response H3 client (the engine WebKit's loader will route H3 loads to).
    void* h3conn { nullptr };               // nghttp3_conn*
    int64_t h3RequestStreamId { -1 };
    int h3Status { 0 };                      // :status pseudo-header
    Vector<std::pair<Vector<uint8_t>, Vector<uint8_t>>> h3ResponseHeaders;
    Vector<uint8_t> h3ResponseBody;
    bool h3ResponseComplete { false };       // end_stream on request stream
    // Request data the client emits (set before submit).
    Vector<uint8_t> h3ReqMethod;
    Vector<uint8_t> h3ReqPath;
    Vector<uint8_t> h3ReqAuthority;

    // Wave .322 BISECT — per-stream members ONLY (no callback edits yet). Testing
    // whether merely embedding these non-trivial members in the ngtcp2 user_data
    // struct breaks the QUIC read path (attempt-1 hypothesis). UNUSED for now.
    struct H3Stream {
        int status { 0 };
        Vector<std::pair<Vector<uint8_t>, Vector<uint8_t>>> headers;
        Vector<uint8_t> body;
        bool complete { false };
    };
    Lock h3StreamsLock;
    HashMap<int64_t, std::unique_ptr<H3Stream>> h3Streams WTF_GUARDED_BY_LOCK(h3StreamsLock);

    // Wave .322 — transport state a persistent DriftstackHttp3Session needs to
    // keep so execute() can pump the SAME connection for many sequential
    // requests (the one-shot driftstackHttp3Execute keeps these as locals).
    void* sslCtx { nullptr };                // SSL_CTX* (owned; freed at session close)
    int udpFd { -1 };                        // SOCKS5 UDP_ASSOCIATE relay socket (owned)
    struct sockaddr_in relaySa { };          // §7 relay endpoint (sendto target)
    struct sockaddr_in peerSa { };           // resolved server addr (ngtcp2 path peer)
    struct sockaddr_in localSa { };          // local bound addr (ngtcp2 path local)
    String peerIp;                           // resolved server IPv4 (for §7 framing)
    uint16_t peerPort { 443 };
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
// Wave 29-499.312 — AEAD/HP ctx structs (moved up from below so the
// set_secret callbacks can build proper ngtcp2_crypto_aead_ctx/cipher_ctx).
struct DriftstackQuicAeadCtx {
    Vector<uint8_t> key;
    bool isAes256 { false };       // 0x1302 (32-byte key)
    bool isChacha20 { false };     // 0x1303 (32-byte key)
};
struct DriftstackQuicHpCtx {
    Vector<uint8_t> key;
    bool isAes256 { false };
    bool isChacha20 { false };
};

// Wave 29-499.312 — install a directional (rx/tx) handshake or 1-RTT key with
// proper ngtcp2_crypto_aead_ctx + cipher_ctx structs. Returns ngtcp2 rv.
// isHandshake selects handshake vs application (1-RTT) install. The aead/hp
// inner ctxs are heap-allocated; ngtcp2 holds them for the conn lifetime (freed
// via delete_crypto_*_ctx callbacks).
static int installDirectionalQuicKey(bool isRx, bool isHandshake,
    const Vector<uint8_t>& key, const Vector<uint8_t>& iv, const Vector<uint8_t>& hp,
    bool isAes256, bool isChacha20, const uint8_t* secret, size_t secret_len, void* connPtr);

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
    // Wave .312 — cipher flags for the AEAD ctx (0x1302=AES-256, 0x1303=ChaCha20).
    bool isAes256 = false, isChacha20 = false;
    if (auto& bf = boringSslQuicFns(); cipher && bf.SSL_CIPHER_get_protocol_id) {
        uint16_t id = bf.SSL_CIPHER_get_protocol_id(cipher);
        isAes256 = (id == 0x1302);
        isChacha20 = (id == 0x1303);
    }
    int rv = -1;
    switch (level) {
    case ssl_encryption_handshake:
        rv = installDirectionalQuicKey(/*isRx=*/true, /*isHandshake=*/true, key, iv, hp, isAes256, isChacha20, secret, secret_len, qc->conn);
        break;
    case ssl_encryption_application:
        rv = installDirectionalQuicKey(/*isRx=*/true, /*isHandshake=*/false, key, iv, hp, isAes256, isChacha20, secret, secret_len, qc->conn);
        break;
    case ssl_encryption_initial:
    case ssl_encryption_early_data:
    default:
        rv = 0;  // Initial via conn_install_initial_key; 0-RTT post-launch.
        break;
    }
    WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.312] QuicSetReadSecret level=%d secret_len=%zu key_len=%zu hp_len=%zu aes256=%d chacha=%d install_rv=%d",
        static_cast<int>(level), secret_len, key.size(), hp.size(), isAes256, isChacha20, rv);
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
    bool isAes256 = false, isChacha20 = false;
    if (auto& bf = boringSslQuicFns(); cipher && bf.SSL_CIPHER_get_protocol_id) {
        uint16_t id = bf.SSL_CIPHER_get_protocol_id(cipher);
        isAes256 = (id == 0x1302);
        isChacha20 = (id == 0x1303);
    }
    int rv = -1;
    switch (level) {
    case ssl_encryption_handshake:
        rv = installDirectionalQuicKey(/*isRx=*/false, /*isHandshake=*/true, key, iv, hp, isAes256, isChacha20, secret, secret_len, qc->conn);
        break;
    case ssl_encryption_application:
        rv = installDirectionalQuicKey(/*isRx=*/false, /*isHandshake=*/false, key, iv, hp, isAes256, isChacha20, secret, secret_len, qc->conn);
        break;
    case ssl_encryption_initial:
    case ssl_encryption_early_data:
    default:
        rv = 0;
        break;
    }
    WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.312] QuicSetWriteSecret level=%d secret_len=%zu key_len=%zu hp_len=%zu aes256=%d chacha=%d install_rv=%d",
        static_cast<int>(level), secret_len, key.size(), hp.size(), isAes256, isChacha20, rv);
    return rv == 0 ? 1 : 0;
}

[[maybe_unused]] static int driftstackQuicAddHandshakeData(void* ssl, ssl_encryption_level_t level,
    const uint8_t* data, size_t len)
{
    DriftstackQuicConn* qc = quicConnFromSsl(ssl);
    if (!qc || !qc->conn) return 0;
    auto& nf = ngtcp2Fns();
    // Wave .314 — map ssl level → ngtcp2 encryption level (enums DIFFER:
    // ngtcp2 HANDSHAKE=1 vs BoringSSL handshake=2). Was a raw cast → wrong.
    uint32_t ngtcp2Level = sslLevelToNgtcp2(level);
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
    ngtcp2_encryption_level level, uint64_t offset,
    const uint8_t* data, size_t datalen, void* user_data)
{
    DriftstackQuicConn* qc = static_cast<DriftstackQuicConn*>(user_data);
    if (!qc || !qc->ssl) return -1;
    auto& f = boringSslQuicFns();
    // Wave .314 — map ngtcp2 encryption level → BoringSSL level (enums differ).
    ssl_encryption_level_t sslLevel = ngtcp2LevelToSsl(static_cast<int>(level));
    int rv = f.SSL_provide_quic_data(qc->ssl, sslLevel, data, datalen);
    WTFLogAlways("[Wave29-499.314] RecvCryptoData ngtcp2Level=%d→sslLevel=%d offset=%llu datalen=%zu provide_rv=%d",
        static_cast<int>(level), static_cast<int>(sslLevel), (unsigned long long)offset, datalen, rv);
    // Wave .315 — drive the TLS state machine immediately after feeding data so
    // BoringSSL processes the just-delivered handshake CRYPTO (EE/Cert/Finished)
    // and emits the next flight + 1-RTT keys within this read.
    if (rv == 1) {
        int hs = f.SSL_do_handshake(qc->ssl);
        if (hs == 1) {
            // Wave .316 — TLS handshake done; tell ngtcp2 so it can complete the
            // QUIC handshake (hand-rolled integration must call this explicitly).
            auto& nf = ngtcp2Fns();
            if (nf.conn_tls_handshake_completed) {
                nf.conn_tls_handshake_completed(qc->conn);
                WTFLogAlways("[Wave29-499.316] SSL_do_handshake=1 → ngtcp2_conn_tls_handshake_completed() called");
            }
        } else {
            int e = f.SSL_get_error ? f.SSL_get_error(qc->ssl, hs) : -999;
            if (e != 2) // not WANT_READ
                WTFLogAlways("[Wave29-499.315] post-provide SSL_do_handshake rv=%d err=%d", hs, e);
        }
    }
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
// DriftstackQuicAeadCtx moved to Wave .312 block above.

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

    // Wave 29-499.276 — ChaCha20-Poly1305 (cipher 0x1303) wired alongside AES paths
    Vector<uint8_t> result;
    if (ctx->isChacha20)
        result = WebKit::driftstackChacha20Poly1305Encrypt(ctx->key, nonceVec, ptVec, aadVec);
    else if (ctx->isAes256)
        result = WebKit::driftstackAes256GcmEncrypt(ctx->key, nonceVec, ptVec, aadVec);
    else
        result = WebKit::driftstackAes128GcmEncrypt(ctx->key, nonceVec, ptVec, aadVec);

    if (result.size() != plaintextlen + 16) // AEAD tag is 16 bytes (GCM + Poly1305)
        return -1;
    memcpy(dest, result.span().data(), result.size());

    // Wave 29-499.307 — log first encrypt call's nonce/aad/key/pt to compare
    // against the server-side reconstruction (stepwise decrypt script).
    static bool loggedEnc = false;
    if (!loggedEnc) {
        loggedEnc = true;
        auto hx = [](const uint8_t* p, size_t n, char* o) {
            static const char* h = "0123456789abcdef";
            for (size_t i = 0; i < n; i++) { o[i*2]=h[p[i]>>4]; o[i*2+1]=h[p[i]&0xf]; }
            o[n*2]='\0';
        };
        char kbuf[80], nbuf[40], abuf[120], pbuf[40];
        hx(ctx->key.span().data(), ctx->key.size() > 32 ? 32 : ctx->key.size(), kbuf);
        hx(nonce, noncelen, nbuf);
        hx(aad, aadlen > 48 ? 48 : aadlen, abuf);
        hx(plaintext, plaintextlen > 16 ? 16 : plaintextlen, pbuf);
        WTFLogAlways("[Wave29-499.307] ENC#1 isChaCha=%d isAes256=%d keylen=%zu key=%s noncelen=%zu nonce=%s aadlen=%zu aad=%s ptlen=%zu pt[0..15]=%s",
            ctx->isChacha20, ctx->isAes256, ctx->key.size(), kbuf, noncelen, nbuf, aadlen, abuf, plaintextlen, pbuf);
    }
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

    // Wave 29-499.276 — ChaCha20-Poly1305 (cipher 0x1303) decrypt
    Vector<uint8_t> result;
    if (ctx->isChacha20)
        result = WebKit::driftstackChacha20Poly1305Decrypt(ctx->key, nonceVec, ctVec, aadVec);
    else if (ctx->isAes256)
        result = WebKit::driftstackAes256GcmDecrypt(ctx->key, nonceVec, ctVec, aadVec);
    else
        result = WebKit::driftstackAes128GcmDecrypt(ctx->key, nonceVec, ctVec, aadVec);

    // Wave 29-499.315 — log decrypt outcome (handshake-level decrypt failures
    // would stall the handshake by silently dropping server CRYPTO).
    static int s_decLog = 0;
    if (s_decLog < 12) {
        s_decLog++;
        WTFLogAlways("[Wave29-499.315] DECRYPT ctlen=%zu aadlen=%zu aes256=%d chacha=%d -> %s (%zu bytes)",
            ciphertextlen, aadlen, ctx->isAes256, ctx->isChacha20,
            result.isEmpty() ? "FAIL" : "ok", result.size());
    }
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
// DriftstackQuicHpCtx moved to Wave .312 block above.

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
    // Wave .302 — explicit dlopen libssl.48 BEFORE dlsym. libwebrtc.dylib
    // bundles its own BoringSSL AES_encrypt with incompatible key schedule;
    // RTLD_DEFAULT may return it instead of LibreSSL. See feedback memory
    // dlopen-libssl-before-dlsym for full root-cause analysis.
    static void* hSsl = dlopen("/usr/lib/libssl.48.dylib", RTLD_NOW | RTLD_GLOBAL);
    void* h = hSsl ? hSsl : RTLD_DEFAULT;
    f.set_encrypt_key = reinterpret_cast<decltype(f.set_encrypt_key)>(dlsym(h, "AES_set_encrypt_key"));
    f.encrypt = reinterpret_cast<decltype(f.encrypt)>(dlsym(h, "AES_encrypt"));
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
        // Wave 29-499.277 — RFC 9001 §5.4.4 ChaCha20 header protection.
        // mask = first 5 bytes of ChaCha20(hp_key, counter=sample[0..4],
        //        nonce=sample[4..16]) encryption of zero-bytes.
        //
        // LibreSSL exposes ChaCha20_ctr32(out, in, len, key, iv) where iv
        // is 16 bytes = LE counter(4) || nonce(12). We dlsym at first call.
        typedef void (*Chacha20Ctr32Fn)(uint8_t* out, const uint8_t* in,
                                         size_t len, const uint8_t* key,
                                         const uint8_t* iv);
        static Chacha20Ctr32Fn chacha20Ctr32 = nullptr;
        static dispatch_once_t chachaOnce;
        dispatch_once(&chachaOnce, ^{
            // Wave .302 — dlopen libssl.48 before dlsym (same lib-mixup risk as
            // AES_encrypt; see dlopen-libssl-before-dlsym feedback memory).
            static void* hSslChacha = dlopen("/usr/lib/libssl.48.dylib", RTLD_NOW | RTLD_GLOBAL);
            void* h = hSslChacha ? hSslChacha : RTLD_DEFAULT;
            chacha20Ctr32 = reinterpret_cast<Chacha20Ctr32Fn>(
                dlsym(h, "ChaCha20_ctr32"));
            if (!chacha20Ctr32)
                chacha20Ctr32 = reinterpret_cast<Chacha20Ctr32Fn>(
                    dlsym(h, "CRYPTO_chacha_20"));
            if (!chacha20Ctr32)
                WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.277] ChaCha20_ctr32 + CRYPTO_chacha_20 NOT FOUND in LibreSSL/BoringSSL — ChaCha20 hp_mask disabled");
        });
        if (!chacha20Ctr32)
            return -1;

        // IV layout = LE counter(4 bytes) || nonce(12 bytes) per RFC 8439 §2.4
        uint8_t iv[16];
        memcpy(iv, sample, 16);
        uint8_t zero[5] = { 0, 0, 0, 0, 0 };
        chacha20Ctr32(dest, zero, 5, ctx->key.span().data(), iv);
        return 0;
    }

    uint8_t aesKeyBuf[256] = { };
    int bits = ctx->isAes256 ? 256 : 128;
    if (f.set_encrypt_key(ctx->key.span().data(), bits, aesKeyBuf) != 0)
        return -1;
    f.encrypt(sample, dest, aesKeyBuf);
    return 0;
}

// Wave 29-499.312 — install handshake/1-RTT keys with proper ngtcp2 ctx structs.
static int installDirectionalQuicKey(bool isRx, bool isHandshake,
    const Vector<uint8_t>& key, const Vector<uint8_t>& iv, const Vector<uint8_t>& hp,
    bool isAes256, bool isChacha20, const uint8_t* secret, size_t secret_len, void* connPtr)
{
    auto& nf = ngtcp2Fns();
    auto* conn = static_cast<ngtcp2_conn*>(connPtr);
    auto* aeadInner = new DriftstackQuicAeadCtx { key, isAes256, isChacha20 };
    auto* hpInner = new DriftstackQuicHpCtx { hp, isAes256, isChacha20 };
    ngtcp2_crypto_aead_ctx aeadCtx { aeadInner };
    ngtcp2_crypto_cipher_ctx hpCtx { hpInner };

    int rv;
    if (isHandshake) {
        rv = isRx
            ? nf.conn_install_rx_handshake_key(conn, &aeadCtx, iv.span().data(), iv.size(), &hpCtx)
            : nf.conn_install_tx_handshake_key(conn, &aeadCtx, iv.span().data(), iv.size(), &hpCtx);
    } else {
        rv = isRx
            ? nf.conn_install_rx_key(conn, secret, secret_len, &aeadCtx, iv.span().data(), iv.size(), &hpCtx)
            : nf.conn_install_tx_key(conn, secret, secret_len, &aeadCtx, iv.span().data(), iv.size(), &hpCtx);
    }
    if (rv != 0) {
        delete aeadInner;
        delete hpInner;
    }
    return rv;
}

// ============================================================================
// Wave 29-499.321 — HTTP/3 request/response layer (nghttp3 ⇄ ngtcp2 bridge).
//
// nghttp3 callbacks: invoked by nghttp3_conn_read_stream as it parses the
// server's HEADERS/DATA frames. conn_user_data is the DriftstackQuicConn*
// (passed to nghttp3_conn_client_new_versioned below).
// ============================================================================

static int driftstackH3RecvHeader(nghttp3_conn* /*conn*/, int64_t streamId,
    int32_t /*token*/, nghttp3_rcbuf* name, nghttp3_rcbuf* value, uint8_t /*flags*/,
    void* connUserData, void* /*streamUserData*/)
{
    auto* qc = static_cast<DriftstackQuicConn*>(connUserData);
    auto& h = ngHttp3Fns();
    nghttp3_vec nv = h.rcbuf_get_buf(name);
    nghttp3_vec vv = h.rcbuf_get_buf(value);
    Vector<uint8_t> nameBuf; nameBuf.append(std::span<const uint8_t> { nv.base, nv.len });
    Vector<uint8_t> valBuf; valBuf.append(std::span<const uint8_t> { vv.base, vv.len });
    // :status pseudo-header → numeric status code.
    int statusCode = -1;
    if (nv.len == 7 && !memcmp(nv.base, ":status", 7)) {
        int code = 0;
        for (size_t i = 0; i < vv.len; ++i) {
            if (vv.base[i] < '0' || vv.base[i] > '9') break;
            code = code * 10 + (vv.base[i] - '0');
        }
        qc->h3Status = code;
        statusCode = code;
    }
    // Wave .322 — per-stream population (additive). KEY = streamId + 1: the h3
    // request bidi stream is stream id 0, and WTF::HashMap<int64_t> reserves 0 as
    // the empty-bucket sentinel — inserting key 0 corrupts the table (this was the
    // attempt-1 break: recv_header crashed on stream 0). +1 keeps every key ≥ 1.
    // Copy because the singular append moves below.
    {
        Locker l { qc->h3StreamsLock };
        auto& slot = qc->h3Streams.ensure(streamId + 1, [] { return makeUniqueWithoutFastMallocCheck<DriftstackQuicConn::H3Stream>(); }).iterator->value;
        if (statusCode >= 0)
            slot->status = statusCode;
        slot->headers.append({ Vector<uint8_t>(nameBuf), Vector<uint8_t>(valBuf) });
    }
    qc->h3ResponseHeaders.append({ std::move(nameBuf), std::move(valBuf) });
    if (qc->h3ResponseHeaders.size() <= 16) {
        WTFLogAlways("[Wave29-499.321] H3 recv_header stream=%lld %.*s: %.*s",
            (long long)streamId, (int)nv.len, nv.base, (int)vv.len, vv.base);
    }
    return 0;
}

static int driftstackH3RecvData(nghttp3_conn* /*conn*/, int64_t streamId,
    const uint8_t* data, size_t datalen, void* connUserData, void* /*streamUserData*/)
{
    auto* qc = static_cast<DriftstackQuicConn*>(connUserData);
    qc->h3ResponseBody.append(std::span<const uint8_t> { data, datalen });
    // Wave .322 — per-stream body (additive; key = streamId + 1, see recv_header).
    {
        Locker l { qc->h3StreamsLock };
        auto& slot = qc->h3Streams.ensure(streamId + 1, [] { return makeUniqueWithoutFastMallocCheck<DriftstackQuicConn::H3Stream>(); }).iterator->value;
        slot->body.append(std::span<const uint8_t> { data, datalen });
    }
    return 0;
}

static int driftstackH3EndStream(nghttp3_conn* /*conn*/, int64_t streamId,
    void* connUserData, void* /*streamUserData*/)
{
    auto* qc = static_cast<DriftstackQuicConn*>(connUserData);
    if (streamId == qc->h3RequestStreamId) {
        qc->h3ResponseComplete = true;
        WTFLogAlways("[Wave29-499.321] H3 end_stream stream=%lld status=%d bodyLen=%zu",
            (long long)streamId, qc->h3Status, qc->h3ResponseBody.size());
    }
    // Wave .322 — mark the per-stream entry complete (additive; key = streamId + 1).
    {
        Locker l { qc->h3StreamsLock };
        auto it = qc->h3Streams.find(streamId + 1);
        if (it != qc->h3Streams.end())
            it->value->complete = true;
    }
    return 0;
}

static int driftstackH3StreamClose(nghttp3_conn* /*conn*/, int64_t streamId,
    uint64_t /*appErrorCode*/, void* connUserData, void* /*streamUserData*/)
{
    auto* qc = static_cast<DriftstackQuicConn*>(connUserData);
    if (streamId == qc->h3RequestStreamId)
        qc->h3ResponseComplete = true;
    // Wave .322 — mark the per-stream entry complete (additive; key = streamId + 1).
    {
        Locker l { qc->h3StreamsLock };
        auto it = qc->h3Streams.find(streamId + 1);
        if (it != qc->h3Streams.end())
            it->value->complete = true;
    }
    return 0;
}

// ngtcp2 stream callbacks: feed received stream bytes into nghttp3, and tell
// nghttp3 how much stream data was acked / when ngtcp2 closes a stream. These
// are wired into initDriftstackNgtcp2Callbacks below (the .311 cb struct).
static int driftstackNgtcp2RecvStreamData(ngtcp2_conn* /*conn*/, uint32_t flags,
    int64_t streamId, uint64_t /*offset*/, const uint8_t* data, size_t datalen,
    void* userData, void* /*streamUserData*/)
{
    auto* qc = static_cast<DriftstackQuicConn*>(userData);
    if (!qc->h3conn)
        return 0;
    auto& h = ngHttp3Fns();
    int fin = (flags & NGTCP2_STREAM_DATA_FLAG_FIN) ? 1 : 0;
    nghttp3_ssize consumed = h.conn_read_stream(static_cast<nghttp3_conn*>(qc->h3conn),
        streamId, data, datalen, fin);
    if (consumed < 0) {
        WTFLogAlways("[Wave29-499.321] nghttp3_conn_read_stream FAILED rv=%zd stream=%lld",
            (ssize_t)consumed, (long long)streamId);
        return -1; // NGTCP2_ERR_CALLBACK_FAILURE
    }
    // Extend QUIC flow-control credit by the bytes nghttp3 consumed (both
    // stream-level + connection-level), else responses larger than the initial
    // window stall once the peer exhausts its send allowance.
    auto& nf = ngtcp2Fns();
    if (consumed > 0) {
        if (nf.conn_extend_max_stream_offset)
            nf.conn_extend_max_stream_offset(qc->conn, streamId, static_cast<uint64_t>(consumed));
        if (nf.conn_extend_max_offset)
            nf.conn_extend_max_offset(qc->conn, static_cast<uint64_t>(consumed));
    }
    return 0;
}

static int driftstackNgtcp2AckedStreamDataOffset(ngtcp2_conn* /*conn*/, int64_t streamId,
    uint64_t /*offset*/, uint64_t datalen, void* userData, void* /*streamUserData*/)
{
    auto* qc = static_cast<DriftstackQuicConn*>(userData);
    if (!qc->h3conn)
        return 0;
    auto& h = ngHttp3Fns();
    if (h.conn_add_ack_offset(static_cast<nghttp3_conn*>(qc->h3conn), streamId, datalen) != 0)
        return -1;
    return 0;
}

static int driftstackNgtcp2StreamClose(ngtcp2_conn* /*conn*/, uint32_t /*flags*/,
    int64_t streamId, uint64_t appErrorCode, void* userData, void* /*streamUserData*/)
{
    auto* qc = static_cast<DriftstackQuicConn*>(userData);
    if (!qc->h3conn)
        return 0;
    auto& h = ngHttp3Fns();
    if (h.conn_close_stream)
        h.conn_close_stream(static_cast<nghttp3_conn*>(qc->h3conn), streamId, appErrorCode);
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
    // Wave 29-499.321 — HTTP/3 stream callbacks: route received stream bytes
    // into nghttp3 + relay ack/close. Only active once qc->h3conn is set
    // (after handshake); they no-op otherwise.
    cb->recv_stream_data = driftstackNgtcp2RecvStreamData;
    cb->acked_stream_data_offset = driftstackNgtcp2AckedStreamDataOffset;
    cb->stream_close = driftstackNgtcp2StreamClose;
    // recv_version_negotiation, recv_token, send_token,
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

    // Wave 29-499.308 — tell ngtcp2 the Initial AEAD overhead is 16 bytes
    // (AES-128-GCM / ChaCha20-Poly1305 tag). Without this, ngtcp2's default
    // Initial crypto ctx has max_overhead=0, so it reserves no tag space and
    // our 16-byte tag overflows the packet → server can't verify → silent drop
    // (root cause of packetsReceived=0; verified Wave .307: key/nonce/aad all
    // matched server reconstruction, only the length accounting was off by 16).
    if (nf.conn_set_initial_crypto_ctx) {
        ngtcp2_crypto_ctx cctx;
        memset(&cctx, 0, sizeof(cctx));
        cctx.aead.native_handle = nullptr;   // we encrypt via the encrypt callback
        cctx.aead.max_overhead = 16;
        cctx.md.native_handle = nullptr;
        cctx.hp.native_handle = nullptr;
        cctx.max_encryption = (1ull << 23);            // RFC 9001 AES-128-GCM limit
        cctx.max_decryption_failure = (1ull << 23);
        nf.conn_set_initial_crypto_ctx(qc->conn, &cctx);
        WTFLogAlways("[Wave29-499.308] set Initial crypto ctx: aead.max_overhead=16");
        // Wave 29-499.318 — ALSO set the Handshake/1-RTT crypto ctx overhead.
        // Without this, ngtcp2 reserves 0 tag bytes for handshake/1-RTT packet
        // writes → ngtcp2_ppe_final assertion abort (SIGABRT) when our encrypt
        // callback appends the 16-byte GCM tag. (Initial ctx alone is insufficient.)
        if (nf.conn_set_crypto_ctx) {
            nf.conn_set_crypto_ctx(qc->conn, &cctx);  // same AEAD overhead=16
            WTFLogAlways("[Wave29-499.318] set Handshake/1-RTT crypto ctx: aead.max_overhead=16");
        }
    } else {
        WTFLogAlways("[Wave29-499.308] WARN conn_set_initial_crypto_ctx unresolved — tag overhead not set");
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

    // Wave 29-499.291 — RFC 9001 Appendix A.1 self-test on first call.
    // dcid = 0x8394c8f03e515708 must produce:
    //   initial_secret = 7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44
    //   client_initial_secret = c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea
    //   client_key = 1f369613dd76d5467730efcbe3b1a22d
    //   client_iv  = fa044b2f42a3fd3b46fb255c
    //   client_hp  = 9f50449e04a0e810283a1e9933adedd2
    static std::once_flag selfTestOnce;
    std::call_once(selfTestOnce, [&] {
        static const uint8_t kTestDcid[8] = { 0x83,0x94,0xc8,0xf0,0x3e,0x51,0x57,0x08 };
        Vector<uint8_t> testSalt(20);
        memcpy(testSalt.mutableSpan().data(), kQuicV1InitialSalt, 20);
        Vector<uint8_t> testDcid(8);
        memcpy(testDcid.mutableSpan().data(), kTestDcid, 8);
        auto initSec = WebKit::driftstackHkdfExtractSha256(testSalt, testDcid);
        // expected first 16 bytes: 7d b5 df 06 e7 a6 9e 43 24 96 ad ed b0 08 51 92
        bool match_secret = initSec.size() == 32
            && initSec[0] == 0x7d && initSec[1] == 0xb5 && initSec[2] == 0xdf && initSec[3] == 0x06
            && initSec[15] == 0x92;
        Vector<uint8_t> emptyC;
        auto cliSec = WebKit::driftstackHkdfExpandLabelSha256(initSec, "client in", emptyC, 32);
        bool match_cli = cliSec.size() == 32
            && cliSec[0] == 0xc0 && cliSec[1] == 0x0c && cliSec[2] == 0xf1 && cliSec[3] == 0x51;
        auto cliKey = WebKit::driftstackHkdfExpandLabelSha256(cliSec, "quic key", emptyC, 16);
        bool match_key = cliKey.size() == 16
            && cliKey[0] == 0x1f && cliKey[1] == 0x36 && cliKey[2] == 0x96 && cliKey[3] == 0x13
            && cliKey[15] == 0x2d;
        auto cliIv = WebKit::driftstackHkdfExpandLabelSha256(cliSec, "quic iv", emptyC, 12);
        bool match_iv = cliIv.size() == 12
            && cliIv[0] == 0xfa && cliIv[1] == 0x04 && cliIv[11] == 0x5c;
        auto cliHp = WebKit::driftstackHkdfExpandLabelSha256(cliSec, "quic hp", emptyC, 16);
        bool match_hp = cliHp.size() == 16
            && cliHp[0] == 0x9f && cliHp[15] == 0xd2;
        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.291] RFC 9001 §A.1 self-test: secret=%d cli_in=%d key=%d iv=%d hp=%d (1=PASS, 0=FAIL)",
            match_secret, match_cli, match_key, match_iv, match_hp);
        if (initSec.size() >= 16) {
            WTFLogAlways("[Wave29-499.291] our initial_secret first 16: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x (expect: 7d b5 df 06 e7 a6 9e 43 24 96 ad ed b0 08 51 92)",
                initSec[0], initSec[1], initSec[2], initSec[3], initSec[4], initSec[5], initSec[6], initSec[7],
                initSec[8], initSec[9], initSec[10], initSec[11], initSec[12], initSec[13], initSec[14], initSec[15]);
        }
        if (cliKey.size() >= 16) {
            WTFLogAlways("[Wave29-499.291] our client_key 16: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x (expect: 1f 36 96 13 dd 76 d5 46 77 30 ef cb e3 b1 a2 2d)",
                cliKey[0], cliKey[1], cliKey[2], cliKey[3], cliKey[4], cliKey[5], cliKey[6], cliKey[7],
                cliKey[8], cliKey[9], cliKey[10], cliKey[11], cliKey[12], cliKey[13], cliKey[14], cliKey[15]);
        }

        // Wave 29-499.292 — RFC 9001 §A.2 packet protection self-test.
        // Verifies AES-128-GCM encrypt + AES-ECB hp_mask produce RFC-canonical
        // bytes. Uses test vector with KNOWN inputs to isolate AEAD/hp bugs
        // from data-dependent issues.
        //
        // RFC 9001 §A.2 specifies (for Initial protection test):
        //   plaintext frame:  CRYPTO frame containing TLS ClientHello (1162 bytes)
        //   But simpler: just encrypt known 16-byte plaintext with known key/nonce/aad
        //   and check tag matches NIST CAVP AES-128-GCM vector.

        // AEAD AES-128-GCM test: NIST GCM-AES-128 test vector #1
        // (https://csrc.nist.gov/projects/cryptographic-standard-and-guidelines/
        //  example-values#aes_gcm)
        // key=00*16, iv=00*12, pt=empty, aad=empty
        // ct=empty, tag=58e2fccefa7e3061367f1d57a4e7455a
        // Wave .303 — explicitly zero. WTF::Vector<POD>(N) reserves N but does NOT
        // zero-initialize for POD types; previous tk(16)/tiv(12) had uninitialized
        // stack memory that sometimes happened to be zero (flaky self-test).
        Vector<uint8_t> tk(16);
        memset(tk.mutableSpan().data(), 0, 16);
        Vector<uint8_t> tiv(12);
        memset(tiv.mutableSpan().data(), 0, 12);
        Vector<uint8_t> tpt;     // empty plaintext
        Vector<uint8_t> taad;    // empty AAD
        auto tct = WebKit::driftstackAes128GcmEncrypt(tk, tiv, tpt, taad);
        bool aead_ok = tct.size() == 16
            && tct[0] == 0x58 && tct[1] == 0xe2 && tct[2] == 0xfc && tct[3] == 0xce
            && tct[15] == 0x5a;
        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.292] AES-128-GCM self-test: %d (1=PASS)", aead_ok);
        if (tct.size() == 16) {
            WTFLogAlways("[Wave29-499.292] AES-128-GCM(k=0,iv=0,pt=empty) tag: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x (expect: 58 e2 fc ce fa 7e 30 61 36 7f 1d 57 a4 e7 45 5a)",
                tct[0], tct[1], tct[2], tct[3], tct[4], tct[5], tct[6], tct[7],
                tct[8], tct[9], tct[10], tct[11], tct[12], tct[13], tct[14], tct[15]);
        }

        // Wave 29-499.306 — NIST GCM Test Case 3 (MULTI-BLOCK plaintext).
        // The empty-pt test above only exercises tag = E(J0); it never tests
        // GHASH-over-data or CTR. QUIC Initial has ~1155-byte plaintext, so
        // this multi-block path MUST be correct.
        //   K = feffe9928665731c6d6a8f9467308308
        //   IV= cafebabefacedbaddecaf888
        //   P = d9313225...ba637b39 (60 bytes)
        //   A = empty
        //   expected C first 4 = 42 83 1e c2 ; T = 5bc94fbc3221a5db94fae95ae7121a47
        {
            static const uint8_t k3[16] = {0xfe,0xff,0xe9,0x92,0x86,0x65,0x73,0x1c,0x6d,0x6a,0x8f,0x94,0x67,0x30,0x83,0x08};
            static const uint8_t iv3[12] = {0xca,0xfe,0xba,0xbe,0xfa,0xce,0xdb,0xad,0xde,0xca,0xf8,0x88};
            static const uint8_t p3[60] = {
                0xd9,0x31,0x32,0x25,0xf8,0x84,0x06,0xe5,0xa5,0x59,0x09,0xc5,0xaf,0xf5,0x26,0x9a,
                0x86,0xa7,0xa9,0x53,0x15,0x34,0xf7,0xda,0x2e,0x4c,0x30,0x3d,0x8a,0x31,0x8a,0x72,
                0x1c,0x3c,0x0c,0x95,0x95,0x68,0x09,0x53,0x2f,0xcf,0x0e,0x24,0x49,0xa6,0xb5,0x25,
                0xb1,0x6a,0xed,0xf5,0xaa,0x0d,0xe6,0x57,0xba,0x63,0x7b,0x39};
            Vector<uint8_t> K3(16); memcpy(K3.mutableSpan().data(), k3, 16);
            Vector<uint8_t> IV3(12); memcpy(IV3.mutableSpan().data(), iv3, 12);
            Vector<uint8_t> P3(60); memcpy(P3.mutableSpan().data(), p3, 60);
            Vector<uint8_t> A3;
            auto ct3 = WebKit::driftstackAes128GcmEncrypt(K3, IV3, P3, A3);
            // empty-AAD expected: C[0..3]=42831ec2, T=cc15abcc191161501aabab46b8fbac85
            bool ok3 = ct3.size() == 76
                && ct3[0]==0x42 && ct3[1]==0x83 && ct3[2]==0x1e && ct3[3]==0xc2
                && ct3[60]==0xcc && ct3[61]==0x15 && ct3[75]==0x85;
            WTFLogAlways("[Wave29-499.306] AES-128-GCM MULTI-BLOCK (NIST TC3) self-test: %d (1=PASS) size=%zu", ok3, ct3.size());
            if (ct3.size() == 76) {
                WTFLogAlways("[Wave29-499.306] C[0..3]=%02x %02x %02x %02x (exp 42 83 1e c2) T[0..3]=%02x %02x %02x %02x (exp cc 15 ab cc) T[15]=%02x (exp 85)",
                    ct3[0],ct3[1],ct3[2],ct3[3], ct3[60],ct3[61],ct3[62],ct3[63], ct3[75]);
            }
        }

        // AES-ECB hp_mask test: encrypt 16-byte zero block with zero key
        // Expected: 66e94bd4ef8a2c3b884cfa59ca342b2e (NIST AES-128 ECB test vector)
        if (resolveAesEncryptFns()) {
            uint8_t aesKeyBuf[256] = { };
            uint8_t zeroKey[16] = { };
            uint8_t zeroBlock[16] = { };
            uint8_t cipher[16] = { };
            if (aesEncryptFns().set_encrypt_key(zeroKey, 128, aesKeyBuf) == 0) {
                aesEncryptFns().encrypt(zeroBlock, cipher, aesKeyBuf);
                bool hp_ok = cipher[0] == 0x66 && cipher[1] == 0xe9 && cipher[15] == 0x2e;
                WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.292] AES-128-ECB hp_mask self-test: %d (1=PASS)", hp_ok);
                WTFLogAlways("[Wave29-499.292] AES-128-ECB(k=0,pt=0) cipher: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x (expect: 66 e9 4b d4 ef 8a 2c 3b 88 4c fa 59 ca 34 2b 2e)",
                    cipher[0], cipher[1], cipher[2], cipher[3], cipher[4], cipher[5], cipher[6], cipher[7],
                    cipher[8], cipher[9], cipher[10], cipher[11], cipher[12], cipher[13], cipher[14], cipher[15]);
            } else {
                WTFLogAlways("[Wave29-499.292] AES_set_encrypt_key returned non-zero — symbol resolution wrong");
            }
        } else {
            WTFLogAlways("[Wave29-499.292] resolveAesEncryptFns FAILED — AES_set_encrypt_key/AES_encrypt symbols not found");
        }
    });

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

// Wave 29-499.321 — set up the nghttp3 client connection after the QUIC
// handshake completes. Opens the HTTP/3 control + QPACK encoder/decoder
// uni-streams, opens a client bidirectional stream, and submits a GET request.
// Returns true on success (qc->h3conn + qc->h3RequestStreamId set).
// Wave .322 — split out of driftstackHttp3SetupAndSubmit so a persistent
// DriftstackHttp3Session can do this ONCE per connection (create the nghttp3
// client + bind the control/QPACK uni-streams) and then submit many requests
// over it. Returns true if qc->h3conn is ready for submit_request calls.
[[maybe_unused]] static bool driftstackHttp3SetupConnection(DriftstackQuicConn* qc)
{
    if (qc->h3conn)
        return true; // already set up (reused connection)
    if (!resolveNgHttp3())
        return false;
    auto& h = ngHttp3Fns();
    auto& nf = ngtcp2Fns();

    nghttp3_settings settings;
    h.settings_default_versioned(NGHTTP3_SETTINGS_VERSION, &settings);

    nghttp3_callbacks cb;
    memset(&cb, 0, sizeof(cb));
    cb.recv_header = driftstackH3RecvHeader;
    cb.recv_data = driftstackH3RecvData;
    cb.end_stream = driftstackH3EndStream;
    cb.stream_close = driftstackH3StreamClose;

    nghttp3_conn* h3 = nullptr;
    int rv = h.conn_client_new_versioned(&h3, NGHTTP3_CALLBACKS_VERSION, &cb,
        NGHTTP3_SETTINGS_VERSION, &settings, /*mem=*/nullptr, /*conn_user_data=*/qc);
    if (rv != 0 || !h3) {
        WTFLogAlways("[Wave29-499.321] nghttp3_conn_client_new FAILED rv=%d", rv);
        return false;
    }
    qc->h3conn = h3;

    // Bind the HTTP/3 control stream + QPACK encoder/decoder streams to three
    // client-initiated unidirectional streams (RFC 9114 §6.2 / §3.2.2).
    int64_t ctrlStream = -1, qpackEnc = -1, qpackDec = -1;
    int rvc = nf.conn_open_uni_stream(qc->conn, &ctrlStream, nullptr);
    int rve = rvc ? rvc : nf.conn_open_uni_stream(qc->conn, &qpackEnc, nullptr);
    int rvd = rve ? rve : nf.conn_open_uni_stream(qc->conn, &qpackDec, nullptr);
    if (rvc || rve || rvd) {
        // NGTCP2_ERR_STREAM_ID_BLOCKED = -209 (peer's uni-stream allowance not
        // yet available); other negatives are hard failures.
        WTFLogAlways("[Wave29-499.321] open_uni_stream FAILED rvc=%d rve=%d rvd=%d (-209=STREAM_ID_BLOCKED)", rvc, rve, rvd);
        return false;
    }
    if (h.conn_bind_control_stream(h3, ctrlStream) != 0) {
        WTFLogAlways("[Wave29-499.321] bind_control_stream FAILED");
        return false;
    }
    if (h.conn_bind_qpack_streams(h3, qpackEnc, qpackDec) != 0) {
        WTFLogAlways("[Wave29-499.321] bind_qpack_streams FAILED");
        return false;
    }
    WTFLogAlways("[Wave29-499.321] H3 connection setup OK: ctrl=%lld qpackEnc=%lld qpackDec=%lld",
        (long long)ctrlStream, (long long)qpackEnc, (long long)qpackDec);
    return true;
}

// Wave .322 — submit ONE request on a fresh bidi stream of an already-set-up
// nghttp3 connection. Resets the per-request response fields so a persistent
// session can reuse the connection for multiple sequential requests.
[[maybe_unused]] static bool driftstackHttp3SubmitRequest(DriftstackQuicConn* qc,
    const DriftstackHttp3Request& request)
{
    auto& h = ngHttp3Fns();
    auto& nf = ngtcp2Fns();
    nghttp3_conn* h3 = static_cast<nghttp3_conn*>(qc->h3conn);
    if (!h3)
        return false;

    // Reset per-request response accumulators (connection-level state persists).
    qc->h3Status = 0;
    qc->h3ResponseHeaders.clear();
    qc->h3ResponseBody.clear();
    qc->h3ResponseComplete = false;

    // Open the request bidi stream and submit GET <path>.
    int64_t reqStream = -1;
    if (nf.conn_open_bidi_stream(qc->conn, &reqStream, nullptr) != 0) {
        WTFLogAlways("[Wave29-499.321] open_bidi_stream (request) FAILED");
        return false;
    }
    qc->h3RequestStreamId = reqStream;

    // Build the request header set. CRITICAL for fingerprint authenticity: send
    // EXACTLY the headers WebKit configured (real Safari UA, Accept, Accept-
    // Language, sec-fetch-*, etc.) via request.extraHeaders — never a synthetic
    // UA. The pseudo-headers use Safari's h2 order (:method, :scheme, :path,
    // :authority); the exact h3 pseudo-header order still wants a real-iPhone
    // capture to confirm (peet.ws/h3 or device). Regular-header ORDER is already
    // lost upstream (NSURLRequest.allHTTPHeaderFields is an unordered dict) —
    // a pre-existing limitation of the URLProtocol approach shared with the TCP
    // path; tracked separately.
    //
    // nghttp3 copies name/value with NGHTTP3_NV_FLAG_NONE, so the backing CString
    // storage only needs to outlive the submit_request call (it does — same scope).
    Vector<std::pair<CString, CString>> store;
    auto add = [&](const char* n, CString v) { store.append({ CString(n), std::move(v) }); };

    // iPhone 17 pseudo-header order m,s,a,p (authority BEFORE path) — matches the
    // corrected h2 order from the BS akamai capture (Wave .323).
    add(":method", request.method.isEmpty() ? CString("GET") : request.method.utf8());
    add(":scheme", request.scheme.isEmpty() ? CString("https") : request.scheme.utf8());
    // :authority — strip the default :443 (real Safari omits it).
    String authStr = request.authority;
    if (authStr.endsWith(":443"_s))
        authStr = authStr.left(authStr.length() - 4);
    add(":authority", authStr.utf8());
    add(":path", request.path.isEmpty() ? CString("/") : request.path.utf8());
    // Forward every non-pseudo, non-connection-specific request header verbatim.
    for (auto& kv : request.extraHeaders) {
        String lname = kv.first.convertToASCIILowercase();
        if (lname.isEmpty() || lname.startsWith(':')
            || lname == "host"_s || lname == "connection"_s
            || lname == "proxy-connection"_s || lname == "keep-alive"_s
            || lname == "transfer-encoding"_s || lname == "upgrade"_s)
            continue;
        store.append({ kv.first.utf8(), kv.second.utf8() });
    }

    Vector<nghttp3_nv> nva;
    nva.reserveInitialCapacity(store.size());
    for (auto& kv : store) {
        nva.append(nghttp3_nv {
            reinterpret_cast<const uint8_t*>(kv.first.data()),
            reinterpret_cast<const uint8_t*>(kv.second.data()),
            kv.first.length(), kv.second.length(), NGHTTP3_NV_FLAG_NONE });
    }

    int rv = h.conn_submit_request(h3, reqStream, nva.span().data(), nva.size(),
        /*data_reader=*/nullptr, /*stream_user_data=*/qc);
    if (rv != 0) {
        WTFLogAlways("[Wave29-499.321] nghttp3_conn_submit_request FAILED rv=%d", rv);
        return false;
    }
    WTFLogAlways("[Wave29-499.321] H3 request submitted: reqStream=%lld %s https://%s%s (%zu headers, real UA forwarded)",
        (long long)reqStream, store[0].second.data(), authStr.utf8().data(),
        request.path.isEmpty() ? "/" : request.path.utf8().data(), store.size());
    return true;
}

// Wave .322 — original one-shot entry point, now a thin wrapper: set up the
// nghttp3 connection (once) then submit the request. Behaviour for the existing
// driftstackHttp3Execute path is unchanged.
[[maybe_unused]] static bool driftstackHttp3SetupAndSubmit(DriftstackQuicConn* qc,
    const DriftstackHttp3Request& request)
{
    if (!driftstackHttp3SetupConnection(qc))
        return false;
    return driftstackHttp3SubmitRequest(qc, request);
}

// Wave 29-499.321 — pull pending HTTP/3 stream data from nghttp3, hand it to
// ngtcp2 for QUIC packetization, and emit each resulting packet via the §7
// SOCKS5 relay. Mirrors the ngtcp2/nghttp3 client write loop. Returns the
// number of packets written, or -1 on a fatal error.
[[maybe_unused]] static int driftstackHttp3DrainWrites(DriftstackQuicConn* qc,
    int udpFd, const Socks5Framing::Endpoint& peerEp,
    const struct sockaddr_in& relaySa)
{
    auto& h = ngHttp3Fns();
    auto& nf = ngtcp2Fns();
    auto* h3 = static_cast<nghttp3_conn*>(qc->h3conn);
    int written = 0;
    for (;;) {
        int64_t sid = -1;
        int fin = 0;
        nghttp3_vec vec[16];
        nghttp3_ssize sveccnt = h.conn_writev_stream(h3, &sid, &fin, vec, 16);
        if (sveccnt < 0) {
            WTFLogAlways("[Wave29-499.321] nghttp3_conn_writev_stream rv=%zd", (ssize_t)sveccnt);
            return -1;
        }

        uint8_t pkt[1500];
        ngtcp2_ssize ndatalen = 0;
        // Set MORE only when nghttp3 handed us stream data (and might have more
        // to coalesce). When there's no stream data (sveccnt==0, sid==-1), MORE
        // would tell ngtcp2 to keep buffering instead of flushing — leaving the
        // request packet unsent. A non-MORE call flushes any buffered packet.
        uint32_t flags = (sveccnt > 0) ? NGTCP2_WRITE_STREAM_FLAG_MORE : 0;
        if (fin)
            flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;
        ngtcp2_pkt_info pi { };
        ngtcp2_ssize n = nf.conn_writev_stream_versioned(qc->conn, /*path=*/nullptr,
            NGTCP2_PKT_INFO_VERSION, &pi, pkt, sizeof(pkt), &ndatalen, flags, sid,
            reinterpret_cast<const ngtcp2_vec*>(vec), static_cast<size_t>(sveccnt),
            driftstackQuicTimestampNow());
        if (n < 0) {
            if (n == NGTCP2_ERR_WRITE_MORE) {
                // ngtcp2 buffered the stream data; account for it and keep going.
                if (sid >= 0 && ndatalen >= 0)
                    h.conn_add_write_offset(h3, sid, static_cast<size_t>(ndatalen));
                continue;
            }
            if (n == NGTCP2_ERR_STREAM_DATA_BLOCKED) {
                // Can't send this stream's data right now; stop draining.
                break;
            }
            WTFLogAlways("[Wave29-499.321] conn_writev_stream rv=%zd", (ssize_t)n);
            return -1;
        }
        if (sid >= 0 && ndatalen >= 0)
            h.conn_add_write_offset(h3, sid, static_cast<size_t>(ndatalen));
        if (n == 0)
            break; // nothing more to send

        Vector<uint8_t> framed;
        if (!Socks5Framing::wrap(peerEp, std::span<const uint8_t> { pkt, static_cast<size_t>(n) }, framed))
            break;
        ssize_t s = sendto(udpFd, framed.span().data(), framed.size(), 0,
            reinterpret_cast<const struct sockaddr*>(&relaySa), sizeof(relaySa));
        if (s > 0)
            ++written;
    }
    return written;
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
    int rv = static_cast<int>(nf.conn_read_pkt_versioned(qc->conn, &path,
        NGTCP2_PKT_INFO_VERSION, &pi, buf, buflen, driftstackQuicTimestampNow()));
    if (rv != 0)
        WTFLogAlways("[Wave29-499.313] conn_read_pkt rv=%d (buflen=%zu)", rv, buflen);
    return rv;
}

// Wave 29-499.321 — resolve a hostname's A record THROUGH the SOCKS5 §7 UDP
// relay, so DNS egress stays on the customer proxy (no local-resolver leak).
// The QUIC path needs an IPv4 literal (gost §7 requires ATYP=0x01), and
// resolving locally via getaddrinfo would leak the destination hostname to the
// Mac fleet's resolver. This sends a DNS A query (wrapped in §7, targeting the
// given resolver) over the already-established udpFd/relay, parses the first A
// answer, and returns it as a dotted-quad String. Returns a null String on any
// failure so the caller can fall back to local getaddrinfo. Validated wire
// format: operations/probes/dns-over-socks5-gost.py.
[[maybe_unused]] static String driftstackResolveHostViaSocks5Relay(const String& host,
    int udpFd, const struct sockaddr_in& relaySa, const char* resolverIp)
{
    // Build the DNS A query (RFC 1035 §4.1).
    Vector<uint8_t> query;
    uint8_t txid[2];
    arc4random_buf(txid, 2);
    query.append(std::span<const uint8_t> { txid, 2 });
    static const uint8_t hdr[] = { 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }; // RD set, QD=1
    query.append(std::span<const uint8_t> { hdr, sizeof(hdr) });
    CString hostC = host.utf8();
    const char* h = hostC.data();
    size_t labelStart = 0, len = strlen(h);
    for (size_t i = 0; i <= len; ++i) {
        if (i == len || h[i] == '.') {
            size_t labelLen = i - labelStart;
            if (labelLen > 0 && labelLen <= 63) {
                query.append(static_cast<uint8_t>(labelLen));
                query.append(std::span<const uint8_t> { reinterpret_cast<const uint8_t*>(h + labelStart), labelLen });
            }
            labelStart = i + 1;
        }
    }
    query.append(static_cast<uint8_t>(0)); // root label
    static const uint8_t qtail[] = { 0x00, 0x01, 0x00, 0x01 }; // QTYPE=A QCLASS=IN
    query.append(std::span<const uint8_t> { qtail, sizeof(qtail) });

    // §7-wrap targeting the resolver:53 and send over the relay.
    Socks5Framing::Endpoint resolverEp { String::fromUTF8(resolverIp), 53 };
    Vector<uint8_t> framed;
    if (!Socks5Framing::wrap(resolverEp, query.span(), framed))
        return String();
    if (sendto(udpFd, framed.span().data(), framed.size(), 0,
            reinterpret_cast<const struct sockaddr*>(&relaySa), sizeof(relaySa)) <= 0)
        return String();

    // Wait for the response (short budget; falls back to getaddrinfo on miss).
    struct timeval tv { 2, 0 };
    fd_set rs;
    FD_ZERO(&rs);
    FD_SET(udpFd, &rs);
    if (select(udpFd + 1, &rs, nullptr, nullptr, &tv) <= 0)
        return String();
    uint8_t inbound[2048];
    ssize_t r = recvfrom(udpFd, inbound, sizeof(inbound), 0, nullptr, nullptr);
    if (r <= 0)
        return String();
    Socks5Framing::Endpoint src;
    Vector<uint8_t> payload;
    if (!Socks5Framing::unwrap(std::span<const uint8_t> { inbound, static_cast<size_t>(r) }, src, payload))
        return String();

    // Parse the DNS response: verify txid, skip header + question, read answers.
    const uint8_t* d = payload.span().data();
    size_t n = payload.size();
    if (n < 12 || d[0] != txid[0] || d[1] != txid[1])
        return String();
    uint16_t qd = (d[4] << 8) | d[5];
    uint16_t an = (d[6] << 8) | d[7];
    size_t i = 12;
    for (uint16_t q = 0; q < qd && i < n; ++q) {
        while (i < n && d[i]) {
            if (d[i] & 0xC0) { i += 2; goto qdone; }
            i += d[i] + 1;
        }
        ++i; // null label
qdone:
        i += 4; // qtype + qclass
    }
    for (uint16_t a = 0; a < an && i + 10 <= n; ++a) {
        if (d[i] & 0xC0)
            i += 2;
        else {
            while (i < n && d[i]) i += d[i] + 1;
            ++i;
        }
        if (i + 10 > n) break;
        uint16_t rtype = (d[i] << 8) | d[i + 1];
        uint16_t rdlen = (d[i + 8] << 8) | d[i + 9];
        i += 10;
        if (i + rdlen > n) break;
        if (rtype == 1 && rdlen == 4) {
            char ipbuf[INET_ADDRSTRLEN] = {};
            snprintf(ipbuf, sizeof(ipbuf), "%u.%u.%u.%u", d[i], d[i + 1], d[i + 2], d[i + 3]);
            WTFLogAlways("[Wave29-499.321] DNS-over-§7 resolved %s -> %s (no local leak)", hostC.data(), ipbuf);
            return String::fromUTF8(ipbuf);
        }
        i += rdlen;
    }
    return String();
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

// Wave 29-499.311 — self-contained raw SOCKS5 UDP_ASSOCIATE for QUIC. Does
// ONLY the TCP control handshake (no internal UDP socket), so the QUIC udpFd
// is the FIRST + ONLY UDP sender on this relay → gost binds the relay to udpFd
// and routes server responses back to it. Mirrors the proven aioquic-via-gost
// bridge. The TCP control fd is kept open process-lifetime (relay dies if it
// closes, RFC 1928 §7). Returns true + fills outRelay on success.
static int s_quicSocks5CtrlFd = -1;
// Wave .321 — outFd (optional): when non-null, the caller owns the TCP control
// fd lifetime (e.g. a short-lived DNS query closes it right after). When null,
// the fd is parked in s_quicSocks5CtrlFd and kept open for the QUIC connection
// lifetime (the original behaviour).
static bool driftstackQuicRawSocks5Associate(struct sockaddr_in* outRelay, int* outFd = nullptr)
{
    const char* proxyEnv = getenv("DRIFTSTACK_SOCKS5_PROXY");
    const char* userEnv = getenv("DRIFTSTACK_SOCKS5_USER");
    const char* passEnv = getenv("DRIFTSTACK_SOCKS5_PASS");
    if (!proxyEnv || !proxyEnv[0]) {
        WTFLogAlways("[Wave29-499.311] raw associate: DRIFTSTACK_SOCKS5_PROXY unset");
        return false;
    }
    // Parse host:port (last colon). Manual parse — WTF::String has no toInt().
    size_t envLen = strlen(proxyEnv);
    const char* colonP = nullptr;
    for (size_t i = envLen; i > 0; --i) {
        if (proxyEnv[i - 1] == ':') { colonP = proxyEnv + (i - 1); break; }
    }
    if (!colonP || colonP == proxyEnv) return false;
    Vector<char> hostBuf;
    for (const char* p = proxyEnv; p < colonP; ++p) hostBuf.append(*p);
    hostBuf.append('\0');
    int proxyPort = 0;
    for (const char* p = colonP + 1; *p; ++p) {
        if (*p < '0' || *p > '9') return false;
        proxyPort = proxyPort * 10 + (*p - '0');
        if (proxyPort > 0xFFFF) return false;
    }
    if (proxyPort <= 0) return false;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return false;
    struct sockaddr_in pa { };
    pa.sin_family = AF_INET;
    pa.sin_port = htons(static_cast<uint16_t>(proxyPort));
    if (inet_pton(AF_INET, hostBuf.span().data(), &pa.sin_addr) != 1) { ::close(fd); return false; }
    if (::connect(fd, reinterpret_cast<struct sockaddr*>(&pa), sizeof(pa)) < 0) {
        WTFLogAlways("[Wave29-499.311] raw associate: TCP connect failed errno=%d", errno);
        ::close(fd); return false;
    }

    // Method negotiation — offer user/pass (0x02).
    uint8_t greet[3] = { 0x05, 0x01, 0x02 };
    if (::send(fd, greet, 3, 0) != 3) { ::close(fd); return false; }
    uint8_t mr[2];
    if (::recv(fd, mr, 2, MSG_WAITALL) != 2 || mr[0] != 0x05) { ::close(fd); return false; }
    if (mr[1] == 0x02) {
        // RFC 1929 user/pass auth.
        size_t ul = userEnv ? strlen(userEnv) : 0, pl = passEnv ? strlen(passEnv) : 0;
        Vector<uint8_t> aReq;
        aReq.append(0x01);
        aReq.append(static_cast<uint8_t>(ul));
        for (size_t i = 0; i < ul; i++) aReq.append(static_cast<uint8_t>(userEnv[i]));
        aReq.append(static_cast<uint8_t>(pl));
        for (size_t i = 0; i < pl; i++) aReq.append(static_cast<uint8_t>(passEnv[i]));
        if (::send(fd, aReq.span().data(), aReq.size(), 0) != static_cast<ssize_t>(aReq.size())) { ::close(fd); return false; }
        uint8_t ar[2];
        if (::recv(fd, ar, 2, MSG_WAITALL) != 2 || ar[1] != 0x00) {
            WTFLogAlways("[Wave29-499.311] raw associate: auth rejected");
            ::close(fd); return false;
        }
    }

    // UDP_ASSOCIATE with 0.0.0.0:0 (accept UDP from any local socket → binds to
    // first sender, which will be the QUIC udpFd).
    uint8_t areq[10] = { 0x05, 0x03, 0x00, 0x01, 0,0,0,0, 0,0 };
    if (::send(fd, areq, 10, 0) != 10) { ::close(fd); return false; }
    uint8_t arep[10];
    if (::recv(fd, arep, 10, MSG_WAITALL) != 10 || arep[0] != 0x05 || arep[1] != 0x00) {
        WTFLogAlways("[Wave29-499.311] raw associate: UDP_ASSOCIATE rejected rep0=%02x rep1=%02x", arep[0], arep[1]);
        ::close(fd); return false;
    }
    // BND.ADDR (4) + BND.PORT (2). If BND.ADDR is 0.0.0.0, use the proxy IP.
    outRelay->sin_family = AF_INET;
    memcpy(&outRelay->sin_addr, arep + 4, 4);
    memcpy(&outRelay->sin_port, arep + 8, 2);
    if (outRelay->sin_addr.s_addr == 0)
        outRelay->sin_addr = pa.sin_addr;

    if (outFd)
        *outFd = fd;            // caller owns lifetime (Wave .321 DNS query path)
    else
        s_quicSocks5CtrlFd = fd;  // keep open — relay lives as long as this TCP does
    char relayIp[INET_ADDRSTRLEN] = {};
    inet_ntop(AF_INET, &outRelay->sin_addr, relayIp, sizeof(relayIp));
    WTFLogAlways("[Wave29-499.311] raw SOCKS5 associate OK — relay %s:%u (ctrlFd=%d kept open, udpFd will be sole sender)",
        relayIp, ntohs(outRelay->sin_port), fd);
    return true;
}

} // anonymous namespace

// Wave 29-499.321 — parse a DNS response payload (post-§7-unwrap): does any
// type-65 HTTPS RR advertise alpn "h3"? RFC 9460 §2.2 SvcParams (alpn = key 1).
static bool driftstackParseHttpsRrAlpnH3(const uint8_t* d, size_t n)
{
    if (n < 12)
        return false;
    uint16_t qd = (d[4] << 8) | d[5];
    uint16_t an = (d[6] << 8) | d[7];
    size_t i = 12;
    for (uint16_t q = 0; q < qd && i < n; ++q) {
        while (i < n && d[i]) {
            if (d[i] & 0xC0) { i += 2; goto qskipped; }
            i += d[i] + 1;
        }
        ++i;
qskipped:
        i += 4;
    }
    for (uint16_t a = 0; a < an && i + 10 <= n; ++a) {
        if (d[i] & 0xC0)
            i += 2;
        else {
            while (i < n && d[i]) i += d[i] + 1;
            ++i;
        }
        if (i + 10 > n) break;
        uint16_t rtype = (d[i] << 8) | d[i + 1];
        uint16_t rdlen = (d[i + 8] << 8) | d[i + 9];
        i += 10;
        if (i + rdlen > n) break;
        if (rtype == 65) {
            size_t p = i, end = i + rdlen;
            p += 2; // SvcPriority
            while (p < end && d[p]) {
                if (d[p] & 0xC0) { p += 2; goto nameDone; }
                p += d[p] + 1;
            }
            ++p; // root label
nameDone:
            while (p + 4 <= end) {
                uint16_t key = (d[p] << 8) | d[p + 1];
                uint16_t vlen = (d[p + 2] << 8) | d[p + 3];
                p += 4;
                if (p + vlen > end) break;
                if (key == 1) { // alpn
                    size_t a2 = p, aend = p + vlen;
                    while (a2 < aend) {
                        uint8_t tl = d[a2++];
                        if (a2 + tl > aend) break;
                        if (tl == 2 && d[a2] == 'h' && d[a2 + 1] == '3')
                            return true;
                        a2 += tl;
                    }
                }
                p += vlen;
            }
        }
        i += rdlen;
    }
    return false;
}

// Wave 29-499.321 — CONCURRENT DNS-over-§7 resolver for HTTPS RR (type 65), used
// for first-contact h3 discovery (the mechanism real Safari uses alongside
// Alt-Svc). One shared §7 DNS relay + a background reader thread that demuxes
// responses by transaction-ID, so MANY origins' lookups run in PARALLEL — no
// per-query serialization (an earlier per-host-associate / serialized-lock cut
// stalled many-origin pages like browserleaks). Per-host result cache.
namespace {
Lock g_dnsLock;
Condition g_dnsCond;
int g_dnsUdpFd = -1;
struct sockaddr_in g_dnsRelaySa { };
bool g_dnsReaderStarted = false;
uint16_t g_dnsNextTxid = 1;
// Lazy function-local statics (namespace-scope NeverDestroyed would need a
// global constructor, which WebKit forbids via -Werror,-Wglobal-constructors).
HashSet<uint16_t>& g_dnsPending() { static NeverDestroyed<HashSet<uint16_t>> s; return s; }   // txids awaiting a response
HashMap<uint16_t, bool>& g_dnsResults() { static NeverDestroyed<HashMap<uint16_t, bool>> s; return s; } // txid -> h3?
HashMap<String, bool>& g_dnsHostCache() { static NeverDestroyed<HashMap<String, bool>> s; return s; }   // host -> h3? (final)

// Reader: blocking recv on the shared relay (NO lock held during recv), then
// briefly locks to deliver the result to the waiting query by txid.
void driftstackDnsReaderLoop()
{
    for (;;) {
        uint8_t inbound[2048];
        ssize_t r = recvfrom(g_dnsUdpFd, inbound, sizeof(inbound), 0, nullptr, nullptr);
        if (r <= 0) {
            if (r < 0 && (errno == EBADF || errno == ENOTSOCK))
                return; // relay torn down
            continue;
        }
        Socks5Framing::Endpoint src;
        Vector<uint8_t> payload;
        if (!Socks5Framing::unwrap(std::span<const uint8_t> { inbound, static_cast<size_t>(r) }, src, payload))
            continue;
        const uint8_t* d = payload.span().data();
        size_t n = payload.size();
        if (n < 12)
            continue;
        uint16_t txid = (d[0] << 8) | d[1];
        bool h3 = driftstackParseHttpsRrAlpnH3(d, n);
        Locker locker { g_dnsLock };
        bool wasPending = g_dnsPending().remove(txid);
        WTFLogAlways("[Wave29-499.321/dnsReader] recv %zdB txid=%u h3=%d pending-hit=%d", r, txid, h3, wasPending);
        if (wasPending) {
            g_dnsResults().set(txid, h3);
            g_dnsCond.notifyAll();
        }
    }
}
} // anonymous namespace

bool driftstackHostAdvertisesH3ViaDns(const WTF::String& host)
{
    {
        Locker locker { g_dnsLock };
        auto it = g_dnsHostCache().find(host);
        if (it != g_dnsHostCache().end())
            return it->value;
    }

    bool h3 = false;
    uint16_t txid = 0;
    bool sent = false;
    {
        Locker locker { g_dnsLock };
        // Lazily open the shared relay + start the reader thread once.
        if (g_dnsUdpFd < 0) {
            struct sockaddr_in rs { };
            int cf = -1;
            if (driftstackQuicRawSocks5Associate(&rs, &cf)) {
                int uf = socket(AF_INET, SOCK_DGRAM, 0);
                if (uf >= 0) {
                    struct sockaddr_in lb { };
                    lb.sin_family = AF_INET;
                    lb.sin_addr.s_addr = htonl(INADDR_ANY);
                    lb.sin_port = 0;
                    bind(uf, reinterpret_cast<struct sockaddr*>(&lb), sizeof(lb));
                    g_dnsUdpFd = uf;
                    g_dnsRelaySa = rs;
                    (void)cf; // control fd parked open for the relay's lifetime
                } else if (cf >= 0)
                    ::close(cf);
            }
        }
        if (g_dnsUdpFd >= 0 && !g_dnsReaderStarted) {
            g_dnsReaderStarted = true;
            Thread::create("driftstack-dns-https-rr"_s, [] { driftstackDnsReaderLoop(); })->detach();
        }

        if (g_dnsUdpFd >= 0) {
            txid = g_dnsNextTxid++;
            if (!g_dnsNextTxid) g_dnsNextTxid = 1;

            // Build the type-65 (HTTPS) query for host.
            Vector<uint8_t> query;
            query.append(static_cast<uint8_t>(txid >> 8));
            query.append(static_cast<uint8_t>(txid & 0xFF));
            static const uint8_t hdr[] = { 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
            query.append(std::span<const uint8_t> { hdr, sizeof(hdr) });
            CString hostC = host.utf8();
            const char* hp = hostC.data();
            size_t lstart = 0, hl = strlen(hp);
            for (size_t i = 0; i <= hl; ++i) {
                if (i == hl || hp[i] == '.') {
                    size_t ll = i - lstart;
                    if (ll > 0 && ll <= 63) {
                        query.append(static_cast<uint8_t>(ll));
                        query.append(std::span<const uint8_t> { reinterpret_cast<const uint8_t*>(hp + lstart), ll });
                    }
                    lstart = i + 1;
                }
            }
            query.append(static_cast<uint8_t>(0));
            static const uint8_t qtail[] = { 0x00, 0x41, 0x00, 0x01 }; // QTYPE=65 QCLASS=IN
            query.append(std::span<const uint8_t> { qtail, sizeof(qtail) });

            Socks5Framing::Endpoint resolverEp { "1.1.1.1"_s, 53 };
            Vector<uint8_t> framed;
            if (Socks5Framing::wrap(resolverEp, query.span(), framed)) {
                g_dnsPending().add(txid);
                ssize_t sret = sendto(g_dnsUdpFd, framed.span().data(), framed.size(), 0,
                        reinterpret_cast<const struct sockaddr*>(&g_dnsRelaySa), sizeof(g_dnsRelaySa));
                WTFLogAlways("[Wave29-499.321/dnsQuery] send host=%s txid=%u fd=%d sret=%zd readerStarted=%d", host.utf8().data(), txid, g_dnsUdpFd, sret, g_dnsReaderStarted);
                if (sret > 0)
                    sent = true;
                else
                    g_dnsPending().remove(txid);
            }
        }

        // Wait (concurrently with other queries — waitUntil releases the lock)
        // for the reader to deliver this txid's result. 800ms cap.
        if (sent) {
            MonotonicTime deadline = MonotonicTime::now() + Seconds::fromMilliseconds(800);
            while (!g_dnsResults().contains(txid)) {
                if (!g_dnsCond.waitUntil(g_dnsLock, deadline))
                    break; // timeout
            }
            auto it = g_dnsResults().find(txid);
            if (it != g_dnsResults().end()) {
                h3 = it->value;
                g_dnsResults().remove(txid);
            }
            g_dnsPending().remove(txid);
        }

        g_dnsHostCache().set(host, h3);
    }

    if (h3)
        WTFLogAlways("[Wave29-499.321] DNS HTTPS RR: %s advertises h3 (first-contact h3, no local leak)", host.utf8().data());
    return h3;
}

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
    auto& nf = ngtcp2Fns();  // Wave .316 — needed for tls_handshake_completed in loop
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

    // Wave 29-499.311 — raw single-socket SOCKS5 UDP_ASSOCIATE for QUIC.
    // The TCP control handshake creates the relay; the QUIC udpFd (created
    // below) is then the FIRST + ONLY UDP sender on it, so gost binds the relay
    // to udpFd and routes server responses back to it. (Prior shared/dedicated
    // client approaches used a separate internal UDP socket → responses routed
    // elsewhere → packetsReceived=0.)
    struct sockaddr_in relaySa { };
    if (!driftstackQuicRawSocks5Associate(&relaySa)) {
        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.311] raw SOCKS5 associate FAILED — h3 falls back to h2");
        bsf.SSL_free(ssl);
        bsf.SSL_CTX_free(ctx);
        resp.failed = true;
        resp.errorMessage = "SOCKS5 UDP_ASSOCIATE failed for HTTP/3 transport"_s;
        return resp;
    }

    // Create + bind local UDP socket. This udpFd is the sole UDP sender on the
    // relay established above.
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
    // relaySa was filled by driftstackQuicRawSocks5Associate above (Wave .311).

    // Peer addr for connectQuic. For this scaffold: cloudflare-quic.com
    // (1.1.1.1:443) — a known h3 server. Wave .239 wires request.authority
    // resolution via hardcodedSTUNHostnameLookup (and adds h3-specific
    // hostname → IPv4 mappings since the .94 map is STUN-focused).
    struct sockaddr_in local { };
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_ANY);
    local.sin_port = htons(boundPort);

    // Wave 29-499.321 — resolve the REAL request host → IPv4 for production
    // routing (was hardcoded 1.1.1.1 smoke target). gost's §7 relay requires
    // ATYP=0x01 (IPv4 literal), so we resolve locally via getaddrinfo before
    // §7-wrapping. (DNS-over-proxy via ATYP=0x03 is a separate hardening item;
    // the QUIC bridge framer path already does the same local pre-resolution
    // per .319b, so this is consistent.) Default port 443 unless the authority
    // carries an explicit :port.
    String authHost;
    uint16_t authPort = 443;
    {
        CString a = request.authority.utf8();
        const char* astr = a.data();
        if (astr && astr[0]) {
            const char* colon = strchr(astr, ':');
            if (colon) {
                authHost = String::fromUTF8(std::span<const char> { astr, static_cast<size_t>(colon - astr) });
                authPort = static_cast<uint16_t>(atoi(colon + 1));
                if (!authPort) authPort = 443;
            } else
                authHost = String::fromUTF8(astr);
        }
    }
    String peerIpStr = "1.1.1.1"_s;  // smoke fallback (empty authority)
    if (!authHost.isEmpty()) {
        // Prefer DNS-over-§7 (resolves through the customer proxy, no local
        // hostname leak). Fall back to local getaddrinfo only if that fails so
        // the path stays functional — best case no leak, worst case current
        // behaviour. (Tracked: the fallback still leaks; the proxy-DNS path is
        // the privacy-correct one.)
        String viaRelay = driftstackResolveHostViaSocks5Relay(authHost, udpFd, relaySa, "1.1.1.1");
        if (!viaRelay.isEmpty())
            peerIpStr = viaRelay;
        else {
            struct addrinfo hints { };
            hints.ai_family = AF_INET;
            hints.ai_socktype = SOCK_DGRAM;
            struct addrinfo* res = nullptr;
            CString hostC = authHost.utf8();
            if (getaddrinfo(hostC.data(), nullptr, &hints, &res) == 0 && res) {
                auto* sin = reinterpret_cast<struct sockaddr_in*>(res->ai_addr);
                char ipbuf[INET_ADDRSTRLEN] = {};
                inet_ntop(AF_INET, &sin->sin_addr, ipbuf, sizeof(ipbuf));
                peerIpStr = String::fromUTF8(ipbuf);
                freeaddrinfo(res);
                WTFLogAlways("[Wave29-499.321] DNS-over-§7 failed for '%s' — fell back to LOCAL getaddrinfo (leaks; %s)", hostC.data(), ipbuf);
            } else {
                WTFLogAlways("[Wave29-499.321] both DNS-over-§7 and getaddrinfo FAILED for '%s' — using 1.1.1.1", hostC.data());
                if (res) freeaddrinfo(res);
            }
        }
    }

    struct sockaddr_in peer { };
    peer.sin_family = AF_INET;
    inet_pton(AF_INET, peerIpStr.utf8().data(), &peer.sin_addr);
    peer.sin_port = htons(authPort);

    {
        char relayIpStr[INET_ADDRSTRLEN] = {};
        inet_ntop(AF_INET, &relaySa.sin_addr, relayIpStr, sizeof(relayIpStr));
        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.321] UDP socket fd=%d localPort=%u, relay=%s:%u, peer=%s:%u (authority=%s). Ready for handshake event loop.",
            udpFd, boundPort, relayIpStr, ntohs(relaySa.sin_port),
            peerIpStr.utf8().data(), authPort, request.authority.utf8().data());
    }

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
    // Wave 29-499.286 — CORRECT IP: cloudflare-quic.com resolves to 104.18.26.14
    // (verified via `dig +short cloudflare-quic.com @8.8.8.8`). Previously
    // hardcoded 162.159.135.96 from Wave .256 was WRONG (that's a different
    // Cloudflare anycast IP not serving QUIC test endpoint). Wave .285 fixed
    // ATYP encoding to 0x01 but still no response because target IP was wrong.
    Socks5Framing::Endpoint peerEp { peerIpStr, authPort };  // Wave .321 — resolved real request host (was hardcoded 1.1.1.1)
    constexpr int kMaxIterations = 40;       // Wave .309 — wider window (was 20)
    constexpr int kPerRecvTimeoutMs = 300;
    int iters = 0;
    int packetsSent = 0;
    int packetsReceived = 0;
    bool remoteTpApplied = false;  // Wave .321 — per-connection (NOT static)
    while (iters < kMaxIterations && !qc->handshakeCompleted) {
        ++iters;
        // Drive TLS state machine. May fire quic_method.set_*_secret +
        // add_handshake_data → ngtcp2_conn_submit_crypto_data.
        int hsRv = bsf.SSL_do_handshake(ssl);
        // Wave .321 — feed the server's QUIC transport parameters (from the TLS
        // quic_transport_parameters extension) into ngtcp2 AS SOON AS available,
        // every iteration until it succeeds. Without this, ngtcp2 keeps default
        // remote limits (initial_max_streams_uni=0) and every
        // ngtcp2_conn_open_uni_stream returns STREAM_ID_BLOCKED (-206), so the 3
        // HTTP/3 control/QPACK streams can't open. Must happen BEFORE ngtcp2
        // marks the handshake complete (which fires from conn_read_pkt, not from
        // SSL_do_handshake==1). The ngtcp2_crypto helper does this automatically;
        // our hand-rolled path must do it explicitly.
        if (!remoteTpApplied && bsf.SSL_get_peer_quic_transport_params
            && nf.conn_decode_and_set_remote_transport_params) {
            const uint8_t* tp = nullptr;
            size_t tpLen = 0;
            bsf.SSL_get_peer_quic_transport_params(ssl, &tp, &tpLen);
            if (tp && tpLen > 0) {
                int tprv = nf.conn_decode_and_set_remote_transport_params(qc->conn, tp, tpLen);
                remoteTpApplied = (tprv == 0);
                WTFLogAlways("[Wave29-499.321] applied server transport params (%zu bytes) rv=%d — uni-stream limits now available", tpLen, tprv);
            }
        }
        if (hsRv == 1) {
            // Wave .316 — TLS done; notify ngtcp2 so QUIC handshake can complete.
            if (nf.conn_tls_handshake_completed && !qc->handshakeCompleted) {
                nf.conn_tls_handshake_completed(qc->conn);
                WTFLogAlways("[Wave29-499.316] (loop) SSL_do_handshake=1 → tls_handshake_completed()");
            }
        } else {
            int sslErr = bsf.SSL_get_error ? bsf.SSL_get_error(ssl, hsRv) : -999;
            // SSL_ERROR_WANT_READ=2 is normal (waiting for more crypto data).
            static int s_hsLogCount = 0;
            if (sslErr != 2 && s_hsLogCount < 6) {
                s_hsLogCount++;
                WTFLogAlways("[Wave29-499.313] iter=%d SSL_do_handshake rv=%d SSL_get_error=%d", iters, hsRv, sslErr);
            }
        }

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
                // Wave 29-499.305b — NetworkProcess sandbox blocks /tmp writes,
                // so emit the FULL Initial as base64 to the log for offline
                // aioquic-crypto decryption test (byte-diff debugging).
                {
                    static const char b64c[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
                    size_t len = static_cast<size_t>(n);
                    char enc[2400];
                    size_t o = 0;
                    for (size_t i = 0; i < len && o + 4 < sizeof(enc); i += 3) {
                        uint32_t v = static_cast<uint32_t>(pkt[i]) << 16;
                        if (i + 1 < len) v |= static_cast<uint32_t>(pkt[i + 1]) << 8;
                        if (i + 2 < len) v |= pkt[i + 2];
                        enc[o++] = b64c[(v >> 18) & 0x3f];
                        enc[o++] = b64c[(v >> 12) & 0x3f];
                        enc[o++] = (i + 1 < len) ? b64c[(v >> 6) & 0x3f] : '=';
                        enc[o++] = (i + 2 < len) ? b64c[v & 0x3f] : '=';
                    }
                    enc[o] = '\0';
                    WTFLogAlways("[Wave29-499.305] INITIAL_B64 len=%zd %s", n, enc);
                }
            }
        }

        // Wait for inbound with a short per-iteration timeout.
        struct timeval tv { 0, kPerRecvTimeoutMs * 1000 };
        fd_set rs;
        FD_ZERO(&rs);
        FD_SET(udpFd, &rs);
        int sel = select(udpFd + 1, &rs, nullptr, nullptr, &tv);
        if (sel <= 0) {
            // Wave 29-499.317 — no inbound this tick: drive ngtcp2 loss recovery
            // so a lost Initial/Handshake packet gets RETRANSMITTED. Without this,
            // a single dropped UDP datagram stalls the handshake (packetsSent=1,
            // packetsReceived=0) → flaky completion. handle_expiry triggers PTO;
            // the next loop iteration's write-drain re-sends the lost packet.
            if (nf.conn_handle_expiry)
                nf.conn_handle_expiry(qc->conn, driftstackQuicTimestampNow());
            continue;
        }

        uint8_t inbound[2048];
        struct sockaddr_in from { };
        socklen_t fromLen = sizeof(from);
        ssize_t r = recvfrom(udpFd, inbound, sizeof(inbound), 0,
            reinterpret_cast<struct sockaddr*>(&from), &fromLen);
        if (r <= 0) continue;
        ++packetsReceived;

        Socks5Framing::Endpoint src;
        Vector<uint8_t> payload;
        bool unwrapped = Socks5Framing::unwrap(std::span<const uint8_t> { inbound, static_cast<size_t>(r) }, src, payload);
        // Wave 29-499.309 — log EVERY inbound datagram + unwrap result to
        // characterize the SOCKS5 §7 recv transport (was: first-only).
        WTFLogAlways("[Wave29-499.309] RECV iter=%d %zd bytes from %s:%u unwrap=%d payload=%zu src=%s:%u first4=%02x %02x %02x %02x",
            iters, r, inet_ntoa(from.sin_addr), ntohs(from.sin_port),
            unwrapped, unwrapped ? payload.size() : 0,
            unwrapped ? src.host.utf8().data() : "?", unwrapped ? src.port : 0,
            r > 0 ? inbound[0] : 0, r > 1 ? inbound[1] : 0, r > 2 ? inbound[2] : 0, r > 3 ? inbound[3] : 0);
        if (!unwrapped)
            continue;

        driftstackQuicReadPacket(qc, payload.span().data(), payload.size(),
            reinterpret_cast<struct sockaddr*>(&peer), sizeof(peer),
            reinterpret_cast<struct sockaddr*>(&local), sizeof(local));
    }

    WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.239] handshake event loop: iters=%d packetsSent=%d packetsReceived=%d handshakeCompleted=%d",
        iters, packetsSent, packetsReceived, qc->handshakeCompleted);

    bool completed = qc->handshakeCompleted;

    // Wave 29-499.321 — HTTP/3 request/response phase. TLS 1.3 reached 1-RTT
    // keys; now create the nghttp3 client, submit the GET, and pump bytes
    // between ngtcp2 streams and nghttp3 until the response is complete (or a
    // bounded budget is exhausted). This turns the smoke harness into a real
    // H3 client — the engine WebKit's loader routes H3 resource loads to.
    if (completed) {
        if (!driftstackHttp3SetupAndSubmit(qc, request)) {
            WTFLogAlways("[Wave29-499.321] H3 setup/submit failed — returning handshake-only success");
        } else {
            // Wave .321 — wider budget; each iteration now DRAINS all queued
            // datagrams (not one), so a multi-packet response completes in a few
            // wakeups instead of one-packet-per-300ms (the cause of the earlier
            // budget-exhausted-at-60KB stall).
            constexpr int kH3MaxIterations = 200;
            int h3iters = 0;
            int h3PacketsSent = 0;
            int h3PacketsReceived = 0;
            while (h3iters < kH3MaxIterations && !qc->h3ResponseComplete) {
                ++h3iters;
                int w = driftstackHttp3DrainWrites(qc, udpFd, peerEp, relaySa);
                if (w > 0) h3PacketsSent += w;
                if (w < 0) break;

                struct timeval tv { 0, kPerRecvTimeoutMs * 1000 };
                fd_set rs;
                FD_ZERO(&rs);
                FD_SET(udpFd, &rs);
                int sel = select(udpFd + 1, &rs, nullptr, nullptr, &tv);
                if (sel <= 0) {
                    if (nf.conn_handle_expiry)
                        nf.conn_handle_expiry(qc->conn, driftstackQuicTimestampNow());
                    continue;
                }
                // Drain EVERY queued datagram this wakeup (non-blocking) so a
                // burst of response packets is consumed in one pass.
                for (;;) {
                    uint8_t inbound[2048];
                    ssize_t r = recvfrom(udpFd, inbound, sizeof(inbound), MSG_DONTWAIT, nullptr, nullptr);
                    if (r <= 0)
                        break;
                    ++h3PacketsReceived;
                    Socks5Framing::Endpoint src;
                    Vector<uint8_t> payload;
                    if (!Socks5Framing::unwrap(std::span<const uint8_t> { inbound, static_cast<size_t>(r) }, src, payload))
                        continue;
                    driftstackQuicReadPacket(qc, payload.span().data(), payload.size(),
                        reinterpret_cast<struct sockaddr*>(&peer), sizeof(peer),
                        reinterpret_cast<struct sockaddr*>(&local), sizeof(local));
                    if (qc->h3ResponseComplete)
                        break;
                }
            }
            // Final write-drain to flush ACKs for the last received packets.
            driftstackHttp3DrainWrites(qc, udpFd, peerEp, relaySa);
            WTFLogAlways("[Wave29-499.321] H3 request loop: iters=%d sent=%d recv=%d complete=%d status=%d bodyLen=%zu",
                h3iters, h3PacketsSent, h3PacketsReceived, qc->h3ResponseComplete,
                qc->h3Status, qc->h3ResponseBody.size());
        }
    }

    // Snapshot H3 results before tearing down the conn.
    bool h3Complete = qc->h3ResponseComplete;
    int h3Status = qc->h3Status;
    Vector<uint8_t> h3Body = std::move(qc->h3ResponseBody);
    Vector<std::pair<Vector<uint8_t>, Vector<uint8_t>>> h3Hdrs = std::move(qc->h3ResponseHeaders);

    if (qc->h3conn) {
        ngHttp3Fns().conn_del(static_cast<nghttp3_conn*>(qc->h3conn));
        qc->h3conn = nullptr;
    }
    ::close(udpFd);
    destroyDriftstackQuicConn(qc);
    bsf.SSL_free(ssl);
    bsf.SSL_CTX_free(ctx);

    if (completed && h3Complete) {
        resp.failed = false;
        resp.statusCode = h3Status ? h3Status : 200;
        resp.body = std::move(h3Body);
        for (auto& kv : h3Hdrs) {
            resp.headers.append({
                String::fromUTF8(std::span<const char8_t> { reinterpret_cast<const char8_t*>(kv.first.span().data()), kv.first.size() }),
                String::fromUTF8(std::span<const char8_t> { reinterpret_cast<const char8_t*>(kv.second.span().data()), kv.second.size() }) });
        }
        resp.errorMessage = ""_s;
        WTFLogAlways("[Wave29-499.321] HTTP/3 REQUEST COMPLETE — status=%d bodyLen=%zu headers=%zu via SOCKS5 §7",
            resp.statusCode, resp.body.size(), resp.headers.size());
        return resp;
    }

    if (completed) {
        // Handshake worked but the H3 exchange didn't finish in budget.
        resp.failed = true;
        resp.statusCode = 0;
        resp.errorMessage = "QUIC handshake complete but HTTP/3 response did not finish (nghttp3 request loop budget exhausted)"_s;
        WTFLogAlways("[Wave29-499.321] handshake OK but H3 response incomplete");
        return resp;
    }

    resp.failed = true;
    char buf[256];
    snprintf(buf, sizeof(buf), "Phase 3 HTTP/3 handshake: iters=%d packetsSent=%d packetsReceived=%d handshakeCompleted=false (likely AEAD/hp_mask decrypt fail on recv Initial - diagnostic .284)",
        iters, packetsSent, packetsReceived);
    resp.errorMessage = String::fromUTF8(buf);
    return resp;
}

// ===========================================================================
// Wave 29-499.322 (Phase 3.5) — DriftstackHttp3Session: persistent QUIC+h3
// connection for pooling. create() does the one-time setup + handshake (mirrors
// driftstackHttp3Execute's bring-up, reusing the same factored primitives —
// connectQuic / driftstackQuicRawSocks5Associate / SetupConnection / etc. — so
// the one-shot Execute path is left completely untouched). A background PUMP
// thread owns the QUIC conn and services it continuously; execute() enqueues a
// request + waits for its stream — so many requests multiplex CONCURRENTLY on the
// one connection (one handshake/origin). ngtcp2/nghttp3 are NOT thread-safe, so
// ALL conn ops (open_bidi_stream, submit, read_pkt, writev, expiry) run ONLY on
// the pump thread; execute() never touches the conn. Gated by DRIFTSTACK_H3_POOL.
// ===========================================================================
namespace {
// One in-flight request: submitted by the pump on a fresh bidi stream; execute()
// waits on the session condvar until done, then reads response.
struct H3PendingReq {
    DriftstackHttp3Request request;
    int64_t streamId { -1 };
    bool done { false };
    DriftstackHttp3Response response;
};
// Per-session pump state (PIMPL behind DriftstackHttp3Session::m_pumpState).
struct H3PumpState {
    Condition cond;                                              // signalled on enqueue + completion
    bool stop { false };
    Vector<std::shared_ptr<H3PendingReq>> queue;                // awaiting submit (guarded by m_lock)
    HashMap<int64_t, std::shared_ptr<H3PendingReq>> inflight;    // (streamId+1) → req (guarded by m_lock)
    RefPtr<Thread> thread;
};
} // namespace

bool driftstackHttp3PoolEnabled()
{
    static const char* e = getenv("DRIFTSTACK_H3_POOL");
    return e && e[0] == '1';
}

DriftstackHttp3Session::DriftstackHttp3Session(void* qc, void* ssl)
    : m_qc(qc)
    , m_ssl(ssl)
{
}

DriftstackHttp3Session::~DriftstackHttp3Session()
{
    // Stop + join the pump thread FIRST so no conn ops race the teardown below.
    if (m_pumpState) {
        auto* st = static_cast<H3PumpState*>(m_pumpState);
        {
            Locker l { m_lock };
            st->stop = true;
            st->cond.notifyAll();
        }
        if (st->thread)
            st->thread->waitForCompletion();
        delete st;
        m_pumpState = nullptr;
    }
    if (!m_qc)
        return;
    DriftstackQuicConn* qc = static_cast<DriftstackQuicConn*>(m_qc);
    auto& bsf = boringSslQuicFns();
    if (qc->h3conn) {
        ngHttp3Fns().conn_del(static_cast<nghttp3_conn*>(qc->h3conn));
        qc->h3conn = nullptr;
    }
    if (qc->udpFd >= 0)
        ::close(qc->udpFd);
    void* ctx = qc->sslCtx;            // read before destroy frees qc
    destroyDriftstackQuicConn(qc);
    if (m_ssl)
        bsf.SSL_free(m_ssl);
    if (ctx)
        bsf.SSL_CTX_free(ctx);
    m_qc = nullptr;
    m_ssl = nullptr;
}

bool DriftstackHttp3Session::isAlive()
{
    Locker locker { m_lock };
    return m_alive && m_qc && static_cast<DriftstackQuicConn*>(m_qc)->handshakeCompleted;
}

RefPtr<DriftstackHttp3Session> DriftstackHttp3Session::create(const String& authority)
{
    if (!resolveNgtcp2() || !resolveBoringSslQuic())
        return nullptr;
    auto& bsf = boringSslQuicFns();
    auto& nf = ngtcp2Fns();

    const void* method = bsf.TLS_client_method();
    void* ctx = bsf.SSL_CTX_new(method);
    if (!ctx)
        return nullptr;
    constexpr int kTLS13 = 0x0304;
    bsf.SSL_CTX_set_min_proto_version(ctx, kTLS13);
    bsf.SSL_CTX_set_max_proto_version(ctx, kTLS13);
    static const uint8_t alpnH3[] = { 0x02, 'h', '3' };
    bsf.SSL_CTX_set_alpn_protos(ctx, alpnH3, sizeof(alpnH3));
    void* ssl = bsf.SSL_new(ctx);
    if (!ssl) {
        bsf.SSL_CTX_free(ctx);
        return nullptr;
    }
    bsf.SSL_set_connect_state(ssl);

    // Parse host[:port] from authority; set SNI.
    String authHost;
    uint16_t authPort = 443;
    {
        CString a = authority.utf8();
        const char* astr = a.data();
        if (astr && astr[0]) {
            const char* colon = strchr(astr, ':');
            if (colon) {
                authHost = String::fromUTF8(std::span<const char> { astr, static_cast<size_t>(colon - astr) });
                authPort = static_cast<uint16_t>(atoi(colon + 1));
                if (!authPort) authPort = 443;
            } else
                authHost = String::fromUTF8(astr);
        }
    }
    if (!authHost.isEmpty())
        bsf.SSL_set_tlsext_host_name(ssl, authHost.utf8().data());

    auto cleanup = [&]() { bsf.SSL_free(ssl); bsf.SSL_CTX_free(ctx); };

    struct sockaddr_in relaySa { };
    if (!driftstackQuicRawSocks5Associate(&relaySa)) {
        WTFLogAlways("[Wave29-499.322/H3POOL] SOCKS5 UDP_ASSOCIATE failed for %s", authority.utf8().data());
        cleanup();
        return nullptr;
    }

    int udpFd = socket(AF_INET, SOCK_DGRAM, 0);
    if (udpFd < 0) { cleanup(); return nullptr; }
    struct sockaddr_in localBind { };
    localBind.sin_family = AF_INET;
    localBind.sin_addr.s_addr = htonl(INADDR_ANY);
    localBind.sin_port = 0;
    if (bind(udpFd, reinterpret_cast<struct sockaddr*>(&localBind), sizeof(localBind)) < 0) {
        ::close(udpFd);
        cleanup();
        return nullptr;
    }
    socklen_t localLen = sizeof(localBind);
    getsockname(udpFd, reinterpret_cast<struct sockaddr*>(&localBind), &localLen);
    uint16_t boundPort = ntohs(localBind.sin_port);

    struct sockaddr_in local { };
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_ANY);
    local.sin_port = htons(boundPort);

    String peerIpStr = "1.1.1.1"_s;
    if (!authHost.isEmpty()) {
        String viaRelay = driftstackResolveHostViaSocks5Relay(authHost, udpFd, relaySa, "1.1.1.1");
        if (!viaRelay.isEmpty())
            peerIpStr = viaRelay;
        else {
            struct addrinfo hints { };
            hints.ai_family = AF_INET;
            hints.ai_socktype = SOCK_DGRAM;
            struct addrinfo* res = nullptr;
            CString hostC = authHost.utf8();
            if (getaddrinfo(hostC.data(), nullptr, &hints, &res) == 0 && res) {
                auto* sin = reinterpret_cast<struct sockaddr_in*>(res->ai_addr);
                char ipbuf[INET_ADDRSTRLEN] = {};
                inet_ntop(AF_INET, &sin->sin_addr, ipbuf, sizeof(ipbuf));
                peerIpStr = String::fromUTF8(ipbuf);
                freeaddrinfo(res);
            } else if (res)
                freeaddrinfo(res);
        }
    }

    struct sockaddr_in peer { };
    peer.sin_family = AF_INET;
    inet_pton(AF_INET, peerIpStr.utf8().data(), &peer.sin_addr);
    peer.sin_port = htons(authPort);

    DriftstackQuicConn* qc = connectQuic(ssl,
        reinterpret_cast<const struct sockaddr*>(&local), sizeof(local),
        reinterpret_cast<const struct sockaddr*>(&peer), sizeof(peer));
    if (!qc) {
        ::close(udpFd);
        cleanup();
        return nullptr;
    }

    // Handshake event loop (mirrors driftstackHttp3Execute .239/.317/.321).
    Socks5Framing::Endpoint peerEp { peerIpStr, authPort };
    constexpr int kMaxIterations = 40;
    constexpr int kPerRecvTimeoutMs = 300;
    int iters = 0;
    bool remoteTpApplied = false;
    while (iters < kMaxIterations && !qc->handshakeCompleted) {
        ++iters;
        int hsRv = bsf.SSL_do_handshake(ssl);
        if (!remoteTpApplied && bsf.SSL_get_peer_quic_transport_params
            && nf.conn_decode_and_set_remote_transport_params) {
            const uint8_t* tp = nullptr;
            size_t tpLen = 0;
            bsf.SSL_get_peer_quic_transport_params(ssl, &tp, &tpLen);
            if (tp && tpLen > 0)
                remoteTpApplied = (nf.conn_decode_and_set_remote_transport_params(qc->conn, tp, tpLen) == 0);
        }
        if (hsRv == 1 && nf.conn_tls_handshake_completed && !qc->handshakeCompleted)
            nf.conn_tls_handshake_completed(qc->conn);
        for (;;) {
            uint8_t pkt[1500];
            ssize_t n = driftstackQuicWritePacket(qc, pkt, sizeof(pkt));
            if (n <= 0)
                break;
            Vector<uint8_t> framed;
            if (!Socks5Framing::wrap(peerEp, std::span<const uint8_t> { pkt, static_cast<size_t>(n) }, framed))
                break;
            sendto(udpFd, framed.span().data(), framed.size(), 0,
                reinterpret_cast<struct sockaddr*>(&relaySa), sizeof(relaySa));
        }
        struct timeval tv { 0, kPerRecvTimeoutMs * 1000 };
        fd_set rs;
        FD_ZERO(&rs);
        FD_SET(udpFd, &rs);
        int sel = select(udpFd + 1, &rs, nullptr, nullptr, &tv);
        if (sel <= 0) {
            if (nf.conn_handle_expiry)
                nf.conn_handle_expiry(qc->conn, driftstackQuicTimestampNow());
            continue;
        }
        uint8_t inbound[2048];
        ssize_t r = recvfrom(udpFd, inbound, sizeof(inbound), 0, nullptr, nullptr);
        if (r <= 0)
            continue;
        Socks5Framing::Endpoint src;
        Vector<uint8_t> payload;
        if (!Socks5Framing::unwrap(std::span<const uint8_t> { inbound, static_cast<size_t>(r) }, src, payload))
            continue;
        driftstackQuicReadPacket(qc, payload.span().data(), payload.size(),
            reinterpret_cast<struct sockaddr*>(&peer), sizeof(peer),
            reinterpret_cast<struct sockaddr*>(&local), sizeof(local));
    }

    if (!qc->handshakeCompleted) {
        WTFLogAlways("[Wave29-499.322/H3POOL] handshake FAILED for %s (iters=%d)", authority.utf8().data(), iters);
        ::close(udpFd);
        destroyDriftstackQuicConn(qc);
        cleanup();
        return nullptr;
    }
    if (!driftstackHttp3SetupConnection(qc)) {
        WTFLogAlways("[Wave29-499.322/H3POOL] nghttp3 setup FAILED for %s", authority.utf8().data());
        ::close(udpFd);
        destroyDriftstackQuicConn(qc);
        cleanup();
        return nullptr;
    }

    // Persist the transport state so execute() can pump the SAME connection.
    qc->sslCtx = ctx;
    qc->udpFd = udpFd;
    qc->relaySa = relaySa;
    qc->peerSa = peer;
    qc->localSa = local;
    qc->peerIp = peerIpStr;
    qc->peerPort = authPort;

    WTFLogAlways("[Wave29-499.322/H3POOL] session ESTABLISHED for %s (peer=%s:%u, handshake OK, h3 streams bound)",
        authority.utf8().data(), peerIpStr.utf8().data(), authPort);
    auto session = adoptRef(new DriftstackHttp3Session(qc, ssl));
    // Start the owner pump thread (services the conn + drains the request queue).
    auto* st = new H3PumpState;
    session->m_pumpState = st;
    DriftstackHttp3Session* raw = session.get(); // dtor joins before freeing → raw stays valid
    st->thread = Thread::create("driftstack-h3-pump"_s, [raw] { raw->runPump(); });
    return session;
}

void DriftstackHttp3Session::runPump()
{
    auto* st = static_cast<H3PumpState*>(m_pumpState);
    DriftstackQuicConn* qc = static_cast<DriftstackQuicConn*>(m_qc);
    auto& nf = ngtcp2Fns();
    Socks5Framing::Endpoint peerEp { qc->peerIp, qc->peerPort };
    while (true) {
        // 1. take queued requests + check stop.
        Vector<std::shared_ptr<H3PendingReq>> toSubmit;
        {
            Locker l { m_lock };
            if (st->stop)
                break;
            toSubmit = std::move(st->queue);
            st->queue.clear();
        }
        // 2. submit each on a fresh bidi stream (conn ops — pump thread ONLY).
        bool anyFailed = false;
        for (auto& p : toSubmit) {
            if (!driftstackHttp3SubmitRequest(qc, p->request)) {
                Locker l { m_lock };
                p->response.failed = true;
                p->response.errorMessage = "h3 submit failed"_s;
                p->done = true;
                anyFailed = true;
                continue;
            }
            int64_t sid = qc->h3RequestStreamId; // SubmitRequest set this to the new stream
            Locker l { m_lock };
            p->streamId = sid;
            st->inflight.set(sid + 1, p); // key +1 to match the per-stream map (stream 0 → key 1)
        }
        if (anyFailed)
            st->cond.notifyAll();
        // 3. service the QUIC conn: flush writes, read inbound (fires nghttp3
        //    callbacks → per-stream map), drive loss recovery, flush ACKs.
        driftstackHttp3DrainWrites(qc, qc->udpFd, peerEp, qc->relaySa);
        struct timeval tv { 0, 20 * 1000 }; // 20ms — responsive to new requests + inbound
        fd_set rs;
        FD_ZERO(&rs);
        FD_SET(qc->udpFd, &rs);
        int sel = select(qc->udpFd + 1, &rs, nullptr, nullptr, &tv);
        if (sel > 0) {
            for (;;) {
                uint8_t inbound[2048];
                ssize_t r = recvfrom(qc->udpFd, inbound, sizeof(inbound), MSG_DONTWAIT, nullptr, nullptr);
                if (r <= 0)
                    break;
                Socks5Framing::Endpoint src;
                Vector<uint8_t> payload;
                if (!Socks5Framing::unwrap(std::span<const uint8_t> { inbound, static_cast<size_t>(r) }, src, payload))
                    continue;
                driftstackQuicReadPacket(qc, payload.span().data(), payload.size(),
                    reinterpret_cast<struct sockaddr*>(&qc->peerSa), sizeof(qc->peerSa),
                    reinterpret_cast<struct sockaddr*>(&qc->localSa), sizeof(qc->localSa));
            }
        } else if (nf.conn_handle_expiry)
            nf.conn_handle_expiry(qc->conn, driftstackQuicTimestampNow());
        driftstackHttp3DrainWrites(qc, qc->udpFd, peerEp, qc->relaySa);
        // 4. harvest completed streams from the per-stream map (written by the
        //    callbacks above, on THIS thread) into their pending-request slots.
        bool anyDone = false;
        {
            Locker sl { qc->h3StreamsLock };
            Locker l { m_lock };
            Vector<int64_t> doneKeys;
            for (auto& entry : st->inflight) {
                int64_t key = entry.key; // streamId + 1
                auto it = qc->h3Streams.find(key);
                if (it == qc->h3Streams.end() || !it->value->complete)
                    continue;
                auto& p = entry.value;
                auto* str = it->value.get();
                p->response.failed = false;
                p->response.statusCode = str->status ? str->status : 200;
                p->response.body = std::move(str->body);
                for (auto& kv : str->headers) {
                    p->response.headers.append({
                        String::fromUTF8(std::span<const char8_t> { reinterpret_cast<const char8_t*>(kv.first.span().data()), kv.first.size() }),
                        String::fromUTF8(std::span<const char8_t> { reinterpret_cast<const char8_t*>(kv.second.span().data()), kv.second.size() }) });
                }
                p->done = true;
                doneKeys.append(key);
                anyDone = true;
            }
            for (int64_t k : doneKeys) {
                st->inflight.remove(k);
                qc->h3Streams.remove(k);
            }
        }
        if (anyDone)
            st->cond.notifyAll();
    }
}

DriftstackHttp3Response DriftstackHttp3Session::execute(const DriftstackHttp3Request& request)
{
    DriftstackHttp3Response resp;
    auto* st = static_cast<H3PumpState*>(m_pumpState);
    if (!st) {
        resp.failed = true;
        resp.errorMessage = "h3 session has no pump"_s;
        return resp;
    }
    // Enqueue the request for the pump thread + wait for ITS stream to complete.
    // execute() NEVER touches the QUIC conn (only the pump does) — so concurrent
    // callers multiplex over the one connection.
    auto p = std::make_shared<H3PendingReq>();
    p->request = request;
    {
        Locker l { m_lock };
        if (!m_alive) {
            resp.failed = true;
            resp.errorMessage = "h3 session not alive"_s;
            return resp;
        }
        st->queue.append(p);
        st->cond.notifyAll(); // wake the pump to submit promptly
        MonotonicTime deadline = MonotonicTime::now() + Seconds(30);
        while (!p->done) {
            if (!st->cond.waitUntil(m_lock, deadline))
                break; // timeout
        }
    }
    if (!p->done) {
        p->response.failed = true;
        if (p->response.errorMessage.isEmpty())
            p->response.errorMessage = "h3 pooled request timeout"_s;
        WTFLogAlways("[Wave29-499.322/H3POOL] pooled request TIMEOUT (stream=%lld)", (long long)p->streamId);
        return p->response;
    }
    WTFLogAlways("[Wave29-499.322/H3POOL] pooled request COMPLETE status=%d bodyLen=%zu (concurrent, stream=%lld)",
        p->response.statusCode, p->response.body.size(), (long long)p->streamId);
    return p->response;
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
