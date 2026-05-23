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

#if PLATFORM(DRIFTSTACK)

#import <dlfcn.h>
#import <stdlib.h>
#import <string.h>
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
    RESOLVE_BQ(SSL_get_ex_data, "SSL_get_ex_data");
    RESOLVE_BQ(SSL_set_ex_data, "SSL_set_ex_data");
    RESOLVE_BQ(SSL_get_ex_new_index, "SSL_get_ex_new_index");
    RESOLVE_BQ(SSL_CIPHER_get_protocol_id, "SSL_CIPHER_get_protocol_id");
    RESOLVE_BQ(SSL_CIPHER_get_name, "SSL_CIPHER_get_name");
#undef RESOLVE_BQ
    f.ready = f.SSL_set_quic_method && f.SSL_provide_quic_data
        && f.SSL_process_quic_post_handshake
        && f.SSL_get_ex_data && f.SSL_set_ex_data && f.SSL_get_ex_new_index;
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
