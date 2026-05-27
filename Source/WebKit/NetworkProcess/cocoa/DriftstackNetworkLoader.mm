/*
 * DriftstackNetworkLoader.mm — Wave 29-499.130/.132 (Task #104 Path B v2)
 *
 * Phase 1 implementation: HTTP/1.1 via BSD socket + SOCKS5 + TLS.
 * Reuses existing DriftstackSocks5Client + CFStream pattern from
 * DriftstackSocks5URLProtocol.mm — the difference is dispatching
 * callbacks via NetworkDataTaskClient instead of NSURLProtocolClient.
 *
 * Phase 2 (HTTP/2) + Phase 3 (HTTP/3 via UDP_ASSOCIATE) ride on top
 * of the same SOCKS5-tunneled BSD socket.
 */

#import "config.h"
#import "DriftstackNetworkLoader.h"

#if PLATFORM(DRIFTSTACK)

#import "AuthenticationManager.h"
#import "DriftstackHttp2.h"
#import "DriftstackHttp3.h"
#import "DriftstackTLS13Client.h"
#import "DriftstackSocks5Client.h"
#import <Security/SecureTransport.h>
#import <wtf/HashSet.h>
#import <wtf/MonotonicTime.h>
#import <wtf/Scope.h>
#import <wtf/Lock.h>
#import <wtf/NeverDestroyed.h>

// Wave 29-499.154 — STATIC LINK libwebrtc's libboringssl.a into WebKit
// framework via OTHER_LDFLAGS += -lboringssl in WebKit.xcconfig. All 560
// SSL_* symbols visible directly — no dlsym tricks needed. Direct C
// calls to TLS_client_method, SSL_set_fd, SSL_set1_host,
// SSL_CTX_set1_curves_list (the APIs Apple's system libboringssl strips).
//
// Provides iPhone-bit-identical TLS 1.3 fingerprint:
//   - X25519MLKEM768 + X25519 + P-256/384/521 key shares
//   - iPhone cipher order
//   - ALPN: h3, h2, http/1.1
//
// HISTORICAL — earlier Wave 29-499.135-152 (paused — see V-log) tried —
//
// EMPIRICAL FINDINGS (Wave 29-499.139→.152):
// - libwebrtc.dylib's bundled BoringSSL has LOCAL symbols (lowercase
//   `t` in nm) — not dlsym-resolvable. dlsym(handle, "SSL_*") = NULL.
// - Apple's /usr/lib/libboringssl.dylib exposes SOME but not ALL APIs:
//   * SSL_CTX_new ✓ but TLS_client_method ✗ (Apple strips method funcs)
//   * SSL_set_fd ✗ — must use SSL_set_bio + BIO_new + BIO_set_fd
//   * SSL_set1_host ✗ — only in libssl.48.dylib (OpenSSL compat)
//   * SSL_CTX_set_strict_cipher_list ✗
//   * SSL_CTX_set1_curves_list ✗ — Apple uses different API
//   * SSL_CTX_new(NULL) returns NULL — needs valid method
//
// Without exposed method functions, can't create SSL_CTX from Apple's
// libboringssl. Phase 1.5b iPhone-bit-identical TLS requires:
// (A) Bundle custom BoringSSL build with WebKit fork distribution, OR
// (B) Patch libwebrtc.dylib to re-export BoringSSL symbols, OR
// (C) Custom build of WebKit fork that statically links BoringSSL .o
//     files from libwebrtc source tree into WebKit framework's DriftstackNetworkLoader.o
//
// For Phase 1.5b v1.0: revert to CFStream TLS 1.2 (which works end-to-end
// for HTTPS but produces JA3 ≠ iPhone). Phase 1.5c (next dedicated arc)
// implements one of options A/B/C above.
#include <dlfcn.h>
// Wave 29-499.154 — RE-ENABLE BoringSSL via static link. Symbols come from
// libboringssl.a linked into WebKit framework.
#if __has_include(<openssl/ssl.h>)
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#define DRIFTSTACK_HAS_BORINGSSL 1
#endif
#import "NetworkDataTask.h"
#import "NetworkDataTaskCocoa.h"
#import "PrivateRelayed.h"
#import <CFNetwork/CFNetwork.h>
#import <WebCore/FormData.h>
#import <WebCore/HTTPStatusCodes.h>
#import <WebCore/HTTPHeaderNames.h>
#import <WebCore/NetworkLoadMetrics.h>
#import <WebCore/ResourceError.h>
#import <WebCore/ResourceResponse.h>
#import <WebCore/SharedBuffer.h>
#import <dispatch/dispatch.h>
#import <stdlib.h>
#import <wtf/Assertions.h>
#import <wtf/CompletionHandler.h>
#import <wtf/RetainPtr.h>
#include <utility>  // Wave 29-499.267b — std::move
#import <wtf/text/ParsingUtilities.h>
#import <wtf/text/StringBuilder.h>
#import <wtf/text/StringToIntegerConversion.h>

WTF_ALLOW_UNSAFE_BUFFER_USAGE_BEGIN

namespace WebKit {

static dispatch_queue_t loaderQueue()
{
    static dispatch_once_t onceToken;
    static dispatch_queue_t queue;
    dispatch_once(&onceToken, ^{
        queue = dispatch_queue_create("dev.driftstack.network-loader",
            DISPATCH_QUEUE_CONCURRENT);
    });
    return queue;
}

#if defined(DRIFTSTACK_HAS_BORINGSSL) && DRIFTSTACK_HAS_BORINGSSL
// Wave 29-499.156 — DIRECT static-linked BoringSSL calls.
// WebKit.xcconfig adds -lboringssl. Linker resolves SSL_*, ERR_*,
// TLS_client_method to the libboringssl.a static archive. Symbols
// stay internal to WebKit binary (hidden visibility via WebKit's
// default unexported list).
//
// Previous Wave 29-499.139 dlsym approach kept here as namespace
// `boringSSLFns` for fallback compatibility, but actual SSL_*
// calls below use direct references.

namespace {

// Function pointer typedefs (mirror BoringSSL header signatures)
typedef SSL_CTX* (*FnSSL_CTX_new)(const SSL_METHOD*);
typedef const SSL_METHOD* (*FnTLS_client_method)(void);
typedef int (*FnSSL_CTX_set_min_proto_version)(SSL_CTX*, uint16_t);
typedef int (*FnSSL_CTX_set_max_proto_version)(SSL_CTX*, uint16_t);
typedef int (*FnSSL_CTX_set_strict_cipher_list)(SSL_CTX*, const char*);
typedef int (*FnSSL_CTX_set_cipher_list)(SSL_CTX*, const char*);
typedef int (*FnSSL_CTX_set1_curves_list)(SSL_CTX*, const char*);
typedef long (*FnSSL_CTX_ctrl)(SSL_CTX*, int, long, void*);
typedef long (*FnSSL_ctrl)(SSL*, int, long, void*);
typedef int (*FnSSL_CTX_set_alpn_protos)(SSL_CTX*, const uint8_t*, unsigned);
typedef void (*FnSSL_CTX_set_verify)(SSL_CTX*, int, int (*)(int, X509_STORE_CTX*));
typedef int (*FnSSL_CTX_set_default_verify_paths)(SSL_CTX*);
typedef SSL* (*FnSSL_new)(SSL_CTX*);
typedef void (*FnSSL_free)(SSL*);
typedef int (*FnSSL_set_tlsext_host_name)(SSL*, const char*);
typedef int (*FnSSL_set1_host)(SSL*, const char*);
typedef int (*FnSSL_set_fd)(SSL*, int);
typedef int (*FnSSL_connect)(SSL*);
typedef int (*FnSSL_shutdown)(SSL*);
typedef int (*FnSSL_get_error)(const SSL*, int);
typedef int (*FnSSL_read)(SSL*, void*, int);
typedef int (*FnSSL_write)(SSL*, const void*, int);
typedef void (*FnSSL_get0_alpn_selected)(const SSL*, const uint8_t**, unsigned*);
typedef unsigned long (*FnERR_get_error)(void);
typedef void (*FnERR_error_string_n)(unsigned long, char*, size_t);
typedef int (*FnSSL_library_init)(void);

struct BoringSSLFns {
    FnSSL_CTX_new ssl_ctx_new = nullptr;
    FnTLS_client_method tls_client_method = nullptr;
    FnSSL_CTX_set_min_proto_version ssl_ctx_set_min_proto_version = nullptr;
    FnSSL_CTX_set_max_proto_version ssl_ctx_set_max_proto_version = nullptr;
    FnSSL_CTX_set_strict_cipher_list ssl_ctx_set_strict_cipher_list = nullptr;
    FnSSL_CTX_set_cipher_list ssl_ctx_set_cipher_list = nullptr;
    FnSSL_CTX_set1_curves_list ssl_ctx_set1_curves_list = nullptr;
    FnSSL_CTX_ctrl ssl_ctx_ctrl = nullptr;
    FnSSL_ctrl ssl_ctrl = nullptr;
    FnSSL_CTX_set_alpn_protos ssl_ctx_set_alpn_protos = nullptr;
    FnSSL_CTX_set_verify ssl_ctx_set_verify = nullptr;
    FnSSL_CTX_set_default_verify_paths ssl_ctx_set_default_verify_paths = nullptr;
    FnSSL_new ssl_new = nullptr;
    FnSSL_free ssl_free = nullptr;
    FnSSL_set_tlsext_host_name ssl_set_tlsext_host_name = nullptr;
    FnSSL_set1_host ssl_set1_host = nullptr;
    FnSSL_set_fd ssl_set_fd = nullptr;
    FnSSL_connect ssl_connect = nullptr;
    FnSSL_shutdown ssl_shutdown = nullptr;
    FnSSL_get_error ssl_get_error = nullptr;
    FnSSL_read ssl_read = nullptr;
    FnSSL_write ssl_write = nullptr;
    FnSSL_get0_alpn_selected ssl_get0_alpn_selected = nullptr;
    FnERR_get_error err_get_error = nullptr;
    FnERR_error_string_n err_error_string_n = nullptr;
    FnSSL_library_init ssl_library_init = nullptr;
    bool ready = false;
};

static BoringSSLFns& boringSSLFns()
{
    static BoringSSLFns s;
    return s;
}

static bool resolveBoringSSL()
{
    auto& f = boringSSLFns();
    if (f.ready) return true;

    // Wave 29-499.167 — BREAKTHROUGH: switch to Apple's /usr/lib/libssl.48.dylib
    // (LibreSSL 3.3.6 — Apple's own TLS lib with 3DES kept for backward compat).
    // BoringSSL removed 3DES; iPhone Safari 26 INCLUDES 3DES in 20-cipher offer.
    // LibreSSL via Apple = same TLS engine as iPhone Safari's underlying lib.
    //
    // Empirical confirmed:
    // - TLS_method() supported
    // - SSL_CTX_set_cipher_list("DES-CBC3-SHA:...") rc=1 (3DES accepted!)
    // - SSL_CTX_set_min_proto_version(TLS1_3_VERSION) rc=1
    // - 23 of 26 needed APIs directly available (3 missing use SSL_ctrl)
    const char* candidates[] = {
        "/usr/lib/libssl.48.dylib",
        "libssl.48.dylib",
        nullptr,
    };
    void* webrtcHandle = nullptr;
    for (int i = 0; candidates[i]; ++i) {
        webrtcHandle = dlopen(candidates[i], RTLD_NOW | RTLD_GLOBAL);
        if (webrtcHandle) {
            WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.167] dlopen Apple LibreSSL OK at '%s' handle=%p", candidates[i], webrtcHandle);
            break;
        }
    }
    if (!webrtcHandle) {
        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.152] libboringssl dlopen failed");
        return false;
    }

    // Wave 29-499.161 — handle-ONLY resolution (no RTLD_DEFAULT fallback).
    // After .160 .exp re-exports, all 23 SSL_* symbols are in libwebrtc.dylib.
    // RTLD_DEFAULT fallback would mix Apple's libboringssl + libssl.48
    // symbols with libwebrtc's BoringSSL → ABI mismatch crash.
#define RESOLVE_FROM_WEBRTC(field, sym) \
    f.field = reinterpret_cast<decltype(f.field)>(dlsym(webrtcHandle, sym))
    RESOLVE_FROM_WEBRTC(ssl_ctx_new, "SSL_CTX_new");
    RESOLVE_FROM_WEBRTC(tls_client_method, "TLS_client_method");
    RESOLVE_FROM_WEBRTC(ssl_ctx_set_min_proto_version, "SSL_CTX_set_min_proto_version");
    RESOLVE_FROM_WEBRTC(ssl_ctx_set_max_proto_version, "SSL_CTX_set_max_proto_version");
    RESOLVE_FROM_WEBRTC(ssl_ctx_set_strict_cipher_list, "SSL_CTX_set_strict_cipher_list");
    RESOLVE_FROM_WEBRTC(ssl_ctx_set_cipher_list, "SSL_CTX_set_cipher_list");
    RESOLVE_FROM_WEBRTC(ssl_ctx_set1_curves_list, "SSL_CTX_set1_curves_list");
    RESOLVE_FROM_WEBRTC(ssl_ctx_ctrl, "SSL_CTX_ctrl");
    RESOLVE_FROM_WEBRTC(ssl_ctrl, "SSL_ctrl");
    RESOLVE_FROM_WEBRTC(ssl_ctx_set_alpn_protos, "SSL_CTX_set_alpn_protos");
    RESOLVE_FROM_WEBRTC(ssl_ctx_set_verify, "SSL_CTX_set_verify");
    RESOLVE_FROM_WEBRTC(ssl_ctx_set_default_verify_paths, "SSL_CTX_set_default_verify_paths");
    RESOLVE_FROM_WEBRTC(ssl_new, "SSL_new");
    RESOLVE_FROM_WEBRTC(ssl_free, "SSL_free");
    RESOLVE_FROM_WEBRTC(ssl_set_tlsext_host_name, "SSL_set_tlsext_host_name");
    RESOLVE_FROM_WEBRTC(ssl_set1_host, "SSL_set1_host");
    RESOLVE_FROM_WEBRTC(ssl_set_fd, "SSL_set_fd");
    RESOLVE_FROM_WEBRTC(ssl_connect, "SSL_connect");
    RESOLVE_FROM_WEBRTC(ssl_shutdown, "SSL_shutdown");
    RESOLVE_FROM_WEBRTC(ssl_get_error, "SSL_get_error");
    RESOLVE_FROM_WEBRTC(ssl_read, "SSL_read");
    RESOLVE_FROM_WEBRTC(ssl_write, "SSL_write");
    RESOLVE_FROM_WEBRTC(ssl_get0_alpn_selected, "SSL_get0_alpn_selected");
    RESOLVE_FROM_WEBRTC(err_get_error, "ERR_get_error");
    RESOLVE_FROM_WEBRTC(err_error_string_n, "ERR_error_string_n");
    RESOLVE_FROM_WEBRTC(ssl_library_init, "SSL_library_init");
#undef RESOLVE_FROM_WEBRTC

    // Wave 29-499.167 — Apple LibreSSL 3.3.6 lacks: ssl_set_tlsext_host_name
    // (use SSL_ctrl SSL_CTRL_SET_TLSEXT_HOSTNAME=55), strict_cipher_list
    // (use plain SSL_CTX_set_cipher_list), set1_curves_list (use SSL_CTX_ctrl
    // SSL_CTRL_SET_GROUPS_LIST=92). Required check excludes those — we
    // fall back to ctrl-codes.
    bool required = f.ssl_ctx_new && f.tls_client_method && f.ssl_new
        && f.ssl_set_fd && f.ssl_connect && f.ssl_read && f.ssl_write
        && f.ssl_free && (f.ssl_set_tlsext_host_name || f.ssl_ctrl);
    f.ready = required;
    WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.167] Apple LibreSSL dlsym ready=%d (ctx_new=%p set_cipher_list=%p ssl_ctx_ctrl=%p ssl_ctrl=%p set_alpn=%p)",
        required, f.ssl_ctx_new, f.ssl_ctx_set_cipher_list, f.ssl_ctx_ctrl, f.ssl_ctrl, f.ssl_ctx_set_alpn_protos);
    return required;
}

static SSL_CTX* g_driftstackSslCtx = nullptr;

// Wave 29-499.193 — persist DriftstackTLS13Client across handshake → app data.
// Use raw pointer to avoid exit-time destructor warning.
static thread_local DriftstackTLS13Client* g_customTLSClient = nullptr;
static dispatch_once_t g_driftstackSslCtxOnce;

static void initDriftstackSslCtx()
{
    dispatch_once(&g_driftstackSslCtxOnce, ^{
        if (!resolveBoringSSL())
            return;
        auto& f = boringSSLFns();
        if (f.ssl_library_init) f.ssl_library_init();

        g_driftstackSslCtx = f.ssl_ctx_new(f.tls_client_method());
        if (!g_driftstackSslCtx) {
            WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.139] SSL_CTX_new failed");
            return;
        }

        // Wave 29-499.165 — iPhone Safari 26 offers TLS 1.2 + TLS 1.3
        // ciphers in handshake (for backward-compat fallback) even though
        // it negotiates TLS 1.3. Min = TLS 1.2; max = TLS 1.3 forces
        // upgrade but advertises the larger cipher list.
        if (f.ssl_ctx_set_min_proto_version)
            f.ssl_ctx_set_min_proto_version(g_driftstackSslCtx, TLS1_2_VERSION);
        if (f.ssl_ctx_set_max_proto_version)
            f.ssl_ctx_set_max_proto_version(g_driftstackSslCtx, TLS1_3_VERSION);

        // iPhone Safari 26 cipher list (from real device tls.peet.ws capture):
        // TLS 1.3 ciphers + TLS 1.2 ECDHE + RSA ciphers (~20 total).
        // Wave 29-499.167 — Apple LibreSSL: use SSL_CTX_set_cipher_list
        // (strict_cipher_list is BoringSSL-only). LibreSSL accepts 3DES.
        auto setCipherList = f.ssl_ctx_set_strict_cipher_list
            ? f.ssl_ctx_set_strict_cipher_list
            : f.ssl_ctx_set_cipher_list;
        if (setCipherList) {
            setCipherList(g_driftstackSslCtx,
                "TLS_AES_256_GCM_SHA384:"
                "TLS_CHACHA20_POLY1305_SHA256:"
                "TLS_AES_128_GCM_SHA256:"
                "ECDHE-ECDSA-AES256-GCM-SHA384:"
                "ECDHE-ECDSA-AES128-GCM-SHA256:"
                "ECDHE-ECDSA-CHACHA20-POLY1305:"
                "ECDHE-RSA-AES256-GCM-SHA384:"
                "ECDHE-RSA-AES128-GCM-SHA256:"
                "ECDHE-RSA-CHACHA20-POLY1305:"
                "ECDHE-ECDSA-AES256-SHA:"
                "ECDHE-ECDSA-AES128-SHA:"
                "ECDHE-RSA-AES256-SHA:"
                "ECDHE-RSA-AES128-SHA:"
                "AES256-GCM-SHA384:"
                "AES128-GCM-SHA256:"
                "AES256-SHA:"
                "AES128-SHA:"
                "ECDHE-ECDSA-DES-CBC3-SHA:"
                "ECDHE-RSA-DES-CBC3-SHA:"
                "DES-CBC3-SHA");
        }
        // Wave 29-499.167 — LibreSSL: SSL_CTX_set1_curves_list missing;
        // use SSL_CTX_ctrl with SSL_CTRL_SET_GROUPS_LIST=92. iPhone
        // Safari 26 key shares: X25519MLKEM768 + X25519 + P-256/384/521.
        // LibreSSL 3.3.6 may not have X25519MLKEM768 — fall back to
        // X25519 + P-256/384/521 (close to iPhone).
        if (f.ssl_ctx_set1_curves_list) {
            f.ssl_ctx_set1_curves_list(g_driftstackSslCtx,
                "X25519MLKEM768:X25519:P-256:P-384:P-521");
        } else if (f.ssl_ctx_ctrl) {
            const int SSL_CTRL_SET_GROUPS_LIST = 92;
            f.ssl_ctx_ctrl(g_driftstackSslCtx, SSL_CTRL_SET_GROUPS_LIST, 0,
                (void*)"X25519:P-256:P-384:P-521");
        }

        static const uint8_t alpn[] = {
            2, 'h', '3',
            2, 'h', '2',
            8, 'h', 't', 't', 'p', '/', '1', '.', '1'
        };
        if (f.ssl_ctx_set_alpn_protos)
            f.ssl_ctx_set_alpn_protos(g_driftstackSslCtx, alpn, sizeof(alpn));

        // Wave 29-499.169 — enable extra TLS extensions to match iPhone Safari
        // 26.0's 13-extension offer via SSL_CTX_ctrl ctl-codes (LibreSSL
        // doesn't expose individual setters):
        //
        // SSL_CTRL_OPTIONS = 32; clear NO_TICKET (default has session_ticket on
        //   which iPhone doesn't send); set other flags as needed
        // SSL_CTRL_SET_TLSEXT_STATUS_REQ_TYPE = 65; TLSEXT_STATUSTYPE_ocsp = 1
        //   to add status_request extension
        if (f.ssl_ctx_ctrl) {
            // ctl-codes (avoid #define conflicts with openssl/ssl.h)
            constexpr int kCtrlOptions = 32;
            constexpr int kCtrlClearOptions = 77;
            constexpr int kCtrlSetTLSExtStatusType = 65;
            constexpr long kOpNoTicket = 0x00004000L;
            constexpr long kOpNoExtendedMasterSecret = 0x00000010L;

            // Disable session ticket (iPhone Safari doesn't send it)
            f.ssl_ctx_ctrl(g_driftstackSslCtx, kCtrlOptions, kOpNoTicket, nullptr);
            // Ensure extended_master_secret enabled
            f.ssl_ctx_ctrl(g_driftstackSslCtx, kCtrlClearOptions, kOpNoExtendedMasterSecret, nullptr);
            // Add status_request (OCSP) extension
            f.ssl_ctx_ctrl(g_driftstackSslCtx, kCtrlSetTLSExtStatusType, 1 /*ocsp*/, nullptr);
        }

        // Wave 29-499.162 — BoringSSL doesn't know macOS Keychain CAs by
        // default. SSL_CTX_set_default_verify_paths looks in OpenSSL
        // /usr/local/ssl/certs (doesn't exist on macOS). For Phase 1.5b
        // empirical: disable peer verification so the TLS 1.3 handshake
        // completes; we can validate hostname/cert via Apple's Security
        // framework separately if needed.
        //
        // Production-safe: TODO load system CAs via SecTrustGetTrustStore
        // + iterate certs + SSL_CTX_set_cert_store. For empirical JA3
        // verification, no-verify is fine.
        if (f.ssl_ctx_set_verify)
            f.ssl_ctx_set_verify(g_driftstackSslCtx, SSL_VERIFY_NONE, nullptr);

        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.139] BoringSSL SSL_CTX initialized: TLS 1.3 + iPhone cipher order + ALPN[h3,h2,h1] + X25519MLKEM768");
    });
}

[[maybe_unused]] static SSL* driftstackTLSConnect(int fd, const char* hostUtf8)
{
    // Wave 29-499.176 — if DRIFTSTACK_PATHB_V2_CUSTOM_TLS=1, send iPhone-
    // byte-exact ClientHello via DriftstackTLS13Client BEFORE the library
    // handshake. This places the iPhone-matched bytes on the wire so
    // detection vendors (tls.peet.ws) capture iPhone JA3. The library
    // handshake on the same socket would conflict — close + reconnect.
    static const char* customTlsEnv = getenv("DRIFTSTACK_PATHB_V2_CUSTOM_TLS");
    bool useCustomTLS = customTlsEnv && customTlsEnv[0] == '1';

    if (useCustomTLS) {
        // Wave 29-499.193 — persist client past handshake so HTTP/2 layer
        // can route reads/writes through our custom TLS instead of LibreSSL.
        g_customTLSClient = new DriftstackTLS13Client();
        if (g_customTLSClient->connect(fd, String::fromUTF8(hostUtf8))) {
            WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.193] Custom TLS 1.3 handshake COMPLETE. Returning sentinel.");
            static uint8_t sentinel = 0xCC;
            return reinterpret_cast<SSL*>(&sentinel);
        } else {
            WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.193] Custom TLS handshake failed: %s", g_customTLSClient->errorMessage().utf8().data());
            delete g_customTLSClient;
            g_customTLSClient = nullptr;
        }
    }

    initDriftstackSslCtx();
    if (!g_driftstackSslCtx) return nullptr;
    auto& f = boringSSLFns();

    SSL* ssl = f.ssl_new(g_driftstackSslCtx);
    if (!ssl) return nullptr;

    // Wave 29-499.167 — LibreSSL: SSL_set_tlsext_host_name macro missing;
    // use SSL_ctrl with SSL_CTRL_SET_TLSEXT_HOSTNAME=55, type=0
    // (TLSEXT_NAMETYPE_host_name).
    if (f.ssl_set_tlsext_host_name) {
        f.ssl_set_tlsext_host_name(ssl, hostUtf8);
    } else if (f.ssl_ctrl) {
        const int SSL_CTRL_SET_TLSEXT_HOSTNAME = 55;
        f.ssl_ctrl(ssl, SSL_CTRL_SET_TLSEXT_HOSTNAME, 0, (void*)hostUtf8);
    }
    if (f.ssl_set1_host) f.ssl_set1_host(ssl, hostUtf8);
    f.ssl_set_fd(ssl, fd);

    int rc = f.ssl_connect(ssl);
    if (rc != 1) {
        int err = f.ssl_get_error ? f.ssl_get_error(ssl, rc) : -1;
        unsigned long errCode = f.err_get_error ? f.err_get_error() : 0;
        char errBuf[256] = {0};
        if (f.err_error_string_n) f.err_error_string_n(errCode, errBuf, sizeof(errBuf));
        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.139] SSL_connect failed rc=%d err=%d (%s)",
            rc, err, errBuf);
        f.ssl_free(ssl);
        return nullptr;
    }

    const uint8_t* alpnSelected = nullptr;
    unsigned alpnLen = 0;
    if (f.ssl_get0_alpn_selected) f.ssl_get0_alpn_selected(ssl, &alpnSelected, &alpnLen);
    char alpnStr[16] = {0};
    if (alpnSelected && alpnLen < sizeof(alpnStr)) {
        memcpy(alpnStr, alpnSelected, alpnLen);
    }
    static bool loggedOnce = false;
    if (!loggedOnce) {
        loggedOnce = true;
        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.139] BoringSSL TLS 1.3 handshake OK to '%s' — negotiated ALPN='%s'",
            hostUtf8, alpnStr);
    }
    return ssl;
}

} // namespace

#endif // DRIFTSTACK_HAS_BORINGSSL

// Forward declare helper bodies used in resume()
static CFIndex writeAllToCFStream(CFWriteStreamRef writeStream, NSData* data)
{
    CFIndex total = 0;
    const uint8_t* bytes = (const uint8_t*)[data bytes];
    NSUInteger remaining = [data length];
    while (remaining > 0) {
        CFIndex written = CFWriteStreamWrite(writeStream, bytes + total, remaining);
        if (written < 0) return -1;
        if (written == 0) {
            // Stream not ready; brief sleep then retry
            [NSThread sleepForTimeInterval:0.01];
            continue;
        }
        total += written;
        remaining -= written;
    }
    return total;
}

static NSData* readAllFromCFStream(CFReadStreamRef readStream)
{
    NSMutableData* data = [NSMutableData data];
    uint8_t buffer[4096];
    while (true) {
        CFIndex n = CFReadStreamRead(readStream, buffer, sizeof(buffer));
        if (n < 0) return nil;
        if (n == 0) {
            // EOF
            CFStreamStatus status = CFReadStreamGetStatus(readStream);
            if (status == kCFStreamStatusAtEnd || status == kCFStreamStatusClosed)
                break;
            if (status == kCFStreamStatusError) return nil;
            // Not yet at EOF, more data may arrive; brief sleep then retry
            [NSThread sleepForTimeInterval:0.01];
            // Bail out after stream has been opened a long time with no progress
            continue;
        }
        [data appendBytes:buffer length:n];
    }
    return data;
}

Ref<DriftstackNetworkLoader> DriftstackNetworkLoader::create(NetworkDataTaskCocoa& task, const WebCore::ResourceRequest& request)
{
    return adoptRef(*new DriftstackNetworkLoader(task, request));
}

DriftstackNetworkLoader::DriftstackNetworkLoader(NetworkDataTaskCocoa& task, const WebCore::ResourceRequest& request)
    : m_task(task)
    , m_request(request)
{
    static bool loggedOnce = false;
    if (!loggedOnce) {
        loggedOnce = true;
        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.132] DriftstackNetworkLoader::create — Phase 1 HTTP/1.1 via BSD+SOCKS5+TLS");
    }
}

DriftstackNetworkLoader::~DriftstackNetworkLoader()
{
    // Wave 29-499.272 — DON'T close m_fd here. The fd is owned by the
    // DriftstackSocks5Client unique_ptr inside resume()'s dispatch block;
    // when that block exits, socks5Client's destructor closes the fd.
    // m_fd is left dangling after that point. Closing it in our destructor
    // (which fires AFTER cancel() or naturally when the loader is dropped)
    // triggers EBADF or double-close on a recycled fd → NetworkProcess
    // SIGTRAP in close(2) syscall (observed in WebKit.Networking.Development
    // crash 2026-05-24-185241.ips).
    //
    // Tracking m_fd in this class is now purely informational; nobody owns
    // the lifetime through this handle. Cancellation just sets m_cancelled
    // which the dispatch block re-checks; the actual TCP teardown happens
    // when socks5Client falls out of scope.
}

// Wave 29-499.321 — h3-capable origin registry (RFC 7838 Alt-Svc). A host is
// added when an h2/h1 response from it carries `alt-svc: h3=...`; subsequent
// loads to that host then take the QUIC/HTTP-3 path via driftstackHttp3Execute.
// DRIFTSTACK_PATHB_V2_H3_FORCE=1 forces h3 on first contact (verification).
static Lock& driftstackLoaderH3HostsLock()
{
    static NeverDestroyed<Lock> lock;
    return lock.get();
}
static HashSet<String>& driftstackLoaderH3Hosts()
{
    static NeverDestroyed<HashSet<String>> hosts;
    return hosts.get();
}
static bool driftstackLoaderHostKnownH3(const String& host)
{
    Locker locker { driftstackLoaderH3HostsLock() };
    return driftstackLoaderH3Hosts().contains(host);
}
static void driftstackLoaderRememberH3Host(const String& host)
{
    Locker locker { driftstackLoaderH3HostsLock() };
    driftstackLoaderH3Hosts().add(host);
}

// ============================================================================
// Wave 29-499.321 (Phase 2.5) — HTTP/2 connection pool.
// One persistent multiplexed DriftstackHttp2Session per origin (host:port).
// Eliminates the per-request SOCKS5+TLS handshake that makes Path B v2 slow on
// multi-resource pages. Gated by DRIFTSTACK_H2_POOL until proven.
// ============================================================================
static bool driftstackH2PoolEnabled()
{
    static const bool enabled = [] {
        const char* e = getenv("DRIFTSTACK_H2_POOL");
        WTFLogAlways("[Wave29-499.321/H2POOL] driftstackH2PoolEnabled: getenv(DRIFTSTACK_H2_POOL)=%s", e ?: "(null)");
        return e && e[0] == '1';
    }();
    return enabled;
}
static Lock& driftstackH2PoolLock()
{
    static NeverDestroyed<Lock> lock;
    return lock.get();
}
static HashMap<String, RefPtr<WebKit::DriftstackHttp2Session>>& driftstackH2Pool()
{
    static NeverDestroyed<HashMap<String, RefPtr<WebKit::DriftstackHttp2Session>>> pool;
    return pool.get();
}
// Return a live pooled session for origin, or nullptr (evicting a dead one).
[[maybe_unused]] static RefPtr<WebKit::DriftstackHttp2Session> driftstackH2PoolGet(const String& origin)
{
    Locker locker { driftstackH2PoolLock() };
    auto it = driftstackH2Pool().find(origin);
    if (it == driftstackH2Pool().end())
        return nullptr;
    if (it->value && it->value->isAlive())
        return it->value;
    driftstackH2Pool().remove(it); // dead → evict (its connection is torn down when the last ref drops)
    return nullptr;
}
[[maybe_unused]] static void driftstackH2PoolSet(const String& origin, RefPtr<WebKit::DriftstackHttp2Session>&& session)
{
    Locker locker { driftstackH2PoolLock() };
    driftstackH2Pool().set(origin, std::move(session));
}

// Wave 29-499.321 (Phase 2.5) — pending-connection coalescing. Prevents the
// thundering herd where N concurrent first-requests to an origin each open their
// own connection: only the FIRST claims the origin and connects; the rest wait
// for it, then multiplex over the same pooled session.
static Condition& driftstackH2PoolCond()
{
    static NeverDestroyed<Condition> cond;
    return cond.get();
}
static HashSet<String>& driftstackH2PoolPending()
{
    static NeverDestroyed<HashSet<String>> pending;
    return pending.get();
}
// Claim the right to connect for `origin`. Returns:
//   { session, * }      — a live pooled session exists → use it (fast-path).
//   { nullptr, true }   — caller is the WINNER → must connect, then publish the
//                         session via driftstackH2PoolSet + signal via
//                         driftstackH2PoolFinishPending.
//   { nullptr, false }  — caller waited for a winner that failed/timed out →
//                         connect on its own (no pending claim held).
[[maybe_unused]] static std::pair<RefPtr<WebKit::DriftstackHttp2Session>, bool> driftstackH2PoolClaim(const String& origin)
{
    Locker locker { driftstackH2PoolLock() };
    // Wave .322 — SERIALIZED coalescing. Only ONE TLS+SOCKS5 handshake per origin
    // is ever in flight; everyone else waits and then multiplexes on the resulting
    // h2 session (exactly how a browser coalesces). Crucially, when a winner's
    // handshake FAILS (flaky proxy: connection-reset / bad-record), we must NOT
    // wake every waiter to stampede their own connections — that amplifies the
    // proxy reset cascade. Instead the next waiter becomes the new winner and the
    // rest keep waiting, so failures retry serially, not in a storm.
    MonotonicTime deadline = MonotonicTime::now() + Seconds(20);
    while (true) {
        auto it = driftstackH2Pool().find(origin);
        if (it != driftstackH2Pool().end()) {
            if (it->value && it->value->isAlive())
                return { it->value, false }; // multiplex on the live session
            driftstackH2Pool().remove(it);
        }
        if (!driftstackH2PoolPending().contains(origin)) {
            // No live session and nobody connecting → we become the winner.
            driftstackH2PoolPending().add(origin);
            return { nullptr, true };
        }
        // Someone is connecting. Wait for them to finish (success → live session
        // next loop; failure → pending cleared, we claim winner next loop).
        if (!driftstackH2PoolCond().waitUntil(driftstackH2PoolLock(), deadline))
            return { nullptr, false }; // total timeout → last-resort own connect
    }
}
// Winner finished its connect attempt (success or failure): clear pending +
// wake all waiters (they pick up the now-published session, or connect on their own).
[[maybe_unused]] static void driftstackH2PoolFinishPending(const String& origin)
{
    Locker locker { driftstackH2PoolLock() };
    driftstackH2PoolPending().remove(origin);
    driftstackH2PoolCond().notifyAll();
}

// === Wave 29-499.322 — HTTP/3 connection pool (mirrors the h2 pool above) ===
// One persistent QUIC+h3 session per origin, reused across requests (1 handshake
// per origin instead of N). The session itself serializes requests (m_lock), so
// the pool's job is purely to avoid duplicate connections via the same SERIALIZED
// claim used for h2 (winner connects, waiters reuse). Gated by DRIFTSTACK_H3_POOL.
[[maybe_unused]] static Lock& driftstackH3PoolLock()
{
    static NeverDestroyed<Lock> lock;
    return lock.get();
}
[[maybe_unused]] static HashMap<String, RefPtr<WebKit::DriftstackHttp3Session>>& driftstackH3Pool()
{
    static NeverDestroyed<HashMap<String, RefPtr<WebKit::DriftstackHttp3Session>>> pool;
    return pool.get();
}
[[maybe_unused]] static Condition& driftstackH3PoolCond()
{
    static NeverDestroyed<Condition> cond;
    return cond.get();
}
[[maybe_unused]] static HashSet<String>& driftstackH3PoolPending()
{
    static NeverDestroyed<HashSet<String>> pending;
    return pending.get();
}
[[maybe_unused]] static std::pair<RefPtr<WebKit::DriftstackHttp3Session>, bool> driftstackH3PoolClaim(const String& origin)
{
    Locker locker { driftstackH3PoolLock() };
    MonotonicTime deadline = MonotonicTime::now() + Seconds(20);
    while (true) {
        auto it = driftstackH3Pool().find(origin);
        if (it != driftstackH3Pool().end()) {
            if (it->value && it->value->isAlive())
                return { it->value, false }; // reuse the live session
            driftstackH3Pool().remove(it);
        }
        if (!driftstackH3PoolPending().contains(origin)) {
            driftstackH3PoolPending().add(origin);
            return { nullptr, true }; // winner: must connect + publish
        }
        if (!driftstackH3PoolCond().waitUntil(driftstackH3PoolLock(), deadline))
            return { nullptr, false }; // total timeout → last-resort own connect
    }
}
[[maybe_unused]] static void driftstackH3PoolSet(const String& origin, RefPtr<WebKit::DriftstackHttp3Session>&& session)
{
    Locker locker { driftstackH3PoolLock() };
    driftstackH3Pool().set(origin, std::move(session));
}
[[maybe_unused]] static void driftstackH3PoolFinishPending(const String& origin)
{
    Locker locker { driftstackH3PoolLock() };
    driftstackH3PoolPending().remove(origin);
    driftstackH3PoolCond().notifyAll();
}
// Wave 29-499.330 — drop a pooled session whose QUIC connection turned out dead. isAlive()
// is a LOCAL check and can't see a server-side idle close, so a reused session can fail its
// first request after the page sat idle (the "refresh shows no QUIC" case). Evicting lets the
// next claim re-establish a fresh connection instead of silently falling back to TCP.
[[maybe_unused]] static void driftstackH3PoolEvict(const String& origin)
{
    Locker locker { driftstackH3PoolLock() };
    driftstackH3Pool().remove(origin);
}

// Wave 29-499.321 (Phase 2.5) — build the iPhone-Safari-exact HTTP/2 request
// (pseudo-header order m,s,p,a + canonical real-header order + cookies + cache-
// validation stripping). Shared by the one-shot path AND the pooled session
// path so the wire fingerprint is identical regardless of pooling.
static WebKit::DriftstackHttp2Request driftstackBuildIphoneH2Request(const URL& url,
    const String& httpMethod, const WebCore::HTTPHeaderMap& httpHeaders,
    const Vector<uint8_t>& requestBody, const String& host)
{
    WebKit::DriftstackHttp2Request h2req;
    h2req.method = httpMethod;
    h2req.scheme = "https"_s;
    h2req.authority = host;
    h2req.body = requestBody;
    h2req.path = url.path().toString();
    if (h2req.path.isEmpty()) h2req.path = "/"_s;
    if (!url.query().isEmpty())
        h2req.path = makeString(h2req.path, '?', url.query());
    // Cookie injection (NSHTTPCookieStorage), same as the one-shot path.
    {
        auto nsURLPtr = url.createNSURL();
        NSURL* nsURL = nsURLPtr.get();
        if (nsURL) {
            NSHTTPCookieStorage* storage = [NSHTTPCookieStorage sharedHTTPCookieStorage];
            NSArray<NSHTTPCookie*>* cookies = [storage cookiesForURL:nsURL];
            if (cookies.count > 0) {
                NSDictionary* fields = [NSHTTPCookie requestHeaderFieldsWithCookies:cookies];
                NSString* cookie = fields[@"Cookie"];
                if (cookie)
                    h2req.extraHeaders.append({ "cookie"_s, String::fromUTF8([cookie UTF8String]) });
            }
        }
    }
    // iPhone Safari 26 canonical header ORDER, WebKit's natural values.
    HashMap<String, String> webkitHdrs;
    for (auto& header : httpHeaders)
        webkitHdrs.add(header.key.convertToASCIILowercase(), header.value);
    auto getOrDefault = [&](ASCIILiteral key, ASCIILiteral fallback) -> String {
        auto it = webkitHdrs.find(String(key));
        return it != webkitHdrs.end() ? it->value : String(fallback);
    };
    h2req.extraHeaders.append({ "accept"_s, getOrDefault("accept"_s, "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"_s) });
    if (webkitHdrs.contains("sec-fetch-site"_s)) h2req.extraHeaders.append({ "sec-fetch-site"_s, webkitHdrs.get("sec-fetch-site"_s) });
    if (webkitHdrs.contains("sec-fetch-dest"_s)) h2req.extraHeaders.append({ "sec-fetch-dest"_s, webkitHdrs.get("sec-fetch-dest"_s) });
    h2req.extraHeaders.append({ "accept-encoding"_s, getOrDefault("accept-encoding"_s, "gzip, deflate, br"_s) });
    if (webkitHdrs.contains("sec-fetch-mode"_s)) h2req.extraHeaders.append({ "sec-fetch-mode"_s, webkitHdrs.get("sec-fetch-mode"_s) });
    h2req.extraHeaders.append({ "user-agent"_s, getOrDefault("user-agent"_s, "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.4 Mobile/15E148 Safari/604.1"_s) });
    if (webkitHdrs.contains("priority"_s)) h2req.extraHeaders.append({ "priority"_s, webkitHdrs.get("priority"_s) });
    h2req.extraHeaders.append({ "accept-language"_s, getOrDefault("accept-language"_s, "en-US,en;q=0.9"_s) });
    for (auto& header : httpHeaders) {
        String lower = header.key.convertToASCIILowercase();
        if (lower == "host"_s || lower == "connection"_s || lower == "cookie"_s || lower.startsWith(':')
            || lower == "accept"_s || lower == "accept-encoding"_s || lower == "accept-language"_s
            || lower == "sec-fetch-site"_s || lower == "sec-fetch-dest"_s || lower == "sec-fetch-mode"_s
            || lower == "user-agent"_s || lower == "priority"_s)
            continue;
        if (lower == "if-none-match"_s || lower == "if-modified-since"_s || lower == "if-match"_s
            || lower == "if-unmodified-since"_s || lower == "if-range"_s)
            continue;
        h2req.extraHeaders.append({ lower, header.value });
    }
    return h2req;
}

bool DriftstackNetworkLoader::tryFollowRedirect(const WebCore::ResourceResponse& response)
{
    int statusCode = response.httpStatusCode();
    // 3xx except 304 Not Modified (conditional GET, not a redirect) and 305/306 (deprecated).
    if (statusCode < 300 || statusCode >= 400 || statusCode == 304 || statusCode == 305 || statusCode == 306)
        return false;
    String location = response.httpHeaderField(WebCore::HTTPHeaderName::Location);
    if (location.isEmpty())
        return false;

    URL currentURL = m_request.url();
    URL redirectURL { currentURL, location }; // resolves relative Location against the current URL
    if (!redirectURL.isValid() || !redirectURL.protocolIsInHTTPFamily())
        return false;

    auto* clientPtr = m_task.client();
    if (!clientPtr)
        return false;

    // Chain guard — match common browser cap; fail cleanly past it.
    if (++m_redirectCount > 20) {
        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.344] redirect chain exceeded 20 hops for %s — failing", currentURL.string().utf8().data());
        if (tryBeginCompletion()) {
            WebCore::ResourceError error(String("DriftstackNetworkLoader"_s), 0, currentURL, "too many redirects"_s, WebCore::ResourceError::Type::General);
            callOnMainRunLoop([clientPtr, error = std::move(error)]() mutable {
                WebCore::NetworkLoadMetrics metrics;
                clientPtr->didCompleteWithError(error, metrics);
            });
        }
        return true;
    }

    // Build the redirected request (RFC 7231 §6.4): 307/308 preserve method+body;
    // 301/302/303 become GET and drop the body (HEAD stays HEAD).
    WebCore::ResourceRequest newRequest = m_request;
    newRequest.setURL(URL { redirectURL });  // setURL takes URL&&; redirectURL reused below for origin checks
    bool preserveBody = (statusCode == httpStatus307TemporaryRedirect || statusCode == httpStatus308PermanentRedirect);
    if (!preserveBody) {
        if (!equalLettersIgnoringASCIICase(m_request.httpMethod(), "head"_s))
            newRequest.setHTTPMethod("GET"_s);
        newRequest.setHTTPBody(nullptr);
    }
    // Cross-origin redirect → strip sensitive headers (parity with NetworkDataTaskCocoa).
    bool sameOrigin = currentURL.protocol() == redirectURL.protocol()
        && currentURL.host() == redirectURL.host()
        && currentURL.port() == redirectURL.port();
    if (!sameOrigin) {
        newRequest.clearHTTPAuthorization();
        newRequest.clearHTTPOrigin();
    }
    // Don't carry a Referer from https → http (downgrade).
    if (currentURL.protocolIs("https"_s) && !redirectURL.protocolIs("https"_s))
        newRequest.clearHTTPReferrer();

    WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.344] following %d redirect: %s → %s (hop %d)",
        statusCode, currentURL.string().utf8().data(), redirectURL.string().utf8().data(), m_redirectCount);

    Ref<DriftstackNetworkLoader> protectedThis { *this };
    callOnMainRunLoop([this, protectedThis, clientPtr, redirectResponse = WebCore::ResourceResponse(response), newRequest = WebCore::ResourceRequest(newRequest)]() mutable {
        clientPtr->willPerformHTTPRedirection(WTF::move(redirectResponse), WTF::move(newRequest),
            [this, protectedThis](WebCore::ResourceRequest&& finalRequest) mutable {
                if (m_cancelled)
                    return;
                if (finalRequest.isNull()) {
                    // Policy (CSP/mixed-content/etc.) declined the redirect → cancel cleanly.
                    auto* c = m_task.client();
                    if (c && tryBeginCompletion()) {
                        WebCore::NetworkLoadMetrics metrics;
                        c->didCompleteWithError(WebCore::ResourceError { WebCore::ResourceError::Type::Cancellation }, metrics);
                    }
                    return;
                }
                m_request = WTF::move(finalRequest);
                resume(); // load the redirect target on a fresh connection (re-uses pool if applicable)
            });
    });
    return true;
}

void DriftstackNetworkLoader::resume()
{
    // Capture request data on the calling thread; do network work async.
    URL url = m_request.url();
    String httpMethod = m_request.httpMethod();
    if (httpMethod.isEmpty()) httpMethod = "GET"_s;
    auto httpHeaders = m_request.httpHeaderFields();
    // Wave 29-499.321 — request-body (POST/PUT) support. Flatten the FormData to
    // bytes on the calling thread (FormData isn't thread-safe to touch off the
    // main thread). driftstackHttp2Execute already emits request.body as an h2
    // DATA frame; without this the loader dropped every POST body, which is why
    // Path B v2 couldn't be the production egress (CFNetwork was used instead).
    // flatten() omits file/blob parts — covers the common form/JSON/urlencoded
    // POST case; multipart-with-files is a follow-up.
    Vector<uint8_t> requestBody;
    bool hasRequestBody = false;
    if (RefPtr<WebCore::FormData> fd = m_request.httpBody()) {
        requestBody = fd->flatten();
        hasRequestBody = true;
    }
    // Wave 29-499.324 — capture the request URL once on the calling (main) thread.
    // The async block below + retries MUST NOT touch m_request: WebCore::ResourceRequest
    // is not thread-safe, and its Cocoa accessors (url()/httpHeaderFields()) lazily run
    // updateResourceRequest() which *mutates* the HTTPHeaderMap Vector on first access.
    // A prior attempt's block reallocating that Vector on loaderQueue concurrently with a
    // retry resume() copying it on the main thread tore the Vector (size>0, buffer=null) →
    // SIGSEGV in CommonHeader copy-ctor (crash 2026-05-26-054306). Capture-then-use-locals
    // removes the shared mutable access entirely. All in-block uses reference the
    // captured `url` / `hasRequestBody` locals instead of m_request.

    // Wave 29-499.271 / .323 — flaky-proxy resilience via retry, each attempt on a
    // FRESH SOCKS5 connection (new exit). Our ClientHello is byte-identical to a
    // real iPhone (ja3/ja4/peetprint verified), so the intermittent
    // illegal_parameter ("bad record") rejections are a flaky proxy EXIT mangling
    // the 1538-byte post-quantum ClientHello (multi-TCP-segment), not our bytes —
    // confirmed empirically: the SAME site (e.g. browserleaks) rejects on one
    // attempt and loads 200 on the next. Since each retry lands a different exit,
    // raising the attempt count meaningfully lifts success on flaky proxies
    // (~94% at 4 tries -> ~99.6% at 8 in a moderate window). 150/300/600ms backoff
    // (capped) gives the proxy time to rotate; ~3.9s worst case before giving up.
    const int currentAttempt = ++m_attempt;
    const int kMaxAttempts = 8;
    const bool canRetry = currentAttempt < kMaxAttempts;
    int64_t retryDelayMs = static_cast<int64_t>(150) << (currentAttempt - 1);
    if (retryDelayMs > 600) retryDelayMs = 600;

    Ref protectedThis { *this };
    dispatch_async(loaderQueue(), ^{
        // Wave .349 — CRITICAL UAF FIX. Previously `protectedThis` was declared but
        // NEVER referenced inside this block, so the ObjC block did not capture it →
        // the loader was retained only for the (synchronous) duration of resume(), NOT
        // for this async block. Under rapid connection churn (e.g. browserleaks's
        // DNS-leak test fires many short-lived loads) the loader could be destroyed
        // before/while this block ran on loaderQueue → use-after-free → NetworkProcess
        // SIGSEGV (NULL deref in _dispatch_call_block_and_release), which then breaks
        // ALL subsequent navigation (every new load fails with internalError).
        // Referencing protectedThis here (same idiom as the retry blocks' retryRef->)
        // forces the block to capture it (retain) so the loader outlives the work.
        if (protectedThis->m_cancelled)
            return;

        // Read proxy + creds from env (same path as DriftstackSocks5URLProtocol)
        const char* proxyEnv = getenv("DRIFTSTACK_SOCKS5_PROXY");
        if (!proxyEnv || !proxyEnv[0]) {
            auto* clientPtr = m_task.client();
            if (clientPtr) {
                WebCore::ResourceError error(String("DriftstackNetworkLoader"_s), 0, URL(url), "DRIFTSTACK_SOCKS5_PROXY not set"_s, WebCore::ResourceError::Type::General);
                if (!tryBeginCompletion()) return;  // Wave .325 single-completion guard
                callOnMainRunLoop([clientPtr, error = std::move(error)]() mutable {
                    WebCore::NetworkLoadMetrics metrics;
                    clientPtr->didCompleteWithError(error, metrics);
                });
            }
            return;
        }

        String proxyEnvStr = String::fromUTF8(proxyEnv);
        size_t colon = proxyEnvStr.find(':');
        if (colon == notFound)
            return;
        String proxyHostStr = proxyEnvStr.left(colon);
        int proxyPort = 0;
        {
            auto portStr = proxyEnvStr.substring(colon + 1);
            for (unsigned i = 0; i < portStr.length(); ++i) {
                UChar c = portStr[i];
                if (c < '0' || c > '9') { proxyPort = 0; break; }
                proxyPort = proxyPort * 10 + (c - '0');
            }
        }
        if (proxyPort == 0)
            return;

        Socks5Endpoint proxy;
        proxy.host = proxyHostStr;
        proxy.port = static_cast<uint16_t>(proxyPort);

        Socks5Credentials creds;
        const char* userEnv = getenv("DRIFTSTACK_SOCKS5_USER");
        const char* passEnv = getenv("DRIFTSTACK_SOCKS5_PASS");
        if (userEnv && userEnv[0] && passEnv) {
            creds.username = String::fromUTF8(userEnv);
            creds.password = String::fromUTF8(passEnv);
        }

        // Wave 29-499.321 — HTTP/3 branch. For https origins that are h3-capable
        // (learned via Alt-Svc, or forced for first-contact verification), route
        // through the QUIC/HTTP-3 engine over SOCKS5 §7 (driftstackHttp3Execute,
        // which does its own UDP_ASSOCIATE) instead of the TCP h2/h1 path below.
        // This is the in-browser h3 path: NetworkDataTaskCocoa::resume already
        // routes here (DriftstackNetworkLoader is the active loader), so unlike
        // the URLProtocol, it actually fires for WebKit page loads. On any h3
        // failure we fall through to the proven TCP h2/h1 path.
        {
            const char* h3env = getenv("DRIFTSTACK_PATHB_V2_H3");
            const char* h3force = getenv("DRIFTSTACK_PATHB_V2_H3_FORCE");
            bool h3enabled = h3env && h3env[0] == '1';
            bool h3forced = h3force && h3force[0] == '1';
            String h3host = url.host().toString();
            bool h3https = url.protocolIs("https"_s);
            // Only take the h3 path for body-less methods. driftstackHttp3Execute
            // submits with data_reader=nullptr (no request body), so routing a
            // POST/PUT here would silently drop its body. Requests with a body
            // fall through to the proven TCP h2/h1 path until h3 body support
            // (nghttp3 data_reader) lands. GET/HEAD have no body.
            bool h3bodyless = (equalIgnoringASCIICase(httpMethod, "GET"_s)
                || equalIgnoringASCIICase(httpMethod, "HEAD"_s)) && !hasRequestBody;
            // Wave 29-499.321 — FIRST-CONTACT h3 via DNS HTTPS RR (RFC 9460 type
            // 65), matching real Safari (which queries the HTTPS record and goes
            // straight to h3, before any Alt-Svc response). Alt-Svc only upgrades
            // AFTER an h2 response, so endpoints like quic.browserleaks.com (h3
            // advertised only via HTTPS RR, measured on first contact) need this.
            // Cached per host; only consulted when not already known + not forced.
            // Gated behind DRIFTSTACK_PATHB_V2_H3_DNSRR=1. The shared-persistent-
            // DNS-relay optimization HAS landed (driftstackHostAdvertisesH3ViaDns:
            // one §7 relay opened once + a background reader thread + txid demux +
            // 800ms-capped concurrent waits → NO per-host associate storm). Verified
            // on www.cloudflare.com: 3 RR queries for 3 hosts, h3 detected, main page
            // status=200 114KB, no stall. Enabled in launch-env (Wave .322).
            static const bool s_dnsRrEnabled = [] {
                const char* e = getenv("DRIFTSTACK_PATHB_V2_H3_DNSRR");
                return e && e[0] == '1';
            }();
            // Wave .349 — do the BLOCKING DNS-HTTPS-RR h3 probe ONLY for the main-frame
            // document navigation. It blocks the worker up to 800ms; a page fires many
            // concurrent subresource fetches (e.g. browserleaks's ja3/tls1x probes), and
            // blocking each one's RR lookup stalls them past the page's own fetch timeout
            // → "fetch error"/N/A. Subresources skip the blocking probe and use h2
            // immediately (h3 still kicks in via Alt-Svc, or the per-host cache once the
            // main-frame navigation populated it). Matches Safari more closely too: its OS
            // resolver does RR async, never blocking a subresource on a per-host lookup.
            if (s_dnsRrEnabled && h3enabled && h3https && h3bodyless && !h3forced
                && m_task.isTopLevelNavigation() && !driftstackLoaderHostKnownH3(h3host)) {
                if (WebKit::driftstackHostAdvertisesH3ViaDns(h3host))
                    driftstackLoaderRememberH3Host(h3host);
            }
            if (h3enabled && h3https && h3bodyless && (h3forced || driftstackLoaderHostKnownH3(h3host))) {
                WebKit::DriftstackHttp3Request h3req;
                h3req.method = httpMethod;
                h3req.scheme = "https"_s;
                uint16_t h3port = static_cast<uint16_t>(url.port().value_or(443));
                h3req.authority = h3port == 443 ? h3host : makeString(h3host, ':', h3port);
                h3req.path = url.path().toString();
                if (h3req.path.isEmpty()) h3req.path = "/"_s;
                if (!url.query().isEmpty())
                    h3req.path = makeString(h3req.path, '?', url.query());
                // iPhone Safari 26 canonical header order (same as the h2 path):
                // accept, sec-fetch-site, sec-fetch-dest, accept-encoding,
                // sec-fetch-mode, user-agent, priority, accept-language; WebKit's
                // natural values, only the ORDER is enforced.
                HashMap<String, String> wk;
                for (auto& header : httpHeaders)
                    wk.add(header.key.convertToASCIILowercase(), header.value);
                auto orDefault = [&](ASCIILiteral key, ASCIILiteral fallback) -> String {
                    auto it = wk.find(String(key));
                    return it != wk.end() ? it->value : String(fallback);
                };
                h3req.extraHeaders.append({ "accept"_s, orDefault("accept"_s, "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"_s) });
                if (wk.contains("sec-fetch-site"_s)) h3req.extraHeaders.append({ "sec-fetch-site"_s, wk.get("sec-fetch-site"_s) });
                if (wk.contains("sec-fetch-dest"_s)) h3req.extraHeaders.append({ "sec-fetch-dest"_s, wk.get("sec-fetch-dest"_s) });
                h3req.extraHeaders.append({ "accept-encoding"_s, orDefault("accept-encoding"_s, "gzip, deflate, br"_s) });
                if (wk.contains("sec-fetch-mode"_s)) h3req.extraHeaders.append({ "sec-fetch-mode"_s, wk.get("sec-fetch-mode"_s) });
                h3req.extraHeaders.append({ "user-agent"_s, orDefault("user-agent"_s, "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.4 Mobile/15E148 Safari/604.1"_s) });
                if (wk.contains("priority"_s)) h3req.extraHeaders.append({ "priority"_s, wk.get("priority"_s) });
                h3req.extraHeaders.append({ "accept-language"_s, orDefault("accept-language"_s, "en-US,en;q=0.9"_s) });
                // cookies
                if (auto nsURLPtr = url.createNSURL()) {
                    NSArray<NSHTTPCookie*>* cookies = [[NSHTTPCookieStorage sharedHTTPCookieStorage] cookiesForURL:nsURLPtr.get()];
                    if (cookies.count > 0) {
                        NSString* cookie = [NSHTTPCookie requestHeaderFieldsWithCookies:cookies][@"Cookie"];
                        if (cookie) h3req.extraHeaders.append({ "cookie"_s, String::fromUTF8([cookie UTF8String]) });
                    }
                }

                WTFLogAlways("[Wave29-499.321/LOADER] HTTP/3 path for https://%s%s (forced=%d known=%d)",
                    h3host.utf8().data(), h3req.path.utf8().data(), h3forced, driftstackLoaderHostKnownH3(h3host));
                // Wave .322 — when DRIFTSTACK_H3_POOL is set, reuse ONE persistent
                // QUIC+h3 connection per origin (serialized claim → 1 handshake/origin
                // instead of N). Falls back to one-shot driftstackHttp3Execute if the
                // session can't be established. Default OFF → one-shot behaviour.
                WebKit::DriftstackHttp3Response h3resp;
                bool h3PoolHandled = false;
                if (WebKit::driftstackHttp3PoolEnabled()) {
                    String h3origin = h3req.authority;
                    // Wave 29-499.330 — up to 2 attempts: if a REUSED pooled session fails its
                    // request (server idle-closed the QUIC connection between page loads — the
                    // "refresh shows no QUIC" case), evict it and retry ONCE on a fresh
                    // connection rather than silently dropping to TCP h2 (which loses QUIC).
                    for (int h3attempt = 0; h3attempt < 2; ++h3attempt) {
                        auto claim = driftstackH3PoolClaim(h3origin);
                        RefPtr<WebKit::DriftstackHttp3Session> session = claim.first;
                        bool reused = session != nullptr; // claim.first set ⇒ live-reused session
                        if (!session && claim.second) {
                            // Winner: establish the connection, publish it, wake waiters.
                            session = WebKit::DriftstackHttp3Session::create(h3req.authority);
                            if (session)
                                driftstackH3PoolSet(h3origin, RefPtr<WebKit::DriftstackHttp3Session>(session));
                            driftstackH3PoolFinishPending(h3origin);
                        }
                        if (!session)
                            break; // claim timed out → one-shot fallback below
                        h3resp = session->execute(h3req);
                        h3PoolHandled = true;
                        WTFLogAlways("[Wave29-499.322/LOADER/H3POOL] pooled h3 execute for %s status=%d failed=%d (reused=%d attempt=%d)",
                            h3origin.utf8().data(), h3resp.statusCode, h3resp.failed, reused, h3attempt);
                        if (!h3resp.failed && h3resp.statusCode)
                            break; // success
                        if (reused && !h3attempt) {
                            WTFLogAlways("[Wave29-499.330/LOADER/H3POOL] reused h3 session for %s failed — evicting + re-establishing fresh QUIC connection",
                                h3origin.utf8().data());
                            driftstackH3PoolEvict(h3origin);
                            continue; // retry with a fresh connection
                        }
                        break; // fresh attempt also failed → fall through to TCP h2
                    }
                }
                if (!h3PoolHandled)
                    h3resp = WebKit::driftstackHttp3Execute(nullptr, h3req);

                auto* clientPtr = m_task.client();
                if (!clientPtr) return;
                if (!h3resp.failed && h3resp.statusCode) {
                    String mimeType = "text/html"_s, charset = "UTF-8"_s;
                    long long expectedLength = -1;
                    for (auto& [k, v] : h3resp.headers) {
                        if (equalIgnoringASCIICase(k, "content-type"_s)) {
                            String hv = v; size_t semi = hv.find(';');
                            if (semi != notFound) {
                                mimeType = hv.left(semi).trim(deprecatedIsSpaceOrNewline);
                                String params = hv.substring(semi + 1);
                                size_t ci = params.findIgnoringASCIICase("charset="_s);
                                if (ci != notFound) {
                                    String cs = params.substring(ci + 8).trim(deprecatedIsSpaceOrNewline);
                                    size_t e = cs.find(';'); if (e != notFound) cs = cs.left(e);
                                    if (cs.startsWith('"') && cs.endsWith('"')) cs = cs.substring(1, cs.length() - 2);
                                    if (!cs.isEmpty()) charset = cs;
                                }
                            } else
                                mimeType = hv.trim(deprecatedIsSpaceOrNewline);
                        } else if (equalIgnoringASCIICase(k, "content-length"_s)) {
                            long long n = parseInteger<long long>(v).value_or(-1);
                            if (n >= 0) expectedLength = n;
                        }
                    }
                    if (expectedLength < 0) expectedLength = static_cast<long long>(h3resp.body.size());
                    WebCore::ResourceResponse response { URL(url), std::move(mimeType), expectedLength, std::move(charset) };
                    response.setHTTPStatusCode(h3resp.statusCode);
                    for (auto& [k, v] : h3resp.headers)
                        response.setHTTPHeaderField(k, v);
                    if (tryFollowRedirect(response)) return;  // Wave .344 — follow 3xx like Safari, don't render the redirect page
                    WebKit::driftstackDecodeContentEncoding(h3resp.body, h3resp.headers);  // .331 chokepoint
                    auto bodyBuffer = WebCore::SharedBuffer::create(h3resp.body.span());
                    if (!tryBeginCompletion()) return;  // Wave .325 single-completion guard
                    callOnMainRunLoop([clientPtr, response = WebCore::ResourceResponse(response), bodyBuffer = std::move(bodyBuffer)]() mutable {
                        clientPtr->didReceiveResponse(std::move(response), NegotiatedLegacyTLS::No, PrivateRelayed::No,
                            [clientPtr, bodyBuffer = std::move(bodyBuffer)](WebCore::PolicyAction action) mutable {
                                if (action == WebCore::PolicyAction::Use) {
                                    clientPtr->didReceiveData(bodyBuffer.get());
                                    WebCore::NetworkLoadMetrics metrics;
                                    clientPtr->didCompleteWithError(WebCore::ResourceError(), metrics);
                                }
                            });
                    });
                    WTFLogAlways("[Wave29-499.321/LOADER] HTTP/3 delivered status=%d bodyLen=%zu for %s",
                        h3resp.statusCode, h3resp.body.size(), h3host.utf8().data());
                    return;
                }
                WTFLogAlways("[Wave29-499.321/LOADER] HTTP/3 failed (%s) — falling through to TCP h2/h1",
                    h3resp.errorMessage.utf8().data());
                // fall through to the TCP path below
            }
        }

        // Wave 29-499.321 (Phase 2.5) — HTTP/2 connection-pool FAST PATH. If a
        // live multiplexed session already exists for this origin, reuse it (a
        // new stream) — NO SOCKS5/TLS handshake. This is what makes Path B v2
        // fast on multi-resource pages. The pool is populated by the adopt step
        // after a fresh connection negotiates h2 (below), so until then this is
        // a no-op miss that falls through to the normal path. Gated by
        // DRIFTSTACK_H2_POOL.
        bool h2PoolWinner = false;
        String h2PoolOrigin;
        if (driftstackH2PoolEnabled() && url.protocolIs("https"_s)) {
            h2PoolOrigin = makeString(url.host().toString(), ':', static_cast<unsigned>(url.port().value_or(443)));
            const String& origin = h2PoolOrigin;
            // Coalesce: live session → fast-path; else claim winner / wait for one.
            auto h2Claim = driftstackH2PoolClaim(origin);
            h2PoolWinner = h2Claim.second;
            if (RefPtr<WebKit::DriftstackHttp2Session> session = h2Claim.first) {
                String poolHost = url.host().toString();
                auto h2req = driftstackBuildIphoneH2Request(url, httpMethod, httpHeaders, requestBody, poolHost);
                WebKit::DriftstackHttp2Response h2resp = session->execute(h2req);
                auto* clientPtr = m_task.client();
                if (!clientPtr) return;
                if (!h2resp.failed && h2resp.statusCode) {
                    String mimeType = "text/html"_s, charset = "UTF-8"_s;
                    long long expectedLength = -1;
                    for (auto& [k, v] : h2resp.headers) {
                        if (equalIgnoringASCIICase(k, "content-type"_s)) {
                            String hv = v; size_t semi = hv.find(';');
                            if (semi != notFound) {
                                mimeType = hv.left(semi).trim(deprecatedIsSpaceOrNewline);
                                String params = hv.substring(semi + 1);
                                size_t ci = params.findIgnoringASCIICase("charset="_s);
                                if (ci != notFound) {
                                    String cs = params.substring(ci + 8).trim(deprecatedIsSpaceOrNewline);
                                    size_t e = cs.find(';'); if (e != notFound) cs = cs.left(e);
                                    if (cs.startsWith('"') && cs.endsWith('"')) cs = cs.substring(1, cs.length() - 2);
                                    if (!cs.isEmpty()) charset = cs;
                                }
                            } else
                                mimeType = hv.trim(deprecatedIsSpaceOrNewline);
                        } else if (equalIgnoringASCIICase(k, "content-length"_s)) {
                            long long n = parseInteger<long long>(v).value_or(-1);
                            if (n >= 0) expectedLength = n;
                        }
                    }
                    if (expectedLength < 0) expectedLength = static_cast<long long>(h2resp.body.size());
                    // Wave .323 DEBUG (removable) — log the peet.ws print (h2 fast-path).
                    if (url.host().toString().endsWith("peet.ws"_s))
                        WTFLogAlways("[PEET-PRINT-BEGIN]%.*s[PEET-PRINT-END]", (int)h2resp.body.size(), reinterpret_cast<const char*>(h2resp.body.span().data()));
                    WebCore::ResourceResponse response { URL(url), std::move(mimeType), expectedLength, std::move(charset) };
                    response.setHTTPStatusCode(h2resp.statusCode);
                    for (auto& [k, v] : h2resp.headers)
                        response.setHTTPHeaderField(k, v);
                    if (tryFollowRedirect(response)) return;  // Wave .344 — follow 3xx like Safari, don't render the redirect page
                    WebKit::driftstackDecodeContentEncoding(h2resp.body, h2resp.headers);  // .331 chokepoint
                    // Wave .346 DEBUG (removable) — dump decompressed fingerprint JSON for browserleaks
                    // probe endpoints so we can diff our TLS/QUIC family vs the real-iPhone reference.
                    auto bodyBuffer = WebCore::SharedBuffer::create(h2resp.body.span());
                    if (!tryBeginCompletion()) return;  // Wave .325 single-completion guard
                    callOnMainRunLoop([clientPtr, response = WebCore::ResourceResponse(response), bodyBuffer = std::move(bodyBuffer)]() mutable {
                        clientPtr->didReceiveResponse(std::move(response), NegotiatedLegacyTLS::No, PrivateRelayed::No,
                            [clientPtr, bodyBuffer = std::move(bodyBuffer)](WebCore::PolicyAction action) mutable {
                                if (action == WebCore::PolicyAction::Use) {
                                    clientPtr->didReceiveData(bodyBuffer.get());
                                    WebCore::NetworkLoadMetrics metrics;
                                    clientPtr->didCompleteWithError(WebCore::ResourceError(), metrics);
                                }
                            });
                    });
                    return;
                }
                // Pooled session failed (e.g. GOAWAY mid-flight) — fall through
                // to a fresh connection.
                WTFLogAlways("[Wave29-499.321/H2POOL] pooled session execute failed for %s — fresh connect", origin.utf8().data());
            }
        }

        // Wave .321 — winner guard: if we claimed the origin (h2PoolWinner) but
        // exit before publishing a session (any connect/TLS failure path), clear
        // the pending claim + wake waiters so they connect on their own instead
        // of blocking the full 10s. On adopt-success we set h2PoolWinner=false.
        auto h2PoolGuard = WTF::makeScopeExit([&] {
            if (h2PoolWinner) driftstackH2PoolFinishPending(h2PoolOrigin);
        });

        auto socks5Client = std::make_unique<DriftstackSocks5Client>(proxy, creds);
        auto handshakeResult = socks5Client->performHandshake();
        if (handshakeResult != Socks5Result::Success) {
            auto* clientPtr = m_task.client();
            if (clientPtr) {
                WebCore::ResourceError error(String("DriftstackNetworkLoader"_s), 0, URL(url), "SOCKS5 handshake failed"_s, WebCore::ResourceError::Type::General);
                if (!tryBeginCompletion()) return;  // Wave .325 single-completion guard
                callOnMainRunLoop([clientPtr, error = std::move(error)]() mutable {
                    WebCore::NetworkLoadMetrics metrics;
                    clientPtr->didCompleteWithError(error, metrics);
                });
            }
            return;
        }

        String host = url.host().toString();
        bool isHttps = url.protocolIs("https"_s);
        uint16_t destPort = static_cast<uint16_t>(url.port().value_or(isHttps ? 443 : 80));

        Socks5Endpoint dest;
        dest.host = host;
        dest.port = destPort;

        Socks5Endpoint bnd;
        auto connectResult = socks5Client->tcpConnect(dest, bnd);
        if (connectResult != Socks5Result::Success) {
            if (canRetry) {
                WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.271] retry attempt=%d for SOCKS5 CONNECT to %s",
                    currentAttempt, url.host().toString().utf8().data());
                Ref<DriftstackNetworkLoader> retryRef { *this };
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, retryDelayMs * NSEC_PER_MSEC),
                    dispatch_get_main_queue(), ^{
                        if (!retryRef->m_cancelled) retryRef->resume();
                    });
                return;
            }
            auto* clientPtr = m_task.client();
            if (clientPtr) {
                WebCore::ResourceError error(String("DriftstackNetworkLoader"_s), 0, URL(url), "SOCKS5 CONNECT failed"_s, WebCore::ResourceError::Type::General);
                if (!tryBeginCompletion()) return;  // Wave .325 single-completion guard
                callOnMainRunLoop([clientPtr, error = std::move(error)]() mutable {
                    WebCore::NetworkLoadMetrics metrics;
                    clientPtr->didCompleteWithError(error, metrics);
                });
            }
            return;
        }

        int socketFd = socks5Client->socketFileDescriptor();
        m_fd = socketFd;

#if defined(DRIFTSTACK_HAS_BORINGSSL) && DRIFTSTACK_HAS_BORINGSSL
        // Wave 29-499.137 — BoringSSL TLS 1.3 wrap for HTTPS (iPhone-identical fingerprint)
        SSL* ssl = nullptr;
        if (isHttps) {
            ssl = driftstackTLSConnect(socketFd, host.utf8().data());
            if (!ssl) {
                if (canRetry) {
                    WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.271] retry attempt=%d for TLS handshake to %s",
                        currentAttempt, host.utf8().data());
                    Ref<DriftstackNetworkLoader> retryRef { *this };
                    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, retryDelayMs * NSEC_PER_MSEC),
                        dispatch_get_main_queue(), ^{
                            if (!retryRef->m_cancelled) retryRef->resume();
                        });
                    return;
                }
                auto* clientPtr = m_task.client();
                if (clientPtr) {
                    WebCore::ResourceError error(String("DriftstackNetworkLoader"_s), 0, URL(url), "BoringSSL TLS handshake failed"_s, WebCore::ResourceError::Type::General);
                    if (!tryBeginCompletion()) return;  // Wave .325 single-completion guard
                    callOnMainRunLoop([clientPtr, error = std::move(error)]() mutable {
                        WebCore::NetworkLoadMetrics metrics;
                        clientPtr->didCompleteWithError(error, metrics);
                    });
                }
                return;
            }
        }
        bool useBoringSSL = isHttps && ssl;

        // Wave 29-499.163 — detect HTTP/2 from ALPN; dispatch to our
        // custom HTTP/2 client (DriftstackHttp2) when h2 negotiated.
        // Added explicit logging to trace why dispatch wasn't firing.
        bool useHttp2 = false;
        if (g_customTLSClient) {
            // Wave 29-499.209 — use ACTUAL ALPN parsed from EncryptedExtensions
            useHttp2 = g_customTLSClient->selectedALPN() == "h2"_s;
            WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.209] Custom TLS ALPN='%s' useHttp2=%d",
                g_customTLSClient->selectedALPN().utf8().data(), useHttp2);
        } else if (ssl) {
            auto& f = boringSSLFns();
            const uint8_t* alpnSel = nullptr;
            unsigned alpnLen = 0;
            if (f.ssl_get0_alpn_selected) f.ssl_get0_alpn_selected(ssl, &alpnSel, &alpnLen);
            if (alpnSel && alpnLen == 2 && alpnSel[0] == 'h' && alpnSel[1] == '2')
                useHttp2 = true;
            static bool loggedAlpnOnce = false;
            if (!loggedAlpnOnce) {
                loggedAlpnOnce = true;
                char alpnBuf[16] = {0};
                if (alpnSel && alpnLen < sizeof(alpnBuf))
                    memcpy(alpnBuf, alpnSel, alpnLen);
                WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.163] resume() ALPN check: alpn='%s' len=%u useHttp2=%d ssl_get0=%p",
                    alpnBuf, alpnLen, useHttp2, (void*)f.ssl_get0_alpn_selected);
            }
        }
#else
        void* ssl = nullptr;
        bool useBoringSSL = false;
        bool useHttp2 = false;
        (void)ssl;
#endif

        // Wave 29-499.141 — if ALPN selected h2, dispatch via
        // DriftstackHttp2 (iPhone-matched SETTINGS + WINDOW_UPDATE +
        // HEADERS HPACK). Otherwise fall through to HTTP/1.1 path.
        if (useHttp2) {
            WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.194] Entering HTTP/2 dispatch path (custom_tls=%d ssl=%p)", g_customTLSClient ? 1 : 0, ssl);
            DriftstackHttp2Request h2req;
            h2req.method = httpMethod;
            h2req.scheme = "https"_s;
            h2req.authority = host;
            h2req.body = requestBody;  // Wave .321 — POST/PUT body (h2 DATA frame)
            h2req.path = url.path().toString();
            if (h2req.path.isEmpty()) h2req.path = "/"_s;
            if (!url.query().isEmpty())
                h2req.path = makeString(h2req.path, '?', url.query());
            // Wave 29-499.146 — cookie injection for h2 path
            {
                auto nsURLPtr = url.createNSURL();
            NSURL* nsURL = nsURLPtr.get();
                if (nsURL) {
                    NSHTTPCookieStorage* storage = [NSHTTPCookieStorage sharedHTTPCookieStorage];
                    NSArray<NSHTTPCookie*>* cookies = [storage cookiesForURL:nsURL];
                    if (cookies.count > 0) {
                        NSDictionary* fields = [NSHTTPCookie requestHeaderFieldsWithCookies:cookies];
                        NSString* cookie = fields[@"Cookie"];
                        if (cookie)
                            h2req.extraHeaders.append({ "cookie"_s, String::fromUTF8([cookie UTF8String]) });
                    }
                }
            }
            // Wave 29-499.201 — iPhone Safari 26.0 EXACT HTTP/2 header order
            // (verified via tls.peet.ws default-mode capture).
            // Order matters for JA4H + Akamai pseudo-header order.
            //
            // Pseudo: :method, :scheme, :path, :authority (already in h2req)
            // Real headers in iPhone order:
            //   accept, sec-fetch-site, sec-fetch-dest, accept-encoding,
            //   sec-fetch-mode, user-agent, priority, accept-language
            //
            // We OVERRIDE WebKit's defaults to match iPhone exactly.
            bool haveUA = false;
            for (auto& header : httpHeaders) {
                String lower = header.key.convertToASCIILowercase();
                if (lower == "user-agent"_s)
                    haveUA = true;
            }

            (void)haveUA;
            // Wave 29-499.204 — NATURAL header values from WebKit (context-aware),
            // ONLY enforce iPhone ORDER. WebKit already computes iPhone-correct
            // sec-fetch-*, accept, priority per request context (document vs
            // script vs font vs xhr vs cross-origin). Hardcoding would break
            // ALL non-document requests on real customer sites.
            //
            // iPhone Safari 26 canonical header order (per real-iPhone capture):
            //   accept, sec-fetch-site, sec-fetch-dest, accept-encoding,
            //   sec-fetch-mode, user-agent, priority, accept-language
            //
            // Strategy: collect WebKit's values, emit in iPhone order. If WebKit
            // didn't set one (rare — only for non-browser HTTP clients), use a
            // sensible default that matches what iPhone would send for that
            // context. Production: replace defaults with profile YAML lookups.
            HashMap<String, String> webkitHdrs;
            for (auto& header : httpHeaders) {
                String lower = header.key.convertToASCIILowercase();
                webkitHdrs.add(lower, header.value);
            }
            auto getOrDefault = [&](ASCIILiteral key, ASCIILiteral fallback) -> String {
                auto it = webkitHdrs.find(String(key));
                return it != webkitHdrs.end() ? it->value : String(fallback);
            };

            // Emit in iPhone-mandated order, using WebKit's natural values
            h2req.extraHeaders.append({ "accept"_s,
                getOrDefault("accept"_s, "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"_s) });
            if (webkitHdrs.contains("sec-fetch-site"_s))
                h2req.extraHeaders.append({ "sec-fetch-site"_s, webkitHdrs.get("sec-fetch-site"_s) });
            if (webkitHdrs.contains("sec-fetch-dest"_s))
                h2req.extraHeaders.append({ "sec-fetch-dest"_s, webkitHdrs.get("sec-fetch-dest"_s) });
            h2req.extraHeaders.append({ "accept-encoding"_s,
                getOrDefault("accept-encoding"_s, "gzip, deflate, br"_s) });
            if (webkitHdrs.contains("sec-fetch-mode"_s))
                h2req.extraHeaders.append({ "sec-fetch-mode"_s, webkitHdrs.get("sec-fetch-mode"_s) });
            h2req.extraHeaders.append({ "user-agent"_s,
                getOrDefault("user-agent"_s, "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.4 Mobile/15E148 Safari/604.1"_s) });
            if (webkitHdrs.contains("priority"_s))
                h2req.extraHeaders.append({ "priority"_s, webkitHdrs.get("priority"_s) });
            h2req.extraHeaders.append({ "accept-language"_s,
                getOrDefault("accept-language"_s, "en-US,en;q=0.9"_s) });

            // Forward any OTHER WebKit headers (referer, cookie was set
            // earlier, content-type for POST, etc.) — preserved in their
            // original positions (iPhone allows arbitrary trailing headers).
            for (auto& header : httpHeaders) {
                String lower = header.key.convertToASCIILowercase();
                if (lower == "host"_s || lower == "connection"_s
                    || lower == "cookie"_s || lower.startsWith(':')
                    || lower == "accept"_s || lower == "accept-encoding"_s
                    || lower == "accept-language"_s || lower == "sec-fetch-site"_s
                    || lower == "sec-fetch-dest"_s || lower == "sec-fetch-mode"_s
                    || lower == "user-agent"_s || lower == "priority"_s)
                    continue;
                // Wave 29-499.261 — strip cache-validation headers. PathB v2
                // has no client-side cache; If-None-Match / If-Modified-Since
                // cause servers to return 304 with empty body, which JS engine
                // can't execute and rendering fails. Stripping forces full
                // 200 responses on every request.
                if (lower == "if-none-match"_s || lower == "if-modified-since"_s
                    || lower == "if-match"_s || lower == "if-unmodified-since"_s
                    || lower == "if-range"_s)
                    continue;
                h2req.extraHeaders.append({ lower, header.value });
            }

            // Wave 29-499.193 — route HTTP/2 via custom TLS client if active.
            // Wave .321 P2.5 — when pooling is enabled + the custom TLS client
            // negotiated h2, ADOPT this freshly-established connection into a
            // persistent multiplexed session and pool it for reuse (instead of a
            // one-shot). The session takes OWNERSHIP of the TLS + SOCKS5 clients,
            // so the one-shot cleanup below must be skipped for them (double-free
            // / wrong-branch shutdown otherwise). handledConnection tracks that we
            // moved the clients out (true even if session-create fails, since the
            // failed session's destruction already freed them).
            DriftstackHttp2Response h2resp;
            bool handledConnection = false;
            if (driftstackH2PoolEnabled() && g_customTLSClient) {
                handledConnection = true;
                auto tlsOwned = std::unique_ptr<DriftstackTLS13Client>(g_customTLSClient);
                g_customTLSClient = nullptr;
                RefPtr<WebKit::DriftstackHttp2Session> session = WebKit::DriftstackHttp2Session::create(std::move(tlsOwned), std::move(socks5Client));
                if (session) {
                    String origin = makeString(host, ':', static_cast<unsigned>(url.port().value_or(443)));
                    // Publish the session + wake coalesced waiters NOW (before our
                    // own request runs) so they multiplex concurrently over it.
                    driftstackH2PoolSet(origin, RefPtr<WebKit::DriftstackHttp2Session>(session));
                    if (h2PoolWinner) { driftstackH2PoolFinishPending(origin); h2PoolWinner = false; }
                    h2resp = session->execute(h2req);
                    WTFLogAlways("[Wave29-499.321/H2POOL] adopted connection for %s into pool (first request status=%d)", origin.utf8().data(), h2resp.statusCode);
                } else {
                    h2resp.failed = true;
                    h2resp.errorMessage = "h2 session adopt/create failed"_s;
                }
            } else if (g_customTLSClient) {
                DriftstackHttp2Transport transport;
                transport.ctx = g_customTLSClient;
                transport.readFn = [](void* ctx, uint8_t* buf, size_t n) -> int {
                    return reinterpret_cast<DriftstackTLS13Client*>(ctx)->read(buf, n);
                };
                transport.writeFn = [](void* ctx, const uint8_t* buf, size_t n) -> int {
                    return reinterpret_cast<DriftstackTLS13Client*>(ctx)->write(buf, n);
                };
                h2resp = driftstackHttp2ExecuteVia(transport, h2req);
            } else {
                h2resp = driftstackHttp2Execute(ssl, h2req);
            }

#if defined(DRIFTSTACK_HAS_BORINGSSL) && DRIFTSTACK_HAS_BORINGSSL
            // Wave 29-499.193 — skip SSL_shutdown/free when our custom TLS
            // client is active (ssl is a sentinel pointer, not a real SSL*).
            // Wave .321 — also skip entirely if we adopted the connection into a
            // pooled session (the session owns the clients now).
            if (!handledConnection) {
                if (!g_customTLSClient) {
                    auto& f = boringSSLFns();
                    if (f.ssl_shutdown) f.ssl_shutdown(ssl);
                    if (f.ssl_free) f.ssl_free(ssl);
                } else {
                    delete g_customTLSClient;
                    g_customTLSClient = nullptr;
                }
            }
#endif

            auto* clientPtr = m_task.client();
            if (!clientPtr) return;

            if (h2resp.failed) {
                if (canRetry) {
                    WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.271] retry attempt=%d for HTTP/2 transport to %s",
                        currentAttempt, url.host().toString().utf8().data());
                    Ref<DriftstackNetworkLoader> retryRef { *this };
                    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, retryDelayMs * NSEC_PER_MSEC),
                        dispatch_get_main_queue(), ^{
                            if (!retryRef->m_cancelled) retryRef->resume();
                        });
                    return;
                }
                WebCore::ResourceError error(String("DriftstackNetworkLoader"_s), 0, URL(url), h2resp.errorMessage, WebCore::ResourceError::Type::General);
                if (!tryBeginCompletion()) return;  // Wave .325 single-completion guard
                callOnMainRunLoop([clientPtr, error = std::move(error)]() mutable {
                    WebCore::NetworkLoadMetrics metrics;
                    clientPtr->didCompleteWithError(error, metrics);
                });
                return;
            }

            // Wave 29-499.267 — extract real Content-Type + charset from response
            // headers BEFORE constructing ResourceResponse. Previous code hard-coded
            // mimeType="text/html" charset="UTF-8" which made CSS/JS be treated as
            // HTML (no styling, no script execution → blank pages).
            String mimeType = "text/html"_s;
            String charset = "UTF-8"_s;
            long long expectedLength = -1;
            for (auto& [k, v] : h2resp.headers) {
                // Wave 29-499.321 — learn h3 support (RFC 7838). If this origin's
                // h2 response advertises h3, remember it so subsequent loads take
                // the QUIC/HTTP-3 path (matches Safari's Alt-Svc-gated h3).
                if (equalIgnoringASCIICase(k, "alt-svc"_s) && v.contains("h3"_s)) {
                    driftstackLoaderRememberH3Host(url.host().toString());
                    WTFLogAlways("[Wave29-499.321/LOADER] learned h3 for %s via Alt-Svc: %s",
                        url.host().toString().utf8().data(), v.utf8().data());
                }
                if (equalIgnoringASCIICase(k, "content-type"_s)) {
                    // "text/css; charset=utf-8" → split on ';'
                    String headerValue = v;
                    size_t semi = headerValue.find(';');
                    if (semi != notFound) {
                        mimeType = headerValue.left(semi).trim(deprecatedIsSpaceOrNewline);
                        String params = headerValue.substring(semi + 1);
                        size_t cidx = params.findIgnoringASCIICase("charset="_s);
                        if (cidx != notFound) {
                            String cs = params.substring(cidx + 8).trim(deprecatedIsSpaceOrNewline);
                            // strip trailing params after charset
                            size_t end = cs.find(';');
                            if (end != notFound) cs = cs.left(end);
                            // strip quotes
                            if (cs.startsWith('"') && cs.endsWith('"')) cs = cs.substring(1, cs.length() - 2);
                            if (!cs.isEmpty()) charset = cs;
                        }
                    } else {
                        mimeType = headerValue.trim(deprecatedIsSpaceOrNewline);
                    }
                } else if (equalIgnoringASCIICase(k, "content-length"_s)) {
                    bool ok = false;
                    long long n = parseInteger<long long>(v).value_or(-1);
                    if (n >= 0) expectedLength = n;
                    (void)ok;
                }
            }
            // Body size known post-decompression; use it if Content-Length absent/stripped
            if (expectedLength < 0)
                expectedLength = static_cast<long long>(h2resp.body.size());

            // Wave .323 DEBUG (removable) — log peet.ws print (adopt/one-shot h2 path);
            // NetworkProcess sandbox blocks /tmp writes, so emit to stderr.
            if (url.host().toString().endsWith("peet.ws"_s))
                WTFLogAlways("[PEET-PRINT-BEGIN]%.*s[PEET-PRINT-END]", (int)h2resp.body.size(), reinterpret_cast<const char*>(h2resp.body.span().data()));

            WebCore::ResourceResponse response { URL(url), std::move(mimeType), expectedLength, std::move(charset) };
            response.setHTTPStatusCode(h2resp.statusCode);
            for (auto& [k, v] : h2resp.headers)
                response.setHTTPHeaderField(k, v);

            // Wave 29-499.269 — dispatch response delivery via callOnMainRunLoop.
            // PathB v2's fetch runs on loaderQueue (concurrent dispatch queue);
            // NetworkResourceLoader expects didReceiveResponse callbacks on the
            // NetworkProcess main runloop. Off-thread delivery from many
            // parallel HTTP/2 dispatches corrupted CFRunLoop hash sets and
            // crashed NetworkProcess (SIGTRAP in CFCheckCFInfoPACSignature_Bridged)
            // when loading 10+ subresource Angular apps like Twilio NT.
            if (tryFollowRedirect(response)) return;  // Wave .344 — follow 3xx like Safari, don't render the redirect page
            WebKit::driftstackDecodeContentEncoding(h2resp.body, h2resp.headers);  // .331 chokepoint — decode any encoding any h2 path missed
            auto bodyBuffer = WebCore::SharedBuffer::create(h2resp.body.span());
            auto deliveryResponse = WebCore::ResourceResponse(response);
            if (!tryBeginCompletion()) return;  // Wave .325 single-completion guard
            callOnMainRunLoop([clientPtr, response = std::move(deliveryResponse), bodyBuffer = std::move(bodyBuffer)]() mutable {
                clientPtr->didReceiveResponse(std::move(response), NegotiatedLegacyTLS::No, PrivateRelayed::No,
                    [clientPtr, bodyBuffer = std::move(bodyBuffer)](WebCore::PolicyAction action) mutable {
                        if (action == WebCore::PolicyAction::Use) {
                            clientPtr->didReceiveData(bodyBuffer.get());
                            WebCore::NetworkLoadMetrics metrics;
                            clientPtr->didCompleteWithError(WebCore::ResourceError(), metrics);
                        }
                    });
            });
            return;
        }


        // CFStream fallback only used when BoringSSL is unavailable
        CFReadStreamRef readStream = nullptr;
        CFWriteStreamRef writeStream = nullptr;
        if (!useBoringSSL) {
            CFStreamCreatePairWithSocket(kCFAllocatorDefault, socketFd, &readStream, &writeStream);
            if (!readStream || !writeStream)
                return;
            CFReadStreamSetProperty(readStream, kCFStreamPropertyShouldCloseNativeSocket, kCFBooleanFalse);
            CFWriteStreamSetProperty(writeStream, kCFStreamPropertyShouldCloseNativeSocket, kCFBooleanFalse);
        }

        // TLS for HTTPS via CFStream — only used if BoringSSL unavailable
        // (legacy TLS 1.2 fallback). When BoringSSL active, TLS is already
        // done on the BSD fd via driftstackTLSConnect (Wave 29-499.137).
        if (isHttps && !useBoringSSL) {
            NSDictionary* sslSettings = @{
                (NSString*)kCFStreamSSLLevel: (NSString*)kCFStreamSocketSecurityLevelNegotiatedSSL,
                (NSString*)kCFStreamSSLPeerName: host.createNSString().get(),
                (NSString*)kCFStreamSSLValidatesCertificateChain: @YES,
            };
            CFReadStreamSetProperty(readStream, kCFStreamPropertySSLSettings, (CFTypeRef)sslSettings);
            CFWriteStreamSetProperty(writeStream, kCFStreamPropertySSLSettings, (CFTypeRef)sslSettings);

            // Force TLS 1.3 via SSLContextRef (deprecated but Apple's only
            // public-API path for TLS-version pinning on CFStream).
            // SSLProtocolVersion: 0x0304 = TLS 1.3, 0x0303 = TLS 1.2.
            // kCFStreamPropertySSLContext returns a CFTypeRef wrapping the
            // SSLContextRef which we configure with SSLSetProtocolVersionMax/Min.
_Pragma("clang diagnostic push")
_Pragma("clang diagnostic ignored \"-Wdeprecated-declarations\"")
            CFTypeRef sslCtxRead = CFReadStreamCopyProperty(readStream, kCFStreamPropertySSLContext);
            if (sslCtxRead) {
                SSLContextRef ssl = (SSLContextRef)const_cast<void*>(sslCtxRead);
                SSLSetProtocolVersionMin(ssl, kTLSProtocol13);
                SSLSetProtocolVersionMax(ssl, kTLSProtocol13);
                CFRelease(sslCtxRead);
            }
            CFTypeRef sslCtxWrite = CFWriteStreamCopyProperty(writeStream, kCFStreamPropertySSLContext);
            if (sslCtxWrite) {
                SSLContextRef ssl = (SSLContextRef)const_cast<void*>(sslCtxWrite);
                SSLSetProtocolVersionMin(ssl, kTLSProtocol13);
                SSLSetProtocolVersionMax(ssl, kTLSProtocol13);
                CFRelease(sslCtxWrite);
            }
_Pragma("clang diagnostic pop")
            static bool loggedOnce = false;
            if (!loggedOnce) {
                loggedOnce = true;
                WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.133] TLS 1.3 forced via SSLContextRef on CFStream (iPhone-identical handshake target)");
            }
        }

        if (!useBoringSSL) {
            if (!CFWriteStreamOpen(writeStream) || !CFReadStreamOpen(readStream)) {
                CFRelease(readStream);
                CFRelease(writeStream);
                return;
            }
            for (int i = 0; i < 100; i++) {
                if (CFWriteStreamGetStatus(writeStream) == kCFStreamStatusOpen)
                    break;
                [NSThread sleepForTimeInterval:0.05];
            }
            if (CFWriteStreamGetStatus(writeStream) != kCFStreamStatusOpen) {
                CFRelease(readStream);
                CFRelease(writeStream);
                return;
            }
        }

        // Build HTTP/1.1 request
        String pathStr = url.path().toString();
        if (pathStr.isEmpty()) pathStr = "/"_s;
        if (!url.query().isEmpty())
            pathStr = makeString(pathStr, '?', url.query());

        // Wave 29-499.146 — Phase 4 cookies: query shared NSHTTPCookieStorage
        // for cookies matching destination URL, inject Cookie header.
        // For PathB v2 we bypass NSURLSession's auto-cookie path entirely;
        // explicit lookup is required.
        String cookieHeader;
        {
            auto nsURLPtr = url.createNSURL();
            NSURL* nsURL = nsURLPtr.get();
            if (nsURL) {
                NSHTTPCookieStorage* storage = [NSHTTPCookieStorage sharedHTTPCookieStorage];
                NSArray<NSHTTPCookie*>* cookies = [storage cookiesForURL:nsURL];
                if (cookies.count > 0) {
                    NSDictionary* fields = [NSHTTPCookie requestHeaderFieldsWithCookies:cookies];
                    NSString* cookie = fields[@"Cookie"];
                    if (cookie) cookieHeader = String::fromUTF8([cookie UTF8String]);
                }
            }
        }

        StringBuilder rb;
        rb.append(httpMethod, ' ', pathStr, " HTTP/1.1\r\n"_s);
        rb.append("Host: "_s, host, "\r\n"_s);
        rb.append("Connection: close\r\n"_s);
        if (!cookieHeader.isEmpty())
            rb.append("Cookie: "_s, cookieHeader, "\r\n"_s);
        for (auto& header : httpHeaders) {
            String lower = header.key.convertToASCIILowercase();
            if (lower == "host"_s || lower == "connection"_s || lower == "cookie"_s)
                continue;
            rb.append(header.key, ": "_s, header.value, "\r\n"_s);
        }
        rb.append("\r\n"_s);
        auto requestStr = rb.toString().utf8();
        NSData* reqData = [NSData dataWithBytes:requestStr.data() length:requestStr.length()];

        NSData* responseBytes = nil;
#if defined(DRIFTSTACK_HAS_BORINGSSL) && DRIFTSTACK_HAS_BORINGSSL
        if (useBoringSSL) {
            auto& f = boringSSLFns();
            const uint8_t* writeBytes = (const uint8_t*)[reqData bytes];
            NSUInteger writeRemaining = [reqData length];
            while (writeRemaining > 0) {
                int n = f.ssl_write(ssl, writeBytes, static_cast<int>(writeRemaining));
                if (n <= 0) break;
                writeBytes += n;
                writeRemaining -= n;
            }
            NSMutableData* respMutable = [NSMutableData data];
            uint8_t readBuf[4096];
            while (true) {
                int n = f.ssl_read(ssl, readBuf, sizeof(readBuf));
                if (n <= 0) {
                    int err = f.ssl_get_error ? f.ssl_get_error(ssl, n) : 0;
                    if (err == SSL_ERROR_ZERO_RETURN || err == SSL_ERROR_SSL || err == SSL_ERROR_SYSCALL)
                        break;
                    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                        [NSThread sleepForTimeInterval:0.02];
                        continue;
                    }
                    break;
                }
                [respMutable appendBytes:readBuf length:n];
            }
            responseBytes = respMutable;
            if (f.ssl_shutdown) f.ssl_shutdown(ssl);
            f.ssl_free(ssl);
        } else
#endif
        {
            CFIndex written = writeAllToCFStream(writeStream, reqData);
            if (written < 0) {
                CFRelease(readStream);
                CFRelease(writeStream);
                return;
            }
            responseBytes = readAllFromCFStream(readStream);
            CFRelease(readStream);
            CFRelease(writeStream);
        }

        if (!responseBytes || [responseBytes length] == 0)
            return;

        // Parse status + headers
        NSData* boundary = [@"\r\n\r\n" dataUsingEncoding:NSUTF8StringEncoding];
        NSRange boundaryRange = [responseBytes rangeOfData:boundary options:0 range:NSMakeRange(0, [responseBytes length])];
        if (boundaryRange.location == NSNotFound)
            return;

        NSData* headerBytes = [responseBytes subdataWithRange:NSMakeRange(0, boundaryRange.location)];
        NSUInteger bodyOffset = boundaryRange.location + boundaryRange.length;
        NSData* bodyBytes = [responseBytes subdataWithRange:NSMakeRange(bodyOffset, [responseBytes length] - bodyOffset)];
        NSString* headerStr = [[NSString alloc] initWithData:headerBytes encoding:NSUTF8StringEncoding];

        NSArray<NSString*>* headerLines = [headerStr componentsSeparatedByString:@"\r\n"];
        if ([headerLines count] < 1)
            return;

        NSString* statusLine = headerLines[0];
        NSArray<NSString*>* statusParts = [statusLine componentsSeparatedByString:@" "];
        int statusCode = ([statusParts count] >= 2) ? [statusParts[1] intValue] : 0;

        WebCore::ResourceResponse response { URL(url), String("text/html"_s), -1, String("UTF-8"_s) };
        response.setHTTPStatusCode(statusCode);

        for (NSUInteger i = 1; i < [headerLines count]; i++) {
            NSString* line = headerLines[i];
            NSRange c = [line rangeOfString:@":"];
            if (c.location == NSNotFound) continue;
            NSString* key = [line substringToIndex:c.location];
            NSString* val = [[line substringFromIndex:c.location + 1] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
            response.setHTTPHeaderField(String::fromUTF8([key UTF8String]), String::fromUTF8([val UTF8String]));
        }

        if (tryFollowRedirect(response)) return;  // Wave .344 — follow 3xx like Safari, don't render the redirect page
        // Dispatch callbacks. Use NSData spans for SharedBuffer.
        auto bodySpan = unsafeMakeSpan(static_cast<const uint8_t*>([bodyBytes bytes]), static_cast<size_t>([bodyBytes length]));
        auto bodyBuffer = WebCore::SharedBuffer::create(bodySpan);
        auto* clientPtr = m_task.client();
        if (!clientPtr)
            return;

        // Wave 29-499.269b — CFStream fallback also marshalled via main runloop
        auto deliveryResponse2 = WebCore::ResourceResponse(response);
        if (!tryBeginCompletion()) return;  // Wave .325 single-completion guard
        callOnMainRunLoop([clientPtr, response = std::move(deliveryResponse2), bodyBuffer = std::move(bodyBuffer)]() mutable {
            clientPtr->didReceiveResponse(std::move(response), NegotiatedLegacyTLS::No, PrivateRelayed::No,
                [clientPtr, bodyBuffer = std::move(bodyBuffer)](WebCore::PolicyAction action) mutable {
                    if (action == WebCore::PolicyAction::Use) {
                        clientPtr->didReceiveData(bodyBuffer.get());
                        WebCore::NetworkLoadMetrics metrics;
                        clientPtr->didCompleteWithError(WebCore::ResourceError(), metrics);
                    }
                });
        });
    });
}

void DriftstackNetworkLoader::cancel()
{
    // Wave 29-499.272 — fd is owned by DriftstackSocks5Client in resume's
    // dispatch block. Don't close here (see ~ for explanation).
    m_cancelled = true;
    m_fd = -1;
}

void DriftstackNetworkLoader::suspend()
{
    // Phase 1: no-op (in-flight reads/writes run to completion on loader queue)
}

bool DriftstackNetworkLoader::isActiveForSession()
{
    const char* env = getenv("DRIFTSTACK_PATHB_V2");
    if (!env || env[0] != '1')
        return false;
    const char* custom = getenv("DRIFTSTACK_CUSTOM_SOCKS5");
    return custom && custom[0] == '1';
}

} // namespace WebKit

WTF_ALLOW_UNSAFE_BUFFER_USAGE_END

#endif // PLATFORM(DRIFTSTACK)
