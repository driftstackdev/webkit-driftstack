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
#import <wtf/FileSystem.h>
#import <wtf/HashSet.h>
#import <wtf/MonotonicTime.h>
#import <wtf/Scope.h>
#import <wtf/Lock.h>
#import <wtf/NeverDestroyed.h>
#import <wtf/OSObjectPtr.h>

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
// PathB v2 ITP: cookie filtering + 3rd-party referer downgrade (match real iPhone NSURLSession path).
#import <WebCore/NetworkStorageSession.h>   // cookieRequestHeaderFieldValue + ApplyTrackingPrevention/IsKnownCrossSiteTracker enums
#import <WebCore/RegistrableDomain.h>       // BUG-42 (#42) areRegistrableDomainsEqual — robust cross-origin (3p) detection on the PathB-v2 loader
#import <WebCore/SecurityOrigin.h>          // BUG-42 (#42) NetworkLoadParameters::sourceOrigin → authoritative initiator origin (firstParty fallback)
#import <WebCore/SameSiteInfo.h>            // SameSiteInfo::create(ResourceRequest&)
#import <WebCore/CookieJar.h>               // full enum class IncludeSecureCookies { No, Yes }
#import "NetworkProcess.h"                  // shouldRelaxThirdPartyCookieBlockingForPage (precedent: NetworkDataTask.cpp:33)
#import "NetworkSession.h"                  // networkStorageSession / networkProcess / isResourceFromKnownCrossSiteTracker
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

// Wave 29-499.349 — the custom TLS client is no longer a thread_local global;
// it's owned per-connection by a stack-local in resume() and handed back from
// driftstackTLSConnect via an out-param (fixes V-XORIGIN-FETCH-CONCURRENCY-RACE
// where concurrent loads on reused GCD threads clobbered each other's client).
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

        // FIX 5 — iOS Safari TCP ALPN = ["h2","http/1.1"] exactly (2 entries, 12/12
        // captures). h3 is QUIC-only and NEVER appears in a TCP ClientHello; advertising
        // it here was a TLS-ALPN tell on this LibreSSL fallback path. (Dead in prod since
        // DRIFTSTACK_PATHB_V2_CUSTOM_TLS=1 routes through the custom builder's makeExtALPN,
        // which already emits h2,http/1.1 — fixed here for safety on the fallback path.)
        static const uint8_t alpn[] = {
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

        // egress audit wxzzaphvp (defense-in-depth): this LibreSSL context backs ONLY the fallback
        // path (driftstackTLSConnect when DRIFTSTACK_PATHB_V2_CUSTOM_TLS != 1) — never used in
        // production, which always runs custom TLS (DriftstackTLS13Client) with its own chain+hostname
        // validation. It previously set SSL_VERIFY_NONE "for empirical JA3 verification", which trusts
        // ANY server certificate (a latent MITM hole). Use SSL_VERIFY_PEER (0x01, stable across
        // OpenSSL/LibreSSL/BoringSSL): combined with ssl_set1_host(hostUtf8) in driftstackTLSConnect,
        // LibreSSL verifies the chain AND hostname and ABORTS the handshake on failure (→ SSL_connect
        // fails → nullptr), so this path can never egress over an unauthenticated TLS session — it
        // fails safe rather than trusting silently if no trust anchors are loaded.
        // TODO (to make the fallback usable, not just safe): load macOS Keychain CAs via
        // SecTrustCopyAnchorCertificates + SSL_CTX_set_cert_store.
        if (f.ssl_ctx_set_verify)
            f.ssl_ctx_set_verify(g_driftstackSslCtx, 0x01 /* SSL_VERIFY_PEER */, nullptr);

        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.139] BoringSSL SSL_CTX initialized: TLS 1.3 + iPhone cipher order + ALPN[h3,h2,h1] + X25519MLKEM768");
    });
}

[[maybe_unused]] static SSL* driftstackTLSConnect(int fd, const char* hostUtf8, std::unique_ptr<DriftstackTLS13Client>& outCustomClient, bool& outPermanentFailure)
{
    outPermanentFailure = false;
    // Wave 29-499.176 — if DRIFTSTACK_PATHB_V2_CUSTOM_TLS=1, send iPhone-
    // byte-exact ClientHello via DriftstackTLS13Client BEFORE the library
    // handshake. This places the iPhone-matched bytes on the wire so
    // detection vendors (tls.peet.ws) capture iPhone JA3. The library
    // handshake on the same socket would conflict — close + reconnect.
    static const char* customTlsEnv = getenv("DRIFTSTACK_PATHB_V2_CUSTOM_TLS");
    bool useCustomTLS = customTlsEnv && customTlsEnv[0] == '1';

    if (useCustomTLS) {
        // Wave 29-499.193 — persist client past handshake so HTTP/2 layer can
        // route reads/writes through our custom TLS instead of LibreSSL.
        // Wave 29-499.349 — hand the client back to the CALLER (per-connection
        // local, owned on its stack) instead of a thread_local, so concurrent
        // loads can't clobber each other's TLS client.
        std::unique_ptr<DriftstackTLS13Client> client(new DriftstackTLS13Client());
        if (client->connect(fd, String::fromUTF8(hostUtf8))) {
            WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.193] Custom TLS 1.3 handshake COMPLETE. Returning sentinel.");
            outCustomClient = std::move(client);
            static uint8_t sentinel = 0xCC;
            return reinterpret_cast<SSL*>(&sentinel);
        }
        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.193] Custom TLS handshake failed: %s", client->errorMessage().utf8().data());
        // egress HRR (2026-07-02): propagate the fast-fail signal (a deterministic post-HRR CH2
        // reject) BEFORE `client` is destroyed, so resume()'s retry loop can skip 8 identical CH2s.
        outPermanentFailure = client->permanentFailure();
        // Wave 29-499.350 — do NOT fall back to LibreSSL when custom TLS is enabled.
        // Two reasons: (1) CRASH — the LibreSSL fallback uses the shared global
        // g_driftstackSslCtx; under the CONCURRENT loaderQueue (e.g. browserleaks.com/tls
        // firing tls/tls10/tls11/tls12 fingerprint sub-fetches at once, several failing the
        // flaky-proxy PQ-ClientHello handshake and falling back together) concurrent
        // ssl_new/handshake/SSL_write on one SSL_CTX corrupts its shared state → SIGSEGV in
        // libssl SSL_write (KERN_INVALID_ADDRESS), which crashes the WHOLE NetworkProcess →
        // every in-flight fetch dies → the page shows ja3/ja4/extensions = "fetch error".
        // (2) FINGERPRINT LIE — LibreSSL emits a non-iPhone ClientHello. Returning null here
        // makes resume()'s retry (Wave .271) re-attempt CUSTOM TLS on a FRESH SOCKS5 exit,
        // which is what actually fixes the intermittent flaky-proxy handshake failures.
        return nullptr;
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
// W3069 — HTTP/1.1 keep-alive-safe read framing. Returns true once the FULL response
// message is buffered in [buf, len). With Connection: keep-alive (W3068) the server does
// NOT close after the response, so a read-until-FIN loop would block until the idle
// timeout. The h1 read loops call this incrementally (after each read) and stop on the
// message framing instead of on EOF:
//   • leading interim 1xx responses (100 Continue / 103 Early Hints) are SKIPPED (W3073): a 1xx is
//     interim (RFC 7230 §3.3 / RFC 8297) and is followed by another response, so framing is done on
//     the FINAL (>=200) response, not the 1xx block,
//   • no-body FINAL responses (HEAD request; 204/304 status, RFC 7230 §3.3.3) → done at the
//     header terminator regardless of any Content-Length,
//   • Transfer-Encoding: chunked → done once the terminating 0-size chunk (+ trailer CRLF)
//     is present (takes precedence over Content-Length per RFC 7230 §3.3.3),
//   • Content-Length: N → done once N body bytes follow the header terminator,
//   • otherwise (neither framing, or the server answered Connection: close) → returns false
//     forever so the caller falls back to read-until-FIN (bounded by the existing idle
//     deadline). Never inspects bytes past what the message frames; safe to over-call.
static bool driftstackH1MessageComplete(const uint8_t* buf, size_t len, const String& method)
{
    // W3073 — locate the FINAL response's header block, SKIPPING any leading interim 1xx blocks. A
    // 1xx (100 Continue / 103 Early Hints, RFC 7230 §3.3 / RFC 8297) is INTERIM: its own header
    // terminator does NOT end the message — another (>=200) response follows. Framing the message on
    // the 1xx block would stop the read loop before the real 200+body arrives (empty/broken page).
    // So advance a start offset past each 1xx header block and re-parse from the next one.
    size_t hdrEnd = 0;          // index just past the FINAL block's CRLFCRLF (== body start)
    int statusCode = 0;
    Vector<String> lines;
    size_t blockStart = 0;
    for (;;) {
        // Locate the header terminator CRLFCRLF at/after blockStart.
        bool haveHdrEnd = false;
        if (len >= blockStart + 4) {
            for (size_t i = blockStart + 3; i < len; ++i) {
                if (buf[i - 3] == '\r' && buf[i - 2] == '\n' && buf[i - 1] == '\r' && buf[i] == '\n') {
                    hdrEnd = i + 1;
                    haveHdrEnd = true;
                    break;
                }
            }
        }
        if (!haveHdrEnd)
            return false; // (final) headers not fully received yet

        // W3074 — decode header bytes with a Latin-1 FALLBACK, not strict UTF-8. HTTP/1.1 field
        // values may legally carry obs-text (0x80-0xFF ISO-8859-1, RFC 7230 §3.2.6 — legacy
        // Content-Disposition filename, Set-Cookie, Server). String::fromUTF8 returns a NULL String
        // on any non-UTF-8 byte → split() empty → lines.isEmpty() → the message is unframable forever
        // (60s stall / permanent hang). A real iPhone decodes headers as Latin-1.
        String headerBlock = String::fromUTF8WithLatin1Fallback(std::span<const uint8_t> { buf + blockStart, hdrEnd - blockStart });
        lines = headerBlock.split("\r\n"_s);
        if (lines.isEmpty())
            return false;
        Vector<String> statusParts = lines[0].split(' ');
        statusCode = statusParts.size() >= 2 ? parseInteger<int>(statusParts[1]).value_or(0) : 0;
        // W3073 — interim 1xx → skip this block and re-frame on the next. A non-1xx status (incl. an
        // unparseable 0) is the FINAL response; fall through to frame on it.
        if (statusCode >= 100 && statusCode < 200) {
            blockStart = hdrEnd;
            continue;
        }
        break;
    }

    // Parse framing headers from the FINAL response block's lines only.
    long long contentLength = -1;
    bool chunked = false;
    for (size_t i = 1; i < lines.size(); ++i) {
        size_t colon = lines[i].find(':');
        if (colon == notFound)
            continue;
        String name = lines[i].left(colon).trim(deprecatedIsSpaceOrNewline);
        String value = lines[i].substring(colon + 1).trim(deprecatedIsSpaceOrNewline);
        if (equalIgnoringASCIICase(name, "content-length"_s)) {
            if (contentLength < 0)
                contentLength = parseInteger<long long>(value).value_or(-1); // first valid Content-Length wins
        } else if (equalIgnoringASCIICase(name, "transfer-encoding"_s)) {
            if (value.containsIgnoringASCIICase("chunked"_s))
                chunked = true;
        }
    }

    const size_t bodyStart = hdrEnd;
    const size_t bodyLen = len - bodyStart;

    // No message body regardless of framing headers (RFC 7230 §3.3.3) — else a HEAD/204/304
    // with a Content-Length that describes the would-be GET body would wait for bytes that
    // never arrive on keep-alive. W3073 — 1xx is handled above (skipped, never terminal here); the
    // genuine no-body terminals are the FINAL response's own HEAD/204/304.
    if (equalIgnoringASCIICase(method, "HEAD"_s)
        || statusCode == 204 || statusCode == 304)
        return true;

    if (chunked) {
        // Walk the chunk framing (mirrors the downstream de-chunker) until the 0-size last
        // chunk + its trailing (possibly empty) trailer section terminates the message.
        const uint8_t* p = buf + bodyStart;
        size_t n = bodyLen, i = 0;
        while (i < n) {
            size_t j = i;
            while (j + 1 < n && !(p[j] == '\r' && p[j + 1] == '\n'))
                ++j;
            if (j + 1 >= n)
                return false; // chunk-size line not fully buffered
            size_t chunkSize = 0;
            bool anyHex = false;
            for (size_t k = i; k < j; ++k) {
                uint8_t c = p[k];
                int d;
                if (c >= '0' && c <= '9') d = c - '0';
                else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
                else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
                else break; // ';' chunk-ext / trailing ws ends the size token
                chunkSize = chunkSize * 16 + d;
                anyHex = true;
                if (chunkSize > n)
                    return false; // bigger than everything buffered → wait for more (also caps overflow)
            }
            if (!anyHex)
                return false; // malformed size line → let read-until-FIN / idle deadline bound it
            i = j + 2; // past the size-line CRLF
            if (!chunkSize) {
                // last-chunk: optional trailers, then a terminating empty line.
                while (i < n) {
                    size_t t = i;
                    while (t + 1 < n && !(p[t] == '\r' && p[t + 1] == '\n'))
                        ++t;
                    if (t + 1 >= n)
                        return false; // trailer line not fully buffered
                    if (t == i)
                        return true; // empty line → end of trailers → message complete
                    i = t + 2;
                }
                return false; // terminating CRLF not yet buffered
            }
            if (i + chunkSize + 2 > n)
                return false; // chunk data + its trailing CRLF not fully buffered
            i += chunkSize;
            if (!(p[i] == '\r' && p[i + 1] == '\n'))
                return false; // broken framing → wait for more / FIN
            i += 2;
        }
        return false; // ran out of buffered bytes before the 0-size last chunk
    }

    if (contentLength >= 0)
        return static_cast<long long>(bodyLen) >= contentLength;

    // Neither Content-Length nor chunked (or the server chose Connection: close) → the
    // message is delimited by connection close; keep reading until FIN (caller's fallback).
    return false;
}

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

static NSData* readAllFromCFStream(CFReadStreamRef readStream, const String& method)
{
    NSMutableData* data = [NSMutableData data];
    uint8_t buffer[4096];
    // W3085 (audit wxbeah3ef): the customTLS/BoringSSL h1 loops got a 60s idle deadline (W3051/W2988)
    // and the h2/h3 transports cap the body at 128MB, but this plaintext-http CFStream fallback had
    // NEITHER. A no-framing keep-alive server that stalls without FIN busy-looped here forever (pinned
    // GCD worker + admission slot); a hostile/huge chunked or Content-Length body accumulated unbounded
    // → NetworkProcess OOM. Bound both: 60s no-progress → stop; 128MB total → stop (return the bounded
    // body; truncation beats OOMing the shared multi-tenant NetworkProcess).
    static const NSUInteger kH1MaxBodyBytes = 128u * 1024u * 1024u;
    const Seconds kH1Idle = Seconds(60);
    MonotonicTime idleDeadline = MonotonicTime::now() + kH1Idle;
    while (true) {
        CFIndex n = CFReadStreamRead(readStream, buffer, sizeof(buffer));
        if (n < 0) return nil;
        if (n == 0) {
            // EOF
            CFStreamStatus status = CFReadStreamGetStatus(readStream);
            if (status == kCFStreamStatusAtEnd || status == kCFStreamStatusClosed)
                break;
            if (status == kCFStreamStatusError) return nil;
            if (MonotonicTime::now() >= idleDeadline)   // W3085: 60s no-progress → abandon (was unbounded)
                break;
            // Not yet at EOF, more data may arrive; brief sleep then retry
            [NSThread sleepForTimeInterval:0.01];
            continue;
        }
        [data appendBytes:buffer length:n];
        idleDeadline = MonotonicTime::now() + kH1Idle;   // W3085: progress → extend the no-progress window
        if ([data length] > kH1MaxBodyBytes)             // W3085: 128MB cap → OOM guard (match h2/h3)
            break;
        // W3069 — keep-alive-safe: stop once the full HTTP/1.1 message is framed. With
        // Connection: keep-alive (W3068) the server won't FIN, so waiting for EOF above would
        // hang until the idle timeout. Falls back to read-until-EOF when the response declares
        // neither Content-Length nor chunked framing (returns false forever there).
        if (driftstackH1MessageComplete((const uint8_t*)[data bytes], [data length], method))
            break;
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

// W2202 STEP 5: upgrade the ThreadSafeWeakPtr to a strong RefPtr — null if the task was destroyed (it dies on
// the main thread; this must be called ON the main thread before touching client()). Defined here where
// NetworkDataTaskCocoa is a complete type.
RefPtr<NetworkDataTaskCocoa> DriftstackNetworkLoader::protectedTask() const
{
    return m_task.get();
}

// BUG-42 Fix #2 — forward decl: the admission semaphore's definition lives below (next
// to the handshake-cap semaphore), but the acquire/release member definitions just below
// reference it.
static dispatch_semaphore_t driftstackRequestAdmissionSemaphore();

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

    // BUG-42 Fix #2 — final safety-net release of the concurrent-request admission slot.
    // The terminal path (tryBeginCompletion) and cancel() normally release it, but a
    // loader can be dropped on a path that completes neither (e.g. the m_cancelled
    // early-return at the top of the dispatch block, or a task-gone early return that
    // doesn't begin completion). Releasing here guarantees no slot is ever leaked across
    // the loader's whole lifetime. Idempotent: only signals if a slot is still held.
    releaseAdmissionSlot();
}

// BUG-42 Fix #2 — MAIN-THREAD non-blocking try-acquire of a process-wide admission slot.
// Returns true (slot now held) or false (cap saturated → caller should defer, never
// block the main thread). Acquired ONCE per logical request: the m_admissionSlotHeld
// guard means retries/redirects that re-enter resume() keep the slot they already hold
// and never double-acquire. Caller has confirmed the egress-reliability gate is on.
bool DriftstackNetworkLoader::tryAcquireAdmissionSlot()
{
    if (m_admissionSlotHeld.load())
        return true; // already admitted (a retry/redirect re-resume) — keep the held slot
    // Non-blocking: DISPATCH_TIME_NOW try-wait. A slot held by THIS process's other
    // in-flight requests means we bail to a deferred re-resume rather than parking here.
    if (dispatch_semaphore_wait(driftstackRequestAdmissionSemaphore(), DISPATCH_TIME_NOW) == 0) {
        m_admissionSlotHeld.store(true);
        return true;
    }
    return false;
}

// BUG-42 Fix #2 — idempotent release. CAS true→false so exactly one of {terminal
// completion, cancel, destructor} signals the semaphore for a given loader, regardless
// of which fires first or how many fire. Safe from any thread (the signal hop and the
// terminal completion both originate on loaderQueue; cancel/destructor on the main
// thread). Gate-off no-op: m_admissionSlotHeld is never set when the gate is off.
void DriftstackNetworkLoader::releaseAdmissionSlot()
{
    bool expected = true;
    if (m_admissionSlotHeld.compare_exchange_strong(expected, false))
        dispatch_semaphore_signal(driftstackRequestAdmissionSemaphore());
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

// BUG-42 egress-reliability arc — ONE master gate for the proxy/custom-HTTP-client
// reliability fixes (the no-UDP-latch local-vs-upstream split + the global
// cross-origin handshake cap). DEFAULT-OFF: when unset, every change below is a
// true no-op and the egress path (TLS/QUIC wire bytes, fingerprint, routing) is
// byte-identical to the prior code. Flipped to "1" only after a coordinated build
// + a non-UDP-proxy live-confirm (see docs/internal/BUG-42-egress-latch-diagnosis.md).
static bool driftstackEgressReliabilityEnabled()
{
    static const bool enabled = [] {
        const char* e = getenv("DRIFTSTACK_EGRESS_RELIABILITY");
        WTFLogAlways("[BUG-42/EgressReliability] DRIFTSTACK_EGRESS_RELIABILITY=%s", e ?: "(null)");
        return e && e[0] == '1';
    }();
    return enabled;
}

// #46 (founder heavy-page / slow-proxy fix) — DEDICATED gate for the PURE ADMISSION-PACING
// bounds (request-admission cap Fix #2 + handshake cap Fix #4 + 3p fast-fail + per-page
// deadline). These change ZERO wire bytes (ClientHello/cipher/curve/ALPN/header order,
// routing all unchanged) — they are the RANK-1 fix for the founder's heavy-page hang:
// PathB-v2 is blocking-thread-per-request, so a many-origin page parks all ~64 GCD workers,
// the concurrent loaderQueue stops scheduling, and subresources never start their connect.
// They were dead in prod only because they shared DRIFTSTACK_EGRESS_RELIABILITY with the
// WIRE-AFFECTING reliability tweaks that were reverted (W2994). This split lets the pure-
// pacing bounds ship independently: DRIFTSTACK_EGRESS_CONCURRENCY=1 enables them with NO
// fingerprint/wire change.
static bool driftstackConcurrencyGovernorEnabled()
{
    static const bool enabled = [] {
        const char* e = getenv("DRIFTSTACK_EGRESS_CONCURRENCY");
        WTFLogAlways("[#46/ConcurrencyGovernor] DRIFTSTACK_EGRESS_CONCURRENCY=%s", e ?: "(null)");
        return e && e[0] == '1';
    }();
    return enabled;
}

// The pure-pacing bounds fire under EITHER the legacy egress-reliability master gate OR the
// new dedicated concurrency-governor gate. Acquire/release stay paired (the admission slot
// is flag-tracked via m_admissionSlotHeld; the handshake cap via a scoped release), so
// toggling the gate never strands a semaphore slot.
static bool driftstackAdmissionPacingEnabled()
{
    return driftstackEgressReliabilityEnabled() || driftstackConcurrencyGovernorEnabled();
}

// a74622fc Phase 1 — the h2-pool fast path calls DriftstackHttp2Session::submitAsync()
// instead of the blocking execute() when set, freeing the calling GCD worker immediately
// instead of pinning it for the full response duration (the westernunion/facebook
// heavy-multi-origin-page hang root cause: NO real-iOS analog, NSURLSession is
// event-driven). Default OFF: gate-off path is byte-identical to before this change.
static bool driftstackAsyncDeliveryEnabled()
{
    static bool enabled = [] {
        const char* env = getenv("DRIFTSTACK_EGRESS_ASYNC_DELIVERY");
        bool on = env && env[0] == '1';
        WTFLogAlways("[a74622fc/AsyncDelivery] DRIFTSTACK_EGRESS_ASYNC_DELIVERY=%s -> %s", env ? env : "(null)", on ? "ON" : "off");
        return on;
    }();
    return enabled;
}

// BUG-42 Fix #4 — process-wide concurrent-handshake cap. The custom loader has NO
// global connection cap; H2/H3 pools coalesce only per-origin, so a heavy multi-
// origin site opens dozens of concurrent SOCKS5 + ML-KEM-768 TLS handshakes on the
// concurrent loaderQueue → relay/thread-pool saturation. Bound the number of
// *fresh* connect+TLS handshakes in flight across all origins to ~Safari's total
// (~17 minus same-origin coalescing already handled by the pools). Pacing ONLY:
// changes no wire bytes (ClientHello/cipher/curve order, header order, ALPN), no
// routing — every handshake still goes through the same loopback gost relay. The
// cap wraps ONLY the winner/own-connect fresh-connection path; fast-path multiplex
// and pooled reuse never touch it. Released via WTF::makeScopeExit on every exit
// path, plus an explicit release right after the H2 winner publishes its session
// (before its first execute) so the first multiplexed request isn't throttled.
// Gate-off no-op: when DRIFTSTACK_EGRESS_RELIABILITY is unset the acquire/release
// are skipped entirely, so the path is byte-identical to the prior code.
static dispatch_semaphore_t driftstackHandshakeCapSemaphore()
{
    static dispatch_semaphore_t sem = dispatch_semaphore_create(10);
    return sem;
}

// BUG-42 Fix #2 — process-wide concurrent-REQUEST admission semaphore (the durable,
// structural bound). UNLIKE the handshake cap above (Fix #4), which bounds only the
// fresh-connect+TLS portion FROM INSIDE an already-dispatched block — so it wastes a
// committed GCD worker thread parked in dispatch_semaphore_wait while throttled — this
// cap is acquired on the MAIN thread BEFORE the dispatch_async submission. Each
// PathB-v2 request pins ONE GCD worker for its ENTIRE blocking life (SOCKS5 + ML-KEM
// TLS + the ≤60s h2/h3 response wait), so the ~64-worker libdispatch ceiling otherwise
// becomes a hard total-in-flight-request cap: a many-origin page (browserleaks
// DNS-leak-test = dozens of unique subdomains; westernunion = a swarm of distinct 3p
// origins) enqueues dozens-to-hundreds of blocking blocks, ~64 workers park, the
// concurrent loaderQueue STOPS scheduling new blocks, and subresources never even start
// their connect (the founder's stall). Bounding admitted in-flight requests to 40 — below
// the ~64 ceiling with headroom — guarantees the queue always has spare workers to keep
// scheduling, so the swarm can never starve itself. On saturation the caller does NOT
// block (resume() runs on the main thread): it re-schedules itself on the main queue
// after a short backoff, so no worker and no main-thread stall while waiting. Pure
// admission pacing: changes no wire bytes (ClientHello/cipher/curve/ALPN/header order),
// no routing — every request still egresses identically through the same gost relay.
// Tunable via DRIFTSTACK_EGRESS_REQUEST_CAP. Gate-off no-op: acquire/release are skipped
// entirely when DRIFTSTACK_EGRESS_RELIABILITY is unset (m_admissionSlotHeld stays false),
// so the path is byte-identical to the prior code.
static dispatch_semaphore_t driftstackRequestAdmissionSemaphore()
{
    static dispatch_semaphore_t sem = [] {
        long cap = 24;  // #46: 24 (was 40) — on a slow proxy each request pins its GCD worker up to 60s, so a 40-cap still allows 40 simultaneous 60s blocks; 24 leaves the ~64-worker pool comfortable headroom AND approximates iOS's bounded-but-warm working set (6/h1-origin + a handful of h2 origins). Override via DRIFTSTACK_EGRESS_REQUEST_CAP.
        if (const char* e = getenv("DRIFTSTACK_EGRESS_REQUEST_CAP")) {
            long parsed = atol(e);
            if (parsed >= 4 && parsed <= 60)
                cap = parsed;
        }
        WTFLogAlways("[BUG-42/Fix2] request-admission cap = %ld (below the ~64 GCD ceiling)", cap);
        return dispatch_semaphore_create(cap);
    }();
    return sem;
}

// BUG-42 Fix #6 — per-PAGE aggregate retry deadline (heavy-site navigate timeout).
// The existing W2750 budget (m_retryDeadline) is PER-REQUEST (20s, set on attempt
// 1 of each loader). On a slow proxy, a heavy multi-origin page (westernunion-class:
// cookielaw/quantummetric/amplitude preconnect storm) spreads its retry chains
// across DOZENS of concurrent subresource loaders, EACH of which is independently
// allowed to burn its own ~20s. The aggregate page-load wall-clock is therefore
// unbounded (≈ slowest-tail × however-many-stalling-subresources), so the WD
// navigate times out before the load settles. Introduce a single page-level
// deadline shared across every request belonging to the same WebPageProxyIdentifier:
// the FIRST request for a page stamps `now + budget`; every later request (and every
// retry) on that page is ALSO bounded by that shared deadline, so the page's total
// retry wall-clock can't compound past the budget. Keyed by the page-proxy id's
// raw uint64 so a redirect re-resume() / a fresh subresource loader all share one
// deadline. Pure pacing of the RETRY decision: it can only cause a stuck request to
// GIVE UP sooner (so the parser/onload can settle), never changes wire bytes,
// routing, or fingerprint. Gate-off no-op: every accessor early-returns when the
// egress-reliability gate is off, so the per-request budget is the only bound (the
// prior code) and behaviour is byte-identical.
//
// Budget rationale: 35s — comfortably above a healthy heavy-site full settle
// (~10-20s on a slow proxy) yet below a typical WD navigate ceiling (60-300s), so a
// genuinely-wedged tail of 3rd-party trackers bounds the navigate to a drivable
// page instead of a timeout. Tunable via DRIFTSTACK_EGRESS_PAGE_DEADLINE_SECS.
static Lock& driftstackPageDeadlineLock()
{
    static NeverDestroyed<Lock> lock;
    return lock.get();
}
static HashMap<uint64_t, MonotonicTime>& driftstackPageDeadlines()
{
    static NeverDestroyed<HashMap<uint64_t, MonotonicTime>> map;
    return map.get();
}
static Seconds driftstackPageDeadlineBudget()
{
    static const Seconds budget = [] {
        double secs = 35.0;
        if (const char* e = getenv("DRIFTSTACK_EGRESS_PAGE_DEADLINE_SECS")) {
            double parsed = atof(e);
            if (parsed >= 5.0 && parsed <= 600.0)
                secs = parsed;
        }
        return Seconds(secs);
    }();
    return budget;
}
// Return the shared deadline for `pageKey`, stamping `now + budget` on first sight.
// pageKey 0 (no WebPageProxyIdentifier — e.g. a non-page load) opts OUT: returns a
// null MonotonicTime so the caller applies no page-level bound. Caller has already
// confirmed the gate is on.
static MonotonicTime driftstackPageDeadlineFor(uint64_t pageKey)
{
    if (!pageKey)
        return { };
    Locker locker { driftstackPageDeadlineLock() };
    auto& map = driftstackPageDeadlines();
    auto it = map.find(pageKey);
    if (it != map.end())
        return it->value;
    // Opportunistic GC: a page key never sees an explicit "page done" signal at this
    // layer, so cap the map by evicting entries already well past their deadline
    // (a stale page can't share its deadline with a genuinely-new load reusing the id).
    if (map.size() > 64) {
        MonotonicTime now = MonotonicTime::now();
        Vector<uint64_t> expired;
        for (auto& entry : map) {
            if (now > entry.value + Seconds(120))
                expired.append(entry.key);
        }
        for (auto k : expired)
            map.remove(k);
    }
    MonotonicTime deadline = MonotonicTime::now() + driftstackPageDeadlineBudget();
    map.set(pageKey, deadline);
    return deadline;
}

// BUG-42 Fix #4 (this batch) — bounded retry budget for THIRD-PARTY parser-blocking
// fetches. pageLoadStrategy=eager still waits on DOMContentLoaded, which a slow
// parser-blocking 3rd-party tracker script in <head> (cookielaw/quantummetric/
// amplitude) stalls indefinitely on a flaky proxy → the navigate never reports
// "interactive"/load-complete and the WD navigate times out even in eager mode.
// We can't change the parser's blocking semantics from the NetworkProcess, but we
// CAN make a stuck 3rd-party (cross-origin) fetch FAIL FAST: a failed/aborted
// script load unblocks the HTML parser (the parser proceeds past a script whose
// load errored), letting DOMContentLoaded fire and the page become drivable.
// First-party requests keep the full W2750 budget (the main document + its own
// scripts must still be given every retry). Tunable via
// DRIFTSTACK_EGRESS_3P_DEADLINE_SECS. Gate-off no-op: only consulted when the
// egress-reliability gate is on; otherwise the original 20s applies to all requests.
static Seconds driftstackThirdPartyRetryBudget()
{
    static const Seconds budget = [] {
        double secs = 8.0;
        if (const char* e = getenv("DRIFTSTACK_EGRESS_3P_DEADLINE_SECS")) {
            double parsed = atof(e);
            if (parsed >= 1.0 && parsed <= 60.0)
                secs = parsed;
        }
        return Seconds(secs);
    }();
    return budget;
}

// BUG-42 (#42) — robust cross-origin (third-party) determination for the PathB-v2 loader.
// `ResourceRequestBase::isThirdParty()` is computed live as `url() vs firstPartyForCookies()`.
// On the custom-TLS egress path the loader's request copy empirically reads an EMPTY
// firstPartyForCookies for subresource trackers (the lazy Cocoa platform-sync of mainDocumentURL
// doesn't always carry through to the loader's copy), so `isThirdParty()` false-NEGATIVES on a
// genuine cross-origin tracker (westernunion's quantummetric/facebook/amplitude/optimizely/bing/
// pubmatic) → the 8s 3p fast-fail never engages and each tracker burns the full 8-attempt/20s
// budget → the 90s page hang. This recovers the signal from BOTH available sources and treats
// the request as third-party if EITHER says cross-origin: (1) the request's own firstParty (when
// populated), and (2) the initiating document's origin (NetworkLoadParameters::sourceOrigin —
// set unconditionally in the NetworkDataTaskCocoa ctor, never lazily synced). Conservative: only
// returns true when a non-empty reference origin's registrable domain DIFFERS from the request
// URL's. An unknown/empty/opaque reference → false (first-party-safe; keeps the full retry budget).
// MAIN THREAD ONLY (touches the request + task). Caller gates on the egress-reliability flag.
static bool driftstackRequestIsThirdParty(const WebCore::ResourceRequest& request, WebCore::SecurityOrigin* sourceOrigin)
{
    const URL& url = request.url();

    // (1) The request's own first-party-for-cookies, when the platform-sync populated it.
    const URL& firstParty = request.firstPartyForCookies();
    if (!firstParty.isNull() && !firstParty.isEmpty() && firstParty.isValid()) {
        if (!WebCore::areRegistrableDomainsEqual(url, firstParty))
            return true;
        // firstParty present AND same-site → trust it as first-party (don't override below).
        return false;
    }

    // (2) Fallback: the initiating document's origin (authoritative, ctor-set, non-lazy).
    if (sourceOrigin && !sourceOrigin->isOpaque()) {
        URL originURL = sourceOrigin->toURL();
        if (!originURL.isNull() && !originURL.isEmpty() && originURL.isValid())
            return !WebCore::areRegistrableDomainsEqual(url, originURL);
    }

    // No usable reference origin → first-party-safe (keep the full per-request budget).
    return false;
}

// BUG-42 (#42) — derive a stable per-PAGE key for Fix6's aggregate deadline. The preferred key is
// the WebPageProxyIdentifier (task->webPageProxyID()); but it empirically reads 0 on the PathB-v2
// loader path for the subresource storm where the retry chains actually live, so Fix6 never
// stamps/honours a page deadline. Fall back to a hash of the page's first-party/source-origin
// registrable domain so every subresource of the SAME page still shares one aggregate deadline.
// Returns 0 only when neither a page-proxy id NOR any reference origin is available (then Fix6
// opts out for that request, as before). MAIN THREAD ONLY. Caller gates on the egress flag.
static uint64_t driftstackPageKeyFor(uint64_t webPageProxyKey, const WebCore::ResourceRequest& request, WebCore::SecurityOrigin* sourceOrigin)
{
    if (webPageProxyKey)
        return webPageProxyKey;

    // Fall back to the page's registrable domain (first-party preferred, source-origin next).
    // High bit set so a domain-hash key can never collide with a real WebPageProxyIdentifier
    // (those are small monotonic counters), keeping the two keyspaces disjoint in the shared map.
    String registrableDomain;
    const URL& firstParty = request.firstPartyForCookies();
    if (!firstParty.isNull() && !firstParty.isEmpty() && firstParty.isValid())
        registrableDomain = WebCore::RegistrableDomain(firstParty).string();
    else if (sourceOrigin && !sourceOrigin->isOpaque()) {
        URL originURL = sourceOrigin->toURL();
        if (!originURL.isNull() && !originURL.isEmpty() && originURL.isValid())
            registrableDomain = WebCore::RegistrableDomain(originURL).string();
    }
    if (registrableDomain.isEmpty())
        return 0;
    return (static_cast<uint64_t>(registrableDomain.hash()) | (1ULL << 63));
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
// W3046 (FOUNDER westernunion): per-origin H2 GOAWAY-churn circuit-breaker. Some origins — session-replay
// beacon endpoints like ingest.quantummetric.com — GOAWAY-retire EVERY H2 session after 1-few streams, so
// each pooled reuse fails (session dead) → fresh connect → re-adopt → GOAWAY → churn. On a heavy page
// (westernunion) that STORMS the slow proxy with 500+ connects (~255 failed-reuse + ~255 fresh), saturating
// the shared admission (40) + handshake (10) caps so the page's REAL content queues behind the beacon storm
// → "loads slowly / doesn't properly load". Track per-origin CONSECUTIVE pooled-reuse failures; once an
// origin churns >= kH2ChurnThreshold, STOP pooling it (skip reuse + skip re-adopt) so its beacons go DIRECT
// (one connect each, no wasted failed-reuse) — halves the storm + stops the adopt/fail loop. Reset on any
// successful pooled reuse (origin recovered). Process-global; guarded by the existing pool lock.
static HashMap<String, std::pair<unsigned, MonotonicTime>>& driftstackH2ChurnMap()
{
    static NeverDestroyed<HashMap<String, std::pair<unsigned, MonotonicTime>>> m;
    return m.get();
}
static constexpr unsigned kH2ChurnThreshold = 3;
// W3084 (audit wxbeah3ef): the breaker must SELF-HEAL. A churning origin SKIPS the pool, so it
// takes no further strikes — without a decay it latches OPEN for the whole (long-lived, per-customer-
// session) NetworkProcess, permanently denying H2 reuse/multiplexing to an origin that only had a
// transient GOAWAY burst (a deploy/restart) and has since fully recovered. Every subresource then
// pays a fresh SOCKS5+TLS handshake through the slow customer proxy — the exact "loads slowly"
// symptom W3046 was meant to prevent, now inverted and permanent. Decay: once no NEW strike has
// landed within kH2ChurnCooldown, report not-churning so ONE pooled reuse re-probes the origin — a
// recovered origin's reuse succeeds → NoteHealthy clears it; a chronic GOAWAY beacon's reuse
// re-fails → NoteChurn re-arms the breaker (≤1 re-probe per cooldown = negligible vs the original storm).
static const Seconds kH2ChurnCooldown = Seconds(45);
[[maybe_unused]] static bool driftstackH2OriginChurning(const String& origin)
{
    Locker locker { driftstackH2PoolLock() };
    auto it = driftstackH2ChurnMap().find(origin);
    if (it == driftstackH2ChurnMap().end() || it->value.first < kH2ChurnThreshold)
        return false;
    return MonotonicTime::now() - it->value.second < kH2ChurnCooldown;   // W3084 decay → self-heal
}
[[maybe_unused]] static void driftstackH2NoteChurn(const String& origin)
{
    Locker locker { driftstackH2PoolLock() };
    auto& e = driftstackH2ChurnMap().add(origin, std::pair<unsigned, MonotonicTime> { 0u, MonotonicTime::now() }).iterator->value;
    if (e.first < 100000u) ++e.first;
    e.second = MonotonicTime::now();   // W3084: refresh the strike time so a chronic churner stays tripped
}
[[maybe_unused]] static void driftstackH2NoteHealthy(const String& origin)
{
    Locker locker { driftstackH2PoolLock() };
    driftstackH2ChurnMap().remove(origin);
}
// W3052 (FOUNDER westernunion — the DEEP fix): per-ORIGIN fresh-connect concurrency cap.
// W3046 stopped the failed-reuse/re-adopt churn, but a session-replay tracker that GOAWAYs
// every session (ingest.quantummetric.com) is treated as "churning" → it BYPASSES the h2Pool
// winner/waiter claim entirely, so MANY concurrent beacons to that one origin ALL become
// last-resort own-connect winners at once (a fresh-connect stampede). Each pins a GCD worker
// + an admission slot (of 24) for its whole life, so ONE tracker can still monopolise the
// admission cap and starve the document's own connects — even though the 24-cap is "active".
// This bounds concurrent NON-POOLED (fresh-connecting) requests to any single origin to
// kMaxFreshConnectsPerOrigin, held from just-before the fresh handshake through request
// completion (released by the same handshakeCapGuard scope-exit that frees the handshake
// slot). So no one origin can occupy more than N of the 24 admission slots; the rest stay
// free for real content. Pooled REUSE requests take the fast path ABOVE this acquire and
// never touch it — legit multiplexed high-fanout origins (a CDN serving 30 subresources over
// ONE pooled H2 connection) are entirely exempt. This mirrors iOS Safari's per-host
// connection bound (HTTPMaximumConnectionsPerHost ~6): a multiplexing origin uses 1 pooled
// connection; a non-multiplexing/churning origin is capped at ~6 concurrent. Fingerprint-
// neutral (pure connect pacing — no ClientHello/cipher/curve/ALPN/header/routing change).
// Gated under the same driftstackAdmissionPacingEnabled() gate; gate-off = true no-op.
static long driftstackMaxFreshConnectsPerOrigin()
{
    static long cap = [] {
        long c = 6;  // = iOS HTTPMaximumConnectionsPerHost
        if (const char* e = getenv("DRIFTSTACK_MAX_CONNS_PER_ORIGIN")) {
            long p = atol(e);
            if (p >= 1 && p <= 24)
                c = p;
        }
        WTFLogAlways("[W3052/Fix3] per-origin fresh-connect cap = %ld", c);
        return c;
    }();
    return cap;
}
[[maybe_unused]] static dispatch_semaphore_t driftstackOriginConnectSemaphore(const String& origin)
{
    // Lazily created, one counting semaphore per origin (cap = the per-origin bound).
    // Guarded by the existing pool lock (brief critical section on cache-miss only; the
    // dispatch_semaphore_wait happens OUTSIDE this lock at the call site). Semaphores are
    // process-lifetime (never removed) — bounded by the unique-origin count of a single
    // per-session process; OSObjectPtr keeps the ARC-managed dispatch object retained.
    static NeverDestroyed<HashMap<String, OSObjectPtr<dispatch_semaphore_t>>> map;
    Locker locker { driftstackH2PoolLock() };
    return map.get().ensure(origin, [] {
        return adoptOSObject(dispatch_semaphore_create(driftstackMaxFreshConnectsPerOrigin()));
    }).iterator->value.get();
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
    // W2342: sweep DEAD sessions on every insert. A pooled session whose reader thread has
    // exited (peer GOAWAY / FIN / transport error → isAlive()==false) otherwise lingers in this
    // map — holding its TLS client, hence its socket fd in CLOSE_WAIT — until the NEXT request to
    // THAT SAME origin evicts it via driftstackH2PoolGet (:614). An origin visited once then never
    // revisited keeps its dead session's fd until the WebContent process exits → slow fd
    // accumulation on a long-lived session that browses many one-off hosts. The reader THREAD is
    // already reclaimed on death (it drops its self-ref when readerLoop returns — that leak class is
    // the W2341/#58 fix's sibling); this only reclaims the lingering fd. Sweeping here bounds it: any
    // new pooling clears every dead entry across all origins. Alive sessions are untouched (no reuse
    // regression). O(pool size) under the lock, negligible (pool is per-WebContent, dozens of origins).
    auto& pool = driftstackH2Pool();
    Vector<String> dead;
    for (auto& [key, sess] : pool) {
        if (!sess || !sess->isAlive())
            dead.append(key);
    }
    for (auto& key : dead)
        pool.remove(key);
    pool.set(origin, std::move(session));
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
    // W3041 (audit w7wqi2pq4 MED): sweep DEAD sessions on every insert, mirroring the h2 pool's W2342
    // fix. A pooled h3 session whose QUIC connection terminated (server CONNECTION_CLOSE / idle-timeout
    // expiry → isAlive()==false once the pump self-terminates per the W3041 runPump fix) otherwise
    // lingers here holding its udpFd + SOCKS5 relay fd. The pool's only other evictors are same-origin
    // re-claim (driftstackH3PoolClaim) and driftstackH3PoolEvict on a reused-session failure, so an h3
    // origin visited ONCE and never revisited keeps that fd until the NetworkProcess exits. Sweeping
    // here bounds it: any new pooling clears every dead entry across all origins. Alive sessions are
    // untouched (no reuse regression). O(pool size) under the lock (dozens of origins — negligible).
    auto& pool = driftstackH3Pool();
    Vector<String> dead;
    for (auto& [key, sess] : pool) {
        if (!sess || !sess->isAlive())
            dead.append(key);
    }
    for (auto& key : dead)
        pool.remove(key);
    pool.set(origin, std::move(session));
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

// W2337 (task #59) — the PathB custom-egress Accept-Language. The ResourceRequest carries NO
// accept-language on this path (WebCore-Cocoa defers it to CFNetwork, which PathB bypasses — W2327),
// so whatever this returns IS the byte shipped on the wire. Derive it from DRIFTSTACK_APPLELANGUAGES
// (the env the harness sets from the proxy-exit geo, gated on DRIFTSTACK_EGRESS_PROBE — A3 W1352) so a
// geo session's Accept-Language FOLLOWS navigator.language/Intl instead of being a fixed en-US (the
// W2327 incoherence). Format = the real-iPhone V-229 pattern: list[0] (region-primary, implicit q=1.0)
// then ",list[i];q=(1.0-0.1*i)". For "en-US,en" this yields exactly "en-US,en;q=0.9" = the prior
// literal fallback (V-229), so the v1.0/en-US path is BYTE-IDENTICAL (env unset → the literal below).
// Input contract drift-locked harness-side (A3 W1351: ≥2 well-formed tags, region-qualified [0]).
// CAVEAT (task #48, BS-gated): the CFNetwork multi-tag/CJK minimization (ja-JP→ja) is NOT modeled here
// — byte-exact for the Latin 2-element locales; coherent-not-yet-byte-exact for ja/zh/no until #48.
// W2557 (per-archetype audit): the per-archetype full User-Agent, forwarded to the NetworkProcess
// via DRIFTSTACK_ARCHETYPE_UA_FULL (ProcessLauncherCocoa). Used only as the PathB request
// user-agent FALLBACK — in normal operation the WebProcess already set the request's user-agent to
// the per-archetype customUserAgent (the contains-check returns it). The prior hardcoded iphone17
// literal would leak the WRONG UA on the wire for every OTHER archetype if the header were ever
// absent; deriving from the forwarded env keeps the fallback per-archetype-correct (launch
// archetype unchanged when the env carries the iphone17 UA).
static String driftstackPathBUserAgentFallback()
{
    const char* ua = getenv("DRIFTSTACK_ARCHETYPE_UA_FULL");
    if (ua && ua[0])
        return String::fromUTF8(ua);
    return "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.4 Mobile/15E148 Safari/604.1"_s;
}

static String driftstackPathBAcceptLanguage()
{
    const char* al = getenv("DRIFTSTACK_APPLELANGUAGES");
    if (!al || !al[0])
        return "en-US,en;q=0.9"_s;
    Vector<String> tags;
    Vector<char> cur;
    for (const char* p = al; ; ++p) {
        if (*p == ',' || *p == '\0') {
            if (!cur.isEmpty()) {
                cur.append('\0');
                tags.append(String::fromUTF8(cur.span().data()));
                cur.clear();
            }
            if (*p == '\0')
                break;
        } else if (*p != ' ')   // GeoLocale tags carry no spaces; defensively drop any
            cur.append(*p);
    }
    if (tags.isEmpty())
        return "en-US,en;q=0.9"_s;
    StringBuilder out;
    out.append(tags[0]);  // primary, implicit q=1.0
    for (size_t i = 1; i < tags.size(); ++i) {
        int q = 10 - static_cast<int>(i);  // 0.9, 0.8, ... (single iPhone-style decimal)
        if (q < 1)
            q = 1;
        out.append(","_s);
        out.append(tags[i]);
        out.append(";q=0."_s);
        out.append(String::number(q));
    }
    return out.toString();
}

// W2340 (refines W2338): the PathB Accept-Encoding, ARCHETYPE-CONDITIONED on the zstd cutover.
// zstd landed in WebKit/Safari 26.3 (W1483), so family-B archetypes (Safari >=26.3, incl the 26.4
// launch) advertise "gzip, deflate, br, zstd"; family-A (Safari 17/18/19 + 26.0/26.1/26.2 — pre-26.3)
// advertise "gzip, deflate, br" (no zstd). W2338 found the loader was shipping the WebProcess Mac
// "gzip, deflate" (getOrDefault passthrough) and forced the iPhone value, but UNCONDITIONALLY — correct
// for the 26.4 launch, wrong for the post-launch family-A configs (they'd advertise zstd Safari 18.6
// never sends). The loader decodes all of gzip/deflate/br/zstd via VENDORED zstd v1.5.7 (W1515/W2326 —
// NOT macOS libcompression, which has no zstd codec), so advertising the full set is safe at decode time.
static String driftstackPathBAcceptEncoding()
{
    const char* arch = getenv("DRIFTSTACK_ARCHETYPE");
    if (arch && arch[0]) {
        String a = String::fromUTF8(arch);
        if (a.contains("safari17_"_s) || a.contains("safari18_"_s) || a.contains("safari19_"_s)
            || a.contains("safari26_0"_s) || a.contains("safari26_1"_s) || a.contains("safari26_2"_s))
            return "gzip, deflate, br"_s;  // pre-26.3 archetype = no zstd
    }
    return "gzip, deflate, br, zstd"_s;  // Safari >=26.3 (incl the 26.4 launch) + default
}

// P3 (#61) — RFC 9218 `priority` header, full per-resource-type matrix. On iOS CFNetwork injects
// it on every request; PathB bypasses CFNetwork, so the value is derived from the request's own
// sec-fetch-dest / accept (already present in the WebProcess request). The full per-type urgency
// matrix is real-device-verified (gt-registry http2_priority_rfc9218: 4 BS cells iOS 18.6–26.5,
// Family A + B, byte-identical) and gated by h2-priority-matrix-gate.sh (FORWARD real-device +
// REVERSE source-assert, both GREEN): document → u=0; {style,script,module} → u=1 (module reports
// sec-fetch-dest=script); image → u=5; {font,preload-font,fetch,xhr,empty,other} → u=3; all `i`.
// `dest` and `accept` are the lowercased header values (empty if absent). If WebKit already
// supplied a `priority` header, pass that through unchanged (handled at the call sites).
static String driftstackPathBPriorityHeader(const String& secFetchDest, const String& accept)
{
    // RFC 9218 priority — per-resource-type u-value, byte-matching real iPhone Safari
    // (gt-registry http2_priority_rfc9218; 4 real-device BS cells iOS 18.6–26.5, byte-identical).
    // W3146 (2nd-audit fix): the real RFC 9218 matrix keys PURELY on sec-fetch-dest (gt-registry
    // http2_priority_rfc9218: "document(navigation)=u=0; fetch/xhr (dest=empty)=u=3"). The bare
    // accept.contains("text/html") over-matched a FETCH/XHR that requests text/html (dest="empty") →
    // it returned u=0 (document) where a real iPhone returns u=3 (dest-keyed). Restrict the accept
    // belt to a sec-fetch-LESS request (secFetchDest EMPTY, i.e. "" — a nav with no Sec-Fetch-Dest), so
    // a fetch (dest="empty", NOT isEmpty) falls through to the correct u=3. Navigations (dest="document")
    // are unchanged; the gate's generic-fetch cell (u=3) is unaffected.
    if (secFetchDest == "document"_s || (secFetchDest.isEmpty() && accept.contains("text/html"_s)))
        return "u=0, i"_s;  // navigation / document
    if (secFetchDest == "style"_s || secFetchDest == "script"_s)
        return "u=1, i"_s;  // CSS, classic script, ES module (module's sec-fetch-dest is "script")
    if (secFetchDest == "image"_s)
        return "u=5, i"_s;  // image
    return "u=3, i"_s;      // font / fetch / xhr / empty / other
}

// W2341 (task #58, design W2323): cancel-aware read adapter for the PathB custom-TLS transports.
// cancel() runs on another thread and must NOT touch the fd (it's owned by this dispatch block;
// a cross-thread shutdown() is a TOCTOU against the block's concurrent close — a closed+reused fd
// would shut down an UNRELATED connection). So cancellation is observed by the READING thread
// itself: pollReadable() waits in 1s slices (poll consumes no bytes → record framing can't tear)
// and re-checks m_cancelled on every timeout tick. A cancelled request returns -1 = transport
// error → the h2 engine unwinds → the block exits → its thread + fd are reclaimed. Previously an
// idle-SSE cancel (or a hung server) parked recv() FOREVER and leaked both — gradual resource
// exhaustion on a long-running node once PathB-v2 is activated.
struct DriftstackCancelAwareTls {
    DriftstackTLS13Client* tls;
    const std::atomic<bool>* cancelled;
};
static int driftstackCancelAwareTlsRead(void* ctxIn, uint8_t* buf, size_t n)
{
    auto* ctx = static_cast<DriftstackCancelAwareTls*>(ctxIn);
    for (;;) {
        if (ctx->cancelled->load(std::memory_order_relaxed))
            return -1;
        int r = ctx->tls->pollReadable(1000);
        if (r > 0)
            return ctx->tls->read(buf, n);
        if (r < 0)
            return -1;
        // r == 0: timeout tick → loop re-checks cancelled
    }
}
static int driftstackCancelAwareTlsWrite(void* ctxIn, const uint8_t* buf, size_t n)
{
    return static_cast<DriftstackCancelAwareTls*>(ctxIn)->tls->write(buf, n);
}

// Wave 29-499.321 (Phase 2.5) — build the iPhone-Safari-exact HTTP/2 request
// (pseudo-header order m,s,a,p + canonical real-header order + cookies + cache-
// validation stripping). Shared by the one-shot path AND the pooled session
// path so the wire fingerprint is identical regardless of pooling.
static WebKit::DriftstackHttp2Request driftstackBuildIphoneH2Request(const URL& url,
    const String& httpMethod, const WebCore::HTTPHeaderMap& httpHeaders,
    const Vector<uint8_t>& requestBody, const String& host, const String& cookieHeader)
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
    // iPhone Safari 26 canonical header ORDER, WebKit's natural values.
    HashMap<String, String> webkitHdrs;
    for (auto& header : httpHeaders)
        webkitHdrs.add(header.key.convertToASCIILowercase(), header.value);
    auto getOrDefault = [&](ASCIILiteral key, ASCIILiteral fallback) -> String {
        auto it = webkitHdrs.find(String(key));
        return it != webkitHdrs.end() ? it->value : String(fallback);
    };
    // TIER-4 wire H2 regular-header ORDER — matched to a real-iPhone-17 raw-wire tls.peet.ws
    // capture (reference/realdevice-bs/tls-full-iPhone_17-2026-06-01...json, sent_frames HEADERS,
    // NOT the Cloudflare-sorted reflection). Real-iOS navigation emits regular headers in this
    // exact order: sec-fetch-dest, user-agent, accept, [referer], sec-fetch-site, sec-fetch-mode,
    // accept-language, priority, accept-encoding. The prior order (accept, sec-fetch-site,
    // sec-fetch-dest, accept-encoding, sec-fetch-mode, user-agent, priority, accept-language) was a
    // wire tell. Header order does NOT affect the Akamai H2 hash (pseudo-only) but IS a distinct
    // JA4H / raw-frame fingerprint. Values are unchanged; only the emit order moved.
    // W3068-CORS (JA4H tracker-path): real iPhone Safari keys the regular-header ORDER on
    // sec-fetch-mode. A cross-origin fetch/XHR GET uses a DIFFERENT order than navigation, so emitting
    // the nav order for a cors GET is a distinct JA4H tell on the fetch/beacon tracker path. Order
    // verified from the iPhone-17 raw-wire capture (reference/realdevice-bs/
    // tls-h1-secfetch-pertype-iPhone17-26_5-2026-07-03.json, cors GET cap #8): Pragma, Accept,
    // Sec-Fetch-Site, Sec-Fetch-Mode, User-Agent, Referer, Sec-Fetch-Dest, Cache-Control,
    // Accept-Language, Priority, Accept-Encoding. Values are unchanged; only the emit order differs.
    // W3068-CORS-POST (JA4H tracker POST path): a cross-origin fetch/XHR/beacon WITH a body (POST/PUT/
    // PATCH/DELETE) uses yet another order — Content-Type/Origin near the front, Content-Length at pos 7
    // (mid). Verified from the iPhone-17 raw-wire capture (reference/realdevice-bs/
    // tls-h1-secfetch-pertype-iPhone17-26_5-2026-07-03.json, cors POST cap #9; cross-checked vs
    // raw-h1-iPhone_17-26-v3-post.json POST caps): Accept, Content-Type, Origin, Pragma, Sec-Fetch-Site,
    // Content-Length, Sec-Fetch-Mode, User-Agent, Referer, Sec-Fetch-Dest, Cache-Control, Accept-Language,
    // Priority, Accept-Encoding. Emitting the nav order for a cors POST is a distinct JA4H tell on the
    // fetch/beacon tracker path. The h1 call-site (:3589) now threads the REAL requestBody so the
    // mid-order Content-Length is the true size — NOT the W3070 empty-harvest 0 (the emit's trailing
    // fallback CL is then correctly skipped via sawContentLength, and the body still sends once).
    bool isCorsGet = (httpMethod == "GET"_s) && webkitHdrs.get("sec-fetch-mode"_s) == "cors"_s;
    bool isCorsPost = webkitHdrs.get("sec-fetch-mode"_s) == "cors"_s
        && httpMethod != "GET"_s && httpMethod != "HEAD"_s;
    if (isCorsGet) {
        if (webkitHdrs.contains("pragma"_s)) h2req.extraHeaders.append({ "pragma"_s, webkitHdrs.get("pragma"_s) });
        h2req.extraHeaders.append({ "accept"_s, getOrDefault("accept"_s, "*/*"_s) });
        if (webkitHdrs.contains("sec-fetch-site"_s)) h2req.extraHeaders.append({ "sec-fetch-site"_s, webkitHdrs.get("sec-fetch-site"_s) });
        if (webkitHdrs.contains("sec-fetch-mode"_s)) h2req.extraHeaders.append({ "sec-fetch-mode"_s, webkitHdrs.get("sec-fetch-mode"_s) });
        h2req.extraHeaders.append({ "user-agent"_s, webkitHdrs.contains("user-agent"_s) ? webkitHdrs.get("user-agent"_s) : driftstackPathBUserAgentFallback() });
        if (webkitHdrs.contains("referer"_s)) h2req.extraHeaders.append({ "referer"_s, webkitHdrs.get("referer"_s) });
        if (webkitHdrs.contains("sec-fetch-dest"_s)) h2req.extraHeaders.append({ "sec-fetch-dest"_s, webkitHdrs.get("sec-fetch-dest"_s) });
        if (webkitHdrs.contains("cache-control"_s)) h2req.extraHeaders.append({ "cache-control"_s, webkitHdrs.get("cache-control"_s) });
        h2req.extraHeaders.append({ "accept-language"_s, driftstackPathBAcceptLanguage() });
        h2req.extraHeaders.append({ "priority"_s, webkitHdrs.contains("priority"_s) ? webkitHdrs.get("priority"_s)
            : driftstackPathBPriorityHeader(webkitHdrs.get("sec-fetch-dest"_s), getOrDefault("accept"_s, "*/*"_s)) });
        h2req.extraHeaders.append({ "accept-encoding"_s, driftstackPathBAcceptEncoding() });
    } else if (isCorsPost) {
        // cors POST/PUT/PATCH order (raw-wire cap #9). Content-Type/Origin/Content-Length carry the body;
        // Content-Length = the real requestBody size (h1 threads it via the :3589 call-site).
        h2req.extraHeaders.append({ "accept"_s, getOrDefault("accept"_s, "*/*"_s) });
        if (webkitHdrs.contains("content-type"_s)) h2req.extraHeaders.append({ "content-type"_s, webkitHdrs.get("content-type"_s) });
        if (webkitHdrs.contains("origin"_s)) h2req.extraHeaders.append({ "origin"_s, webkitHdrs.get("origin"_s) });
        if (webkitHdrs.contains("pragma"_s)) h2req.extraHeaders.append({ "pragma"_s, webkitHdrs.get("pragma"_s) });
        if (webkitHdrs.contains("sec-fetch-site"_s)) h2req.extraHeaders.append({ "sec-fetch-site"_s, webkitHdrs.get("sec-fetch-site"_s) });
        h2req.extraHeaders.append({ "content-length"_s, String::number(requestBody.size()) });
        if (webkitHdrs.contains("sec-fetch-mode"_s)) h2req.extraHeaders.append({ "sec-fetch-mode"_s, webkitHdrs.get("sec-fetch-mode"_s) });
        h2req.extraHeaders.append({ "user-agent"_s, webkitHdrs.contains("user-agent"_s) ? webkitHdrs.get("user-agent"_s) : driftstackPathBUserAgentFallback() });
        if (webkitHdrs.contains("referer"_s)) h2req.extraHeaders.append({ "referer"_s, webkitHdrs.get("referer"_s) });
        if (webkitHdrs.contains("sec-fetch-dest"_s)) h2req.extraHeaders.append({ "sec-fetch-dest"_s, webkitHdrs.get("sec-fetch-dest"_s) });
        if (webkitHdrs.contains("cache-control"_s)) h2req.extraHeaders.append({ "cache-control"_s, webkitHdrs.get("cache-control"_s) });
        h2req.extraHeaders.append({ "accept-language"_s, driftstackPathBAcceptLanguage() });
        h2req.extraHeaders.append({ "priority"_s, webkitHdrs.contains("priority"_s) ? webkitHdrs.get("priority"_s)
            : driftstackPathBPriorityHeader(webkitHdrs.get("sec-fetch-dest"_s), getOrDefault("accept"_s, "*/*"_s)) });
        h2req.extraHeaders.append({ "accept-encoding"_s, driftstackPathBAcceptEncoding() });
    } else {
    if (webkitHdrs.contains("sec-fetch-dest"_s)) h2req.extraHeaders.append({ "sec-fetch-dest"_s, webkitHdrs.get("sec-fetch-dest"_s) });
    h2req.extraHeaders.append({ "user-agent"_s, webkitHdrs.contains("user-agent"_s) ? webkitHdrs.get("user-agent"_s) : driftstackPathBUserAgentFallback() });
    h2req.extraHeaders.append({ "accept"_s, getOrDefault("accept"_s, "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"_s) });
    if (webkitHdrs.contains("referer"_s)) h2req.extraHeaders.append({ "referer"_s, webkitHdrs.get("referer"_s) });
    if (webkitHdrs.contains("sec-fetch-site"_s)) h2req.extraHeaders.append({ "sec-fetch-site"_s, webkitHdrs.get("sec-fetch-site"_s) });
    if (webkitHdrs.contains("sec-fetch-mode"_s)) h2req.extraHeaders.append({ "sec-fetch-mode"_s, webkitHdrs.get("sec-fetch-mode"_s) });
    h2req.extraHeaders.append({ "accept-language"_s, driftstackPathBAcceptLanguage() });
    // P3/W2438 (#61): real iOS sends the RFC 9218 `priority` header on every request — `u=0, i` for
    // document/navigation, `u=3, i` for fetch/XHR (40 in-repo aio captures, 100% consistent). On iOS
    // it's injected by CFNetwork; PathB bypasses CFNetwork, so the WebProcess request has no `priority`
    // and omitting it is a wire tell. Pass WebKit's value through if present, else derive nav-vs-fetch
    // urgency from sec-fetch-dest / accept.
    h2req.extraHeaders.append({ "priority"_s, webkitHdrs.contains("priority"_s) ? webkitHdrs.get("priority"_s)
        : driftstackPathBPriorityHeader(webkitHdrs.get("sec-fetch-dest"_s), getOrDefault("accept"_s, "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"_s)) });
    // W2338: FORCE the iPhone Accept-Encoding (NOT getOrDefault). The request's accept-encoding is the
    // Mac WebKit default "gzip, deflate" (no br/zstd); real iPhone Safari = "gzip, deflate, br, zstd"
    // (W1512). The PathB loader decodes gzip/deflate/br/zstd before WebKit sees the body (W2326). Real
    // iOS emits accept-encoding LAST of the regular headers (raw-wire reference).
    h2req.extraHeaders.append({ "accept-encoding"_s, driftstackPathBAcceptEncoding() });
    }
    for (auto& header : httpHeaders) {
        String lower = header.key.convertToASCIILowercase();
        if (lower == "host"_s || lower == "connection"_s || lower == "cookie"_s || lower.startsWith(':')
            || lower == "accept"_s || lower == "accept-encoding"_s || lower == "accept-language"_s
            || lower == "sec-fetch-site"_s || lower == "sec-fetch-dest"_s || lower == "sec-fetch-mode"_s
            || lower == "user-agent"_s || lower == "priority"_s || lower == "referer"_s
            || ((isCorsGet || isCorsPost) && (lower == "pragma"_s || lower == "cache-control"_s))
            || (isCorsPost && (lower == "content-type"_s || lower == "origin"_s || lower == "content-length"_s)))
            continue;
        if (lower == "if-none-match"_s || lower == "if-modified-since"_s || lower == "if-match"_s
            || lower == "if-unmodified-since"_s || lower == "if-range"_s)
            continue;
        h2req.extraHeaders.append({ lower, header.value });
    }
    // Cookie LAST — real iPhone Safari 26.x emits Cookie as the TERMINAL H2 header
    // (reference/realdevice-bs/h2-hpack-encoder-iPhone_17_*2026-07-03.json: every cookie'd stream ends
    // ...accept-encoding, cookie). The trailing loop above skips cookie, so appending here makes it the
    // final entry — mirrors the H1 serializer's Cookie-penultimate (H2/H3 drop Connection).
    // PathB v2 ITP: caller passes the ITP-filtered Cookie header; empty => omit.
    if (!cookieHeader.isEmpty())
        h2req.extraHeaders.append({ "cookie"_s, cookieHeader });
    return h2req;
}

bool DriftstackNetworkLoader::tryFollowRedirect(const WebCore::ResourceResponse& response, const Vector<String>& rawSetCookies)
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

    // PathB v2 egress (Set-Cookie WRITE): we've confirmed this is a redirect we WILL follow. Persist the
    // 3xx response's Set-Cookie BEFORE the re-resume is marshalled, so an OneTrust/cookielaw consent gate's
    // 302+Set-Cookie stores its cookie before the next hop re-reads the (otherwise empty) store and loops
    // forever (the westernunion symptom). MAIN THREAD: tryFollowRedirect runs on loaderQueue (called from
    // the response sites) but driftstackPersistSetCookies touches m_request/task ITP state — marshal it to
    // the main runloop. callOnMainRunLoop is FIFO, and the re-resume below is also marshalled to the main
    // runloop AFTER this, so the WRITE is ordered before the next hop's READ. m_request is still the
    // PRE-redirect request here, so the consent cookie is stored first-party to the consent domain. Gate-off
    // (DRIFTSTACK_EGRESS_SET_COOKIE_PERSIST=0): driftstackPersistSetCookies is a no-op.
    if (!rawSetCookies.isEmpty()) {
        Ref<DriftstackNetworkLoader> cookieRef { *this };
        callOnMainRunLoop([cookieRef = WTF::move(cookieRef), responseURL = URL(currentURL), rawSetCookies = Vector<String>(rawSetCookies)]() mutable {
            cookieRef->driftstackPersistSetCookies(responseURL, rawSetCookies);
        });
    }

    // W2202 STEP 5: this runs on loaderQueue — never cache the raw client across the main-thread
    // hop. Use a task-existence early-out only; re-acquire the client inside the callOnMainRunLoop block.
    RefPtr task = protectedTask();
    if (!task)
        return false;
    Ref<DriftstackNetworkLoader> protectedThis { *this };

    // Chain guard — match common browser cap; fail cleanly past it.
    if (++m_redirectCount > 20) {
        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.344] redirect chain exceeded 20 hops for %s — failing", currentURL.string().utf8().data());
        if (tryBeginCompletion()) {
            WebCore::ResourceError error(String("DriftstackNetworkLoader"_s), 0, currentURL, "too many redirects"_s, WebCore::ResourceError::Type::General);
            callOnMainRunLoop([protectedThis, error = std::move(error)]() mutable {
                RefPtr task = protectedThis->protectedTask();
                if (!task)
                    return;
                RefPtr client = task->client();
                if (!client)
                    return;
                WebCore::NetworkLoadMetrics metrics;
                client->didCompleteWithError(error, metrics);
            });
        }
        return true;
    }

    // Build the redirected request (RFC 7231 §6.4): 307/308 preserve method+body;
    // 301/302/303 become GET and drop the body (HEAD stays HEAD).
    // W3101 (NetworkProcess ~dtor double-free fix): tryFollowRedirect runs on loaderQueue, so this is a
    // cross-thread copy of m_request. A plain copy SHARES m_request's WTF::String StringImpls (which m_request
    // in turn shares with the main-thread-owned task ResourceRequest). newRequest is later destroyed on the main
    // thread (the willPerformHTTPRedirection block), so the non-atomic StringImpl refcount ops race — corrupting
    // m_request's Vector<String> and double-freeing it at ~DriftstackNetworkLoader. isolatedCopy() gives newRequest
    // independent StringImpls (deep char copy, no shared refcount) — value-equivalent redirect, no cross-thread race.
    WebCore::ResourceRequest newRequest = m_request.isolatedCopy();
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

    callOnMainRunLoop([this, protectedThis, redirectResponse = WebCore::ResourceResponse(response), newRequest = WebCore::ResourceRequest(newRequest)]() mutable {
        RefPtr task = protectedThis->protectedTask();
        if (!task)
            return;
        RefPtr client = task->client();
        if (!client)
            return;
        client->willPerformHTTPRedirection(WTF::move(redirectResponse), WTF::move(newRequest),
            [this, protectedThis](WebCore::ResourceRequest&& finalRequest) mutable {
                if (m_cancelled)
                    return;
                if (finalRequest.isNull()) {
                    // Policy (CSP/mixed-content/etc.) declined the redirect → cancel cleanly.
                    RefPtr task = protectedThis->protectedTask();
                    if (task && tryBeginCompletion()) {
                        RefPtr client = task->client();
                        if (!client)
                            return;
                        WebCore::NetworkLoadMetrics metrics;
                        client->didCompleteWithError(WebCore::ResourceError { WebCore::ResourceError::Type::Cancellation }, metrics);
                    }
                    return;
                }
                m_request = WTF::move(finalRequest);
                // W3011/egress FIX-C: the redirect TARGET is a distinct request and deserves a fresh
                // retry budget. Without this, m_attempt + the per-request m_retryDeadline carried over
                // from the PRE-redirect request, so a redirect chain that consumed attempts (or wall-
                // clock) on the source URL could land on the target with little/no retry budget left,
                // failing a flaky exit that a fresh request would have ridden out. Reset both: m_attempt
                // = 0 so the next failure re-stamps the deadline as attempt 1 (the ++m_attempt==1 path),
                // and clear m_retryDeadline to its unset (default MonotonicTime, the epoch) value so the
                // stale within-budget check can't pass before that re-stamp. The chain stays bounded by
                // m_redirectCount (cap 20). Additive + gate-independent.
                m_attempt = 0;
                m_retryDeadline = MonotonicTime();
                resume(); // load the redirect target on a fresh connection (re-uses pool if applicable)
            });
    });
    return true;
}

// Wave 29-499.348 — resolve the request body INCLUDING file parts. flatten()
// omits EncodedFileData, which forced every multipart file upload off PathB v2
// onto CFNetwork (Mac TLS fingerprint — the W2014-2031 TLS-split). File parts
// are read from disk here; the eligibility gate in NetworkDataTaskCocoa caps
// total file size and still bypasses blob elements (not resolvable at this
// layer). Returns false if any part can't be read — the caller must FAIL the
// load; an incomplete body must never go on the wire.
static bool driftstackResolveRequestBody(WebCore::FormData& formData, Vector<uint8_t>& out)
{
    for (auto& element : formData.elements()) {
        bool ok = WTF::switchOn(element.data,
            [&](const Vector<uint8_t>& data) {
                out.appendVector(data);
                return true;
            },
            [&](const WebCore::FormDataElement::EncodedFileData& fileData) {
                auto contents = FileSystem::readEntireFile(fileData.filename);
                if (!contents)
                    return false;
                size_t start = fileData.fileStart > 0 ? static_cast<size_t>(fileData.fileStart) : 0;
                if (start > contents->size())
                    return false;
                size_t length = contents->size() - start;
                if (fileData.fileLength >= 0)
                    length = std::min(length, static_cast<size_t>(fileData.fileLength));
                out.append(contents->span().subspan(start, length));
                return true;
            },
            [&](const WebCore::FormDataElement::EncodedBlobData&) {
                return false;
            });
        if (!ok)
            return false;
    }
    return true;
}

// PathB v2 within-session Set-Cookie WRITE kill-switch. DEFAULT-ON: this is a correctness fix
// (the egress READS cookies but never WROTE Set-Cookie, so a 302+Set-Cookie consent gate looped
// forever — westernunion). Set DRIFTSTACK_EGRESS_SET_COOKIE_PERSIST=0 to disable (restores the
// broken drop-Set-Cookie behaviour). NetworkProcess-only => glyphHash-neutral.
static bool driftstackEgressSetCookiePersistEnabled()
{
    static const bool enabled = [] {
        const char* e = getenv("DRIFTSTACK_EGRESS_SET_COOKIE_PERSIST");
        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/SetCookie] DRIFTSTACK_EGRESS_SET_COOKIE_PERSIST=%s (default ON)", e ?: "(null)");
        return !e || e[0] != '0';   // default-ON: only "0" disables
    }();
    return enabled;
}

// Extract the RAW (un-folded) Set-Cookie header values from a protocol's header container.
// Each Set-Cookie response header is ONE entry — they must NOT be comma-joined (an Expires=...
// date contains a comma, and multiple Set-Cookie headers fold into one ambiguous value). We read
// the raw [key,value] vector each transport already produces (NOT response.httpHeaderField(),
// which setHTTPHeaderField has already comma-folded). One String per Set-Cookie header line.
// Returns empty when the gate is OFF, so every downstream isEmpty()-guarded persist (final-response
// hop AND the redirect persist inside tryFollowRedirect) is skipped → gate-off is a true no-op.
static Vector<String> driftstackExtractRawSetCookies(const Vector<std::pair<String, String>>& rawHeaders)
{
    Vector<String> out;
    if (!driftstackEgressSetCookiePersistEnabled())
        return out;
    for (auto& [k, v] : rawHeaders) {
        if (equalIgnoringASCIICase(k, "set-cookie"_s) && !v.isEmpty())
            out.append(v);
    }
    return out;
}

// PathB v2 within-session Set-Cookie WRITE. Persists each RAW Set-Cookie value through the SAME
// 9-arg ITP context as the READ (driftstackITPCookieHeader). MAIN THREAD ONLY (touches m_request +
// task ITP state — like the READ). Callers on loaderQueue marshal via callOnMainRunLoop BEFORE the
// redirect/delivery hop (callOnMainRunLoop is FIFO, so the WRITE lands before the next-hop re-read).
// Gate-off (DRIFTSTACK_EGRESS_SET_COOKIE_PERSIST=0): no-op. NetworkProcess-only => glyphHash-neutral.
void DriftstackNetworkLoader::driftstackPersistSetCookies(const URL& responseURL, const Vector<String>& setCookieValues)
{
    if (!driftstackEgressSetCookiePersistEnabled())
        return;
    if (setCookieValues.isEmpty())
        return;
    RefPtr task = protectedTask();
    if (!task)
        return;
    WebKit::NetworkSession* session = task->networkSession();
    if (!session)
        return;
    CheckedPtr<WebCore::NetworkStorageSession> storageSession = session->networkStorageSession();
    if (!storageSession)
        return;

    // Same ITP args the READ uses (cookieRequestHeaderFieldValue above), so the WRITE inherits the
    // SAME 3rd-party/partition decision — PathB stays byte-equivalent to NSURLSession ITP.
    const URL& firstParty = m_request.firstPartyForCookies();
    WebCore::SameSiteInfo sameSiteInfo = WebCore::SameSiteInfo::create(m_request);
    for (const String& setCookieValue : setCookieValues) {
        storageSession->driftstackSetCookiesFromHTTPResponse(
            firstParty, sameSiteInfo, responseURL, task->frameID(), task->pageID(),
            WebCore::ApplyTrackingPrevention::Yes,
            session->networkProcess().shouldRelaxThirdPartyCookieBlockingForPage(task->webPageProxyID()),
            WebKit::NetworkSession::isResourceFromKnownCrossSiteTracker(firstParty, responseURL),
            setCookieValue);
    }
}

// PathB v2 ITP: compute the EXACT Cookie header real Safari's NSURLSession would send for this request.
// PathB replaces NSURLSession, which is where CFNetwork applies WebKit's Intelligent Tracking Prevention;
// the prior 4 sites sourced cookies raw from NSHTTPCookieStorage (requestHeaderFieldsWithCookies) and so
// bypassed 3rd-party cookie blocking entirely — a tracker-handling tell vs a real iPhone. This routes
// through NetworkStorageSession::cookieRequestHeaderFieldValue (the 9-arg ITP overload) with the same args
// the in-browser path uses (NetworkConnectionToWebProcess.cpp:848). Returns the full Cookie header value,
// or a null/empty String when ITP blocks all cookies (caller injects NO Cookie header). MAIN THREAD ONLY
// (touches m_request + task ITP state — not safe on loaderQueue). NetworkProcess-only => glyphHash-neutral.
String DriftstackNetworkLoader::driftstackITPCookieHeader()
{
    RefPtr task = protectedTask();
    if (!task)
        return { };
    WebKit::NetworkSession* session = task->networkSession();
    if (!session)
        return { };
    CheckedPtr<WebCore::NetworkStorageSession> storageSession = session->networkStorageSession();
    if (!storageSession)
        return { };

    const URL& firstParty = m_request.firstPartyForCookies();
    const URL& url = m_request.url();
    WebCore::SameSiteInfo sameSiteInfo = WebCore::SameSiteInfo::create(m_request);
    WebCore::IncludeSecureCookies includeSecureCookies = url.protocolIs("https"_s)
        ? WebCore::IncludeSecureCookies::Yes : WebCore::IncludeSecureCookies::No;

    auto [cookieHeader, secureCookiesAccessed] = storageSession->cookieRequestHeaderFieldValue(
        firstParty, sameSiteInfo, url, task->frameID(), task->pageID(), includeSecureCookies,
        WebCore::ApplyTrackingPrevention::Yes,
        session->networkProcess().shouldRelaxThirdPartyCookieBlockingForPage(task->webPageProxyID()),
        WebKit::NetworkSession::isResourceFromKnownCrossSiteTracker(firstParty, url));
    (void)secureCookiesAccessed;
    return cookieHeader; // null/empty => ITP blocked all cookies => caller injects NO Cookie header
}

// W3093 (FOUNDER "no new-tab IP panel" / new-tab "PAGE FAILED TO LOAD"): the GUI sends a fixed new-tab
// sentinel URL (driftstack.dev/newtab) which the box previously fetched THROUGH the SOCKS5 proxy — a
// proxy hiccup blanked the whole tab. A2 Option-1: intercept the sentinel at the loader + serve a
// self-contained, box-local panel with ZERO egress (no proxy hop → it can never fail to load). The
// exit_identity (the IP/geo/tz + QUIC availability the world sees THROUGH the proxy) is baked in from
// DRIFTSTACK_EXIT_IDENTITY_JSON, which the harness sets from the W3091-decoded assign block; when unset
// (before A2's populate lands) the page renders with graceful placeholders.
static bool driftstackIsNewTabSentinel(const URL& url)
{
    if (!url.protocolIs("https"_s))
        return false;
    auto host = url.host();
    if (host != "driftstack.dev"_s && host != "www.driftstack.dev"_s)
        return false;
    auto path = url.path();
    return path == "/newtab"_s || path == "/newtab/"_s;
}

static const char* kDriftstackNewTabHead = R"NT(<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover"><title>New Tab</title><style>:root{color-scheme:dark}*{box-sizing:border-box;-webkit-user-select:none;user-select:none}html,body{margin:0;height:100%}body{background:#0b0d12;color:#e8eaf0;font:15px/1.4 -apple-system,"SF Pro Text",system-ui,sans-serif;display:flex;align-items:center;justify-content:center;padding:env(safe-area-inset-top) 20px env(safe-area-inset-bottom)}.card{width:100%;max-width:360px;background:#151922;border:1px solid #232a37;border-radius:18px;padding:22px 20px;box-shadow:0 10px 40px rgba(0,0,0,.4)}.brand{font-size:12px;letter-spacing:.08em;text-transform:uppercase;color:#6b7488;margin:0 0 14px}.ip{font:600 30px/1.1 "SF Mono",ui-monospace,monospace;letter-spacing:-.01em;word-break:break-all;margin:0 0 4px}.loc{font-size:15px;color:#aab3c5;margin:0 0 18px;min-height:1.4em}.rows{display:grid;gap:10px}.row{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:11px 13px;background:#0f131b;border:1px solid #1e2530;border-radius:12px}.row .k{color:#7d879b;font-size:13px}.row .v{font-weight:600;text-align:right}.dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:7px;vertical-align:1px}.ok{background:#34c759}.off{background:#3a4152}.foot{margin:16px 2px 0;font-size:11px;color:#5a6379}.mono{font-family:"SF Mono",ui-monospace,monospace}</style>)NT";

static const char* kDriftstackNewTabTail = R"NT(</head><body><main class="card" role="main"><p class="brand">Driftstack &middot; Session</p><p class="ip mono" id="ip">&mdash;</p><p class="loc" id="loc"></p><div class="rows"><div class="row"><span class="k">Timezone</span><span class="v" id="tz">&mdash;</span></div><div class="row"><span class="k">HTTP/3 &middot; QUIC</span><span class="v" id="quic">&mdash;</span></div><div class="row"><span class="k">Country</span><span class="v" id="country">&mdash;</span></div></div><p class="foot" id="foot"></p></main><script>(function(){var q=window.__DS_EXIT_IDENTITY||{};function set(id,v){var el=document.getElementById(id);if(el)el.textContent=v;}var ip=q.ip;set("ip",ip&&ip.length?ip:"No exit IP");var city=q.city,region=q.region,country=q.country;var parts=[city,region].filter(function(x){return x&&x.length;});set("loc",parts.length?parts.join(", "):(country?"":"Location unavailable"));set("tz",q.timezone||"—");set("country",country||"—");var qe=document.getElementById("quic");var quic=q.quic_ok;if(qe){if(quic===true)qe.innerHTML='<span class="dot ok"></span>Available';else if(quic===false)qe.innerHTML='<span class="dot off"></span>Unavailable';else qe.textContent="—";}var at=q.probed_at;if(at){var d=new Date(at);set("foot",isNaN(d.getTime())?"":("Verified "+d.toLocaleString()));}})();</script></body></html>)NT";

// Build the served bytes = head + <script>window.__DS_EXIT_IDENTITY=<JSON>;</script> + tail. The JSON
// comes from the env var (CP-sourced via the harness). Injection safety: it lands inside a <script>, so
// reject any value carrying a `</` script-close tell and fall back to {} (placeholders).
static String driftstackFromUTF8CStr(const char* s)
{
    return String::fromUTF8(std::span<const uint8_t> { reinterpret_cast<const uint8_t*>(s), strlen(s) });
}

static Vector<uint8_t> driftstackNewTabPanelBytes()
{
    const char* ei = getenv("DRIFTSTACK_EXIT_IDENTITY_JSON");
    String json = (ei && *ei) ? driftstackFromUTF8CStr(ei) : String("{}"_s);
    if (json.isNull() || json.contains("</"_s))
        json = "{}"_s;
    auto utf8 = makeString(driftstackFromUTF8CStr(kDriftstackNewTabHead),
        "<script>window.__DS_EXIT_IDENTITY="_s, json, ";</script>"_s,
        driftstackFromUTF8CStr(kDriftstackNewTabTail)).utf8();
    Vector<uint8_t> out;
    out.append(std::span<const uint8_t> { reinterpret_cast<const uint8_t*>(utf8.data()), utf8.length() });
    return out;
}

void DriftstackNetworkLoader::resume()
{
    // W3093 — new-tab sentinel intercept. FIRST thing, before admission/egress: serve the box-local panel
    // directly with no proxy hop (kills the new-tab "PAGE FAILED TO LOAD"). No admission slot is taken.
    if (driftstackIsNewTabSentinel(m_request.url())) {
        URL ntURL = m_request.url();
        auto bytes = driftstackNewTabPanelBytes();
        WebCore::ResourceResponse ntResponse { URL(ntURL), String("text/html"_s), static_cast<long long>(bytes.size()), String("UTF-8"_s) };
        ntResponse.setHTTPStatusCode(200);
        ntResponse.setHTTPHeaderField("content-type"_s, "text/html; charset=utf-8"_s);
        ntResponse.setHTTPHeaderField("cache-control"_s, "no-store"_s);
        auto ntBody = WebCore::SharedBuffer::create(bytes.span());
        if (!tryBeginCompletion()) return;
        Ref<DriftstackNetworkLoader> ntProtected { *this };
        callOnMainRunLoop([ntProtected, ntResponse = WebCore::ResourceResponse(ntResponse), ntBody = std::move(ntBody)]() mutable {
            RefPtr task = ntProtected->protectedTask();
            if (!task) return;
            RefPtr client = task->client();
            if (!client) return;
            client->didReceiveResponse(std::move(ntResponse), NegotiatedLegacyTLS::No, PrivateRelayed::No,
                [ntProtected, ntBody = std::move(ntBody)](WebCore::PolicyAction action) mutable {
                    if (action != WebCore::PolicyAction::Use) return;
                    RefPtr task = ntProtected->protectedTask();
                    if (!task) return;
                    RefPtr client = task->client();
                    if (!client) return;
                    client->didReceiveData(ntBody.get());
                    WebCore::NetworkLoadMetrics metrics;
                    client->didCompleteWithError(WebCore::ResourceError(), metrics);
                });
        });
        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/W3093] served box-local new-tab panel (%zuB, no proxy hop)", bytes.size());
        return;
    }
    // BUG-42 Fix #2 (egress-reliability, gated) — process-wide concurrent-REQUEST
    // admission. MUST run FIRST, before any per-call work below (cookie header, body
    // flatten, ++m_attempt, retry-deadline stamping): on saturation we defer the WHOLE
    // resume() to the main queue, and the deferred re-entry must NOT have consumed a
    // retry attempt or re-flattened the body. resume() always runs on the main thread
    // (initial NetworkDataTaskCocoa::resume; retry/redirect re-resume via the main
    // queue), so a non-blocking try-acquire here can never stall a GCD worker — and we
    // only submit the blocking dispatch_async block (below) once a slot is HELD, so the
    // ~64-worker GCD pool can never be saturated past the cap. A retry/redirect that
    // re-enters resume() already holds its slot (m_admissionSlotHeld) and proceeds
    // immediately. Gate-off: skipped entirely → byte-identical to the prior code.
    if (driftstackAdmissionPacingEnabled() && !m_cancelled) {
        if (!tryAcquireAdmissionSlot()) {
            // Cap saturated. Don't block the main thread and don't pin a GCD worker:
            // re-schedule this resume() after a short backoff so an in-flight request
            // can release its slot first. Bound the deferral loop (50 × ~20ms ≈ 1s) so
            // a persistently-wedged cap degrades to proceed-without-a-slot (prior
            // unbounded behaviour for this ONE request) rather than starving forever.
            constexpr int kMaxAdmissionDeferrals = 50;
            if (m_admissionDeferrals < kMaxAdmissionDeferrals) {
                ++m_admissionDeferrals;
                Ref<DriftstackNetworkLoader> deferRef { *this };
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, static_cast<int64_t>(20) * NSEC_PER_MSEC),
                    dispatch_get_main_queue(), ^{
                        if (!deferRef->m_cancelled) deferRef->resume();
                    });
                return;
            }
            WTFLogAlways("[BUG-42/Fix2] request-admission cap saturated >%dx — proceeding without a slot for %s",
                kMaxAdmissionDeferrals, m_request.url().host().toString().utf8().data());
            // fall through: proceed without a slot (m_admissionSlotHeld stays false → no
            // release later for this request, and it doesn't count against the cap).
        }
    }

    // Capture request data on the calling thread; do network work async.
    URL url = m_request.url();
    String httpMethod = m_request.httpMethod();
    if (httpMethod.isEmpty()) httpMethod = "GET"_s;
    auto httpHeaders = m_request.httpHeaderFields();
    // PathB v2 ITP (main thread, before dispatch): (a) compute the ITP-filtered Cookie header ONCE and
    // thread it to all transports; (b) apply the 3rd-party Referer->origin downgrade in-place, replicating
    // NetworkDataTask::restrictRequestReferrerToOriginIfNeeded (that method is protected on NetworkDataTask,
    // not callable here). Both must happen here: ResourceRequest + the ITP state are not thread-safe on loaderQueue.
    String driftstackCookieHeader = driftstackITPCookieHeader();
    if (RefPtr task = protectedTask()) {
        if (WebKit::NetworkSession* session = task->networkSession()) {
            if ((session->sessionID().isEphemeral() || session->isTrackingPreventionEnabled())
                && session->shouldDowngradeReferrer() && m_request.isThirdParty())
                m_request.setExistingHTTPReferrerToOriginString();
        }
    }
    // Re-read headers AFTER the possible referer downgrade so every transport forwards the downgraded value.
    httpHeaders = m_request.httpHeaderFields();
    // BUG-42 Fix #4 + #6 (egress-reliability, gated) — capture the per-PAGE key and the
    // third-party flag HERE, on the main thread, while m_request + the task are safe to
    // touch (webPageProxyID() / isThirdParty() are not thread-safe on loaderQueue). Both
    // feed the retry-budget decision below. Computed unconditionally (cheap); only CONSUMED
    // when the gate is on.
    //
    // #42 ROOT-CAUSE FIX: the prior `m_request.isThirdParty()` (= url vs firstPartyForCookies)
    // and `webPageProxyID()` both empirically read FALSE/0 on the PathB-v2 custom-TLS loader for
    // the westernunion 3p-tracker storm (firstParty empty on the loader's request copy; page-proxy
    // id 0 on the subresource path) → both Fix4's 8s 3p fast-fail and Fix6's per-page deadline
    // collapsed to gate-OFF behaviour. Recover both signals from the initiating document's origin
    // (NetworkLoadParameters::sourceOrigin — ctor-set, never lazily synced) as a fallback.
    uint64_t webPageProxyKey = 0;
    WebCore::SecurityOrigin* sourceOriginPtr = nullptr;
    if (RefPtr task = protectedTask()) {
        if (auto id = task->webPageProxyID())
            webPageProxyKey = id->toUInt64();
#if PLATFORM(DRIFTSTACK)
        sourceOriginPtr = task->driftstackSourceOrigin();
#endif
    }
    const bool requestIsThirdParty = driftstackRequestIsThirdParty(m_request, sourceOriginPtr);
    const uint64_t pageKey = driftstackPageKeyFor(webPageProxyKey, m_request, sourceOriginPtr);
    if (driftstackEgressReliabilityEnabled()) {
        // One-time-per-process diagnostic so the #42 canary can confirm the predicates now FIRE
        // (and which source supplied them). Gated → byte-identical no-op when egress-reliability off.
        static bool loggedPredicatesOnce = false;
        if (!loggedPredicatesOnce) {
            loggedPredicatesOnce = true;
            WTFLogAlways("[BUG-42/Fix4+6] predicate-capture: requestIsThirdParty=%d pageKey=%llu (webPageProxyKey=%llu rawIsThirdParty=%d firstPartyEmpty=%d sourceOrigin=%d) url=%s",
                requestIsThirdParty,
                static_cast<unsigned long long>(pageKey),
                static_cast<unsigned long long>(webPageProxyKey),
                m_request.isThirdParty(),
                (m_request.firstPartyForCookies().isNull() || m_request.firstPartyForCookies().isEmpty()),
                !!sourceOriginPtr,
                url.host().toString().utf8().data());
        }
    }
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
        // Wave 29-499.348 — full body resolution (data + file parts). A failure
        // here (file vanished/unreadable since the eligibility check) FAILS the
        // load — never send a partial body.
        if (!driftstackResolveRequestBody(*fd, requestBody)) {
            WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.348] request-body resolution FAILED (file part unreadable) for %s — failing load", url.string().utf8().data());
            // W2202 STEP 5: this branch runs synchronously on the main thread (inside resume()),
            // but the callOnMainRunLoop re-defers delivery → re-acquire task/client inside the block.
            RefPtr task = protectedTask();
            if (task) {
                WebCore::ResourceError error(String("DriftstackNetworkLoader"_s), 0, URL(url), "request body file part unreadable"_s, WebCore::ResourceError::Type::General);
                if (!tryBeginCompletion()) return;
                callOnMainRunLoop([protectedThis = Ref { *this }, error = std::move(error)]() mutable {
                    RefPtr task = protectedThis->protectedTask();
                    if (!task)
                        return;
                    RefPtr client = task->client();
                    if (!client)
                        return;
                    WebCore::NetworkLoadMetrics metrics;
                    client->didCompleteWithError(error, metrics);
                });
            }
            return;
        }
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
    // W2750 (#20 first-load latency, founder "unrealistically slow ~76s — can't be proxy-only"): bound the TOTAL
    // retry wall-clock, not just the count. The 150-600ms backoff (~3.9s) was the only prior bound, but it ignored
    // each attempt's connect+TLS-handshake cost — a slow/flaky exit burns up to the 6s TLS / 8s SOCKS5 recv timeout
    // PER attempt, so 8 attempts compounded to ~50-76s (matching the report). Budget the chain to 20s: a FAST proxy
    // still gets all 8 attempts (8 quick ClientHello-reject fails fit easily in 20s, preserving the ~99.6% flaky
    // success), but a consistently-SLOW exit gives up at ~20s (page errors) instead of ~76s. Slow ORIGINS are NOT
    // retries (a single attempt awaiting the response), so they are unaffected. Deadline set once, on attempt 1.
    // BUG-42 Fix #4 (gated): a THIRD-PARTY parser-blocking fetch that hangs in <head>
    // stalls DOMContentLoaded even under pageLoadStrategy=eager. Give 3rd-party requests
    // a TIGHTER per-request budget (default 8s) so a wedged cross-origin tracker script
    // fails fast → the HTML parser proceeds past the errored script → the page becomes
    // drivable. First-party requests keep the full 20s W2750 budget. Gate-off: always 20s.
    if (currentAttempt == 1) {
        Seconds perRequestBudget = Seconds(20);
        // #46: the 8s 3p fast-fail STAYS on EGRESS_RELIABILITY (NOT the new concurrency gate) — W2994
        // disabled it because too-tight deadlines crashed pages on real residential NodeMaven RTT. The new
        // EGRESS_CONCURRENCY gate ships ONLY the pure-pacing caps (admission + handshake), the proven RANK-1
        // hang fix with no crash history; the deadlines re-enable separately after a wider NodeMaven verify.
        if (driftstackEgressReliabilityEnabled() && requestIsThirdParty)
            perRequestBudget = driftstackThirdPartyRetryBudget();
        m_retryDeadline = MonotonicTime::now() + perRequestBudget;
    }
    bool withinRetryBudget = MonotonicTime::now() < m_retryDeadline;
    // BUG-42 Fix #6 (gated): also bound the retry decision by the per-PAGE aggregate
    // deadline shared across every request belonging to this page, so dozens of
    // concurrent slow subresources can't compound the page-load wall-clock past the
    // budget (the cause of the WD navigate timeout on heavy multi-origin sites). The
    // first request for a page stamps the deadline; all later requests + retries honour
    // it. Gate-off no-op: driftstackPageDeadlineFor is only consulted when the gate is on.
    // #46: the per-page deadline STAYS on EGRESS_RELIABILITY (NOT the new concurrency gate) — same W2994
    // crash-risk reasoning as the 3p fast-fail above; only the admission/handshake caps ship under EGRESS_CONCURRENCY.
    if (driftstackEgressReliabilityEnabled() && pageKey) {
        MonotonicTime pageDeadline = driftstackPageDeadlineFor(pageKey);
        if (pageDeadline && MonotonicTime::now() >= pageDeadline) {
            withinRetryBudget = false;
            WTFLogAlways("[BUG-42/Fix6] page-deadline reached for page %llu — no further retries for %s", static_cast<unsigned long long>(pageKey), url.host().toString().utf8().data());
        }
    }
    const bool canRetry = (currentAttempt < kMaxAttempts) && withinRetryBudget;
    int64_t retryBaseMs = static_cast<int64_t>(150) << (currentAttempt - 1);
    if (retryBaseMs > 600) retryBaseMs = 600;
    // W3067 (slow-proxy tuning): add equal-jitter (half fixed + half random) so retries DESYNCHRONIZE.
    // Without jitter, many subresources that failed at the same instant (a flaky proxy blip / one dead
    // exit) all retry in lockstep -> a thundering herd that re-hammers the already-struggling proxy and
    // makes the blip worse. Spreading each retry over [base/2, base] is the standard resilient-client
    // behavior under flaky networks (AWS backoff guidance). Pure timing — wire/fingerprint-neutral.
    int64_t retryDelayMs = retryBaseMs / 2 + static_cast<int64_t>(arc4random_uniform(static_cast<uint32_t>(retryBaseMs / 2) + 1));

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
            RefPtr task = protectedTask();
            if (task) {
                WebCore::ResourceError error(String("DriftstackNetworkLoader"_s), 0, URL(url), "DRIFTSTACK_SOCKS5_PROXY not set"_s, WebCore::ResourceError::Type::General);
                if (!tryBeginCompletion()) return;  // Wave .325 single-completion guard
                callOnMainRunLoop([protectedThis, error = std::move(error)]() mutable {
                    RefPtr task = protectedThis->protectedTask();
                    if (!task)
                        return;
                    RefPtr client = task->client();
                    if (!client)
                        return;
                    WebCore::NetworkLoadMetrics metrics;
                    client->didCompleteWithError(error, metrics);
                });
            }
            return;
        }

        String proxyEnvStr = String::fromUTF8(proxyEnv);
        size_t colon = proxyEnvStr.find(':');
        if (colon == notFound) {
            // W2200 (fork-egress audit): a malformed DRIFTSTACK_SOCKS5_PROXY must FAIL the load (mirror the
            // no-proxy branch above), not bare-return — a bare return left m_completionStarted=false forever →
            // the request hung until the page-load watchdog (the NSURLSession path was already bypassed).
            RefPtr task = protectedTask();
            if (task) {
                WebCore::ResourceError error(String("DriftstackNetworkLoader"_s), 0, URL(url), "DRIFTSTACK_SOCKS5_PROXY malformed (no host:port colon)"_s, WebCore::ResourceError::Type::General);
                if (!tryBeginCompletion()) return;
                callOnMainRunLoop([protectedThis, error = std::move(error)]() mutable {
                    RefPtr task = protectedThis->protectedTask();
                    if (!task)
                        return;
                    RefPtr client = task->client();
                    if (!client)
                        return;
                    WebCore::NetworkLoadMetrics metrics;
                    client->didCompleteWithError(error, metrics);
                });
            }
            return;
        }
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
        if (proxyPort == 0) {
            // W2200: same fail-closed contract as the malformed-colon branch above (was a bare-return hang).
            RefPtr task = protectedTask();
            if (task) {
                WebCore::ResourceError error(String("DriftstackNetworkLoader"_s), 0, URL(url), "DRIFTSTACK_SOCKS5_PROXY malformed (bad/zero port)"_s, WebCore::ResourceError::Type::General);
                if (!tryBeginCompletion()) return;
                callOnMainRunLoop([protectedThis, error = std::move(error)]() mutable {
                    RefPtr task = protectedThis->protectedTask();
                    if (!task)
                        return;
                    RefPtr client = task->client();
                    if (!client)
                        return;
                    WebCore::NetworkLoadMetrics metrics;
                    client->didCompleteWithError(error, metrics);
                });
            }
            return;
        }

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
            // Wave 29-499.357 — SSE (text/event-stream) must NOT take the h3 path.
            // driftstackHttp3Execute BUFFERS the whole response, so an infinite
            // EventSource would HANG forever (h3 + DNS-RR are both on in launch-env,
            // so this is a live bug for any h3-advertising host — Cloudflare/Google
            // etc.). The h2/TCP path streams SSE incrementally (Wave .350); exclude
            // it from h3 exactly like a request body is excluded.
            bool h3IsSSE = false;
            for (auto& h : httpHeaders) {
                if (equalIgnoringASCIICase(h.key, "accept"_s) && h.value.containsIgnoringASCIICase("text/event-stream"_s)) {
                    h3IsSSE = true;
                    break;
                }
            }
            bool h3bodyless = (equalIgnoringASCIICase(httpMethod, "GET"_s)
                || equalIgnoringASCIICase(httpMethod, "HEAD"_s)) && !hasRequestBody && !h3IsSSE;
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
            // Wave 29-499.356 — first-contact DNS-HTTPS-RR h3 probe for the main-frame
            // navigation AND cross-origin subresources. The earlier .349 gate restricted
            // this to top-level navigations only (to stop many concurrent subresource RR
            // lookups from stalling a page → ja3/tls1x "N/A"). But that BROKE QUIC on
            // cross-origin endpoints whose fp is measured ON FIRST CONTACT — e.g.
            // quic.browserleaks.com is a SUBRESOURCE fetch, never a top-level nav, so it
            // went h2/TCP and browserleaks.com/quic reported "no QUIC" (Alt-Svc upgrades
            // too late — the connection is already h2). The original stall is now bounded
            // by two mechanisms already in driftstackHostAdvertisesH3ViaDns: (1) ONE shared
            // §7 DNS relay + background reader + txid demux → responses arrive in ~one
            // proxy-RTT (~120ms), not the 800ms cap; (2) a 6-way concurrency semaphore that
            // returns immediately (h2) when saturated. So subresource probes no longer
            // starve the worker pool. Per-host cache means each origin is probed at most once.
            // BUG-42 Fix #1 (gated): mirror the W2648 Alt-Svc gate at the next branch
            // and skip the first-contact DNS-HTTPS-RR probe once the no-UDP latch is
            // down — otherwise every novel HTTPS host fires a ~4s associate even on a
            // known-no-UDP proxy (the DNS-spinner amplifier). Gate-off no-op: the added
            // term collapses to `true` (!driftstackEgressReliabilityEnabled() short-
            // circuits), leaving the original condition byte-identical.
            if (s_dnsRrEnabled && h3enabled && h3https && h3bodyless && !h3forced
                && !driftstackLoaderHostKnownH3(h3host)
                && (!driftstackEgressReliabilityEnabled() || !WebKit::driftstackUdpRelayKnownDown())) {
                if (WebKit::driftstackHostAdvertisesH3ViaDns(h3host))
                    driftstackLoaderRememberH3Host(h3host);
            }
            // W2648 (audit udp-1): the Alt-Svc-learned known-h3 registry bypassed the no-UDP latch — on a
            // no-UDP proxy, request 1 went h2 and learned `alt-svc: h3`, then request 2+ took THIS gate and
            // hung ~4-16s per request (silent white screen). Consult the shared latch here too, so once UDP is
            // known-down every request (DNS-RR gate AND this Alt-Svc gate) chooses h2/TCP.
            if (h3enabled && h3https && h3bodyless && !WebKit::driftstackUdpRelayKnownDown() && (h3forced || driftstackLoaderHostKnownH3(h3host))) {
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
                // TIER-4 wire H3 regular-header ORDER — same real-iPhone-17 raw-wire order as the H2
                // builder above (sec-fetch-dest, user-agent, accept, [referer], sec-fetch-site,
                // sec-fetch-mode, accept-language, priority, accept-encoding). Values unchanged.
                // W3068-CORS (JA4H tracker-path, mirror of the h2 builder): a cross-origin fetch/XHR
                // GET uses a different regular-header order than nav. Same iPhone-17 raw-wire cors GET
                // order. h3 has no extras loop, so pragma/cache-control are placed here only if present.
                bool isCorsGet = (httpMethod == "GET"_s) && wk.get("sec-fetch-mode"_s) == "cors"_s;
                if (isCorsGet) {
                    if (wk.contains("pragma"_s)) h3req.extraHeaders.append({ "pragma"_s, wk.get("pragma"_s) });
                    h3req.extraHeaders.append({ "accept"_s, orDefault("accept"_s, "*/*"_s) });
                    if (wk.contains("sec-fetch-site"_s)) h3req.extraHeaders.append({ "sec-fetch-site"_s, wk.get("sec-fetch-site"_s) });
                    if (wk.contains("sec-fetch-mode"_s)) h3req.extraHeaders.append({ "sec-fetch-mode"_s, wk.get("sec-fetch-mode"_s) });
                    h3req.extraHeaders.append({ "user-agent"_s, wk.contains("user-agent"_s) ? wk.get("user-agent"_s) : driftstackPathBUserAgentFallback() });
                    if (wk.contains("referer"_s)) h3req.extraHeaders.append({ "referer"_s, wk.get("referer"_s) });
                    if (wk.contains("sec-fetch-dest"_s)) h3req.extraHeaders.append({ "sec-fetch-dest"_s, wk.get("sec-fetch-dest"_s) });
                    if (wk.contains("cache-control"_s)) h3req.extraHeaders.append({ "cache-control"_s, wk.get("cache-control"_s) });
                    h3req.extraHeaders.append({ "accept-language"_s, driftstackPathBAcceptLanguage() });
                    h3req.extraHeaders.append({ "priority"_s, wk.contains("priority"_s) ? wk.get("priority"_s)
                        : driftstackPathBPriorityHeader(wk.get("sec-fetch-dest"_s), orDefault("accept"_s, "*/*"_s)) });
                    h3req.extraHeaders.append({ "accept-encoding"_s, driftstackPathBAcceptEncoding() });
                } else {
                if (wk.contains("sec-fetch-dest"_s)) h3req.extraHeaders.append({ "sec-fetch-dest"_s, wk.get("sec-fetch-dest"_s) });
                h3req.extraHeaders.append({ "user-agent"_s, wk.contains("user-agent"_s) ? wk.get("user-agent"_s) : driftstackPathBUserAgentFallback() });
                h3req.extraHeaders.append({ "accept"_s, orDefault("accept"_s, "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"_s) });
                if (wk.contains("referer"_s)) h3req.extraHeaders.append({ "referer"_s, wk.get("referer"_s) });
                if (wk.contains("sec-fetch-site"_s)) h3req.extraHeaders.append({ "sec-fetch-site"_s, wk.get("sec-fetch-site"_s) });
                if (wk.contains("sec-fetch-mode"_s)) h3req.extraHeaders.append({ "sec-fetch-mode"_s, wk.get("sec-fetch-mode"_s) });
                h3req.extraHeaders.append({ "accept-language"_s, driftstackPathBAcceptLanguage() });
                // P3/W2438 (#61): derive the RFC 9218 `priority` (u=0 nav / u=3 fetch) when WebKit
                // doesn't supply one — h3 bypasses CFNetwork same as h2 (see the h2 builder note).
                h3req.extraHeaders.append({ "priority"_s, wk.contains("priority"_s) ? wk.get("priority"_s)
                    : driftstackPathBPriorityHeader(wk.get("sec-fetch-dest"_s), orDefault("accept"_s, "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"_s)) });
                h3req.extraHeaders.append({ "accept-encoding"_s, driftstackPathBAcceptEncoding() });
                }
                // PathB v2 ITP: inject the ITP-filtered Cookie header (computed on the main thread). Empty => omit.
                if (!driftstackCookieHeader.isEmpty())
                    h3req.extraHeaders.append({ "cookie"_s, driftstackCookieHeader });

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

                {
                RefPtr task = protectedTask();
                if (!task) return;
                }
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
                    // PathB v2 egress Set-Cookie WRITE — extract RAW un-folded Set-Cookie from h3resp.headers
                    // (NOT response.httpHeaderField, which folds duplicates with commas).
                    Vector<String> h3SetCookies = driftstackExtractRawSetCookies(h3resp.headers);
                    if (tryFollowRedirect(response, h3SetCookies)) return;  // Wave .344 — follow 3xx like Safari, don't render the redirect page (redirect Set-Cookie persisted inside)
                    WebKit::driftstackDecodeContentEncoding(h3resp.body, h3resp.headers);  // .331 chokepoint
                    auto bodyBuffer = WebCore::SharedBuffer::create(h3resp.body.span());
                    if (!tryBeginCompletion()) return;  // Wave .325 single-completion guard
                    // Final (non-redirect) response: persist Set-Cookie after the single-completion guard wins
                    // (so an overlapping re-delivery can't double-store). Main thread; ordered before delivery.
                    if (!h3SetCookies.isEmpty()) {
                        Ref<DriftstackNetworkLoader> cookieRef { *this };
                        callOnMainRunLoop([cookieRef = WTF::move(cookieRef), responseURL = URL(url), h3SetCookies = WTF::move(h3SetCookies)]() mutable {
                            cookieRef->driftstackPersistSetCookies(responseURL, h3SetCookies);
                        });
                    }
                    callOnMainRunLoop([protectedThis, response = WebCore::ResourceResponse(response), bodyBuffer = std::move(bodyBuffer)]() mutable {
                        RefPtr task = protectedThis->protectedTask();
                        if (!task)
                            return;
                        RefPtr client = task->client();
                        if (!client)
                            return;
                        client->didReceiveResponse(std::move(response), NegotiatedLegacyTLS::No, PrivateRelayed::No,
                            [protectedThis, bodyBuffer = std::move(bodyBuffer)](WebCore::PolicyAction action) mutable {
                                if (action == WebCore::PolicyAction::Use) {
                                    RefPtr task = protectedThis->protectedTask();
                                    if (!task)
                                        return;
                                    RefPtr client = task->client();
                                    if (!client)
                                        return;
                                    client->didReceiveData(bodyBuffer.get());
                                    WebCore::NetworkLoadMetrics metrics;
                                    client->didCompleteWithError(WebCore::ResourceError(), metrics);
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
            // W3046: a GOAWAY-churning origin's pooled reuse always fails → skip the pool entirely (go
            // direct fresh connect, no wasted failed-reuse + no re-adopt) so its beacon storm can't saturate
            // the shared admission/handshake caps the real page content needs.
            auto h2Claim = driftstackH2OriginChurning(origin)
                ? std::pair<RefPtr<WebKit::DriftstackHttp2Session>, bool> { nullptr, false }
                : driftstackH2PoolClaim(origin);
            h2PoolWinner = h2Claim.second;
            if (RefPtr<WebKit::DriftstackHttp2Session> session = h2Claim.first) {
                String poolHost = url.host().toString();
                auto h2req = driftstackBuildIphoneH2Request(url, httpMethod, httpHeaders, requestBody, poolHost, driftstackCookieHeader);
                // a74622fc Phase 1 — the success-handling logic factored into a lambda so it can be
                // invoked either synchronously (gate-off, blocking execute() — behavior UNCHANGED) or
                // from submitAsync's onComplete callback (gate-on) without duplicating the mime/
                // redirect/cookie/decompress/deliver logic. Returns true if it fully handled the
                // response (caller must return immediately, matching today's `return;`), false if the
                // caller should fall through to the fresh-connect path below (pooled session failed).
                Ref<DriftstackNetworkLoader> protectedThisForH2 { *this };
                auto finishH2Response = [protectedThisForH2, url, origin](WebKit::DriftstackHttp2Response&& h2resp) -> bool {
                    auto& loader = protectedThisForH2.get();
                    RefPtr task = loader.protectedTask();
                    if (!task) return true; // task gone — nothing more to do, don't fall through either
                    if (!h2resp.failed && h2resp.statusCode) {
                        driftstackH2NoteHealthy(origin);   // W3046: pooled reuse worked — clear any churn strike
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
                        WebCore::ResourceResponse response { URL(url), std::move(mimeType), expectedLength, std::move(charset) };
                        response.setHTTPStatusCode(h2resp.statusCode);
                        for (auto& [k, v] : h2resp.headers)
                            response.setHTTPHeaderField(k, v);
                        // PathB v2 egress Set-Cookie WRITE — raw un-folded Set-Cookie from h2resp.headers.
                        Vector<String> h2SetCookies = driftstackExtractRawSetCookies(h2resp.headers);
                        if (loader.tryFollowRedirect(response, h2SetCookies)) return true;  // Wave .344 — follow 3xx like Safari, don't render the redirect page (redirect Set-Cookie persisted inside)
                        WebKit::driftstackDecodeContentEncoding(h2resp.body, h2resp.headers);  // .331 chokepoint
                        auto bodyBuffer = WebCore::SharedBuffer::create(h2resp.body.span());
                        if (!loader.tryBeginCompletion()) return true;  // Wave .325 single-completion guard
                        // Final (non-redirect) response: persist Set-Cookie after the single-completion guard wins.
                        if (!h2SetCookies.isEmpty()) {
                            Ref<DriftstackNetworkLoader> cookieRef { loader };
                            callOnMainRunLoop([cookieRef = WTF::move(cookieRef), responseURL = URL(url), h2SetCookies = WTF::move(h2SetCookies)]() mutable {
                                cookieRef->driftstackPersistSetCookies(responseURL, h2SetCookies);
                            });
                        }
                        Ref<DriftstackNetworkLoader> protectedThis { loader };
                        callOnMainRunLoop([protectedThis, response = WebCore::ResourceResponse(response), bodyBuffer = std::move(bodyBuffer)]() mutable {
                            RefPtr task = protectedThis->protectedTask();
                            if (!task)
                                return;
                            RefPtr client = task->client();
                            if (!client)
                                return;
                            client->didReceiveResponse(std::move(response), NegotiatedLegacyTLS::No, PrivateRelayed::No,
                                [protectedThis, bodyBuffer = std::move(bodyBuffer)](WebCore::PolicyAction action) mutable {
                                    if (action == WebCore::PolicyAction::Use) {
                                        RefPtr task = protectedThis->protectedTask();
                                        if (!task)
                                            return;
                                        RefPtr client = task->client();
                                        if (!client)
                                            return;
                                        client->didReceiveData(bodyBuffer.get());
                                        WebCore::NetworkLoadMetrics metrics;
                                        client->didCompleteWithError(WebCore::ResourceError(), metrics);
                                    }
                                });
                        });
                        return true;
                    }
                    return false; // failed — caller falls through to fresh-connect
                };
                if (driftstackAsyncDeliveryEnabled()) {
                    // Non-blocking: submit and return immediately, freeing this GCD worker for the ENTIRE
                    // response duration (the actual fix — see driftstackAsyncDeliveryEnabled comment).
                    // On failure, mark the origin churning (identical accounting to the sync path below)
                    // then RE-ENTER resume() on the main queue — resume() re-derives everything from
                    // m_request and, seeing the origin now churning (driftstackH2OriginChurning, checked
                    // above where h2Claim is computed), naturally skips the pool and falls through to the
                    // EXISTING fresh-connect code — reusing that fallback path verbatim rather than
                    // duplicating it here.
                    auto accum = std::make_shared<WebKit::DriftstackHttp2Response>();
                    WebKit::DriftstackHttp2Session::AsyncStreamCallbacks cb;
                    cb.onHeaders = [accumPtr = accum.get()](int status, const Vector<std::pair<String, String>>& headers) {
                        accumPtr->statusCode = status;
                        accumPtr->headers = headers;
                    };
                    cb.onData = [accumPtr = accum.get()](const uint8_t* data, size_t length) {
                        accumPtr->body.append(std::span<const uint8_t> { data, length });
                    };
                    Ref<DriftstackNetworkLoader> protectedThisForRetry { *this };
                    cb.onComplete = [accum, finishH2Response, protectedThisForRetry, origin, httpMethod, url](bool failed, const String& errorMessage) mutable {
                        if (failed) {
                            accum->failed = true;
                            if (accum->errorMessage.isEmpty()) accum->errorMessage = errorMessage;
                        }
                        const String h2PooledErr = accum->errorMessage;   // W3088: capture BEFORE finishH2Response consumes accum
                        if (finishH2Response(std::move(*accum)))
                            return; // handled (success delivered, or task already gone)
                        driftstackH2NoteChurn(origin);   // W3046: count the churn; a persistently-GOAWAY origin trips the breaker (skip pool)
                        // W3088 (audit wxbeah3ef): re-entering resume() re-sends the request on a fresh connection
                        // → a double-submit for a non-idempotent method the server may have already processed. Same
                        // idempotency gate as the sync path: only re-enter (retry fresh) for idempotent / provably-
                        // not-processed; otherwise deliver the error without re-sending.
                        const bool idempotentMethod = equalIgnoringASCIICase(httpMethod, "GET"_s) || equalIgnoringASCIICase(httpMethod, "HEAD"_s)
                            || equalIgnoringASCIICase(httpMethod, "OPTIONS"_s) || equalIgnoringASCIICase(httpMethod, "PUT"_s)
                            || equalIgnoringASCIICase(httpMethod, "DELETE"_s) || equalIgnoringASCIICase(httpMethod, "TRACE"_s);
                        if (!idempotentMethod && !h2PooledErr.contains("not processed"_s)) {
                            WTFLogAlways("[Driftstack-EG-WK-PathB-v2/W3088] pooled h2 submitAsync failed for %s on non-idempotent %s that MAY have executed — NOT re-sending (avoid double-submit), delivering error", origin.utf8().data(), httpMethod.utf8().data());
                            if (!protectedThisForRetry->tryBeginCompletion()) return;  // Wave .325 single-completion guard
                            WebCore::ResourceError error(String("DriftstackNetworkLoader"_s), 0, URL(url),
                                h2PooledErr.isEmpty() ? String("h2 pooled reuse failed (non-idempotent, not retried to avoid double-submit)"_s) : h2PooledErr,
                                WebCore::ResourceError::Type::General);
                            callOnMainRunLoop([protectedThisForRetry, error = std::move(error)]() mutable {
                                RefPtr task = protectedThisForRetry->protectedTask();
                                if (!task) return;
                                RefPtr client = task->client();
                                if (!client) return;
                                WebCore::NetworkLoadMetrics metrics;
                                client->didCompleteWithError(error, metrics);
                            });
                            return;
                        }
                        WTFLogAlways("[Wave29-499.321/H2POOL] pooled session submitAsync failed for %s — re-entering resume() for fresh connect", origin.utf8().data());
                        callOnMainRunLoop([protectedThisForRetry] {
                            if (!protectedThisForRetry->m_cancelled)
                                protectedThisForRetry->resume();
                        });
                    };
                    session->submitAsync(h2req, std::move(cb));
                    return;
                }
                WebKit::DriftstackHttp2Response h2resp = session->execute(h2req);
                {
                RefPtr task = protectedTask();
                if (!task) return;
                }
                const String h2PooledErr = h2resp.errorMessage;   // W3088: capture BEFORE finishH2Response consumes h2resp
                if (finishH2Response(std::move(h2resp)))
                    return;
                // Pooled session failed (e.g. GOAWAY mid-flight).
                driftstackH2NoteChurn(origin);   // W3046: count the churn; a persistently-GOAWAY origin trips the breaker (skip pool)
                // W3088 (audit wxbeah3ef): the h2 HEADERS+body were ALREADY transmitted on the pooled stream,
                // which the server MAY have processed (RST/GOAWAY/conn-loss AFTER the request landed). Falling
                // through to a FRESH connection re-sends the identical body → a double-submit for a non-idempotent
                // method (double payment / double form post / duplicated write). Mirror the W3062 guard: fall
                // through (retry on a fresh connection) ONLY for an idempotent method OR a provably-not-processed
                // failure; otherwise deliver the error WITHOUT re-sending — a real iPhone never re-POSTs a sent request.
                {
                    const bool idempotentMethod = equalIgnoringASCIICase(httpMethod, "GET"_s) || equalIgnoringASCIICase(httpMethod, "HEAD"_s)
                        || equalIgnoringASCIICase(httpMethod, "OPTIONS"_s) || equalIgnoringASCIICase(httpMethod, "PUT"_s)
                        || equalIgnoringASCIICase(httpMethod, "DELETE"_s) || equalIgnoringASCIICase(httpMethod, "TRACE"_s);
                    if (!idempotentMethod && !h2PooledErr.contains("not processed"_s)) {
                        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/W3088] pooled h2 reuse failed for %s on non-idempotent %s that MAY have executed — NOT re-sending on a fresh connection (avoid double-submit), delivering error", origin.utf8().data(), httpMethod.utf8().data());
                        if (!tryBeginCompletion()) return;  // Wave .325 single-completion guard
                        Ref<DriftstackNetworkLoader> protectedThisDS { *this };
                        WebCore::ResourceError error(String("DriftstackNetworkLoader"_s), 0, URL(url),
                            h2PooledErr.isEmpty() ? String("h2 pooled reuse failed (non-idempotent, not retried to avoid double-submit)"_s) : h2PooledErr,
                            WebCore::ResourceError::Type::General);
                        callOnMainRunLoop([protectedThisDS, error = std::move(error)]() mutable {
                            RefPtr task = protectedThisDS->protectedTask();
                            if (!task) return;
                            RefPtr client = task->client();
                            if (!client) return;
                            WebCore::NetworkLoadMetrics metrics;
                            client->didCompleteWithError(error, metrics);
                        });
                        return;
                    }
                }
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

        // BUG-42 Fix #4 — global concurrent fresh-handshake cap. Acquire a slot
        // IMMEDIATELY before the fresh connect+TLS sequence (this loader is a
        // winner / last-resort own-connect here — the pool fast-path and pooled
        // reuse above already returned). Bounded wait (never FOREVER) so a saturated
        // cap can't extend a load past the per-request retry budget; on timeout we
        // proceed without a slot rather than fail (worst case = today's unbounded
        // behaviour for that one handshake). Released exactly once: either by the
        // scope-exit below (covering every connect/TLS/session-create early return,
        // the SSE return, and the retry-dispatch return) OR by the explicit release
        // right after the H2 winner publishes its session (before its first execute,
        // so the first multiplexed request isn't throttled). `handshakeSlotHeld`
        // makes the two mutually exclusive. Gate-off: no acquire, no release — true
        // no-op (handshakeSlotHeld stays false; the scope-exit does nothing).
        bool handshakeSlotHeld = false;
        bool originSlotHeld = false;
        dispatch_semaphore_t originConnectSem = nullptr;
        if (driftstackAdmissionPacingEnabled()) {
            // Cap the wait at the remaining retry budget (clamped to a sane floor) so
            // a fully-saturated cap degrades to proceed-without-slot, never a hang.
            Seconds remaining = m_retryDeadline - MonotonicTime::now();
            double waitSecs = remaining.value();
            if (waitSecs < 1.0) waitSecs = 1.0;
            if (waitSecs > 20.0) waitSecs = 20.0;
            // W3052 — per-ORIGIN fresh-connect cap FIRST (tighter than the global handshake
            // cap for a single flooding origin). Held through request completion (released by
            // the scope-exit below, NOT early at the H2-publish point), so it bounds the
            // origin's concurrent-REQUEST footprint — a churning tracker can occupy at most N
            // of the 24 admission slots. Pooled reuse never reaches here (fast path above).
            // Derive the key from the URL directly (h2PoolOrigin is only populated when the H2
            // pool is enabled AND https — for http / pool-off it's empty, which would collapse
            // every origin onto one shared semaphore and over-throttle).
            const String capOrigin = !h2PoolOrigin.isEmpty()
                ? h2PoolOrigin
                : makeString(url.host().toString(), ':', static_cast<unsigned>(url.port().value_or(url.protocolIs("https"_s) ? 443 : 80)));
            originConnectSem = driftstackOriginConnectSemaphore(capOrigin);
            dispatch_time_t originDeadline = dispatch_time(DISPATCH_TIME_NOW, static_cast<int64_t>(waitSecs * NSEC_PER_SEC));
            if (dispatch_semaphore_wait(originConnectSem, originDeadline) == 0)
                originSlotHeld = true;
            else
                WTFLogAlways("[W3052/Fix3] per-origin fresh-connect cap (%ld) saturated (>%.1fs) — proceeding for %s", driftstackMaxFreshConnectsPerOrigin(), waitSecs, capOrigin.utf8().data());
            // BUG-42 Fix #4 — global concurrent fresh-handshake cap. Recompute the remaining
            // budget so the two sequential waits together stay bounded by the request deadline.
            Seconds remaining2 = m_retryDeadline - MonotonicTime::now();
            double waitSecs2 = remaining2.value();
            if (waitSecs2 < 1.0) waitSecs2 = 1.0;
            if (waitSecs2 > 20.0) waitSecs2 = 20.0;
            dispatch_time_t deadline = dispatch_time(DISPATCH_TIME_NOW, static_cast<int64_t>(waitSecs2 * NSEC_PER_SEC));
            if (dispatch_semaphore_wait(driftstackHandshakeCapSemaphore(), deadline) == 0)
                handshakeSlotHeld = true;
            else
                WTFLogAlways("[BUG-42/Fix4] handshake-cap saturated (>%.1fs) — proceeding without a slot for %s", waitSecs2, url.host().toString().utf8().data());
        }
        auto handshakeCapGuard = WTF::makeScopeExit([&] {
            if (handshakeSlotHeld) {
                handshakeSlotHeld = false;
                dispatch_semaphore_signal(driftstackHandshakeCapSemaphore());
            }
            // W3052 — release the per-origin fresh-connect slot on EVERY exit (connect/TLS/
            // session-create early returns, SSE return, retry-dispatch return, and normal
            // completion after execute). Deliberately NOT early-released at the H2-publish
            // point (unlike the handshake slot): holding it through execute is what bounds the
            // origin's concurrent-REQUEST footprint, not merely its handshakes.
            if (originSlotHeld) {
                originSlotHeld = false;
                dispatch_semaphore_signal(originConnectSem);
            }
        });

        auto socks5Client = std::make_unique<DriftstackSocks5Client>(proxy, creds);
        auto handshakeResult = socks5Client->performHandshake();
        if (handshakeResult != Socks5Result::Success) {
            RefPtr task = protectedTask();
            if (task) {
                WebCore::ResourceError error(String("DriftstackNetworkLoader"_s), 0, URL(url), "SOCKS5 handshake failed"_s, WebCore::ResourceError::Type::General);
                if (!tryBeginCompletion()) return;  // Wave .325 single-completion guard
                callOnMainRunLoop([protectedThis, error = std::move(error)]() mutable {
                    RefPtr task = protectedThis->protectedTask();
                    if (!task)
                        return;
                    RefPtr client = task->client();
                    if (!client)
                        return;
                    WebCore::NetworkLoadMetrics metrics;
                    client->didCompleteWithError(error, metrics);
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
            // W2868 (#39): a network/host-unreachable REP (0x03/0x04) is PERMANENT for this proxy+dest (e.g. an
            // IPv6-literal dest via an IPv4-only proxy) — do NOT retry it. The 7× retry-storm burned the 45s nav
            // budget → the founder's -1001 page-load hang on a UDP proxy. Fail FAST so the page proceeds without
            // the dead resource (a domain/IPv4 dest still retries normally on transient ConnectFailed).
            bool destUnreachable = (connectResult == Socks5Result::DestinationUnreachable);
            if (destUnreachable)
                WTFLogAlways("[Driftstack-EG-WK-PathB-v2/W2868] SOCKS5 dest %s UNREACHABLE via proxy (network/host-unreachable) — fail fast, NO retry",
                    url.host().toString().utf8().data());
            if (canRetry && !destUnreachable) {
                WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.271] retry attempt=%d for SOCKS5 CONNECT to %s",
                    currentAttempt, url.host().toString().utf8().data());
                Ref<DriftstackNetworkLoader> retryRef { *this };
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, retryDelayMs * NSEC_PER_MSEC),
                    dispatch_get_main_queue(), ^{
                        if (!retryRef->m_cancelled) retryRef->resume();
                    });
                return;
            }
            RefPtr task = protectedTask();
            if (task) {
                WebCore::ResourceError error(String("DriftstackNetworkLoader"_s), 0, URL(url), "SOCKS5 CONNECT failed"_s, WebCore::ResourceError::Type::General);
                if (!tryBeginCompletion()) return;  // Wave .325 single-completion guard
                callOnMainRunLoop([protectedThis, error = std::move(error)]() mutable {
                    RefPtr task = protectedThis->protectedTask();
                    if (!task)
                        return;
                    RefPtr client = task->client();
                    if (!client)
                        return;
                    WebCore::NetworkLoadMetrics metrics;
                    client->didCompleteWithError(error, metrics);
                });
            }
            return;
        }

        int socketFd = socks5Client->socketFileDescriptor();
        m_fd = socketFd;

#if defined(DRIFTSTACK_HAS_BORINGSSL) && DRIFTSTACK_HAS_BORINGSSL
        // Wave 29-499.137 — BoringSSL TLS 1.3 wrap for HTTPS (iPhone-identical fingerprint)
        SSL* ssl = nullptr;
        // Wave 29-499.349 — per-connection owner for the custom TLS client (was a
        // thread_local). Lives for this resume() invocation only; moved into the
        // h2 session on the pooled path, reset on the one-shot path.
        std::unique_ptr<DriftstackTLS13Client> customTLSClient;
        bool tlsPermanentFailure = false;   // egress HRR (2026-07-02): set true on a deterministic post-HRR CH2 reject
        if (isHttps) {
            ssl = driftstackTLSConnect(socketFd, host.utf8().data(), customTLSClient, tlsPermanentFailure);
            if (!ssl) {
                if (tlsPermanentFailure)
                    WTFLogAlways("[Driftstack-EG-WK-PathB-v2/W3054] TLS CH2 deterministically rejected by %s (post-HRR alert) — fail fast, NO retry", host.utf8().data());
                if (canRetry && !tlsPermanentFailure) {
                    WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.271] retry attempt=%d for TLS handshake to %s",
                        currentAttempt, host.utf8().data());
                    Ref<DriftstackNetworkLoader> retryRef { *this };
                    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, retryDelayMs * NSEC_PER_MSEC),
                        dispatch_get_main_queue(), ^{
                            if (!retryRef->m_cancelled) retryRef->resume();
                        });
                    return;
                }
                RefPtr task = protectedTask();
                if (task) {
                    WebCore::ResourceError error(String("DriftstackNetworkLoader"_s), 0, URL(url), "BoringSSL TLS handshake failed"_s, WebCore::ResourceError::Type::General);
                    if (!tryBeginCompletion()) return;  // Wave .325 single-completion guard
                    callOnMainRunLoop([protectedThis, error = std::move(error)]() mutable {
                        RefPtr task = protectedThis->protectedTask();
                        if (!task)
                            return;
                        RefPtr client = task->client();
                        if (!client)
                            return;
                        WebCore::NetworkLoadMetrics metrics;
                        client->didCompleteWithError(error, metrics);
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
        if (customTLSClient) {
            // Wave 29-499.209 — use ACTUAL ALPN parsed from EncryptedExtensions
            useHttp2 = customTLSClient->selectedALPN() == "h2"_s;
            WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.209] Custom TLS ALPN='%s' useHttp2=%d",
                customTLSClient->selectedALPN().utf8().data(), useHttp2);
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
            WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.194] Entering HTTP/2 dispatch path (custom_tls=%d ssl=%p)", customTLSClient ? 1 : 0, ssl);
            DriftstackHttp2Request h2req;
            h2req.method = httpMethod;
            h2req.scheme = "https"_s;
            h2req.authority = host;
            h2req.body = requestBody;  // Wave .321 — POST/PUT body (h2 DATA frame)
            h2req.path = url.path().toString();
            if (h2req.path.isEmpty()) h2req.path = "/"_s;
            if (!url.query().isEmpty())
                h2req.path = makeString(h2req.path, '?', url.query());
            // Wave 29-499.201 — iPhone Safari 26.0 EXACT HTTP/2 header order
            // (verified via tls.peet.ws default-mode capture).
            // Order matters for JA4H + Akamai pseudo-header order.
            //
            // Pseudo: :method, :scheme, :authority, :path (m,s,a,p — wire order
            // is set by DriftstackHttp2 HEADERS emit; authority BEFORE path)
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

            // TIER-4 wire H2 regular-header ORDER — real-iPhone-17 raw-wire (tls-full reference):
            // sec-fetch-dest, user-agent, accept, [referer], sec-fetch-site, sec-fetch-mode,
            // accept-language, priority, accept-encoding. Same order as the pool builder above.
            // W3068-CORS (JA4H tracker-path, mirror of the driftstackBuildIphoneH2Request builder): a
            // cross-origin fetch/XHR GET reorders the regular headers vs nav (same iPhone-17 raw-wire
            // cors GET order); pragma/cache-control are placed in-template here + skipped in the loop.
            bool isCorsGet = (httpMethod == "GET"_s) && webkitHdrs.get("sec-fetch-mode"_s) == "cors"_s;
            bool isCorsPost = webkitHdrs.get("sec-fetch-mode"_s) == "cors"_s
                && httpMethod != "GET"_s && httpMethod != "HEAD"_s;
            if (isCorsGet) {
                if (webkitHdrs.contains("pragma"_s)) h2req.extraHeaders.append({ "pragma"_s, webkitHdrs.get("pragma"_s) });
                h2req.extraHeaders.append({ "accept"_s, getOrDefault("accept"_s, "*/*"_s) });
                if (webkitHdrs.contains("sec-fetch-site"_s)) h2req.extraHeaders.append({ "sec-fetch-site"_s, webkitHdrs.get("sec-fetch-site"_s) });
                if (webkitHdrs.contains("sec-fetch-mode"_s)) h2req.extraHeaders.append({ "sec-fetch-mode"_s, webkitHdrs.get("sec-fetch-mode"_s) });
                h2req.extraHeaders.append({ "user-agent"_s, webkitHdrs.contains("user-agent"_s) ? webkitHdrs.get("user-agent"_s) : driftstackPathBUserAgentFallback() });
                if (webkitHdrs.contains("referer"_s)) h2req.extraHeaders.append({ "referer"_s, webkitHdrs.get("referer"_s) });
                if (webkitHdrs.contains("sec-fetch-dest"_s)) h2req.extraHeaders.append({ "sec-fetch-dest"_s, webkitHdrs.get("sec-fetch-dest"_s) });
                if (webkitHdrs.contains("cache-control"_s)) h2req.extraHeaders.append({ "cache-control"_s, webkitHdrs.get("cache-control"_s) });
                h2req.extraHeaders.append({ "accept-language"_s, driftstackPathBAcceptLanguage() });
                h2req.extraHeaders.append({ "priority"_s, webkitHdrs.contains("priority"_s) ? webkitHdrs.get("priority"_s)
                    : driftstackPathBPriorityHeader(webkitHdrs.get("sec-fetch-dest"_s), getOrDefault("accept"_s, "*/*"_s)) });
                h2req.extraHeaders.append({ "accept-encoding"_s, driftstackPathBAcceptEncoding() });
            } else if (isCorsPost) {
                // cors POST/PUT/PATCH order (raw-wire cap #9); h2req.body=requestBody set above so
                // Content-Length (mid-order) is the real size. Mirror of the shared h2 builder.
                h2req.extraHeaders.append({ "accept"_s, getOrDefault("accept"_s, "*/*"_s) });
                if (webkitHdrs.contains("content-type"_s)) h2req.extraHeaders.append({ "content-type"_s, webkitHdrs.get("content-type"_s) });
                if (webkitHdrs.contains("origin"_s)) h2req.extraHeaders.append({ "origin"_s, webkitHdrs.get("origin"_s) });
                if (webkitHdrs.contains("pragma"_s)) h2req.extraHeaders.append({ "pragma"_s, webkitHdrs.get("pragma"_s) });
                if (webkitHdrs.contains("sec-fetch-site"_s)) h2req.extraHeaders.append({ "sec-fetch-site"_s, webkitHdrs.get("sec-fetch-site"_s) });
                h2req.extraHeaders.append({ "content-length"_s, String::number(requestBody.size()) });
                if (webkitHdrs.contains("sec-fetch-mode"_s)) h2req.extraHeaders.append({ "sec-fetch-mode"_s, webkitHdrs.get("sec-fetch-mode"_s) });
                h2req.extraHeaders.append({ "user-agent"_s, webkitHdrs.contains("user-agent"_s) ? webkitHdrs.get("user-agent"_s) : driftstackPathBUserAgentFallback() });
                if (webkitHdrs.contains("referer"_s)) h2req.extraHeaders.append({ "referer"_s, webkitHdrs.get("referer"_s) });
                if (webkitHdrs.contains("sec-fetch-dest"_s)) h2req.extraHeaders.append({ "sec-fetch-dest"_s, webkitHdrs.get("sec-fetch-dest"_s) });
                if (webkitHdrs.contains("cache-control"_s)) h2req.extraHeaders.append({ "cache-control"_s, webkitHdrs.get("cache-control"_s) });
                h2req.extraHeaders.append({ "accept-language"_s, driftstackPathBAcceptLanguage() });
                h2req.extraHeaders.append({ "priority"_s, webkitHdrs.contains("priority"_s) ? webkitHdrs.get("priority"_s)
                    : driftstackPathBPriorityHeader(webkitHdrs.get("sec-fetch-dest"_s), getOrDefault("accept"_s, "*/*"_s)) });
                h2req.extraHeaders.append({ "accept-encoding"_s, driftstackPathBAcceptEncoding() });
            } else {
            if (webkitHdrs.contains("sec-fetch-dest"_s))
                h2req.extraHeaders.append({ "sec-fetch-dest"_s, webkitHdrs.get("sec-fetch-dest"_s) });
            h2req.extraHeaders.append({ "user-agent"_s,
                webkitHdrs.contains("user-agent"_s) ? webkitHdrs.get("user-agent"_s) : driftstackPathBUserAgentFallback() });
            h2req.extraHeaders.append({ "accept"_s,
                getOrDefault("accept"_s, "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"_s) });
            if (webkitHdrs.contains("referer"_s))
                h2req.extraHeaders.append({ "referer"_s, webkitHdrs.get("referer"_s) });
            if (webkitHdrs.contains("sec-fetch-site"_s))
                h2req.extraHeaders.append({ "sec-fetch-site"_s, webkitHdrs.get("sec-fetch-site"_s) });
            if (webkitHdrs.contains("sec-fetch-mode"_s))
                h2req.extraHeaders.append({ "sec-fetch-mode"_s, webkitHdrs.get("sec-fetch-mode"_s) });
            h2req.extraHeaders.append({ "accept-language"_s,
                driftstackPathBAcceptLanguage() });
            // P3/W2438 (#61): derive the RFC 9218 `priority` (u=0 nav / u=3 fetch) when WebKit doesn't
            // supply one — the one-shot path bypasses CFNetwork same as the pool builder above.
            h2req.extraHeaders.append({ "priority"_s,
                webkitHdrs.contains("priority"_s) ? webkitHdrs.get("priority"_s)
                    : driftstackPathBPriorityHeader(webkitHdrs.get("sec-fetch-dest"_s), getOrDefault("accept"_s, "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"_s)) });
            h2req.extraHeaders.append({ "accept-encoding"_s,
                driftstackPathBAcceptEncoding() });
            }

            // Forward any OTHER WebKit headers (content-type for POST, etc.) —
            // preserved in their original positions (iPhone allows arbitrary
            // trailing headers). referer is emitted above in its iOS slot.
            for (auto& header : httpHeaders) {
                String lower = header.key.convertToASCIILowercase();
                if (lower == "host"_s || lower == "connection"_s
                    || lower == "cookie"_s || lower.startsWith(':')
                    || lower == "accept"_s || lower == "accept-encoding"_s
                    || lower == "accept-language"_s || lower == "sec-fetch-site"_s
                    || lower == "sec-fetch-dest"_s || lower == "sec-fetch-mode"_s
                    || lower == "user-agent"_s || lower == "priority"_s || lower == "referer"_s
                    || ((isCorsGet || isCorsPost) && (lower == "pragma"_s || lower == "cache-control"_s))
                    || (isCorsPost && (lower == "content-type"_s || lower == "origin"_s || lower == "content-length"_s)))
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

            // Cookie LAST — see driftstackBuildIphoneH2Request. Trailing loop above skips cookie; append
            // here so it is the terminal H2 header (real iPhone: ...accept-encoding, cookie). ITP: empty => omit.
            if (!driftstackCookieHeader.isEmpty())
                h2req.extraHeaders.append({ "cookie"_s, driftstackCookieHeader });

            // Wave 29-499.193 — route HTTP/2 via custom TLS client if active.
            // Wave .321 P2.5 — when pooling is enabled + the custom TLS client
            // negotiated h2, ADOPT this freshly-established connection into a
            // persistent multiplexed session and pool it for reuse (instead of a
            // one-shot). The session takes OWNERSHIP of the TLS + SOCKS5 clients,
            // so the one-shot cleanup below must be skipped for them (double-free
            // / wrong-branch shutdown otherwise). handledConnection tracks that we
            // moved the clients out (true even if session-create fails, since the
            // failed session's destruction already freed them).
            // Wave 29-499.350 — Server-Sent Events / EventSource INCREMENTAL
            // delivery over PathB v2. EventSource sends Accept: text/event-stream
            // and the body never ends, so the buffer-all path would hang. Stream
            // it: didReceiveResponse on the first HEADERS (gated on the policy
            // decision), didReceiveData per DATA frame, didCompleteWithError when
            // the server closes. Works over EITHER iPhone-JA4 transport (custom
            // TLS13 or BoringSSL ssl). Forces a dedicated one-shot connection
            // (never pooled — an open SSE stream must not block the shared pool).
            {
                String acceptHdr = webkitHdrs.get("accept"_s);
                bool isSSE = acceptHdr.containsIgnoringASCIICase("text/event-stream"_s);
                // Both the custom-TLS13 transport AND the BoringSSL `ssl` path are
                // iPhone-JA4 production paths and either may be chosen per
                // connection — SSE streaming must work on both, else it
                // intermittently falls to the buffer-all path and hangs (Wave .350
                // originally handled only customTLSClient → flaky SSE).
                if (isSSE) {
                    WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.350] SSE stream → incremental PathB delivery for %s", url.string().utf8().data());
                    // W2202 STEP 5: SSE fires onHeaders/onBodyChunk repeatedly over the stream lifetime on
                    // loaderQueue — never cache the raw client. Task-existence early-out only; selfRef keeps
                    // the loader alive across every hop; re-acquire protectedTask()->client() inside each block.
                    {
                    RefPtr task = protectedTask();
                    if (!task) return;
                    }
                    Ref<DriftstackNetworkLoader> selfRef { *this };

                    struct StreamPolicy {
                        Lock lock;
                        Condition cond;
                        bool received { false };
                        bool use { false };
                    };
                    auto policy = std::make_shared<StreamPolicy>();

                    h2req.onHeaders = [selfRef, policy, url](int statusCode, const Vector<std::pair<String, String>>& headers) -> bool {
                        if (selfRef->m_cancelled) return false;
                        String mimeType = "text/event-stream"_s, charset = "UTF-8"_s;
                        for (auto& [k, v] : headers) {
                            if (equalIgnoringASCIICase(k, "content-type"_s)) {
                                String hv = v; size_t semi = hv.find(';');
                                mimeType = (semi != notFound) ? hv.left(semi).trim(deprecatedIsSpaceOrNewline) : hv.trim(deprecatedIsSpaceOrNewline);
                            }
                        }
                        WebCore::ResourceResponse response { URL(url), std::move(mimeType), -1, std::move(charset) };
                        response.setHTTPStatusCode(statusCode);
                        for (auto& [k, v] : headers)
                            response.setHTTPHeaderField(k, v);
                        callOnMainRunLoop([selfRef, response = WebCore::ResourceResponse(response), policy]() mutable {
                            RefPtr task = selfRef->protectedTask();
                            if (!task) {
                                // Task gone: unblock the loaderQueue wait below so the stream tears down.
                                Locker locker { policy->lock };
                                policy->use = false;
                                policy->received = true;
                                policy->cond.notifyAll();
                                return;
                            }
                            RefPtr client = task->client();
                            if (!client) {
                                Locker locker { policy->lock };
                                policy->use = false;
                                policy->received = true;
                                policy->cond.notifyAll();
                                return;
                            }
                            client->didReceiveResponse(std::move(response), NegotiatedLegacyTLS::No, PrivateRelayed::No,
                                [policy](WebCore::PolicyAction action) mutable {
                                    Locker locker { policy->lock };
                                    policy->use = (action == WebCore::PolicyAction::Use);
                                    policy->received = true;
                                    policy->cond.notifyAll();
                                });
                        });
                        Locker locker { policy->lock };
                        while (!policy->received)
                            policy->cond.wait(policy->lock);
                        return policy->use && !selfRef->m_cancelled;
                    };
                    h2req.onBodyChunk = [selfRef](std::span<const uint8_t> chunk) -> bool {
                        if (selfRef->m_cancelled) return false;
                        auto buf = WebCore::SharedBuffer::create(chunk);
                        callOnMainRunLoop([selfRef, buf]() mutable {
                            RefPtr task = selfRef->protectedTask();
                            if (!task)
                                return;
                            RefPtr client = task->client();
                            if (!client)
                                return;
                            client->didReceiveData(buf.get());
                        });
                        return true;
                    };

                    DriftstackHttp2Response sseResp;
                    if (customTLSClient) {
                        // W2341 (task #58): cancel-aware reads — an idle SSE stream cancelled
                        // mid-wait must unblock within one poll slice (was: leaked thread+fd).
                        DriftstackHttp2Transport sseTransport;
                        DriftstackCancelAwareTls sseTlsCtx { customTLSClient.get(), &m_cancelled };
                        sseTransport.ctx = &sseTlsCtx;
                        sseTransport.readFn = driftstackCancelAwareTlsRead;
                        sseTransport.writeFn = driftstackCancelAwareTlsWrite;
                        sseResp = driftstackHttp2ExecuteVia(sseTransport, h2req);
                        customTLSClient.reset();
                    } else {
                        // BoringSSL `ssl` transport (also iPhone JA4). Stream over it,
                        // then shut down + free the SSL like the normal path does.
                        sseResp = driftstackHttp2Execute(ssl, h2req);
#if defined(DRIFTSTACK_HAS_BORINGSSL) && DRIFTSTACK_HAS_BORINGSSL
                        auto& f = boringSSLFns();
                        if (f.ssl_shutdown) f.ssl_shutdown(ssl);
                        if (f.ssl_free) f.ssl_free(ssl);
#endif
                    }

                    RefPtr doneTask = protectedTask();
                    if (!doneTask) return;
                    if (!tryBeginCompletion()) return;
                    WebCore::ResourceError err = sseResp.failed && !m_cancelled
                        ? WebCore::ResourceError(String("DriftstackNetworkLoader"_s), 0, URL(url), sseResp.errorMessage, WebCore::ResourceError::Type::General)
                        : WebCore::ResourceError();
                    callOnMainRunLoop([selfRef, err = WebCore::ResourceError(err)]() mutable {
                        RefPtr task = selfRef->protectedTask();
                        if (!task)
                            return;
                        RefPtr client = task->client();
                        if (!client)
                            return;
                        WebCore::NetworkLoadMetrics metrics;
                        client->didCompleteWithError(err, metrics);
                    });
                    return;
                }
            }

            DriftstackHttp2Response h2resp;
            bool handledConnection = false;
            if (driftstackH2PoolEnabled() && customTLSClient) {
                handledConnection = true;
                auto tlsOwned = std::move(customTLSClient);
                RefPtr<WebKit::DriftstackHttp2Session> session = WebKit::DriftstackHttp2Session::create(std::move(tlsOwned), std::move(socks5Client));
                if (session) {
                    String origin = makeString(host, ':', static_cast<unsigned>(url.port().value_or(443)));
                    // Publish the session + wake coalesced waiters NOW (before our
                    // own request runs) so they multiplex concurrently over it.
                    // W3046: do NOT re-pool a GOAWAY-churning origin — it would just be reused-then-fail again
                    // next request (the adopt/GOAWAY loop). Serve THIS request on the fresh session, then drop it.
                    if (!driftstackH2OriginChurning(origin))
                        driftstackH2PoolSet(origin, RefPtr<WebKit::DriftstackHttp2Session>(session));
                    if (h2PoolWinner) { driftstackH2PoolFinishPending(origin); h2PoolWinner = false; }
                    // BUG-42 Fix #4 — the fresh connect+TLS handshake is DONE and the
                    // session is published; release the handshake-cap slot NOW (before
                    // our own first request executes) so the first multiplexed request
                    // and coalesced waiters aren't throttled by the cap. The scope-exit
                    // guard becomes a no-op (handshakeSlotHeld cleared). Gate-off: held
                    // is false, this is a no-op.
                    if (handshakeSlotHeld) {
                        handshakeSlotHeld = false;
                        dispatch_semaphore_signal(driftstackHandshakeCapSemaphore());
                    }
                    h2resp = session->execute(h2req);
                    WTFLogAlways("[Wave29-499.321/H2POOL] adopted connection for %s into pool (first request status=%d)", origin.utf8().data(), h2resp.statusCode);
                } else {
                    h2resp.failed = true;
                    h2resp.errorMessage = "h2 session adopt/create failed"_s;
                }
            } else if (customTLSClient) {
                // W2341 (task #58): cancel-aware reads (see driftstackCancelAwareTlsRead) —
                // a slow/hung server can otherwise park this block in recv() past cancel().
                DriftstackHttp2Transport transport;
                DriftstackCancelAwareTls tlsCtx { customTLSClient.get(), &m_cancelled };
                transport.ctx = &tlsCtx;
                transport.readFn = driftstackCancelAwareTlsRead;
                transport.writeFn = driftstackCancelAwareTlsWrite;
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
                if (!customTLSClient) {
                    auto& f = boringSSLFns();
                    if (f.ssl_shutdown) f.ssl_shutdown(ssl);
                    if (f.ssl_free) f.ssl_free(ssl);
                } else {
                    customTLSClient.reset();
                }
            }
#endif

            {
            RefPtr task = protectedTask();
            if (!task) return;
            }

            if (h2resp.failed) {
                // W3055 (FOUNDER westernunion): do NOT retry a failed request to a CHURNING 3rd-party
                // origin. Session-replay/analytics beacon endpoints (e.g. ingest.quantummetric.com) close
                // the h2 connection per beacon, so each of a page's ~85 beacons fails its pooled reuse ->
                // a fresh SOCKS5+TLS handshake through the (slow) customer proxy; retrying DOUBLES that. The
                // storm monopolises the egress workers/admission slots and STARVES the first-party document
                // (westernunion) behind it -> pageLoad-timeout -> "won't load". These beacons are
                // fire-and-forget (a real iPhone does not retry-storm them), so failing them fast returns the
                // freed capacity to real content. Scoped to churning(W3046) AND 3rd-party, so first-party and
                // healthy origins keep full retry resilience. Wire/fingerprint-neutral (retry pacing only).
                String w3055Origin = makeString(url.host().toString(), ':', static_cast<unsigned>(url.port().value_or(443)));
                const bool churningBeacon = requestIsThirdParty && driftstackH2OriginChurning(w3055Origin);
                // W3062 (audit): never auto-retry a non-idempotent request (POST/PATCH) that MAY have been
                // executed — the h2 HEADERS+body were already transmitted, so a blind retry DOUBLE-SUBMITS
                // (double payment / double form post). A real iPhone never re-POSTs a sent request. Retry a
                // non-idempotent method ONLY if the server PROVABLY did not process it (h2 GOAWAY on a stream
                // above last-processed -> "not processed by server").
                const bool idempotentMethod = equalIgnoringASCIICase(httpMethod, "GET"_s) || equalIgnoringASCIICase(httpMethod, "HEAD"_s)
                    || equalIgnoringASCIICase(httpMethod, "OPTIONS"_s) || equalIgnoringASCIICase(httpMethod, "PUT"_s)
                    || equalIgnoringASCIICase(httpMethod, "DELETE"_s) || equalIgnoringASCIICase(httpMethod, "TRACE"_s);
                const bool unsafeReplay = !idempotentMethod && !h2resp.errorMessage.contains("not processed"_s);
                if (canRetry && !churningBeacon && !unsafeReplay) {
                    WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.271] retry attempt=%d for HTTP/2 transport to %s",
                        currentAttempt, url.host().toString().utf8().data());
                    Ref<DriftstackNetworkLoader> retryRef { *this };
                    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, retryDelayMs * NSEC_PER_MSEC),
                        dispatch_get_main_queue(), ^{
                            if (!retryRef->m_cancelled) retryRef->resume();
                        });
                    return;
                }
                if (churningBeacon)
                    WTFLogAlways("[Driftstack-EG-WK-PathB-v2/W3055] churning 3rd-party beacon %s failed — fail fast, NO retry (frees egress for first-party content)", w3055Origin.utf8().data());
                WebCore::ResourceError error(String("DriftstackNetworkLoader"_s), 0, URL(url), h2resp.errorMessage, WebCore::ResourceError::Type::General);
                if (!tryBeginCompletion()) return;  // Wave .325 single-completion guard
                callOnMainRunLoop([protectedThis, error = std::move(error)]() mutable {
                    RefPtr task = protectedThis->protectedTask();
                    if (!task)
                        return;
                    RefPtr client = task->client();
                    if (!client)
                        return;
                    WebCore::NetworkLoadMetrics metrics;
                    client->didCompleteWithError(error, metrics);
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

            WebCore::ResourceResponse response { URL(url), std::move(mimeType), expectedLength, std::move(charset) };
            response.setHTTPStatusCode(h2resp.statusCode);
            for (auto& [k, v] : h2resp.headers)
                response.setHTTPHeaderField(k, v);
            // PathB v2 egress Set-Cookie WRITE — raw un-folded Set-Cookie from h2resp.headers (h2 pool/main path).
            Vector<String> h2PoolSetCookies = driftstackExtractRawSetCookies(h2resp.headers);

            // Wave 29-499.269 — dispatch response delivery via callOnMainRunLoop.
            // PathB v2's fetch runs on loaderQueue (concurrent dispatch queue);
            // NetworkResourceLoader expects didReceiveResponse callbacks on the
            // NetworkProcess main runloop. Off-thread delivery from many
            // parallel HTTP/2 dispatches corrupted CFRunLoop hash sets and
            // crashed NetworkProcess (SIGTRAP in CFCheckCFInfoPACSignature_Bridged)
            // when loading 10+ subresource Angular apps like Twilio NT.
            if (tryFollowRedirect(response, h2PoolSetCookies)) return;  // Wave .344 — follow 3xx like Safari, don't render the redirect page (redirect Set-Cookie persisted inside)
            WebKit::driftstackDecodeContentEncoding(h2resp.body, h2resp.headers);  // .331 chokepoint — decode any encoding any h2 path missed
            auto bodyBuffer = WebCore::SharedBuffer::create(h2resp.body.span());
            auto deliveryResponse = WebCore::ResourceResponse(response);
            if (!tryBeginCompletion()) return;  // Wave .325 single-completion guard
            // Final (non-redirect) response: persist Set-Cookie after the single-completion guard wins.
            if (!h2PoolSetCookies.isEmpty()) {
                Ref<DriftstackNetworkLoader> cookieRef { *this };
                callOnMainRunLoop([cookieRef = WTF::move(cookieRef), responseURL = URL(url), h2PoolSetCookies = WTF::move(h2PoolSetCookies)]() mutable {
                    cookieRef->driftstackPersistSetCookies(responseURL, h2PoolSetCookies);
                });
            }
            callOnMainRunLoop([protectedThis, response = std::move(deliveryResponse), bodyBuffer = std::move(bodyBuffer)]() mutable {
                RefPtr task = protectedThis->protectedTask();
                if (!task)
                    return;
                RefPtr client = task->client();
                if (!client)
                    return;
                client->didReceiveResponse(std::move(response), NegotiatedLegacyTLS::No, PrivateRelayed::No,
                    [protectedThis, bodyBuffer = std::move(bodyBuffer)](WebCore::PolicyAction action) mutable {
                        if (action == WebCore::PolicyAction::Use) {
                            RefPtr task = protectedThis->protectedTask();
                            if (!task)
                                return;
                            RefPtr client = task->client();
                            if (!client)
                                return;
                            client->didReceiveData(bodyBuffer.get());
                            WebCore::NetworkLoadMetrics metrics;
                            client->didCompleteWithError(WebCore::ResourceError(), metrics);
                        }
                    });
            });
            return;
        }


        // CFStream fallback only used when BoringSSL is unavailable
        CFReadStreamRef readStream = nullptr;
        CFWriteStreamRef writeStream = nullptr;
        // W3087 (audit wxbeah3ef): the CFStream (plaintext-http) setup-failure branches below previously
        // bare-returned → the load hung forever (no didReceiveResponse/error) + the admission slot stayed
        // pinned until task teardown (the W2200/W3061/W3063 bug class). Route them through the same
        // idempotent-retry-then-error policy failH1 uses (failH1 itself is defined only after the request
        // is sent, so this mirrors it for the pre-send setup phase).
        [[maybe_unused]] auto failCFSetup = [&](ASCIILiteral reason) {
            const bool idempotent = equalIgnoringASCIICase(httpMethod, "GET"_s) || equalIgnoringASCIICase(httpMethod, "HEAD"_s)
                || equalIgnoringASCIICase(httpMethod, "OPTIONS"_s) || equalIgnoringASCIICase(httpMethod, "PUT"_s)
                || equalIgnoringASCIICase(httpMethod, "DELETE"_s) || equalIgnoringASCIICase(httpMethod, "TRACE"_s);
            if (canRetry && idempotent) {
                Ref<DriftstackNetworkLoader> retryRef { *this };
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, retryDelayMs * NSEC_PER_MSEC),
                    dispatch_get_main_queue(), ^{ if (!retryRef->m_cancelled) retryRef->resume(); });
                return;
            }
            if (!tryBeginCompletion()) return;  // Wave .325 single-completion guard
            WebCore::ResourceError err(String("DriftstackNetworkLoader"_s), 0, URL(url), reason, WebCore::ResourceError::Type::General);
            Ref<DriftstackNetworkLoader> protectedThisCF { *this };
            callOnMainRunLoop([protectedThisCF, err = std::move(err)]() mutable {
                RefPtr task = protectedThisCF->protectedTask();
                if (!task) return;
                RefPtr client = task->client();
                if (!client) return;
                WebCore::NetworkLoadMetrics metrics;
                client->didCompleteWithError(err, metrics);
            });
        };
        if (!useBoringSSL) {
            CFStreamCreatePairWithSocket(kCFAllocatorDefault, socketFd, &readStream, &writeStream);
            if (!readStream || !writeStream) {
                if (readStream) CFRelease(readStream);
                if (writeStream) CFRelease(writeStream);
                failCFSetup("CFStream socket-pair create failed"_s);
                return;
            }
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
                failCFSetup("CFStream open failed"_s);   // W3087 — complete the load, don't bare-return-hang
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
                failCFSetup("CFStream write-stream open timeout"_s);   // W3087 — complete the load, don't bare-return-hang
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
        // PathB v2 ITP: use the ITP-filtered Cookie header computed on the main thread (resume()).
        // Empty => ITP blocked all cookies => the `if (!cookieHeader.isEmpty())` below injects no Cookie line.
        String cookieHeader = driftstackCookieHeader;

        // W3068 — iPhone-Safari-faithful HTTP/1.1 request framing. The prior builder forwarded
        // WebKit's LOWERCASE header map in WebKit's own order and hardcoded `Connection: close`
        // — NOT Safari's h1 wire shape, and a JA4H tell that made 3rd-party endpoints reject the
        // request (branch.io / js.adsrvr.org / cloudfront / unagi.amazon.com returned zero bytes).
        // Build from the SAME ordered header vector the h2 builder emits (JA4H-verified iPhone-17
        // raw-wire order: sec-fetch-dest, user-agent, accept, [referer], sec-fetch-site,
        // sec-fetch-mode, accept-language, priority, accept-encoding — reused so the order is not
        // re-invented) and apply the captured h1 framing transform:
        //   1) drop the h2 pseudo-headers (the extraHeaders vector carries none),
        //   2) Title-Case every header name (WebKit stores lowercase; Safari h1 sends Title-Case),
        //   3) Host FIRST (immediately after the request-line),
        //   4) Connection: keep-alive LAST (never `close` — that is a bot tell),
        //   5) Cookie PENULTIMATE (immediately before Connection, i.e. after Accept-Encoding),
        //   6) Upgrade-Insecure-Requests is NOT emitted: real Safari sends it only on http://
        //      document/iframe navigations, and this path is always over TLS (https),
        //   7) Accept-Encoding: gzip, deflate, br, zstd + the per-dest Priority header are already
        //      carried by the h2 vector.
        // keep-alive means the server won't close after the response — the read loops below stop
        // on the message framing (W3069), not on FIN. An empty body is passed to the h2 builder
        // purely to harvest the ordered header vector; this path forwards headers only (sending a
        // request body over pure-h1 is unchanged from before — it was not sent previously either).
        // W3068-CORS-POST: thread the REAL requestBody (was Vector<uint8_t>{ } — the W3070 empty harvest)
        // so the cors-POST builder emits the mid-order Content-Length at its true size. The h1 wire still
        // sends the body once from the OUTER requestBody (below); h1Req.body is unused by the h1 emit, and
        // the trailing fallback Content-Length is skipped since the builder now emits it (sawContentLength).
        auto h1Req = driftstackBuildIphoneH2Request(url, httpMethod, httpHeaders, requestBody, host, cookieHeader);
        auto titleCaseHeaderName = [](const String& lower) -> String {
            // Title-Case = capitalize the first letter + each letter after '-'.
            StringBuilder tc;
            bool atWordStart = true;
            for (unsigned i = 0; i < lower.length(); ++i) {
                char16_t c = lower[i];
                if (atWordStart && c >= 'a' && c <= 'z')
                    c = static_cast<char16_t>(c - 'a' + 'A');
                tc.append(c);
                atWordStart = (c == '-');
            }
            return tc.toString();
        };
        StringBuilder rb;
        rb.append(httpMethod, ' ', pathStr, " HTTP/1.1\r\n"_s);
        rb.append("Host: "_s, host, "\r\n"_s); // Host FIRST
        bool sawContentLength = false;
        for (auto& [name, value] : h1Req.extraHeaders) {
            // Cookie is emitted penultimate (below); UIR is never emitted on this https path.
            if (equalIgnoringASCIICase(name, "cookie"_s) || equalIgnoringASCIICase(name, "upgrade-insecure-requests"_s))
                continue;
            if (equalIgnoringASCIICase(name, "content-length"_s))
                sawContentLength = true;
            rb.append(titleCaseHeaderName(name), ": "_s, value, "\r\n"_s);
        }
        // W3070 — POST/PUT body over pure-h1. The builder harvests headers via an EMPTY body to the
        // h2 vector, so a body method to a TLS1.2/http1.1-only origin (unagi.amazon.com and other
        // older stacks a real iPhone POSTs to fine) previously went out with Content-Length: N (WebKit
        // forwards it) but ZERO body bytes → the server waited for a body that never arrived → empty
        // response / load fail. Append the real body bytes (below), and add a Content-Length fallback
        // only if WebKit didn't already forward one (it normally does for a body method).
        if (!requestBody.isEmpty() && !sawContentLength)
            rb.append("Content-Length: "_s, String::number(requestBody.size()), "\r\n"_s);
        if (!cookieHeader.isEmpty())
            rb.append("Cookie: "_s, cookieHeader, "\r\n"_s); // PENULTIMATE — immediately before Connection
        rb.append("Connection: keep-alive\r\n"_s);           // LAST — never `close`
        rb.append("\r\n"_s);
        auto requestStr = rb.toString().utf8();
        NSMutableData* reqData = [NSMutableData dataWithBytes:requestStr.data() length:requestStr.length()];
        if (!requestBody.isEmpty()) {
            auto bodySpan = requestBody.span(); // WTF-safe buffer accessor (Vector::data() is private)
            [reqData appendBytes:bodySpan.data() length:bodySpan.size()]; // W3070 — h1 request body after the header terminator
        }
        if (!equalIgnoringASCIICase(httpMethod, "GET"_s)) // W3070 diag: verify body-method h1 requests carry their body on the wire
            WTFLogAlways("[Driftstack-EG-WK-PathB-v2/W3070] h1 %s to %s: body=%zuB, reqData(total)=%luB",
                httpMethod.utf8().data(), host.utf8().data(), requestBody.size(), (unsigned long)[reqData length]);

        NSData* responseBytes = nil;
        // W3086 (audit wxbeah3ef): cap the h1 response body at 128MB. The h2/h3 transports enforce a
        // 128MB kMaxBodyBytes, but the custom-TLS/BoringSSL h1 read loops accumulated `respMutable`
        // UNBOUNDED, so a hostile or huge origin (endless Transfer-Encoding: chunked body, or
        // Content-Length: 10GB — which driftstackH1MessageComplete reads in full) that a real iPhone
        // never downloads could OOM the shared multi-tenant NetworkProcess, taking down networking for
        // every tab/session on the node. Overflow → hard-fail (no retry; a re-download re-overflows).
        bool h1BodyOverflow = false;
        static const NSUInteger kH1MaxRespBytes = 128u * 1024u * 1024u;
#if defined(DRIFTSTACK_HAS_BORINGSSL) && DRIFTSTACK_HAS_BORINGSSL
        if (customTLSClient) {
            // Wave 29-499.355 — HTTP/1.1 over the CUSTOM TLS client. When PathB v2
            // custom TLS is active (production), `ssl` is a sentinel — the real TLS
            // connection is DriftstackTLS13Client. Any TLS-1.2+http/1.1-only server
            // (tls12.browserleaks.com and other older HTTPS stacks — a real iPhone
            // loads these fine) negotiates useHttp2=0 and lands here. Previously this
            // path only knew the BoringSSL `ssl` handle or CFStream, so it sent over a
            // handle that never did the handshake → empty response → the load failed
            // (internallyFailedLoadTimerFired). Send/recv over the custom client's
            // read/write, exactly like the h2 transport adapter above.
            const uint8_t* writeBytes = (const uint8_t*)[reqData bytes];
            size_t writeRemaining = [reqData length];
            while (writeRemaining > 0) {
                int n = customTLSClient->write(writeBytes, writeRemaining);
                if (n <= 0) break;
                writeBytes += n;
                writeRemaining -= static_cast<size_t>(n);
            }
            // W3069: the request now sends Connection: keep-alive (W3068), so the server does
            // NOT close after the response — driftstackH1MessageComplete() below terminates the
            // loop on the HTTP/1.1 message framing (Content-Length / chunked / no-body). A
            // read() returning <= 0 (close_notify / FIN — e.g. the server chose Connection:
            // close, or an unframed body) still terminates the loop as before.
            // W2341 (task #58): poll in 1s slices + re-check m_cancelled so a cancel
            // mid-response (or a server that never closes) can't park this block in
            // recv() forever (the thread+fd leak). On cancel the partial response is
            // discarded by the m_cancelled guards downstream.
            //
            // W2988 (audit wggdfj7od #2): the W2341 poll-slice loop has NO wall-clock
            // deadline — a server that dribbles a byte every <1s keeps pr>0 forever (the
            // m_cancelled check is on the pr==0 tick only, so it's never even reached), and
            // a server that goes silent without a FIN yields pr==0 each tick but, before the
            // cancel-wiring fix (#1), m_cancelled never flips → the loop (and its W2983
            // admission slot + GCD worker) leaks forever. Give it the same 60s idle/no-
            // progress deadline the h2 path already has (DriftstackHttp2.mm:1711
            // kIdleTimeout=Seconds(60)): progress (a read) extends the window, 60s of no
            // progress breaks out and delivers the partial via the normal completion path
            // so the slot is released within 60s regardless of cancel wiring. Also re-check
            // m_cancelled on the DATA path, not just the pr==0 tick, so the #1 cancel-wiring
            // takes effect on a dribbling server too. Gated under DRIFTSTACK_EGRESS_RELIABILITY
            // so when the gate is off the loop is byte-identical to the prior W2341 code.
            NSMutableData* respMutable = [NSMutableData data];
            uint8_t readBuf[4096];
            // W3051 (FOUNDER westernunion, workflow wx1i6f1ee RANK-6): gate the h1 60s idle/no-progress deadline
            // on the ACTIVE pacing governor, not the reverted-in-prod EGRESS_RELIABILITY. The identical h2 idle
            // (DriftstackHttp2.mm) is always-on; the h1 one was gated on EGRESS_RELIABILITY (off in prod, W2994)
            // → a silent/dribbling no-FIN h1 tracker held its admission slot (1 of 24) + a GCD worker until
            // external cancel, compounding the beacon-storm starvation. driftstackAdmissionPacingEnabled() is
            // true in prod (EGRESS_CONCURRENCY=1), so this activates the h1 deadline exactly where the cap it
            // protects is active. Gate-off (both flags unset) = byte-identical to the prior W2341 code.
            const bool h1DeadlineActive = driftstackAdmissionPacingEnabled();
            const Seconds kH1IdleTimeout = Seconds(60); // match the h2 kIdleTimeout
            MonotonicTime h1IdleDeadline = MonotonicTime::now() + kH1IdleTimeout;
            while (true) {
                if (m_cancelled) break;
                if (h1DeadlineActive && MonotonicTime::now() >= h1IdleDeadline) {
                    WTFLogAlways("[BUG-42/W2988] h1 app-data idle-timeout (60s no progress) — abandoning response for %s (slot released)", host.utf8().data());
                    break;
                }
                int pr = customTLSClient->pollReadable(1000);
                if (pr == 0) {
                    if (m_cancelled) break;
                    continue;
                }
                if (pr < 0) break;
                int n = customTLSClient->read(readBuf, sizeof(readBuf));
                if (n <= 0) break;
                [respMutable appendBytes:readBuf length:static_cast<NSUInteger>(n)];
                if ([respMutable length] > kH1MaxRespBytes) { h1BodyOverflow = true; break; } // W3086: 128MB OOM guard
                if (h1DeadlineActive)
                    h1IdleDeadline = MonotonicTime::now() + kH1IdleTimeout; // progress → extend the window
                // W3069 — keep-alive-safe: stop on the message framing (the server won't FIN on
                // Connection: keep-alive). Unframed responses return false → fall through to the
                // FIN / idle-deadline paths above.
                if (driftstackH1MessageComplete((const uint8_t*)[respMutable bytes], [respMutable length], httpMethod))
                    break;
            }
            responseBytes = respMutable;
        } else if (useBoringSSL) {
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
                if ([respMutable length] > kH1MaxRespBytes) { h1BodyOverflow = true; break; } // W3086: 128MB OOM guard
                // W3069 — keep-alive-safe: stop on the HTTP/1.1 message framing (the server won't
                // FIN on Connection: keep-alive). Unframed responses return false → keep reading
                // until ssl_read reports FIN/close_notify above.
                if (driftstackH1MessageComplete((const uint8_t*)[respMutable bytes], [respMutable length], httpMethod))
                    break;
            }
            responseBytes = respMutable;
            if (f.ssl_shutdown) f.ssl_shutdown(ssl);
            f.ssl_free(ssl);
        } else
#endif
        {
            CFIndex written = writeAllToCFStream(writeStream, reqData);
            // W3087 (audit wxbeah3ef): a write failure previously did a bare `return;` → the load hung
            // forever (no didReceiveResponse, no error) + the admission slot stayed pinned until task
            // teardown. Leave responseBytes nil and fall through to the failH1 handler below (retry on an
            // idempotent method / deliver a terminal error), like every other h1 terminal path.
            if (written >= 0)
                responseBytes = readAllFromCFStream(readStream, httpMethod); // W3069 — framing-aware read (keep-alive-safe)
            CFRelease(readStream);
            CFRelease(writeStream);
        }

        // W3086 (audit wxbeah3ef): the custom-TLS / BoringSSL h1 read loop hit the 128MB body cap. Hard-fail
        // (a re-download would re-overflow, so NO retry) with the single-completion guard — never OOM the
        // shared NetworkProcess by accumulating an unbounded/hostile body.
        if (h1BodyOverflow) {
            WTFLogAlways("[Driftstack-EG-WK-PathB-v2/W3086] h1 response exceeded 128MB cap host=%s method=%s — hard-failing (OOM guard, no retry)", host.utf8().data(), httpMethod.utf8().data());
            if (!tryBeginCompletion()) return;  // Wave .325 single-completion guard
            Ref<DriftstackNetworkLoader> protectedThisOom { *this };
            WebCore::ResourceError err(String("DriftstackNetworkLoader"_s), 0, URL(url), "response body exceeds 128MB limit"_s, WebCore::ResourceError::Type::General);
            callOnMainRunLoop([protectedThisOom, err = std::move(err)]() mutable {
                RefPtr task = protectedThisOom->protectedTask();
                if (!task) return;
                RefPtr client = task->client();
                if (!client) return;
                WebCore::NetworkLoadMetrics metrics;
                client->didCompleteWithError(err, metrics);
            });
            return;
        }

        // W3061 (audit) + W3063 (founder): the h1 terminal path used bare `return;` on an empty/malformed
        // response, which NEVER completed the load (no didReceiveResponse, no error) -> the request hangs
        // forever ("loads then silently stops"). But an empty h1 response is usually TRANSIENT (the server
        // closed the connection with no reply / a keep-alive race), so a real browser RETRIES it on a fresh
        // connection and succeeds — surfacing a hard error on the first empty read is itself a regression
        // ("new error: empty HTTP/1.1 response"). So: retry on a fresh connection for idempotent methods
        // (bounded by kMaxAttempts), and only deliver the error after retries are exhausted OR for a
        // non-idempotent method (never re-POST a possibly-executed request). Always log the host for RCA.
        auto failH1 = [&](ASCIILiteral reason) {
            const bool idempotent = equalIgnoringASCIICase(httpMethod, "GET"_s) || equalIgnoringASCIICase(httpMethod, "HEAD"_s)
                || equalIgnoringASCIICase(httpMethod, "OPTIONS"_s) || equalIgnoringASCIICase(httpMethod, "PUT"_s)
                || equalIgnoringASCIICase(httpMethod, "DELETE"_s) || equalIgnoringASCIICase(httpMethod, "TRACE"_s);
            const bool willRetry = canRetry && idempotent;
            WTFLogAlways("[Driftstack-EG-WK-PathB-v2/W3063] h1 %s host=%s method=%s attempt=%d -> %s",
                reason.characters(), url.host().toString().utf8().data(), httpMethod.utf8().data(), currentAttempt,
                willRetry ? "retry (transient)" : "deliver error (exhausted/non-idempotent)");
            if (willRetry) {
                Ref<DriftstackNetworkLoader> retryRef { *this };
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, retryDelayMs * NSEC_PER_MSEC),
                    dispatch_get_main_queue(), ^{ if (!retryRef->m_cancelled) retryRef->resume(); });
                return;
            }
            if (!tryBeginCompletion()) return;  // Wave .325 single-completion guard
            WebCore::ResourceError err(String("DriftstackNetworkLoader"_s), 0, URL(url), reason, WebCore::ResourceError::Type::General);
            callOnMainRunLoop([protectedThis, err = std::move(err)]() mutable {
                RefPtr task = protectedThis->protectedTask();
                if (!task) return;
                RefPtr client = task->client();
                if (!client) return;
                WebCore::NetworkLoadMetrics metrics;
                client->didCompleteWithError(err, metrics);
            });
        };
        if (!responseBytes || [responseBytes length] == 0) { failH1("empty HTTP/1.1 response"_s); return; }

        // Parse status + headers
        NSData* boundary = [@"\r\n\r\n" dataUsingEncoding:NSUTF8StringEncoding];
        // W3073 — skip any leading interim 1xx response blocks (100 Continue / 103 Early Hints,
        // RFC 7230 §3.3 / RFC 8297) so the DELIVERED status line + headers + body are the FINAL
        // (>=200) response, not the interim one. Mirrors driftstackH1MessageComplete's framing skip:
        // each 1xx is a complete header block that is followed by another response, so splitting on
        // the FIRST \r\n\r\n would hand the renderer the 103's headers + the real 200 response as
        // "body". Scans block-by-block until a non-1xx (or unparseable) status.
        NSData* headerBytes = nil;
        NSUInteger bodyOffset = 0;
        {
            NSUInteger scanStart = 0;
            for (;;) {
                NSRange r = [responseBytes rangeOfData:boundary options:0 range:NSMakeRange(scanStart, [responseBytes length] - scanStart)];
                if (r.location == NSNotFound) { failH1("malformed HTTP/1.1 response (no header terminator)"_s); return; }
                NSData* blockBytes = [responseBytes subdataWithRange:NSMakeRange(scanStart, r.location - scanStart)];
                // W3074 — decode with a Latin-1 FALLBACK (obs-text safe): a status line is ASCII, but
                // preceding folded field bytes may be obs-text and would nil a strict-UTF-8 decode.
                NSString* blockStr = [[NSString alloc] initWithData:blockBytes encoding:NSUTF8StringEncoding];
                if (!blockStr) blockStr = [[NSString alloc] initWithData:blockBytes encoding:NSISOLatin1StringEncoding];
                int blockStatus = 0;
                NSArray<NSString*>* blockLines = [blockStr componentsSeparatedByString:@"\r\n"];
                if ([blockLines count] >= 1) {
                    NSArray<NSString*>* sp = [blockLines[0] componentsSeparatedByString:@" "];
                    blockStatus = ([sp count] >= 2) ? [sp[1] intValue] : 0;
                }
                if (blockStatus >= 100 && blockStatus < 200) {
                    scanStart = r.location + r.length; // interim → skip this block, scan for the next
                    continue;
                }
                headerBytes = blockBytes;
                bodyOffset = r.location + r.length;
                break;
            }
        }
        NSData* bodyBytes = [responseBytes subdataWithRange:NSMakeRange(bodyOffset, [responseBytes length] - bodyOffset)];
        // W3074 — obs-text (0x80-0xFF ISO-8859-1, RFC 7230 §3.2.6) in a legacy Content-Disposition
        // filename / Set-Cookie / Server value nils a strict NSUTF8StringEncoding decode → the whole
        // response fails to parse. Fall back to NSISOLatin1StringEncoding (a real iPhone decodes
        // headers as Latin-1). Body bytes stay raw — only header parsing changes.
        NSString* headerStr = [[NSString alloc] initWithData:headerBytes encoding:NSUTF8StringEncoding];
        if (!headerStr) headerStr = [[NSString alloc] initWithData:headerBytes encoding:NSISOLatin1StringEncoding];

        NSArray<NSString*>* headerLines = [headerStr componentsSeparatedByString:@"\r\n"];
        if ([headerLines count] < 1) { failH1("malformed HTTP/1.1 response (no status line)"_s); return; }

        NSString* statusLine = headerLines[0];
        NSArray<NSString*>* statusParts = [statusLine componentsSeparatedByString:@" "];
        int statusCode = ([statusParts count] >= 2) ? [statusParts[1] intValue] : 0;
        // Wave 29-499.355 — HTTP/1.1 path observability (mirrors the h2 path's
        // "completed: status=N, body=N"). Confirms the custom-TLS h1 send/recv path.
        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.355] HTTP/1.1 response: status=%d body=%lu bytes (customTLS=%d)",
            statusCode, static_cast<unsigned long>([bodyBytes length]), customTLSClient ? 1 : 0);

        WebCore::ResourceResponse response { URL(url), String("text/html"_s), -1, String("UTF-8"_s) };
        response.setHTTPStatusCode(statusCode);

        // W1517 — the pure-h1 path previously delivered the RAW body (gzip/br/zstd
        // UNDECODED, unlike the h2/h3 chokepoints at .331). Collect headers into a Vector
        // and run the shared decoder, which decodes the body + strips content-encoding/
        // length, then set the (stripped) headers on the response so WebCore doesn't
        // re-decode or mismatch content-length.
        Vector<std::pair<String, String>> h1headers;
        for (NSUInteger i = 1; i < [headerLines count]; i++) {
            NSString* line = headerLines[i];
            NSRange c = [line rangeOfString:@":"];
            if (c.location == NSNotFound) continue;
            NSString* key = [line substringToIndex:c.location];
            NSString* val = [[line substringFromIndex:c.location + 1] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
            h1headers.append({ String::fromUTF8([key UTF8String]), String::fromUTF8([val UTF8String]) });
        }
        Vector<uint8_t> h1body;
        h1body.resize([bodyBytes length]);
        if ([bodyBytes length])
            memcpy(h1body.mutableSpan().data(), [bodyBytes bytes], [bodyBytes length]);
        // egress audit wxzzaphvp (HIGH): de-frame Transfer-Encoding: chunked BEFORE content-decoding.
        // The h1 body above is the raw bytes after the header CRLFCRLF; if the server used chunked
        // transfer-encoding the body is still chunk-framed (<hex-size>[;ext] CRLF <data> CRLF … 0 CRLF
        // [trailers] CRLF), and delivering it raw injects the chunk-size lines + trailers into the page
        // → corrupted body in the renderer. RFC 7230 §3.3.1: the receiver reverses Transfer-Encoding
        // (de-chunk) FIRST, then Content-Encoding (gzip/br/zstd, done by the decoder below).
        {
            bool isChunked = false;
            for (auto& [k, v] : h1headers) {
                if (k.convertToASCIILowercase() == "transfer-encoding"_s
                    && v.convertToASCIILowercase().contains("chunked"_s)) { isChunked = true; break; }
            }
            if (isChunked) {
                Vector<uint8_t> dechunked;
                const uint8_t* p = h1body.span().data();
                size_t n = h1body.size(), i = 0;
                while (i < n) {
                    // chunk-size line: hex digits up to ';' (chunk-ext) or CRLF
                    size_t j = i;
                    while (j + 1 < n && !(p[j] == '\r' && p[j + 1] == '\n')) j++;
                    if (j + 1 >= n) break;              // no CRLF — malformed/truncated
                    size_t chunkSize = 0; bool anyHex = false;
                    for (size_t k = i; k < j; k++) {
                        uint8_t c = p[k];
                        int d;
                        if (c >= '0' && c <= '9') d = c - '0';
                        else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
                        else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
                        else break;                     // ';' chunk-ext or trailing ws ends the size token
                        chunkSize = chunkSize * 16 + d; anyHex = true;
                        if (chunkSize > n) { anyHex = false; break; }  // W3060 (audit): a chunk can't exceed the buffered body n; caps chunkSize so a size_t overflow can't wrap past the truncation clamp below -> OOB read / over-alloc crash
                    }
                    if (!anyHex) break;                 // malformed size line
                    i = j + 2;                          // past the size line's CRLF
                    if (!chunkSize) break;              // last-chunk (0) — trailers follow, ignore
                    if (i + chunkSize > n) chunkSize = n - i;  // truncated body — take what is present
                    dechunked.append(std::span<const uint8_t> { p + i, chunkSize });
                    i += chunkSize;
                    if (i + 2 <= n && p[i] == '\r' && p[i + 1] == '\n') i += 2;  // trailing CRLF after chunk data
                }
                h1body = std::move(dechunked);
                // Strip Transfer-Encoding so WebCore + the content-decoder don't re-expect chunk framing.
                Vector<std::pair<String, String>> filtered;
                filtered.reserveInitialCapacity(h1headers.size());
                for (auto& h : h1headers) {
                    if (h.first.convertToASCIILowercase() == "transfer-encoding"_s) continue;
                    filtered.append(h);
                }
                h1headers = std::move(filtered);
            }
        }
        WebKit::driftstackDecodeContentEncoding(h1body, h1headers);  // .331 chokepoint — pure-h1 (W1517)
        for (auto& [k, v] : h1headers)
            response.setHTTPHeaderField(k, v);
        // W3059 (audit): the h1 response was constructed with a HARDCODED text/html mimeType, and
        // setHTTPHeaderField(Content-Type) does NOT update the cached mimeType — so CSS/JS/JSON/images
        // from HTTP/1.1 origins were mis-typed as HTML (no styling, no script execution -> broken/blank
        // render, the h2 path already parses this at ~2963). Parse the real Content-Type + charset.
        for (auto& [k, v] : h1headers) {
            if (k.convertToASCIILowercase() == "content-type"_s) {
                size_t semi = v.find(';');
                String mime = (semi == WTF::notFound ? v : v.substring(0, static_cast<unsigned>(semi))).convertToASCIILowercase();
                if (!mime.isEmpty()) response.setMimeType(WTF::move(mime));
                size_t cs = v.findIgnoringASCIICase("charset="_s);
                if (cs != WTF::notFound) {
                    String charset = v.substring(static_cast<unsigned>(cs) + 8);
                    size_t end = charset.find(';');
                    if (end != WTF::notFound) charset = charset.substring(0, static_cast<unsigned>(end));
                    if (!charset.isEmpty()) response.setTextEncodingName(WTF::move(charset));
                }
                break;
            }
        }
        // PathB v2 egress Set-Cookie WRITE — raw un-folded Set-Cookie from the h1 parsed header lines
        // (each Set-Cookie: line is one h1headers entry; the content-encoding decode above strips only
        // content-encoding/length, never Set-Cookie).
        Vector<String> h1SetCookies = driftstackExtractRawSetCookies(h1headers);

        if (tryFollowRedirect(response, h1SetCookies)) return;  // Wave .344 — follow 3xx like Safari, don't render the redirect page (redirect Set-Cookie persisted inside)
        // Dispatch callbacks. Use the DECODED body for SharedBuffer.
        auto bodyBuffer = WebCore::SharedBuffer::create(h1body.span());
        {
        RefPtr task = protectedTask();
        if (!task)
            return;
        }

        // Wave 29-499.269b — CFStream fallback also marshalled via main runloop
        auto deliveryResponse2 = WebCore::ResourceResponse(response);
        if (!tryBeginCompletion()) return;  // Wave .325 single-completion guard
        // Final (non-redirect) response: persist Set-Cookie after the single-completion guard wins.
        if (!h1SetCookies.isEmpty()) {
            Ref<DriftstackNetworkLoader> cookieRef { *this };
            callOnMainRunLoop([cookieRef = WTF::move(cookieRef), responseURL = URL(url), h1SetCookies = WTF::move(h1SetCookies)]() mutable {
                cookieRef->driftstackPersistSetCookies(responseURL, h1SetCookies);
            });
        }
        callOnMainRunLoop([protectedThis, response = std::move(deliveryResponse2), bodyBuffer = std::move(bodyBuffer)]() mutable {
            RefPtr task = protectedThis->protectedTask();
            if (!task)
                return;
            RefPtr client = task->client();
            if (!client)
                return;
            client->didReceiveResponse(std::move(response), NegotiatedLegacyTLS::No, PrivateRelayed::No,
                [protectedThis, bodyBuffer = std::move(bodyBuffer)](WebCore::PolicyAction action) mutable {
                    if (action == WebCore::PolicyAction::Use) {
                        RefPtr task = protectedThis->protectedTask();
                        if (!task)
                            return;
                        RefPtr client = task->client();
                        if (!client)
                            return;
                        client->didReceiveData(bodyBuffer.get());
                        WebCore::NetworkLoadMetrics metrics;
                        client->didCompleteWithError(WebCore::ResourceError(), metrics);
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
    // BUG-42 Fix #2 — a cancelled request will never reach tryBeginCompletion's
    // terminal release, so free its admission slot now (idempotent). Gate-off no-op.
    releaseAdmissionSlot();
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
