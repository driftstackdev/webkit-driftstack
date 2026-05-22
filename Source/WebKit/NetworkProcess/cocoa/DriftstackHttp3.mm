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
#import <wtf/Assertions.h>

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
    bool ready = false;
};

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
#undef RESOLVE

    bool required = f.settings_default && f.transport_params_default
        && f.conn_client_new_versioned && f.conn_del && f.conn_open_bidi_stream
        && f.conn_get_expiry && f.conn_handle_expiry
        && f.addr_init && f.cid_init && f.ccerr_default;
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

#endif // PLATFORM(DRIFTSTACK)
