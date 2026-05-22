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
#import "DriftstackSocks5Client.h"
#import <Security/SecureTransport.h>

// Wave 29-499.135-139 — BoringSSL via DRIFTSTACK_BORINGSSL_HEADER_PATH
// (added to BaseTarget.xcconfig HEADER_SEARCH_PATHS). Provides TLS 1.3
// with iPhone-matched cipher list + ALPN + key shares — bypasses
// CFStream's legacy TLS 1.2 SecureTransport limitations.
//
// Linking strategy: WebKit framework doesn't link libwebrtc.dylib
// directly (allowable_client restriction). Use dlsym at runtime to
// resolve BoringSSL symbols from libwebrtc.dylib which is loaded
// transitively via WebCore.framework. Empirical (.139 probe): all
// required SSL_* symbols resolve via RTLD_DEFAULT after libwebrtc
// is in the process address space.
#include <dlfcn.h>
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
#import <WebCore/HTTPStatusCodes.h>
#import <WebCore/NetworkLoadMetrics.h>
#import <WebCore/ResourceError.h>
#import <WebCore/ResourceResponse.h>
#import <WebCore/SharedBuffer.h>
#import <dispatch/dispatch.h>
#import <stdlib.h>
#import <wtf/Assertions.h>
#import <wtf/CompletionHandler.h>
#import <wtf/RetainPtr.h>
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
// Wave 29-499.139 — dlsym-resolved BoringSSL function pointers.
// libwebrtc.dylib must be in process address space first; we dlopen it
// on first use. WebKit framework can't link libwebrtc directly.

namespace {

// Function pointer typedefs (mirror BoringSSL header signatures)
typedef SSL_CTX* (*FnSSL_CTX_new)(const SSL_METHOD*);
typedef const SSL_METHOD* (*FnTLS_client_method)(void);
typedef int (*FnSSL_CTX_set_min_proto_version)(SSL_CTX*, uint16_t);
typedef int (*FnSSL_CTX_set_max_proto_version)(SSL_CTX*, uint16_t);
typedef int (*FnSSL_CTX_set_strict_cipher_list)(SSL_CTX*, const char*);
typedef int (*FnSSL_CTX_set1_curves_list)(SSL_CTX*, const char*);
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
    FnSSL_CTX_set1_curves_list ssl_ctx_set1_curves_list = nullptr;
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

    // libwebrtc.dylib path inside WebKit framework's containing build dir
    Dl_info info;
    if (!dladdr((const void*)&boringSSLFns, &info)) {
        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.139] dladdr failed");
        return false;
    }
    // Try several possible libwebrtc paths
    const char* candidates[] = {
        // Same dir as WebKit.framework's binary (development)
        "libwebrtc.dylib",
        "/Users/john/code/webkit-driftstack/WebKitBuild/Release/libwebrtc.dylib",
        nullptr,
    };
    void* webrtcHandle = nullptr;
    for (int i = 0; candidates[i]; ++i) {
        webrtcHandle = dlopen(candidates[i], RTLD_NOW | RTLD_GLOBAL);
        if (webrtcHandle) {
            WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.139] dlopen libwebrtc OK at '%s'", candidates[i]);
            break;
        }
    }
    if (!webrtcHandle) {
        // Try lookup without explicit dlopen — might already be loaded transitively
        if (!dlsym(RTLD_DEFAULT, "SSL_CTX_new")) {
            WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.139] libwebrtc dlopen failed AND symbol not resolvable");
            return false;
        }
    }

    f.ssl_ctx_new = (FnSSL_CTX_new)dlsym(RTLD_DEFAULT, "SSL_CTX_new");
    f.tls_client_method = (FnTLS_client_method)dlsym(RTLD_DEFAULT, "TLS_client_method");
    f.ssl_ctx_set_min_proto_version = (FnSSL_CTX_set_min_proto_version)dlsym(RTLD_DEFAULT, "SSL_CTX_set_min_proto_version");
    f.ssl_ctx_set_max_proto_version = (FnSSL_CTX_set_max_proto_version)dlsym(RTLD_DEFAULT, "SSL_CTX_set_max_proto_version");
    f.ssl_ctx_set_strict_cipher_list = (FnSSL_CTX_set_strict_cipher_list)dlsym(RTLD_DEFAULT, "SSL_CTX_set_strict_cipher_list");
    f.ssl_ctx_set1_curves_list = (FnSSL_CTX_set1_curves_list)dlsym(RTLD_DEFAULT, "SSL_CTX_set1_curves_list");
    f.ssl_ctx_set_alpn_protos = (FnSSL_CTX_set_alpn_protos)dlsym(RTLD_DEFAULT, "SSL_CTX_set_alpn_protos");
    f.ssl_ctx_set_verify = (FnSSL_CTX_set_verify)dlsym(RTLD_DEFAULT, "SSL_CTX_set_verify");
    f.ssl_ctx_set_default_verify_paths = (FnSSL_CTX_set_default_verify_paths)dlsym(RTLD_DEFAULT, "SSL_CTX_set_default_verify_paths");
    f.ssl_new = (FnSSL_new)dlsym(RTLD_DEFAULT, "SSL_new");
    f.ssl_free = (FnSSL_free)dlsym(RTLD_DEFAULT, "SSL_free");
    f.ssl_set_tlsext_host_name = (FnSSL_set_tlsext_host_name)dlsym(RTLD_DEFAULT, "SSL_set_tlsext_host_name");
    f.ssl_set1_host = (FnSSL_set1_host)dlsym(RTLD_DEFAULT, "SSL_set1_host");
    f.ssl_set_fd = (FnSSL_set_fd)dlsym(RTLD_DEFAULT, "SSL_set_fd");
    f.ssl_connect = (FnSSL_connect)dlsym(RTLD_DEFAULT, "SSL_connect");
    f.ssl_shutdown = (FnSSL_shutdown)dlsym(RTLD_DEFAULT, "SSL_shutdown");
    f.ssl_get_error = (FnSSL_get_error)dlsym(RTLD_DEFAULT, "SSL_get_error");
    f.ssl_read = (FnSSL_read)dlsym(RTLD_DEFAULT, "SSL_read");
    f.ssl_write = (FnSSL_write)dlsym(RTLD_DEFAULT, "SSL_write");
    f.ssl_get0_alpn_selected = (FnSSL_get0_alpn_selected)dlsym(RTLD_DEFAULT, "SSL_get0_alpn_selected");
    f.err_get_error = (FnERR_get_error)dlsym(RTLD_DEFAULT, "ERR_get_error");
    f.err_error_string_n = (FnERR_error_string_n)dlsym(RTLD_DEFAULT, "ERR_error_string_n");
    f.ssl_library_init = (FnSSL_library_init)dlsym(RTLD_DEFAULT, "SSL_library_init");

    bool required = f.ssl_ctx_new && f.tls_client_method && f.ssl_new
        && f.ssl_set_fd && f.ssl_connect && f.ssl_read && f.ssl_write
        && f.ssl_free && f.ssl_set_tlsext_host_name;
    f.ready = required;
    WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.139] BoringSSL dlsym ready=%d (ctx_new=%p set_curves=%p set_alpn=%p set1_host=%p)",
        required, f.ssl_ctx_new, f.ssl_ctx_set1_curves_list, f.ssl_ctx_set_alpn_protos, f.ssl_set1_host);
    return required;
}

static SSL_CTX* g_driftstackSslCtx = nullptr;
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

        if (f.ssl_ctx_set_min_proto_version)
            f.ssl_ctx_set_min_proto_version(g_driftstackSslCtx, TLS1_3_VERSION);
        if (f.ssl_ctx_set_max_proto_version)
            f.ssl_ctx_set_max_proto_version(g_driftstackSslCtx, TLS1_3_VERSION);

        if (f.ssl_ctx_set_strict_cipher_list) {
            f.ssl_ctx_set_strict_cipher_list(g_driftstackSslCtx,
                "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256");
        }
        if (f.ssl_ctx_set1_curves_list) {
            f.ssl_ctx_set1_curves_list(g_driftstackSslCtx,
                "X25519MLKEM768:X25519:P-256:P-384:P-521");
        }

        static const uint8_t alpn[] = {
            2, 'h', '3',
            2, 'h', '2',
            8, 'h', 't', 't', 'p', '/', '1', '.', '1'
        };
        if (f.ssl_ctx_set_alpn_protos)
            f.ssl_ctx_set_alpn_protos(g_driftstackSslCtx, alpn, sizeof(alpn));

        if (f.ssl_ctx_set_verify) f.ssl_ctx_set_verify(g_driftstackSslCtx, SSL_VERIFY_PEER, nullptr);
        if (f.ssl_ctx_set_default_verify_paths) f.ssl_ctx_set_default_verify_paths(g_driftstackSslCtx);

        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.139] BoringSSL SSL_CTX initialized: TLS 1.3 + iPhone cipher order + ALPN[h3,h2,h1] + X25519MLKEM768");
    });
}

[[maybe_unused]] static SSL* driftstackTLSConnect(int fd, const char* hostUtf8)
{
    initDriftstackSslCtx();
    if (!g_driftstackSslCtx) return nullptr;
    auto& f = boringSSLFns();

    SSL* ssl = f.ssl_new(g_driftstackSslCtx);
    if (!ssl) return nullptr;

    f.ssl_set_tlsext_host_name(ssl, hostUtf8);
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
    if (m_fd >= 0)
        close(m_fd);
}

void DriftstackNetworkLoader::resume()
{
    // Capture request data on the calling thread; do network work async.
    URL url = m_request.url();
    String httpMethod = m_request.httpMethod();
    if (httpMethod.isEmpty()) httpMethod = "GET"_s;
    auto httpHeaders = m_request.httpHeaderFields();
    // TODO Phase 2: support request body (POST)
    (void)m_request.httpBody();

    Ref protectedThis { *this };
    dispatch_async(loaderQueue(), ^{
        if (m_cancelled)
            return;

        // Read proxy + creds from env (same path as DriftstackSocks5URLProtocol)
        const char* proxyEnv = getenv("DRIFTSTACK_SOCKS5_PROXY");
        if (!proxyEnv || !proxyEnv[0]) {
            auto* clientPtr = m_task.client();
            if (clientPtr) {
                WebCore::ResourceError error(String("DriftstackNetworkLoader"_s), 0, URL(m_request.url()), "DRIFTSTACK_SOCKS5_PROXY not set"_s, WebCore::ResourceError::Type::General);
                WebCore::NetworkLoadMetrics metrics;
                clientPtr->didCompleteWithError(error, metrics);
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

        auto socks5Client = std::make_unique<DriftstackSocks5Client>(proxy, creds);
        auto handshakeResult = socks5Client->performHandshake();
        if (handshakeResult != Socks5Result::Success) {
            auto* clientPtr = m_task.client();
            if (clientPtr) {
                WebCore::ResourceError error(String("DriftstackNetworkLoader"_s), 0, URL(m_request.url()), "SOCKS5 handshake failed"_s, WebCore::ResourceError::Type::General);
                WebCore::NetworkLoadMetrics metrics;
                clientPtr->didCompleteWithError(error, metrics);
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
            auto* clientPtr = m_task.client();
            if (clientPtr) {
                WebCore::ResourceError error(String("DriftstackNetworkLoader"_s), 0, URL(m_request.url()), "SOCKS5 CONNECT failed"_s, WebCore::ResourceError::Type::General);
                WebCore::NetworkLoadMetrics metrics;
                clientPtr->didCompleteWithError(error, metrics);
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
                auto* clientPtr = m_task.client();
                if (clientPtr) {
                    WebCore::ResourceError error(String("DriftstackNetworkLoader"_s), 0, URL(m_request.url()), "BoringSSL TLS handshake failed"_s, WebCore::ResourceError::Type::General);
                    WebCore::NetworkLoadMetrics metrics;
                    clientPtr->didCompleteWithError(error, metrics);
                }
                return;
            }
        }
        bool useBoringSSL = isHttps && ssl;

        // Wave 29-499.141 — detect HTTP/2 from ALPN; dispatch to our
        // custom HTTP/2 client (DriftstackHttp2) when h2 negotiated.
        bool useHttp2 = false;
        if (ssl) {
            auto& f = boringSSLFns();
            const uint8_t* alpnSel = nullptr;
            unsigned alpnLen = 0;
            if (f.ssl_get0_alpn_selected) f.ssl_get0_alpn_selected(ssl, &alpnSel, &alpnLen);
            if (alpnSel && alpnLen == 2 && alpnSel[0] == 'h' && alpnSel[1] == '2')
                useHttp2 = true;
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
            DriftstackHttp2Request h2req;
            h2req.method = httpMethod;
            h2req.scheme = "https"_s;
            h2req.authority = host;
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
            for (auto& header : httpHeaders) {
                String lower = header.key.convertToASCIILowercase();
                if (lower == "host"_s || lower == "connection"_s
                    || lower == "cookie"_s || lower.startsWith(':'))
                    continue;
                h2req.extraHeaders.append({ lower, header.value });
            }

            auto h2resp = driftstackHttp2Execute(ssl, h2req);

#if defined(DRIFTSTACK_HAS_BORINGSSL) && DRIFTSTACK_HAS_BORINGSSL
            // SSL_shutdown + SSL_free done by driftstackHttp2Execute? No —
            // driftstackHttp2Execute does NOT free ssl. We free here.
            {
                auto& f = boringSSLFns();
                if (f.ssl_shutdown) f.ssl_shutdown(ssl);
                if (f.ssl_free) f.ssl_free(ssl);
            }
#endif

            auto* clientPtr = m_task.client();
            if (!clientPtr) return;

            if (h2resp.failed) {
                WebCore::ResourceError error(String("DriftstackNetworkLoader"_s), 0, URL(m_request.url()), h2resp.errorMessage, WebCore::ResourceError::Type::General);
                WebCore::NetworkLoadMetrics metrics;
                clientPtr->didCompleteWithError(error, metrics);
                return;
            }

            WebCore::ResourceResponse response { URL(m_request.url()), String("text/html"_s), -1, String("UTF-8"_s) };
            response.setHTTPStatusCode(h2resp.statusCode);
            for (auto& [k, v] : h2resp.headers)
                response.setHTTPHeaderField(k, v);

            auto bodyBuffer = WebCore::SharedBuffer::create(h2resp.body.span());

            clientPtr->didReceiveResponse(WebCore::ResourceResponse(response), NegotiatedLegacyTLS::No, PrivateRelayed::No,
                [clientPtr, bodyBuffer = WTF::move(bodyBuffer)](WebCore::PolicyAction action) mutable {
                    if (action == WebCore::PolicyAction::Use) {
                        clientPtr->didReceiveData(bodyBuffer.get());
                        WebCore::NetworkLoadMetrics metrics;
                        clientPtr->didCompleteWithError(WebCore::ResourceError(), metrics);
                    }
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

        WebCore::ResourceResponse response { URL(m_request.url()), String("text/html"_s), -1, String("UTF-8"_s) };
        response.setHTTPStatusCode(statusCode);

        for (NSUInteger i = 1; i < [headerLines count]; i++) {
            NSString* line = headerLines[i];
            NSRange c = [line rangeOfString:@":"];
            if (c.location == NSNotFound) continue;
            NSString* key = [line substringToIndex:c.location];
            NSString* val = [[line substringFromIndex:c.location + 1] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
            response.setHTTPHeaderField(String::fromUTF8([key UTF8String]), String::fromUTF8([val UTF8String]));
        }

        // Dispatch callbacks. Use NSData spans for SharedBuffer.
        auto bodySpan = unsafeMakeSpan(static_cast<const uint8_t*>([bodyBytes bytes]), static_cast<size_t>([bodyBytes length]));
        auto bodyBuffer = WebCore::SharedBuffer::create(bodySpan);
        auto* clientPtr = m_task.client();
        if (!clientPtr)
            return;

        clientPtr->didReceiveResponse(WebCore::ResourceResponse(response), NegotiatedLegacyTLS::No, PrivateRelayed::No,
            [clientPtr, bodyBuffer = WTF::move(bodyBuffer)](WebCore::PolicyAction action) mutable {
                if (action == WebCore::PolicyAction::Use) {
                    clientPtr->didReceiveData(bodyBuffer.get());
                    WebCore::NetworkLoadMetrics metrics;
                    clientPtr->didCompleteWithError(WebCore::ResourceError(), metrics);
                }
            });
    });
}

void DriftstackNetworkLoader::cancel()
{
    m_cancelled = true;
    if (m_fd >= 0) {
        close(m_fd);
        m_fd = -1;
    }
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
