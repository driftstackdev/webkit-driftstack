/*
 * DriftstackNetworkLoader.h — Wave 29-499.130 (Task #104 Path B v2)
 *
 * Custom network loader that replaces NSURLSessionDataTask when SOCKS5
 * customer-proxy is active. Bypasses Apple's NSURLSession/CFNetwork
 * entirely (which has h3-disable-with-proxy gates we cannot override
 * from configuration).
 *
 * Architecture:
 *   NetworkDataTaskCocoa::NetworkDataTaskCocoa (in cocoa/NetworkDataTaskCocoa.mm)
 *     - When DRIFTSTACK_CUSTOM_SOCKS5=1 + SOCKS5 active:
 *         m_loader = DriftstackNetworkLoader::create(*this, request)
 *         m_loader->resume()
 *     - Otherwise: existing m_task = [session dataTaskWithRequest:] path
 *
 * Loader internal flow (per request):
 *   1. Open BSD TCP socket → gost (SOCKS5 proxy)
 *   2. SOCKS5 GREETING + AUTH + CONNECT to destination
 *   3. Layer TLS on top of socket (BoringSSL or SecureTransport via fd)
 *      - SNI = destination hostname
 *      - ALPN = [h3, h2, http/1.1] (no Apple gate; we control ALPN)
 *      - Validate cert chain
 *   4. Negotiate HTTP version:
 *      - h3 (QUIC over UDP_ASSOCIATE) if ALPN selects h3
 *      - h2 if ALPN selects h2 (nghttp2-style framing)
 *      - http/1.1 fallback
 *   5. Send request, read response
 *   6. Dispatch back through NetworkDataTaskClient callbacks
 *
 * Path B v1 (existing URLProtocol) used CFStream+SOCKS5+TLS for HTTP/1.1
 * but couldn't intercept WebKit's modern HTTPS path. Path B v2 hooks
 * one layer deeper at NetworkDataTaskCocoa creation.
 *
 * Implementation phases (multi-week):
 *   Phase 1 (Day 8-10): scaffold + HTTP/1.1 via BSD+SOCKS5+TLS
 *   Phase 2 (Day 11-15): HTTP/2 via nghttp2
 *   Phase 3 (Day 16-25): HTTP/3 via custom QUIC over UDP_ASSOCIATE
 *   Phase 4 (Day 26-30): cookie/cache integration, redirects, auth, errors
 *   Phase 5 (Day 31+): testing against Twilio NTS + browserleaks/quic
 */

#pragma once

#if PLATFORM(DRIFTSTACK)

#include <WebCore/ResourceRequest.h>
#include <wtf/CompletionHandler.h>
#include <wtf/Forward.h>
#include <wtf/RefCounted.h>
#include <wtf/text/WTFString.h>

namespace WebKit {

class NetworkDataTaskCocoa;

class DriftstackNetworkLoader : public RefCounted<DriftstackNetworkLoader> {
public:
    static Ref<DriftstackNetworkLoader> create(NetworkDataTaskCocoa& task, const WebCore::ResourceRequest& request);
    ~DriftstackNetworkLoader();

    void resume();
    void cancel();
    void suspend();

    // Phase 1 scaffold returns false (loader inactive). Once
    // HTTP/1.1 BSD-socket path implemented, returns true to indicate
    // NetworkDataTaskCocoa should use this loader instead of NSURLSession.
    static bool isActiveForSession();

private:
    DriftstackNetworkLoader(NetworkDataTaskCocoa&, const WebCore::ResourceRequest&);

    [[maybe_unused]] NetworkDataTaskCocoa& m_task;
    WebCore::ResourceRequest m_request;
    bool m_cancelled { false };
    int m_fd { -1 };  // BSD socket fd to gost
    int m_attempt { 0 };  // Wave 29-499.271 — retry counter for transient TLS/H2 failures
};

} // namespace WebKit

#endif // PLATFORM(DRIFTSTACK)
