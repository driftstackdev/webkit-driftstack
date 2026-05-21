/*
 * DriftstackNetworkLoader.mm — Wave 29-499.130 (Task #104 Path B v2)
 *
 * Phase 1 skeleton. isActiveForSession() returns false until the
 * BSD-socket HTTP/1.1 loader path is fully wired (Day 9-10 work).
 * Until then, NetworkDataTaskCocoa falls back to NSURLSession path.
 */

#import "config.h"
#import "DriftstackNetworkLoader.h"

#if PLATFORM(DRIFTSTACK)

#import "NetworkDataTaskCocoa.h"
#import <stdlib.h>
#import <wtf/Assertions.h>

namespace WebKit {

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
        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.130] DriftstackNetworkLoader constructed — phase 1 skeleton (BSD-socket HTTP/1.1 path not yet wired)");
    }
}

DriftstackNetworkLoader::~DriftstackNetworkLoader()
{
    if (m_fd >= 0)
        close(m_fd);
}

void DriftstackNetworkLoader::resume()
{
    // Phase 1: not yet implemented.
    // Day 9-10 work: open BSD TCP → gost, SOCKS5 GREETING+AUTH+CONNECT,
    // TLS handshake to dest, send HTTP/1.1 request, parse response,
    // dispatch via NetworkDataTaskClient (see m_task).
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
    // Phase 1: no-op (no in-flight work yet).
}

bool DriftstackNetworkLoader::isActiveForSession()
{
    // Phase 1: NOT active. Returns false so NetworkDataTaskCocoa falls
    // back to the existing NSURLSession path. Once Phase 1 lands, this
    // returns true when DRIFTSTACK_PATHB_V2=1 env is set AND
    // DRIFTSTACK_CUSTOM_SOCKS5=1.
    const char* env = getenv("DRIFTSTACK_PATHB_V2");
    if (!env || env[0] != '1')
        return false;
    // Phase 1 placeholder — refuse activation until impl ready.
    return false;
}

} // namespace WebKit

#endif // PLATFORM(DRIFTSTACK)
