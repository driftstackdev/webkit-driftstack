/*
 * DriftstackWebDriverServer.mm — Driftstack item-9 in-process WebDriver entry.
 * See header. Bridges MiniBrowser (plain ObjC) to the C++ WebDriverService.
 */

#include "config.h"
#import "DriftstackWebDriverServer.h"

#if PLATFORM(DRIFTSTACK)

#import "SessionHost.h"
#import "WebDriverService.h"
#import <WebKit/_WKAutomationSession.h>
#import <memory>
#import <netinet/in.h>
#import <string.h>
#import <sys/socket.h>
#import <unistd.h>
#import <wtf/text/WTFString.h>

// Pick a free localhost TCP port (bind to 0 → OS assigns → read it back → close).
// Small TOCTOU window before the WD server re-binds it; acceptable for launch (the
// harness retries on the port-file, and per-session ports rarely collide).
static uint16_t driftstackPickFreeLoopbackPort()
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return 0;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;

    uint16_t port = 0;
    if (!bind(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr))) {
        socklen_t len = sizeof(addr);
        if (!getsockname(fd, reinterpret_cast<struct sockaddr*>(&addr), &len))
            port = ntohs(addr.sin_port);
    }
    close(fd);
    return port;
}

void DriftstackStartWebDriverServer(NSString *sessionID, _WKAutomationSession *session)
{
    if (!sessionID.length || !session)
        return;

    // One WD server per process; keep it alive for the process lifetime.
    static std::unique_ptr<WebDriver::WebDriverService> s_service;
    if (s_service)
        return;

    WebDriver::SessionHost::setSharedInProcessAutomationSession(session);

    uint16_t port = driftstackPickFreeLoopbackPort();
    if (!port) {
        NSLog(@"[Driftstack] WebDriver: could not pick a free port");
        return;
    }

    s_service = std::make_unique<WebDriver::WebDriverService>();
    if (!s_service->driftstackListenInProcess(String("127.0.0.1"_s), port)) {
        NSLog(@"[Driftstack] WebDriver: failed to listen on 127.0.0.1:%u", port);
        s_service = nullptr;
        return;
    }

    // Write the port-file the instant the socket is accepting (A3 W161: the harness
    // polls /tmp/driftstack-webdriver-<sessionId>.port; writing it now — before any
    // heavy init — shrinks the harness connect head-of-line window). atomically:YES
    // so the harness never reads a half-written file.
    NSString *portPath = [NSString stringWithFormat:@"/tmp/driftstack-webdriver-%@.port", sessionID];
    NSString *portStr = [NSString stringWithFormat:@"%u\n", port];
    NSError *error = nil;
    if (![portStr writeToFile:portPath atomically:YES encoding:NSUTF8StringEncoding error:&error]) {
        NSLog(@"[Driftstack] WebDriver: failed to write port-file %@: %@", portPath, error);
        return;
    }

    NSLog(@"[Driftstack] WebDriver: in-process server on 127.0.0.1:%u, port-file %@", port, portPath);
}

#endif // PLATFORM(DRIFTSTACK)
