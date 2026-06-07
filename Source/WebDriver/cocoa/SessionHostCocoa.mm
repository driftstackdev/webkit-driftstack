/*
 * SessionHostCocoa.mm — Driftstack item-9 in-process WebDriver SessionHost.
 *
 * The cocoa SessionHost drives the MiniBrowser's _WKAutomationSession DIRECTLY,
 * replacing the glib-subprocess (SessionHostGlib) and socket-RemoteInspector
 * (SessionHostSocket) transports. Because the automation backend lives in THIS
 * process (MiniBrowser creates the session via -[WKProcessPool _setAutomationSession:]
 * before the WD server starts), there is no subprocess to launch, no socket to
 * connect, and no RemoteInspector target-list/pairing handshake: connect installs a
 * response channel, and the W3C Automation messages flow straight in/out via the
 * _driftstack* SPI on _WKAutomationSession. See PRODUCTION-DRIVE-IMPL-PLAN.md.
 */

#include "config.h"
#include "SessionHost.h"

#if PLATFORM(DRIFTSTACK)

#import <WebKit/_WKAutomationSession.h>
#import <wtf/NeverDestroyed.h>
#import <wtf/RetainPtr.h>
#import <wtf/UUID.h>
#import <wtf/text/WTFString.h>

namespace WebDriver {

// The one in-process automation session (one per MiniBrowser, set before the WD
// server starts). RetainPtr keeps it alive for the process. Accessed only on the
// main thread (MiniBrowser sets it at launch; SessionHosts read it on connect).
static RetainPtr<_WKAutomationSession>& sharedInProcessAutomationSession()
{
    static NeverDestroyed<RetainPtr<_WKAutomationSession>> session;
    return session.get();
}

void SessionHost::setSharedInProcessAutomationSession(_WKAutomationSession *session)
{
    sharedInProcessAutomationSession() = session;
}

SessionHost::~SessionHost()
{
}

bool SessionHost::isConnected() const
{
    return m_connected;
}

void SessionHost::connectToBrowser(Function<void (std::optional<String> error)>&& completionHandler)
{
    m_automationSession = sharedInProcessAutomationSession();
    if (!m_automationSession) {
        completionHandler(String("no in-process automation session"_s));
        return;
    }

    // Install the response channel. Backend responses arrive on the main thread via
    // the block and route into the common SessionHost::dispatchMessage -> the W3C
    // Session. Capture a RefPtr so the SessionHost outlives the channel; the channel
    // lives for the process (one in-process session per MiniBrowser), so this is a
    // deliberate process-lifetime retain (matches the channel's own ownership).
    RefPtr<SessionHost> protectedThis = this;
    [m_automationSession _driftstackConnectWithMessageHandler:^(NSString *responseJSON) {
        protectedThis->dispatchMessage(String(responseJSON));
    }];

    m_connected = true;
    completionHandler(std::nullopt);
}

void SessionHost::startAutomationSession(Function<void (bool, std::optional<String>)>&& completionHandler)
{
    // In-process: the automation session already exists, so there is no
    // StartAutomationSession event / target-list handshake (those are RemoteInspector
    // transport concerns). Just establish the W3C session id used for HTTP routing
    // and report success. Automation commands then flow via sendMessageToBackend.
    m_sessionID = createVersion4UUIDString();
    completionHandler(true, std::nullopt);
}

void SessionHost::sendMessageToBackend(const String& message)
{
    // The unwrapped Automation JSON goes straight to the backend; in-process there is
    // no SendMessageToBackend/connectionID/targetID envelope (WebAutomationSession::
    // dispatchMessageFromRemote expects the raw message, same as the RemoteInspector
    // path delivers post-unwrap).
    [m_automationSession _driftstackDispatchMessageFromRemote:message.createNSString().get()];
}

// NOTE: inspectorDisconnected() is defined in the shared SessionHost.cpp (it finishes pending
// commands with an error + notifies BIDI observers — the canonical cross-platform behavior). We
// must NOT redefine it here (ODR — caused a duplicate-symbol link error). The in-process drive
// binds the session to the process lifecycle, so the m_connected reset this used to do is benign
// to drop (disconnect ≈ shutdown; the shared handler already fails outstanding commands).

} // namespace WebDriver

#endif // PLATFORM(DRIFTSTACK)
