/*
 * DriftstackRTCSocks5Bridge.mm — Phase A scaffold implementation.
 * See header for design context + multi-phase rollout plan.
 */

#import "config.h"
#import "DriftstackRTCSocks5Bridge.h"

#if PLATFORM(DRIFTSTACK) && USE(LIBWEBRTC) && PLATFORM(COCOA)

#include <stdlib.h>
#include <wtf/Assertions.h>

namespace WebKit {

namespace DriftstackRTC {

bool isCustomSocks5Active()
{
    const char* customSocks5 = getenv("DRIFTSTACK_CUSTOM_SOCKS5");
    const char* socks5Proxy = getenv("DRIFTSTACK_SOCKS5_PROXY");
    return customSocks5 && customSocks5[0] == '1'
        && socks5Proxy && socks5Proxy[0];
}

BridgeResult establishRelayChannel(RelayChannel& out)
{
    if (!isCustomSocks5Active())
        return BridgeResult::Socks5Disabled;

    static bool loggedOnce = false;
    if (!loggedOnce) {
        loggedOnce = true;
        WTFLogAlways("[Driftstack-EG-WK-1.8/Task#15] establishRelayChannel: Phase A scaffold — NotImplemented. Phase B (slice 2.2) will wire DriftstackSocks5Client::udpAssociate() to open the relay channel.");
    }
    out.relayHost = String();
    out.relayPort = 0;
    return BridgeResult::NotImplemented;
}

BridgeResult wrapOutgoingDatagram(const webrtc::SocketAddress&, std::span<const uint8_t>, Vector<uint8_t>& out)
{
    if (!isCustomSocks5Active())
        return BridgeResult::Socks5Disabled;

    static bool loggedOnce = false;
    if (!loggedOnce) {
        loggedOnce = true;
        WTFLogAlways("[Driftstack-EG-WK-1.8/Task#15] wrapOutgoingDatagram: Phase A scaffold — NotImplemented. Phase C (slice 2.3) will call DriftstackSocks5Client::wrapUdpDatagram (Wave 29-368 §7 helper).");
    }
    out.clear();
    return BridgeResult::NotImplemented;
}

BridgeResult unwrapIncomingDatagram(std::span<const uint8_t>, UnwrappedDatagram& out)
{
    if (!isCustomSocks5Active())
        return BridgeResult::Socks5Disabled;

    static bool loggedOnce = false;
    if (!loggedOnce) {
        loggedOnce = true;
        WTFLogAlways("[Driftstack-EG-WK-1.8/Task#15] unwrapIncomingDatagram: Phase A scaffold — NotImplemented. Phase C (slice 2.3) will call DriftstackSocks5Client::unwrapUdpDatagram (Wave 29-368 §7 helper).");
    }
    out.sourceHost = String();
    out.sourcePort = 0;
    out.payload.clear();
    return BridgeResult::NotImplemented;
}

} // namespace DriftstackRTC

} // namespace WebKit

#endif // PLATFORM(DRIFTSTACK) && USE(LIBWEBRTC) && PLATFORM(COCOA)
