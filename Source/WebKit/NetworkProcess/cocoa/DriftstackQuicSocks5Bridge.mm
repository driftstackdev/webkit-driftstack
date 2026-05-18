/*
 * DriftstackQuicSocks5Bridge.mm — Phase A scaffold for Task #16 (EG-WK-
 * 1.10) QUIC SOCKS5 routing. See header for design context + 12-slice
 * roadmap.
 */

#import "config.h"
#import "DriftstackQuicSocks5Bridge.h"

#if PLATFORM(DRIFTSTACK)

#import <Foundation/Foundation.h>
#import <Network/Network.h>
#include <stdlib.h>
#include <wtf/Assertions.h>

namespace WebKit {

namespace DriftstackQuic {

bool isCustomSocks5Active()
{
    const char* customSocks5 = getenv("DRIFTSTACK_CUSTOM_SOCKS5");
    const char* socks5Proxy = getenv("DRIFTSTACK_SOCKS5_PROXY");
    return customSocks5 && customSocks5[0] == '1'
        && socks5Proxy && socks5Proxy[0];
}

// Slice 16.4.b interpose gate. Inspect nw_parameters protocol stack —
// return true if QUIC is configured anywhere in the layers. Phase A
// scaffold inspects via nw_parameters_copy_default_protocol_stack +
// nw_protocol_stack_iterate_application_protocols; Phase B will refine
// based on empirical CFNetwork QUIC parameter shape.
bool parametersUseQuic(nw_parameters_t parameters)
{
    if (!parameters)
        return false;
    // Phase A scaffold: conservative — return false until Slice 16.4.b
    // validates the inspection logic against real CFNetwork QUIC params.
    // Returning false means the interpose falls through to original
    // behavior, which is the safe default.
    static bool loggedOnce = false;
    if (!loggedOnce && isCustomSocks5Active()) {
        loggedOnce = true;
        WTFLogAlways("[Driftstack-EG-WK-1.10/Task#16] parametersUseQuic: Phase A scaffold — returning false. Slice 16.4.b will inspect nw_protocol_stack for QUIC layer.");
    }
    return false;
}

BridgeResult wrapOutgoingQuicPacket(const String&, uint16_t, std::span<const uint8_t>, Vector<uint8_t>& out)
{
    if (!isCustomSocks5Active())
        return BridgeResult::Socks5Disabled;

    static bool loggedOnce = false;
    if (!loggedOnce) {
        loggedOnce = true;
        WTFLogAlways("[Driftstack-EG-WK-1.10/Task#16] wrapOutgoingQuicPacket: Phase A scaffold — NotImplemented. Slice 16.5 will reuse DriftstackSocks5Client::wrapUdpDatagram §7 helper (Wave 29-368).");
    }
    out.clear();
    return BridgeResult::NotImplemented;
}

BridgeResult unwrapIncomingQuicPacket(std::span<const uint8_t>, UnwrappedQuicPacket& out)
{
    if (!isCustomSocks5Active())
        return BridgeResult::Socks5Disabled;

    static bool loggedOnce = false;
    if (!loggedOnce) {
        loggedOnce = true;
        WTFLogAlways("[Driftstack-EG-WK-1.10/Task#16] unwrapIncomingQuicPacket: Phase A scaffold — NotImplemented. Slice 16.6 will reuse DriftstackSocks5Client::unwrapUdpDatagram §7 helper.");
    }
    out.sourceHost = String();
    out.sourcePort = 0;
    out.payload.clear();
    return BridgeResult::NotImplemented;
}

RetainPtr<nw_connection_t> createRelayConnectionForQuic(nw_endpoint_t, nw_parameters_t)
{
    if (!isCustomSocks5Active())
        return nullptr;

    static bool loggedOnce = false;
    if (!loggedOnce) {
        loggedOnce = true;
        WTFLogAlways("[Driftstack-EG-WK-1.10/Task#16] createRelayConnectionForQuic: Phase A scaffold — NotImplemented. Slice 16.4 will bind nw_connection_t to SOCKS5 relay BND.ADDR/BND.PORT via Task #15 SharedRelayState (Slice 2.2 singleton reuse).");
    }
    return nullptr;
}

} // namespace DriftstackQuic

} // namespace WebKit

#endif // PLATFORM(DRIFTSTACK)
