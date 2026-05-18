/*
 * DriftstackQuicSocks5Bridge.mm — Phase A scaffold for Task #16 (EG-WK-
 * 1.10) QUIC SOCKS5 routing. See header for design context + 12-slice
 * roadmap.
 */

#import "config.h"
#import "DriftstackQuicSocks5Bridge.h"

#if PLATFORM(DRIFTSTACK)

#import "DriftstackSocks5Client.h"

#import <Foundation/Foundation.h>
#import <Network/Network.h>
#include <stdlib.h>
#include <wtf/Assertions.h>
#include <wtf/cocoa/SpanCocoa.h>

namespace WebKit {

namespace DriftstackQuic {

bool isCustomSocks5Active()
{
    const char* customSocks5 = getenv("DRIFTSTACK_CUSTOM_SOCKS5");
    const char* socks5Proxy = getenv("DRIFTSTACK_SOCKS5_PROXY");
    return customSocks5 && customSocks5[0] == '1'
        && socks5Proxy && socks5Proxy[0];
}

bool endpointToHostPort(nw_endpoint_t endpoint, String& outHost, uint16_t& outPort)
{
    if (!endpoint)
        return false;
    nw_endpoint_type_t type = nw_endpoint_get_type(endpoint);
    if (type != nw_endpoint_type_host && type != nw_endpoint_type_url)
        return false; // IP-form endpoint — caller uses Socks5Endpoint with IP literal
    const char* hostname = nw_endpoint_get_hostname(endpoint);
    if (!hostname || !hostname[0])
        return false;
    outHost = String::fromUTF8(hostname);
    outPort = nw_endpoint_get_port(endpoint);

    static bool loggedOnce = false;
    if (!loggedOnce && isCustomSocks5Active()) {
        loggedOnce = true;
        WTFLogAlways("[Driftstack-EG-WK-1.10/Task#16] endpointToHostPort: FIRST hostname extract — '%s':%u. Slice 16.4/16.4.b call sites pass this to wrapOutgoingQuicPacket for ATYP=0x03 framing.",
            hostname, static_cast<unsigned>(outPort));
    }
    return true;
}

// Wave 29-397 Slice 16.4.b.4: nw_protocol_stack inspector.
// Walks the parameters' default protocol stack via
// nw_protocol_stack_iterate_application_protocols, comparing each layer's
// definition against nw_protocol_copy_quic_definition() via
// nw_protocol_definition_is_equal. Returns true if any application-layer
// protocol matches QUIC.
//
// Performance: called on every nw_connection_create when interpose is
// active. Must be FAST (<100ns on non-QUIC paths). Apple's iterator +
// definition-equality comparison are both inline-friendly; empirically
// negligible vs the cost of nw_connection_create itself.
//
// Recursion safety: this function does NOT call nw_connection_create —
// it only inspects already-built nw_parameters. No interpose-recursion
// risk.
bool parametersUseQuic(nw_parameters_t parameters)
{
    if (!parameters)
        return false;

    nw_protocol_stack_t stack = nw_parameters_copy_default_protocol_stack(parameters);
    if (!stack)
        return false;

    RetainPtr<nw_protocol_definition_t> quicDef = adoptNS(nw_protocol_copy_quic_definition());
    __block bool foundQuic = false;

    nw_protocol_stack_iterate_application_protocols(stack, ^(nw_protocol_options_t appOptions) {
        if (foundQuic)
            return;
        nw_protocol_definition_t appDef = nw_protocol_options_copy_definition(appOptions);
        if (appDef && quicDef && nw_protocol_definition_is_equal(appDef, quicDef.get()))
            foundQuic = true;
        if (appDef)
            nw_release(appDef);
    });
    nw_release(stack);

    static bool loggedHitOnce = false;
    if (foundQuic && !loggedHitOnce && isCustomSocks5Active()) {
        loggedHitOnce = true;
        WTFLogAlways("[Driftstack-EG-WK-1.10/Task#16] parametersUseQuic: FIRST QUIC match in protocol stack — Slice 16.4.b.4 inspector ACTIVE. Subsequent matches silent.");
    }
    return foundQuic;
}

BridgeResult wrapOutgoingQuicPacket(const String& destinationHost, uint16_t destinationPort, std::span<const uint8_t> payload, Vector<uint8_t>& out)
{
    if (!isCustomSocks5Active())
        return BridgeResult::Socks5Disabled;

    if (destinationHost.isEmpty() || destinationPort == 0)
        return BridgeResult::ProtocolError;
    if (destinationHost.utf8().length() > 255)
        return BridgeResult::DomainTooLong;

    Socks5Endpoint destination;
    destination.host = destinationHost;
    destination.port = destinationPort;

    RetainPtr<NSData> payloadData = adoptNS([[NSData alloc] initWithBytes:payload.data() length:payload.size()]);
    RetainPtr<NSData> framed = DriftstackSocks5Client::wrapUdpDatagram(destination, payloadData.get());
    if (!framed) {
        WTFLogAlways("[Driftstack-EG-WK-1.10/Task#16] wrapOutgoingQuicPacket: §7 frame helper returned nil for dest=%s:%u",
            destinationHost.utf8().data(), destinationPort);
        return BridgeResult::ProtocolError;
    }

    static bool loggedSuccessOnce = false;
    if (!loggedSuccessOnce) {
        loggedSuccessOnce = true;
        WTFLogAlways("[Driftstack-EG-WK-1.10/Task#16] wrapOutgoingQuicPacket: FIRST wrap — dest=%s:%u, %zu→%zu bytes. Task #15 §7 helper reuse confirmed.",
            destinationHost.utf8().data(), destinationPort, payload.size(), static_cast<size_t>([framed.get() length]));
    }

    out.clear();
    out.append(WTF::span(framed.get()));
    return BridgeResult::Success;
}

BridgeResult unwrapIncomingQuicPacket(std::span<const uint8_t> frame, UnwrappedQuicPacket& out)
{
    if (!isCustomSocks5Active())
        return BridgeResult::Socks5Disabled;

    RetainPtr<NSData> frameData = adoptNS([[NSData alloc] initWithBytes:frame.data() length:frame.size()]);
    Socks5Endpoint source;
    RetainPtr<NSData> payload = DriftstackSocks5Client::unwrapUdpDatagram(frameData.get(), source);
    if (!payload) {
        WTFLogAlways("[Driftstack-EG-WK-1.10/Task#16] unwrapIncomingQuicPacket: §7 frame helper returned nil (protocol error)");
        return BridgeResult::ProtocolError;
    }

    out.sourceHost = source.host;
    out.sourcePort = source.port;
    out.payload.clear();
    out.payload.append(WTF::span(payload.get()));

    static bool loggedSuccessOnce = false;
    if (!loggedSuccessOnce) {
        loggedSuccessOnce = true;
        WTFLogAlways("[Driftstack-EG-WK-1.10/Task#16] unwrapIncomingQuicPacket: FIRST unwrap — src=%s:%u, %zu→%zu bytes (§7 helper reuse from Task #15)",
            out.sourceHost.utf8().data(), out.sourcePort, frame.size(), out.payload.size());
    }
    return BridgeResult::Success;
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
