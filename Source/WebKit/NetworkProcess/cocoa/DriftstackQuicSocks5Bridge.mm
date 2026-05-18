/*
 * DriftstackQuicSocks5Bridge.mm — Phase A scaffold for Task #16 (EG-WK-
 * 1.10) QUIC SOCKS5 routing. See header for design context + 12-slice
 * roadmap.
 */

#import "config.h"
#import "DriftstackQuicSocks5Bridge.h"

#if PLATFORM(DRIFTSTACK)

#import "DriftstackSocks5Client.h"

#import "../webrtc/DriftstackRTCSocks5Bridge.h"
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

// Wave 29-397 Slice 16.4.b.6.b: nw_framer_definition for §7 wrap/unwrap.
// Bidirectional UDP-message processor: outgoing CFNetwork datagrams get
// §7-wrapped before transit to the relay; incoming relay datagrams get
// §7-unwrapped before delivery to CFNetwork. The framer is attached to
// the relay-bound nw_connection's protocol options.
//
// Lazy-init the framer definition once-per-process; same definition
// reused across all relay connections.
static nw_protocol_definition_t driftstackSocks5FramerDefinition()
{
    static nw_protocol_definition_t s_definition = nullptr;
    static dispatch_once_t s_token;
    dispatch_once(&s_token, ^{
        s_definition = nw_framer_create_definition("DriftstackSocks5Framer",
            NW_FRAMER_CREATE_FLAGS_DEFAULT,
            ^nw_framer_start_result_t (nw_framer_t framer) {
                // start handler: nothing to do per-instance; the framer is
                // stateless. send/receive handlers process bytes inline.
                nw_framer_set_output_handler(framer, ^(nw_framer_t framerInner, nw_framer_message_t message, size_t messageLength, bool isComplete) {
                    // Slice 16.4.b.6.b scaffold: read the full outgoing message
                    // and §7-wrap it via Socks5Framing::wrap. Phase A
                    // scaffold passes through raw bytes (relay will reject as
                    // protocol error — visible in gost log; flags missing
                    // §7 framer to operator).
                    nw_framer_parse_output(framerInner, messageLength, messageLength, nullptr, ^size_t (uint8_t* buffer, size_t bufferLength, bool isComplete) {
                        // Phase A: write through unchanged.
                        nw_framer_write_output(framerInner, buffer, bufferLength);
                        return bufferLength;
                    });
                });
                nw_framer_set_input_handler(framer, ^size_t (nw_framer_t framerInner) {
                    // Slice 16.4.b.6.b scaffold: parse §7 header from incoming
                    // bytes + deliver only payload upstream. Phase A scaffold
                    // passes through.
                    nw_framer_parse_input(framerInner, 1, UINT16_MAX, nullptr, ^size_t (uint8_t* buffer, size_t bufferLength, bool isComplete) {
                        nw_framer_deliver_input(framerInner, buffer, bufferLength, nw_framer_message_create(framerInner), true);
                        return bufferLength;
                    });
                    return 0;
                });
                static bool loggedOnce = false;
                if (!loggedOnce) {
                    loggedOnce = true;
                    WTFLogAlways("[Driftstack-EG-WK-1.10/Task#16] nw_framer started — Phase A scaffold passes through unchanged. Slice 16.4.b.6.b full impl will §7-wrap output + §7-unwrap input.");
                }
                return nw_framer_start_result_ready;
            });
    });
    return s_definition;
}

RetainPtr<nw_connection_t> createRelayConnectionForQuic(nw_endpoint_t originalEndpoint, nw_parameters_t parameters)
{
    if (!isCustomSocks5Active())
        return nullptr;

    // Wave 29-397 Slice 16.4.b.6: bind a fresh nw_connection_t to the SOCKS5
    // BND.ADDR:BND.PORT obtained from Task #15's SharedRelayState (DriftstackRTC
    // bridge — ONE UDP ASSOCIATE channel serves WebRTC + WebTransport + future
    // HTTP/3 simultaneously).
    //
    // §7 wrap/unwrap framing on the QUIC payload is NOT YET applied at this
    // layer — CFNetwork's QUIC stack writes raw QUIC packets to the returned
    // connection. Slice 16.4.b.6.b will add a custom nw_framer_definition that
    // injects/strips the §7 header on send/receive. Without that framer, the
    // SOCKS5 relay receives malformed (un-framed) QUIC packets — the relay
    // logs a protocol error. The CONNECTION IS BOUND CORRECTLY; the framer
    // is the missing piece for clean SOCKS5 transit.
    //
    // Slice 16.4.b.6 atomic scope: connection creation + bind + start. Framer
    // injection deferred to 16.4.b.6.b for clarity (one architectural decision
    // per atomic slice).

    DriftstackRTC::RelayChannel channel;
    DriftstackRTC::BridgeResult r = DriftstackRTC::establishRelayChannel(channel);
    if (r != DriftstackRTC::BridgeResult::Success) {
        static bool loggedFailOnce = false;
        if (!loggedFailOnce) {
            loggedFailOnce = true;
            WTFLogAlways("[Driftstack-EG-WK-1.10/Task#16] createRelayConnectionForQuic: relay establish failed (result=%d) — fall through; CFNetwork QUIC will use direct UDP (LEAK)",
                static_cast<int>(r));
        }
        return nullptr;
    }

    // Build nw_parameters for the relay-bound connection (UDP only, no QUIC
    // layer — we want raw UDP to the relay endpoint; the original QUIC
    // params describe what CFNetwork wants to do, but the wire layer to the
    // proxy is plain UDP).
    auto relayParams = adoptNS(nw_parameters_create_secure_udp(NW_PARAMETERS_DISABLE_PROTOCOL, NW_PARAMETERS_DEFAULT_CONFIGURATION));

    // Wave 29-397 Slice 16.4.b.6.b: attach §7 framer to the relay
    // connection's protocol stack. Phase A scaffold framer passes bytes
    // through unchanged (gost will see un-framed UDP and reject as
    // protocol error). Slice 16.4.b.6.b full impl populates the output
    // handler with Socks5Framing::wrap and input handler with
    // Socks5Framing::unwrap.
    nw_protocol_definition_t framerDef = driftstackSocks5FramerDefinition();
    if (framerDef) {
        auto framerOptions = adoptNS(nw_framer_create_options(framerDef));
        auto stack = adoptNS(nw_parameters_copy_default_protocol_stack(relayParams.get()));
        nw_protocol_stack_prepend_application_protocol(stack.get(), framerOptions.get());
    }

    auto relayHostUtf8 = channel.relayHost.utf8();
    auto relayEndpoint = adoptNS(nw_endpoint_create_host(relayHostUtf8.data(), String::number(channel.relayPort).utf8().data()));

    auto relayConnection = adoptNS(nw_connection_create(relayEndpoint.get(), relayParams.get()));
    if (!relayConnection) {
        WTFLogAlways("[Driftstack-EG-WK-1.10/Task#16] createRelayConnectionForQuic: nw_connection_create returned nil");
        return nullptr;
    }

    static bool loggedSuccessOnce = false;
    if (!loggedSuccessOnce) {
        loggedSuccessOnce = true;
        WTFLogAlways("[Driftstack-EG-WK-1.10/Task#16] createRelayConnectionForQuic: relay-bound nw_connection created — relay=%s:%u. Slice 16.4.b.6.b will add §7 nw_framer for clean SOCKS5 transit; current connection accepts raw UDP only.",
            relayHostUtf8.data(), channel.relayPort);
    }

    return relayConnection;
}

} // namespace DriftstackQuic

} // namespace WebKit

#endif // PLATFORM(DRIFTSTACK)
