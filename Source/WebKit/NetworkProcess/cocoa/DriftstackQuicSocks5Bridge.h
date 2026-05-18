/*
 * DriftstackQuicSocks5Bridge.h — QUIC packet relay through SOCKS5 UDP
 * ASSOCIATE (Task #16 / EG-WK-1.10).
 *
 * Owners: Driftstack engineering.
 * Track: Task #16 Option B (founder Tier-3 verdict LOCKED 2026-05-18
 * ~11:10 CEST — intercept QUIC + route through SOCKS5).
 *
 * Purpose: QUIC packets (used by WebTransport explicit + HTTP/3 NSURL-
 * Session) flow over UDP. Without a SOCKS5 routing bridge, the Mac
 * fleet's IP leaks via direct nw_connection UDP to QUIC peers (CDNs
 * with h3 enabled, WebTransport servers). Task #16 closure routes
 * those packets through DriftstackSocks5Client::udpAssociate relay
 * channel (Wave 29-379) — mirrors Task #15 WebRTC SOCKS5 closure
 * pattern.
 *
 * Reuse from Task #15 (90%):
 * - DriftstackSocks5Client (Wave 29-368 + 29-379) — §3 handshake +
 *   §4 UDP ASSOCIATE primitives.
 * - DriftstackRTC::SharedRelayState singleton (Slice 2.2) — single
 *   UDP ASSOCIATE relay channel shared across WebRTC + WebTransport
 *   + HTTP/3. One relay; many subscribers.
 * - §7 wrap/unwrap static helpers (DriftstackSocks5Client::wrapUdp-
 *   Datagram + unwrapUdpDatagram, Wave 29-368) — QUIC packets are
 *   UDP datagrams; same framing applies.
 * - DriftstackRTC::allocateSentinelForHostname / lookupHostname-
 *   ForSentinel (Slice 2.7.b.2-4) — DNS via ATYP=0x03 sentinel;
 *   reusable for QUIC connection hostnames.
 *
 * Two distinct integration paths (per EG-WK-1.10 design doc):
 *
 * 1. WebTransport (explicit nw_parameters_create_webtransport_http):
 *    - Hook in NetworkTransportSession::create PLATFORM(DRIFTSTACK)
 *      block. When isCustomSocks5Active(): replace nw_connection_
 *      group_create with bridge-routed equivalent.
 *
 * 2. HTTP/3 NSURLSession (opaque inside CFNetwork):
 *    - DYLD_INTERPOSE on Network.framework's nw_connection_create.
 *    - When parameters are QUIC-configured, route through bridge.
 *    - Else fall through to original.
 *
 * Phase A scaffold (Wave 29-397 Slice 16.3): API surface declared;
 * all networking returns NotImplemented + WTFLogAlways under
 * [Driftstack-EG-WK-1.10/Task#16] tag. Slices 16.4-16.8 wire actual
 * routing.
 */

#pragma once

#if PLATFORM(DRIFTSTACK)

#import <Network/Network.h>
#include <wtf/Forward.h>
#include <wtf/RetainPtr.h>
#include <wtf/Vector.h>
#include <wtf/text/WTFString.h>

namespace WebKit {

namespace DriftstackQuic {

enum class BridgeResult : uint8_t {
    Success,
    NotImplemented,
    Socks5Disabled,
    UdpAssociateFailed,
    DomainTooLong,
    NetworkError,
    ProtocolError,
    ParametersNotQuic,    // Slice 16.4.b interpose gate fall-through
};

// Slice 16.4.b interpose gate: inspect nw_parameters_t and report whether
// the underlying connection is QUIC-bound. False → caller falls through
// to original nw_connection_create (TCP / non-QUIC UDP unchanged).
bool parametersUseQuic(nw_parameters_t parameters);

// Slice 16.5: wrap an outgoing QUIC packet in RFC 1928 §7 framing for
// transit through the SOCKS5 UDP ASSOCIATE relay channel.
// destinationHost = remote QUIC server hostname (or sentinel-mapped
// hostname via DriftstackRTC::lookupHostnameForSentinel). destinationPort
// = remote port (typically 443 for h3). out = §7-framed bytes ready for
// nw_connection_send through the relay.
BridgeResult wrapOutgoingQuicPacket(const String& destinationHost, uint16_t destinationPort, std::span<const uint8_t> payload, Vector<uint8_t>& out);

// Slice 16.6: unwrap an incoming SOCKS5 §7 frame received on the relay
// channel; recover the QUIC packet payload + source endpoint.
struct UnwrappedQuicPacket {
    String sourceHost;
    uint16_t sourcePort;
    Vector<uint8_t> payload;
};
BridgeResult unwrapIncomingQuicPacket(std::span<const uint8_t> frame, UnwrappedQuicPacket& out);

// Slice 16.4 (WebTransport hook): replace nw_connection_group_create
// when isCustomSocks5Active(). Returns a connection_group bound to the
// SOCKS5 relay endpoint instead of the original peer endpoint. Receiver
// callbacks dispatch unwrapped packets back to libwebrtc / CFNetwork.
RetainPtr<nw_connection_t> createRelayConnectionForQuic(nw_endpoint_t originalEndpoint, nw_parameters_t parameters);

// Helper: gate on DRIFTSTACK_CUSTOM_SOCKS5=1 + DRIFTSTACK_SOCKS5_PROXY
// set. Shares the SharedRelayState singleton with Task #15.
bool isCustomSocks5Active();

} // namespace DriftstackQuic

} // namespace WebKit

#endif // PLATFORM(DRIFTSTACK)
