/*
 * DriftstackRTCSocks5Bridge.h — SOCKS5 UDP ASSOCIATE relay bridge for WebRTC.
 *
 * Owners: Driftstack engineering.
 * Track: EG-WK-1.8 Slice 2 (Wave 29-397 Slice 2.1, paired with Task #15
 * "WebRTC SOCKS5 (PacketSocketFactory + ICE resolver)").
 *
 * Purpose: WebRTC peer-connection traffic uses Cocoa-native nw_connection
 * sockets (NetworkRTCUDPSocketCocoa / NetworkRTCTCPSocketCocoa) that BYPASS
 * NSURLSession — they don't route through the WKDriftstackSocks5URLProtocol
 * (Wave 29-396 sub-1.9.a) registered for HTTP/HTTPS. Without an explicit
 * WebRTC SOCKS5 bridge, the Mac fleet's real IP leaks through STUN and TURN
 * candidate-ping datagrams (even though Wave 29-318 EG-WK-1.3 ICE force-relay
 * routes the media stream itself through customer TURN).
 *
 * Phase A scaffold (this slice): expose the API surface that NetworkRTCUDP-
 * SocketCocoa + NetworkRTCResolverCocoa will call once Phase B/C wires
 * through DriftstackSocks5Client::udpAssociate() (Wave 29-379) + RFC 1928 §7
 * frame helpers (Wave 29-368 wrapUdpDatagram / unwrapUdpDatagram). All
 * methods return NotImplemented + WTFLogAlways under
 * [Driftstack-EG-WK-1.8/Task#15] tag so any premature production usage is
 * loud + visible.
 *
 * Phase B (next slice 2.2): UDP ASSOCIATE establish — open the SOCKS5 relay
 * channel on socket creation, hold the TCP control connection for relay
 * lifetime, surface the BND.ADDR/BND.PORT to the caller.
 *
 * Phase C (slice 2.3-2.4): wrapOutgoing + unwrapIncoming — RFC 1928 §7
 * framing applied to every datagram crossing the WebRTC ↔ network boundary.
 *
 * Phase D (slice 2.5-2.6): PacketSocketFactory hook + ICE candidate
 * generation — ensure server-reflexive / relay candidates report the SOCKS5
 * relay-channel endpoint, not the Mac fleet's nw_connection-resolved local
 * endpoint.
 *
 * Phase E (slice 2.7): NetworkRTCResolverCocoa DNS hook — STUN/TURN hostname
 * resolution via SOCKS5 ATYP=0x03 (proxy-only DNS) instead of local
 * getaddrinfo. Pairs with EG-WK-1.9 Slice 1 (same ATYP=0x03 framing).
 */

#pragma once

#if PLATFORM(DRIFTSTACK) && USE(LIBWEBRTC) && PLATFORM(COCOA)

#include <wtf/Forward.h>
#include <wtf/Vector.h>
#include <wtf/text/WTFString.h>

namespace webrtc { class SocketAddress; }

namespace WebKit {

namespace DriftstackRTC {

enum class BridgeResult : uint8_t {
    Success,
    NotImplemented,
    Socks5Disabled,
    UdpAssociateFailed,
    DomainTooLong,
    NetworkError,
    ProtocolError,
};

// Phase B (slice 2.2): UDP ASSOCIATE relay-channel handle. Encapsulates the
// SOCKS5 TCP control connection lifetime + the BND.ADDR/BND.PORT relay
// endpoint that all datagrams flow through.
//
// Phase A returns std::nullopt + logs NotImplemented.
struct RelayChannel {
    String relayHost;   // BND.ADDR
    uint16_t relayPort; // BND.PORT
    // Implementation owns the TCP control connection FD; opaque to callers.
};

// Phase B: establish UDP ASSOCIATE relay against the configured SOCKS5
// proxy (DRIFTSTACK_SOCKS5_PROXY env). Returns the BND.ADDR/BND.PORT the
// caller should send all subsequent UDP datagrams to.
BridgeResult establishRelayChannel(RelayChannel& out);

// Wave 29-499.310 — DEDICATED UDP ASSOCIATE for the QUIC/HTTP-3 flow.
// The shared relay (establishRelayChannel) is bound by gost to the first
// sender (STUN socket), so QUIC responses route there, not our udpFd. A fresh
// dedicated associate binds to the QUIC sender → responses return correctly.
// The dedicated client's TCP control connection is kept alive process-lifetime.
BridgeResult establishDedicatedQuicRelay(RelayChannel& out);

// Phase C: wrap an outgoing UDP datagram in RFC 1928 §7 framing.
// dest = peer the application wants to reach; payload = original UDP bytes.
// out = SOCKS5-framed bytes the caller sends to the relayPort.
BridgeResult wrapOutgoingDatagram(const webrtc::SocketAddress& dest, std::span<const uint8_t> payload, Vector<uint8_t>& out);

// Phase C: unwrap an incoming SOCKS5-framed UDP datagram received on the
// relay channel.
// frame = bytes received from relayPort; out = unwrapped payload + source
// peer endpoint (host + port).
struct UnwrappedDatagram {
    String sourceHost;
    uint16_t sourcePort;
    Vector<uint8_t> payload;
};
BridgeResult unwrapIncomingDatagram(std::span<const uint8_t> frame, UnwrappedDatagram& out);

// Helper: is DRIFTSTACK_CUSTOM_SOCKS5=1 + DRIFTSTACK_SOCKS5_PROXY set?
// Callers gate Phase B/C/D activation on this returning true; otherwise
// fall through to legacy Cocoa-native path.
bool isCustomSocks5Active();

// Wave 29-397 Slice 2.7.b.2: sentinel-IP allocator + IP→hostname sidecar.
// Phase E DNS short-circuit support. When NetworkRTCProvider::createResolver
// runs in bridge-active mode, instead of calling getaddrinfo on the
// hostname (leak surface), allocate a fresh sentinel IP that uniquely
// represents the hostname for libwebrtc's IP-based ICE candidate model.
// sendTo (Slice 2.7.b.4) consults the sidecar to recover the original
// hostname for ATYP=0x03 framing in the SOCKS5 §7 wrap.
//
// allocateSentinelForHostname(host): returns a 127.0.0.X IPv4 string
//   (X allocated from a monotonically-incrementing counter starting at
//   2 to avoid colliding with the standard 127.0.0.1 loopback). Same
//   hostname reuses its allocated sentinel on subsequent calls.
//
// lookupHostnameForSentinel(ipString): returns the original hostname
//   if ipString is a registered sentinel, otherwise empty String.
String allocateSentinelForHostname(const String& hostname);
String lookupHostnameForSentinel(const String& ipString);

// Wave 29-499.102 — realIp ↔ sentinel reverse mapping. Populated at
// outbound resolve time; consulted at inbound to remap STUN response
// source from real STUN server IP back to sentinel, so libwebrtc's
// StunPort source-validation accepts the response.
void rememberRealIpForSentinel(const String& realIp, const String& sentinel);
String lookupSentinelForRealIp(const String& realIp);

// Wave 29-499.221 — hostname-fallback path support for Twilio (and other
// anycast hostnames not in the hardcoded .94 STUN map). recordPendingSentinel-
// ForPort is called at outbound when ATYP=0x03 hostname-form is used (because
// resolveHostnameToIPv4 returned empty). learnRealIpFromPendingPort is called
// at inbound on packets from unknown real IPs; if any pending sentinel matches
// the source port (= our dstPort) it binds and returns the sentinel.
void recordPendingSentinelForPort(const String& sentinel, uint16_t port);
String learnRealIpFromPendingPort(const String& realIp, uint16_t srcPort);

} // namespace DriftstackRTC

} // namespace WebKit

#endif // PLATFORM(DRIFTSTACK) && USE(LIBWEBRTC) && PLATFORM(COCOA)
