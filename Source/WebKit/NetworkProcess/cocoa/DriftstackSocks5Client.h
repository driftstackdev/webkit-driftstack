/*
 * DriftstackSocks5Client — custom SOCKS5 client framing (Wave 29-368).
 *
 * Replaces CFNetwork's shallow built-in SOCKS5 (kCFNetworkProxiesSOCKSEnable)
 * with an explicit RFC 1928 / RFC 1929 implementation that:
 *
 *   (1) Always sends ATYP=0x03 (DOMAINNAME) on TCP CONNECT, never ATYP=0x01
 *       (IPv4). Closes the EG-WK-1.9 Slice 1 DNS-leak surface where
 *       CFNetwork pre-resolves locally via getaddrinfo() before issuing
 *       CONNECT — leaking the destination hostname to Mac fleet DNS.
 *
 *   (2) Implements UDP ASSOCIATE (CMD=0x03) for UDP/QUIC payload relay.
 *       Closes the EG-WK-1.8 Slice 1 UDP-egress surface where the
 *       NetworkSessionCocoa kCFNetworkProxies* path supports only TCP.
 *
 * Per founder addendum 2026-05-17: combined fire as one shared framing
 * code site. See:
 *   docs/planning/133-egress-orientation.md (binding spec)
 *   /operations/verification-log.md Wave 29-366 (EG-WK-1.2 prior),
 *                                   Wave 29-368 (this scaffold)
 *
 * Phase A scope (this scaffold): module interface + RFC 1928 constants +
 * compile-clean stub returning error. Phase B: TCP CONNECT
 * implementation. Phase C: UDP ASSOCIATE implementation.
 */

#pragma once

#if PLATFORM(DRIFTSTACK)

#import <Foundation/Foundation.h>
#include <wtf/Forward.h>
#include <wtf/RetainPtr.h>
#include <wtf/text/WTFString.h>

namespace WebKit {

// RFC 1928 §3 (handshake) + §4 (request) protocol constants.
namespace Socks5 {

constexpr uint8_t kVersion5 = 0x05;

// §3 method codes (handshake).
constexpr uint8_t kMethodNoAuth = 0x00;
constexpr uint8_t kMethodUsernamePassword = 0x02;
constexpr uint8_t kMethodNoneAcceptable = 0xFF;

// §4 CMD codes.
constexpr uint8_t kCmdConnect = 0x01;       // TCP CONNECT
constexpr uint8_t kCmdBind = 0x02;          // TCP bind (unused in v1)
constexpr uint8_t kCmdUdpAssociate = 0x03;  // UDP ASSOCIATE — Slice 1.c

// §4 ATYP codes.
constexpr uint8_t kAtypIpv4 = 0x01;
constexpr uint8_t kAtypDomain = 0x03;       // EG-WK-1.9 Slice 1 default
constexpr uint8_t kAtypIpv6 = 0x04;

// §6 REP codes (server reply).
constexpr uint8_t kReplySucceeded = 0x00;
constexpr uint8_t kReplyGeneralFailure = 0x01;
constexpr uint8_t kReplyConnectionNotAllowed = 0x02;
constexpr uint8_t kReplyNetworkUnreachable = 0x03;
constexpr uint8_t kReplyHostUnreachable = 0x04;
constexpr uint8_t kReplyConnectionRefused = 0x05;
constexpr uint8_t kReplyTTLExpired = 0x06;
constexpr uint8_t kReplyCommandNotSupported = 0x07;
constexpr uint8_t kReplyAddressTypeNotSupported = 0x08;

constexpr uint8_t kReserved = 0x00;

} // namespace Socks5

enum class Socks5Result : uint8_t {
    Success = 0,
    HandshakeFailed,
    AuthRequired,
    AuthFailed,
    ConnectFailed,
    UdpAssociateFailed,
    DomainTooLong,        // RFC 1928 §5 limits domain to 255 bytes
    NotImplemented,       // Phase A scaffold stub return
    NetworkError,
    ProtocolError,
    DestinationUnreachable, // W2868 (#39): SOCKS5 REP=0x03 (network unreachable) / 0x04 (host unreachable) — a
                            // PERMANENT condition for this proxy+dest (classically an IPv6-literal dest via an
                            // IPv4-only proxy). The caller MUST fail fast, never retry (retrying burns the page
                            // nav budget → the founder's 45s -1001 page-load hang).
};

struct Socks5Endpoint {
    String host;          // ATYP-domain form preferred; resolution remote.
    uint16_t port { 0 };
};

struct Socks5Credentials {
    String username;
    String password;
    bool isEmpty() const { return username.isEmpty(); }
};

// Output of a successful UDP ASSOCIATE.
struct Socks5UdpRelayChannel {
    String relayHost;     // BND.ADDR from server reply
    uint16_t relayPort { 0 };  // BND.PORT — datagrams sent here, wrapped per §7
};

// W2900 (#46) — kind of a CONNECT destination host. Hostnames go ATYP=0x03
// (domain; proxy-side DNS, no local leak) and are eligible for a single
// IPv4-forcing re-resolution on REP=0x03/0x04; IP literals use ATYP=0x01/0x04
// and are never retried (an IPv6 literal on an IPv4-only proxy is genuinely
// unreachable — preserves the W2868 fail-fast).
enum class DestAddrKind : uint8_t { Hostname, IPv4Literal, IPv6Literal };

// Phase A (Wave 29-368): interface only. Phase B/C land actual networking.
class DriftstackSocks5Client {
public:
    DriftstackSocks5Client(const Socks5Endpoint& proxy, const Socks5Credentials& creds);
    ~DriftstackSocks5Client();

    DriftstackSocks5Client(const DriftstackSocks5Client&) = delete;
    DriftstackSocks5Client& operator=(const DriftstackSocks5Client&) = delete;

    // §3 handshake. Result indicates which method server selected.
    Socks5Result performHandshake();

    // §4 TCP CONNECT with ATYP=0x03 (domain). Returns BND.ADDR/PORT in `out`.
    Socks5Result tcpConnect(const Socks5Endpoint& destination, Socks5Endpoint& out);

    // §4 UDP ASSOCIATE. Returns relay endpoint UDP datagrams should be sent to
    // (each datagram framed per §7 with destination ATYP/ADDR/PORT prefix).
    Socks5Result udpAssociate(Socks5UdpRelayChannel& out);

    // Returns the underlying TCP socket for the established TCP CONNECT (use to
    // transport application bytes). nullptr if not connected.
    RetainPtr<NSInputStream> tcpReadStream() const;
    RetainPtr<NSOutputStream> tcpWriteStream() const;

    // Wave 29-396 sub-slice 1.7.2.a: raw BSD socket descriptor for CFStream
    // pair wrapping by caller. -1 if no successful tcpConnect yet.
    // Caller must NOT close() the FD — DriftstackSocks5Client owns it
    // via Impl destructor.
    int socketFileDescriptor() const;

    // Wrap a UDP datagram per RFC 1928 §7: [RSV 2 bytes][FRAG 1][ATYP 1][DST.ADDR
    // var][DST.PORT 2][DATA var]. Returns the wrapped frame ready to send to the
    // UDP relay endpoint.
    static RetainPtr<NSData> wrapUdpDatagram(const Socks5Endpoint& destination,
                                              NSData* payload);

    // Inverse of wrapUdpDatagram: parses an incoming UDP frame from the relay
    // into destination + raw payload. Returns nil on protocol error.
    static RetainPtr<NSData> unwrapUdpDatagram(NSData* frame,
                                                 Socks5Endpoint& source);

private:
    // W2900 (#46) — send one CONNECT with the ATYP matching `kind`, read the §6
    // reply header + drain BND.ADDR/PORT. `outRep` returns the reply REP byte so
    // tcpConnect can distinguish a retry-eligible 0x03/0x04 from a hard failure
    // (false return). No retry policy here — that lives in tcpConnect.
    bool sendConnectAndReadReply(int fd, const Socks5Endpoint& destination, DestAddrKind kind,
        uint8_t& outRep, String& outBndHost, uint16_t& outBndPort);

    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace WebKit

#endif // PLATFORM(DRIFTSTACK)
