/*
 * DriftstackSocks5Framing.h — RFC 1928 §7 UDP frame wrap/unwrap helpers.
 *
 * Wave 29-397 Slice 16.4.b.3 shared-library refactor: extracted from
 * DriftstackSocks5Client::wrapUdpDatagram / unwrapUdpDatagram (Wave
 * 29-368). PURE-BYTE API — no NSData / RetainPtr / Cocoa dependencies.
 *
 * Designed for compilation into BOTH the WebKit framework binary AND
 * the (future) DriftstackQuicInterpose dylib (Slice 16.4.b.5). Single
 * source of truth for §7 framing across both contexts.
 *
 * The wrapper layer at DriftstackSocks5Client::wrapUdpDatagram /
 * unwrapUdpDatagram is now a thin Cocoa adaptor that converts
 * NSData ↔ std::span / Vector and delegates here.
 *
 * No fingerprint surfaces touched.
 */

#pragma once

#if PLATFORM(DRIFTSTACK)

#include <span>
#include <wtf/Vector.h>
#include <wtf/text/WTFString.h>

namespace WebKit {
namespace Socks5Framing {

struct Endpoint {
    String host;          // ATYP-domain form preferred; resolution remote.
    uint16_t port { 0 };
};

// RFC 1928 §7 wrap: [RSV 2][FRAG 1][ATYP 1][DST.ADDR var][DST.PORT 2][DATA var].
// Always emits ATYP=0x03 (domain) per EG-WK-1.9 proxy-only DNS default.
// Returns true on success (outFrame populated). False on:
//   - destination.host.empty()
//   - destination.host.utf8() > 255 bytes (RFC §5 domain limit)
bool wrap(const Endpoint& destination, std::span<const uint8_t> payload, Vector<uint8_t>& outFrame);

// RFC 1928 §7 unwrap: inverse of wrap(). Parses incoming relay frame +
// populates outSource (host + port) and outPayload. Accepts ATYP={0x01
// IPv4, 0x03 domain, 0x04 IPv6}.
// Returns true on success. False on:
//   - frame length < 7 bytes (header minimum)
//   - FRAG byte != 0 (v1 doesn't reassemble)
//   - unknown ATYP
//   - declared address/port lengths exceed frame
bool unwrap(std::span<const uint8_t> frame, Endpoint& outSource, Vector<uint8_t>& outPayload);

} // namespace Socks5Framing
} // namespace WebKit

#endif // PLATFORM(DRIFTSTACK)
