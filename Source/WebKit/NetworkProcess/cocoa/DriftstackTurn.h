/*
 * DriftstackTurn.h — Wave 29-499.149 (Task #104 Phase 5)
 *
 * Custom TURN client (RFC 5766) for iPhone-bit-identical WebRTC TURN
 * traffic over SOCKS5 UDP_ASSOCIATE. Targets Twilio NTS compatibility
 * (long-term credential MESSAGE-INTEGRITY auth, Allocate, Create
 * Permission, Send Indication / Data Indication).
 *
 * Existing infrastructure leveraged:
 *   - SOCKS5 UDP_ASSOCIATE relay (Wave 29-499.99-106 .mm files):
 *     - DriftstackQuicSocks5Bridge.mm: createRelayConnectionForQuic +
 *       UDP_ASSOCIATE setup
 *     - DriftstackSocks5Framing.mm: §7 UDP wrap/unwrap
 *     - DriftstackRTCSocks5Bridge.mm: hardcoded hostname → IP map for
 *       sandboxed-NetworkProcess that can't getaddrinfo
 *
 * Twilio NTS test failures pre-Phase 5:
 *   - NTS TURN UDP Connectivity: structural SOCKS5+UDP-NAT mapping issue
 *   - NTS TURN TCP Connectivity: TCP variant
 *   - NTS TURN TLS Connectivity: TLS-wrapped variant
 *
 * Phase 5 implementation roadmap (multi-day work):
 *   1. STUN/TURN message encoder/decoder (header + 20-byte transaction ID
 *      + attributes)
 *   2. HMAC-SHA1 for MESSAGE-INTEGRITY (RFC 5389 §15.4)
 *   3. CRC32 for FINGERPRINT (RFC 5389 §15.5)
 *   4. ALLOCATE request → 401 + REALM + NONCE → retry with auth
 *   5. CreatePermission for peer IPs (e.g. STUN binding tests against
 *      our SRflx candidate)
 *   6. Send Indication wrapping for outbound packets
 *   7. Data Indication unwrapping for inbound packets
 *
 * For Twilio NTS specifically: the test sends UDP STUN binding to TURN
 * relay's allocated address; relay forwards to client wrapped in Data
 * Indication. Our SOCKS5 §7 UDP relay already handles inbound from
 * relay endpoint (Wave 29-499.99-106 BSD socket recv loop), but the
 * TURN protocol layer needs to recognize Data Indications + extract
 * actual STUN payload.
 *
 * Implementation note: libwebrtc has TURN code in
 * Source/ThirdParty/libwebrtc/.../p2p/base/turn_port.{cc,h}. We could
 * dlsym from libwebrtc.dylib OR reimplement minimal subset directly
 * (better fingerprint control).
 */

#pragma once

#if PLATFORM(DRIFTSTACK)

#include <stdint.h>
#include <wtf/Vector.h>
#include <wtf/text/WTFString.h>

namespace WebKit {

struct DriftstackTurnAllocation {
    String relayedHost;        // XOR-RELAYED-ADDRESS (Twilio's allocated IP)
    uint16_t relayedPort { 0 };
    String mappedHost;         // XOR-MAPPED-ADDRESS (our SRflx as seen by TURN)
    uint16_t mappedPort { 0 };
    String realm;              // For subsequent auth
    Vector<uint8_t> nonce;     // For subsequent auth
    bool ok { false };
    String errorMessage;
};

struct DriftstackTurnConfig {
    String serverHost;         // "global.turn.twilio.com"
    uint16_t serverPort { 3478 };  // standard TURN port
    String username;           // Twilio TURN credential
    String password;           // Twilio TURN credential (long-term)
    // SOCKS5 UDP relay endpoint (from existing infrastructure)
    String socks5UdpRelayHost;
    uint16_t socks5UdpRelayPort { 0 };
};

// Phase 5 Allocate: sends ALLOCATE request, handles 401 challenge,
// retries with MESSAGE-INTEGRITY using REALM+NONCE+credentials. Returns
// allocation info on success.
DriftstackTurnAllocation driftstackTurnAllocate(const DriftstackTurnConfig& config);

// Phase 5 gate (DRIFTSTACK_PATHB_V2_TURN=1).
bool driftstackTurnEnabled();

} // namespace WebKit

#endif // PLATFORM(DRIFTSTACK)
