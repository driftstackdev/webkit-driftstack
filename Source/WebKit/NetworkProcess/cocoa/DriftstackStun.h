/*
 * DriftstackStun.h — Wave 29-499.212 (Phase 5 TURN)
 *
 * STUN (RFC 5389) message encoder/decoder + TURN (RFC 5766) attribute
 * helpers. Used by DriftstackTurn for Twilio NTS compatibility.
 *
 * STUN message format:
 *   Type (u16) + Length (u16) + Magic Cookie (0x2112A442 u32)
 *   + Transaction ID (12 bytes) + Attributes (TLV)
 *
 * Attributes used by TURN ALLOCATE flow:
 *   USERNAME (0x0006)
 *   MESSAGE-INTEGRITY (0x0008) — HMAC-SHA1 of message
 *   ERROR-CODE (0x0009)
 *   REALM (0x0014)
 *   NONCE (0x0015)
 *   XOR-MAPPED-ADDRESS (0x0020)
 *   XOR-RELAYED-ADDRESS (0x0016) — TURN ext
 *   LIFETIME (0x000D)
 *   REQUESTED-TRANSPORT (0x0019) — TURN
 *   FINGERPRINT (0x8028) — CRC32 of message
 */

#pragma once

#if PLATFORM(DRIFTSTACK)

#include <stdint.h>
#include <wtf/Vector.h>
#include <wtf/text/WTFString.h>

namespace WebKit {

// STUN method codes (lower 12 bits of message type)
constexpr uint16_t kStunMethodBinding   = 0x001;
constexpr uint16_t kStunMethodAllocate  = 0x003;  // TURN
constexpr uint16_t kStunMethodRefresh   = 0x004;
constexpr uint16_t kStunMethodSend      = 0x006;
constexpr uint16_t kStunMethodData      = 0x007;
constexpr uint16_t kStunMethodCreatePerm = 0x008;
constexpr uint16_t kStunMethodChannelBind = 0x009;

// Class bits 0x100=indication, 0x110=request, 0x010=success, 0x111=error
constexpr uint16_t kStunClassRequest      = 0x000;
constexpr uint16_t kStunClassIndication   = 0x010;
constexpr uint16_t kStunClassSuccess      = 0x100;
constexpr uint16_t kStunClassError        = 0x110;

constexpr uint32_t kStunMagicCookie = 0x2112A442;

// STUN attribute types
constexpr uint16_t kAttrMappedAddress         = 0x0001;
constexpr uint16_t kAttrUsername              = 0x0006;
constexpr uint16_t kAttrMessageIntegrity      = 0x0008;
constexpr uint16_t kAttrErrorCode             = 0x0009;
constexpr uint16_t kAttrUnknownAttributes     = 0x000A;
constexpr uint16_t kAttrLifetime              = 0x000D;
constexpr uint16_t kAttrXorPeerAddress        = 0x0012;  // TURN
constexpr uint16_t kAttrData                  = 0x0013;  // TURN
constexpr uint16_t kAttrRealm                 = 0x0014;
constexpr uint16_t kAttrNonce                 = 0x0015;
constexpr uint16_t kAttrXorRelayedAddress     = 0x0016;  // TURN
constexpr uint16_t kAttrRequestedTransport    = 0x0019;  // TURN (0x11 = UDP)
constexpr uint16_t kAttrXorMappedAddress      = 0x0020;
constexpr uint16_t kAttrSoftware              = 0x8022;
constexpr uint16_t kAttrFingerprint           = 0x8028;

// STUN message builder
class StunMessageBuilder {
public:
    StunMessageBuilder(uint16_t method, uint16_t klass);
    StunMessageBuilder(uint16_t method, uint16_t klass, const Vector<uint8_t>& txnId);

    // Add a TLV attribute (auto-aligns to 4-byte boundary)
    void addAttribute(uint16_t type, const Vector<uint8_t>& value);
    void addAttributeString(uint16_t type, const String& value);

    // Append MESSAGE-INTEGRITY (HMAC-SHA1 of message-so-far with key)
    // Key per RFC 5389 §15.4 for long-term cred: MD5(username + ":" + realm + ":" + password)
    void appendMessageIntegrity(const Vector<uint8_t>& hmacKey);

    // Append FINGERPRINT (CRC32 of message-so-far XOR 0x5354554E)
    void appendFingerprint();

    // Get the final encoded message
    const Vector<uint8_t>& bytes() const { return m_bytes; }
    const Vector<uint8_t>& transactionId() const { return m_txnId; }

private:
    Vector<uint8_t> m_bytes;
    Vector<uint8_t> m_txnId;
    void updateLength();
};

// STUN message parser
struct StunAttribute {
    uint16_t type { 0 };
    Vector<uint8_t> value;
};

struct StunMessage {
    uint16_t type { 0 };  // method | class
    uint16_t method { 0 };
    uint16_t klass { 0 };
    Vector<uint8_t> transactionId; // 12 bytes
    Vector<StunAttribute> attributes;
    bool parsed { false };
};

bool driftstackParseStun(const uint8_t* data, size_t len, StunMessage& out);

// Find first attribute of given type; returns nullptr if not present
const StunAttribute* driftstackFindStunAttr(const StunMessage& msg, uint16_t type);

// Parse XOR-MAPPED-ADDRESS or XOR-RELAYED-ADDRESS attribute → host + port
bool driftstackParseXorAddress(const StunAttribute& attr,
                                const Vector<uint8_t>& transactionId,
                                String& outHost,
                                uint16_t& outPort);

// HMAC-SHA1 key for long-term credentials: MD5("user:realm:password")
Vector<uint8_t> driftstackLongTermKey(const String& username,
                                       const String& realm,
                                       const String& password);

// CRC32 (RFC 1952, for STUN FINGERPRINT)
uint32_t driftstackCrc32(const uint8_t* data, size_t len);

} // namespace WebKit

#endif // PLATFORM(DRIFTSTACK)
