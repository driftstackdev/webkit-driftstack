/*
 * DriftstackStun.mm — Wave 29-499.212 (Phase 5 TURN)
 *
 * STUN/TURN message encoder/decoder with LibreSSL HMAC-SHA1 + CRC32.
 */

#import "config.h"
#import "DriftstackStun.h"

#if PLATFORM(DRIFTSTACK)

#import <dlfcn.h>
#import <stdlib.h>
#import <string.h>
#import <Security/SecRandom.h>
#import <CommonCrypto/CommonDigest.h>
#import <wtf/Assertions.h>

WTF_ALLOW_UNSAFE_BUFFER_USAGE_BEGIN

namespace WebKit {

namespace {

// LibreSSL HMAC dlsym helper
typedef void* (*FnHMAC)(const void* md, const uint8_t* key, int keyLen,
                        const uint8_t* data, size_t dataLen,
                        uint8_t* out, unsigned int* outLen);
typedef const void* (*FnSha)(void);

struct StunCryptoFns {
    FnHMAC hmac = nullptr;
    FnSha sha1 = nullptr;
    bool ready = false;
};
StunCryptoFns& stunCryptoFns()
{
    static StunCryptoFns f;
    if (!f.ready) {
        void* h = dlopen("/usr/lib/libssl.48.dylib", RTLD_NOW | RTLD_GLOBAL);
        if (h) {
            f.hmac = (FnHMAC)dlsym(h, "HMAC");
            f.sha1 = (FnSha)dlsym(h, "EVP_sha1");
            f.ready = f.hmac && f.sha1;
        }
    }
    return f;
}

void appendU16(Vector<uint8_t>& v, uint16_t x)
{
    v.append(static_cast<uint8_t>(x >> 8));
    v.append(static_cast<uint8_t>(x & 0xFF));
}
void appendU32(Vector<uint8_t>& v, uint32_t x)
{
    v.append(static_cast<uint8_t>((x >> 24) & 0xFF));
    v.append(static_cast<uint8_t>((x >> 16) & 0xFF));
    v.append(static_cast<uint8_t>((x >> 8) & 0xFF));
    v.append(static_cast<uint8_t>(x & 0xFF));
}

uint16_t readU16(const uint8_t* d) { return (static_cast<uint16_t>(d[0]) << 8) | d[1]; }
uint32_t readU32(const uint8_t* d)
{
    return (static_cast<uint32_t>(d[0]) << 24) | (static_cast<uint32_t>(d[1]) << 16)
         | (static_cast<uint32_t>(d[2]) << 8) | d[3];
}

} // anonymous namespace

// === StunMessageBuilder ===

static uint16_t encodeMessageType(uint16_t method, uint16_t klass)
{
    // STUN message type = M11..M0 + C1 C0 bits per RFC 5389
    // C1=bit8, C0=bit4
    uint16_t c1 = (klass >> 4) & 0x01;
    uint16_t c0 = klass & 0x01;
    uint16_t m_high = (method >> 7) & 0x1F;
    uint16_t m_mid = (method >> 4) & 0x07;
    uint16_t m_low = method & 0x0F;
    return (m_high << 9) | (c1 << 8) | (m_mid << 5) | (c0 << 4) | m_low;
}

StunMessageBuilder::StunMessageBuilder(uint16_t method, uint16_t klass)
{
    m_txnId.resize(12);
    (void)SecRandomCopyBytes(kSecRandomDefault, 12, m_txnId.mutableSpan().data());

    appendU16(m_bytes, encodeMessageType(method, klass));
    appendU16(m_bytes, 0);  // length placeholder
    appendU32(m_bytes, kStunMagicCookie);
    m_bytes.append(m_txnId.span());
}

StunMessageBuilder::StunMessageBuilder(uint16_t method, uint16_t klass, const Vector<uint8_t>& txnId)
{
    m_txnId = txnId;
    appendU16(m_bytes, encodeMessageType(method, klass));
    appendU16(m_bytes, 0);
    appendU32(m_bytes, kStunMagicCookie);
    m_bytes.append(m_txnId.span());
}

void StunMessageBuilder::updateLength()
{
    // Length = bytes after 20-byte header (excluding header itself)
    uint16_t len = static_cast<uint16_t>(m_bytes.size() - 20);
    m_bytes[2] = (len >> 8) & 0xFF;
    m_bytes[3] = len & 0xFF;
}

void StunMessageBuilder::addAttribute(uint16_t type, const Vector<uint8_t>& value)
{
    appendU16(m_bytes, type);
    appendU16(m_bytes, static_cast<uint16_t>(value.size()));
    m_bytes.append(value.span());
    // 4-byte padding
    while (m_bytes.size() % 4 != 0)
        m_bytes.append(0);
    updateLength();
}

void StunMessageBuilder::addAttributeString(uint16_t type, const String& value)
{
    auto utf8 = value.utf8();
    Vector<uint8_t> bytes;
    bytes.append(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(utf8.data()), utf8.length()));
    addAttribute(type, bytes);
}

void StunMessageBuilder::appendMessageIntegrity(const Vector<uint8_t>& hmacKey)
{
    // Temporarily set length field to current_length + 24 (MI attr size)
    uint16_t fakeLen = static_cast<uint16_t>(m_bytes.size() - 20 + 24);
    m_bytes[2] = (fakeLen >> 8) & 0xFF;
    m_bytes[3] = fakeLen & 0xFF;

    auto& f = stunCryptoFns();
    Vector<uint8_t> mac(20);
    if (f.hmac && f.sha1) {
        unsigned int outLen = 20;
        f.hmac(f.sha1(), hmacKey.span().data(), static_cast<int>(hmacKey.size()),
               m_bytes.span().data(), m_bytes.size(),
               mac.mutableSpan().data(), &outLen);
        mac.resize(outLen);
    }

    // Append MESSAGE-INTEGRITY attribute (20-byte HMAC-SHA1)
    appendU16(m_bytes, kAttrMessageIntegrity);
    appendU16(m_bytes, 20);
    m_bytes.append(mac.span());
    updateLength();
}

void StunMessageBuilder::appendFingerprint()
{
    // Set length to current + 8 (FINGERPRINT attr is 8 bytes)
    uint16_t fakeLen = static_cast<uint16_t>(m_bytes.size() - 20 + 8);
    m_bytes[2] = (fakeLen >> 8) & 0xFF;
    m_bytes[3] = fakeLen & 0xFF;

    uint32_t crc = driftstackCrc32(m_bytes.span().data(), m_bytes.size()) ^ 0x5354554EUL;
    appendU16(m_bytes, kAttrFingerprint);
    appendU16(m_bytes, 4);
    appendU32(m_bytes, crc);
    updateLength();
}

// === Parser ===

bool driftstackParseStun(const uint8_t* data, size_t len, StunMessage& out)
{
    if (len < 20) return false;
    out.type = readU16(data);
    // length field at +2
    uint16_t bodyLen = readU16(data + 2);
    uint32_t cookie = readU32(data + 4);
    if (cookie != kStunMagicCookie) return false;
    if (20 + bodyLen > len) return false;

    // Decode method + class
    out.method = ((out.type >> 9) & 0x1F) << 7;
    out.method |= ((out.type >> 5) & 0x07) << 4;
    out.method |= out.type & 0x0F;
    out.klass = ((out.type >> 8) & 0x1) << 4;
    out.klass |= ((out.type >> 4) & 0x1);

    out.transactionId.resize(12);
    memcpy(out.transactionId.mutableSpan().data(), data + 8, 12);

    size_t off = 20;
    size_t end = 20 + bodyLen;
    while (off + 4 <= end) {
        uint16_t attrType = readU16(data + off);
        uint16_t attrLen = readU16(data + off + 2);
        off += 4;
        if (off + attrLen > end) break;
        StunAttribute attr;
        attr.type = attrType;
        attr.value.resize(attrLen);
        memcpy(attr.value.mutableSpan().data(), data + off, attrLen);
        out.attributes.append(std::move(attr));
        off += attrLen;
        while (off < end && off % 4 != 0) off++;
    }
    out.parsed = true;
    return true;
}

const StunAttribute* driftstackFindStunAttr(const StunMessage& msg, uint16_t type)
{
    for (auto& a : msg.attributes)
        if (a.type == type)
            return &a;
    return nullptr;
}

bool driftstackParseXorAddress(const StunAttribute& attr,
                                const Vector<uint8_t>& transactionId,
                                String& outHost,
                                uint16_t& outPort)
{
    // XOR-MAPPED-ADDRESS: family(1) + reserved(1) + port(2-XOR-cookie) + addr(4 or 16, XOR-cookie/txnid)
    if (attr.value.size() < 8) return false;
    uint8_t family = attr.value[1];
    uint16_t xorPort = (static_cast<uint16_t>(attr.value[2]) << 8) | attr.value[3];
    outPort = xorPort ^ ((kStunMagicCookie >> 16) & 0xFFFF);

    if (family == 0x01) {  // IPv4
        if (attr.value.size() < 8) return false;
        uint8_t addrBytes[4];
        uint32_t cookieBytes[4] = {
            (kStunMagicCookie >> 24) & 0xFF,
            (kStunMagicCookie >> 16) & 0xFF,
            (kStunMagicCookie >> 8) & 0xFF,
            kStunMagicCookie & 0xFF
        };
        for (int i = 0; i < 4; ++i)
            addrBytes[i] = attr.value[4 + i] ^ cookieBytes[i];
        char buf[16];
        snprintf(buf, sizeof(buf), "%u.%u.%u.%u", addrBytes[0], addrBytes[1], addrBytes[2], addrBytes[3]);
        outHost = String::fromUTF8(unsafeMakeSpan(buf, strlen(buf)));
        return true;
    }
    // IPv6 not implemented this iteration
    return false;
}

// HMAC key = MD5(user:realm:password) per RFC 5389 §15.4
Vector<uint8_t> driftstackLongTermKey(const String& username, const String& realm, const String& password)
{
    auto u = username.utf8();
    auto r = realm.utf8();
    auto p = password.utf8();
    Vector<uint8_t> in;
    in.append(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(u.data()), u.length()));
    in.append(':');
    in.append(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(r.data()), r.length()));
    in.append(':');
    in.append(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(p.data()), p.length()));

    Vector<uint8_t> out(16);
    CC_MD5(in.span().data(), static_cast<CC_LONG>(in.size()), out.mutableSpan().data());
    return out;
}

// CRC32 (zlib/RFC 1952 polynomial 0xEDB88320, init 0xFFFFFFFF, final XOR 0xFFFFFFFF)
uint32_t driftstackCrc32(const uint8_t* data, size_t len)
{
    static uint32_t table[256];
    static bool tableInit = false;
    if (!tableInit) {
        for (uint32_t i = 0; i < 256; ++i) {
            uint32_t c = i;
            for (int k = 0; k < 8; ++k)
                c = (c & 1) ? (0xEDB88320U ^ (c >> 1)) : (c >> 1);
            table[i] = c;
        }
        tableInit = true;
    }
    uint32_t crc = 0xFFFFFFFFU;
    for (size_t i = 0; i < len; ++i)
        crc = table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
    return crc ^ 0xFFFFFFFFU;
}

} // namespace WebKit

WTF_ALLOW_UNSAFE_BUFFER_USAGE_END

#endif // PLATFORM(DRIFTSTACK)
