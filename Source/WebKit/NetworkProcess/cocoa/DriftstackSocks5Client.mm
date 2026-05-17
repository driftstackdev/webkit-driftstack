/*
 * DriftstackSocks5Client.mm — Wave 29-368 Phase A scaffold stub.
 *
 * See DriftstackSocks5Client.h for design + RFC 1928 / RFC 1929 constants.
 *
 * Phase A (this commit): all methods return NotImplemented + log via
 * WTFLogAlways under [Driftstack-EG-WK-1.8/1.9] tag so any premature
 * production usage is visibly noisy. The Wave 29-366 CFNetwork SOCKS5
 * path remains the shipped behavior until Phase B (TCP CONNECT) +
 * Phase C (UDP ASSOCIATE) land and DRIFTSTACK_CUSTOM_SOCKS5=1 explicit
 * opt-in switches over.
 *
 * Phase B (next slice): TCP CONNECT via CFStreamPair + ATYP=0x03 domain.
 * Phase C: UDP ASSOCIATE via separate UDP socket + §7 frame wrapping.
 */

#import "config.h"
#import "DriftstackSocks5Client.h"

#if PLATFORM(DRIFTSTACK)

#import <arpa/inet.h>
#import <wtf/Assertions.h>
#import <wtf/text/MakeString.h>

namespace WebKit {

struct DriftstackSocks5Client::Impl {
    Socks5Endpoint proxy;
    Socks5Credentials creds;
    RetainPtr<NSInputStream> readStream;
    RetainPtr<NSOutputStream> writeStream;
    bool handshakeOk { false };
    bool tcpConnected { false };
    bool udpAssociated { false };
};

DriftstackSocks5Client::DriftstackSocks5Client(const Socks5Endpoint& proxy, const Socks5Credentials& creds)
    : m_impl(std::make_unique<Impl>())
{
    m_impl->proxy = proxy;
    m_impl->creds = creds;
}

DriftstackSocks5Client::~DriftstackSocks5Client() = default;

Socks5Result DriftstackSocks5Client::performHandshake()
{
    static bool loggedOnce = false;
    if (!loggedOnce) {
        loggedOnce = true;
        WTFLogAlways("[Driftstack-EG-WK-1.8] DriftstackSocks5Client::performHandshake() called — Phase A scaffold (Wave 29-368); networking impl pending Phase B");
    }
    return Socks5Result::NotImplemented;
}

Socks5Result DriftstackSocks5Client::tcpConnect(const Socks5Endpoint& destination, Socks5Endpoint& out)
{
    static bool loggedOnce = false;
    if (!loggedOnce) {
        loggedOnce = true;
        WTFLogAlways("[Driftstack-EG-WK-1.9] DriftstackSocks5Client::tcpConnect(%s:%u) — Phase A scaffold; ATYP=0x03 domain impl pending Phase B",
            destination.host.utf8().data(), unsigned(destination.port));
    }
    UNUSED_PARAM(out);
    return Socks5Result::NotImplemented;
}

Socks5Result DriftstackSocks5Client::udpAssociate(Socks5UdpRelayChannel& out)
{
    static bool loggedOnce = false;
    if (!loggedOnce) {
        loggedOnce = true;
        WTFLogAlways("[Driftstack-EG-WK-1.8] DriftstackSocks5Client::udpAssociate() — Phase A scaffold; UDP ASSOCIATE impl pending Phase C");
    }
    UNUSED_PARAM(out);
    return Socks5Result::NotImplemented;
}

RetainPtr<NSInputStream> DriftstackSocks5Client::tcpReadStream() const
{
    return m_impl->readStream;
}

RetainPtr<NSOutputStream> DriftstackSocks5Client::tcpWriteStream() const
{
    return m_impl->writeStream;
}

RetainPtr<NSData> DriftstackSocks5Client::wrapUdpDatagram(const Socks5Endpoint& destination, NSData* payload)
{
    // RFC 1928 §7: [RSV 2][FRAG 1][ATYP 1][DST.ADDR var][DST.PORT 2][DATA var]
    // We always use ATYP=0x03 (domain) for outbound UDP per EG-WK-1.9 default.
    auto domainUtf8 = destination.host.utf8();
    if (domainUtf8.length() > 255) {
        WTFLogAlways("[Driftstack-EG-WK-1.8] wrapUdpDatagram domain too long (%zu > 255 bytes)", domainUtf8.length());
        return nullptr;
    }

    NSMutableData* frame = [NSMutableData dataWithCapacity:7 + domainUtf8.length() + (payload ? [payload length] : 0)];
    uint8_t header[4] = {
        Socks5::kReserved, Socks5::kReserved,  // RSV
        0x00,                                    // FRAG (no fragmentation in v1)
        Socks5::kAtypDomain                      // ATYP=0x03
    };
    [frame appendBytes:header length:4];

    uint8_t domainLen = static_cast<uint8_t>(domainUtf8.length());
    [frame appendBytes:&domainLen length:1];
    [frame appendBytes:domainUtf8.data() length:domainUtf8.length()];

    uint16_t portNetOrder = htons(destination.port);
    [frame appendBytes:&portNetOrder length:2];

    if (payload && [payload length])
        [frame appendData:payload];

    return frame;
}

// RFC 1928 §7 frame parser. Self-contained; bounds-checked via explicit
// span access. Returns parsed payload + populates outSource. Returns nullptr
// on protocol or size error.
WTF_ALLOW_UNSAFE_BUFFER_USAGE_BEGIN
static RetainPtr<NSData> parseUdpFrame(NSData* frame, Socks5Endpoint& outSource)
{
    if (!frame || [frame length] < 7)
        return nullptr;

    NSUInteger len = [frame length];
    const uint8_t* bytes = static_cast<const uint8_t*>([frame bytes]);

    // bytes[0..1] RSV; bytes[2] FRAG; bytes[3] ATYP.
    if (bytes[2] != 0x00)
        return nullptr;  // v1 doesn't reassemble fragmented datagrams.

    uint8_t atyp = bytes[3];
    NSUInteger cursor = 4;

    if (atyp == Socks5::kAtypDomain) {
        if (cursor + 1 > len) return nullptr;
        uint8_t domainLen = bytes[cursor++];
        if (cursor + domainLen + 2 > len) return nullptr;
        outSource.host = String::fromUTF8(unsafeMakeSpan(bytes + cursor, static_cast<size_t>(domainLen)));
        cursor += domainLen;
    } else if (atyp == Socks5::kAtypIpv4) {
        if (cursor + 4 + 2 > len) return nullptr;
        outSource.host = makeString(
            unsigned(bytes[cursor]), '.',
            unsigned(bytes[cursor + 1]), '.',
            unsigned(bytes[cursor + 2]), '.',
            unsigned(bytes[cursor + 3]));
        cursor += 4;
    } else if (atyp == Socks5::kAtypIpv6) {
        if (cursor + 16 + 2 > len) return nullptr;
        outSource.host = "[ipv6]"_s;
        cursor += 16;
    } else
        return nullptr;

    uint16_t portNetOrder = (static_cast<uint16_t>(bytes[cursor]) << 8) | bytes[cursor + 1];
    outSource.port = ntohs(portNetOrder);
    cursor += 2;

    if (cursor > len) return nullptr;
    return [NSData dataWithBytes:(bytes + cursor) length:(len - cursor)];
}
WTF_ALLOW_UNSAFE_BUFFER_USAGE_END

RetainPtr<NSData> DriftstackSocks5Client::unwrapUdpDatagram(NSData* frame, Socks5Endpoint& source)
{
    return parseUdpFrame(frame, source);
}

} // namespace WebKit

#endif // PLATFORM(DRIFTSTACK)
