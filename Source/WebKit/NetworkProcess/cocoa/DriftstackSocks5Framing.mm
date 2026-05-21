/*
 * DriftstackSocks5Framing.mm — pure-byte §7 wrap/unwrap implementation.
 * See header for design context. Wave 29-397 Slice 16.4.b.3.
 */

// Wave 29-397 Slice 16.4.b.5.b prep: config.h is WebKit-framework-internal
// and not on the include path when this .mm is compiled into the
// standalone DriftstackQuicInterpose dylib. Guard the inclusion: WebKit
// framework's xcodeproj defines DRIFTSTACK_FRAMING_BUILT_WITH_WEBKIT_CONFIG
// when including config.h is appropriate; dylib build doesn't define it
// and skips config.h. PLATFORM(DRIFTSTACK) define is supplied by the
// build environment (xcodeproj for framework, -DWTF_PLATFORM_DRIFTSTACK=1
// for dylib).
#if __has_include("config.h")
#import "config.h"
#endif
#import "DriftstackSocks5Framing.h"

#if PLATFORM(DRIFTSTACK)

#include <arpa/inet.h>
#include <wtf/text/MakeString.h>

namespace WebKit {
namespace Socks5Framing {

// Local constants — duplicate of DriftstackSocks5Client.h Socks5:: scope
// to keep this file self-contained (no WebKit framework header
// dependencies beyond WTF).
namespace {
constexpr uint8_t kReserved   = 0x00;
constexpr uint8_t kAtypIpv4   = 0x01;
constexpr uint8_t kAtypDomain = 0x03;
constexpr uint8_t kAtypIpv6   = 0x04;
}

bool wrap(const Endpoint& destination, std::span<const uint8_t> payload, Vector<uint8_t>& outFrame)
{
    auto hostUtf8 = destination.host.utf8();
    if (hostUtf8.length() == 0 || hostUtf8.length() > 255)
        return false;

    // Wave 29-499.95 — detect dotted-decimal IPv4 string and emit ATYP=0x01
    // instead of ATYP=0x03 domain form. gost has a bug with ATYP=0x03 (per
    // .91/.92 empirical: outbound ATYP=0x03 produced response garbage from
    // gost's own IP; ATYP=0x01 with pre-resolved IP works correctly).
    struct in_addr ipv4Addr { };
    bool isIPv4 = inet_pton(AF_INET, hostUtf8.data(), &ipv4Addr) == 1;

    outFrame.clear();
    outFrame.reserveInitialCapacity(10 + hostUtf8.length() + payload.size());

    // RSV(2) + FRAG(1)
    outFrame.append(kReserved);
    outFrame.append(kReserved);
    outFrame.append(static_cast<uint8_t>(0x00));   // FRAG (no fragmentation in v1)

    if (isIPv4) {
        // ATYP=0x01 IPv4 (per RFC 1928 §7)
        outFrame.append(kAtypIpv4);
        // s_addr is in network byte order; emit byte-for-byte.
        WTF_ALLOW_UNSAFE_BUFFER_USAGE_BEGIN
        const uint8_t* addrBytes = reinterpret_cast<const uint8_t*>(&ipv4Addr.s_addr);
        outFrame.append(addrBytes[0]);
        outFrame.append(addrBytes[1]);
        outFrame.append(addrBytes[2]);
        outFrame.append(addrBytes[3]);
        WTF_ALLOW_UNSAFE_BUFFER_USAGE_END
    } else {
        // ATYP=0x03 domain (fallback for hostnames we can't pre-resolve;
        // gost likely fails on these so the caller should ensure most
        // STUN/TURN hostnames are pre-resolved via the .94 hardcoded map).
        outFrame.append(kAtypDomain);
        outFrame.append(static_cast<uint8_t>(hostUtf8.length()));
        {
            WTF_ALLOW_UNSAFE_BUFFER_USAGE_BEGIN
            outFrame.append(unsafeMakeSpan(reinterpret_cast<const uint8_t*>(hostUtf8.data()), hostUtf8.length()));
            WTF_ALLOW_UNSAFE_BUFFER_USAGE_END
        }
    }

    // Port (network byte order)
    uint16_t portNetOrder = htons(destination.port);
    outFrame.append(static_cast<uint8_t>((portNetOrder >> 0) & 0xFF));
    outFrame.append(static_cast<uint8_t>((portNetOrder >> 8) & 0xFF));

    // Payload
    if (!payload.empty())
        outFrame.append(payload);

    return true;
}

WTF_ALLOW_UNSAFE_BUFFER_USAGE_BEGIN
bool unwrap(std::span<const uint8_t> frame, Endpoint& outSource, Vector<uint8_t>& outPayload)
{
    if (frame.size() < 7)
        return false;

    const uint8_t* bytes = frame.data();
    size_t len = frame.size();

    // bytes[0..1] RSV; bytes[2] FRAG; bytes[3] ATYP.
    if (bytes[2] != 0x00)
        return false;  // v1 doesn't reassemble fragmented datagrams.

    uint8_t atyp = bytes[3];
    size_t cursor = 4;

    if (atyp == kAtypDomain) {
        if (cursor + 1 > len) return false;
        uint8_t domainLen = bytes[cursor++];
        if (cursor + domainLen + 2 > len) return false;
        outSource.host = String::fromUTF8(unsafeMakeSpan(bytes + cursor, static_cast<size_t>(domainLen)));
        cursor += domainLen;
    } else if (atyp == kAtypIpv4) {
        if (cursor + 4 + 2 > len) return false;
        outSource.host = makeString(
            unsigned(bytes[cursor]), '.',
            unsigned(bytes[cursor + 1]), '.',
            unsigned(bytes[cursor + 2]), '.',
            unsigned(bytes[cursor + 3]));
        cursor += 4;
    } else if (atyp == kAtypIpv6) {
        if (cursor + 16 + 2 > len) return false;
        outSource.host = "[ipv6]"_s;
        cursor += 16;
    } else
        return false;

    // Wave 29-499.100 — port byte-order fix. Manual byte-by-byte
    // construction from network-order bytes already produces the correct
    // host-order value; calling ntohs() then would double-swap on
    // little-endian (x86/ARM64). Empirical: bytes [0x4B, 0x66] (=19302
    // network order) were producing port=26187 (=0x664B = byte-swapped)
    // → libwebrtc rejected the STUN binding response as source-port
    // mismatch → no srflx candidate → browserleaks/webrtc showed no IP.
    outSource.port = (static_cast<uint16_t>(bytes[cursor]) << 8) | bytes[cursor + 1];
    cursor += 2;

    if (cursor > len) return false;
    outPayload.clear();
    if (cursor < len)
        outPayload.append(unsafeMakeSpan(bytes + cursor, len - cursor));
    return true;
}
WTF_ALLOW_UNSAFE_BUFFER_USAGE_END

} // namespace Socks5Framing
} // namespace WebKit

#endif // PLATFORM(DRIFTSTACK)
