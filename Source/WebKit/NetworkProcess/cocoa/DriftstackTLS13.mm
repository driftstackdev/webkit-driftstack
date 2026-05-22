/*
 * DriftstackTLS13.mm — Wave 29-499.172 (PathB v2 Phase 1.5e)
 *
 * TLS 1.3 record reader + ServerHello parser. Crypto layered on
 * top of LibreSSL via DriftstackCrypto (next iteration .173).
 */

#import "config.h"
#import "DriftstackTLS13.h"

#if PLATFORM(DRIFTSTACK)

#import <errno.h>
#import <sys/socket.h>
#import <unistd.h>
#import <wtf/Assertions.h>

WTF_ALLOW_UNSAFE_BUFFER_USAGE_BEGIN

namespace WebKit {

namespace {

constexpr uint8_t kHandshakeTypeServerHello = 0x02;
constexpr uint16_t kExtSupportedVersions = 43;
constexpr uint16_t kExtKeyShare = 51;

// Read exactly N bytes from fd; returns false on EOF/error.
bool readExact(int fd, uint8_t* buf, size_t n)
{
    size_t got = 0;
    while (got < n) {
        ssize_t r = recv(fd, buf + got, n - got, 0);
        if (r > 0) { got += static_cast<size_t>(r); continue; }
        if (r == 0) return false;  // EOF
        if (errno == EINTR) continue;
        return false;
    }
    return true;
}

} // anonymous namespace

bool driftstackReadTLSRecord(int fd, uint8_t& outType, uint16_t& outVersion, Vector<uint8_t>& outBody)
{
    uint8_t header[5];
    if (!readExact(fd, header, 5))
        return false;
    outType = header[0];
    outVersion = static_cast<uint16_t>((header[1] << 8) | header[2]);
    uint16_t bodyLen = static_cast<uint16_t>((header[3] << 8) | header[4]);
    outBody.resize(bodyLen);
    if (bodyLen == 0) return true;
    return readExact(fd, outBody.mutableSpan().data(), bodyLen);
}

bool driftstackParseServerHello(const uint8_t* data, size_t len, TLS13ServerHello& out)
{
    // ServerHello body structure:
    //   legacy_version (2)
    //   random (32)
    //   legacy_session_id_echo (1 + N)
    //   cipher_suite (2)
    //   legacy_compression_method (1)
    //   extensions (2-byte length + variable)
    if (len < 2 + 32 + 1 + 2 + 1 + 2)
        return false;

    size_t off = 0;

    // Skip legacy_version (server should send 0x0303)
    off += 2;

    // server_random (32 bytes)
    out.serverRandom.resize(32);
    memcpy(out.serverRandom.mutableSpan().data(), data + off, 32);
    off += 32;

    // legacy_session_id_echo
    uint8_t sidLen = data[off++];
    if (off + sidLen > len) return false;
    out.sessionIdEcho.resize(sidLen);
    memcpy(out.sessionIdEcho.mutableSpan().data(), data + off, sidLen);
    off += sidLen;

    // cipher_suite
    if (off + 2 > len) return false;
    out.cipherSuite = static_cast<uint16_t>((data[off] << 8) | data[off + 1]);
    off += 2;

    // legacy_compression_method (skip 1 byte)
    if (off + 1 > len) return false;
    off += 1;

    // extensions block length
    if (off + 2 > len) return false;
    uint16_t extsLen = static_cast<uint16_t>((data[off] << 8) | data[off + 1]);
    off += 2;
    if (off + extsLen > len) return false;

    size_t extsEnd = off + extsLen;
    while (off + 4 <= extsEnd) {
        uint16_t extType = static_cast<uint16_t>((data[off] << 8) | data[off + 1]);
        uint16_t extLen = static_cast<uint16_t>((data[off + 2] << 8) | data[off + 3]);
        off += 4;
        if (off + extLen > extsEnd) return false;

        if (extType == kExtSupportedVersions) {
            // server sends single u16 = selected version
            if (extLen == 2)
                out.selectedVersion = static_cast<uint16_t>((data[off] << 8) | data[off + 1]);
        } else if (extType == kExtKeyShare) {
            // server sends KeyShareEntry: group (u16) + key_exchange (u16-len + bytes)
            if (extLen >= 4) {
                out.keyShareGroup = static_cast<uint16_t>((data[off] << 8) | data[off + 1]);
                uint16_t kxLen = static_cast<uint16_t>((data[off + 2] << 8) | data[off + 3]);
                if (4 + kxLen <= extLen) {
                    out.keyShareKey.resize(kxLen);
                    memcpy(out.keyShareKey.mutableSpan().data(), data + off + 4, kxLen);
                }
            }
        }
        off += extLen;
    }

    WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.172] ServerHello parsed: cipher=0x%04x version=0x%04x keyShareGroup=0x%04x keyLen=%zu",
        out.cipherSuite, out.selectedVersion, out.keyShareGroup, out.keyShareKey.size());

    return true;
}

} // namespace WebKit

WTF_ALLOW_UNSAFE_BUFFER_USAGE_END

#endif // PLATFORM(DRIFTSTACK)
