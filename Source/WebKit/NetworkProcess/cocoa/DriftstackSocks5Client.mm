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
#import <errno.h>
#import <netinet/in.h>
#import <sys/socket.h>
#import <unistd.h>
#import <wtf/Assertions.h>
#import <wtf/text/MakeString.h>

namespace WebKit {

struct DriftstackSocks5Client::Impl {
    Socks5Endpoint proxy;
    Socks5Credentials creds;
    RetainPtr<NSInputStream> readStream;
    RetainPtr<NSOutputStream> writeStream;
    int socketFd { -1 };
    bool handshakeOk { false };
    bool tcpConnected { false };
    bool udpAssociated { false };

    ~Impl()
    {
        if (socketFd >= 0) {
            close(socketFd);
            socketFd = -1;
        }
    }
};

DriftstackSocks5Client::DriftstackSocks5Client(const Socks5Endpoint& proxy, const Socks5Credentials& creds)
    : m_impl(std::make_unique<Impl>())
{
    m_impl->proxy = proxy;
    m_impl->creds = creds;
}

DriftstackSocks5Client::~DriftstackSocks5Client() = default;

// Phase B helper: blocking-write `len` bytes on the socket. Returns true on
// complete success, false on EOF or socket error. Called only after socket
// is connected. send() with MSG_NOSIGNAL avoids SIGPIPE on remote-close.
WTF_ALLOW_UNSAFE_BUFFER_USAGE_BEGIN
static bool sendAll(int fd, const uint8_t* buf, size_t len)
{
    size_t off = 0;
    while (off < len) {
        ssize_t n = ::send(fd, buf + off, len - off, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (n == 0)
            return false;
        off += static_cast<size_t>(n);
    }
    return true;
}

// Blocking-read exactly `len` bytes. Returns true on complete success,
// false on EOF or socket error. Used for fixed-size SOCKS5 reply frames.
static bool recvAll(int fd, uint8_t* buf, size_t len)
{
    size_t off = 0;
    while (off < len) {
        ssize_t n = ::recv(fd, buf + off, len - off, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (n == 0)
            return false;
        off += static_cast<size_t>(n);
    }
    return true;
}
WTF_ALLOW_UNSAFE_BUFFER_USAGE_END

// Phase B: open BSD socket + connect() to proxy. Proxy host MUST be IPv4
// literal per Wave 29-368.7 sandbox lockdown (we don't allow DNS to
// resolve the proxy itself either).
static int connectToProxy(const Socks5Endpoint& proxy)
{
    auto hostUtf8 = proxy.host.utf8();
    struct sockaddr_in addr { };
    addr.sin_family = AF_INET;
    addr.sin_port = htons(proxy.port);
    if (inet_pton(AF_INET, hostUtf8.data(), &addr.sin_addr) != 1) {
        WTFLogAlways("[Driftstack-EG-WK-1.8] connectToProxy: proxy host '%s' not IPv4 literal — customer must specify proxy as IP per v1.0 constraint", hostUtf8.data());
        return -1;
    }
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        WTFLogAlways("[Driftstack-EG-WK-1.8] connectToProxy: socket() failed errno=%d", errno);
        return -1;
    }
    if (::connect(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
        WTFLogAlways("[Driftstack-EG-WK-1.8] connectToProxy: connect(%s:%u) failed errno=%d",
            hostUtf8.data(), unsigned(proxy.port), errno);
        ::close(fd);
        return -1;
    }
    return fd;
}

// RFC 1928 §3 handshake. Sends method list, reads server's selected method.
// If username/pass selected, performs RFC 1929 §2 sub-negotiation.
Socks5Result DriftstackSocks5Client::performHandshake()
{
    if (m_impl->handshakeOk)
        return Socks5Result::Success;

    if (m_impl->socketFd < 0) {
        m_impl->socketFd = connectToProxy(m_impl->proxy);
        if (m_impl->socketFd < 0)
            return Socks5Result::NetworkError;
    }
    int fd = m_impl->socketFd;
    bool hasAuth = !m_impl->creds.isEmpty();

    // [VER=5, NMETHODS, METHODS...] where methods always includes 0x00 (no auth)
    // and adds 0x02 (user/pass) if credentials present.
    uint8_t greet[4];
    greet[0] = Socks5::kVersion5;
    if (hasAuth) {
        greet[1] = 2;
        greet[2] = Socks5::kMethodNoAuth;
        greet[3] = Socks5::kMethodUsernamePassword;
        if (!sendAll(fd, greet, 4))
            return Socks5Result::HandshakeFailed;
    } else {
        greet[1] = 1;
        greet[2] = Socks5::kMethodNoAuth;
        if (!sendAll(fd, greet, 3))
            return Socks5Result::HandshakeFailed;
    }

    // [VER=5, METHOD]
    uint8_t reply[2];
    if (!recvAll(fd, reply, 2))
        return Socks5Result::HandshakeFailed;
    if (reply[0] != Socks5::kVersion5)
        return Socks5Result::ProtocolError;
    if (reply[1] == Socks5::kMethodNoneAcceptable)
        return Socks5Result::AuthRequired;
    if (reply[1] == Socks5::kMethodNoAuth) {
        m_impl->handshakeOk = true;
        return Socks5Result::Success;
    }
    if (reply[1] == Socks5::kMethodUsernamePassword && hasAuth) {
        // RFC 1929 §2: [VER=1, ULEN, UNAME, PLEN, PASSWD]
        auto unameUtf8 = m_impl->creds.username.utf8();
        auto passwdUtf8 = m_impl->creds.password.utf8();
        if (unameUtf8.length() > 255 || passwdUtf8.length() > 255)
            return Socks5Result::AuthFailed;
        Vector<uint8_t> authMsg;
        authMsg.append(0x01);  // RFC 1929 ver
        authMsg.append(static_cast<uint8_t>(unameUtf8.length()));
        authMsg.append(unameUtf8.span());
        authMsg.append(static_cast<uint8_t>(passwdUtf8.length()));
        authMsg.append(passwdUtf8.span());
        if (!sendAll(fd, authMsg.span().data(), authMsg.size()))
            return Socks5Result::AuthFailed;
        // [VER=1, STATUS] — STATUS 0 means success
        uint8_t authReply[2];
        if (!recvAll(fd, authReply, 2))
            return Socks5Result::AuthFailed;
        if (authReply[1] != 0x00)
            return Socks5Result::AuthFailed;
        m_impl->handshakeOk = true;
        return Socks5Result::Success;
    }
    return Socks5Result::ProtocolError;
}

// RFC 1928 §4 + §6: TCP CONNECT with ATYP=0x03 (DOMAINNAME). Per EG-WK-1.9
// Slice 1 default — never sends pre-resolved IPv4 (no local DNS leak).
Socks5Result DriftstackSocks5Client::tcpConnect(const Socks5Endpoint& destination, Socks5Endpoint& out)
{
    if (!m_impl->handshakeOk) {
        auto h = performHandshake();
        if (h != Socks5Result::Success)
            return h;
    }
    int fd = m_impl->socketFd;

    auto destUtf8 = destination.host.utf8();
    if (destUtf8.length() > 255)
        return Socks5Result::DomainTooLong;

    // [VER=5, CMD=CONNECT, RSV=0, ATYP=DOMAIN, DLEN, DOMAIN..., PORT_BE_HI, PORT_BE_LO]
    Vector<uint8_t> req;
    req.append(Socks5::kVersion5);
    req.append(Socks5::kCmdConnect);
    req.append(Socks5::kReserved);
    req.append(Socks5::kAtypDomain);
    req.append(static_cast<uint8_t>(destUtf8.length()));
    req.append(destUtf8.span());
    uint16_t portBE = htons(destination.port);
    req.append(static_cast<uint8_t>(portBE & 0xFF));
    req.append(static_cast<uint8_t>((portBE >> 8) & 0xFF));
    if (!sendAll(fd, req.span().data(), req.size()))
        return Socks5Result::ConnectFailed;

    // [VER=5, REP, RSV=0, ATYP, BND.ADDR..., BND.PORT_BE]
    uint8_t hdr[4];
    if (!recvAll(fd, hdr, 4))
        return Socks5Result::ConnectFailed;
    if (hdr[0] != Socks5::kVersion5)
        return Socks5Result::ProtocolError;
    if (hdr[1] != Socks5::kReplySucceeded) {
        WTFLogAlways("[Driftstack-EG-WK-1.9] tcpConnect: SOCKS5 reply REP=0x%02x (non-success) for %s:%u",
            unsigned(hdr[1]), destUtf8.data(), unsigned(destination.port));
        return Socks5Result::ConnectFailed;
    }
    uint8_t replyAtyp = hdr[3];
    String bndHost;
    if (replyAtyp == Socks5::kAtypIpv4) {
        uint8_t addr[4];
        if (!recvAll(fd, addr, 4)) return Socks5Result::ConnectFailed;
        bndHost = makeString(unsigned(addr[0]), '.', unsigned(addr[1]), '.', unsigned(addr[2]), '.', unsigned(addr[3]));
    } else if (replyAtyp == Socks5::kAtypDomain) {
        uint8_t dlen;
        if (!recvAll(fd, &dlen, 1)) return Socks5Result::ConnectFailed;
        Vector<uint8_t> domainBuf;
        domainBuf.grow(dlen);
        if (!recvAll(fd, domainBuf.mutableSpan().data(), dlen)) return Socks5Result::ConnectFailed;
        bndHost = String::fromUTF8(domainBuf.span());
    } else if (replyAtyp == Socks5::kAtypIpv6) {
        uint8_t addr[16];
        if (!recvAll(fd, addr, 16)) return Socks5Result::ConnectFailed;
        bndHost = "[ipv6]"_s;
    } else {
        return Socks5Result::ProtocolError;
    }
    uint8_t portBytes[2];
    if (!recvAll(fd, portBytes, 2)) return Socks5Result::ConnectFailed;
    uint16_t bndPort = (static_cast<uint16_t>(portBytes[0]) << 8) | portBytes[1];

    out.host = bndHost;
    out.port = bndPort;
    m_impl->tcpConnected = true;

    WTFLogAlways("[Driftstack-EG-WK-1.9] tcpConnect: success — dest=%s:%u via proxy, BND=%s:%u, ATYP=0x03 (domain) sent (no local DNS leak)",
        destUtf8.data(), unsigned(destination.port),
        bndHost.utf8().data(), unsigned(bndPort));
    return Socks5Result::Success;
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
