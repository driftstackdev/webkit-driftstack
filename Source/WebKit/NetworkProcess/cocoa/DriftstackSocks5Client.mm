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

#import "DriftstackSocks5Framing.h"

#if PLATFORM(DRIFTSTACK)

#import <arpa/inet.h>
#import <errno.h>
#import <netinet/in.h>
#import <sys/socket.h>
#import <fcntl.h>   // W2744: O_NONBLOCK for the bounded non-blocking connect
#import <poll.h>    // W2744: poll() connect deadline
#import <time.h>    // W2747: clock_gettime(CLOCK_MONOTONIC) for the EINTR-safe connect deadline
#import <sys/time.h>
#import <wtf/Scope.h>
#import <unistd.h>
#import <wtf/Assertions.h>
#import <wtf/cocoa/SpanCocoa.h>
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
    // W1531: defensive timeout on the SOCKS5 CONNECT handshake recvs. The session
    // UDP probe (NetworkSessionCocoa) and the TLS-1.3 handshake reads already bound
    // their reads with SO_RCVTIMEO; connectToProxy() did not, leaving one unbounded
    // blocking recv on the control socket. If a proxy ever accepts the TCP
    // connection but stalls the SOCKS5 reply, recvAll() would block until the ~25s
    // WebContent pageLoad timeout. 8s bounds it to a fast failure → recvAll returns
    // false → performHandshake fails (load errors instead of stalling). 8s is
    // generous (a working chain replies in <2s); the TLS-1.3 client re-sets and
    // clears its own timeout once it owns the fd, so the data phase is unaffected.
    // (Robustness hygiene — NOT a fix for the A3-W448 "fork SOCKS5 load hang",
    // which W450 retracted as a probe-env artifact: the fork loads correctly through
    // both single-hop [W1516] and 2-hop [A2-W200] SOCKS5 chains.)
    struct timeval socks5HandshakeTimeout { 8, 0 };
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &socks5HandshakeTimeout, sizeof(socks5HandshakeTimeout));
    ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &socks5HandshakeTimeout, sizeof(socks5HandshakeTimeout));
    // W2744: SO_SNDTIMEO/SO_RCVTIMEO (set above) do NOT bound connect() on macOS/BSD — they govern
    // send/recv, not the TCP-SYN wait. A dead/black-holed proxy exit made a BLOCKING connect() hang the
    // kernel default (~75s) → the founder's "first page blank ~76s then renders" (the load finally lands
    // after the hang). Bound it: non-blocking connect + poll(POLLOUT, 5s) + SO_ERROR check. A TCP connect
    // to the proxy host is normally <1s; 5s is generous for a slow residential proxy; a dead exit fails in
    // 5s → the loader retries a FRESH exit fast (W2700) instead of a ~75s stall. Restore blocking afterward
    // so the SO_RCVTIMEO-bounded SOCKS5 handshake recvs behave exactly as before.
    int connFlags = ::fcntl(fd, F_GETFL, 0);
    ::fcntl(fd, F_SETFL, connFlags | O_NONBLOCK);
    int connRc = ::connect(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));
    if (connRc < 0 && errno == EINPROGRESS) {
        // W2747 (PROD-DOWN regression fix): the W2744 poll was UNGUARDED — a SINGLE poll() whose `pr < 0`
        // (errno==EINTR) was treated as a fatal connect failure. The WebKit Network process is signal-heavy
        // (libdispatch timers etc.), so poll() on the proxy connect got interrupted (EINTR) and HARD-FAILED
        // the connect → "[W2744] poll error within 5s" on every load → "socks5 handshake failed on all
        // sites" (the proxy is a LOCAL relay 127.0.0.1:* that NEVER takes 75s, so the bounded connect must
        // not be fragile). FIX: an EINTR-safe poll loop bounded by an absolute 5s monotonic deadline. Only a
        // genuine timeout or a confirmed SO_ERROR fast-fails (→ fresh-exit retry, the W2744 intent). An
        // UNEXPECTED (non-EINTR) poll error no longer hard-fails — it falls through to blocking-connect
        // completion (bounded by the 8s SO_*TIMEO below) so a poll quirk can never break prod again.
        struct timespec ts;
        ::clock_gettime(CLOCK_MONOTONIC, &ts);
        int64_t deadlineMs = int64_t(ts.tv_sec) * 1000 + ts.tv_nsec / 1000000 + 5000;
        bool fastFailed = false;
        for (;;) {
            ::clock_gettime(CLOCK_MONOTONIC, &ts);
            int remainingMs = int(deadlineMs - (int64_t(ts.tv_sec) * 1000 + ts.tv_nsec / 1000000));
            if (remainingMs <= 0) {
                WTFLogAlways("[Driftstack-EG-WK-1.8/W2747] connectToProxy: connect(%s:%u) did not complete within 5s — fast-failing for retry",
                    hostUtf8.data(), unsigned(proxy.port));
                ::close(fd); fastFailed = true; break;
            }
            struct pollfd pfd { fd, POLLOUT, 0 };
            int pr = ::poll(&pfd, 1, remainingMs);
            if (pr > 0) {
                int soErr = 0; socklen_t soLen = sizeof(soErr);
                ::getsockopt(fd, SOL_SOCKET, SO_ERROR, &soErr, &soLen);
                if (soErr) {
                    WTFLogAlways("[Driftstack-EG-WK-1.8/W2747] connectToProxy: connect(%s:%u) failed errno=%d",
                        hostUtf8.data(), unsigned(proxy.port), soErr);
                    ::close(fd); fastFailed = true;
                }
                break;   // connected (soErr==0) → proceed below; or fast-failed
            }
            if (pr == 0) {
                WTFLogAlways("[Driftstack-EG-WK-1.8/W2747] connectToProxy: connect(%s:%u) did not complete within 5s — fast-failing for retry",
                    hostUtf8.data(), unsigned(proxy.port));
                ::close(fd); fastFailed = true; break;
            }
            if (errno == EINTR)
                continue;   // ← THE W2744 BUG: poll interrupted by a signal — re-poll the remaining deadline, do NOT fail
            WTFLogAlways("[Driftstack-EG-WK-1.8/W2747] connectToProxy: connect(%s:%u) poll errno=%d — falling back to blocking completion",
                hostUtf8.data(), unsigned(proxy.port), errno);
            break;   // unexpected non-EINTR poll error → fall through to blocking completion (don't hard-fail prod)
        }
        if (fastFailed)
            return -1;
    } else if (connRc < 0) {
        WTFLogAlways("[Driftstack-EG-WK-1.8] connectToProxy: connect(%s:%u) failed errno=%d",
            hostUtf8.data(), unsigned(proxy.port), errno);
        ::close(fd);
        return -1;
    }
    ::fcntl(fd, F_SETFL, connFlags);   // restore blocking for the bounded SOCKS5 handshake recvs
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

// RFC 1928 §4 + §6 UDP ASSOCIATE (CMD=0x03). Sends request over the
// established TCP control channel (handshake required), reads BND.ADDR /
// BND.PORT from reply. The returned relay endpoint receives UDP datagrams
// wrapped per §7 (use wrapUdpDatagram / unwrapUdpDatagram).
//
// EG-WK-1.8 Phase C closure. The TCP control channel must stay open for
// the duration of UDP ASSOCIATE — close it and proxy terminates the relay.
Socks5Result DriftstackSocks5Client::udpAssociate(Socks5UdpRelayChannel& out)
{
    if (m_impl->udpAssociated) {
        out.relayHost = "(already-associated)"_s;
        return Socks5Result::Success;
    }
    if (!m_impl->handshakeOk) {
        auto h = performHandshake();
        if (h != Socks5Result::Success)
            return h;
    }
    int fd = m_impl->socketFd;

    // W1531: defensive timeout on the UDP_ASSOCIATE reply recv. A chained SOCKS5
    // proxy (per-session relay → upstream) accepts the TCP control connection but
    // may never reply to UDP_ASSOCIATE (no UDP forwarding through the chain) →
    // recvAll(hdr) below would block until the pageLoad timeout. On timeout recvAll
    // returns false → UdpAssociateFailed → the caller's graceful TCP-only fallback
    // (Slice16.7.a) proceeds instead of stalling. Cleared on EVERY return path so
    // the data/fallback phase keeps an un-timed (blocking) socket. A working proxy
    // replies in <1s, so 4s is safe. (Robustness hygiene; same defensive pass as
    // connectToProxy above — NOT a fix for A3-W448, retracted W450 as a probe
    // artifact.)
    struct timeval udpProbeTimeout { 4, 0 };
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &udpProbeTimeout, sizeof(udpProbeTimeout));
    auto clearUdpProbeTimeout = makeScopeExit([fd]() {
        struct timeval noTimeout { 0, 0 };
        ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &noTimeout, sizeof(noTimeout));
    });

    // [VER=5, CMD=UDP_ASSOC, RSV=0, ATYP=IPV4, 0.0.0.0, port=0]
    // RFC 1928 §4 — DST.ADDR/PORT in UDP_ASSOCIATE request are the LOCAL
    // address from which the client will send UDP datagrams. Setting to
    // 0.0.0.0:0 lets the proxy accept datagrams from any source (which
    // we then send to the BND endpoint).
    uint8_t req[10] = {
        Socks5::kVersion5,
        Socks5::kCmdUdpAssociate,
        Socks5::kReserved,
        Socks5::kAtypIpv4,
        0x00, 0x00, 0x00, 0x00,   // DST.ADDR = 0.0.0.0
        0x00, 0x00                 // DST.PORT = 0
    };
    if (!sendAll(fd, req, 10))
        return Socks5Result::UdpAssociateFailed;

    // [VER=5, REP, RSV=0, ATYP, BND.ADDR, BND.PORT_BE]
    uint8_t hdr[4];
    if (!recvAll(fd, hdr, 4))
        return Socks5Result::UdpAssociateFailed;
    if (hdr[0] != Socks5::kVersion5)
        return Socks5Result::ProtocolError;
    if (hdr[1] != Socks5::kReplySucceeded) {
        WTFLogAlways("[Driftstack-EG-WK-1.8] udpAssociate: SOCKS5 reply REP=0x%02x (non-success) — proxy refused UDP ASSOCIATE (may not support UDP relay)",
            unsigned(hdr[1]));
        return Socks5Result::UdpAssociateFailed;
    }
    uint8_t replyAtyp = hdr[3];
    String bndHost;
    if (replyAtyp == Socks5::kAtypIpv4) {
        uint8_t addr[4];
        if (!recvAll(fd, addr, 4)) return Socks5Result::UdpAssociateFailed;
        bndHost = makeString(unsigned(addr[0]), '.', unsigned(addr[1]), '.', unsigned(addr[2]), '.', unsigned(addr[3]));
    } else if (replyAtyp == Socks5::kAtypDomain) {
        uint8_t dlen;
        if (!recvAll(fd, &dlen, 1)) return Socks5Result::UdpAssociateFailed;
        Vector<uint8_t> domainBuf;
        domainBuf.grow(dlen);
        if (!recvAll(fd, domainBuf.mutableSpan().data(), dlen)) return Socks5Result::UdpAssociateFailed;
        bndHost = String::fromUTF8(domainBuf.span());
    } else if (replyAtyp == Socks5::kAtypIpv6) {
        uint8_t addr[16];
        if (!recvAll(fd, addr, 16)) return Socks5Result::UdpAssociateFailed;
        bndHost = "[ipv6]"_s;
    } else {
        return Socks5Result::ProtocolError;
    }
    uint8_t portBytes[2];
    if (!recvAll(fd, portBytes, 2)) return Socks5Result::UdpAssociateFailed;
    uint16_t bndPort = (static_cast<uint16_t>(portBytes[0]) << 8) | portBytes[1];

    out.relayHost = bndHost;
    out.relayPort = bndPort;
    m_impl->udpAssociated = true;

    WTFLogAlways("[Driftstack-EG-WK-1.8] udpAssociate: success — UDP relay endpoint %s:%u (TCP control channel must stay open). Send §7-wrapped datagrams here.",
        bndHost.utf8().data(), unsigned(bndPort));
    return Socks5Result::Success;
}

RetainPtr<NSInputStream> DriftstackSocks5Client::tcpReadStream() const
{
    return m_impl->readStream;
}

// Wave 29-396 sub-slice 1.7.2.a: raw socket FD accessor.
int DriftstackSocks5Client::socketFileDescriptor() const
{
    return m_impl->tcpConnected ? m_impl->socketFd : -1;
}

RetainPtr<NSOutputStream> DriftstackSocks5Client::tcpWriteStream() const
{
    return m_impl->writeStream;
}

// Wave 29-397 Slice 16.4.b.3: §7 framing now delegated to
// DriftstackSocks5Framing (pure-byte API, no Cocoa types). The methods
// below are thin Cocoa adaptors that convert NSData ↔ Vector + Socks5-
// Endpoint ↔ Socks5Framing::Endpoint. The shared framing module is
// designed to be re-compilable by the (future) DriftstackQuicInterpose
// dylib without pulling in WebKit framework dependencies.
RetainPtr<NSData> DriftstackSocks5Client::wrapUdpDatagram(const Socks5Endpoint& destination, NSData* payload)
{
    Socks5Framing::Endpoint framingDest { destination.host, destination.port };
    Vector<uint8_t> frameBytes;
    if (!Socks5Framing::wrap(framingDest, WTF::span(payload), frameBytes)) {
        WTFLogAlways("[Driftstack-EG-WK-1.8] wrapUdpDatagram failed (Socks5Framing::wrap returned false)");
        return nullptr;
    }
    return [NSData dataWithBytes:frameBytes.span().data() length:frameBytes.size()];
}

RetainPtr<NSData> DriftstackSocks5Client::unwrapUdpDatagram(NSData* frame, Socks5Endpoint& source)
{
    if (!frame || ![frame length])
        return nullptr;
    Socks5Framing::Endpoint framingSource;
    Vector<uint8_t> payloadBytes;
    if (!Socks5Framing::unwrap(WTF::span(frame), framingSource, payloadBytes))
        return nullptr;
    source.host = framingSource.host;
    source.port = framingSource.port;
    return [NSData dataWithBytes:payloadBytes.span().data() length:payloadBytes.size()];
}

} // namespace WebKit

#endif // PLATFORM(DRIFTSTACK)
