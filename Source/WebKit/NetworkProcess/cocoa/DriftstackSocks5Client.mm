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
#import <span>
#import <wtf/Assertions.h>
#import <wtf/cocoa/SpanCocoa.h>
#import <wtf/text/CString.h>
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
    // W2751 (FIX the W2744/W2747 first-page regression): connectToProxy ALWAYS targets the harness's LOCAL
    // relay (127.0.0.1:<listenerPort>), never a remote host — so a plain BLOCKING ::connect() is instant (or
    // ECONNREFUSED-instant if the relay isn't up yet) and CANNOT incur the ~75s remote-dead-exit hang W2744
    // worried about (that hang was MISATTRIBUTED to this connect; the real first-load amplifier is the retry
    // stack [W2750] + Spotlight CPU). W2744's non-blocking-connect + poll(POLLOUT) was unnecessary here AND
    // BROKEN in the sandboxed WebKit Network process: poll() returns EPERM (errno 1) on the connecting socket,
    // so W2747's "fall back to blocking" returned the fd with the connect still IN-FLIGHT → a cold first
    // connect's blocking SOCKS5 greeting raced the unfinished connect → "SOCKS5 handshake failed" on the FIRST
    // page (warm connects then worked — the founder's exact report). A plain blocking connect to localhost has
    // no poll, no race, no EPERM, no hang; the SO_*TIMEO set above still bound the subsequent handshake recvs.
    if (::connect(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
        WTFLogAlways("[Driftstack-EG-WK-1.8/W2751] connectToProxy: connect(%s:%u) failed errno=%d (local relay — refused = relay not up yet → caller retries)",
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

// W2900 (#46) — classify a destination host string. Most dests are HOSTNAMES
// (ATYP=0x03 domain, proxy-side resolution, no local DNS leak). But the WebKit
// loader can also hand us an IP LITERAL (e.g. a page that references a resource
// by raw IP — browserleaks' IPv6 connectivity probes do exactly this with
// [2604:a880:…] literals). Sending a literal as ATYP=0x03 makes the proxy try to
// resolve the dotted/colon string as a DNS name → REP=0x03. Send the matching
// ATYP for literals so a real IPv4-literal dest connects, and so we can tell a
// hostname (retry-eligible) apart from a literal (genuinely unreachable on an
// IPv4-only proxy, no retry — preserves W2868 fail-fast).
WTF_ALLOW_UNSAFE_BUFFER_USAGE_BEGIN
// W2900 (#48) — WebKit's URL::host() returns IPv6 literals WITH surrounding
// brackets (e.g. "[2606:...]"), which inet_pton(AF_INET6) rejects. Strip a single
// leading '[' + trailing ']' so a bracketed IPv6 literal is recognized as an
// IPv6Literal (→ ATYP=0x04 with the correct 16-byte address), not misclassified as
// a hostname (ATYP=0x03 domain, retry-eligible). No-op for a hostname or a
// bracket-less literal.
static CString stripIpv6Brackets(const CString& host)
{
    if (host.length() >= 2 && host.data()[0] == '[' && host.data()[host.length() - 1] == ']')
        return CString(host.data() + 1, host.length() - 2);
    return host;
}
static DestAddrKind classifyDest(const CString& hostUtf8)
{
    struct in_addr a4 { };
    if (inet_pton(AF_INET, hostUtf8.data(), &a4) == 1)
        return DestAddrKind::IPv4Literal;
    struct in6_addr a6 { };
    if (inet_pton(AF_INET6, stripIpv6Brackets(hostUtf8).data(), &a6) == 1)
        return DestAddrKind::IPv6Literal;
    return DestAddrKind::Hostname;
}

// W2900 (#46) — send one RFC 1928 §4 CONNECT request on `fd` with the ATYP that
// matches the destination kind, then read the §6 reply header [VER, REP, RSV,
// ATYP] and drain the BND.ADDR/BND.PORT. On success fills `outBndHost`/`outBndPort`.
// Returns the reply REP byte via `outRep` so the caller can distinguish the
// IPv4-fallback-eligible 0x03/0x04 from a hard protocol/transport failure
// (signalled by a false return). Pure transport helper — no retry policy here.
bool DriftstackSocks5Client::sendConnectAndReadReply(int fd, const Socks5Endpoint& destination, DestAddrKind kind,
    uint8_t& outRep, String& outBndHost, uint16_t& outBndPort)
{
    auto destUtf8 = destination.host.utf8();
    Vector<uint8_t> req;
    req.append(Socks5::kVersion5);
    req.append(Socks5::kCmdConnect);
    req.append(Socks5::kReserved);
    if (kind == DestAddrKind::IPv4Literal) {
        // [ATYP=0x01, 4-byte IPv4 in network order]
        req.append(Socks5::kAtypIpv4);
        struct in_addr a4 { };
        inet_pton(AF_INET, destUtf8.data(), &a4);
        uint32_t net = a4.s_addr;  // already network byte order
        req.append(std::span<const uint8_t> { reinterpret_cast<const uint8_t*>(&net), 4 });
    } else if (kind == DestAddrKind::IPv6Literal) {
        // [ATYP=0x04, 16-byte IPv6] — W2900 (#48) strip brackets so inet_pton parses
        // the address (URL::host() gives "[2606:...]"); without this a6 stays :: (all-zero).
        req.append(Socks5::kAtypIpv6);
        struct in6_addr a6 { };
        inet_pton(AF_INET6, stripIpv6Brackets(destUtf8).data(), &a6);
        req.append(std::span<const uint8_t> { a6.s6_addr, 16 });
    } else {
        // [ATYP=0x03 DOMAIN, DLEN, DOMAIN...] — default, proxy-side DNS, no local leak.
        req.append(Socks5::kAtypDomain);
        req.append(static_cast<uint8_t>(destUtf8.length()));
        req.append(destUtf8.span());
    }
    uint16_t portBE = htons(destination.port);
    req.append(static_cast<uint8_t>(portBE & 0xFF));
    req.append(static_cast<uint8_t>((portBE >> 8) & 0xFF));
    if (!sendAll(fd, req.span().data(), req.size()))
        return false;

    // [VER=5, REP, RSV=0, ATYP, BND.ADDR..., BND.PORT_BE]
    uint8_t hdr[4];
    if (!recvAll(fd, hdr, 4))
        return false;
    if (hdr[0] != Socks5::kVersion5)
        return false;
    outRep = hdr[1];
    if (hdr[1] != Socks5::kReplySucceeded)
        return true;  // a valid reply frame, but non-success — caller inspects outRep

    uint8_t replyAtyp = hdr[3];
    if (replyAtyp == Socks5::kAtypIpv4) {
        uint8_t addr[4];
        if (!recvAll(fd, addr, 4)) return false;
        outBndHost = makeString(unsigned(addr[0]), '.', unsigned(addr[1]), '.', unsigned(addr[2]), '.', unsigned(addr[3]));
    } else if (replyAtyp == Socks5::kAtypDomain) {
        uint8_t dlen;
        if (!recvAll(fd, &dlen, 1)) return false;
        Vector<uint8_t> domainBuf;
        domainBuf.grow(dlen);
        if (!recvAll(fd, domainBuf.mutableSpan().data(), dlen)) return false;
        outBndHost = String::fromUTF8(domainBuf.span());
    } else if (replyAtyp == Socks5::kAtypIpv6) {
        uint8_t addr[16];
        if (!recvAll(fd, addr, 16)) return false;
        outBndHost = "[ipv6]"_s;
    } else
        return false;
    uint8_t portBytes[2];
    if (!recvAll(fd, portBytes, 2)) return false;
    outBndPort = (static_cast<uint16_t>(portBytes[0]) << 8) | portBytes[1];
    return true;
}
WTF_ALLOW_UNSAFE_BUFFER_USAGE_END

// RFC 1928 §4 + §6: TCP CONNECT. Hostname dests use ATYP=0x03 (DOMAINNAME) —
// proxy-side resolution, never a pre-resolved address (no local DNS leak), the
// EG-WK-1.9 Slice 1 default. IP-literal dests use the matching ATYP (0x01/0x04).
//
// W2900 (#46 — westernunion + heavy dual-stack sites): some SOCKS5 proxies
// (the founder's nodemaven gate is IPv4-only-egress) resolve a dual-stack
// hostname to its AAAA record on their side and then can't route it → REP=0x03
// (network unreachable). That selection is NON-DETERMINISTIC per resolution
// (verified: 80/80 ATYP=domain CONNECTs to westernunion.com succeed on IPv4,
// but the founder's live load hit a transient AAAA pick → REP=0x03). W2868 made
// 0x03/0x04 fail FAST with NO retry to stop the 7× nav-budget-burning retry
// storm — correct for an IP-literal dest, but it also permanently dropped a
// hostname that a single fresh re-resolution would have routed over IPv4. So:
// for a HOSTNAME dest that REP=0x03/0x04s, tear down the proxy socket and retry
// the CONNECT exactly ONCE on a fresh connection+handshake. The proxy re-resolves
// (independent A/AAAA pick), so the retry lands on a reachable IPv4 with
// overwhelming probability — still ATYP=0x03 (no local DNS leak), still bounded
// (one extra round-trip, not the 7× loader storm W2868 killed). An IP-LITERAL
// dest is NOT retried (an IPv6 literal on an IPv4-only proxy is genuinely
// unreachable, exactly as it is on a real IPv4-only iPhone — preserves W2868).
Socks5Result DriftstackSocks5Client::tcpConnect(const Socks5Endpoint& destination, Socks5Endpoint& out)
{
    if (!m_impl->handshakeOk) {
        auto h = performHandshake();
        if (h != Socks5Result::Success)
            return h;
    }

    auto destUtf8 = destination.host.utf8();
    if (destUtf8.length() > 255)
        return Socks5Result::DomainTooLong;
    DestAddrKind kind = classifyDest(destUtf8);

    const int kMaxConnectAttempts = (kind == DestAddrKind::Hostname) ? 2 : 1;
    for (int attempt = 1; attempt <= kMaxConnectAttempts; ++attempt) {
        int fd = m_impl->socketFd;
        uint8_t rep = Socks5::kReplyGeneralFailure;
        String bndHost;
        uint16_t bndPort = 0;
        bool replyOk = sendConnectAndReadReply(fd, destination, kind, rep, bndHost, bndPort);

        if (replyOk && rep == Socks5::kReplySucceeded) {
            out.host = bndHost;
            out.port = bndPort;
            m_impl->tcpConnected = true;
            WTFLogAlways("[Driftstack-EG-WK-1.9] tcpConnect: success — dest=%s:%u via proxy, BND=%s:%u, ATYP=0x%02x sent%s (attempt %d/%d, no local DNS leak)",
                destUtf8.data(), unsigned(destination.port),
                bndHost.utf8().data(), unsigned(bndPort),
                unsigned(kind == DestAddrKind::IPv4Literal ? Socks5::kAtypIpv4 : kind == DestAddrKind::IPv6Literal ? Socks5::kAtypIpv6 : Socks5::kAtypDomain),
                kind == DestAddrKind::Hostname ? " (domain)" : " (literal)",
                attempt, kMaxConnectAttempts);
            return Socks5Result::Success;
        }

        if (!replyOk) {
            // transport/protocol failure reading the reply — not a routing REP.
            WTFLogAlways("[Driftstack-EG-WK-1.9] tcpConnect: send/recv failure for %s:%u (attempt %d/%d)",
                destUtf8.data(), unsigned(destination.port), attempt, kMaxConnectAttempts);
            return Socks5Result::ConnectFailed;
        }

        // Valid SOCKS5 reply, non-success REP.
        WTFLogAlways("[Driftstack-EG-WK-1.9] tcpConnect: SOCKS5 reply REP=0x%02x (non-success) for %s:%u (attempt %d/%d)",
            unsigned(rep), destUtf8.data(), unsigned(destination.port), attempt, kMaxConnectAttempts);

        bool unreachable = (rep == Socks5::kReplyNetworkUnreachable || rep == Socks5::kReplyHostUnreachable);
        bool canRetry = unreachable && kind == DestAddrKind::Hostname && attempt < kMaxConnectAttempts;
        if (canRetry) {
            // W2900: the proxy's per-resolution AAAA-vs-A pick failed this time. Drop the proxy
            // socket and re-handshake so the next CONNECT triggers a fresh proxy-side resolution
            // (overwhelmingly IPv4 on an IPv4-only-egress proxy). Still ATYP=0x03 — no local DNS leak.
            WTFLogAlways("[Driftstack-EG-WK-PathB-v2/W2900] hostname %s REP=0x%02x via proxy — re-resolving over a FRESH proxy connection (one IPv4-forcing retry, ATYP=0x03, no leak)",
                destUtf8.data(), unsigned(rep));
            if (m_impl->socketFd >= 0) {
                ::close(m_impl->socketFd);
                m_impl->socketFd = -1;
            }
            m_impl->handshakeOk = false;
            auto h = performHandshake();
            if (h != Socks5Result::Success) {
                WTFLogAlways("[Driftstack-EG-WK-PathB-v2/W2900] re-handshake to proxy failed (%d) on IPv4-forcing retry for %s",
                    static_cast<int>(h), destUtf8.data());
                return h;
            }
            continue;
        }

        // No retry: an IP-literal dest, or the hostname retry already failed. Surface the
        // distinct fail-fast result so the loader does NOT retry-storm (W2868).
        if (unreachable) {
            WTFLogAlways("[Driftstack-EG-WK-PathB-v2/W2868] SOCKS5 dest %s UNREACHABLE via proxy (network/host-unreachable, %s) — fail fast, NO further retry",
                destUtf8.data(), kind == DestAddrKind::Hostname ? "hostname after IPv4-forcing retry" : "IP literal");
            return Socks5Result::DestinationUnreachable;
        }
        return Socks5Result::ConnectFailed;
    }
    return Socks5Result::ConnectFailed;
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
