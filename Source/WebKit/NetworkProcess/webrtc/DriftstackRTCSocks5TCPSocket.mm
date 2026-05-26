/*
 * DriftstackRTCSocks5TCPSocket.mm — Phase 1 implementation (plain TCP, no TLS).
 *
 * Wave 29-499.275 — follow-up to .274 hard-block. Replaces nw_connection_t
 * with a BSD socket established via SOCKS5 CONNECT (DriftstackSocks5Client).
 * Reads through dispatch_source DISPATCH_SOURCE_TYPE_READ on the fd; writes
 * via write(2) syscall. STUN/TURN framing handled per Apple's existing
 * NetworkRTCTCPSocketCocoa logic (length-prefix + STUN padding).
 */

#import "config.h"
#import "DriftstackRTCSocks5TCPSocket.h"

#if PLATFORM(DRIFTSTACK) && USE(LIBWEBRTC) && PLATFORM(COCOA)

#import "../cocoa/DriftstackSocks5Client.h"
#import "../cocoa/DriftstackTLS13Client.h"
#import "LibWebRTCNetworkMessages.h"
#import <WebCore/STUNMessageParsing.h>
#import <unistd.h>
#import <sys/socket.h>
#import <wtf/BlockPtr.h>
#import <wtf/Locker.h>
#import <wtf/TZoneMallocInlines.h>

WTF_IGNORE_WARNINGS_IN_THIRD_PARTY_CODE_BEGIN
#import <webrtc/api/packet_socket_factory.h>
#import <webrtc/rtc_base/time_utils.h>
WTF_IGNORE_WARNINGS_IN_THIRD_PARTY_CODE_END

WTF_ALLOW_UNSAFE_BUFFER_USAGE_BEGIN

namespace WebKit {

WTF_MAKE_TZONE_ALLOCATED_IMPL(DriftstackRTCSocks5TCPSocket);

static dispatch_queue_t socks5TcpReadQueue()
{
    static dispatch_queue_t queue;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        queue = dispatch_queue_create("dev.driftstack.rtc-socks5-tcp-read",
            DISPATCH_QUEUE_CONCURRENT);
    });
    return queue;
}

std::unique_ptr<NetworkRTCProvider::Socket> DriftstackRTCSocks5TCPSocket::create(
    WebCore::LibWebRTCSocketIdentifier identifier,
    NetworkRTCProvider& rtcProvider,
    const webrtc::SocketAddress& remoteAddress,
    int options,
    Ref<IPC::Connection>&& connection)
{
    // Wave 29-499.341 — construct only; the SOCKS5 CONNECT (+TLS) runs async via
    // beginAsyncConnect() so it doesn't serialize on the RTC network thread.
    return std::unique_ptr<DriftstackRTCSocks5TCPSocket>(
        new DriftstackRTCSocks5TCPSocket(identifier, rtcProvider, remoteAddress, options, WTF::move(connection)));
}

// Background-thread connect: builds a SOCKS5 client + (optionally) the TURN-TLS
// client locally, touching NO socket members. Returns the connected transport via
// out-params. Safe to run after the owning socket may have been destroyed.
static bool connectSocks5TransportStatic(const std::string& host, uint16_t port, bool isTLS,
    std::unique_ptr<DriftstackSocks5Client>& outClient, std::unique_ptr<DriftstackTLS13Client>& outTls)
{
    const char* proxyEnv = getenv("DRIFTSTACK_SOCKS5_PROXY");
    if (!proxyEnv || !proxyEnv[0])
        return false;
    String proxyEnvStr = String::fromUTF8(proxyEnv);
    size_t colon = proxyEnvStr.find(':');
    if (colon == notFound)
        return false;
    Socks5Endpoint proxy;
    proxy.host = proxyEnvStr.left(colon);
    int proxyPort = 0;
    {
        auto portStr = proxyEnvStr.substring(colon + 1);
        for (unsigned i = 0; i < portStr.length(); ++i) {
            UChar c = portStr[i];
            if (c < '0' || c > '9') { proxyPort = 0; break; }
            proxyPort = proxyPort * 10 + (c - '0');
        }
    }
    if (proxyPort == 0)
        return false;
    proxy.port = static_cast<uint16_t>(proxyPort);

    Socks5Credentials creds;
    if (const char* u = getenv("DRIFTSTACK_SOCKS5_USER")) {
        if (const char* p = getenv("DRIFTSTACK_SOCKS5_PASS")) {
            if (u[0]) { creds.username = String::fromUTF8(u); creds.password = String::fromUTF8(p); }
        }
    }

    auto client = std::make_unique<DriftstackSocks5Client>(proxy, creds);
    if (client->performHandshake() != Socks5Result::Success)
        return false;
    Socks5Endpoint dest;
    dest.host = String::fromUTF8(host.c_str());
    dest.port = port;
    Socks5Endpoint bnd;
    if (client->tcpConnect(dest, bnd) != Socks5Result::Success)
        return false;

    int fd = client->socketFileDescriptor();
    if (fd < 0)
        return false;

    if (isTLS) {
        auto tls = std::make_unique<DriftstackTLS13Client>();
        String sni = String::fromUTF8(host.c_str());
        if (!tls->connect(fd, sni)) {
            WTFLogAlways("[Driftstack-EG-WK-1.8/Wave29-499.279] TURN-TLS handshake FAILED for %s:%u — %s",
                host.c_str(), port, tls->errorMessage().utf8().data());
            return false;
        }
        WTFLogAlways("[Driftstack-EG-WK-1.8/Wave29-499.279] TURN-TLS handshake COMPLETE for %s:%u (ALPN=%s) — iPhone-byte-exact ClientHello",
            host.c_str(), port, tls->selectedALPN().utf8().data());
        outTls = WTF::move(tls);
    }
    outClient = WTF::move(client);
    return true;
}

void DriftstackRTCSocks5TCPSocket::beginAsyncConnect()
{
    std::string host = m_remoteAddress.hostname();
    if (host.empty())
        host = m_remoteAddress.ipaddr().ToString();
    uint16_t port = m_remoteAddress.port();
    bool isTLS = m_isTLS;
    auto identifier = m_identifier;
    Ref<NetworkRTCProvider> provider = m_rtcProvider.get();

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), makeBlockPtr([provider, identifier, host, port, isTLS]() mutable {
        std::unique_ptr<DriftstackSocks5Client> client;
        std::unique_ptr<DriftstackTLS13Client> tls;
        bool ok = connectSocks5TransportStatic(host, port, isTLS, client, tls);
        if (!ok)
            WTFLogAlways("[Driftstack-EG-WK-1.8/Wave29-499.341] async SOCKS5 CONNECT to %s:%u FAILED (isTLS=%d) — will signal closed", host.c_str(), port, isTLS);
        // Hand the connected transport back on the RTC network thread, where the
        // socket lives and is torn down — so the lookup + adopt is race-free and the
        // background thread never touches the (possibly-freed) socket object.
        provider->callOnRTCNetworkThread([provider, identifier, ok, client = WTF::move(client), tls = WTF::move(tls)]() mutable {
            provider->finishDriftstackTCPConnect(identifier, ok, WTF::move(client), WTF::move(tls));
        });
    }).get());
}

void DriftstackRTCSocks5TCPSocket::adoptConnectedTransport(
    std::unique_ptr<DriftstackSocks5Client>&& client, std::unique_ptr<DriftstackTLS13Client>&& tls)
{
    int fd;
    {
        Locker locker { m_lock };
        if (m_closed)
            return; // socket closed during connect — drop the transport (fd closed by client dtor)
        m_socks5Client = WTF::move(client);
        m_tls = WTF::move(tls);
        m_fd = m_socks5Client->socketFileDescriptor();
        fd = m_fd;
    }
    startReadLoop();
    m_connection->send(Messages::LibWebRTCNetwork::SignalConnect(m_identifier), 0);
    WTFLogAlways("[Driftstack-EG-WK-1.8/Wave29-499.341] DriftstackRTCSocks5TCPSocket ESTABLISHED (async) to %s:%u (fd=%d, isSTUN=%d, isTLS=%d)",
        m_remoteAddress.hostname().c_str(), m_remoteAddress.port(), fd, m_isSTUN ? 1 : 0, m_isTLS ? 1 : 0);
}

DriftstackRTCSocks5TCPSocket::DriftstackRTCSocks5TCPSocket(
    WebCore::LibWebRTCSocketIdentifier identifier,
    NetworkRTCProvider& rtcProvider,
    const webrtc::SocketAddress& remoteAddress,
    int options,
    Ref<IPC::Connection>&& connection)
    : m_identifier(identifier)
    , m_rtcProvider(rtcProvider)
    , m_connection(WTF::move(connection))
    , m_remoteAddress(remoteAddress)
    , m_options(options)
    , m_isSTUN(options & webrtc::PacketSocketFactory::OPT_STUN)
    , m_isTLS(options & webrtc::PacketSocketFactory::OPT_TLS)
{
}

DriftstackRTCSocks5TCPSocket::~DriftstackRTCSocks5TCPSocket()
{
    close();
}

bool DriftstackRTCSocks5TCPSocket::connectViaSocks5(const std::string& host, uint16_t port)
{
    const char* proxyEnv = getenv("DRIFTSTACK_SOCKS5_PROXY");
    if (!proxyEnv || !proxyEnv[0])
        return false;

    String proxyEnvStr = String::fromUTF8(proxyEnv);
    size_t colon = proxyEnvStr.find(':');
    if (colon == notFound)
        return false;
    String proxyHostStr = proxyEnvStr.left(colon);
    int proxyPort = 0;
    {
        auto portStr = proxyEnvStr.substring(colon + 1);
        for (unsigned i = 0; i < portStr.length(); ++i) {
            UChar c = portStr[i];
            if (c < '0' || c > '9') { proxyPort = 0; break; }
            proxyPort = proxyPort * 10 + (c - '0');
        }
    }
    if (proxyPort == 0)
        return false;

    Socks5Endpoint proxy;
    proxy.host = proxyHostStr;
    proxy.port = static_cast<uint16_t>(proxyPort);

    Socks5Credentials creds;
    const char* userEnv = getenv("DRIFTSTACK_SOCKS5_USER");
    const char* passEnv = getenv("DRIFTSTACK_SOCKS5_PASS");
    if (userEnv && userEnv[0] && passEnv) {
        creds.username = String::fromUTF8(userEnv);
        creds.password = String::fromUTF8(passEnv);
    }

    m_socks5Client = std::make_unique<DriftstackSocks5Client>(proxy, creds);
    if (m_socks5Client->performHandshake() != Socks5Result::Success) {
        m_socks5Client.reset();
        return false;
    }

    Socks5Endpoint dest;
    dest.host = String::fromUTF8(host.c_str());
    dest.port = port;
    Socks5Endpoint bnd;
    if (m_socks5Client->tcpConnect(dest, bnd) != Socks5Result::Success) {
        m_socks5Client.reset();
        return false;
    }

    int fd;
    {
        Locker locker { m_lock };
        m_fd = m_socks5Client->socketFileDescriptor();
        fd = m_fd;
    }
    return fd >= 0;
}

void DriftstackRTCSocks5TCPSocket::startReadLoop()
{
    int fd;
    {
        Locker locker { m_lock };
        if (m_fd < 0 || m_closed)
            return;
        fd = m_fd;
    }

    auto src = dispatch_source_create(DISPATCH_SOURCE_TYPE_READ, fd, 0, socks5TcpReadQueue());
    {
        Locker locker { m_lock };
        m_readSource = src;
    }

    dispatch_source_set_event_handler(src, ^{
        int fd;
        {
            Locker l { m_lock };
            if (m_closed) return;
            fd = m_fd;
        }
        if (fd < 0) return;
        uint8_t buf[4096];
        ssize_t n;
        // Wave 29-499.279 — TLS-wrapped path reads through DriftstackTLS13Client
        // which handles record framing + decryption. Plain TCP reads raw fd.
        if (m_tls) {
            n = m_tls->read(buf, sizeof(buf));
        } else {
            n = read(fd, buf, sizeof(buf));
        }
        if (n > 0)
            onIncomingData(std::span<const uint8_t> { buf, static_cast<size_t>(n) });
        else if (n == 0 || (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK))
            close();
    });

    dispatch_source_set_cancel_handler(src, ^{
        // Source cancellation cleanup is done in close()
    });

    dispatch_resume(src);
}

void DriftstackRTCSocks5TCPSocket::onIncomingData(std::span<const uint8_t> chunk)
{
    m_rxBuffer.append(chunk);

    // Wave 29-499.339 — log raw inbound on the TCP tunnel + each extracted message
    // type, so we can see whether TURN-over-TCP Allocate responses actually arrive
    // and frame correctly (the UDP path's "no response" turned out to be a logging
    // gap; verify the TCP path the same way before concluding anything).
    unsigned extractedCount = 0;
    size_t rxBefore = m_rxBuffer.size();

    // STUN/TURN framing: extract messages via Apple's existing helper.
    Vector<uint8_t> moved = std::exchange(m_rxBuffer, Vector<uint8_t>());
    auto remaining = WebCore::WebRTC::extractMessages(WTF::move(moved),
        m_isSTUN ? WebCore::WebRTC::MessageType::STUN : WebCore::WebRTC::MessageType::Data,
        [&](auto data) {
            uint16_t mt = data.size() >= 2 ? ((static_cast<uint16_t>(data[0]) << 8) | data[1]) : 0;
            ++extractedCount;
            WTFLogAlways("[Driftstack-EG-WK-1.8/Wave29-499.339] TCP recv: extracted TURN msgType=0x%04x len=%zu ← %s:%u",
                mt, data.size(), m_remoteAddress.hostname().c_str(), m_remoteAddress.port());
            m_connection->send(Messages::LibWebRTCNetwork::SignalReadPacket {
                m_identifier,
                data,
                WebKit::RTCNetwork::IPAddress(m_remoteAddress.ipaddr()),  // explicit qualifier
                m_remoteAddress.port(),
                webrtc::TimeMicros(),
                WebKit::WebRTCNetwork::EcnMarking::kNotEct,
            }, 0);
        });
    m_rxBuffer = WTF::move(remaining);
    WTFLogAlways("[Driftstack-EG-WK-1.8/Wave29-499.339] TCP onIncomingData: %zu raw bytes (rxBuf %zu→%zu), extracted %u STUN/TURN msg(s) from %s:%u",
        chunk.size(), rxBefore, m_rxBuffer.size(), extractedCount,
        m_remoteAddress.hostname().c_str(), m_remoteAddress.port());
}

void DriftstackRTCSocks5TCPSocket::close()
{
    dispatch_source_t src;
    {
        Locker locker { m_lock };
        if (m_closed) return;
        m_closed = true;
        src = m_readSource;
        m_fd = -1;
        m_readSource = nullptr;
    }
    if (src)
        dispatch_source_cancel(src);
    // fd is owned by m_socks5Client; its destructor closes it.
    m_socks5Client.reset();

    Ref { m_rtcProvider.get() }->takeSocket(m_identifier);
}

void DriftstackRTCSocks5TCPSocket::setOption(int /*option*/, int /*value*/)
{
    // DSCP / traffic-class not enforceable on raw BSD socket from userspace.
    // No-op for now; iPhone Safari rarely sets DSCP and TURN doesn't depend on it.
}

void DriftstackRTCSocks5TCPSocket::sendTo(std::span<const uint8_t> data,
    const webrtc::SocketAddress& /*addr*/,
    const webrtc::AsyncSocketPacketOptions& options)
{
    // Apply STUN padding or length-prefix framing (matches Apple impl).
    Vector<uint8_t> buffer;
    if (m_isSTUN) {
        auto messageLengths = WebCore::WebRTC::getSTUNOrTURNMessageLengths(data);
        if (!messageLengths)
            return;
        buffer.reserveInitialCapacity(messageLengths->messageLengthWithPadding);
        buffer.append(data);
        for (size_t i = 0; i < messageLengths->messageLengthWithPadding - data.size(); ++i)
            buffer.append(static_cast<uint8_t>(0));
    } else {
        if (data.size() >= std::numeric_limits<uint16_t>::max())
            return;
        buffer.reserveInitialCapacity(data.size() + 2);
        buffer.appendList({ static_cast<uint8_t>((data.size() >> 8) & 0xFF),
                            static_cast<uint8_t>(data.size() & 0xFF) });
        buffer.append(data);
    }

    int fd;
    {
        Locker locker { m_lock };
        if (m_closed) return;
        fd = m_fd;
    }
    if (fd < 0) return;

    // Wave 29-499.339 — log outgoing TURN/STUN message type over the TCP tunnel
    // (TURN TCP/TLS path; mirrors the UDP §7 catch-all that proved UDP works).
    if (data.size() >= 2) {
        uint16_t mt = (static_cast<uint16_t>(data[0]) << 8) | data[1];
        WTFLogAlways("[Driftstack-EG-WK-1.8/Wave29-499.339] TCP sendTo: TURN msgType=0x%04x payload=%zu framed=%zu (isSTUN=%d isTLS=%d) → %s:%u",
            mt, data.size(), buffer.size(), m_isSTUN, m_tls ? 1 : 0,
            m_remoteAddress.hostname().c_str(), m_remoteAddress.port());
    }

    // Wave 29-499.279 — if TLS-wrapped (TURN-TLS), route through
    // DriftstackTLS13Client::write which encrypts + frames per TLS 1.3.
    if (m_tls) {
        int wrote = m_tls->write(buffer.span().data(), buffer.size());
        if (wrote < 0) {
            close();
            return;
        }
    } else {
        ssize_t total = 0;
        while (total < static_cast<ssize_t>(buffer.size())) {
            ssize_t n = write(fd, buffer.span().data() + total, buffer.size() - total);
            if (n < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
                close();
                return;
            }
            total += n;
        }
    }

    m_connection->send(Messages::LibWebRTCNetwork::SignalSentPacket {
        m_identifier, options.packet_id, webrtc::TimeMillis()
    }, 0);
}

} // namespace WebKit

WTF_ALLOW_UNSAFE_BUFFER_USAGE_END

#endif // PLATFORM(DRIFTSTACK) && USE(LIBWEBRTC) && PLATFORM(COCOA)
