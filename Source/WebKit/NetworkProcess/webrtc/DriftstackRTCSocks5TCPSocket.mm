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
#import "LibWebRTCNetworkMessages.h"
#import <WebCore/STUNMessageParsing.h>
#import <unistd.h>
#import <sys/socket.h>
#import <wtf/Locker.h>
#import <wtf/TZoneMallocInlines.h>

WTF_IGNORE_WARNINGS_IN_THIRD_PARTY_CODE_BEGIN
#import <webrtc/api/packet_socket_factory.h>
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
    auto socket = std::unique_ptr<DriftstackRTCSocks5TCPSocket>(
        new DriftstackRTCSocks5TCPSocket(identifier, rtcProvider, remoteAddress, options, WTF::move(connection)));

    auto host = remoteAddress.hostname();
    if (host.empty())
        host = remoteAddress.ipaddr().ToString();

    if (!socket->connectViaSocks5(host, remoteAddress.port())) {
        WTFLogAlways("[Driftstack-EG-WK-1.8/Wave29-499.275] SOCKS5 CONNECT to %s:%u FAILED — signaling closed",
            host.c_str(), remoteAddress.port());
        return nullptr;
    }

    if (socket->m_isTLS) {
        // Phase 2 TODO — wrap fd with DriftstackTLS13Client for
        // iPhone-byte-exact ClientHello. Until then, refuse TURN-TLS at
        // socket level (caller signalSocketIsClosed).
        WTFLogAlways("[Driftstack-EG-WK-1.8/Wave29-499.275] TURN-TLS requested but Phase 2 wrap not yet wired — refusing socket (id=%" PRIu64 ")",
            identifier.toUInt64());
        return nullptr;
    }

    socket->startReadLoop();

    // Signal libwebrtc that the connection is ready (matches what
    // NetworkRTCTCPSocketCocoa's nw_connection_state_ready handler does).
    socket->m_connection->send(Messages::LibWebRTCNetwork::SignalConnect(identifier), 0);

    WTFLogAlways("[Driftstack-EG-WK-1.8/Wave29-499.275] DriftstackRTCSocks5TCPSocket ESTABLISHED to %s:%u (fd=%d, isSTUN=%d, isTLS=%d)",
        host.c_str(), remoteAddress.port(), socket->m_fd, socket->m_isSTUN ? 1 : 0, socket->m_isTLS ? 1 : 0);

    return socket;
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

    {
        Locker locker { m_lock };
        m_fd = m_socks5Client->socketFileDescriptor();
    }
    return m_fd >= 0;
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
        ssize_t n = read(fd, buf, sizeof(buf));
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

    // STUN/TURN framing: extract messages via Apple's existing helper.
    Vector<uint8_t> moved = std::exchange(m_rxBuffer, Vector<uint8_t>());
    auto remaining = WebRTC::extractMessages(WTF::move(moved),
        m_isSTUN ? WebRTC::MessageType::STUN : WebRTC::MessageType::Data,
        [&](auto data) {
            m_connection->send(Messages::LibWebRTCNetwork::SignalReadPacket {
                m_identifier,
                data,
                WebKit::RTCNetwork::IPAddress(m_remoteAddress.ipaddr()),
                m_remoteAddress.port(),
                webrtc::TimeMicros(),
                WebRTCNetwork::EcnMarking::kNotEct,
            }, 0);
        });
    m_rxBuffer = WTF::move(remaining);
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
        auto messageLengths = WebRTC::getSTUNOrTURNMessageLengths(data);
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

    m_connection->send(Messages::LibWebRTCNetwork::SignalSentPacket {
        m_identifier, options.packet_id, webrtc::TimeMillis()
    }, 0);
}

} // namespace WebKit

WTF_ALLOW_UNSAFE_BUFFER_USAGE_END

#endif // PLATFORM(DRIFTSTACK) && USE(LIBWEBRTC) && PLATFORM(COCOA)
