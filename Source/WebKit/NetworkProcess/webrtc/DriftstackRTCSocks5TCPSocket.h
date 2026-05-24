/*
 * DriftstackRTCSocks5TCPSocket.h — SOCKS5 CONNECT routed TCP socket for
 * libwebrtc TURN TCP / TURN TLS transports.
 *
 * Track: EG-WK-1.8 Slice 3 / Wave 29-499.275 (follow-up to .274 hard-block).
 *
 * Purpose: Apple's NetworkRTCTCPSocketCocoa opens nw_connection_create
 * directly, bypassing SOCKS5 entirely — leaks Mac LAN IP. This class
 * replaces that path when DRIFTSTACK_CUSTOM_SOCKS5=1: opens a TCP via
 * DriftstackSocks5Client::tcpConnect (SOCKS5 CONNECT through proxy),
 * services libwebrtc's sendTo / receive through a BSD socket fd, and
 * exposes the same Socket interface NetworkRTCProvider expects.
 *
 * Phase 1 (this slice): plain TURN-TCP (no TLS). Sufficient for STUN-TCP
 * + TURN-TCP allocate.
 * Phase 2 (next slice): TURN-TLS wrap via DriftstackTLS13Client reuse for
 * iPhone-byte-exact ClientHello over the SOCKS5 tunnel.
 */

#pragma once

#if PLATFORM(DRIFTSTACK) && USE(LIBWEBRTC) && PLATFORM(COCOA)

#include "NetworkRTCProvider.h"
#include "../cocoa/DriftstackSocks5Client.h"
#include "../cocoa/DriftstackTLS13Client.h"
#include <wtf/Lock.h>
#include <wtf/RetainPtr.h>
#include <wtf/TZoneMalloc.h>
#include <wtf/Vector.h>
#include <memory>

#include <dispatch/dispatch.h>

namespace WebKit {

class DriftstackRTCSocks5TCPSocket final : public NetworkRTCProvider::Socket {
    WTF_MAKE_TZONE_ALLOCATED(DriftstackRTCSocks5TCPSocket);
public:
    static std::unique_ptr<NetworkRTCProvider::Socket> create(WebCore::LibWebRTCSocketIdentifier, NetworkRTCProvider&, const webrtc::SocketAddress& remoteAddress, int options, Ref<IPC::Connection>&&);

    ~DriftstackRTCSocks5TCPSocket();

    Type type() const final { return Type::ClientTCP; }
    WebCore::LibWebRTCSocketIdentifier identifier() const final { return m_identifier; }
    void close() final;
    void setOption(int option, int value) final;
    void sendTo(std::span<const uint8_t>, const webrtc::SocketAddress&, const webrtc::AsyncSocketPacketOptions&) final;

private:
    DriftstackRTCSocks5TCPSocket(WebCore::LibWebRTCSocketIdentifier, NetworkRTCProvider&, const webrtc::SocketAddress& remoteAddress, int options, Ref<IPC::Connection>&&);

    bool connectViaSocks5(const std::string& host, uint16_t port);
    void startReadLoop();
    void onIncomingData(std::span<const uint8_t>);

    WebCore::LibWebRTCSocketIdentifier m_identifier;
    Ref<NetworkRTCProvider> m_rtcProvider;
    Ref<IPC::Connection> m_connection;
    webrtc::SocketAddress m_remoteAddress;
    int m_options { 0 };
    bool m_isSTUN { false };
    bool m_isTLS { false };

    Lock m_lock;
    int m_fd WTF_GUARDED_BY_LOCK(m_lock) { -1 };
    bool m_closed WTF_GUARDED_BY_LOCK(m_lock) { false };
    dispatch_source_t m_readSource WTF_GUARDED_BY_LOCK(m_lock) { nullptr };
    std::unique_ptr<DriftstackSocks5Client> m_socks5Client;  // owns fd lifetime
    std::unique_ptr<DriftstackTLS13Client> m_tls;  // Wave 29-499.279 — TURN-TLS wrap (iPhone-byte-exact ClientHello)

    Vector<uint8_t> m_rxBuffer;  // accumulate incoming bytes between TCP-framing
};

} // namespace WebKit

#endif // PLATFORM(DRIFTSTACK) && USE(LIBWEBRTC) && PLATFORM(COCOA)
