/*
 * DriftstackRTCSocks5Bridge.mm — Phase A scaffold implementation.
 * See header for design context + multi-phase rollout plan.
 */

#import "config.h"
#import "DriftstackRTCSocks5Bridge.h"

#if PLATFORM(DRIFTSTACK) && USE(LIBWEBRTC) && PLATFORM(COCOA)

#import "DriftstackSocks5Client.h"

#import <Foundation/Foundation.h>
#include <mutex>
#include <stdlib.h>
#include <string.h>
// NetworkRTCProvider's include path lets webrtc::SocketAddress reach this
// translation unit without including <webrtc/rtc_base/socket_address.h>
// directly (which transitively triggers the macOS-incompatible
// webrtc/rtc_base/byte_order.h on Apple Silicon).
#include "NetworkRTCProvider.h"
#include <webrtc/rtc_base/async_packet_socket.h>
#include <wtf/Assertions.h>
#include <wtf/Lock.h>
#include <wtf/NeverDestroyed.h>
#include <wtf/cocoa/SpanCocoa.h>

namespace WebKit {

namespace DriftstackRTC {

bool isCustomSocks5Active()
{
    const char* customSocks5 = getenv("DRIFTSTACK_CUSTOM_SOCKS5");
    const char* socks5Proxy = getenv("DRIFTSTACK_SOCKS5_PROXY");
    return customSocks5 && customSocks5[0] == '1'
        && socks5Proxy && socks5Proxy[0];
}

// Wave 29-397 Slice 2.2: shared relay client + cached channel. Per RFC 1928
// §6 the TCP control connection MUST stay open for the lifetime of the UDP
// association; we keep one DriftstackSocks5Client instance in a NeverDestroyed
// singleton + one Socks5UdpRelayChannel cached after the first successful
// open. All WebRTC sockets share the same relay endpoint (datagrams are
// per-destination via the §7 wrap, not per-relay).
//
// Thread safety: the WebRTC network thread (m_rtcNetworkThreadQueue) calls
// establishRelayChannel; std::once_flag guards single-init.
struct SharedRelayState {
    Lock lock;
    std::unique_ptr<DriftstackSocks5Client> client WTF_GUARDED_BY_LOCK(lock);
    Socks5UdpRelayChannel channel WTF_GUARDED_BY_LOCK(lock);
    bool established WTF_GUARDED_BY_LOCK(lock) { false };
};

static SharedRelayState& sharedRelayState()
{
    static NeverDestroyed<SharedRelayState> s_state;
    return s_state.get();
}

WTF_ALLOW_UNSAFE_BUFFER_USAGE_BEGIN
static bool parseProxyEndpoint(const char* env, Socks5Endpoint& out)
{
    // DRIFTSTACK_SOCKS5_PROXY is "host:port". Plain ASCII, no brackets for
    // IPv6 expected in Driftstack deployments (Mac fleet uses IPv4 to local
    // gost or customer SOCKS5). Wraps strrchr / atoi / span ctor under
    // WTF_ALLOW_UNSAFE_BUFFER_USAGE at function scope per the Wave 29-368
    // parseUdpFrame helper pattern.
    if (!env || !env[0])
        return false;
    size_t len = 0;
    while (env[len] && len < 256) ++len;
    const char* colon = nullptr;
    for (size_t i = len; i > 0; --i) {
        if (env[i - 1] == ':') { colon = env + (i - 1); break; }
    }
    if (!colon || colon == env)
        return false;
    out.host = String::fromUTF8(std::span<const char> { env, static_cast<size_t>(colon - env) });
    int port = 0;
    for (const char* p = colon + 1; *p; ++p) {
        if (*p < '0' || *p > '9')
            return false;
        port = port * 10 + (*p - '0');
        if (port > 0xFFFF)
            return false;
    }
    if (port <= 0)
        return false;
    out.port = static_cast<uint16_t>(port);
    return true;
}
WTF_ALLOW_UNSAFE_BUFFER_USAGE_END

BridgeResult establishRelayChannel(RelayChannel& out)
{
    if (!isCustomSocks5Active())
        return BridgeResult::Socks5Disabled;

    auto& state = sharedRelayState();
    Locker locker { state.lock };

    if (state.established) {
        out.relayHost = state.channel.relayHost;
        out.relayPort = state.channel.relayPort;
        return BridgeResult::Success;
    }

    Socks5Endpoint proxy;
    if (!parseProxyEndpoint(getenv("DRIFTSTACK_SOCKS5_PROXY"), proxy)) {
        WTFLogAlways("[Driftstack-EG-WK-1.8/Task#15] establishRelayChannel: DRIFTSTACK_SOCKS5_PROXY malformed (expected host:port)");
        return BridgeResult::ProtocolError;
    }

    Socks5Credentials creds;
    if (const char* u = getenv("DRIFTSTACK_SOCKS5_USER"))
        creds.username = String::fromUTF8(u);
    if (const char* p = getenv("DRIFTSTACK_SOCKS5_PASS"))
        creds.password = String::fromUTF8(p);

    // DriftstackSocks5Client isn't WTF_MAKE_FAST_ALLOCATED — fall back to
    // std::make_unique which doesn't require the WTFIsFastMallocAllocated
    // trait. Future cleanup: add WTF_MAKE_TZONE_ALLOCATED to Wave 29-368
    // DriftstackSocks5Client class definition.
    state.client = std::make_unique<DriftstackSocks5Client>(proxy, creds);

    Socks5Result handshakeResult = state.client->performHandshake();
    if (handshakeResult != Socks5Result::Success) {
        WTFLogAlways("[Driftstack-EG-WK-1.8/Task#15] establishRelayChannel: SOCKS5 handshake FAILED with proxy %s:%u (result=%d). WebRTC will leak direct UDP until proxy reachable.",
            proxy.host.utf8().data(), proxy.port, static_cast<int>(handshakeResult));
        state.client.reset();
        return BridgeResult::NetworkError;
    }

    Socks5Result assocResult = state.client->udpAssociate(state.channel);
    if (assocResult != Socks5Result::Success) {
        WTFLogAlways("[Driftstack-EG-WK-1.8/Task#15] establishRelayChannel: UDP ASSOCIATE FAILED with proxy %s:%u (result=%d). Proxy may not support UDP relay; WebRTC will leak direct UDP.",
            proxy.host.utf8().data(), proxy.port, static_cast<int>(assocResult));
        state.client.reset();
        return BridgeResult::UdpAssociateFailed;
    }

    state.established = true;
    WTFLogAlways("[Driftstack-EG-WK-1.8/Task#15] establishRelayChannel: SUCCESS — UDP relay endpoint %s:%u (Phase B). Phase C wrap/unwrap (slice 2.3) and PacketSocketFactory hook (slice 2.5) still required before WebRTC datagrams actually transit SOCKS5.",
        state.channel.relayHost.utf8().data(), state.channel.relayPort);

    out.relayHost = state.channel.relayHost;
    out.relayPort = state.channel.relayPort;
    return BridgeResult::Success;
}

// Wave 29-397 Slice 2.3: socketAddress → Socks5Endpoint. Prefers numeric
// IP form when set (libwebrtc resolves DNS before passing to the socket
// layer in most paths); falls back to hostname otherwise.
static Socks5Endpoint endpointFromSocketAddress(const webrtc::SocketAddress& address)
{
    Socks5Endpoint endpoint;
    if (!address.ipaddr().IsNil()) {
        auto ip = address.ipaddr().ToString();
        endpoint.host = String::fromUTF8(ip.c_str());
    } else {
        auto host = address.hostname();
        endpoint.host = String::fromUTF8(host.c_str());
    }
    endpoint.port = address.port();
    return endpoint;
}

BridgeResult wrapOutgoingDatagram(const webrtc::SocketAddress& dest, std::span<const uint8_t> payload, Vector<uint8_t>& out)
{
    if (!isCustomSocks5Active())
        return BridgeResult::Socks5Disabled;

    Socks5Endpoint destination = endpointFromSocketAddress(dest);
    if (destination.host.isEmpty() || destination.port == 0) {
        WTFLogAlways("[Driftstack-EG-WK-1.8/Task#15] wrapOutgoingDatagram: invalid destination (host empty or port=0); dropping datagram to prevent leak");
        return BridgeResult::ProtocolError;
    }
    if (destination.host.utf8().length() > 255)
        return BridgeResult::DomainTooLong;

    RetainPtr<NSData> payloadData = adoptNS([[NSData alloc] initWithBytes:payload.data() length:payload.size()]);
    RetainPtr<NSData> framed = DriftstackSocks5Client::wrapUdpDatagram(destination, payloadData.get());
    if (!framed) {
        WTFLogAlways("[Driftstack-EG-WK-1.8/Task#15] wrapOutgoingDatagram: §7 frame helper returned nil for dest=%s:%u",
            destination.host.utf8().data(), destination.port);
        return BridgeResult::ProtocolError;
    }

    out.clear();
    out.append(WTF::span(framed.get()));
    return BridgeResult::Success;
}

BridgeResult unwrapIncomingDatagram(std::span<const uint8_t> frame, UnwrappedDatagram& out)
{
    if (!isCustomSocks5Active())
        return BridgeResult::Socks5Disabled;

    RetainPtr<NSData> frameData = adoptNS([[NSData alloc] initWithBytes:frame.data() length:frame.size()]);
    Socks5Endpoint source;
    RetainPtr<NSData> payload = DriftstackSocks5Client::unwrapUdpDatagram(frameData.get(), source);
    if (!payload) {
        WTFLogAlways("[Driftstack-EG-WK-1.8/Task#15] unwrapIncomingDatagram: §7 frame helper returned nil (protocol error)");
        return BridgeResult::ProtocolError;
    }

    out.sourceHost = source.host;
    out.sourcePort = source.port;
    out.payload.clear();
    out.payload.append(WTF::span(payload.get()));
    return BridgeResult::Success;
}

} // namespace DriftstackRTC

} // namespace WebKit

#endif // PLATFORM(DRIFTSTACK) && USE(LIBWEBRTC) && PLATFORM(COCOA)
