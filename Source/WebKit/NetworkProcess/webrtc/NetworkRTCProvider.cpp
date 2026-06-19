/*
 * Copyright (C) 2017-2025 Apple Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE INC. AND ITS CONTRIBUTORS ``AS IS''
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL APPLE INC. OR ITS CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"
#include "NetworkRTCProvider.h"

#if USE(LIBWEBRTC)

#include "LibWebRTCNetworkMessages.h"
#include "LibWebRTCSocketClient.h"
#include "Logging.h"
#include "NetworkConnectionToWebProcess.h"
#include "NetworkProcess.h"
#include "NetworkRTCProviderMessages.h"
#include "NetworkSession.h"
#include "RTCPacketOptions.h"
#include "RTCSocketCreationFlags.h"
#include "WebRTCResolverMessages.h"
#include <WebCore/LibWebRTCMacros.h>
#include <WebCore/LibWebRTCProvider.h>
#include <wtf/MainThread.h>
#include <wtf/text/WTFString.h>

#if PLATFORM(COCOA)
#include "NetworkRTCTCPSocketCocoa.h"
#include "NetworkRTCUDPSocketCocoa.h"
#include "NetworkSessionCocoa.h"
#if PLATFORM(DRIFTSTACK)
#include "DriftstackRTCSocks5Bridge.h"
#include "DriftstackRTCSocks5TCPSocket.h"
// NOTE: do NOT include DriftstackSocks5Client.h / DriftstackTLS13Client.h here —
// they pull in Objective-C Foundation and this is a pure-C++ TU. finishDriftstackTCPConnect
// takes the transport unique_ptrs by rvalue-REFERENCE and only forwards them; the owning
// lambda (in DriftstackRTCSocks5TCPSocket.mm) destroys them where the types are complete.
#include <arpa/inet.h>
#endif
#else // PLATFORM(COCOA)

WTF_IGNORE_WARNINGS_IN_THIRD_PARTY_CODE_BEGIN
#include <webrtc/api/environment/environment_factory.h>
#include <webrtc/rtc_base/async_packet_socket.h>
WTF_IGNORE_WARNINGS_IN_THIRD_PARTY_CODE_END
#endif // !PLATFORM(COCOA)

namespace WebKit {
using namespace WebCore;

#define RTC_RELEASE_LOG(fmt, ...) RELEASE_LOG(Network, "%p - NetworkRTCProvider::" fmt, this, ##__VA_ARGS__)
#define RTC_RELEASE_LOG_ERROR(fmt, ...) RELEASE_LOG_ERROR(Network, "%p - NetworkRTCProvider::" fmt, this, ##__VA_ARGS__)

NetworkRTCProvider::NetworkRTCProvider(NetworkConnectionToWebProcess& connection)
    : m_connection(&connection)
    , m_ipcConnection(connection.connection())
    , m_rtcMonitor(*this)
    , m_sharedPreferences(connection.sharedPreferencesForWebProcessValue())
#if PLATFORM(COCOA)
    , m_sourceApplicationAuditToken(connection.networkProcess().sourceApplicationAuditToken())
    , m_rtcNetworkThreadQueue(WorkQueue::create("NetworkRTCProvider Queue"_s, WorkQueue::QOS::UserInitiated))
#else
    , m_packetSocketFactory(makeUniqueRefWithoutFastMallocCheck<webrtc::BasicPacketSocketFactory>(rtcNetworkThread().socketserver()))
#endif
{
#if PLATFORM(COCOA)
    if (CheckedPtr session = downcast<NetworkSessionCocoa>(connection.networkSession()))
        m_applicationBundleIdentifier = session->sourceApplicationBundleIdentifier().utf8();
#endif
#if !RELEASE_LOG_DISABLED
    LibWebRTCProvider::setRTCLogging(WebKit2LogWebRTC.state == WTFLogChannelState::On ? WTFLogLevel::Info : WTFLogLevel::Warning);
#endif
}

void NetworkRTCProvider::startListeningForIPC()
{
    protect(connection())->addMessageReceiver(*this, *this, Messages::NetworkRTCProvider::messageReceiverName());
}

NetworkRTCProvider::~NetworkRTCProvider()
{
    ASSERT(!m_connection);
    ASSERT(!m_sockets.size());
    ASSERT(!m_rtcMonitor.isStarted());
}

void NetworkRTCProvider::close()
{
    RTC_RELEASE_LOG("close");

    protect(connection())->removeMessageReceiver(Messages::NetworkRTCProvider::messageReceiverName());
    m_connection = nullptr;
    protect(m_rtcMonitor)->stopUpdating();

    callOnRTCNetworkThread([this, protectedThis = Ref { *this }] {
        auto sockets = std::exchange(m_sockets, { });
        for (auto& socket : sockets)
            socket.second->close();
        ASSERT(m_sockets.empty());
#if PLATFORM(COCOA)
        m_attributedBundleIdentifiers.clear();
#endif
    });
}

void NetworkRTCProvider::sendToSocket(LibWebRTCSocketIdentifier identifier, std::span<const uint8_t> data, RTCNetwork::SocketAddress&& address, RTCPacketOptions&& options)
{
    assertIsRTCNetworkThread();
    auto iterator = m_sockets.find(identifier);
    if (iterator == m_sockets.end())
        return;
    iterator->second->sendTo(data, address.rtcAddress(), options.options);
}

void NetworkRTCProvider::closeSocket(LibWebRTCSocketIdentifier identifier)
{
    assertIsRTCNetworkThread();
    auto iterator = m_sockets.find(identifier);
    if (iterator == m_sockets.end())
        return;
    iterator->second->close();
}

void NetworkRTCProvider::setSocketOption(LibWebRTCSocketIdentifier identifier, int option, int value)
{
    assertIsRTCNetworkThread();
    auto iterator = m_sockets.find(identifier);
    if (iterator == m_sockets.end())
        return;
    iterator->second->setOption(option, value);
}

void NetworkRTCProvider::addSocket(LibWebRTCSocketIdentifier identifier, std::unique_ptr<Socket>&& socket)
{
    assertIsRTCNetworkThread();
    ASSERT(socket);
    ASSERT(!m_sockets.contains(identifier));
    m_sockets.emplace(identifier, WTF::move(socket));

    RTC_RELEASE_LOG("new socket %" PRIu64 ", total socket number is %lu", identifier.toUInt64(), m_sockets.size());
    if (m_sockets.size() > maxSockets) {
        auto socketIdentifierToClose = m_sockets.begin()->first;
        RTC_RELEASE_LOG_ERROR("too many sockets, closing %" PRIu64, socketIdentifierToClose.toUInt64());
        closeSocket(socketIdentifierToClose);
        ASSERT(m_sockets.find(socketIdentifierToClose) == m_sockets.end());
    }
}

std::unique_ptr<NetworkRTCProvider::Socket> NetworkRTCProvider::takeSocket(LibWebRTCSocketIdentifier identifier)
{
    assertIsRTCNetworkThread();
    auto iterator = m_sockets.find(identifier);
    if (iterator == m_sockets.end())
        return nullptr;

    auto socket = WTF::move(iterator->second);
    m_sockets.erase(iterator);
    return socket;
}

void NetworkRTCProvider::dispatch(Function<void()>&& callback)
{
    callOnRTCNetworkThread((WTF::move(callback)));
}

void NetworkRTCProvider::createResolver(LibWebRTCResolverIdentifier identifier, String&& address)
{
    if (!isMainRunLoop()) {
        callOnMainRunLoop([this, protectedThis = Ref { *this }, identifier, address = WTF::move(address).isolatedCopy()]() mutable {
            if (!m_connection)
                return;
            createResolver(identifier, WTF::move(address));
        });
        return;
    }

    RefPtr connection = m_connection.get();
    if (connection && protect(connection->mdnsRegister())->hasRegisteredName(address)) {
        Vector<WebKit::WebRTCNetwork::IPAddress> ipAddresses;
        Ref rtcMonitor = m_rtcMonitor;
        if (!rtcMonitor->ipv4().isUnspecified())
            ipAddresses.append(rtcMonitor->ipv4());
        if (!rtcMonitor->ipv6().isUnspecified())
            ipAddresses.append(rtcMonitor->ipv6());
        protect(this->connection())->send(Messages::WebRTCResolver::SetResolvedAddress(ipAddresses), identifier);
        return;
    }

#if PLATFORM(DRIFTSTACK)
    // Wave 29-397 Slice 2.7.b.3: SHORT-CIRCUIT DNS resolution when bridge
    // active. Allocate a sentinel 127.0.0.X IP for the hostname (Slice
    // 2.7.b.2 allocator); send SetResolvedAddress to libwebrtc with the
    // sentinel; skip WebCore::resolveDNS entirely. The original hostname
    // is preserved in the sidecar map for Slice 2.7.b.4's wrap helper
    // to emit ATYP=0x03 framing via SOCKS5.
    //
    // Replaces Slice 2.7.a's observability-only log path.
    if (DriftstackRTC::isCustomSocks5Active()) {
        String sentinelStr = DriftstackRTC::allocateSentinelForHostname(address);
        if (!sentinelStr.isEmpty()) {
            static bool loggedShortCircuitOnce = false;
            if (!loggedShortCircuitOnce) {
                loggedShortCircuitOnce = true;
                WTFLogAlways("[Driftstack-EG-WK-1.8/EG-WK-1.9/Task#15] createResolver: SHORT-CIRCUIT — hostname='%s' → sentinel=%s. Local DNS bypassed; ATYP=0x03 framing via Slice 2.7.b.4 wrap helper.",
                    address.utf8().data(), sentinelStr.utf8().data());
            }
            struct in_addr sentinelAddr { };
            if (inet_pton(AF_INET, sentinelStr.utf8().data(), &sentinelAddr) == 1) {
                Vector<WebKit::WebRTCNetwork::IPAddress> sentinelAddresses;
                SUPPRESS_MEMORY_UNSAFE_CAST sentinelAddresses.append(RTCNetwork::IPAddress { webrtc::IPAddress { sentinelAddr } });
                protect(this->connection())->send(Messages::WebRTCResolver::SetResolvedAddress(sentinelAddresses), identifier);
                return;
            }
            WTFLogAlways("[Driftstack-EG-WK-1.8/EG-WK-1.9/Task#15] createResolver: inet_pton failed for sentinel '%s'; falling through to local DNS (LEAK)",
                sentinelStr.utf8().data());
        }
    }
#endif

    WebCore::DNSCompletionHandler completionHandler = [connection = m_connection, identifier](auto&& result) {
        ASSERT(isMainRunLoop());
        if (!connection)
            return;
        RefPtr protectedConnection = connection.get();

        if (!result.has_value()) {
            if (result.error() != WebCore::DNSError::Cancelled)
                protectedConnection->connection().send(Messages::WebRTCResolver::ResolvedAddressError(1), identifier);
            return;
        }

        auto ipAddresses = WTF::compactMap(result.value(), [](auto& address) -> std::optional<RTCNetwork::IPAddress> {
            if (address.isIPv4())
                // FIXME: Remove SUPPRESS_MEMORY_UNSAFE_CAST once rdar://144236356 is fixed.
                SUPPRESS_MEMORY_UNSAFE_CAST return RTCNetwork::IPAddress { webrtc::IPAddress { address.ipv4Address() } };
            if (address.isIPv6())
                // FIXME: Remove SUPPRESS_MEMORY_UNSAFE_CAST once rdar://144236356 is fixed.
                SUPPRESS_MEMORY_UNSAFE_CAST return RTCNetwork::IPAddress { webrtc::IPAddress { address.ipv6Address() } };
            return std::nullopt;
        });

        protectedConnection->connection().send(Messages::WebRTCResolver::SetResolvedAddress(ipAddresses), identifier);
    };

    WebCore::resolveDNS(address, identifier.toUInt64(), WTF::move(completionHandler));
}

void NetworkRTCProvider::stopResolver(LibWebRTCResolverIdentifier identifier)
{
    if (!isMainRunLoop()) {
        callOnMainRunLoop([this, protectedThis = Ref { *this }, identifier] {
            if (!m_connection)
                return;
            stopResolver(identifier);
        });
        return;
    }
    WebCore::stopResolveDNS(identifier.toUInt64());
}

#if PLATFORM(COCOA)
bool NetworkRTCProvider::webRTCInterfaceMonitoringViaNWEnabled() const
{
    auto* connection = m_connection.get();
    return connection && connection->webRTCInterfaceMonitoringViaNWEnabled();
}

const String& NetworkRTCProvider::attributedBundleIdentifierFromPageIdentifier(WebPageProxyIdentifier pageIdentifier)
{
    return m_attributedBundleIdentifiers.ensure(pageIdentifier, [protectedThis = Ref { *this }, pageIdentifier]() -> String {
        String value;
        callOnMainRunLoopAndWait([protectedThis, &value, pageIdentifier] {
            RefPtr connection = protectedThis->m_connection.get();
            if (CheckedPtr session = connection ? connection->networkSession() : nullptr)
                value = session->attributedBundleIdentifierFromPageIdentifier(pageIdentifier).isolatedCopy();
        });
        return value;
    }).iterator->value;
}

void NetworkRTCProvider::createUDPSocket(LibWebRTCSocketIdentifier identifier, const RTCNetwork::SocketAddress& address, uint16_t minPort, uint16_t maxPort, WebPageProxyIdentifier pageIdentifier, RTCSocketCreationFlags flags, WebCore::RegistrableDomain&& domain)
{
    assertIsRTCNetworkThread();

    if (m_sockets.contains(identifier)) {
        RELEASE_LOG_ERROR(WebRTC, "NetworkRTCProvider::createUDPSocket duplicate identifier");
        return;
    }

#if PLATFORM(DRIFTSTACK)
    // Wave 29-397 Slice 2.5: PacketSocketFactory hook — eagerly establish
    // the SOCKS5 UDP ASSOCIATE relay channel at socket-creation time when
    // DRIFTSTACK_CUSTOM_SOCKS5=1. The first WebRTC socket triggers handshake
    // + udpAssociate; subsequent sockets share the cached SharedRelayState
    // (Slice 2.2 singleton). On failure, log loudly + fall through to direct
    // nw_connection — Slice 2.6 will harden this into hard-block when
    // DRIFTSTACK_REQUIRE_PROXY=1.
    //
    // Pre-Slice-2.5 (Wave 29-383 scaffold): only logged the leak. This slice
    // upgrades to actively initializing the relay, so sendTo (Slice 2.4)
    // sees cached relayEstablished=true on first call instead of synchronous
    // establish-on-hot-path.
    if (DriftstackRTC::isCustomSocks5Active()) {
        static bool establishLoggedOnce = false;
        static bool establishOkOnce = false;
        DriftstackRTC::RelayChannel channel;
        DriftstackRTC::BridgeResult r = DriftstackRTC::establishRelayChannel(channel);
        if (r == DriftstackRTC::BridgeResult::Success && !establishOkOnce) {
            establishOkOnce = true;
            WTFLogAlways("[Driftstack-EG-WK-1.8/Task#15] createUDPSocket: relay channel READY at socket-creation time — relay=%s:%u. Slice 2.6 will redirect nw_connection destination to this endpoint.",
                channel.relayHost.utf8().data(), channel.relayPort);
        } else if (r != DriftstackRTC::BridgeResult::Success) {
            if (!establishLoggedOnce) {
                establishLoggedOnce = true;
                WTFLogAlways("[Driftstack-EG-WK-1.8/Task#15] createUDPSocket: relay channel establish FAILED at socket-creation time (result=%d). Verify gost/SOCKS5 proxy reachable at DRIFTSTACK_SOCKS5_PROXY.",
                    static_cast<int>(r));
            }
            // Wave 29-397 Slice 2.5.b: hard-block WebRTC UDP socket creation
            // when DRIFTSTACK_REQUIRE_PROXY=1 + relay channel unavailable.
            // Replaces fall-through-with-leak behavior. signalSocketIsClosed
            // surfaces the failure to libwebrtc which gracefully terminates
            // the peer-connection negotiation (better than leaking direct
            // UDP). When DRIFTSTACK_REQUIRE_PROXY is unset, legacy fall-
            // through path remains for debugging without the egress lock.
            const char* requireProxy = getenv("DRIFTSTACK_REQUIRE_PROXY");
            if (requireProxy && requireProxy[0] == '1') {
                WTFLogAlways("[Driftstack-EG-WK-1.8/Task#15] createUDPSocket: DRIFTSTACK_REQUIRE_PROXY=1 + relay unavailable → HARD-BLOCK socket creation (id=%" PRIu64 "). libwebrtc will fail this candidate gracefully.",
                    identifier.toUInt64());
                signalSocketIsClosed(identifier);
                return;
            }
            WTFLogAlways("[Driftstack-EG-WK-1.8/Task#15] createUDPSocket: DRIFTSTACK_REQUIRE_PROXY unset — falling through to direct nw_connection (LEAK ALLOWED for debugging). Set DRIFTSTACK_REQUIRE_PROXY=1 to enforce egress lock.");
        }
    } else {
        // EGRESS channel-5 hardening (2026-06-18 channel-leak enumeration): SOCKS5 INACTIVE. Under
        // REQUIRE_PROXY=1 a WebRTC UDP socket must NOT be created direct — NetworkRTCUDPSocketCocoa would
        // nw_connection at the Mac fleet IP, and its sendTo/setListeningPort fail-closed are gated on
        // isCustomSocks5Active() so they DON'T fire in this state → leak. Hard-block like the SOCKS5-active-
        // relay-unavailable case above (348). NOT reachable today (the spawn env couples DRIFTSTACK_CUSTOM_SOCKS5
        // + DRIFTSTACK_REQUIRE_PROXY); defense-in-depth so a future decoupling can't leak.
        const char* requireProxyInactive = getenv("DRIFTSTACK_REQUIRE_PROXY");
        if (requireProxyInactive && requireProxyInactive[0] == '1') {
            WTFLogAlways("[Driftstack-EG-WK-1.8] createUDPSocket: REQUIRE_PROXY=1 + DRIFTSTACK_CUSTOM_SOCKS5 unset → HARD-BLOCK (no direct WebRTC UDP socket; id=%" PRIu64 ").", identifier.toUInt64());
            signalSocketIsClosed(identifier);
            return;
        }
        // Legacy Wave 29-383 observability when DRIFTSTACK_CUSTOM_SOCKS5
        // unset but DRIFTSTACK_SOCKS5_PROXY set (env-fallback path Wave
        // 29-366 active for HTTP/HTTPS but not WebRTC yet).
        static bool loggedOnce = false;
        const char* socks5Env = getenv("DRIFTSTACK_SOCKS5_PROXY");
        if (!loggedOnce && socks5Env && socks5Env[0]) {
            loggedOnce = true;
            WTFLogAlways("[Driftstack-EG-WK-1.8/Task#15] WebRTC UDP socket created via NetworkRTCUDPSocketCocoa — DRIFTSTACK_CUSTOM_SOCKS5 unset, falling through to direct nw_connection (env-fallback path only covers HTTP/HTTPS via NSURLSession). Set DRIFTSTACK_CUSTOM_SOCKS5=1 to activate WebRTC SOCKS5 bridge (Slice 2.5).");
        }
    }
#endif

    auto socket = makeUnique<NetworkRTCUDPSocketCocoa>(identifier, *this, address.rtcAddress(), m_ipcConnection.copyRef(), String(attributedBundleIdentifierFromPageIdentifier(pageIdentifier)), flags, WTF::move(domain));
    addSocket(identifier, WTF::move(socket));
}

void NetworkRTCProvider::createClientTCPSocket(LibWebRTCSocketIdentifier identifier, const RTCNetwork::SocketAddress& localAddress, const RTCNetwork::SocketAddress& remoteAddress, String&& userAgent, int options, WebPageProxyIdentifier pageIdentifier, RTCSocketCreationFlags flags, WebCore::RegistrableDomain&& domain)
{
    assertIsRTCNetworkThread();

    if (m_sockets.contains(identifier)) {
        RELEASE_LOG_ERROR(WebRTC, "NetworkRTCProvider::createClientTCPSocket duplicate identifier");
        return;
    }

#if PLATFORM(DRIFTSTACK)
    // Wave 29-499.274 → .275: route TURN TCP via SOCKS5 CONNECT through
    // DriftstackRTCSocks5TCPSocket (BSD-socket replacement for nw_connection_t).
    // Previous .274 hard-blocked all TCP socket creation when CUSTOM_SOCKS5=1
    // to prevent Mac-IP leak via NetworkRTCTCPSocketCocoa's direct
    // nw_connection_create. This slice replaces the block with a tunneled
    // socket that actually carries TURN TCP through the proxy.
    // TURN-TLS still refused at create() time (Phase 2 wrap pending).
    if (DriftstackRTC::isCustomSocks5Active()) {
        // Wave 29-499.341 — construct + register the socket immediately, then connect
        // ASYNC so the SOCKS5 CONNECT (+TURN-TLS handshake) doesn't block this thread
        // and serialize across sockets (which made TURN TCP/TLS miss Twilio's 5s
        // deadline). finishDriftstackTCPConnect adopts the transport (or closes) later.
        auto socket = DriftstackRTCSocks5TCPSocket::create(identifier, *this, remoteAddress.rtcAddress(), options, m_ipcConnection.copyRef());
        auto* rawSocket = static_cast<DriftstackRTCSocks5TCPSocket*>(socket.get());
        WTFLogAlways("[Driftstack-EG-WK-1.8/Wave29-499.341] TURN TCP via SOCKS5 CONNECT — socket registered (id=%" PRIu64 ", dest=%s:%d), connecting async",
            identifier.toUInt64(),
            remoteAddress.rtcAddress().hostname().c_str(),
            remoteAddress.rtcAddress().port());
        addSocket(identifier, WTF::move(socket));
        rawSocket->beginAsyncConnect();
        return;
    }
#endif

#if PLATFORM(DRIFTSTACK)
    // EGRESS channel-5 hardening (2026-06-18): SOCKS5 INACTIVE (the isCustomSocks5Active tunnel above didn't
    // fire). Under REQUIRE_PROXY=1 do NOT create a DIRECT TCP socket — NetworkRTCTCPSocketCocoa nw_connections
    // at the Mac fleet IP = leak. Fail closed (signalSocketIsClosed → libwebrtc abandons the candidate), the same
    // posture as the createUDPSocket hard-block. NOT reachable today (spawn env couples CUSTOM_SOCKS5 +
    // REQUIRE_PROXY); defense-in-depth so a future decoupling can't leak TURN-TCP direct.
    {
        const char* requireProxyTCP = getenv("DRIFTSTACK_REQUIRE_PROXY");
        if (requireProxyTCP && requireProxyTCP[0] == '1') {
            WTFLogAlways("[Driftstack-EG-WK-1.8] createClientTCPSocket: REQUIRE_PROXY=1 + DRIFTSTACK_CUSTOM_SOCKS5 unset → FAIL-CLOSED (no direct TCP socket; id=%" PRIu64 ").", identifier.toUInt64());
            signalSocketIsClosed(identifier);
            return;
        }
    }
#endif

    auto socket = NetworkRTCTCPSocketCocoa::createClientTCPSocket(identifier, *this, remoteAddress.rtcAddress(), options, attributedBundleIdentifierFromPageIdentifier(pageIdentifier), flags, domain, m_ipcConnection.copyRef());
    if (socket)
        addSocket(identifier, WTF::move(socket));
    else
        signalSocketIsClosed(identifier);
}

#if PLATFORM(DRIFTSTACK)
void NetworkRTCProvider::finishDriftstackTCPConnect(LibWebRTCSocketIdentifier identifier, bool ok,
    std::unique_ptr<DriftstackSocks5Client>&& client, std::unique_ptr<DriftstackTLS13Client>&& tls)
{
    assertIsRTCNetworkThread();
    auto iterator = m_sockets.find(identifier);
    if (iterator == m_sockets.end()) {
        // Socket already closed/destroyed during the async connect — drop the
        // transport (unique_ptr dtors close the fd). libwebrtc already tore it down.
        WTFLogAlways("[Driftstack-EG-WK-1.8/Wave29-499.341] async connect for id=%" PRIu64 " completed but socket gone — dropping transport", identifier.toUInt64());
        return;
    }
    if (!ok) {
        signalSocketIsClosed(identifier);
        auto dead = takeSocket(identifier); // unlinks from map first; destroyed at scope end
        return;
    }
    static_cast<DriftstackRTCSocks5TCPSocket*>(iterator->second.get())->adoptConnectedTransport(WTF::move(client), WTF::move(tls));
}
#endif

void NetworkRTCProvider::getInterfaceName(URL&& url, WebPageProxyIdentifier pageIdentifier, RTCSocketCreationFlags flags, WebCore::RegistrableDomain&& domain, CompletionHandler<void(String&&)>&& completionHandler)
{
    if (!url.protocolIsInHTTPFamily()) {
        completionHandler({ });
        return;
    }

    NetworkRTCTCPSocketCocoa::getInterfaceName(*this, url, attributedBundleIdentifierFromPageIdentifier(pageIdentifier), flags, domain)->whenSettled(m_rtcNetworkThreadQueue, [completionHandler = WTF::move(completionHandler)](auto&& result) mutable {
        completionHandler(result ? WTF::move(result.value()) : String { });
    });
}

void NetworkRTCProvider::callOnRTCNetworkThread(Function<void()>&& callback)
{
    m_rtcNetworkThreadQueue->dispatch(WTF::move(callback));
}

void NetworkRTCProvider::assertIsRTCNetworkThread()
{
    assertIsCurrent(m_rtcNetworkThreadQueue);
}

#else // PLATFORM(COCOA)
webrtc::Thread& NetworkRTCProvider::rtcNetworkThread()
{
    static NeverDestroyed<std::unique_ptr<webrtc::Thread>> networkThread = [] {
        auto networkThread = webrtc::Thread::CreateWithSocketServer();
        networkThread->SetName("RTC Network Thread", nullptr);

        auto result = networkThread->Start();
        ASSERT_UNUSED(result, result);
        return networkThread;
    }();
    return *networkThread.get();
}

void NetworkRTCProvider::createUDPSocket(LibWebRTCSocketIdentifier identifier, const RTCNetwork::SocketAddress& address, uint16_t minPort, uint16_t maxPort, WebPageProxyIdentifier pageIdentifier, RTCSocketCreationFlags, WebCore::RegistrableDomain&& domain)
{
    assertIsRTCNetworkThread();

    std::unique_ptr<webrtc::AsyncPacketSocket> socket(m_packetSocketFactory->CreateUdpSocket(webrtc::CreateEnvironment(), address.rtcAddress(), minPort, maxPort));
    createSocket(identifier, WTF::move(socket), Socket::Type::UDP, m_ipcConnection.copyRef());
}

void NetworkRTCProvider::createClientTCPSocket(LibWebRTCSocketIdentifier identifier, const RTCNetwork::SocketAddress& localAddress, const RTCNetwork::SocketAddress& remoteAddress, String&& userAgent, int options, WebPageProxyIdentifier pageIdentifier, RTCSocketCreationFlags, WebCore::RegistrableDomain&& domain)
{
    assertIsRTCNetworkThread();

    if (m_sockets.contains(identifier)) {
        RELEASE_LOG_ERROR(WebRTC, "NetworkRTCProvider::createClientTCPSocket duplicate identifier");
        return;
    }

    callOnMainRunLoop([this, protectedThis = Ref { *this }, identifier, localAddress, remoteAddress, userAgent = WTF::move(userAgent).isolatedCopy(), options]() mutable {
        if (!m_connection)
            return;

        if (!m_connection->networkSession()) {
            signalSocketIsClosed(identifier);
            return;
        }
        callOnRTCNetworkThread([this, protectedThis = Ref { *this }, identifier, localAddress = localAddress.rtcAddress(), remoteAddress = remoteAddress.rtcAddress(), options]() mutable {

            if (m_sockets.contains(identifier)) {
                RELEASE_LOG_ERROR(WebRTC, "NetworkRTCProvider::createClientTCPSocket duplicate identifier");
                return;
            }

            webrtc::PacketSocketTcpOptions tcpOptions;
            tcpOptions.opts = options;
            std::unique_ptr<webrtc::AsyncPacketSocket> socket(m_packetSocketFactory->CreateClientTcpSocket(webrtc::CreateEnvironment(), localAddress, remoteAddress, tcpOptions));
            createSocket(identifier, WTF::move(socket), Socket::Type::ClientTCP, m_ipcConnection.copyRef());
        });
    });
}

void NetworkRTCProvider::createSocket(LibWebRTCSocketIdentifier identifier, std::unique_ptr<webrtc::AsyncPacketSocket>&& socket, Socket::Type type, Ref<IPC::Connection>&& connection)
{
    assertIsRTCNetworkThread();
    if (!socket) {
        RTC_RELEASE_LOG_ERROR("createSocket with %lu sockets is unable to create a new socket", m_sockets.size());
        connection->send(Messages::LibWebRTCNetwork::SignalClose(identifier, 1), 0);
        return;
    }
    addSocket(identifier, makeUnique<LibWebRTCSocketClient>(identifier, *this, WTF::move(socket), type, WTF::move(connection)));
}

void NetworkRTCProvider::callOnRTCNetworkThread(Function<void()>&& callback)
{
    rtcNetworkThread().PostTask(WTF::move(callback));
}

void NetworkRTCProvider::assertIsRTCNetworkThread()
{
    ASSERT(rtcNetworkThread().IsCurrent());
}
#endif // !PLATFORM(COCOA)

void NetworkRTCProvider::signalSocketIsClosed(LibWebRTCSocketIdentifier identifier)
{
    protect(connection())->send(Messages::LibWebRTCNetwork::SignalClose(identifier, 1), 0);
}

std::optional<SharedPreferencesForWebProcess> NetworkRTCProvider::sharedPreferencesForWebProcess(IPC::Connection& connection)
{
    Locker locker { m_sharedPreferencesLock };
    return m_sharedPreferences;
}

void NetworkRTCProvider::updateSharedPreferencesForWebProcess(const SharedPreferencesForWebProcess& preferences)
{
    Locker locker { m_sharedPreferencesLock };
    m_sharedPreferences = preferences;
}

#undef RTC_RELEASE_LOG
#undef RTC_RELEASE_LOG_ERROR

} // namespace WebKit

#endif // USE(LIBWEBRTC)
