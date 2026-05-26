/*
 * Copyright (C) 2021-2023 Apple Inc. All rights reserved.
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

#import "config.h"
#import "NetworkRTCUDPSocketCocoa.h"

#if USE(LIBWEBRTC) && PLATFORM(COCOA)

#if PLATFORM(DRIFTSTACK)
#include "DriftstackRTCSocks5Bridge.h"
#include <arpa/inet.h>
// Wave 29-499.99 — raw BSD UDP socket replacement for m_relayConnection
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <wtf/OSObjectPtr.h>
#endif

#include "LibWebRTCNetworkMessages.h"
#include "Logging.h"
#include "NetworkRTCUtilitiesCocoa.h"
#include "RTCSocketCreationFlags.h"
#include <WebCore/STUNMessageParsing.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <pal/spi/cocoa/NetworkSPI.h>
#include <webrtc/rtc_base/async_packet_socket.h>
#include <webrtc/rtc_base/time_utils.h>
#include <wtf/BlockPtr.h>
#include <wtf/SoftLinking.h>
#include <wtf/SystemFree.h>
#include <wtf/TZoneMallocInlines.h>
#include <wtf/ThreadSafeRefCounted.h>
#include <wtf/cocoa/SpanCocoa.h>
#include <wtf/darwin/DispatchOSObject.h>
#include <wtf/posix/SocketPOSIX.h>

namespace WebKit {

using namespace WebCore;

WTF_MAKE_TZONE_ALLOCATED_IMPL(NetworkRTCUDPSocketCocoa);

class NetworkRTCUDPSocketCocoaConnections : public ThreadSafeRefCountedAndCanMakeThreadSafeWeakPtr<NetworkRTCUDPSocketCocoaConnections> {
public:
    static Ref<NetworkRTCUDPSocketCocoaConnections> create(WebCore::LibWebRTCSocketIdentifier identifier, NetworkRTCProvider& provider, const webrtc::SocketAddress& address, Ref<IPC::Connection>&& connection, String&& attributedBundleIdentifier, RTCSocketCreationFlags flags, const WebCore::RegistrableDomain& domain) { return adoptRef(*new NetworkRTCUDPSocketCocoaConnections(identifier, provider, address, WTF::move(connection), WTF::move(attributedBundleIdentifier), flags, domain)); }

    ~NetworkRTCUDPSocketCocoaConnections();

    void close();
    void setOption(int option, int value);
    void sendTo(std::span<const uint8_t>, const webrtc::SocketAddress&, const webrtc::AsyncSocketPacketOptions&);

    class ConnectionStateTracker : public ThreadSafeRefCounted<ConnectionStateTracker> {
    public:
        static Ref<ConnectionStateTracker> NODELETE create() { return adoptRef(*new ConnectionStateTracker()); }
        void NODELETE markAsStopped() { m_isStopped = true; }
        bool NODELETE isStopped() const { return m_isStopped; }
        bool NODELETE shouldLogMissingECN() const { return !m_didLogMissingECN; }
        void NODELETE didLogMissingECN() { m_didLogMissingECN = true; }

        bool NODELETE hasPendingSend() const { return m_pendingSendCount; }
        void NODELETE incrementPendingSendCount() { ++m_pendingSendCount; }
        void NODELETE decrementPendingSendCount()
        {
            ASSERT(m_pendingSendCount);
            --m_pendingSendCount;
        }

    private:
        std::atomic<bool> m_isStopped { false };
        bool m_didLogMissingECN { false };
        std::atomic<size_t> m_pendingSendCount { 0 };
    };

private:
    NetworkRTCUDPSocketCocoaConnections(WebCore::LibWebRTCSocketIdentifier, NetworkRTCProvider&, const webrtc::SocketAddress&, Ref<IPC::Connection>&&, String&& attributedBundleIdentifier, RTCSocketCreationFlags, const WebCore::RegistrableDomain&);

    struct Connection {
        RetainPtr<nw_connection_t> nwConnection;
        RefPtr<ConnectionStateTracker> tracker;
    };
    Connection createNWConnection(const webrtc::SocketAddress&);
    void setupNWConnection(nw_connection_t, ConnectionStateTracker&, const webrtc::SocketAddress&);
    void configureParameters(nw_parameters_t, nw_ip_version_t);
    void setListeningPort(int);

#if PLATFORM(DRIFTSTACK)
    // Wave 29-397 Slice 2.4.b.2: lazy-init the relay nw_connection_t on
    // first SOCKS5-active sendTo. Caller must hold m_nwConnectionsLock.
    bool ensureRelayConnection() WTF_REQUIRES_LOCK(m_nwConnectionsLock);
#endif

    WebCore::LibWebRTCSocketIdentifier m_identifier;
    const Ref<IPC::Connection> m_connection;
    bool m_isFirstParty { false };
    bool m_isKnownTracker { false };
    bool m_shouldBypassRelay { false };
    bool m_enableServiceClass { false };

    CString m_sourceApplicationBundleIdentifier;
    std::optional<audit_token_t> m_sourceApplicationAuditToken;
    String m_attributedBundleIdentifier;

    webrtc::SocketAddress m_address;
    RetainPtr<nw_listener_t> m_nwListener;
    Lock m_nwConnectionsLock;
    bool m_isClosed WTF_GUARDED_BY_LOCK(m_nwConnectionsLock) { false };
    HashMap<webrtc::SocketAddress, Connection> m_nwConnections WTF_GUARDED_BY_LOCK(m_nwConnectionsLock);
    std::optional<uint32_t> m_trafficClass;

#if PLATFORM(DRIFTSTACK)
    // Wave 29-397 Slice 2.4.b.2: single relay nw_connection_t replaces the
    // per-peer m_nwConnections map when DriftstackRTC::isCustomSocks5Active()
    // returns true. All outbound UDP datagrams flow through m_relayConnection
    // (bound to SOCKS5 BND.ADDR:BND.PORT from establishRelayChannel) after
    // being SOCKS5 §7-wrapped. Inbound datagrams arrive on the same channel
    // and are §7-unwrapped before being dispatched to libwebrtc with the
    // original peer's IP/port restored.
    //
    // Lifetime: created at the first sendTo() with bridge active (lazy init
    // matches the per-peer map's ensure() pattern); destroyed at close().
    // Guarded by m_nwConnectionsLock (same lock that protects m_nwConnections
    // — single locking domain for all UDP connection state).
    RetainPtr<nw_connection_t> m_relayConnection WTF_GUARDED_BY_LOCK(m_nwConnectionsLock);
    RefPtr<ConnectionStateTracker> m_relayTracker WTF_GUARDED_BY_LOCK(m_nwConnectionsLock);
    bool m_relayStarted WTF_GUARDED_BY_LOCK(m_nwConnectionsLock) { false };

    // Wave 29-499.99 — raw BSD UDP socket replacement for m_relayConnection.
    // Empirical (V-2026-05-21-W29-499.98): Apple's nw_connection_t for UDP
    // doesn't reliably traverse the SOCKS5 UDP_ASSOCIATE relay — receives
    // only gost-self-sourced keepalive frames, never real STUN responses.
    // Python with raw BSD UDP socket on same proxy works perfectly. Switch
    // to BSD socket here. Lifecycle: socket + dispatch source created in
    // ensureRelayConnection alongside m_relayConnection; sendTo uses
    // sendto(); a GCD dispatch_source_t on the socket fd handles inbound
    // recvfrom + §7-unwrap + SignalReadPacket dispatch.
    int m_relayBsdSocket WTF_GUARDED_BY_LOCK(m_nwConnectionsLock) { -1 };
    OSObjectPtr<dispatch_source_t> m_relayBsdReadSource WTF_GUARDED_BY_LOCK(m_nwConnectionsLock);
    String m_relayBndHost; // BND.ADDR — copy out so dispatch handler doesn't need the lock.
    uint16_t m_relayBndPort { 0 };

    // Wave 29-499.332 — ONE per-socket SOCKS5 UDP ASSOCIATE for THIS socket, established
    // lazily and shared by both setListeningPort (ICE candidate address) and
    // ensureRelayConnection (send/recv). Each socket thus egresses from a distinct relay
    // 5-tuple, so concurrent TURN allocations (Twilio UDP/TCP/TLS tests) don't collide
    // with error 437. Replaces the process-wide shared relay for WebRTC.
    Lock m_perSocketRelayLock;
    bool m_perSocketRelayReady WTF_GUARDED_BY_LOCK(m_perSocketRelayLock) { false };
    DriftstackRTC::RelayChannel m_perSocketRelay WTF_GUARDED_BY_LOCK(m_perSocketRelayLock);
    bool ensurePerSocketRelay(DriftstackRTC::RelayChannel& out);
#endif
};

static dispatch_queue_t udpSocketQueueSingleton()
{
    static NeverDestroyed<OSObjectPtr<dispatch_queue_t>> queue = adoptOSObject(dispatch_queue_create("WebRTC UDP socket queue", OSObjectPtr { DISPATCH_QUEUE_CONCURRENT }.get()));
    return queue.get().get();
}

NetworkRTCUDPSocketCocoa::NetworkRTCUDPSocketCocoa(WebCore::LibWebRTCSocketIdentifier identifier, NetworkRTCProvider& rtcProvider, const webrtc::SocketAddress& address, Ref<IPC::Connection>&& connection, String&& attributedBundleIdentifier, RTCSocketCreationFlags flags, const WebCore::RegistrableDomain& domain)
    : m_rtcProvider(rtcProvider)
    , m_identifier(identifier)
    , m_connections(NetworkRTCUDPSocketCocoaConnections::create(identifier, rtcProvider, address, WTF::move(connection), WTF::move(attributedBundleIdentifier), flags, domain))
{
}

NetworkRTCUDPSocketCocoa::~NetworkRTCUDPSocketCocoa() = default;

void NetworkRTCUDPSocketCocoa::close()
{
    m_connections->close();
    Ref { m_rtcProvider.get() }->takeSocket(m_identifier);
}

void NetworkRTCUDPSocketCocoa::setOption(int option, int value)
{
    m_connections->setOption(option, value);
}

void NetworkRTCUDPSocketCocoa::sendTo(std::span<const uint8_t> data, const webrtc::SocketAddress& address, const webrtc::AsyncSocketPacketOptions& options)
{
    m_connections->sendTo(data, address, options);
}

static WebRTCNetwork::EcnMarking getECN(nw_content_context_t nwContext, NetworkRTCUDPSocketCocoaConnections::ConnectionStateTracker& connection)
{
    auto protocol = adoptNS(nw_protocol_copy_ip_definition());
    auto metadata = adoptNS(nw_content_context_copy_protocol_metadata(nwContext, protocol.get()));

    if (metadata && nw_protocol_metadata_is_ip(metadata.get())) {
        auto ecnFlag = nw_ip_metadata_get_ecn_flag(metadata.get());
        switch (ecnFlag) {
        case nw_ip_ecn_flag_non_ect:
            return WebRTCNetwork::EcnMarking::kNotEct;
        case nw_ip_ecn_flag_ect_0:
            return WebRTCNetwork::EcnMarking::kEct0;
        case nw_ip_ecn_flag_ect_1:
            return WebRTCNetwork::EcnMarking::kEct1;
        case nw_ip_ecn_flag_ce:
            return WebRTCNetwork::EcnMarking::kCe;
        default:
            return WebRTCNetwork::EcnMarking::kNotEct;
        }
    }

    if (!metadata && connection.shouldLogMissingECN()) {
        connection.didLogMissingECN();
        RELEASE_LOG_INFO(WebRTC, "Could not retrieve the metadata from UDPSocket Context, so use default ECN value");
    }

    return WebRTCNetwork::EcnMarking::kNotEct;
}

static webrtc::SocketAddress socketAddressFromIncomingConnection(nw_connection_t connection)
{
    auto endpoint = adoptNS(nw_connection_copy_endpoint(connection));
    auto type = nw_endpoint_get_type(endpoint.get());
    if (type == nw_endpoint_type_address) {
        auto ipAddress = adoptSystemMalloc(nw_endpoint_copy_address_string(endpoint.get()));
        webrtc::SocketAddress remoteAddress { ipAddress.get(), nw_endpoint_get_port(endpoint.get()) };
        return remoteAddress;
    }
    return webrtc::SocketAddress { nw_endpoint_get_hostname(endpoint.get()), nw_endpoint_get_port(endpoint.get()) };
}

static inline bool isNat64IPAddress(const webrtc::IPAddress& ip)
{
    if (ip.family() != AF_INET)
        return false;

    struct ifaddrs* interfaces;
    if (getifaddrs(&interfaces))
        return true;
    std::unique_ptr<struct ifaddrs> toBeFreed(interfaces);

    for (auto* interface = interfaces; interface; interface = interface->ifa_next) {
        auto* address = dynamicCastToIPV4SocketAddress(*interface->ifa_addr);
        if (!address)
            continue;

        webrtc::IPAddress interfaceAddress { address->sin_addr };
        if (ip != interfaceAddress)
            continue;

        return nw_nat64_does_interface_index_support_nat64(if_nametoindex(interface->ifa_name));
    }

    return false;
}

static std::string computeHostAddress(const webrtc::SocketAddress& address)
{
    if (address.ipaddr().IsNil())
        return address.hostname();

    if (!isNat64IPAddress(address.ipaddr()))
        return address.ipaddr().ToString();

    return "0.0.0.0";
}

NetworkRTCUDPSocketCocoaConnections::NetworkRTCUDPSocketCocoaConnections(WebCore::LibWebRTCSocketIdentifier identifier, NetworkRTCProvider& rtcProvider, const webrtc::SocketAddress& address, Ref<IPC::Connection>&& connection, String&& attributedBundleIdentifier, RTCSocketCreationFlags flags, const WebCore::RegistrableDomain& domain)
    : m_identifier(identifier)
    , m_connection(WTF::move(connection))
    , m_isFirstParty(flags.isFirstParty)
    , m_isKnownTracker(isKnownTracker(domain))
    , m_shouldBypassRelay(flags.isRelayDisabled)
    , m_enableServiceClass(flags.enableServiceClass)
    , m_sourceApplicationBundleIdentifier(rtcProvider.applicationBundleIdentifier())
    , m_sourceApplicationAuditToken(rtcProvider.sourceApplicationAuditToken())
    , m_attributedBundleIdentifier(WTF::move(attributedBundleIdentifier))
{
    auto parameters = adoptNS(nw_parameters_create_secure_udp(NW_PARAMETERS_DISABLE_PROTOCOL, NW_PARAMETERS_DEFAULT_CONFIGURATION));
    {
        auto hostAddress = computeHostAddress(address);
        auto localEndpoint = adoptNS(nw_endpoint_create_host_with_numeric_port(hostAddress.c_str(), 0));
        m_address = { nw_endpoint_get_hostname(localEndpoint.get()), nw_endpoint_get_port(localEndpoint.get()) };
        nw_parameters_set_local_endpoint(parameters.get(), localEndpoint.get());
    }
    configureParameters(parameters.get(), address.family() == AF_INET ? nw_ip_version_4 : nw_ip_version_6);

    m_nwListener = adoptNS(nw_listener_create(parameters.get()));
    nw_listener_set_queue(m_nwListener.get(), udpSocketQueueSingleton());

    // The callback holds a reference to the nw_listener and we clear it when going in nw_listener_state_cancelled state, which is triggered when closing the socket.
    nw_listener_set_state_changed_handler(m_nwListener.get(), makeBlockPtr([nwListener = m_nwListener, connection = m_connection.copyRef(), protectedRTCProvider = Ref { rtcProvider }, identifier = m_identifier, weakThis = ThreadSafeWeakPtr { *this }](nw_listener_state_t state, nw_error_t error) mutable {
        switch (state) {
        case nw_listener_state_invalid:
        case nw_listener_state_waiting:
            break;
        case nw_listener_state_ready:
            protectedRTCProvider->callOnRTCNetworkThread([weakThis, port = nw_listener_get_port(nwListener.get())] {
                if (RefPtr protectedThis = weakThis.get())
                    protectedThis->setListeningPort(port);
            });
            break;
        case nw_listener_state_failed:
            RELEASE_LOG_ERROR(WebRTC, "NetworkRTCUDPSocketCocoaConnections failed with error %d", error ? nw_error_get_error_code(error) : 0);
            protectedRTCProvider->callOnRTCNetworkThread([protectedRTCProvider, identifier] {
                protectedRTCProvider->closeSocket(identifier);
            });
            connection->send(Messages::LibWebRTCNetwork::SignalClose(identifier, -1), 0);
            break;
        case nw_listener_state_cancelled:
            RELEASE_LOG(WebRTC, "NetworkRTCUDPSocketCocoaConnections cancelled listener %" PRIu64, identifier.toUInt64());
            nwListener.clear();
            break;
        }
    }).get());

    nw_listener_set_new_connection_handler(m_nwListener.get(), makeBlockPtr([protectedThis = Ref { *this }](nw_connection_t nwConnection) {
        Locker locker { protectedThis->m_nwConnectionsLock };
        if (protectedThis->m_isClosed)
            return;

        auto remoteAddress = socketAddressFromIncomingConnection(nwConnection);
        ASSERT(remoteAddress != HashTraits<webrtc::SocketAddress>::emptyValue() && !HashTraits<webrtc::SocketAddress>::isDeletedValue(remoteAddress));

        Ref connectionStateTracker = ConnectionStateTracker::create();
        protectedThis->setupNWConnection(nwConnection, connectionStateTracker.get(), remoteAddress);
        if (protectedThis->m_trafficClass)
            nw_connection_reset_traffic_class(nwConnection, *protectedThis->m_trafficClass);

        protectedThis->m_nwConnections.set(remoteAddress, Connection { nwConnection, WTF::move(connectionStateTracker) });
    }).get());

    nw_listener_start(m_nwListener.get());
}

NetworkRTCUDPSocketCocoaConnections::~NetworkRTCUDPSocketCocoaConnections()
{
    ASSERT(m_isClosed);
}

#if PLATFORM(DRIFTSTACK)
// Wave 29-499.332 — establish (once) and return THIS socket's own SOCKS5 UDP ASSOCIATE.
// Both the ICE-address path (setListeningPort) and the send/recv path (ensureRelayConnection)
// call this so they agree on one per-socket relay endpoint with a unique 5-tuple.
bool NetworkRTCUDPSocketCocoaConnections::ensurePerSocketRelay(DriftstackRTC::RelayChannel& out)
{
    Locker locker { m_perSocketRelayLock };
    if (m_perSocketRelayReady) {
        out = m_perSocketRelay;
        return true;
    }
    DriftstackRTC::RelayChannel ch;
    if (DriftstackRTC::establishPerSocketRelay(ch) == DriftstackRTC::BridgeResult::Success
        && !ch.relayHost.isEmpty() && ch.relayPort > 0) {
        m_perSocketRelay = ch;
        m_perSocketRelayReady = true;
        out = ch;
        return true;
    }
    return false;
}
#endif

void NetworkRTCUDPSocketCocoaConnections::setListeningPort(int port)
{
    m_address.SetPort(port);

#if PLATFORM(DRIFTSTACK)
    // Wave 29-397 Slice 2.6: when DRIFTSTACK_CUSTOM_SOCKS5=1 + relay channel
    // established, OVERRIDE the libwebrtc-visible local address to the SOCKS5
    // relay's BND.ADDR / BND.PORT instead of the local Mac IP/port. ICE
    // candidate generation sees the relay endpoint → server-reflexive +
    // relay candidates report the relay endpoint to the WebRTC peer, NOT the
    // Mac fleet's nw_connection-resolved local endpoint.
    //
    // This is the address-side closure paired with Slice 2.4/2.5 (send-side
    // wrap + bridge activation). Together: peer sees SOCKS5 relay as the
    // src of all datagrams; Mac fleet IP never reaches the ICE wire.
    if (DriftstackRTC::isCustomSocks5Active()) {
        DriftstackRTC::RelayChannel channel;
        bool relayOk = ensurePerSocketRelay(channel); // Wave .332 — per-socket relay (unique 5-tuple)
        DriftstackRTC::BridgeResult r = relayOk ? DriftstackRTC::BridgeResult::Success : DriftstackRTC::BridgeResult::UdpAssociateFailed;
        if (relayOk && !channel.relayHost.isEmpty() && channel.relayPort > 0) {
            auto relayHostUtf8 = channel.relayHost.utf8();
            webrtc::SocketAddress relayAddr(relayHostUtf8.data(), channel.relayPort);
            static bool loggedOnce = false;
            if (!loggedOnce) {
                loggedOnce = true;
                WTFLogAlways("[Driftstack-EG-WK-1.8/Task#15] setListeningPort: ICE local-address OVERRIDDEN — was Mac %s:%d → now relay %s:%u. ICE candidates will report relay endpoint, not Mac fleet IP.",
                    m_address.ipaddr().IsNil() ? m_address.hostname().c_str() : m_address.ipaddr().ToString().c_str(),
                    port,
                    relayHostUtf8.data(), channel.relayPort);
            }
            m_connection->send(Messages::LibWebRTCNetwork::SignalAddressReady(m_identifier, RTCNetwork::SocketAddress(relayAddr)), 0);
            return;
        }
        static bool loggedFailOnce = false;
        if (!loggedFailOnce) {
            loggedFailOnce = true;
            WTFLogAlways("[Driftstack-EG-WK-1.8/Task#15] setListeningPort: SOCKS5 active but relay not established (result=%d) — falling through to Mac-local address (LEAK risk; verify proxy reachable)",
                static_cast<int>(r));
        }
    }
#endif

    m_connection->send(Messages::LibWebRTCNetwork::SignalAddressReady(m_identifier, RTCNetwork::SocketAddress(m_address)), 0);
}

void NetworkRTCUDPSocketCocoaConnections::configureParameters(nw_parameters_t parameters, nw_ip_version_t version)
{
    auto protocolStack = adoptNS(nw_parameters_copy_default_protocol_stack(parameters));
    auto options = adoptNS(nw_protocol_stack_copy_internet_protocol(protocolStack.get()));
    nw_ip_options_set_version(options.get(), version);

    setNWParametersApplicationIdentifiers(parameters, m_sourceApplicationBundleIdentifier.data(), m_sourceApplicationAuditToken, m_attributedBundleIdentifier);
    setNWParametersTrackerOptions(parameters, m_shouldBypassRelay, m_isFirstParty, m_isKnownTracker);

    nw_parameters_set_reuse_local_address(parameters, true);

    if (m_enableServiceClass) {
        RELEASE_LOG_INFO(WebRTC, "NetworkRTCUDPSocketCocoaConnections: serviceClass is set to interactive video\n");
        nw_parameters_set_service_class(parameters, nw_service_class_interactive_video);
    }
}

void NetworkRTCUDPSocketCocoaConnections::close()
{
    Locker locker { m_nwConnectionsLock };
    m_isClosed = true;

    for (auto& connection : m_nwConnections.values()) {
        connection.tracker->markAsStopped();
        if (!connection.tracker->hasPendingSend())
            nw_connection_cancel(connection.nwConnection.get());
    }
    m_nwConnections.clear();

    nw_listener_cancel(m_nwListener.get());
    m_nwListener = nullptr;
}

void NetworkRTCUDPSocketCocoaConnections::setOption(int option, int value)
{
    if (option != webrtc::Socket::OPT_DSCP)
        return;

    auto trafficClass = trafficClassFromDSCP(static_cast<webrtc::DiffServCodePoint>(value), m_enableServiceClass);
    if (!trafficClass) {
        RELEASE_LOG_ERROR(WebRTC, "NetworkRTCUDPSocketCocoaConnections has an unexpected DSCP value %d", value);
        return;
    }

    m_trafficClass = trafficClass;

    Locker locker { m_nwConnectionsLock };
    for (auto& connection : m_nwConnections.values())
        nw_connection_reset_traffic_class(connection.nwConnection.get(), *m_trafficClass);
}

static inline void processUDPData(RetainPtr<nw_connection_t>&& nwConnection, Ref<NetworkRTCUDPSocketCocoaConnections::ConnectionStateTracker> connectionStateTracker, int errorCode, Function<void(std::span<const uint8_t>, WebRTCNetwork::EcnMarking)>&& processData)
{
    auto nwConnectionReference = nwConnection.get();
    // Wave 29-499.97 — try bounded nw_connection_receive max=1500 (UDP MTU)
    // instead of nw_connection_receive_message (which empirically still
    // returned 4096-byte buffers despite Apple docs claiming per-message
    // semantics). With max=1500, each call should return one datagram (or
    // truncated if real datagrams >1500 bytes, which is rare for STUN/UDP).
    nw_connection_receive(nwConnectionReference, 1, 1500, makeBlockPtr([nwConnection = WTF::move(nwConnection), processData = WTF::move(processData), errorCode, connectionStateTracker = WTF::move(connectionStateTracker)](dispatch_data_t content, nw_content_context_t context, bool, nw_error_t error) mutable {
        if (content) {
            dispatch_data_apply_span(content, [&](std::span<const uint8_t> data) {
                processData(data, getECN(context, connectionStateTracker.get()));
                return true;
            });
        }
        if (connectionStateTracker->isStopped() || nw_content_context_get_is_final(context))
            return;

        if (error && errorCode != nw_error_get_error_code(error)) {
            errorCode = nw_error_get_error_code(error);
            RELEASE_LOG_ERROR(WebRTC, "NetworkRTCUDPSocketCocoaConnections failed processing UDP data with error %d", errorCode);
        }
        processUDPData(WTF::move(nwConnection), WTF::move(connectionStateTracker), errorCode, WTF::move(processData));
    }).get());
}

#if PLATFORM(DRIFTSTACK)
// Wave 29-397 Slice 2.4.b.2: lazy-init the relay nw_connection_t on first
// SOCKS5-active sendTo. Bound to BND.ADDR:BND.PORT from
// DriftstackRTC::establishRelayChannel (cached by the SharedRelayState
// singleton — first call performs handshake + udpAssociate; subsequent
// calls return cached).
//
// Returns true if relay channel is up + connection ready. False if
// establish failed (caller falls through to direct nw_connection unless
// DRIFTSTACK_REQUIRE_PROXY=1 hard-block kicked in at createUDPSocket time
// per Slice 2.5.b).
//
// Must be called under m_nwConnectionsLock by the caller.
bool NetworkRTCUDPSocketCocoaConnections::ensureRelayConnection() WTF_REQUIRES_LOCK(m_nwConnectionsLock)
{
    // Wave 29-499.89 — granular trace inside ensureRelayConnection. The .88
    // trace showed execution hung INSIDE this function with m_nwConnectionsLock
    // held. Need to know exact pause point.
    WTFLogAlways("[Wave29-499.89] ensureRelayConnection: ENTRY (m_relayStarted=%d, m_relayConnection=%p)",
        m_relayStarted ? 1 : 0, m_relayConnection.get());

    if (m_relayStarted) {
        // Wave .335 — readiness keys on the BSD socket (the default sole relay path),
        // not m_relayConnection (created only under the legacy NWCONN_RELAY=1 flag).
        bool ready = m_relayBsdSocket >= 0 || m_relayConnection != nullptr;
        WTFLogAlways("[Wave29-499.89] ensureRelayConnection: EXIT-EARLY (m_relayStarted=true, ready=%d, bsdFd=%d)",
            ready ? 1 : 0, m_relayBsdSocket);
        return ready;
    }

    WTFLogAlways("[Wave29-499.332] ensureRelayConnection: about to establish PER-SOCKET relay...");
    DriftstackRTC::RelayChannel channel;
    bool relayOk = ensurePerSocketRelay(channel); // Wave .332 — same per-socket relay as setListeningPort
    WTFLogAlways("[Wave29-499.332] ensureRelayConnection: per-socket relay ok=%d, relayHost=%s, relayPort=%u",
        relayOk ? 1 : 0, channel.relayHost.utf8().data(), channel.relayPort);
    if (!relayOk) {
        m_relayStarted = true;
        return false;
    }

    auto relayHostUtf8 = channel.relayHost.utf8(); // needed by both the nw_connection + BSD paths

    // Wave 29-499.335 — by DEFAULT do not create the nw_connection relay at all. Creating
    // m_relayConnection (a UDP nw_connection to the relay BND) triggers the Task#16
    // interpose, which builds its OWN relay connection that RECEIVES inbound — splitting
    // the relay: WebRTC SENDS via the BSD socket (sendTo) but the interpose STEALS inbound,
    // so TURN CreatePermission/data responses never reach the BSD socket and TURN times out
    // after a successful Allocate. Skipping m_relayConnection makes the BSD socket the SOLE
    // send+receive path (one source 5-tuple, one inbound reader). Reversible:
    // DRIFTSTACK_WEBRTC_NWCONN_RELAY=1 restores the legacy nw_connection relay.
    static const bool s_startNwConnRelay = [] {
        const char* e = getenv("DRIFTSTACK_WEBRTC_NWCONN_RELAY");
        return e && e[0] == '1';
    }();
    if (s_startNwConnRelay) {
    auto parameters = adoptNS(nw_parameters_create_secure_udp(NW_PARAMETERS_DISABLE_PROTOCOL, NW_PARAMETERS_DEFAULT_CONFIGURATION));
    configureParameters(parameters.get(), nw_ip_version_4);
    if (m_trafficClass)
        nw_parameters_set_traffic_class(parameters.get(), *m_trafficClass);

    auto endpoint = adoptNS(nw_endpoint_create_host(relayHostUtf8.data(), String::number(channel.relayPort).utf8().data()));
    m_relayConnection = adoptNS(nw_connection_create(endpoint.get(), parameters.get()));
    m_relayTracker = ConnectionStateTracker::create();

    nw_connection_set_queue(m_relayConnection.get(), udpSocketQueueSingleton());

    nw_connection_set_state_changed_handler(m_relayConnection.get(), makeBlockPtr([tracker = Ref { *m_relayTracker }](nw_connection_state_t state, _Nullable nw_error_t error) {
        RELEASE_LOG_ERROR_IF(state == nw_connection_state_failed, WebRTC, "[Driftstack-EG-WK-1.8/Task#15] m_relayConnection failed with error %d", error ? nw_error_get_error_code(error) : 0);
        if (state == nw_connection_state_failed || state == nw_connection_state_cancelled)
            tracker->markAsStopped();
    }).get());

    // Wave 29-397 Slice 2.x: recv-side §7 unwrap + SignalReadPacket dispatch.
    // Every inbound datagram on the relay channel is a SOCKS5 §7 frame
    // (RSV + FRAG + ATYP + DST.ADDR + DST.PORT + DATA). Strip the framing
    // to recover the original peer's IP/port + the application payload;
    // dispatch upstream to libwebrtc via SignalReadPacket. Drops malformed
    // frames silently (logged once-per-class) — bad frames must not crash
    // the relay channel.
    processUDPData(RetainPtr<nw_connection_t> { m_relayConnection }, Ref { *m_relayTracker }, 0, [identifier = m_identifier, ipcConnection = m_connection.copyRef()](std::span<const uint8_t> frame, WebRTCNetwork::EcnMarking ecn) {
        // Wave 29-499.91 — diagnostic hex dump of incoming relay frames
        // (first 5 receives, first 64 bytes each). The earlier trace showed
        // unwrap producing source 45.17.110.89:56453 + 4086-byte payload,
        // which doesn't match RFC 1928 §7 (source should be the STUN
        // server's IP, not the SOCKS5 relay's own IP). Need raw bytes.
        {
            static std::atomic<unsigned> s_recvCount { 0 };
            unsigned thisRecv = s_recvCount.fetch_add(1, std::memory_order_relaxed) + 1;
            if (thisRecv <= 5) {
                size_t hexLen = std::min<size_t>(frame.size(), 32);
                // Pull first 32 bytes as individual %02x args (32-arg log).
                auto b = [&frame](size_t i) -> unsigned {
                    return i < frame.size() ? static_cast<unsigned>(frame[i]) : 0;
                };
                WTFLogAlways("[Wave29-499.91] recv#%u: frameSize=%zu — first %zu bytes: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
                    thisRecv, frame.size(), hexLen,
                    b(0), b(1), b(2), b(3), b(4), b(5), b(6), b(7),
                    b(8), b(9), b(10), b(11), b(12), b(13), b(14), b(15),
                    b(16), b(17), b(18), b(19), b(20), b(21), b(22), b(23),
                    b(24), b(25), b(26), b(27), b(28), b(29), b(30), b(31));
            }
        }
        DriftstackRTC::UnwrappedDatagram unwrapped;
        DriftstackRTC::BridgeResult r = DriftstackRTC::unwrapIncomingDatagram(frame, unwrapped);
        if (r != DriftstackRTC::BridgeResult::Success) {
            static bool loggedUnwrapFailOnce = false;
            if (!loggedUnwrapFailOnce) {
                loggedUnwrapFailOnce = true;
                WTFLogAlways("[Driftstack-EG-WK-1.8/Task#15] m_relayConnection recv: unwrap FAILED (result=%d, frameSize=%zu) — dropping",
                    static_cast<int>(r), frame.size());
            }
            return;
        }
        // Wave 29-499.98 — filter out gost keepalive frames. gost sends
        // periodic §7-headers-with-empty-payload from its own egress IP
        // as keepalives. These confuse libwebrtc which would try to STUN-
        // parse them. Real STUN responses come from real STUN servers
        // (74.x for Google, 162.x for Cloudflare). Drop frames whose
        // source is the SOCKS5 proxy IP itself OR have empty/tiny
        // payloads (<8 bytes can't be a valid STUN message).
        if (unwrapped.payload.size() < 8) {
            static std::atomic<unsigned> s_keepalivesDropped { 0 };
            unsigned n = s_keepalivesDropped.fetch_add(1, std::memory_order_relaxed) + 1;
            if (n == 1 || (n & (n - 1)) == 0) { // log on 1, 2, 4, 8, 16...
                WTFLogAlways("[Driftstack-EG-WK-1.8/Task#15/Wave29-499.98] m_relayConnection recv: DROPPED gost-keepalive #%u (payload=%zu bytes from %s:%u)",
                    n, unwrapped.payload.size(),
                    unwrapped.sourceHost.utf8().data(), unwrapped.sourcePort);
            }
            return;
        }
        // Filter: if source host is the SOCKS5 proxy itself (gost), drop.
        // Real STUN responses come from real STUN servers, not gost.
        // Use WTF::String operations to avoid raw-pointer unsafe-buffer warnings.
        {
            String proxyEnvStr = String::fromLatin1(getenv("DRIFTSTACK_SOCKS5_PROXY"));
            size_t colonIdx = proxyEnvStr.find(':');
            if (colonIdx != notFound && colonIdx > 0) {
                String proxyIp = proxyEnvStr.substring(0, colonIdx);
                if (unwrapped.sourceHost == proxyIp) {
                    static std::atomic<unsigned> s_proxyDropped { 0 };
                    unsigned n = s_proxyDropped.fetch_add(1, std::memory_order_relaxed) + 1;
                    if (n == 1 || (n & (n - 1)) == 0) {
                        WTFLogAlways("[Driftstack-EG-WK-1.8/Task#15/Wave29-499.98] m_relayConnection recv: DROPPED proxy-sourced frame #%u (gost keepalive/echo from %s:%u, payload=%zu bytes)",
                            n, unwrapped.sourceHost.utf8().data(), unwrapped.sourcePort, unwrapped.payload.size());
                    }
                    return;
                }
            }
        }
        webrtc::IPAddress webrtcIp;
        // Wave 29-499.14 — close IPv6 TODO in WebRTC SOCKS5 §7 unwrap path.
        // ATYP=0x01 (IPv4) is the common case; ATYP=0x04 (IPv6) now handled
        // for SOCKS5 servers that relay IPv6 traffic (e.g., STUN/TURN over
        // IPv6 peer endpoints). ATYP=0x03 (domain) on RECEIVE is still
        // dropped because resolving domains at the client side would defeat
        // the SOCKS5 proxy resolution discipline (and leak DNS).
        struct in_addr sourceAddr4 { };
        struct in6_addr sourceAddr6 { };
        if (inet_pton(AF_INET, unwrapped.sourceHost.utf8().data(), &sourceAddr4) == 1) {
            webrtcIp = webrtc::IPAddress { sourceAddr4 };
        } else if (inet_pton(AF_INET6, unwrapped.sourceHost.utf8().data(), &sourceAddr6) == 1) {
            webrtcIp = webrtc::IPAddress { sourceAddr6 };
            static bool loggedIpv6Once = false;
            if (!loggedIpv6Once) {
                loggedIpv6Once = true;
                WTFLogAlways("[Driftstack-EG-WK-1.8/Task#15] m_relayConnection recv: FIRST IPv6 source '%s' from §7 unwrap accepted (ATYP=0x04 path)",
                    unwrapped.sourceHost.utf8().data());
            }
        } else {
            // ATYP=0x03 domain form OR malformed — drop. Resolving at client
            // would defeat the no-DNS-leak property of proxy-side resolution.
            static bool loggedDropOnce = false;
            if (!loggedDropOnce) {
                loggedDropOnce = true;
                WTFLogAlways("[Driftstack-EG-WK-1.8/Task#15] m_relayConnection recv: domain-form (ATYP=0x03) or malformed source '%s' — dropping (client-side resolution would leak DNS)",
                    unwrapped.sourceHost.utf8().data());
            }
            return;
        }
        // Wave 29-499.102 + .221 — apply sentinel remap (direct map first,
        // then hostname-fallback learn-on-first-recv).
        webrtc::IPAddress remappedIp = webrtcIp;
        String apparentSourceHost = unwrapped.sourceHost;
        String sentinel = DriftstackRTC::lookupSentinelForRealIp(unwrapped.sourceHost);
        if (sentinel.isEmpty())
            sentinel = DriftstackRTC::learnRealIpFromPendingPort(unwrapped.sourceHost, unwrapped.sourcePort);
        if (!sentinel.isEmpty()) {
            apparentSourceHost = sentinel;
            struct in_addr sentinelAddr { };
            if (inet_pton(AF_INET, sentinel.utf8().data(), &sentinelAddr) == 1)
                remappedIp = webrtc::IPAddress { sentinelAddr };
            static bool loggedFirstNwRemapOnce = false;
            if (!loggedFirstNwRemapOnce) {
                loggedFirstNwRemapOnce = true;
                WTFLogAlways("[Wave29-499.102+221/nw_connection] inbound source REMAP: realIp=%s → sentinel=%s",
                    unwrapped.sourceHost.utf8().data(), sentinel.utf8().data());
            }
        }
        static bool loggedRecvOnce = false;
        if (!loggedRecvOnce) {
            loggedRecvOnce = true;
            WTFLogAlways("[Driftstack-EG-WK-1.8/Task#15] m_relayConnection recv: FIRST unwrapped datagram from %s:%u (%zu payload bytes). Dispatching SignalReadPacket to libwebrtc.",
                apparentSourceHost.utf8().data(), unwrapped.sourcePort, unwrapped.payload.size());
        }
        SUPPRESS_MEMORY_UNSAFE_CAST ipcConnection->send(Messages::LibWebRTCNetwork::SignalReadPacket { identifier, unwrapped.payload.span(), RTCNetwork::IPAddress(remappedIp), unwrapped.sourcePort, webrtc::TimeMicros(), ecn }, 0);
    });

    nw_connection_start(m_relayConnection.get());

    static bool loggedOnce = false;
    if (!loggedOnce) {
        loggedOnce = true;
        WTFLogAlways("[Driftstack-EG-WK-1.8/Wave29-499.335] m_relayConnection STARTED (legacy nw_connection relay path; default is BSD-only).");
    }
    } // end if (s_startNwConnRelay) — Wave .335: BSD socket is the sole relay path by default

    // Wave 29-499.99 — also set up a raw BSD UDP socket as PARALLEL path.
    // Per V-2026-05-21-W29-499.98 empirical finding, Apple's nw_connection_t
    // doesn't reliably traverse SOCKS5 UDP_ASSOCIATE. Python via raw BSD
    // UDP socket on the same proxy works perfectly. Use BSD socket as the
    // ACTUAL outbound path going forward; nw_connection_t stays for backwards
    // compatibility / state tracking only.
    m_relayBndHost = channel.relayHost;
    m_relayBndPort = channel.relayPort;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        WTFLogAlways("[Driftstack-EG-WK-1.8/Task#15/Wave29-499.99] BSD socket() failed errno=%d — falling back to nw_connection_t path", errno);
    } else {
        struct sockaddr_in localAddr { };
        localAddr.sin_family = AF_INET;
        localAddr.sin_addr.s_addr = htonl(INADDR_ANY);
        localAddr.sin_port = 0;
        if (bind(fd, reinterpret_cast<struct sockaddr*>(&localAddr), sizeof(localAddr)) < 0) {
            WTFLogAlways("[Wave29-499.99] BSD bind() failed errno=%d", errno);
            ::close(fd);
        } else {
            socklen_t localLen = sizeof(localAddr);
            getsockname(fd, reinterpret_cast<struct sockaddr*>(&localAddr), &localLen);
            uint16_t boundPort = ntohs(localAddr.sin_port);
            m_relayBsdSocket = fd;
            // Set up GCD dispatch source for inbound on this BSD fd.
            m_relayBsdReadSource = adoptOSObject(dispatch_source_create(
                DISPATCH_SOURCE_TYPE_READ, fd, 0, udpSocketQueueSingleton()));
            int capturedFd = fd;
            auto identifier = m_identifier;
            auto ipcConnection = m_connection.copyRef();
            dispatch_source_set_event_handler(m_relayBsdReadSource.get(), [capturedFd, identifier, ipcConnection]() mutable {
                uint8_t buf[65536];
                struct sockaddr_in src { };
                socklen_t srcLen = sizeof(src);
                ssize_t n = recvfrom(capturedFd, buf, sizeof(buf), 0,
                    reinterpret_cast<struct sockaddr*>(&src), &srcLen);
                if (n <= 0)
                    return;
                std::span<const uint8_t> frame { buf, static_cast<size_t>(n) };
                static std::atomic<unsigned> s_bsdRecvCount { 0 };
                unsigned thisRecv = s_bsdRecvCount.fetch_add(1, std::memory_order_relaxed) + 1;
                if (thisRecv <= 5) {
                    auto b = [&frame](size_t i) -> unsigned {
                        return i < frame.size() ? static_cast<unsigned>(frame[i]) : 0;
                    };
                    WTFLogAlways("[Wave29-499.99] BSD recvfrom#%u: %zd bytes from %s:%u — first 32 hex: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
                        thisRecv, n, inet_ntoa(src.sin_addr), ntohs(src.sin_port),
                        b(0), b(1), b(2), b(3), b(4), b(5), b(6), b(7),
                        b(8), b(9), b(10), b(11), b(12), b(13), b(14), b(15),
                        b(16), b(17), b(18), b(19), b(20), b(21), b(22), b(23),
                        b(24), b(25), b(26), b(27), b(28), b(29), b(30), b(31));
                }
                // §7 unwrap + SignalReadPacket dispatch
                DriftstackRTC::UnwrappedDatagram unwrapped;
                DriftstackRTC::BridgeResult r = DriftstackRTC::unwrapIncomingDatagram(frame, unwrapped);
                if (r != DriftstackRTC::BridgeResult::Success) {
                    static bool loggedFailOnce = false;
                    if (!loggedFailOnce) {
                        loggedFailOnce = true;
                        WTFLogAlways("[Wave29-499.99] BSD unwrap FAIL result=%d frameSize=%zd", static_cast<int>(r), n);
                    }
                    return;
                }
                // Wave 29-499.102 — source remap: if the real STUN server IP
                // has a sentinel registered (.93 outbound resolve populated it),
                // present the source AS the sentinel so libwebrtc's StunPort
                // source-validation accepts the response (it checks source
                // against the request's destination, which is the sentinel).
                String apparentSourceHost = unwrapped.sourceHost;
                String sentinel = DriftstackRTC::lookupSentinelForRealIp(unwrapped.sourceHost);
                if (sentinel.isEmpty()) {
                    // Wave 29-499.221 — hostname-fallback learn: try to bind
                    // by matching source port to a pending sentinel recorded
                    // at outbound time (Twilio anycast + other hostnames not
                    // in the .94 hardcoded map).
                    sentinel = DriftstackRTC::learnRealIpFromPendingPort(unwrapped.sourceHost, unwrapped.sourcePort);
                    if (!sentinel.isEmpty()) {
                        static bool loggedFirstLearnOnce = false;
                        if (!loggedFirstLearnOnce) {
                            loggedFirstLearnOnce = true;
                            WTFLogAlways("[Wave29-499.221] inbound LEARN: realIp=%s:%u → sentinel=%s (bound from pending-by-port at recv; hostname-fallback flow)",
                                unwrapped.sourceHost.utf8().data(), unwrapped.sourcePort, sentinel.utf8().data());
                        }
                    }
                }
                if (!sentinel.isEmpty()) {
                    apparentSourceHost = sentinel;
                    static bool loggedFirstRemapOnce = false;
                    if (!loggedFirstRemapOnce) {
                        loggedFirstRemapOnce = true;
                        WTFLogAlways("[Wave29-499.102] inbound source REMAP: realIp=%s → sentinel=%s (libwebrtc StunPort source-validation will accept)",
                            unwrapped.sourceHost.utf8().data(), sentinel.utf8().data());
                    }
                }
                struct in_addr a4 { };
                if (inet_pton(AF_INET, apparentSourceHost.utf8().data(), &a4) != 1)
                    return;
                webrtc::IPAddress peerIp { a4 };
                static bool loggedFirstUnwrapOnce = false;
                if (!loggedFirstUnwrapOnce) {
                    loggedFirstUnwrapOnce = true;
                    WTFLogAlways("[Wave29-499.99] BSD FIRST unwrapped: realSource=%s:%u apparentSource=%s payload=%zu bytes — dispatching SignalReadPacket to libwebrtc",
                        unwrapped.sourceHost.utf8().data(), unwrapped.sourcePort,
                        apparentSourceHost.utf8().data(), unwrapped.payload.size());
                }
                SUPPRESS_MEMORY_UNSAFE_CAST ipcConnection->send(Messages::LibWebRTCNetwork::SignalReadPacket {
                    identifier, unwrapped.payload.span(),
                    RTCNetwork::IPAddress(peerIp), unwrapped.sourcePort,
                    webrtc::TimeMicros(), WebRTCNetwork::EcnMarking::kNotEct }, 0);
            });
            dispatch_resume(m_relayBsdReadSource.get());
            WTFLogAlways("[Wave29-499.99] BSD UDP socket SET UP: fd=%d localPort=%u target=%s:%u — recv loop armed",
                fd, boundPort, channel.relayHost.utf8().data(), channel.relayPort);
        }
    }

    m_relayStarted = true;
    return m_relayBsdSocket >= 0 || m_relayConnection != nullptr; // Wave .335 — BSD is the default relay
}
#endif

auto NetworkRTCUDPSocketCocoaConnections::createNWConnection(const webrtc::SocketAddress& remoteAddress) -> Connection
{
    auto parameters = adoptNS(nw_parameters_create_secure_udp(NW_PARAMETERS_DISABLE_PROTOCOL, NW_PARAMETERS_DEFAULT_CONFIGURATION));
    {
        auto hostAddress = m_address.ipaddr().ToString();
        if (m_address.ipaddr().IsNil())
            hostAddress = m_address.hostname();

        nw_parameters_allow_sharing_port_with_listener(parameters.get(), m_nwListener.get());
        auto localEndpoint = adoptNS(nw_endpoint_create_host_with_numeric_port(hostAddress.c_str(), m_address.port()));
        nw_parameters_set_local_endpoint(parameters.get(), localEndpoint.get());
    }
    configureParameters(parameters.get(), remoteAddress.family() == AF_INET ? nw_ip_version_4 : nw_ip_version_6);

    if (m_trafficClass)
        nw_parameters_set_traffic_class(parameters.get(), *m_trafficClass);

    auto remoteHostAddress = remoteAddress.ipaddr().ToString();
    if (remoteAddress.ipaddr().IsNil())
        remoteHostAddress = remoteAddress.hostname();
    auto host = adoptNS(nw_endpoint_create_host(remoteHostAddress.c_str(), String::number(remoteAddress.port()).utf8().data()));
    auto nwConnection = adoptNS(nw_connection_create(host.get(), parameters.get()));

    auto connectionStateTracker = ConnectionStateTracker::create();

    setupNWConnection(nwConnection.get(), connectionStateTracker.get(), remoteAddress);
    return { WTF::move(nwConnection), WTF::move(connectionStateTracker) };
}

void NetworkRTCUDPSocketCocoaConnections::setupNWConnection(nw_connection_t nwConnection, ConnectionStateTracker& connectionStateTracker, const webrtc::SocketAddress& remoteAddress)
{
    nw_connection_set_queue(nwConnection, udpSocketQueueSingleton());

    nw_connection_set_state_changed_handler(nwConnection, makeBlockPtr([connectionStateTracker = Ref  { connectionStateTracker }](nw_connection_state_t state, _Nullable nw_error_t error) {
        RELEASE_LOG_ERROR_IF(state == nw_connection_state_failed, WebRTC, "NetworkRTCUDPSocketCocoaConnections connection failed with error %d", error ? nw_error_get_error_code(error) : 0);
        if (state == nw_connection_state_failed || state == nw_connection_state_cancelled)
            connectionStateTracker->markAsStopped();
    }).get());

    processUDPData(nwConnection, Ref  { connectionStateTracker }, 0, [identifier = m_identifier, connection = m_connection.copyRef(), ip = remoteAddress.ipaddr(), port = remoteAddress.port()](std::span<const uint8_t> message, WebRTCNetwork::EcnMarking ecn) mutable {
        connection->send(Messages::LibWebRTCNetwork::SignalReadPacket { identifier, message, RTCNetwork::IPAddress(ip), port, webrtc::TimeMicros(), ecn }, 0);
    });

    nw_connection_start(nwConnection);
}

void NetworkRTCUDPSocketCocoaConnections::sendTo(std::span<const uint8_t> data, const webrtc::SocketAddress& remoteAddress, const webrtc::AsyncSocketPacketOptions& options)
{
    bool isInCorrectValue = (remoteAddress == HashTraits<webrtc::SocketAddress>::emptyValue()) || HashTraits<webrtc::SocketAddress>::isDeletedValue(remoteAddress);
    ASSERT(!isInCorrectValue);
    if (isInCorrectValue)
        return;

#if PLATFORM(DRIFTSTACK)
    // Wave 29-499.86 — diagnostic: log first sendTo invocation regardless
    // of any gating. Distinguishes "sendTo not called at all" from
    // "sendTo called but redirect-path branch missed". Empirical (post-
    // .86 verify): sendTo IS invoked (libwebrtc routes STUN through
    // NetworkRTCUDPSocketCocoa correctly).
    //
    // Wave 29-499.87 — ALSO log SOCKS5-active state at function entry so
    // we can distinguish "active=false → fell through to legacy direct
    // path" from "active=true → reached redirect block".
    {
        static bool loggedFirstSendToOnce = false;
        if (!loggedFirstSendToOnce) {
            loggedFirstSendToOnce = true;
            auto hostStr = remoteAddress.HostAsURIString();
            bool socks5Active = DriftstackRTC::isCustomSocks5Active();
            const char* customSocks5Env = getenv("DRIFTSTACK_CUSTOM_SOCKS5");
            const char* socks5ProxyEnv = getenv("DRIFTSTACK_SOCKS5_PROXY");
            WTFLogAlways("[Driftstack-EG-WK-1.8/Task#15/Wave29-499.86] sendTo: FIRST entry — dest=%s:%u, payload=%zu bytes, isCustomSocks5Active=%d (CUSTOM_SOCKS5='%s', SOCKS5_PROXY='%s')",
                hostStr.c_str(), remoteAddress.port(), data.size(),
                socks5Active ? 1 : 0,
                customSocks5Env ? customSocks5Env : "(unset)",
                socks5ProxyEnv ? socks5ProxyEnv : "(unset)");
        }
    }

    // Wave 29-397 Slice 2.4.b.3: data-plane SOCKS5 redirect. When the
    // bridge is active + relay channel established, the datagram is
    // §7-wrapped and sent through m_relayConnection (single nw_connection
    // bound to SOCKS5 BND.ADDR:BND.PORT) instead of the per-peer
    // m_nwConnections map. The Mac fleet IP is replaced by the relay's
    // local-side endpoint on the wire — actual SOCKS5 routing.
    //
    // Replaces Slice 2.4's wrap-validate-but-still-send-direct behavior.
    // Falls through to legacy per-peer path only when:
    //   - bridge inactive (DRIFTSTACK_CUSTOM_SOCKS5 != 1), OR
    //   - relay establish failed AND DRIFTSTACK_REQUIRE_PROXY != 1
    //     (Slice 2.5.b hard-blocks REQUIRE_PROXY=1 at createUDPSocket
    //     time so this fall-through should be unreachable in that mode).
    // Wave 29-499.336 — INTERPOSE-ONLY routing test. When set, skip the bridge/BSD
    // relay entirely so sendTo falls through to the per-peer nw_connection path, which
    // the Task#16 interpose redirects through createRelayConnectionForQuic + nw_framer §7
    // (the SAME relay that carries QUIC end-to-end). This unifies WebRTC onto ONE §7
    // relay: per-peer connection to one TURN server = one coherent relay/5-tuple for the
    // whole Allocate→CreatePermission→Send/Data lifecycle, instead of splitting between
    // the bridge BSD socket and the interpose (which lost CreatePermission responses).
    static const bool s_interposeOnly = [] {
        const char* e = getenv("DRIFTSTACK_WEBRTC_INTERPOSE_ONLY");
        return e && e[0] == '1'; // DEFAULT OFF — interpose-only drops all inbound (per-peer
                                  // recv not wired to libwebrtc); keep the bridge/BSD path
                                  // (allocate + STUN work). Both paths proven incomplete →
                                  // unifying rewrite required (see V-log .336).
    }();
    if (DriftstackRTC::isCustomSocks5Active() && !s_interposeOnly) {
        // Wave 29-499.88 — unconditional first-call trace through the SOCKS5
        // redirect block so we know exactly which sub-branch is taken (the
        // existing loggedXOnce statics gave a misleading silent trace).
        static std::atomic<unsigned> s_sendToCallCount { 0 };
        unsigned thisCall = s_sendToCallCount.fetch_add(1, std::memory_order_relaxed) + 1;
        bool traceThisCall = (thisCall <= 5);
        if (traceThisCall)
            WTFLogAlways("[Wave29-499.88] sendTo call#%u: entered SOCKS5 redirect block", thisCall);

        bool relayReady;
        RetainPtr<nw_connection_t> relayConn;
        RefPtr<ConnectionStateTracker> relayTracker;
        {
            Locker locker { m_nwConnectionsLock };
            relayReady = ensureRelayConnection();
            if (relayReady) {
                relayConn = m_relayConnection;
                relayTracker = m_relayTracker;
            }
        }
        if (traceThisCall)
            WTFLogAlways("[Wave29-499.88] sendTo call#%u: ensureRelayConnection returned relayReady=%d, relayConn=%p",
                thisCall, relayReady ? 1 : 0, relayConn.get());

        if (relayReady) { // Wave .335 — BSD-only default: don't require relayConn (nw_connection)
            Vector<uint8_t> framed;
            DriftstackRTC::BridgeResult wr = DriftstackRTC::wrapOutgoingDatagram(remoteAddress, data, framed);
            if (traceThisCall)
                WTFLogAlways("[Wave29-499.88] sendTo call#%u: wrapOutgoingDatagram result=%d (Success=0), framedSize=%zu",
                    thisCall, static_cast<int>(wr), framed.size());
            // Wave 29-499.92 — hex-dump OUTBOUND framed bytes (first 5 sends).
            // Compare with Python's working IPv4-form §7 frame to determine
            // if WebKit's wrap format is what gost expects.
            if (traceThisCall && wr == DriftstackRTC::BridgeResult::Success) {
                auto fb = [&framed](size_t i) -> unsigned {
                    return i < framed.size() ? static_cast<unsigned>(framed[i]) : 0;
                };
                WTFLogAlways("[Wave29-499.92] sendTo call#%u: OUTBOUND frame first 32 bytes: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
                    thisCall,
                    fb(0), fb(1), fb(2), fb(3), fb(4), fb(5), fb(6), fb(7),
                    fb(8), fb(9), fb(10), fb(11), fb(12), fb(13), fb(14), fb(15),
                    fb(16), fb(17), fb(18), fb(19), fb(20), fb(21), fb(22), fb(23),
                    fb(24), fb(25), fb(26), fb(27), fb(28), fb(29), fb(30), fb(31));
            }
            if (wr == DriftstackRTC::BridgeResult::Success) {
                static bool loggedRedirectOnce = false;
                if (!loggedRedirectOnce) {
                    loggedRedirectOnce = true;
                    WTFLogAlways("[Driftstack-EG-WK-1.8/Task#15] sendTo: REDIRECT ACTIVE — datagram %zu→%zu bytes via SOCKS5 §7.",
                        data.size(), framed.size());
                }
                // Wave 29-499.99 — prefer BSD socket send over nw_connection_send.
                // BSD socket avoids the Apple nw_connection UDP-over-SOCKS5
                // bug that returned only gost keepalive frames on inbound.
                int bsdFd = -1;
                String bndHost;
                uint16_t bndPort = 0;
                {
                    Locker locker { m_nwConnectionsLock };
                    bsdFd = m_relayBsdSocket;
                    bndHost = m_relayBndHost;
                    bndPort = m_relayBndPort;
                }
                if (bsdFd >= 0 && !bndHost.isEmpty() && bndPort > 0) {
                    struct sockaddr_in dst { };
                    dst.sin_family = AF_INET;
                    dst.sin_port = htons(bndPort);
                    auto bndHostUtf8 = bndHost.utf8();
                    inet_pton(AF_INET, bndHostUtf8.data(), &dst.sin_addr);
                    ssize_t sent = sendto(bsdFd, framed.span().data(), framed.size(), 0,
                        reinterpret_cast<struct sockaddr*>(&dst), sizeof(dst));
                    int sendErrno = (sent < 0) ? errno : 0;
                    static bool loggedBsdSendOnce = false;
                    if (!loggedBsdSendOnce) {
                        loggedBsdSendOnce = true;
                        WTFLogAlways("[Wave29-499.99] sendTo BSD: sendto fd=%d → %s:%u, %zu bytes → returned %zd errno=%d",
                            bsdFd, bndHostUtf8.data(), bndPort, framed.size(), sent, sendErrno);
                    }
                    // Notify libwebrtc that the send completed (immediately).
                    m_connection->send(Messages::LibWebRTCNetwork::SignalSentPacket {
                        m_identifier, options.packet_id, webrtc::TimeMillis() }, 0);
                    return;
                }
                // Fallback to nw_connection_send (legacy path) — only when the BSD socket
                // isn't available AND the nw_connection relay exists (NWCONN_RELAY=1).
                // Wave .335 — in BSD-only default, relayConn is null; if the BSD send above
                // didn't fire, drop the datagram rather than deref a null relay connection.
                if (!relayConn || !relayTracker) {
                    WTFLogAlways("[Wave29-499.335] sendTo: BSD relay socket unavailable and no nw_connection relay — dropping datagram (proxy egress not ready).");
                    return;
                }
                Ref<ConnectionStateTracker> trackerRef = relayTracker.releaseNonNull();
                trackerRef->incrementPendingSendCount();
                OSObjectPtr framedValue = adoptOSObject(dispatch_data_create(framed.span().data(), framed.size(), nullptr, DISPATCH_DATA_DESTRUCTOR_DEFAULT));
                nw_connection_send(relayConn.get(), framedValue.get(), NW_CONNECTION_DEFAULT_MESSAGE_CONTEXT, true, makeBlockPtr([identifier = m_identifier, ipcConnection = m_connection.copyRef(), trackerRef, options](_Nullable nw_error_t error) mutable {
                    RELEASE_LOG_ERROR_IF(error, WebRTC, "[Driftstack-EG-WK-1.8/Task#15] m_relayConnection send failed with error %d", error ? nw_error_get_error_code(error) : 0);
                    ipcConnection->send(Messages::LibWebRTCNetwork::SignalSentPacket { identifier, options.packet_id, webrtc::TimeMillis() }, 0);
                    trackerRef->decrementPendingSendCount();
                }).get());
                return; // bypass per-peer path
            }
            // Wave 29-499.88 — wrap-FAIL branch always logs (no static gate)
            // for the first 5 calls; ensures we don't miss this state.
            if (traceThisCall)
                WTFLogAlways("[Wave29-499.88] sendTo call#%u: wrap-FAIL branch — wr=%d, falling through to legacy direct",
                    thisCall, static_cast<int>(wr));
            static bool loggedWrapFailOnce = false;
            if (!loggedWrapFailOnce) {
                loggedWrapFailOnce = true;
                WTFLogAlways("[Driftstack-EG-WK-1.8/Task#15] sendTo: §7 wrap FAILED (result=%d) — falling through to direct nw_connection (LEAK)",
                    static_cast<int>(wr));
            }
        } else {
            // Wave 29-499.88 — no-relay branch unconditional log
            if (traceThisCall)
                WTFLogAlways("[Wave29-499.88] sendTo call#%u: no-relay branch — relayReady=%d relayConn=%p, falling through to legacy direct",
                    thisCall, relayReady ? 1 : 0, relayConn.get());
            static bool loggedNoRelayOnce = false;
            if (!loggedNoRelayOnce) {
                loggedNoRelayOnce = true;
                WTFLogAlways("[Driftstack-EG-WK-1.8/Task#15] sendTo: bridge active but m_relayConnection unavailable — falling through to direct nw_connection (LEAK ALLOWED; set DRIFTSTACK_REQUIRE_PROXY=1 to enforce egress lock via createUDPSocket hard-block)");
            }
        }
        if (traceThisCall)
            WTFLogAlways("[Wave29-499.88] sendTo call#%u: EXITING SOCKS5 block (will hit legacy direct nw_connection path next)",
                thisCall);
    }
#endif

    auto connection = [&] {
        Locker locker { m_nwConnectionsLock };
        return m_nwConnections.ensure(remoteAddress, [this, &remoteAddress] {
            return createNWConnection(remoteAddress);
        }).iterator->value;
    }();
    connection.tracker->incrementPendingSendCount();

    OSObjectPtr value = adoptOSObject(dispatch_data_create(data.data(), data.size(), nullptr, DISPATCH_DATA_DESTRUCTOR_DEFAULT));
    nw_connection_send(connection.nwConnection.get(), value.get(), NW_CONNECTION_DEFAULT_MESSAGE_CONTEXT, true, makeBlockPtr([identifier = m_identifier, ipcConnection = m_connection.copyRef(), connection, options](_Nullable nw_error_t error) mutable {
        RELEASE_LOG_ERROR_IF(error, WebRTC, "NetworkRTCUDPSocketCocoaConnections::sendTo failed with error %d", error ? nw_error_get_error_code(error) : 0);
        ipcConnection->send(Messages::LibWebRTCNetwork::SignalSentPacket { identifier, options.packet_id, webrtc::TimeMillis() }, 0);

        connection.tracker->decrementPendingSendCount();
        if (!connection.tracker->hasPendingSend() && connection.tracker->isStopped()) {
            nw_connection_cancel(connection.nwConnection.get());
            connection = { };
        }
    }).get());
}

} // namespace WebKit

#endif // USE(LIBWEBRTC) && PLATFORM(COCOA)
