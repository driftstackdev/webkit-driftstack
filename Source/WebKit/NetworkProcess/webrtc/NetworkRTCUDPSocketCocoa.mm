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
        DriftstackRTC::BridgeResult r = DriftstackRTC::establishRelayChannel(channel);
        if (r == DriftstackRTC::BridgeResult::Success && !channel.relayHost.isEmpty() && channel.relayPort > 0) {
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
    nw_connection_receive(nwConnectionReference, 1, std::numeric_limits<uint32_t>::max(), makeBlockPtr([nwConnection = WTF::move(nwConnection), processData = WTF::move(processData), errorCode, connectionStateTracker = WTF::move(connectionStateTracker)](dispatch_data_t content, nw_content_context_t context, bool, nw_error_t error) mutable {
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
    if (m_relayStarted)
        return m_relayConnection != nullptr;

    DriftstackRTC::RelayChannel channel;
    DriftstackRTC::BridgeResult r = DriftstackRTC::establishRelayChannel(channel);
    if (r != DriftstackRTC::BridgeResult::Success) {
        m_relayStarted = true;
        return false;
    }

    auto parameters = adoptNS(nw_parameters_create_secure_udp(NW_PARAMETERS_DISABLE_PROTOCOL, NW_PARAMETERS_DEFAULT_CONFIGURATION));
    configureParameters(parameters.get(), nw_ip_version_4);
    if (m_trafficClass)
        nw_parameters_set_traffic_class(parameters.get(), *m_trafficClass);

    auto relayHostUtf8 = channel.relayHost.utf8();
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
        static bool loggedRecvOnce = false;
        if (!loggedRecvOnce) {
            loggedRecvOnce = true;
            WTFLogAlways("[Driftstack-EG-WK-1.8/Task#15] m_relayConnection recv: FIRST unwrapped datagram from %s:%u (%zu payload bytes). Dispatching SignalReadPacket to libwebrtc.",
                unwrapped.sourceHost.utf8().data(), unwrapped.sourcePort, unwrapped.payload.size());
        }
        SUPPRESS_MEMORY_UNSAFE_CAST ipcConnection->send(Messages::LibWebRTCNetwork::SignalReadPacket { identifier, unwrapped.payload.span(), RTCNetwork::IPAddress(webrtcIp), unwrapped.sourcePort, webrtc::TimeMicros(), ecn }, 0);
    });

    nw_connection_start(m_relayConnection.get());

    static bool loggedOnce = false;
    if (!loggedOnce) {
        loggedOnce = true;
        WTFLogAlways("[Driftstack-EG-WK-1.8/Task#15] m_relayConnection STARTED — bound to relay %s:%u. All outbound UDP datagrams flow through this connection (Slice 2.4.b.3 redirect activates).",
            relayHostUtf8.data(), channel.relayPort);
    }
    m_relayStarted = true;
    return true;
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
    if (DriftstackRTC::isCustomSocks5Active()) {
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
        if (relayReady && relayConn) {
            Vector<uint8_t> framed;
            DriftstackRTC::BridgeResult wr = DriftstackRTC::wrapOutgoingDatagram(remoteAddress, data, framed);
            if (wr == DriftstackRTC::BridgeResult::Success) {
                static bool loggedRedirectOnce = false;
                if (!loggedRedirectOnce) {
                    loggedRedirectOnce = true;
                    WTFLogAlways("[Driftstack-EG-WK-1.8/Task#15] sendTo: REDIRECT to m_relayConnection ACTIVE — datagram %zu→%zu bytes via SOCKS5 §7. Per-peer m_nwConnections bypassed.",
                        data.size(), framed.size());
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
            static bool loggedWrapFailOnce = false;
            if (!loggedWrapFailOnce) {
                loggedWrapFailOnce = true;
                WTFLogAlways("[Driftstack-EG-WK-1.8/Task#15] sendTo: §7 wrap FAILED (result=%d) — falling through to direct nw_connection (LEAK)",
                    static_cast<int>(wr));
            }
        } else {
            static bool loggedNoRelayOnce = false;
            if (!loggedNoRelayOnce) {
                loggedNoRelayOnce = true;
                WTFLogAlways("[Driftstack-EG-WK-1.8/Task#15] sendTo: bridge active but m_relayConnection unavailable — falling through to direct nw_connection (LEAK ALLOWED; set DRIFTSTACK_REQUIRE_PROXY=1 to enforce egress lock via createUDPSocket hard-block)");
            }
        }
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
