/*
 * DriftstackQuicSocks5Bridge.mm — Phase A scaffold for Task #16 (EG-WK-
 * 1.10) QUIC SOCKS5 routing. See header for design context + 12-slice
 * roadmap.
 */

#import "config.h"
#import "DriftstackQuicSocks5Bridge.h"

#if PLATFORM(DRIFTSTACK)

#import "DriftstackQuicSocks5Exports.h"
#import "DriftstackSocks5Client.h"
#import "DriftstackSocks5Framing.h"
#import "DriftstackSocks5TCPFramer.h"

#import "../webrtc/DriftstackRTCSocks5Bridge.h"
#import <Foundation/Foundation.h>
#import <Network/Network.h>
// Wave 29-499.84 — BSD socket headers for IP-form endpoint extraction.
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <atomic>
#include <stdlib.h>
#include <wtf/Assertions.h>
#include <wtf/HashMap.h>
#include <wtf/Lock.h>
#include <wtf/NeverDestroyed.h>
#include <wtf/cocoa/SpanCocoa.h>

namespace WebKit {

namespace DriftstackQuic {

// Wave 29-397 Slice 16.6 (Task #16 EG-WK-1.10 production observability):
// atomic counters for SOCKS5 QUIC code path activity. Counters expose
// internal state to:
//   - the harness (via the extern "C" diagnostic accessors at file end)
//   - periodic summary logs (every 100 events of any type)
//
// These counters cover the full lifecycle of a SOCKS5-routed QUIC packet:
// outgoing wraps, incoming unwraps, framer fires, relay setup failures,
// endpoint extraction failures. Customer-facing dashboards in the harness
// poll these to detect SOCKS5-routing degradation (e.g., elevated unwrap
// failures may signal proxy MITM).
//
// All counters are std::atomic to avoid lock overhead on the hot data path.
struct Slice16_6_Counters {
    std::atomic<uint64_t> wrapOutgoingFires { 0 };
    std::atomic<uint64_t> wrapOutgoingFailures { 0 };
    std::atomic<uint64_t> unwrapIncomingFires { 0 };
    std::atomic<uint64_t> unwrapIncomingFailures { 0 };
    std::atomic<uint64_t> framerOutputFires { 0 };
    std::atomic<uint64_t> framerInputFires { 0 };
    std::atomic<uint64_t> framerWithoutDestination { 0 };
    std::atomic<uint64_t> framerWrapFailures { 0 };
    std::atomic<uint64_t> relayEstablishFailures { 0 };
    std::atomic<uint64_t> relayConnectionCreateFailures { 0 };
    std::atomic<uint64_t> attachFramerFailures { 0 };
    std::atomic<uint64_t> endpointExtractFailures { 0 };
};

static Slice16_6_Counters& slice16_6_counters()
{
    static NeverDestroyed<Slice16_6_Counters> s_counters;
    return s_counters.get();
}

// Periodic summary log: every 100 events (sum across all counters), emit
// a snapshot. Throttled to avoid log spam at high throughput.
static void maybeLogCounterSummary()
{
    auto& c = slice16_6_counters();
    uint64_t totalFires = c.wrapOutgoingFires.load(std::memory_order_relaxed)
        + c.unwrapIncomingFires.load(std::memory_order_relaxed)
        + c.framerOutputFires.load(std::memory_order_relaxed)
        + c.framerInputFires.load(std::memory_order_relaxed);
    if (totalFires == 0 || totalFires % 100)
        return;
    WTFLogAlways("[Driftstack-EG-WK-1.10/Task#16/Slice16.6] counter snapshot — "
        "wraps=%llu (fail=%llu)  unwraps=%llu (fail=%llu)  framer_out=%llu  framer_in=%llu  "
        "no_dest=%llu  framer_wrap_fail=%llu  relay_est_fail=%llu  conn_create_fail=%llu  "
        "attach_fail=%llu  endpoint_fail=%llu",
        static_cast<unsigned long long>(c.wrapOutgoingFires.load()),
        static_cast<unsigned long long>(c.wrapOutgoingFailures.load()),
        static_cast<unsigned long long>(c.unwrapIncomingFires.load()),
        static_cast<unsigned long long>(c.unwrapIncomingFailures.load()),
        static_cast<unsigned long long>(c.framerOutputFires.load()),
        static_cast<unsigned long long>(c.framerInputFires.load()),
        static_cast<unsigned long long>(c.framerWithoutDestination.load()),
        static_cast<unsigned long long>(c.framerWrapFailures.load()),
        static_cast<unsigned long long>(c.relayEstablishFailures.load()),
        static_cast<unsigned long long>(c.relayConnectionCreateFailures.load()),
        static_cast<unsigned long long>(c.attachFramerFailures.load()),
        static_cast<unsigned long long>(c.endpointExtractFailures.load()));
}

bool isCustomSocks5Active()
{
    const char* customSocks5 = getenv("DRIFTSTACK_CUSTOM_SOCKS5");
    const char* socks5Proxy = getenv("DRIFTSTACK_SOCKS5_PROXY");
    return customSocks5 && customSocks5[0] == '1'
        && socks5Proxy && socks5Proxy[0];
}

bool endpointToHostPort(nw_endpoint_t endpoint, String& outHost, uint16_t& outPort)
{
    if (!endpoint)
        return false;
    nw_endpoint_type_t type = nw_endpoint_get_type(endpoint);

    if (type == nw_endpoint_type_host || type == nw_endpoint_type_url) {
        const char* hostname = nw_endpoint_get_hostname(endpoint);
        if (!hostname || !hostname[0])
            return false;
        outHost = String::fromUTF8(hostname);
        outPort = nw_endpoint_get_port(endpoint);

        static bool loggedHostnameOnce = false;
        if (!loggedHostnameOnce && isCustomSocks5Active()) {
            loggedHostnameOnce = true;
            WTFLogAlways("[Driftstack-EG-WK-1.10/Task#16] endpointToHostPort: FIRST hostname extract — '%s':%u. Slice 16.4/16.4.b call sites pass this to wrapOutgoingQuicPacket for ATYP=0x03 framing.",
                hostname, static_cast<unsigned>(outPort));
        }
        return true;
    }

    if (type == nw_endpoint_type_address) {
        // Wave 29-499.84 — IP-form endpoint handling. CFNetwork resolves
        // DNS before nw_connection_create, so QUIC + plain-UDP endpoints
        // arrive as IP literals (nw_endpoint_type_address). Convert
        // sockaddr to text via inet_ntop; caller wraps as ATYP=0x01
        // (IPv4) or ATYP=0x04 (IPv6) in §6/§7 framing.
        //
        // Pre-fix: returned false → createRelayConnectionForQuic logged
        // "endpointToHostPort failed for originalEndpoint — §7 wrap will
        // see empty destination (gost will reject)" → all QUIC + raw UDP
        // datagrams dropped at proxy. Empirically: HTTP/3 + WebRTC both
        // failed despite Slice 16.7.b interpose firing correctly.
        const struct sockaddr* sa = nw_endpoint_get_address(endpoint);
        if (!sa)
            return false;
        char ipBuf[INET6_ADDRSTRLEN] = { };
        const void* addrPtr = nullptr;
        uint16_t port = 0;
        if (sa->sa_family == AF_INET) {
            const struct sockaddr_in* sin = reinterpret_cast<const struct sockaddr_in*>(sa);
            addrPtr = &sin->sin_addr;
            port = ntohs(sin->sin_port);
        } else if (sa->sa_family == AF_INET6) {
            const struct sockaddr_in6* sin6 = reinterpret_cast<const struct sockaddr_in6*>(sa);
            addrPtr = &sin6->sin6_addr;
            port = ntohs(sin6->sin6_port);
        } else {
            return false;
        }
        if (!inet_ntop(sa->sa_family, addrPtr, ipBuf, sizeof(ipBuf)))
            return false;
        outHost = String::fromUTF8(ipBuf);
        outPort = port;
        static bool loggedAddressOnce = false;
        if (!loggedAddressOnce && isCustomSocks5Active()) {
            loggedAddressOnce = true;
            WTFLogAlways("[Driftstack-EG-WK-1.10/Task#16/Wave29-499.84] endpointToHostPort: FIRST IP-form extract — '%s':%u (AF_%s). Wraps as SOCKS5 ATYP=0x%02x — UDP relay can now reach destination.",
                ipBuf, static_cast<unsigned>(port),
                sa->sa_family == AF_INET ? "INET" : "INET6",
                sa->sa_family == AF_INET ? 0x01 : 0x04);
        }
        return true;
    }

    return false;
}

// Wave 29-397 Slice 16.4.b.4: nw_protocol_stack inspector.
// Walks the parameters' default protocol stack via
// nw_protocol_stack_iterate_application_protocols, comparing each layer's
// definition against nw_protocol_copy_quic_definition() via
// nw_protocol_definition_is_equal. Returns true if any application-layer
// protocol matches QUIC.
//
// Performance: called on every nw_connection_create when interpose is
// active. Must be FAST (<100ns on non-QUIC paths). Apple's iterator +
// definition-equality comparison are both inline-friendly; empirically
// negligible vs the cost of nw_connection_create itself.
//
// Recursion safety: this function does NOT call nw_connection_create —
// it only inspects already-built nw_parameters. No interpose-recursion
// risk.
bool parametersUseQuic(nw_parameters_t parameters)
{
    if (!parameters)
        return false;

    nw_protocol_stack_t stack = nw_parameters_copy_default_protocol_stack(parameters);
    if (!stack)
        return false;

    RetainPtr<nw_protocol_definition_t> quicDef = adoptNS(nw_protocol_copy_quic_definition());
    __block bool foundQuic = false;

    nw_protocol_stack_iterate_application_protocols(stack, ^(nw_protocol_options_t appOptions) {
        if (foundQuic)
            return;
        nw_protocol_definition_t appDef = nw_protocol_options_copy_definition(appOptions);
        if (appDef && quicDef && nw_protocol_definition_is_equal(appDef, quicDef.get()))
            foundQuic = true;
        if (appDef)
            nw_release(appDef);
    });
    nw_release(stack);

    static bool loggedHitOnce = false;
    if (foundQuic && !loggedHitOnce && isCustomSocks5Active()) {
        loggedHitOnce = true;
        WTFLogAlways("[Driftstack-EG-WK-1.10/Task#16] parametersUseQuic: FIRST QUIC match in protocol stack — Slice 16.4.b.4 inspector ACTIVE. Subsequent matches silent.");
    }
    return foundQuic;
}

// Wave 29-499 Slice 16.7.b — detect plain UDP transport (WebRTC, WebTransport
// raw UDP, raw datagram nw_connection). When SOCKS5 is active and the
// parameters are UDP-transport, the interpose must redirect through
// createRelayConnectionForQuic so the UDP datagrams flow through the
// SOCKS5 UDP_ASSOCIATE relay (existing infrastructure) instead of leaking
// the real client IP to the destination.
//
// Approach: pull the transport protocol options from the default protocol
// stack and compare its definition to nw_protocol_copy_udp_definition().
// Since QUIC parameters built with nw_parameters_create_secure_udp ALSO
// have UDP as transport, parametersUseUdpTransport will return true for
// both plain-UDP and QUIC; callers should typically OR the two predicates
// or just use this helper as the broader gate.
//
// Recursion safety: like parametersUseQuic, this function only inspects
// nw_parameters — no nw_connection_create call — so it cannot trigger
// interpose recursion.
bool parametersUseUdpTransport(nw_parameters_t parameters)
{
    if (!parameters)
        return false;

    nw_protocol_stack_t stack = nw_parameters_copy_default_protocol_stack(parameters);
    if (!stack)
        return false;

    nw_protocol_options_t transport = nw_protocol_stack_copy_transport_protocol(stack);
    nw_release(stack);
    if (!transport)
        return false;

    nw_protocol_definition_t transportDef = nw_protocol_options_copy_definition(transport);
    nw_release(transport);
    if (!transportDef)
        return false;

    RetainPtr<nw_protocol_definition_t> udpDef = adoptNS(nw_protocol_copy_udp_definition());
    bool isUdp = udpDef && nw_protocol_definition_is_equal(transportDef, udpDef.get());
    nw_release(transportDef);

    static bool loggedHitOnce = false;
    if (isUdp && !loggedHitOnce && isCustomSocks5Active()) {
        loggedHitOnce = true;
        WTFLogAlways("[Driftstack-EG-WK-1.10/Task#16/Slice16.7.b] parametersUseUdpTransport: FIRST UDP-transport match (covers WebRTC + QUIC + raw datagram nw_connection) — relay path will engage on subsequent UDP nw_connection_create calls. Subsequent matches silent.");
    }
    return isUdp;
}

BridgeResult wrapOutgoingQuicPacket(const String& destinationHost, uint16_t destinationPort, std::span<const uint8_t> payload, Vector<uint8_t>& out)
{
    if (!isCustomSocks5Active())
        return BridgeResult::Socks5Disabled;

    if (destinationHost.isEmpty() || destinationPort == 0)
        return BridgeResult::ProtocolError;
    if (destinationHost.utf8().length() > 255)
        return BridgeResult::DomainTooLong;

    Socks5Endpoint destination;
    destination.host = destinationHost;
    destination.port = destinationPort;

    RetainPtr<NSData> payloadData = adoptNS([[NSData alloc] initWithBytes:payload.data() length:payload.size()]);
    RetainPtr<NSData> framed = DriftstackSocks5Client::wrapUdpDatagram(destination, payloadData.get());
    if (!framed) {
        slice16_6_counters().wrapOutgoingFailures.fetch_add(1, std::memory_order_relaxed);
        WTFLogAlways("[Driftstack-EG-WK-1.10/Task#16] wrapOutgoingQuicPacket: §7 frame helper returned nil for dest=%s:%u",
            destinationHost.utf8().data(), destinationPort);
        return BridgeResult::ProtocolError;
    }

    slice16_6_counters().wrapOutgoingFires.fetch_add(1, std::memory_order_relaxed);
    maybeLogCounterSummary();

    static bool loggedSuccessOnce = false;
    if (!loggedSuccessOnce) {
        loggedSuccessOnce = true;
        WTFLogAlways("[Driftstack-EG-WK-1.10/Task#16] wrapOutgoingQuicPacket: FIRST wrap — dest=%s:%u, %zu→%zu bytes. Task #15 §7 helper reuse confirmed.",
            destinationHost.utf8().data(), destinationPort, payload.size(), static_cast<size_t>([framed.get() length]));
    }

    out.clear();
    out.append(WTF::span(framed.get()));
    return BridgeResult::Success;
}

BridgeResult unwrapIncomingQuicPacket(std::span<const uint8_t> frame, UnwrappedQuicPacket& out)
{
    if (!isCustomSocks5Active())
        return BridgeResult::Socks5Disabled;

    RetainPtr<NSData> frameData = adoptNS([[NSData alloc] initWithBytes:frame.data() length:frame.size()]);
    Socks5Endpoint source;
    RetainPtr<NSData> payload = DriftstackSocks5Client::unwrapUdpDatagram(frameData.get(), source);
    if (!payload) {
        slice16_6_counters().unwrapIncomingFailures.fetch_add(1, std::memory_order_relaxed);
        WTFLogAlways("[Driftstack-EG-WK-1.10/Task#16] unwrapIncomingQuicPacket: §7 frame helper returned nil (protocol error)");
        return BridgeResult::ProtocolError;
    }

    out.sourceHost = source.host;
    out.sourcePort = source.port;
    out.payload.clear();
    out.payload.append(WTF::span(payload.get()));

    slice16_6_counters().unwrapIncomingFires.fetch_add(1, std::memory_order_relaxed);
    maybeLogCounterSummary();

    static bool loggedSuccessOnce = false;
    if (!loggedSuccessOnce) {
        loggedSuccessOnce = true;
        WTFLogAlways("[Driftstack-EG-WK-1.10/Task#16] unwrapIncomingQuicPacket: FIRST unwrap — src=%s:%u, %zu→%zu bytes (§7 helper reuse from Task #15)",
            out.sourceHost.utf8().data(), out.sourcePort, frame.size(), out.payload.size());
    }
    return BridgeResult::Success;
}

// Wave 29-397 Slice 16.4.b.6.b: nw_framer_definition for §7 wrap/unwrap.
// Bidirectional UDP-message processor: outgoing CFNetwork datagrams get
// §7-wrapped via Socks5Framing::wrap before transit to the relay;
// incoming relay datagrams get §7-unwrapped via Socks5Framing::unwrap
// before delivery to CFNetwork.
//
// Per-framer destination (the original peer endpoint extracted at
// createRelayConnectionForQuic time): stashed in a small process-wide
// table keyed by the framer pointer. Phase B atomic scope: one
// destination per relay connection (h3 to a single server is one
// destination). Multi-destination per relay (future advanced scenario)
// not required at v1.0; can be added by promoting the table to per-
// stream metadata.
struct FramerDestination {
    String host;
    uint16_t port { 0 };
};

struct FramerDestinationRegistry {
    Lock lock;
    HashMap<uintptr_t, FramerDestination> byFramerPtr WTF_GUARDED_BY_LOCK(lock);
    // Most-recently-set destination — used by start_handler since the
    // framer pointer is the only handle we have at that point. Single-
    // connection scenarios (v1.0 norm) write/read in lockstep order
    // (createRelayConnectionForQuic → nw_connection_create → start_handler
    // fires synchronously on the same thread for the just-set framer).
    FramerDestination pendingDestination WTF_GUARDED_BY_LOCK(lock);
};

static FramerDestinationRegistry& framerDestinationRegistry()
{
    static NeverDestroyed<FramerDestinationRegistry> s_registry;
    return s_registry.get();
}

static void setPendingFramerDestination(const String& host, uint16_t port)
{
    auto& registry = framerDestinationRegistry();
    Locker locker { registry.lock };
    registry.pendingDestination.host = host;
    registry.pendingDestination.port = port;
}

static FramerDestination claimDestinationForFramer(nw_framer_t framer)
{
    auto& registry = framerDestinationRegistry();
    Locker locker { registry.lock };
    auto pending = registry.pendingDestination;
    registry.byFramerPtr.set(reinterpret_cast<uintptr_t>(framer), pending);
    return pending;
}

static FramerDestination destinationForFramer(nw_framer_t framer)
{
    auto& registry = framerDestinationRegistry();
    Locker locker { registry.lock };
    auto it = registry.byFramerPtr.find(reinterpret_cast<uintptr_t>(framer));
    if (it == registry.byFramerPtr.end())
        return { };
    return it->value;
}

static nw_protocol_definition_t driftstackSocks5FramerDefinition()
{
    static nw_protocol_definition_t s_definition = nullptr;
    static dispatch_once_t s_token;
    dispatch_once(&s_token, ^{
        s_definition = nw_framer_create_definition("DriftstackSocks5Framer",
            NW_FRAMER_CREATE_FLAGS_DEFAULT,
            ^nw_framer_start_result_t (nw_framer_t framer) {
                // Claim the pending destination for this framer instance.
                FramerDestination destination = claimDestinationForFramer(framer);

                // OUTPUT handler — CFNetwork → wire. §7-wrap with destination.
                nw_framer_set_output_handler(framer, ^(nw_framer_t framerInner, nw_framer_message_t message, size_t messageLength, bool isComplete) {
                    nw_framer_parse_output(framerInner, messageLength, messageLength, nullptr, ^size_t (uint8_t* buffer, size_t bufferLength, bool isComplete) {
                        FramerDestination dest = destinationForFramer(framerInner);
                        if (dest.host.isEmpty() || dest.port == 0) {
                            // No destination metadata; pass through (will fail at
                            // gost as malformed SOCKS5 frame, but no crash).
                            slice16_6_counters().framerWithoutDestination.fetch_add(1, std::memory_order_relaxed);
                            nw_framer_write_output(framerInner, buffer, bufferLength);
                            return bufferLength;
                        }
                        Socks5Framing::Endpoint framingDest { dest.host, dest.port };
                        WTF_ALLOW_UNSAFE_BUFFER_USAGE_BEGIN
                        std::span<const uint8_t> payloadSpan = unsafeMakeSpan(buffer, bufferLength);
                        WTF_ALLOW_UNSAFE_BUFFER_USAGE_END
                        Vector<uint8_t> framed;
                        if (Socks5Framing::wrap(framingDest, payloadSpan, framed)) {
                            nw_framer_write_output(framerInner, framed.span().data(), framed.size());
                            slice16_6_counters().framerOutputFires.fetch_add(1, std::memory_order_relaxed);
                            maybeLogCounterSummary();
                        } else {
                            slice16_6_counters().framerWrapFailures.fetch_add(1, std::memory_order_relaxed);
                            nw_framer_write_output(framerInner, buffer, bufferLength);
                        }
                        static bool loggedOnce = false;
                        if (!loggedOnce) {
                            loggedOnce = true;
                            WTFLogAlways("[Driftstack-EG-WK-1.10/Task#16] nw_framer output: FIRST §7-wrap fired — dest=%s:%u, %zu→%zu bytes",
                                dest.host.utf8().data(), dest.port, bufferLength, static_cast<size_t>(framed.size()));
                        }
                        return bufferLength;
                    });
                });

                // INPUT handler — wire → CFNetwork. §7-unwrap + deliver payload only.
                nw_framer_set_input_handler(framer, ^size_t (nw_framer_t framerInner) {
                    nw_framer_parse_input(framerInner, 1, UINT16_MAX, nullptr, ^size_t (uint8_t* buffer, size_t bufferLength, bool isComplete) {
                        WTF_ALLOW_UNSAFE_BUFFER_USAGE_BEGIN
                        std::span<const uint8_t> frameSpan = unsafeMakeSpan(buffer, bufferLength);
                        WTF_ALLOW_UNSAFE_BUFFER_USAGE_END
                        Socks5Framing::Endpoint source;
                        Vector<uint8_t> payload;
                        if (Socks5Framing::unwrap(frameSpan, source, payload)) {
                            nw_framer_deliver_input(framerInner, payload.span().data(), payload.size(), nw_framer_message_create(framerInner), true);
                            slice16_6_counters().framerInputFires.fetch_add(1, std::memory_order_relaxed);
                            maybeLogCounterSummary();
                            static bool loggedOnce = false;
                            if (!loggedOnce) {
                                loggedOnce = true;
                                WTFLogAlways("[Driftstack-EG-WK-1.10/Task#16] nw_framer input: FIRST §7-unwrap fired — src=%s:%u, %zu→%zu bytes",
                                    source.host.utf8().data(), source.port, bufferLength, payload.size());
                            }
                        } else {
                            // Pass through on protocol error — CFNetwork sees raw
                            // bytes, will surface its own QUIC error.
                            slice16_6_counters().unwrapIncomingFailures.fetch_add(1, std::memory_order_relaxed);
                            nw_framer_deliver_input(framerInner, buffer, bufferLength, nw_framer_message_create(framerInner), true);
                        }
                        return bufferLength;
                    });
                    return 0;
                });

                static bool loggedStartOnce = false;
                if (!loggedStartOnce) {
                    loggedStartOnce = true;
                    WTFLogAlways("[Driftstack-EG-WK-1.10/Task#16] nw_framer started Phase B — destination=%s:%u. Socks5Framing::wrap/unwrap active on output/input handlers.",
                        destination.host.utf8().data(), destination.port);
                }
                return nw_framer_start_result_ready;
            });
    });
    return s_definition;
}

RetainPtr<nw_connection_t> createRelayConnectionForQuic(nw_endpoint_t originalEndpoint, nw_parameters_t parameters)
{
    if (!isCustomSocks5Active())
        return nullptr;

    // Wave 29-397 Slice 16.4.b.6: bind a fresh nw_connection_t to the SOCKS5
    // BND.ADDR:BND.PORT obtained from Task #15's SharedRelayState (DriftstackRTC
    // bridge — ONE UDP ASSOCIATE channel serves WebRTC + WebTransport + future
    // HTTP/3 simultaneously).
    //
    // §7 wrap/unwrap framing on the QUIC payload is NOT YET applied at this
    // layer — CFNetwork's QUIC stack writes raw QUIC packets to the returned
    // connection. Slice 16.4.b.6.b will add a custom nw_framer_definition that
    // injects/strips the §7 header on send/receive. Without that framer, the
    // SOCKS5 relay receives malformed (un-framed) QUIC packets — the relay
    // logs a protocol error. The CONNECTION IS BOUND CORRECTLY; the framer
    // is the missing piece for clean SOCKS5 transit.
    //
    // Slice 16.4.b.6 atomic scope: connection creation + bind + start. Framer
    // injection deferred to 16.4.b.6.b for clarity (one architectural decision
    // per atomic slice).

    DriftstackRTC::RelayChannel channel;
    DriftstackRTC::BridgeResult r = DriftstackRTC::establishRelayChannel(channel);
    if (r != DriftstackRTC::BridgeResult::Success) {
        slice16_6_counters().relayEstablishFailures.fetch_add(1, std::memory_order_relaxed);
        static bool loggedFailOnce = false;
        if (!loggedFailOnce) {
            loggedFailOnce = true;
            WTFLogAlways("[Driftstack-EG-WK-1.10/Task#16] createRelayConnectionForQuic: relay establish failed (result=%d) — fall through; CFNetwork QUIC will use direct UDP (LEAK)",
                static_cast<int>(r));
        }
        return nullptr;
    }

    // Build nw_parameters for the relay-bound connection (UDP only, no QUIC
    // layer — we want raw UDP to the relay endpoint; the original QUIC
    // params describe what CFNetwork wants to do, but the wire layer to the
    // proxy is plain UDP).
    auto relayParams = adoptNS(nw_parameters_create_secure_udp(NW_PARAMETERS_DISABLE_PROTOCOL, NW_PARAMETERS_DEFAULT_CONFIGURATION));

    // Wave 29-397 Slice 16.4.b.6.b Phase B: attach §7 framer to the relay
    // connection's protocol stack. The framer's output handler §7-wraps
    // outgoing CFNetwork bytes with the original peer's host:port; input
    // handler §7-unwraps incoming bytes from the relay before delivery
    // to CFNetwork.
    //
    // Destination metadata: extracted from originalEndpoint via
    // endpointToHostPort (Slice 16.4.b.8 helper) and stashed in the
    // framer-destination registry just before nw_connection_create — the
    // framer's start_handler claims it for the new framer instance.
    String destHost;
    uint16_t destPort = 0;
    if (endpointToHostPort(originalEndpoint, destHost, destPort))
        setPendingFramerDestination(destHost, destPort);
    else {
        slice16_6_counters().endpointExtractFailures.fetch_add(1, std::memory_order_relaxed);
        WTFLogAlways("[Driftstack-EG-WK-1.10/Task#16] createRelayConnectionForQuic: endpointToHostPort failed for originalEndpoint — §7 wrap will see empty destination (gost will reject)");
    }

    nw_protocol_definition_t framerDef = driftstackSocks5FramerDefinition();
    if (framerDef) {
        auto framerOptions = adoptNS(nw_framer_create_options(framerDef));
        auto stack = adoptNS(nw_parameters_copy_default_protocol_stack(relayParams.get()));
        nw_protocol_stack_prepend_application_protocol(stack.get(), framerOptions.get());
    }

    auto relayHostUtf8 = channel.relayHost.utf8();
    auto relayEndpoint = adoptNS(nw_endpoint_create_host(relayHostUtf8.data(), String::number(channel.relayPort).utf8().data()));

    auto relayConnection = adoptNS(nw_connection_create(relayEndpoint.get(), relayParams.get()));
    if (!relayConnection) {
        slice16_6_counters().relayConnectionCreateFailures.fetch_add(1, std::memory_order_relaxed);
        WTFLogAlways("[Driftstack-EG-WK-1.10/Task#16] createRelayConnectionForQuic: nw_connection_create returned nil");
        return nullptr;
    }

    static bool loggedSuccessOnce = false;
    if (!loggedSuccessOnce) {
        loggedSuccessOnce = true;
        WTFLogAlways("[Driftstack-EG-WK-1.10/Task#16] createRelayConnectionForQuic: relay-bound nw_connection created — relay=%s:%u. Slice 16.4.b.6.b will add §7 nw_framer for clean SOCKS5 transit; current connection accepts raw UDP only.",
            relayHostUtf8.data(), channel.relayPort);
    }

    return relayConnection;
}

// Wave 29-397 Slice 16.5 (Task #16 EG-WK-1.10): attach §7 framer to
// caller-owned nw_parameters_t. Used by WebTransport hook (Network-
// TransportSessionCocoa.mm) where we cannot swap the parameters wholesale
// — they were built by createParameters() with webtransport-specific
// configuration. We instead prepend the framer to the existing protocol
// stack and stash the destination metadata so the framer's start_handler
// claims it for the new framer instance.
bool attachSocks5FramerToParameters(nw_parameters_t parameters, const String& destinationHost, uint16_t destinationPort)
{
    if (!isCustomSocks5Active())
        return false;
    if (!parameters)
        return false;
    if (destinationHost.isEmpty() || destinationPort == 0)
        return false;

    DriftstackRTC::RelayChannel channel;
    DriftstackRTC::BridgeResult r = DriftstackRTC::establishRelayChannel(channel);
    if (r != DriftstackRTC::BridgeResult::Success) {
        slice16_6_counters().relayEstablishFailures.fetch_add(1, std::memory_order_relaxed);
        slice16_6_counters().attachFramerFailures.fetch_add(1, std::memory_order_relaxed);
        static bool loggedFailOnce = false;
        if (!loggedFailOnce) {
            loggedFailOnce = true;
            WTFLogAlways("[Driftstack-EG-WK-1.10/Task#16] attachSocks5FramerToParameters: relay establish failed (result=%d) — caller falls through to direct UDP (LEAK)",
                static_cast<int>(r));
        }
        return false;
    }

    nw_protocol_definition_t framerDef = driftstackSocks5FramerDefinition();
    if (!framerDef) {
        slice16_6_counters().attachFramerFailures.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    setPendingFramerDestination(destinationHost, destinationPort);

    auto framerOptions = adoptNS(nw_framer_create_options(framerDef));
    auto stack = adoptNS(nw_parameters_copy_default_protocol_stack(parameters));
    if (!stack) {
        slice16_6_counters().attachFramerFailures.fetch_add(1, std::memory_order_relaxed);
        WTFLogAlways("[Driftstack-EG-WK-1.10/Task#16] attachSocks5FramerToParameters: nw_parameters_copy_default_protocol_stack returned nil");
        return false;
    }
    nw_protocol_stack_prepend_application_protocol(stack.get(), framerOptions.get());

    static bool loggedSuccessOnce = false;
    if (!loggedSuccessOnce) {
        loggedSuccessOnce = true;
        WTFLogAlways("[Driftstack-EG-WK-1.10/Task#16] attachSocks5FramerToParameters: §7 framer prepended to caller parameters — dest=%s:%u, relay=%s:%u. Caller must now swap connection-group endpoint to getRelayEndpoint().",
            destinationHost.utf8().data(), destinationPort,
            channel.relayHost.utf8().data(), channel.relayPort);
    }

    return true;
}

RetainPtr<nw_endpoint_t> getRelayEndpoint()
{
    if (!isCustomSocks5Active())
        return nullptr;

    DriftstackRTC::RelayChannel channel;
    DriftstackRTC::BridgeResult r = DriftstackRTC::establishRelayChannel(channel);
    if (r != DriftstackRTC::BridgeResult::Success)
        return nullptr;

    auto relayHostUtf8 = channel.relayHost.utf8();
    return adoptNS(nw_endpoint_create_host(relayHostUtf8.data(),
        String::number(channel.relayPort).utf8().data()));
}

// Wave 29-499.116 (Task #104 Day 2) — TCP SOCKS5 CONNECT relay creation.
// Replaces nw_proxy_config_create_socksv5 for TCP routing. CFNetwork's
// nw_connection to "destination" is intercepted; we substitute with a
// connection to gost + attach DriftstackSocks5TCPFramer that does
// SOCKS5 GREETING + AUTH + CONNECT to original destination at start,
// then becomes transparent passthrough.
RetainPtr<nw_connection_t> createTCPRelayConnection(nw_endpoint_t originalEndpoint, nw_parameters_t parameters)
{
    if (!isCustomSocks5Active())
        return nullptr;

    // Extract original destination
    String destHost;
    uint16_t destPort = 0;
    if (!endpointToHostPort(originalEndpoint, destHost, destPort)) {
        WTFLogAlways("[Driftstack-EG-WK-1.10/Task#104/Wave29-499.116] createTCPRelayConnection: endpointToHostPort failed");
        return nullptr;
    }

    // Read proxy host:port + creds from env
    const char* proxyEnv = getenv("DRIFTSTACK_SOCKS5_PROXY");
    if (!proxyEnv || !proxyEnv[0])
        return nullptr;
    String proxyEnvStr = String::fromUTF8(proxyEnv);
    size_t colon = proxyEnvStr.find(':');
    if (colon == notFound || colon == 0 || colon + 1 >= proxyEnvStr.length())
        return nullptr;
    String proxyHost = proxyEnvStr.left(colon);
    int proxyPort = 0;
    auto portStr = proxyEnvStr.substring(colon + 1);
    for (unsigned i = 0; i < portStr.length(); ++i) {
        UChar c = portStr[i];
        if (c < '0' || c > '9') { proxyPort = 0; break; }
        proxyPort = proxyPort * 10 + (c - '0');
    }
    if (proxyPort == 0)
        return nullptr;

    const char* userEnv = getenv("DRIFTSTACK_SOCKS5_USER");
    const char* passEnv = getenv("DRIFTSTACK_SOCKS5_PASS");
    String proxyUser = (userEnv && userEnv[0]) ? String::fromUTF8(userEnv) : String();
    String proxyPass = (passEnv && passEnv[0]) ? String::fromUTF8(passEnv) : String();

    // Stash destination + creds for framer to claim on start
    DriftstackSocks5TCPFramer::setPendingTcpDestination(destHost, destPort, proxyUser, proxyPass);

    // Wave 29-499.124 (Task #104 Day 7) — CRITICAL FIX: use the original
    // CFNetwork parameters (preserve TLS config + SNI for destination).
    // Previously (.116) we created fresh tcpParams with DISABLE_PROTOCOL,
    // which threw away TLS — CFNetwork's HTTPS handshake then failed
    // because no TLS layer was in the stack. By keeping original params,
    // TLS validates against destination's cert via SNI=destHost (preserved
    // from CFNetwork's original setup), and our framer below TLS rewires
    // the TCP layer to actually reach gost. After SOCKS5 CONNECT succeeds,
    // framer is transparent → TLS handshake flows through the tunnel to
    // the real destination.
    // Wave 29-499.125 — proper stack ordering: framer BELOW TLS.
    // Apple's prepend_application_protocol puts the protocol on TOP (closest
    // to application). For SOCKS5 we need framer at BOTTOM (closest to TCP),
    // so it sees raw TCP bytes BEFORE TLS encrypts them.
    //
    // Pattern: capture existing app protocols (e.g. TLS), clear them, prepend
    // framer first (now at bottom), then prepend captured protocols on top.
    // Result: [TLS, framer] = TLS-on-top, framer-on-bottom (closest to TCP).
    nw_protocol_definition_t framerDef = DriftstackSocks5TCPFramer::getFramerDefinition();
    if (framerDef) {
        auto framerOptions = adoptNS(nw_framer_create_options(framerDef));
        auto stack = adoptNS(nw_parameters_copy_default_protocol_stack(parameters));
        if (stack) {
            // Wave 29-499.126 — RETAIN options before clear (nw_protocol_options_t
            // uses nw_retain/nw_release; ARC __bridge doesn't increment).
            // Without retain, clear_application_protocols releases them and
            // re-prepend operates on dangling pointers (silent no-op).
            __block Vector<RetainPtr<nw_protocol_options_t>> existingProtocols;
            nw_protocol_stack_iterate_application_protocols(stack.get(),
                ^(nw_protocol_options_t opt) {
                    if (opt)
                        existingProtocols.append(RetainPtr<nw_protocol_options_t> { opt });
                });
            nw_protocol_stack_clear_application_protocols(stack.get());
            // Add framer first → it ends up at bottom (closest to TCP)
            nw_protocol_stack_prepend_application_protocol(stack.get(), framerOptions.get());
            // Re-prepend originals in reverse so original ordering preserved
            for (size_t i = existingProtocols.size(); i > 0; --i)
                nw_protocol_stack_prepend_application_protocol(stack.get(), existingProtocols[i - 1].get());
            static bool loggedStackOnce = false;
            if (!loggedStackOnce) {
                loggedStackOnce = true;
                WTFLogAlways("[Driftstack-EG-WK-1.10/Task#104/Wave29-499.126] protocol stack: framer inserted BELOW %zu existing app protocols (RETAINED before clear)",
                    existingProtocols.size());
            }
        }
    }

    // Endpoint = gost SOCKS5 proxy (so TCP connects to gost, not dest)
    auto proxyHostUtf8 = proxyHost.utf8();
    auto proxyPortStr = String::number(proxyPort).utf8();
    auto proxyEndpoint = adoptNS(nw_endpoint_create_host(proxyHostUtf8.data(), proxyPortStr.data()));
    if (!proxyEndpoint)
        return nullptr;

    // Use the ORIGINAL parameters (preserves TLS config) — only the
    // endpoint is rewired to gost.
    auto conn = adoptNS(nw_connection_create(proxyEndpoint.get(), parameters));
    static bool loggedFirstTCPOnce = false;
    if (conn && !loggedFirstTCPOnce) {
        loggedFirstTCPOnce = true;
        WTFLogAlways("[Driftstack-EG-WK-1.10/Task#104/Wave29-499.124] createTCPRelayConnection: FIRST TCP relay (preserved-TLS) — proxy=%s:%d → dest=%s:%u. Framer does SOCKS5 CONNECT, then TLS handshakes with dest through tunnel.",
            proxyHost.utf8().data(), proxyPort,
            destHost.utf8().data(), destPort);
    }
    return conn;
}

bool tcpInterposeActive()
{
    if (!isCustomSocks5Active())
        return false;
    const char* env = getenv("DRIFTSTACK_SOCKS5_TCP_INTERPOSE");
    return env && env[0] == '1';
}

} // namespace DriftstackQuic

} // namespace WebKit

// Wave 29-397 Slice 16.4.b.5.b: extern "C" stable-named wrappers for the
// DYLD_INSERT_LIBRARIES interpose dylib to dlsym(RTLD_DEFAULT, ...) at
// runtime. The interpose dylib cannot statically link WebKit (circular —
// dylib loads BEFORE WebKit framework), so it resolves these symbols
// after WebKit is loaded into NetworkProcess.
//
// Wave 29-499 Slice 16.6.b PRODUCTION FIX: declarations + visibility
// annotations live in the installed PrivateHeader DriftstackQuicSocks5Exports.h
// (imported at top of this .mm). The DRIFTSTACK_QUIC_EXPORT macro applies
// __attribute__((visibility("default"))) so symbols survive the WebKit
// framework's default -fvisibility=hidden link step — without this, the
// interpose dylib's dlsym(RTLD_DEFAULT, "driftstack_quic_*") returns NULL
// and the entire SOCKS5 QUIC interpose is silently inert.
//
// The installed PrivateHeader (added to project.pbxproj Headers Copy phase
// with Private attribute) also satisfies GenerateTAPI / InstallAPI
// verification on Release builds.
//
// Naming: driftstack_quic_<lowercased> matches the dylib's dlsym
// lookup table. Stable across WebKit framework releases.
extern "C" {

DRIFTSTACK_QUIC_EXPORT bool driftstack_quic_isCustomSocks5Active(void)
{
    return WebKit::DriftstackQuic::isCustomSocks5Active();
}

DRIFTSTACK_QUIC_EXPORT bool driftstack_quic_parametersUseQuic(nw_parameters_t parameters)
{
    return WebKit::DriftstackQuic::parametersUseQuic(parameters);
}

// Wave 29-499 Slice 16.7.b — interpose checks UDP transport (broader than
// QUIC) to catch WebRTC + raw-datagram UDP so they route through the SOCKS5
// UDP_ASSOCIATE relay infrastructure, preventing real-client-IP leak.
DRIFTSTACK_QUIC_EXPORT bool driftstack_quic_parametersUseUdpTransport(nw_parameters_t parameters)
{
    return WebKit::DriftstackQuic::parametersUseUdpTransport(parameters);
}

DRIFTSTACK_QUIC_EXPORT nw_connection_t driftstack_quic_createRelayConnection(nw_endpoint_t endpoint, nw_parameters_t parameters)
{
    return WebKit::DriftstackQuic::createRelayConnectionForQuic(endpoint, parameters).leakRef();
}

DRIFTSTACK_QUIC_EXPORT nw_connection_t driftstack_quic_createTCPRelayConnection(nw_endpoint_t endpoint, nw_parameters_t parameters)
{
    return WebKit::DriftstackQuic::createTCPRelayConnection(endpoint, parameters).leakRef();
}

DRIFTSTACK_QUIC_EXPORT bool driftstack_quic_tcpInterposeActive(void)
{
    return WebKit::DriftstackQuic::tcpInterposeActive();
}

// Wave 29-397 Slice 16.6 (Task #16 EG-WK-1.10): production observability
// accessors. Harness reads via dlsym(RTLD_DEFAULT, "driftstack_quic_counter_*")
// + polls for dashboard updates. NO LOCKING — atomic load is wait-free.
// Stable signature: returns uint64_t. Naming: driftstack_quic_counter_<lowercase>.
DRIFTSTACK_QUIC_EXPORT uint64_t driftstack_quic_counter_wrap_fires(void)
{ return WebKit::DriftstackQuic::slice16_6_counters().wrapOutgoingFires.load(std::memory_order_relaxed); }
DRIFTSTACK_QUIC_EXPORT uint64_t driftstack_quic_counter_wrap_failures(void)
{ return WebKit::DriftstackQuic::slice16_6_counters().wrapOutgoingFailures.load(std::memory_order_relaxed); }
DRIFTSTACK_QUIC_EXPORT uint64_t driftstack_quic_counter_unwrap_fires(void)
{ return WebKit::DriftstackQuic::slice16_6_counters().unwrapIncomingFires.load(std::memory_order_relaxed); }
DRIFTSTACK_QUIC_EXPORT uint64_t driftstack_quic_counter_unwrap_failures(void)
{ return WebKit::DriftstackQuic::slice16_6_counters().unwrapIncomingFailures.load(std::memory_order_relaxed); }
DRIFTSTACK_QUIC_EXPORT uint64_t driftstack_quic_counter_framer_output_fires(void)
{ return WebKit::DriftstackQuic::slice16_6_counters().framerOutputFires.load(std::memory_order_relaxed); }
DRIFTSTACK_QUIC_EXPORT uint64_t driftstack_quic_counter_framer_input_fires(void)
{ return WebKit::DriftstackQuic::slice16_6_counters().framerInputFires.load(std::memory_order_relaxed); }
DRIFTSTACK_QUIC_EXPORT uint64_t driftstack_quic_counter_framer_without_destination(void)
{ return WebKit::DriftstackQuic::slice16_6_counters().framerWithoutDestination.load(std::memory_order_relaxed); }
DRIFTSTACK_QUIC_EXPORT uint64_t driftstack_quic_counter_framer_wrap_failures(void)
{ return WebKit::DriftstackQuic::slice16_6_counters().framerWrapFailures.load(std::memory_order_relaxed); }
DRIFTSTACK_QUIC_EXPORT uint64_t driftstack_quic_counter_relay_establish_failures(void)
{ return WebKit::DriftstackQuic::slice16_6_counters().relayEstablishFailures.load(std::memory_order_relaxed); }
DRIFTSTACK_QUIC_EXPORT uint64_t driftstack_quic_counter_relay_connection_create_failures(void)
{ return WebKit::DriftstackQuic::slice16_6_counters().relayConnectionCreateFailures.load(std::memory_order_relaxed); }
DRIFTSTACK_QUIC_EXPORT uint64_t driftstack_quic_counter_attach_framer_failures(void)
{ return WebKit::DriftstackQuic::slice16_6_counters().attachFramerFailures.load(std::memory_order_relaxed); }
DRIFTSTACK_QUIC_EXPORT uint64_t driftstack_quic_counter_endpoint_extract_failures(void)
{ return WebKit::DriftstackQuic::slice16_6_counters().endpointExtractFailures.load(std::memory_order_relaxed); }

} // extern "C"

#endif // PLATFORM(DRIFTSTACK)
