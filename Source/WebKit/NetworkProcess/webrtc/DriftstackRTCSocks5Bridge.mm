/*
 * DriftstackRTCSocks5Bridge.mm — Phase A scaffold implementation.
 * See header for design context + multi-phase rollout plan.
 */

#import "config.h"
#import "DriftstackRTCSocks5Bridge.h"

#if PLATFORM(DRIFTSTACK) && USE(LIBWEBRTC) && PLATFORM(COCOA)

#import "DriftstackSocks5Client.h"

#import <Foundation/Foundation.h>
// Wave 29-499.93 — BSD socket headers for getaddrinfo (sentinel → real IP
// resolution). Required because gost has a bug with SOCKS5 §7 ATYP=0x03
// (domain-form) — doesn't resolve hostnames server-side. WebKit must
// pre-resolve and emit ATYP=0x01 (IPv4) for gost to relay correctly.
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
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
#include <wtf/HashMap.h>
#include <wtf/Lock.h>
#include <wtf/NeverDestroyed.h>
#include <wtf/cocoa/SpanCocoa.h>
#include <wtf/text/MakeString.h>
#include <wtf/text/StringHash.h>

// Wave 29-499.241 — file-scope extern "C" forward declaration of the H3
// smoke hook in DriftstackHttp3.mm. Called from establishRelayChannel
// success path (in-namespace) via the unqualified-id syntax. Both TUs
// link into WebKit framework so resolution is link-time, no dlsym needed.
extern "C" void driftstackHttp3FireSmoke();

namespace WebKit {

namespace DriftstackRTC {

bool isCustomSocks5Active()
{
    const char* customSocks5 = getenv("DRIFTSTACK_CUSTOM_SOCKS5");
    const char* socks5Proxy = getenv("DRIFTSTACK_SOCKS5_PROXY");
    return customSocks5 && customSocks5[0] == '1'
        && socks5Proxy && socks5Proxy[0];
}

// Wave 29-397 Slice 2.7.b.2: sentinel-IP + sidecar map state.
//
// Sentinel range: 127.0.0.2 .. 127.0.0.254 (skipping 127.0.0.1 standard
// loopback + 127.0.0.255 broadcast). Allows ~253 distinct STUN/TURN
// hostnames per NetworkProcess session — well above typical WebRTC peer-
// connection requirements (usually 1-3 STUN/TURN servers per session).
//
// If exhausted (counter rolls past 254), wraps to 2 and emits a
// WTFLogAlways warning; in practice this is unreachable under normal use.
struct SentinelMapState {
    Lock lock;
    HashMap<String, String> ipToHostname WTF_GUARDED_BY_LOCK(lock);
    HashMap<String, String> hostnameToIp WTF_GUARDED_BY_LOCK(lock);
    // Wave 29-499.102 — realIp → sentinel reverse mapping. Populated at
    // outbound resolve time (when sentinel hostname is resolved to a real
    // IPv4 via .94 hardcoded STUN map). Consulted at inbound to remap the
    // source IP of STUN responses from the REAL STUN server IP back to the
    // sentinel libwebrtc knows — without this, libwebrtc's StunPort
    // discards responses whose source doesn't match the request's
    // destination (a security check that defends against off-path STUN
    // injection attacks).
    HashMap<String, String> realIpToSentinel WTF_GUARDED_BY_LOCK(lock);
    // Wave 29-499.221 — pending sentinels indexed by destination port for
    // hostname-fallback flows (e.g., Twilio anycast hostnames not in the
    // .94 hardcoded map). When endpointFromSocketAddress falls back to
    // ATYP=0x03 domain form, the response will arrive from gost-resolved
    // real IP we can't predict. Record (sentinel, dstPort) at sendTo, then
    // on first recv from any IP with matching srcPort, learn realIp →
    // sentinel and apply Wave 29-499.102 remap. Without this Twilio TURN
    // responses are rejected by libwebrtc StunPort source-validation.
    HashMap<uint16_t, Vector<String>> pendingSentinelsByPort WTF_GUARDED_BY_LOCK(lock);
    unsigned nextOctet WTF_GUARDED_BY_LOCK(lock) { 2 };
};

static SentinelMapState& sentinelMapState()
{
    static NeverDestroyed<SentinelMapState> s_state;
    return s_state.get();
}

String allocateSentinelForHostname(const String& hostname)
{
    if (hostname.isEmpty())
        return String();

    auto& state = sentinelMapState();
    Locker locker { state.lock };

    auto existing = state.hostnameToIp.find(hostname);
    if (existing != state.hostnameToIp.end())
        return existing->value;

    unsigned octet = state.nextOctet;
    if (octet >= 255) {
        WTFLogAlways("[Driftstack-EG-WK-1.8/EG-WK-1.9/Task#15] allocateSentinelForHostname: 127.0.0.X sentinel range exhausted; wrapping to 2 (may collide with earlier entry — investigate session lifetime)");
        octet = 2;
    }
    state.nextOctet = octet + 1;

    String sentinel = makeString("127.0.0."_s, octet);
    state.ipToHostname.set(sentinel, hostname);
    state.hostnameToIp.set(hostname, sentinel);

    static bool loggedFirstAllocOnce = false;
    if (!loggedFirstAllocOnce) {
        loggedFirstAllocOnce = true;
        WTFLogAlways("[Driftstack-EG-WK-1.8/EG-WK-1.9/Task#15] allocateSentinelForHostname: FIRST allocation — hostname='%s' → sentinel=%s. Subsequent allocations log only on wrap.",
            hostname.utf8().data(), sentinel.utf8().data());
    }
    return sentinel;
}

String lookupHostnameForSentinel(const String& ipString)
{
    if (ipString.isEmpty())
        return String();

    auto& state = sentinelMapState();
    Locker locker { state.lock };

    auto it = state.ipToHostname.find(ipString);
    if (it == state.ipToHostname.end())
        return String();
    return it->value;
}

// Wave 29-499.102 — store a realIp ↔ sentinel mapping populated at
// outbound resolve time. Called by endpointFromSocketAddress when the
// .94 hardcoded STUN map resolves a sentinel-mapped hostname to a real
// IPv4. The reverse map lets inbound STUN responses be remapped from
// real STUN server source (e.g., 74.125.250.129) to the sentinel
// (127.0.0.2) that libwebrtc's StunPort expects.
void rememberRealIpForSentinel(const String& realIp, const String& sentinel)
{
    if (realIp.isEmpty() || sentinel.isEmpty())
        return;
    auto& state = sentinelMapState();
    Locker locker { state.lock };
    state.realIpToSentinel.set(realIp, sentinel);
}

String lookupSentinelForRealIp(const String& realIp)
{
    if (realIp.isEmpty())
        return String();
    auto& state = sentinelMapState();
    Locker locker { state.lock };
    auto it = state.realIpToSentinel.find(realIp);
    if (it == state.realIpToSentinel.end())
        return String();
    return it->value;
}

// Wave 29-499.221 — record a pending sentinel waiting for a response on
// the given destination port. Called when endpointFromSocketAddress falls
// back to hostname-form (resolveHostnameToIPv4 returned empty).
void recordPendingSentinelForPort(const String& sentinel, uint16_t port)
{
    if (sentinel.isEmpty() || port == 0)
        return;
    auto& state = sentinelMapState();
    Locker locker { state.lock };
    auto& vec = state.pendingSentinelsByPort.add(port, Vector<String> { }).iterator->value;
    // De-duplicate: skip if sentinel already pending on this port.
    for (const auto& s : vec) {
        if (s == sentinel)
            return;
    }
    vec.append(sentinel);
}

// Wave 29-499.221 — on first inbound packet from an unknown real IP,
// look up any pending sentinel with matching source port (= our dstPort)
// and learn the realIp → sentinel mapping. Returns the sentinel (now also
// stored in realIpToSentinel for future recvs), or empty if no pending
// match. Intended for the hostname-fallback path where we couldn't
// predict the real IP at sendTo time.
String learnRealIpFromPendingPort(const String& realIp, uint16_t srcPort)
{
    if (realIp.isEmpty() || srcPort == 0)
        return String();
    auto& state = sentinelMapState();
    Locker locker { state.lock };

    // Skip if we already know this realIp.
    if (state.realIpToSentinel.contains(realIp))
        return state.realIpToSentinel.get(realIp);

    auto portIt = state.pendingSentinelsByPort.find(srcPort);
    if (portIt == state.pendingSentinelsByPort.end() || portIt->value.isEmpty())
        return String();

    // Pop the first pending sentinel for this port (FIFO order matches
    // typical STUN/ICE one-shot binding flow). If multiple sentinels are
    // pending for the same port, subsequent recvs will bind to subsequent
    // sentinels — best-effort heuristic; works perfectly for the common
    // single-server case and acceptably for multi-server ICE candidate
    // gathering where each server response will bind to a sentinel.
    String sentinel = portIt->value.first();
    portIt->value.removeAt(0);
    state.realIpToSentinel.set(realIp, sentinel);
    return sentinel;
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

// Wave 29-499.310 — dedicated QUIC relay. Separate NeverDestroyed client so its
// fresh UDP_ASSOCIATE binds to the QUIC udpFd (first sender), unlike the shared
// relay which gost binds to the STUN socket.
struct DedicatedQuicRelayState {
    Lock lock;
    std::unique_ptr<DriftstackSocks5Client> client WTF_GUARDED_BY_LOCK(lock);
    Socks5UdpRelayChannel channel WTF_GUARDED_BY_LOCK(lock);
    bool established WTF_GUARDED_BY_LOCK(lock) { false };
};

static DedicatedQuicRelayState& dedicatedQuicRelayState()
{
    static NeverDestroyed<DedicatedQuicRelayState> s;
    return s.get();
}

BridgeResult establishDedicatedQuicRelay(RelayChannel& out)
{
    if (!isCustomSocks5Active())
        return BridgeResult::Socks5Disabled;

    auto& state = dedicatedQuicRelayState();
    Locker locker { state.lock };
    if (state.established) {
        out.relayHost = state.channel.relayHost;
        out.relayPort = state.channel.relayPort;
        return BridgeResult::Success;
    }

    Socks5Endpoint proxy;
    if (!parseProxyEndpoint(getenv("DRIFTSTACK_SOCKS5_PROXY"), proxy)) {
        WTFLogAlways("[Wave29-499.310] establishDedicatedQuicRelay: DRIFTSTACK_SOCKS5_PROXY malformed");
        return BridgeResult::ProtocolError;
    }
    Socks5Credentials creds;
    if (const char* u = getenv("DRIFTSTACK_SOCKS5_USER"))
        creds.username = String::fromUTF8(u);
    if (const char* p = getenv("DRIFTSTACK_SOCKS5_PASS"))
        creds.password = String::fromUTF8(p);

    state.client = std::make_unique<DriftstackSocks5Client>(proxy, creds);
    if (state.client->performHandshake() != Socks5Result::Success) {
        WTFLogAlways("[Wave29-499.310] dedicated QUIC relay: handshake FAILED");
        state.client.reset();
        return BridgeResult::NetworkError;
    }
    if (state.client->udpAssociate(state.channel) != Socks5Result::Success) {
        WTFLogAlways("[Wave29-499.310] dedicated QUIC relay: UDP ASSOCIATE FAILED");
        state.client.reset();
        return BridgeResult::UdpAssociateFailed;
    }
    state.established = true;
    out.relayHost = state.channel.relayHost;
    out.relayPort = state.channel.relayPort;
    WTFLogAlways("[Wave29-499.310] dedicated QUIC relay SUCCESS — fresh relay %s:%u (binds to QUIC udpFd)",
        state.channel.relayHost.utf8().data(), state.channel.relayPort);
    return BridgeResult::Success;
}

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

    // Wave 29-499.248 — smoke disabled by default; .247 empirical crash
    // in ngtcp2_conn_client_new_versioned (Translation fault @ garbage PC)
    // indicates ngtcp2_callbacks ABI issue. Production traffic stays on
    // PathB v2 h2 fallback (returns failed from driftstackHttp3Execute).
    // To re-enable for investigation: DRIFTSTACK_PATHB_V2_H3_SMOKE_FORCE=1.
    static bool firedOnce = false;
    const char* forceSmoke = getenv("DRIFTSTACK_PATHB_V2_H3_SMOKE_FORCE");
    if (!firedOnce && forceSmoke && forceSmoke[0] == '1') {
        firedOnce = true;
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
            ::driftstackHttp3FireSmoke();
        });
    }

    return BridgeResult::Success;
}

// Wave 29-397 Slice 2.3: socketAddress → Socks5Endpoint. Prefers numeric
// IP form when set (libwebrtc resolves DNS before passing to the socket
// layer in most paths); falls back to hostname otherwise.
//
// Wave 29-397 Slice 2.7.b.4: when bridge-active + Slice 2.7.b.3 DNS short-
// circuit allocated a 127.0.0.X sentinel for the original hostname, the
// SocketAddress here arrives with that sentinel as ipaddr. We MUST consult
// the sidecar map (lookupHostnameForSentinel) to recover the original
// hostname — otherwise the wrap helper would emit a §7 frame addressed to
// 127.0.0.X (which the SOCKS5 proxy can't reach as the actual STUN/TURN
// host). When sidecar match found, emit the hostname so wrapUdpDatagram
// produces an ATYP=0x03 (domain) §7 frame with the real hostname embedded.
// Fall-through when sidecar miss: use the IP literal (ATYP=0x01).
// Wave 29-499.93 — gost-compatible §7 outbound: pre-resolve sentinel
// hostnames to IPv4 and emit ATYP=0x01 instead of ATYP=0x03.
//
// Empirical (.92 hex dump on browserleaks/webrtc):
//   WebKit outbound: ATYP=0x03 11 "stun.l.google.com" 4b66 [stun]
//   Python via same proxy with ATYP=0x01 + pre-resolved IP: WORKED
//   Python via same proxy with ATYP=0x03 + hostname: TIMED OUT
//
// gost's SOCKS5 UDP_ASSOCIATE §7 handler doesn't resolve domain names
// server-side. Force ATYP=0x01 by pre-resolving sentinel→hostname→IP
// at sendTo time, using cached map for hot-path (resolve once per
// hostname for the process).
//
// Trade-off: DNS resolution happens at Mac (one query per unique
// hostname, cached). Minor DNS leak via Mac-side getaddrinfo for STUN/
// TURN hostnames — fixed in v1.1 by routing the resolution through
// SOCKS5 TCP DNS-over-CONNECT.
// Wave 29-499.94 — hardcoded STUN/TURN hostname → IPv4 map for v1.0
// NetworkProcess. Apple's sandbox blocks getaddrinfo (.93 attempt rc=8
// EAI_NONAME); CFHost works but is async + requires runloop integration.
// For v1.0 demo, hardcode common STUN servers. v1.1 will route DNS
// through the SOCKS5 control channel (SOCKS5 TCP CONNECT to 1.1.1.1:53,
// send binary DNS query, parse response — gost will resolve at egress
// avoiding any client-side DNS leak).
static String hardcodedSTUNHostnameLookup(const String& hostname)
{
    // Returns IPv4 for known STUN/TURN hostnames. Empty string if not in
    // the table — caller falls back to domain-form (which gost may also
    // fail at, but at least we tried).
    if (hostname == "stun.l.google.com"_s
        || hostname == "stun1.l.google.com"_s
        || hostname == "stun2.l.google.com"_s
        || hostname == "stun3.l.google.com"_s
        || hostname == "stun4.l.google.com"_s)
        return "74.125.250.129"_s; // Google STUN A-record (Anycast, stable across IPs).
    if (hostname == "stun.cloudflare.com"_s)
        return "162.159.207.0"_s; // Cloudflare STUN.
    if (hostname == "stun.services.mozilla.com"_s)
        return "52.26.250.139"_s; // Mozilla STUN (AWS Oregon).
    if (hostname == "stun.miwifi.com"_s)
        return "111.206.174.3"_s;
    // Wave 29-499.288 — QUIC test endpoints (DriftstackHttp3 smoke targets)
    if (hostname == "cloudflare-quic.com"_s)
        return "104.18.26.14"_s;  // verified via dig +short @8.8.8.8
    if (hostname == "quic.nginx.org"_s)
        return "3.130.143.18"_s;  // another known QUIC test server
    // Wave 29-499.290 — OpenRelay TURN endpoints + Metered STUN
    if (hostname == "openrelay.metered.ca"_s)
        return "15.235.47.158"_s;  // dig +short @8.8.8.8 (free TURN service)
    if (hostname == "stun.relay.metered.ca"_s)
        return "72.14.189.175"_s;
    // Wave 29-499.110-revert — Twilio TURN servers REMOVED from hardcoded map.
    // Twilio uses GeoDNS anycast — hardcoding a specific IP routes to wrong
    // region. Empirical: ATYP=0x03 domain fallback (when getaddrinfo fails)
    // correctly reaches Twilio's geo-routed TURN server, but Twilio NTS test
    // still fails because:
    //   - SOCKS5+UDP NAT mapping doesn't expose a public IP for Twilio's
    //     TURN servers to reach (structural SOCKS5 limit; iPhone+SOCKS5
    //     has same issue)
    //   - Twilio's auth retry flow may not complete through proxy
    //
    // For full TURN over customer proxy: requires Phase 2/3 WireGuard/
    // OpenVPN customer-proxy modes (network-level tunnel, not application-
    // level SOCKS5) per planning 133.
    return { };
}

static String resolveHostnameToIPv4(const String& hostname)
{
    // Cache resolved IPs per-hostname for the process lifetime.
    static NeverDestroyed<HashMap<String, String>> s_resolvedCache;
    static NeverDestroyed<Lock> s_cacheLock;
    {
        Locker locker { s_cacheLock.get() };
        auto it = s_resolvedCache.get().find(hostname);
        if (it != s_resolvedCache.get().end())
            return it->value;
    }

    // Wave 29-499.94 — try hardcoded STUN hostname map first (covers
    // 99% of WebRTC ICE STUN servers in practice). Avoids the sandboxed
    // NetworkProcess getaddrinfo failure.
    String hardcoded = hardcodedSTUNHostnameLookup(hostname);
    if (!hardcoded.isEmpty()) {
        {
            Locker locker { s_cacheLock.get() };
            s_resolvedCache.get().set(hostname, hardcoded);
        }
        static bool loggedFirstHardcodedOnce = false;
        if (!loggedFirstHardcodedOnce) {
            loggedFirstHardcodedOnce = true;
            WTFLogAlways("[Driftstack-EG-WK-1.8/Task#15/Wave29-499.94] resolveHostnameToIPv4: FIRST hardcoded-map hit — '%s' → '%s'. Bypassing NetworkProcess sandboxed-getaddrinfo (rc=8 EAI_NONAME).",
                hostname.utf8().data(), hardcoded.utf8().data());
        }
        return hardcoded;
    }

    // Fallback: try getaddrinfo (will fail under NetworkProcess sandbox
    // but logs the failure for diagnostic visibility).
    struct addrinfo hints { };
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    struct addrinfo* res = nullptr;
    auto cs = hostname.utf8();
    int rc = getaddrinfo(cs.data(), nullptr, &hints, &res);
    if (rc != 0 || !res) {
        static bool loggedFirstFailOnce = false;
        if (!loggedFirstFailOnce) {
            loggedFirstFailOnce = true;
            WTFLogAlways("[Driftstack-EG-WK-1.8/Task#15/Wave29-499.93] resolveHostnameToIPv4: getaddrinfo('%s') failed rc=%d (probably sandbox); add hostname to .94 hardcoded map OR implement SOCKS5-DNS-CONNECT for v1.1.",
                cs.data(), rc);
        }
        return { };
    }
    char ipBuf[INET_ADDRSTRLEN] = { };
    auto* sin = reinterpret_cast<const struct sockaddr_in*>(res->ai_addr);
    inet_ntop(AF_INET, &sin->sin_addr, ipBuf, sizeof(ipBuf));
    freeaddrinfo(res);
    String ipString = String::fromUTF8(ipBuf);
    {
        Locker locker { s_cacheLock.get() };
        s_resolvedCache.get().set(hostname, ipString);
    }
    return ipString;
}

// Wave 29-499.325 — DNS pre-resolve gate. DEFAULT OFF = leak-free ATYP=0x03
// domain-form: the SOCKS5 proxy resolves the STUN/TURN hostname server-side.
// This (a) satisfies the founder-locked EG-WK-1.9 proxy-only-DNS requirement at
// v1.0 (no Mac-side getaddrinfo leak), and (b) lets GeoDNS-routed TURN (e.g.
// Twilio anycast) resolve to the correct region — the hardcoded-IP pre-resolve
// path mis-routed those (see hardcodedSTUNHostnameLookup .110-revert note).
// Empirically validated 2026-05-26: STUN Binding + TURN Allocate via ATYP=0x03
// through the customer proxy both succeed (V-CUSTOMER-PROXY-ATYP03-OK).
// Set DRIFTSTACK_SOCKS5_PRERESOLVE=1 ONLY for a proxy with the gost ATYP=0x03
// server-side-resolution bug (then we pre-resolve + emit ATYP=0x01 IPv4).
static bool shouldPreResolveDns()
{
    static bool enabled = [] {
        const char* e = getenv("DRIFTSTACK_SOCKS5_PRERESOLVE");
        return e && e[0] == '1';
    }();
    return enabled;
}

static Socks5Endpoint endpointFromSocketAddress(const webrtc::SocketAddress& address)
{
    Socks5Endpoint endpoint;
    if (!address.ipaddr().IsNil()) {
        auto ipStr = address.ipaddr().ToString();
        String ipString = String::fromUTF8(ipStr.c_str());

        // Sidecar consult (Slice 2.7.b.4): translate sentinel back to hostname.
        String hostname = lookupHostnameForSentinel(ipString);
        if (!hostname.isEmpty()) {
            // Wave 29-499.93 — pre-resolve hostname to IPv4 (ATYP=0x01) ONLY when
            // the gost-compat gate is set; otherwise resolvedIp stays empty so we
            // take the proven ATYP=0x03 domain-form + recordPendingSentinelForPort
            // path below (.325 leak-free default).
            String resolvedIp = shouldPreResolveDns() ? resolveHostnameToIPv4(hostname) : String();
            if (!resolvedIp.isEmpty()) {
                endpoint.host = resolvedIp;
                // Wave 29-499.102 — remember the realIp → sentinel mapping
                // so inbound STUN responses can be source-remapped from
                // realIp back to sentinel (libwebrtc StunPort's source-
                // validation needs the source to match the request's dest).
                rememberRealIpForSentinel(resolvedIp, ipString);
                static bool loggedSentinelHitOnce = false;
                if (!loggedSentinelHitOnce) {
                    loggedSentinelHitOnce = true;
                    WTFLogAlways("[Driftstack-EG-WK-1.8/EG-WK-1.9/Task#15/Wave29-499.93+102] endpointFromSocketAddress: sentinel %s → hostname='%s' → IPv4='%s'. §7 frame uses ATYP=0x01; remembered realIp→sentinel for inbound source remap.",
                        ipString.utf8().data(), hostname.utf8().data(), resolvedIp.utf8().data());
                }
            } else {
                // Fall back to domain form if resolution fails (e.g.,
                // Twilio anycast hostnames intentionally removed from the
                // hardcoded map per .110-revert). The proxy will resolve
                // server-side; we record (sentinel, port) so first recv
                // from the proxy-resolved real IP binds back to sentinel.
                endpoint.host = hostname;
                recordPendingSentinelForPort(ipString, address.port());
                static bool loggedFirstFallbackOnce = false;
                if (!loggedFirstFallbackOnce) {
                    loggedFirstFallbackOnce = true;
                    WTFLogAlways("[Driftstack-EG-WK-1.8/Wave29-499.221] endpointFromSocketAddress: hostname-fallback path — sentinel %s + hostname='%s' recorded as pending on port=%u; first response from any IP on that port will bind back to sentinel.",
                        ipString.utf8().data(), hostname.utf8().data(), address.port());
                }
            }
        } else {
            endpoint.host = ipString;
        }
    } else {
        auto host = address.hostname();
        String hostString = String::fromUTF8(host.c_str());
        // Wave 29-499.93/.325 — pre-resolve only under the gost-compat gate;
        // default emits ATYP=0x03 domain form (proxy resolves server-side).
        String resolvedIp = shouldPreResolveDns() ? resolveHostnameToIPv4(hostString) : String();
        endpoint.host = resolvedIp.isEmpty() ? hostString : resolvedIp;
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

    // Wave 29-499.278 — log STUN/TURN message type for outbound diagnostics.
    // STUN/TURN message format: 2-byte type + 2-byte length + 4-byte magic + 12-byte txid.
    // Type 0x0001=Binding, 0x0003=Allocate, 0x0004=Refresh, 0x0006=Send, 0x0008=CreatePerm,
    // 0x0009=ChannelBind, 0x0101=Binding Success, 0x0103=Allocate Success,
    // 0x0111=Binding Error, 0x0113=Allocate Error.
    if (payload.size() >= 20 && payload.size() < 65536) {
        uint16_t msgType = (static_cast<uint16_t>(payload[0]) << 8) | payload[1];
        uint16_t msgLen = (static_cast<uint16_t>(payload[2]) << 8) | payload[3];
        bool isStun = (payload[4] == 0x21 && payload[5] == 0x12 && payload[6] == 0xa4 && payload[7] == 0x42);
        const char* typeName = "?";
        switch (msgType) {
            case 0x0001: typeName = "Binding"; break;
            case 0x0003: typeName = "Allocate"; break;
            case 0x0004: typeName = "Refresh"; break;
            case 0x0006: typeName = "Send"; break;
            case 0x0008: typeName = "CreatePerm"; break;
            case 0x0009: typeName = "ChannelBind"; break;
            case 0x0101: typeName = "Binding-Success"; break;
            case 0x0103: typeName = "Allocate-Success"; break;
            case 0x0111: typeName = "Binding-Error"; break;
            case 0x0113: typeName = "Allocate-Error"; break;
        }
        if (isStun && (msgType == 0x0003 || msgType == 0x0006 || msgType == 0x0008 || msgType == 0x0009)) {
            WTFLogAlways("[Driftstack-EG-WK-1.8/Wave29-499.278] wrapOutgoing TURN %s (0x%04x) → %s:%u (payload=%zu, msgLen=%u)",
                typeName, msgType, destination.host.utf8().data(), destination.port, payload.size(), msgLen);
        }
    }

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

    // Wave 29-499.278 — log incoming TURN response message-type for diagnostics
    // Wave 29-499.289 — parse ERROR-CODE attribute for TURN Allocate-Error
    auto p = WTF::span(payload.get());
    if (p.size() >= 20) {
        uint16_t msgType = (static_cast<uint16_t>(p[0]) << 8) | p[1];
        uint16_t msgLen = (static_cast<uint16_t>(p[2]) << 8) | p[3];
        bool isStun = (p[4] == 0x21 && p[5] == 0x12 && p[6] == 0xa4 && p[7] == 0x42);
        if (isStun && (msgType == 0x0103 || msgType == 0x0113 || msgType == 0x0117)) {
            const char* tn = msgType == 0x0103 ? "Allocate-Success"
                          : msgType == 0x0113 ? "Allocate-Error"
                          : "Refresh-Error";

            // Wave 29-499.289 — walk STUN attributes for ERROR-CODE (0x0009)
            // Each attr: type(2) + len(2) + value(padded to 4 bytes)
            int errorCode = 0;
            String errorReason;
            String realm;
            String nonce;
            size_t attrCursor = 20;  // attrs start after 20-byte header
            while (attrCursor + 4 <= p.size()) {
                uint16_t aType = (static_cast<uint16_t>(p[attrCursor]) << 8) | p[attrCursor + 1];
                uint16_t aLen = (static_cast<uint16_t>(p[attrCursor + 2]) << 8) | p[attrCursor + 3];
                if (attrCursor + 4 + aLen > p.size()) break;
                if (aType == 0x0009 && aLen >= 4) {  // ERROR-CODE
                    uint8_t errClass = p[attrCursor + 4 + 2] & 0x07;
                    uint8_t errNum = p[attrCursor + 4 + 3];
                    errorCode = errClass * 100 + errNum;
                    if (aLen > 4) {
                        Vector<uint8_t> reasonBytes;
                        for (size_t i = 4; i < aLen; ++i) reasonBytes.append(p[attrCursor + 4 + i]);
                        errorReason = String::fromUTF8(byteCast<char>(reasonBytes.span()));
                    }
                } else if (aType == 0x0014 && aLen > 0) {  // REALM
                    Vector<uint8_t> rBytes;
                    for (size_t i = 0; i < aLen; ++i) rBytes.append(p[attrCursor + 4 + i]);
                    realm = String::fromUTF8(byteCast<char>(rBytes.span()));
                } else if (aType == 0x0015 && aLen > 0) {  // NONCE
                    Vector<uint8_t> nBytes;
                    for (size_t i = 0; i < aLen && i < 32; ++i) nBytes.append(p[attrCursor + 4 + i]);
                    nonce = String::fromUTF8(byteCast<char>(nBytes.span()));
                }
                // Advance with 4-byte padding
                attrCursor += 4 + ((aLen + 3) & ~3);
            }

            if (errorCode > 0) {
                WTFLogAlways("[Driftstack-EG-WK-1.8/Wave29-499.289] unwrapIncoming TURN %s (0x%04x) ← %s:%u ERROR-CODE=%d '%s' REALM='%s' NONCE='%s' (payload=%zu)",
                    tn, msgType, source.host.utf8().data(), source.port,
                    errorCode, errorReason.utf8().data(), realm.utf8().data(),
                    nonce.utf8().data(), p.size());
            } else {
                WTFLogAlways("[Driftstack-EG-WK-1.8/Wave29-499.278] unwrapIncoming TURN %s (0x%04x) ← %s:%u (payload=%zu, msgLen=%u)",
                    tn, msgType, source.host.utf8().data(), source.port, p.size(), msgLen);
            }
        }
    }
    return BridgeResult::Success;
}

} // namespace DriftstackRTC

} // namespace WebKit

#endif // PLATFORM(DRIFTSTACK) && USE(LIBWEBRTC) && PLATFORM(COCOA)
