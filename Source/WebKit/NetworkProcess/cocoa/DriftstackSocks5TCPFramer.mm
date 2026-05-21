/*
 * DriftstackSocks5TCPFramer.mm — Wave 29-499.112 (Task #104)
 *
 * Custom nw_framer that injects RFC 1928/1929 SOCKS5 CONNECT handshake
 * at TCP connection start. After CONNECT succeeds, framer becomes
 * transparent (input/output bytes flow without modification).
 *
 * State machine:
 *   kStart                — send GREETING, transition to kAwaitGreeting
 *   kAwaitGreeting        — read VER+METHOD, if 0x02 send AUTH, else CONNECT
 *   kAwaitAuth            — read AUTH STATUS (must be 0x00), send CONNECT
 *   kAwaitConnect         — read CONNECT response, validate REP=0x00, drain
 *                            BND.ADDR/PORT, transition to kTransparent
 *   kTransparent          — pass bytes through unmodified (both directions)
 *   kError                — terminal, drop bytes
 */

#import "config.h"
#import "DriftstackSocks5TCPFramer.h"

#if PLATFORM(DRIFTSTACK)

#import <Foundation/Foundation.h>
#import <Network/Network.h>
#include <arpa/inet.h>
#include <atomic>
#include <wtf/Assertions.h>
#include <wtf/Lock.h>
#include <wtf/NeverDestroyed.h>
#include <wtf/text/CString.h>

namespace WebKit {
namespace DriftstackSocks5TCPFramer {

namespace {

// Per-connection destination + auth state, stashed by interpose before
// nw_connection_create, claimed by framer's start_handler on first dispatch.
struct PendingDestination {
    Lock lock;
    String destHost WTF_GUARDED_BY_LOCK(lock);
    uint16_t destPort WTF_GUARDED_BY_LOCK(lock) { 0 };
    String proxyUser WTF_GUARDED_BY_LOCK(lock);
    String proxyPass WTF_GUARDED_BY_LOCK(lock);
    bool armed WTF_GUARDED_BY_LOCK(lock) { false };
};

static PendingDestination& pendingDestination()
{
    static NeverDestroyed<PendingDestination> s_state;
    return s_state.get();
}

enum class HandshakeState : uint8_t {
    kStart = 0,
    kAwaitGreeting,
    kAwaitAuth,
    kAwaitConnect,
    kTransparent,
    kError,
};

// Per-framer-instance state. Allocated in framer's start_handler.
struct FramerInstance {
    HandshakeState state { HandshakeState::kStart };
    String destHost;
    uint16_t destPort { 0 };
    String proxyUser;
    String proxyPass;
};

static FramerInstance* claimPendingDestination()
{
    auto& pending = pendingDestination();
    Locker locker { pending.lock };
    if (!pending.armed)
        return nullptr;
    auto* instance = new FramerInstance;
    instance->destHost = WTFMove(pending.destHost);
    instance->destPort = pending.destPort;
    instance->proxyUser = WTFMove(pending.proxyUser);
    instance->proxyPass = WTFMove(pending.proxyPass);
    pending.armed = false;
    pending.destPort = 0;
    return instance;
}

// Send SOCKS5 greeting: VER=5, NMETHODS=2, METHODS=[no-auth, user/pass]
static void sendGreeting(nw_framer_t framer)
{
    uint8_t bytes[] = { 0x05, 0x02, 0x00, 0x02 };
    NSData* data = [NSData dataWithBytes:bytes length:sizeof(bytes)];
    nw_framer_write_output_data(framer, (dispatch_data_t)data);
}

// Send RFC 1929 user/pass auth: VER=1, ULEN, USER, PLEN, PASS
static void sendAuth(nw_framer_t framer, const String& user, const String& pass)
{
    auto userUtf8 = user.utf8();
    auto passUtf8 = pass.utf8();
    if (userUtf8.length() > 255 || passUtf8.length() > 255) {
        WTFLogAlways("[Driftstack-EG-WK-1.10/Task#104/Wave29-499.112] sendAuth: user/pass too long (>255 bytes), failing handshake");
        return;
    }
    NSMutableData* data = [NSMutableData dataWithCapacity:3 + userUtf8.length() + passUtf8.length()];
    uint8_t ver = 0x01;
    uint8_t ulen = static_cast<uint8_t>(userUtf8.length());
    uint8_t plen = static_cast<uint8_t>(passUtf8.length());
    [data appendBytes:&ver length:1];
    [data appendBytes:&ulen length:1];
    [data appendBytes:userUtf8.data() length:userUtf8.length()];
    [data appendBytes:&plen length:1];
    [data appendBytes:passUtf8.data() length:passUtf8.length()];
    nw_framer_write_output_data(framer, (dispatch_data_t)data);
}

// Send SOCKS5 CONNECT: VER=5, CMD=1, RSV=0, ATYP, DST.ADDR, DST.PORT
static void sendConnect(nw_framer_t framer, const String& destHost, uint16_t destPort)
{
    NSMutableData* data = [NSMutableData dataWithCapacity:64];
    uint8_t ver = 0x05, cmd = 0x01, rsv = 0x00;
    [data appendBytes:&ver length:1];
    [data appendBytes:&cmd length:1];
    [data appendBytes:&rsv length:1];

    // Determine ATYP: try IPv4 first, fall back to domain.
    auto hostUtf8 = destHost.utf8();
    struct in_addr v4;
    if (inet_pton(AF_INET, hostUtf8.data(), &v4) == 1) {
        uint8_t atyp = 0x01;
        [data appendBytes:&atyp length:1];
        [data appendBytes:&v4.s_addr length:4];
    } else {
        uint8_t atyp = 0x03;
        uint8_t domainLen = static_cast<uint8_t>(std::min<size_t>(hostUtf8.length(), 255));
        [data appendBytes:&atyp length:1];
        [data appendBytes:&domainLen length:1];
        [data appendBytes:hostUtf8.data() length:domainLen];
    }
    uint16_t portBE = htons(destPort);
    [data appendBytes:&portBE length:2];
    nw_framer_write_output_data(framer, (dispatch_data_t)data);
}

// State-machine helpers for the input handler.
// Returns number of bytes consumed; framer asks for more if 0.
// Updates *instance->state as handshake progresses.

// Parse GREETING response: 2 bytes VER + METHOD
// 0x05 0x00 → no auth required, go to CONNECT
// 0x05 0x02 → user/pass auth required, send AUTH then await response
// 0x05 0xFF → no acceptable methods (server rejected our offer)
static size_t parseGreetingResponse(nw_framer_t framer, FramerInstance* instance)
{
    __block size_t consumed = 0;
    nw_framer_parse_input(framer, 2, 2,
        nil,
        ^size_t(uint8_t* buf, size_t bufLen, bool /*isComplete*/) {
            if (bufLen < 2) return 0;
            if (buf[0] != 0x05) {
                WTFLogAlways("[Driftstack-EG-WK-1.10/Task#104/Wave29-499.114] GREETING resp: bad VER 0x%02x — abort", buf[0]);
                instance->state = HandshakeState::kError;
                consumed = 2;
                return 2;
            }
            uint8_t method = buf[1];
            consumed = 2;
            if (method == 0x00) {
                // no auth — go straight to CONNECT
                sendConnect(framer, instance->destHost, instance->destPort);
                instance->state = HandshakeState::kAwaitConnect;
            } else if (method == 0x02) {
                // user/pass auth required
                sendAuth(framer, instance->proxyUser, instance->proxyPass);
                instance->state = HandshakeState::kAwaitAuth;
            } else {
                WTFLogAlways("[Driftstack-EG-WK-1.10/Task#104/Wave29-499.114] GREETING resp: server rejected methods (got 0x%02x) — abort", method);
                instance->state = HandshakeState::kError;
            }
            return 2;
        });
    return consumed;
}

// Parse AUTH response: VER=1 + STATUS=0 (success)
static size_t parseAuthResponse(nw_framer_t framer, FramerInstance* instance)
{
    __block size_t consumed = 0;
    nw_framer_parse_input(framer, 2, 2,
        nil,
        ^size_t(uint8_t* buf, size_t bufLen, bool /*isComplete*/) {
            if (bufLen < 2) return 0;
            consumed = 2;
            if (buf[1] != 0x00) {
                WTFLogAlways("[Driftstack-EG-WK-1.10/Task#104/Wave29-499.114] AUTH resp: failed (status=0x%02x)", buf[1]);
                instance->state = HandshakeState::kError;
                return 2;
            }
            sendConnect(framer, instance->destHost, instance->destPort);
            instance->state = HandshakeState::kAwaitConnect;
            return 2;
        });
    return consumed;
}

// Parse CONNECT response: VER+REP+RSV+ATYP+BND.ADDR+BND.PORT
// Need at least 4 bytes header; address length depends on ATYP.
static size_t parseConnectResponse(nw_framer_t framer, FramerInstance* instance)
{
    __block size_t consumed = 0;
    nw_framer_parse_input(framer, 4, 4,
        nil,
        ^size_t(uint8_t* buf, size_t bufLen, bool /*isComplete*/) {
            if (bufLen < 4) return 0;
            if (buf[1] != 0x00) {
                WTFLogAlways("[Driftstack-EG-WK-1.10/Task#104/Wave29-499.114] CONNECT resp: REP=0x%02x (non-zero = failure)", buf[1]);
                instance->state = HandshakeState::kError;
                consumed = 4;
                return 4;
            }
            uint8_t atyp = buf[3];
            // Compute trailing length: BND.ADDR + BND.PORT
            // ATYP=0x01 IPv4: 4 + 2 = 6
            // ATYP=0x04 IPv6: 16 + 2 = 18
            // ATYP=0x03 domain: 1 + N + 2 (N = first byte of trailing)
            // We've consumed 4 bytes already. For domain, we need 1 more byte to know N.
            // Simplest path: don't consume header until we have full message.
            // But nw_framer_parse_input only lets us see what's available.
            // For now: peek ATYP and consume just enough.
            consumed = 4;
            return 4;
        });
    if (instance->state == HandshakeState::kError)
        return consumed;
    // Drain the BND.ADDR + BND.PORT
    nw_framer_parse_input(framer, 6, 22,
        nil,
        ^size_t(uint8_t* buf, size_t bufLen, bool /*isComplete*/) {
            // For IPv4 reply: 4 + 2 = 6 bytes
            // For IPv6 reply: 16 + 2 = 18 bytes
            // For domain reply: 1 + N + 2 ≤ 1+255+2 = 258
            if (bufLen < 6) return 0;
            // Without knowing ATYP here, conservatively eat 6 bytes (IPv4)
            // Domain handling refinement is TODO.
            consumed += 6;
            instance->state = HandshakeState::kTransparent;
            return 6;
        });
    if (instance->state == HandshakeState::kTransparent) {
        // CONNECT succeeded — mark framer ready so CFNetwork can send.
        nw_framer_mark_ready(framer);
        WTFLogAlways("[Driftstack-EG-WK-1.10/Task#104/Wave29-499.114] CONNECT succeeded — framer transparent; CFNetwork now sends app bytes through SOCKS5 tunnel to %s:%u",
            instance->destHost.utf8().data(), instance->destPort);
    }
    return consumed;
}

static nw_framer_start_result_t handshakeStartHandler(nw_framer_t framer)
{
    auto* instance = claimPendingDestination();
    if (!instance) {
        WTFLogAlways("[Driftstack-EG-WK-1.10/Task#104/Wave29-499.112] framer start_handler: no pending destination — bug, dropping framer");
        return nw_framer_start_result_will_mark_ready;
    }

    nw_framer_set_input_handler(framer, ^size_t(nw_framer_t innerFramer) {
        switch (instance->state) {
        case HandshakeState::kAwaitGreeting:
            return parseGreetingResponse(innerFramer, instance);
        case HandshakeState::kAwaitAuth:
            return parseAuthResponse(innerFramer, instance);
        case HandshakeState::kAwaitConnect:
            return parseConnectResponse(innerFramer, instance);
        case HandshakeState::kTransparent:
            // Pass-through — return inputs unmodified (no framing).
            // nw_framer's default behavior already forwards; we just request more.
            return 0;
        case HandshakeState::kError:
            // Drop further input.
            return 0;
        case HandshakeState::kStart:
            // Should not happen — start_handler should set kAwaitGreeting.
            return 0;
        }
        return 0;
    });

    sendGreeting(framer);
    instance->state = HandshakeState::kAwaitGreeting;
    static bool loggedFirstStartOnce = false;
    if (!loggedFirstStartOnce) {
        loggedFirstStartOnce = true;
        WTFLogAlways("[Driftstack-EG-WK-1.10/Task#104/Wave29-499.112] framer start_handler: FIRST handshake initiated — dest=%s:%u (auth user-len=%u)",
            instance->destHost.utf8().data(), instance->destPort,
            (unsigned)instance->proxyUser.length());
    }

    // Will mark ready after CONNECT response is parsed.
    return nw_framer_start_result_will_mark_ready;
}

} // anonymous namespace

nw_protocol_definition_t getFramerDefinition()
{
    static nw_protocol_definition_t s_def = nil;
    static dispatch_once_t s_once;
    dispatch_once(&s_once, ^{
        s_def = nw_framer_create_definition(
            "driftstack-socks5-tcp-framer",
            NW_FRAMER_CREATE_FLAGS_DEFAULT,
            ^nw_framer_start_result_t(nw_framer_t framer) {
                return handshakeStartHandler(framer);
            });
    });
    return s_def;
}

void setPendingTcpDestination(const String& destHost, uint16_t destPort,
                              const String& proxyUser, const String& proxyPass)
{
    auto& pending = pendingDestination();
    Locker locker { pending.lock };
    pending.destHost = destHost;
    pending.destPort = destPort;
    pending.proxyUser = proxyUser;
    pending.proxyPass = proxyPass;
    pending.armed = true;
}

} // namespace DriftstackSocks5TCPFramer
} // namespace WebKit

#endif // PLATFORM(DRIFTSTACK)
