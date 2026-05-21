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

static nw_framer_start_result_t handshakeStartHandler(nw_framer_t framer)
{
    auto* instance = claimPendingDestination();
    if (!instance) {
        WTFLogAlways("[Driftstack-EG-WK-1.10/Task#104/Wave29-499.112] framer start_handler: no pending destination — bug, dropping framer");
        return nw_framer_start_result_will_mark_ready;
    }
    nw_framer_set_input_handler(framer, ^size_t(nw_framer_t innerFramer) {
        // Parse handshake state machine on input bytes.
        // For now: this is a stub. Will be filled in next iteration with
        // greeting-response + auth-response + connect-response parsing.
        // Once parsing completes, mark framer ready + set transparent
        // input/output handlers.
        return 0; // request more bytes
    });

    sendGreeting(framer);
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
