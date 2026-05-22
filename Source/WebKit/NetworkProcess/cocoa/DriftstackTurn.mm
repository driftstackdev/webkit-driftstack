/*
 * DriftstackTurn.mm — Wave 29-499.213 (Phase 5 TURN ALLOCATE)
 *
 * Twilio NTS TURN client: ALLOCATE → 401 challenge → retry with
 * MESSAGE-INTEGRITY → success with XOR-RELAYED-ADDRESS.
 *
 * Uses existing SOCKS5 UDP_ASSOCIATE relay (Wave 29-499.99-106) as
 * transport — packets are §7-wrapped before sendto.
 */

#import "config.h"
#import "DriftstackTurn.h"
#import "DriftstackStun.h"
#import <wtf/HexNumber.h>
#import <wtf/text/MakeString.h>

#if PLATFORM(DRIFTSTACK)

#import <errno.h>
#import <netdb.h>
#import <netinet/in.h>
#import <stdlib.h>
#import <string.h>
#import <sys/socket.h>
#import <unistd.h>
#import <wtf/Assertions.h>

WTF_ALLOW_UNSAFE_BUFFER_USAGE_BEGIN

namespace WebKit {

namespace {

// Open UDP socket to socks5 relay endpoint + send STUN message;
// receive STUN response. Returns false on timeout/error.
bool sendRecvStun(const String& relayHost, uint16_t relayPort,
                   const Vector<uint8_t>& packet,
                   Vector<uint8_t>& outResponse)
{
    // Resolve relay endpoint (gost SOCKS5 UDP relay address)
    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = htons(relayPort);
    auto h = relayHost.utf8();
    if (inet_pton(AF_INET, h.data(), &dst.sin_addr) != 1) {
        // Try DNS resolve
        struct addrinfo hints = {0};
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_DGRAM;
        struct addrinfo* res = nullptr;
        if (getaddrinfo(h.data(), nullptr, &hints, &res) != 0 || !res)
            return false;
        memcpy(&dst.sin_addr, &reinterpret_cast<struct sockaddr_in*>(res->ai_addr)->sin_addr, sizeof(dst.sin_addr));
        freeaddrinfo(res);
    }

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return false;

    struct timeval tv = {3, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    if (sendto(fd, packet.span().data(), packet.size(), 0,
               (struct sockaddr*)&dst, sizeof(dst)) < 0) {
        close(fd);
        return false;
    }

    uint8_t buf[2048];
    ssize_t n = recv(fd, buf, sizeof(buf), 0);
    close(fd);
    if (n <= 0) return false;

    outResponse.resize(n);
    memcpy(outResponse.mutableSpan().data(), buf, n);
    return true;
}

} // anonymous namespace

DriftstackTurnAllocation driftstackTurnAllocate(const DriftstackTurnConfig& config)
{
    DriftstackTurnAllocation alloc;

    // === Step 1: ALLOCATE request (no auth) — expect 401 with REALM/NONCE ===
    StunMessageBuilder ch1(kStunMethodAllocate, kStunClassRequest);

    // REQUESTED-TRANSPORT: UDP (17)
    Vector<uint8_t> reqTrans;
    reqTrans.append(17);  // UDP
    reqTrans.append(0); reqTrans.append(0); reqTrans.append(0);  // RFFU
    ch1.addAttribute(kAttrRequestedTransport, reqTrans);

    // LIFETIME: 600 sec
    Vector<uint8_t> lifetime;
    lifetime.append(0); lifetime.append(0); lifetime.append(0x02); lifetime.append(0x58);
    ch1.addAttribute(kAttrLifetime, lifetime);

    ch1.appendFingerprint();

    Vector<uint8_t> resp1;
    if (!sendRecvStun(config.socks5UdpRelayHost, config.socks5UdpRelayPort, ch1.bytes(), resp1)) {
        alloc.ok = false;
        alloc.errorMessage = "ALLOCATE request 1 failed (no response from TURN server)"_s;
        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.213] %s", alloc.errorMessage.utf8().data());
        return alloc;
    }

    StunMessage parsed1;
    if (!driftstackParseStun(resp1.span().data(), resp1.size(), parsed1)) {
        alloc.ok = false;
        alloc.errorMessage = "ALLOCATE response 1 parse failed"_s;
        return alloc;
    }

    // Expected: error class + 401 Unauthorized + REALM + NONCE
    auto realmAttr = driftstackFindStunAttr(parsed1, kAttrRealm);
    auto nonceAttr = driftstackFindStunAttr(parsed1, kAttrNonce);
    if (!realmAttr || !nonceAttr) {
        alloc.ok = false;
        alloc.errorMessage = "ALLOCATE response 1 missing REALM or NONCE"_s;
        return alloc;
    }
    alloc.realm = String::fromUTF8(unsafeMakeSpan(
        reinterpret_cast<const char*>(realmAttr->value.span().data()), realmAttr->value.size()));
    alloc.nonce = nonceAttr->value;

    WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.213] TURN 401 challenge — REALM='%s' NONCE=%zu bytes",
        alloc.realm.utf8().data(), alloc.nonce.size());

    // === Step 2: ALLOCATE request with MESSAGE-INTEGRITY ===
    auto hmacKey = driftstackLongTermKey(config.username, alloc.realm, config.password);
    if (hmacKey.size() != 16) {
        alloc.ok = false;
        alloc.errorMessage = "long-term key derivation failed"_s;
        return alloc;
    }

    StunMessageBuilder ch2(kStunMethodAllocate, kStunClassRequest);
    ch2.addAttribute(kAttrRequestedTransport, reqTrans);
    ch2.addAttribute(kAttrLifetime, lifetime);
    ch2.addAttributeString(kAttrUsername, config.username);
    ch2.addAttribute(kAttrRealm, realmAttr->value);
    ch2.addAttribute(kAttrNonce, alloc.nonce);
    ch2.appendMessageIntegrity(hmacKey);
    ch2.appendFingerprint();

    Vector<uint8_t> resp2;
    if (!sendRecvStun(config.socks5UdpRelayHost, config.socks5UdpRelayPort, ch2.bytes(), resp2)) {
        alloc.ok = false;
        alloc.errorMessage = "ALLOCATE request 2 (authed) failed (no response)"_s;
        return alloc;
    }

    StunMessage parsed2;
    if (!driftstackParseStun(resp2.span().data(), resp2.size(), parsed2)) {
        alloc.ok = false;
        alloc.errorMessage = "ALLOCATE response 2 parse failed"_s;
        return alloc;
    }

    if (parsed2.klass != kStunClassSuccess) {
        auto errAttr = driftstackFindStunAttr(parsed2, kAttrErrorCode);
        alloc.ok = false;
        alloc.errorMessage = makeString("TURN ALLOCATE failed (class=0x"_s, hex(parsed2.klass, 2),
            errAttr ? " with ERROR-CODE attr"_s : ""_s, ")"_s);
        return alloc;
    }

    // Extract XOR-RELAYED-ADDRESS (TURN-allocated public endpoint)
    auto relayed = driftstackFindStunAttr(parsed2, kAttrXorRelayedAddress);
    if (relayed && driftstackParseXorAddress(*relayed, parsed2.transactionId, alloc.relayedHost, alloc.relayedPort)) {
        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.213] TURN allocated relay: %s:%u",
            alloc.relayedHost.utf8().data(), alloc.relayedPort);
    }

    // Extract XOR-MAPPED-ADDRESS (our SRflx as seen by TURN server)
    auto mapped = driftstackFindStunAttr(parsed2, kAttrXorMappedAddress);
    if (mapped && driftstackParseXorAddress(*mapped, parsed2.transactionId, alloc.mappedHost, alloc.mappedPort)) {
        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.213] TURN mapped (our SRflx): %s:%u",
            alloc.mappedHost.utf8().data(), alloc.mappedPort);
    }

    alloc.ok = true;
    return alloc;
}

bool driftstackTurnEnabled()
{
    const char* env = getenv("DRIFTSTACK_PATHB_V2_TURN");
    return env && env[0] == '1';
}

} // namespace WebKit

WTF_ALLOW_UNSAFE_BUFFER_USAGE_END

#endif // PLATFORM(DRIFTSTACK)
