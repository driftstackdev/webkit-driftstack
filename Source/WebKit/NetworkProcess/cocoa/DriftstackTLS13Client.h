/*
 * DriftstackTLS13Client.h — Wave 29-499.175 (PathB v2 Phase 1.5e)
 *
 * End-to-end TLS 1.3 client using:
 *   - DriftstackCustomTLS: iPhone-byte-exact ClientHello emission
 *   - DriftstackTLS13: record reader + ServerHello parser
 *   - DriftstackCrypto: SHA-384, HKDF, X25519, AES-256-GCM via LibreSSL
 *   - DriftstackTLS13KeySchedule: RFC 8446 §7.1 key derivation
 *
 * Public API mirrors what callers expect from a TLS library: connect,
 * read, write, shutdown. Internally manages the full TLS 1.3 state
 * machine + iPhone-byte-exact wire format.
 *
 * Usage:
 *   auto client = std::make_unique<DriftstackTLS13Client>();
 *   if (!client->connect(socketFd, "example.com")) { ... }
 *   client->write(reqBytes);
 *   auto resp = client->read();
 *
 * After connect() completes successfully, the wire JA3 should equal
 * iPhone Safari 26.0's ecdf4f49dd59effc439639da29186671.
 */

#pragma once

#if PLATFORM(DRIFTSTACK)

#include "DriftstackCrypto.h"
#include "DriftstackTLS13KeySchedule.h"
#include <memory>
#include <stdint.h>
#include <wtf/Vector.h>
#include <wtf/text/WTFString.h>

namespace WebKit {

struct SHA384Ctx;  // forward (from DriftstackCrypto)
struct TLS13ServerHello;  // forward (from DriftstackTLS13) — used by the TLS 1.2 path

class DriftstackTLS13Client {
public:
    DriftstackTLS13Client();
    ~DriftstackTLS13Client();

    // Establish TLS 1.3 with iPhone-byte-exact ClientHello.
    // Returns true on success; check errorMessage() on failure.
    bool connect(int socketFd, const String& sniHostname);

    // Write application data. Returns bytes written; -1 on error.
    int write(const uint8_t* data, size_t len);

    // Read application data. Returns bytes read; 0 on EOF; -1 on error.
    int read(uint8_t* buf, size_t maxLen);

    // Get negotiated ALPN protocol (e.g. "h2", "http/1.1").
    const String& selectedALPN() const { return m_selectedALPN; }

    // Cleanly shut down the connection.
    void shutdown();

    const String& errorMessage() const { return m_errorMessage; }

private:
    int m_fd { -1 };
    bool m_appReadBlockingRestored { false };  // Wave .352 — reset handshake recv-timeout once on first app read
    String m_sniHostname;
    String m_selectedALPN;
    String m_errorMessage;

    // Wave 29-499.186 — cipher-aware transcript: accumulate ALL handshake
    // bytes; compute hash on demand using the negotiated cipher's digest.
    uint16_t m_negotiatedCipher { 0 };
    Vector<uint8_t> m_transcriptBytes;

    // Key schedule
    TLS13KeySchedule m_keySchedule;

    // Handshake traffic keys
    TLS13TrafficKey m_clientHsKey;
    TLS13TrafficKey m_serverHsKey;

    // Application traffic keys
    TLS13TrafficKey m_clientAppKey;
    TLS13TrafficKey m_serverAppKey;

    // Saved ephemeral X25519 private key (for ECDH after ServerHello)
    Vector<uint8_t> m_ourX25519Private;

    // Saved ECDH shared secret (until handshake secret derived)
    Vector<uint8_t> m_ecdhShared;

    // Wave 29-499.215 — P-256 keypair for HRR retry path
    P256Keypair m_p256Keypair;

    // Wave 29-499.219 — MLKEM768 keypair for hybrid X25519MLKEM768
    MLKEM768Keypair m_mlkemKeypair;
    Vector<uint8_t> m_ourX25519Public;  // 32 bytes (kept alongside private)

    // Wave 29-499.195 — read buffer for leftover decrypted bytes between
    // read() calls. TLS record may contain >1 HTTP/2 frames; must not
    // discard bytes that don't fit in caller's maxLen.
    Vector<uint8_t> m_readBuffer;

    // Wave 29-499.340 — TLS 1.2 fallback path. Twilio's TURN turns: :443 endpoint
    // negotiates TLS 1.2 (cipher 0xc02f ECDHE_RSA_AES128GCM, no key_share), so a
    // real iPhone completes a 1.2 handshake there. The iPhone-byte-exact ClientHello
    // already offers TLS 1.2 cipher suites + supported_versions[1.3,1.2]; when the
    // server picks 1.2 we run the full 1.2 ECDHE handshake here (RFC 5246 + RFC 5288
    // AEAD). Kept entirely separate from the 1.3 state machine above.
    bool m_isTLS12 { false };
    bool m_t12EMS { false };                   // extended_master_secret negotiated (RFC 7627)
    Vector<uint8_t> m_clientRandom;            // 32 bytes, saved from ClientHello
    Vector<uint8_t> m_serverRandom;            // 32 bytes, from ServerHello
    Vector<uint8_t> m_t12MasterSecret;         // 48 bytes
    Vector<uint8_t> m_t12ClientKey;            // 16 (AES-128)
    Vector<uint8_t> m_t12ServerKey;            // 16
    Vector<uint8_t> m_t12ClientFixedIV;        // 4 (implicit nonce prefix)
    Vector<uint8_t> m_t12ServerFixedIV;        // 4
    uint64_t m_t12ClientSeq { 0 };
    uint64_t m_t12ServerSeq { 0 };
    Vector<uint8_t> m_t12ReadBuffer;           // leftover decrypted app bytes

    // Internal helpers
    bool sendClientHello();
    bool receiveServerHello();
    bool readEncryptedHandshakeMessages();
    bool sendClientFinished();
    int writeApplicationRecord(const uint8_t* data, size_t len);
    Vector<uint8_t> readApplicationRecord();

    // Wave 29-499.340 — TLS 1.2 handshake + record layer.
    bool doTLS12Handshake(const TLS13ServerHello& sh);
    int writeTLS12Record(const uint8_t* data, size_t len, uint8_t contentType = 0x17);
    Vector<uint8_t> readTLS12Record();
};

} // namespace WebKit

#endif // PLATFORM(DRIFTSTACK)
