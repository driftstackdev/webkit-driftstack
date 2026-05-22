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

    // Wave 29-499.195 — read buffer for leftover decrypted bytes between
    // read() calls. TLS record may contain >1 HTTP/2 frames; must not
    // discard bytes that don't fit in caller's maxLen.
    Vector<uint8_t> m_readBuffer;

    // Internal helpers
    bool sendClientHello();
    bool receiveServerHello();
    bool readEncryptedHandshakeMessages();
    bool sendClientFinished();
    int writeApplicationRecord(const uint8_t* data, size_t len);
    Vector<uint8_t> readApplicationRecord();
};

} // namespace WebKit

#endif // PLATFORM(DRIFTSTACK)
