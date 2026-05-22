/*
 * DriftstackTLS13.h — Wave 29-499.172 (PathB v2 Phase 1.5e)
 *
 * TLS 1.3 client state machine. Implements RFC 8446 handshake with
 * iPhone-byte-exact ClientHello (from DriftstackCustomTLS).
 *
 * State machine:
 *   START → CLIENT_HELLO_SENT → SERVER_HELLO_RCVD → KEY_DERIVED
 *   → ENCRYPTED_EXTENSIONS_RCVD → CERTIFICATE_RCVD → CERT_VERIFY_RCVD
 *   → SERVER_FINISHED_RCVD → CLIENT_FINISHED_SENT → APP_DATA
 *
 * Crypto via LibreSSL primitives:
 *   - SHA-384 transcript hash (EVP_MD_CTX_*)
 *   - HKDF-Expand-Label (EVP_KDF_*)
 *   - X25519 ECDH (EVP_PKEY_*)
 *   - AES-256-GCM record encrypt/decrypt (EVP_CIPHER_*)
 */

#pragma once

#if PLATFORM(DRIFTSTACK)

#include <stdint.h>
#include <wtf/Vector.h>
#include <wtf/text/WTFString.h>

namespace WebKit {

enum class TLS13State : uint8_t {
    Start,
    ClientHelloSent,
    ServerHelloRcvd,        // key shares exchanged; handshake secrets derived
    EncryptedExtensionsRcvd,
    CertificateRcvd,
    CertVerifyRcvd,
    ServerFinishedRcvd,     // client_handshake_traffic_secret derived
    ClientFinishedSent,     // master secret + application traffic secrets derived
    Established,            // application data flow
    Closed,
    Failed,
};

// Parsed ServerHello fields (iPhone-relevant subset).
struct TLS13ServerHello {
    uint16_t cipherSuite { 0 };  // negotiated cipher, e.g. 0x1302 = TLS_AES_256_GCM_SHA384
    Vector<uint8_t> serverRandom; // 32 bytes
    Vector<uint8_t> sessionIdEcho; // up to 32 bytes
    Vector<uint8_t> keyShareEntry;  // server's key_share — group + key_exchange
    uint16_t keyShareGroup { 0 };   // e.g. 0x001D = X25519
    Vector<uint8_t> keyShareKey;    // raw pubkey bytes
    uint16_t selectedVersion { 0 }; // supported_versions extension result
};

// Parse a TLS 1.3 ServerHello from a record's handshake body (after the
// 4-byte handshake header). Returns false on malformed input.
bool driftstackParseServerHello(const uint8_t* data, size_t len, TLS13ServerHello& out);

// Read a single TLS record (5-byte header + body) from the socket fd.
// Out: type (handshake/app_data/etc), version, body. Blocks until full
// record received or socket closed.
bool driftstackReadTLSRecord(int fd, uint8_t& outType, uint16_t& outVersion, Vector<uint8_t>& outBody);

} // namespace WebKit

#endif // PLATFORM(DRIFTSTACK)
