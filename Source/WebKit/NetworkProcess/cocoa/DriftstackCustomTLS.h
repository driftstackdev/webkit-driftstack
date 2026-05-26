/*
 * DriftstackCustomTLS.h — Wave 29-499.171 (PathB v2 Phase 1.5e)
 *
 * Custom TLS 1.3 client implementing byte-exact iPhone Safari 26.0
 * ClientHello. Solves the architectural ceiling of LibreSSL 3.3.6 +
 * BoringSSL: neither library can emit iPhone's exact 13-extension list.
 *
 * Strategy:
 *   1. CRAFT raw TLS ClientHello bytes matching iPhone Safari 26 exactly
 *      (20 ciphers including 3DES, 13 extensions in iPhone order, GREASE).
 *   2. Send via BSD socket (already SOCKS5-tunneled via DriftstackNetworkLoader).
 *   3. Parse server's ServerHello + EncryptedExtensions + Certificate +
 *      CertificateVerify + Finished.
 *   4. Derive handshake & application secrets via LibreSSL crypto primitives
 *      (HKDF-SHA384, X25519 key share).
 *   5. Encrypt/decrypt application data with AES-256-GCM (LibreSSL primitive).
 *
 * The TLS state machine, record framing, and handshake messages are all
 * implemented in driftstack code. LibreSSL is used only for crypto
 * primitives (HKDF, AES-GCM, X25519, SHA-384).
 *
 * Result: iPhone-bit-identical JA3 = ecdf4f49dd59effc439639da29186671
 * achievable via PathB v2, matching default mode's JA3 produced by
 * Apple CFNetwork.
 *
 * Multi-iteration scope:
 *   .171: ClientHello byte-exact emission + connection (this file)
 *   .172: ServerHello parse + handshake secret derivation
 *   .173: EncryptedExtensions + Certificate parse (skip verify)
 *   .174: Finished message + application key derivation
 *   .175: Application data encrypt/decrypt + HTTP/2 over our TLS
 */

#pragma once

#if PLATFORM(DRIFTSTACK)

#include <stdint.h>
#include <wtf/Vector.h>
#include <wtf/text/WTFString.h>

namespace WebKit {

// iPhone Safari 26.0 reference ClientHello captured via tls.peet.ws.
// JA3:      ecdf4f49dd59effc439639da29186671
// JA4:      t13d2013h2_a09f3c656075_7f0f34a4126d
//
// Structure:
//   record_layer_header (5 bytes: type, version, length)
//   handshake_header (4 bytes: type, length)
//   client_version (2 bytes: TLS 1.2 = 0x0303)
//   random (32 bytes)
//   session_id (33 bytes: len-byte + 32 random bytes)
//   ciphers (43 bytes: len-byte len-byte + 20*2 bytes = total 42 bytes content)
//   compression_methods (2 bytes: 1, 0)
//   extensions (variable):
//     server_name (0)
//     extended_master_secret (23)
//     extensionRenegotiationInfo (65281)
//     supported_groups (10)
//     ec_point_formats (11)
//     application_layer_protocol_negotiation (16)
//     status_request (5)
//     signature_algorithms (13)
//     signed_certificate_timestamp (18)
//     key_share (51)
//     psk_key_exchange_modes (45)
//     supported_versions (43)
//     compress_certificate (27)
//     + 2 GREASE (5a5a, fafa) at positions iPhone uses
//
// Total ClientHello typically ~520 bytes.

// Build a byte-exact iPhone Safari 26.0 ClientHello for the given SNI
// hostname. Random + GREASE values are randomized per-connection
// (matches iPhone's behavior).
// Wave 29-499.187 — caller now provides the REAL X25519 public key for
// key_share so ECDH produces matching shared secret with server.
Vector<uint8_t> driftstackBuildIPhoneClientHello(const String& sni,
    const Vector<uint8_t>& x25519PublicKey,    // 32 bytes (real ECDH pubkey)
    Vector<uint8_t>& outClientRandom);         // 32 bytes (for handshake derivation)

// Wave 29-499.219 — Build CH with X25519MLKEM768 hybrid + X25519 keyshare entries
// (matches iPhone Safari 26 exactly when MLKEM is available)
Vector<uint8_t> driftstackBuildIPhoneClientHelloHybrid(const String& sni,
    const Vector<uint8_t>& mlkemPubKey,    // 1184 bytes MLKEM768 encoded
    const Vector<uint8_t>& x25519PubKey,   // 32 bytes
    Vector<uint8_t>& outClientRandom);

// Wave 29-499.216 — CH2 for HRR retry with P-256 keyshare
// Per RFC 8446 §4.1.2: CH2 mirrors CH1 except key_share + early_data + pre_shared_key.
// Builder takes a custom key_share group + entry bytes (P-256 = 65 bytes uncompressed pubkey).
Vector<uint8_t> driftstackBuildIPhoneClientHelloP256(const String& sni,
    const Vector<uint8_t>& p256PublicKey,      // 65 bytes uncompressed
    Vector<uint8_t>& outClientRandom);

// Wave 29-499.348 — iPhone-exact QUIC ClientHello (raw handshake msg for the Initial
// CRYPTO frame; no TLS record header). For the custom QUIC-TLS backend (replaces
// BoringSSL as ngtcp2's driver). h3 ALPN + quic_transport_parameters(0x0039) + 3 TLS1.3
// ciphers; drops TCP-only exts. Target ja4 == iPhone q13d0311h3_55b375c5d22e_f2a83c8e78ae.
Vector<uint8_t> driftstackBuildIPhoneQuicClientHello(const String& sni,
    const Vector<uint8_t>& mlkemPubKey,
    const Vector<uint8_t>& x25519PubKey,
    const Vector<uint8_t>& transportParams,
    Vector<uint8_t>& outClientRandom);

// Phase 1.5e gate (DRIFTSTACK_PATHB_V2_CUSTOM_TLS=1).
bool driftstackCustomTlsEnabled();

} // namespace WebKit

#endif // PLATFORM(DRIFTSTACK)
