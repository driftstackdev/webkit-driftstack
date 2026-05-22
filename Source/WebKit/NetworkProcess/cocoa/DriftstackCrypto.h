/*
 * DriftstackCrypto.h — Wave 29-499.173 (PathB v2 Phase 1.5e)
 *
 * TLS 1.3 crypto primitives layered over LibreSSL 3.3.6
 * (/usr/lib/libssl.48.dylib + /usr/lib/libcrypto.48.dylib).
 *
 * Functions:
 *   - SHA-384 transcript hash (running)
 *   - HKDF-Extract-SHA384, HKDF-Expand-Label (RFC 5869 + RFC 8446 §7.1)
 *   - X25519 keypair gen + shared-secret derivation (RFC 7748)
 *   - AES-256-GCM record encrypt/decrypt
 */

#pragma once

#if PLATFORM(DRIFTSTACK)

#include <stdint.h>
#include <wtf/Vector.h>

namespace WebKit {

// Resolve LibreSSL crypto symbols (one-shot dispatch_once).
// Returns true if all required APIs found.
bool driftstackCryptoInit();

// === SHA-384 ===

// Streaming SHA-384 for TLS transcript hash. The `ctx` is opaque — created
// via createSHA384Ctx, updated via updateSHA384, finalized via finalizeSHA384.
struct SHA384Ctx;
SHA384Ctx* driftstackCreateSHA384Ctx();
void driftstackUpdateSHA384(SHA384Ctx*, const uint8_t* data, size_t len);
Vector<uint8_t> driftstackFinalizeSHA384(SHA384Ctx*);  // 48 bytes
Vector<uint8_t> driftstackCloneFinalizeSHA384(SHA384Ctx*);  // snapshot without consuming
void driftstackFreeSHA384Ctx(SHA384Ctx*);

// One-shot SHA-384.
Vector<uint8_t> driftstackSHA384(const uint8_t* data, size_t len);

// === HKDF-SHA384 ===

// HKDF-Extract: salt + IKM → 48-byte PRK
Vector<uint8_t> driftstackHkdfExtractSha384(const Vector<uint8_t>& salt,
                                            const Vector<uint8_t>& ikm);

// HKDF-Expand-Label (RFC 8446 §7.1):
//   HkdfLabel: u16(length) + u8len("tls13 " + label) + u8len(context)
Vector<uint8_t> driftstackHkdfExpandLabelSha384(const Vector<uint8_t>& secret,
                                                 const char* label,
                                                 const Vector<uint8_t>& context,
                                                 size_t outLen);

// Derive-Secret: HKDF-Expand-Label(secret, label, Hash(messages), Hash.length)
Vector<uint8_t> driftstackDeriveSecretSha384(const Vector<uint8_t>& secret,
                                              const char* label,
                                              const Vector<uint8_t>& transcriptHash);

// === X25519 ECDH ===

// Generate ephemeral X25519 keypair.
// outPrivate = 32 bytes, outPublic = 32 bytes.
bool driftstackX25519GenerateKeypair(Vector<uint8_t>& outPrivate,
                                       Vector<uint8_t>& outPublic);

// Derive shared secret from our private + peer public. Out = 32 bytes.
Vector<uint8_t> driftstackX25519SharedSecret(const Vector<uint8_t>& ourPrivate,
                                               const Vector<uint8_t>& peerPublic);

// === AES-256-GCM ===

// Encrypt plaintext with 32-byte key + 12-byte nonce. AAD is the record
// header bytes for TLS 1.3. Output = ciphertext (= plaintext length) +
// 16-byte authentication tag appended.
Vector<uint8_t> driftstackAes256GcmEncrypt(const Vector<uint8_t>& key,
                                            const Vector<uint8_t>& nonce,
                                            const Vector<uint8_t>& plaintext,
                                            const Vector<uint8_t>& aad);

// Decrypt ciphertext (last 16 bytes are tag). Returns empty Vector on
// authentication failure.
Vector<uint8_t> driftstackAes256GcmDecrypt(const Vector<uint8_t>& key,
                                            const Vector<uint8_t>& nonce,
                                            const Vector<uint8_t>& ciphertext,
                                            const Vector<uint8_t>& aad);

// === HMAC-SHA384 (for Finished message) ===
Vector<uint8_t> driftstackHmacSha384(const Vector<uint8_t>& key,
                                      const Vector<uint8_t>& data);

} // namespace WebKit

#endif // PLATFORM(DRIFTSTACK)
