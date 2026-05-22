/*
 * DriftstackTLS13KeySchedule.h — Wave 29-499.174 (PathB v2 Phase 1.5e)
 *
 * TLS 1.3 key schedule per RFC 8446 §7.1. Computes all the secrets
 * and traffic keys needed to encrypt/decrypt handshake + application
 * records.
 *
 * Flow (one step at a time):
 *   1. early_secret = HKDF-Extract(salt=0, IKM=PSK or 0)
 *   2. (skip — no early data)
 *   3. handshake_secret = HKDF-Extract(salt=derive(early_secret,"derived",""),
 *                                       IKM=ECDH_shared)
 *   4. client_hs_secret = derive(handshake_secret, "c hs traffic", hash(CH..SH))
 *      server_hs_secret = derive(handshake_secret, "s hs traffic", hash(CH..SH))
 *   5. master_secret = HKDF-Extract(salt=derive(handshake_secret,"derived",""),
 *                                    IKM=0)
 *   6. client_app_secret = derive(master_secret, "c ap traffic",
 *                                 hash(CH..server_Finished))
 *      server_app_secret = derive(master_secret, "s ap traffic",
 *                                 hash(CH..server_Finished))
 *   7. traffic_key  = HKDF-Expand-Label(secret, "key", "", AEAD_key_len)
 *      traffic_iv   = HKDF-Expand-Label(secret, "iv",  "", AEAD_iv_len)
 *
 * AES-256-GCM = key 32, iv 12.
 */

#pragma once

#if PLATFORM(DRIFTSTACK)

#include <stdint.h>
#include <wtf/Vector.h>

namespace WebKit {

// Traffic key+iv pair derived from a traffic secret.
struct TLS13TrafficKey {
    Vector<uint8_t> key;  // 32 bytes for AES-256-GCM
    Vector<uint8_t> iv;   // 12 bytes
    uint64_t seqNum { 0 }; // record sequence (used in nonce per record)
};

class TLS13KeySchedule {
public:
    // Initialize the schedule with the ECDH shared secret + transcript hash
    // of ClientHello..ServerHello. Returns handshake-stage secrets.
    bool initFromHandshake(const Vector<uint8_t>& ecdhShared,
                           const Vector<uint8_t>& transcriptHashCHtoSH);

    // After server's Finished received: install master secret + derive
    // application-stage secrets from transcript hash of CH..server_Finished.
    bool deriveApplicationSecrets(const Vector<uint8_t>& transcriptHashCHtoServerFinished);

    // Accessors (call after corresponding init step):
    const Vector<uint8_t>& clientHandshakeSecret() const { return m_clientHsSecret; }
    const Vector<uint8_t>& serverHandshakeSecret() const { return m_serverHsSecret; }
    const Vector<uint8_t>& clientApplicationSecret() const { return m_clientAppSecret; }
    const Vector<uint8_t>& serverApplicationSecret() const { return m_serverAppSecret; }

    // Derive traffic key+iv from a traffic secret for AES-256-GCM.
    static TLS13TrafficKey deriveTrafficKey(const Vector<uint8_t>& trafficSecret);

    // Construct a per-record nonce: iv XOR (sequence_number padded to 12 bytes).
    static Vector<uint8_t> recordNonce(const Vector<uint8_t>& iv, uint64_t seqNum);

private:
    Vector<uint8_t> m_earlySecret;       // 48 bytes
    Vector<uint8_t> m_handshakeSecret;   // 48 bytes
    Vector<uint8_t> m_masterSecret;      // 48 bytes
    Vector<uint8_t> m_clientHsSecret;    // 48 bytes
    Vector<uint8_t> m_serverHsSecret;    // 48 bytes
    Vector<uint8_t> m_clientAppSecret;   // 48 bytes
    Vector<uint8_t> m_serverAppSecret;   // 48 bytes
};

} // namespace WebKit

#endif // PLATFORM(DRIFTSTACK)
