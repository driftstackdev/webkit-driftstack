/*
 * DriftstackTLS13KeySchedule.mm — Wave 29-499.174 (PathB v2 Phase 1.5e)
 *
 * TLS 1.3 key schedule implementation. Uses DriftstackCrypto for HKDF +
 * SHA-384 primitives.
 */

#import "config.h"
#import "DriftstackTLS13KeySchedule.h"
#import "DriftstackCrypto.h"

#if PLATFORM(DRIFTSTACK)

#import <string.h>
#import <wtf/Assertions.h>

WTF_ALLOW_UNSAFE_BUFFER_USAGE_BEGIN

namespace WebKit {

namespace {
// SHA-384 hash of empty string (used in derive-secret with empty messages).
// Computed once at startup.
Vector<uint8_t> emptyHashSha384()
{
    return driftstackSHA384(nullptr, 0);
}
} // namespace

bool TLS13KeySchedule::initFromHandshake(const Vector<uint8_t>& ecdhShared,
                                          const Vector<uint8_t>& transcriptHashCHtoSH)
{
    // Step 1: early_secret = HKDF-Extract(salt=zeros, IKM=zeros) — no PSK
    Vector<uint8_t> zeros(48, 0);
    Vector<uint8_t> zeroSalt(48, 0);
    m_earlySecret = driftstackHkdfExtractSha384(zeroSalt, zeros);
    if (m_earlySecret.size() != 48) {
        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.174] early_secret derivation failed");
        return false;
    }

    // Step 2 (PSK derivation skipped — not using PSK)

    // Step 3: handshake_secret = HKDF-Extract(salt=derive(early,"derived",empty_hash),
    //                                          IKM=ECDH)
    auto emptyHash = emptyHashSha384();
    auto hsSalt = driftstackDeriveSecretSha384(m_earlySecret, "derived", emptyHash);
    m_handshakeSecret = driftstackHkdfExtractSha384(hsSalt, ecdhShared);
    if (m_handshakeSecret.size() != 48) {
        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.174] handshake_secret derivation failed");
        return false;
    }

    // Step 4: client/server handshake traffic secrets
    m_clientHsSecret = driftstackDeriveSecretSha384(m_handshakeSecret, "c hs traffic", transcriptHashCHtoSH);
    m_serverHsSecret = driftstackDeriveSecretSha384(m_handshakeSecret, "s hs traffic", transcriptHashCHtoSH);
    if (m_clientHsSecret.size() != 48 || m_serverHsSecret.size() != 48) {
        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.174] handshake traffic secrets failed");
        return false;
    }

    WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.174] Handshake secrets derived OK (client/server)");
    return true;
}

bool TLS13KeySchedule::deriveApplicationSecrets(const Vector<uint8_t>& transcriptHashCHtoServerFinished)
{
    // Step 5: master_secret = HKDF-Extract(salt=derive(handshake,"derived",empty),
    //                                       IKM=zeros)
    auto emptyHash = emptyHashSha384();
    auto msSalt = driftstackDeriveSecretSha384(m_handshakeSecret, "derived", emptyHash);
    Vector<uint8_t> zeros(48, 0);
    m_masterSecret = driftstackHkdfExtractSha384(msSalt, zeros);
    if (m_masterSecret.size() != 48) {
        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.174] master_secret derivation failed");
        return false;
    }

    // Step 6: client/server application traffic secrets
    m_clientAppSecret = driftstackDeriveSecretSha384(m_masterSecret, "c ap traffic", transcriptHashCHtoServerFinished);
    m_serverAppSecret = driftstackDeriveSecretSha384(m_masterSecret, "s ap traffic", transcriptHashCHtoServerFinished);
    if (m_clientAppSecret.size() != 48 || m_serverAppSecret.size() != 48) {
        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.174] app traffic secrets failed");
        return false;
    }

    WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.174] Application secrets derived OK");
    return true;
}

TLS13TrafficKey TLS13KeySchedule::deriveTrafficKey(const Vector<uint8_t>& trafficSecret)
{
    TLS13TrafficKey out;
    // For AES-256-GCM:
    //   key = HKDF-Expand-Label(secret, "key", "", 32)
    //   iv  = HKDF-Expand-Label(secret, "iv",  "", 12)
    out.key = driftstackHkdfExpandLabelSha384(trafficSecret, "key", {}, 32);
    out.iv = driftstackHkdfExpandLabelSha384(trafficSecret, "iv", {}, 12);
    out.seqNum = 0;
    return out;
}

Vector<uint8_t> TLS13KeySchedule::recordNonce(const Vector<uint8_t>& iv, uint64_t seqNum)
{
    Vector<uint8_t> nonce = iv;
    // Per RFC 8446 §5.3: nonce = iv XOR (seq padded to 12 bytes, big-endian)
    for (int i = 0; i < 8; ++i)
        nonce[11 - i] ^= static_cast<uint8_t>((seqNum >> (8 * i)) & 0xFF);
    return nonce;
}

} // namespace WebKit

WTF_ALLOW_UNSAFE_BUFFER_USAGE_END

#endif // PLATFORM(DRIFTSTACK)
