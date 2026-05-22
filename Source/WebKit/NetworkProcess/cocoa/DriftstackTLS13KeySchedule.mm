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

// Cipher-aware HKDF dispatchers
Vector<uint8_t> hkdfExtract(uint16_t cipher, const Vector<uint8_t>& salt, const Vector<uint8_t>& ikm)
{
    if (cipher == 0x1302)  // SHA-384
        return driftstackHkdfExtractSha384(salt, ikm);
    return driftstackHkdfExtractSha256(salt, ikm);
}

Vector<uint8_t> hkdfExpandLabel(uint16_t cipher, const Vector<uint8_t>& secret,
                                  const char* label, const Vector<uint8_t>& context, size_t outLen)
{
    if (cipher == 0x1302)
        return driftstackHkdfExpandLabelSha384(secret, label, context, outLen);
    return driftstackHkdfExpandLabelSha256(secret, label, context, outLen);
}

Vector<uint8_t> deriveSecret(uint16_t cipher, const Vector<uint8_t>& secret,
                              const char* label, const Vector<uint8_t>& transcriptHash, size_t hashLen)
{
    return hkdfExpandLabel(cipher, secret, label, transcriptHash, hashLen);
}

Vector<uint8_t> emptyHash(uint16_t cipher)
{
    if (cipher == 0x1302)
        return driftstackSHA384(nullptr, 0);
    return driftstackSHA256(nullptr, 0);
}

} // namespace

void TLS13KeySchedule::setCipherSuite(uint16_t cipher)
{
    m_cipherSuite = cipher;
    // 0x1302 = TLS_AES_256_GCM_SHA384, 0x1301 = TLS_AES_128_GCM_SHA256, 0x1303 = CHACHA
    if (cipher == 0x1302) {
        m_hashLen = 48;
        m_keyLen = 32;
    } else {
        // 0x1301 + 0x1303 use SHA-256; AES-128 = 16 bytes, ChaCha20 = 32 bytes
        m_hashLen = 32;
        m_keyLen = (cipher == 0x1303) ? 32 : 16;
    }
}

bool TLS13KeySchedule::initFromHandshake(const Vector<uint8_t>& ecdhShared,
                                          const Vector<uint8_t>& transcriptHashCHtoSH)
{
    // Cipher-aware (Wave 29-499.186): hashLen is 32 (SHA-256) or 48 (SHA-384).
    Vector<uint8_t> zeros(m_hashLen);
    memset(zeros.mutableSpan().data(), 0, m_hashLen);
    Vector<uint8_t> zeroSalt(m_hashLen);
    memset(zeroSalt.mutableSpan().data(), 0, m_hashLen);
    m_earlySecret = hkdfExtract(m_cipherSuite, zeroSalt, zeros);
    if (m_earlySecret.size() != m_hashLen) {
        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.186] early_secret derivation failed (cipher=0x%04x hashLen=%zu)", m_cipherSuite, m_hashLen);
        return false;
    }

    auto eh = emptyHash(m_cipherSuite);
    auto hsSalt = deriveSecret(m_cipherSuite, m_earlySecret, "derived", eh, m_hashLen);
    m_handshakeSecret = hkdfExtract(m_cipherSuite, hsSalt, ecdhShared);
    if (m_handshakeSecret.size() != m_hashLen) {
        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.186] handshake_secret derivation failed");
        return false;
    }

    m_clientHsSecret = deriveSecret(m_cipherSuite, m_handshakeSecret, "c hs traffic", transcriptHashCHtoSH, m_hashLen);
    m_serverHsSecret = deriveSecret(m_cipherSuite, m_handshakeSecret, "s hs traffic", transcriptHashCHtoSH, m_hashLen);
    if (m_clientHsSecret.size() != m_hashLen || m_serverHsSecret.size() != m_hashLen) {
        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.186] handshake traffic secrets failed");
        return false;
    }

    WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.186] Handshake secrets derived OK (cipher=0x%04x hashLen=%zu keyLen=%zu)", m_cipherSuite, m_hashLen, m_keyLen);
    return true;
}

bool TLS13KeySchedule::deriveApplicationSecrets(const Vector<uint8_t>& transcriptHashCHtoServerFinished)
{
    auto eh = emptyHash(m_cipherSuite);
    auto msSalt = deriveSecret(m_cipherSuite, m_handshakeSecret, "derived", eh, m_hashLen);
    Vector<uint8_t> zeros(m_hashLen);
    memset(zeros.mutableSpan().data(), 0, m_hashLen);
    m_masterSecret = hkdfExtract(m_cipherSuite, msSalt, zeros);
    if (m_masterSecret.size() != m_hashLen) {
        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.186] master_secret derivation failed");
        return false;
    }

    m_clientAppSecret = deriveSecret(m_cipherSuite, m_masterSecret, "c ap traffic", transcriptHashCHtoServerFinished, m_hashLen);
    m_serverAppSecret = deriveSecret(m_cipherSuite, m_masterSecret, "s ap traffic", transcriptHashCHtoServerFinished, m_hashLen);
    if (m_clientAppSecret.size() != m_hashLen || m_serverAppSecret.size() != m_hashLen) {
        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.186] app traffic secrets failed");
        return false;
    }
    WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.186] Application secrets derived OK");
    return true;
}

TLS13TrafficKey TLS13KeySchedule::deriveTrafficKey(const Vector<uint8_t>& trafficSecret) const
{
    TLS13TrafficKey out;
    out.key = hkdfExpandLabel(m_cipherSuite, trafficSecret, "key", {}, m_keyLen);
    out.iv = hkdfExpandLabel(m_cipherSuite, trafficSecret, "iv", {}, 12);
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
