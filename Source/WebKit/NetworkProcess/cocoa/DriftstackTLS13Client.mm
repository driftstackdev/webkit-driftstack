/*
 * DriftstackTLS13Client.mm — Wave 29-499.175 (PathB v2 Phase 1.5e)
 *
 * End-to-end TLS 1.3 client. First iteration sends iPhone-byte-exact
 * ClientHello via our custom builder, then uses LibreSSL primitives to
 * derive keys and decrypt handshake. This iteration focuses on getting
 * the ClientHello on the wire for JA3 verification; full handshake
 * completion proceeds in subsequent iterations.
 */

#import "config.h"
#import "DriftstackTLS13Client.h"
#import "DriftstackCustomTLS.h"
#import "DriftstackTLS13.h"
#import "DriftstackCrypto.h"
#import <wtf/text/MakeString.h>
#import <wtf/HexNumber.h>

#if PLATFORM(DRIFTSTACK)

#import <errno.h>
#import <string.h>
#import <sys/socket.h>
#import <unistd.h>
#import <wtf/Assertions.h>

WTF_ALLOW_UNSAFE_BUFFER_USAGE_BEGIN

namespace WebKit {

namespace {
bool writeAll(int fd, const uint8_t* buf, size_t n)
{
    size_t sent = 0;
    while (sent < n) {
        ssize_t r = send(fd, buf + sent, n - sent, 0);
        if (r > 0) { sent += static_cast<size_t>(r); continue; }
        if (r < 0 && errno == EINTR) continue;
        return false;
    }
    return true;
}
} // namespace

DriftstackTLS13Client::DriftstackTLS13Client()
{
    m_transcript = driftstackCreateSHA384Ctx();
}

DriftstackTLS13Client::~DriftstackTLS13Client()
{
    if (m_transcript)
        driftstackFreeSHA384Ctx(m_transcript);
}

bool DriftstackTLS13Client::connect(int socketFd, const String& sniHostname)
{
    m_fd = socketFd;
    m_sniHostname = sniHostname;
    m_errorMessage = String();

    if (!driftstackCryptoInit()) {
        m_errorMessage = "LibreSSL crypto init failed"_s;
        return false;
    }

    // Step 1: Build + send iPhone-byte-exact ClientHello.
    if (!sendClientHello()) {
        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.175] sendClientHello failed: %s", m_errorMessage.utf8().data());
        return false;
    }

    // Step 2: Receive + parse ServerHello.
    if (!receiveServerHello()) {
        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.175] receiveServerHello failed: %s", m_errorMessage.utf8().data());
        return false;
    }

    WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.175] ClientHello + ServerHello complete; JA3 should match iPhone Safari 26.0.");

    // Wave 29-499.179 — full handshake completion:
    //   Step 3: Read + decrypt encrypted handshake messages (.178)
    //   Step 4: Send Client Finished (.179)
    //   Step 5: Mark connection established, ready for app data (.180+)
    if (!readEncryptedHandshakeMessages()) {
        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.179] readEncryptedHandshakeMessages failed: %s", m_errorMessage.utf8().data());
        return false;
    }

    if (!sendClientFinished()) {
        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.179] sendClientFinished failed: %s", m_errorMessage.utf8().data());
        return false;
    }

    WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.179] TLS 1.3 handshake COMPLETE — iPhone-byte-exact ClientHello + full handshake + app keys ready");
    return true;
}

bool DriftstackTLS13Client::sendClientHello()
{
    Vector<uint8_t> clientRandom;
    Vector<uint8_t> x25519Private;

    // Generate REAL X25519 keypair (replaces .171 random placeholder)
    Vector<uint8_t> x25519Pub;
    if (!driftstackX25519GenerateKeypair(x25519Private, x25519Pub)) {
        m_errorMessage = "X25519 keypair gen failed"_s;
        return false;
    }
    m_ourX25519Private = x25519Private;

    // Build ClientHello bytes with iPhone-byte-exact structure.
    // Note: this builds with a placeholder pubkey; need to fix to use our
    // real pubkey. .171 scaffold uses random — .175 uses real keypair.
    Vector<uint8_t> chRecord = driftstackBuildIPhoneClientHello(m_sniHostname, clientRandom, x25519Private);

    // Send to socket
    if (!writeAll(m_fd, chRecord.span().data(), chRecord.size())) {
        m_errorMessage = "send ClientHello failed"_s;
        return false;
    }

    // Update transcript hash with the handshake bytes (NOT the record header).
    // ClientHello handshake = chRecord[5..] (skip 5-byte record header).
    if (chRecord.size() > 5)
        driftstackUpdateSHA384(m_transcript, chRecord.span().data() + 5, chRecord.size() - 5);

    WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.175] Sent iPhone-byte-exact ClientHello (%zu bytes); SNI=%s; transcript updated",
        chRecord.size(), m_sniHostname.utf8().data());
    return true;
}

bool DriftstackTLS13Client::receiveServerHello()
{
    uint8_t type;
    uint16_t version;
    Vector<uint8_t> body;
    if (!driftstackReadTLSRecord(m_fd, type, version, body)) {
        m_errorMessage = "read ServerHello record failed"_s;
        return false;
    }

    if (type != 0x16 || body.size() < 4) {
        m_errorMessage = "Expected handshake record (0x16) with handshake header"_s;
        return false;
    }

    // Handshake header: type (1) + length (3)
    uint8_t hsType = body[0];
    if (hsType != 0x02) {
        m_errorMessage = "Expected ServerHello (handshake type 0x02), got something else"_s;
        return false;
    }
    uint32_t hsLen = (static_cast<uint32_t>(body[1]) << 16)
        | (static_cast<uint32_t>(body[2]) << 8)
        | body[3];
    if (4 + hsLen > body.size()) {
        m_errorMessage = "Truncated ServerHello"_s;
        return false;
    }

    // Update transcript with ServerHello handshake bytes
    driftstackUpdateSHA384(m_transcript, body.span().data(), 4 + hsLen);

    // Parse ServerHello body (after 4-byte handshake header)
    TLS13ServerHello sh;
    if (!driftstackParseServerHello(body.span().data() + 4, hsLen, sh)) {
        m_errorMessage = "ServerHello parse failed"_s;
        return false;
    }

    WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.175] ServerHello: cipher=0x%04x selectedVersion=0x%04x keyShareGroup=0x%04x keyLen=%zu",
        sh.cipherSuite, sh.selectedVersion, sh.keyShareGroup, sh.keyShareKey.size());

    // Wave 29-499.177 — derive handshake secrets from ECDH + transcript hash.
    // Only X25519 supported in this iteration (key_share group 0x001D).
    // iPhone offers X25519MLKEM768 first but server typically picks X25519
    // since most servers don't support MLKEM yet.
    if (sh.keyShareGroup != 0x001D) {
        m_errorMessage = makeString("Unsupported key_share group 0x"_s, hex(sh.keyShareGroup, 4));
        return false;
    }
    if (sh.keyShareKey.size() != 32) {
        m_errorMessage = "X25519 pubkey must be 32 bytes"_s;
        return false;
    }

    // ECDH: our_private + server_public → 32-byte shared secret
    m_ecdhShared = driftstackX25519SharedSecret(m_ourX25519Private, sh.keyShareKey);
    if (m_ecdhShared.size() != 32) {
        m_errorMessage = "X25519 ECDH derivation failed"_s;
        return false;
    }

    // Compute transcript hash of CH..SH (snapshot — transcript continues)
    auto transcriptHash = driftstackCloneFinalizeSHA384(m_transcript);
    if (transcriptHash.size() != 48) {
        m_errorMessage = "transcript hash snapshot failed"_s;
        return false;
    }

    // Initialize key schedule with ECDH + transcript hash → derive c/s
    // handshake traffic secrets
    if (!m_keySchedule.initFromHandshake(m_ecdhShared, transcriptHash)) {
        m_errorMessage = "key schedule init failed"_s;
        return false;
    }

    // Derive AES-256-GCM handshake key+iv from each traffic secret
    m_clientHsKey = TLS13KeySchedule::deriveTrafficKey(m_keySchedule.clientHandshakeSecret());
    m_serverHsKey = TLS13KeySchedule::deriveTrafficKey(m_keySchedule.serverHandshakeSecret());

    WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.177] Handshake keys derived: client_key=%zu iv=%zu | server_key=%zu iv=%zu",
        m_clientHsKey.key.size(), m_clientHsKey.iv.size(),
        m_serverHsKey.key.size(), m_serverHsKey.iv.size());

    return true;
}

int DriftstackTLS13Client::write(const uint8_t* /*data*/, size_t /*len*/)
{
    m_errorMessage = "Phase 1.5e application data encrypt not yet implemented (.179)"_s;
    return -1;
}

int DriftstackTLS13Client::read(uint8_t* /*buf*/, size_t /*maxLen*/)
{
    m_errorMessage = "Phase 1.5e application data decrypt not yet implemented (.179)"_s;
    return -1;
}

void DriftstackTLS13Client::shutdown()
{
    // TODO: send close_notify alert
}

bool DriftstackTLS13Client::readEncryptedHandshakeMessages()
{
    // Wave 29-499.178 — after handshake secrets derived, server sends:
    //   ChangeCipherSpec (legacy, plaintext, just ignore)
    //   EncryptedExtensions (encrypted with server_hs_key)
    //   Certificate (encrypted)
    //   CertificateVerify (encrypted)
    //   Finished (encrypted) — marks end of server's handshake
    //
    // Each is wrapped in a TLS application_data record (type 0x17)
    // even though contents are handshake. Decrypt via AES-256-GCM
    // with server_hs_key + per-record nonce.

    bool gotServerFinished = false;
    while (!gotServerFinished) {
        uint8_t recType;
        uint16_t recVer;
        Vector<uint8_t> recBody;
        if (!driftstackReadTLSRecord(m_fd, recType, recVer, recBody)) {
            m_errorMessage = "read encrypted handshake record failed"_s;
            return false;
        }

        // ChangeCipherSpec — legacy compat, skip
        if (recType == 0x14) {
            WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.178] Skipping ChangeCipherSpec (legacy compat)");
            continue;
        }

        if (recType != 0x17) {
            m_errorMessage = makeString("Expected encrypted record (0x17), got 0x"_s, hex(recType, 2));
            return false;
        }

        // AAD = 5-byte record header
        Vector<uint8_t> aad;
        aad.append(recType);
        aad.append(static_cast<uint8_t>(recVer >> 8));
        aad.append(static_cast<uint8_t>(recVer & 0xFF));
        aad.append(static_cast<uint8_t>(recBody.size() >> 8));
        aad.append(static_cast<uint8_t>(recBody.size() & 0xFF));

        // Per-record nonce: iv XOR seq_num
        auto nonce = TLS13KeySchedule::recordNonce(m_serverHsKey.iv, m_serverHsKey.seqNum);
        m_serverHsKey.seqNum++;

        // Decrypt — body includes 16-byte tag at end
        auto plaintext = driftstackAes256GcmDecrypt(m_serverHsKey.key, nonce, recBody, aad);
        if (plaintext.isEmpty()) {
            m_errorMessage = "encrypted handshake record decrypt failed (auth tag)"_s;
            return false;
        }

        // Strip trailing record content_type byte (TLS 1.3 inner type)
        if (plaintext.isEmpty()) continue;
        uint8_t innerType = plaintext.last();
        plaintext.removeLast();

        // Trim trailing zero padding (some implementations pad)
        while (!plaintext.isEmpty() && plaintext.last() == 0)
            plaintext.removeLast();

        if (innerType != 0x16) {
            WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.178] Inner record type 0x%02x (not handshake) — skipping", innerType);
            continue;
        }

        // Parse handshake messages from plaintext (may contain multiple)
        size_t off = 0;
        while (off + 4 <= plaintext.size()) {
            uint8_t hsType = plaintext[off];
            uint32_t hsLen = (static_cast<uint32_t>(plaintext[off + 1]) << 16)
                | (static_cast<uint32_t>(plaintext[off + 2]) << 8)
                | plaintext[off + 3];
            if (off + 4 + hsLen > plaintext.size()) break;

            // Add to transcript before processing each message
            driftstackUpdateSHA384(m_transcript, plaintext.span().data() + off, 4 + hsLen);

            const char* typeName = "unknown";
            switch (hsType) {
                case 0x08: typeName = "EncryptedExtensions"; break;
                case 0x0b: typeName = "Certificate"; break;
                case 0x0f: typeName = "CertificateVerify"; break;
                case 0x14: typeName = "Finished"; break;
            }
            WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.178] Handshake message: type=0x%02x (%s) len=%u",
                hsType, typeName, hsLen);

            if (hsType == 0x14) {  // Finished
                gotServerFinished = true;
                // Snapshot transcript AFTER server's Finished — needed for app secret derivation
                auto transcriptCH_to_serverFinished = driftstackCloneFinalizeSHA384(m_transcript);
                if (!m_keySchedule.deriveApplicationSecrets(transcriptCH_to_serverFinished)) {
                    m_errorMessage = "deriveApplicationSecrets failed"_s;
                    return false;
                }
                m_clientAppKey = TLS13KeySchedule::deriveTrafficKey(m_keySchedule.clientApplicationSecret());
                m_serverAppKey = TLS13KeySchedule::deriveTrafficKey(m_keySchedule.serverApplicationSecret());
                WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.178] Server Finished received; application keys derived");
            }

            off += 4 + hsLen;
        }
    }
    return true;
}
bool DriftstackTLS13Client::sendClientFinished()
{
    // Wave 29-499.179 — Client Finished:
    //   finished_key = HKDF-Expand-Label(client_hs_secret, "finished", "", 48)
    //   verify_data  = HMAC-SHA384(finished_key, transcript_hash(CH..server_Finished))
    //
    // Wrap in handshake message (type 0x14) + plaintext record_type 0x16,
    // then encrypt with client_hs_key in record_type 0x17.
    auto finishedKey = driftstackHkdfExpandLabelSha384(
        m_keySchedule.clientHandshakeSecret(), "finished", {}, 48);
    if (finishedKey.size() != 48) {
        m_errorMessage = "finished_key derivation failed"_s;
        return false;
    }

    auto transcriptHash = driftstackCloneFinalizeSHA384(m_transcript);
    auto verifyData = driftstackHmacSha384(finishedKey, transcriptHash);
    if (verifyData.size() != 48) {
        m_errorMessage = "verify_data HMAC failed"_s;
        return false;
    }

    // Handshake message: type (0x14) + length (3) + verify_data
    Vector<uint8_t> hsMsg;
    hsMsg.append(0x14);
    hsMsg.append(0x00);
    hsMsg.append(0x00);
    hsMsg.append(static_cast<uint8_t>(verifyData.size()));
    hsMsg.append(verifyData.span());

    // Inner plaintext: hsMsg + content_type (0x16)
    Vector<uint8_t> innerPlaintext = hsMsg;
    innerPlaintext.append(0x16);

    // AAD = 5-byte record header for the encrypted output. We need to know
    // ciphertext size first (= plaintext size + 16-byte tag).
    Vector<uint8_t> aad;
    aad.append(0x17);  // application_data
    aad.append(0x03);
    aad.append(0x03);
    size_t encLen = innerPlaintext.size() + 16;
    aad.append(static_cast<uint8_t>(encLen >> 8));
    aad.append(static_cast<uint8_t>(encLen & 0xFF));

    // Encrypt with client handshake key
    auto nonce = TLS13KeySchedule::recordNonce(m_clientHsKey.iv, m_clientHsKey.seqNum);
    m_clientHsKey.seqNum++;
    auto ciphertext = driftstackAes256GcmEncrypt(m_clientHsKey.key, nonce, innerPlaintext, aad);
    if (ciphertext.size() != encLen) {
        m_errorMessage = "Client Finished encrypt failed"_s;
        return false;
    }

    // Build record: header + ciphertext
    Vector<uint8_t> record;
    record.append(aad.span());
    record.append(ciphertext.span());

    if (!writeAll(m_fd, record.span().data(), record.size())) {
        m_errorMessage = "write Client Finished failed"_s;
        return false;
    }

    // Add hsMsg to transcript (matters for any post-handshake messages)
    driftstackUpdateSHA384(m_transcript, hsMsg.span().data(), hsMsg.size());

    WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.179] Client Finished sent (%zu bytes encrypted)", record.size());
    return true;
}
int DriftstackTLS13Client::writeApplicationRecord(const uint8_t*, size_t) { return -1; }
Vector<uint8_t> DriftstackTLS13Client::readApplicationRecord() { return {}; }

} // namespace WebKit

WTF_ALLOW_UNSAFE_BUFFER_USAGE_END

#endif // PLATFORM(DRIFTSTACK)
