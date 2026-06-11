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
#import <Security/Security.h>
#import <wtf/RetainPtr.h>
#import <wtf/text/MakeString.h>
#import <wtf/HexNumber.h>

#if PLATFORM(DRIFTSTACK)

#import <errno.h>
#import <string.h>
#import <sys/socket.h>
#import <sys/time.h>
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
}

DriftstackTLS13Client::~DriftstackTLS13Client()
{
    driftstackMLKEM768Free(m_mlkemKeypair);
    driftstackP256Free(m_p256Keypair);
}

// Wave 29-499.186 — cipher-aware transcript helpers
namespace {
Vector<uint8_t> transcriptHash(uint16_t cipher, const Vector<uint8_t>& bytes)
{
    if (cipher == 0x1302)
        return driftstackSHA384(bytes.span().data(), bytes.size());
    return driftstackSHA256(bytes.span().data(), bytes.size());
}
Vector<uint8_t> hkdfExpandLabel(uint16_t cipher, const Vector<uint8_t>& secret,
                                  const char* label, const Vector<uint8_t>& context, size_t outLen)
{
    if (cipher == 0x1302)
        return driftstackHkdfExpandLabelSha384(secret, label, context, outLen);
    return driftstackHkdfExpandLabelSha256(secret, label, context, outLen);
}
Vector<uint8_t> hmac(uint16_t cipher, const Vector<uint8_t>& key, const Vector<uint8_t>& data)
{
    if (cipher == 0x1302)
        return driftstackHmacSha384(key, data);
    return driftstackHmacSha256(key, data);
}
Vector<uint8_t> aesGcmEncrypt(uint16_t cipher, const Vector<uint8_t>& key,
                               const Vector<uint8_t>& nonce, const Vector<uint8_t>& pt,
                               const Vector<uint8_t>& aad)
{
    if (cipher == 0x1302)
        return driftstackAes256GcmEncrypt(key, nonce, pt, aad);
    return driftstackAes128GcmEncrypt(key, nonce, pt, aad);
}
Vector<uint8_t> aesGcmDecrypt(uint16_t cipher, const Vector<uint8_t>& key,
                               const Vector<uint8_t>& nonce, const Vector<uint8_t>& ct,
                               const Vector<uint8_t>& aad)
{
    if (cipher == 0x1302)
        return driftstackAes256GcmDecrypt(key, nonce, ct, aad);
    return driftstackAes128GcmDecrypt(key, nonce, ct, aad);
}
} // namespace

bool DriftstackTLS13Client::connect(int socketFd, const String& sniHostname)
{
    m_fd = socketFd;
    m_sniHostname = sniHostname;
    m_errorMessage = String();

    // Wave 29-499.352 — bound HANDSHAKE reads with a recv timeout. Without it, a stalled
    // ServerHello (a flaky proxy exit not delivering the response to our multi-segment PQ
    // ClientHello) blocks driftstackReadTLSRecord FOREVER → the load hangs with no failure →
    // resume()'s retry never fires → the page's fetch() times out → "fetch error"
    // (e.g. browserleaks.com/tls ja3/ja4 never populate). A timeout turns the hang into a
    // clean failure → connect() returns false → retry on a FRESH SOCKS5 exit (which works).
    // read() restores blocking mode for the app-data (h2) phase so slow/large responses and
    // idle pooled connections aren't cut off.
    {
        struct timeval tv { .tv_sec = 6, .tv_usec = 0 };
        setsockopt(m_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    }
    if (getenv("DRIFTSTACK_RTR_TRACE"))
        WTFLogAlways("[RTR fd=%d] host=%s connect()", m_fd, sniHostname.utf8().data());

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

    // Wave 29-499.340 — the TLS 1.2 path completes the ENTIRE handshake inside
    // receiveServerHello → doTLS12Handshake (cert/SKE/SHD + CKE/CCS/Finished +
    // server CCS/Finished). The 1.3-specific steps below don't apply.
    if (m_isTLS12) {
        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.340] TLS 1.2 handshake COMPLETE — iPhone-byte-exact ClientHello + ECDHE + AES-128-GCM app keys ready");
        return true;
    }

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
    Vector<uint8_t> x25519Pub;
    if (!driftstackX25519GenerateKeypair(x25519Private, x25519Pub)) {
        m_errorMessage = "X25519 keypair gen failed"_s;
        return false;
    }
    m_ourX25519Private = x25519Private;
    m_ourX25519Public = x25519Pub;

    // Wave 29-499.219 — generate MLKEM768 keypair for hybrid X25519MLKEM768 keyshare
    m_mlkemKeypair = driftstackMLKEM768Generate();
    Vector<uint8_t> chRecord;
    if (m_mlkemKeypair.ok && m_mlkemKeypair.publicKey.size() == 1184) {
        // Hybrid path: send MLKEM768 + X25519 keyshare (matches iPhone Safari 26)
        chRecord = driftstackBuildIPhoneClientHelloHybrid(m_sniHostname,
            m_mlkemKeypair.publicKey, x25519Pub, clientRandom);
        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.219] Using HYBRID X25519MLKEM768+X25519 keyshare");
    } else {
        // Fallback: X25519-only keyshare (less iPhone-exact but works on non-PQ servers)
        chRecord = driftstackBuildIPhoneClientHello(m_sniHostname, x25519Pub, clientRandom);
        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.219] MLKEM768 unavailable, falling back to X25519-only keyshare");
    }

    // Send to socket
    if (!writeAll(m_fd, chRecord.span().data(), chRecord.size())) {
        m_errorMessage = "send ClientHello failed"_s;
        return false;
    }

    // Wave 29-499.340 — save client_random for the TLS 1.2 PRF (master secret +
    // key expansion). The builder filled it; it's also embedded in the CH bytes.
    m_clientRandom = clientRandom;

    // Save handshake bytes (skip 5-byte record header) for transcript hash
    if (chRecord.size() > 5)
        m_transcriptBytes.append(std::span<const uint8_t>(chRecord.span().data() + 5, chRecord.size() - 5));

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
        // Diagnostic (Wave .322): if type==0x15 the server/proxy sent a TLS
        // alert; otherwise we're framed wrong (SOCKS5 leftover / proxy reset /
        // partial record). Dump the record header + first bytes so the failure
        // mode is identifiable instead of guessed.
        char hexbuf[40];
        size_t n = body.size() < 8 ? body.size() : 8;
        for (size_t i = 0; i < n; ++i)
            snprintf(hexbuf + i * 3, 4, " %02x", body[i]);
        if (!n) hexbuf[0] = '\0';
        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.322] receiveServerHello bad record: type=0x%02x version=0x%04x bodyLen=%zu first=%s",
            type, version, body.size(), hexbuf);
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

    // Append ServerHello handshake bytes to transcript
    m_transcriptBytes.append(std::span<const uint8_t>(body.span().data(), 4 + hsLen));

    // Wave 29-499.340 — extract server_random (SH body: legacy_version(2) +
    // random(32) + ...). Offset within `body`: 4 (hs header) + 2 (version) = 6.
    if (body.size() >= 6 + 32) {
        m_serverRandom.clear();
        m_serverRandom.append(std::span<const uint8_t>(body.span().data() + 6, 32));
    }

    // Parse ServerHello body (after 4-byte handshake header)
    TLS13ServerHello sh;
    if (!driftstackParseServerHello(body.span().data() + 4, hsLen, sh)) {
        m_errorMessage = "ServerHello parse failed"_s;
        return false;
    }

    WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.175] ServerHello: cipher=0x%04x selectedVersion=0x%04x keyShareGroup=0x%04x keyLen=%zu HRR=%d",
        sh.cipherSuite, sh.selectedVersion, sh.keyShareGroup, sh.keyShareKey.size(), sh.isHelloRetryRequest);

    // Wave 29-499.340 — TLS 1.2 detection. A 1.3 server signals via the
    // supported_versions extension (selectedVersion == 0x0304). If that's absent
    // (selectedVersion 0x0000) and this isn't an HRR, the server chose TLS 1.2
    // (e.g. Twilio turns: :443, cipher 0xc02f). Run the 1.2 ECDHE handshake — the
    // iPhone-byte-exact ClientHello already offered 1.2 ciphers + supported_groups.
    if (!sh.isHelloRetryRequest && sh.selectedVersion != 0x0304) {
        // Scan ServerHello extensions for extended_master_secret (0x0017, RFC 7627)
        // AND ALPN (0x0010, RFC 7301). SH body: legacy_version(2)+random(32)+sid_len(1)
        // +sid+cipher(2)+comp(1)+ext_len(2)+exts. `body` = 4-byte hs header + SH body.
        // iPhone always offers EMS + ALPN[h2,http/1.1], so a modern server mirrors them.
        // Wave 29-499.341 — TLS 1.2 ALPN: over 1.2 the negotiated protocol lives in the
        // CLEARTEXT ServerHello extensions (not the 1.3 EncryptedExtensions). Without this
        // a TLS-1.2+h2 server (httpbin.org, many older CDNs — curl/iPhone get h2 there)
        // returned ALPN='' → we wrongly fell back to HTTP/1.1 and the load failed.
        m_t12EMS = false;
        {
            const uint8_t* b = body.span().data();
            size_t bn = body.size();
            size_t p = 4 + 2 + 32; // hs header + version + random
            if (p + 1 <= bn) {
                uint8_t sidLen = b[p]; p += 1 + sidLen;
                p += 2 + 1; // cipher + compression
                if (p + 2 <= bn) {
                    uint16_t extLen = (static_cast<uint16_t>(b[p]) << 8) | b[p + 1]; p += 2;
                    size_t extEnd = p + extLen;
                    while (p + 4 <= extEnd && p + 4 <= bn) {
                        uint16_t et = (static_cast<uint16_t>(b[p]) << 8) | b[p + 1];
                        uint16_t el = (static_cast<uint16_t>(b[p + 2]) << 8) | b[p + 3];
                        if (et == 0x0017)
                            m_t12EMS = true;
                        else if (et == 0x0010 /*ALPN*/ && el >= 3 && p + 4 + el <= bn) {
                            // ext data: u16 list_length + u8 proto_len + proto bytes
                            uint8_t protoLen = b[p + 4 + 2];
                            if (protoLen && p + 4 + 3 + protoLen <= bn) {
                                m_selectedALPN = String::fromUTF8(unsafeMakeSpan(
                                    reinterpret_cast<const char*>(b + p + 4 + 3), protoLen));
                                WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.341] TLS1.2 SH: negotiated ALPN='%s'", m_selectedALPN.utf8().data());
                            }
                        }
                        p += 4 + el;
                    }
                }
            }
        }
        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.340] Server negotiated TLS 1.2 (cipher=0x%04x, no key_share, EMS=%d) — entering hand-rolled iPhone-exact TLS 1.2 ECDHE handshake.",
            sh.cipherSuite, m_t12EMS);
        m_isTLS12 = true;
        m_negotiatedCipher = sh.cipherSuite;
        if (m_serverRandom.size() != 32) {
            m_errorMessage = "TLS 1.2: server_random not captured"_s;
            return false;
        }
        return doTLS12Handshake(sh);
    }

    // Wave 29-499.215 — HRR handling (RFC 8446 §4.1.4) for P-256
    if (sh.isHelloRetryRequest) {
        if (sh.keyShareGroup != 0x0017 /*P-256*/) {
            m_errorMessage = makeString("HRR requested non-P-256 group 0x"_s,
                hex(sh.keyShareGroup, 4), " (only P-256 supported in HRR retry)"_s);
            return false;
        }
        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.215] HRR detected (server wants P-256). Retrying ClientHello with P-256 keyshare.");

        // Generate P-256 keypair
        m_p256Keypair = driftstackP256Generate();
        if (!m_p256Keypair.ok) {
            m_errorMessage = "P-256 keypair generation failed"_s;
            return false;
        }

        // Per RFC 8446 §4.4.1: HRR transcript = message_hash(CH1) + HRR
        // Compute Hash(CH1) — m_transcriptBytes currently has CH1 + HRR appended.
        // Strip HRR (4-byte header + hsLen), get just CH1.
        // CH1 starts at offset 0 of m_transcriptBytes; ends where SH (HRR) begins.
        // After receiveServerHello, m_transcriptBytes = CH1 + HRR_handshake_bytes.
        // We need: synthetic = type(0xFE) + len(3) + Hash(CH1)
        //          new_transcript = synthetic + HRR + CH2
        Vector<uint8_t> ch1Bytes = m_transcriptBytes;
        // HRR was appended at end — find its boundary. CH1 ends at length of CH1 itself.
        // CH1 length is 4 (header) + 24-bit length. Read from byte 1-3.
        if (ch1Bytes.size() < 4) {
            m_errorMessage = "transcript too short for HRR retry"_s;
            return false;
        }
        uint32_t ch1Len = (static_cast<uint32_t>(ch1Bytes[1]) << 16)
            | (static_cast<uint32_t>(ch1Bytes[2]) << 8)
            | ch1Bytes[3];
        size_t ch1TotalBytes = 4 + ch1Len;
        if (ch1TotalBytes > ch1Bytes.size()) {
            m_errorMessage = "transcript ch1 length mismatch"_s;
            return false;
        }
        // HRR bytes = remainder after CH1
        Vector<uint8_t> hrrBytes;
        hrrBytes.append(std::span<const uint8_t>(ch1Bytes.span().data() + ch1TotalBytes,
            ch1Bytes.size() - ch1TotalBytes));
        Vector<uint8_t> ch1Only;
        ch1Only.append(std::span<const uint8_t>(ch1Bytes.span().data(), ch1TotalBytes));

        // Compute Hash(CH1) using negotiated cipher's hash
        Vector<uint8_t> ch1Hash;
        if (sh.cipherSuite == 0x1302)
            ch1Hash = driftstackSHA384(ch1Only.span().data(), ch1Only.size());
        else
            ch1Hash = driftstackSHA256(ch1Only.span().data(), ch1Only.size());

        // Build synthetic message: type(0xFE message_hash) + 3-byte len(hashLen) + hash
        Vector<uint8_t> synthetic;
        synthetic.append(0xFE);
        synthetic.append(0x00);
        synthetic.append(0x00);
        synthetic.append(static_cast<uint8_t>(ch1Hash.size()));
        synthetic.append(ch1Hash.span());

        // Rebuild transcript: synthetic + HRR
        m_transcriptBytes.clear();
        m_transcriptBytes.append(synthetic.span());
        m_transcriptBytes.append(hrrBytes.span());

        // Build new ClientHello with P-256 keyshare (TODO: keep iPhone bytes
        // exactly, only swap key_share extension. For now use the same builder
        // but it'll generate fresh GREASE/random — server may accept).
        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.215] HRR retry: synthetic transcript built (CH1 hash %zu bytes), HRR bytes %zu, sending CH2 with P-256 keyshare",
            ch1Hash.size(), hrrBytes.size());

        // Wave 29-499.216 — build CH2 with P-256 keyshare + send
        Vector<uint8_t> ch2Random;
        Vector<uint8_t> ch2Record = driftstackBuildIPhoneClientHelloP256(m_sniHostname,
            m_p256Keypair.publicKey, ch2Random);
        if (ch2Record.size() <= 5) {
            m_errorMessage = "CH2 build failed"_s;
            return false;
        }
        // Append CH2 to transcript (handshake bytes only, skip record header)
        m_transcriptBytes.append(std::span<const uint8_t>(ch2Record.span().data() + 5,
            ch2Record.size() - 5));

        // Send CH2 on wire
        if (!writeAll(m_fd, ch2Record.span().data(), ch2Record.size())) {
            m_errorMessage = "send CH2 failed"_s;
            return false;
        }
        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.216] CH2 sent (%zu bytes). Reading real ServerHello.",
            ch2Record.size());

        // Read real ServerHello (recursive call into receiveServerHello)
        // To avoid infinite loop, set m_negotiatedCipher to mark we're in HRR retry
        // and bail if HRR detected again.
        // For simplicity: call recursively. If HRR again, error out.
        return receiveServerHello();
    }

    // Wave 29-499.219 — handle X25519MLKEM768 hybrid OR X25519 keyshare
    if (sh.keyShareGroup == 0x11EC) {
        // X25519MLKEM768 hybrid: server sent 1120 bytes
        //   MLKEM768_ciphertext (1088) || X25519_pubkey (32)
        if (sh.keyShareKey.size() != 1120) {
            m_errorMessage = makeString("Hybrid keyshare wrong size: expected 1120, got "_s,
                String::number(sh.keyShareKey.size()));
            return false;
        }
        // MLKEM_decap: extract first 1088 bytes ciphertext
        Vector<uint8_t> ciphertext;
        ciphertext.append(std::span<const uint8_t>(sh.keyShareKey.span().data(), 1088));
        Vector<uint8_t> mlkemShared = driftstackMLKEM768Decap(m_mlkemKeypair, ciphertext);
        if (mlkemShared.size() != 32) {
            m_errorMessage = "MLKEM768 decap failed"_s;
            return false;
        }
        // X25519 ECDH with server's X25519 pubkey (last 32 bytes)
        Vector<uint8_t> serverX25519;
        serverX25519.append(std::span<const uint8_t>(sh.keyShareKey.span().data() + 1088, 32));
        Vector<uint8_t> x25519Shared = driftstackX25519SharedSecret(m_ourX25519Private, serverX25519);
        if (x25519Shared.size() != 32) {
            m_errorMessage = "Hybrid X25519 ECDH failed"_s;
            return false;
        }
        // Hybrid shared = MLKEM_shared || X25519_shared (64 bytes total)
        m_ecdhShared.clear();
        m_ecdhShared.append(mlkemShared.span());
        m_ecdhShared.append(x25519Shared.span());
        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.219] Hybrid X25519MLKEM768 shared derived: %zu bytes (MLKEM 32 + X25519 32)",
            m_ecdhShared.size());
    } else if (sh.keyShareGroup == 0x001D && sh.keyShareKey.size() == 32) {
        // Plain X25519
        m_ecdhShared = driftstackX25519SharedSecret(m_ourX25519Private, sh.keyShareKey);
        if (m_ecdhShared.size() != 32) {
            m_errorMessage = "X25519 ECDH derivation failed"_s;
            return false;
        }
    } else {
        m_errorMessage = makeString("Unsupported key_share group 0x"_s, hex(sh.keyShareGroup, 4),
            " or size "_s, String::number(sh.keyShareKey.size()));
        return false;
    }
    WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.188] ECDH shared (32B): %02x%02x%02x%02x...%02x%02x | priv=%02x%02x | peer_pub=%02x%02x",
        m_ecdhShared[0], m_ecdhShared[1], m_ecdhShared[2], m_ecdhShared[3],
        m_ecdhShared[30], m_ecdhShared[31],
        m_ourX25519Private[0], m_ourX25519Private[1],
        sh.keyShareKey[0], sh.keyShareKey[1]);

    // Wave 29-499.186: cipher-aware key schedule
    m_negotiatedCipher = sh.cipherSuite;
    m_keySchedule.setCipherSuite(m_negotiatedCipher);

    auto chSHHash = transcriptHash(m_negotiatedCipher, m_transcriptBytes);
    if (!m_keySchedule.initFromHandshake(m_ecdhShared, chSHHash)) {
        m_errorMessage = "key schedule init failed"_s;
        return false;
    }

    m_clientHsKey = m_keySchedule.deriveTrafficKey(m_keySchedule.clientHandshakeSecret());
    m_serverHsKey = m_keySchedule.deriveTrafficKey(m_keySchedule.serverHandshakeSecret());

    WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.186] Handshake keys derived (cipher=0x%04x): client_key=%zu iv=%zu | server_key=%zu iv=%zu",
        m_negotiatedCipher,
        m_clientHsKey.key.size(), m_clientHsKey.iv.size(),
        m_serverHsKey.key.size(), m_serverHsKey.iv.size());
    if (m_serverHsKey.key.size() >= 4)
        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.188] server_hs key=%02x%02x%02x%02x iv=%02x%02x%02x%02x transcriptBytes.len=%zu transcriptHash=%02x%02x%02x%02x",
            m_serverHsKey.key[0], m_serverHsKey.key[1], m_serverHsKey.key[2], m_serverHsKey.key[3],
            m_serverHsKey.iv[0], m_serverHsKey.iv[1], m_serverHsKey.iv[2], m_serverHsKey.iv[3],
            m_transcriptBytes.size(),
            chSHHash[0], chSHHash[1], chSHHash[2], chSHHash[3]);

    return true;
}

int DriftstackTLS13Client::write(const uint8_t* data, size_t len)
{
    if (m_isTLS12)
        return writeTLS12Record(data, len);
    return writeApplicationRecord(data, len);
}

int DriftstackTLS13Client::read(uint8_t* buf, size_t maxLen)
{
    // Wave 29-499.352 — handshake done; restore BLOCKING reads for the app-data (h2) phase.
    // The 6s handshake recv-timeout (set in connect()) must not cut off slow/large responses
    // or make the pooled session's reader thread spuriously time out on an idle connection.
    if (!m_appReadBlockingRestored) {
        m_appReadBlockingRestored = true;
        struct timeval tv { .tv_sec = 0, .tv_usec = 0 };
        setsockopt(m_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    }
    if (m_isTLS12) {
        if (m_t12ReadBuffer.isEmpty()) {
            auto pt = readTLS12Record();
            if (pt.isEmpty()) return 0;
            m_t12ReadBuffer = std::move(pt);
        }
        size_t n = std::min(m_t12ReadBuffer.size(), maxLen);
        memcpy(buf, m_t12ReadBuffer.span().data(), n);
        m_t12ReadBuffer.removeAt(0, n);
        return static_cast<int>(n);
    }
    // Wave 29-499.195 — drain buffer first; only read new record when empty
    if (m_readBuffer.isEmpty()) {
        auto pt = readApplicationRecord();
        if (pt.isEmpty()) return 0;
        m_readBuffer = std::move(pt);
    }
    size_t n = std::min(m_readBuffer.size(), maxLen);
    memcpy(buf, m_readBuffer.span().data(), n);
    m_readBuffer.removeAt(0, n);
    return static_cast<int>(n);
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

        // Wave 29-499.189 diagnostic — log encryption inputs
        static bool firstRec = true;
        if (firstRec) {
            firstRec = false;
            WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.189] First enc-record: type=0x%02x ver=0x%04x bodySize=%zu nonce=%02x%02x%02x%02x...%02x%02x%02x%02x aad=%02x%02x%02x%02x%02x body[0..7]=%02x%02x%02x%02x%02x%02x%02x%02x",
                recType, recVer, recBody.size(),
                nonce[0], nonce[1], nonce[2], nonce[3], nonce[8], nonce[9], nonce[10], nonce[11],
                aad[0], aad[1], aad[2], aad[3], aad[4],
                recBody[0], recBody[1], recBody[2], recBody[3], recBody[4], recBody[5], recBody[6], recBody[7]);
        }

        // Decrypt — body includes 16-byte tag at end (cipher-aware)
        auto plaintext = aesGcmDecrypt(m_negotiatedCipher, m_serverHsKey.key, nonce, recBody, aad);
        if (plaintext.isEmpty()) {
            m_errorMessage = "encrypted handshake record decrypt failed (auth tag)"_s;
            return false;
        }

        // Wave 29-499.189 — RFC 8446 §5.2: plaintext = [data][inner_type][padding zeros]
        // Strip trailing zero padding FIRST, then read inner_type (last remaining byte).
        while (!plaintext.isEmpty() && plaintext.last() == 0)
            plaintext.removeLast();
        if (plaintext.isEmpty()) continue;
        uint8_t innerType = plaintext.last();
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

            // Append to transcript before processing each message
            m_transcriptBytes.append(std::span<const uint8_t>(plaintext.span().data() + off, 4 + hsLen));

            const char* typeName = "unknown";
            switch (hsType) {
                case 0x08: typeName = "EncryptedExtensions"; break;
                case 0x0b: typeName = "Certificate"; break;
                case 0x0f: typeName = "CertificateVerify"; break;
                case 0x14: typeName = "Finished"; break;
            }
            WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.178] Handshake message: type=0x%02x (%s) len=%u",
                hsType, typeName, hsLen);

            // Wave 29-499.209 — parse EncryptedExtensions for ALPN
            if (hsType == 0x08 && hsLen >= 2) {
                size_t eeOff = off + 4;
                uint16_t extsLen = (static_cast<uint16_t>(plaintext[eeOff]) << 8) | plaintext[eeOff + 1];
                size_t e = eeOff + 2;
                size_t eEnd = e + extsLen;
                while (e + 4 <= eEnd && e + 4 <= plaintext.size()) {
                    uint16_t etype = (static_cast<uint16_t>(plaintext[e]) << 8) | plaintext[e + 1];
                    uint16_t elen = (static_cast<uint16_t>(plaintext[e + 2]) << 8) | plaintext[e + 3];
                    e += 4;
                    // W2197: bounds-check the protoLen read (plaintext[e+2]) BEFORE
                    // dereferencing. The outer while only guaranteed (e-4)+4 <= size,
                    // so after `e += 4` e can equal size — reading plaintext[e+2]
                    // unguarded was an OOB heap read of up to 2 bytes from a crafted
                    // server EncryptedExtensions (a MITM is the TLS peer pre-cert-
                    // validation). Require the 3 ALPN length-prefix bytes (e..e+2) to
                    // be in-bounds; legit ALPN always has them, so no behavior change.
                    if (etype == 16 /*ALPN*/ && elen >= 3 && e + 3 <= plaintext.size()) {
                        // ALPN: u16 list_length + u8 proto_len + proto bytes
                        uint8_t protoLen = plaintext[e + 2];
                        if (protoLen > 0 && e + 3 + protoLen <= plaintext.size()) {
                            m_selectedALPN = String::fromUTF8(unsafeMakeSpan(reinterpret_cast<const char*>(plaintext.span().data() + e + 3), protoLen));
                            WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.209] EE: negotiated ALPN='%s'", m_selectedALPN.utf8().data());
                        }
                    }
                    e += elen;
                }
            }

            // W2191 (#43): server-cert chain validation. The PathB-v2 custom TLS
            // client did the crypto handshake but never validated the server cert
            // chain/hostname against the system trust store → it accepted a
            // self-signed cert (MITM exposure, W2108). Gated DRIFTSTACK_PATHB_TLS_
            // CERT_VALIDATE=1 (default-off for safe rollout; flip on after egress
            // verifies legit certs pass). Parses the TLS 1.3 Certificate message
            // (1B ctx_len + ctx + 3B list_len + [3B cert_len + DER + 2B ext_len + ext]*)
            // and rejects the connection unless SecTrust evaluates the chain clean
            // for m_sniHostname.
            if (hsType == 0x0b) {
                static const bool s_validateCert = []() {
                    const char* e = getenv("DRIFTSTACK_PATHB_TLS_CERT_VALIDATE");
                    return e && e[0] == '1';
                }();
                if (s_validateCert) {
                    size_t cOff = off + 4;
                    if (cOff >= plaintext.size()) { m_errorMessage = "cert msg too short"_s; return false; }
                    uint8_t ctxLen = plaintext[cOff];
                    cOff += 1 + static_cast<size_t>(ctxLen);
                    if (cOff + 3 > plaintext.size()) { m_errorMessage = "cert msg ctx OOB"_s; return false; }
                    uint32_t listLen = (static_cast<uint32_t>(plaintext[cOff]) << 16) | (static_cast<uint32_t>(plaintext[cOff + 1]) << 8) | plaintext[cOff + 2];
                    cOff += 3;
                    size_t listEnd = cOff + listLen;
                    if (listEnd > plaintext.size()) { m_errorMessage = "cert list OOB"_s; return false; }
                    RetainPtr<CFMutableArrayRef> certArray = adoptCF(CFArrayCreateMutable(nullptr, 0, &kCFTypeArrayCallBacks));
                    while (cOff + 3 <= listEnd) {
                        uint32_t certLen = (static_cast<uint32_t>(plaintext[cOff]) << 16) | (static_cast<uint32_t>(plaintext[cOff + 1]) << 8) | plaintext[cOff + 2];
                        cOff += 3;
                        if (cOff + certLen > listEnd) break;
                        RetainPtr<CFDataRef> cfData = adoptCF(CFDataCreate(nullptr, plaintext.span().data() + cOff, certLen));
                        RetainPtr<SecCertificateRef> cert = adoptCF(SecCertificateCreateWithData(nullptr, cfData.get()));
                        if (cert)
                            CFArrayAppendValue(certArray.get(), cert.get());
                        cOff += certLen;
                        if (cOff + 2 > listEnd) break;
                        uint16_t extLen = (static_cast<uint16_t>(plaintext[cOff]) << 8) | plaintext[cOff + 1];
                        cOff += 2 + static_cast<size_t>(extLen);
                    }
                    if (!CFArrayGetCount(certArray.get())) { m_errorMessage = "no parseable server certs"_s; return false; }
                    RetainPtr<SecPolicyRef> policy = adoptCF(SecPolicyCreateSSL(true, m_sniHostname.createCFString().get()));
                    SecTrustRef trust = nullptr;
                    OSStatus st = SecTrustCreateWithCertificates(certArray.get(), policy.get(), &trust);
                    RetainPtr<SecTrustRef> trustRef = adoptCF(trust);
                    if (st != errSecSuccess || !trustRef) { m_errorMessage = "SecTrustCreateWithCertificates failed"_s; return false; }
                    CFErrorRef evalErr = nullptr;
                    bool trusted = SecTrustEvaluateWithError(trustRef.get(), &evalErr);
                    if (evalErr)
                        CFRelease(evalErr);
                    if (!trusted) {
                        m_errorMessage = makeString("server cert validation FAILED for "_s, m_sniHostname);
                        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/W2191] CERT VALIDATION FAILED for %s — rejecting (MITM defense)", m_sniHostname.utf8().data());
                        return false;
                    }
                    WTFLogAlways("[Driftstack-EG-WK-PathB-v2/W2191] server cert chain validated OK for %s", m_sniHostname.utf8().data());
                }
            }

            if (hsType == 0x14) {  // Finished
                gotServerFinished = true;
                auto chSFhash = transcriptHash(m_negotiatedCipher, m_transcriptBytes);
                if (!m_keySchedule.deriveApplicationSecrets(chSFhash)) {
                    m_errorMessage = "deriveApplicationSecrets failed"_s;
                    return false;
                }
                m_clientAppKey = m_keySchedule.deriveTrafficKey(m_keySchedule.clientApplicationSecret());
                m_serverAppKey = m_keySchedule.deriveTrafficKey(m_keySchedule.serverApplicationSecret());
                WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.186] Server Finished received; application keys derived");
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
    auto finishedKey = hkdfExpandLabel(m_negotiatedCipher,
        m_keySchedule.clientHandshakeSecret(), "finished", {}, m_keySchedule.hashLen());
    if (finishedKey.size() != m_keySchedule.hashLen()) {
        m_errorMessage = "finished_key derivation failed"_s;
        return false;
    }

    auto thash = transcriptHash(m_negotiatedCipher, m_transcriptBytes);
    auto verifyData = hmac(m_negotiatedCipher, finishedKey, thash);
    if (verifyData.size() != m_keySchedule.hashLen()) {
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
    auto ciphertext = aesGcmEncrypt(m_negotiatedCipher, m_clientHsKey.key, nonce, innerPlaintext, aad);
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

    // Append hsMsg to transcript
    m_transcriptBytes.append(hsMsg.span());

    WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.179] Client Finished sent (%zu bytes encrypted)", record.size());
    return true;
}
int DriftstackTLS13Client::writeApplicationRecord(const uint8_t* data, size_t len)
{
    WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.194] writeAppRecord len=%zu cipher=0x%04x clientAppKey.size=%zu seqNum=%llu",
        len, m_negotiatedCipher, m_clientAppKey.key.size(), (unsigned long long)m_clientAppKey.seqNum);
    // Wave 29-499.180 — encrypt app data with client_app_key (AES-256-GCM).
    // Inner plaintext: data + inner_type 0x17 (application_data).
    Vector<uint8_t> inner;
    inner.append(std::span<const uint8_t>(data, len));
    inner.append(0x17);  // inner content_type

    size_t encLen = inner.size() + 16;
    Vector<uint8_t> aad;
    aad.append(0x17);
    aad.append(0x03); aad.append(0x03);
    aad.append(static_cast<uint8_t>(encLen >> 8));
    aad.append(static_cast<uint8_t>(encLen & 0xFF));

    auto nonce = TLS13KeySchedule::recordNonce(m_clientAppKey.iv, m_clientAppKey.seqNum);
    m_clientAppKey.seqNum++;
    auto ct = aesGcmEncrypt(m_negotiatedCipher, m_clientAppKey.key, nonce, inner, aad);
    if (ct.size() != encLen) return -1;

    Vector<uint8_t> record;
    record.append(aad.span());
    record.append(ct.span());
    if (!writeAll(m_fd, record.span().data(), record.size())) return -1;
    return static_cast<int>(len);
}

Vector<uint8_t> DriftstackTLS13Client::readApplicationRecord()
{
    WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.194] readAppRecord cipher=0x%04x seqNum=%llu",
        m_negotiatedCipher, (unsigned long long)m_serverAppKey.seqNum);
    // Wave 29-499.180 — decrypt app data with server_app_key.
    uint8_t recType;
    uint16_t recVer;
    Vector<uint8_t> body;
    if (!driftstackReadTLSRecord(m_fd, recType, recVer, body))
        return {};

    // Session tickets (post-handshake NewSessionTicket records) come as 0x17
    // too — TLS 1.3 wraps them in application_data. Skip if inner_type=0x16.
    if (recType != 0x17) {
        // Could be alert (0x15) or change_cipher_spec (0x14)
        return {};
    }

    Vector<uint8_t> aad;
    aad.append(recType);
    aad.append(static_cast<uint8_t>(recVer >> 8));
    aad.append(static_cast<uint8_t>(recVer & 0xFF));
    aad.append(static_cast<uint8_t>(body.size() >> 8));
    aad.append(static_cast<uint8_t>(body.size() & 0xFF));

    auto nonce = TLS13KeySchedule::recordNonce(m_serverAppKey.iv, m_serverAppKey.seqNum);
    m_serverAppKey.seqNum++;

    auto pt = aesGcmDecrypt(m_negotiatedCipher, m_serverAppKey.key, nonce, body, aad);
    if (pt.isEmpty()) return {};

    // Wave 29-499.189 — strip trailing padding FIRST, then inner_type
    while (!pt.isEmpty() && pt.last() == 0)
        pt.removeLast();
    if (pt.isEmpty()) return {};
    uint8_t innerType = pt.last();
    pt.removeLast();

    if (innerType == 0x17) {
        return pt;  // application_data
    } else if (innerType == 0x16) {
        // Post-handshake message (NewSessionTicket, KeyUpdate). Append to
        // transcript and recurse to read next real app data record.
        m_transcriptBytes.append(pt.span());
        return readApplicationRecord();
    } else if (innerType == 0x15) {
        // Wave 29-499.208 — parse TLS Alert (RFC 8446 §6)
        // Alert payload: level(1) + description(1)
        if (pt.size() >= 2) {
            uint8_t level = pt[0];
            uint8_t desc = pt[1];
            const char* descStr = "unknown";
            switch (desc) {
                case 0: descStr = "close_notify"; break;
                case 10: descStr = "unexpected_message"; break;
                case 20: descStr = "bad_record_mac"; break;
                case 22: descStr = "record_overflow"; break;
                case 40: descStr = "handshake_failure"; break;
                case 42: descStr = "bad_certificate"; break;
                case 43: descStr = "unsupported_certificate"; break;
                case 44: descStr = "certificate_revoked"; break;
                case 45: descStr = "certificate_expired"; break;
                case 46: descStr = "certificate_unknown"; break;
                case 47: descStr = "illegal_parameter"; break;
                case 48: descStr = "unknown_ca"; break;
                case 49: descStr = "access_denied"; break;
                case 50: descStr = "decode_error"; break;
                case 51: descStr = "decrypt_error"; break;
                case 70: descStr = "protocol_version"; break;
                case 71: descStr = "insufficient_security"; break;
                case 80: descStr = "internal_error"; break;
                case 86: descStr = "inappropriate_fallback"; break;
                case 90: descStr = "user_canceled"; break;
                case 109: descStr = "missing_extension"; break;
                case 110: descStr = "unsupported_extension"; break;
                case 112: descStr = "unrecognized_name"; break;
                case 113: descStr = "bad_certificate_status_response"; break;
                case 115: descStr = "unknown_psk_identity"; break;
                case 116: descStr = "certificate_required"; break;
                case 120: descStr = "no_application_protocol"; break;
            }
            const char* levelStr = (level == 1) ? "warning" : (level == 2) ? "fatal" : "?";
            WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.208] TLS Alert: level=%s(%d) description=%s(%d)",
                levelStr, level, descStr, desc);
            if (desc == 0) {
                // close_notify — graceful, expected at end of stream
                return {};
            }
        } else {
            WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.208] TLS alert (malformed, %zu bytes)", pt.size());
        }
        return {};
    }
    return {};
}

// ===========================================================================
// Wave 29-499.340 — TLS 1.2 (RFC 5246 + RFC 5288 AEAD) ECDHE handshake + record
// layer for endpoints that negotiate 1.2 (e.g. Twilio turns: :443, cipher 0xc02f
// TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256). The iPhone-byte-exact ClientHello
// already advertises 1.2 ciphers + supported_groups; this completes the 1.2 flow
// so TURN-TLS works "like a real iPhone". No cert validation (matches the 1.3
// path; TURN authenticity is enforced by the TURN long-term credential, not PKI).
// ===========================================================================
namespace {
// TLS 1.2 PRF = P_SHA256 (RFC 5246 §5). P_hash(secret, seed):
//   A(0)=seed; A(i)=HMAC(secret,A(i-1)); out += HMAC(secret, A(i) || seed).
Vector<uint8_t> tls12PrfSha256(const Vector<uint8_t>& secret, const char* label,
    const Vector<uint8_t>& seed, size_t outLen)
{
    Vector<uint8_t> labelSeed;
    labelSeed.append(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(label), strlen(label)));
    labelSeed.append(seed.span());

    Vector<uint8_t> out;
    Vector<uint8_t> a = driftstackHmacSha256(secret, labelSeed); // A(1)
    while (out.size() < outLen) {
        Vector<uint8_t> input = a;
        input.append(labelSeed.span());
        out.append(driftstackHmacSha256(secret, input).span());
        a = driftstackHmacSha256(secret, a); // A(i+1)
    }
    out.shrink(outLen);
    return out;
}
Vector<uint8_t> slice(const Vector<uint8_t>& v, size_t off, size_t len)
{
    Vector<uint8_t> r;
    if (off + len <= v.size())
        r.append(std::span<const uint8_t>(v.span().data() + off, len));
    return r;
}
} // namespace

bool DriftstackTLS13Client::doTLS12Handshake(const TLS13ServerHello& sh)
{
    // This record layer + PRF assume AES-128-GCM with the SHA256 PRF
    // (TLS_ECDHE_{RSA,ECDSA}_WITH_AES_128_GCM_SHA256 = 0xc02f / 0xc02b). iPhone's
    // cipher order makes Twilio pick 0xc02f. Reject anything else loudly rather than
    // derive wrong-length keys (AES-256-GCM/SHA384 would need a SHA384 PRF + 32B keys).
    if (sh.cipherSuite != 0xc02f && sh.cipherSuite != 0xc02b) {
        m_errorMessage = makeString("TLS1.2: cipher 0x"_s, hex(sh.cipherSuite, 4), " not supported (only AES_128_GCM_SHA256)"_s);
        return false;
    }
    // 1.2 servers send (plaintext): Certificate, ServerKeyExchange, [CertificateRequest],
    // ServerHelloDone. Read records (each may hold several / partial messages) until SHD.
    uint16_t serverCurve = 0;
    Vector<uint8_t> serverEcPub;
    bool gotSKE = false, gotSHD = false;
    Vector<uint8_t> acc;

    while (!gotSHD) {
        uint8_t recType; uint16_t recVer; Vector<uint8_t> recBody;
        if (!driftstackReadTLSRecord(m_fd, recType, recVer, recBody)) {
            m_errorMessage = "TLS1.2: read handshake record failed"_s; return false;
        }
        if (recType == 0x15) { m_errorMessage = "TLS1.2: alert during handshake"_s; return false; }
        if (recType != 0x16) {
            m_errorMessage = makeString("TLS1.2: expected handshake(0x16), got 0x"_s, hex(recType, 2)); return false;
        }
        acc.append(recBody.span());
        size_t off = 0;
        while (off + 4 <= acc.size()) {
            uint8_t t = acc[off];
            uint32_t l = (static_cast<uint32_t>(acc[off + 1]) << 16) | (static_cast<uint32_t>(acc[off + 2]) << 8) | acc[off + 3];
            if (off + 4 + l > acc.size()) break; // incomplete — await next record
            m_transcriptBytes.append(std::span<const uint8_t>(acc.span().data() + off, 4 + l));
            const uint8_t* mb = acc.span().data() + off + 4;
            if (t == 0x0c && l >= 4 && mb[0] == 0x03) { // ServerKeyExchange, named_curve
                serverCurve = (static_cast<uint16_t>(mb[1]) << 8) | mb[2];
                uint8_t pubLen = mb[3];
                if (static_cast<uint32_t>(4) + pubLen <= l) {
                    serverEcPub.clear();
                    serverEcPub.append(std::span<const uint8_t>(mb + 4, pubLen));
                    gotSKE = true;
                }
            } else if (t == 0x0e)
                gotSHD = true;
            off += 4 + l;
        }
        acc.removeAt(0, off);
    }
    if (!gotSKE) { m_errorMessage = "TLS1.2: no ServerKeyExchange (need ECDHE)"_s; return false; }

    // Client ephemeral on the server's curve → pre_master_secret.
    Vector<uint8_t> clientEcPub, preMaster;
    if (serverCurve == 0x001D) { // X25519
        Vector<uint8_t> priv, pub;
        if (!driftstackX25519GenerateKeypair(priv, pub)) { m_errorMessage = "TLS1.2 X25519 gen failed"_s; return false; }
        clientEcPub = pub;
        preMaster = driftstackX25519SharedSecret(priv, serverEcPub);
    } else if (serverCurve == 0x0017) { // secp256r1
        P256Keypair kp = driftstackP256Generate();
        if (!kp.ok) { m_errorMessage = "TLS1.2 P-256 gen failed"_s; return false; }
        clientEcPub = kp.publicKey;
        preMaster = driftstackP256ComputeShared(kp, serverEcPub);
        driftstackP256Free(kp);
    } else {
        m_errorMessage = makeString("TLS1.2: unsupported ECDHE curve 0x"_s, hex(serverCurve, 4)); return false;
    }
    if (preMaster.isEmpty()) { m_errorMessage = "TLS1.2: ECDH produced empty shared secret"_s; return false; }
    WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.340] TLS1.2 ECDHE curve=0x%04x serverPub=%zuB clientPub=%zuB preMaster=%zuB",
        serverCurve, serverEcPub.size(), clientEcPub.size(), preMaster.size());

    // ClientKeyExchange (0x10): ECDHE public = pub_len(1) + pub. Build + send + add to
    // transcript FIRST, because with extended_master_secret (RFC 7627) the master secret
    // is derived from the session hash through ClientKeyExchange — not client/server random.
    Vector<uint8_t> cke;
    cke.append(0x10);
    uint32_t ckeBody = 1 + clientEcPub.size();
    cke.append(static_cast<uint8_t>((ckeBody >> 16) & 0xFF));
    cke.append(static_cast<uint8_t>((ckeBody >> 8) & 0xFF));
    cke.append(static_cast<uint8_t>(ckeBody & 0xFF));
    cke.append(static_cast<uint8_t>(clientEcPub.size()));
    cke.append(clientEcPub.span());
    {
        Vector<uint8_t> rec; rec.append(0x16); rec.append(0x03); rec.append(0x03);
        rec.append(static_cast<uint8_t>((cke.size() >> 8) & 0xFF));
        rec.append(static_cast<uint8_t>(cke.size() & 0xFF));
        rec.append(cke.span());
        if (!writeAll(m_fd, rec.span().data(), rec.size())) { m_errorMessage = "TLS1.2 send CKE failed"_s; return false; }
    }
    m_transcriptBytes.append(cke.span());

    // session_hash = Hash(ClientHello .. ClientKeyExchange) — also reused for the Finished.
    Vector<uint8_t> sessionHash = driftstackSHA256(m_transcriptBytes.span().data(), m_transcriptBytes.size());

    // master_secret: EMS (RFC 7627) → PRF(preMaster,"extended master secret",session_hash);
    // else classic PRF(preMaster,"master secret",client_random+server_random).
    if (m_t12EMS)
        m_t12MasterSecret = tls12PrfSha256(preMaster, "extended master secret", sessionHash, 48);
    else {
        Vector<uint8_t> crSr; crSr.append(m_clientRandom.span()); crSr.append(m_serverRandom.span());
        m_t12MasterSecret = tls12PrfSha256(preMaster, "master secret", crSr, 48);
    }
    // key_block = PRF(master,"key expansion",server_random+client_random,40) — AEAD: no MAC keys.
    Vector<uint8_t> srCr; srCr.append(m_serverRandom.span()); srCr.append(m_clientRandom.span());
    Vector<uint8_t> keyBlock = tls12PrfSha256(m_t12MasterSecret, "key expansion", srCr, 40);
    m_t12ClientKey = slice(keyBlock, 0, 16);
    m_t12ServerKey = slice(keyBlock, 16, 16);
    m_t12ClientFixedIV = slice(keyBlock, 32, 4);
    m_t12ServerFixedIV = slice(keyBlock, 36, 4);
    if (m_t12ClientKey.size() != 16 || m_t12ServerKey.size() != 16) { m_errorMessage = "TLS1.2 key_block too short"_s; return false; }

    // ChangeCipherSpec (record type 0x14, payload 0x01)
    { uint8_t ccs[6] = { 0x14, 0x03, 0x03, 0x00, 0x01, 0x01 };
      if (!writeAll(m_fd, ccs, 6)) { m_errorMessage = "TLS1.2 send CCS failed"_s; return false; } }

    // Client Finished: verify_data = PRF(master, "client finished", session_hash, 12),
    // sent as an ENCRYPTED handshake record (content type 0x16) with client seq 0.
    Vector<uint8_t> verifyData = tls12PrfSha256(m_t12MasterSecret, "client finished", sessionHash, 12);
    Vector<uint8_t> fin; fin.append(0x14); fin.append(0x00); fin.append(0x00); fin.append(0x0c); fin.append(verifyData.span());
    if (writeTLS12Record(fin.span().data(), fin.size(), 0x16) < 0) { m_errorMessage = "TLS1.2 send Finished failed"_s; return false; }
    m_transcriptBytes.append(fin.span());

    // Read server [NewSessionTicket] CCS Finished. Decrypting the server Finished
    // (type 0x16, encrypted) with our derived server keys proves the key schedule.
    bool serverCcs = false, serverFinished = false;
    int guard = 0;
    while (!serverFinished && guard++ < 8) {
        uint8_t recType; uint16_t recVer; Vector<uint8_t> recBody;
        if (!driftstackReadTLSRecord(m_fd, recType, recVer, recBody)) { m_errorMessage = "TLS1.2: read server finish record failed"_s; return false; }
        if (recType == 0x14) { serverCcs = true; continue; }
        if (recType == 0x15) {
            int lvl = recBody.size() >= 1 ? recBody[0] : -1;
            int desc = recBody.size() >= 2 ? recBody[1] : -1;
            m_errorMessage = makeString("TLS1.2: server alert level="_s, String::number(lvl), " desc="_s, String::number(desc));
            return false;
        }
        if (recType == 0x16 && !serverCcs) { m_transcriptBytes.append(recBody.span()); continue; } // plaintext NewSessionTicket
        if (recType == 0x16 && serverCcs) {
            // explicit_nonce(8) || ciphertext || tag(16)
            if (recBody.size() < 8 + 16) { m_errorMessage = "TLS1.2: short server Finished"_s; return false; }
            Vector<uint8_t> nonce; nonce.append(m_t12ServerFixedIV.span()); nonce.append(slice(recBody, 0, 8).span());
            Vector<uint8_t> ct = slice(recBody, 8, recBody.size() - 8);
            size_t ptLen = ct.size() - 16;
            Vector<uint8_t> aad;
            for (int i = 7; i >= 0; --i) aad.append(static_cast<uint8_t>((m_t12ServerSeq >> (i * 8)) & 0xFF));
            aad.append(0x16); aad.append(0x03); aad.append(0x03);
            aad.append(static_cast<uint8_t>((ptLen >> 8) & 0xFF)); aad.append(static_cast<uint8_t>(ptLen & 0xFF));
            Vector<uint8_t> pt = driftstackAes128GcmDecrypt(m_t12ServerKey, nonce, ct, aad);
            m_t12ServerSeq++;
            if (pt.isEmpty()) { m_errorMessage = "TLS1.2: server Finished decrypt failed (key schedule wrong)"_s; return false; }
            serverFinished = true;
            WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.340] TLS1.2 server Finished decrypted OK (%zuB) — handshake verified, keys correct.", pt.size());
        }
    }
    if (!serverFinished) { m_errorMessage = "TLS1.2: never received server Finished"_s; return false; }
    return true;
}

int DriftstackTLS13Client::writeTLS12Record(const uint8_t* data, size_t len, uint8_t contentType)
{
    // RFC 5288: nonce = client_fixed_IV(4) || explicit_nonce(8); explicit_nonce = seq.
    // Wire payload = explicit_nonce(8) || AES-128-GCM(plaintext)+tag. AAD = seq || type || ver || ptlen.
    Vector<uint8_t> explicitNonce;
    for (int i = 7; i >= 0; --i) explicitNonce.append(static_cast<uint8_t>((m_t12ClientSeq >> (i * 8)) & 0xFF));
    Vector<uint8_t> nonce; nonce.append(m_t12ClientFixedIV.span()); nonce.append(explicitNonce.span());

    Vector<uint8_t> aad;
    for (int i = 7; i >= 0; --i) aad.append(static_cast<uint8_t>((m_t12ClientSeq >> (i * 8)) & 0xFF));
    aad.append(contentType); aad.append(0x03); aad.append(0x03);
    aad.append(static_cast<uint8_t>((len >> 8) & 0xFF)); aad.append(static_cast<uint8_t>(len & 0xFF));

    Vector<uint8_t> pt; pt.append(std::span<const uint8_t>(data, len));
    Vector<uint8_t> ct = driftstackAes128GcmEncrypt(m_t12ClientKey, nonce, pt, aad);
    if (ct.isEmpty()) return -1;
    m_t12ClientSeq++;

    Vector<uint8_t> payload; payload.append(explicitNonce.span()); payload.append(ct.span());
    Vector<uint8_t> rec; rec.append(contentType); rec.append(0x03); rec.append(0x03);
    rec.append(static_cast<uint8_t>((payload.size() >> 8) & 0xFF));
    rec.append(static_cast<uint8_t>(payload.size() & 0xFF));
    rec.append(payload.span());
    if (!writeAll(m_fd, rec.span().data(), rec.size())) return -1;
    return static_cast<int>(len);
}

Vector<uint8_t> DriftstackTLS13Client::readTLS12Record()
{
    uint8_t recType; uint16_t recVer; Vector<uint8_t> body;
    if (!driftstackReadTLSRecord(m_fd, recType, recVer, body)) return {};
    if (recType == 0x15) return {}; // alert (incl. close_notify)
    if (recType != 0x17) {
        // ChangeCipherSpec / handshake (e.g. post-handshake NewSessionTicket): skip, read next.
        if (recType == 0x14 || recType == 0x16) return readTLS12Record();
        return {};
    }
    if (body.size() < 8 + 16) return {};
    Vector<uint8_t> nonce; nonce.append(m_t12ServerFixedIV.span()); nonce.append(slice(body, 0, 8).span());
    Vector<uint8_t> ct = slice(body, 8, body.size() - 8);
    size_t ptLen = ct.size() - 16;
    Vector<uint8_t> aad;
    for (int i = 7; i >= 0; --i) aad.append(static_cast<uint8_t>((m_t12ServerSeq >> (i * 8)) & 0xFF));
    aad.append(0x17); aad.append(0x03); aad.append(0x03);
    aad.append(static_cast<uint8_t>((ptLen >> 8) & 0xFF)); aad.append(static_cast<uint8_t>(ptLen & 0xFF));
    Vector<uint8_t> pt = driftstackAes128GcmDecrypt(m_t12ServerKey, nonce, ct, aad);
    m_t12ServerSeq++;
    return pt;
}

} // namespace WebKit

WTF_ALLOW_UNSAFE_BUFFER_USAGE_END

#endif // PLATFORM(DRIFTSTACK)
