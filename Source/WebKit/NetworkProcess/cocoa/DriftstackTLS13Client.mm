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
#import "DriftstackTLS13Verify.h"   // W2202 L3: the shared CertificateVerify helper (decl); defined below + called by the h2 + h3 0x0f arms
#import <Security/Security.h>
#import <wtf/RetainPtr.h>
#import <wtf/text/MakeString.h>
#import <wtf/HexNumber.h>
#import <zlib.h>   // W2730: system libz — RFC 8879 CompressedCertificate (zlib) decode

#if PLATFORM(DRIFTSTACK)

#import <errno.h>
#import <optional>   // W3075 — std::optional AEAD success/failure channel for t12OpenRecord
#import <poll.h>
#import <stdlib.h>   // BUG-42 Fix #4: atof for DRIFTSTACK_EGRESS_HANDSHAKE_DEADLINE_SECS
#import <string.h>
#import <sys/socket.h>
#import <sys/time.h>
#import <unistd.h>
#import <wtf/Seconds.h>   // BUG-42 Fix #4: Seconds(double) ctor for the handshake deadline
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
    // a74622fc — 0x1303 (TLS_CHACHA20_POLY1305_SHA256) was MISSING from this dispatcher and
    // fell through to the AES-128-GCM branch below: decrypting/encrypting ChaCha20-Poly1305
    // ciphertext as if it were AES-GCM, which deterministically fails the AEAD auth tag on
    // EVERY record. Any server whose top cipher-suite preference is 0x1303 (Meta/Facebook's
    // edge among them) never completes the TLS handshake — the root cause of the
    // westernunion/facebook "page could not be loaded" reports. The implementation already
    // existed (built for QUIC's cipher 0x1303) — it was just never wired in here.
    if (cipher == 0x1303)
        return driftstackChacha20Poly1305Encrypt(key, nonce, pt, aad);
    if (cipher == 0x1302)
        return driftstackAes256GcmEncrypt(key, nonce, pt, aad);
    return driftstackAes128GcmEncrypt(key, nonce, pt, aad);
}
Vector<uint8_t> aesGcmDecrypt(uint16_t cipher, const Vector<uint8_t>& key,
                               const Vector<uint8_t>& nonce, const Vector<uint8_t>& ct,
                               const Vector<uint8_t>& aad)
{
    // a74622fc — see aesGcmEncrypt above for why 0x1303 needs its own branch.
    if (cipher == 0x1303)
        return driftstackChacha20Poly1305Decrypt(key, nonce, ct, aad);
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

    // BUG-42 Fix #4 (egress-reliability, gated) — stamp a TOTAL handshake wall-clock
    // deadline. The 6s SO_RCVTIMEO above bounds ONE quiet record, but it RESETS on every
    // record that arrives, so a slow/dribbling origin (record-after-record, each just
    // under 6s) pins this loaderQueue worker indefinitely — defeating Fix #2 (which frees
    // a worker only when the request completes/errors). The per-record read loops below
    // check handshakeDeadlineExceeded() and bail to a clean failure once this is past, so
    // a stalled origin frees its worker fast (→ a fresh-exit retry, or the page settles).
    // 12s default: comfortably above a healthy full PQ TLS-1.3 handshake on a slow proxy
    // (a handful of records, ~1-3 proxy-RTTs) yet far below the per-request retry budget,
    // so it only ever trips on a genuinely-wedged origin. Tunable via
    // DRIFTSTACK_EGRESS_HANDSHAKE_DEADLINE_SECS. Gate-off: left null → every check no-ops.
    {
        static const bool s_reliabilityEnabled = [] {
            const char* e = getenv("DRIFTSTACK_EGRESS_RELIABILITY");
            return e && e[0] == '1';
        }();
        if (s_reliabilityEnabled) {
            static const double s_budgetSecs = [] {
                double secs = 12.0;
                if (const char* e = getenv("DRIFTSTACK_EGRESS_HANDSHAKE_DEADLINE_SECS")) {
                    double parsed = atof(e);
                    if (parsed >= 3.0 && parsed <= 60.0)
                        secs = parsed;
                }
                return secs;
            }();
            m_handshakeDeadline = MonotonicTime::now() + Seconds(s_budgetSecs);
        }
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
    // Keypair A — used for the X25519MLKEM768 hybrid (0x11EC) key_share tail (and the
    // X25519-only fallback / classical archetype, each of which carries a SINGLE X25519 entry).
    Vector<uint8_t> x25519PrivateA;
    Vector<uint8_t> x25519PubA;
    if (!driftstackX25519GenerateKeypair(x25519PrivateA, x25519PubA)) {
        m_errorMessage = "X25519 keypair A gen failed"_s;
        return false;
    }
    m_ourX25519PrivateA = x25519PrivateA;
    m_ourX25519PublicA = x25519PubA;

    // Keypair B — INDEPENDENT ephemeral, used for the standalone X25519 (0x001D) key_share
    // entry in the hybrid CH. Real iPhone Safari 26.2-26.5 sends TWO distinct X25519
    // ephemerals (verified 7/7 captures: the standalone X25519 != the hybrid's X25519 slot,
    // every connection). The fork previously reused keypair A for both → the two wire X25519
    // components were byte-identical = a deterministic structural correlation a TLS-
    // introspecting server/DPI computes (invisible to JA3/JA4/peetprint, which hash no key
    // material). Gated by DRIFTSTACK_TLS_KEYSHARE_DISTINCT (default-ON, evaluated inside the
    // builder); when off, the builder reuses keypair A's pub for the standalone entry. The
    // server selects ONE group, so derivation picks the matching private (A for 0x11EC,
    // B for 0x001D) — see receiveServerHello.
    Vector<uint8_t> x25519PrivateB;
    Vector<uint8_t> x25519PubB;
    if (!driftstackX25519GenerateKeypair(x25519PrivateB, x25519PubB)) {
        m_errorMessage = "X25519 keypair B gen failed"_s;
        return false;
    }
    m_ourX25519PrivateB = x25519PrivateB;
    m_ourX25519PublicB = x25519PubB;

    // Wave 29-499.219 — generate MLKEM768 keypair for hybrid X25519MLKEM768 keyshare
    m_mlkemKeypair = driftstackMLKEM768Generate();
    Vector<uint8_t> chRecord;
    if (m_mlkemKeypair.ok && m_mlkemKeypair.publicKey.size() == 1184) {
        // Hybrid path: send MLKEM768 + X25519 keyshare (matches iPhone Safari 26).
        // Pubkey A → hybrid X25519 tail; pubkey B → standalone X25519 (0x001D) entry.
        chRecord = driftstackBuildIPhoneClientHelloHybrid(m_sniHostname,
            m_mlkemKeypair.publicKey, x25519PubA, clientRandom, x25519PubB);
        // The standalone 0x001D entry carries keypair B's pubkey ONLY when the builder
        // actually emitted the 26.x HYBRID keyshare (non-18.x archetype) AND the distinct
        // gate is ON. An 18.x archetype takes the builder's preSafari26 branch → single
        // X25519 entry with keypair A (so this stays false → derivation uses A). This is set
        // at build time (not re-derived in receiveServerHello) so a 0x001D server selection
        // is matched to the EXACT private that produced the wire pubkey.
        m_standaloneX25519IsB = !driftstackArchetypeIsPreSafari26() && driftstackTlsKeyShareDistinctEnabled();
        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.219] Using HYBRID X25519MLKEM768+X25519 keyshare (standalone X25519 distinct=%d)", m_standaloneX25519IsB);
    } else {
        // Fallback: X25519-only keyshare (single 0x001D entry → keypair A; no two-keypair
        // issue → m_standaloneX25519IsB stays false → derivation uses private A).
        chRecord = driftstackBuildIPhoneClientHello(m_sniHostname, x25519PubA, clientRandom);
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

// egress HRR (2026-07-02) — RFC 8446 §6 alert descriptions, so a handshake failure surfaces the
// actual reason (e.g. illegal_parameter/decode_error on a rejected CH2) instead of the generic
// "read ServerHello record failed" that masked the multi-day bing.com failure.
static ASCIILiteral driftstackAlertName(uint8_t desc)
{
    switch (desc) {
    case 0: return "close_notify"_s;
    case 10: return "unexpected_message"_s;
    case 20: return "bad_record_mac"_s;
    case 22: return "record_overflow"_s;
    case 40: return "handshake_failure"_s;
    case 42: return "bad_certificate"_s;
    case 43: return "unsupported_certificate"_s;
    case 44: return "certificate_revoked"_s;
    case 45: return "certificate_expired"_s;
    case 46: return "certificate_unknown"_s;
    case 47: return "illegal_parameter"_s;
    case 48: return "unknown_ca"_s;
    case 49: return "access_denied"_s;
    case 50: return "decode_error"_s;
    case 51: return "decrypt_error"_s;
    case 70: return "protocol_version"_s;
    case 71: return "insufficient_security"_s;
    case 80: return "internal_error"_s;
    case 86: return "inappropriate_fallback"_s;
    case 90: return "user_canceled"_s;
    case 109: return "missing_extension"_s;
    case 110: return "unsupported_extension"_s;
    case 112: return "unrecognized_name"_s;
    case 116: return "certificate_required"_s;
    case 120: return "no_application_protocol"_s;
    default: return "unknown"_s;
    }
}

bool DriftstackTLS13Client::receiveServerHello()
{
    uint8_t type;
    uint16_t version;
    Vector<uint8_t> body;
    // W3053 (FOUNDER westernunion): RFC 8446 §D.4 middlebox-compat — a ChangeCipherSpec
    // (0x14) record can arrive interleaved with the server's first handshake flight (some
    // servers, and observed nodemaven-proxy exits, emit it before we've consumed the
    // ServerHello). It carries no handshake meaning and is NOT part of the TLS transcript,
    // so a robust client (incl. real Safari) skips it. Previously any leading CCS was
    // rejected as a "bad record" → the whole TLS handshake failed → fresh-connect churn
    // (the observed quantummetric-via-proxy status=0 failures). Skip leading CCS record(s)
    // and read the next; bounded so a peer streaming CCS can't loop forever. Fingerprint-
    // neutral: changes only what we TOLERATE on receive, never what we send.
    int ccsSkips = 0;
    for (;;) {
        if (!driftstackReadTLSRecord(m_fd, type, version, body)) {
            m_errorMessage = "read ServerHello record failed"_s;
            return false;
        }
        if (type != 0x14)
            break;
        if (++ccsSkips > 3) {
            m_errorMessage = "Too many ChangeCipherSpec records before ServerHello"_s;
            return false;
        }
        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.322] receiveServerHello: skipping interleaved ChangeCipherSpec (RFC8446 D.4), skip#%d", ccsSkips);
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
        if (type == 0x15 && body.size() >= 2) {
            // egress HRR (2026-07-02): a TLS alert. Surface the level+description so the failure is
            // identifiable. If it lands AFTER our HRR (m_hrrSeen), it is a deterministic reject of
            // CH2 (same reject on every fresh exit) → mark permanent so the loader fails fast rather
            // than firing 8 identical CH2s. A CH1-phase alert stays retryable (flaky-proxy resilience).
            uint8_t level = body[0];
            uint8_t desc = body[1];
            m_errorMessage = makeString("TLS alert level="_s, static_cast<unsigned>(level),
                " description="_s, static_cast<unsigned>(desc), " ("_s, driftstackAlertName(desc),
                ") after "_s, m_hrrSeen ? "CH2"_s : "CH1"_s);
            if (m_hrrSeen)
                m_permanentFailure = true;
            WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.353] %s", m_errorMessage.utf8().data());
        } else
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
        // W2208 (parser-robustness audit weta2casf P1): RFC 8446 §4.1.4 — a client MUST abort on a SECOND
        // HelloRetryRequest. receiveServerHello() recurses on HRR (the `return receiveServerHello()` below);
        // with NO depth guard a hostile peer (this runs pre-cert-validation) answering every ClientHello with
        // a valid P-256 HRR drives unbounded recursion → NetworkProcess stack exhaustion (SIGSEGV) → session
        // crash-loop. At most ONE HRR is legitimate, so this bounds recursion to depth ≤2 with zero impact on
        // a real handshake (which sends 0 or 1 HRR).
        if (m_hrrSeen) {
            m_errorMessage = "second HelloRetryRequest (RFC 8446 §4.1.4 forbids) — rejecting"_s;
            WTFLogAlways("[Driftstack-EG-WK-PathB-v2/W2208] second HelloRetryRequest — rejecting (unbounded-recursion DoS defense)");
            return false;
        }
        m_hrrSeen = true;
        // egress bing P-521 HRR (2026-07-02): accept the EC groups a real iPhone offers in
        // supported_groups — P-256 (0x0017), P-384 (0x0018), P-521 (0x0019). bing.com HRRs to P-521;
        // the prior code only did P-256 → the handshake failed after 7 fruitless retries. A real iPhone
        // answers the HRR with a key_share for the requested curve, so this is iPhone-faithful.
        int hrrNid = 0;
        switch (sh.keyShareGroup) {
        case 0x0017: hrrNid = kDriftstackNIDP256; break;
        case 0x0018: hrrNid = kDriftstackNIDP384; break;
        case 0x0019: hrrNid = kDriftstackNIDP521; break;
        default:
            m_errorMessage = makeString("HRR requested unsupported group 0x"_s,
                hex(sh.keyShareGroup, 4), " (only P-256/P-384/P-521 supported in HRR retry)"_s);
            return false;
        }
        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.215] HRR detected (server wants group 0x%04x). Retrying ClientHello with matching EC keyshare.", sh.keyShareGroup);

        // Generate the keypair for the requested curve (P256Keypair is curve-agnostic: EC key + pubkey).
        m_p256Keypair = driftstackECGenerate(hrrNid);
        if (!m_p256Keypair.ok) {
            m_errorMessage = makeString("HRR EC keypair generation failed for group 0x"_s, hex(sh.keyShareGroup, 4));
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

        // egress bing/Akamai HRR (2026-07-02): CH2 = byte-exact CH1 with ONLY the key_share swapped
        // to the server-requested EC group + the HRR cookie echoed (RFC 8446 §4.1.2/§4.1.4). Byte-
        // surgery on ch1Only preserves client_random/session_id/GREASE/cipher-order EXACTLY — a real
        // iPhone resends CH1 unmodified except key_share. (The prior builder regenerated fresh
        // random/GREASE, which strict servers — bing/Akamai/F5 — reject → the multi-day failure.)
        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.353] HRR retry: synthetic transcript built (CH1 hash %zu bytes), HRR bytes %zu, cookie %zu bytes, building CH2 for group 0x%04x",
            ch1Hash.size(), hrrBytes.size(), sh.cookie.size(), sh.keyShareGroup);

        Vector<uint8_t> ch2Record = driftstackBuildCH2FromCH1(ch1Only,
            sh.keyShareGroup, m_p256Keypair.publicKey, sh.cookie);
        if (ch2Record.size() <= 5) {
            m_errorMessage = "CH2 byte-surgery failed (could not locate/replace CH1 key_share)"_s;
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
        // X25519 ECDH with server's X25519 pubkey (last 32 bytes). The server selected the
        // hybrid group (0x11EC), so its X25519 share is the DH against the pubkey we put in
        // the HYBRID X25519 tail = keypair A → derive with private A. (With the gate ON the
        // standalone 0x001D entry carried a DIFFERENT pubkey/private B; using B here would
        // derive the WRONG secret → handshake failure. This per-group selection is the
        // correctness pivot of the two-keypair change.)
        Vector<uint8_t> serverX25519;
        serverX25519.append(std::span<const uint8_t>(sh.keyShareKey.span().data() + 1088, 32));
        Vector<uint8_t> x25519Shared = driftstackX25519SharedSecret(m_ourX25519PrivateA, serverX25519);
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
        // Plain X25519. The server selected the STANDALONE X25519 entry (0x001D). Derive
        // with the EXACT private that produced that entry's wire pubkey: keypair B when the
        // 26.x hybrid CH emitted a distinct standalone pubkey (m_standaloneX25519IsB), else
        // keypair A (the X25519-only fallback builder + 18.x archetype each emit a SINGLE
        // 0x001D entry carrying A, and the gate-off hybrid reuses A). Using the wrong private
        // here would derive a mismatched secret → Finished verification / decrypt failure.
        const Vector<uint8_t>& standalonePriv =
            m_standaloneX25519IsB ? m_ourX25519PrivateB : m_ourX25519PrivateA;
        m_ecdhShared = driftstackX25519SharedSecret(standalonePriv, sh.keyShareKey);
        if (m_ecdhShared.size() != 32) {
            m_errorMessage = "X25519 ECDH derivation failed"_s;
            return false;
        }
    } else if (sh.keyShareGroup == 0x0017 || sh.keyShareGroup == 0x0018 || sh.keyShareGroup == 0x0019) {
        // egress audit wxzzaphvp (#7) + bing P-521 (2026-07-02): after an HRR the server's (CH2)
        // ServerHello carries its key_share for the group it requested — P-256 (0x0017, 65-byte point),
        // P-384 (0x0018, 97-byte), or P-521 (0x0019, 133-byte). The CH2 path (~:442) generated
        // m_p256Keypair for that curve; derive the ECDH shared from the server's uncompressed point via
        // the same keypair. (Without P-384/P-521 here, bing.com — which HRRs to P-521 — always failed
        // the handshake; driftstackECComputeShared derives the field size from the point, covering all
        // three. The prior code only handled P-256 → the else branch rejected P-384/P-521.)
        if (!m_p256Keypair.ok) {
            m_errorMessage = makeString("server selected EC group 0x"_s, hex(sh.keyShareGroup, 4),
                " but no CH2 EC keypair was generated"_s);
            return false;
        }
        size_t expectPoint = (sh.keyShareGroup == 0x0017) ? 65 : (sh.keyShareGroup == 0x0018) ? 97 : 133;
        if (sh.keyShareKey.size() != expectPoint) {
            m_errorMessage = makeString("EC key_share group 0x"_s, hex(sh.keyShareGroup, 4),
                " must be a "_s, String::number(expectPoint), "-byte uncompressed point, got "_s,
                String::number(sh.keyShareKey.size()));
            return false;
        }
        m_ecdhShared = driftstackECComputeShared(m_p256Keypair, sh.keyShareKey);
        size_t expectShared = (sh.keyShareGroup == 0x0017) ? 32 : (sh.keyShareGroup == 0x0018) ? 48 : 66;
        if (m_ecdhShared.size() != expectShared) {
            m_errorMessage = makeString("EC ECDH derivation failed for group 0x"_s, hex(sh.keyShareGroup, 4));
            return false;
        }
    } else {
        m_errorMessage = makeString("Unsupported key_share group 0x"_s, hex(sh.keyShareGroup, 4),
            " or size "_s, String::number(sh.keyShareKey.size()));
        return false;
    }
    WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.188] ECDH shared (32B): %02x%02x%02x%02x...%02x%02x | privA=%02x%02x | peer_pub=%02x%02x",
        m_ecdhShared[0], m_ecdhShared[1], m_ecdhShared[2], m_ecdhShared[3],
        m_ecdhShared[30], m_ecdhShared[31],
        m_ourX25519PrivateA[0], m_ourX25519PrivateA[1],
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
        // W3064 (audit): also clear the 8s SO_SNDTIMEO that DriftstackSocks5Client::connectToProxy set
        // for the SOCKS5 handshake and which LEAKED into the data phase — a large upload (POST body) over
        // a slow proxy would abort mid-write at 8s where a real iPhone blocks-and-succeeds. Restore
        // blocking writes for the app-data phase (matches the SO_RCVTIMEO restore above).
        setsockopt(m_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    }
    if (m_isTLS12) {
        // W3075 — a prior record failed AEAD auth (bad_record_mac): stay failed, never resume as
        // a clean EOF that would truncate/complete the response as if the peer closed.
        if (m_t12ReadFatal) return -1;
        if (m_t12ReadBuffer.isEmpty()) {
            auto pt = readTLS12Record();
            // W3075 — distinguish a fatal decrypt/auth error from a genuine transport close:
            // readTLS12Record sets m_t12ReadFatal on a bad_record_mac → return -1 (error). An
            // empty pt WITHOUT the fatal flag is a real close_notify/FIN → return 0 (EOF).
            if (m_t12ReadFatal) return -1;
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

int DriftstackTLS13Client::pollReadable(int timeoutMs)
{
    // W2341 (task #58): buffered decrypted plaintext → read() returns immediately.
    if (!(m_isTLS12 ? m_t12ReadBuffer.isEmpty() : m_readBuffer.isEmpty()))
        return 1;
    if (m_fd < 0)
        return -1;
    // poll() consumes nothing, so timing out here can never tear TLS record framing
    // (the hazard of an SO_RCVTIMEO that fires mid-record inside readExact()).
    struct pollfd pfd { .fd = m_fd, .events = POLLIN, .revents = 0 };
    int r = ::poll(&pfd, 1, timeoutMs);
    if (r > 0)
        return 1;  // readable (incl. HUP/ERR — read() surfaces the actual condition)
    if (r == 0)
        return 0;  // timeout tick — caller re-checks its cancel flag and loops
    if (errno == EINTR)
        return 0;  // treat as a tick, not an error
    // W3090 (FOUNDER westernunion "empty http1/1 response", multi-day): poll() returns
    // -1/EPERM ("Operation not permitted") on these SOCKS5-proxied sockets inside the
    // sandboxed NetworkProcess. This h1 read loop was the ONLY remaining poll() caller
    // (the h2 pooled reader dropped poll in W3083 and reads via blocking transportReadExact,
    // which is why h2 always worked while http/1.1-only origins — content.westernunion.com
    // and every h1 subresource — bailed with ZERO bytes read → the persistent empty-h1 error).
    // Fall back to a timed MSG_PEEK recv: the SAME blocking recv() primitive the handshake and
    // h2 reader use successfully, which detects readiness WITHOUT consuming bytes (record
    // framing stays intact — the subsequent read()/readExact() reads the full record). Bounded
    // by a temporary SO_RCVTIMEO so the caller still re-checks its cancel flag once per slice;
    // restored to blocking (0) afterward for the record reads. poll() stays the fast path where
    // it works, so environments where poll succeeds are byte-identical to before.
    struct timeval tv { .tv_sec = timeoutMs / 1000, .tv_usec = (timeoutMs % 1000) * 1000 };
    setsockopt(m_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    uint8_t peekByte = 0;
    ssize_t pk = ::recv(m_fd, &peekByte, 1, MSG_PEEK);
    int pkErrno = errno;
    struct timeval zero { .tv_sec = 0, .tv_usec = 0 };
    setsockopt(m_fd, SOL_SOCKET, SO_RCVTIMEO, &zero, sizeof(zero)); // restore blocking record reads
    if (pk > 0)
        return 1;   // bytes available (peeked, not consumed)
    if (pk == 0)
        return 1;   // peer closed — let read()/readExact surface the EOF/close
    if (pkErrno == EAGAIN || pkErrno == EWOULDBLOCK || pkErrno == EINTR)
        return 0;   // timeout tick — re-check cancel, loop
    return -1;      // genuine socket error
}

void DriftstackTLS13Client::shutdown()
{
    // W2314: actively unblock a reader thread parked in a BLOCKING recv(). read() clears
    // SO_RCVTIMEO for the app-data phase (restores blocking reads so slow/idle pooled
    // connections aren't cut off), so a DriftstackWebSocket cancel()/destructor on an idle or
    // unresponsive-server connection would otherwise block waitForCompletion() FOREVER —
    // m_stop is unchecked inside the recv() syscall, and the previous stub did nothing, leaking
    // the reader thread + its fd (resource exhaustion on the fleet once DRIFTSTACK_WS_PATHB is
    // enabled). shutdown(SHUT_RDWR) forces the blocked recv() to return → the reader checks
    // m_stop → exits → the thread joins. SHUT_RDWR does NOT close the fd (the socket owner
    // close()s it), so no double-close. (close_notify is skipped — an abrupt transport close is
    // acceptable for teardown.)
    if (m_fd >= 0)
        ::shutdown(m_fd, SHUT_RDWR);
}

// W2191 (#43) / W2730: validate a TLS 1.3 Certificate message BODY (RFC 8446 §4.4.2):
//   1B certificate_request_context_len + ctx + 3B certificate_list_len + [3B cert_len + DER + 2B ext_len + ext]*
// Parses the chain, stores the leaf (m_leafCert, first cert — for the 0x0f key-possession check), SecTrust-
// evaluates against m_sniHostname (network revocation fetch DISABLED — see the OCSP rationale below), and
// captures Transcript-Hash(CH..Certificate). Shared by the plain Certificate (0x0b) arm and the RFC 8879
// CompressedCertificate (0x19) arm (which passes the DECOMPRESSED body). Returns false (with m_errorMessage
// set) on any parse/trust failure. `body` is exactly the message body (the 4-byte handshake header already
// stripped), so all bounds are vs body.size().
bool DriftstackTLS13Client::validateCertificateBody(std::span<const uint8_t> body)
{
    if (body.empty()) { m_errorMessage = "cert msg too short"_s; return false; }
    uint8_t ctxLen = body[0];
    size_t cOff = 1 + static_cast<size_t>(ctxLen);
    if (cOff + 3 > body.size()) { m_errorMessage = "cert msg ctx OOB"_s; return false; }
    uint32_t listLen = (static_cast<uint32_t>(body[cOff]) << 16) | (static_cast<uint32_t>(body[cOff + 1]) << 8) | body[cOff + 2];
    cOff += 3;
    size_t listEnd = cOff + listLen;
    if (listEnd > body.size()) { m_errorMessage = "cert list OOB"_s; return false; }
    RetainPtr<CFMutableArrayRef> certArray = adoptCF(CFArrayCreateMutable(nullptr, 0, &kCFTypeArrayCallBacks));
    while (cOff + 3 <= listEnd) {
        uint32_t certLen = (static_cast<uint32_t>(body[cOff]) << 16) | (static_cast<uint32_t>(body[cOff + 1]) << 8) | body[cOff + 2];
        cOff += 3;
        if (cOff + certLen > listEnd) break;
        RetainPtr<CFDataRef> cfData = adoptCF(CFDataCreate(nullptr, body.subspan(cOff, certLen).data(), certLen));
        RetainPtr<SecCertificateRef> cert = adoptCF(SecCertificateCreateWithData(nullptr, cfData.get()));
        if (cert) {
            if (!m_leafCert) m_leafCert = cert;   // W2202 L3: the leaf (first cert) — for CertificateVerify key-possession
            CFArrayAppendValue(certArray.get(), cert.get());
        }
        cOff += certLen;
        if (cOff + 2 > listEnd) break;
        uint16_t extLen = (static_cast<uint16_t>(body[cOff]) << 8) | body[cOff + 1];
        cOff += 2 + static_cast<size_t>(extLen);
    }
    if (!CFArrayGetCount(certArray.get())) { m_errorMessage = "no parseable server certs"_s; return false; }
    RetainPtr<SecPolicyRef> policy = adoptCF(SecPolicyCreateSSL(true, m_sniHostname.createCFString().get()));
    SecTrustRef trust = nullptr;
    OSStatus st = SecTrustCreateWithCertificates(certArray.get(), policy.get(), &trust);
    RetainPtr<SecTrustRef> trustRef = adoptCF(trust);
    if (st != errSecSuccess || !trustRef) { m_errorMessage = "SecTrustCreateWithCertificates failed"_s; return false; }
    // Driftstack (egress channel-4 + iPhone-fidelity, 2026-06-19): disable per-evaluation NETWORK
    // revocation fetches. Without this, SecTrustEvaluateWithError lets `trustd` (a separate system
    // daemon that does NOT honor our SOCKS5 proxy) fetch OCSP/CRL DIRECT off the Mac IP = a
    // customer-egress leak (the CA + on-path observers see the fleet IP + the browsing pattern). It
    // is ALSO an iPhone divergence: modern Apple platforms use OCSP stapling + the aggregated
    // valid.apple.com revocation cache, NOT live per-cert OCSP from the device. Disabling network
    // fetch keeps stapled/cached revocation (soft-fail, same as iOS) → no validation regression,
    // matches iPhone, and the trustd OCSP/CRL traffic can never leave the host.
    SecTrustSetNetworkFetchAllowed(trustRef.get(), false);
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
    // W2202 L3: capture Transcript-Hash(CH..Certificate) NOW — m_transcriptBytes ends exactly at the cert
    // message just appended at the loop top (Certificate 0x0b, or the CompressedCertificate 0x19 — RFC 8879 §4
    // puts the COMPRESSED message in the transcript). The 0x0f arm verifies the server's signature over THIS
    // hash (RFC 8446 §4.4.3).
    m_transcriptHashThroughCert = transcriptHash(m_negotiatedCipher, m_transcriptBytes);
    return true;
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
    size_t hsRecordsRead = 0;
    // egress audit wxzzaphvp (#9): a single TLS 1.3 handshake message (typically Certificate, or the RFC 8879
    // CompressedCertificate) can be FRAGMENTED across multiple encrypted records when the chain exceeds ~16 KiB.
    // The per-record parse loop below dropped the partial tail (its `break`), so the message was never fully
    // parsed → m_leafCert stayed null → CertificateVerify/Finished failed → handshake failed for big-cert-chain
    // servers. hsLeftover carries the unconsumed partial-message bytes to the next record (prepended to that
    // record's plaintext) so the existing per-message parser always sees COMPLETE messages.
    Vector<uint8_t> hsLeftover;
    while (!gotServerFinished) {
        // W2208 (parser-robustness audit weta2casf P2): bound a hostile peer (this runs pre-cert-validation)
        // that keeps the handshake never-completing — a stream of ChangeCipherSpec records (skipped below
        // WITHOUT advancing gotServerFinished), inner non-0x16 records, or unbounded handshake messages, while
        // never sending Finished → infinite reader-thread spin (the per-record recv timeout resets on each
        // record that has data) + unbounded m_transcriptBytes growth (memory DoS). A legit server handshake is
        // a handful of records (< ~30 even with a fragmented cert chain) totalling well under these caps, so
        // they reject ONLY a malicious stream (zero false-reject on a real handshake).
        if (++hsRecordsRead > 512) {
            m_errorMessage = "server sent >512 handshake records without Finished — rejecting (DoS defense)"_s;
            WTFLogAlways("[Driftstack-EG-WK-PathB-v2/W2208] TLS1.3 handshake record cap (512) exceeded without Finished — rejecting (hostile-peer DoS defense)");
            return false;
        }
        // BUG-42 Fix #4 (gated): total handshake wall-clock cap. The per-record 6s
        // SO_RCVTIMEO resets on every record with data, so a slow/dribbling origin
        // could pin this loaderQueue worker indefinitely; bail once the connect()-stamped
        // deadline is past so the worker frees fast. Gate-off: m_handshakeDeadline is
        // null → no-op.
        if (handshakeDeadlineExceeded()) {
            m_errorMessage = "TLS1.3 handshake exceeded total wall-clock deadline — rejecting (slow-origin worker-hold defense)"_s;
            WTFLogAlways("[BUG-42/Fix4] TLS1.3 handshake total-deadline exceeded for %s — failing fast (frees the worker)", m_sniHostname.utf8().data());
            return false;
        }
        if (m_transcriptBytes.size() > (static_cast<size_t>(1) << 20)) {   // 1 MiB — vastly above any legit transcript
            m_errorMessage = "handshake transcript exceeded 1 MiB without Finished — rejecting (DoS defense)"_s;
            WTFLogAlways("[Driftstack-EG-WK-PathB-v2/W2208] TLS1.3 transcript >1 MiB without Finished — rejecting (unbounded-alloc DoS defense)");
            return false;
        }
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
            WTFLogAlways("[a74622fc/TLSDecryptDiag] sni=%s recordIndex=%zu(1-based) cipher=0x%04x bodySize=%zu seqNumAtFail=%llu",
                m_sniHostname.utf8().data(), hsRecordsRead, m_negotiatedCipher,
                recBody.size(), static_cast<unsigned long long>(m_serverHsKey.seqNum - 1));
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

        // egress audit wxzzaphvp (#9): prepend any partial handshake-message bytes carried from a prior
        // record so the parser below sees COMPLETE messages (fragmented cert chains). Common case
        // (hsLeftover empty) leaves `plaintext` byte-identical to the single-record path.
        if (!hsLeftover.isEmpty()) {
            Vector<uint8_t> combined = std::move(hsLeftover);
            combined.append(plaintext.span());
            plaintext = std::move(combined);
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
            // W2191 (#43) / W2730: server-cert chain validation, factored into validateCertificateBody() so the
            // plain Certificate (0x0b) AND the RFC 8879 CompressedCertificate (0x19) arms share ONE audited path
            // (parse chain → SecTrust vs m_sniHostname → store leaf → capture Transcript-Hash(CH..Certificate)).
            // Gated DRIFTSTACK_PATHB_TLS_CERT_VALIDATE=1 (default-off for safe rollout; flip on after egress
            // verifies legit certs pass).
            static const bool s_validateCert = []() {
                const char* e = getenv("DRIFTSTACK_PATHB_TLS_CERT_VALIDATE");
                return e && e[0] == '1';
            }();
            if (hsType == 0x0b && s_validateCert) {
                if (!validateCertificateBody(plaintext.span().subspan(off + 4, hsLen)))
                    return false;
            }

            // W2730 (#43, founder "boringssl tls handshake failed"): RFC 8879 Compressed Certificate. We advertise
            // compress_certificate(27)=zlib in the ClientHello to match the iPhone fingerprint, so a server MAY
            // reply with CompressedCertificate(25/0x19) INSTEAD of Certificate(0x0b). Before this, 0x19 fell through
            // as "unknown" → m_leafCert stayed null → the 0x0f arm failed "no leaf certificate" → handshake failed →
            // slow/failed loads on cert-compressing servers (Cloudflare/Google/most sites). RFC 8879 §4 body:
            // algorithm(2) + uncompressed_length(u24) + CompressedCertificateMessage(u24 len + bytes). The TRANSCRIPT
            // correctly uses the 0x19 message AS SENT (appended at the loop top); we only DECOMPRESS to recover the
            // leaf for the 0x0f key-possession check. §5 bomb-defense: uncompressed_length is bounded and the inflate
            // output MUST equal it exactly.
            if (hsType == 0x19 && s_validateCert) {
                auto cbody = plaintext.span().subspan(off + 4, hsLen);
                if (cbody.size() < 8) { m_errorMessage = "CompressedCertificate too short"_s; return false; }
                uint16_t algorithm = (static_cast<uint16_t>(cbody[0]) << 8) | cbody[1];
                uint32_t uncompressedLen = (static_cast<uint32_t>(cbody[2]) << 16) | (static_cast<uint32_t>(cbody[3]) << 8) | cbody[4];
                uint32_t compLen = (static_cast<uint32_t>(cbody[5]) << 16) | (static_cast<uint32_t>(cbody[6]) << 8) | cbody[7];
                if (algorithm != 1) {   // zlib — the only algorithm we advertise (DriftstackCustomTLS makeExtCompressCertificate)
                    WTFLogAlways("[Driftstack-EG-WK-PathB-v2/W2730] CompressedCertificate unsupported algorithm %u for %s — rejecting", algorithm, m_sniHostname.utf8().data());
                    m_errorMessage = "CompressedCertificate unsupported compression algorithm"_s;
                    return false;
                }
                static constexpr uint32_t kMaxCertChainBytes = 1u << 17;   // 128 KiB — generous for a real chain, bounds a decompression bomb (RFC 8879 §5)
                if (!uncompressedLen || uncompressedLen > kMaxCertChainBytes) {
                    WTFLogAlways("[Driftstack-EG-WK-PathB-v2/W2730] CompressedCertificate uncompressed_length %u out of range — rejecting", uncompressedLen);
                    m_errorMessage = "CompressedCertificate uncompressed_length out of range"_s;
                    return false;
                }
                if (static_cast<size_t>(8) + compLen != static_cast<size_t>(hsLen)) {
                    m_errorMessage = "CompressedCertificate length mismatch"_s;
                    return false;
                }
                Vector<uint8_t> decompressed(uncompressedLen);
                z_stream zs;
                memset(&zs, 0, sizeof(zs));
                if (inflateInit2(&zs, 15 + 32) != Z_OK) { m_errorMessage = "CompressedCertificate inflateInit failed"_s; return false; }
                zs.next_in = const_cast<Bytef*>(cbody.subspan(8, compLen).data());
                zs.avail_in = static_cast<uInt>(compLen);
                zs.next_out = decompressed.mutableSpan().data();
                zs.avail_out = static_cast<uInt>(uncompressedLen);
                int rv = inflate(&zs, Z_FINISH);
                uLong produced = zs.total_out;
                inflateEnd(&zs);
                if (rv != Z_STREAM_END || produced != uncompressedLen) {
                    WTFLogAlways("[Driftstack-EG-WK-PathB-v2/W2730] CompressedCertificate inflate failed (rv=%d produced=%lu expected=%u) for %s", rv, produced, uncompressedLen, m_sniHostname.utf8().data());
                    m_errorMessage = "CompressedCertificate decompression failed"_s;
                    return false;
                }
                WTFLogAlways("[Driftstack-EG-WK-PathB-v2/W2730] CompressedCertificate (RFC 8879 zlib) %u->%u bytes for %s", compLen, uncompressedLen, m_sniHostname.utf8().data());
                if (!validateCertificateBody(decompressed.span()))
                    return false;
            }

            if (hsType == 0x0f) {  // CertificateVerify — W2202 L3: verify the server's signature over Transcript-Hash(CH..Certificate)
                static const bool s_validateCV = []() {
                    const char* e = getenv("DRIFTSTACK_PATHB_TLS_CERT_VALIDATE");
                    return e && e[0] == '1';
                }();
                if (s_validateCV && !m_sniHostname.isEmpty()) {
                    // CV body (plaintext[off+4..], hsLen bytes): 2B SignatureScheme + 2B sig_len + sig.
                    if (hsLen < 4 || off + 8 > plaintext.size()) { m_errorMessage = "CertificateVerify too short"_s; return false; }
                    uint16_t scheme = (static_cast<uint16_t>(plaintext[off + 4]) << 8) | plaintext[off + 5];
                    uint16_t sigLen = (static_cast<uint16_t>(plaintext[off + 6]) << 8) | plaintext[off + 7];
                    if (static_cast<size_t>(8) + sigLen > static_cast<size_t>(4) + hsLen || off + 8 + static_cast<size_t>(sigLen) > plaintext.size()) { m_errorMessage = "CertificateVerify sig OOB"_s; return false; }
                    std::span<const uint8_t> sig(plaintext.span().data() + off + 8, sigLen);
                    String cvErr;
                    if (!driftstackVerifyCertificateVerify(m_leafCert.get(), sig, scheme, m_transcriptHashThroughCert, /*isServerContext=*/true, cvErr)) {
                        m_errorMessage = makeString("CertificateVerify FAILED: "_s, cvErr);
                        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/W2202] h2 CertificateVerify FAILED (%s) for %s — rejecting (MITM key-possession defense)", cvErr.utf8().data(), m_sniHostname.utf8().data());
                        return false;
                    }
                    m_gotCertVerify = true;  // W2202 L3: REQUIRED by the Finished arm below — set ONLY after a successful verify (which itself requires a chain-valid leaf)
                    WTFLogAlways("[Driftstack-EG-WK-PathB-v2/W2202] h2 CertificateVerify OK for %s", m_sniHostname.utf8().data());
                }
            }

            if (hsType == 0x14) {  // Finished
                // W2202 STEP 3a (verify-gate ws4cffit6): verify the server Finished verify_data MAC BEFORE
                // deriving app secrets / setting gotServerFinished. The 0x0b cert chain proves IDENTITY; this
                // proves key-possession (RFC 8446 §4.4.4) — without it a MITM with its own ECDHE is accepted.
                static const bool s_validateFin = []() {
                    const char* e = getenv("DRIFTSTACK_PATHB_TLS_CERT_VALIDATE");
                    return e && e[0] == '1';
                }();
                if (s_validateFin && !m_sniHostname.isEmpty()) {
                    // m_transcriptBytes ALREADY includes this server Finished (appended at the loop top), so the
                    // server's verify_data covers Transcript-Hash(CH..CertificateVerify) = the prefix EXCLUDING
                    // the trailing 4+hsLen bytes. (Hashing the FULL transcript here would include the Finished →
                    // false-reject EVERY handshake. NOTE: the app-secret chSFhash below DELIBERATELY hashes the
                    // FULL transcript incl. Finished — the two windows differ; do not unify them.)
                    size_t finMsgLen = 4 + hsLen;
                    if (m_transcriptBytes.size() < finMsgLen) { m_errorMessage = "server Finished transcript underflow"_s; return false; }
                    size_t prefixLen = m_transcriptBytes.size() - finMsgLen;
                    Vector<uint8_t> thruCV = (m_negotiatedCipher == 0x1302)
                        ? driftstackSHA384(m_transcriptBytes.span().data(), prefixLen)
                        : driftstackSHA256(m_transcriptBytes.span().data(), prefixLen);
                    auto sFinKey = hkdfExpandLabel(m_negotiatedCipher, m_keySchedule.serverHandshakeSecret(), "finished", {}, m_keySchedule.hashLen());
                    auto expected = hmac(m_negotiatedCipher, sFinKey, thruCV);
                    if (hsLen != expected.size() || off + 4 + hsLen > plaintext.size()) { m_errorMessage = "server Finished length mismatch"_s; return false; }
                    const uint8_t* recvVd = plaintext.span().data() + off + 4;
                    uint8_t diff = 0;
                    for (size_t i = 0; i < expected.size(); ++i) diff |= (expected[i] ^ recvVd[i]);  // constant-time
                    if (diff != 0) {
                        m_errorMessage = makeString("server Finished MAC INVALID for "_s, m_sniHostname);
                        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/W2202] h2 server Finished MAC INVALID — rejecting (handshake auth failure)");
                        return false;
                    }
                    WTFLogAlways("[Driftstack-EG-WK-PathB-v2/W2202] h2 server Finished MAC verified OK");
                    // W2202 L3 REQUIRE-gate (workflow wmxshy3ke finding #5): the 0x0f arm only verifies a
                    // CertificateVerify IF one is sent. A MITM that replays a chain-valid cert it does not own
                    // can forge this ECDHE-based Finished MAC and simply OMIT CertificateVerify — the 0x0f arm
                    // never runs, and verify-if-present would silently accept. CertificateVerify is the ONLY
                    // proof of leaf-private-key possession (RFC 8446 §4.4.3), so REQUIRE it was verified.
                    // (m_gotCertVerify is set true only after a successful verify, which requires a chain-valid
                    // leaf — so this one check closes cert-omit, certverify-omit, and both-omit.)
                    if (!m_gotCertVerify) {
                        m_errorMessage = makeString("server omitted CertificateVerify (MITM cert-skip) for "_s, m_sniHostname);
                        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/W2202] h2 handshake MISSING verified CertificateVerify — rejecting (MITM cert-skip defense)");
                        return false;
                    }
                }
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
        // egress audit wxzzaphvp (#9): retain the unconsumed partial-message tail (a handshake message
        // fragmented across records) for the next record. `plaintext` already includes any prior leftover
        // (prepended above), so REPLACE hsLeftover with the tail. Bound it (a legit fragmented handshake
        // message — even a large cert chain — is < 128 KiB; 256 KiB is safe headroom) to reject a hostile
        // peer dribbling never-completing message bytes (DoS), complementing the 512-record cap above.
        hsLeftover.clear();
        if (off < plaintext.size()) {
            if (plaintext.size() - off > (static_cast<size_t>(256) << 10)) {
                m_errorMessage = "handshake message fragment exceeds 256 KiB — rejecting (DoS defense)"_s;
                WTFLogAlways("[Driftstack-EG-WK-PathB-v2/wxzzaphvp] handshake fragment >256 KiB (%zu) — rejecting", plaintext.size() - off);
                return false;
            }
            hsLeftover.append(plaintext.span().subspan(off));
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
    // W3077 — RFC 8446 §5.2: TLSInnerPlaintext MUST be ≤ 2^14 (16384) bytes. A single caller write
    // larger than that (a >16 KiB POST body on the h1 custom-TLS path, or a >16 KiB WebSocket frame)
    // would make a compliant server reply record_overflow (alert 22), and a >~64 KiB write would
    // truncate the 2-byte record-length field (static_cast<uint8_t>(encLen>>8)) → wire framing desync.
    // Emit one record per ≤16384-byte plaintext chunk, each with its own seal + sequence-number
    // increment + length header, and return the TOTAL bytes consumed so the caller's send loop still
    // sees the full length. A single-record write (len ≤ 16384, incl. the AES-128-GCM common path) is
    // byte-identical to the prior one-record code; the do/while preserves the len==0 case too (one
    // empty application_data record).
    constexpr size_t kMaxTLSRecordPlaintext = 16384;
    size_t off = 0;
    do {
        size_t chunk = std::min(len - off, kMaxTLSRecordPlaintext);
        // Wave 29-499.180 — encrypt app data with client_app_key (AES-256-GCM).
        // Inner plaintext: data + inner_type 0x17 (application_data).
        Vector<uint8_t> inner;
        inner.append(std::span<const uint8_t>(data + off, chunk));
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
        off += chunk;
    } while (off < len);
    return static_cast<int>(len);
}

Vector<uint8_t> DriftstackTLS13Client::readApplicationRecord(int depth)
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
        // W3065 (audit): a ZERO-LENGTH application_data record is legal (RFC 8446 §5.4). Returning an
        // empty pt here is WRONG — the caller (read()) treats an empty return as EOF and TRUNCATES the
        // response (blank/broken page). Read the NEXT record instead, bounded by the same depth guard as
        // the 0x16 branch; reserve the empty return strictly for a true readTLSRecord failure (real EOF).
        if (pt.isEmpty()) {
            if (depth >= 32) { m_errorMessage = "too many empty app-data records — rejecting (DoS defense)"_s; return {}; }
            return readApplicationRecord(depth + 1);
        }
        return pt;  // application_data
    } else if (innerType == 0x16) {
        // Post-handshake message (NewSessionTicket, KeyUpdate). Append to
        // transcript and recurse to read next real app data record.
        // W2209 (parser-robustness audit weta2casf): a hostile server flooding inner-0x16 post-handshake
        // records drove UNBOUNDED recursion here (stack-exhaustion crash) + unbounded m_transcriptBytes growth.
        // Bound the recursion depth (a legit server sends a few NewSessionTickets / rare KeyUpdate — 32 is huge
        // headroom + stack-safe) AND the transcript size (cross-call growth → 1 MiB, far above any handshake).
        if (depth >= 32 || m_transcriptBytes.size() > (static_cast<size_t>(1) << 20)) {
            m_errorMessage = "too many post-handshake records — rejecting (DoS defense)"_s;
            WTFLogAlways("[Driftstack-EG-WK-PathB-v2/W2209] post-handshake 0x16 flood (depth=%d transcript=%zu) — rejecting (recursion/alloc DoS defense)", depth, m_transcriptBytes.size());
            return { };
        }
        // egress audit wxzzaphvp (#8): handle a server KeyUpdate (RFC 8446 §7.2, handshake type 0x18)
        // BEFORE the transcript append. The server has switched to the next server
        // application_traffic_secret; without rekeying our READ key here, EVERY subsequent record fails
        // its AEAD tag ("decrypt failed") → the connection breaks mid-session. Advance the secret via
        // HKDF-Expand-Label("traffic upd") + re-derive the read key (deriveTrafficKey resets seqNum→0).
        // KeyUpdate is post-handshake → NOT transcript material, so it is NOT appended. We deliberately
        // do NOT rotate our own SEND key / echo a KeyUpdate on update_requested: the server keeps
        // decrypting our records with our unchanged send key, so the connection stays valid — send-key
        // rotation is a minor RFC-SHOULD follow-up, not required to keep reading.
        if (!pt.isEmpty() && pt[0] == 0x18) {
            if (m_serverAppSecretCurrent.isEmpty())
                m_serverAppSecretCurrent = m_keySchedule.serverApplicationSecret();
            auto next = hkdfExpandLabel(m_negotiatedCipher, m_serverAppSecretCurrent, "traffic upd", { }, m_keySchedule.hashLen());
            if (next.size() != m_keySchedule.hashLen()) {
                m_errorMessage = "KeyUpdate: server traffic-secret update (traffic upd) failed"_s;
                return { };
            }
            m_serverAppSecretCurrent = std::move(next);
            m_serverAppKey = m_keySchedule.deriveTrafficKey(m_serverAppSecretCurrent);
            WTFLogAlways("[Driftstack-EG-WK-PathB-v2/wxzzaphvp] server KeyUpdate — server app read-key rekeyed (traffic upd), seqNum reset to 0");
            return readApplicationRecord(depth + 1);
        }
        m_transcriptBytes.append(pt.span());
        return readApplicationRecord(depth + 1);
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
// W3071 — per-suite TLS 1.2 AEAD parameters. The six suites the iPhone-byte-exact ClientHello
// advertises (see kIPhoneCiphers): AES-128-GCM-SHA256 (0xc02f/0xc02b, the original path),
// AES-256-GCM-SHA384 (0xc030/0xc02c) and ChaCha20-Poly1305 (0xcca8/0xcca9, RFC 7905). All are
// AEAD (mac_key_len = 0). RSA vs ECDSA (…RSA… vs …ECDSA…) differ ONLY in the SKE signature type,
// which the SKE-verify path already keys off the wire SignatureScheme — the record/PRF/key
// schedule is identical within a {hash, enc, iv} class, so we parameterize on those three.
bool t12CipherIsSha384(uint16_t cipher)   // W3071 — *_SHA384 suites use the SHA-384 PRF + transcript
{
    return cipher == 0xc030 || cipher == 0xc02c;
}
bool t12CipherIsChaCha(uint16_t cipher)   // W3071 — RFC 7905 record construction (no explicit nonce)
{
    return cipher == 0xcca8 || cipher == 0xcca9;
}
size_t t12CipherEncKeyLen(uint16_t cipher)   // W3071 — 16 (AES-128) / 32 (AES-256, ChaCha)
{
    if (cipher == 0xc02f || cipher == 0xc02b)
        return 16;
    return 32; // 0xc030/0xc02c AES-256, 0xcca8/0xcca9 ChaCha20
}
size_t t12CipherFixedIvLen(uint16_t cipher)   // W3071 — 4 (GCM implicit-IV prefix) / 12 (ChaCha)
{
    return t12CipherIsChaCha(cipher) ? 12 : 4;
}
bool t12CipherIsSupported(uint16_t cipher)   // W3071 — accept-list for the 1.2 fallback
{
    return cipher == 0xc02f || cipher == 0xc02b   // AES-128-GCM-SHA256 (RSA / ECDSA)
        || cipher == 0xc030 || cipher == 0xc02c   // AES-256-GCM-SHA384 (RSA / ECDSA)
        || cipher == 0xcca8 || cipher == 0xcca9;  // ChaCha20-Poly1305   (RSA / ECDSA)
}

// TLS 1.2 PRF (RFC 5246 §5). P_hash(secret, seed): A(0)=seed; A(i)=HMAC(secret,A(i-1));
// out += HMAC(secret, A(i) || seed). W3071: the HMAC hash is now selectable — SHA-384 for the
// *_SHA384 suites (0xc030/0xc02c), SHA-256 for every other suite (AES-128-GCM AND ChaCha20, both
// SHA256-PRF). Used for master_secret, key_block expansion, AND the 12-byte Finished verify_data.
Vector<uint8_t> tls12Prf(bool sha384, const Vector<uint8_t>& secret, const char* label,
    const Vector<uint8_t>& seed, size_t outLen)
{
    Vector<uint8_t> labelSeed;
    labelSeed.append(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(label), strlen(label)));
    labelSeed.append(seed.span());

    auto H = [&](const Vector<uint8_t>& k, const Vector<uint8_t>& d) {   // W3071
        return sha384 ? driftstackHmacSha384(k, d) : driftstackHmacSha256(k, d);
    };
    Vector<uint8_t> out;
    Vector<uint8_t> a = H(secret, labelSeed); // A(1)
    while (out.size() < outLen) {
        Vector<uint8_t> input = a;
        input.append(labelSeed.span());
        out.append(H(secret, input).span());
        a = H(secret, a); // A(i+1)
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

// W3071 — dispatch to the negotiated suite's AEAD primitive. AES-GCM (the driftstackAes*Gcm impl
// keys off key.size(): 16→AES-128, 32→AES-256) vs ChaCha20-Poly1305 (RFC 7905). Both take a
// 12-byte nonce and append a 16-byte tag; the AES-256 wrappers forward to the AES-128 impl, so the
// AES-128 path stays byte-for-byte identical to the original.
Vector<uint8_t> t12Aead(uint16_t cipher, bool encrypt, const Vector<uint8_t>& key,
    const Vector<uint8_t>& nonce, const Vector<uint8_t>& in, const Vector<uint8_t>& aad)
{
    if (t12CipherIsChaCha(cipher))
        return encrypt ? driftstackChacha20Poly1305Encrypt(key, nonce, in, aad)
                       : driftstackChacha20Poly1305Decrypt(key, nonce, in, aad);
    return encrypt ? driftstackAes256GcmEncrypt(key, nonce, in, aad)
                   : driftstackAes256GcmDecrypt(key, nonce, in, aad);
}

// W3071 — seal one TLS 1.2 record's plaintext into its on-the-wire PAYLOAD (the bytes AFTER the
// 5-byte record header). Shared by the client-write (writeTLS12Record) + client-Finished paths.
//   GCM (RFC 5288): nonce = fixed_iv(4) || explicit(8); explicit = seq_be(8); payload = explicit || AEAD.
//   ChaCha (RFC 7905): nonce = fixed_iv(12) XOR (0x00000000 || seq_be(8)); NO explicit nonce → payload = AEAD.
//   AAD (both) = seq_be(8) || type(1) || 0x0303 || plaintext_len(2)  (TLS 1.2 AAD uses the PLAINTEXT length).
// Returns empty on AEAD failure (a real record is always ≥16 bytes: the tag).
Vector<uint8_t> t12SealRecord(uint16_t cipher, const Vector<uint8_t>& key, const Vector<uint8_t>& fixedIV,
    uint64_t seq, uint8_t contentType, std::span<const uint8_t> plaintext)
{
    Vector<uint8_t> seqBytes;
    for (int i = 7; i >= 0; --i) seqBytes.append(static_cast<uint8_t>((seq >> (i * 8)) & 0xFF)); // seq_be(8)
    const bool isChaCha = t12CipherIsChaCha(cipher);
    Vector<uint8_t> nonce;
    if (isChaCha) {
        Vector<uint8_t> padded;   // 0x00000000 || seq_be(8) = 12 bytes
        padded.append(0x00); padded.append(0x00); padded.append(0x00); padded.append(0x00);
        padded.append(seqBytes.span());
        for (size_t i = 0; i < fixedIV.size(); ++i)
            nonce.append(static_cast<uint8_t>(fixedIV[i] ^ padded[i]));   // fixed_iv(12) XOR padded
    } else {
        nonce.append(fixedIV.span());     // fixed_iv(4)
        nonce.append(seqBytes.span());    // explicit(8) = seq_be
    }
    Vector<uint8_t> aad;
    aad.append(seqBytes.span());
    aad.append(contentType); aad.append(0x03); aad.append(0x03);
    aad.append(static_cast<uint8_t>((plaintext.size() >> 8) & 0xFF));
    aad.append(static_cast<uint8_t>(plaintext.size() & 0xFF));
    Vector<uint8_t> pt; pt.append(plaintext);
    Vector<uint8_t> ct = t12Aead(cipher, /*encrypt*/ true, key, nonce, pt, aad);
    if (ct.isEmpty()) return { };
    Vector<uint8_t> payload;
    if (!isChaCha)
        payload.append(seqBytes.span());   // GCM prepends the 8-byte explicit nonce on the wire
    payload.append(ct.span());
    return payload;
}

// W3071 — open a TLS 1.2 record PAYLOAD (bytes AFTER the 5-byte header) → plaintext. `seq` is our
// local receive counter (used for the AAD, and — ChaCha only — the nonce). For GCM the explicit
// nonce is taken FROM THE WIRE (first 8 bytes), per RFC 5288, not from `seq`. Shared by the
// server-Finished + readTLS12Record paths.
// W3075 — returns std::optional to give AEAD auth a success/failure channel INDEPENDENT of the
// plaintext length: std::nullopt = malformed record OR AEAD auth failure (bad_record_mac); a
// present-but-EMPTY vector = a genuinely-decrypted 0-length application_data record (RFC 5246
// §6.2.1). The old `Vector` return conflated the two — an empty result meant BOTH "auth failed"
// and "valid empty record", so the caller mistook a tampered record (and a legal empty record)
// for a clean EOF and silently truncated the response.
std::optional<Vector<uint8_t>> t12OpenRecord(uint16_t cipher, const Vector<uint8_t>& key, const Vector<uint8_t>& fixedIV,
    uint64_t seq, uint8_t contentType, const Vector<uint8_t>& payload)
{
    Vector<uint8_t> seqBytes;
    for (int i = 7; i >= 0; --i) seqBytes.append(static_cast<uint8_t>((seq >> (i * 8)) & 0xFF));
    const bool isChaCha = t12CipherIsChaCha(cipher);
    Vector<uint8_t> nonce, ct;
    if (isChaCha) {
        if (payload.size() < 16) return std::nullopt;   // W3075 — tag floor (no explicit nonce on the wire) → malformed
        Vector<uint8_t> padded;
        padded.append(0x00); padded.append(0x00); padded.append(0x00); padded.append(0x00);
        padded.append(seqBytes.span());
        for (size_t i = 0; i < fixedIV.size(); ++i)
            nonce.append(static_cast<uint8_t>(fixedIV[i] ^ padded[i]));
        ct.append(payload.span());             // whole payload = ciphertext || tag
    } else {
        if (payload.size() < 8 + 16) return std::nullopt;   // W3075 — explicit_nonce(8) + tag(16) floor → malformed
        nonce.append(fixedIV.span());              // fixed_iv(4)
        nonce.append(slice(payload, 0, 8).span()); // explicit(8) FROM THE WIRE
        ct = slice(payload, 8, payload.size() - 8);
    }
    size_t ptLen = ct.size() - 16;
    Vector<uint8_t> aad;
    aad.append(seqBytes.span());
    aad.append(contentType); aad.append(0x03); aad.append(0x03);
    aad.append(static_cast<uint8_t>((ptLen >> 8) & 0xFF)); aad.append(static_cast<uint8_t>(ptLen & 0xFF));
    Vector<uint8_t> pt = t12Aead(cipher, /*encrypt*/ false, key, nonce, ct, aad);
    if (!pt.isEmpty())
        return pt;                                  // COMMON PATH — authentic, non-empty plaintext (byte-for-byte unchanged)
    // W3075 — t12Aead returns empty for BOTH an AEAD auth FAILURE and a genuinely-decrypted
    // 0-length record. Disambiguate: with ptLen>0 an authentic decrypt is never empty, so an
    // empty result there is unambiguously an auth failure → nullopt. Only when ptLen==0 (a legal
    // empty application_data record whose ciphertext is exactly the 16-byte tag) is it ambiguous;
    // re-derive the tag over an empty plaintext (GCM/ChaCha are deterministic for a fixed
    // key||nonce||aad — this recomputes exactly the decrypt's expected tag) and constant-time
    // compare it to the record's tag. A match proves an authentic 0-length record; a mismatch is
    // a tampered/forged empty record (bad_record_mac) → nullopt.
    if (ptLen == 0 && ct.size() == 16) {
        Vector<uint8_t> reTag = t12Aead(cipher, /*encrypt*/ true, key, nonce, Vector<uint8_t> { }, aad);
        if (reTag.size() == 16) {
            uint8_t diff = 0;
            for (size_t i = 0; i < 16; ++i) diff |= static_cast<uint8_t>(reTag[i] ^ ct[i]);
            if (!diff)
                return Vector<uint8_t> { };         // authentic 0-length application_data record
        }
    }
    return std::nullopt;                            // AEAD auth failure (bad_record_mac) / malformed
}
} // namespace

// W2202 L4: verify a TLS 1.2 ServerKeyExchange signature (RFC 5246 §7.4.3 / RFC 4492 §5.4) — the 1.2 analogue
// of CertificateVerify: the server signs client_random || server_random || ServerECDHParams with the leaf
// private key, proving key-possession (the Finished MAC only proves ECDHE-key-possession, which a MITM has).
// The 2-byte field is a SignatureScheme (RFC 8446-style) OR the legacy {hash,sig} pair — same wire values for
// the schemes a real iPhone-negotiated 1.2 server uses. Unlike 1.3, TLS 1.2 PERMITS rsa_pkcs1_* — map it HERE
// (the shared 1.3 mapper driftstackSecKeyAlgorithmForScheme rejects PKCS1). ...Message... variants → SecKey
// hashes the blob itself. Self-contained (defined before doTLS12Handshake; no dep on the 1.3 mapper below).
static bool driftstackVerifyTLS12Signature(SecCertificateRef leaf, std::span<const uint8_t> signedData,
    std::span<const uint8_t> sig, uint16_t sigScheme, String& outError)
{
    if (!leaf) { outError = "no leaf cert"_s; return false; }
    if (sig.empty() || signedData.empty()) { outError = "empty SKE sig/data"_s; return false; }
    SecKeyAlgorithm alg = nullptr;
    switch (sigScheme) {
    case 0x0401: alg = kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256; break; // rsa_pkcs1_sha256 (1.2-legal; == legacy {SHA256,RSA})
    case 0x0501: alg = kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA384; break;
    case 0x0601: alg = kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA512; break;
    case 0x0804: alg = kSecKeyAlgorithmRSASignatureMessagePSSSHA256; break;      // rsa_pss_rsae_sha256
    case 0x0805: alg = kSecKeyAlgorithmRSASignatureMessagePSSSHA384; break;
    case 0x0806: alg = kSecKeyAlgorithmRSASignatureMessagePSSSHA512; break;
    case 0x0403: alg = kSecKeyAlgorithmECDSASignatureMessageX962SHA256; break;   // ecdsa_secp256r1_sha256 (DER r,s)
    case 0x0503: alg = kSecKeyAlgorithmECDSASignatureMessageX962SHA384; break;
    case 0x0603: alg = kSecKeyAlgorithmECDSASignatureMessageX962SHA512; break;
    default:
        outError = makeString("unsupported TLS1.2 SKE sig scheme 0x"_s, hex(sigScheme, 4));
        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/W2202] TLS1.2 SKE sig scheme 0x%04x unsupported — rejecting (fail-closed)", sigScheme);
        return false;
    }
    RetainPtr<SecKeyRef> pubKey = adoptCF(SecCertificateCopyKey(leaf));
    if (!pubKey) { outError = "SecCertificateCopyKey failed"_s; return false; }
    RetainPtr<CFDataRef> dataCF = adoptCF(CFDataCreate(nullptr, signedData.data(), signedData.size()));
    RetainPtr<CFDataRef> sigCF = adoptCF(CFDataCreate(nullptr, sig.data(), sig.size()));
    if (!dataCF || !sigCF) { outError = "CFDataCreate failed"_s; return false; }
    CFErrorRef cfErr = nullptr;
    bool ok = SecKeyVerifySignature(pubKey.get(), alg, dataCF.get(), sigCF.get(), &cfErr);
    if (cfErr)
        CFRelease(cfErr);
    if (!ok) { outError = "TLS1.2 SKE signature INVALID"_s; return false; }
    return true;
}

bool DriftstackTLS13Client::doTLS12Handshake(const TLS13ServerHello& sh)
{
    // W3071 — the record layer + PRF + key schedule below are now suite-parameterized (see the
    // t12Cipher* / tls12Prf / t12SealRecord / t12OpenRecord helpers). Accept the six AEAD ECDHE
    // suites the iPhone-byte-exact ClientHello advertises: AES-128-GCM-SHA256 (0xc02f/0xc02b, the
    // original path — unchanged byte-for-byte), AES-256-GCM-SHA384 (0xc030/0xc02c) and
    // ChaCha20-Poly1305/RFC 7905 (0xcca8/0xcca9). A TLS-1.2-only origin offering ONLY AES-256-GCM
    // or ChaCha20 (not AES-128-GCM) now completes the handshake, matching a real iPhone. Reject
    // anything else loudly rather than derive wrong-length keys.
    if (!t12CipherIsSupported(sh.cipherSuite)) {
        m_errorMessage = makeString("TLS1.2: cipher 0x"_s, hex(sh.cipherSuite, 4),
            " not supported (only AES-128/256-GCM + ChaCha20-Poly1305 ECDHE)"_s);
        return false;
    }
    const bool t12UseSha384 = t12CipherIsSha384(sh.cipherSuite);   // W3071 — PRF + transcript hash selector
    // 1.2 servers send (plaintext): Certificate, ServerKeyExchange, [CertificateRequest],
    // ServerHelloDone. Read records (each may hold several / partial messages) until SHD.
    uint16_t serverCurve = 0;
    Vector<uint8_t> serverEcPub;
    bool gotSKE = false, gotSHD = false;
    bool gotCertRequest = false; // W3072 — server sent CertificateRequest (0x0d) → we owe an (empty) client Certificate
    Vector<uint8_t> acc;

    // W2202 L4: TLS 1.2 server authentication (workflow w2tykgdqj finding #6). Without this the 1.2 fallback
    // accepts ANY/self-signed/no cert — a network MITM or malicious SOCKS5 exit downgrades to 1.2+0xc02f and
    // fully re-opens the cert-skip MITM the 1.3 require-gate closed. Gate like 1.3 (validate flag + non-empty
    // SNI; relay/smoke handshakes skip). We REQUIRE both a chain-valid Certificate (0x0b) AND a verified
    // ServerKeyExchange signature (the 1.2 key-possession proof) before returning true.
    static const bool s_validateT12 = []() {
        const char* e = getenv("DRIFTSTACK_PATHB_TLS_CERT_VALIDATE");
        return e && e[0] == '1';
    }();
    const bool doValidate = s_validateT12 && !m_sniHostname.isEmpty();
    RetainPtr<SecCertificateRef> t12Leaf;
    bool t12CertValidated = false, t12SkeVerified = false;

    size_t t12RecordsRead = 0;
    while (!gotSHD) {
        // W2208 (parser-robustness audit weta2casf P3): bound a hostile TLS1.2 server (reachable via downgrade)
        // that streams handshake records forever without ServerHelloDone (0x0e) → unbounded `acc` growth +
        // infinite loop (the per-record recv timeout resets on each record). A legit 1.2 server flight
        // (Certificate + ServerKeyExchange + ServerHelloDone) is a few records totalling well under these caps.
        if (++t12RecordsRead > 512) {
            m_errorMessage = "TLS1.2: >512 handshake records without ServerHelloDone — rejecting (DoS defense)"_s;
            WTFLogAlways("[Driftstack-EG-WK-PathB-v2/W2208] TLS1.2 handshake record cap (512) exceeded without ServerHelloDone — rejecting (hostile-peer DoS defense)");
            return false;
        }
        // BUG-42 Fix #4 (gated): total handshake wall-clock cap (mirrors the 1.3 loop) —
        // a slow 1.2 server's resetting per-record timeout can't pin the worker past the
        // connect()-stamped deadline. Gate-off: m_handshakeDeadline null → no-op.
        if (handshakeDeadlineExceeded()) {
            m_errorMessage = "TLS1.2 handshake exceeded total wall-clock deadline — rejecting (slow-origin worker-hold defense)"_s;
            WTFLogAlways("[BUG-42/Fix4] TLS1.2 handshake total-deadline exceeded for %s — failing fast (frees the worker)", m_sniHostname.utf8().data());
            return false;
        }
        if (acc.size() > (static_cast<size_t>(1) << 20)) {   // 1 MiB — vastly above any legit 1.2 server flight
            m_errorMessage = "TLS1.2: handshake accumulation exceeded 1 MiB without ServerHelloDone — rejecting (DoS defense)"_s;
            WTFLogAlways("[Driftstack-EG-WK-PathB-v2/W2208] TLS1.2 acc >1 MiB without ServerHelloDone — rejecting (unbounded-alloc DoS defense)");
            return false;
        }
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
            if (t == 0x0b && doValidate) { // Certificate → SecTrust chain+hostname (W2202 L4; mirrors the 1.3 0x0b arm)
                // TLS 1.2 Certificate body: 3B cert_list_len + [3B cert_len + DER]* (NO per-cert extensions — that's 1.3 only).
                if (l < 3) { m_errorMessage = "TLS1.2: Certificate msg too short"_s; return false; }
                uint32_t listLen = (static_cast<uint32_t>(mb[0]) << 16) | (static_cast<uint32_t>(mb[1]) << 8) | mb[2];
                size_t cOff = 3, listEnd = static_cast<size_t>(3) + listLen;
                if (listEnd > l) { m_errorMessage = "TLS1.2: Certificate list OOB"_s; return false; }
                RetainPtr<CFMutableArrayRef> certArray = adoptCF(CFArrayCreateMutable(nullptr, 0, &kCFTypeArrayCallBacks));
                while (cOff + 3 <= listEnd) {
                    uint32_t certLen = (static_cast<uint32_t>(mb[cOff]) << 16) | (static_cast<uint32_t>(mb[cOff + 1]) << 8) | mb[cOff + 2];
                    cOff += 3;
                    if (cOff + certLen > listEnd) break;
                    RetainPtr<CFDataRef> cfData = adoptCF(CFDataCreate(nullptr, mb + cOff, certLen));
                    RetainPtr<SecCertificateRef> cert = adoptCF(SecCertificateCreateWithData(nullptr, cfData.get()));
                    if (cert) { if (!t12Leaf) t12Leaf = cert; CFArrayAppendValue(certArray.get(), cert.get()); }
                    cOff += certLen;
                }
                if (!CFArrayGetCount(certArray.get())) { m_errorMessage = "TLS1.2: no parseable server certs"_s; return false; }
                RetainPtr<SecPolicyRef> policy = adoptCF(SecPolicyCreateSSL(true, m_sniHostname.createCFString().get()));
                SecTrustRef trust = nullptr;
                OSStatus st = SecTrustCreateWithCertificates(certArray.get(), policy.get(), &trust);
                RetainPtr<SecTrustRef> trustRef = adoptCF(trust);
                if (st != errSecSuccess || !trustRef) { m_errorMessage = "TLS1.2: SecTrustCreateWithCertificates failed"_s; return false; }
                // Driftstack (egress channel-4 + iPhone-fidelity, 2026-06-19): disable per-evaluation NETWORK
                // revocation fetches so trustd cannot fetch OCSP/CRL DIRECT off the Mac IP (egress leak +
                // non-iPhone traffic; iOS uses stapling + valid.apple.com aggregation, not live per-cert OCSP).
                // Keeps stapled/cached revocation (soft-fail, same as iOS) → no validation regression.
                SecTrustSetNetworkFetchAllowed(trustRef.get(), false);
                CFErrorRef evalErr = nullptr;
                bool trusted = SecTrustEvaluateWithError(trustRef.get(), &evalErr);
                if (evalErr)
                    CFRelease(evalErr);
                if (!trusted) {
                    m_errorMessage = makeString("TLS1.2: server cert chain UNTRUSTED for "_s, m_sniHostname);
                    WTFLogAlways("[Driftstack-EG-WK-PathB-v2/W2202] TLS1.2 CERT VALIDATION FAILED for %s — rejecting (MITM defense)", m_sniHostname.utf8().data());
                    return false;
                }
                t12CertValidated = true;
                WTFLogAlways("[Driftstack-EG-WK-PathB-v2/W2202] TLS1.2 server cert chain validated OK for %s", m_sniHostname.utf8().data());
            } else if (t == 0x0c && l >= 4 && mb[0] == 0x03) { // ServerKeyExchange, named_curve
                serverCurve = (static_cast<uint16_t>(mb[1]) << 8) | mb[2];
                uint8_t pubLen = mb[3];
                if (static_cast<uint32_t>(4) + pubLen <= l) {
                    serverEcPub.clear();
                    serverEcPub.append(std::span<const uint8_t>(mb + 4, pubLen));
                    gotSKE = true;
                    // W2202 L4: verify the SKE signature = the 1.2 key-possession proof. After the ServerECDHParams
                    // (curve_type(1)=0x03 || named_curve(2) || pubLen(1) || pub) come SignatureScheme(2) + sig_len(2) + sig.
                    // The signed blob is client_random || server_random || ServerECDHParams. 0x0b precedes 0x0c, so t12Leaf is set.
                    if (doValidate) {
                        size_t pOff = static_cast<size_t>(4) + pubLen; // == params length; start of SignatureScheme
                        if (pOff + 4 > l) { m_errorMessage = "TLS1.2: SKE missing signature"_s; return false; }
                        uint16_t sigScheme = (static_cast<uint16_t>(mb[pOff]) << 8) | mb[pOff + 1];
                        uint16_t skeSigLen = (static_cast<uint16_t>(mb[pOff + 2]) << 8) | mb[pOff + 3];
                        if (pOff + 4 + static_cast<size_t>(skeSigLen) > l) { m_errorMessage = "TLS1.2: SKE sig OOB"_s; return false; }
                        Vector<uint8_t> signedBlob;
                        signedBlob.append(m_clientRandom.span());
                        signedBlob.append(m_serverRandom.span());
                        signedBlob.append(std::span<const uint8_t>(mb, pOff)); // ServerECDHParams (curve_type..pub)
                        std::span<const uint8_t> skeSig(mb + pOff + 4, skeSigLen);
                        String skeErr;
                        if (!driftstackVerifyTLS12Signature(t12Leaf.get(), signedBlob.span(), skeSig, sigScheme, skeErr)) {
                            m_errorMessage = makeString("TLS1.2: SKE signature verify FAILED: "_s, skeErr);
                            WTFLogAlways("[Driftstack-EG-WK-PathB-v2/W2202] TLS1.2 SKE signature INVALID (%s) for %s — rejecting (MITM key-possession defense)", skeErr.utf8().data(), m_sniHostname.utf8().data());
                            return false;
                        }
                        t12SkeVerified = true;
                        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/W2202] TLS1.2 SKE signature OK for %s", m_sniHostname.utf8().data());
                    }
                }
            } else if (t == 0x0d) // W3072 — CertificateRequest: a real iPhone answers with an (empty) client
                gotCertRequest = true; // Certificate before ClientKeyExchange (RFC 5246 §7.4.6), else mTLS servers reject
            else if (t == 0x0e)
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

    // W3072 — the server sent a CertificateRequest (0x0d). RFC 5246 §7.4.6: the client MUST answer with a
    // Certificate message; with no client cert to offer (a real iPhone in a normal browse has none) it sends
    // an EMPTY certificate_list. Sent BEFORE ClientKeyExchange and appended to the transcript in that exact
    // position so the session_hash / Finished match. NO CertificateVerify follows (that's only when a cert IS
    // sent). Servers that merely REQUEST a client cert then proceed; a strict mTLS-required server still
    // rejects — exactly as it would a real, certless iPhone.
    if (gotCertRequest) {
        const uint8_t emptyCert[7] = { 0x0b, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00 }; // Certificate: msg_len=3, cert_list_len=0
        m_transcriptBytes.append(std::span<const uint8_t>(emptyCert, sizeof(emptyCert)));
        Vector<uint8_t> rec; rec.append(0x16); rec.append(0x03); rec.append(0x03);
        rec.append(0x00); rec.append(static_cast<uint8_t>(sizeof(emptyCert)));
        rec.append(std::span<const uint8_t>(emptyCert, sizeof(emptyCert)));
        if (!writeAll(m_fd, rec.span().data(), rec.size())) { m_errorMessage = "TLS1.2 send empty client Certificate failed"_s; return false; }
        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/W3072] TLS1.2 CertificateRequest → sent empty client Certificate (RFC 5246 §7.4.6) for %s", m_sniHostname.utf8().data());
    }

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
    // W3071: SHA-384 for the *_SHA384 suites (0xc030/0xc02c), SHA-256 otherwise (incl. ChaCha20).
    Vector<uint8_t> sessionHash = t12UseSha384
        ? driftstackSHA384(m_transcriptBytes.span().data(), m_transcriptBytes.size())
        : driftstackSHA256(m_transcriptBytes.span().data(), m_transcriptBytes.size());

    // master_secret: EMS (RFC 7627) → PRF(preMaster,"extended master secret",session_hash);
    // else classic PRF(preMaster,"master secret",client_random+server_random).
    // W3071: the PRF hash follows the suite (t12UseSha384) — same selector as session_hash.
    if (m_t12EMS)
        m_t12MasterSecret = tls12Prf(t12UseSha384, preMaster, "extended master secret", sessionHash, 48);
    else {
        Vector<uint8_t> crSr; crSr.append(m_clientRandom.span()); crSr.append(m_serverRandom.span());
        m_t12MasterSecret = tls12Prf(t12UseSha384, preMaster, "master secret", crSr, 48);
    }
    // key_block = PRF(master,"key expansion",server_random+client_random, key_block_len) — AEAD: no MAC keys.
    // W3071: key_block_len = 2*enc_key_len + 2*fixed_iv_len, computed from the suite (16/32-byte keys,
    // 4-byte GCM / 12-byte ChaCha fixed IVs) — NOT hardcoded. Split: [clientKey][serverKey][clientIV][serverIV].
    const size_t encKeyLen = t12CipherEncKeyLen(sh.cipherSuite);        // W3071
    const size_t fixedIvLen = t12CipherFixedIvLen(sh.cipherSuite);      // W3071
    const size_t keyBlockLen = 2 * encKeyLen + 2 * fixedIvLen;          // W3071
    Vector<uint8_t> srCr; srCr.append(m_serverRandom.span()); srCr.append(m_clientRandom.span());
    Vector<uint8_t> keyBlock = tls12Prf(t12UseSha384, m_t12MasterSecret, "key expansion", srCr, keyBlockLen);   // W3071
    m_t12ClientKey = slice(keyBlock, 0, encKeyLen);                                  // W3071
    m_t12ServerKey = slice(keyBlock, encKeyLen, encKeyLen);                          // W3071
    m_t12ClientFixedIV = slice(keyBlock, 2 * encKeyLen, fixedIvLen);                 // W3071
    m_t12ServerFixedIV = slice(keyBlock, 2 * encKeyLen + fixedIvLen, fixedIvLen);    // W3071
    if (m_t12ClientKey.size() != encKeyLen || m_t12ServerKey.size() != encKeyLen        // W3071
        || m_t12ClientFixedIV.size() != fixedIvLen || m_t12ServerFixedIV.size() != fixedIvLen) {   // W3071
        m_errorMessage = "TLS1.2 key_block too short"_s; return false; }

    // ChangeCipherSpec (record type 0x14, payload 0x01)
    { uint8_t ccs[6] = { 0x14, 0x03, 0x03, 0x00, 0x01, 0x01 };
      if (!writeAll(m_fd, ccs, 6)) { m_errorMessage = "TLS1.2 send CCS failed"_s; return false; } }

    // Client Finished: verify_data = PRF(master, "client finished", session_hash, 12),
    // sent as an ENCRYPTED handshake record (content type 0x16) with client seq 0.
    // W3071: verify_data STAYS 12 bytes for ALL these suites (TLS 1.2 default) — even the SHA384
    // suites truncate the PRF output to 12. Only the PRF hash follows the suite (t12UseSha384).
    Vector<uint8_t> verifyData = tls12Prf(t12UseSha384, m_t12MasterSecret, "client finished", sessionHash, 12);
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
            // W3071 — decrypt the server Finished (handshake content type 0x16, server seq 0) via the
            // shared suite-generic open helper: GCM strips the wire explicit_nonce(8); ChaCha (RFC 7905)
            // has none. Successful AEAD auth = the derived key schedule is correct.
            // W3075 — t12OpenRecord now returns std::optional: std::nullopt = AEAD auth failure
            // (== wrong key schedule here) / malformed; a present vector = decrypted plaintext (a
            // real empty vs a failure is now distinguished — the server Finished is always the
            // 16-byte handshake message, never empty, but the check no longer conflates them).
            std::optional<Vector<uint8_t>> pt = t12OpenRecord(sh.cipherSuite, m_t12ServerKey, m_t12ServerFixedIV,
                m_t12ServerSeq, /*contentType*/ 0x16, recBody);
            m_t12ServerSeq++;
            if (!pt) { m_errorMessage = "TLS1.2: server Finished decrypt failed (key schedule wrong)"_s; return false; }
            serverFinished = true;
            WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.340] TLS1.2 server Finished decrypted OK (%zuB) — handshake verified, keys correct.", pt->size());
        }
    }
    if (!serverFinished) { m_errorMessage = "TLS1.2: never received server Finished"_s; return false; }
    // W2202 L4 REQUIRE-gate: a MITM could OMIT the Certificate or send an unsigned ServerKeyExchange. Require
    // BOTH a chain-valid leaf AND a verified SKE signature before completing (analogue of the 1.3 m_gotCertVerify
    // gate). Gated on doValidate so relay/smoke handshakes (no SNI) are unaffected.
    if (doValidate && (!t12CertValidated || !t12SkeVerified)) {
        m_errorMessage = makeString("TLS1.2: server omitted Certificate or SKE-signature (MITM downgrade) for "_s, m_sniHostname);
        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/W2202] TLS1.2 handshake MISSING validated cert + SKE-sig for %s — rejecting (MITM downgrade defense)", m_sniHostname.utf8().data());
        return false;
    }
    return true;
}

int DriftstackTLS13Client::writeTLS12Record(const uint8_t* data, size_t len, uint8_t contentType)
{
    // W3077 — chunk into ≤16384-byte TLS records (RFC 5246 §6.2.1 TLSPlaintext / RFC 8446 §5.2). A
    // single caller write >16 KiB would else be one oversized record (record_overflow alert 22) or,
    // >~64 KiB, truncate the 2-byte length field below → wire framing desync. Each chunk gets its own
    // seal + seq increment; return the TOTAL bytes consumed. len ≤ 16384 (incl. the AES-128-GCM common
    // path and the small client-Finished 0x16 record) is byte-identical to the prior single-record
    // write; the do/while preserves the len==0 case too.
    constexpr size_t kMaxTLSRecordPlaintext = 16384;
    size_t off = 0;
    do {
        size_t chunk = std::min(len - off, kMaxTLSRecordPlaintext);
        // W3071 — seal via the shared suite-generic helper (branches on m_negotiatedCipher): GCM prepends
        // the 8-byte explicit nonce; ChaCha20-Poly1305 (RFC 7905) does not. `payload` is the record body
        // AFTER the 5-byte header. On the AES-128-GCM path this reproduces the original wire bytes exactly.
        Vector<uint8_t> payload = t12SealRecord(m_negotiatedCipher, m_t12ClientKey, m_t12ClientFixedIV,
            m_t12ClientSeq, contentType, std::span<const uint8_t>(data + off, chunk));
        if (payload.isEmpty()) return -1;
        m_t12ClientSeq++;

        Vector<uint8_t> rec; rec.append(contentType); rec.append(0x03); rec.append(0x03);
        rec.append(static_cast<uint8_t>((payload.size() >> 8) & 0xFF));
        rec.append(static_cast<uint8_t>(payload.size() & 0xFF));
        rec.append(payload.span());
        if (!writeAll(m_fd, rec.span().data(), rec.size())) return -1;
        off += chunk;
    } while (off < len);
    return static_cast<int>(len);
}

Vector<uint8_t> DriftstackTLS13Client::readTLS12Record(int depth)
{
    uint8_t recType; uint16_t recVer; Vector<uint8_t> body;
    if (!driftstackReadTLSRecord(m_fd, recType, recVer, body)) return {};
    if (recType == 0x15) return {}; // alert (incl. close_notify)
    if (recType != 0x17) {
        // ChangeCipherSpec / handshake (e.g. post-handshake NewSessionTicket): skip, read next.
        // W2209: bound the post-handshake recursion — a hostile 1.2 server flooding CCS/0x16 records would
        // otherwise recurse unbounded → stack exhaustion. 32 is far above any legit CCS+NewSessionTicket flight.
        if (recType == 0x14 || recType == 0x16) {
            if (depth >= 32) { WTFLogAlways("[Driftstack-EG-WK-PathB-v2/W2209] TLS1.2 post-handshake skip flood (depth=%d) — rejecting (recursion DoS defense)", depth); return { }; }
            return readTLS12Record(depth + 1);
        }
        return {};
    }
    // W3071 — open application-data (content type 0x17) via the shared suite-generic helper: GCM takes
    // the explicit nonce from the wire; ChaCha20-Poly1305 (RFC 7905) derives it from the seq. On the
    // AES-128-GCM path a normal non-empty record is byte-for-byte the original logic (returned below).
    std::optional<Vector<uint8_t>> pt = t12OpenRecord(m_negotiatedCipher, m_t12ServerKey, m_t12ServerFixedIV,
        m_t12ServerSeq, /*contentType*/ 0x17, body);
    m_t12ServerSeq++;
    // W3075 — nullopt = AEAD auth failure (bad_record_mac) / malformed. This is NOT an orderly
    // close: mark the read stream fatally failed so read() returns -1 (error), not 0 (EOF). The
    // old code returned an empty Vector here, which read() mapped to a clean EOF → a tampered
    // record silently TRUNCATED the response as if the peer had closed.
    if (!pt) {
        m_t12ReadFatal = true;
        m_errorMessage = "TLS1.2: application_data AEAD authentication failed (bad_record_mac)"_s;
        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/W3075] TLS1.2 app-data record failed AEAD auth (seq=%llu) — surfacing as read error, not EOF", (unsigned long long)(m_t12ServerSeq - 1));
        return { };
    }
    // W3075 — a VALID 0-length application_data record (RFC 5246 §6.2.1 traffic-analysis
    // countermeasure). Returning the empty vector would look like EOF to read() and truncate the
    // stream prematurely; instead read the NEXT record, bounded by the same depth guard as the
    // CCS/0x16 skip path above (mirrors the TLS 1.3 zero-length handling in readApplicationRecord).
    if (pt->isEmpty()) {
        if (depth >= 32) { WTFLogAlways("[Driftstack-EG-WK-PathB-v2/W3075] TLS1.2 empty app-data record flood (depth=%d) — rejecting (recursion DoS defense)", depth); m_t12ReadFatal = true; m_errorMessage = "TLS1.2: too many empty app-data records"_s; return { }; }
        return readTLS12Record(depth + 1);
    }
    return std::move(*pt);
}

// === W2202 cert-validation Landing 3: CertificateVerify (0x0f) signature verification ===
// Defined HERE (not a standalone TU) so the h2 (this file) AND h3 (DriftstackHttp3.mm) 0x0f arms share ONE
// implementation via intra-framework linkage, avoiding a pbxproj-wired TU. The whole file is already inside the
// WTF_ALLOW_UNSAFE_BUFFER_USAGE region (top), so the raw-buffer ops below are permitted. RFC 8446 §4.4.3.

// TLS SignatureScheme (RFC 8446 §4.2.3) → SecKeyAlgorithm. nullptr = unsupported/forbidden (caller fails closed).
// TLS 1.3 CertificateVerify FORBIDS rsa_pkcs1_* (0x0401/0501/0601) — not mapped. ed25519 (0x0807) has NO EdDSA
// SecKeyAlgorithm constant in the macOS SDK → rejected (fail-closed). ...Message... variants (NOT ...Digest...)
// so SecKeyVerifySignature digests the full signed content itself.
static SecKeyAlgorithm driftstackSecKeyAlgorithmForScheme(uint16_t scheme)
{
    switch (scheme) {
    case 0x0804: return kSecKeyAlgorithmRSASignatureMessagePSSSHA256;     // rsa_pss_rsae_sha256
    case 0x0805: return kSecKeyAlgorithmRSASignatureMessagePSSSHA384;     // rsa_pss_rsae_sha384
    case 0x0806: return kSecKeyAlgorithmRSASignatureMessagePSSSHA512;     // rsa_pss_rsae_sha512
    case 0x0809: return kSecKeyAlgorithmRSASignatureMessagePSSSHA256;     // rsa_pss_pss_sha256 (key-keyed; same alg)
    case 0x080a: return kSecKeyAlgorithmRSASignatureMessagePSSSHA384;     // rsa_pss_pss_sha384
    case 0x080b: return kSecKeyAlgorithmRSASignatureMessagePSSSHA512;     // rsa_pss_pss_sha512
    case 0x0403: return kSecKeyAlgorithmECDSASignatureMessageX962SHA256;  // ecdsa_secp256r1_sha256 (DER r,s)
    case 0x0503: return kSecKeyAlgorithmECDSASignatureMessageX962SHA384;  // ecdsa_secp384r1_sha384
    case 0x0603: return kSecKeyAlgorithmECDSASignatureMessageX962SHA512;  // ecdsa_secp521r1_sha512
    default:     return nullptr;
    }
}

bool driftstackVerifyCertificateVerify(SecCertificateRef leaf, std::span<const uint8_t> sig, uint16_t sigScheme,
    const Vector<uint8_t>& transcriptHashThroughCert, bool isServerContext, String& outError)
{
    if (!leaf) { outError = "no leaf certificate"_s; return false; }
    if (sig.empty()) { outError = "empty CertificateVerify signature"_s; return false; }
    if (transcriptHashThroughCert.isEmpty()) { outError = "empty transcript hash"_s; return false; }

    SecKeyAlgorithm alg = driftstackSecKeyAlgorithmForScheme(sigScheme);
    if (!alg) {
        outError = "unsupported/forbidden CertificateVerify sigScheme"_s;
        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/W2202] CertificateVerify sigScheme 0x%04x unsupported/forbidden — rejecting (fail-closed)", sigScheme);
        return false;
    }

    RetainPtr<SecKeyRef> pubKey = adoptCF(SecCertificateCopyKey(leaf));
    if (!pubKey) { outError = "could not extract leaf public key"_s; return false; }

    // RFC 8446 §4.4.3 signed content: 64×0x20 || context-string || 0x00 || Transcript-Hash(CH..Certificate).
    // The SERVER context string is exactly "TLS 1.3, server CertificateVerify" (33 bytes, NO trailing NUL).
    const char* ctx = isServerContext ? "TLS 1.3, server CertificateVerify" : "TLS 1.3, client CertificateVerify";
    constexpr size_t kCtxLen = 33;
    Vector<uint8_t> signedContent;
    signedContent.reserveInitialCapacity(64 + kCtxLen + 1 + transcriptHashThroughCert.size());
    for (size_t i = 0; i < 64; ++i)
        signedContent.append(static_cast<uint8_t>(0x20));
    for (size_t i = 0; i < kCtxLen; ++i)
        signedContent.append(static_cast<uint8_t>(ctx[i]));  // exactly 33 bytes, NOT the implicit NUL at [33]
    signedContent.append(static_cast<uint8_t>(0x00));
    signedContent.append(transcriptHashThroughCert.span());

    RetainPtr<CFDataRef> contentData = adoptCF(CFDataCreate(nullptr, signedContent.span().data(), signedContent.size()));
    RetainPtr<CFDataRef> sigData = adoptCF(CFDataCreate(nullptr, sig.data(), sig.size()));
    if (!contentData || !sigData) { outError = "CFDataCreate failed"_s; return false; }

    CFErrorRef cfErr = nullptr;
    bool ok = SecKeyVerifySignature(pubKey.get(), alg, contentData.get(), sigData.get(), &cfErr);
    if (cfErr)
        CFRelease(cfErr);
    if (!ok) {
        outError = "CertificateVerify signature verification FAILED"_s;
        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/W2202] CertificateVerify signature INVALID (scheme 0x%04x) — rejecting (MITM defense)", sigScheme);
        return false;
    }
    return true;
}

} // namespace WebKit

WTF_ALLOW_UNSAFE_BUFFER_USAGE_END

#endif // PLATFORM(DRIFTSTACK)
