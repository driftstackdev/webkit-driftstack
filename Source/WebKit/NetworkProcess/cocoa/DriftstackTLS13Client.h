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
#include <wtf/MonotonicTime.h>   // BUG-42 Fix #4: total handshake wall-clock deadline
#include <wtf/Vector.h>
#include <wtf/text/WTFString.h>
#include <Security/Security.h>   // W2202 L3: SecCertificateRef for the retained leaf cert
#include <wtf/RetainPtr.h>

namespace WebKit {

struct SHA384Ctx;  // forward (from DriftstackCrypto)
struct TLS13ServerHello;  // forward (from DriftstackTLS13) — used by the TLS 1.2 path

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

    // W2341 (task #58): wait up to timeoutMs for read() to have data without consuming
    // any bytes (buffered plaintext OR poll(POLLIN) on the fd — record framing can't
    // tear). Returns 1 = read() won't block on the record header, 0 = timeout (caller
    // re-checks its cancel flag and loops), -1 = poll error. Lets a blocking read loop
    // observe cancellation on ITS OWN thread in timeout slices — no cross-thread fd
    // access (the W2323 TOCTOU), no change to read()'s blocking semantics.
    int pollReadable(int timeoutMs);

    // Get negotiated ALPN protocol (e.g. "h2", "http/1.1").
    const String& selectedALPN() const { return m_selectedALPN; }

    // Cleanly shut down the connection.
    void shutdown();

    const String& errorMessage() const { return m_errorMessage; }

    // egress HRR (2026-07-02): true when the failure is a deterministic post-HRR TLS alert (a CH2
    // rejected identically on every fresh exit) — the loader then fails fast instead of 8x identical
    // retries (mirrors the W2868 destUnreachable fast-fail). CH1-phase alerts stay retryable.
    bool permanentFailure() const { return m_permanentFailure; }

private:
    int m_fd { -1 };
    bool m_appReadBlockingRestored { false };  // Wave .352 — reset handshake recv-timeout once on first app read

    // BUG-42 Fix #4 (egress-reliability, gated) — TOTAL handshake wall-clock deadline.
    // The per-record SO_RCVTIMEO (6s, connect():116) RESETS on every record that has
    // data, so a slow/dribbling origin can pin the loaderQueue worker thread FAR past
    // one timeout (record-after-record, each just under 6s) — defeating Fix #2's whole
    // point of freeing the worker fast. Stamp `now + budget` once at the top of
    // connect(); the per-record read loops bail when it's exceeded, turning a slow
    // origin into a clean fast failure (→ a fresh-exit retry / page settle) instead of
    // an indefinitely-held worker. Null (default-constructed) when the gate is off →
    // every deadline check is a no-op → byte-identical to the prior code.
    MonotonicTime m_handshakeDeadline;
    bool handshakeDeadlineExceeded() const { return m_handshakeDeadline && MonotonicTime::now() >= m_handshakeDeadline; }
    String m_sniHostname;
    String m_selectedALPN;
    String m_errorMessage;

    // Wave 29-499.186 — cipher-aware transcript: accumulate ALL handshake
    // bytes; compute hash on demand using the negotiated cipher's digest.
    uint16_t m_negotiatedCipher { 0 };
    Vector<uint8_t> m_transcriptBytes;
    RetainPtr<SecCertificateRef> m_leafCert;        // W2202 L3: validated leaf cert (set in the 0x0b arm) — for CertificateVerify key-possession
    Vector<uint8_t> m_transcriptHashThroughCert;    // W2202 L3: Transcript-Hash(CH..Certificate), captured in 0x0b, verified in 0x0f
    bool m_gotCertVerify { false };                 // W2202 L3: set true ONLY after a CertificateVerify SUCCESSFULLY verifies — the Finished arm REQUIRES this (a MITM that omits 0x0f must be rejected, not silently accepted)
    bool m_hrrSeen { false };                       // W2208: true once a HelloRetryRequest was processed — a SECOND HRR is rejected (RFC 8446 §4.1.4) to bound receiveServerHello()'s recursion (hostile-peer stack-exhaustion DoS defense)
    bool m_permanentFailure { false };              // egress HRR (2026-07-02): set on a post-HRR (CH2) TLS alert; a deterministic reject → loader fails fast, no 8x retry. See permanentFailure().

    // Key schedule
    TLS13KeySchedule m_keySchedule;

    // Handshake traffic keys
    TLS13TrafficKey m_clientHsKey;
    TLS13TrafficKey m_serverHsKey;

    // Application traffic keys
    TLS13TrafficKey m_clientAppKey;
    TLS13TrafficKey m_serverAppKey;
    // egress audit wxzzaphvp (#8): the CURRENT server application_traffic_secret, advanced on each
    // server KeyUpdate (RFC 8446 §7.2 "traffic upd"). Empty until the first KeyUpdate, then tracks
    // secret_N so successive KeyUpdates chain correctly. Read/updated only in readApplicationRecord.
    Vector<uint8_t> m_serverAppSecretCurrent;

    // Saved ephemeral X25519 private keys (for ECDH after ServerHello).
    // DRIFTSTACK_TLS_KEYSHARE_DISTINCT (default-ON): the iPhone-correct wire emits TWO
    // INDEPENDENT X25519 ephemeral keypairs — keypair A's pubkey in the X25519MLKEM768
    // hybrid (0x11EC) key_share tail, keypair B's pubkey in the standalone X25519 (0x001D)
    // key_share entry (verified 7/7 real-device captures: the standalone X25519 component
    // != the hybrid's X25519 slot, every connection). The fork previously reused ONE
    // keypair for both slots → the two wire X25519 components were byte-identical = a
    // deterministic structural correlation a TLS-introspecting DPI/server computes by
    // parsing the two key_share entries (invisible to JA3/JA4/peetprint). A TLS 1.3 server
    // selects exactly ONE group, so derivation MUST pick the matching private per the
    // server's selected group: 0x11EC → private A (the hybrid X25519 tail), 0x001D →
    // private B (the standalone entry). When the gate is OFF, B == A (the old behavior:
    // both slots carry the same pubkey, A derives both).
    Vector<uint8_t> m_ourX25519PrivateA;
    Vector<uint8_t> m_ourX25519PrivateB;
    // True ONLY when the standalone X25519 (0x001D) key_share entry on the wire carried
    // keypair B's pubkey — i.e. the 26.x HYBRID builder ran (MLKEM available, non-18.x
    // archetype) AND DRIFTSTACK_TLS_KEYSHARE_DISTINCT is ON. Set at CH-build time so
    // derivation is unambiguous: if a server selects 0x001D, use private B iff this is
    // true, else private A. (The X25519-only FALLBACK builder + 18.x archetype emit a
    // SINGLE 0x001D entry carrying keypair A, so this stays false and derivation correctly
    // uses A there — re-deriving the gate condition in receiveServerHello would WRONGLY
    // pick B for those single-entry-A cases → handshake failure.)
    bool m_standaloneX25519IsB { false };

    // Saved ECDH shared secret (until handshake secret derived)
    Vector<uint8_t> m_ecdhShared;

    // Wave 29-499.215 — P-256 keypair for HRR retry path
    P256Keypair m_p256Keypair;

    // Wave 29-499.219 — MLKEM768 keypair for hybrid X25519MLKEM768
    MLKEM768Keypair m_mlkemKeypair;
    Vector<uint8_t> m_ourX25519PublicA;  // 32 bytes — keypair A pub (hybrid X25519MLKEM768 tail)
    Vector<uint8_t> m_ourX25519PublicB;  // 32 bytes — keypair B pub (standalone X25519 0x001D)

    // Wave 29-499.195 — read buffer for leftover decrypted bytes between
    // read() calls. TLS record may contain >1 HTTP/2 frames; must not
    // discard bytes that don't fit in caller's maxLen.
    Vector<uint8_t> m_readBuffer;

    // Wave 29-499.340 — TLS 1.2 fallback path. Twilio's TURN turns: :443 endpoint
    // negotiates TLS 1.2 (cipher 0xc02f ECDHE_RSA_AES128GCM, no key_share), so a
    // real iPhone completes a 1.2 handshake there. The iPhone-byte-exact ClientHello
    // already offers TLS 1.2 cipher suites + supported_versions[1.3,1.2]; when the
    // server picks 1.2 we run the full 1.2 ECDHE handshake here (RFC 5246 + RFC 5288
    // AEAD). Kept entirely separate from the 1.3 state machine above.
    bool m_isTLS12 { false };
    bool m_t12EMS { false };                   // extended_master_secret negotiated (RFC 7627)
    Vector<uint8_t> m_clientRandom;            // 32 bytes, saved from ClientHello
    Vector<uint8_t> m_serverRandom;            // 32 bytes, from ServerHello
    Vector<uint8_t> m_t12MasterSecret;         // 48 bytes
    // W3071: sizes now follow the negotiated suite — enc key 16 (AES-128-GCM) / 32 (AES-256-GCM,
    // ChaCha20); fixed IV 4 (GCM implicit-nonce prefix) / 12 (ChaCha20, RFC 7905). See t12CipherEncKeyLen
    // / t12CipherFixedIvLen and the key_block split in doTLS12Handshake.
    Vector<uint8_t> m_t12ClientKey;            // 16 (AES-128) or 32 (AES-256 / ChaCha20)   W3071
    Vector<uint8_t> m_t12ServerKey;            // 16 or 32                                    W3071
    Vector<uint8_t> m_t12ClientFixedIV;        // 4 (GCM implicit prefix) or 12 (ChaCha20)    W3071
    Vector<uint8_t> m_t12ServerFixedIV;        // 4 or 12                                     W3071
    uint64_t m_t12ClientSeq { 0 };
    uint64_t m_t12ServerSeq { 0 };
    Vector<uint8_t> m_t12ReadBuffer;           // leftover decrypted app bytes

    // Internal helpers
    bool sendClientHello();
    bool receiveServerHello();
    bool readEncryptedHandshakeMessages();
    // W2730: validate a TLS 1.3 Certificate message BODY (1B ctx_len + ctx + 3B list_len + cert_list) —
    // parse chain, store m_leafCert, SecTrust-evaluate vs m_sniHostname, capture m_transcriptHashThroughCert.
    // Shared by the plain Certificate (0x0b) arm AND the RFC 8879 CompressedCertificate (0x19) arm (which
    // calls it on the decompressed body). Returns false (with m_errorMessage set) on any parse/trust failure.
    bool validateCertificateBody(std::span<const uint8_t> body);
    bool sendClientFinished();
    int writeApplicationRecord(const uint8_t* data, size_t len);
    Vector<uint8_t> readApplicationRecord(int depth = 0);   // W2209: depth bounds the post-handshake (inner-0x16) recursion

    // Wave 29-499.340 — TLS 1.2 handshake + record layer.
    bool doTLS12Handshake(const TLS13ServerHello& sh);
    int writeTLS12Record(const uint8_t* data, size_t len, uint8_t contentType = 0x17);
    Vector<uint8_t> readTLS12Record(int depth = 0);   // W2209: depth bounds the post-handshake (CCS/0x16) recursion
};

} // namespace WebKit

#endif // PLATFORM(DRIFTSTACK)
