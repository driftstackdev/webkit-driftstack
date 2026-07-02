/*
 * DriftstackCustomTLS.mm — Wave 29-499.171 (Phase 1.5e ClientHello)
 *
 * Byte-exact, PER-ARCHETYPE iPhone Safari TLS ClientHello emission.
 *
 * iPhone reference (captured via tls.peet.ws V-2026-05-21-W29-499.108):
 *   Safari 26.x: JA4 t13d2013h2_a09f3c656075_7f0f34a4126d
 *                JA3 ecdf4f49dd59effc439639da29186671
 *   Safari 18.x (P1, per-archetype): JA4 t13d2014h2_a09f3c656075_7f0f34a4126d
 *     (BS real-device VERIFIED 2026-06-26 on iOS 18.3/18.4/18.5/18.6 — iPhone
 *     13/16/16e/16Pro/16Plus; the earlier "_e42f34c56612" was an UNCAPTURED wrong
 *     prediction. The sig-alg list is IDENTICAL to 26.x so the JA4 3rd component is
 *     the same 7f0f34a4126d; the 18.x JA4 differs from 26.x ONLY in the ext-count
 *     digit, 2014 vs 2013, from the added padding ext. NOTE: iOS <=18.2 — e.g.
 *     18.0.1 — additionally carries ecdsa_sha1 (0x0203) in sig_algs → JA4
 *     _874d27d7ca63; Apple dropped 0203 by 18.3. Launch Family-A is 18.6 = 7f0f...)
 *     deltas vs 26.x: drop X25519MLKEM768 from supported_groups+key_share;
 *     TLS1.3 cipher trio order 4865-4866-4867; padding ext (0x15) PRESENT.
 *   MLKEM landing = the iOS-MAJOR boundary (OS Network.framework TLS stack, not
 *     WebKit): every iOS-26.x device (Safari 26.2-26.5 BS-VERIFIED) emits 0x11EC;
 *     no iOS-18.x device does. BS pool cannot yield Safari 26.0/26.1 (min is 26.2),
 *     but Apple docs gate PQ TLS on "iOS 26 or later" → 26.0 emits MLKEM. zstd in
 *     Accept-Encoding lands at Safari/iOS 26.3 (WebKit blog + BS-confirmed 26.3).
 *     Selected by driftstackArchetypeIsPreSafari26() (DRIFTSTACK_ARCHETYPE).
 *
 * GREASE values vary per-connection; non-GREASE structure is constant.
 */

#import "config.h"
#import "DriftstackCustomTLS.h"

#if PLATFORM(DRIFTSTACK)

#import <stdlib.h>
#import <Security/SecRandom.h>
#import <wtf/Assertions.h>

WTF_ALLOW_UNSAFE_BUFFER_USAGE_BEGIN

namespace WebKit {

namespace {

// TLS message constants
constexpr uint8_t kTLSRecordTypeHandshake = 0x16;
constexpr uint8_t kTLSHandshakeTypeClientHello = 0x01;
constexpr uint16_t kTLSVersionTLS12 = 0x0303;  // ClientHello legacy_version field

// iPhone Safari 26.0 cipher list (20 ciphers in exact order)
// JA3 includes these in cipher_suites field.
constexpr uint16_t kIPhoneCiphers[] = {
    // GREASE placeholder — replaced per-connection at offset 0
    0x0A0A,  // (will be substituted with random GREASE value)
    // Real ciphers (per iPhone Safari 26.0 capture)
    0x1302,  // TLS_AES_256_GCM_SHA384
    0x1303,  // TLS_CHACHA20_POLY1305_SHA256
    0x1301,  // TLS_AES_128_GCM_SHA256 (TLS1.3 trio: 26.x order = 1302-1303-1301)
    0xC02C,  // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    0xC02B,  // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    0xCCA9,  // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
    0xC030,  // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    0xC02F,  // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    0xCCA8,  // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
    0xC00A,  // TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
    0xC009,  // TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
    0xC014,  // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
    0xC013,  // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
    0x009D,  // TLS_RSA_WITH_AES_256_GCM_SHA384
    0x009C,  // TLS_RSA_WITH_AES_128_GCM_SHA256
    0x0035,  // TLS_RSA_WITH_AES_256_CBC_SHA
    0x002F,  // TLS_RSA_WITH_AES_128_CBC_SHA
    0xC008,  // TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA
    0xC012,  // TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
    0x000A,  // TLS_RSA_WITH_3DES_EDE_CBC_SHA
};
constexpr size_t kIPhoneCipherCount = sizeof(kIPhoneCiphers) / sizeof(kIPhoneCiphers[0]);

// GREASE values per RFC 8701. iPhone draws an INDEPENDENT GREASE value per slot —
// cipher, leading-extension, trailing-extension, and version GREASE are ALL distinct
// in 12/12 real-device captures (the group GREASE == key_share GREASE is the only
// intentional pairing, per RFC 8446 §4.2.8). The earlier "1 GREASE byte for all" note
// was a false premise that produced a 100%-correlated cipher==ext0 raw-bytes tell.
// Valid GREASE values: 0x0a0a, 0x1a1a, 0x2a2a, ... 0xfafa.
constexpr uint16_t kGreaseValues[] = {
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A,
    0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A, 0xAAAA, 0xBABA,
    0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
};

uint16_t pickGreaseValue()
{
    uint8_t b;
    (void)SecRandomCopyBytes(kSecRandomDefault, 1, &b);
    return kGreaseValues[b & 0x0F];
}

// P1 — per-archetype ClientHello: pre-Safari-26 archetypes (iOS 17/18/19) emit the
// iOS-18.x ClientHello; Safari >=26 emits the 26.x ClientHello. The version source is
// the DRIFTSTACK_ARCHETYPE env var, read with the SAME string-match template as the
// Accept-Encoding/zstd cutover (DriftstackNetworkLoader.mm:886-896) so both gates read
// the same archetype Safari version. Three wire deltas for <26 (vs 26.x):
//   1. supported_groups + key_share DROP X25519MLKEM768 (0x11EC) — classical groups only.
//   2. TLS1.3 cipher trio order = 4865-4866-4867 (26.x = 4866-4867-4865).
//   3. padding extension (0x0015) PRESENT (26.x omits it) → JA4 ext-count 14 vs 13.
// 18.x JA4 = t13d2014h2_a09f3c656075_7f0f34a4126d ; 26.x = t13d2013h2_a09f3c656075_7f0f34a4126d
// (BS real-device VERIFIED 2026-06-26 — the two bands differ ONLY in the 2014/2013 ext-count digit).
// (Definition moved OUT of the anonymous namespace — now WebKit-namespace external linkage so the
// TLS client can read it to pick the matching ECDH private for the two-keypair key_share.)
} // close anonymous namespace for the externally-linked archetype predicate

bool driftstackArchetypeIsPreSafari26()
{
    const char* arch = getenv("DRIFTSTACK_ARCHETYPE");
    if (arch && arch[0]) {
        String a = String::fromUTF8(arch);
        if (a.contains("safari17_"_s) || a.contains("safari18_"_s) || a.contains("safari19_"_s))
            return true;
    }
    return false;  // Safari >=26 (incl the 26.4 launch) + default → 26.x ClientHello
}

namespace { // reopen anonymous namespace for the remaining file-local builder helpers

// Append big-endian u16
void appendU16(Vector<uint8_t>& out, uint16_t v)
{
    out.append(static_cast<uint8_t>(v >> 8));
    out.append(static_cast<uint8_t>(v & 0xFF));
}

// Append a vector with a length prefix (u16 length).
void appendVecU16Len(Vector<uint8_t>& out, const Vector<uint8_t>& vec)
{
    appendU16(out, static_cast<uint16_t>(vec.size()));
    out.append(vec.span());
}

// Append a length-prefixed (u8) opaque blob.
void appendU8LenBlob(Vector<uint8_t>& out, const uint8_t* data, size_t len)
{
    out.append(static_cast<uint8_t>(len));
    out.append(std::span<const uint8_t>(data, len));
}

// Build a TLS extension: type (u16) + length (u16) + body.
Vector<uint8_t> makeExtension(uint16_t type, const Vector<uint8_t>& body)
{
    Vector<uint8_t> ext;
    appendU16(ext, type);
    appendVecU16Len(ext, body);
    return ext;
}

// P1 — padding (21 / 0x0015) — RFC 7685. iOS 18.x always sends a padding extension; the JA4
// counts its PRESENCE only (the pad-byte length is JA4-irrelevant and server-irrelevant), so
// an empty body is sufficient to flip the JA4 ext-count to the 2014 form. Safari 26.x does NOT
// send 0x15 (count stays 2013). Only emitted for pre-Safari-26 archetypes.
Vector<uint8_t> makeExtPadding()
{
    return makeExtension(0x0015, Vector<uint8_t>());
}

// server_name (0)
Vector<uint8_t> makeExtServerName(const String& sni)
{
    auto utf8 = sni.utf8();
    Vector<uint8_t> body;
    Vector<uint8_t> entry;
    entry.append(0x00);  // name_type = host_name
    appendU16(entry, static_cast<uint16_t>(utf8.length()));
    entry.append(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(utf8.data()), utf8.length()));
    appendVecU16Len(body, entry);
    return makeExtension(0, body);
}

// extended_master_secret (23) — empty body
Vector<uint8_t> makeExtExtendedMasterSecret()
{
    return makeExtension(23, Vector<uint8_t>());
}

// renegotiation_info (65281) — 0x00 (empty renegotiated_connection)
Vector<uint8_t> makeExtRenegotiationInfo()
{
    Vector<uint8_t> body;
    body.append(0x00);
    return makeExtension(65281, body);
}

// supported_groups (10) — iPhone: GREASE + X25519MLKEM768 + X25519 + P-256/384/521
// Wave 29-499.328 — the GREASE group MUST be the SAME value used in key_share's GREASE
// entry (RFC 8446 §4.2.8: every key_share group must appear in supported_groups; RFC 8701
// §3.1: the GREASE value must match across both). Caller passes one greaseGroup so they
// agree; previously each extension picked its own random GREASE → mismatch → strict edges
// (e.g. browserleaks's Cloudflare) abort the handshake with illegal_parameter.
// P1 — preSafari26: iOS 18.x DROPS X25519MLKEM768 (post-quantum hybrid landed in Safari 26);
// the 18.x supported_groups is classical-only (GREASE + X25519 + P-256/384/521). 26.x keeps
// 0x11EC first. The GREASE group still leads and must match key_share's GREASE.
// FIX 4 — forceClassicalGroups: keep supported_groups LOCK-STEP with key_share even on a
// 26.x archetype when the runtime KEY_SHARE cannot carry X25519MLKEM768 (e.g. MLKEM-768
// keygen FAILED → the X25519-only fallback builder runs with preSafari26=false). RFC 8446
// §4.2.8: every key_share group MUST appear in supported_groups, but advertising 0x11EC in
// supported_groups while the key_share OMITS it produces an internally-incoherent CH that NO
// real iPhone emits (6/6 BS-verified: 26.x carries 0x11EC in groups AND key_share in
// lock-step). Strict edges (Cloudflare/Akamai — used by heavy sites like westernunion.com)
// reject the mismatch with illegal_parameter → heavy-site load failure. The X25519-only
// fallback builder passes forceClassicalGroups=true so its classical groups match its
// classical key_share. The NORMAL 26.x hybrid path (key_share HAS 0x11EC) leaves this false
// → groups AND key_share both carry 0x11EC, byte-identical to before.
Vector<uint8_t> makeExtSupportedGroups(uint16_t greaseGroup, bool preSafari26 = false, bool forceClassicalGroups = false)
{
    Vector<uint8_t> list;
    appendU16(list, greaseGroup);  // GREASE (must match key_share)
    if (!preSafari26 && !forceClassicalGroups)
        appendU16(list, 0x11EC);  // X25519MLKEM768 (Safari >=26 only)
    appendU16(list, 0x001D);  // X25519
    appendU16(list, 0x0017);  // P-256 (secp256r1)
    appendU16(list, 0x0018);  // P-384 (secp384r1)
    appendU16(list, 0x0019);  // P-521 (secp521r1)
    Vector<uint8_t> body;
    appendVecU16Len(body, list);
    return makeExtension(10, body);
}

// ec_point_formats (11) — iPhone: uncompressed only
Vector<uint8_t> makeExtEcPointFormats()
{
    Vector<uint8_t> body;
    uint8_t fmts[] = {0x00};  // uncompressed
    appendU8LenBlob(body, fmts, sizeof(fmts));
    return makeExtension(11, body);
}

// ALPN (16) — iPhone: h2, http/1.1
Vector<uint8_t> makeExtALPN()
{
    Vector<uint8_t> list;
    list.append(0x02); list.append('h'); list.append('2');
    list.append(0x08); list.append('h'); list.append('t'); list.append('t'); list.append('p');
    list.append('/'); list.append('1'); list.append('.'); list.append('1');
    Vector<uint8_t> body;
    appendVecU16Len(body, list);
    return makeExtension(16, body);
}

// Wave 29-499.348 — ALPN (16) for QUIC: iPhone HTTP/3 advertises ONLY "h3".
Vector<uint8_t> makeExtALPNQuic()
{
    Vector<uint8_t> list;
    list.append(0x02); list.append('h'); list.append('3');
    Vector<uint8_t> body;
    appendVecU16Len(body, list);
    return makeExtension(16, body);
}

// Wave 29-499.348 — quic_transport_parameters (0x0039). Body = the already-encoded
// iPhone transport-parameters TLV blob (built by buildIphoneQuicTransportParams).
Vector<uint8_t> makeExtQuicTransportParams(const Vector<uint8_t>& tpBlob)
{
    Vector<uint8_t> body;
    body.append(tpBlob.span());
    return makeExtension(0x0039, body);
}

// status_request (5) — OCSP, iPhone always sends with cert_status_type=ocsp,
// responder_id_list empty, request_extensions empty
Vector<uint8_t> makeExtStatusRequest()
{
    Vector<uint8_t> body;
    body.append(0x01);  // status_type = ocsp
    appendU16(body, 0x0000);  // responder_id_list length = 0
    appendU16(body, 0x0000);  // request_extensions length = 0
    return makeExtension(5, body);
}

// Wave 29-499.196 — iPhone Safari 26 signature_algorithms (10 algs)
// Verified via tls.peet.ws default-mode capture (which is iPhone-bit-identical):
// includes ecdsa_sha1 (0x0203) at position 5 — Apple legacy compat
Vector<uint8_t> makeExtSignatureAlgorithms()
{
    Vector<uint8_t> list;
    // Wave 29-499.197 — iPhone sends 10 sigalgs incl 0x080b (rsa_pss_pss_sha384)
    // tls.peet.ws labels 0x080b as "rsa_pss_rsae_sha384" (same as 0x0805) due to
    // its mapping table → shows duplicate in human-readable list.
    appendU16(list, 0x0403);  // ecdsa_secp256r1_sha256
    appendU16(list, 0x0804);  // rsa_pss_rsae_sha256
    appendU16(list, 0x0401);  // rsa_pkcs1_sha256
    appendU16(list, 0x0503);  // ecdsa_secp384r1_sha384
    appendU16(list, 0x0805);  // rsa_pss_rsae_sha384
    appendU16(list, 0x0805);  // rsa_pss_rsae_sha384 (iPhone DUPLICATE — Apple TLS stack)
    appendU16(list, 0x0501);  // rsa_pkcs1_sha384
    appendU16(list, 0x0806);  // rsa_pss_rsae_sha512
    appendU16(list, 0x0601);  // rsa_pkcs1_sha512
    appendU16(list, 0x0201);  // rsa_pkcs1_sha1 (legacy)
    Vector<uint8_t> body;
    appendVecU16Len(body, list);
    return makeExtension(13, body);
}

// signed_certificate_timestamp (18) — empty body
Vector<uint8_t> makeExtSCT()
{
    return makeExtension(18, Vector<uint8_t>());
}

// Wave 29-499.216 — key_share with P-256 only (HRR retry CH2 per RFC 8446)
// egress bing P-521 HRR (2026-07-02): HRR CH2 key_share for the server-requested EC group. Generalizes
// the P-256-only version to P-384 (0x0018, 97-byte pubkey) + P-521 (0x0019, 133-byte) so the fork can
// answer any HRR a real iPhone would (it offers P-256/384/521 in supported_groups). No GREASE in the HRR
// CH2 key_share (RFC 8446 §4.1.4 — most clients strip it). The group + pubkey length are the ONLY bytes
// that differ from the P-256 case; the rest of CH2 stays iPhone-byte-exact via the shared builder.
Vector<uint8_t> makeExtKeyShareECGroup(uint16_t group, const Vector<uint8_t>& ecPubKey)
{
    Vector<uint8_t> list;
    appendU16(list, group);
    appendU16(list, static_cast<uint16_t>(ecPubKey.size()));
    list.append(ecPubKey.span());
    Vector<uint8_t> body;
    appendVecU16Len(body, list);
    return makeExtension(51, body);
}


// key_share (51) — iPhone offers GREASE+empty + X25519MLKEM768+pubkey + X25519+pubkey
// For .171 scaffold: include GREASE+empty + X25519+pubkey only (skip MLKEM since
// LibreSSL doesn't have it; iPhone's key_share includes MLKEM which adds bytes).
// For perfect match: need MLKEM-768 pubkey generation (768 bytes); deferred.
// Wave 29-499.219 — X25519MLKEM768 hybrid keyshare entry
// Format per IETF TLS WG draft-ietf-tls-hybrid-design:
//   group: 0x11EC (X25519MLKEM768)
//   key_exchange (1216 bytes): MLKEM768_pubkey (1184) || X25519_pubkey (32)
//   ORDER: MLKEM first, X25519 second (per draft + iPhone Safari)
//
// DRIFTSTACK_TLS_KEYSHARE_DISTINCT (default-ON): the hybrid X25519 tail carries keypair
// A's pubkey (x25519PubKeyA); the standalone X25519 (0x001D) entry carries keypair B's
// pubkey (x25519PubKeyB) — two INDEPENDENT ephemeral keypairs, so the two wire X25519
// components DIFFER, matching real iPhone (7/7 captures). When x25519PubKeyB is empty
// (the QUIC builder, or the gate-off path) the standalone entry reuses x25519PubKeyA —
// byte-identical to the prior single-keypair behavior.
Vector<uint8_t> makeExtKeyShareHybrid(const Vector<uint8_t>& mlkemPubKey, const Vector<uint8_t>& x25519PubKeyA, uint16_t greaseGroup, const Vector<uint8_t>& x25519PubKeyB = Vector<uint8_t>())
{
    // Standalone (0x001D) pubkey: keypair B when provided + gate ON, else reuse A.
    const Vector<uint8_t>& standalonePub =
        (driftstackTlsKeyShareDistinctEnabled() && x25519PubKeyB.size() == 32) ? x25519PubKeyB : x25519PubKeyA;

    Vector<uint8_t> list;
    // GREASE entry (1-byte placeholder for keyshare list slot 0).
    // Wave 29-499.328 — greaseGroup MUST equal the supported_groups GREASE value, else
    // the key_share offers a group not in supported_groups → illegal_parameter on strict
    // servers. Caller threads the same value into makeExtSupportedGroups.
    appendU16(list, greaseGroup);
    appendU16(list, 0x0001);
    list.append(0x00);

    // X25519MLKEM768 (0x11EC): 1216-byte combined keyshare — X25519 tail = keypair A.
    appendU16(list, 0x11EC);
    appendU16(list, 0x04C0);  // 1216 bytes
    list.append(mlkemPubKey.span());   // 1184 bytes first
    list.append(x25519PubKeyA.span()); // 32 bytes second (keypair A)

    // X25519 (0x001D): 32-byte keyshare (iPhone offers both) — keypair B (independent).
    appendU16(list, 0x001D);
    appendU16(list, 0x0020);
    list.append(standalonePub.span());

    Vector<uint8_t> body;
    appendVecU16Len(body, list);
    return makeExtension(51, body);
}

Vector<uint8_t> makeExtKeyShare(const Vector<uint8_t>& x25519PubKey, uint16_t greaseGroup)
{
    Vector<uint8_t> list;

    // GREASE entry (empty key_exchange — iPhone uses this pattern).
    // Wave 29-499.328 — greaseGroup MUST match supported_groups' GREASE.
    appendU16(list, greaseGroup);
    appendU16(list, 0x0001);  // length = 1
    list.append(0x00);  // 1-byte placeholder

    // X25519MLKEM768 — placeholder (768+32 = ~1184 bytes pubkey)
    // For first iteration we skip MLKEM and only do X25519 — fingerprint
    // delta is ~1 byte in key_share entry count.
    // TODO: implement MLKEM-768 keypair gen for byte-exact match.

    // X25519
    appendU16(list, 0x001D);  // x25519 group
    appendU16(list, 0x0020);  // key_exchange length = 32
    list.append(x25519PubKey.span());

    Vector<uint8_t> body;
    appendVecU16Len(body, list);
    return makeExtension(51, body);
}

// psk_key_exchange_modes (45) — iPhone offers psk_dhe_ke = 1
Vector<uint8_t> makeExtPSKKeyExchangeModes()
{
    Vector<uint8_t> body;
    uint8_t modes[] = {0x01};  // psk_dhe_ke
    appendU8LenBlob(body, modes, sizeof(modes));
    return makeExtension(45, body);
}

// supported_versions (43) — iPhone: GREASE + TLS 1.3 + TLS 1.2 (Safari 26.x). The 18.x
// (pre-Safari-26) band ALSO offers TLS 1.1 + TLS 1.0 (GREASE + 4 versions, list_len 0x0a) —
// confirmed on all 18.x real-device captures (iPhone 13/16/16e/16Pro/16Plus): the version
// list = GREASE,772,771,770,769. (QUIC uses makeExtSupportedVersionsQuic = TLS 1.3 only.)
Vector<uint8_t> makeExtSupportedVersions(bool preSafari26 = false)
{
    Vector<uint8_t> list;
    if (preSafari26) {
        list.append(static_cast<uint8_t>(0x0a));  // versions list = 10 bytes (GREASE + TLS 1.3/1.2/1.1/1.0)
        uint16_t versions[] = { pickGreaseValue(), 0x0304, 0x0303, 0x0302, 0x0301 };
        for (int i = 0; i < 5; ++i)
            appendU16(list, versions[i]);
    } else {
        list.append(static_cast<uint8_t>(0x06));  // versions list = 6 bytes (GREASE + TLS 1.3/1.2)
        uint16_t versions[] = { pickGreaseValue(), 0x0304, 0x0303 };
        for (int i = 0; i < 3; ++i)
            appendU16(list, versions[i]);
    }
    return makeExtension(43, list);
}

// Wave .349 — QUIC supported_versions: GREASE + TLS 1.3 ONLY.
// RFC 9001 §8.2: a QUIC client MUST NOT offer TLS versions older than 1.3;
// offering 1.2 makes the server reject the CH (CRYPTO_ERROR alert).
Vector<uint8_t> makeExtSupportedVersionsQuic()
{
    Vector<uint8_t> list;
    list.append(static_cast<uint8_t>(0x04));  // versions list = 4 bytes (GREASE + 1.3)
    appendU16(list, pickGreaseValue());
    appendU16(list, 0x0304);  // TLS 1.3
    return makeExtension(43, list);
}

// compress_certificate (27) — RFC 8879. iPhone: [zlib=0x0001]
// Wave 29-499.199 — verified via default-mode peetprint capture: iPhone sends 1 (zlib), not 2 (brotli)
Vector<uint8_t> makeExtCompressCertificate()
{
    Vector<uint8_t> body;
    body.append(0x02);  // len = 2 (one algo entry)
    appendU16(body, 0x0001);  // zlib (iPhone)
    return makeExtension(27, body);
}

// GREASE empty extension
Vector<uint8_t> makeExtGREASE(uint16_t greaseValue)
{
    return makeExtension(greaseValue, Vector<uint8_t>());
}

} // anonymous namespace

Vector<uint8_t> driftstackBuildIPhoneClientHello(const String& sni,
    const Vector<uint8_t>& x25519PublicKey,
    Vector<uint8_t>& outClientRandom)
{
    // Generate client_random (32 bytes)
    outClientRandom.resize(32);
    (void)SecRandomCopyBytes(kSecRandomDefault, 32, outClientRandom.mutableSpan().data());

    // Generate session_id (32 bytes; iPhone uses TLS 1.3 32-byte session_id)
    Vector<uint8_t> sessionId(32);
    (void)SecRandomCopyBytes(kSecRandomDefault, 32, sessionId.mutableSpan().data());

    // Wave 29-499.187 — use caller-provided REAL X25519 public key
    Vector<uint8_t> x25519Pub = x25519PublicKey;

    // Pick the SAME GREASE value used throughout (iPhone uses one GREASE byte)
    uint16_t greasePrimary = pickGreaseValue();
    uint16_t greaseSecondary = pickGreaseValue();
    while (greaseSecondary == greasePrimary)
        greaseSecondary = pickGreaseValue();
    // Wave 29-499.328 — shared GREASE group for supported_groups + key_share (RFC 8446
    // §4.2.8 / RFC 8701); independent picks caused illegal_parameter on strict edges.
    uint16_t greaseGroup = pickGreaseValue();
    // iOS draws the cipher-suites GREASE INDEPENDENTLY of the leading-extension GREASE
    // (0/12 real-device captures have them equal; the fork previously reused greasePrimary
    // for both, a 100%-correlated raw-bytes tell). Use a separate greaseCipher, distinct
    // from the primary (leading-ext), secondary (trailing-ext) and group GREASE values.
    uint16_t greaseCipher = pickGreaseValue();
    while (greaseCipher == greasePrimary || greaseCipher == greaseSecondary || greaseCipher == greaseGroup)
        greaseCipher = pickGreaseValue();

    // P1 — X25519-only fallback CH; apply the 18.x deltas for pre-Safari-26 archetypes
    // (cipher trio reorder + supported_groups MLKEM drop + padding ext). This builder
    // already emits an X25519-only key_share, so no key_share branch is needed.
    const bool preSafari26 = driftstackArchetypeIsPreSafari26();

    // Build cipher_suites (40 bytes content + 2-byte length = 42 bytes)
    Vector<uint8_t> ciphers;
    appendU16(ciphers, greaseCipher);  // GREASE cipher
    if (preSafari26) {
        appendU16(ciphers, 0x1301);  // 18.x TLS1.3 trio order 4865-4866-4867
        appendU16(ciphers, 0x1302);
        appendU16(ciphers, 0x1303);
        for (size_t i = 4; i < kIPhoneCipherCount; ++i)
            appendU16(ciphers, kIPhoneCiphers[i]);
    } else {
        for (size_t i = 1; i < kIPhoneCipherCount; ++i)
            appendU16(ciphers, kIPhoneCiphers[i]);
    }

    // Build extensions block — iPhone order (per JA3/JA4 capture)
    Vector<uint8_t> extensions;
    extensions.append(makeExtGREASE(greasePrimary).span());        // GREASE-1
    extensions.append(makeExtServerName(sni).span());              // server_name (0)
    extensions.append(makeExtExtendedMasterSecret().span());       // extended_master_secret (23)
    extensions.append(makeExtRenegotiationInfo().span());          // renegotiation_info (65281)
    // FIX 4 — this builder's key_share (makeExtKeyShare below) is X25519-only and can NEVER
    // carry X25519MLKEM768 (0x11EC). It runs as the MLKEM-unavailable fallback for ALL bands,
    // including 26.x (preSafari26=false) when MLKEM-768 keygen fails at runtime. forceClassical-
    // Groups=true keeps supported_groups classical-only so it stays LOCK-STEP with the X25519-only
    // key_share (no orphaned 0x11EC → no illegal_parameter on strict edges).
    extensions.append(makeExtSupportedGroups(greaseGroup, preSafari26, /*forceClassicalGroups*/ true).span()); // supported_groups (10)
    extensions.append(makeExtEcPointFormats().span());             // ec_point_formats (11)
    extensions.append(makeExtALPN().span());                       // ALPN (16)
    extensions.append(makeExtStatusRequest().span());              // status_request (5)
    extensions.append(makeExtSignatureAlgorithms().span());        // signature_algorithms (13)
    extensions.append(makeExtSCT().span());                        // signed_certificate_timestamp (18)
    extensions.append(makeExtKeyShare(x25519Pub, greaseGroup).span()); // key_share (51)
    extensions.append(makeExtPSKKeyExchangeModes().span());        // psk_key_exchange_modes (45)
    extensions.append(makeExtSupportedVersions(preSafari26).span());          // supported_versions (43)
    extensions.append(makeExtCompressCertificate().span());        // compress_certificate (27)
    extensions.append(makeExtGREASE(greaseSecondary).span());      // GREASE-2
    if (preSafari26)
        extensions.append(makeExtPadding().span());                // padding (21) — 18.x only, LAST (iOS emits padding AFTER the trailing GREASE)

    // Build ClientHello body (handshake message)
    Vector<uint8_t> body;
    appendU16(body, kTLSVersionTLS12);  // legacy_version
    body.append(outClientRandom.span()); // client_random (32 bytes)
    appendU8LenBlob(body, sessionId.span().data(), sessionId.size());  // session_id
    appendVecU16Len(body, ciphers);     // cipher_suites
    body.append(0x01); body.append(0x00);  // compression_methods: 1 byte len + null
    appendVecU16Len(body, extensions);  // extensions

    // Handshake header: type (1) + length (3)
    Vector<uint8_t> handshake;
    handshake.append(kTLSHandshakeTypeClientHello);
    handshake.append(static_cast<uint8_t>((body.size() >> 16) & 0xFF));
    handshake.append(static_cast<uint8_t>((body.size() >> 8) & 0xFF));
    handshake.append(static_cast<uint8_t>(body.size() & 0xFF));
    handshake.append(body.span());

    // Record header: type (1) + version (2) + length (2)
    Vector<uint8_t> record;
    record.append(kTLSRecordTypeHandshake);
    appendU16(record, kTLSVersionTLS12);
    appendU16(record, static_cast<uint16_t>(handshake.size()));
    record.append(handshake.span());

    WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.171] iPhone ClientHello built: total=%zu bytes (extensions=%zu bytes), 20 ciphers, 13 extensions + 2 GREASE",
        record.size(), extensions.size());

    // Wave 29-499.192 — log full ClientHello hex for JA3 verification
    {
        char hex[2048] = {0};
        size_t off = 0;
        for (size_t i = 0; i < record.size() && off < sizeof(hex) - 3; ++i)
            off += snprintf(hex + off, sizeof(hex) - off, "%02x", record[i]);
        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.192] CH_HEX=%s", hex);
    }

    return record;
}

// Wave 29-499.219 — CH with X25519MLKEM768 hybrid + X25519 keyshare
// (iPhone-byte-exact since iPhone Safari 26 sends both entries)
Vector<uint8_t> driftstackBuildIPhoneClientHelloHybrid(const String& sni,
    const Vector<uint8_t>& mlkemPubKey,
    const Vector<uint8_t>& x25519PubKeyA,
    Vector<uint8_t>& outClientRandom,
    const Vector<uint8_t>& x25519PubKeyB)
{
    outClientRandom.resize(32);
    (void)SecRandomCopyBytes(kSecRandomDefault, 32, outClientRandom.mutableSpan().data());
    Vector<uint8_t> sessionId(32);
    (void)SecRandomCopyBytes(kSecRandomDefault, 32, sessionId.mutableSpan().data());

    uint16_t greasePrimary = pickGreaseValue();
    uint16_t greaseSecondary = pickGreaseValue();
    while (greaseSecondary == greasePrimary)
        greaseSecondary = pickGreaseValue();
    // Wave 29-499.328 — one GREASE value shared by supported_groups + key_share so the
    // key_share GREASE group is present in supported_groups (RFC 8446 §4.2.8 / RFC 8701).
    // Independent picks here caused intermittent illegal_parameter aborts on strict edges.
    uint16_t greaseGroup = pickGreaseValue();
    // iOS draws the cipher-suites GREASE INDEPENDENTLY of the leading-extension GREASE
    // (0/12 real-device captures have them equal; the fork previously reused greasePrimary
    // for both, a 100%-correlated raw-bytes tell). Use a separate greaseCipher, distinct
    // from the primary (leading-ext), secondary (trailing-ext) and group GREASE values.
    uint16_t greaseCipher = pickGreaseValue();
    while (greaseCipher == greasePrimary || greaseCipher == greaseSecondary || greaseCipher == greaseGroup)
        greaseCipher = pickGreaseValue();

    // P1 — pre-Safari-26 archetypes (iOS 17/18/19) emit the iOS-18.x ClientHello.
    const bool preSafari26 = driftstackArchetypeIsPreSafari26();

    Vector<uint8_t> ciphers;
    appendU16(ciphers, greaseCipher);
    if (preSafari26) {
        // 18.x TLS1.3 cipher trio order = 4865-4866-4867 (0x1301,0x1302,0x1303);
        // the remaining 17 ciphers (slots 4..) are identical to 26.x.
        appendU16(ciphers, 0x1301);
        appendU16(ciphers, 0x1302);
        appendU16(ciphers, 0x1303);
        for (size_t i = 4; i < kIPhoneCipherCount; ++i)
            appendU16(ciphers, kIPhoneCiphers[i]);
    } else {
        for (size_t i = 1; i < kIPhoneCipherCount; ++i)
            appendU16(ciphers, kIPhoneCiphers[i]);
    }

    Vector<uint8_t> extensions;
    extensions.append(makeExtGREASE(greasePrimary).span());
    extensions.append(makeExtServerName(sni).span());
    extensions.append(makeExtExtendedMasterSecret().span());
    extensions.append(makeExtRenegotiationInfo().span());
    extensions.append(makeExtSupportedGroups(greaseGroup, preSafari26).span());
    extensions.append(makeExtEcPointFormats().span());
    extensions.append(makeExtALPN().span());
    extensions.append(makeExtStatusRequest().span());
    extensions.append(makeExtSignatureAlgorithms().span());
    extensions.append(makeExtSCT().span());
    if (preSafari26)
        // 18.x: classical X25519-only key_share (GREASE + X25519 + pubkey) — no MLKEM hybrid.
        // ONE X25519 entry only → no two-keypair correlation; uses keypair A.
        extensions.append(makeExtKeyShare(x25519PubKeyA, greaseGroup).span());
    else
        // 26.x HYBRID keyshare: GREASE + X25519MLKEM768(tail=keypair A) + standalone X25519(=keypair B,
        // distinct when DRIFTSTACK_TLS_KEYSHARE_DISTINCT default-ON; reuses A if B empty/gate-off).
        extensions.append(makeExtKeyShareHybrid(mlkemPubKey, x25519PubKeyA, greaseGroup, x25519PubKeyB).span());
    extensions.append(makeExtPSKKeyExchangeModes().span());
    extensions.append(makeExtSupportedVersions(preSafari26).span());
    extensions.append(makeExtCompressCertificate().span());
    extensions.append(makeExtGREASE(greaseSecondary).span());
    if (preSafari26)
        // 18.x: padding extension (0x0015) PRESENT → JA4 ext-count 2014; emitted LAST (after the trailing GREASE) to match iOS wire order.
        extensions.append(makeExtPadding().span());

    Vector<uint8_t> body;
    appendU16(body, kTLSVersionTLS12);
    body.append(outClientRandom.span());
    appendU8LenBlob(body, sessionId.span().data(), sessionId.size());
    appendVecU16Len(body, ciphers);
    body.append(0x01); body.append(0x00);
    appendVecU16Len(body, extensions);

    Vector<uint8_t> handshake;
    handshake.append(kTLSHandshakeTypeClientHello);
    handshake.append(static_cast<uint8_t>((body.size() >> 16) & 0xFF));
    handshake.append(static_cast<uint8_t>((body.size() >> 8) & 0xFF));
    handshake.append(static_cast<uint8_t>(body.size() & 0xFF));
    handshake.append(body.span());

    Vector<uint8_t> record;
    record.append(kTLSRecordTypeHandshake);
    appendU16(record, kTLSVersionTLS12);
    appendU16(record, static_cast<uint16_t>(handshake.size()));
    record.append(handshake.span());

    WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.219] iPhone HYBRID ClientHello built: %zu bytes (MLKEM768 1184 + X25519 32 in keyshare)",
        record.size());
    return record;
}

// Wave 29-499.216 — CH2 for HRR retry with P-256 keyshare
// egress bing P-521 HRR (2026-07-02): CH2 for an HRR retry on the server-requested EC group
// (keyShareGroup: P-256 0x0017 / P-384 0x0018 / P-521 0x0019). Only the key_share extension's group +
// pubkey differ per curve; every other byte stays iPhone-exact (a real iPhone offers all three groups
// and answers the HRR in kind). Was driftstackBuildIPhoneClientHelloP256 (P-256-only).
Vector<uint8_t> driftstackBuildIPhoneClientHelloHRR(const String& sni,
    uint16_t keyShareGroup,
    const Vector<uint8_t>& ecPublicKey,
    Vector<uint8_t>& outClientRandom)
{
    outClientRandom.resize(32);
    (void)SecRandomCopyBytes(kSecRandomDefault, 32, outClientRandom.mutableSpan().data());

    Vector<uint8_t> sessionId(32);
    (void)SecRandomCopyBytes(kSecRandomDefault, 32, sessionId.mutableSpan().data());

    uint16_t greasePrimary = pickGreaseValue();
    uint16_t greaseSecondary = pickGreaseValue();
    while (greaseSecondary == greasePrimary)
        greaseSecondary = pickGreaseValue();
    // Wave 29-499.328 — HRR CH2 key_share (P-256) carries no GREASE, so supported_groups'
    // GREASE is standalone here; still use a valid GREASE value.
    uint16_t greaseGroup = pickGreaseValue();
    // iOS draws the cipher-suites GREASE INDEPENDENTLY of the leading-extension GREASE
    // (0/12 real-device captures have them equal; the fork previously reused greasePrimary
    // for both, a 100%-correlated raw-bytes tell). Use a separate greaseCipher, distinct
    // from the primary (leading-ext), secondary (trailing-ext) and group GREASE values.
    uint16_t greaseCipher = pickGreaseValue();
    while (greaseCipher == greasePrimary || greaseCipher == greaseSecondary || greaseCipher == greaseGroup)
        greaseCipher = pickGreaseValue();

    // P1 — CH2 mirrors CH1 except key_share (RFC 8446 §4.1.2), so carry the same 18.x
    // deltas (cipher trio reorder + supported_groups MLKEM drop + padding) for pre-26.
    const bool preSafari26 = driftstackArchetypeIsPreSafari26();

    Vector<uint8_t> ciphers;
    appendU16(ciphers, greaseCipher);
    if (preSafari26) {
        appendU16(ciphers, 0x1301);
        appendU16(ciphers, 0x1302);
        appendU16(ciphers, 0x1303);
        for (size_t i = 4; i < kIPhoneCipherCount; ++i)
            appendU16(ciphers, kIPhoneCiphers[i]);
    } else {
        for (size_t i = 1; i < kIPhoneCipherCount; ++i)
            appendU16(ciphers, kIPhoneCiphers[i]);
    }

    Vector<uint8_t> extensions;
    extensions.append(makeExtGREASE(greasePrimary).span());
    extensions.append(makeExtServerName(sni).span());
    extensions.append(makeExtExtendedMasterSecret().span());
    extensions.append(makeExtRenegotiationInfo().span());
    extensions.append(makeExtSupportedGroups(greaseGroup, preSafari26).span());
    extensions.append(makeExtEcPointFormats().span());
    extensions.append(makeExtALPN().span());
    extensions.append(makeExtStatusRequest().span());
    extensions.append(makeExtSignatureAlgorithms().span());
    extensions.append(makeExtSCT().span());
    extensions.append(makeExtKeyShareECGroup(keyShareGroup, ecPublicKey).span());  // ← HRR key_share (P-256/384/521)
    extensions.append(makeExtPSKKeyExchangeModes().span());
    extensions.append(makeExtSupportedVersions(preSafari26).span());
    extensions.append(makeExtCompressCertificate().span());
    extensions.append(makeExtGREASE(greaseSecondary).span());
    if (preSafari26)
        extensions.append(makeExtPadding().span());

    Vector<uint8_t> body;
    appendU16(body, kTLSVersionTLS12);
    body.append(outClientRandom.span());
    appendU8LenBlob(body, sessionId.span().data(), sessionId.size());
    appendVecU16Len(body, ciphers);
    body.append(0x01); body.append(0x00);
    appendVecU16Len(body, extensions);

    Vector<uint8_t> handshake;
    handshake.append(kTLSHandshakeTypeClientHello);
    handshake.append(static_cast<uint8_t>((body.size() >> 16) & 0xFF));
    handshake.append(static_cast<uint8_t>((body.size() >> 8) & 0xFF));
    handshake.append(static_cast<uint8_t>(body.size() & 0xFF));
    handshake.append(body.span());

    Vector<uint8_t> record;
    record.append(kTLSRecordTypeHandshake);
    appendU16(record, kTLSVersionTLS12);
    appendU16(record, static_cast<uint16_t>(handshake.size()));
    record.append(handshake.span());

    WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.216] CH2 (HRR retry, P-256 keyshare) built: %zu bytes",
        record.size());
    return record;
}

// Wave 29-499.348 — iPhone-exact QUIC ClientHello (for the custom QUIC-TLS backend that
// replaces BoringSSL as ngtcp2's driver). Differs from the TCP CH: (1) only the 3 TLS 1.3
// AEAD ciphers (QUIC is TLS-1.3-only) + GREASE; (2) ALPN = h3; (3) quic_transport_parameters
// (0x0039) carrying the encoded transport params; (4) DROPS the TCP-only extensions
// ec_point_formats/extended_master_secret/renegotiation_info; (5) NO TLS record header —
// the handshake message goes directly into the QUIC Initial CRYPTO frame; (6) empty
// legacy_session_id per QUIC convention (RFC 9001 §8.4). Target ja4 == iPhone
// q13d0311h3_55b375c5d22e_f2a83c8e78ae (ext set 0005,000a,000d,0012,001b,002b,002d,0033,0039
// + SNI + ALPN; sigalg list incl dup 0805 via makeExtSignatureAlgorithms).
Vector<uint8_t> driftstackBuildIPhoneQuicClientHello(const String& sni,
    const Vector<uint8_t>& mlkemPubKey,
    const Vector<uint8_t>& x25519PubKey,
    const Vector<uint8_t>& transportParams,
    Vector<uint8_t>& outClientRandom)
{
    outClientRandom.resize(32);
    (void)SecRandomCopyBytes(kSecRandomDefault, 32, outClientRandom.mutableSpan().data());

    uint16_t greasePrimary = pickGreaseValue();
    uint16_t greaseSecondary = pickGreaseValue();
    while (greaseSecondary == greasePrimary)
        greaseSecondary = pickGreaseValue();
    uint16_t greaseGroup = pickGreaseValue();
    // iOS draws the cipher-suites GREASE INDEPENDENTLY of the leading-extension GREASE
    // (0/12 real-device captures have them equal; the fork previously reused greasePrimary
    // for both, a 100%-correlated raw-bytes tell). Use a separate greaseCipher, distinct
    // from the primary (leading-ext), secondary (trailing-ext) and group GREASE values.
    uint16_t greaseCipher = pickGreaseValue();
    while (greaseCipher == greasePrimary || greaseCipher == greaseSecondary || greaseCipher == greaseGroup)
        greaseCipher = pickGreaseValue();

    // QUIC ciphers: GREASE + the 3 TLS 1.3 AEAD suites (iPhone offers no TLS 1.2 suites
    // over QUIC). ja4 cipher hash 55b375c5d22e (GREASE excluded from the hash).
    Vector<uint8_t> ciphers;
    appendU16(ciphers, greaseCipher);
    appendU16(ciphers, 0x1301);  // TLS_AES_128_GCM_SHA256
    appendU16(ciphers, 0x1302);  // TLS_AES_256_GCM_SHA384
    appendU16(ciphers, 0x1303);  // TLS_CHACHA20_POLY1305_SHA256

    // iPhone QUIC extension set — verified bit-identical to real iPhone Safari 26.4
    // (quic.browserleaks.com/fp ja4 q13d0311h3_55b375c5d22e_f2a83c8e78ae, Wave .349):
    // 9 non-GREASE/non-SNI/non-ALPN extensions + SNI + ALPN = 11. Drops the TCP-only
    // ec_point_formats/extended_master_secret/renegotiation_info; adds
    // quic_transport_parameters(0x0039); supported_versions is 1.3-only (RFC 9001 §8.2).
    // P1/P2 — pre-Safari-26 archetypes drop X25519MLKEM768 from supported_groups + key_share
    // here too (the shared makeExtSupportedGroups/makeExtKeyShare carry the same classical-only
    // delta as the TCP CH). QUIC's cipher order is the fixed TLS1.3 trio (1301-1302-1303) for
    // all versions, so the TCP trio reorder does not apply; QUIC has no padding extension.
    const bool preSafari26 = driftstackArchetypeIsPreSafari26();

    Vector<uint8_t> extensions;
    extensions.append(makeExtGREASE(greasePrimary).span());
    extensions.append(makeExtServerName(sni).span());
    extensions.append(makeExtSupportedGroups(greaseGroup, preSafari26).span());      // GREASE [+0x11EC if >=26] + X25519 + P-256/384/521
    extensions.append(makeExtALPNQuic().span());                        // h3
    extensions.append(makeExtStatusRequest().span());                  // 0005
    extensions.append(makeExtSignatureAlgorithms().span());            // 000d — incl. iPhone's dup 0805
    extensions.append(makeExtSCT().span());                            // 0012
    if (preSafari26)
        extensions.append(makeExtKeyShare(x25519PubKey, greaseGroup).span());        // 18.x: GREASE + X25519 only
    else
        extensions.append(makeExtKeyShareHybrid(mlkemPubKey, x25519PubKey, greaseGroup).span()); // 26.x: GREASE + X25519MLKEM768 + X25519
    extensions.append(makeExtPSKKeyExchangeModes().span());            // 002d
    extensions.append(makeExtSupportedVersionsQuic().span());          // 002b — GREASE + TLS 1.3 only
    extensions.append(makeExtCompressCertificate().span());            // 001b — zlib
    extensions.append(makeExtQuicTransportParams(transportParams).span()); // 0039
    extensions.append(makeExtGREASE(greaseSecondary).span());

    Vector<uint8_t> body;
    appendU16(body, kTLSVersionTLS12);          // legacy_version
    body.append(outClientRandom.span());
    appendU8LenBlob(body, nullptr, 0);          // empty legacy_session_id (QUIC)
    appendVecU16Len(body, ciphers);
    body.append(0x01); body.append(0x00);       // compression methods: null
    appendVecU16Len(body, extensions);

    // QUIC carries the raw handshake message in CRYPTO — NO TLS record header.
    Vector<uint8_t> handshake;
    handshake.append(kTLSHandshakeTypeClientHello);
    handshake.append(static_cast<uint8_t>((body.size() >> 16) & 0xFF));
    handshake.append(static_cast<uint8_t>((body.size() >> 8) & 0xFF));
    handshake.append(static_cast<uint8_t>(body.size() & 0xFF));
    handshake.append(body.span());

    WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.349] iPhone QUIC ClientHello built: %zu bytes (3 TLS1.3 ciphers, h3 ALPN, transport_params %zuB, X25519MLKEM768 hybrid keyshare) — ja4 q13d0311h3_55b375c5d22e_f2a83c8e78ae",
        handshake.size(), transportParams.size());
    return handshake;
}

bool driftstackCustomTlsEnabled()
{
    const char* env = getenv("DRIFTSTACK_PATHB_V2_CUSTOM_TLS");
    return env && env[0] == '1';
}

// DRIFTSTACK_TLS_KEYSHARE_DISTINCT (default-ON) — emit two INDEPENDENT X25519 ephemeral
// pubkeys across the two key_share entries (hybrid X25519MLKEM768 tail vs standalone
// X25519), matching real iPhone Safari 26.2-26.5 (verified 7/7 captures: the standalone
// X25519 component != the hybrid's X25519 slot, every connection). The reuse of one
// keypair for both made key_share[0x11EC].key_exchange[1184:1216] == key_share[0x001D]
// byte-for-byte — a deterministic structural correlation a TLS-introspecting server/DPI
// computes (invisible to JA3/JA4/peetprint, which hash no key material). Default-ON is the
// iOS-correct behavior; an explicit "0" reverts to the single-keypair wire (escape hatch
// if a derivation bug ever surfaces). Read once (static-init thread-safe).
bool driftstackTlsKeyShareDistinctEnabled()
{
    static const bool s_enabled = [] {
        const char* e = getenv("DRIFTSTACK_TLS_KEYSHARE_DISTINCT");
        return !(e && e[0] == '0');   // default-ON: only an explicit "0" disables
    }();
    return s_enabled;
}

} // namespace WebKit

WTF_ALLOW_UNSAFE_BUFFER_USAGE_END

#endif // PLATFORM(DRIFTSTACK)
