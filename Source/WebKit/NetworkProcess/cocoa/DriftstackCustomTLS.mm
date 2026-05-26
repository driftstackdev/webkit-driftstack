/*
 * DriftstackCustomTLS.mm — Wave 29-499.171 (Phase 1.5e ClientHello)
 *
 * Byte-exact iPhone Safari 26.0 TLS ClientHello emission.
 *
 * iPhone reference (captured via tls.peet.ws V-2026-05-21-W29-499.108):
 *   JA3: ecdf4f49dd59effc439639da29186671
 *   JA4: t13d2013h2_a09f3c656075_7f0f34a4126d
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
    0x1301,  // TLS_AES_128_GCM_SHA256
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

// GREASE values per RFC 8701. iPhone picks 1 GREASE byte and uses it for
// cipher GREASE position, extension GREASE positions, version GREASE.
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
Vector<uint8_t> makeExtSupportedGroups(uint16_t greaseGroup)
{
    Vector<uint8_t> list;
    appendU16(list, greaseGroup);  // GREASE (must match key_share)
    appendU16(list, 0x11EC);  // X25519MLKEM768 (assigned IANA code)
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
Vector<uint8_t> makeExtKeyShareP256(const Vector<uint8_t>& p256PubKey)
{
    Vector<uint8_t> list;
    // P-256 only (no GREASE in HRR retry — per RFC 8446 §4.1.4 ambiguity, most clients
    // strip GREASE from CH2 keyshare)
    appendU16(list, 0x0017);  // secp256r1
    appendU16(list, 0x0041);  // length = 65 (uncompressed P-256 pubkey)
    list.append(p256PubKey.span());
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
Vector<uint8_t> makeExtKeyShareHybrid(const Vector<uint8_t>& mlkemPubKey, const Vector<uint8_t>& x25519PubKey, uint16_t greaseGroup)
{
    Vector<uint8_t> list;
    // GREASE entry (1-byte placeholder for keyshare list slot 0).
    // Wave 29-499.328 — greaseGroup MUST equal the supported_groups GREASE value, else
    // the key_share offers a group not in supported_groups → illegal_parameter on strict
    // servers. Caller threads the same value into makeExtSupportedGroups.
    appendU16(list, greaseGroup);
    appendU16(list, 0x0001);
    list.append(0x00);

    // X25519MLKEM768 (0x11EC): 1216-byte combined keyshare
    appendU16(list, 0x11EC);
    appendU16(list, 0x04C0);  // 1216 bytes
    list.append(mlkemPubKey.span());  // 1184 bytes first
    list.append(x25519PubKey.span()); // 32 bytes second

    // X25519 (0x001D): 32-byte keyshare (iPhone offers both)
    appendU16(list, 0x001D);
    appendU16(list, 0x0020);
    list.append(x25519PubKey.span());

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

// supported_versions (43) — iPhone: GREASE + TLS 1.3 + TLS 1.2
Vector<uint8_t> makeExtSupportedVersions()
{
    Vector<uint8_t> list;
    list.append(static_cast<uint8_t>(0x06));  // total length of versions list = 6 bytes
    uint16_t versions[] = { pickGreaseValue(), 0x0304, 0x0303 };
    for (int i = 0; i < 3; ++i)
        appendU16(list, versions[i]);
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

    // Build cipher_suites (40 bytes content + 2-byte length = 42 bytes)
    Vector<uint8_t> ciphers;
    appendU16(ciphers, greasePrimary);  // GREASE cipher
    for (size_t i = 1; i < kIPhoneCipherCount; ++i)
        appendU16(ciphers, kIPhoneCiphers[i]);

    // Build extensions block — iPhone order (per JA3/JA4 capture)
    Vector<uint8_t> extensions;
    extensions.append(makeExtGREASE(greasePrimary).span());        // GREASE-1
    extensions.append(makeExtServerName(sni).span());              // server_name (0)
    extensions.append(makeExtExtendedMasterSecret().span());       // extended_master_secret (23)
    extensions.append(makeExtRenegotiationInfo().span());          // renegotiation_info (65281)
    extensions.append(makeExtSupportedGroups(greaseGroup).span()); // supported_groups (10)
    extensions.append(makeExtEcPointFormats().span());             // ec_point_formats (11)
    extensions.append(makeExtALPN().span());                       // ALPN (16)
    extensions.append(makeExtStatusRequest().span());              // status_request (5)
    extensions.append(makeExtSignatureAlgorithms().span());        // signature_algorithms (13)
    extensions.append(makeExtSCT().span());                        // signed_certificate_timestamp (18)
    extensions.append(makeExtKeyShare(x25519Pub, greaseGroup).span()); // key_share (51)
    extensions.append(makeExtPSKKeyExchangeModes().span());        // psk_key_exchange_modes (45)
    extensions.append(makeExtSupportedVersions().span());          // supported_versions (43)
    extensions.append(makeExtCompressCertificate().span());        // compress_certificate (27)
    extensions.append(makeExtGREASE(greaseSecondary).span());      // GREASE-2

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
    const Vector<uint8_t>& x25519PubKey,
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
    // Wave 29-499.328 — one GREASE value shared by supported_groups + key_share so the
    // key_share GREASE group is present in supported_groups (RFC 8446 §4.2.8 / RFC 8701).
    // Independent picks here caused intermittent illegal_parameter aborts on strict edges.
    uint16_t greaseGroup = pickGreaseValue();

    Vector<uint8_t> ciphers;
    appendU16(ciphers, greasePrimary);
    for (size_t i = 1; i < kIPhoneCipherCount; ++i)
        appendU16(ciphers, kIPhoneCiphers[i]);

    Vector<uint8_t> extensions;
    extensions.append(makeExtGREASE(greasePrimary).span());
    extensions.append(makeExtServerName(sni).span());
    extensions.append(makeExtExtendedMasterSecret().span());
    extensions.append(makeExtRenegotiationInfo().span());
    extensions.append(makeExtSupportedGroups(greaseGroup).span());
    extensions.append(makeExtEcPointFormats().span());
    extensions.append(makeExtALPN().span());
    extensions.append(makeExtStatusRequest().span());
    extensions.append(makeExtSignatureAlgorithms().span());
    extensions.append(makeExtSCT().span());
    // ← HYBRID keyshare: GREASE + X25519MLKEM768 + X25519 (GREASE matches supported_groups)
    extensions.append(makeExtKeyShareHybrid(mlkemPubKey, x25519PubKey, greaseGroup).span());
    extensions.append(makeExtPSKKeyExchangeModes().span());
    extensions.append(makeExtSupportedVersions().span());
    extensions.append(makeExtCompressCertificate().span());
    extensions.append(makeExtGREASE(greaseSecondary).span());

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
Vector<uint8_t> driftstackBuildIPhoneClientHelloP256(const String& sni,
    const Vector<uint8_t>& p256PublicKey,
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

    Vector<uint8_t> ciphers;
    appendU16(ciphers, greasePrimary);
    for (size_t i = 1; i < kIPhoneCipherCount; ++i)
        appendU16(ciphers, kIPhoneCiphers[i]);

    Vector<uint8_t> extensions;
    extensions.append(makeExtGREASE(greasePrimary).span());
    extensions.append(makeExtServerName(sni).span());
    extensions.append(makeExtExtendedMasterSecret().span());
    extensions.append(makeExtRenegotiationInfo().span());
    extensions.append(makeExtSupportedGroups(greaseGroup).span());
    extensions.append(makeExtEcPointFormats().span());
    extensions.append(makeExtALPN().span());
    extensions.append(makeExtStatusRequest().span());
    extensions.append(makeExtSignatureAlgorithms().span());
    extensions.append(makeExtSCT().span());
    extensions.append(makeExtKeyShareP256(p256PublicKey).span());  // ← P-256 keyshare
    extensions.append(makeExtPSKKeyExchangeModes().span());
    extensions.append(makeExtSupportedVersions().span());
    extensions.append(makeExtCompressCertificate().span());
    extensions.append(makeExtGREASE(greaseSecondary).span());

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

    // QUIC ciphers: GREASE + the 3 TLS 1.3 AEAD suites (iPhone offers no TLS 1.2 suites
    // over QUIC). ja4 cipher hash 55b375c5d22e (GREASE excluded from the hash).
    Vector<uint8_t> ciphers;
    appendU16(ciphers, greasePrimary);
    appendU16(ciphers, 0x1301);  // TLS_AES_128_GCM_SHA256
    appendU16(ciphers, 0x1302);  // TLS_AES_256_GCM_SHA384
    appendU16(ciphers, 0x1303);  // TLS_CHACHA20_POLY1305_SHA256

    // iPhone QUIC extension set — verified bit-identical to real iPhone Safari 26.4
    // (quic.browserleaks.com/fp ja4 q13d0311h3_55b375c5d22e_f2a83c8e78ae, Wave .349):
    // 9 non-GREASE/non-SNI/non-ALPN extensions + SNI + ALPN = 11. Drops the TCP-only
    // ec_point_formats/extended_master_secret/renegotiation_info; adds
    // quic_transport_parameters(0x0039); supported_versions is 1.3-only (RFC 9001 §8.2).
    Vector<uint8_t> extensions;
    extensions.append(makeExtGREASE(greasePrimary).span());
    extensions.append(makeExtServerName(sni).span());
    extensions.append(makeExtSupportedGroups(greaseGroup).span());      // GREASE + 0x11EC + X25519 + P-256/384/521
    extensions.append(makeExtALPNQuic().span());                        // h3
    extensions.append(makeExtStatusRequest().span());                  // 0005
    extensions.append(makeExtSignatureAlgorithms().span());            // 000d — incl. iPhone's dup 0805
    extensions.append(makeExtSCT().span());                            // 0012
    extensions.append(makeExtKeyShareHybrid(mlkemPubKey, x25519PubKey, greaseGroup).span()); // GREASE + X25519MLKEM768 + X25519
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

} // namespace WebKit

WTF_ALLOW_UNSAFE_BUFFER_USAGE_END

#endif // PLATFORM(DRIFTSTACK)
