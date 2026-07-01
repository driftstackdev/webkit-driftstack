/*
 * DriftstackCrypto.mm — Wave 29-499.173 (PathB v2 Phase 1.5e)
 *
 * LibreSSL-backed crypto primitives via dlsym. All functions resolve at
 * runtime from /usr/lib/libcrypto.48.dylib (+ libssl.48 for X25519 EVP_PKEY).
 *
 * Coverage:
 *   ✓ SHA-384 streaming + one-shot (EVP_MD + EVP_MD_CTX)
 *   ✓ HKDF-Extract-SHA384 + HKDF-Expand-Label (RFC 5869 + RFC 8446 §7.1)
 *   ✓ X25519 keypair gen + ECDH (EVP_PKEY_*)
 *   ✓ AES-256-GCM (EVP_CIPHER + EVP_aes_256_gcm)
 */

#import "config.h"
#import "DriftstackCrypto.h"

#if PLATFORM(DRIFTSTACK)

#import <CommonCrypto/CommonCrypto.h>
#import <CommonCrypto/CommonCryptor.h>
#import <wtf/Lock.h>
#import <dispatch/dispatch.h>
#import <dlfcn.h>
#import <stdlib.h>
#import <string.h>
#import <string>
#import <wtf/Assertions.h>

// Wave 29-499.294 — Apple CommonCrypto GCM oneshot SPI (private on macOS,
// resolved via dlsym below). Bypasses LibreSSL EVP_Cipher path that produced
// garbage tag bytes on macOS 26.2.
typedef int32_t (*CCCryptorGCMOneshotEncryptFn)(uint32_t alg,
    const void* key, size_t keySize,
    const void* iv, size_t ivSize,
    const void* aData, size_t aDataSize,
    const void* dataIn, size_t dataInSize,
    void* dataOut,
    void* tag, size_t* tagSize);
typedef int32_t (*CCCryptorGCMOneshotDecryptFn)(uint32_t alg,
    const void* key, size_t keySize,
    const void* iv, size_t ivSize,
    const void* aData, size_t aDataSize,
    const void* dataIn, size_t dataInSize,
    void* dataOut,
    const void* tag, size_t tagSize);

// Wave 29-499.296 — CCMode + CCParameter constants for GCM via public CCCryptor
// API (defined in CommonCryptorSPI.h which the macOS SDK doesn't ship publicly).
enum { kCCModeGCM_DS = 11 };
enum {
    kCCParameterIV_DS = 0,
    kCCParameterAuthData_DS = 1,
    kCCMacSize_DS = 2,
    kCCDataSize_DS = 3,
    kCCParameterAuthTag_DS = 4,
};
typedef uint32_t CCParameter_DS;

// Forward-declare CCCryptorAddParameter / CCCryptorGetParameter (SPI, not in
// public CommonCryptor.h but exported from libcommonCrypto.dylib).
extern "C" CCCryptorStatus CCCryptorAddParameter(CCCryptorRef cryptor,
    CCParameter_DS parameter, const void* data, size_t dataSize);
extern "C" CCCryptorStatus CCCryptorGetParameter(CCCryptorRef cryptor,
    CCParameter_DS parameter, void* data, size_t* dataSize);

WTF_ALLOW_UNSAFE_BUFFER_USAGE_BEGIN

namespace WebKit {

namespace {

// Function pointer typedefs (LibreSSL/OpenSSL 1.1+ API)
struct CryptoFns {
    // SHA / EVP_MD
    const void* (*evp_sha384)(void) = nullptr;
    void* (*evp_md_ctx_new)(void) = nullptr;
    void (*evp_md_ctx_free)(void*) = nullptr;
    int (*evp_digestinit_ex)(void*, const void*, void*) = nullptr;
    int (*evp_digestupdate)(void*, const void*, size_t) = nullptr;
    int (*evp_digestfinal_ex)(void*, uint8_t*, unsigned int*) = nullptr;
    int (*evp_md_ctx_copy_ex)(void*, const void*) = nullptr;

    // HKDF via EVP_KDF
    void* (*evp_kdf_fetch)(void* libctx, const char* algo, const char* props) = nullptr;
    void (*evp_kdf_free)(void*) = nullptr;
    void* (*evp_kdf_ctx_new)(void* kdf) = nullptr;
    void (*evp_kdf_ctx_free)(void*) = nullptr;
    int (*evp_kdf_derive)(void* kctx, uint8_t* out, size_t outLen, const void* params) = nullptr;
    // Older LibreSSL: HKDF via EVP_PKEY_derive on EVP_PKEY_HKDF
    void* (*evp_pkey_ctx_new_id)(int id, void* engine) = nullptr;
    int (*evp_pkey_derive_init)(void* ctx) = nullptr;
    int (*evp_pkey_ctx_ctrl)(void* ctx, int keytype, int optype, int cmd, int p1, void* p2) = nullptr;
    int (*evp_pkey_derive)(void* ctx, uint8_t* key, size_t* keyLen) = nullptr;
    void (*evp_pkey_ctx_free)(void*) = nullptr;
    int (*hkdf_ctrl_str)(void* ctx, const char* type, const char* value) = nullptr;
    // Raw HKDF helpers if exposed (LibreSSL 3.6+)
    int (*hkdf)(const void* md, const uint8_t* salt, size_t saltLen,
                const uint8_t* key, size_t keyLen,
                const uint8_t* info, size_t infoLen,
                uint8_t* out, size_t outLen) = nullptr;

    // HMAC
    void* (*hmac)(const void* md, const uint8_t* key, int keyLen,
                  const uint8_t* data, size_t dataLen,
                  uint8_t* out, unsigned int* outLen) = nullptr;

    // Wave 29-499.185 — LibreSSL direct HKDF (much simpler than EVP_PKEY)
    int (*hkdf_extract)(uint8_t* out, size_t* outLen, const void* md,
                        const uint8_t* secret, size_t secretLen,
                        const uint8_t* salt, size_t saltLen) = nullptr;
    int (*hkdf_expand)(uint8_t* out, size_t outLen, const void* md,
                       const uint8_t* prk, size_t prkLen,
                       const uint8_t* info, size_t infoLen) = nullptr;

    // SHA-256 (in addition to SHA-384) — server may pick TLS_AES_128_GCM_SHA256
    const void* (*evp_sha256)(void) = nullptr;

    // EVP_PKEY for X25519 (legacy — LibreSSL uses direct X25519_keypair instead)
    void* (*evp_pkey_ctx_new_from_name)(void* libctx, const char* name, const char* props) = nullptr;
    int (*evp_pkey_keygen_init)(void* ctx) = nullptr;
    int (*evp_pkey_keygen)(void* ctx, void** pkey) = nullptr;
    int (*evp_pkey_get_raw_private_key)(const void* pkey, uint8_t* priv, size_t* len) = nullptr;
    int (*evp_pkey_get_raw_public_key)(const void* pkey, uint8_t* pub, size_t* len) = nullptr;
    void* (*evp_pkey_new_raw_private_key)(int type, void* e, const uint8_t* priv, size_t len) = nullptr;
    void* (*evp_pkey_new_raw_public_key)(int type, void* e, const uint8_t* pub, size_t len) = nullptr;
    void* (*evp_pkey_ctx_new)(void* pkey, void* e) = nullptr;
    int (*evp_pkey_derive_set_peer)(void* ctx, void* peer) = nullptr;
    void (*evp_pkey_free)(void*) = nullptr;

    // Wave 29-499.184 — LibreSSL direct X25519 API (preferred over EVP_PKEY)
    void (*x25519_keypair)(uint8_t out_public[32], uint8_t out_private[32]) = nullptr;
    int (*x25519)(uint8_t out_shared[32], const uint8_t private_key[32], const uint8_t peer_public[32]) = nullptr;

    // Wave 29-499.218 — MLKEM768 hybrid key exchange (resolved from libwebrtc.dylib)
    void (*mlkem768_generate_key)(uint8_t out_pub[1184], uint8_t out_seed[64], void* out_priv) = nullptr;
    int (*mlkem768_decap)(uint8_t out_shared[32], const uint8_t* ciphertext, size_t ctLen, const void* priv) = nullptr;

    // Wave 29-499.207 — P-256 ECDH via EC_KEY API
    void* (*ec_key_new_by_curve_name)(int nid) = nullptr;
    int (*ec_key_generate_key)(void* eckey) = nullptr;
    const void* (*ec_key_get0_public_key)(const void* eckey) = nullptr;
    const void* (*ec_key_get0_private_key)(const void* eckey) = nullptr;
    int (*ec_key_set_public_key)(void* eckey, const void* point) = nullptr;
    void (*ec_key_free)(void* eckey) = nullptr;
    const void* (*ec_key_get0_group)(const void* eckey) = nullptr;
    void* (*ec_point_new)(const void* group) = nullptr;
    void (*ec_point_free)(void* point) = nullptr;
    size_t (*ec_point_point2oct)(const void* group, const void* point, int form,
                                   uint8_t* buf, size_t bufLen, void* bnctx) = nullptr;
    int (*ec_point_oct2point)(const void* group, void* point, const uint8_t* buf, size_t bufLen, void* bnctx) = nullptr;
    int (*ecdh_compute_key)(void* out, size_t outlen, const void* peerPoint, void* eckey,
                             void* (*kdf)(const void*, size_t, void*, size_t*)) = nullptr;
    int (*bn_bn2bin)(const void* bn, uint8_t* buf) = nullptr;
    int (*bn_num_bytes)(const void* bn) = nullptr;

    // AES-GCM
    const void* (*evp_aes_256_gcm)(void) = nullptr;
    const void* (*evp_aes_128_gcm)(void) = nullptr;

    // Wave 29-499.190 — LibreSSL/BoringSSL AEAD API (works where EVP_Cipher* doesn't)
    const void* (*evp_aead_aes_128_gcm)(void) = nullptr;
    const void* (*evp_aead_aes_256_gcm)(void) = nullptr;
    // Wave 29-499.276 — ChaCha20-Poly1305 for QUIC AEAD cipher 0x1303
    const void* (*evp_aead_chacha20_poly1305)(void) = nullptr;
    int (*evp_aead_ctx_init)(void* ctx, const void* aead, const uint8_t* key, size_t keyLen,
                              size_t tagLen, void* engine) = nullptr;
    void (*evp_aead_ctx_cleanup)(void* ctx) = nullptr;
    int (*evp_aead_ctx_seal)(void* ctx, uint8_t* out, size_t* outLen, size_t maxOut,
                              const uint8_t* nonce, size_t nonceLen,
                              const uint8_t* in, size_t inLen,
                              const uint8_t* ad, size_t adLen) = nullptr;
    int (*evp_aead_ctx_open)(void* ctx, uint8_t* out, size_t* outLen, size_t maxOut,
                              const uint8_t* nonce, size_t nonceLen,
                              const uint8_t* in, size_t inLen,
                              const uint8_t* ad, size_t adLen) = nullptr;
    void* (*evp_aead_ctx_new)(void) = nullptr;
    void (*evp_aead_ctx_free)(void* ctx) = nullptr;
    void* (*evp_cipher_ctx_new)(void) = nullptr;
    void (*evp_cipher_ctx_free)(void*) = nullptr;
    int (*evp_encryptinit_ex)(void* ctx, const void* cipher, void* e, const uint8_t* key, const uint8_t* iv) = nullptr;
    int (*evp_decryptinit_ex)(void* ctx, const void* cipher, void* e, const uint8_t* key, const uint8_t* iv) = nullptr;
    int (*evp_cipher_ctx_ctrl)(void* ctx, int type, int arg, void* ptr) = nullptr;
    int (*evp_encryptupdate)(void* ctx, uint8_t* out, int* outLen, const uint8_t* in, int inLen) = nullptr;
    int (*evp_decryptupdate)(void* ctx, uint8_t* out, int* outLen, const uint8_t* in, int inLen) = nullptr;
    int (*evp_encryptfinal_ex)(void* ctx, uint8_t* out, int* outLen) = nullptr;
    int (*evp_decryptfinal_ex)(void* ctx, uint8_t* out, int* outLen) = nullptr;

    // Wave 29-499.294 — Apple CommonCrypto GCM oneshot SPI
    CCCryptorGCMOneshotEncryptFn cc_gcm_oneshot_encrypt = nullptr;
    CCCryptorGCMOneshotDecryptFn cc_gcm_oneshot_decrypt = nullptr;

    bool ready = false;
};

CryptoFns& cryptoFns()
{
    static CryptoFns f;
    return f;
}

// Wave 29-499.183 — LibreSSL X25519 NID is 950 (verified via OBJ_txt2nid)
[[maybe_unused]] const int kEVPPkeyX25519 = 950;
const int kEVPPkeyHKDF = 1036;    // NID_hkdf
const int kEVPCtrlAEADSetIvLen = 0x9;
const int kEVPCtrlAEADGetTag = 0x10;
const int kEVPCtrlAEADSetTag = 0x11;

} // anonymous namespace

bool driftstackCryptoInit()
{
    static dispatch_once_t once;
    auto& f = cryptoFns();
    dispatch_once(&once, ^{
        // Wave 29-499.182 — Apple ships libssl.48.dylib only; crypto API
        // is bundled inside libssl. No separate libcrypto.48 exists.
        void* hSsl = dlopen("/usr/lib/libssl.48.dylib", RTLD_NOW | RTLD_GLOBAL);
        if (!hSsl) {
            WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.182] dlopen libssl.48 failed");
            return;
        }
        void* h = hSsl;
#define R(field, name) f.field = reinterpret_cast<decltype(f.field)>(dlsym(h, name))
        R(evp_sha384, "EVP_sha384");
        R(evp_md_ctx_new, "EVP_MD_CTX_new");
        R(evp_md_ctx_free, "EVP_MD_CTX_free");
        R(evp_digestinit_ex, "EVP_DigestInit_ex");
        R(evp_digestupdate, "EVP_DigestUpdate");
        R(evp_digestfinal_ex, "EVP_DigestFinal_ex");
        R(evp_md_ctx_copy_ex, "EVP_MD_CTX_copy_ex");
        R(evp_pkey_ctx_new_id, "EVP_PKEY_CTX_new_id");
        R(evp_pkey_derive_init, "EVP_PKEY_derive_init");
        R(evp_pkey_ctx_ctrl, "EVP_PKEY_CTX_ctrl");
        R(evp_pkey_derive, "EVP_PKEY_derive");
        R(evp_pkey_ctx_free, "EVP_PKEY_CTX_free");
        R(evp_pkey_ctx_new, "EVP_PKEY_CTX_new");
        R(evp_pkey_keygen_init, "EVP_PKEY_keygen_init");
        R(evp_pkey_keygen, "EVP_PKEY_keygen");
        R(evp_pkey_get_raw_private_key, "EVP_PKEY_get_raw_private_key");
        R(evp_pkey_get_raw_public_key, "EVP_PKEY_get_raw_public_key");
        R(evp_pkey_new_raw_private_key, "EVP_PKEY_new_raw_private_key");
        R(evp_pkey_new_raw_public_key, "EVP_PKEY_new_raw_public_key");
        R(evp_pkey_derive_set_peer, "EVP_PKEY_derive_set_peer");
        R(evp_pkey_free, "EVP_PKEY_free");
        R(x25519_keypair, "X25519_keypair");
        R(x25519, "X25519");
        // Wave 29-499.218 — MLKEM768 from libwebrtc.dylib (re-exported via .217)
        // Try multiple dlopen paths since libwebrtc is loaded transitively
        void* webrtcH = dlopen("libwebrtc.dylib", RTLD_NOW | RTLD_GLOBAL);
        if (!webrtcH) {
            // V-211: the dev build-products dir derives from the environment
            // (DRIFTSTACK_BUILD_DIR, else $HOME/code/webkit-driftstack/
            // WebKitBuild/Release) instead of a hardcoded build-machine home.
            const char* dir = getenv("DRIFTSTACK_BUILD_DIR");
            const char* home = getenv("HOME");
            std::string p = (dir && *dir) ? std::string(dir) : std::string(home ? home : "") + "/code/webkit-driftstack/WebKitBuild/Release";
            p += "/libwebrtc.dylib";
            webrtcH = dlopen(p.c_str(), RTLD_NOW | RTLD_GLOBAL);
        }
        if (webrtcH) {
            f.mlkem768_generate_key = reinterpret_cast<decltype(f.mlkem768_generate_key)>(dlsym(webrtcH, "MLKEM768_generate_key"));
            f.mlkem768_decap = reinterpret_cast<decltype(f.mlkem768_decap)>(dlsym(webrtcH, "MLKEM768_decap"));
        }
        // Also try RTLD_DEFAULT (libwebrtc loaded transitively)
        if (!f.mlkem768_generate_key)
            f.mlkem768_generate_key = reinterpret_cast<decltype(f.mlkem768_generate_key)>(dlsym(RTLD_DEFAULT, "MLKEM768_generate_key"));
        if (!f.mlkem768_decap)
            f.mlkem768_decap = reinterpret_cast<decltype(f.mlkem768_decap)>(dlsym(RTLD_DEFAULT, "MLKEM768_decap"));
        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.218] MLKEM768 dlsym: gen=%p decap=%p",
            (void*)f.mlkem768_generate_key, (void*)f.mlkem768_decap);
        R(ec_key_new_by_curve_name, "EC_KEY_new_by_curve_name");
        R(ec_key_generate_key, "EC_KEY_generate_key");
        R(ec_key_get0_public_key, "EC_KEY_get0_public_key");
        R(ec_key_get0_private_key, "EC_KEY_get0_private_key");
        R(ec_key_set_public_key, "EC_KEY_set_public_key");
        R(ec_key_free, "EC_KEY_free");
        R(ec_key_get0_group, "EC_KEY_get0_group");
        R(ec_point_new, "EC_POINT_new");
        R(ec_point_free, "EC_POINT_free");
        R(ec_point_point2oct, "EC_POINT_point2oct");
        R(ec_point_oct2point, "EC_POINT_oct2point");
        R(ecdh_compute_key, "ECDH_compute_key");
        R(bn_bn2bin, "BN_bn2bin");
        R(bn_num_bytes, "BN_num_bytes");
        R(hmac, "HMAC");
        R(hkdf_extract, "HKDF_extract");
        R(hkdf_expand, "HKDF_expand");
        R(evp_sha256, "EVP_sha256");
        R(evp_aes_256_gcm, "EVP_aes_256_gcm");
        R(evp_aes_128_gcm, "EVP_aes_128_gcm");
        R(evp_aead_aes_128_gcm, "EVP_aead_aes_128_gcm");
        R(evp_aead_aes_256_gcm, "EVP_aead_aes_256_gcm");
        R(evp_aead_chacha20_poly1305, "EVP_aead_chacha20_poly1305");  // Wave .276
        R(evp_aead_ctx_init, "EVP_AEAD_CTX_init");
        R(evp_aead_ctx_cleanup, "EVP_AEAD_CTX_cleanup");
        R(evp_aead_ctx_seal, "EVP_AEAD_CTX_seal");
        R(evp_aead_ctx_open, "EVP_AEAD_CTX_open");
        R(evp_aead_ctx_new, "EVP_AEAD_CTX_new");
        R(evp_aead_ctx_free, "EVP_AEAD_CTX_free");
        R(evp_cipher_ctx_new, "EVP_CIPHER_CTX_new");
        R(evp_cipher_ctx_free, "EVP_CIPHER_CTX_free");
        R(evp_encryptinit_ex, "EVP_EncryptInit_ex");
        R(evp_decryptinit_ex, "EVP_DecryptInit_ex");
        R(evp_cipher_ctx_ctrl, "EVP_CIPHER_CTX_ctrl");
        R(evp_encryptupdate, "EVP_EncryptUpdate");
        R(evp_decryptupdate, "EVP_DecryptUpdate");
        R(evp_encryptfinal_ex, "EVP_EncryptFinal_ex");
        R(evp_decryptfinal_ex, "EVP_DecryptFinal_ex");
#undef R

        // Wave 29-499.294 — Apple CommonCrypto GCM oneshot SPI (private but
        // exported on macOS 10.13+). dlsym from libcommonCrypto.dylib or RTLD_DEFAULT.
        void* hCC = dlopen("/usr/lib/system/libcommonCrypto.dylib", RTLD_NOW | RTLD_GLOBAL);
        if (!hCC) hCC = dlopen("libcommonCrypto.dylib", RTLD_NOW | RTLD_GLOBAL);
        void* hCCResolver = hCC ? hCC : RTLD_DEFAULT;
        f.cc_gcm_oneshot_encrypt = reinterpret_cast<CCCryptorGCMOneshotEncryptFn>(
            dlsym(hCCResolver, "CCCryptorGCMOneshotEncrypt"));
        f.cc_gcm_oneshot_decrypt = reinterpret_cast<CCCryptorGCMOneshotDecryptFn>(
            dlsym(hCCResolver, "CCCryptorGCMOneshotDecrypt"));
        if (!f.cc_gcm_oneshot_encrypt)
            f.cc_gcm_oneshot_encrypt = reinterpret_cast<CCCryptorGCMOneshotEncryptFn>(
                dlsym(RTLD_DEFAULT, "CCCryptorGCMOneshotEncrypt"));
        if (!f.cc_gcm_oneshot_decrypt)
            f.cc_gcm_oneshot_decrypt = reinterpret_cast<CCCryptorGCMOneshotDecryptFn>(
                dlsym(RTLD_DEFAULT, "CCCryptorGCMOneshotDecrypt"));
        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.294] CCCryptorGCMOneshot dlsym: enc=%p dec=%p",
            (void*)f.cc_gcm_oneshot_encrypt, (void*)f.cc_gcm_oneshot_decrypt);

        bool required = f.evp_sha384 && f.evp_md_ctx_new && f.evp_digestupdate
            && f.evp_digestfinal_ex && f.evp_pkey_ctx_new_id && f.evp_pkey_derive_init
            && f.evp_pkey_derive && f.evp_aes_256_gcm && f.evp_cipher_ctx_new
            && f.evp_encryptupdate && f.evp_decryptupdate;
        f.ready = required;
        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.173] LibreSSL crypto dlsym ready=%d", required);
    });
    return f.ready;
}

// === SHA-384 ===

SHA384Ctx* driftstackCreateSHA384Ctx()
{
    if (!driftstackCryptoInit()) return nullptr;
    auto& f = cryptoFns();
    void* ctx = f.evp_md_ctx_new();
    if (ctx)
        f.evp_digestinit_ex(ctx, f.evp_sha384(), nullptr);
    return reinterpret_cast<SHA384Ctx*>(ctx);
}

void driftstackUpdateSHA384(SHA384Ctx* ctx, const uint8_t* data, size_t len)
{
    if (!ctx) return;
    cryptoFns().evp_digestupdate(reinterpret_cast<void*>(ctx), data, len);
}

Vector<uint8_t> driftstackFinalizeSHA384(SHA384Ctx* ctx)
{
    Vector<uint8_t> out(48);
    if (!ctx) return out;
    unsigned int outLen = 48;
    cryptoFns().evp_digestfinal_ex(reinterpret_cast<void*>(ctx), out.mutableSpan().data(), &outLen);
    cryptoFns().evp_md_ctx_free(reinterpret_cast<void*>(ctx));
    out.resize(outLen);
    return out;
}

Vector<uint8_t> driftstackCloneFinalizeSHA384(SHA384Ctx* ctx)
{
    Vector<uint8_t> out(48);
    if (!ctx) return out;
    auto& f = cryptoFns();
    void* tmp = f.evp_md_ctx_new();
    if (!tmp) return out;
    if (f.evp_md_ctx_copy_ex)
        f.evp_md_ctx_copy_ex(tmp, reinterpret_cast<const void*>(ctx));
    unsigned int outLen = 48;
    f.evp_digestfinal_ex(tmp, out.mutableSpan().data(), &outLen);
    f.evp_md_ctx_free(tmp);
    out.resize(outLen);
    return out;
}

void driftstackFreeSHA384Ctx(SHA384Ctx* ctx)
{
    if (ctx)
        cryptoFns().evp_md_ctx_free(reinterpret_cast<void*>(ctx));
}

Vector<uint8_t> driftstackSHA384(const uint8_t* data, size_t len)
{
    auto* ctx = driftstackCreateSHA384Ctx();
    if (!ctx) return {};
    driftstackUpdateSHA384(ctx, data, len);
    return driftstackFinalizeSHA384(ctx);
}

// === HKDF-SHA384 (LibreSSL via EVP_PKEY_HKDF) ===

namespace {

// Wave 29-499.190 — AEAD-based encrypt/decrypt (LibreSSL/BoringSSL API).
// Defined HERE (early) because used by both 256-GCM and 128-GCM wrappers.
Vector<uint8_t> aeadEncrypt(const void* aead,
                             const Vector<uint8_t>& key,
                             const Vector<uint8_t>& nonce,
                             const Vector<uint8_t>& plaintext,
                             const Vector<uint8_t>& aad)
{
    if (!driftstackCryptoInit() || !aead) return {};
    auto& f = cryptoFns();
    if (!f.evp_aead_ctx_init || !f.evp_aead_ctx_seal || !f.evp_aead_ctx_cleanup) return {};
    // Wave 29-499.191 — LibreSSL EVP_AEAD_CTX is caller-allocated.
    // EVP_AEAD_CTX_new doesn't exist; use stack buffer.
    uint8_t ctxBuf[1024];
    if (f.evp_aead_ctx_init(ctxBuf, aead, key.span().data(), key.size(), 16, nullptr) != 1)
        return {};
    Vector<uint8_t> out(plaintext.size() + 16);
    size_t outLen = 0;
    int rc = f.evp_aead_ctx_seal(ctxBuf, out.mutableSpan().data(), &outLen, out.size(),
        nonce.span().data(), nonce.size(),
        plaintext.span().data(), plaintext.size(),
        aad.span().data(), aad.size());
    f.evp_aead_ctx_cleanup(ctxBuf);
    if (rc != 1) return {};
    out.resize(outLen);
    return out;
}

Vector<uint8_t> aeadDecrypt(const void* aead,
                             const Vector<uint8_t>& key,
                             const Vector<uint8_t>& nonce,
                             const Vector<uint8_t>& ciphertext,
                             const Vector<uint8_t>& aad)
{
    if (!driftstackCryptoInit() || !aead || ciphertext.size() < 16) return {};
    auto& f = cryptoFns();
    if (!f.evp_aead_ctx_init || !f.evp_aead_ctx_open || !f.evp_aead_ctx_cleanup) return {};
    uint8_t ctxBuf[1024];
    if (f.evp_aead_ctx_init(ctxBuf, aead, key.span().data(), key.size(), 16, nullptr) != 1)
        return {};
    Vector<uint8_t> out(ciphertext.size());
    size_t outLen = 0;
    int rc = f.evp_aead_ctx_open(ctxBuf, out.mutableSpan().data(), &outLen, out.size(),
        nonce.span().data(), nonce.size(),
        ciphertext.span().data(), ciphertext.size(),
        aad.span().data(), aad.size());
    f.evp_aead_ctx_cleanup(ctxBuf);
    if (rc != 1) return {};
    out.resize(outLen);
    return out;
}

} // anonymous namespace early-defs

namespace {
const int kEVPPkeyOpDerive = (1 << 10);
const int kEVPPkeyCtrlHkdfMode = 0x1000;
const int kEVPPkeyCtrlHkdfSalt = 0x1001;
const int kEVPPkeyCtrlHkdfKey = 0x1002;
const int kEVPPkeyCtrlHkdfInfo = 0x1003;
const int kEVPPkeyCtrlHkdfMd = 0x1004;
[[maybe_unused]] const int kEVPHkdfExtractAndExpand = 0;
const int kEVPHkdfExtractOnly = 1;
const int kEVPHkdfExpandOnly = 2;

[[maybe_unused]] Vector<uint8_t> hkdfDerive(int mode, const void* md,
                            const Vector<uint8_t>& salt,
                            const Vector<uint8_t>& key,
                            const Vector<uint8_t>& info,
                            size_t outLen)
{
    auto& f = cryptoFns();
    Vector<uint8_t> out(outLen);
    void* ctx = f.evp_pkey_ctx_new_id(kEVPPkeyHKDF, nullptr);
    if (!ctx) return {};
    if (f.evp_pkey_derive_init(ctx) <= 0) { f.evp_pkey_ctx_free(ctx); return {}; }
    // Set mode
    f.evp_pkey_ctx_ctrl(ctx, -1, kEVPPkeyOpDerive, kEVPPkeyCtrlHkdfMode, mode, nullptr);
    // Set MD
    f.evp_pkey_ctx_ctrl(ctx, -1, kEVPPkeyOpDerive, kEVPPkeyCtrlHkdfMd, 0, const_cast<void*>(md));
    // Set salt (extract only / extract+expand)
    if (mode != kEVPHkdfExpandOnly && salt.size())
        f.evp_pkey_ctx_ctrl(ctx, -1, kEVPPkeyOpDerive, kEVPPkeyCtrlHkdfSalt, static_cast<int>(salt.size()), const_cast<uint8_t*>(salt.span().data()));
    // Set key (IKM or PRK)
    f.evp_pkey_ctx_ctrl(ctx, -1, kEVPPkeyOpDerive, kEVPPkeyCtrlHkdfKey, static_cast<int>(key.size()), const_cast<uint8_t*>(key.span().data()));
    // Set info (expand only / extract+expand)
    if (mode != kEVPHkdfExtractOnly && info.size())
        f.evp_pkey_ctx_ctrl(ctx, -1, kEVPPkeyOpDerive, kEVPPkeyCtrlHkdfInfo, static_cast<int>(info.size()), const_cast<uint8_t*>(info.span().data()));
    size_t actualLen = outLen;
    int rc = f.evp_pkey_derive(ctx, out.mutableSpan().data(), &actualLen);
    f.evp_pkey_ctx_free(ctx);
    if (rc <= 0) return {};
    out.resize(actualLen);
    return out;
}
} // namespace

Vector<uint8_t> driftstackHkdfExtractSha384(const Vector<uint8_t>& salt,
                                            const Vector<uint8_t>& ikm)
{
    if (!driftstackCryptoInit()) return {};
    auto& f = cryptoFns();
    if (!f.hkdf_extract) return {};
    Vector<uint8_t> out(48);
    size_t outLen = 48;
    if (f.hkdf_extract(out.mutableSpan().data(), &outLen, f.evp_sha384(),
                       ikm.span().data(), ikm.size(),
                       salt.span().data(), salt.size()) != 1)
        return {};
    out.resize(outLen);
    return out;
}

Vector<uint8_t> driftstackHkdfExpandLabelSha384(const Vector<uint8_t>& secret,
                                                 const char* label,
                                                 const Vector<uint8_t>& context,
                                                 size_t outLen)
{
    if (!driftstackCryptoInit()) return {};
    auto& f = cryptoFns();
    if (!f.hkdf_expand) return {};
    // Build HkdfLabel per RFC 8446 §7.1
    Vector<uint8_t> hkdfLabel;
    hkdfLabel.append(static_cast<uint8_t>(outLen >> 8));
    hkdfLabel.append(static_cast<uint8_t>(outLen & 0xFF));
    const char* prefix = "tls13 ";
    size_t fullLabelLen = strlen(prefix) + strlen(label);
    hkdfLabel.append(static_cast<uint8_t>(fullLabelLen));
    hkdfLabel.append(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(prefix), strlen(prefix)));
    hkdfLabel.append(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(label), strlen(label)));
    hkdfLabel.append(static_cast<uint8_t>(context.size()));
    hkdfLabel.append(context.span());

    Vector<uint8_t> out(outLen);
    if (f.hkdf_expand(out.mutableSpan().data(), outLen, f.evp_sha384(),
                      secret.span().data(), secret.size(),
                      hkdfLabel.span().data(), hkdfLabel.size()) != 1)
        return {};
    return out;
}

Vector<uint8_t> driftstackDeriveSecretSha384(const Vector<uint8_t>& secret,
                                              const char* label,
                                              const Vector<uint8_t>& transcriptHash)
{
    return driftstackHkdfExpandLabelSha384(secret, label, transcriptHash, 48);
}

// === X25519 ECDH ===

bool driftstackX25519GenerateKeypair(Vector<uint8_t>& outPrivate, Vector<uint8_t>& outPublic)
{
    if (!driftstackCryptoInit()) return false;
    auto& f = cryptoFns();
    if (!f.x25519_keypair) return false;
    outPrivate.resize(32);
    outPublic.resize(32);
    f.x25519_keypair(outPublic.mutableSpan().data(), outPrivate.mutableSpan().data());
    return true;
}

Vector<uint8_t> driftstackX25519SharedSecret(const Vector<uint8_t>& ourPrivate,
                                               const Vector<uint8_t>& peerPublic)
{
    if (!driftstackCryptoInit()) return {};
    auto& f = cryptoFns();
    if (!f.x25519 || ourPrivate.size() != 32 || peerPublic.size() != 32) return {};
    Vector<uint8_t> shared(32);
    if (f.x25519(shared.mutableSpan().data(), ourPrivate.span().data(), peerPublic.span().data()) != 1)
        return {};
    return shared;
}

// Wave 29-499.218 — MLKEM768 (PQ hybrid for iPhone Safari 26+ key_share)
// a74622fc HARDENING: this size was hand-derived from reading a BoringSSL header at some point
// (512*(3+3+9)+32+32+32=7776) against /usr/lib/libssl.48.dylib — a macOS SYSTEM library that
// updates every OS release, backing a struct BoringSSL explicitly does NOT guarantee ABI-stable
// across versions. Investigated as a candidate cause of the facebook.com TLS auth-tag failures
// (ruled out empirically — bumping this buffer alone did not change the failure rate; the real
// cause was the missing 0x1303/ChaCha20-Poly1305 cipher branch in aesGcmEncrypt/Decrypt below,
// see DriftstackTLS13Client.mm). Kept at this generous size anyway as defense-in-depth against a
// future macOS update changing the real struct size: decap only ever READS through this pointer
// at whatever size BoringSSL's OWN struct actually is, so extra headroom is harmless.
constexpr size_t kMLKEM768PrivateKeyBytes = 32768;
constexpr size_t kMLKEM768PublicKeyBytes = 1184;
constexpr size_t kMLKEM768CiphertextBytes = 1088;
constexpr size_t kMLKEMSharedSecretBytes = 32;

// a74622fc HARDENING: dlsym'd from a PRIVATE, undocumented symbol in the macOS system
// libssl.48.dylib (not a public/supported API) — Apple gives zero thread-safety guarantee for
// concurrent calls through it, and a heavy multi-origin page opens MANY simultaneous TLS
// connections (each on its own worker thread, each calling MLKEM768_generate_key/_decap
// concurrently). Investigated as a candidate cause of the facebook.com TLS auth-tag failures
// (ruled out empirically — serializing alone did not change the failure rate; the real cause was
// the missing 0x1303/ChaCha20-Poly1305 cipher branch, see DriftstackTLS13Client.mm). Kept anyway:
// serializing is cheap (keygen/decap are microseconds) and removes a real, still-live risk —
// nothing guarantees this private symbol is safe under concurrent invocation.
static Lock& mlkem768Lock()
{
    static Lock lock;
    return lock;
}

MLKEM768Keypair driftstackMLKEM768Generate()
{
    MLKEM768Keypair kp;
    if (!driftstackCryptoInit()) return kp;
    auto& f = cryptoFns();
    if (!f.mlkem768_generate_key) {
        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.218] MLKEM768_generate_key not available");
        return kp;
    }
    kp.privateKey = malloc(kMLKEM768PrivateKeyBytes);
    if (!kp.privateKey) return kp;
    memset(kp.privateKey, 0, kMLKEM768PrivateKeyBytes);

    kp.publicKey.resize(kMLKEM768PublicKeyBytes);
    {
        Locker locker { mlkem768Lock() };
        f.mlkem768_generate_key(kp.publicKey.mutableSpan().data(), nullptr, kp.privateKey);
    }
    kp.ok = true;
    return kp;
}

void driftstackMLKEM768Free(MLKEM768Keypair& kp)
{
    if (kp.privateKey) {
        free(kp.privateKey);
        kp.privateKey = nullptr;
    }
    kp.ok = false;
}

Vector<uint8_t> driftstackMLKEM768Decap(const MLKEM768Keypair& kp, const Vector<uint8_t>& ciphertext)
{
    if (!kp.ok || !kp.privateKey || ciphertext.size() != kMLKEM768CiphertextBytes) return {};
    auto& f = cryptoFns();
    if (!f.mlkem768_decap) return {};
    Vector<uint8_t> shared(kMLKEMSharedSecretBytes);
    int rc;
    {
        Locker locker { mlkem768Lock() };
        rc = f.mlkem768_decap(shared.mutableSpan().data(), ciphertext.span().data(),
            ciphertext.size(), kp.privateKey);
    }
    if (rc != 1) return {};
    return shared;
}

// Wave 29-499.214 — P-256 ECDH stateful keypair (HRR retry uses it)
constexpr int kNIDP256 = 415;             // NID_X9_62_prime256v1
constexpr int kPointConvUncompressed = 4; // POINT_CONVERSION_UNCOMPRESSED

P256Keypair driftstackP256Generate()
{
    P256Keypair kp;
    if (!driftstackCryptoInit()) return kp;
    auto& f = cryptoFns();
    if (!f.ec_key_new_by_curve_name || !f.ec_key_generate_key) return kp;
    void* eckey = f.ec_key_new_by_curve_name(kNIDP256);
    if (!eckey) return kp;
    if (f.ec_key_generate_key(eckey) != 1) { f.ec_key_free(eckey); return kp; }

    // Export public key: 65 bytes uncompressed (0x04 + 32 X + 32 Y)
    const void* point = f.ec_key_get0_public_key(eckey);
    const void* group = f.ec_key_get0_group(eckey);
    kp.publicKey.resize(65);
    size_t pubLen = f.ec_point_point2oct(group, point, kPointConvUncompressed,
        kp.publicKey.mutableSpan().data(), 65, nullptr);
    if (pubLen != 65) { f.ec_key_free(eckey); return kp; }

    kp.ecKey = eckey;
    kp.ok = true;
    return kp;
}

void driftstackP256Free(P256Keypair& kp)
{
    auto& f = cryptoFns();
    if (kp.ecKey && f.ec_key_free) {
        f.ec_key_free(kp.ecKey);
        kp.ecKey = nullptr;
    }
    kp.ok = false;
}

Vector<uint8_t> driftstackP256ComputeShared(const P256Keypair& kp, const Vector<uint8_t>& peerPublic)
{
    if (!kp.ok || !kp.ecKey || peerPublic.size() != 65 || peerPublic[0] != 0x04)
        return {};
    auto& f = cryptoFns();
    if (!f.ec_point_new || !f.ec_point_oct2point || !f.ecdh_compute_key || !f.ec_key_get0_group)
        return {};
    const void* group = f.ec_key_get0_group(kp.ecKey);
    void* peerPoint = f.ec_point_new(group);
    if (!peerPoint) return {};
    if (f.ec_point_oct2point(group, peerPoint, peerPublic.span().data(), peerPublic.size(), nullptr) != 1) {
        f.ec_point_free(peerPoint);
        return {};
    }
    Vector<uint8_t> shared(32);
    int rc = f.ecdh_compute_key(shared.mutableSpan().data(), 32, peerPoint, kp.ecKey, nullptr);
    f.ec_point_free(peerPoint);
    if (rc != 32) return {};
    return shared;
}

// === AES-256-GCM ===

Vector<uint8_t> driftstackAes256GcmEncrypt(const Vector<uint8_t>& key,
                                            const Vector<uint8_t>& nonce,
                                            const Vector<uint8_t>& plaintext,
                                            const Vector<uint8_t>& aad)
{
    auto& f = cryptoFns();
    return aeadEncrypt(f.evp_aead_aes_256_gcm ? f.evp_aead_aes_256_gcm() : nullptr,
                       key, nonce, plaintext, aad);
}

Vector<uint8_t> driftstackAes256GcmDecrypt(const Vector<uint8_t>& key,
                                            const Vector<uint8_t>& nonce,
                                            const Vector<uint8_t>& ciphertext,
                                            const Vector<uint8_t>& aad)
{
    auto& f = cryptoFns();
    return aeadDecrypt(f.evp_aead_aes_256_gcm ? f.evp_aead_aes_256_gcm() : nullptr,
                       key, nonce, ciphertext, aad);
}

// === HMAC-SHA384 ===

Vector<uint8_t> driftstackHmacSha384(const Vector<uint8_t>& key, const Vector<uint8_t>& data)
{
    if (!driftstackCryptoInit()) return {};
    auto& f = cryptoFns();
    if (!f.hmac || !f.evp_sha384) return {};
    Vector<uint8_t> out(48);
    unsigned int outLen = 48;
    f.hmac(f.evp_sha384(), key.span().data(), static_cast<int>(key.size()),
           data.span().data(), data.size(),
           out.mutableSpan().data(), &outLen);
    out.resize(outLen);
    return out;
}

// === Wave 29-499.186 — SHA-256 + AES-128-GCM variants for cipher 0x1301 ===

SHA256Ctx* driftstackCreateSHA256Ctx()
{
    if (!driftstackCryptoInit()) return nullptr;
    auto& f = cryptoFns();
    void* ctx = f.evp_md_ctx_new();
    if (ctx)
        f.evp_digestinit_ex(ctx, f.evp_sha256(), nullptr);
    return reinterpret_cast<SHA256Ctx*>(ctx);
}

void driftstackUpdateSHA256(SHA256Ctx* ctx, const uint8_t* data, size_t len)
{
    if (!ctx) return;
    cryptoFns().evp_digestupdate(reinterpret_cast<void*>(ctx), data, len);
}

Vector<uint8_t> driftstackFinalizeSHA256(SHA256Ctx* ctx)
{
    Vector<uint8_t> out(32);
    if (!ctx) return out;
    unsigned int outLen = 32;
    cryptoFns().evp_digestfinal_ex(reinterpret_cast<void*>(ctx), out.mutableSpan().data(), &outLen);
    cryptoFns().evp_md_ctx_free(reinterpret_cast<void*>(ctx));
    out.resize(outLen);
    return out;
}

Vector<uint8_t> driftstackCloneFinalizeSHA256(SHA256Ctx* ctx)
{
    Vector<uint8_t> out(32);
    if (!ctx) return out;
    auto& f = cryptoFns();
    void* tmp = f.evp_md_ctx_new();
    if (!tmp) return out;
    if (f.evp_md_ctx_copy_ex)
        f.evp_md_ctx_copy_ex(tmp, reinterpret_cast<const void*>(ctx));
    unsigned int outLen = 32;
    f.evp_digestfinal_ex(tmp, out.mutableSpan().data(), &outLen);
    f.evp_md_ctx_free(tmp);
    out.resize(outLen);
    return out;
}

void driftstackFreeSHA256Ctx(SHA256Ctx* ctx)
{
    if (ctx)
        cryptoFns().evp_md_ctx_free(reinterpret_cast<void*>(ctx));
}

Vector<uint8_t> driftstackSHA256(const uint8_t* data, size_t len)
{
    auto* ctx = driftstackCreateSHA256Ctx();
    if (!ctx) return {};
    driftstackUpdateSHA256(ctx, data, len);
    return driftstackFinalizeSHA256(ctx);
}

Vector<uint8_t> driftstackHkdfExtractSha256(const Vector<uint8_t>& salt,
                                            const Vector<uint8_t>& ikm)
{
    if (!driftstackCryptoInit()) return {};
    auto& f = cryptoFns();
    if (!f.hkdf_extract) return {};
    Vector<uint8_t> out(32);
    size_t outLen = 32;
    if (f.hkdf_extract(out.mutableSpan().data(), &outLen, f.evp_sha256(),
                       ikm.span().data(), ikm.size(),
                       salt.span().data(), salt.size()) != 1)
        return {};
    out.resize(outLen);
    return out;
}

Vector<uint8_t> driftstackHkdfExpandLabelSha256(const Vector<uint8_t>& secret,
                                                 const char* label,
                                                 const Vector<uint8_t>& context,
                                                 size_t outLen)
{
    if (!driftstackCryptoInit()) return {};
    auto& f = cryptoFns();
    if (!f.hkdf_expand) return {};
    Vector<uint8_t> hkdfLabel;
    hkdfLabel.append(static_cast<uint8_t>(outLen >> 8));
    hkdfLabel.append(static_cast<uint8_t>(outLen & 0xFF));
    const char* prefix = "tls13 ";
    size_t fullLabelLen = strlen(prefix) + strlen(label);
    hkdfLabel.append(static_cast<uint8_t>(fullLabelLen));
    hkdfLabel.append(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(prefix), strlen(prefix)));
    hkdfLabel.append(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(label), strlen(label)));
    hkdfLabel.append(static_cast<uint8_t>(context.size()));
    hkdfLabel.append(context.span());

    Vector<uint8_t> out(outLen);
    if (f.hkdf_expand(out.mutableSpan().data(), outLen, f.evp_sha256(),
                      secret.span().data(), secret.size(),
                      hkdfLabel.span().data(), hkdfLabel.size()) != 1)
        return {};
    return out;
}

Vector<uint8_t> driftstackHmacSha256(const Vector<uint8_t>& key, const Vector<uint8_t>& data)
{
    if (!driftstackCryptoInit()) return {};
    auto& f = cryptoFns();
    if (!f.hmac || !f.evp_sha256) return {};
    Vector<uint8_t> out(32);
    unsigned int outLen = 32;
    f.hmac(f.evp_sha256(), key.span().data(), static_cast<int>(key.size()),
           data.span().data(), data.size(),
           out.mutableSpan().data(), &outLen);
    out.resize(outLen);
    return out;
}

namespace {

[[maybe_unused]] Vector<uint8_t> aesGcmEncryptImpl(const void* cipher,
                                   const Vector<uint8_t>& key,
                                   const Vector<uint8_t>& nonce,
                                   const Vector<uint8_t>& plaintext,
                                   const Vector<uint8_t>& aad)
{
    if (!driftstackCryptoInit() || !cipher) return {};
    auto& f = cryptoFns();
    void* ctx = f.evp_cipher_ctx_new();
    if (!ctx) return {};
    f.evp_encryptinit_ex(ctx, cipher, nullptr, nullptr, nullptr);
    f.evp_cipher_ctx_ctrl(ctx, kEVPCtrlAEADSetIvLen, static_cast<int>(nonce.size()), nullptr);
    f.evp_encryptinit_ex(ctx, nullptr, nullptr, key.span().data(), nonce.span().data());
    int len = 0;
    if (aad.size())
        f.evp_encryptupdate(ctx, nullptr, &len, aad.span().data(), static_cast<int>(aad.size()));
    Vector<uint8_t> output(plaintext.size() + 16);
    int outLen = 0;
    f.evp_encryptupdate(ctx, output.mutableSpan().data(), &outLen, plaintext.span().data(), static_cast<int>(plaintext.size()));
    int finalLen = 0;
    f.evp_encryptfinal_ex(ctx, output.mutableSpan().data() + outLen, &finalLen);
    f.evp_cipher_ctx_ctrl(ctx, kEVPCtrlAEADGetTag, 16, output.mutableSpan().data() + outLen + finalLen);
    f.evp_cipher_ctx_free(ctx);
    output.resize(outLen + finalLen + 16);
    return output;
}

[[maybe_unused]] Vector<uint8_t> aesGcmDecryptImpl(const void* cipher,
                                   const Vector<uint8_t>& key,
                                   const Vector<uint8_t>& nonce,
                                   const Vector<uint8_t>& ciphertext,
                                   const Vector<uint8_t>& aad)
{
    if (!driftstackCryptoInit() || !cipher || ciphertext.size() < 16) return {};
    auto& f = cryptoFns();
    void* ctx = f.evp_cipher_ctx_new();
    if (!ctx) return {};
    size_t ctLen = ciphertext.size() - 16;
    const uint8_t* tag = ciphertext.span().data() + ctLen;
    f.evp_decryptinit_ex(ctx, cipher, nullptr, nullptr, nullptr);
    f.evp_cipher_ctx_ctrl(ctx, kEVPCtrlAEADSetIvLen, static_cast<int>(nonce.size()), nullptr);
    f.evp_decryptinit_ex(ctx, nullptr, nullptr, key.span().data(), nonce.span().data());
    int len = 0;
    if (aad.size())
        f.evp_decryptupdate(ctx, nullptr, &len, aad.span().data(), static_cast<int>(aad.size()));
    Vector<uint8_t> output(ctLen);
    int outLen = 0;
    f.evp_decryptupdate(ctx, output.mutableSpan().data(), &outLen, ciphertext.span().data(), static_cast<int>(ctLen));
    f.evp_cipher_ctx_ctrl(ctx, kEVPCtrlAEADSetTag, 16, const_cast<uint8_t*>(tag));
    int finalLen = 0;
    int rc = f.evp_decryptfinal_ex(ctx, output.mutableSpan().data() + outLen, &finalLen);
    f.evp_cipher_ctx_free(ctx);
    if (rc <= 0) return {};
    output.resize(outLen + finalLen);
    return output;
}
} // namespace

// Wave 29-499.297 — Manual AES-128-GCM implementation per NIST SP 800-38D.
// All Apple/LibreSSL high-level GCM APIs failed on macOS 26.2:
//   * LibreSSL EVP_AEAD: tag baaf8dd7… (wrong)
//   * LibreSSL EVP_Cipher: garbage "5000\0…" (wrong)
//   * Apple CCCryptorGCMOneshotEncrypt: rc=-4300 kCCParamError
//   * Apple CCCryptorCreateWithMode(kCCModeGCM): rc=-4305 kCCUnimplemented
// AES-128-ECB via LibreSSL AES_encrypt is verified correct (NIST test PASS).
// Build GCM on top of working ECB primitive.

namespace driftstack_gcm {

typedef void (*AesEncFn)(const uint8_t* in, uint8_t* out, const void* aesKey);
typedef int (*AesSetKeyFn)(const uint8_t* userKey, int bits, void* aesKey);

struct AesPrimitives {
    AesSetKeyFn setKey = nullptr;
    AesEncFn encrypt = nullptr;
    bool ready = false;
};

static AesPrimitives& aesPrim()
{
    static AesPrimitives p;
    return p;
}

static bool resolveAes()
{
    auto& p = aesPrim();
    if (p.ready) return true;
    // Wave .300 — explicitly dlopen libssl.48 BEFORE dlsym. If we use RTLD_DEFAULT
    // before libssl.48 is loaded, dlsym hits libwebrtc.dylib's bundled BoringSSL
    // AES_encrypt which has incompatible key-schedule format and produces wrong
    // ciphertext (cc96aeb8… instead of 66e94bd4… for AES_ECB(0, 0)).
    static void* hSsl = dlopen("/usr/lib/libssl.48.dylib", RTLD_NOW | RTLD_GLOBAL);
    if (!hSsl) {
        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.300] dlopen libssl.48 FAILED for AES resolution");
        return false;
    }
    p.setKey = reinterpret_cast<AesSetKeyFn>(dlsym(hSsl, "AES_set_encrypt_key"));
    p.encrypt = reinterpret_cast<AesEncFn>(dlsym(hSsl, "AES_encrypt"));
    p.ready = p.setKey && p.encrypt;
    WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.300] resolveAes from libssl.48: setKey=%p encrypt=%p ready=%d",
        (void*)p.setKey, (void*)p.encrypt, p.ready);
    return p.ready;
}

// GF(2^128) multiplication, NIST SP 800-38D §6.3 (right-shift method).
// Bytes are stored big-endian per GCM spec.
inline void gf128Mul(const uint8_t x[16], const uint8_t y[16], uint8_t out[16])
{
    uint8_t v[16];
    uint8_t z[16] = {0};
    memcpy(v, y, 16);
    for (int i = 0; i < 128; i++) {
        // bit i of x (MSB-first across bytes)
        int byte = i >> 3;
        int bit = 7 - (i & 7);
        if ((x[byte] >> bit) & 1) {
            for (int k = 0; k < 16; k++) z[k] ^= v[k];
        }
        // v = v >> 1, if lsb(v_pre) then v ^= R where R = 0xe1<<120
        bool lsb = v[15] & 1;
        for (int k = 15; k > 0; k--) {
            v[k] = (v[k] >> 1) | ((v[k - 1] & 1) << 7);
        }
        v[0] >>= 1;
        if (lsb) v[0] ^= 0xe1;
    }
    memcpy(out, z, 16);
}

inline void ghashUpdate(uint8_t y[16], const uint8_t* blocks, size_t numBlocks, const uint8_t h[16])
{
    for (size_t i = 0; i < numBlocks; i++) {
        for (int k = 0; k < 16; k++) y[k] ^= blocks[i * 16 + k];
        uint8_t tmp[16];
        gf128Mul(y, h, tmp);
        memcpy(y, tmp, 16);
    }
}

inline void incrCounter(uint8_t ctr[16])
{
    // Increment last 32-bit word (big-endian).
    for (int i = 15; i >= 12; i--) {
        ctr[i]++;
        if (ctr[i] != 0) break;
    }
}

} // namespace driftstack_gcm

Vector<uint8_t> driftstackAes128GcmEncrypt(const Vector<uint8_t>& key,
                                            const Vector<uint8_t>& nonce,
                                            const Vector<uint8_t>& plaintext,
                                            const Vector<uint8_t>& aad)
{
    using namespace driftstack_gcm;
    if (!resolveAes() || key.size() != 16 || nonce.size() != 12) {
        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.297] AES-GCM precondition fail (resolveAes=%d key=%zu nonce=%zu)",
            resolveAes(), key.size(), nonce.size());
        return {};
    }
    auto& p = aesPrim();

    // Wave .303 — log EVERY zero-key call to identify race/state corruption.
    bool isZeroKey = true;
    for (int i = 0; i < 16; i++) if (key.span().data()[i]) { isZeroKey = false; break; }

    alignas(16) uint8_t aesKey[512] = { };
    if (p.setKey(key.span().data(), 128, aesKey) != 0) {
        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.297] AES_set_encrypt_key failed");
        return {};
    }

    uint8_t zeroBlock[16] = { };
    uint8_t H[16] = { };
    p.encrypt(zeroBlock, H, aesKey);

    if (isZeroKey) {
        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.303] ZERO-KEY call (NIST test): nonce.size=%zu pt.size=%zu aad.size=%zu aesKey[0..15]=%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x H=%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x (expect H=66e94bd4ef8a2c3b884cfa59ca342b2e)",
            nonce.size(), plaintext.size(), aad.size(),
            aesKey[0],aesKey[1],aesKey[2],aesKey[3],aesKey[4],aesKey[5],aesKey[6],aesKey[7],
            aesKey[8],aesKey[9],aesKey[10],aesKey[11],aesKey[12],aesKey[13],aesKey[14],aesKey[15],
            H[0],H[1],H[2],H[3],H[4],H[5],H[6],H[7],H[8],H[9],H[10],H[11],H[12],H[13],H[14],H[15]);
    }

    // J0 for 96-bit IV: nonce || 0x00000001 (big-endian)
    uint8_t J0[16];
    memcpy(J0, nonce.span().data(), 12);
    J0[12] = 0; J0[13] = 0; J0[14] = 0; J0[15] = 1;

    // CTR mode: starting counter = J0+1, ..., for each 16-byte plaintext block.
    Vector<uint8_t> output(plaintext.size() + 16);
    uint8_t ctr[16];
    memcpy(ctr, J0, 16);
    size_t fullBlocks = plaintext.size() / 16;
    size_t tail = plaintext.size() % 16;
    for (size_t i = 0; i < fullBlocks; i++) {
        incrCounter(ctr);
        uint8_t ks[16];
        p.encrypt(ctr, ks, aesKey);
        for (int k = 0; k < 16; k++)
            output[i * 16 + k] = plaintext.span().data()[i * 16 + k] ^ ks[k];
    }
    if (tail) {
        incrCounter(ctr);
        uint8_t ks[16];
        p.encrypt(ctr, ks, aesKey);
        for (size_t k = 0; k < tail; k++)
            output[fullBlocks * 16 + k] = plaintext.span().data()[fullBlocks * 16 + k] ^ ks[k];
    }

    // GHASH(H, A || pad || C || pad || lenA||lenC)
    uint8_t Y[16] = {0};
    size_t aadBlocks = aad.size() / 16;
    size_t aadTail = aad.size() % 16;
    if (aadBlocks) ghashUpdate(Y, aad.span().data(), aadBlocks, H);
    if (aadTail) {
        uint8_t pad[16] = {0};
        memcpy(pad, aad.span().data() + aadBlocks * 16, aadTail);
        ghashUpdate(Y, pad, 1, H);
    }
    if (fullBlocks) ghashUpdate(Y, output.span().data(), fullBlocks, H);
    if (tail) {
        uint8_t pad[16] = {0};
        memcpy(pad, output.span().data() + fullBlocks * 16, tail);
        ghashUpdate(Y, pad, 1, H);
    }
    // Length block: lenA in bits BE u64 || lenC in bits BE u64
    uint8_t lenBlock[16];
    uint64_t lenAbits = uint64_t(aad.size()) * 8;
    uint64_t lenCbits = uint64_t(plaintext.size()) * 8;
    for (int i = 0; i < 8; i++) lenBlock[i] = uint8_t(lenAbits >> (56 - i * 8));
    for (int i = 0; i < 8; i++) lenBlock[8 + i] = uint8_t(lenCbits >> (56 - i * 8));
    ghashUpdate(Y, lenBlock, 1, H);

    // Tag = E_K(J0) ⊕ Y
    uint8_t EJ0[16];
    p.encrypt(J0, EJ0, aesKey);
    for (int k = 0; k < 16; k++)
        output[plaintext.size() + k] = EJ0[k] ^ Y[k];

    return output;
}

Vector<uint8_t> driftstackAes128GcmDecrypt(const Vector<uint8_t>& key,
                                            const Vector<uint8_t>& nonce,
                                            const Vector<uint8_t>& ciphertext,
                                            const Vector<uint8_t>& aad)
{
    using namespace driftstack_gcm;
    if (!resolveAes() || key.size() != 16 || nonce.size() != 12 || ciphertext.size() < 16)
        return {};
    auto& p = aesPrim();

    uint8_t aesKey[256] = { };
    if (p.setKey(key.span().data(), 128, aesKey) != 0)
        return {};

    uint8_t zeroBlock[16] = { };
    uint8_t H[16] = { };
    p.encrypt(zeroBlock, H, aesKey);

    uint8_t J0[16];
    memcpy(J0, nonce.span().data(), 12);
    J0[12] = 0; J0[13] = 0; J0[14] = 0; J0[15] = 1;

    size_t ctLen = ciphertext.size() - 16;
    const uint8_t* tag = ciphertext.span().data() + ctLen;

    // GHASH FIRST (over ciphertext, before CTR decrypts it).
    uint8_t Y[16] = {0};
    size_t aadBlocks = aad.size() / 16;
    size_t aadTail = aad.size() % 16;
    if (aadBlocks) ghashUpdate(Y, aad.span().data(), aadBlocks, H);
    if (aadTail) {
        uint8_t pad[16] = {0};
        memcpy(pad, aad.span().data() + aadBlocks * 16, aadTail);
        ghashUpdate(Y, pad, 1, H);
    }
    size_t fullBlocks = ctLen / 16;
    size_t tail = ctLen % 16;
    if (fullBlocks) ghashUpdate(Y, ciphertext.span().data(), fullBlocks, H);
    if (tail) {
        uint8_t pad[16] = {0};
        memcpy(pad, ciphertext.span().data() + fullBlocks * 16, tail);
        ghashUpdate(Y, pad, 1, H);
    }
    uint8_t lenBlock[16];
    uint64_t lenAbits = uint64_t(aad.size()) * 8;
    uint64_t lenCbits = uint64_t(ctLen) * 8;
    for (int i = 0; i < 8; i++) lenBlock[i] = uint8_t(lenAbits >> (56 - i * 8));
    for (int i = 0; i < 8; i++) lenBlock[8 + i] = uint8_t(lenCbits >> (56 - i * 8));
    ghashUpdate(Y, lenBlock, 1, H);

    uint8_t EJ0[16];
    p.encrypt(J0, EJ0, aesKey);
    uint8_t expectedTag[16];
    for (int k = 0; k < 16; k++)
        expectedTag[k] = EJ0[k] ^ Y[k];

    // Constant-time tag compare.
    uint8_t diff = 0;
    for (int k = 0; k < 16; k++) diff |= expectedTag[k] ^ tag[k];
    if (diff) return {};

    // CTR decrypt.
    Vector<uint8_t> output(ctLen);
    uint8_t ctr[16];
    memcpy(ctr, J0, 16);
    for (size_t i = 0; i < fullBlocks; i++) {
        incrCounter(ctr);
        uint8_t ks[16];
        p.encrypt(ctr, ks, aesKey);
        for (int k = 0; k < 16; k++)
            output[i * 16 + k] = ciphertext.span().data()[i * 16 + k] ^ ks[k];
    }
    if (tail) {
        incrCounter(ctr);
        uint8_t ks[16];
        p.encrypt(ctr, ks, aesKey);
        for (size_t k = 0; k < tail; k++)
            output[fullBlocks * 16 + k] = ciphertext.span().data()[fullBlocks * 16 + k] ^ ks[k];
    }
    return output;
}

// Wave 29-499.276 — ChaCha20-Poly1305 AEAD for QUIC cipher 0x1303
// + TLS 1.3 fallback. Some QUIC servers prefer ChaCha20 for mobile clients
// even when AES-NI is available (heuristic by remote OS hint).
Vector<uint8_t> driftstackChacha20Poly1305Encrypt(const Vector<uint8_t>& key,
                                                   const Vector<uint8_t>& nonce,
                                                   const Vector<uint8_t>& plaintext,
                                                   const Vector<uint8_t>& aad)
{
    auto& f = cryptoFns();
    return aeadEncrypt(f.evp_aead_chacha20_poly1305 ? f.evp_aead_chacha20_poly1305() : nullptr,
                       key, nonce, plaintext, aad);
}

Vector<uint8_t> driftstackChacha20Poly1305Decrypt(const Vector<uint8_t>& key,
                                                   const Vector<uint8_t>& nonce,
                                                   const Vector<uint8_t>& ciphertext,
                                                   const Vector<uint8_t>& aad)
{
    auto& f = cryptoFns();
    return aeadDecrypt(f.evp_aead_chacha20_poly1305 ? f.evp_aead_chacha20_poly1305() : nullptr,
                       key, nonce, ciphertext, aad);
}

} // namespace WebKit

WTF_ALLOW_UNSAFE_BUFFER_USAGE_END

#endif // PLATFORM(DRIFTSTACK)
