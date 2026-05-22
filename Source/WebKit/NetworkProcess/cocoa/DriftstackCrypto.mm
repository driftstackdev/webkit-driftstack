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

#import <dispatch/dispatch.h>
#import <dlfcn.h>
#import <stdlib.h>
#import <string.h>
#import <wtf/Assertions.h>

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

    // EVP_PKEY for X25519
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

    // AES-GCM
    const void* (*evp_aes_256_gcm)(void) = nullptr;
    void* (*evp_cipher_ctx_new)(void) = nullptr;
    void (*evp_cipher_ctx_free)(void*) = nullptr;
    int (*evp_encryptinit_ex)(void* ctx, const void* cipher, void* e, const uint8_t* key, const uint8_t* iv) = nullptr;
    int (*evp_decryptinit_ex)(void* ctx, const void* cipher, void* e, const uint8_t* key, const uint8_t* iv) = nullptr;
    int (*evp_cipher_ctx_ctrl)(void* ctx, int type, int arg, void* ptr) = nullptr;
    int (*evp_encryptupdate)(void* ctx, uint8_t* out, int* outLen, const uint8_t* in, int inLen) = nullptr;
    int (*evp_decryptupdate)(void* ctx, uint8_t* out, int* outLen, const uint8_t* in, int inLen) = nullptr;
    int (*evp_encryptfinal_ex)(void* ctx, uint8_t* out, int* outLen) = nullptr;
    int (*evp_decryptfinal_ex)(void* ctx, uint8_t* out, int* outLen) = nullptr;

    bool ready = false;
};

CryptoFns& cryptoFns()
{
    static CryptoFns f;
    return f;
}

const int kEVPPkeyX25519 = 1034;  // NID_X25519 (LibreSSL)
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
        void* hCrypto = dlopen("/usr/lib/libcrypto.48.dylib", RTLD_NOW | RTLD_GLOBAL);
        void* hSsl = dlopen("/usr/lib/libssl.48.dylib", RTLD_NOW | RTLD_GLOBAL);
        if (!hCrypto || !hSsl) {
            WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.173] dlopen failed (crypto=%p ssl=%p)", hCrypto, hSsl);
            return;
        }

        void* h = hCrypto;
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
        R(evp_aes_256_gcm, "EVP_aes_256_gcm");
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
const int kEVPPkeyOpDerive = (1 << 10);
const int kEVPPkeyCtrlHkdfMode = 0x1000;
const int kEVPPkeyCtrlHkdfSalt = 0x1001;
const int kEVPPkeyCtrlHkdfKey = 0x1002;
const int kEVPPkeyCtrlHkdfInfo = 0x1003;
const int kEVPPkeyCtrlHkdfMd = 0x1004;
const int kEVPHkdfExtractAndExpand = 0;
const int kEVPHkdfExtractOnly = 1;
const int kEVPHkdfExpandOnly = 2;

Vector<uint8_t> hkdfDerive(int mode, const void* md,
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
    return hkdfDerive(kEVPHkdfExtractOnly, cryptoFns().evp_sha384(), salt, ikm, {}, 48);
}

Vector<uint8_t> driftstackHkdfExpandLabelSha384(const Vector<uint8_t>& secret,
                                                 const char* label,
                                                 const Vector<uint8_t>& context,
                                                 size_t outLen)
{
    if (!driftstackCryptoInit()) return {};
    // Build HkdfLabel per RFC 8446 §7.1:
    //   u16 length, opaque label<7..255> ("tls13 " + label), opaque context<0..255>
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
    return hkdfDerive(kEVPHkdfExpandOnly, cryptoFns().evp_sha384(), {}, secret, hkdfLabel, outLen);
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
    void* ctx = f.evp_pkey_ctx_new_id(kEVPPkeyX25519, nullptr);
    if (!ctx) return false;
    if (f.evp_pkey_keygen_init(ctx) <= 0) { f.evp_pkey_ctx_free(ctx); return false; }
    void* pkey = nullptr;
    if (f.evp_pkey_keygen(ctx, &pkey) <= 0) { f.evp_pkey_ctx_free(ctx); return false; }
    f.evp_pkey_ctx_free(ctx);

    outPrivate.resize(32); size_t privLen = 32;
    outPublic.resize(32); size_t pubLen = 32;
    f.evp_pkey_get_raw_private_key(pkey, outPrivate.mutableSpan().data(), &privLen);
    f.evp_pkey_get_raw_public_key(pkey, outPublic.mutableSpan().data(), &pubLen);
    f.evp_pkey_free(pkey);
    outPrivate.resize(privLen);
    outPublic.resize(pubLen);
    return outPrivate.size() == 32 && outPublic.size() == 32;
}

Vector<uint8_t> driftstackX25519SharedSecret(const Vector<uint8_t>& ourPrivate,
                                               const Vector<uint8_t>& peerPublic)
{
    if (!driftstackCryptoInit()) return {};
    auto& f = cryptoFns();
    void* ourKey = f.evp_pkey_new_raw_private_key(kEVPPkeyX25519, nullptr, ourPrivate.span().data(), ourPrivate.size());
    void* peerKey = f.evp_pkey_new_raw_public_key(kEVPPkeyX25519, nullptr, peerPublic.span().data(), peerPublic.size());
    if (!ourKey || !peerKey) {
        if (ourKey) f.evp_pkey_free(ourKey);
        if (peerKey) f.evp_pkey_free(peerKey);
        return {};
    }
    void* ctx = f.evp_pkey_ctx_new(ourKey, nullptr);
    f.evp_pkey_derive_init(ctx);
    f.evp_pkey_derive_set_peer(ctx, peerKey);
    Vector<uint8_t> shared(32);
    size_t sharedLen = 32;
    f.evp_pkey_derive(ctx, shared.mutableSpan().data(), &sharedLen);
    f.evp_pkey_ctx_free(ctx);
    f.evp_pkey_free(ourKey);
    f.evp_pkey_free(peerKey);
    shared.resize(sharedLen);
    return shared;
}

// === AES-256-GCM ===

Vector<uint8_t> driftstackAes256GcmEncrypt(const Vector<uint8_t>& key,
                                            const Vector<uint8_t>& nonce,
                                            const Vector<uint8_t>& plaintext,
                                            const Vector<uint8_t>& aad)
{
    if (!driftstackCryptoInit()) return {};
    auto& f = cryptoFns();
    void* ctx = f.evp_cipher_ctx_new();
    if (!ctx) return {};

    f.evp_encryptinit_ex(ctx, f.evp_aes_256_gcm(), nullptr, nullptr, nullptr);
    f.evp_cipher_ctx_ctrl(ctx, kEVPCtrlAEADSetIvLen, static_cast<int>(nonce.size()), nullptr);
    f.evp_encryptinit_ex(ctx, nullptr, nullptr, key.span().data(), nonce.span().data());

    int len = 0;
    // AAD
    if (aad.size())
        f.evp_encryptupdate(ctx, nullptr, &len, aad.span().data(), static_cast<int>(aad.size()));

    Vector<uint8_t> output(plaintext.size() + 16);
    int outLen = 0;
    f.evp_encryptupdate(ctx, output.mutableSpan().data(), &outLen, plaintext.span().data(), static_cast<int>(plaintext.size()));
    int finalLen = 0;
    f.evp_encryptfinal_ex(ctx, output.mutableSpan().data() + outLen, &finalLen);
    // Get tag (16 bytes)
    f.evp_cipher_ctx_ctrl(ctx, kEVPCtrlAEADGetTag, 16, output.mutableSpan().data() + outLen + finalLen);
    f.evp_cipher_ctx_free(ctx);

    output.resize(outLen + finalLen + 16);
    return output;
}

Vector<uint8_t> driftstackAes256GcmDecrypt(const Vector<uint8_t>& key,
                                            const Vector<uint8_t>& nonce,
                                            const Vector<uint8_t>& ciphertext,
                                            const Vector<uint8_t>& aad)
{
    if (!driftstackCryptoInit() || ciphertext.size() < 16) return {};
    auto& f = cryptoFns();
    void* ctx = f.evp_cipher_ctx_new();
    if (!ctx) return {};

    size_t ctLen = ciphertext.size() - 16;  // last 16 bytes are tag
    const uint8_t* tag = ciphertext.span().data() + ctLen;

    f.evp_decryptinit_ex(ctx, f.evp_aes_256_gcm(), nullptr, nullptr, nullptr);
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
    if (rc <= 0) {
        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.173] AES-GCM auth failed");
        return {};
    }
    output.resize(outLen + finalLen);
    return output;
}

} // namespace WebKit

WTF_ALLOW_UNSAFE_BUFFER_USAGE_END

#endif // PLATFORM(DRIFTSTACK)
