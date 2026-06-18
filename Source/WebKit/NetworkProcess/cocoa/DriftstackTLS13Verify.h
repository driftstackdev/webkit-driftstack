// DriftstackTLS13Verify.h — W2202 cert-validation Landing 3: CertificateVerify (0x0f) signature verification.
//
// Shared by the h2 (DriftstackTLS13Client) and h3 (DriftstackHttp3) custom-TLS PathB egress paths. Binds the
// chain validated in Landing 1/2 to the key that actually finished the handshake (RFC 8446 §4.4.3) — defeats a
// MITM replaying a valid-for-host certificate it does NOT hold the private key for. The per-scheme
// SecKeyAlgorithm mapping lives in exactly one place here so both paths stay in lockstep.

#pragma once

#import <Security/Security.h>
#import <span>
#import <wtf/Vector.h>
#import <wtf/text/WTFString.h>

namespace WebKit {

// Verify a TLS 1.3 server CertificateVerify signature.
//   leaf                      - the server leaf certificate (its public key is extracted via SecCertificateCopyKey).
//   sig                       - the raw signature bytes from the CertificateVerify message.
//   sigScheme                 - the 2-byte TLS SignatureScheme value (host byte order).
//   transcriptHashThroughCert - Transcript-Hash(ClientHello .. Certificate), the RAW digest (not hex), computed
//                               by the caller BEFORE CertificateVerify was appended to the transcript.
//   isServerContext           - true for a server CertificateVerify (the only case the egress client verifies).
// Returns true ONLY if the signature verifies. Returns false (FAIL-CLOSED) and sets outError on any
// unsupported/forbidden scheme, missing public key, malformed input, or verification failure.
bool driftstackVerifyCertificateVerify(SecCertificateRef leaf, std::span<const uint8_t> sig, uint16_t sigScheme,
    const Vector<uint8_t>& transcriptHashThroughCert, bool isServerContext, String& outError);

} // namespace WebKit
