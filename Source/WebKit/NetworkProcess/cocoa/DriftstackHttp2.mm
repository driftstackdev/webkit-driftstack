/*
 * DriftstackHttp2.mm — Wave 29-499.140 (Task #104 Phase 2)
 *
 * Minimal RFC 7540 HTTP/2 client. Sends iPhone-Safari-bit-identical
 * SETTINGS + WINDOW_UPDATE + HEADERS sequence, executes one request,
 * returns full response.
 *
 * Implementation notes:
 *  - Frame format: 9 bytes header (length:24, type:8, flags:8, streamId:32)
 *    + payload[0..length]
 *  - HPACK (RFC 7541): minimal static-table encoding for known iPhone
 *    Safari headers. No dynamic table updates from us (size=0). Server's
 *    HEADERS responses parsed via static-table decode + literal headers.
 *  - SSL_read / SSL_write through dlsym table (defined in
 *    DriftstackNetworkLoader.mm). For this Phase 2 scaffold, we expect
 *    caller to provide pre-resolved function pointers OR we resolve
 *    locally via dlsym(RTLD_DEFAULT, ...).
 */

#import "config.h"
#import "DriftstackHttp2.h"

#if PLATFORM(DRIFTSTACK)

#import "DriftstackTLS13Client.h"
#import "DriftstackSocks5Client.h"

#import <compression.h>
#import <dlfcn.h>
#import <zlib.h>  // Wave 29-499.263 — system libz for gzip/deflate decode
#import "zstd/zstd.h"  // W1515 — vendored zstd v1.5.7 decompressor for Content-Encoding: zstd
#import <wtf/Assertions.h>
#import <wtf/MonotonicTime.h>
#import <wtf/StdLibExtras.h>
#import <wtf/text/CString.h>
#import <wtf/text/MakeString.h>
#import <wtf/text/StringBuilder.h>  // Wave 29-499.266 — header dump diagnostic

WTF_ALLOW_UNSAFE_BUFFER_USAGE_BEGIN

namespace WebKit {

namespace {

// HTTP/2 connection preface (RFC 7540 §3.5)
static const char kHttp2Preface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

// Frame types (RFC 7540 §6)
enum FrameType : uint8_t {
    kFrameData          = 0x0,
    kFrameHeaders       = 0x1,
    kFramePriority      = 0x2,
    kFrameRstStream     = 0x3,
    kFrameSettings      = 0x4,
    kFramePushPromise   = 0x5,
    kFramePing          = 0x6,
    kFrameGoaway        = 0x7,
    kFrameWindowUpdate  = 0x8,
    kFrameContinuation  = 0x9,
};

// Frame flags
enum FrameFlag : uint8_t {
    kFlagEndStream      = 0x1,
    kFlagAck            = 0x1,  // For SETTINGS / PING
    kFlagEndHeaders     = 0x4,
    kFlagPadded         = 0x8,
    kFlagPriority       = 0x20,
};

// W2415 — receive-side per-frame size cap. We advertise NO SETTINGS_MAX_FRAME_SIZE (matching the
// real-iPhone akamai SETTINGS fingerprint: 2,3,4,9), so the default 16384 applies and a compliant
// server MUST NOT send a frame whose payload exceeds it (RFC 7540 §4.2 — else FRAME_SIZE_ERROR).
// Without a cap the loop `payload.resize(length)`'d an attacker-chosen 24-bit length (up to 16MB)
// per frame off a malicious/compromised upstream — a transient over-alloc + slowloris buffer.
// The RFC 8441 ConnectStream paths already cap at kMaxConnectFrameBytes (1MB); the one-shot +
// pooled request loops did not. Cap them at the same 1MB (well above any legit 16384 frame, so it
// never rejects compliant traffic — only a non-compliant oversized frame).
static constexpr uint32_t kMaxRecvFrameBytes = 1u << 20;

// Mid-stream flow-control WINDOW_UPDATE cadence (iOS-faithful, gt-registry
// http2_windowupdate_midstream_cadence). On a download LARGER than our receive
// window, a real iPhone re-opens its windows on a WINDOW-FRACTION schedule, NOT
// at a fixed byte count: it replenishes the STREAM window when ~1/4 of the
// 2 MiB stream window is consumed, and the CONNECTION window when ~1/2 of the
// ~10 MiB connection window is consumed (captured ×2 on iPhone 17/iOS 18.7/
// Safari 26.5: first stream WINDOW_UPDATE at byte 2097152 then every ~507900 =
// 2097152/4 minus one max-frame; connection every ~5259237 = 10485760/2). These
// are DERIVED from our OWN advertised receive windows (kSettingInitialWindowSize
// 2097152 + the +10420225 connection bump = 10485760 connection), so changing the
// window also moves the cadence coherently. The previous fixed 1 MiB (1u<<20) on
// BOTH stream and connection was an invented heuristic that matched neither.
// NUANCE (captured, modeled as window/4 here): iOS fires its FIRST stream update
// only after the full 2 MiB initial window is consumed (at byte 2097152), then
// switches to the ~window/4 incremental cadence; emitting the first at window/4
// is a slightly earlier first update. This window/4 constant captures the
// dominant per-update increment fingerprint; first-at-full is a second-order
// refinement (add a per-stream "first update fired" flag if a detector ever
// scores the first-update offset specifically).
static constexpr uint32_t kDriftstackStreamRecvWindow     = 2097152;  // our SETTINGS INITIAL_WINDOW_SIZE
static constexpr uint32_t kDriftstackConnRecvWindow       = 10485760; // 65535 + the +10420225 connection bump
static constexpr uint32_t kDriftstackStreamWUThreshold    = kDriftstackStreamRecvWindow / 4; // 524288 (~ iOS stream/4 cadence)
static constexpr uint32_t kDriftstackConnWUThreshold      = kDriftstackConnRecvWindow / 2;   // 5242880 (~ iOS conn/2 cadence)

// SETTINGS identifiers (RFC 7540 §6.5.2)
enum SettingsId : uint16_t {
    kSettingHeaderTableSize       = 0x1,
    kSettingEnablePush            = 0x2,
    kSettingMaxConcurrentStreams  = 0x3,
    kSettingInitialWindowSize     = 0x4,
    kSettingMaxFrameSize          = 0x5,
    kSettingMaxHeaderListSize     = 0x6,
    kSettingEnableConnectProtocol = 0x8,  // RFC 8441 — WS-over-h2 Extended CONNECT
    kSettingNoRfc7540Priorities   = 0x9,
};

// SSL function pointer table (dlsym-resolved on first use)
typedef int (*FnSSL_read)(void*, void*, int);
typedef int (*FnSSL_write)(void*, const void*, int);
struct SSLFns {
    FnSSL_read read = nullptr;
    FnSSL_write write = nullptr;
    bool ready = false;
};

static SSLFns& sslFns()
{
    static SSLFns s;
    // SEC-2026-06-18 (audit INFO): dispatch_once removes the formal first-use data race on the non-atomic
    // s.ready flag/pointers (benign — idempotent dlsym, identical word-aligned writes on arm64 — but TSan-flagged).
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        // Wave 29-499.167 — dlsym from Apple's /usr/lib/libssl.48.dylib
        // (LibreSSL 3.3.6 — iPhone-compatible TLS with 3DES support).
        // SSL* type and read/write ABI come from same library as
        // DriftstackNetworkLoader's TLS handshake.
        void* h = dlopen("/usr/lib/libssl.48.dylib", RTLD_NOW | RTLD_GLOBAL);
        if (!h) h = dlopen("libssl.48.dylib", RTLD_NOW | RTLD_GLOBAL);
        if (h) {
            s.read = (FnSSL_read)dlsym(h, "SSL_read");
            s.write = (FnSSL_write)dlsym(h, "SSL_write");
            s.ready = s.read && s.write;
            WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.164] DriftstackHttp2 SSL fns from libwebrtc: read=%p write=%p ready=%d",
                (void*)s.read, (void*)s.write, s.ready);
        }
    });
    return s;
}

// Wave 29-499.349 — per-connection transport routing. When `transport` is
// non-null (custom-TLS path, DriftstackTLS13Client, ssl==sentinel) reads/writes
// dispatch through its callbacks; otherwise via SSL_read/SSL_write on `ssl`.
// Passed EXPLICITLY (no thread_local) so concurrent cross-origin requests on
// reused GCD threads can't clobber each other's routing — root fix for
// V-XORIGIN-FETCH-CONCURRENCY-RACE (6 concurrent fetches completed TLS but
// 0 delivered, erratic by run, because the bridge routed via thread_local).

// Read N bytes from the connection; returns false on error/EOF.
static bool sslReadExact(void* ssl, const DriftstackHttp2Transport* transport, uint8_t* buf, size_t n)
{
    if (transport && transport->readFn) {
        size_t got = 0;
        while (got < n) {
            int rc = transport->readFn(transport->ctx, buf + got, n - got);
            if (rc <= 0) return false;
            got += rc;
        }
        return true;
    }
    auto& f = sslFns();
    if (!f.ready) return false;
    size_t got = 0;
    while (got < n) {
        int rc = f.read(ssl, buf + got, static_cast<int>(n - got));
        if (rc <= 0) return false;
        got += rc;
    }
    return true;
}

static bool sslWriteAll(void* ssl, const DriftstackHttp2Transport* transport, const uint8_t* buf, size_t n)
{
    if (transport && transport->writeFn) {
        size_t sent = 0;
        while (sent < n) {
            int rc = transport->writeFn(transport->ctx, buf + sent, n - sent);
            if (rc <= 0) return false;
            sent += rc;
        }
        return true;
    }
    auto& f = sslFns();
    if (!f.ready) return false;
    size_t sent = 0;
    while (sent < n) {
        int rc = f.write(ssl, buf + sent, static_cast<int>(n - sent));
        if (rc <= 0) return false;
        sent += rc;
    }
    return true;
}

// Encode 9-byte H/2 frame header into buf (must be >= 9 bytes).
static void encodeFrameHeader(uint8_t* buf, uint32_t length, uint8_t type, uint8_t flags, uint32_t streamId)
{
    buf[0] = (length >> 16) & 0xff;
    buf[1] = (length >> 8) & 0xff;
    buf[2] = length & 0xff;
    buf[3] = type;
    buf[4] = flags;
    buf[5] = (streamId >> 24) & 0x7f;  // top bit = reserved
    buf[6] = (streamId >> 16) & 0xff;
    buf[7] = (streamId >> 8) & 0xff;
    buf[8] = streamId & 0xff;
}

// Parse 9-byte H/2 frame header. Returns true on success.
static bool decodeFrameHeader(const uint8_t* buf, uint32_t& length, uint8_t& type, uint8_t& flags, uint32_t& streamId)
{
    length = (uint32_t(buf[0]) << 16) | (uint32_t(buf[1]) << 8) | uint32_t(buf[2]);
    type = buf[3];
    flags = buf[4];
    streamId = (uint32_t(buf[5] & 0x7f) << 24) | (uint32_t(buf[6]) << 16) | (uint32_t(buf[7]) << 8) | uint32_t(buf[8]);
    return true;
}

// HPACK static table (RFC 7541 Appendix A) — partial list of entries used
// by typical browsers. Index 1-61.
static const std::pair<const char*, const char*> kHpackStatic[] = {
    { nullptr, nullptr },  // index 0 unused
    { ":authority", "" },
    { ":method", "GET" },
    { ":method", "POST" },
    { ":path", "/" },
    { ":path", "/index.html" },
    { ":scheme", "http" },
    { ":scheme", "https" },
    { ":status", "200" },
    { ":status", "204" },
    { ":status", "206" },
    { ":status", "304" },
    { ":status", "400" },
    { ":status", "404" },
    { ":status", "500" },
    { "accept-charset", "" },
    // Wave 29-499.262 — re-enabled gzip+deflate+br after fixing streaming
    // decoder via compression_stream API.
    // ⚠ egress audit wxzzaphvp (HIGH): this is the HPACK static table (RFC 7541 Appendix A) — a
    // FIXED codebook shared by client encoder AND server decoder; entry 16 MUST be the RFC value.
    // It was wrongly set to the iPhone Accept-Encoding "gzip, deflate, br, zstd", so hpackFindFullMatch
    // encoded the client's Accept-Encoding as a bare index 16, which EVERY server decodes as its own
    // RFC slot-16 value "gzip, deflate" → the server withholds br/zstd AND it is a wire tell (real
    // Safari emits a literal value with an indexed name, since its value is not in the static table).
    // The advertised Accept-Encoding is set independently via driftstackPathBAcceptEncoding()
    // (DriftstackNetworkLoader.mm request extraHeaders) — unaffected by this codebook entry. With the
    // RFC value here, hpackFindFullMatch no longer full-matches and the encoder correctly falls to
    // name-index-16 + literal value; the decoder resolves a server's index 16 to the correct "gzip, deflate".
    // (Fork still advertises + decodes zstd: vendored libzstd in driftstackDecodeContentEncoding /
    //  driftstackDecompressHttp3Body, W1513/W1514 bit-exact — the advertise path is separate from this table.)
    { "accept-encoding", "gzip, deflate" },
    { "accept-language", "" },
    { "accept-ranges", "" },
    { "accept", "" },
    { "access-control-allow-origin", "" },
    { "age", "" },
    { "allow", "" },
    { "authorization", "" },
    { "cache-control", "" },
    { "content-disposition", "" },
    { "content-encoding", "" },
    { "content-language", "" },
    { "content-length", "" },
    { "content-location", "" },
    { "content-range", "" },
    { "content-type", "" },
    { "cookie", "" },
    { "date", "" },
    { "etag", "" },
    { "expect", "" },
    { "expires", "" },
    { "from", "" },
    { "host", "" },
    { "if-match", "" },
    { "if-modified-since", "" },
    { "if-none-match", "" },
    { "if-range", "" },
    { "if-unmodified-since", "" },
    { "last-modified", "" },
    { "link", "" },
    { "location", "" },
    { "max-forwards", "" },
    { "proxy-authenticate", "" },
    { "proxy-authorization", "" },
    { "range", "" },
    { "referer", "" },
    { "refresh", "" },
    { "retry-after", "" },
    { "server", "" },
    { "set-cookie", "" },
    { "strict-transport-security", "" },
    { "transfer-encoding", "" },
    { "user-agent", "" },
    { "vary", "" },
    { "via", "" },
    { "www-authenticate", "" },
};
static const int kHpackStaticCount = sizeof(kHpackStatic) / sizeof(kHpackStatic[0]);

// HPACK integer encoding (RFC 7541 §5.1). Writes prefix-padded integer
// to `out`. Returns number of bytes written.
static size_t hpackEncodeInteger(Vector<uint8_t>& out, uint32_t value, int prefixBits, uint8_t prefixHigh)
{
    size_t initialSize = out.size();
    uint32_t maxPrefix = (1U << prefixBits) - 1;
    if (value < maxPrefix) {
        out.append(static_cast<uint8_t>(prefixHigh | value));
    } else {
        out.append(static_cast<uint8_t>(prefixHigh | maxPrefix));
        value -= maxPrefix;
        while (value >= 128) {
            out.append(static_cast<uint8_t>((value & 0x7f) | 0x80));
            value >>= 7;
        }
        out.append(static_cast<uint8_t>(value));
    }
    return out.size() - initialSize;
}

// Forward decls — the Huffman code table (kHpackHuffmanTable) and the per-byte
// bit-length helper are defined alongside the DECODER lower in this file (RFC 7541
// Appendix B). Declared here so the literal-string ENCODER can Huffman-compress.
static size_t hpackHuffmanEncodedLength(const CString&);
static void hpackHuffmanEncodeBytes(Vector<uint8_t>& out, const CString&);

// RFC 7541 §5.2 — emit a Huffman-encoded HPACK literal (H bit set in the length
// prefix). Used by hpackEncodeString when Huffman is shorter than raw.
static void hpackEncodeHuffmanString(Vector<uint8_t>& out, const CString& utf8)
{
    size_t huffLen = hpackHuffmanEncodedLength(utf8);
    hpackEncodeInteger(out, huffLen, 7, 0x80);  // H bit = 1
    hpackHuffmanEncodeBytes(out, utf8);
}

// HPACK string literal encoding (RFC 7541 §5.2): length-prefixed octets, optionally
// Huffman-compressed. Real iOS Safari (CFNetwork h2) Huffman-encodes every literal
// name and value when the Huffman form is shorter (verified: the captured iPhone
// HEADERS frame length matches Huffman-of-names+values to the byte; raw plaintext
// is ~25% larger — a sub-akamai raw-HPACK wire tell). Gated for safety: when OFF
// the legacy raw-plaintext path is used unchanged.
static void hpackEncodeString(Vector<uint8_t>& out, const String& s)
{
    auto utf8 = s.utf8();
    // DRIFTSTACK_H2_HPACK_HUFFMAN: iOS-faithful Huffman literal compression.
    // Default OFF pending A3 on-box build-verify — this changes EVERY h2 request's
    // header bytes, so a regression would break all h2 (the server must Huffman-
    // decode, which standard h2 servers do). When ON, apply the canonical heuristic
    // (Huffman only when strictly shorter; ties → raw, matching nghttp2/CFNetwork).
    static const bool huffmanEnabled = getenv("DRIFTSTACK_H2_HPACK_HUFFMAN") != nullptr;
    if (huffmanEnabled) {
        size_t huffLen = hpackHuffmanEncodedLength(utf8);
        if (huffLen < utf8.length()) {
            hpackEncodeHuffmanString(out, utf8);
            return;
        }
    }
    hpackEncodeInteger(out, utf8.length(), 7, 0x00);  // huffman flag = 0 (raw)
    for (size_t i = 0; i < utf8.length(); ++i)
        out.append(static_cast<uint8_t>(utf8.data()[i]));
}

// Find static-table index for (name, value). Returns 0 if not found.
static int hpackFindFullMatch(const String& name, const String& value)
{
    auto nameUtf8 = name.utf8();
    auto valueUtf8 = value.utf8();
    for (int i = 1; i < kHpackStaticCount; ++i) {
        if (!strcmp(kHpackStatic[i].first, nameUtf8.data()) && !strcmp(kHpackStatic[i].second, valueUtf8.data()))
            return i;
    }
    return 0;
}

static int hpackFindNameOnly(const String& name)
{
    auto nameUtf8 = name.utf8();
    for (int i = 1; i < kHpackStaticCount; ++i) {
        if (!strcmp(kHpackStatic[i].first, nameUtf8.data()))
            return i;
    }
    return 0;
}

// Encode one header (name, value) into HPACK block.
static void hpackEncodeHeader(Vector<uint8_t>& out, const String& name, const String& value)
{
    int fullIdx = hpackFindFullMatch(name, value);
    if (fullIdx > 0) {
        hpackEncodeInteger(out, fullIdx, 7, 0x80);
        return;
    }
    int nameIdx = hpackFindNameOnly(name);
    if (nameIdx > 0) {
        hpackEncodeInteger(out, nameIdx, 4, 0x00);
        hpackEncodeString(out, value);
    } else {
        out.append(0x00);
        hpackEncodeString(out, name);
        hpackEncodeString(out, value);
    }
}

// HPACK integer decoding (RFC 7541 §5.1). Returns true on success, advances cursor.
static bool hpackDecodeInteger(const uint8_t* data, size_t len, size_t& cursor, int prefixBits, uint32_t& value)
{
    if (cursor >= len) return false;
    uint32_t maxPrefix = (1U << prefixBits) - 1;
    uint8_t prefix = data[cursor] & maxPrefix;
    cursor++;
    if (prefix < maxPrefix) {
        value = prefix;
        return true;
    }
    value = prefix;
    uint32_t m = 0;
    while (cursor < len) {
        uint8_t b = data[cursor++];
        value += (uint32_t(b & 0x7f)) << m;
        if (!(b & 0x80)) return true;
        m += 7;
        if (m >= 32) return false;
    }
    return false;
}

// HPACK Huffman decoder (RFC 7541 Appendix B).
// Code lengths and code values from the canonical static table.
// Implemented as bit-by-bit prefix tree walker; code lengths range
// from 5 to 30 bits.
//
// Strategy: pack (code, code_length) pairs for symbols 0-256 (257
// total; symbol 256 = EOS). For each input bit, walk through codes
// matching that prefix length. When unique match found, emit byte.
//
// For performance later we could build a lookup table of 256-entry
// nibble jumps; for correctness-first Phase 2.6 we use direct table.
struct HuffmanEntry { uint32_t code; uint8_t bits; };
// RFC 7541 Appendix B — 257 entries (sym 0..256).
static const HuffmanEntry kHpackHuffmanTable[257] = {
    {0x1ff8, 13}, {0x7fffd8, 23}, {0xfffffe2, 28}, {0xfffffe3, 28}, {0xfffffe4, 28},
    {0xfffffe5, 28}, {0xfffffe6, 28}, {0xfffffe7, 28}, {0xfffffe8, 28}, {0xffffea, 24},
    {0x3ffffffc, 30}, {0xfffffe9, 28}, {0xfffffea, 28}, {0x3ffffffd, 30}, {0xfffffeb, 28},
    {0xfffffec, 28}, {0xfffffed, 28}, {0xfffffee, 28}, {0xfffffef, 28}, {0xffffff0, 28},
    {0xffffff1, 28}, {0xffffff2, 28}, {0x3ffffffe, 30}, {0xffffff3, 28}, {0xffffff4, 28},
    {0xffffff5, 28}, {0xffffff6, 28}, {0xffffff7, 28}, {0xffffff8, 28}, {0xffffff9, 28},
    {0xffffffa, 28}, {0xffffffb, 28}, {0x14, 6}, {0x3f8, 10}, {0x3f9, 10},
    {0xffa, 12}, {0x1ff9, 13}, {0x15, 6}, {0xf8, 8}, {0x7fa, 11},
    {0x3fa, 10}, {0x3fb, 10}, {0xf9, 8}, {0x7fb, 11}, {0xfa, 8},
    {0x16, 6}, {0x17, 6}, {0x18, 6}, {0x0, 5}, {0x1, 5},
    {0x2, 5}, {0x19, 6}, {0x1a, 6}, {0x1b, 6}, {0x1c, 6},
    {0x1d, 6}, {0x1e, 6}, {0x1f, 6}, {0x5c, 7}, {0xfb, 8},
    {0x7ffc, 15}, {0x20, 6}, {0xffb, 12}, {0x3fc, 10}, {0x1ffa, 13},
    {0x21, 6}, {0x5d, 7}, {0x5e, 7}, {0x5f, 7}, {0x60, 7},
    {0x61, 7}, {0x62, 7}, {0x63, 7}, {0x64, 7}, {0x65, 7},
    {0x66, 7}, {0x67, 7}, {0x68, 7}, {0x69, 7}, {0x6a, 7},
    {0x6b, 7}, {0x6c, 7}, {0x6d, 7}, {0x6e, 7}, {0x6f, 7},
    {0x70, 7}, {0x71, 7}, {0x72, 7}, {0xfc, 8}, {0x73, 7},
    {0xfd, 8}, {0x1ffb, 13}, {0x7fff0, 19}, {0x1ffc, 13}, {0x3ffc, 14},
    {0x22, 6}, {0x7ffd, 15}, {0x3, 5}, {0x23, 6}, {0x4, 5},
    {0x24, 6}, {0x5, 5}, {0x25, 6}, {0x26, 6}, {0x27, 6},
    {0x6, 5}, {0x74, 7}, {0x75, 7}, {0x28, 6}, {0x29, 6},
    {0x2a, 6}, {0x7, 5}, {0x2b, 6}, {0x76, 7}, {0x2c, 6},
    {0x8, 5}, {0x9, 5}, {0x2d, 6}, {0x77, 7}, {0x78, 7},
    {0x79, 7}, {0x7a, 7}, {0x7b, 7}, {0x7ffe, 15}, {0x7fc, 11},
    {0x3ffd, 14}, {0x1ffd, 13}, {0xffffffc, 28}, {0xfffe6, 20}, {0x3fffd2, 22},
    {0xfffe7, 20}, {0xfffe8, 20}, {0x3fffd3, 22}, {0x3fffd4, 22}, {0x3fffd5, 22},
    {0x7fffd9, 23}, {0x3fffd6, 22}, {0x7fffda, 23}, {0x7fffdb, 23}, {0x7fffdc, 23},
    {0x7fffdd, 23}, {0x7fffde, 23}, {0xffffeb, 24}, {0x7fffdf, 23}, {0xffffec, 24},
    {0xffffed, 24}, {0x3fffd7, 22}, {0x7fffe0, 23}, {0xffffee, 24}, {0x7fffe1, 23},
    {0x7fffe2, 23}, {0x7fffe3, 23}, {0x7fffe4, 23}, {0x1fffdc, 21}, {0x3fffd8, 22},
    {0x7fffe5, 23}, {0x3fffd9, 22}, {0x7fffe6, 23}, {0x7fffe7, 23}, {0xffffef, 24},
    {0x3fffda, 22}, {0x1fffdd, 21}, {0xfffe9, 20}, {0x3fffdb, 22}, {0x3fffdc, 22},
    {0x7fffe8, 23}, {0x7fffe9, 23}, {0x1fffde, 21}, {0x7fffea, 23}, {0x3fffdd, 22},
    {0x3fffde, 22}, {0xfffff0, 24}, {0x1fffdf, 21}, {0x3fffdf, 22}, {0x7fffeb, 23},
    {0x7fffec, 23}, {0x1fffe0, 21}, {0x1fffe1, 21}, {0x3fffe0, 22}, {0x1fffe2, 21},
    {0x7fffed, 23}, {0x3fffe1, 22}, {0x7fffee, 23}, {0x7fffef, 23}, {0xfffea, 20},
    {0x3fffe2, 22}, {0x3fffe3, 22}, {0x3fffe4, 22}, {0x7ffff0, 23}, {0x3fffe5, 22},
    {0x3fffe6, 22}, {0x7ffff1, 23}, {0x3ffffe0, 26}, {0x3ffffe1, 26}, {0xfffeb, 20},
    {0x7fff1, 19}, {0x3fffe7, 22}, {0x7ffff2, 23}, {0x3fffe8, 22}, {0x1ffffec, 25},
    {0x3ffffe2, 26}, {0x3ffffe3, 26}, {0x3ffffe4, 26}, {0x7ffffde, 27}, {0x7ffffdf, 27},
    {0x3ffffe5, 26}, {0xfffff1, 24}, {0x1ffffed, 25}, {0x7fff2, 19}, {0x1fffe3, 21},
    {0x3ffffe6, 26}, {0x7ffffe0, 27}, {0x7ffffe1, 27}, {0x3ffffe7, 26}, {0x7ffffe2, 27},
    {0xfffff2, 24}, {0x1fffe4, 21}, {0x1fffe5, 21}, {0x3ffffe8, 26}, {0x3ffffe9, 26},
    {0xffffffd, 28}, {0x7ffffe3, 27}, {0x7ffffe4, 27}, {0x7ffffe5, 27}, {0xfffec, 20},
    {0xfffff3, 24}, {0xfffed, 20}, {0x1fffe6, 21}, {0x3fffe9, 22}, {0x1fffe7, 21},
    {0x1fffe8, 21}, {0x7ffff3, 23}, {0x3fffea, 22}, {0x3fffeb, 22}, {0x1ffffee, 25},
    {0x1ffffef, 25}, {0xfffff4, 24}, {0xfffff5, 24}, {0x3ffffea, 26}, {0x7ffff4, 23},
    {0x3ffffeb, 26}, {0x7ffffe6, 27}, {0x3ffffec, 26}, {0x3ffffed, 26}, {0x7ffffe7, 27},
    {0x7ffffe8, 27}, {0x7ffffe9, 27}, {0x7ffffea, 27}, {0x7ffffeb, 27}, {0xffffffe, 28},
    {0x7ffffec, 27}, {0x7ffffed, 27}, {0x7ffffee, 27}, {0x7ffffef, 27}, {0x7fffff0, 27},
    {0x3ffffee, 26}, {0x3fffffff, 30}
};

// RFC 7541 §5.2 / Appendix B — HPACK Huffman ENCODER. Mirrors the decoder's
// kHpackHuffmanTable above: per source byte, emit its variable-length code MSB-first
// into a bit accumulator. The final partial byte is right-padded with the EOS prefix
// (all 1s) per spec, which is exactly what the existing decoder treats as padding
// (it stops once <8 bits or >31 unconsumed bits remain). hpackHuffmanEncodedLength
// computes the byte length without materialising bytes (for the shorter-than-raw
// heuristic in hpackEncodeString).
static size_t hpackHuffmanEncodedLength(const CString& utf8)
{
    size_t bits = 0;
    const auto* p = reinterpret_cast<const uint8_t*>(utf8.data());
    for (size_t i = 0; i < utf8.length(); ++i)
        bits += kHpackHuffmanTable[p[i]].bits;
    return (bits + 7) / 8;  // ceil to whole octets; remainder padded with 1s (EOS prefix)
}

static void hpackHuffmanEncodeBytes(Vector<uint8_t>& out, const CString& utf8)
{
    uint64_t acc = 0;   // bit accumulator, MSB-first
    int accBits = 0;
    const auto* p = reinterpret_cast<const uint8_t*>(utf8.data());
    for (size_t i = 0; i < utf8.length(); ++i) {
        uint8_t sym = p[i];
        uint32_t code = kHpackHuffmanTable[sym].code;
        int len = kHpackHuffmanTable[sym].bits;   // 5..30 bits
        acc = (acc << len) | code;
        accBits += len;
        while (accBits >= 8) {
            accBits -= 8;
            out.append(static_cast<uint8_t>((acc >> accBits) & 0xff));
        }
    }
    // Pad the final partial octet with the EOS code's high bits (all 1s), RFC 7541 §5.2.
    if (accBits > 0) {
        int pad = 8 - accBits;
        uint8_t last = static_cast<uint8_t>(((acc << pad) | ((1U << pad) - 1)) & 0xff);
        out.append(last);
    }
}

// Decode HPACK Huffman-encoded byte stream.
static Vector<uint8_t> hpackHuffmanDecode(const uint8_t* data, size_t len)
{
    Vector<uint8_t> out;
    uint64_t buffer = 0;  // bit buffer
    int bufferBits = 0;

    for (size_t i = 0; i < len; ++i) {
        buffer = (buffer << 8) | data[i];
        bufferBits += 8;

        // Try to decode as many symbols as possible from current buffer
        while (bufferBits >= 5) {  // shortest code = 5 bits
            bool found = false;
            for (int sym = 0; sym < 256; ++sym) {  // skip EOS=256
                int bits = kHpackHuffmanTable[sym].bits;
                if (bits > bufferBits) continue;
                uint32_t code = kHpackHuffmanTable[sym].code;
                uint32_t extracted = (buffer >> (bufferBits - bits)) & ((1U << bits) - 1);
                if (extracted == code) {
                    out.append(static_cast<uint8_t>(sym));
                    bufferBits -= bits;
                    found = true;
                    break;
                }
            }
            if (!found) break;
        }
        // W2131: a complete prefix code consumes every ≤30-bit prefix, so >31 UNCONSUMED
        // bits means the rest of the stream is invalid / over-long EOS padding (RFC 7541
        // §5.2). Stop decoding — this also prevents an undefined ≥64-bit shift of the
        // 64-bit `buffer` (bufferBits could otherwise reach 64+ on a crafted all-1s string,
        // making `buffer >> (bufferBits - bits)` UB). Legit partial codes leave ≤29 bits.
        if (bufferBits > 31)
            break;
    }
    return out;
}

static String hpackDecodeString(const uint8_t* data, size_t len, size_t& cursor)
{
    if (cursor >= len) return String();
    bool huffman = (data[cursor] & 0x80) != 0;
    uint32_t strLen = 0;
    if (!hpackDecodeInteger(data, len, cursor, 7, strLen))
        return String();
    if (cursor + strLen > len) return String();

    if (!huffman) {
        String s = String::fromUTF8(unsafeMakeSpan(reinterpret_cast<const char*>(data + cursor), strLen));
        cursor += strLen;
        return s;
    }
    // Wave 29-499.145 — Full Huffman decoder via RFC 7541 Appendix B table.
    auto decoded = hpackHuffmanDecode(data + cursor, strLen);
    cursor += strLen;
    if (decoded.isEmpty()) return String();
    return String::fromUTF8(byteCast<char>(decoded.span()));
}

// Wave 29-499.351 — HPACK DYNAMIC TABLE (RFC 7541 §2.3.2 / §4). Previously absent:
// the decoder only handled the static table (idx 1..61) and bailed on any dynamic
// reference (idx >= 62) → it dropped every header the server emitted by dynamic
// index. On a REUSED (pooled) h2 connection the server progressively moves headers
// into its dynamic table and references them by index — so later responses lost
// headers, including access-control-allow-origin → WebKit CORS-blocked the cross-
// origin fetch → browserleaks.com/tls showed ja3/ja4/extensions = "fetch error".
// HPACK decode state is PER-CONNECTION + order-dependent: one instance per h2
// connection, fed every HEADERS block in arrival order (the pooled session holds it
// as a member; the one-shot path uses a fresh local).
struct HpackDecoderState {
    Vector<std::pair<String, String>> dynTable; // index 0 = most recent (HPACK index kHpackStaticCount)
    size_t dynSize { 0 };
    size_t maxDynSize { 4096 }; // SETTINGS_HEADER_TABLE_SIZE default

    void evict() {
        while (dynSize > maxDynSize && !dynTable.isEmpty()) {
            auto& back = dynTable.last();
            dynSize -= back.first.length() + back.second.length() + 32;
            dynTable.removeLast();
        }
    }
    void add(const String& name, const String& value) {
        size_t entrySize = name.length() + value.length() + 32; // RFC 7541 §4.1
        if (entrySize > maxDynSize) { dynTable.clear(); dynSize = 0; return; }
        dynTable.insert(0, { name, value });
        dynSize += entrySize;
        evict();
    }
    // hpackIdx: 1..(kHpackStaticCount-1) static; >= kHpackStaticCount dynamic.
    bool lookup(uint32_t hpackIdx, String& name, String& value) const {
        if (!hpackIdx) return false;
        if (hpackIdx < kHpackStaticCount) {
            name = String::fromUTF8(kHpackStatic[hpackIdx].first);
            value = String::fromUTF8(kHpackStatic[hpackIdx].second);
            return true;
        }
        size_t di = hpackIdx - kHpackStaticCount; // kHpackStaticCount -> 0 (most recent)
        if (di >= dynTable.size()) return false;
        name = dynTable[di].first; value = dynTable[di].second;
        return true;
    }
    bool lookupName(uint32_t nameIdx, String& name) const {
        String v;
        return lookup(nameIdx, name, v);
    }
};

// HPACK decode one header field representation. Appends to out. Updates `dyn`
// (dynamic table) per RFC 7541. Returns true on success, false on parse error.
static bool hpackDecodeOneHeader(const uint8_t* data, size_t len, size_t& cursor,
    Vector<std::pair<String, String>>& out, HpackDecoderState& dyn)
{
    if (cursor >= len) return false;
    uint8_t firstByte = data[cursor];

    if (firstByte & 0x80) {
        // 1xxxxxxx — Indexed Header Field (static OR dynamic)
        uint32_t idx = 0;
        if (!hpackDecodeInteger(data, len, cursor, 7, idx) || idx == 0)
            return false;
        String name, value;
        if (!dyn.lookup(idx, name, value))
            return false;
        out.append({ name, value });
        return true;
    } else if ((firstByte & 0xc0) == 0x40) {
        // 01xxxxxx — Literal with Incremental Indexing (ADD to dynamic table)
        uint32_t nameIdx = 0;
        if (!hpackDecodeInteger(data, len, cursor, 6, nameIdx))
            return false;
        String name;
        if (nameIdx > 0) { if (!dyn.lookupName(nameIdx, name)) return false; }
        else name = hpackDecodeString(data, len, cursor);
        String value = hpackDecodeString(data, len, cursor);
        dyn.add(name, value);
        out.append({ name, value });
        return true;
    } else if ((firstByte & 0xe0) == 0x20) {
        // 001xxxxx — Dynamic Table Size Update
        uint32_t newSize = 0;
        if (!hpackDecodeInteger(data, len, cursor, 5, newSize))
            return false;
        // RFC 7541 §6.3: the update MUST NOT exceed the client-advertised
        // SETTINGS_HEADER_TABLE_SIZE; a larger value is a decoding error. We OMIT that
        // setting (matching the real-iPhone SETTINGS fingerprint), so the limit is the
        // HPACK default 4096. Without this cap a malicious server's oversized update lets
        // the dynamic table grow unbounded (evict() never fires) → OOM the NetworkProcess.
        if (newSize > 4096)
            return false;
        dyn.maxDynSize = newSize;
        dyn.evict();
        return true;
    } else {
        // 0000xxxx or 0001xxxx — Literal w/o or never indexing (NOT added to table)
        uint32_t nameIdx = 0;
        if (!hpackDecodeInteger(data, len, cursor, 4, nameIdx))
            return false;
        String name;
        if (nameIdx > 0) { if (!dyn.lookupName(nameIdx, name)) return false; }
        else name = hpackDecodeString(data, len, cursor);
        String value = hpackDecodeString(data, len, cursor);
        out.append({ name, value });
        return true;
    }
}

} // anonymous namespace

// Wave 29-499.328 — shared Content-Encoding decompressor. iPhone Safari decompresses
// transparently; our custom delivery path does not, so the body must be decoded here or
// WebKit renders raw compressed bytes (garbled page). The single-request path
// (driftstackHttp2Execute) decodes inline; the POOLED path (DriftstackHttp2Session::execute)
// did NOT — browserleaks served brotli over a pooled stream → garbage. Handles gzip/deflate
// (zlib, window 15+32 auto-detect) and br (Apple libcompression), with grow loops so
// large/high-ratio bodies aren't truncated. Strips content-encoding/content-length after.
// W2140: cap the DECOMPRESSED size. A malicious server's gzip/zstd bomb (tiny body, ~1000x
// ratio) would otherwise grow the output buffer UNBOUNDED → OOM the NetworkProcess (a customer
// browsing a hostile site). 512MB is generous for any legit browser response; a bomb is
// neutralized (decode stops → ok=false → body left compressed → page breaks, no OOM). Shared
// with the inline one-shot decoder (driftstackHttp2Execute) below.
static constexpr size_t kMaxDecompressedBytes = 512u * 1024 * 1024;
void driftstackDecodeContentEncoding(Vector<uint8_t>& body, Vector<std::pair<String, String>>& headers)
{
    if (body.isEmpty())
        return;
    String enc;
    for (auto& [k, v] : headers) {
        if (equalIgnoringASCIICase(k, "content-encoding"_s)) { enc = v.convertToASCIILowercase().trim(deprecatedIsSpaceOrNewline); break; }
    }
    if (enc.isEmpty())
        return;

    Vector<uint8_t> out;
    bool ok = false;

    if (enc == "gzip"_s || enc == "deflate"_s || enc == "x-gzip"_s) {
        z_stream zs;
        memset(&zs, 0, sizeof(zs));
        if (inflateInit2(&zs, 15 + 32) == Z_OK) {  // 15+32 = auto-detect gzip vs zlib
            zs.next_in = const_cast<Bytef*>(body.span().data());
            zs.avail_in = static_cast<uInt>(body.size());
            size_t cap = std::max<size_t>(body.size() * 4, 64 * 1024);
            out.resize(cap);
            for (;;) {
                zs.next_out = out.mutableSpan().data() + zs.total_out;
                zs.avail_out = static_cast<uInt>(cap - zs.total_out);
                int rv = inflate(&zs, Z_FINISH);
                if (rv == Z_STREAM_END) { ok = true; break; }
                if (rv == Z_OK || (rv == Z_BUF_ERROR && zs.avail_out == 0)) {
                    if (zs.avail_out == 0) {  // grow + retry (bounded vs a decompression bomb, W2140)
                        if (cap >= kMaxDecompressedBytes) break;
                        cap = std::min(cap * 2, kMaxDecompressedBytes); out.resize(cap); continue;
                    }
                }
                break;  // real error or stalled
            }
            if (ok) out.resize(zs.total_out);
            inflateEnd(&zs);
        }
    } else if (enc == "br"_s) {
        size_t cap = std::max<size_t>(body.size() * 8, 64 * 1024);
        for (int attempt = 0; attempt < 6; ++attempt) {
            out.resize(cap);
            size_t n = compression_decode_buffer(out.mutableSpan().data(), cap,
                body.span().data(), body.size(), nullptr, COMPRESSION_BROTLI);
            if (n > 0 && n < cap) { out.resize(n); ok = true; break; }  // n<cap ⇒ complete
            if (!n) break;                                              // hard failure
            if (cap >= kMaxDecompressedBytes) break;                    // W2140 decompression-bomb cap
            cap = std::min(cap * 2, kMaxDecompressedBytes);             // n==cap ⇒ maybe truncated, grow
        }
    } else if (enc == "zstd"_s) {
        // W1515 — vendored zstd v1.5.7 decoder (NetworkProcess/cocoa/zstd/zstddeclib.c).
        // Streaming decompress + grow loop (mirrors the gzip branch) so high-ratio/large
        // bodies aren't truncated. Logic validated bit-exact W1513/W1514 (85B + 266KB)
        // against this exact amalgamation. Lets the fork advertise + honour the real-iPhone
        // "gzip, deflate, br, zstd" Accept-Encoding (W1512) without corrupting zstd responses.
        if (ZSTD_DStream* ds = ZSTD_createDStream()) {
            ZSTD_initDStream(ds);
            ZSTD_inBuffer in = { body.span().data(), body.size(), 0 };
            size_t cap = std::max<size_t>(body.size() * 4, 64 * 1024);
            out.resize(cap);
            size_t written = 0;
            for (;;) {
                if (written == cap) {  // W2140 decompression-bomb cap
                    if (cap >= kMaxDecompressedBytes) break;
                    cap = std::min(cap * 2, kMaxDecompressedBytes); out.resize(cap);
                }
                ZSTD_outBuffer outb = { out.mutableSpan().data() + written, cap - written, 0 };
                size_t rv = ZSTD_decompressStream(ds, &outb, &in);
                if (ZSTD_isError(rv)) break;
                written += outb.pos;
                if (!rv) { ok = true; break; }                            // a frame completed
                if (in.pos == in.size && !outb.pos) { ok = true; break; } // input drained
            }
            if (ok) out.resize(written);
            ZSTD_freeDStream(ds);
        }
    } else
        return;  // unknown encoding — leave as-is

    if (!ok) {
        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.331] decode FAILED enc=%s in=%zu first=0x%02x", enc.utf8().data(), body.size(), body.isEmpty() ? 0 : body[0]);
        return;
    }
    WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.331] decoded enc=%s %zu -> %zu", enc.utf8().data(), body.size(), out.size());
    body = std::move(out);
    Vector<std::pair<String, String>> filtered;
    for (auto& [k, v] : headers) {
        String kl = k.convertToASCIILowercase();
        if (kl != "content-encoding"_s && kl != "content-length"_s)
            filtered.append({ k, v });
    }
    headers = std::move(filtered);
}

static void driftstackDecompressHttp2Body(DriftstackHttp2Response& resp)
{
    driftstackDecodeContentEncoding(resp.body, resp.headers);
}

static DriftstackHttp2Response driftstackHttp2ExecuteImpl(void* ssl, const DriftstackHttp2Transport* transport, const DriftstackHttp2Request& request)
{
    DriftstackHttp2Response resp;

    if (!ssl && !transport) {
        resp.failed = true;
        resp.errorMessage = "null SSL and no transport"_s;
        return resp;
    }
    auto& f = sslFns();
    if (!transport && !f.ready) {
        resp.failed = true;
        resp.errorMessage = "SSL_read/write dlsym not resolved"_s;
        return resp;
    }

    // 1. Send connection preface
    if (!sslWriteAll(ssl, transport,(const uint8_t*)kHttp2Preface, sizeof(kHttp2Preface) - 1)) {
        resp.failed = true;
        resp.errorMessage = "preface write failed"_s;
        return resp;
    }

    // 2. Send our SETTINGS frame (iPhone Safari 26.0 values)
    // Each setting = 6 bytes (id:16 + value:32)
    Vector<uint8_t> settingsPayload;
    auto pushSetting = [&](uint16_t id, uint32_t val) {
        settingsPayload.append(static_cast<uint8_t>(id >> 8));
        settingsPayload.append(static_cast<uint8_t>(id & 0xff));
        settingsPayload.append(static_cast<uint8_t>((val >> 24) & 0xff));
        settingsPayload.append(static_cast<uint8_t>((val >> 16) & 0xff));
        settingsPayload.append(static_cast<uint8_t>((val >> 8) & 0xff));
        settingsPayload.append(static_cast<uint8_t>(val & 0xff));
    };
    // iPhone 17 / Safari 26.4 SETTINGS — order + values from a real-device BS
    // capture against tls.peet.ws (Wave .323): akamai = 2:0;3:100;4:2097152;9:1.
    // ORDER is 2,3,4,9 (MAX_CONCURRENT_STREAMS BEFORE INITIAL_WINDOW_SIZE) and
    // INITIAL_WINDOW_SIZE = 2097152 (2MB, NOT 4194304 — that was a stale value).
    pushSetting(kSettingEnablePush, 0);              // 2:0
    pushSetting(kSettingMaxConcurrentStreams, 100);  // 3:100
    pushSetting(kSettingInitialWindowSize, 2097152); // 4:2097152
    pushSetting(kSettingNoRfc7540Priorities, 1);     // 9:1

    uint8_t settingsHeader[9];
    encodeFrameHeader(settingsHeader, settingsPayload.size(), kFrameSettings, 0, 0);
    if (!sslWriteAll(ssl, transport,settingsHeader, 9) || !sslWriteAll(ssl, transport,settingsPayload.span().data(), settingsPayload.size())) {
        resp.failed = true;
        resp.errorMessage = "SETTINGS write failed"_s;
        return resp;
    }

    // 3. Send WINDOW_UPDATE for connection (stream 0). Real iPhone 17 sends
    //    +10420225 (= target 10485760 - default initial 65535), per BS capture.
    uint8_t windowUpdate[13];
    encodeFrameHeader(windowUpdate, 4, kFrameWindowUpdate, 0, 0);
    uint32_t inc = 10420225;
    windowUpdate[9] = (inc >> 24) & 0xff;
    windowUpdate[10] = (inc >> 16) & 0xff;
    windowUpdate[11] = (inc >> 8) & 0xff;
    windowUpdate[12] = inc & 0xff;
    if (!sslWriteAll(ssl, transport,windowUpdate, 13)) {
        resp.failed = true;
        resp.errorMessage = "WINDOW_UPDATE write failed"_s;
        return resp;
    }

    // 4. Send HEADERS frame for stream 1 (client-initiated streams are odd).
    Vector<uint8_t> headersBlock;
    // iPhone 17 pseudo-header order m,s,a,p (method, scheme, authority, path —
    // authority BEFORE path) — BS capture Wave .323 / W95 tls.peet.ws.
    hpackEncodeHeader(headersBlock, ":method"_s, request.method);
    hpackEncodeHeader(headersBlock, ":scheme"_s, request.scheme);
    hpackEncodeHeader(headersBlock, ":authority"_s, request.authority);
    hpackEncodeHeader(headersBlock, ":path"_s, request.path);
    for (auto& [key, val] : request.extraHeaders) {
        hpackEncodeHeader(headersBlock, key.convertToASCIILowercase(), val);
    }

    bool hasBody = !request.body.isEmpty();
    uint8_t headersFrameHeader[9];
    uint8_t flags = kFlagEndHeaders;
    if (!hasBody) flags |= kFlagEndStream;
    encodeFrameHeader(headersFrameHeader, headersBlock.size(), kFrameHeaders, flags, 1);
    if (!sslWriteAll(ssl, transport,headersFrameHeader, 9) || !sslWriteAll(ssl, transport,headersBlock.span().data(), headersBlock.size())) {
        resp.failed = true;
        resp.errorMessage = "HEADERS write failed"_s;
        return resp;
    }

    // 5. Send DATA frame(s) if body present — chunked + flow-controlled
    // (Wave 29-499.349). The previous single-frame send broke every body
    // > 16384 (exceeds the peer's default SETTINGS_MAX_FRAME_SIZE → instant
    // connection error) and ignored the 65535-octet initial send windows
    // (> 64KB = FLOW_CONTROL_ERROR) — uploads/POSTs above 16KB always failed.
    // Chunks at the 16384 protocol default (always legal); when the send
    // window is exhausted, reads frames inline: SETTINGS/WINDOW_UPDATE/PING
    // handled here, response frames for our stream stashed for the main read
    // loop below (an early response, e.g. 413, also stops the body send like
    // Safari does).
    struct PendingFrame {
        uint8_t hdr[9];
        Vector<uint8_t> payload;
    };
    Vector<PendingFrame> pendingFrames;
    size_t pendingCursor = 0;
    if (hasBody) {
        constexpr size_t kMaxDataChunk = 16384;
        int64_t connSendWindow = 65535;
        int64_t streamSendWindow = 65535;
        uint32_t peerInitialWindow = 65535;
        size_t offset = 0;
        const size_t total = request.body.size();
        bool earlyResponse = false;
        while (offset < total && !earlyResponse) {
            size_t windowBudget = static_cast<size_t>(std::max<int64_t>(0, std::min(connSendWindow, streamSendWindow)));
            size_t budget = std::min({ kMaxDataChunk, total - offset, windowBudget });
            if (!budget) {
                uint8_t fhdr[9];
                if (!sslReadExact(ssl, transport, fhdr, 9)) {
                    resp.failed = true;
                    resp.errorMessage = "frame read failed while send-window blocked"_s;
                    return resp;
                }
                uint32_t flen;
                uint8_t ftype, fflags;
                uint32_t fsid;
                decodeFrameHeader(fhdr, flen, ftype, fflags, fsid);
                // W2210 (parser-audit weta2casf): the send-window-blocked drain read a frame via the raw 24-bit
                // length (up to 16 MiB) WITHOUT the per-frame cap the normal recv loop applies (:966). A hostile
                // upstream that stalls our send window could force a 16 MiB resize per stashed frame. Mirror the
                // recv guard (kMaxRecvFrameBytes = 1 MiB, far above the 16384 default → no legit false-reject).
                if (flen > kMaxRecvFrameBytes) {
                    resp.failed = true;
                    resp.errorMessage = "frame exceeds max receive size"_s;
                    return resp;
                }
                Vector<uint8_t> fpayload;
                fpayload.resize(flen);
                if (flen > 0 && !sslReadExact(ssl, transport, fpayload.mutableSpan().data(), flen)) {
                    resp.failed = true;
                    resp.errorMessage = "frame payload read failed while send-window blocked"_s;
                    return resp;
                }
                if (ftype == kFrameWindowUpdate && flen >= 4) {
                    uint32_t inc = (uint32_t(fpayload[0] & 0x7f) << 24) | (uint32_t(fpayload[1]) << 16) | (uint32_t(fpayload[2]) << 8) | fpayload[3];
                    if (fsid == 0)
                        connSendWindow += inc;
                    else if (fsid == 1)
                        streamSendWindow += inc;
                } else if (ftype == kFrameSettings && !(fflags & kFlagAck)) {
                    // INITIAL_WINDOW_SIZE retro-adjusts open-stream send windows (RFC 7540 §6.9.2).
                    for (size_t i = 0; i + 6 <= fpayload.size(); i += 6) {
                        uint16_t id = (uint16_t(fpayload[i]) << 8) | fpayload[i + 1];
                        uint32_t val = (uint32_t(fpayload[i + 2]) << 24) | (uint32_t(fpayload[i + 3]) << 16) | (uint32_t(fpayload[i + 4]) << 8) | fpayload[i + 5];
                        if (id == kSettingInitialWindowSize) {
                            streamSendWindow += int64_t(val) - int64_t(peerInitialWindow);
                            peerInitialWindow = val;
                        }
                    }
                    uint8_t ack[9];
                    encodeFrameHeader(ack, 0, kFrameSettings, kFlagAck, 0);
                    sslWriteAll(ssl, transport, ack, 9);
                } else if (ftype == kFramePing && !(fflags & kFlagAck)) {
                    uint8_t pong[17] = { 0 };
                    encodeFrameHeader(pong, 8, kFramePing, kFlagAck, 0);
                    for (size_t i = 0; i < 8 && i < fpayload.size(); ++i)
                        pong[9 + i] = fpayload[i];
                    sslWriteAll(ssl, transport, pong, 17);
                } else if (ftype == kFrameGoaway || (ftype == kFrameRstStream && fsid == 1)) {
                    resp.failed = true;
                    resp.errorMessage = "GOAWAY/RST_STREAM during body send"_s;
                    return resp;
                } else if ((ftype == kFrameHeaders || ftype == kFrameData) && fsid == 1) {
                    PendingFrame pf;
                    memcpy(pf.hdr, fhdr, 9);
                    pf.payload = std::move(fpayload);
                    pendingFrames.append(std::move(pf));
                    earlyResponse = true;
                } else {
                    PendingFrame pf;
                    memcpy(pf.hdr, fhdr, 9);
                    pf.payload = std::move(fpayload);
                    pendingFrames.append(std::move(pf));
                }
                continue;
            }
            uint8_t dataHeader[9];
            bool last = (offset + budget == total);
            encodeFrameHeader(dataHeader, budget, kFrameData, last ? kFlagEndStream : 0, 1);
            if (!sslWriteAll(ssl, transport, dataHeader, 9) || !sslWriteAll(ssl, transport, request.body.span().subspan(offset, budget).data(), budget)) {
                resp.failed = true;
                resp.errorMessage = "DATA write failed"_s;
                return resp;
            }
            offset += budget;
            connSendWindow -= budget;
            streamSendWindow -= budget;
        }
    }

    // 6. Read frames until END_STREAM on stream 1
    uint32_t streamId = 1;
    bool streamComplete = false;
    int frameCount = 0;
    // Wave 29-499.321 — was `frameCount < 100`, which truncated responses larger
    // than ~1.6 MB (100 × 16 KB max frame) — e.g. big JS bundles. Raise the frame
    // ceiling to effectively unbounded for normal use, and bound MEMORY with a
    // total-body cap below (kMaxBodyBytes). True unbounded streams (SSE) never
    // reach here — NetworkDataTaskCocoa::resume routes text/event-stream to
    // CFNetwork (Wave .321 streaming-bypass).
    constexpr int kMaxFrames = 500000;
    constexpr size_t kMaxBodyBytes = 128 * 1024 * 1024; // 128 MB safety cap
    // Wave 29-499.350 — streaming (SSE) state. A streaming request has no frame
    // ceiling (an EventSource is unbounded); the cap below applies only to the
    // buffer-all path. onHeaders fires once; the byte counter drives periodic
    // WINDOW_UPDATE so a long stream never stalls on the receive window.
    const bool streaming = static_cast<bool>(request.onBodyChunk);
    bool streamingHeadersFired = false;
    // iOS-faithful mid-stream WINDOW_UPDATE cadence (gt http2_windowupdate_midstream_cadence):
    // STREAM and CONNECTION replenish on DIFFERENT window-fraction thresholds, so
    // track received bytes for each independently (was one counter @ a fixed 1 MiB).
    uint64_t streamRecvSinceUpdate = 0; // toward kDriftstackStreamWUThreshold (window/4)
    uint64_t connRecvSinceUpdate   = 0; // toward kDriftstackConnWUThreshold   (window/2)
    // W2132: streaming bypasses the kMaxFrames TOTAL cap (a stream is unbounded), so the
    // flood guard must be a NO-PROGRESS bound instead — abort if this many frames arrive
    // with no DATA delivered (a malicious server spinning CONTINUATION/PING/control frames
    // and never sending body would otherwise loop forever, holding a connection + CPU).
    // Reset on each delivered DATA chunk; legit streams deliver DATA long before this.
    constexpr int kMaxStreamIdleFrames = 100000;
    int streamIdleFrames = 0;
    HpackDecoderState hpackDyn; // one-shot: one connection, fresh decode state
    while (!streamComplete && (streaming || frameCount < kMaxFrames)) {
        ++frameCount;
        if (streaming && ++streamIdleFrames > kMaxStreamIdleFrames) {
            resp.failed = true;
            resp.errorMessage = "stream frame-flood: no body progress"_s;
            return resp;
        }
        uint32_t length;
        uint8_t type, frameFlags;
        uint32_t sid;
        Vector<uint8_t> payload;
        // Wave 29-499.349 — frames stashed during the flow-controlled body
        // send (response frames that arrived while window-blocked) are
        // processed before reading new ones off the wire.
        if (pendingCursor < pendingFrames.size()) {
            auto& pf = pendingFrames[pendingCursor++];
            decodeFrameHeader(pf.hdr, length, type, frameFlags, sid);
            payload = std::move(pf.payload);
        } else {
            uint8_t hdr[9];
            if (!sslReadExact(ssl, transport,hdr, 9)) {
                resp.failed = true;
                resp.errorMessage = "frame header read failed"_s;
                return resp;
            }
            decodeFrameHeader(hdr, length, type, frameFlags, sid);
            if (length > kMaxRecvFrameBytes) {  // W2415 — reject oversized frame (FRAME_SIZE_ERROR)
                resp.failed = true;
                resp.errorMessage = "frame exceeds max receive size"_s;
                return resp;
            }
            payload.resize(length);
            if (length > 0 && !sslReadExact(ssl, transport,payload.mutableSpan().data(), length)) {
                resp.failed = true;
                resp.errorMessage = "frame payload read failed"_s;
                return resp;
            }
        }

        switch (type) {
        case kFrameSettings:
            if (!(frameFlags & kFlagAck)) {
                // Send ACK
                uint8_t ack[9];
                encodeFrameHeader(ack, 0, kFrameSettings, kFlagAck, 0);
                sslWriteAll(ssl, transport,ack, 9);
            }
            break;
        case kFrameHeaders:
            if (sid == streamId) {
                // Wave 29-499.143 — HPACK decode (basic, non-Huffman)
                Vector<std::pair<String, String>> decoded;
                size_t cursor = 0;
                // Skip padding/priority if present
                size_t payloadStart = 0;
                size_t headerEnd = payload.size();
                if (frameFlags & kFlagPadded) {
                    // RFC 7540 §6.2 (W2528): Pad Length is a 1-byte FRONT field; the padding bytes
                    // sit at the END of the payload (mirror the §6.1 DATA-frame trim at kFrameData).
                    // The header block is [payloadStart, size - padLen). Treating padLen as a front
                    // offset starts HPACK mid-field → desync → corrupted/dropped response headers.
                    if (payload.size() < 1) break;
                    uint8_t padLen = payload[0];
                    if (static_cast<size_t>(padLen) + 1 > payload.size()) break;
                    payloadStart = 1;
                    headerEnd = payload.size() - padLen;
                }
                if (frameFlags & kFlagPriority) {
                    if (payload.size() < payloadStart + 5) break;
                    payloadStart += 5;
                }
                // egress audit wxzzaphvp (#3): CONTINUATION reassembly (RFC 7540 §6.10). If END_HEADERS is
                // NOT set, the header block continues in immediately-following CONTINUATION frames on the
                // SAME stream (a large block — big Set-Cookie / many headers — exceeds one 16 KiB frame). The
                // decode used to run on only this frame's fragment → garbled/truncated response headers.
                // CONTINUATION MUST immediately follow (no interleaving) and the body/flow-control phase
                // (which is what populates pendingFrames) hasn't started, so read them inline off the wire
                // and concatenate before decoding. Common case (END_HEADERS set) leaves blockData/blockLen
                // pointing at this frame's block — byte-identical to the single-frame path.
                const uint8_t* blockData = payload.span().data() + payloadStart;
                size_t blockLen = headerEnd - payloadStart;
                Vector<uint8_t> contBlock;
                if (!(frameFlags & kFlagEndHeaders)) {
                    contBlock.append(std::span<const uint8_t>(blockData, blockLen));
                    bool contEnd = false;
                    while (!contEnd) {
                        uint8_t chdr[9];
                        if (!sslReadExact(ssl, transport, chdr, 9)) {
                            resp.failed = true; resp.errorMessage = "CONTINUATION header read failed"_s; return resp;
                        }
                        uint32_t clen, csid; uint8_t ctype, cflags;
                        decodeFrameHeader(chdr, clen, ctype, cflags, csid);
                        if (ctype != kFrameContinuation || csid != streamId) {
                            resp.failed = true; resp.errorMessage = "expected CONTINUATION on the header stream (PROTOCOL_ERROR)"_s; return resp;
                        }
                        if (clen > kMaxRecvFrameBytes) {
                            resp.failed = true; resp.errorMessage = "CONTINUATION exceeds max receive frame size"_s; return resp;
                        }
                        Vector<uint8_t> cpay(clen);
                        if (clen > 0 && !sslReadExact(ssl, transport, cpay.mutableSpan().data(), clen)) {
                            resp.failed = true; resp.errorMessage = "CONTINUATION payload read failed"_s; return resp;
                        }
                        contBlock.append(cpay.span());
                        if (contBlock.size() > (static_cast<size_t>(1) << 20)) {  // 1 MiB — bound a CONTINUATION flood (DoS)
                            resp.failed = true; resp.errorMessage = "header block exceeds 1 MiB (CONTINUATION flood)"_s; return resp;
                        }
                        if (cflags & kFlagEndHeaders) contEnd = true;
                    }
                    blockData = contBlock.span().data();
                    blockLen = contBlock.size();
                }
                cursor = 0;
                while (cursor < blockLen) {
                    if (!hpackDecodeOneHeader(blockData, blockLen, cursor, decoded, hpackDyn))
                        break;
                }
                for (auto& [k, v] : decoded) {
                    if (k == ":status"_s) {
                        // Parse status digit by digit (no parseInteger header bloat)
                        int statusCode = 0;
                        auto v8 = v.utf8();
                        for (size_t i = 0; i < v8.length(); ++i) {
                            char c = v8.data()[i];
                            if (c < '0' || c > '9') break;
                            statusCode = statusCode * 10 + (c - '0');
                        }
                        if (statusCode > 0) resp.statusCode = statusCode;
                    } else if (!k.startsWith(':')) {
                        resp.headers.append({ k, v });
                    }
                }
                if (resp.statusCode == 0) resp.statusCode = 200;  // fallback if HPACK Huffman
                // Wave 29-499.350 — streaming (SSE): fire onHeaders once the
                // response HEADERS are parsed, before any body. A false return
                // (policy declined / loader cancelled) aborts the stream.
                if (request.onHeaders && !streamingHeadersFired) {
                    streamingHeadersFired = true;
                    if (!request.onHeaders(resp.statusCode, resp.headers)) {
                        resp.failed = true;
                        resp.errorMessage = "stream cancelled at headers"_s;
                        return resp;
                    }
                }
                if (frameFlags & kFlagEndStream)
                    streamComplete = true;
            }
            break;
        case kFrameData:
            if (sid == streamId) {
                // Wave 29-499.264 — strip RFC 7540 §6.1 padding when PADDED
                // flag set. Was missing → first byte of every PADDED DATA
                // frame leaked into body, breaking gzip header magic check
                // (saw "fa 1f 8b 08" where "fa" was the pad-length byte).
                std::span<const uint8_t> dataSpan = payload.span();
                if (frameFlags & kFlagPadded) {
                    if (dataSpan.size() < 1) break;
                    uint8_t padLen = dataSpan[0];
                    if (static_cast<size_t>(padLen) + 1 > dataSpan.size()) break;
                    dataSpan = dataSpan.subspan(1, dataSpan.size() - 1 - padLen);
                }
                // Wave 29-499.350 — streaming delivery (onBodyChunk) vs buffer-all accumulation.
                if (request.onBodyChunk) {
                    if (dataSpan.size() && !request.onBodyChunk(dataSpan)) {
                        resp.failed = true;
                        resp.errorMessage = "stream cancelled mid-body"_s;
                        return resp;
                    }
                } else {
                    resp.body.append(dataSpan);
                    if (resp.body.size() > kMaxBodyBytes) {
                        resp.failed = true;
                        resp.errorMessage = "response body exceeds 128MB cap"_s;
                        return resp;
                    }
                }
                // RFC 7540 §6.9 — replenish our receive windows for EVERY delivered DATA frame,
                // streaming AND buffer-all. egress audit wxzzaphvp (HIGH): this WINDOW_UPDATE emission
                // used to live ONLY inside the onBodyChunk branch, so a buffer-all response larger than
                // the initial stream/connection receive window exhausted the window and the server
                // stopped sending → permanent flow-control deadlock (hang) on any response over ~2 MB
                // (heavy pages). iOS-faithful cadence (gt http2_windowupdate_midstream_cadence): STREAM
                // replenishes at window/4 (kDriftstackStreamWUThreshold), CONNECTION at window/2
                // (kDriftstackConnWUThreshold), tracked separately; increment == bytes consumed since
                // that window's last update.
                streamIdleFrames = 0; // W2132: body progress — reset the no-progress flood guard
                streamRecvSinceUpdate += dataSpan.size();
                connRecvSinceUpdate   += dataSpan.size();
                if (streamRecvSinceUpdate >= kDriftstackStreamWUThreshold) {
                    uint32_t inc = static_cast<uint32_t>(streamRecvSinceUpdate);
                    uint8_t wu[13];
                    encodeFrameHeader(wu, 4, kFrameWindowUpdate, 0, streamId);
                    wu[9] = (inc >> 24) & 0xff; wu[10] = (inc >> 16) & 0xff; wu[11] = (inc >> 8) & 0xff; wu[12] = inc & 0xff;
                    sslWriteAll(ssl, transport, wu, 13);
                    streamRecvSinceUpdate = 0;
                }
                if (connRecvSinceUpdate >= kDriftstackConnWUThreshold) {
                    uint32_t inc = static_cast<uint32_t>(connRecvSinceUpdate);
                    uint8_t wuc[13];
                    encodeFrameHeader(wuc, 4, kFrameWindowUpdate, 0, 0);
                    wuc[9] = (inc >> 24) & 0xff; wuc[10] = (inc >> 16) & 0xff; wuc[11] = (inc >> 8) & 0xff; wuc[12] = inc & 0xff;
                    sslWriteAll(ssl, transport, wuc, 13);
                    connRecvSinceUpdate = 0;
                }
                if (frameFlags & kFlagEndStream)
                    streamComplete = true;
            }
            break;
        case kFrameWindowUpdate:
            // Ignore — we don't flow-control outbound (small requests fit in window)
            break;
        case kFramePing:
            // Wave 29-499.210 — respond to PING with PING ACK
            // (RFC 7540 §6.7: must echo opaque payload, set ACK flag)
            if (!(frameFlags & kFlagAck) && length == 8) {
                uint8_t pingResp[9 + 8];
                encodeFrameHeader(pingResp, 8, kFramePing, kFlagAck, 0);
                memcpy(pingResp + 9, payload.span().data(), 8);
                sslWriteAll(ssl, transport,pingResp, sizeof(pingResp));
                WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.210] PING received + ACK sent");
            }
            break;
        case kFrameGoaway:
            // Wave 29-499.211 — GOAWAY (RFC 7540 §6.8)
            // Server announces graceful shutdown. If our stream_id < last_stream_id,
            // server will still process us; just absorb our remaining data + close.
            // Payload: last_stream_id (4) + error_code (4) + debug_data
            if (length >= 8) {
                uint32_t lastStreamId = (static_cast<uint32_t>(payload[0]) << 24)
                    | (static_cast<uint32_t>(payload[1]) << 16)
                    | (static_cast<uint32_t>(payload[2]) << 8)
                    | payload[3];
                uint32_t errorCode = (static_cast<uint32_t>(payload[4]) << 24)
                    | (static_cast<uint32_t>(payload[5]) << 16)
                    | (static_cast<uint32_t>(payload[6]) << 8)
                    | payload[7];
                WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.211] GOAWAY: lastStreamId=%u errorCode=%u (our stream=%u)",
                    lastStreamId, errorCode, streamId);
                if (streamId > lastStreamId) {
                    resp.failed = true;
                    resp.errorMessage = "GOAWAY: server won't process our stream"_s;
                    return resp;
                }
                // else: server still processes us; continue reading
            }
            break;
        case kFrameRstStream:
            if (sid == streamId) {
                resp.failed = true;
                resp.errorMessage = "received RST_STREAM"_s;
                return resp;
            }
            break;
        default:
            // Ignore unknown frame types (RFC 7540 §5.5)
            break;
        }
    }

    WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.140] HTTP/2 request to %s%s completed: status=%d, body=%zu bytes (frames=%d)",
        request.authority.utf8().data(), request.path.utf8().data(),
        resp.statusCode, resp.body.size(), frameCount);

    // Wave 29-499.220 — auto-decompress response body based on content-encoding
    // WebKit's fast path doesn't auto-decompress; iPhone Safari does it natively.
    // Use Apple's libcompression for gzip/deflate; brotli also supported.
    String contentEncoding;
    {
        // Wave 29-499.266 — dump all response headers for diagnosis
        StringBuilder hdrDump;
        for (auto& [k, v] : resp.headers) {
            hdrDump.append(k);
            hdrDump.append(": "_s);
            hdrDump.append(v);
            hdrDump.append(" | "_s);
        }
        WTFLogAlways("[Wave29-499.266] response headers for %s: %s",
            request.path.utf8().data(), hdrDump.toString().utf8().data());
    }
    for (auto& [k, v] : resp.headers) {
        if (equalIgnoringASCIICase(k, "content-encoding"_s)) {
            contentEncoding = v.convertToASCIILowercase();
            break;
        }
    }
    // Wave 29-499.259 — use system zlib (libz.dylib) directly for gzip+deflate.
    // Apple's COMPRESSION_ZLIB is RFC 1950 (ZLIB-wrapped) and can't decode
    // either raw deflate OR gzip. libz's inflate with windowBits=15+32 auto-
    // detects gzip vs zlib wrappers, handling both formats and the FNAME/FHCRC
    // gzip-header variants Twilio's CDN uses.
    // Wave 29-499.263 — use system libz via <zlib.h>. Apple ships libz at
    // /usr/lib/libz.dylib; we link via -lz. inflateInit2 with windowBits=
    // 15+32 auto-detects gzip OR zlib wrapper format.
    if (!contentEncoding.isEmpty() && !resp.body.isEmpty()
        && (contentEncoding == "gzip"_s || contentEncoding == "deflate"_s)) {
        // Wave 29-499.263b — diagnostic: log first 16 bytes of body to
        // confirm gzip magic (1F 8B 08) or zlib magic (78 ??).
        {
            const uint8_t* b = resp.body.span().data();
            size_t n = resp.body.size();
            WTFLogAlways("[Wave29-499.263b] body first 16 bytes (size=%zu, encoding=%s): %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
                n, contentEncoding.utf8().data(),
                n>0?b[0]:0, n>1?b[1]:0, n>2?b[2]:0, n>3?b[3]:0,
                n>4?b[4]:0, n>5?b[5]:0, n>6?b[6]:0, n>7?b[7]:0,
                n>8?b[8]:0, n>9?b[9]:0, n>10?b[10]:0, n>11?b[11]:0,
                n>12?b[12]:0, n>13?b[13]:0, n>14?b[14]:0, n>15?b[15]:0);
        }
        z_stream zs;
        memset(&zs, 0, sizeof(zs));
        // 15 + 32 = max window + auto-detect gzip/zlib
        int initRv = inflateInit2(&zs, 15 + 32);
        if (initRv == Z_OK) {
            size_t outCapacity = std::min<size_t>(resp.body.size() * 12, kMaxDecompressedBytes); // W2140 bomb cap
            if (outCapacity < 64 * 1024) outCapacity = 64 * 1024;
            Vector<uint8_t> decompressed(outCapacity);

            zs.next_in = const_cast<Bytef*>(resp.body.span().data());
            zs.avail_in = static_cast<uInt>(resp.body.size());
            zs.next_out = decompressed.mutableSpan().data();
            zs.avail_out = static_cast<uInt>(outCapacity);

            int rv = inflate(&zs, Z_FINISH);
            size_t actualLen = zs.total_out;
            inflateEnd(&zs);

            if ((rv == Z_STREAM_END || rv == Z_OK) && actualLen > 0) {
                decompressed.resize(actualLen);
                WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.263] zlib auto-decoded %s: %zu→%zu bytes (rv=%d)",
                    contentEncoding.utf8().data(), resp.body.size(), actualLen, rv);
                resp.body = std::move(decompressed);
                // Wave 29-499.265 — also strip content-length (was compressed
                // size; mismatch w/ decompressed body breaks WebKit parsing).
                Vector<std::pair<String, String>> filtered;
                for (auto& [k, v] : resp.headers) {
                    String klow = k.convertToASCIILowercase();
                    if (klow != "content-encoding"_s && klow != "content-length"_s)
                        filtered.append({ k, v });
                }
                resp.headers = std::move(filtered);
            } else {
                WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.263] zlib inflate FAILED for %s: rv=%d msg='%s'",
                    contentEncoding.utf8().data(), rv, zs.msg ? zs.msg : "(none)");
            }
        } else {
            WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.263] inflateInit2 FAILED rv=%d", initRv);
        }
    } else if (!contentEncoding.isEmpty() && !resp.body.isEmpty()) {
        compression_algorithm algo = (compression_algorithm)0;
        if (contentEncoding == "br"_s)
            algo = COMPRESSION_BROTLI;

        if (algo) {
            // Allocate generous output buffer (10x input as heuristic)
            size_t outCapacity = std::min<size_t>(resp.body.size() * 10, kMaxDecompressedBytes); // W2140 bomb cap
            if (outCapacity < 64 * 1024) outCapacity = 64 * 1024;
            Vector<uint8_t> decompressed(outCapacity);

            const uint8_t* src = resp.body.span().data();
            size_t srcLen = resp.body.size();
            // Wave 29-499.258 — RFC 1952 gzip header parsing. Was fixed-10
            // assumption; broke on gzip streams with FNAME/FCOMMENT/FEXTRA/FHCRC
            // (most production servers set FNAME or FHCRC).
            //
            // Layout:
            //   ID1 ID2 CM FLG MTIME(4) XFL OS [FEXTRA-len(2)+XLEN] [FNAME...\0]
            //   [FCOMMENT...\0] [FHCRC(2)] <DEFLATE> CRC32(4) ISIZE(4)
            if (contentEncoding == "gzip"_s && srcLen >= 18 && src[0] == 0x1F && src[1] == 0x8B) {
                uint8_t flg = src[3];
                size_t hdrLen = 10;  // ID1..OS fixed
                if (flg & 0x04) {  // FEXTRA
                    if (hdrLen + 2 > srcLen) { src = nullptr; }
                    else {
                        uint16_t xlen = src[hdrLen] | (src[hdrLen + 1] << 8);
                        hdrLen += 2 + xlen;
                    }
                }
                if (src && (flg & 0x08)) {  // FNAME (null-terminated)
                    while (hdrLen < srcLen && src[hdrLen] != 0) ++hdrLen;
                    if (hdrLen < srcLen) ++hdrLen;  // skip null
                }
                if (src && (flg & 0x10)) {  // FCOMMENT (null-terminated)
                    while (hdrLen < srcLen && src[hdrLen] != 0) ++hdrLen;
                    if (hdrLen < srcLen) ++hdrLen;
                }
                if (src && (flg & 0x02)) {  // FHCRC
                    hdrLen += 2;
                }
                if (src && hdrLen + 8 <= srcLen) {
                    src = resp.body.span().data() + hdrLen;
                    srcLen = resp.body.size() - hdrLen - 8;  // strip CRC32+ISIZE
                } else {
                    // Malformed; fall back to fixed-10 + 8 strip. W2144: clamp the offset to
                    // the body size so the pointer is never formed PAST-END (technically UB
                    // even when unused) on a body < 10 bytes — behavior-preserving: off=10
                    // when size>=10, else off=size with srcLen=0 (the >18 guard already => 0).
                    size_t off = std::min<size_t>(10, resp.body.size());
                    src = resp.body.span().data() + off;
                    srcLen = (resp.body.size() > 18) ? resp.body.size() - 18 : 0;
                }
            }

            size_t actualLen = compression_decode_buffer(decompressed.mutableSpan().data(),
                outCapacity, src, srcLen, nullptr, algo);
            if (actualLen > 0) {
                decompressed.resize(actualLen);
                WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.220] Decompressed %s: %zu → %zu bytes",
                    contentEncoding.utf8().data(), resp.body.size(), actualLen);
                resp.body = std::move(decompressed);
                // Remove content-encoding header so caller doesn't try to decompress again
                Vector<std::pair<String, String>> filtered;
                for (auto& [k, v] : resp.headers) {
                    if (k.convertToASCIILowercase() != "content-encoding"_s)
                        filtered.append({ k, v });
                }
                resp.headers = std::move(filtered);
            } else {
                WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.220] Decompression failed for %s",
                    contentEncoding.utf8().data());
            }
        }
    }

    // Wave 29-499.200 — log response body to syslog for fingerprint extraction
    // (NetworkProcess sandbox blocks /tmp writes; logs go through XPC).
    {
        const auto& body = resp.body;
        for (size_t off = 0; off < body.size(); off += 800) {
            size_t chunk = std::min(static_cast<size_t>(800), body.size() - off);
            char buf[820] = {0};
            for (size_t i = 0; i < chunk && i < sizeof(buf) - 1; ++i) {
                uint8_t c = body[off + i];
                buf[i] = (c >= 32 && c < 127) ? c : '_';  // printable + placeholder
            }
            WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.200] body[%zu..%zu]=%s", off, off + chunk, buf);
        }
    }

    return resp;
}

// SSL*-based execute (LibreSSL/BoringSSL path; no custom transport).
DriftstackHttp2Response driftstackHttp2Execute(void* ssl, const DriftstackHttp2Request& request)
{
    return driftstackHttp2ExecuteImpl(ssl, nullptr, request);
}

// Wave 29-499.193 — transport-based execute (for custom TLS path).
// Wave 29-499.349 — route the transport EXPLICITLY through the impl instead of
// a thread_local. The ssl arg is a non-null sentinel only so the null-guard
// passes; it is never dereferenced (transport routes every read/write).
DriftstackHttp2Response driftstackHttp2ExecuteVia(const DriftstackHttp2Transport& transport,
                                                  const DriftstackHttp2Request& request)
{
    static uint8_t dummySsl;
    return driftstackHttp2ExecuteImpl(&dummySsl, &transport, request);
}

// ============================================================================
// Wave 29-499.321 (Phase 2.5) — persistent multiplexed HTTP/2 session.
// ============================================================================

static bool transportWriteAll(const DriftstackHttp2Transport& t, const uint8_t* buf, size_t n)
{
    size_t off = 0;
    while (off < n) {
        int w = t.writeFn(t.ctx, buf + off, n - off);
        if (w <= 0)
            return false;
        off += static_cast<size_t>(w);
    }
    return true;
}

static bool transportReadExact(const DriftstackHttp2Transport& t, uint8_t* buf, size_t n)
{
    size_t off = 0;
    while (off < n) {
        int r = t.readFn(t.ctx, buf + off, n - off);
        if (r <= 0)
            return false;
        off += static_cast<size_t>(r);
    }
    return true;
}

RefPtr<DriftstackHttp2Session> DriftstackHttp2Session::create(std::unique_ptr<DriftstackTLS13Client>&& tls,
    std::unique_ptr<DriftstackSocks5Client>&& socks5)
{
    if (!tls)
        return nullptr;
    RefPtr<DriftstackHttp2Session> session = adoptRef(new DriftstackHttp2Session(std::move(tls), std::move(socks5)));
    if (!session->sendPrefaceAndSettings())
        return nullptr;
    // Start the background reader. It holds a ref so the session (and the TLS +
    // SOCKS5 connection it owns) stays alive while the connection is open; it
    // drops the ref when the loop exits (peer GOAWAY / transport error).
    session->m_readerThread = Thread::create("driftstack-h2-session"_s, [session = session.copyRef()]() mutable {
        session->readerLoop();
    });
    return session;
}

DriftstackHttp2Session::DriftstackHttp2Session(std::unique_ptr<DriftstackTLS13Client>&& tls,
    std::unique_ptr<DriftstackSocks5Client>&& socks5)
    : m_tls(std::move(tls))
    , m_socks5(std::move(socks5))
{
    // Transport reads/writes go through the owned TLS client.
    m_transport.ctx = m_tls.get();
    m_transport.readFn = [](void* ctx, uint8_t* buf, size_t n) -> int {
        return reinterpret_cast<DriftstackTLS13Client*>(ctx)->read(buf, n);
    };
    m_transport.writeFn = [](void* ctx, const uint8_t* buf, size_t n) -> int {
        return reinterpret_cast<DriftstackTLS13Client*>(ctx)->write(buf, n);
    };
}

DriftstackHttp2Session::~DriftstackHttp2Session()
{
}

bool DriftstackHttp2Session::isAlive()
{
    Locker locker { m_lock };
    return m_alive;
}

bool DriftstackHttp2Session::sendPrefaceAndSettings()
{
    Locker locker { m_writeLock };
    if (!transportWriteAll(m_transport, reinterpret_cast<const uint8_t*>(kHttp2Preface), sizeof(kHttp2Preface) - 1))
        return false;
    // iPhone Safari 26 SETTINGS (same values + order as the one-shot path).
    Vector<uint8_t> sp;
    auto pushSetting = [&](uint16_t id, uint32_t val) {
        sp.append(static_cast<uint8_t>(id >> 8)); sp.append(static_cast<uint8_t>(id & 0xff));
        sp.append(static_cast<uint8_t>((val >> 24) & 0xff)); sp.append(static_cast<uint8_t>((val >> 16) & 0xff));
        sp.append(static_cast<uint8_t>((val >> 8) & 0xff)); sp.append(static_cast<uint8_t>(val & 0xff));
    };
    // iPhone 17 / Safari 26.4 order+values (BS capture Wave .323): 2:0;3:100;4:2097152;9:1
    pushSetting(kSettingEnablePush, 0);              // 2:0
    pushSetting(kSettingMaxConcurrentStreams, 100);  // 3:100
    pushSetting(kSettingInitialWindowSize, 2097152); // 4:2097152
    pushSetting(kSettingNoRfc7540Priorities, 1);     // 9:1
    uint8_t sh[9];
    encodeFrameHeader(sh, sp.size(), kFrameSettings, 0, 0);
    if (!transportWriteAll(m_transport, sh, 9) || !transportWriteAll(m_transport, sp.span().data(), sp.size()))
        return false;
    uint8_t wu[13];
    encodeFrameHeader(wu, 4, kFrameWindowUpdate, 0, 0);
    uint32_t inc = 10420225;
    wu[9] = (inc >> 24) & 0xff; wu[10] = (inc >> 16) & 0xff; wu[11] = (inc >> 8) & 0xff; wu[12] = inc & 0xff;
    return transportWriteAll(m_transport, wu, 13);
}

void DriftstackHttp2Session::readerLoop()
{
    // HPACK decode state for THIS connection — persists across every HEADERS block
    // for the whole session lifetime (HPACK is stateful + order-dependent; the
    // reader thread is the single decoder). This is what makes dynamic-indexed
    // response headers (e.g. access-control-allow-origin on reused connections)
    // decode correctly instead of being dropped.
    HpackDecoderState hpackDyn;
    // a74622fc Phase 1 — collects (callbacks, resp) pairs for async streams that just became
    // terminal so they can be invoked AFTER releasing m_lock (never call out to arbitrary
    // client code while holding the session lock — risk (a) in the design). Reused at all 4
    // terminal points (markDeadAndFailAll, GOAWAY, RST_STREAM, HEADERS/DATA END_STREAM).
    struct FinishedAsync { AsyncStreamCallbacks cb; DriftstackHttp2Response resp; bool headersAlreadyDelivered { false }; };
    auto deliverFinishedAsync = [](Vector<FinishedAsync>&& finished) {
        for (auto& f : finished) {
            if (!f.resp.failed)
                driftstackDecompressHttp2Body(f.resp);
            if (!f.headersAlreadyDelivered && f.cb.onHeaders)
                f.cb.onHeaders(f.resp.statusCode, f.resp.headers);
            if (!f.resp.body.isEmpty() && f.cb.onData)
                f.cb.onData(f.resp.body.span().data(), f.resp.body.size());
            if (f.cb.onComplete)
                f.cb.onComplete(f.resp.failed, f.resp.errorMessage);
        }
    };
    auto markDeadAndFailAll = [&] {
        Vector<FinishedAsync> finished;
        {
            Locker locker { m_lock };
            m_alive = false;
            Vector<uint32_t> toRemove;
            for (auto& [id, s] : m_streams) {
                // Don't clobber a stream that already completed successfully but whose
                // execute() hasn't removed it from the map yet (race: reader hits EOF
                // right after delivering END_STREAM). Only fail still-in-flight streams.
                if (!s->complete) {
                    s->failed = true;
                    s->complete = true;
                    if (s->asyncCallbacks) {
                        s->resp.failed = true;
                        if (s->resp.errorMessage.isEmpty())
                            s->resp.errorMessage = "h2 connection lost"_s;
                        finished.append({ std::exchange(*s->asyncCallbacks, {}), std::move(s->resp), s->asyncHeadersDelivered });
                        toRemove.append(id);
                    }
                }
            }
            for (auto id : toRemove)
                m_streams.remove(id);
            m_cond.notifyAll();
        }
        deliverFinishedAsync(std::move(finished));
    };

    for (;;) {
        uint8_t hdr[9];
        if (!transportReadExact(m_transport, hdr, 9)) { markDeadAndFailAll(); return; }
        uint32_t length; uint8_t type, frameFlags; uint32_t sid;
        decodeFrameHeader(hdr, length, type, frameFlags, sid);
        if (length > kMaxRecvFrameBytes) { markDeadAndFailAll(); return; }  // W2415 — reject oversized frame

        Vector<uint8_t> payload;
        if (length) {
            payload.resize(length);
            if (!transportReadExact(m_transport, payload.mutableSpan().data(), length)) { markDeadAndFailAll(); return; }
        }

        switch (type) {
        case kFrameSettings:
            if (!(frameFlags & kFlagAck)) {
                Locker w { m_writeLock };
                uint8_t ack[9]; encodeFrameHeader(ack, 0, kFrameSettings, kFlagAck, 0);
                transportWriteAll(m_transport, ack, 9);
            }
            break;
        case kFramePing:
            if (!(frameFlags & kFlagAck) && length == 8) {
                Locker w { m_writeLock };
                uint8_t pong[9 + 8]; encodeFrameHeader(pong, 8, kFramePing, kFlagAck, 0);
                memcpy(pong + 9, payload.span().data(), 8);
                transportWriteAll(m_transport, pong, sizeof(pong));
            }
            break;
        case kFrameGoaway: {
            uint32_t lastSid = payload.size() >= 4 ? ((uint32_t(payload[0]) << 24) | (uint32_t(payload[1]) << 16) | (uint32_t(payload[2]) << 8) | payload[3]) : 0;
            uint32_t errCode = payload.size() >= 8 ? ((uint32_t(payload[4]) << 24) | (uint32_t(payload[5]) << 16) | (uint32_t(payload[6]) << 8) | payload[7]) : 0;
            // RFC 7540 §6.8 — GOAWAY means "no NEW streams", but streams with id <= lastStreamId
            // MAY still be completed by the server. Failing them all (the old behavior) loses the
            // response for an in-flight request whenever a server gracefully closes after serving
            // it (e.g. tls.browserleaks.com sends GOAWAY lastStreamId=1 errorCode=0 right around
            // the response → ja3/ja4 rendered N/A). So: retire the session for reuse, fail ONLY
            // streams > lastStreamId, and keep reading so streams <= lastStreamId can complete.
            bool anyInflight = false;
            Vector<FinishedAsync> goawayFinished;
            {
                Locker locker { m_lock };
                m_alive = false;
                Vector<uint32_t> toRemove;
                for (auto& [id, s] : m_streams) {
                    if (id > lastSid) {
                        s->failed = true; s->complete = true;
                        if (s->asyncCallbacks) {
                            s->resp.failed = true;
                            if (s->resp.errorMessage.isEmpty())
                                s->resp.errorMessage = "h2 GOAWAY (stream not processed by server)"_s;
                            goawayFinished.append({ std::exchange(*s->asyncCallbacks, {}), std::move(s->resp), s->asyncHeadersDelivered });
                            toRemove.append(id);
                        }
                    } else if (!s->complete) anyInflight = true;
                }
                for (auto id : toRemove)
                    m_streams.remove(id);
                m_cond.notifyAll();
            }
            deliverFinishedAsync(std::move(goawayFinished));
            WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.342] h2 GOAWAY: lastStreamId=%u errorCode=%u — session retired; %s",
                lastSid, errCode, anyInflight ? "draining in-flight streams <= lastStreamId" : "no in-flight streams, closing");
            if (!anyInflight) { markDeadAndFailAll(); return; }
            break; // keep reading until the in-flight (<= lastStreamId) streams finish, then EOF closes us
        }
        case kFrameWindowUpdate:
            break; // we replenish our own receive window in the DATA path
        case kFrameRstStream: {
            uint32_t errCode = payload.size() >= 4 ? ((uint32_t(payload[0]) << 24) | (uint32_t(payload[1]) << 16) | (uint32_t(payload[2]) << 8) | payload[3]) : 0;
            WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.342] h2 RST_STREAM on stream %u errorCode=%u — failing stream (session stays alive)", sid, errCode);
            std::optional<FinishedAsync> rstFinished;
            {
                Locker locker { m_lock };
                if (auto it = m_streams.find(sid); it != m_streams.end()) {
                    it->value->failed = true;
                    it->value->complete = true;
                    if (it->value->asyncCallbacks) {
                        it->value->resp.failed = true;
                        if (it->value->resp.errorMessage.isEmpty())
                            it->value->resp.errorMessage = makeString("h2 RST_STREAM errorCode="_s, errCode);
                        rstFinished.emplace(FinishedAsync { std::exchange(*it->value->asyncCallbacks, {}), std::move(it->value->resp), it->value->asyncHeadersDelivered });
                        m_streams.remove(sid);
                    }
                    m_cond.notifyAll();
                }
            }
            if (rstFinished)
                deliverFinishedAsync({ std::move(*rstFinished) });
            break;
        }
        case kFrameHeaders: {
            Vector<std::pair<String, String>> decoded;
            size_t start = 0;
            size_t headerEnd = payload.size();
            // RFC 7540 §6.2 (W2528): pad length is a FRONT byte, padding is at the END; the header
            // block is [start, size - padLen). Mirror the §6.1 DATA-frame trim (treating padLen as a
            // front offset desyncs HPACK → corrupted response headers).
            if (frameFlags & kFlagPadded) { if (payload.size() < 1) break; uint8_t padLen = payload[0]; if (static_cast<size_t>(padLen) + 1 > payload.size()) break; start = 1; headerEnd = payload.size() - padLen; }
            if (frameFlags & kFlagPriority) { if (payload.size() < start + 5) break; start += 5; }
            // egress audit wxzzaphvp (#3): CONTINUATION reassembly (RFC 7540 §6.10) — same as the one-shot
            // reader (webkit eb4010919a90). If END_HEADERS is not set the header block continues in
            // immediately-following CONTINUATION frames on the SAME stream (no interleaving allowed, even on
            // a multiplexed session); read them inline via transportReadExact + concatenate before decoding,
            // else a >16 KiB block (large Set-Cookie / many headers) decoded only its first fragment →
            // garbled headers. Common END_HEADERS case leaves blockData/blockLen at this frame → byte-identical.
            const uint8_t* blockData = payload.span().data() + start;
            size_t blockLen = headerEnd - start;
            Vector<uint8_t> contBlock;
            if (!(frameFlags & kFlagEndHeaders)) {
                contBlock.append(std::span<const uint8_t>(blockData, blockLen));
                bool contEnd = false;
                while (!contEnd) {
                    uint8_t chdr[9];
                    if (!transportReadExact(m_transport, chdr, 9)) { markDeadAndFailAll(); return; }
                    uint32_t clen, csid; uint8_t ctype, cflags;
                    decodeFrameHeader(chdr, clen, ctype, cflags, csid);
                    if (ctype != kFrameContinuation || csid != sid || clen > kMaxRecvFrameBytes) { markDeadAndFailAll(); return; }
                    Vector<uint8_t> cpay(clen);
                    if (clen > 0 && !transportReadExact(m_transport, cpay.mutableSpan().data(), clen)) { markDeadAndFailAll(); return; }
                    contBlock.append(cpay.span());
                    if (contBlock.size() > (static_cast<size_t>(1) << 20)) { markDeadAndFailAll(); return; }  // 1 MiB — CONTINUATION-flood DoS bound
                    if (cflags & kFlagEndHeaders) contEnd = true;
                }
                blockData = contBlock.span().data();
                blockLen = contBlock.size();
            }
            size_t cursor = 0;
            while (cursor < blockLen) {
                if (!hpackDecodeOneHeader(blockData, blockLen, cursor, decoded, hpackDyn))
                    break;
            }
            std::function<void(int, const Vector<std::pair<String, String>>&)> headersCb;
            int headersCbStatus = 0;
            Vector<std::pair<String, String>> headersCbHeaders;
            std::optional<FinishedAsync> headersOnlyFinished;
            {
                Locker locker { m_lock };
                auto it = m_streams.find(sid);
                if (it != m_streams.end()) {
                    for (auto& [k, v] : decoded) {
                        if (k == ":status"_s) {
                            int sc = 0; auto v8 = v.utf8();
                            for (size_t i = 0; i < v8.length(); ++i) { char c = v8.data()[i]; if (c < '0' || c > '9') break; sc = sc * 10 + (c - '0'); }
                            if (sc > 0) it->value->resp.statusCode = sc;
                        } else if (!k.startsWith(':'))
                            it->value->resp.headers.append({ k, v });
                    }
                    if (!it->value->resp.statusCode) it->value->resp.statusCode = 200;
                    if (it->value->asyncCallbacks) {
                        it->value->idleDeadline = MonotonicTime::now() + Seconds(60); // progress → extend (Wave .354 semantic, ported)
                        if (frameFlags & kFlagEndStream) {
                            // Headers-only response (no DATA frames coming) — complete now. Pass
                            // headersAlreadyDelivered=false (it->value->asyncHeadersDelivered is still
                            // its default false here) so deliverFinishedAsync delivers onHeaders itself.
                            it->value->complete = true;
                            headersOnlyFinished.emplace(FinishedAsync { std::exchange(*it->value->asyncCallbacks, {}), std::move(it->value->resp), false });
                            m_streams.remove(sid);
                        } else if (it->value->asyncCallbacks->onHeaders) {
                            headersCb = it->value->asyncCallbacks->onHeaders; // copy — callbacks struct still needed for the body/completion path
                            headersCbStatus = it->value->resp.statusCode;
                            headersCbHeaders = it->value->resp.headers; // copy
                            it->value->asyncHeadersDelivered = true; // so DATA-end/RST/GOAWAY finish paths don't re-call onHeaders
                        }
                    }
                    if (frameFlags & kFlagEndStream) { it->value->complete = true; m_cond.notifyAll(); }
                }
            }
            if (headersCb)
                headersCb(headersCbStatus, headersCbHeaders);
            if (headersOnlyFinished)
                deliverFinishedAsync({ std::move(*headersOnlyFinished) });
            break;
        }
        case kFrameData: {
            std::span<const uint8_t> dataSpan = payload.span();
            if (frameFlags & kFlagPadded) {
                if (dataSpan.size() < 1) break;
                uint8_t padLen = dataSpan[0];
                if (static_cast<size_t>(padLen) + 1 > dataSpan.size()) break;
                dataSpan = dataSpan.subspan(1, dataSpan.size() - 1 - padLen);
            }
            std::optional<FinishedAsync> dataFinished;
            {
                Locker locker { m_lock };
                if (auto it = m_streams.find(sid); it != m_streams.end()) {
                    // W2210 (parser-audit weta2casf): cap the per-response body — the one-shot path enforces
                    // kMaxBodyBytes (:924/:1088) but the POOLED path had NO body cap, so a hostile site streaming
                    // unbounded DATA (the window is replenished every frame below) → NetworkProcess OOM. 128 MB
                    // mirrors the one-shot cap (no false-reject of a legit large download; SSE never takes the
                    // pooled/buffered path). On exceed: fail+complete the stream + skip the window replenish so the
                    // server's send window closes (break exits the case before the WINDOW_UPDATE below).
                    constexpr size_t kMaxPooledBodyBytes = 128 * 1024 * 1024;
                    if (it->value->resp.body.size() + dataSpan.size() > kMaxPooledBodyBytes) {
                        it->value->resp.failed = true;
                        it->value->resp.errorMessage = "response body exceeds 128MB cap"_s;
                        it->value->complete = true;
                        if (it->value->asyncCallbacks) {
                            dataFinished.emplace(FinishedAsync { std::exchange(*it->value->asyncCallbacks, {}), std::move(it->value->resp), it->value->asyncHeadersDelivered });
                            m_streams.remove(sid);
                        }
                        m_cond.notifyAll();
                        break;
                    }
                    it->value->resp.body.append(dataSpan);
                    if (it->value->asyncCallbacks)
                        it->value->idleDeadline = MonotonicTime::now() + Seconds(60); // progress → extend (ported .354 semantic)
                    if (frameFlags & kFlagEndStream) {
                        it->value->complete = true;
                        if (it->value->asyncCallbacks) {
                            dataFinished.emplace(FinishedAsync { std::exchange(*it->value->asyncCallbacks, {}), std::move(it->value->resp), it->value->asyncHeadersDelivered });
                            m_streams.remove(sid);
                        }
                        m_cond.notifyAll();
                    }
                }
            }
            if (dataFinished)
                deliverFinishedAsync({ std::move(*dataFinished) });
            // Replenish flow-control windows (connection + stream) by the FULL
            // frame length so large/streamed responses don't stall.
            if (length) {
                Locker w { m_writeLock };
                uint8_t wu[13];
                uint32_t inc = length;
                encodeFrameHeader(wu, 4, kFrameWindowUpdate, 0, 0);
                wu[9] = (inc >> 24) & 0xff; wu[10] = (inc >> 16) & 0xff; wu[11] = (inc >> 8) & 0xff; wu[12] = inc & 0xff;
                transportWriteAll(m_transport, wu, 13); // connection (stream 0)
                encodeFrameHeader(wu, 4, kFrameWindowUpdate, 0, sid);
                transportWriteAll(m_transport, wu, 13); // this stream
            }
            break;
        }
        default:
            break;
        }
    }
}

// a74622fc Phase 1 — factored VERBATIM out of execute() (same body/comments) so submitAsync()
// sends BYTE-IDENTICAL wire frames in the SAME id-alloc+write-lock ordering. Returns the
// allocated stream id, or 0 with outFailureResp.failed=true on send failure (the stream, if
// allocated, has already been removed from m_streams and m_alive cleared in that case — the
// caller must NOT touch m_streams for streamId==0).
uint32_t DriftstackHttp2Session::sendRequestFrames(const DriftstackHttp2Request& request, DriftstackHttp2Response& outFailureResp)
{
    // Wave 29-499.349 — the pooled path still single-frames the body (no
    // chunking/flow control on the shared multiplexed connection yet). A body
    // > 16384 would exceed the peer's default SETTINGS_MAX_FRAME_SIZE and kill
    // the WHOLE pooled connection (GOAWAY fails every in-flight stream). Fail
    // fast instead — the loader falls through to a fresh one-shot connection,
    // whose body send is chunked + flow-controlled.
    if (request.body.size() > 16384) {
        outFailureResp.failed = true;
        outFailureResp.errorMessage = "pooled h2 path declines bodies > 16384 (no per-stream flow control); use one-shot"_s;
        return 0;
    }

    // Build the HEADERS block FIRST — the HPACK encoder is static-table-only (literal
    // WITHOUT indexing; no dynamic table mutation) and writes to this per-call buffer, so it
    // is stateless and needs no lock. The stream id lives in the FRAME header, not the block,
    // so the block is id-independent.
    // iPhone 17 pseudo-header order m,s,a,p (authority BEFORE path) — BS capture Wave .323.
    Vector<uint8_t> hb;
    hpackEncodeHeader(hb, ":method"_s, request.method);
    hpackEncodeHeader(hb, ":scheme"_s, request.scheme);
    hpackEncodeHeader(hb, ":authority"_s, request.authority);
    hpackEncodeHeader(hb, ":path"_s, request.path);
    for (auto& [k, v] : request.extraHeaders)
        hpackEncodeHeader(hb, k.convertToASCIILowercase(), v);

    bool hasBody = !request.body.isEmpty();
    bool sendOk = true;
    uint32_t streamId = 0;
    {
        // Wave 29-499.357 — allocate the stream id AND write its HEADERS ATOMICALLY under the
        // write lock, so concurrent execute() calls emit HEADERS in STRICTLY INCREASING
        // stream-id order. RFC 7540 §5.1.1: opening a higher stream id implicitly closes lower
        // idle streams. The old split-lock path allocated the id under m_lock, RELEASED it, then
        // contended separately for m_writeLock — so stream 5's HEADERS could race ahead of
        // stream 3's. The server then saw a HEADERS frame on the now-implicitly-closed stream 3
        // → connection error GOAWAY STREAM_CLOSED (errorCode 5), which failed EVERY in-flight
        // stream on that connection (the concurrent-subresource stall: github.githubassets.com
        // et al. dropped 6 streams at once, page subresources never loaded). curl never hit this
        // because it serializes HEADERS in id order. Holding m_writeLock across alloc+send fixes
        // the ordering; m_lock is taken briefly inside for m_streams/m_nextStreamId (the reader
        // never nests m_lock→m_writeLock, so no deadlock).
        Locker w { m_writeLock };
        {
            Locker locker { m_lock };
            if (!m_alive) { outFailureResp.failed = true; outFailureResp.errorMessage = "h2 session not alive"_s; return 0; }
            streamId = m_nextStreamId;
            m_nextStreamId += 2;
            if (m_nextStreamId >= 0x7FFFFFFF) m_alive = false; // stream-id space nearly exhausted; retire after this
            m_streams.set(streamId, makeUniqueWithoutFastMallocCheck<Stream>());
        }
        uint8_t fh[9];
        uint8_t flags = kFlagEndHeaders;
        if (!hasBody) flags |= kFlagEndStream;
        encodeFrameHeader(fh, hb.size(), kFrameHeaders, flags, streamId);
        sendOk = transportWriteAll(m_transport, fh, 9) && transportWriteAll(m_transport, hb.span().data(), hb.size());
        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.343] pooled execute: sent HEADERS on stream %u (%s) sendOk=%d path=%s",
            streamId, hasBody ? "with body" : "END_STREAM", sendOk ? 1 : 0, request.path.utf8().data());
        if (sendOk && hasBody) {
            uint8_t dh[9];
            encodeFrameHeader(dh, request.body.size(), kFrameData, kFlagEndStream, streamId);
            sendOk = transportWriteAll(m_transport, dh, 9) && transportWriteAll(m_transport, request.body.span().data(), request.body.size());
        }
    }

    if (!sendOk) {
        Locker locker { m_lock };
        m_streams.remove(streamId);
        m_alive = false;
        outFailureResp.failed = true; outFailureResp.errorMessage = "h2 stream write failed"_s;
        return 0;
    }
    return streamId;
}

DriftstackHttp2Response DriftstackHttp2Session::execute(const DriftstackHttp2Request& request)
{
    DriftstackHttp2Response resp;
    uint32_t streamId = sendRequestFrames(request, resp);
    if (!streamId)
        return resp; // resp already carries failed=true + errorMessage from sendRequestFrames

    Locker locker { m_lock };
    // Wave 29-499.343 — wait for the STREAM to complete, not for the session to stay
    // alive (a graceful GOAWAY sets m_alive=false but our in-flight stream still gets its
    // response a few frames later — breaking on !m_alive lost it → status=0 / ja3 N/A).
    // Wave 29-499.353 — IDLE timeout instead of a fixed 30s total. The concurrent-fetch
    // residual: the server completes the handshake + sends its SETTINGS but never sends the
    // response → the stream gets NO frames. A NO-PROGRESS timeout retires a truly-dead session
    // so the loader retries on a FRESH connection (clears the per-connection concurrency wedge).
    // A large/slow but PROGRESSING response (body grows / status arrives) resets the window each
    // frame, so it is never cut off.
    // Wave 29-499.354 — the timeout MUST match iPhone: iOS NSURLSession.timeoutIntervalForRequest
    // defaults to 60s and means exactly "fail if no additional data for N seconds" — the same
    // no-progress semantic as this loop. The earlier 8s value was a behavioral DIVERGENCE: a real
    // iPhone WAITS for a slow-first-byte endpoint (e.g. httpbin.org/delay/12, slow APIs, heavy
    // queries — curl/iPhone get 200 in ~12s) but 8s cut it off → retry → re-cut → page FAILED on a
    // request iOS would complete. 60s recovers from a genuine permanent stall on iPhone's timeline.
    const Seconds kIdleTimeout = Seconds(60);
    MonotonicTime idleDeadline = MonotonicTime::now() + kIdleTimeout;
    size_t lastBody = 0; int lastStatus = 0; bool idleTimedOut = false;
    static const bool h2wtrace = getenv("DRIFTSTACK_RTR_TRACE") != nullptr;
    int waitIters = 0;
    if (h2wtrace) WTFLogAlways("[H2WAIT] stream=%u REACHED wait-loop (alive=%d)", streamId, m_alive ? 1 : 0);
    while (true) {
        auto it = m_streams.find(streamId);
        if (it == m_streams.end()) break;
        if (it->value->complete) break;
        if (it->value->resp.body.size() != lastBody || it->value->resp.statusCode != lastStatus) {
            lastBody = it->value->resp.body.size(); lastStatus = it->value->resp.statusCode;
            idleDeadline = MonotonicTime::now() + kIdleTimeout; // progress → extend the window
        }
        bool signaled = m_cond.waitUntil(m_lock, idleDeadline);
        if (h2wtrace) WTFLogAlways("[H2WAIT] stream=%u iter=%d waitUntil signaled=%d body=%zu status=%d", streamId, ++waitIters, signaled ? 1 : 0, m_streams.contains(streamId) ? m_streams.get(streamId)->resp.body.size() : 0, m_streams.contains(streamId) ? m_streams.get(streamId)->resp.statusCode : -1);
        if (!signaled) {
            auto it2 = m_streams.find(streamId);
            if (it2 == m_streams.end() || it2->value->complete) break;
            if (it2->value->resp.body.size() == lastBody && it2->value->resp.statusCode == lastStatus) { idleTimedOut = true; break; }
            // else: progress raced in just as we timed out — loop resets the window
        }
    }
    if (h2wtrace) WTFLogAlways("[H2WAIT] stream=%u EXIT loop (idleTimedOut=%d iters=%d)", streamId, idleTimedOut ? 1 : 0, waitIters);
    auto it = m_streams.find(streamId);
    if (it != m_streams.end()) {
        resp = std::move(it->value->resp);
        bool failed = it->value->failed || !it->value->complete;
        m_streams.remove(streamId);
        if (failed && !resp.statusCode) { resp.failed = true; if (resp.errorMessage.isEmpty()) resp.errorMessage = "h2 stream incomplete"_s; }
    } else {
        resp.failed = true; resp.errorMessage = "h2 stream lost"_s;
    }
    // A stalled stream means this connection is wedged — retire it so the loader's retry
    // builds a FRESH connection instead of re-claiming this dead session from the pool.
    if (idleTimedOut) {
        m_alive = false;
        WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.354] pooled stream %u IDLE-timeout (60s no progress, iOS timeoutIntervalForRequest) — retiring session for fresh retry", streamId);
    }
    // Wave 29-499.328 — the pooled path delivers the raw body; decompress Content-Encoding
    // here (gzip/deflate/br) exactly like the single-request path, or WebKit renders the raw
    // compressed bytes (the browserleaks brotli "garbage page").
    if (!resp.failed)
        driftstackDecompressHttp2Body(resp);
    WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.321] HTTP/2 pooled stream %u completed: status=%d, body=%zu bytes (failed=%d)",
        streamId, resp.statusCode, resp.body.size(), resp.failed ? 1 : 0);
    return resp;
}

uint32_t DriftstackHttp2Session::submitAsync(const DriftstackHttp2Request& request, AsyncStreamCallbacks&& callbacks)
{
    DriftstackHttp2Response failureResp;
    uint32_t streamId = sendRequestFrames(request, failureResp);
    if (!streamId) {
        // sendRequestFrames already removed any partially-allocated stream + marked !alive.
        // Nobody else has a handle on this failure — invoke onComplete synchronously so the
        // caller (which returned immediately and has no other way to learn the outcome) isn't
        // left silently hanging forever waiting for a callback that would otherwise never fire.
        if (callbacks.onComplete)
            callbacks.onComplete(true, failureResp.errorMessage);
        return 0;
    }
    Locker locker { m_lock };
    auto it = m_streams.find(streamId);
    if (it == m_streams.end()) {
        // Reader thread already retired the session (e.g. a GOAWAY landed between the send
        // above and this lock) and removed/failed the stream before we could attach callbacks.
        // Deliver the failure now rather than leaking a silent hang.
        locker.unlockEarly();
        if (callbacks.onComplete)
            callbacks.onComplete(true, "h2 stream lost before callbacks attached"_s);
        return 0;
    }
    it->value->idleDeadline = MonotonicTime::now() + Seconds(60); // mirrors execute()'s kIdleTimeout (Wave .354)
    bool alreadyComplete = it->value->complete;
    bool alreadyFailed = it->value->failed;
    DriftstackHttp2Response snapshotResp;
    if (alreadyComplete) {
        // Frames for this stream arrived and completed it between sendRequestFrames() returning
        // and us re-acquiring m_lock here (a real, if narrow, race on a fast/small response —
        // the reader thread runs concurrently with us the whole time). Take over delivery
        // ourselves rather than storing callbacks nobody will ever invoke.
        snapshotResp = std::move(it->value->resp);
        m_streams.remove(streamId);
    } else {
        it->value->asyncCallbacks = std::move(callbacks);
    }
    locker.unlockEarly();
    if (alreadyComplete) {
        if (!alreadyFailed)
            driftstackDecompressHttp2Body(snapshotResp);
        if (callbacks.onHeaders)
            callbacks.onHeaders(snapshotResp.statusCode, snapshotResp.headers);
        if (!snapshotResp.body.isEmpty() && callbacks.onData)
            callbacks.onData(snapshotResp.body.span().data(), snapshotResp.body.size());
        if (callbacks.onComplete)
            callbacks.onComplete(alreadyFailed, snapshotResp.errorMessage);
    }
    return streamId;
}

void DriftstackHttp2Session::cancelStream(uint32_t streamId)
{
    bool hadStream = false;
    {
        Locker locker { m_lock };
        hadStream = m_streams.remove(streamId);
    }
    if (!hadStream)
        return; // already completed + removed by the reader, or never existed — no-op
    Locker w { m_writeLock };
    uint8_t rst[9 + 4];
    encodeFrameHeader(rst, 4, kFrameRstStream, 0, streamId);
    uint32_t cancelCode = 0x8; // CANCEL (RFC 7540 §7)
    rst[9] = (cancelCode >> 24) & 0xff; rst[10] = (cancelCode >> 16) & 0xff; rst[11] = (cancelCode >> 8) & 0xff; rst[12] = cancelCode & 0xff;
    transportWriteAll(m_transport, rst, sizeof(rst));
}

// ===== Wave 29-499.352 — RFC 8441 WebSocket-over-HTTP/2 (Extended CONNECT) =====

// Wave 29-499.356 (security) — per-frame size cap. We advertise no
// SETTINGS_MAX_FRAME_SIZE (default 16384), so a frame larger than this is
// non-compliant; a malicious server could claim a 24-bit length (up to 16MB) per
// frame to force large allocations. 1MB is generous vs the 16KB default while
// bounding the worst case; over it we abort the stream.
static constexpr uint32_t kMaxConnectFrameBytes = 1u << 20;

DriftstackHttp2ConnectStream::DriftstackHttp2ConnectStream(const DriftstackHttp2Transport& t)
    : m_transport(t)
{
}

DriftstackHttp2ConnectStream::~DriftstackHttp2ConnectStream() = default;

int DriftstackHttp2ConnectStream::open(const DriftstackHttp2ConnectRequest& req)
{
    const DriftstackHttp2Transport* tp = &m_transport;
    if (!sslWriteAll(nullptr, tp, reinterpret_cast<const uint8_t*>(kHttp2Preface), sizeof(kHttp2Preface) - 1))
        return -1;

    // SETTINGS (iPhone values — same as the one-shot path for fingerprint parity).
    Vector<uint8_t> sp;
    auto pushSetting = [&](uint16_t id, uint32_t v) {
        sp.append(static_cast<uint8_t>(id >> 8)); sp.append(static_cast<uint8_t>(id & 0xff));
        sp.append(static_cast<uint8_t>((v >> 24) & 0xff)); sp.append(static_cast<uint8_t>((v >> 16) & 0xff));
        sp.append(static_cast<uint8_t>((v >> 8) & 0xff)); sp.append(static_cast<uint8_t>(v & 0xff));
    };
    pushSetting(kSettingEnablePush, 0);
    pushSetting(kSettingMaxConcurrentStreams, 100);
    pushSetting(kSettingInitialWindowSize, 2097152);
    pushSetting(kSettingNoRfc7540Priorities, 1);
    uint8_t sh[9];
    encodeFrameHeader(sh, sp.size(), kFrameSettings, 0, 0);
    if (!sslWriteAll(nullptr, tp, sh, 9) || !sslWriteAll(nullptr, tp, sp.span().data(), sp.size()))
        return -1;

    uint8_t wu[13];
    encodeFrameHeader(wu, 4, kFrameWindowUpdate, 0, 0);
    uint32_t cinc = 10420225;
    wu[9] = (cinc >> 24) & 0xff; wu[10] = (cinc >> 16) & 0xff; wu[11] = (cinc >> 8) & 0xff; wu[12] = cinc & 0xff;
    if (!sslWriteAll(nullptr, tp, wu, 13))
        return -1;

    HpackDecoderState hpackDyn;

    // RFC 8441 §3 — a client MUST NOT send Extended CONNECT until it has received
    // SETTINGS_ENABLE_CONNECT_PROTOCOL. Read frames until the server's first
    // SETTINGS; if 8441 isn't advertised, return -2 (the caller declines WS-over-h2
    // cleanly rather than eating a 400 like postman-echo, which negotiates h2 but
    // doesn't support 8441).
    bool seenServerSettings = false;
    while (!seenServerSettings) {
        uint8_t hdr[9];
        if (!sslReadExact(nullptr, tp, hdr, 9))
            return -1;
        uint32_t length; uint8_t type, flags; uint32_t sid;
        decodeFrameHeader(hdr, length, type, flags, sid);
        Vector<uint8_t> payload;
        if (length > kMaxConnectFrameBytes) return -1;
        payload.resize(length);
        if (length && !sslReadExact(nullptr, tp, payload.mutableSpan().data(), length))
            return -1;
        switch (type) {
        case kFrameSettings:
            if (!(flags & kFlagAck)) {
                for (size_t i = 0; i + 6 <= payload.size(); i += 6) {
                    uint16_t id = (uint16_t(payload[i]) << 8) | payload[i + 1];
                    uint32_t val = (uint32_t(payload[i + 2]) << 24) | (uint32_t(payload[i + 3]) << 16) | (uint32_t(payload[i + 4]) << 8) | payload[i + 5];
                    if (id == kSettingEnableConnectProtocol && val == 1)
                        m_serverEnabledConnectProtocol = true;
                    if (id == kSettingInitialWindowSize) {
                        Locker locker { m_writeLock };
                        m_sendWindow += int64_t(val) - int64_t(m_peerInitialWindow);
                        m_peerInitialWindow = val;
                    }
                }
                { Locker locker { m_writeLock }; uint8_t ack[9]; encodeFrameHeader(ack, 0, kFrameSettings, kFlagAck, 0); sslWriteAll(nullptr, tp, ack, 9); }
                seenServerSettings = true;
            }
            break;
        case kFrameWindowUpdate:
            if (length >= 4) {
                uint32_t winc = (uint32_t(payload[0] & 0x7f) << 24) | (uint32_t(payload[1]) << 16) | (uint32_t(payload[2]) << 8) | payload[3];
                Locker locker { m_writeLock }; m_sendWindow += winc;
            }
            break;
        case kFramePing:
            if (!(flags & kFlagAck)) {
                Locker locker { m_writeLock };
                uint8_t pong[17] = { 0 }; encodeFrameHeader(pong, 8, kFramePing, kFlagAck, 0);
                for (size_t i = 0; i < 8 && i < payload.size(); ++i) pong[9 + i] = payload[i];
                sslWriteAll(nullptr, tp, pong, 17);
            }
            break;
        case kFrameGoaway:
            return -1;
        default:
            break;
        }
    }
    if (!m_serverEnabledConnectProtocol)
        return -2; // server negotiated h2 but does not support RFC 8441

    // Extended CONNECT HEADERS (RFC 8441 §4) — no END_STREAM (stream stays open).
    Vector<uint8_t> hb;
    hpackEncodeHeader(hb, ":method"_s, "CONNECT"_s);
    hpackEncodeHeader(hb, ":protocol"_s, req.protocol);
    hpackEncodeHeader(hb, ":scheme"_s, "https"_s);
    hpackEncodeHeader(hb, ":authority"_s, req.authority);
    hpackEncodeHeader(hb, ":path"_s, req.path);
    for (auto& [k, v] : req.extraHeaders)
        hpackEncodeHeader(hb, k.convertToASCIILowercase(), v);
    uint8_t hh[9];
    encodeFrameHeader(hh, hb.size(), kFrameHeaders, kFlagEndHeaders, kStreamId);
    if (!sslWriteAll(nullptr, tp, hh, 9) || !sslWriteAll(nullptr, tp, hb.span().data(), hb.size()))
        return -1;

    int status = 0;
    bool gotHeaders = false;
    // W2134: completes W2132 for the pooled path — bound the pre-HEADERS frame COUNT so a
    // malicious server stalling HEADERS / flooding control frames can't spin this forever
    // (per-frame length is already capped at kMaxConnectFrameBytes; a legit server sends a
    // handful of frames before HEADERS). Tear down on flood.
    int preHeaderFrames = 0;
    while (!gotHeaders) {
        if (++preHeaderFrames > 100000)
            return -1;
        uint8_t hdr[9];
        if (!sslReadExact(nullptr, tp, hdr, 9))
            return -1;
        uint32_t length; uint8_t type, flags; uint32_t sid;
        decodeFrameHeader(hdr, length, type, flags, sid);
        Vector<uint8_t> payload;
        if (length > kMaxConnectFrameBytes) return -1;
        payload.resize(length);
        if (length && !sslReadExact(nullptr, tp, payload.mutableSpan().data(), length))
            return -1;
        switch (type) {
        case kFrameSettings:
            if (!(flags & kFlagAck)) {
                for (size_t i = 0; i + 6 <= payload.size(); i += 6) {
                    uint16_t id = (uint16_t(payload[i]) << 8) | payload[i + 1];
                    uint32_t val = (uint32_t(payload[i + 2]) << 24) | (uint32_t(payload[i + 3]) << 16) | (uint32_t(payload[i + 4]) << 8) | payload[i + 5];
                    if (id == kSettingEnableConnectProtocol && val == 1)
                        m_serverEnabledConnectProtocol = true;
                    if (id == kSettingInitialWindowSize) {
                        Locker locker { m_writeLock };
                        m_sendWindow += int64_t(val) - int64_t(m_peerInitialWindow);
                        m_peerInitialWindow = val;
                    }
                }
                Locker locker { m_writeLock };
                uint8_t ack[9]; encodeFrameHeader(ack, 0, kFrameSettings, kFlagAck, 0);
                sslWriteAll(nullptr, tp, ack, 9);
            }
            break;
        case kFrameWindowUpdate:
            if (length >= 4) {
                uint32_t winc = (uint32_t(payload[0] & 0x7f) << 24) | (uint32_t(payload[1]) << 16) | (uint32_t(payload[2]) << 8) | payload[3];
                Locker locker { m_writeLock };
                m_sendWindow += winc; m_windowCond.notifyAll();
            }
            break;
        case kFramePing:
            if (!(flags & kFlagAck)) {
                Locker locker { m_writeLock };
                uint8_t pong[17] = { 0 }; encodeFrameHeader(pong, 8, kFramePing, kFlagAck, 0);
                for (size_t i = 0; i < 8 && i < payload.size(); ++i) pong[9 + i] = payload[i];
                sslWriteAll(nullptr, tp, pong, 17);
            }
            break;
        case kFrameHeaders:
            if (sid == kStreamId) {
                Vector<std::pair<String, String>> decoded;
                size_t cursor = 0, start = 0, headerEnd = payload.size();
                // RFC 7540 §6.2 (W2528): pad length is a FRONT byte, padding is at the END; the
                // header block is [start, size - padLen). Mirror the §6.1 DATA-frame trim.
                if (flags & kFlagPadded) { if (payload.size() < 1) break; uint8_t padLen = payload[0]; if (static_cast<size_t>(padLen) + 1 > payload.size()) break; start = 1; headerEnd = payload.size() - padLen; }
                if (flags & kFlagPriority) { if (payload.size() < start + 5) break; start += 5; }
                // egress audit wxzzaphvp (#3): CONTINUATION reassembly (RFC 7540 §6.10) — same pattern as the
                // one-shot/readerLoop readers. A CONNECT-response header block spanning records is never legit
                // (CONNECT responses are tiny) but an adversarial server could split it; reassemble the
                // immediately-following CONTINUATION frames before decoding rather than mis-parsing :status.
                // Common END_HEADERS case leaves blockData/blockLen at this frame → byte-identical.
                const uint8_t* blockData = payload.span().data() + start;
                size_t blockLen = headerEnd - start;
                Vector<uint8_t> contBlock;
                if (!(flags & kFlagEndHeaders)) {
                    contBlock.append(std::span<const uint8_t>(blockData, blockLen));
                    bool contEnd = false;
                    while (!contEnd) {
                        uint8_t chdr[9];
                        if (!sslReadExact(nullptr, tp, chdr, 9)) return -1;
                        uint32_t clen, csid; uint8_t ctype, cflags;
                        decodeFrameHeader(chdr, clen, ctype, cflags, csid);
                        if (ctype != kFrameContinuation || csid != kStreamId || clen > kMaxConnectFrameBytes) return -1;
                        Vector<uint8_t> cpay(clen);
                        if (clen > 0 && !sslReadExact(nullptr, tp, cpay.mutableSpan().data(), clen)) return -1;
                        contBlock.append(cpay.span());
                        if (contBlock.size() > (static_cast<size_t>(1) << 20)) return -1;  // 1 MiB — CONTINUATION-flood bound
                        if (cflags & kFlagEndHeaders) contEnd = true;
                    }
                    blockData = contBlock.span().data();
                    blockLen = contBlock.size();
                }
                cursor = 0;
                while (cursor < blockLen) {
                    if (!hpackDecodeOneHeader(blockData, blockLen, cursor, decoded, hpackDyn))
                        break;
                }
                for (auto& [k, v] : decoded) {
                    if (k == ":status"_s) {
                        status = 0; auto v8 = v.utf8();
                        for (size_t i = 0; i < v8.length(); ++i) { char c = v8.data()[i]; if (c < '0' || c > '9') break; status = status * 10 + (c - '0'); }
                    } else if (!k.startsWith(':'))
                        m_responseHeaders.append({ k, v });
                }
                if (!status) status = 200; // HPACK Huffman :status fallback
                if (flags & kFlagEndStream) m_streamEnded = true;
                gotHeaders = true;
            }
            break;
        case kFrameData:
            // Wave 29-499.356 (security) — DATA before the response HEADERS is an
            // h2 protocol violation; a malicious server streaming it here would
            // grow m_dataLeftover UNBOUNDED → OOM the multi-tenant node. Reject.
            if (sid == kStreamId)
                return -1;
            break;
        case kFrameRstStream:
            if (sid == kStreamId) return -1;
            break;
        case kFrameGoaway:
            return -1;
        default:
            break;
        }
    }
    return status;
}

int DriftstackHttp2ConnectStream::readData(uint8_t* buf, size_t maxLen)
{
    const DriftstackHttp2Transport* tp = &m_transport;
    if (!m_dataLeftover.isEmpty()) {
        size_t take = std::min(maxLen, m_dataLeftover.size());
        memcpy(buf, m_dataLeftover.span().data(), take);
        Vector<uint8_t> rest;
        if (take < m_dataLeftover.size())
            rest.append(m_dataLeftover.span().subspan(take));
        m_dataLeftover = std::move(rest);
        return static_cast<int>(take);
    }
    if (m_streamEnded)
        return 0;
    // W2134: bound the frames read in a single recv call so a server flooding non-DATA
    // frames (never delivering body) can't spin this loop forever (mirrors W2132's
    // streaming no-progress guard; this loop returns on each DATA frame so the counter is
    // per-call). Tear down on flood.
    int framesThisRead = 0;
    while (true) {
        if (++framesThisRead > 100000)
            return -1;
        uint8_t hdr[9];
        if (!sslReadExact(nullptr, tp, hdr, 9))
            return -1;
        uint32_t length; uint8_t type, flags; uint32_t sid;
        decodeFrameHeader(hdr, length, type, flags, sid);
        Vector<uint8_t> payload;
        if (length > kMaxConnectFrameBytes) return -1;
        payload.resize(length);
        if (length && !sslReadExact(nullptr, tp, payload.mutableSpan().data(), length))
            return -1;
        switch (type) {
        case kFrameData:
            if (sid == kStreamId) {
                std::span<const uint8_t> ds = payload.span();
                if (flags & kFlagPadded) { if (ds.size() < 1) break; uint8_t pl = ds[0]; if (size_t(pl) + 1 > ds.size()) break; ds = ds.subspan(1, ds.size() - 1 - pl); }
                m_recvSinceUpdate += ds.size();
                m_connRecvSinceUpdate += ds.size();
                // iOS-faithful mid-stream WINDOW_UPDATE cadence (gt http2_windowupdate_midstream_cadence,
                // real-iPhone captured ×2): the STREAM window replenishes at window/4
                // (kDriftstackStreamWUThreshold) and the CONNECTION window at window/2
                // (kDriftstackConnWUThreshold) — DIFFERENT thresholds, tracked separately.
                // The earlier "coherence" fix made both a fixed 1 MiB; that was coherent
                // but matched neither iOS cadence. Now both paths (streaming + this CONNECT
                // path) share the SAME window-fraction rule so they're coherent AND correct.
                if (m_recvSinceUpdate >= kDriftstackStreamWUThreshold) {
                    uint32_t inc = static_cast<uint32_t>(m_recvSinceUpdate);
                    Locker locker { m_writeLock };
                    uint8_t w[13]; encodeFrameHeader(w, 4, kFrameWindowUpdate, 0, kStreamId);
                    w[9] = (inc >> 24) & 0xff; w[10] = (inc >> 16) & 0xff; w[11] = (inc >> 8) & 0xff; w[12] = inc & 0xff;
                    sslWriteAll(nullptr, tp, w, 13);
                    m_recvSinceUpdate = 0;
                }
                if (m_connRecvSinceUpdate >= kDriftstackConnWUThreshold) {
                    uint32_t inc = static_cast<uint32_t>(m_connRecvSinceUpdate);
                    Locker locker { m_writeLock };
                    uint8_t wc[13]; encodeFrameHeader(wc, 4, kFrameWindowUpdate, 0, 0);
                    wc[9] = (inc >> 24) & 0xff; wc[10] = (inc >> 16) & 0xff; wc[11] = (inc >> 8) & 0xff; wc[12] = inc & 0xff;
                    sslWriteAll(nullptr, tp, wc, 13);
                    m_connRecvSinceUpdate = 0;
                }
                if (flags & kFlagEndStream) m_streamEnded = true;
                if (ds.empty()) { if (m_streamEnded) return 0; continue; }
                size_t take = std::min(maxLen, ds.size());
                memcpy(buf, ds.data(), take);
                if (take < ds.size()) m_dataLeftover.append(ds.subspan(take, ds.size() - take));
                return static_cast<int>(take);
            }
            break;
        case kFrameWindowUpdate:
            if (length >= 4) {
                uint32_t winc = (uint32_t(payload[0] & 0x7f) << 24) | (uint32_t(payload[1]) << 16) | (uint32_t(payload[2]) << 8) | payload[3];
                Locker locker { m_writeLock };
                m_sendWindow += winc; m_windowCond.notifyAll();
            }
            break;
        case kFrameSettings:
            if (!(flags & kFlagAck)) {
                for (size_t i = 0; i + 6 <= payload.size(); i += 6) {
                    uint16_t id = (uint16_t(payload[i]) << 8) | payload[i + 1];
                    uint32_t val = (uint32_t(payload[i + 2]) << 24) | (uint32_t(payload[i + 3]) << 16) | (uint32_t(payload[i + 4]) << 8) | payload[i + 5];
                    if (id == kSettingInitialWindowSize) {
                        Locker locker { m_writeLock };
                        m_sendWindow += int64_t(val) - int64_t(m_peerInitialWindow);
                        m_peerInitialWindow = val; m_windowCond.notifyAll();
                    }
                }
                Locker locker { m_writeLock };
                uint8_t ack[9]; encodeFrameHeader(ack, 0, kFrameSettings, kFlagAck, 0);
                sslWriteAll(nullptr, tp, ack, 9);
            }
            break;
        case kFramePing:
            if (!(flags & kFlagAck)) {
                Locker locker { m_writeLock };
                uint8_t pong[17] = { 0 }; encodeFrameHeader(pong, 8, kFramePing, kFlagAck, 0);
                for (size_t i = 0; i < 8 && i < payload.size(); ++i) pong[9 + i] = payload[i];
                sslWriteAll(nullptr, tp, pong, 17);
            }
            break;
        case kFrameRstStream:
            if (sid == kStreamId) return -1;
            break;
        case kFrameGoaway:
            return -1;
        default:
            break;
        }
    }
}

bool DriftstackHttp2ConnectStream::sendData(const uint8_t* data, size_t len)
{
    const DriftstackHttp2Transport* tp = &m_transport;
    constexpr size_t kChunk = 16384;
    size_t off = 0;
    if (!len) // a zero-length WS write is a no-op (END_STREAM is via close())
        return true;
    while (off < len) {
        Locker locker { m_writeLock };
        while (m_sendWindow <= 0 && !m_closed)
            m_windowCond.wait(m_writeLock);
        if (m_closed)
            return false;
        size_t budget = std::min({ kChunk, len - off, static_cast<size_t>(m_sendWindow) });
        uint8_t dh[9];
        encodeFrameHeader(dh, budget, kFrameData, 0, kStreamId);
        if (!sslWriteAll(nullptr, tp, dh, 9) || !sslWriteAll(nullptr, tp, data + off, budget))
            return false;
        m_sendWindow -= budget;
        off += budget;
    }
    return true;
}

void DriftstackHttp2ConnectStream::close()
{
    Locker locker { m_writeLock };
    if (m_closed)
        return;
    m_closed = true;
    const DriftstackHttp2Transport* tp = &m_transport;
    uint8_t dh[9];
    encodeFrameHeader(dh, 0, kFrameData, kFlagEndStream, kStreamId);
    sslWriteAll(nullptr, tp, dh, 9);
    m_windowCond.notifyAll();
}

} // namespace WebKit

WTF_ALLOW_UNSAFE_BUFFER_USAGE_END

#endif // PLATFORM(DRIFTSTACK)
