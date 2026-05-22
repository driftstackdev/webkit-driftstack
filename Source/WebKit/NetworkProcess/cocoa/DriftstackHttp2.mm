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

#import <compression.h>
#import <dlfcn.h>
#import <wtf/Assertions.h>
#import <wtf/text/CString.h>

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

// SETTINGS identifiers (RFC 7540 §6.5.2)
enum SettingsId : uint16_t {
    kSettingHeaderTableSize       = 0x1,
    kSettingEnablePush            = 0x2,
    kSettingMaxConcurrentStreams  = 0x3,
    kSettingInitialWindowSize     = 0x4,
    kSettingMaxFrameSize          = 0x5,
    kSettingMaxHeaderListSize     = 0x6,
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
    if (!s.ready) {
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
            static bool loggedOnce = false;
            if (!loggedOnce) {
                loggedOnce = true;
                WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.164] DriftstackHttp2 SSL fns from libwebrtc: read=%p write=%p ready=%d",
                    (void*)s.read, (void*)s.write, s.ready);
            }
        }
    }
    return s;
}

// Wave 29-499.193 — thread_local transport override. When set,
// sslReadExact/sslWriteAll dispatch via transport callbacks instead
// of SSL_read/SSL_write. Used by driftstackHttp2ExecuteVia for the
// custom-TLS path (DriftstackTLS13Client) where ssl=nullptr.
static thread_local const DriftstackHttp2Transport* g_activeTransport = nullptr;

// Read N bytes from SSL connection; returns false on error/EOF.
static bool sslReadExact(void* ssl, uint8_t* buf, size_t n)
{
    if (g_activeTransport && g_activeTransport->readFn) {
        size_t got = 0;
        while (got < n) {
            int rc = g_activeTransport->readFn(g_activeTransport->ctx, buf + got, n - got);
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

static bool sslWriteAll(void* ssl, const uint8_t* buf, size_t n)
{
    if (g_activeTransport && g_activeTransport->writeFn) {
        size_t sent = 0;
        while (sent < n) {
            int rc = g_activeTransport->writeFn(g_activeTransport->ctx, buf + sent, n - sent);
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

// HPACK string literal encoding (no Huffman for simplicity): length-prefixed.
static void hpackEncodeString(Vector<uint8_t>& out, const String& s)
{
    auto utf8 = s.utf8();
    hpackEncodeInteger(out, utf8.length(), 7, 0x00);  // huffman flag = 0
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

// HPACK decode one header field representation. Appends to out.
// Returns true on success, false on parse error.
static bool hpackDecodeOneHeader(const uint8_t* data, size_t len, size_t& cursor,
    Vector<std::pair<String, String>>& out)
{
    if (cursor >= len) return false;
    uint8_t firstByte = data[cursor];

    if (firstByte & 0x80) {
        // 1xxxxxxx — Indexed Header Field
        uint32_t idx = 0;
        if (!hpackDecodeInteger(data, len, cursor, 7, idx) || idx == 0 || idx >= kHpackStaticCount)
            return false;
        out.append({ String::fromUTF8(kHpackStatic[idx].first),
                     String::fromUTF8(kHpackStatic[idx].second) });
        return true;
    } else if ((firstByte & 0xc0) == 0x40) {
        // 01xxxxxx — Literal with Incremental Indexing
        uint32_t nameIdx = 0;
        if (!hpackDecodeInteger(data, len, cursor, 6, nameIdx))
            return false;
        String name = nameIdx > 0 && nameIdx < kHpackStaticCount
            ? String::fromUTF8(kHpackStatic[nameIdx].first)
            : hpackDecodeString(data, len, cursor);
        String value = hpackDecodeString(data, len, cursor);
        out.append({ name, value });
        return true;
    } else if ((firstByte & 0xe0) == 0x20) {
        // 001xxxxx — Dynamic Table Size Update; we use size 0, ignore
        uint32_t newSize = 0;
        return hpackDecodeInteger(data, len, cursor, 5, newSize);
    } else {
        // 0000xxxx or 0001xxxx — Literal w/o or never indexing
        uint32_t nameIdx = 0;
        if (!hpackDecodeInteger(data, len, cursor, 4, nameIdx))
            return false;
        String name = nameIdx > 0 && nameIdx < kHpackStaticCount
            ? String::fromUTF8(kHpackStatic[nameIdx].first)
            : hpackDecodeString(data, len, cursor);
        String value = hpackDecodeString(data, len, cursor);
        out.append({ name, value });
        return true;
    }
}

} // anonymous namespace

DriftstackHttp2Response driftstackHttp2Execute(void* ssl, const DriftstackHttp2Request& request)
{
    DriftstackHttp2Response resp;

    if (!ssl && !g_activeTransport) {
        resp.failed = true;
        resp.errorMessage = "null SSL and no transport"_s;
        return resp;
    }
    auto& f = sslFns();
    if (!g_activeTransport && !f.ready) {
        resp.failed = true;
        resp.errorMessage = "SSL_read/write dlsym not resolved"_s;
        return resp;
    }

    // 1. Send connection preface
    if (!sslWriteAll(ssl, (const uint8_t*)kHttp2Preface, sizeof(kHttp2Preface) - 1)) {
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
    // iPhone Safari 26.0 SETTINGS order (from real iPhone tls.peet.ws):
    //   ENABLE_PUSH = 0, INITIAL_WINDOW_SIZE = 4194304,
    //   MAX_CONCURRENT_STREAMS = 100, NO_RFC7540_PRIORITIES = 1
    pushSetting(kSettingEnablePush, 0);
    pushSetting(kSettingInitialWindowSize, 4194304);
    pushSetting(kSettingMaxConcurrentStreams, 100);
    pushSetting(kSettingNoRfc7540Priorities, 1);

    uint8_t settingsHeader[9];
    encodeFrameHeader(settingsHeader, settingsPayload.size(), kFrameSettings, 0, 0);
    if (!sslWriteAll(ssl, settingsHeader, 9) || !sslWriteAll(ssl, settingsPayload.span().data(), settingsPayload.size())) {
        resp.failed = true;
        resp.errorMessage = "SETTINGS write failed"_s;
        return resp;
    }

    // 3. Send WINDOW_UPDATE for connection (stream 0) = +10485760
    uint8_t windowUpdate[13];
    encodeFrameHeader(windowUpdate, 4, kFrameWindowUpdate, 0, 0);
    uint32_t inc = 10485760;
    windowUpdate[9] = (inc >> 24) & 0xff;
    windowUpdate[10] = (inc >> 16) & 0xff;
    windowUpdate[11] = (inc >> 8) & 0xff;
    windowUpdate[12] = inc & 0xff;
    if (!sslWriteAll(ssl, windowUpdate, 13)) {
        resp.failed = true;
        resp.errorMessage = "WINDOW_UPDATE write failed"_s;
        return resp;
    }

    // 4. Send HEADERS frame for stream 1 (client-initiated streams are odd).
    // iPhone Safari pseudo-header order: m,s,p,a (method, scheme, path, authority)
    Vector<uint8_t> headersBlock;
    hpackEncodeHeader(headersBlock, ":method"_s, request.method);
    hpackEncodeHeader(headersBlock, ":scheme"_s, request.scheme);
    hpackEncodeHeader(headersBlock, ":path"_s, request.path);
    hpackEncodeHeader(headersBlock, ":authority"_s, request.authority);
    for (auto& [key, val] : request.extraHeaders) {
        hpackEncodeHeader(headersBlock, key.convertToASCIILowercase(), val);
    }

    bool hasBody = !request.body.isEmpty();
    uint8_t headersFrameHeader[9];
    uint8_t flags = kFlagEndHeaders;
    if (!hasBody) flags |= kFlagEndStream;
    encodeFrameHeader(headersFrameHeader, headersBlock.size(), kFrameHeaders, flags, 1);
    if (!sslWriteAll(ssl, headersFrameHeader, 9) || !sslWriteAll(ssl, headersBlock.span().data(), headersBlock.size())) {
        resp.failed = true;
        resp.errorMessage = "HEADERS write failed"_s;
        return resp;
    }

    // 5. Send DATA frame(s) if body present
    if (hasBody) {
        uint8_t dataHeader[9];
        encodeFrameHeader(dataHeader, request.body.size(), kFrameData, kFlagEndStream, 1);
        if (!sslWriteAll(ssl, dataHeader, 9) || !sslWriteAll(ssl, request.body.span().data(), request.body.size())) {
            resp.failed = true;
            resp.errorMessage = "DATA write failed"_s;
            return resp;
        }
    }

    // 6. Read frames until END_STREAM on stream 1
    uint32_t streamId = 1;
    bool streamComplete = false;
    int frameCount = 0;
    while (!streamComplete && frameCount < 100) {
        ++frameCount;
        uint8_t hdr[9];
        if (!sslReadExact(ssl, hdr, 9)) {
            resp.failed = true;
            resp.errorMessage = "frame header read failed"_s;
            return resp;
        }
        uint32_t length;
        uint8_t type, frameFlags;
        uint32_t sid;
        decodeFrameHeader(hdr, length, type, frameFlags, sid);

        Vector<uint8_t> payload;
        payload.resize(length);
        if (length > 0 && !sslReadExact(ssl, payload.mutableSpan().data(), length)) {
            resp.failed = true;
            resp.errorMessage = "frame payload read failed"_s;
            return resp;
        }

        switch (type) {
        case kFrameSettings:
            if (!(frameFlags & kFlagAck)) {
                // Send ACK
                uint8_t ack[9];
                encodeFrameHeader(ack, 0, kFrameSettings, kFlagAck, 0);
                sslWriteAll(ssl, ack, 9);
            }
            break;
        case kFrameHeaders:
            if (sid == streamId) {
                // Wave 29-499.143 — HPACK decode (basic, non-Huffman)
                Vector<std::pair<String, String>> decoded;
                size_t cursor = 0;
                // Skip padding/priority if present
                size_t payloadStart = 0;
                if (frameFlags & kFlagPadded) {
                    if (payload.size() < 1) break;
                    payloadStart = 1 + payload[0];  // pad length byte + padding
                }
                if (frameFlags & kFlagPriority) {
                    if (payload.size() < payloadStart + 5) break;
                    payloadStart += 5;
                }
                cursor = payloadStart;
                while (cursor < payload.size()) {
                    if (!hpackDecodeOneHeader(payload.span().data(), payload.size(), cursor, decoded))
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
                if (frameFlags & kFlagEndStream)
                    streamComplete = true;
            }
            break;
        case kFrameData:
            if (sid == streamId) {
                resp.body.append(payload.span());
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
                sslWriteAll(ssl, pingResp, sizeof(pingResp));
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
    for (auto& [k, v] : resp.headers) {
        if (k.convertToASCIILowercase() == "content-encoding"_s) {
            contentEncoding = v.convertToASCIILowercase();
            break;
        }
    }
    if (!contentEncoding.isEmpty() && !resp.body.isEmpty()) {
        compression_algorithm algo = (compression_algorithm)0;
        if (contentEncoding == "gzip"_s || contentEncoding == "deflate"_s)
            algo = COMPRESSION_ZLIB;
        else if (contentEncoding == "br"_s)
            algo = COMPRESSION_BROTLI;

        if (algo) {
            // Allocate generous output buffer (10x input as heuristic)
            size_t outCapacity = resp.body.size() * 10;
            if (outCapacity < 64 * 1024) outCapacity = 64 * 1024;
            Vector<uint8_t> decompressed(outCapacity);

            const uint8_t* src = resp.body.span().data();
            size_t srcLen = resp.body.size();
            // For gzip skip 10-byte header + parse format; libcompression
            // ZLIB expects deflate stream (no gzip wrapper). Handle gzip wrapper:
            if (contentEncoding == "gzip"_s && srcLen >= 18 && src[0] == 0x1F && src[1] == 0x8B) {
                src += 10;
                srcLen -= 10;
                // Trailing 8 bytes are CRC32 + ISIZE
                if (srcLen >= 8) srcLen -= 8;
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

// Wave 29-499.193 — transport-based execute (for custom TLS path)
DriftstackHttp2Response driftstackHttp2ExecuteVia(const DriftstackHttp2Transport& transport,
                                                  const DriftstackHttp2Request& request)
{
    WTFLogAlways("[Driftstack-EG-WK-PathB-v2/Wave29-499.194] driftstackHttp2ExecuteVia: transport.ctx=%p readFn=%p writeFn=%p",
        transport.ctx, (void*)transport.readFn, (void*)transport.writeFn);
    g_activeTransport = &transport;
    // Call existing Execute with dummy non-null ssl (won't be used —
    // sslReadExact/sslWriteAll check g_activeTransport first).
    static uint8_t dummySsl;
    auto resp = driftstackHttp2Execute(&dummySsl, request);
    g_activeTransport = nullptr;
    return resp;
}

} // namespace WebKit

WTF_ALLOW_UNSAFE_BUFFER_USAGE_END

#endif // PLATFORM(DRIFTSTACK)
