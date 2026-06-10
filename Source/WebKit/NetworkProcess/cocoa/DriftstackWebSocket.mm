/*
 * DriftstackWebSocket.mm — Wave 29-499.351. See DriftstackWebSocket.h.
 */

#import "config.h"
#import "DriftstackWebSocket.h"

#if PLATFORM(DRIFTSTACK)

#import "DriftstackHttp2.h"
#import "DriftstackSocks5Client.h"
#import "DriftstackTLS13Client.h"
#import <stdlib.h>
#import <sys/socket.h>
#import <wtf/Assertions.h>
#import <wtf/StdLibExtras.h>
#import <wtf/text/Base64.h>
#import <wtf/text/CString.h>
#import <wtf/text/MakeString.h>
#import <wtf/text/StringBuilder.h>
#import <wtf/text/StringToIntegerConversion.h>

namespace WebKit {

WTF_ALLOW_UNSAFE_BUFFER_USAGE_BEGIN

DriftstackWebSocket::DriftstackWebSocket(DriftstackWebSocketConfig&& config, DriftstackWebSocketCallbacks&& cb)
    : m_config(std::move(config))
    , m_cb(std::move(cb))
{
}

DriftstackWebSocket::~DriftstackWebSocket()
{
    cancel();
    if (m_thread)
        m_thread->waitForCompletion();
}

void DriftstackWebSocket::start()
{
    m_thread = Thread::create("DriftstackWebSocket"_s, [this] {
        if (!connectAndHandshake()) {
            if (!m_stop.load() && m_cb.onError)
                m_cb.onError("WebSocket handshake failed"_s);
            return;
        }
        readerLoop();
    });
}

int DriftstackWebSocket::tlsRead(uint8_t* buf, size_t n)
{
    // h2 (RFC 8441): the WS bytes are tunneled in h2 DATA frames — read them via
    // the CONNECT stream. The RFC 6455 frame parser above is transport-agnostic.
    if (m_isH2 && m_h2stream)
        return m_h2stream->readData(buf, n);
    if (m_config.secure && m_tls)
        return m_tls->read(buf, n);
    int fd = m_socks5 ? m_socks5->socketFileDescriptor() : -1;
    if (fd < 0)
        return -1;
    return static_cast<int>(::recv(fd, buf, n, 0));
}

bool DriftstackWebSocket::tlsWriteAll(const uint8_t* buf, size_t n)
{
    if (m_isH2 && m_h2stream)
        return m_h2stream->sendData(buf, n);
    size_t off = 0;
    while (off < n) {
        int w;
        if (m_config.secure && m_tls)
            w = m_tls->write(buf + off, n - off);
        else {
            int fd = m_socks5 ? m_socks5->socketFileDescriptor() : -1;
            if (fd < 0)
                return false;
            w = static_cast<int>(::send(fd, buf + off, n - off, 0));
        }
        if (w <= 0)
            return false;
        off += static_cast<size_t>(w);
    }
    return true;
}

bool DriftstackWebSocket::connectAndHandshake()
{
    // SOCKS5 to the customer proxy.
    Socks5Endpoint proxy;
    proxy.host = m_config.proxyHost;
    proxy.port = m_config.proxyPort;
    Socks5Credentials creds;
    if (!m_config.proxyUser.isEmpty()) {
        creds.username = m_config.proxyUser;
        creds.password = m_config.proxyPass;
    }
    m_socks5 = std::make_unique<DriftstackSocks5Client>(proxy, creds);
    if (m_socks5->performHandshake() != Socks5Result::Success) {
        WTFLogAlways("[Driftstack-EG-WK-WS/Wave29-499.351] SOCKS5 handshake failed to %s:%u", proxy.host.utf8().data(), unsigned(proxy.port));
        return false;
    }
    Socks5Endpoint dest;
    dest.host = m_config.host;
    dest.port = m_config.port;
    Socks5Endpoint bnd;
    if (m_socks5->tcpConnect(dest, bnd) != Socks5Result::Success) {
        WTFLogAlways("[Driftstack-EG-WK-WS/Wave29-499.351] SOCKS5 tcpConnect failed to %s:%u", m_config.host.utf8().data(), unsigned(m_config.port));
        return false;
    }

    // TLS for wss:// (iPhone-byte-exact ClientHello → same JA4 as page loads).
    if (m_config.secure) {
        int fd = m_socks5->socketFileDescriptor();
        if (fd < 0)
            return false;
        m_tls = std::make_unique<DriftstackTLS13Client>();
        if (!m_tls->connect(fd, m_config.host)) {
            WTFLogAlways("[Driftstack-EG-WK-WS/Wave29-499.351] TLS handshake failed to %s", m_config.host.utf8().data());
            return false;
        }
        // The iPhone ClientHello offers ALPN [h3,h2,http/1.1] (JA4 fidelity — we
        // do NOT narrow it). If the server selected h2, WebSocket rides RFC 8441
        // Extended CONNECT (tunneled in an h2 stream) instead of the h1.1 Upgrade.
        if (m_tls->selectedALPN() == "h2"_s)
            return h2ConnectHandshake();
    }

    // RFC 6455 §4.1 client handshake. Sec-WebSocket-Key = base64(16 random bytes).
    uint8_t keyBytes[16];
    arc4random_buf(keyBytes, sizeof(keyBytes));
    String secKey = base64EncodeToString(std::span<const uint8_t> { keyBytes, sizeof(keyBytes) });

    StringBuilder req;
    req.append("GET "_s, m_config.path.isEmpty() ? "/"_s : m_config.path, " HTTP/1.1\r\n"_s);
    req.append("Host: "_s, m_config.host);
    if ((m_config.secure && m_config.port != 443) || (!m_config.secure && m_config.port != 80))
        req.append(':', String::number(m_config.port));
    req.append("\r\n"_s);
    req.append("Upgrade: websocket\r\n"_s);
    req.append("Connection: Upgrade\r\n"_s);
    req.append("Sec-WebSocket-Key: "_s, secKey, "\r\n"_s);
    req.append("Sec-WebSocket-Version: 13\r\n"_s);
    if (!m_config.origin.isEmpty())
        req.append("Origin: "_s, m_config.origin, "\r\n"_s);
    for (auto& [k, v] : m_config.extraHeaders)
        req.append(k, ": "_s, v, "\r\n"_s);
    req.append("\r\n"_s);

    CString reqUtf8 = req.toString().utf8();
    if (!tlsWriteAll(reinterpret_cast<const uint8_t*>(reqUtf8.data()), reqUtf8.length()))
        return false;

    // Read the response headers (until \r\n\r\n). Leftover bytes → m_readBuffer.
    Vector<uint8_t> resp;
    uint8_t chunk[2048];
    size_t headerEnd = notFound;
    while (headerEnd == notFound) {
        int n = tlsRead(chunk, sizeof(chunk));
        if (n <= 0)
            return false;
        resp.append(std::span<const uint8_t> { chunk, static_cast<size_t>(n) });
        if (resp.size() >= 4) {
            for (size_t i = 3; i < resp.size(); ++i) {
                if (resp[i - 3] == '\r' && resp[i - 2] == '\n' && resp[i - 1] == '\r' && resp[i] == '\n') {
                    headerEnd = i + 1;
                    break;
                }
            }
        }
        if (resp.size() > (1u << 16))
            return false; // runaway handshake response
    }
    String headerStr = String::fromUTF8(std::span<const uint8_t> { resp.span().data(), headerEnd });
    if (headerEnd < resp.size())
        m_readBuffer.append(resp.span().subspan(headerEnd, resp.size() - headerEnd));

    // Parse status line + headers.
    Vector<String> lines = headerStr.split("\r\n"_s);
    if (lines.isEmpty())
        return false;
    Vector<String> statusParts = lines[0].split(' ');
    int statusCode = statusParts.size() >= 2 ? parseInteger<int>(statusParts[1]).value_or(0) : 0;
    if (statusCode != 101) {
        WTFLogAlways("[Driftstack-EG-WK-WS/Wave29-499.351] handshake non-101 status=%d for %s", statusCode, m_config.host.utf8().data());
        return false;
    }
    Vector<std::pair<String, String>> respHeaders;
    String protocol;
    for (size_t i = 1; i < lines.size(); ++i) {
        size_t colon = lines[i].find(':');
        if (colon == notFound)
            continue;
        String k = lines[i].left(colon).trim(deprecatedIsSpaceOrNewline);
        String v = lines[i].substring(colon + 1).trim(deprecatedIsSpaceOrNewline);
        respHeaders.append({ k, v });
        if (equalIgnoringASCIICase(k, "sec-websocket-protocol"_s))
            protocol = v;
    }

    WTFLogAlways("[Driftstack-EG-WK-WS/Wave29-499.351] WS handshake OK (101) to %s%s via SOCKS5 (iPhone TLS)",
        m_config.host.utf8().data(), m_config.path.utf8().data());
    if (m_cb.onConnect)
        m_cb.onConnect(statusCode, protocol, respHeaders);
    return true;
}

// RFC 8441 — WebSocket over HTTP/2. The TLS connection negotiated h2 ALPN, so the
// WS handshake is an Extended CONNECT (not an h1.1 Upgrade); after :status 200 the
// RFC 6455 frames are tunneled in h2 DATA frames (tlsRead/tlsWriteAll route to the
// CONNECT stream). The ClientHello/JA4 is identical — only the WS bootstrap differs.
bool DriftstackWebSocket::h2ConnectHandshake()
{
    DriftstackHttp2Transport t;
    t.ctx = m_tls.get();
    t.readFn = [](void* c, uint8_t* b, size_t n) -> int { return reinterpret_cast<DriftstackTLS13Client*>(c)->read(b, n); };
    t.writeFn = [](void* c, const uint8_t* b, size_t n) -> int { return reinterpret_cast<DriftstackTLS13Client*>(c)->write(b, n); };
    m_h2stream = std::make_unique<DriftstackHttp2ConnectStream>(t);

    DriftstackHttp2ConnectRequest req;
    req.protocol = "websocket"_s;
    StringBuilder auth;
    auth.append(m_config.host);
    if ((m_config.secure && m_config.port != 443) || (!m_config.secure && m_config.port != 80))
        auth.append(':', String::number(m_config.port));
    req.authority = auth.toString();
    req.path = m_config.path.isEmpty() ? "/"_s : m_config.path;
    req.extraHeaders.append({ "sec-websocket-version"_s, "13"_s });
    if (!m_config.origin.isEmpty())
        req.extraHeaders.append({ "origin"_s, m_config.origin });
    for (auto& [k, v] : m_config.extraHeaders)
        req.extraHeaders.append({ k, v });

    int status = m_h2stream->open(req);
    if (status != 200) {
        WTFLogAlways("[Driftstack-EG-WK-WS/Wave29-499.352] RFC8441 CONNECT non-200 status=%d (server enableConnectProtocol=%d) for %s",
            status, m_h2stream->serverEnabledConnectProtocol(), m_config.host.utf8().data());
        return false;
    }
    m_isH2 = true;
    String protocol;
    for (auto& [k, v] : m_h2stream->responseHeaders()) {
        if (equalIgnoringASCIICase(k, "sec-websocket-protocol"_s))
            protocol = v;
    }
    WTFLogAlways("[Driftstack-EG-WK-WS/Wave29-499.352] WS-over-h2 (RFC 8441) tunnel OPEN to %s%s via SOCKS5 (iPhone TLS, h2)",
        m_config.host.utf8().data(), m_config.path.utf8().data());
    if (m_cb.onConnect)
        m_cb.onConnect(status, protocol, m_h2stream->responseHeaders());
    return true;
}

// Reliable read of exactly n bytes (from leftover buffer then the wire).
static bool wsReadExact(DriftstackWebSocket* self, Vector<uint8_t>& readBuffer,
    std::function<int(uint8_t*, size_t)> rd, uint8_t* out, size_t n, std::atomic<bool>& stop)
{
    size_t got = 0;
    if (!readBuffer.isEmpty()) {
        size_t take = std::min(n, readBuffer.size());
        memcpy(out, readBuffer.span().data(), take);
        Vector<uint8_t> rest;
        if (take < readBuffer.size())
            rest.append(readBuffer.span().subspan(take));
        readBuffer = std::move(rest);
        got = take;
    }
    while (got < n) {
        if (stop.load())
            return false;
        int r = rd(out + got, n - got);
        if (r <= 0)
            return false;
        got += static_cast<size_t>(r);
    }
    return true;
}

void DriftstackWebSocket::readerLoop()
{
    auto rd = [this](uint8_t* b, size_t n) { return tlsRead(b, n); };
    Vector<uint8_t> messageBuffer;
    uint8_t messageOpcode = 0;

    while (!m_stop.load()) {
        uint8_t hdr[2];
        if (!wsReadExact(this, m_readBuffer, rd, hdr, 2, m_stop))
            break;
        bool fin = hdr[0] & 0x80;
        uint8_t opcode = hdr[0] & 0x0f;
        bool masked = hdr[1] & 0x80;
        uint64_t len = hdr[1] & 0x7f;
        if (len == 126) {
            uint8_t ext[2];
            if (!wsReadExact(this, m_readBuffer, rd, ext, 2, m_stop)) break;
            len = (uint64_t(ext[0]) << 8) | ext[1];
        } else if (len == 127) {
            uint8_t ext[8];
            if (!wsReadExact(this, m_readBuffer, rd, ext, 8, m_stop)) break;
            len = 0;
            for (int i = 0; i < 8; ++i) len = (len << 8) | ext[i];
        }
        uint8_t maskKey[4] = { 0, 0, 0, 0 };
        if (masked && !wsReadExact(this, m_readBuffer, rd, maskKey, 4, m_stop))
            break;
        if (len > (64u * 1024 * 1024)) // 64MB single-frame cap
            break;
        Vector<uint8_t> payload;
        payload.grow(static_cast<size_t>(len));
        if (len && !wsReadExact(this, m_readBuffer, rd, payload.mutableSpan().data(), len, m_stop))
            break;
        if (masked) {
            for (size_t i = 0; i < payload.size(); ++i)
                payload[i] ^= maskKey[i & 3];
        }

        switch (opcode) {
        case 0x0: // continuation
        case 0x1: // text
        case 0x2: // binary
            if (opcode != 0x0)
                messageOpcode = opcode;
            messageBuffer.appendVector(payload);
            if (fin) {
                if (messageOpcode == 0x1) {
                    if (m_cb.onText)
                        m_cb.onText(String::fromUTF8(messageBuffer.span()));
                } else if (m_cb.onBinary)
                    m_cb.onBinary(messageBuffer.span());
                messageBuffer.clear();
                messageOpcode = 0;
            }
            break;
        case 0x8: { // close
            uint16_t code = 1005;
            String reason;
            if (payload.size() >= 2) {
                code = (uint16_t(payload[0]) << 8) | payload[1];
                if (payload.size() > 2)
                    reason = String::fromUTF8(payload.span().subspan(2, payload.size() - 2));
            }
            // Echo the close (RFC 6455 §5.5.1) then stop.
            sendFrame(0x8, payload.span());
            m_closed.store(true);
            if (m_cb.onClose)
                m_cb.onClose(code, reason);
            return;
        }
        case 0x9: // ping → pong
            sendFrame(0xA, payload.span());
            break;
        case 0xA: // pong → ignore
            break;
        default:
            break;
        }
    }

    if (!m_closed.load() && !m_stop.load() && m_cb.onClose)
        m_cb.onClose(1006, "abnormal closure"_s); // 1006 = no close frame
}

bool DriftstackWebSocket::sendFrame(uint8_t opcode, std::span<const uint8_t> payload)
{
    Locker locker { m_writeLock };
    Vector<uint8_t> frame;
    frame.append(0x80 | opcode); // FIN + opcode
    size_t len = payload.size();
    if (len < 126)
        frame.append(0x80 | static_cast<uint8_t>(len)); // MASK + len
    else if (len <= 0xffff) {
        frame.append(0x80 | 126);
        frame.append(static_cast<uint8_t>((len >> 8) & 0xff));
        frame.append(static_cast<uint8_t>(len & 0xff));
    } else {
        frame.append(0x80 | 127);
        for (int i = 7; i >= 0; --i)
            frame.append(static_cast<uint8_t>((len >> (i * 8)) & 0xff));
    }
    uint8_t maskKey[4];
    arc4random_buf(maskKey, 4);
    frame.append(std::span<const uint8_t> { maskKey, 4 });
    size_t maskStart = frame.size();
    frame.append(payload);
    for (size_t i = 0; i < len; ++i)
        frame[maskStart + i] ^= maskKey[i & 3];
    return tlsWriteAll(frame.span().data(), frame.size());
}

void DriftstackWebSocket::sendText(std::span<const uint8_t> utf8)
{
    sendFrame(0x1, utf8);
}

void DriftstackWebSocket::sendBinary(std::span<const uint8_t> data)
{
    sendFrame(0x2, data);
}

void DriftstackWebSocket::closeConnection(uint16_t code, const String& reason)
{
    if (m_closed.exchange(true))
        return;
    Vector<uint8_t> payload;
    payload.append(static_cast<uint8_t>((code >> 8) & 0xff));
    payload.append(static_cast<uint8_t>(code & 0xff));
    CString r = reason.utf8();
    payload.append(std::span<const uint8_t> { reinterpret_cast<const uint8_t*>(r.data()), r.length() });
    sendFrame(0x8, payload.span());
    m_stop.store(true);
    if (m_h2stream)
        m_h2stream->close();
    if (m_tls)
        m_tls->shutdown();
}

void DriftstackWebSocket::cancel()
{
    m_stop.store(true);
    if (m_h2stream)
        m_h2stream->close();
    if (m_tls)
        m_tls->shutdown();
}

WTF_ALLOW_UNSAFE_BUFFER_USAGE_END

} // namespace WebKit

#endif // PLATFORM(DRIFTSTACK)
