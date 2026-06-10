/*
 * DriftstackWebSocket.h — Wave 29-499.351 (Task #40, the last egress TLS-split symptom).
 *
 * Routes ws/wss through the customer SOCKS5 proxy + the iPhone-byte-exact
 * DriftstackTLS13Client, instead of NSURLSessionWebSocketTask (Mac TLS/JA4).
 * Implements the RFC 6455 client handshake (HTTP/1.1 Upgrade) + framing over the
 * established TLS connection. A background reader thread demuxes incoming frames
 * to text/binary/close callbacks (replying to ping with pong); sends are masked
 * per RFC 6455 §5.3 and serialized under a write lock.
 *
 * Real Safari 26 prefers WS-over-h2 (RFC 8441) where the server allows; the
 * h1.1 Upgrade here keeps ws/wss on the iPhone JA4 today (the TLS ClientHello is
 * identical regardless of the WS application layer). RFC 8441 is a follow-up.
 */

#pragma once

#if PLATFORM(DRIFTSTACK)

#include <functional>
#include <memory>
#include <span>
#include <stdint.h>
#include <wtf/Lock.h>
#include <wtf/Threading.h>
#include <wtf/Vector.h>
#include <wtf/text/WTFString.h>

namespace WebKit {

class DriftstackSocks5Client;
class DriftstackTLS13Client;

struct DriftstackWebSocketConfig {
    String host;            // ws/wss target host
    uint16_t port { 0 };    // 80 (ws) / 443 (wss) or explicit
    String path;            // "/chat?x=1"
    bool secure { true };   // wss → TLS
    String origin;          // Origin header
    Vector<std::pair<String, String>> extraHeaders;  // cookie, sec-websocket-protocol, etc.
    // SOCKS5 proxy (env-fallback path, same as the loader/URLProtocol).
    String proxyHost;
    uint16_t proxyPort { 0 };
    String proxyUser;
    String proxyPass;
};

struct DriftstackWebSocketCallbacks {
    std::function<void(int statusCode, const String& protocol, const Vector<std::pair<String, String>>& headers)> onConnect;
    std::function<void(const String& text)> onText;
    std::function<void(std::span<const uint8_t> data)> onBinary;
    std::function<void(uint16_t code, const String& reason)> onClose;
    std::function<void(const String& message)> onError;
};

class DriftstackWebSocket {
public:
    DriftstackWebSocket(DriftstackWebSocketConfig&&, DriftstackWebSocketCallbacks&&);
    ~DriftstackWebSocket();

    // Establish SOCKS5 + TLS + RFC 6455 handshake, then start the reader thread.
    // Non-blocking: returns immediately; onConnect/onError fire from the worker.
    void start();

    // Mask + frame + send. Thread-safe.
    void sendText(std::span<const uint8_t> utf8);
    void sendBinary(std::span<const uint8_t>);

    // Send a CLOSE frame then tear down.
    void closeConnection(uint16_t code, const String& reason);

    // Hard cancel (no close frame).
    void cancel();

private:
    bool connectAndHandshake();   // SOCKS5 + TLS + Upgrade; returns true on 101
    void readerLoop();            // demux incoming frames until close/error
    bool sendFrame(uint8_t opcode, std::span<const uint8_t> payload);
    int tlsRead(uint8_t* buf, size_t n);
    bool tlsWriteAll(const uint8_t* buf, size_t n);

    DriftstackWebSocketConfig m_config;
    DriftstackWebSocketCallbacks m_cb;
    std::unique_ptr<DriftstackSocks5Client> m_socks5;
    std::unique_ptr<DriftstackTLS13Client> m_tls;
    RefPtr<Thread> m_thread;
    Lock m_writeLock;
    std::atomic<bool> m_stop { false };
    std::atomic<bool> m_closed { false };
    Vector<uint8_t> m_readBuffer;   // leftover bytes between frame reads
};

} // namespace WebKit

#endif // PLATFORM(DRIFTSTACK)
