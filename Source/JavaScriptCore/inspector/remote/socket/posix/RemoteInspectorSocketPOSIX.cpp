/*
 * Copyright (C) 2019 Sony Interactive Entertainment Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE INC. AND ITS CONTRIBUTORS ``AS IS''
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL APPLE INC. OR ITS CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"
#include "RemoteInspectorSocket.h"

#if ENABLE(REMOTE_INSPECTOR)

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <wtf/UniStdExtras.h>

namespace Inspector {

namespace Socket {

void init()
{
}

std::optional<PlatformSocketType> connect(const char* serverAddress, uint16_t serverPort)
{
    struct sockaddr_in address = { };

    address.sin_family = AF_INET;
    inet_aton(serverAddress, &address.sin_addr);
    address.sin_port = htons(serverPort);

    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) {
        LOG_ERROR("Failed to create socket for %s:%d, errno = %d", serverAddress, serverPort, errno);
        return std::nullopt;
    }

    int error = ::connect(fd, (struct sockaddr*)&address, sizeof(address));
    if (error < 0) {
        LOG_ERROR("Failed to connect to %s:%u, errno = %d", serverAddress, serverPort, errno);
        ::close(fd);
        return std::nullopt;
    }

    return fd;
}

std::optional<PlatformSocketType> listen(const char* addressStr, uint16_t port)
{
    struct sockaddr_in address = { };

    int fdListen = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fdListen < 0) {
        LOG_ERROR("socket() failed, errno = %d", errno);
#if PLATFORM(DRIFTSTACK)
        WTFLogAlways("[Driftstack-W1386] socket() failed errno=%d", errno);
#endif
        return std::nullopt;
    }

    const int enabled = 1;
    int error = setsockopt(fdListen, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled));
    if (error < 0) {
        LOG_ERROR("setsockopt() SO_REUSEADDR, errno = %d", errno);
#if PLATFORM(DRIFTSTACK)
        WTFLogAlways("[Driftstack-W1386] setsockopt(SO_REUSEADDR) failed errno=%d", errno);
#endif
        ::close(fdListen);
        return std::nullopt;
    }

    error = setsockopt(fdListen, SOL_SOCKET, SO_REUSEPORT, &enabled, sizeof(enabled));
    if (error < 0) {
        LOG_ERROR("setsockopt() SO_REUSEPORT, errno = %d", errno);
#if PLATFORM(DRIFTSTACK)
        WTFLogAlways("[Driftstack-W1386] setsockopt(SO_REUSEPORT) failed errno=%d (non-fatal, continuing)", errno);
#endif
#if PLATFORM(DRIFTSTACK)
        // W1385: the App Sandbox (MiniBrowser item-9 in-process WD server) denies SO_REUSEPORT
        // (ENOPROTOOPT/42) even with the network.server entitlement. SO_REUSEPORT is a port-SHARING
        // optimization (multiple listeners on one port) — the single in-process listener does NOT
        // need it, so treat its absence as non-fatal: keep the SO_REUSEADDR'd socket and continue
        // to bind()+listen() (those work under network.server). Without this, listen() aborts here.
        (void)error;
#else
        ::close(fdListen);
        return std::nullopt;
#endif
    }

#if PLATFORM(PLAYSTATION)
    if (setsockopt(fdListen, SOL_SOCKET, SO_USE_DEVLAN, &enabled, sizeof(enabled)) < 0) {
        LOG_ERROR("setsocketopt() SO_USE_DEVLAN, errno = %d", errno);
        ::close(fdListen);
        return std::nullopt;
    }
#endif

    // FIXME: Support AF_INET6 connections.
    address.sin_family = AF_INET;
    if (addressStr && *addressStr)
        inet_aton(addressStr, &address.sin_addr);
    else
        address.sin_addr.s_addr = htonl(INADDR_ANY);
    address.sin_port = htons(port);
    error = ::bind(fdListen, (struct sockaddr*)&address, sizeof(address));
    if (error < 0) {
        LOG_ERROR("bind() failed, errno = %d", errno);
#if PLATFORM(DRIFTSTACK)
        WTFLogAlways("[Driftstack-W1386] bind(127.0.0.1:%u) failed errno=%d", ntohs(address.sin_port), errno);
#endif
        ::close(fdListen);
        return std::nullopt;
    }

    error = ::listen(fdListen, 1);
    if (error < 0) {
        LOG_ERROR("listen() failed, errno = %d", errno);
#if PLATFORM(DRIFTSTACK)
        WTFLogAlways("[Driftstack-W1386] listen() failed errno=%d", errno);
#endif
        ::close(fdListen);
        return std::nullopt;
    }

    return fdListen;
}

std::optional<PlatformSocketType> accept(PlatformSocketType socket)
{
    struct sockaddr_in address = { };

    socklen_t len = sizeof(struct sockaddr_in);
    int fd = ::accept(socket, (struct sockaddr*) &address, &len);
    if (fd >= 0)
        return fd;

#if PLATFORM(DRIFTSTACK)
    // Preserve errno across LOG_ERROR (WTFReportError runs in release builds and can clobber errno) so the
    // caller — RemoteInspectorSocketEndpoint::acceptInetSocketIfEnabled — can classify a transient accept()
    // failure (retry, keep listening) versus a fatal one (re-bind). Warm-tab -1004 fix.
    int driftstackAcceptErrno = errno;
#endif
    LOG_ERROR("accept(inet) error (errno = %d)", errno);
#if PLATFORM(DRIFTSTACK)
    errno = driftstackAcceptErrno;
#endif
    return std::nullopt;
}

std::optional<std::array<PlatformSocketType, 2>> createPair()
{
    std::array<PlatformSocketType, 2> sockets;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, &sockets[0]))
        return std::nullopt;

    return sockets;
}

bool setup(PlatformSocketType socket)
{
    if (!setCloseOnExec(socket)) {
        LOG_ERROR("setCloseOnExec() error");
#if PLATFORM(DRIFTSTACK)
        WTFLogAlways("[Driftstack-W1387] setup: setCloseOnExec() failed errno=%d", errno);
#endif
        return false;
    }

    if (!setNonBlock(socket)) {
        LOG_ERROR("setNonBlock() error (errno = %d)", errno);
#if PLATFORM(DRIFTSTACK)
        WTFLogAlways("[Driftstack-W1387] setup: setNonBlock() failed errno=%d", errno);
#endif
        return false;
    }

    if (setsockopt(socket, SOL_SOCKET, SO_RCVBUF, &BufferSize, sizeof(BufferSize))) {
        LOG_ERROR("setsockopt(SO_RCVBUF) error (errno = %d)", errno);
#if PLATFORM(DRIFTSTACK)
        // W1387: the App Sandbox (MiniBrowser item-9 in-process WD server) can deny SO_RCVBUF/SO_SNDBUF
        // (ENOPROTOOPT/42) even with the network.server entitlement. These are buffer-SIZE optimizations
        // only — the localhost WD control channel (tiny JSON frames) works fine with the kernel defaults,
        // so treat the failure as non-fatal: keep the socket and continue. Without this, setup() returns
        // false → setSocket() fails → the ListenerConnection closes the listening fd → isListening()=false
        // → listenInet() returns nullopt → "failed to listen on 127.0.0.1:<port>" (the W1384 errno=42 we saw).
        WTFLogAlways("[Driftstack-W1387] setup: setsockopt(SO_RCVBUF) failed errno=%d (non-fatal, continuing)", errno);
#else
        return false;
#endif
    }

    if (setsockopt(socket, SOL_SOCKET, SO_SNDBUF, &BufferSize, sizeof(BufferSize))) {
        LOG_ERROR("setsockopt(SO_SNDBUF) error (errno = %d)", errno);
#if PLATFORM(DRIFTSTACK)
        WTFLogAlways("[Driftstack-W1387] setup: setsockopt(SO_SNDBUF) failed errno=%d (non-fatal, continuing)", errno);
#else
        return false;
#endif
    }

    return true;
}

bool isValid(PlatformSocketType socket)
{
    return socket != INVALID_SOCKET_VALUE;
}

bool isListening(PlatformSocketType socket)
{
    int out;
    socklen_t outSize = sizeof(out);
    if (getsockopt(socket, SOL_SOCKET, SO_ACCEPTCONN, &out, &outSize) != -1)
        return out;

    LOG_ERROR("getsockopt(SO_ACCEPTCONN) error (errno = %d)", errno);
#if PLATFORM(DRIFTSTACK)
    // W1388: under the MiniBrowser App Sandbox (item-9 in-process WD server), getsockopt(SO_ACCEPTCONN)
    // is denied (ENOPROTOOPT/42) even though the socket IS listening — SO_ACCEPTCONN is a read-only query
    // the sandbox refuses. This is the ACTUAL item-9 listen failure: Socket::listen() + setup() both
    // succeed (no W1386/W1387), but this verification query fails → Socket::isListening() returns false
    // → ListenerConnection::isListening() false → listenInet() returns nullopt → HTTPServer::listen()
    // returns false → "failed to listen on 127.0.0.1:<port>" with the leftover errno=42 (W1384).
    // The fd is a valid socket we just successfully bind()+listen()'d, so an unqueryable SO_ACCEPTCONN
    // means "can't verify", NOT "not listening" — treat it as listening. (The only callers query a socket
    // we just listen()'d, or are deciding whether to accept on one already accepted into m_listeners.)
    if (errno == ENOPROTOOPT && isValid(socket)) {
        // isListening() is polled every worker-thread tick — log only the first time so the
        // sandbox-fallback is observable without flooding the log (W1388). A benign double-log
        // race across the worker/main threads is harmless for a diagnostic.
        static bool logged = false;
        if (!logged) {
            logged = true;
            WTFLogAlways("[Driftstack-W1388] getsockopt(SO_ACCEPTCONN) ENOPROTOOPT under App Sandbox — treating valid socket as listening (logged once)");
        }
        return true;
    }
    WTFLogAlways("[Driftstack-W1388] getsockopt(SO_ACCEPTCONN) failed errno=%d (not ENOPROTOOPT) — returning false", errno);
#endif
    return false;
}

std::optional<uint16_t> getPort(PlatformSocketType socket)
{
    ASSERT(isValid(socket));

    struct sockaddr_in address = { };
    socklen_t len = sizeof(address);
    if (getsockname(socket, reinterpret_cast<struct sockaddr*>(&address), &len)) {
        LOG_ERROR("getsockname() error (errno = %d)", errno);
        return std::nullopt;
    }
    return address.sin_port;
}

std::optional<size_t> read(PlatformSocketType socket, void* buffer, int bufferSize)
{
    ASSERT(isValid(socket));

    ssize_t readSize = ::recv(socket, buffer, bufferSize, MSG_NOSIGNAL);
    if (readSize >= 0)
        return static_cast<size_t>(readSize);

    LOG_ERROR("read error (errno = %d)", errno);
    return std::nullopt;
}

std::optional<size_t> write(PlatformSocketType socket, const void* data, int size)
{
    ASSERT(isValid(socket));

    ssize_t writeSize = ::send(socket, data, size, MSG_NOSIGNAL);
    if (writeSize >= 0)
        return static_cast<size_t>(writeSize);

    LOG_ERROR("write error (errno = %d)", errno);
    return std::nullopt;
}

void close(PlatformSocketType& socket)
{
    if (!isValid(socket))
        return;

    ::close(socket);
    socket = INVALID_SOCKET_VALUE;
}

PollingDescriptor preparePolling(PlatformSocketType socket)
{
    PollingDescriptor poll = { };
    poll.fd = socket;
    poll.events = POLLIN;
    return poll;
}

bool poll(Vector<PollingDescriptor>& pollDescriptors, int timeout)
{
    int ret = ::poll(pollDescriptors.mutableSpan().data(), pollDescriptors.size(), timeout);
    return ret > 0;
}

bool isReadable(const PollingDescriptor& poll)
{
    return poll.revents & POLLIN;
}

bool isWritable(const PollingDescriptor& poll)
{
    return poll.revents & POLLOUT;
}

void markWaitingWritable(PollingDescriptor& poll)
{
    poll.events |= POLLOUT;
}

void clearWaitingWritable(PollingDescriptor& poll)
{
    poll.events &= ~POLLOUT;
}

} // namespace Socket

} // namespace Inspector

#endif // ENABLE(REMOTE_INSPECTOR)
