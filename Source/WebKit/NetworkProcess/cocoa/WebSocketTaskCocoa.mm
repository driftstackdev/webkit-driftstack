/*
 * Copyright (C) 2016-2018 Apple Inc. All rights reserved.
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

#import "config.h"
#import "WebSocketTaskCocoa.h"

#import "NetworkSessionCocoa.h"
#import "NetworkSocketChannel.h"
#if PLATFORM(DRIFTSTACK)
#import "DriftstackWebSocket.h"
#import <wtf/MainThread.h>
#import <wtf/StdLibExtras.h>
#import <wtf/text/MakeString.h>
#import <wtf/text/StringBuilder.h>
#import <wtf/text/StringToIntegerConversion.h>
#endif
#import <Foundation/NSURLSession.h>
#import <WebCore/ClientOrigin.h>
#import <WebCore/ResourceRequest.h>
#import <WebCore/ResourceResponse.h>
#import <WebCore/ThreadableWebSocketChannel.h>
#import <wtf/BlockPtr.h>
#import <wtf/TZoneMallocInlines.h>
#import <wtf/cocoa/SpanCocoa.h>

namespace WebKit {

using namespace WebCore;

WTF_MAKE_TZONE_ALLOCATED_IMPL(WebSocketTask);

Ref<WebSocketTask> WebSocketTask::create(NetworkSocketChannel& channel, WebPageProxyIdentifier webProxyPageID, std::optional<WebCore::FrameIdentifier> frameID, std::optional<WebCore::PageIdentifier> pageID, WeakPtr<SessionSet>&& sessionSet, const WebCore::ResourceRequest& request, const WebCore::ClientOrigin& clientOrigin, RetainPtr<NSURLSessionWebSocketTask>&& task, WebCore::StoredCredentialsPolicy storedCredentialsPolicy)
{
    return adoptRef(*new WebSocketTask(channel, webProxyPageID, frameID, pageID, WTF::move(sessionSet), request, clientOrigin, WTF::move(task), storedCredentialsPolicy));
}

WebSocketTask::WebSocketTask(NetworkSocketChannel& channel, WebPageProxyIdentifier webProxyPageID, std::optional<FrameIdentifier> frameID, std::optional<PageIdentifier> pageID, WeakPtr<SessionSet>&& sessionSet, const WebCore::ResourceRequest& request, const WebCore::ClientOrigin& clientOrigin, RetainPtr<NSURLSessionWebSocketTask>&& task, WebCore::StoredCredentialsPolicy storedCredentialsPolicy)
    : NetworkTaskCocoa(*channel.session())
    , m_channel(channel)
    , m_task(WTF::move(task))
    , m_webProxyPageID(webProxyPageID)
    , m_frameID(frameID)
    , m_pageID(pageID)
    , m_sessionSet(WTF::move(sessionSet))
    , m_partition(request.cachePartition())
    , m_storedCredentialsPolicy(storedCredentialsPolicy)
{
    // We use topOrigin in case of service worker websocket connections, for which pageID does not link to a real page.
    // In that case, let's only call the callback for same origin loads.
    if (clientOrigin.topOrigin == clientOrigin.clientOrigin)
        m_topOrigin = clientOrigin.topOrigin;

    bool shouldBlockCookies = storedCredentialsPolicy == WebCore::StoredCredentialsPolicy::EphemeralStateless;
    if (CheckedPtr session = networkSession(); CheckedPtr networkStorageSession = session ? session->networkStorageSession() : nullptr) {
        if (!shouldBlockCookies)
            shouldBlockCookies = networkStorageSession->shouldBlockCookies(request, frameID, pageID, shouldRelaxThirdPartyCookieBlocking(), NetworkSession::isRequestToKnownCrossSiteTracker(request));
    }
    if (shouldBlockCookies)
        blockCookies();

#if PLATFORM(DRIFTSTACK)
    bool driftstackWS = startDriftstackWebSocketIfActive(request, clientOrigin);
#else
    bool driftstackWS = false;
#endif
    if (!driftstackWS)
        readNextMessage();
    protect(m_channel)->didSendHandshakeRequest(ResourceRequest { [m_task currentRequest] });

#if ENABLE(OPT_IN_PARTITIONED_COOKIES) && defined(CFN_COOKIE_ACCEPTS_POLICY_PARTITION) && CFN_COOKIE_ACCEPTS_POLICY_PARTITION
    updateTaskWithStoragePartitionIdentifier(request);
#endif
}

WebSocketTask::~WebSocketTask() = default;

void WebSocketTask::readNextMessage()
{
    [m_task receiveMessageWithCompletionHandler:makeBlockPtr([weakThis = ThreadSafeWeakPtr { *this }](NSURLSessionWebSocketMessage* _Nullable message, NSError * _Nullable error) {
        RefPtr protectedThis = weakThis.get();
        if (!protectedThis)
            return;

        RefPtr channel = protectedThis->m_channel.get();
        if (error) {
            // If closeCode is not zero, we are closing the connection and didClose will be called for us.
            if ([protectedThis->m_task closeCode])
                return;

            if (!protectedThis->m_receivedDidConnect) {
                ResourceResponse response { [protectedThis->m_task response] };
                if (!response.isNull())
                    channel->didReceiveHandshakeResponse(WTF::move(response));
            }

            channel->didReceiveMessageError([error localizedDescription]);
            protectedThis->didClose(WebCore::ThreadableWebSocketChannel::CloseEventCodeAbnormalClosure, emptyString());
            return;
        }
        if (message.type == NSURLSessionWebSocketMessageTypeString)
            channel->didReceiveText(message.string);
        else
            channel->didReceiveBinaryData(span(message.data));

        protectedThis->readNextMessage();
    }).get()];
}

void WebSocketTask::cancel()
{
#if PLATFORM(DRIFTSTACK)
    if (m_driftstackWS) {
        m_driftstackWS->cancel();
        return;
    }
#endif
    [m_task cancel];
}

void WebSocketTask::resume()
{
#if PLATFORM(DRIFTSTACK)
    if (m_driftstackWS) {
        m_driftstackWS->start();
        return;
    }
#endif
    [m_task resume];
}

void WebSocketTask::didConnect(const String& protocol)
{
    String extensionsValue;
    RetainPtr response = [m_task response];
    if (RetainPtr httpResponse  = dynamic_objc_cast<NSHTTPURLResponse>(response.get()))
        extensionsValue = [httpResponse valueForHTTPHeaderField:@"Sec-WebSocket-Extensions"];

    m_receivedDidConnect = true;
    RefPtr channel = m_channel.get();
    channel->didConnect(protocol, extensionsValue);
    channel->didReceiveHandshakeResponse(ResourceResponse { [m_task response] });
}

void WebSocketTask::didClose(unsigned short code, const String& reason)
{
    if (m_receivedDidClose)
        return;

    m_receivedDidClose = true;
    protect(m_channel)->didClose(code, reason);
}

void WebSocketTask::sendString(std::span<const uint8_t> utf8String, CompletionHandler<void()>&& callback)
{
#if PLATFORM(DRIFTSTACK)
    if (m_driftstackWS) {
        m_driftstackWS->sendText(utf8String);
        callback();
        return;
    }
#endif
    auto text = adoptNS([[NSString alloc] initWithBytes:utf8String.data() length:utf8String.size() encoding:NSUTF8StringEncoding]);
    if (!text) {
        callback();
        return;
    }
    auto message = adoptNS([[NSURLSessionWebSocketMessage alloc] initWithString:text.get()]);
    [m_task sendMessage:message.get() completionHandler:makeBlockPtr([callback = WTF::move(callback)](NSError * _Nullable) mutable {
        callback();
    }).get()];
}

void WebSocketTask::sendData(std::span<const uint8_t> data, CompletionHandler<void()>&& callback)
{
#if PLATFORM(DRIFTSTACK)
    if (m_driftstackWS) {
        m_driftstackWS->sendBinary(data);
        callback();
        return;
    }
#endif
    RetainPtr nsData = toNSData(data);
    auto message = adoptNS([[NSURLSessionWebSocketMessage alloc] initWithData:nsData.get()]);
    [m_task sendMessage:message.get() completionHandler:makeBlockPtr([callback = WTF::move(callback)](NSError * _Nullable) mutable {
        callback();
    }).get()];
}

void WebSocketTask::close(int32_t code, const String& reason)
{
#if PLATFORM(DRIFTSTACK)
    if (m_driftstackWS) {
        uint16_t wsCode = (code == WebCore::ThreadableWebSocketChannel::CloseEventCodeNotSpecified) ? 1000 : static_cast<uint16_t>(code);
        m_driftstackWS->closeConnection(wsCode, reason);
        return;
    }
#endif
    if (code == WebCore::ThreadableWebSocketChannel::CloseEventCodeNotSpecified)
        code = NSURLSessionWebSocketCloseCodeInvalid;
    auto utf8 = reason.utf8();
    RetainPtr nsData = toNSData(byteCast<uint8_t>(utf8.span()));
    if ([m_task respondsToSelector:@selector(_sendCloseCode:reason:)]) {
        [m_task _sendCloseCode:(NSURLSessionWebSocketCloseCode)code reason:nsData.get()];
        return;
    }
    [m_task cancelWithCloseCode:(NSURLSessionWebSocketCloseCode)code reason:nsData.get()];
}

WebSocketTask::TaskIdentifier WebSocketTask::identifier() const
{
    return [m_task taskIdentifier];
}

NetworkSessionCocoa* WebSocketTask::networkSession()
{
    return downcast<NetworkSessionCocoa>(m_channel->session());
}

NSURLSessionTask* WebSocketTask::task() const
{
    return m_task.get();
}

#if PLATFORM(DRIFTSTACK)
// Wave 29-499.351 — when the customer SOCKS5 is active (DRIFTSTACK_CUSTOM_SOCKS5=1
// + a proxy set), build + arm a DriftstackWebSocket so ws/wss rides the iPhone
// TLS13 path instead of NSURLSessionWebSocketTask (Mac JA4). Returns true if armed
// (the engine is started in resume()); false → fall through to the native task.
bool WebSocketTask::startDriftstackWebSocketIfActive(const WebCore::ResourceRequest& request, const WebCore::ClientOrigin& clientOrigin)
{
    const char* customSocks5 = getenv("DRIFTSTACK_CUSTOM_SOCKS5");
    const char* proxyEnv = getenv("DRIFTSTACK_SOCKS5_PROXY");
    if (!customSocks5 || customSocks5[0] != '1' || !proxyEnv || !proxyEnv[0])
        return false;
    // Wave 29-499.351 — OPT-IN until RFC 8441 (WS-over-h2) lands. Modern servers
    // negotiate h2 ALPN, which the h1.1-Upgrade engine can't carry (it declines
    // h2 → the connection fails rather than falling back). Arming for all ws/wss
    // now would REGRESS WebSocket to those servers (they work today via CFNetwork).
    // DRIFTSTACK_WS_PATHB=1 enables it for the http/1.1-server functional gate +
    // future 8441 rollout; production stays on CFNetwork until 8441 is verified.
    const char* wsPathB = getenv("DRIFTSTACK_WS_PATHB");
    if (!wsPathB || wsPathB[0] != '1')
        return false;

    URL url = request.url();
    String scheme = url.protocol().toString().convertToASCIILowercase();
    if (scheme != "ws"_s && scheme != "wss"_s)
        return false;

    String host = url.host().toString();
    if (host.isEmpty())
        return false;

    // Loopback / private hosts bypass SOCKS5 (matches the loader/URLProtocol).
    if (host == "localhost"_s || host.startsWith("127."_s) || host == "::1"_s
        || host.startsWith("10."_s) || host.startsWith("192.168."_s))
        return false;

    DriftstackWebSocketConfig config;
    config.secure = (scheme == "wss"_s);
    config.host = host;
    config.port = url.port().value_or(config.secure ? 443 : 80);
    StringBuilder path;
    path.append(url.path().isEmpty() ? "/"_s : url.path().toString());
    if (!url.query().isEmpty())
        path.append('?', url.query().toString());
    config.path = path.toString();

    // Forward cookie + sec-websocket-protocol / extensions (everything WebKit set
    // except hop-by-hop + the handshake headers we synthesize). The Origin header
    // (already computed by WebKit from the client origin) is captured for the
    // handshake rather than forwarded verbatim.
    for (auto& header : request.httpHeaderFields()) {
        String lower = header.key.convertToASCIILowercase();
        if (lower == "origin"_s) {
            config.origin = header.value;
            continue;
        }
        if (lower == "host"_s || lower == "connection"_s || lower == "upgrade"_s
            || lower == "sec-websocket-key"_s || lower == "sec-websocket-version"_s)
            continue;
        config.extraHeaders.append({ header.key, header.value });
    }
    UNUSED_PARAM(clientOrigin);

    // Proxy from env (same fallback the loader uses; per-session plumb-through TBD).
    String proxySpec = String::fromUTF8(proxyEnv);
    proxySpec = proxySpec.startsWith("socks5h://"_s) ? proxySpec.substring(10)
        : (proxySpec.startsWith("socks5://"_s) ? proxySpec.substring(9) : proxySpec);
    size_t colon = proxySpec.reverseFind(':');
    if (colon == notFound)
        return false;
    config.proxyHost = proxySpec.left(colon);
    config.proxyPort = static_cast<uint16_t>(parseInteger<int>(proxySpec.substring(colon + 1)).value_or(0));
    if (const char* u = getenv("DRIFTSTACK_SOCKS5_USER"); u && u[0]) {
        config.proxyUser = String::fromUTF8(u);
        if (const char* p = getenv("DRIFTSTACK_SOCKS5_PASS"))
            config.proxyPass = String::fromUTF8(p);
    }

    ThreadSafeWeakPtr<WebSocketTask> weakThis { *this };
    DriftstackWebSocketCallbacks cb;
    cb.onConnect = [weakThis](int, const String& protocol, const Vector<std::pair<String, String>>& headers) {
        String extensions;
        for (auto& [k, v] : headers) {
            if (equalIgnoringASCIICase(k, "sec-websocket-extensions"_s))
                extensions = v;
        }
        callOnMainRunLoop([weakThis, protocol = protocol.isolatedCopy(), extensions = extensions.isolatedCopy()]() mutable {
            RefPtr self = weakThis.get();
            if (!self) return;
            RefPtr channel = self->m_channel.get();
            if (!channel) return;
            self->m_receivedDidConnect = true;
            channel->didConnect(protocol, extensions);
        });
    };
    cb.onText = [weakThis](const String& text) {
        callOnMainRunLoop([weakThis, text = text.isolatedCopy()]() mutable {
            RefPtr self = weakThis.get();
            if (!self) return;
            if (RefPtr channel = self->m_channel.get())
                channel->didReceiveText(text);
        });
    };
    cb.onBinary = [weakThis](std::span<const uint8_t> data) {
        Vector<uint8_t> copy(data);
        callOnMainRunLoop([weakThis, copy = std::move(copy)]() mutable {
            RefPtr self = weakThis.get();
            if (!self) return;
            if (RefPtr channel = self->m_channel.get())
                channel->didReceiveBinaryData(copy.span());
        });
    };
    cb.onClose = [weakThis](uint16_t code, const String& reason) {
        callOnMainRunLoop([weakThis, code, reason = reason.isolatedCopy()]() mutable {
            RefPtr self = weakThis.get();
            if (!self) return;
            self->didClose(code, reason);
        });
    };
    cb.onError = [weakThis](const String& message) {
        callOnMainRunLoop([weakThis, message = message.isolatedCopy()]() mutable {
            RefPtr self = weakThis.get();
            if (!self) return;
            if (RefPtr channel = self->m_channel.get())
                channel->didReceiveMessageError(String { message });
            self->didClose(WebCore::ThreadableWebSocketChannel::CloseEventCodeAbnormalClosure, emptyString());
        });
    };

    m_driftstackWS = std::make_unique<DriftstackWebSocket>(std::move(config), std::move(cb));
    WTFLogAlways("[Driftstack-EG-WK-WS/Wave29-499.351] ws/wss '%s://%s%s' armed on iPhone-TLS SOCKS5 path (not NSURLSession)",
        scheme.utf8().data(), host.utf8().data(), config.path.utf8().data());
    return true;
}
#endif

}
