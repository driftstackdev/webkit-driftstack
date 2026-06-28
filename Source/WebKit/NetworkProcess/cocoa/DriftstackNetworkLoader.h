/*
 * DriftstackNetworkLoader.h — Wave 29-499.130 (Task #104 Path B v2)
 *
 * Custom network loader that replaces NSURLSessionDataTask when SOCKS5
 * customer-proxy is active. Bypasses Apple's NSURLSession/CFNetwork
 * entirely (which has h3-disable-with-proxy gates we cannot override
 * from configuration).
 *
 * Architecture:
 *   NetworkDataTaskCocoa::NetworkDataTaskCocoa (in cocoa/NetworkDataTaskCocoa.mm)
 *     - When DRIFTSTACK_CUSTOM_SOCKS5=1 + SOCKS5 active:
 *         m_loader = DriftstackNetworkLoader::create(*this, request)
 *         m_loader->resume()
 *     - Otherwise: existing m_task = [session dataTaskWithRequest:] path
 *
 * Loader internal flow (per request):
 *   1. Open BSD TCP socket → gost (SOCKS5 proxy)
 *   2. SOCKS5 GREETING + AUTH + CONNECT to destination
 *   3. Layer TLS on top of socket (BoringSSL or SecureTransport via fd)
 *      - SNI = destination hostname
 *      - ALPN = [h3, h2, http/1.1] (no Apple gate; we control ALPN)
 *      - Validate cert chain
 *   4. Negotiate HTTP version:
 *      - h3 (QUIC over UDP_ASSOCIATE) if ALPN selects h3
 *      - h2 if ALPN selects h2 (nghttp2-style framing)
 *      - http/1.1 fallback
 *   5. Send request, read response
 *   6. Dispatch back through NetworkDataTaskClient callbacks
 *
 * Path B v1 (existing URLProtocol) used CFStream+SOCKS5+TLS for HTTP/1.1
 * but couldn't intercept WebKit's modern HTTPS path. Path B v2 hooks
 * one layer deeper at NetworkDataTaskCocoa creation.
 *
 * Implementation phases (multi-week):
 *   Phase 1 (Day 8-10): scaffold + HTTP/1.1 via BSD+SOCKS5+TLS
 *   Phase 2 (Day 11-15): HTTP/2 via nghttp2
 *   Phase 3 (Day 16-25): HTTP/3 via custom QUIC over UDP_ASSOCIATE
 *   Phase 4 (Day 26-30): cookie/cache integration, redirects, auth, errors
 *   Phase 5 (Day 31+): testing against Twilio NTS + browserleaks/quic
 */

#pragma once

#if PLATFORM(DRIFTSTACK)

#include <WebCore/ResourceRequest.h>
#include <atomic>
#include <wtf/CompletionHandler.h>
#include <wtf/Forward.h>
#include <wtf/MonotonicTime.h>   // W2750 (#20): wall-clock retry budget
#include <wtf/RefCounted.h>
#include <wtf/ThreadSafeWeakPtr.h>
#include <wtf/text/WTFString.h>

namespace WebCore {
class ResourceResponse;
}

namespace WebKit {

class NetworkDataTaskCocoa;

class DriftstackNetworkLoader : public RefCounted<DriftstackNetworkLoader> {
public:
    static Ref<DriftstackNetworkLoader> create(NetworkDataTaskCocoa& task, const WebCore::ResourceRequest& request);
    ~DriftstackNetworkLoader();

    void resume();
    void cancel();
    void suspend();

    // Phase 1 scaffold returns false (loader inactive). Once
    // HTTP/1.1 BSD-socket path implemented, returns true to indicate
    // NetworkDataTaskCocoa should use this loader instead of NSURLSession.
    static bool isActiveForSession();

private:
    DriftstackNetworkLoader(NetworkDataTaskCocoa&, const WebCore::ResourceRequest&);

    // W2202 STEP 5 (fork-egress audit ws4cffit6): the loader runs I/O on a concurrent loaderQueue and marshals
    // delivery back via callOnMainRunLoop; the task (a ThreadSafeRefCounted NetworkDataTask, destroyed on the
    // main thread) can die mid-flight — a bare `NetworkDataTaskCocoa&` dangled + a cached raw client() ptr was a
    // UAF. Hold a ThreadSafeWeakPtr; upgrade to a strong RefPtr ON the main thread (protectedTask) inside each
    // delivery block + re-acquire client() there; never cache the raw client ptr across the queue→main hop.
    ThreadSafeWeakPtr<NetworkDataTaskCocoa> m_task;
    RefPtr<NetworkDataTaskCocoa> protectedTask() const;   // strong upgrade (null if the task is gone); defn in .mm (type complete there)
    WTF::String driftstackITPCookieHeader();   // PathB v2 ITP (task #14): the ITP-filtered Cookie header real Safari's NSURLSession would send (computed on the main thread in resume())

    // PathB v2 within-session Set-Cookie WRITE (egress audit). The egress READS cookies
    // (driftstackITPCookieHeader → cookieRequestHeaderFieldValue) but never WROTE Set-Cookie: PathB
    // bypasses NSURLSession, so CFNetwork's auto-parse of every Set-Cookie (incl on 3xx) into
    // HTTPCookieStorage is gone. httpOnly server-set cookies (session/auth/consent) were dropped →
    // a 302+Set-Cookie consent gate (OneTrust/cookielaw = westernunion) looped forever. This persists
    // each RAW (un-folded) Set-Cookie value through the SAME 9-arg ITP context as the READ. MAIN THREAD
    // ONLY (touches m_request + the task's ITP state, like driftstackITPCookieHeader); the response
    // sites run on loaderQueue and marshal the call via callOnMainRunLoop BEFORE the redirect/delivery
    // hop, so the consent cookie is stored before the next hop re-reads the store. Gated by
    // DRIFTSTACK_EGRESS_SET_COOKIE_PERSIST (default-ON; a correctness fix). NetworkProcess-only =>
    // glyphHash-neutral. `setCookieValues` are the raw Set-Cookie lines, one entry per response header.
    void driftstackPersistSetCookies(const URL& responseURL, const Vector<WTF::String>& setCookieValues);
    WebCore::ResourceRequest m_request;
    // W2341 (task #58): atomic — cancel() runs on another thread while the concurrent
    // dispatch block's read loops poll it (was a plain-bool data race; now also the
    // cancel signal the poll-slice readers observe, see driftstackCancelAwareTlsRead).
    std::atomic<bool> m_cancelled { false };
    int m_fd { -1 };  // BSD socket fd to gost
    int m_attempt { 0 };  // Wave 29-499.271 — retry counter for transient TLS/H2 failures
    MonotonicTime m_retryDeadline;  // W2750 (#20): wall-clock cap on the whole retry chain (set on attempt 1)
    int m_redirectCount { 0 };  // Wave 29-499.344 — 3xx redirect-follow chain guard

    // Wave 29-499.344 — HTTP redirect following (Phase 4, previously unimplemented).
    // Our custom loader bypasses NSURLSession, which used to follow 3xx transparently;
    // without this a 301/302 (e.g. http→https) was delivered as the FINAL response, so
    // the browser rendered the "Moved Permanently" page instead of redirecting like
    // Safari. Returns true if the response is a 3xx+Location and a redirect was
    // dispatched (caller must NOT deliver the response); the client's
    // willPerformHTTPRedirection applies policy + updates the URL, then we re-resume()
    // on the returned request.
    // `rawSetCookies` (PathB v2 egress audit) = the RAW un-folded Set-Cookie values from this response's
    // transport header vector. When this IS a followed 3xx redirect, they're persisted (on the main thread)
    // BEFORE the re-resume is marshalled, so a 302+Set-Cookie consent gate stores its cookie before the next
    // hop re-reads the store. Empty/default for callers that don't carry cookies (or when the gate is off).
    bool tryFollowRedirect(const WebCore::ResourceResponse&, const Vector<WTF::String>& rawSetCookies = { });

    // Wave 29-499.325 — single-completion guard. loaderQueue() is a CONCURRENT
    // dispatch queue and resume() has no re-entry guard, so overlapping attempts
    // (e.g. a cookie-version re-resume creating a second loader) could each deliver
    // a full didReceiveResponse/didReceiveData/didCompleteWithError sequence to the
    // same client — a second response after completion is use-after-complete on
    // NetworkLoad (crash/corruption). tryBeginCompletion() lets exactly the first
    // terminal path through; all others no-op. Atomic because deliveries originate
    // on loaderQueue (concurrent) before being marshalled to the main runloop.
    std::atomic<bool> m_completionStarted { false };
    bool tryBeginCompletion()
    {
        bool expected = false;
        bool won = m_completionStarted.compare_exchange_strong(expected, true);
        // BUG-42 Fix #2 (egress-reliability, gated) — the request reached its single
        // terminal completion; free its process-wide admission slot NOW (before the
        // delivery hop) so a waiting subresource can start immediately. Idempotent:
        // releaseAdmissionSlot() only signals if this loader still holds a slot.
        // Gate-off no-op: m_admissionSlotHeld is never set when the gate is off.
        if (won)
            releaseAdmissionSlot();
        return won;
    }

    // BUG-42 Fix #2 (egress-reliability, gated) — process-wide concurrent-REQUEST
    // admission. The defect: 1 in-flight PathB-v2 request == 1 GCD worker pinned for
    // the WHOLE blocking lifecycle (SOCKS5 + ML-KEM TLS + h2/h3 response wait), so the
    // ~64-thread libdispatch ceiling becomes a hard total-request cap — a many-origin
    // swarm parks every worker, the concurrent loaderQueue stops scheduling NEW blocks,
    // and subresources never start (the stall). m_admissionSlotHeld tracks whether THIS
    // loader holds a slot; it's acquired ONCE per logical request in resume() (the first
    // call; retries/redirects re-enter resume() but already hold it) BEFORE the
    // dispatch_async submission, and released exactly once on the terminal path
    // (tryBeginCompletion), on cancel(), or in the destructor (safety net). Atomic +
    // CAS so the at-most-once release is race-free across the queue→main hop.
    std::atomic<bool> m_admissionSlotHeld { false };
    int m_admissionDeferrals { 0 };   // Fix #2: main-thread re-resume deferrals while the cap is saturated (bounded)
    bool tryAcquireAdmissionSlot();   // main thread; non-blocking try-acquire. defn in .mm
    void releaseAdmissionSlot();      // idempotent; safe from any thread. defn in .mm
};

} // namespace WebKit

#endif // PLATFORM(DRIFTSTACK)
