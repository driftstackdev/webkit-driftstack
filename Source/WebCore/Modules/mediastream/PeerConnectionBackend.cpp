/*
 * Copyright (C) 2015 Ericsson AB. All rights reserved.
 * Copyright (C) 2016-2017 Apple Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer
 *    in the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name of Ericsson nor the names of its contributors
 *    may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"
#include "PeerConnectionBackend.h"

#if ENABLE(WEB_RTC)

#include "DocumentPage.h"
#include "EventNames.h"
#include "JSDOMConvertInterface.h"
#include "JSDOMPromiseDeferred.h"
#include "JSRTCCertificate.h"
#include "Logging.h"
#include "Page.h"
#include "RTCDtlsTransport.h"
#include "RTCIceCandidate.h"
#include "RTCPeerConnection.h"
#include "RTCPeerConnectionIceEvent.h"
#include "RTCRtpCapabilities.h"
#include "RTCSctpTransportBackend.h"
#include "RTCSessionDescriptionInit.h"
#include "RTCTrackEvent.h"
#include "WebRTCProvider.h"
#include <algorithm>
#include <wtf/EnumTraits.h>
#include <wtf/FilePrintStream.h>
#include <wtf/UUID.h>
#include <wtf/text/Base64.h>
#include <wtf/text/StringBuilder.h>
#include <wtf/text/StringToIntegerConversion.h>

#if USE(GSTREAMER_WEBRTC)
#include "GStreamerWebRTCUtils.h"
#endif

#if USE(LIBWEBRTC)
#include "LibWebRTCCertificateGenerator.h"
#include "LibWebRTCProvider.h"
#endif

namespace WebCore {

#if USE(LIBWEBRTC) || USE(GSTREAMER_WEBRTC)

std::optional<RTCRtpCapabilities> PeerConnectionBackend::receiverCapabilities(ScriptExecutionContext& context, const String& kind)
{
    RefPtr page = downcast<Document>(context).page();
    if (!page)
        return { };
    return page->webRTCProvider().receiverCapabilities(kind);
}

std::optional<RTCRtpCapabilities> PeerConnectionBackend::senderCapabilities(ScriptExecutionContext& context, const String& kind)
{
    RefPtr page = downcast<Document>(context).page();
    if (!page)
        return { };
    return page->webRTCProvider().senderCapabilities(kind);
}

#else

static std::unique_ptr<PeerConnectionBackend> createNoPeerConnectionBackend(RTCPeerConnection&, MediaEndpointConfiguration&&)
{
    return nullptr;
}

CreatePeerConnectionBackend PeerConnectionBackend::create = createNoPeerConnectionBackend;

std::optional<RTCRtpCapabilities> PeerConnectionBackend::receiverCapabilities(ScriptExecutionContext&, const String&)
{
    ASSERT_NOT_REACHED();
    return { };
}

std::optional<RTCRtpCapabilities> PeerConnectionBackend::senderCapabilities(ScriptExecutionContext&, const String&)
{
    ASSERT_NOT_REACHED();
    return { };
}
#endif // USE(LIBWEBRTC) || USE(GSTREAMER_WEBRTC)

#if PLATFORM(WPE) || PLATFORM(GTK)
class JSONFileHandler {
public:
    JSONFileHandler(String&& path)
        : m_path(WTF::move(path))
    {
        Locker lock(m_clientsLock);
        open(true);
    }

    void log(String&& event)
    {
        Locker lock(m_clientsLock);
        if (m_logFile)
            m_logFile->println(WTF::move(event));
    }

    void addClient(uint64_t identifier)
    {
        Locker lock(m_clientsLock);
        m_clients.append(identifier);
        if (!m_logFile)
            open(false);
    }

    void removeClient(uint64_t identifier)
    {
        Locker lock(m_clientsLock);
        if (!m_clients.contains(identifier))
            return;

        m_clients.removeFirst(identifier);
        if (m_clients.isEmpty())
            m_logFile = nullptr;
    }

private:
    void open(bool overwrite)
    {
        ASSERT(!m_logFile);
        ASSERT(m_clientsLock.isHeld());

        m_logFile = FilePrintStream::open(m_path.utf8().data(), overwrite ? "w" : "a");

        // Prefer unbuffered output, so that we get a full log upon crash or deadlock.
        setvbuf(m_logFile->file(), nullptr, _IONBF, 0);
    }

    String m_path;
    Lock m_clientsLock;
    std::unique_ptr<FilePrintStream> m_logFile WTF_GUARDED_BY_LOCK(m_clientsLock);
    Vector<uint64_t> m_clients WTF_GUARDED_BY_LOCK(m_clientsLock);
};

JSONFileHandler& jsonFileHandler()
{
    auto path = String::fromUTF8(getenv("WEBKIT_WEBRTC_JSON_EVENTS_FILE"));
    ASSERT(!path.isEmpty());
    static NeverDestroyed<JSONFileHandler> sharedInstance(WTF::move(path));
    return sharedInstance;
}
#endif

PeerConnectionBackend::PeerConnectionBackend(RTCPeerConnection& peerConnection)
    : m_peerConnection(peerConnection)
#if !RELEASE_LOG_DISABLED
    , m_logger(peerConnection.logger())
    , m_logIdentifier(peerConnection.logIdentifier())
#endif
{
#if USE(LIBWEBRTC)
    auto* document = peerConnection.document();
    if (auto* page = document ? document->page() : nullptr)
        m_shouldFilterICECandidates = page->webRTCProvider().isSupportingMDNS();
#endif

#if RELEASE_LOG_DISABLED
    m_logIdentifierString = makeString(hex(reinterpret_cast<uintptr_t>(this)));
#endif

#if !RELEASE_LOG_DISABLED && (PLATFORM(WPE) || PLATFORM(GTK))
    m_jsonFilePath = String::fromUTF8(getenv("WEBKIT_WEBRTC_JSON_EVENTS_FILE"));
    if (!m_jsonFilePath.isEmpty())
        jsonFileHandler().addClient(m_logIdentifier);

    m_logger->addMessageHandlerObserver(*this);
    ALWAYS_LOG(LOGIDENTIFIER, "PeerConnection created"_s);
#endif
}

PeerConnectionBackend::~PeerConnectionBackend()
{
#if !RELEASE_LOG_DISABLED && (PLATFORM(WPE) || PLATFORM(GTK))
    ALWAYS_LOG(LOGIDENTIFIER, "Disposing PeerConnection"_s);
    m_logger->removeMessageHandlerObserver(*this);

    if (isJSONLogStreamingEnabled())
        jsonFileHandler().removeClient(m_logIdentifier);
#endif
}

#if !RELEASE_LOG_DISABLED && (PLATFORM(WPE) || PLATFORM(GTK))
void PeerConnectionBackend::handleLogMessage(const WTFLogChannel& channel, WTFLogLevel, std::optional<WTFLogLocation>, const Vector<JSONLogValue>& values)
{
    auto name = StringView::fromLatin1(channel.name);
    if (name != "WebRTC"_s)
        return;

    // Ignore logs containing only the call site information or JSON logs.
    if (values.size() < 2 || values[1].type == JSONLogValue::Type::JSON)
        return;

    if (!isJSONLogStreamingEnabled())
        return;

    // Parse "foo::bar(hexidentifier) "
    auto& callSite = values[0].value;
    auto leftParenthesisIndex = callSite.reverseFind('(');
    if (leftParenthesisIndex == notFound)
        return;

    auto rightParenthesisIndex = callSite.reverseFind(')');
    if (rightParenthesisIndex == notFound)
        return;

    if (!m_logIdentifierString)
        m_logIdentifierString = makeString(m_logIdentifier);

    auto identifier = callSite.substring(leftParenthesisIndex + 1, rightParenthesisIndex - leftParenthesisIndex - 1);
    if (identifier != m_logIdentifierString)
        return;

    String event;

    // Check if the third message is a multi-lines string, concatenating such message would look ugly in log events.
    if (values.size() >= 3 && values[2].value.find("\r\n"_s) != notFound)
        event = generateJSONLogEvent(MessageLogEvent { values[1].value, { byteCast<uint8_t>(values[2].value.span8()) } }, false);
    else {
        StringBuilder builder;
        for (auto& value : values.subvector(1))
            builder.append(WTF::makeStringByReplacingAll(value.value, '\"', '\''));
        event = generateJSONLogEvent(MessageLogEvent { builder.toString(), { } }, false);
    }
    emitJSONLogEvent(WTF::move(event));
}
#endif // !RELEASE_LOG_DISABLED && (PLATFORM(WPE) || PLATFORM(GTK))

#if PLATFORM(DRIFTSTACK)
// ── Family-A (Safari ≤26.3) WebRTC createOffer dynamic payload-type remap ──
// GT: reference/realdevice-bs/aio-iPhone_16_Pro_Max-1781873317444.json
//     .vendor.v3-webrtc-sdp-probe-1-0 .webrtc.createOffer.sdp_structure_canonical
//
// On real iOS 18.6 the createOffer VIDEO m-line dynamic PTs differ from the Mac
// fork's newer-libwebrtc (26.x) defaults. The codec SET + ORDER + rtcp-fb + fmtp
// content + extmap are byte-identical 18.6-vs-26.x — ONLY the PT integers move.
// This is a deterministic PT remap (NOT a libwebrtc version bound): the 26.x
// layout was verified identical across iPhone 17 / iPhone 17 Pro Max captures.
//
// Fixed table (26.x default → 18.6 target), keyed by CODEC IDENTITY (the four
// H264 + two VP9 entries share a codec name, so they are disambiguated by their
// fmtp packetization-mode+profile-level-id / profile-id):
//   H264 42e01f pm0 : 103→102 ; rtx 104→103
//   H265            : 35→104  ; rtx 36→105
//   VP8            : 107→106 ; rtx 108→107
//   VP9 profile-id 0: 109→108 ; rtx 114→109
//   VP9 profile-id 2: 115→127 ; rtx 116→125
//   AV1            : 37→35   ; rtx 38→36
//   red            : 117→112 ; rtx 118→113
//   ulpfec         : 119→114
// (H264 96/98/100 + their rtx 97/99/101 are unchanged 18.6-vs-26.x.)
//
// AUDIO m-line + datachannel m-line: UNTOUCHED. Answer SDP: the probe captures
// createOffer only; createAnswer mirrors the negotiated remote PTs (echoes the
// peer's offer), so it is NOT munged here — see createAnswerSucceeded note.
//
// Launch-safety: gated Family-A only (Safari ≤26.3). The 26.4 LAUNCH default and
// 26.5 KEEP the 26.x PTs (no env, or major.minor > 26.3 → no remap). Live getenv
// each call (NOT static-cached — silently-inert-gate sweep 2026-06-27).
static bool driftstackIsFamilyARTC()
{
    const char* a = getenv("DRIFTSTACK_ARCHETYPE");
    if (!a || !a[0])
        return false;
    std::string_view sv(a);
    auto pos = sv.find("safari");
    if (pos == std::string_view::npos)
        return false;
    sv.remove_prefix(pos + 6);
    if (sv.empty() || sv[0] < '0' || sv[0] > '9')
        return false;
    int major = 0, minor = 0;
    size_t i = 0;
    while (i < sv.size() && sv[i] >= '0' && sv[i] <= '9') { major = major * 10 + (sv[i] - '0'); ++i; }
    if (i < sv.size() && (sv[i] == '_' || sv[i] == '.'))
        ++i;
    while (i < sv.size() && sv[i] >= '0' && sv[i] <= '9') { minor = minor * 10 + (sv[i] - '0'); ++i; }
    // Family A = Safari ≤ 26.3. 26.4 launch / 26.5 keep 26.x PTs.
    if (major < 26)
        return true;
    if (major == 26)
        return minor <= 3;
    return false;
}

// Parse "<pt> <codec>/<rate>[/<ch>]" rtpmap value → (pt, lowercased codec name).
// Identify a codec entry by name + (for H264) packetization-mode/profile-level-id
// taken from its fmtp, (for VP9) profile-id. Returns the 18.6 target PT for a
// given old PT, or the same PT when unmapped. Atomic: the table is built from the
// ORIGINAL tokens, so SRC∩DST collisions (35,36,103,104,107,108,109,114) never
// double-apply.
static String driftstackRemapFamilyAVideoPTs(const String& sdp)
{
    StringView view(sdp);

    // 1) Locate the video m-line section [videoStart, videoEnd).
    size_t videoStart = notFound;
    size_t videoEnd = sdp.length();
    {
        size_t cursor = 0;
        while (cursor < sdp.length()) {
            size_t lineEnd = sdp.find('\n', cursor);
            size_t next = (lineEnd == notFound) ? sdp.length() : lineEnd + 1;
            StringView line = view.substring(cursor, next - cursor);
            if (line.startsWith("m="_s)) {
                if (videoStart != notFound) { videoEnd = cursor; break; }
                if (line.startsWith("m=video"_s))
                    videoStart = cursor;
            }
            cursor = next;
        }
    }
    if (videoStart == notFound)
        return sdp;

    // 2) Build oldPT → newPT table by codec identity from the video section.
    HashMap<int, int> remap;
    {
        // First pass: collect rtpmap (pt → codec name) and fmtp (pt → params).
        HashMap<int, String> codecName; // primary codec only (non-rtx)
        HashMap<int, String> rtxApt;     // rtx pt → referenced apt pt (string-int)
        HashMap<int, String> fmtpParams; // pt → fmtp params
        size_t cursor = videoStart;
        while (cursor < videoEnd) {
            size_t lineEnd = sdp.find('\n', cursor);
            size_t next = (lineEnd == notFound || lineEnd >= videoEnd) ? videoEnd : lineEnd + 1;
            StringView line = view.substring(cursor, next - cursor);
            auto parsePt = [&](StringView prefix, int& outPt, StringView& outRest) -> bool {
                if (!line.startsWith(prefix))
                    return false;
                StringView body = line.substring(prefix.length());
                size_t sp = body.find(' ');
                StringView ptStr = (sp == notFound) ? body : body.substring(0, sp);
                // strip trailing CR/LF for the pt token
                while (ptStr.length() && (ptStr[ptStr.length() - 1] == '\r' || ptStr[ptStr.length() - 1] == '\n'))
                    ptStr = ptStr.substring(0, ptStr.length() - 1);
                auto v = parseInteger<int>(ptStr);
                if (!v)
                    return false;
                outPt = *v;
                outRest = (sp == notFound) ? StringView() : body.substring(sp + 1);
                return true;
            };
            int pt = 0; StringView rest;
            if (parsePt("a=rtpmap:"_s, pt, rest)) {
                // rest = "codec/rate[/ch]"
                size_t slash = rest.find('/');
                StringView name = (slash == notFound) ? rest : rest.substring(0, slash);
                codecName.set(pt, name.convertToASCIILowercase());
            } else if (parsePt("a=fmtp:"_s, pt, rest)) {
                fmtpParams.set(pt, rest.toString());
                if (auto aptPos = rest.find("apt="_s); aptPos != notFound) {
                    StringView aptVal = rest.substring(aptPos + 4);
                    size_t semi = aptVal.find(';');
                    StringView aptPt = (semi == notFound) ? aptVal : aptVal.substring(0, semi);
                    while (aptPt.length() && (aptPt[aptPt.length() - 1] == '\r' || aptPt[aptPt.length() - 1] == '\n'))
                        aptPt = aptPt.substring(0, aptPt.length() - 1);
                    rtxApt.set(pt, aptPt.toString());
                }
            }
            cursor = next;
        }

        // Identify the primary (non-rtx) codec PTs by name + disambiguator, assign
        // the 18.6 target, then propagate to each rtx via apt.
        auto fmtpOf = [&](int pt) -> String {
            auto it = fmtpParams.find(pt);
            return it != fmtpParams.end() ? it->value : String();
        };
        for (auto& entry : codecName) {
            int oldPt = entry.key;
            const String& name = entry.value;
            String params = fmtpOf(oldPt);
            int newPt = oldPt;
            if (name == "h264"_s) {
                bool pm0 = params.contains("packetization-mode=0"_s);
                bool e01f = params.contains("profile-level-id=42e01f"_s);
                if (pm0 && e01f)
                    newPt = 102; // 103→102 (the only remapped H264 entry)
                // pm1 (96/98) and 640c1f pm0 (100) keep their PTs.
            } else if (name == "h265"_s)
                newPt = 104;     // 35→104
            else if (name == "vp8"_s)
                newPt = 106;     // 107→106
            else if (name == "vp9"_s) {
                if (params.contains("profile-id=2"_s))
                    newPt = 127; // 115→127
                else
                    newPt = 108; // profile-id=0 : 109→108
            } else if (name == "av1"_s)
                newPt = 35;      // 37→35
            else if (name == "red"_s)
                newPt = 112;     // 117→112
            else if (name == "ulpfec"_s)
                newPt = 114;     // 119→114
            if (newPt != oldPt)
                remap.set(oldPt, newPt);
        }
        // rtx PTs follow their apt-referenced primary's remap, per the fixed table.
        for (auto& entry : rtxApt) {
            int rtxPt = entry.key;
            auto apt = parseInteger<int>(StringView(entry.value));
            if (!apt)
                continue;
            // Only remap rtx whose primary is remapped; emit the spec target.
            // (rtx target is uniquely determined by the primary it protects.)
            int newRtx = rtxPt;
            switch (*apt) {
            case 102: case 103: newRtx = 103; break;  // H264 42e01f pm0 rtx 104→103 (apt may be old 103 or new 102)
            case 104: case 35: newRtx = 105; break;   // H265 rtx 36→105
            case 106: case 107: newRtx = 107; break;  // VP8 rtx 108→107
            case 108: case 109: newRtx = 109; break;  // VP9 pid0 rtx 114→109
            case 127: case 115: newRtx = 125; break;  // VP9 pid2 rtx 116→125
            case 37: newRtx = 36; break;              // AV1 rtx 38→36
            case 112: case 117: newRtx = 113; break;  // red rtx 118→113
            default: break;
            }
            if (newRtx != rtxPt)
                remap.set(rtxPt, newRtx);
        }
    }

    if (remap.isEmpty())
        return sdp;

    // 3) Single-pass rewrite over the video section. Every PT reference is looked
    // up in `remap` (built from the original tokens), so collisions never compound.
    auto mapPt = [&](int pt) -> int {
        auto it = remap.find(pt);
        return it != remap.end() ? it->value : pt;
    };

    StringBuilder out;
    out.append(view.substring(0, videoStart));

    size_t cursor = videoStart;
    while (cursor < videoEnd) {
        size_t lineEnd = sdp.find('\n', cursor);
        size_t next = (lineEnd == notFound || lineEnd >= videoEnd) ? videoEnd : lineEnd + 1;
        StringView line = view.substring(cursor, next - cursor);

        auto remapLeadingPt = [&](StringView prefix) -> bool {
            if (!line.startsWith(prefix))
                return false;
            StringView body = line.substring(prefix.length());
            size_t sp = body.find(' ');
            StringView ptStr = (sp == notFound) ? body : body.substring(0, sp);
            StringView trailer = (sp == notFound) ? StringView() : body.substring(sp);
            // peel CR/LF off ptStr (only when no space, i.e. bare pt line — rare)
            StringView crlf;
            while (ptStr.length() && (ptStr[ptStr.length() - 1] == '\r' || ptStr[ptStr.length() - 1] == '\n')) {
                crlf = ptStr.substring(ptStr.length() - 1);
                ptStr = ptStr.substring(0, ptStr.length() - 1);
            }
            auto v = parseInteger<int>(ptStr);
            if (!v) {
                out.append(line);
                return true;
            }
            out.append(prefix, mapPt(*v));
            if (sp == notFound) out.append(crlf);
            else out.append(trailer);
            return true;
        };

        if (line.startsWith("m=video"_s)) {
            // m=video 9 UDP/TLS/RTP/SAVPF <pt list...>
            size_t hdrEnd = 0;
            // skip 4 tokens: "m=video", port, proto, then the PT list
            int spaces = 0;
            for (size_t k = 0; k < line.length(); ++k) {
                if (line[k] == ' ') {
                    if (++spaces == 3) { hdrEnd = k + 1; break; }
                }
            }
            out.append(line.substring(0, hdrEnd));
            StringView ptList = line.substring(hdrEnd);
            // peel trailing CR/LF off the PT list, remember how many to re-append.
            size_t trailer = 0;
            while (ptList.length() && (ptList[ptList.length() - 1] == '\r' || ptList[ptList.length() - 1] == '\n')) {
                ++trailer;
                ptList = ptList.substring(0, ptList.length() - 1);
            }
            bool first = true;
            size_t tokStart = 0;
            for (size_t k = 0; k <= ptList.length(); ++k) {
                if (k == ptList.length() || ptList[k] == ' ') {
                    StringView tok = ptList.substring(tokStart, k - tokStart);
                    if (tok.length()) {
                        if (!first) out.append(' ');
                        first = false;
                        if (auto v = parseInteger<int>(tok))
                            out.append(mapPt(*v));
                        else
                            out.append(tok);
                    }
                    tokStart = k + 1;
                }
            }
            out.append(line.substring(hdrEnd + ptList.length(), trailer));
        } else if (remapLeadingPt("a=rtpmap:"_s)) {
            // handled
        } else if (remapLeadingPt("a=rtcp-fb:"_s)) {
            // handled
        } else if (line.startsWith("a=fmtp:"_s)) {
            // a=fmtp:<pt> <params...>  — remap the leading pt AND any apt=<pt>.
            StringView body = line.substring(7 /* "a=fmtp:" */);
            size_t sp = body.find(' ');
            StringView ptStr = (sp == notFound) ? body : body.substring(0, sp);
            StringView params = (sp == notFound) ? StringView() : body.substring(sp + 1);
            if (auto v = parseInteger<int>(ptStr))
                out.append("a=fmtp:"_s, mapPt(*v));
            else
                out.append("a=fmtp:"_s, ptStr);
            if (sp != notFound) {
                out.append(' ');
                // rewrite apt=<pt> if present, else copy params verbatim.
                size_t aptPos = params.find("apt="_s);
                if (aptPos != notFound) {
                    out.append(params.substring(0, aptPos + 4));
                    StringView aptVal = params.substring(aptPos + 4);
                    size_t end = 0;
                    while (end < aptVal.length() && aptVal[end] >= '0' && aptVal[end] <= '9')
                        ++end;
                    StringView aptPt = aptVal.substring(0, end);
                    if (auto av = parseInteger<int>(aptPt))
                        out.append(mapPt(*av));
                    else
                        out.append(aptPt);
                    out.append(aptVal.substring(end));
                } else
                    out.append(params);
            }
        } else
            out.append(line);

        cursor = next;
    }

    out.append(view.substring(videoEnd));
    return out.toString();
}
#endif // PLATFORM(DRIFTSTACK)

void PeerConnectionBackend::createOffer(RTCOfferOptions&& options, CreateCallback&& callback)
{
    ASSERT(!m_offerAnswerCallback);
    ASSERT(!m_peerConnection->isClosed());

    m_offerAnswerCallback = WTF::move(callback);
    doCreateOffer(WTF::move(options));
}

void PeerConnectionBackend::createOfferSucceeded(String&& sdp)
{
    ASSERT(isMainThread());

#if PLATFORM(DRIFTSTACK)
    // Family-A createOffer video-PT remap (26.x default → iOS 18.6). Live-gated,
    // Family A only (Safari ≤26.3); 26.4 launch / 26.5 keep 26.x PTs. createOffer
    // only (per the GT probe). The munged PTs are still valid for setLocalDescription
    // (libwebrtc accepts caller-renumbered dynamic PTs). Mirrors the red-fmtp munge
    // pattern at LibWebRTCProvider.cpp:485-510.
    if (driftstackIsFamilyARTC())
        sdp = driftstackRemapFamilyAVideoPTs(sdp);
#endif

#if !RELEASE_LOG_DISABLED
    logger().toObservers(LogWebRTC, WTFLogLevel::Always, { }, LOGIDENTIFIER, "SDP offer created:\n", sdp);
    RELEASE_LOG_FORWARDABLE(WebRTC, PeerConnectionBackendCreateOfferSucceeded, logIdentifier(), sdp.utf8());
#endif

    ASSERT(m_offerAnswerCallback);
    validateSDP(sdp);
    ActiveDOMObject::queueTaskKeepingObjectAlive(protect(m_peerConnection).get(), TaskSource::Networking, [callback = WTF::move(m_offerAnswerCallback), sdp = WTF::move(sdp)](auto&) mutable {
        callback(RTCSessionDescriptionInit { RTCSdpType::Offer, sdp });
    });
}

void PeerConnectionBackend::createOfferFailed(Exception&& exception)
{
    ASSERT(isMainThread());
    ALWAYS_LOG(LOGIDENTIFIER, exception.message());

    ASSERT(m_offerAnswerCallback);
    ActiveDOMObject::queueTaskKeepingObjectAlive(protect(m_peerConnection).get(), TaskSource::Networking, [callback = WTF::move(m_offerAnswerCallback), exception = WTF::move(exception)](auto&) mutable {
        callback(WTF::move(exception));
    });
}

void PeerConnectionBackend::createAnswer(RTCAnswerOptions&& options, CreateCallback&& callback)
{
    ASSERT(!m_offerAnswerCallback);
    ASSERT(!m_peerConnection->isClosed());

    m_offerAnswerCallback = WTF::move(callback);
    doCreateAnswer(WTF::move(options));
}

void PeerConnectionBackend::createAnswerSucceeded(String&& sdp)
{
    ASSERT(isMainThread());

#if !RELEASE_LOG_DISABLED
    logger().toObservers(LogWebRTC, WTFLogLevel::Always, { }, LOGIDENTIFIER, "SDP answer created:\n", sdp);
    RELEASE_LOG_FORWARDABLE(WebRTC, PeerConnectionBackendCreateAnswerSucceeded, logIdentifier(), sdp.utf8());
#endif

    ASSERT(m_offerAnswerCallback);
    ActiveDOMObject::queueTaskKeepingObjectAlive(protect(m_peerConnection).get(), TaskSource::Networking, [callback = WTF::move(m_offerAnswerCallback), sdp = WTF::move(sdp)](auto&) mutable {
        callback(RTCSessionDescriptionInit { RTCSdpType::Answer, sdp });
    });
}

void PeerConnectionBackend::createAnswerFailed(Exception&& exception)
{
    ASSERT(isMainThread());
    ALWAYS_LOG(LOGIDENTIFIER, exception.message());

    ASSERT(m_offerAnswerCallback);
    ActiveDOMObject::queueTaskKeepingObjectAlive(protect(m_peerConnection).get(), TaskSource::Networking, [callback = WTF::move(m_offerAnswerCallback), exception = WTF::move(exception)](auto&) mutable {
        callback(WTF::move(exception));
    });
}

void PeerConnectionBackend::setLocalDescription(const RTCSessionDescription* sessionDescription, Function<void(ExceptionOr<void>&&)>&& callback)
{
    ASSERT(!m_peerConnection->isClosed());

    m_isProcessingLocalDescriptionAnswer = sessionDescription && (sessionDescription->type() == RTCSdpType::Answer || sessionDescription->type() == RTCSdpType::Pranswer);
    m_setDescriptionCallback = WTF::move(callback);
    doSetLocalDescription(sessionDescription);
}

struct MediaStreamAndTrackItem {
    Ref<MediaStream> stream;
    Ref<MediaStreamTrack> track;
};

// https://w3c.github.io/webrtc-pc/#set-associated-remote-streams
static void setAssociatedRemoteStreams(RTCRtpReceiver& receiver, const PeerConnectionBackend::TransceiverState& state, Vector<MediaStreamAndTrackItem>& addList, Vector<MediaStreamAndTrackItem>& removeList)
{
    for (auto& currentStream : receiver.associatedStreams()) {
        if (currentStream && std::ranges::none_of(state.receiverStreams, [&currentStream](auto& stream) { return stream->id() == currentStream->id(); }))
            removeList.append({ Ref { *currentStream }, Ref { receiver.track() } });
    }

    for (auto& stream : state.receiverStreams) {
        if (std::ranges::none_of(receiver.associatedStreams(), [&stream](auto& currentStream) { return stream->id() == currentStream->id(); }))
            addList.append({ stream, Ref { receiver.track() } });
    }

    receiver.setAssociatedStreams(WTF::map(state.receiverStreams, [](auto& stream) { return WeakPtr { stream.get() }; }));
}

static bool NODELETE isDirectionReceiving(RTCRtpTransceiverDirection direction)
{
    return direction == RTCRtpTransceiverDirection::Sendrecv || direction == RTCRtpTransceiverDirection::Recvonly;
}

// https://w3c.github.io/webrtc-pc/#process-remote-tracks
static void processRemoteTracks(RTCRtpTransceiver& transceiver, PeerConnectionBackend::TransceiverState&& state, Vector<MediaStreamAndTrackItem>& addList, Vector<MediaStreamAndTrackItem>& removeList, Vector<Ref<RTCTrackEvent>>& trackEventList, Vector<Ref<MediaStreamTrack>>& muteTrackList)
{
    Ref receiver = transceiver.receiver();
    if (!transceiver.stopped()) {
        auto addListSize = addList.size();
        setAssociatedRemoteStreams(receiver.get(), state, addList, removeList);
        if ((state.firedDirection && isDirectionReceiving(*state.firedDirection) && (!transceiver.firedDirection() || !isDirectionReceiving(*transceiver.firedDirection()))) || addListSize != addList.size()) {
            // https://w3c.github.io/webrtc-pc/#process-remote-track-addition
            trackEventList.append(RTCTrackEvent::create(eventNames().trackEvent, Event::CanBubble::No, Event::IsCancelable::No, receiver.copyRef(), receiver->track(), WTF::move(state.receiverStreams), transceiver));
        }
    }
    if (!(state.firedDirection && isDirectionReceiving(*state.firedDirection)) && transceiver.firedDirection() && isDirectionReceiving(*transceiver.firedDirection())) {
        // https://w3c.github.io/webrtc-pc/#process-remote-track-removal
        muteTrackList.append(receiver->track());
    }
    transceiver.setFiredDirection(state.firedDirection);
}

void PeerConnectionBackend::setLocalDescriptionSucceeded(std::optional<DescriptionStates>&& descriptionStates, std::optional<TransceiverStates>&& transceiverStates, std::unique_ptr<RTCSctpTransportBackend>&& sctpBackend, std::optional<double> maxMessageSize)
{
    ASSERT(isMainThread());
    ALWAYS_LOG(LOGIDENTIFIER, "Set local description succeeded");
    if (transceiverStates)
        DEBUG_LOG(LOGIDENTIFIER, "Transceiver states: ", *transceiverStates);
    ASSERT(m_setDescriptionCallback);
    ActiveDOMObject::queueTaskKeepingObjectAlive(protect(m_peerConnection).get(), TaskSource::Networking, [this, protectedThis = Ref { *this }, callback = WTF::move(m_setDescriptionCallback), descriptionStates = WTF::move(descriptionStates), transceiverStates = WTF::move(transceiverStates), sctpBackend = WTF::move(sctpBackend), maxMessageSize](auto& peerConnection) mutable {
        if (peerConnection.isClosed())
            return;

        peerConnection.updateTransceiversAfterSuccessfulLocalDescription();
        peerConnection.updateSctpBackend(WTF::move(sctpBackend), maxMessageSize);

        if (descriptionStates) {
            peerConnection.updateDescriptions(WTF::move(*descriptionStates));
            if (peerConnection.isClosed())
                return;
        }

        peerConnection.processIceTransportChanges();
        if (peerConnection.isClosed())
            return;

        if (m_isProcessingLocalDescriptionAnswer && transceiverStates) {
            // Compute track related events.
            Vector<MediaStreamAndTrackItem> removeList;
            Vector<Ref<MediaStreamTrack>> muteTrackList;
            Vector<MediaStreamAndTrackItem> addListNoOp;
            for (auto& transceiverState : *transceiverStates) {
                RefPtr<RTCRtpTransceiver> transceiver;
                for (auto& item : peerConnection.currentTransceivers()) {
                    if (item->mid() == transceiverState.mid) {
                        transceiver = item.ptr();
                        break;
                    }
                }
                if (transceiver) {
                    if (!(transceiverState.firedDirection && isDirectionReceiving(*transceiverState.firedDirection)) && transceiver->firedDirection() && isDirectionReceiving(*transceiver->firedDirection())) {
                        setAssociatedRemoteStreams(transceiver->receiver(), transceiverState, addListNoOp, removeList);
                        muteTrackList.append(transceiver->receiver().track());
                    }
                }
                transceiver->setFiredDirection(transceiverState.firedDirection);
            }
            for (auto& track : muteTrackList) {
                track->setShouldFireMuteEventImmediately(true);
                protect(track->source())->setMuted(true);
                track->setShouldFireMuteEventImmediately(false);
                if (peerConnection.isClosed())
                    return;
            }

            for (auto& pair : removeList) {
                DEBUG_LOG(LOGIDENTIFIER, "Removing track "_s, pair.track->id(), " from MediaStream "_s, pair.stream->id());
                pair.stream->privateStream().removeTrack(pair.track->privateTrack());
                if (peerConnection.isClosed())
                    return;
            }
        }

        callback({ });
    });
}

void PeerConnectionBackend::setLocalDescriptionFailed(Exception&& exception)
{
    ASSERT(isMainThread());
    ALWAYS_LOG(LOGIDENTIFIER, "Set local description failed:", exception.message());

    ASSERT(m_setDescriptionCallback);
    ActiveDOMObject::queueTaskKeepingObjectAlive(protect(m_peerConnection).get(), TaskSource::Networking, [callback = WTF::move(m_setDescriptionCallback), exception = WTF::move(exception)](auto& peerConnection) mutable {
        if (peerConnection.isClosed())
            return;

        callback(WTF::move(exception));
    });
}

void PeerConnectionBackend::setRemoteDescription(const RTCSessionDescription& sessionDescription, Function<void(ExceptionOr<void>&&)>&& callback)
{
    ASSERT(!m_peerConnection->isClosed());

    m_setDescriptionCallback = WTF::move(callback);
    doSetRemoteDescription(sessionDescription);
}

void PeerConnectionBackend::setRemoteDescriptionSucceeded(std::optional<DescriptionStates>&& descriptionStates, std::optional<TransceiverStates>&& transceiverStates, std::unique_ptr<RTCSctpTransportBackend>&& sctpBackend, std::optional<double> maxMessageSize)
{
    ASSERT(isMainThread());
    ALWAYS_LOG(LOGIDENTIFIER, "Set remote description succeeded");
    if (transceiverStates)
        DEBUG_LOG(LOGIDENTIFIER, "Transceiver states: ", *transceiverStates);
    ASSERT(m_setDescriptionCallback);

    ActiveDOMObject::queueTaskKeepingObjectAlive(protect(m_peerConnection).get(), TaskSource::Networking, [this, callback = WTF::move(m_setDescriptionCallback), descriptionStates = WTF::move(descriptionStates), transceiverStates = WTF::move(transceiverStates), sctpBackend = WTF::move(sctpBackend), maxMessageSize](auto& peerConnection) mutable {
        UNUSED_PARAM(this);

        if (peerConnection.isClosed())
            return;

        Vector<MediaStreamAndTrackItem> removeList;
        if (transceiverStates) {
            for (auto& transceiver : peerConnection.currentTransceivers()) {
                if (std::ranges::none_of(*transceiverStates, [&transceiver](auto& state) { return state.mid == transceiver->mid(); })) {
                    for (auto& stream : transceiver->receiver().associatedStreams()) {
                        if (stream)
                            removeList.append({ Ref { *stream }, Ref { transceiver->receiver().track() } });
                    }
                }
            }
        }

        peerConnection.updateTransceiversAfterSuccessfulRemoteDescription();
        peerConnection.updateSctpBackend(WTF::move(sctpBackend), maxMessageSize);

        if (descriptionStates) {
            peerConnection.updateDescriptions(WTF::move(*descriptionStates));
            if (peerConnection.isClosed()) {
                DEBUG_LOG(LOGIDENTIFIER, "PeerConnection closed after descriptions update");
                return;
            }
        }

        peerConnection.processIceTransportChanges();
        if (peerConnection.isClosed()) {
            DEBUG_LOG(LOGIDENTIFIER, "PeerConnection closed after ICE transport changes");
            return;
        }

        if (transceiverStates) {
            // Compute track related events.
            Vector<Ref<MediaStreamTrack>> muteTrackList;
            Vector<MediaStreamAndTrackItem> addList;
            Vector<Ref<RTCTrackEvent>> trackEventList;
            for (auto& transceiverState : *transceiverStates) {
                RefPtr<RTCRtpTransceiver> transceiver;
                for (auto& item : peerConnection.currentTransceivers()) {
                    if (item->mid() == transceiverState.mid) {
                        transceiver = item.ptr();
                        break;
                    }
                }
                if (transceiver)
                    processRemoteTracks(*transceiver, WTF::move(transceiverState), addList, removeList, trackEventList, muteTrackList);
            }

            DEBUG_LOG(LOGIDENTIFIER, "Processing ", muteTrackList.size(), " muted tracks");
            for (auto& track : muteTrackList) {
                track->setShouldFireMuteEventImmediately(true);
                protect(track->source())->setMuted(true);
                track->setShouldFireMuteEventImmediately(false);
                if (peerConnection.isClosed()) {
                    DEBUG_LOG(LOGIDENTIFIER, "PeerConnection closed while processing muted tracks");
                    return;
                }
            }

            DEBUG_LOG(LOGIDENTIFIER, "Removing ", removeList.size(), " tracks");
            for (auto& pair : removeList) {
                pair.stream->privateStream().removeTrack(pair.track->privateTrack());
                if (peerConnection.isClosed()) {
                    DEBUG_LOG(LOGIDENTIFIER, "PeerConnection closed while removing tracks");
                    return;
                }
            }

            DEBUG_LOG(LOGIDENTIFIER, "Adding ", addList.size(), " tracks");
            for (auto& pair : addList) {
                Ref { pair.stream }->addTrackFromPlatform(pair.track.copyRef());
                if (peerConnection.isClosed()) {
                    DEBUG_LOG(LOGIDENTIFIER, "PeerConnection closed while adding tracks");
                    return;
                }
            }

            DEBUG_LOG(LOGIDENTIFIER, "Dispatching ", trackEventList.size(), " track events");
            for (auto& event : trackEventList) {
                RefPtr track = event->track();
                ALWAYS_LOG(LOGIDENTIFIER, "Dispatching track event for track ", track->id());
                peerConnection.dispatchEvent(event);
                if (peerConnection.isClosed()) {
                    DEBUG_LOG(LOGIDENTIFIER, "PeerConnection closed while dispatching track events");
                    return;
                }
            }
        }

        callback({ });
    });
}

void PeerConnectionBackend::setRemoteDescriptionFailed(Exception&& exception)
{
    ASSERT(isMainThread());
    ALWAYS_LOG(LOGIDENTIFIER, "Set remote description failed:", exception.message());

    ASSERT(m_setDescriptionCallback);
    ActiveDOMObject::queueTaskKeepingObjectAlive(protect(m_peerConnection).get(), TaskSource::Networking, [callback = WTF::move(m_setDescriptionCallback), exception = WTF::move(exception)](auto& peerConnection) mutable {
        if (peerConnection.isClosed())
            return;

        callback(WTF::move(exception));
    });
}

void PeerConnectionBackend::iceGatheringStateChanged(RTCIceGatheringState state)
{
    ActiveDOMObject::queueTaskKeepingObjectAlive(protect(m_peerConnection).get(), TaskSource::Networking, [this, protectedThis = Ref { *this }, state](auto& peerConnection) {
        if (peerConnection.isClosed())
            return;

        if (state == RTCIceGatheringState::Complete) {
            doneGatheringCandidates();
            return;
        }
        peerConnection.updateIceGatheringState(state);
    });
}

static String extractIPAddress(StringView sdp)
{
    unsigned counter = 0;
    for (auto item : StringView { sdp }.split(' ')) {
        if (++counter == 5)
            return item.toString();
    }
    return { };
}

static inline bool shouldIgnoreIceCandidate(const RTCIceCandidate& iceCandidate)
{
    auto address = extractIPAddress(iceCandidate.candidate());
    if (!address.endsWithIgnoringASCIICase(".local"_s))
        return false;

    if (!WTF::isVersion4UUID(StringView { address }.left(address.length() - 6))) {
        RELEASE_LOG_ERROR(WebRTC, "mDNS candidate is not a Version 4 UUID");
        return true;
    }
    return false;
}

void PeerConnectionBackend::addIceCandidate(RTCIceCandidate* iceCandidate, Function<void(ExceptionOr<void>&&)>&& callback)
{
    ASSERT(!m_peerConnection->isClosed());

    if (!iceCandidate) {
        callback({ });
        return;
    }

    if (shouldIgnoreIceCandidate(*iceCandidate)) {
        callback({ });
        return;
    }

    doAddIceCandidate(*iceCandidate, [weakThis = WeakPtr { *this }, callback = WTF::move(callback)]<typename Result> (Result&& result) mutable {
        RefPtr protectedThis = weakThis.get();
        if (!protectedThis)
            return;

        ActiveDOMObject::queueTaskKeepingObjectAlive(protect(protectedThis->m_peerConnection).get(), TaskSource::Networking, [callback = WTF::move(callback), result = std::forward<Result>(result)](auto& peerConnection) mutable {
            if (peerConnection.isClosed())
                return;

            if (result.hasException()) {
                RELEASE_LOG_ERROR(WebRTC, "Adding ice candidate failed %hhu", std::to_underlying(result.exception().code()));
                callback(result.releaseException());
                return;
            }

            if (auto descriptions = result.releaseReturnValue())
                peerConnection.updateDescriptions(WTF::move(*descriptions));
            callback({ });
        });
    });
}

void PeerConnectionBackend::enableICECandidateFiltering()
{
    m_shouldFilterICECandidates = true;
}

void PeerConnectionBackend::disableICECandidateFiltering()
{
    m_shouldFilterICECandidates = false;
}

void PeerConnectionBackend::validateSDP(const String& sdp) const
{
#if ASSERT_ENABLED
    if (!m_shouldFilterICECandidates)
        return;
    sdp.split('\n', [](auto line) {
        ASSERT(!line.startsWith("a=candidate"_s) || line.contains(".local"_s));
    });
#else
    UNUSED_PARAM(sdp);
#endif
}

void PeerConnectionBackend::newICECandidate(String&& sdp, String&& mid, unsigned short sdpMLineIndex, String&& serverURL, std::optional<DescriptionStates>&& descriptions)
{
    ActiveDOMObject::queueTaskKeepingObjectAlive(protect(m_peerConnection).get(), TaskSource::Networking, [logSiteIdentifier = LOGIDENTIFIER, this, protectedThis = Ref { *this }, sdp = WTF::move(sdp), mid = WTF::move(mid), sdpMLineIndex, serverURL = WTF::move(serverURL), descriptions = WTF::move(descriptions)](auto& peerConnection) mutable {
        if (peerConnection.isClosed())
            return;

        if (descriptions)
            peerConnection.updateDescriptions(WTF::move(*descriptions));

        if (peerConnection.isClosed())
            return;

        UNUSED_PARAM(logSiteIdentifier);
        ALWAYS_LOG(logSiteIdentifier, "Gathered ice candidate:", sdp);
        m_finishedGatheringCandidates = false;

        ASSERT(!m_shouldFilterICECandidates || sdp.contains(".local"_s) || sdp.contains(" srflx "_s) || sdp.contains(" relay "_s));
        auto candidate = RTCIceCandidate::create(WTF::move(sdp), WTF::move(mid), sdpMLineIndex);
        ALWAYS_LOG(logSiteIdentifier, "Dispatching ICE event for SDP ", candidate->candidate());
        peerConnection.dispatchEvent(RTCPeerConnectionIceEvent::create(Event::CanBubble::No, Event::IsCancelable::No, WTF::move(candidate), WTF::move(serverURL)));
    });
}

void PeerConnectionBackend::newDataChannel(UniqueRef<RTCDataChannelHandler>&& channelHandler, String&& label, RTCDataChannelInit&& channelInit)
{
    protect(m_peerConnection)->dispatchDataChannelEvent(WTF::move(channelHandler), WTF::move(label), WTF::move(channelInit));
}

void PeerConnectionBackend::doneGatheringCandidates()
{
    ASSERT(isMainThread());
    ALWAYS_LOG(LOGIDENTIFIER, "Finished ice candidate gathering");
    m_finishedGatheringCandidates = true;

    Ref peerConnection = m_peerConnection.get();
    peerConnection->scheduleEvent(RTCPeerConnectionIceEvent::create(Event::CanBubble::No, Event::IsCancelable::No, nullptr, { }));
    peerConnection->updateIceGatheringState(RTCIceGatheringState::Complete);
}

void PeerConnectionBackend::stop()
{
    m_offerAnswerCallback = nullptr;
    m_setDescriptionCallback = nullptr;

    doStop();
}

void PeerConnectionBackend::markAsNeedingNegotiation(uint32_t eventId)
{
    protect(m_peerConnection)->updateNegotiationNeededFlag(eventId);
}

ExceptionOr<Ref<RTCRtpSender>> PeerConnectionBackend::addTrack(MediaStreamTrack&, FixedVector<String>&&)
{
    return Exception { ExceptionCode::NotSupportedError, "Not implemented"_s };
}

ExceptionOr<Ref<RTCRtpTransceiver>> PeerConnectionBackend::addTransceiver(const String&, const RTCRtpTransceiverInit&, IgnoreNegotiationNeededFlag)
{
    return Exception { ExceptionCode::NotSupportedError, "Not implemented"_s };
}

ExceptionOr<Ref<RTCRtpTransceiver>> PeerConnectionBackend::addTransceiver(Ref<MediaStreamTrack>&&, const RTCRtpTransceiverInit&)
{
    return Exception { ExceptionCode::NotSupportedError, "Not implemented"_s };
}

void PeerConnectionBackend::generateCertificate(Document& document, const CertificateInformation& info, DOMPromiseDeferred<IDLInterface<RTCCertificate>>&& promise)
{
#if USE(LIBWEBRTC)
    RefPtr page = document.page();
    if (!page) {
        promise.reject(ExceptionCode::InvalidStateError);
        return;
    }

    auto& webRTCProvider = downcast<LibWebRTCProvider>(page->webRTCProvider());
    LibWebRTCCertificateGenerator::generateCertificate(document.securityOrigin(), webRTCProvider, info, [promise = WTF::move(promise)](auto&& result) mutable {
        promise.settle(WTF::move(result));
    });
#elif USE(GSTREAMER_WEBRTC)
    auto certificate = ::WebCore::generateCertificate(document.securityOrigin(), info);
    if (certificate.has_value())
        promise.resolve(*certificate);
    else
        promise.reject(ExceptionCode::NotSupportedError);
#else
    UNUSED_PARAM(document);
    UNUSED_PARAM(info);
    promise.reject(ExceptionCode::NotSupportedError);
#endif
}

ScriptExecutionContext* PeerConnectionBackend::context() const
{
    return m_peerConnection->scriptExecutionContext();
}

#if !RELEASE_LOG_DISABLED
WTFLogChannel& PeerConnectionBackend::logChannel() const
{
    return LogWebRTC;
}
#endif

static Ref<JSON::Object> toJSONObject(const PeerConnectionBackend::TransceiverState& transceiverState)
{
    auto object = JSON::Object::create();
    object->setString("mid"_s, transceiverState.mid);

    auto receiverStreams = JSON::Array::create();
    for (auto receiverStream : transceiverState.receiverStreams)
        receiverStreams->pushString(receiverStream->id());
    object->setArray("receiverStreams"_s, WTF::move(receiverStreams));

    if (auto firedDirection = transceiverState.firedDirection)
        object->setString("firedDirection"_s, convertEnumerationToString(*firedDirection));

    return object;
}

static Ref<JSON::Array> toJSONArray(const PeerConnectionBackend::TransceiverStates& transceiverStates)
{
    auto array = JSON::Array::create();
    for (auto transceiverState : transceiverStates)
        array->pushObject(toJSONObject(transceiverState));

    return array;
}

static String toJSONString(const PeerConnectionBackend::TransceiverState& transceiverState)
{
    return toJSONObject(transceiverState)->toJSONString();
}

static String toJSONString(const PeerConnectionBackend::TransceiverStates& transceiverStates)
{
    return toJSONArray(transceiverStates)->toJSONString();
}

void PeerConnectionBackend::ref() const
{
    m_peerConnection->ref();
}

void PeerConnectionBackend::deref() const
{
    m_peerConnection->deref();
}

String PeerConnectionBackend::generateJSONLogEvent(LogEvent&& logEvent, bool isForGatherLogs)
{
    ASCIILiteral type;
    String event;
    WTF::switchOn(WTF::move(logEvent), [&](MessageLogEvent&& logEvent) {
        type = "event"_s;
        StringBuilder builder;
        auto strippedMessage = logEvent.message.removeCharacters([](auto character) {
            return character == '\n';
        });
        builder.append("{\"message\":\""_s, strippedMessage, "\",\"payload\":\""_s);
        if (logEvent.payload)
            builder.append(WTF::base64EncodeToString(*logEvent.payload));
        builder.append("\"}"_s);
        event = builder.toString();
    }, [&](StatsLogEvent&& logEvent) {
        type = "stats"_s;
        event = WTF::move(logEvent);
    });

    if (isForGatherLogs) {
        UNUSED_VARIABLE(type);
        return event;
    }

    auto timestamp = WTF::WallTime::now().secondsSinceEpoch().microseconds();
    return makeString("{\"peer-connection\":\""_s, m_logIdentifierString, "\",\"timestamp\":"_s, timestamp, ",\"type\":\""_s, type, "\",\"event\":"_s, event, '}');
}

void PeerConnectionBackend::emitJSONLogEvent(String&& event)
{
#if PLATFORM(WPE) || PLATFORM(GTK)
    if (!isJSONLogStreamingEnabled())
        return;

    auto& handler = jsonFileHandler();
    handler.log(WTF::move(event));
#else
    UNUSED_PARAM(event);
#endif
}

} // namespace WebCore

namespace WTF {

String LogArgument<WebCore::PeerConnectionBackend::TransceiverState>::toString(const WebCore::PeerConnectionBackend::TransceiverState& transceiverState)
{
    return toJSONString(transceiverState);
}

String LogArgument<WebCore::PeerConnectionBackend::TransceiverStates>::toString(const WebCore::PeerConnectionBackend::TransceiverStates& transceiverStates)
{
    return toJSONString(transceiverStates);
}

}

#endif // ENABLE(WEB_RTC)
