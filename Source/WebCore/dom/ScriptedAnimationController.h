/*
 * Copyright (C) 2011 Google Inc. All rights reserved.
 * Copyright (C) 2020 Apple Inc. All rights reserved.
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
 *  THIS SOFTWARE IS PROVIDED BY APPLE INC. AND ITS CONTRIBUTORS ``AS IS'' AND ANY
 *  EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 *  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 *  DISCLAIMED. IN NO EVENT SHALL APPLE INC. OR ITS CONTRIBUTORS BE LIABLE FOR ANY
 *  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 *  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 *  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 *  ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 *  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#pragma once

#include "AnimationFrameRate.h"
#include "Document.h"
#include "ReducedResolutionSeconds.h"
#include "Timer.h"
#include <wtf/CheckedPtr.h>
#include <wtf/OptionSet.h>
#include <wtf/RefCounted.h>
#include <wtf/RefPtr.h>
#include <wtf/Vector.h>

namespace WebCore {

class ImminentlyScheduledWorkScope;
class Page;
class RequestAnimationFrameCallback;
class UserGestureToken;
class WeakPtrImplWithEventTargetData;

class ScriptedAnimationController : public RefCounted<ScriptedAnimationController>
{
public:
    static Ref<ScriptedAnimationController> create(Document& document)
    {
        return adoptRef(*new ScriptedAnimationController(document));
    }
    ~ScriptedAnimationController();
    void clearDocumentPointer() { m_document = nullptr; }

    WEBCORE_EXPORT Seconds NODELETE interval() const;
    WEBCORE_EXPORT OptionSet<ThrottlingReason> NODELETE throttlingReasons() const;

    void NODELETE suspend();
    void resume();

    void addThrottlingReason(ThrottlingReason reason) { m_throttlingReasons.add(reason); }
    void removeThrottlingReason(ThrottlingReason reason) { m_throttlingReasons.remove(reason); }

    using CallbackId = int;
    CallbackId registerCallback(Ref<RequestAnimationFrameCallback>&&);
    void cancelCallback(CallbackId);
    void serviceRequestAnimationFrameCallbacks(ReducedResolutionSeconds);

private:
    ScriptedAnimationController(Document&);

    Page* NODELETE page() const;
    Seconds NODELETE preferredScriptedAnimationInterval() const;
    bool isThrottledRelativeToPage() const;
    bool shouldRescheduleRequestAnimationFrame(ReducedResolutionSeconds) const;
    void scheduleAnimation();

    struct CallbackData {
        Ref<RequestAnimationFrameCallback> callback;
        RefPtr<UserGestureToken> userGestureTokenToForward;
        RefPtr<ImminentlyScheduledWorkScope> scheduledWorkScope;
    };
    Vector<CallbackData> m_callbackDataList;

    WeakPtr<Document, WeakPtrImplWithEventTargetData> m_document;
    CallbackId m_nextCallbackId { 0 };
    int m_suspendCount { 0 };

    ReducedResolutionSeconds m_lastAnimationFrameTimestamp;
#if PLATFORM(DRIFTSTACK)
    // Wave 29-258 / cumrig rAF first-frame closure: counter to detect the
    // FIRST service call (when env DRIFTSTACK_RAF_FIRST_FRAME_CLAMP=1 is set,
    // clamp the JS-visible timestamp on the SECOND callback to make
    // deltas[0] match iPhone Safari's ~10ms pattern rather than Mac
    // MiniBrowser process-startup overhead ~28-39ms).
    uint32_t m_driftstackCallbackInvocationCount { 0 };
    double m_driftstackFirstCallbackTimestampMs { 0 };
    double m_driftstackTimestampShiftMs { 0 };
    // Wave 29-499.6 Task #76 — long-tail jitter clamp. Mac fork rAF
    // sometimes sees wall-clock deltas up to 376ms vs iPhone tight
    // 17-24ms band (60Hz ProMotion-non-fast mode). Detection vector:
    // any probe that records per-frame deltas + computes p95/p99 or
    // max catches the divergence. Mitigation: when env
    // DRIFTSTACK_RAF_DELTA_CLAMP=1 set, cap each JS-visible delta at
    // DRIFTSTACK_RAF_DELTA_CLAMP_MS (default 17ms = 60Hz quantum),
    // accumulating the shift. Subsequent timestamps stay in iPhone
    // distribution even if Mac main-thread scheduling produced
    // hiccups. Tradeoff: under heavy load, JS animations may drift
    // ~Nms behind wall-clock — same graceful-degradation pattern real
    // iPhone exhibits under main-thread contention.
    double m_driftstackLastClampedTimestampMs { 0 };
#endif
    OptionSet<ThrottlingReason> m_throttlingReasons;
};

} // namespace WebCore
