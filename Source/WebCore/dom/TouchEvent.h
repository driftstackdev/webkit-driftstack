/*
 * Copyright 2008, The Android Open Source Project
 * Copyright (C) 2012 Research In Motion Limited. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL APPLE INC. OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#pragma once

#if ENABLE(IOS_TOUCH_EVENTS)
#include <WebKitAdditions/TouchEventIOS.h>
#elif ENABLE(TOUCH_EVENTS) || ENABLE(DRIFTSTACK_TOUCH_STUBS)

#include "MouseRelatedEvent.h"
#include "TouchList.h"

namespace WebCore {

class TouchEvent final : public MouseRelatedEvent {
    WTF_MAKE_TZONE_ALLOCATED(TouchEvent);
public:
    virtual ~TouchEvent();

    static Ref<TouchEvent> create(TouchList* touches, TouchList* targetTouches, TouchList* changedTouches,
        const AtomString& type, RefPtr<WindowProxy>&& view, const DoublePoint& globalLocation, OptionSet<Modifier> modifiers)
    {
        return adoptRef(*new TouchEvent(touches, targetTouches, changedTouches, type, WTF::move(view), globalLocation, modifiers));
    }
    static Ref<TouchEvent> createForBindings()
    {
        return adoptRef(*new TouchEvent);
    }

    struct Init : EventModifierInit {
        RefPtr<TouchList> touches;
        RefPtr<TouchList> targetTouches;
        RefPtr<TouchList> changedTouches;
    };

    static Ref<TouchEvent> create(const AtomString& type, const Init& initializer, IsTrusted isTrusted = IsTrusted::No)
    {
        return adoptRef(*new TouchEvent(type, initializer, isTrusted));
    }

    TouchList* touches() const { return m_touches.get(); }
    TouchList* targetTouches() const { return m_targetTouches.get(); }
    TouchList* changedTouches() const { return m_changedTouches.get(); }

    // iOS TouchEvent also exposes multi-touch rotation/scale + the legacy initTouchEvent (verified vs real
    // iPhone-17 apiEnum.proto.TouchEvent, 2026-06-01: the fork lacked these 3). Default (non-gesture) values;
    // legacy init is presence-only (modern code uses the constructor).
    float rotation() const { return 0.0f; }
    float scale() const { return 1.0f; }
    void initTouchEvent() { }

    void setTouches(RefPtr<TouchList>&& touches) { m_touches = touches; }
    void setTargetTouches(RefPtr<TouchList>&& targetTouches) { m_targetTouches = targetTouches; }
    void setChangedTouches(RefPtr<TouchList>&& changedTouches) { m_changedTouches = changedTouches; }

private:
    TouchEvent();
    TouchEvent(TouchList* touches, TouchList* targetTouches, TouchList* changedTouches, const AtomString& type,
        RefPtr<WindowProxy>&&, const DoublePoint& globalLocation, OptionSet<Modifier>);
    TouchEvent(const AtomString&, const Init&, IsTrusted);

    RefPtr<TouchList> m_touches;
    RefPtr<TouchList> m_targetTouches;
    RefPtr<TouchList> m_changedTouches;
};

} // namespace WebCore

SPECIALIZE_TYPE_TRAITS_EVENT(TouchEvent)

#endif // ENABLE(TOUCH_EVENTS) || ENABLE(DRIFTSTACK_TOUCH_STUBS)
