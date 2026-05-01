/*
 * Copyright (C) 2026 Driftstack. All rights reserved.
 *
 * Minimal stub of iOS Safari's GestureEvent so the JS-visible
 * window.GestureEvent constructor exposes 'function' typeof matching
 * iPhone Safari (file 109 hard rule). Never dispatched on Mac fleet
 * (no touch input); constructor exists for fingerprint authenticity.
 *
 * On builds where IOS_GESTURE_EVENTS or MAC_GESTURE_EVENTS is enabled
 * (USE(APPLE_INTERNAL_SDK)), the real GestureEvent comes from
 * WebKitAdditions/GestureEvent.h instead — this file's contents are
 * skipped via the #elif gate.
 */

#pragma once

#if ENABLE(IOS_GESTURE_EVENTS)
#include <WebKitAdditions/GestureEventIOS.h>
#elif ENABLE(MAC_GESTURE_EVENTS)
#include <WebKitAdditions/GestureEvent.h>
#elif ENABLE(DRIFTSTACK_TOUCH_STUBS)

#include "UIEvent.h"
#include <wtf/TZoneMalloc.h>

namespace WebCore {

class GestureEvent final : public UIEvent {
    WTF_MAKE_TZONE_ALLOCATED(GestureEvent);
public:
    static Ref<GestureEvent> create()
    {
        return adoptRef(*new GestureEvent);
    }

    float scale() const { return 1.0f; }
    float rotation() const { return 0.0f; }

private:
    GestureEvent() : UIEvent(EventInterfaceType::GestureEvent) { }
};

} // namespace WebCore

SPECIALIZE_TYPE_TRAITS_EVENT(GestureEvent)

#endif // ENABLE(IOS_GESTURE_EVENTS) || ENABLE(MAC_GESTURE_EVENTS) || ENABLE(DRIFTSTACK_TOUCH_STUBS)
