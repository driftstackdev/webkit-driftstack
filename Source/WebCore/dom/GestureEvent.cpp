/*
 * Copyright (C) 2026 Driftstack. All rights reserved.
 *
 * See GestureEvent.h for the rationale.
 */

#include "config.h"

#if ENABLE(DRIFTSTACK_TOUCH_STUBS) && !ENABLE(IOS_GESTURE_EVENTS) && !ENABLE(MAC_GESTURE_EVENTS)

#include "GestureEvent.h"

namespace WebCore {

WTF_MAKE_TZONE_ALLOCATED_IMPL(GestureEvent);

// Out-of-line virtual destructor anchors the vtable in this .o.
GestureEvent::~GestureEvent() = default;

} // namespace WebCore

#endif // ENABLE(DRIFTSTACK_TOUCH_STUBS) && !ENABLE(IOS_GESTURE_EVENTS) && !ENABLE(MAC_GESTURE_EVENTS)
