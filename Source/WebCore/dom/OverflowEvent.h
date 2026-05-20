/*
 * Wave 29-408.2 (Driftstack 2026-05-20): OverflowEvent restoration for Family A.
 * See OverflowEvent.idl for the surface motivation.
 */

#pragma once

#include "Event.h"
#include "EventInit.h"
#include <wtf/Forward.h>

namespace WebCore {

class OverflowEvent final : public Event {
    WTF_MAKE_TZONE_ALLOCATED(OverflowEvent);

public:
    // Legacy DOM3 constants (matches real iPhone Safari 18.x exposure).
    static constexpr unsigned short HORIZONTAL = 0;
    static constexpr unsigned short VERTICAL = 1;
    static constexpr unsigned short BOTH = 2;

    struct Init : EventInit {
        unsigned short orient { 0 };
        bool horizontalOverflow { false };
        bool verticalOverflow { false };
    };

    static Ref<OverflowEvent> create(const AtomString& type, Init&&, IsTrusted = IsTrusted::No);
    static Ref<OverflowEvent> createForBindings();

    unsigned short orient() const { return m_orient; }
    bool horizontalOverflow() const { return m_horizontalOverflow; }
    bool verticalOverflow() const { return m_verticalOverflow; }

private:
    OverflowEvent();
    OverflowEvent(const AtomString& type, Init&&, IsTrusted = IsTrusted::No);

    unsigned short m_orient { 0 };
    bool m_horizontalOverflow { false };
    bool m_verticalOverflow { false };
};

} // namespace WebCore
