/*
 * Wave 29-408.2 (Driftstack 2026-05-20): OverflowEvent restoration for Family A.
 * See OverflowEvent.idl for the surface motivation.
 */

#include "config.h"
#include "OverflowEvent.h"

#include <wtf/TZoneMallocInlines.h>

namespace WebCore {

WTF_MAKE_TZONE_ALLOCATED_IMPL(OverflowEvent);

OverflowEvent::OverflowEvent()
    : Event(EventInterfaceType::OverflowEvent)
{
}

OverflowEvent::OverflowEvent(const AtomString& type, Init&& initializer, IsTrusted isTrusted)
    : Event(EventInterfaceType::OverflowEvent, type, WTF::move(initializer), isTrusted)
    , m_orient(initializer.orient)
    , m_horizontalOverflow(initializer.horizontalOverflow)
    , m_verticalOverflow(initializer.verticalOverflow)
{
}

Ref<OverflowEvent> OverflowEvent::create(const AtomString& type, Init&& initializer, IsTrusted isTrusted)
{
    return adoptRef(*new OverflowEvent(type, WTF::move(initializer), isTrusted));
}

Ref<OverflowEvent> OverflowEvent::createForBindings()
{
    return adoptRef(*new OverflowEvent);
}

} // namespace WebCore
