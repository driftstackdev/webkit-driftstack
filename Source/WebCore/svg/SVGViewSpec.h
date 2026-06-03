/*
 * Copyright (C) 2007 Rob Buis <buis@kde.org>
 * Copyright (C) 2018-2019 Apple Inc. All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public License
 * along with this library; see the file COPYING.LIB.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 */

#pragma once

#include "SVGFitToViewBox.h"
#include "SVGZoomAndPan.h"
#include <wtf/TZoneMalloc.h>
#include <wtf/WeakPtr.h>

namespace WebCore {

class SVGElement;
class SVGTransformList;
class WeakPtrImplWithEventTargetData;

class SVGViewSpec final : public RefCounted<SVGViewSpec>, public SVGFitToViewBox, public SVGZoomAndPan {
    WTF_MAKE_TZONE_ALLOCATED(SVGViewSpec);
public:
    static Ref<SVGViewSpec> create(SVGElement& contextElement)
    {
        return adoptRef(*new SVGViewSpec(contextElement));
    }

    bool parseViewSpec(StringView);
    void reset();
    void resetContextElement() { m_contextElement = nullptr; }

    String transformString() const { return m_transform->valueAsString(); }
    Ref<SVGTransformList>& transform() { return m_transform; }

    // W393: SVG1.1 SVGViewSpec.viewTarget / viewTargetString — removed from SVG2 (WebCore previously parsed-then-
    // discarded the viewTarget token, SVGViewSpec.cpp), but real iPhone-17 Safari still exposes both on the prototype.
    // viewTargetString is the raw id captured during parse; viewTarget resolves it against the context element's tree scope.
    String viewTargetString() const { return m_viewTargetString; }
    RefPtr<SVGElement> viewTarget() const;

    SVGElement* contextElementConcurrently() const { return m_contextElement; }

    using PropertyRegistry = SVGPropertyOwnerRegistry<SVGViewSpec, SVGFitToViewBox>;

private:
    explicit SVGViewSpec(SVGElement&);

    WeakPtr<SVGElement, WeakPtrImplWithEventTargetData> m_contextElement;
    Ref<SVGTransformList> m_transform;
    String m_viewTargetString; // W393: raw viewTarget id captured during parseViewSpec (SVG1.1 viewTarget support)
};

} // namespace WebCore
