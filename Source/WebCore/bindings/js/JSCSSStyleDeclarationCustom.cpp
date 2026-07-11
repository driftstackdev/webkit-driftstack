/*
 * Copyright (C) 2007-2021 Apple Inc. All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY APPLE INC. ``AS IS'' AND ANY
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

#include "config.h"
#include "JSCSSStyleDeclaration.h"

#include "CSSFontFaceDescriptors.h"
#include "CSSFunctionDescriptors.h"
#include "CSSPageDescriptors.h"
#include "CSSPositionTryDescriptors.h"
#include "CSSStyleProperties.h"
#include "DOMWrapperWorld.h"
#include "Document.h"
#include "Settings.h"
#include "JSCSSFontFaceDescriptors.h"
#include "JSCSSFunctionDescriptors.h"
#include "JSCSSPageDescriptors.h"
#include "JSCSSPositionTryDescriptors.h"
#include "JSCSSRuleCustom.h"
#include "JSCSSStyleProperties.h"
#include "JSDOMConvertInterface.h"
#include "JSDOMConvertStrings.h"
#include "JSDeprecatedCSSOMValue.h"
#include "JSNodeCustom.h"
#include "JSStyleSheetCustom.h"
#include "StyledElement.h"
#include "WebCoreOpaqueRootInlines.h"

namespace WebCore {
using namespace JSC;

WebCoreOpaqueRoot root(CSSStyleDeclaration* style)
{
    ASSERT(style);
    if (auto* parentRule = style->parentRule())
        return root(parentRule);
    if (auto* styleSheet = style->parentStyleSheet())
        return root(styleSheet);
    if (SUPPRESS_UNCHECKED_LOCAL auto* parentElement = style->parentElement())
        return root(parentElement);
    return WebCoreOpaqueRoot { style };
}

template<typename Visitor>
void JSCSSStyleDeclaration::visitAdditionalChildrenInGCThread(Visitor& visitor)
{
    addWebCoreOpaqueRoot(visitor, wrapped());
}

DEFINE_VISIT_ADDITIONAL_CHILDREN_IN_GC_THREAD(JSCSSStyleDeclaration);

#if PLATFORM(DRIFTSTACK)
// CSSStyleDeclaration-186 (2026-07-11 net-audit follow-on): real iPhone Safari <26 (Family-A/18.6) is PRE-split
// — the ~1450 CSS property accessors live directly on CSSStyleDeclaration.prototype. Safari 26 split them onto a
// new CSSStyleProperties interface, so the (26.x-based) fork generates them onto JSCSSStylePropertiesPrototype.
// For Family-A, reify that same table onto the CSSStyleDeclaration prototype so window.CSSStyleDeclaration.prototype
// matches the real pre-split shape. Gated on !cssDescriptorBlocksEnabled — the same Family-A setting that already
// hides window.CSSStyleProperties. JSCSSStylePropertiesPrototypeTableValues has external linkage via the
// CodeGeneratorJS.pm change; its size must match the generated table (a mismatch is a link error, caught at build).
extern const std::array<JSC::HashTableValue, 1553> JSCSSStylePropertiesPrototypeTableValues;

// External linkage: the generated JSCSSStyleDeclarationPrototype::finishCreation calls this via a matching
// local declaration (no forwarding header). Declare it here first to satisfy -Wmissing-prototypes.
void driftstackReifyFamilyACSSAccessorsOnStyleDeclaration(JSC::VM&, JSDOMGlobalObject&, JSC::JSObject&);
void driftstackReifyFamilyACSSAccessorsOnStyleDeclaration(JSC::VM& vm, JSDOMGlobalObject& globalObject, JSC::JSObject& styleDeclProto)
{
    auto* document = dynamicDowncast<Document>(globalObject.scriptExecutionContext());
    if (!document || document->settingsValues().cssDescriptorBlocksEnabled)
        return; // Safari 26.x: post-split, accessors stay on CSSStyleProperties.prototype (launch-safe no-op).
    reifyStaticProperties(vm, JSCSSStyleProperties::info(), JSCSSStylePropertiesPrototypeTableValues, styleDeclProto);

    // The generated table is 26.x-based (1553 accessors). Real Safari 18.6 CSSStyleDeclaration.prototype has
    // exactly 1450 own properties — the 26.x-added CSS properties did not exist yet. Delete the 113 post-18.6
    // property names (both dashed + camelCase forms) so window.CSSStyleDeclaration.prototype byte-matches the real
    // pre-split shape. List captured from a real iPhone Safari 18.6 (apiEnum.drillOwn.CSSStyleDeclaration → 1450
    // ownNames, proto hash f1639565); pinned by apienum-cssstyledeclaration-protosplit-186-gate. Family-A only:
    // guarded by !cssDescriptorBlocksEnabled above, so the 26.x launch band is never touched.
    static constexpr std::array<ASCIILiteral, 113> driftstackCSSPropertiesAddedAfter186 { {
        "-apple-color-filter"_s, "-apple-visual-effect"_s, "AppleColorFilter"_s, "AppleVisualEffect"_s, "anchor-name"_s, "anchor-scope"_s,
        "anchorName"_s, "anchorScope"_s, "animation-range"_s, "animation-range-end"_s, "animation-range-start"_s, "animation-timeline"_s,
        "animationRange"_s, "animationRangeEnd"_s, "animationRangeStart"_s, "animationTimeline"_s, "block-ellipsis"_s, "block-step"_s,
        "block-step-align"_s, "block-step-insert"_s, "block-step-round"_s, "block-step-size"_s, "blockEllipsis"_s, "blockStep"_s,
        "blockStepAlign"_s, "blockStepInsert"_s, "blockStepRound"_s, "blockStepSize"_s, "continue"_s, "corner-bottom-left-shape"_s,
        "corner-bottom-right-shape"_s, "corner-end-end-shape"_s, "corner-end-start-shape"_s, "corner-shape"_s, "corner-start-end-shape"_s, "corner-start-start-shape"_s,
        "corner-top-left-shape"_s, "corner-top-right-shape"_s, "cornerBottomLeftShape"_s, "cornerBottomRightShape"_s, "cornerEndEndShape"_s, "cornerEndStartShape"_s,
        "cornerShape"_s, "cornerStartEndShape"_s, "cornerStartStartShape"_s, "cornerTopLeftShape"_s, "cornerTopRightShape"_s, "d"_s,
        "dynamic-range-limit"_s, "dynamicRangeLimit"_s, "field-sizing"_s, "fieldSizing"_s, "flow-tolerance"_s, "flowTolerance"_s,
        "font-variant-emoji"_s, "fontVariantEmoji"_s, "input-security"_s, "inputSecurity"_s, "line-clamp"_s, "line-fit-edge"_s,
        "lineClamp"_s, "lineFitEdge"_s, "math-depth"_s, "math-shift"_s, "mathDepth"_s, "mathShift"_s,
        "max-lines"_s, "maxLines"_s, "overflow-anchor"_s, "overflow-block"_s, "overflow-clip-margin"_s, "overflow-inline"_s,
        "overflowAnchor"_s, "overflowBlock"_s, "overflowClipMargin"_s, "overflowInline"_s, "position-anchor"_s, "position-area"_s,
        "position-try"_s, "position-try-fallbacks"_s, "position-try-order"_s, "position-visibility"_s, "positionAnchor"_s, "positionArea"_s,
        "positionTry"_s, "positionTryFallbacks"_s, "positionTryOrder"_s, "positionVisibility"_s, "result"_s, "scroll-timeline"_s,
        "scroll-timeline-axis"_s, "scroll-timeline-name"_s, "scrollTimeline"_s, "scrollTimelineAxis"_s, "scrollTimelineName"_s, "scrollbar-color"_s,
        "scrollbarColor"_s, "text-group-align"_s, "text-justify"_s, "text-spacing-trim"_s, "textGroupAlign"_s, "textJustify"_s,
        "textSpacingTrim"_s, "timeline-scope"_s, "timelineScope"_s, "view-timeline"_s, "view-timeline-axis"_s, "view-timeline-inset"_s,
        "view-timeline-name"_s, "viewTimeline"_s, "viewTimelineAxis"_s, "viewTimelineInset"_s, "viewTimelineName"_s,
    } };
    VM::DeletePropertyModeScope deleteScope(vm, VM::DeletePropertyMode::IgnoreConfigurable);
    for (auto& name : driftstackCSSPropertiesAddedAfter186) {
        auto propertyName = Identifier::fromString(vm, name);
        DeletePropertySlot slot;
        JSObject::deleteProperty(&styleDeclProto, &globalObject, propertyName, slot);
    }
}
#endif

} // namespace WebCore
