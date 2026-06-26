/*
 * Copyright (C) 2018-2023 Apple Inc. All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY APPLE INC. AND ITS CONTRIBUTORS ``AS IS''
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL APPLE INC. OR ITS CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"
#include "CSSParserContext.h"

#include "CSSPropertyNames.h"
#include "CSSValuePool.h"
#include "DocumentLoader.h"
#include "DocumentQuirks.h"
#include "DocumentSecurityOrigin.h"
#include "OriginAccessPatterns.h"
#include "Page.h"
#include "Settings.h"
#include <wtf/NeverDestroyed.h>

namespace WebCore {

const CSSParserContext& strictCSSParserContext()
{
    static MainThreadNeverDestroyed<CSSParserContext> strictContext(HTMLStandardMode);
    return strictContext;
}

static void NODELETE applyUASheetBehaviorsToContext(CSSParserContext& context)
{
    // FIXME: We should turn all of the features on from their WebCore Settings defaults.
    context.cssAppearanceBaseEnabled = true;
    context.cssRubyDisplayTypesEnabled = true;
    context.cssTextTransformMathAutoEnabled = true;
    context.popoverAttributeEnabled = true;
    context.propertySettings.cssInputSecurityEnabled = true;
    context.propertySettings.supportHDRDisplayEnabled = true;
    context.propertySettings.cssFieldSizingEnabled = true;
    context.cssMathDepthEnabled = true;
    context.propertySettings.cssMathDepthEnabled = true;
#if HAVE(CORE_MATERIAL)
    context.propertySettings.useSystemAppearance = true;
#endif
    context.propertySettings.cssAnchorPositioningEnabled = true;
    context.cssInternalAutoBaseParsingEnabled = true;
    context.htmlEnhancedSelectEnabled = true;
}

CSSParserContext::CSSParserContext(CSSParserMode mode, const URL& baseURL)
    : baseURL(baseURL)
    , mode(mode)
{
    if (isUASheetBehavior(mode))
        applyUASheetBehaviorsToContext(*this);

    StaticCSSValuePool::init();
}

CSSParserContext::CSSParserContext(const Document& document)
{
    *this = document.cssParserContext();
}

CSSParserContext::CSSParserContext(const Document& document, const URL& sheetBaseURL, ASCIILiteral charset)
    : CSSParserContext(document.settings())
{
    baseURL = sheetBaseURL.isNull() ? document.baseURL() : sheetBaseURL;
    this->charset = charset;
    mode = document.inQuirksMode() ? HTMLQuirksMode : HTMLStandardMode;
    isHTMLDocument = document.isHTMLDocument();
    hasDocumentSecurityOrigin = sheetBaseURL.isNull() || protect(document.securityOrigin())->canRequest(baseURL, OriginAccessPatternsForWebProcess::singleton());
    webkitMediaTextTrackDisplayQuirkEnabled = document.quirks().needsWebKitMediaTextTrackDisplayQuirk();
}

CSSParserContext::CSSParserContext(const Settings& settings)
    : mode { HTMLStandardMode }
    , useSystemAppearance { settings.useSystemAppearance() }
    , counterStyleAtRuleImageSymbolsEnabled { settings.cssCounterStyleAtRuleImageSymbolsEnabled() }
    , springTimingFunctionEnabled { settings.springTimingFunctionEnabled() }
#if HAVE(CORE_ANIMATION_SEPARATED_LAYERS)
    , cssTransformStyleSeparatedEnabled { settings.cssTransformStyleSeparatedEnabled() }
#endif
    , gridLanesEnabled { settings.gridLanesEnabled() }
    , cssAppearanceBaseEnabled { settings.cssAppearanceBaseEnabled() }
    , cssPaintingAPIEnabled { settings.cssPaintingAPIEnabled() }
    , cssTextDecorationLineErrorValues { settings.cssTextDecorationLineErrorValues() }
    , cssWordBreakAutoPhraseEnabled { settings.cssWordBreakAutoPhraseEnabled() }
    , popoverAttributeEnabled { settings.popoverAttributeEnabled() }
    , cssTextWrapPrettyEnabled { settings.cssTextWrapPrettyEnabled() }
#if ENABLE(SERVICE_CONTROLS)
    , imageControlsEnabled { settings.imageControlsEnabled() }
#endif
    , colorLayersEnabled { settings.cssColorLayersEnabled() }
    , cssPickerPseudoElementEnabled { settings.cssPickerPseudoElementEnabled() }
    , targetTextPseudoElementEnabled { settings.targetTextPseudoElementEnabled() }
    , htmlEnhancedSelectEnabled { settings.htmlEnhancedSelectEnabled() }
    , cssRandomFunctionEnabled { settings.cssRandomFunctionEnabled() }
    , cssRubyDisplayTypesEnabled { settings.cssRubyDisplayTypesInAuthorStylesEnabled() }
    , cssTreeCountingFunctionsEnabled { settings.cssTreeCountingFunctionsEnabled() }
    , cssURLModifiersEnabled { settings.cssURLModifiersEnabled() }
    , cssURLIntegrityModifierEnabled { settings.cssURLIntegrityModifierEnabled() }
    , cssAxisRelativePositionKeywordsEnabled { settings.cssAxisRelativePositionKeywordsEnabled() }
    , cssDynamicRangeLimitMixEnabled { settings.cssDynamicRangeLimitMixEnabled() }
    , cssConstrainedDynamicRangeLimitEnabled { settings.cssConstrainedDynamicRangeLimitEnabled() }
    , cssTextTransformMathAutoEnabled { settings.cssTextTransformMathAutoEnabled() }
    , cssFontSynthesisStyleObliqueOnlyEnabled { settings.cssFontSynthesisStyleObliqueOnlyEnabled() }
    , cssInternalAutoBaseParsingEnabled { settings.cssInternalAutoBaseParsingEnabled() }
    , cssMathDepthEnabled { settings.cssMathDepthEnabled() }
    , openPseudoClassEnabled { settings.openPseudoClassEnabled() }
    , cssAttrSubstitutionFunctionEnabled { settings.cssAttrSubstitutionFunctionEnabled() }
    , propertySettings { CSSPropertySettings { settings } }
{
#if PLATFORM(DRIFTSTACK)
    // V-527.A.1 (2026-05-09): force-enable CSS feature flags that real
    // iPhone Safari 26.4 reports as supported via CSS.supports() but
    // fork's runtime path leaves disabled despite YAML default=true.
    // Empirical (V-527-A): anchor-name / position-anchor / animation-timeline
    // all returned False on fork pre-patch. CSSAnchorPositioningEnabled
    // YAML default=true at compile time (WebPreferencesDefinitions.h:677)
    // but propertySettings.cssAnchorPositioningEnabled was constructed
    // false from the WebProcess Settings copy — IPC propagation gap not
    // localized in source dive. Force-true here for iPhone-archetype
    // parity; propertySettings is the parser's authority over which
    // properties parse without fallback. Same pattern as
    // applyUASheetBehaviorsToContext line 62.
    //
    // Wave 29-404 §11.A.3: Family A iPhone Safari 18.6 (BS capture
    // 2026-05-19) returns `CSS.supports('top: anchor(top)')` === false.
    // For Family A archetype, RESPECT the Settings value (which
    // WebPage::updatePreferences sets to false). Force-enable only
    // applies to Family B archetypes (Safari 26.4+ launch path).
    static const bool s_isFamilyAArchetype = []() {
        const char* archetype = getenv("DRIFTSTACK_ARCHETYPE");
        if (!archetype)
            return false;
        std::string_view sv(archetype);
        return sv.find("safari17_") != std::string_view::npos
            || sv.find("safari18_") != std::string_view::npos
            || sv.find("safari19_") != std::string_view::npos
            || sv.find("safari20_") != std::string_view::npos
            || sv.find("safari21_") != std::string_view::npos
            || sv.find("safari22_") != std::string_view::npos
            || sv.find("safari23_") != std::string_view::npos
            || sv.find("safari24_") != std::string_view::npos
            || sv.find("safari25_") != std::string_view::npos;
    }();
    if (!s_isFamilyAArchetype) {
        // V-527.A.1 follow-up (2026-06-02, W306): the original patch's comment
        // listed `animation-timeline` among the pre-patch False properties but
        // only force-enabled the anchor flag. `animation-timeline` is gated by
        // scrollDrivenAnimationsEnabled, NOT cssAnchorPositioningEnabled, so this
        // mirrors the same propertySettings force-true for Family B parity. This
        // makes the animation-timeline PROPERTY parse (CSS.supports('animation-
        // timeline: auto'/'none') === true, matching real iPhone 17/26.4).
        //
        // VERIFIED (FA-CSS, production-path capture via launch-webprocess.sh WebDriver,
        // NOT MiniBrowser — the W802-804 "stays False" claims were MiniBrowser artifacts,
        // now retracted): under a Family-B archetype the production WebContent path serves
        //   CSS.supports('anchor-name: --foo')        === true   (real 26.x = true) ✓
        //   CSS.supports('position-anchor: --foo')    === true   (real 26.x = true) ✓
        //   CSS.supports('animation-timeline: scroll()') === true (real 26.x = true) ✓
        //   CSS.supports('inset-area: center')        === false  (real 26.x = false) ✓
        // i.e. the anchor + animation-timeline force-enables here ARE honored production-
        // path; the old "absent from the parser / scroll() unimplemented" notes were wrong.
        //
        // NAMED-TIMELINE CSS PROPERTIES (scroll-timeline*/view-timeline*/timeline-scope):
        // CAPTURE-CORRECTED (aio-iPhone_17_Pro_Max, Safari 26.4) — real iPhone 26.x serves
        //   CSS.supports('scroll-timeline-name: --x') === true ✓
        //   CSS.supports('view-timeline-name: --x')   === true ✓
        //   CSS.supports('timeline-scope: --x')       === true ✓
        // and Family A (aio-iPhone_16_Pro_Max, Safari 18.6) serves all three === false.
        // The prior d9ae2575d3 comment ("real iPhone 26.x = false") was BACKWARDS and is
        // RETRACTED: it defaulted cssNamedTimelinePropertiesEnabled false on EVERY archetype,
        // which made the 26.4 LAUNCH archetype LEAK (served false; real = true). Those 8 CSS
        // properties were split onto their own cssNamedTimelinePropertiesEnabled flag (default
        // false in YAML so Family A is correct without intervention); here we force it TRUE for
        // Family B so the 26.x cohort (incl launch 26.4) matches real iOS. animation-timeline/
        // animation-range stay on scrollDrivenAnimationsEnabled (also true for Family B). The
        // per-archetype split: Family B → both flags true (named-timeline + animation-timeline
        // all parse), Family A → respects Settings (both false). JS timeline constructor IDL
        // gating is unaffected.
        propertySettings.scrollDrivenAnimationsEnabled = true;
        propertySettings.cssNamedTimelinePropertiesEnabled = true;
    }
#endif
}

void add(Hasher& hasher, const CSSParserContext& context)
{
    auto bits = WTF::packBools(
        context.isHTMLDocument,
        context.hasDocumentSecurityOrigin,
        static_cast<bool>(context.loadedFromOpaqueSource),
        context.useSystemAppearance,
        context.shouldIgnoreImportRules,
        context.counterStyleAtRuleImageSymbolsEnabled,
        context.springTimingFunctionEnabled,
#if HAVE(CORE_ANIMATION_SEPARATED_LAYERS)
        context.cssTransformStyleSeparatedEnabled,
#endif
        context.gridLanesEnabled,
        context.cssAppearanceBaseEnabled,
        context.cssPaintingAPIEnabled,
        context.cssWordBreakAutoPhraseEnabled,
        context.popoverAttributeEnabled,
        context.cssTextWrapPrettyEnabled,
#if ENABLE(SERVICE_CONTROLS)
        context.imageControlsEnabled,
#endif
        context.colorLayersEnabled,
        context.cssPickerPseudoElementEnabled,
        context.targetTextPseudoElementEnabled,
        context.htmlEnhancedSelectEnabled,
        context.cssRandomFunctionEnabled,
        context.cssRubyDisplayTypesEnabled,
        context.cssTreeCountingFunctionsEnabled,
        context.cssURLModifiersEnabled,
        context.cssURLIntegrityModifierEnabled,
        context.cssAxisRelativePositionKeywordsEnabled,
        context.cssDynamicRangeLimitMixEnabled,
        context.cssConstrainedDynamicRangeLimitEnabled,
        context.cssTextDecorationLineErrorValues,
        context.cssTextTransformMathAutoEnabled,
        context.cssFontSynthesisStyleObliqueOnlyEnabled,
        context.cssInternalAutoBaseParsingEnabled,
        context.webkitMediaTextTrackDisplayQuirkEnabled,
        context.cssMathDepthEnabled,
        context.openPseudoClassEnabled,
        context.cssAttrSubstitutionFunctionEnabled
    );
    add(hasher, context.baseURL, context.charset, context.propertySettings, context.mode, context.enclosingRuleType, bits);
}

void CSSParserContext::setUASheetMode()
{
    mode = UASheetMode;
    applyUASheetBehaviorsToContext(*this);
}

} // namespace WebCore
