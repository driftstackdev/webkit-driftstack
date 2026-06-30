/*
 * DriftstackCrWebBootstrap.h -- page-world __gCrWeb bootstrap for browser:chrome
 * (Chrome-on-iOS / CriOS) archetypes.
 *
 * Real Chrome-on-iOS injects a __gCrWeb object tree into the page's MAIN content
 * world at document-start (it is page-JS-visible, an enumerable own property of
 * window). A real Safari session exposes NO __gCrWeb. The fork's chrome
 * archetypes (iphone17_ios18_7_chrome148/149/150) were missing it, making them
 * detectable as not-real-Chrome (typeof window.__gCrWeb === 'undefined').
 *
 * This script reconstructs the real Chrome-iOS surface to the captured detection
 * depth (depth 2 -- top-level 8 keys + every nested own key + type). It is
 * evaluated in mainThreadNormalWorld() at UserScriptInjectionTime::DocumentStart
 * by LocalFrame::injectUserScripts, gated on driftstackArchetypeIsChromeBrowser().
 *
 * Ground truth (deep, BS chromium / real iPhone 17, 2026-06-30):
 *   reference/realdevice-bs/criosdelta-iPhone_17-1782822507714.json
 *   operations/closure-evidence/crios-chrome-ios.json
 *
 * Structure matched (window own keys, injection order -- descriptor order is a tell):
 *   _injected_wrap_gcrweb_functions = true   (boolean)
 *   gcrweb            = { gCrWebLegacy: <alias to __gCrWeb> }   (enumerable)
 *   _injected_gcrweb  = true   (boolean)
 *   __gCrWeb          = {                                       (enumerable)
 *     autofill_form_features: { 16 fns: is*/set* feature toggles },
 *     common:  { JSONSafeObject: fn, JSONStringify: fn },
 *     fill:    { ID_SYMBOL: symbol, value: fn, + 28 fns },
 *     form:    { 10 fns + wasEditedByUser: object },
 *     message: { getExistingFrames: fn, getFrameId: fn },
 *     setWebViewScrollViewIsDragging: fn (length 1),
 *     stringify: fn (length 1),
 *     webSelection: { getSelectedText: fn },
 *   }
 *
 * Per CLAUDE.md zero-JS-lies rule: this is NOT a fingerprint modification of a
 * built-in -- it is the faithful reproduction of a global that real Chrome-iOS
 * itself injects via the identical WKUserScript main-world mechanism. The
 * detection target IS that __gCrWeb is present and correctly shaped; a Chrome
 * archetype WITHOUT it is the lie. Safari archetypes inject nothing (gated).
 */

#pragma once

#if PLATFORM(DRIFTSTACK)

#include <wtf/text/ASCIILiteral.h>

namespace WebCore {

// The bootstrap source. IIFE; idempotent (no-op if __gCrWeb already present);
// builds the tree, then defines the four window own-properties in the GT order
// (_injected_wrap_gcrweb_functions, gcrweb, _injected_gcrweb, __gCrWeb), all
// enumerable, matching the real-device descriptor.enumerable=true.
constexpr ASCIILiteral driftstackCrWebBootstrapScript()
{
    return R"DSJS(
(function() {
  "use strict";
  try {
    if (typeof window.__gCrWeb !== "undefined") return; // idempotent

    // Minimal faithful function bodies. Real Chrome-iOS bodies are proprietary;
    // a fingerprinter reads SHAPE (typeof / own-keys / fn presence / length),
    // not source. Each is a real callable function so typeof === "function".
    var FN0 = function() {};
    var FN1 = function(a) {};
    var FNB = function() { return false; }; // boolean feature getters

    var gCrWeb = {};

    // --- autofill_form_features: 16 feature is*/set* toggles ---
    gCrWeb.autofill_form_features = {
      isAutofillAcrossIframesEnabled: FNB,
      isAutofillAcrossIframesThrottlingEnabled: FNB,
      isAutofillAllowDefaultPreventedSubmission: FNB,
      isAutofillCorrectUserEditedBitInParsedField: FNB,
      isAutofillDedupeFormSubmissionEnabled: FNB,
      isAutofillDisallowSlashDotLabelsEnabled: FNB,
      isAutofillFixPaymentSheetSpamEnabled: FNB,
      isAutofillIsolatedContentWorldEnabled: FNB,
      setAutofillAcrossIframes: FN1,
      setAutofillAcrossIframesThrottling: FN1,
      setAutofillAllowDefaultPreventedSubmission: FN1,
      setAutofillCorrectUserEditedBitInParsedField: FN1,
      setAutofillDedupeFormSubmission: FN1,
      setAutofillDisallowSlashDotLabels: FN1,
      setAutofillFixPaymentSheetSpam: FN1,
      setAutofillIsolatedContentWorld: FN1
    };

    // --- common: JSON helpers ---
    gCrWeb.common = {
      JSONSafeObject: FN1,
      JSONStringify: function(v) { try { return JSON.stringify(v); } catch (e) { return ""; } }
    };

    // --- fill: ID_SYMBOL (symbol) + value (fn) + 28 inference/util fns ---
    gCrWeb.fill = {
      ID_SYMBOL: Symbol("__gChrome_id"),
      autofillSubmissionData: FN1,
      combineAndCollapseWhitespace: FN1,
      getAriaDescription: FN1,
      getAriaLabel: FN1,
      getCanonicalActionForForm: FN1,
      getOptionStringsFromElement: FN1,
      getUniqueID: FN1,
      getUnownedAutofillableFormFieldElements: FN1,
      hasTagName: FN1,
      inferLabelForElement: FN1,
      inferLabelFromDefinitionList: FN1,
      inferLabelFromDivTable: FN1,
      inferLabelFromEnclosingLabel: FN1,
      inferLabelFromListItem: FN1,
      inferLabelFromPrevious: FN1,
      inferLabelFromTableColumn: FN1,
      inferLabelFromTableRow: FN1,
      isAutofillableElement: FN1,
      isAutofillableInputElement: FN1,
      isCheckableElement: FN1,
      isElementInsideFormOrFieldSet: FN1,
      isSelectElement: FN1,
      isVisibleNode: FN1,
      setInputElementValue: FN1,
      shouldAutocomplete: FN1,
      unownedFormElementsAndFieldSetsToFormData: FN1,
      value: FN1,
      webFormControlElementToFormField: FN1,
      webFormElementToFormData: FN1
    };

    // --- form: 10 fns + wasEditedByUser (object) ---
    gCrWeb.form = {
      fieldWasEditedByUser: FN1,
      formSubmitted: FN1,
      getFieldIdentifier: FN1,
      getFieldName: FN1,
      getFormControlElements: FN1,
      getFormElementFromIdentifier: FN1,
      getFormElementFromRendererId: FN1,
      getFormIdentifier: FN1,
      getIframeElements: FN1,
      isFormControlElement: FN1,
      wasEditedByUser: {}
    };

    // --- message: frame helpers ---
    gCrWeb.message = {
      getExistingFrames: FN0,
      getFrameId: FN0
    };

    // --- top-level fns (length 1, anonymous name "") ---
    gCrWeb.setWebViewScrollViewIsDragging = function(a) {};
    gCrWeb.stringify = function(a) {
      if (a === undefined) return "undefined";
      try { return gCrWeb.common.JSONStringify(a); } catch (e) { return ""; }
    };

    // --- webSelection ---
    gCrWeb.webSelection = { getSelectedText: FN0 };

    // Define window own-properties in the GT injection order. enumerable:true to
    // match real-device descriptor.enumerable (a non-enumerable __gCrWeb would be
    // a detectable mismatch). writable/configurable left default (true) -- real
    // Chrome leaves them configurable.
    var def = function(name, value) {
      Object.defineProperty(window, name, { value: value, writable: true, enumerable: true, configurable: true });
    };
    def("_injected_wrap_gcrweb_functions", true);
    def("gcrweb", { gCrWebLegacy: gCrWeb });
    def("_injected_gcrweb", true);
    def("__gCrWeb", gCrWeb);
  } catch (e) { /* never throw into the page */ }
})();
)DSJS"_s;
}

} // namespace WebCore

#endif // PLATFORM(DRIFTSTACK)
