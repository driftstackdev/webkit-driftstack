/*
 * Copyright (C) 2010-2025 Apple Inc. All rights reserved.
 * Copyright (C) 2012 Intel Corporation. All rights reserved.
 * Copyright (C) 2010 Nokia Corporation and/or its subsidiary(-ies)
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
#include "WebPage.h"

#include "APIArray.h"
#include "APIGeometry.h"
#include "APIInjectedBundleEditorClient.h"
#include "APIInjectedBundleFormClient.h"
#include "APIInjectedBundlePageContextMenuClient.h"
#include "APIInjectedBundlePageLoaderClient.h"
#include "APIInjectedBundlePageResourceLoadClient.h"
#include "APIInjectedBundlePageUIClient.h"
#include "Connection.h"
#include "ContentAsStringIncludesChildFrames.h"
#include "DragControllerAction.h"
#include "DragEventForwardingData.h"
#include "DrawingArea.h"
#include "DrawingAreaMessages.h"
#include "Shared/DriftstackScrollCoastMath.h"
#include "Shared/DriftstackRubberBandMath.h"
#include "EditorState.h"
#include "EventDispatcher.h"
#include "FindController.h"
#include "FocusedElementInformation.h"
#include "FormDataReference.h"
#include "FrameTreeNodeData.h"
#include "GeolocationPermissionRequestManager.h"
#include "GoToBackForwardItemParameters.h"
#include "ImageOptions.h"
#include "InjectUserScriptImmediately.h"
#include "InjectedBundle.h"
#include "InjectedBundleHitTestResult.h"
#include "InjectedBundleScriptWorld.h"
#include "JavaScriptEvaluationResult.h"
#include "LibWebRTCCodecs.h"
#include "LibWebRTCProvider.h"
#include "LoadParameters.h"
#include "Logging.h"
#include "MediaKeySystemPermissionRequestManager.h"
#include "MediaPlaybackState.h"
#include "MessageSenderInlines.h"
#include "NetworkConnectionToWebProcessMessages.h"
#include "NetworkProcessConnection.h"
#include "NodeHitTestResult.h"
#include "NotificationPermissionRequestManager.h"
#include "PageBanner.h"
#include "PageInspectorTarget.h"
#include "PlaybackSessionContextIdentifier.h"
#include "PluginView.h"
#include "PolicyDecision.h"
#include "PrintInfo.h"
#include "ProvisionalFrameCreationParameters.h"
#include "RemoteRenderingBackendProxy.h"
#include "RemoteScrollingCoordinator.h"
#include "RemoteSnapshotRecorderProxy.h"
#include "RemoteWebInspectorUI.h"
#include "RemoteWebInspectorUIMessages.h"
#include "RunJavaScriptParameters.h"
#include "SessionState.h"
#include "SessionStateConversion.h"
#include "ShareableBitmapUtilities.h"
#include "SharedBufferReference.h"
#include "TextRecognitionUpdateResult.h"
#include "UserMediaPermissionRequestManager.h"
#include "ViewGestureGeometryCollector.h"
#include "VisitedLinkTableController.h"
#include "WKBundleAPICast.h"
#include "WKRetainPtr.h"
#include "WKSharedAPICast.h"
#include "WebAlternativeTextClient.h"
#include "WebAttachmentElementClient.h"
#include "WebBackForwardListItem.h"
#include "WebBackForwardListProxy.h"
#include "WebBadgeClient.h"
#include "WebBroadcastChannelRegistry.h"
#include "WebCacheStorageProvider.h"
#include "WebChromeClient.h"
#include "WebColorChooser.h"
#include "WebContextMenu.h"
#include "WebContextMenuClient.h"
#include "WebCookieJar.h"
#include "WebCryptoClient.h"
#include "WebDataListSuggestionPicker.h"
#include "WebDatabaseProvider.h"
#include "WebDateTimeChooser.h"
#include "WebDiagnosticLoggingClient.h"
#include "WebDocumentSyncClient.h"
#include "WebDragClient.h"
#include "WebEditorClient.h"
#include "WebErrors.h"
#include "WebEventConversion.h"
#include "WebEventFactory.h"
#include "WebFoundTextRange.h"
#include "WebFoundTextRangeController.h"
#include "WebFrame.h"
#include "WebFrameMetrics.h"
#include "WebFullScreenManager.h"
#include "WebFullScreenManagerMessages.h"
#include "WebFullScreenManagerProxyMessages.h"
#include "WebGamepadProvider.h"
#include "WebGeolocationClient.h"
#include "WebHistoryItemClient.h"
#include "WebHitTestResultData.h"
#include "WebImage.h"
#include "WebInspectorBackend.h"
#include "WebInspectorBackendClient.h"
#include "WebInspectorBackendMessages.h"
#include "WebInspectorUI.h"
#include "WebInspectorUIMessages.h"
#include "WebKeyboardEvent.h"
#include "WebLoaderStrategy.h"
#include "WebLocalFrameLoaderClient.h"
#include "WebMediaKeyStorageManager.h"
#include "WebMediaKeySystemClient.h"
#include "WebMediaStrategy.h"
#include "WebModelPlayerProvider.h"
#include "WebMouseEvent.h"
#include "WebNotificationClient.h"
#include "WebOpenPanelResultListener.h"
#include "WebPageCreationParameters.h"
#include "WebPageGroupProxy.h"
#include "WebPageInlines.h"
#include "WebPageInternals.h"
#include "WebPageMessages.h"
#include "WebPageOverlay.h"
#include "WebPageProxyMessages.h"
#include "WebPageTesting.h"
#include "WebPaymentCoordinator.h"
#include "WebPerformanceLoggingClient.h"
#include "WebPluginInfoProvider.h"
#include "WebPopupMenu.h"
#include "WebPreferencesDefinitions.h"
#include "WebPreferencesKeys.h"
#include "WebPreferencesStore.h"
#include "WebProcess.h"
#include "WebProcessPoolMessages.h"
#include "WebProcessProxyMessages.h"
#include "WebProgressTrackerClient.h"
#include "WebRemoteFrameClient.h"
#include "WebScreenOrientationManager.h"
#include "WebServiceWorkerProvider.h"
#include "WebSocketProvider.h"
#include "WebSpeechRecognitionProvider.h"
#include "WebSpeechSynthesisClient.h"
#include "WebStorageNamespaceProvider.h"
#include "WebStorageProvider.h"
#include "WebTouchEvent.h"
#include "WebURLSchemeHandlerProxy.h"
#include "WebUndoStep.h"
#include "WebUserContentController.h"
#include "WebUserMediaClient.h"
#include "WebValidationMessageClient.h"
#include "WebWheelEvent.h"
#include "WebsiteDataStoreParameters.h"
#include "WebsitePoliciesData.h"
#include <JavaScriptCore/APICast.h>
#include <JavaScriptCore/JSCInlines.h>
#include <JavaScriptCore/JSCJSValue.h>
#include <JavaScriptCore/JSLock.h>
#include <JavaScriptCore/ProfilerDatabase.h>
#include <JavaScriptCore/SamplingProfiler.h>
#include <WebCore/AXObjectCache.h>
#include <WebCore/AnimationTimelinesController.h>
#include <WebCore/AppHighlight.h>
#include <WebCore/ArchiveResource.h>
#include <WebCore/BackForwardCache.h>
#include <WebCore/BackForwardController.h>
#include <WebCore/BitmapImage.h>
#include <WebCore/CachedPage.h>
#include <WebCore/CaptionUserPreferences.h>
#include <WebCore/Chrome.h>
#include <WebCore/CommonVM.h>
#include <WebCore/ContactsRequestData.h>
#include <WebCore/ContainerNodeInlines.h>
#include <WebCore/ContextMenuController.h>
#include <WebCore/CrossOriginEmbedderPolicy.h>
#include <WebCore/CrossOriginOpenerPolicy.h>
#include <WebCore/DOMPasteAccess.h>
#include <WebCore/DOMWrapperWorld.h>
#include <WebCore/DataTransfer.h>
#include <WebCore/DatabaseManager.h>
#include <WebCore/DeprecatedGlobalSettings.h>
#include <WebCore/DisplayListRecorderImpl.h>
#include <WebCore/Document.h>
#include <WebCore/DocumentFragment.h>
#include <WebCore/DocumentFullscreen.h>
#include <WebCore/DocumentImmersive.h>
#include <WebCore/DocumentInlines.h>
#include <WebCore/DocumentLoader.h>
#include <WebCore/DocumentMarkerController.h>
#include <WebCore/DocumentMarkers.h>
#include <WebCore/DocumentPage.h>
#include <WebCore/DocumentQuirks.h>
#include <WebCore/DocumentStorageAccess.h>
#include <WebCore/DocumentSyncData.h>
#include <WebCore/DocumentView.h>
#include <WebCore/DragController.h>
#include <WebCore/DragData.h>
#include <WebCore/DragEventTargetData.h>
#include <WebCore/Editing.h>
#include <WebCore/Editor.h>
#include <WebCore/ElementAncestorIteratorInlines.h>
#include <WebCore/ElementTargetingController.h>
#include <WebCore/EventHandler.h>
#include <WebCore/EventNames.h>
#include <WebCore/ExceptionCode.h>
#include <WebCore/File.h>
#include <WebCore/FocusController.h>
#include <WebCore/FocusControllerTypes.h>
#include <WebCore/FocusOptions.h>
#include <WebCore/FontAttributeChanges.h>
#include <WebCore/FontAttributes.h>
#include <WebCore/FormState.h>
#include <WebCore/FragmentDirectiveParser.h>
#include <WebCore/FragmentDirectiveRangeFinder.h>
#include <WebCore/FragmentDirectiveUtilities.h>
#include <WebCore/FrameDestructionObserverInlines.h>
#include <WebCore/FrameInlines.h>
#include <WebCore/FrameInspectorController.h>
#include <WebCore/FrameLoadRequest.h>
#include <WebCore/FrameLoaderTypes.h>
#include <WebCore/GeometryUtilities.h>
#include <WebCore/HTMLAttachmentElement.h>
#include <WebCore/HTMLBodyElement.h>
#include <WebCore/HTMLFormElement.h>
#include <WebCore/HTMLImageElement.h>
#include <WebCore/HTMLInputElement.h>
#include <WebCore/HTMLModelElement.h>
#include <WebCore/HTMLPlugInElement.h>
#include <WebCore/HTMLSelectElement.h>
#include <WebCore/HTMLTextAreaElement.h>
#include <WebCore/HTMLTextFormControlElement.h>
#include <WebCore/HTTPParsers.h>
#include <WebCore/HTTPStatusCodes.h>
#include <WebCore/HandleUserInputEventResult.h>
#include <WebCore/Highlight.h>
#include <WebCore/HighlightRegistry.h>
#include <WebCore/HistoryController.h>
#include <WebCore/HistoryItem.h>
#include <WebCore/HitTestRequest.h>
#include <WebCore/HitTestResult.h>
#include <WebCore/ImageAnalysisQueue.h>
#include <WebCore/ImageOverlay.h>
#include <WebCore/ImageUtilities.h>
#include <WebCore/JSDOMExceptionHandling.h>
#include <WebCore/JSNode.h>
#include <WebCore/KeyboardEvent.h>
#include <WebCore/LegacySchemeRegistry.h>
#include <WebCore/LocalFrameInlines.h>
#include <WebCore/LocalFrameView.h>
#include <WebCore/LocalizedStrings.h>
#include <WebCore/LoginStatus.h>
#include <WebCore/MIMETypeRegistry.h>
#include <WebCore/MediaDocument.h>
#include <WebCore/MediaPlayer.h>
#include <WebCore/MouseEvent.h>
#include <WebCore/NavigationScheduler.h>
#include <WebCore/NotImplemented.h>
#include <WebCore/NotificationController.h>
#include <WebCore/OriginAccessPatterns.h>
#include <WebCore/Page.h>
#include <WebCore/PageConfiguration.h>
#include <WebCore/PageGroup.h>
#include <WebCore/PageInspectorController.h>
#include <WebCore/PingLoader.h>
#include <WebCore/PlatformKeyboardEvent.h>
#include <WebCore/PlatformMediaSessionManager.h>
#include <WebCore/PlatformMouseEvent.h>
#include <WebCore/PlatformStrategies.h>
#include <WebCore/PluginDocument.h>
#include <WebCore/PointerCaptureController.h>
#include <WebCore/PopupMenuClient.h>
#include <WebCore/PrintContext.h>
#include <WebCore/ProcessCapabilities.h>
#include <WebCore/PromisedAttachmentInfo.h>
#include <WebCore/Quirks.h>
#include <WebCore/Range.h>
#include <WebCore/RegistrableDomain.h>
#include <WebCore/RemoteDOMWindow.h>
#include <WebCore/RemoteFrame.h>
#include <WebCore/RemoteFrameClient.h>
#include <WebCore/RemoteFrameGeometryTransformer.h>
#include <WebCore/RemoteFrameView.h>
#include <WebCore/RemoteUserInputEventData.h>
#include <WebCore/RenderImage.h>
#include <WebCore/RenderLayer.h>
#include <WebCore/RenderLayerCompositor.h>
#include <WebCore/RenderTheme.h>
#include <WebCore/RenderTreeAsText.h>
#include <WebCore/RenderVideoInlines.h>
#include <WebCore/RenderView.h>
#include <WebCore/Report.h>
#include <WebCore/ReportingScope.h>
#include <WebCore/ResourceLoadStatistics.h>
#include <WebCore/ResourceRequest.h>
#include <WebCore/ResourceResponse.h>
#include <WebCore/ResourceTiming.h>
#include <WebCore/ResourceTimingInformation.h>
#include <WebCore/RunJavaScriptParameters.h>
#include <WebCore/SWClientConnection.h>
#include <WebCore/ScriptController.h>
#include <WebCore/ScriptDisallowedScope.h>
#include <WebCore/ScrollableArea.h>
#include <WebCore/SecurityPolicy.h>
#include <WebCore/SelectionRestorationMode.h>
#include <WebCore/SerializedScriptValue.h>
#include <WebCore/Settings.h>
#include <WebCore/ShadowRoot.h>
#include <WebCore/ShareableBitmap.h>
#include <WebCore/SharedBuffer.h>
#include <WebCore/StaticRange.h>
#include <WebCore/StyleProperties.h>
#include <WebCore/SubframeLoader.h>
#include <WebCore/SubresourceLoader.h>
#include <WebCore/SubstituteData.h>
#include <WebCore/SystemPreviewInfo.h>
#include <WebCore/TextExtraction.h>
#include <WebCore/TextIterator.h>
#include <WebCore/TextManipulationController.h>
#include <WebCore/TextRecognitionOptions.h>
#include <WebCore/TranslationContextMenuInfo.h>
#include <WebCore/UserContentURLPattern.h>
#include <WebCore/UserGestureIndicator.h>
#include <WebCore/UserScript.h>
#include <WebCore/UserStyleSheet.h>
#include <WebCore/UserTypingGestureIndicator.h>
#include <WebCore/ViolationReportType.h>
#include <WebCore/VisiblePosition.h>
#include <WebCore/VisibleUnits.h>
#include <WebCore/WebKitJSHandle.h>
#include <WebCore/WritingDirection.h>
#include <WebCore/markup.h>
#include <algorithm>
#include <pal/SessionID.h>
#include <ranges>
#include <wtf/Borrow.h>
#include <wtf/CoroutineUtilities.h>
#include <wtf/ProcessID.h>
#include <wtf/RunLoop.h>
#include <wtf/Scope.h>
#include <wtf/SetForScope.h>
#include <wtf/SystemTracing.h>
#include <wtf/text/MakeString.h>
#include <wtf/text/TextStream.h>

#if ENABLE(APP_HIGHLIGHTS)
#include <WebCore/AppHighlightStorage.h>
#endif

#if ENABLE(DATA_DETECTION)
#include "DataDetectionResult.h"
#endif

#if ENABLE(MHTML)
#include <WebCore/MHTMLArchive.h>
#endif

#if ENABLE(POINTER_LOCK)
#include <WebCore/PointerLockController.h>
#endif

#if PLATFORM(COCOA)
#include "DefaultWebBrowserChecks.h"
#include "InsertTextOptions.h"
#include "PlaybackSessionManager.h"
#include "RemoteLayerTreeDrawingArea.h"
#include "RemoteObjectRegistryMessages.h"
#include "TextAnimationController.h"
#include "TextCheckingControllerProxy.h"
#include "VideoPresentationManager.h"
#include "WKStringCF.h"
#include "WebRemoteObjectRegistry.h"
#include <WebCore/LegacyWebArchive.h>
#include <WebCore/VP9UtilitiesCocoa.h>
#include <pal/spi/cg/ImageIOSPI.h>
#include <wtf/MachSendRight.h>
#include <wtf/cocoa/RuntimeApplicationChecksCocoa.h>
#include <wtf/spi/darwin/SandboxSPI.h>
#endif

#if PLATFORM(GTK)
#include "WebPrintOperationGtk.h"
#include <WebCore/SelectionData.h>
#include <gtk/gtk.h>
#endif

#if PLATFORM(IOS_FAMILY)
#include "InteractionInformationAtPosition.h"
#include "InteractionInformationRequest.h"
#include "WebAutocorrectionContext.h"
#include <CoreGraphics/CoreGraphics.h>
#include <WebCore/Icon.h>
#include <pal/spi/cf/CoreTextSPI.h>
#endif

#if PLATFORM(MAC)
#include <WebCore/LocalDefaultSystemAppearance.h>
#include <pal/spi/cf/CFUtilitiesSPI.h>
#endif

#if ENABLE(DATA_DETECTION)
#include <WebCore/DataDetection.h>
#include <WebCore/DataDetectionResultsStorage.h>
#endif

#if ENABLE(MEDIA_STREAM) && USE(GSTREAMER)
#include <WebCore/MockRealtimeMediaSourceCenter.h>
#endif

#if ENABLE(WEB_AUTHN)
#include "DigitalCredentialsCoordinator.h"
#include "WebAuthenticatorCoordinator.h"
#include <WebCore/AuthenticatorCoordinator.h>
#include <WebCore/DigitalCredentialsRequestData.h>
#include <WebCore/DigitalCredentialsResponseData.h>
#include <WebCore/ExceptionData.h>
#endif // ENABLE(WEB_AUTHN)

#if PLATFORM(IOS_FAMILY) && ENABLE(DEVICE_ORIENTATION)
#include "WebDeviceOrientationUpdateProvider.h"
#endif

#if ENABLE(GPU_PROCESS)
#include "RemoteMediaPlayerManager.h"
#if ENABLE(ENCRYPTED_MEDIA)
#include "RemoteCDMFactory.h"
#endif
#if ENABLE(LEGACY_ENCRYPTED_MEDIA)
#include "RemoteLegacyCDMFactory.h"
#endif
#if HAVE(AVASSETREADER)
#include "RemoteImageDecoderAVFManager.h"
#endif
#endif

#if ENABLE(IMAGE_ANALYSIS)
#include <WebCore/TextRecognitionResult.h>
#endif

#if ENABLE(MEDIA_SESSION_COORDINATOR)
#include "RemoteMediaSessionCoordinator.h"
#include <WebCore/MediaSessionCoordinator.h>
#include <WebCore/NavigatorMediaSession.h>
#endif


#if PLATFORM(IOS) || PLATFORM(VISION)
#include "WebPreferencesDefaultValuesIOS.h"
#endif

#if ENABLE(MODEL_PROCESS)
#include "ModelProcessConnection.h"
#endif

#if USE(SKIA)
#include <WebCore/FontRenderOptions.h>
#endif

#if USE(CG)
// FIXME: Move the CG-specific PDF painting code out of WebPage.cpp.
#include <WebCore/GraphicsContextCG.h>
#endif

#if ENABLE(LOCKDOWN_MODE_API)
#import <pal/spi/cg/CoreGraphicsSPI.h>
#endif

#if ENABLE(WK_WEB_EXTENSIONS) && PLATFORM(COCOA)
#include "WebExtensionControllerProxy.h"
#endif

#if ENABLE(WEBXR)
#include "PlatformXRSystemProxy.h"
#endif

#if ENABLE(PDF_HUD)
#include "PDFPluginBase.h"
#endif

#if HAVE(AUDIT_TOKEN)
#include "CoreIPCAuditToken.h"
#endif

#if ENABLE(VIDEO) || ENABLE(WEB_AUDIO)
#include "RemoteMediaSessionManager.h"
#endif

#if __has_include(<WebKitAdditions/WebPreferencesDefaultValuesAdditions.h>)
#include <WebKitAdditions/WebPreferencesDefaultValuesAdditions.h>
#endif

namespace WebKit {
using namespace JSC;
using namespace WebCore;

#if PLATFORM(DRIFTSTACK)
// V-FOREGROUND-CHOKEPOINT (W1331 visibility + W1332 focus; founder "the driver must be 100%
// undetectable"): every Driftstack session is a WebDriver-driven MiniBrowser on a multi-session/
// headless fleet Mac, so its window is typically NOT the foreground key window → WebContent would
// observe the page as hidden/occluded/unfocused and report document.visibilityState='hidden' +
// document.hidden=true + requestAnimationFrame paused + document.hasFocus()=false (and, at
// construction, prerender). A real iPhone Safari foreground tab is ALWAYS visible + focused:
// visibilityState='visible' / hidden=false / rAF@60fps / hasFocus()=true. Force the full
// foreground-FOCUSED activity bits on every WebContent activity-state application regardless of
// the real window state, so the surface stays coherent — visible+focused together (visible alone
// is iPhone-incoherent: a visible foreground tab is also focused; and fixing only a getter would
// leave rAF paused = its own tell). Forcing the bits CONSISTENTLY means they never change, so no
// spurious focus/blur/visibilitychange events fire after construction. (W1332 adds IsFocused/
// WindowIsActive: hasFocus() IS a probed surface [media-events-animation] — the W1331 "not probed"
// note was wrong — and FocusController.isActive/isFocused read exactly these bits + setFocused
// points the focused frame at the main frame, so this yields hasFocus()=true. Foreground-focus is
// the correct impersonation state for autoplay/selection-color/IME too.)
static OptionSet<ActivityState> driftstackForceForeground(OptionSet<ActivityState> state)
{
    state.add({ ActivityState::IsVisible, ActivityState::IsVisibleOrOccluded, ActivityState::IsInWindow,
                ActivityState::WindowIsActive, ActivityState::IsFocused });
    // Driftstack rAF-LEAK-1 / #16: the host WindowServer marks an unattended desktop page visually-idle,
    // which throttles rAF to 30fps and aligns foreground DOM-timers to 1s. Real iOS holds the settled
    // foreground page at 60fps with no idle throttle. Clear IsVisuallyIdle so the impersonated page is
    // never treated as host-idle.
    state.remove(ActivityState::IsVisuallyIdle);
    return state;
}
#endif

static const Seconds pageScrollHysteresisDuration { 300_ms };
static const Seconds initialLayerVolatilityTimerInterval { 20_ms };
static const Seconds maximumLayerVolatilityTimerInterval { 2_s };

#if PLATFORM(IOS_FAMILY)
static constexpr Seconds updateFocusedElementInformationDebounceInterval { 100_ms };
static constexpr Seconds updateLayoutViewportHeightExpansionTimerInterval { 200_ms };
#endif

#define WEBPAGE_RELEASE_LOG(channel, fmt, ...) RELEASE_LOG(channel, "%p - [webPageID=%" PRIu64 "] WebPage::" fmt, this, m_identifier.toUInt64(), ##__VA_ARGS__)
#define WEBPAGE_RELEASE_LOG_FORWARDABLE(channel, fmt, ...) RELEASE_LOG_FORWARDABLE(channel, fmt, m_identifier.toUInt64(), ##__VA_ARGS__)
#define WEBPAGE_RELEASE_LOG_ERROR(channel, fmt, ...) RELEASE_LOG_ERROR(channel, "%p - [webPageID=%" PRIu64 "] WebPage::" fmt, this, m_identifier.toUInt64(), ##__VA_ARGS__)

class SendStopResponsivenessTimer {
public:
    ~SendStopResponsivenessTimer()
    {
        protect(WebProcess::singleton().parentProcessConnection())->send(Messages::WebProcessProxy::StopResponsivenessTimer(), 0);
    }
};

Ref<WebPage> WebPage::create(PageIdentifier pageID, WebPageCreationParameters&& parameters)
{
    auto mainFrameOpenerIdentifier = parameters.mainFrameOpenerIdentifier;
    String openedMainFrameName = parameters.openedMainFrameName;
    auto page = adoptRef(*new WebPage(pageID, WTF::move(parameters)));

    if (RefPtr injectedBundle = WebProcess::singleton().injectedBundle())
        injectedBundle->didCreatePage(page);

    Ref mainFrame = page->corePage()->mainFrame();
    if (mainFrame->tree().specifiedName().isNull())
        mainFrame->tree().setSpecifiedName(AtomString(openedMainFrameName));

    if (mainFrameOpenerIdentifier && !mainFrame->opener())
        page->m_unresolvedMainFrameOpenerIdentifier = mainFrameOpenerIdentifier;

    for (Ref otherCorePage : protect(page->corePage())->group().pages()) {
        if (otherCorePage.ptr() == page->corePage())
            continue;
        RefPtr otherWebPage = WebPage::fromCorePage(otherCorePage);
        if (!otherWebPage || !otherWebPage->m_unresolvedMainFrameOpenerIdentifier)
            continue;
        if (*otherWebPage->m_unresolvedMainFrameOpenerIdentifier != mainFrame->frameID())
            continue;
        protect(otherCorePage->mainFrame())->updateOpener(mainFrame.get(), Frame::NotifyUIProcess::No);
        otherWebPage->m_unresolvedMainFrameOpenerIdentifier = std::nullopt;
    }

#if HAVE(SANDBOX_STATE_FLAGS)
    setHasLaunchedWebContentProcess();
#endif

    return page;
}

void WebPage::ref() const
{
    API::ObjectImpl<API::Object::Type::BundlePage>::ref();
}

void WebPage::deref() const
{
    API::ObjectImpl<API::Object::Type::BundlePage>::deref();
}

static Vector<UserContentURLPattern> parseAndAllowAccessToCORSDisablingPatterns(const Vector<String>& input)
{
    return WTF::compactMap(input, [](auto& pattern) -> std::optional<UserContentURLPattern> {
        UserContentURLPattern parsedPattern(pattern);
        if (!parsedPattern.isValid())
            return std::nullopt;
        WebCore::OriginAccessPatternsForWebProcess::singleton().allowAccessTo(parsedPattern);
        return parsedPattern;
    });
}

static PageConfiguration::MainFrameCreationParameters mainFrameCreationParameters(Ref<WebFrame>&& mainFrame, auto frameType, auto initialSandboxFlags, auto initialReferrerPolicy)
{
    auto invalidator = mainFrame->makeInvalidator();
    switch (frameType) {
    case Frame::FrameType::Local:
        return PageConfiguration::LocalMainFrameCreationParameters {
            { [mainFrame = WTF::move(mainFrame), invalidator = WTF::move(invalidator)] (auto& localFrame, auto& frameLoader) mutable {
                return makeUniqueRefWithoutRefCountedCheck<WebLocalFrameLoaderClient>(localFrame, frameLoader, WTF::move(mainFrame), WTF::move(invalidator));
            } },
            initialSandboxFlags,
            initialReferrerPolicy
        };
    case Frame::FrameType::Remote:
        return CompletionHandler<UniqueRef<RemoteFrameClient>(RemoteFrame&)> { [mainFrame = WTF::move(mainFrame), invalidator = WTF::move(invalidator)] (auto&) mutable {
            return makeUniqueRef<WebRemoteFrameClient>(WTF::move(mainFrame), WTF::move(invalidator));
        } };
    }
    RELEASE_ASSERT_NOT_REACHED();
}

static RefPtr<Frame> frameFromIdentifier(std::optional<FrameIdentifier> identifier)
{
    if (!identifier)
        return nullptr;
    RefPtr webFrame = WebProcess::singleton().webFrame(*identifier);
    if (!webFrame)
        return nullptr;
    return webFrame->coreFrame();
}

WebPage::WebPage(PageIdentifier pageID, WebPageCreationParameters&& parameters)
    : m_internals(makeUniqueRef<Internals>())
    , m_identifier(pageID)
    , m_viewSize(parameters.viewSize)
    , m_drawingArea(DrawingArea::create(*this, parameters))
    , m_webPageTesting(WebPageTesting::create(*this))
    , m_mainFrame(WebFrame::create(*this, parameters.mainFrameIdentifier))
    , m_pageGroup(WebProcess::singleton().webPageGroup(WTF::move(parameters.pageGroupData)))
#if ENABLE(TILED_CA_DRAWING_AREA)
    , m_drawingAreaType(parameters.drawingAreaType)
#endif
    , m_alwaysShowsHorizontalScroller { parameters.alwaysShowsHorizontalScroller }
    , m_alwaysShowsVerticalScroller { parameters.alwaysShowsVerticalScroller }
    , m_shouldRenderCanvasInGPUProcess { parameters.shouldRenderCanvasInGPUProcess }
    , m_shouldRenderDOMInGPUProcess { parameters.shouldRenderDOMInGPUProcess }
    , m_shouldPlayMediaInGPUProcess { parameters.shouldPlayMediaInGPUProcess }
#if ENABLE(WEBGL)
    , m_shouldRenderWebGLInGPUProcess { parameters.shouldRenderWebGLInGPUProcess }
#endif
    , m_shouldSendConsoleLogsToUIProcessForTesting(parameters.shouldSendConsoleLogsToUIProcessForTesting)
#if HAVE(NSVIEW_CORNER_CONFIGURATION)
    , m_scrollbarAvoidanceCornerRadii(parameters.scrollbarAvoidanceCornerRadii)
#endif
#if ENABLE(PLATFORM_DRIVEN_TEXT_CHECKING)
    , m_textCheckingControllerProxy(makeUniqueRefWithoutRefCountedCheck<TextCheckingControllerProxy>(*this))
#endif
#if PLATFORM(COCOA) || PLATFORM(GTK)
    , m_viewGestureGeometryCollector(ViewGestureGeometryCollector::create(*this))
#elif PLATFORM(GTK)
    , m_accessibilityObject(nullptr)
#endif
#if USE(GRAPHICS_LAYER_TEXTURE_MAPPER) || USE(GRAPHICS_LAYER_WC)
    , m_nativeWindowHandle(parameters.nativeWindowHandle)
#endif
    , m_setCanStartMediaTimer(RunLoop::mainSingleton(), "WebPage::SetCanStartMediaTimer"_s, this, &WebPage::setCanStartMediaTimerFired)
#if ENABLE(CONTEXT_MENUS)
    , m_contextMenuClient(makeUnique<API::InjectedBundle::PageContextMenuClient>())
#endif
    , m_editorClient { makeUnique<API::InjectedBundle::EditorClient>() }
    , m_formClient(makeUnique<API::InjectedBundle::FormClient>())
    , m_loaderClient(makeUnique<API::InjectedBundle::PageLoaderClient>())
    , m_resourceLoadClient(makeUnique<API::InjectedBundle::ResourceLoadClient>())
    , m_uiClient(makeUnique<API::InjectedBundle::PageUIClient>())
    , m_findController(makeUniqueRef<FindController>(this))
    , m_foundTextRangeController(makeUniqueRef<WebFoundTextRangeController>(*this))
    , m_userContentController(WebUserContentController::getOrCreate(WTF::move(parameters.userContentControllerParameters)))
    , m_screenOrientationManager(makeUniqueRefWithoutRefCountedCheck<WebScreenOrientationManager>(*this))
#if ENABLE(GEOLOCATION)
    , m_geolocationPermissionRequestManager(makeUniqueRefWithoutRefCountedCheck<GeolocationPermissionRequestManager>(*this))
#endif
#if ENABLE(MEDIA_STREAM)
    , m_userMediaPermissionRequestManager { makeUniqueRefWithoutRefCountedCheck<UserMediaPermissionRequestManager>(*this) }
#endif
#if ENABLE(ENCRYPTED_MEDIA)
    , m_mediaKeySystemPermissionRequestManager { makeUniqueRefWithoutRefCountedCheck<MediaKeySystemPermissionRequestManager>(*this) }
#endif
    , m_pageScrolledHysteresis([this](PAL::HysteresisState state) { if (state == PAL::HysteresisState::Stopped) pageStoppedScrolling(); }, pageScrollHysteresisDuration)
    , m_canRunBeforeUnloadConfirmPanel(parameters.canRunBeforeUnloadConfirmPanel)
    , m_canRunModal(parameters.canRunModal)
#if HAVE(TOUCH_BAR)
    , m_requiresUserActionForEditingControlsManager(parameters.requiresUserActionForEditingControlsManager)
#endif
#if HAVE(UIKIT_RESIZABLE_WINDOWS)
    , m_isWindowResizingEnabled(parameters.hasResizableWindows)
#endif
#if PLATFORM(MAC)
    , m_overflowHeightForTopScrollEdgeEffect(parameters.overflowHeightForTopScrollEdgeEffect)
#endif
#if ENABLE(META_VIEWPORT)
    , m_forceAlwaysUserScalable(parameters.ignoresViewportScaleLimits)
#endif
#if PLATFORM(IOS_FAMILY)
    , m_screenIsBeingCaptured(parameters.isCapturingScreen)
    , m_screenSize(parameters.screenSize)
    , m_availableScreenSize(parameters.availableScreenSize)
    , m_overrideScreenSize(parameters.overrideScreenSize)
    , m_overrideAvailableScreenSize(parameters.overrideAvailableScreenSize)
    , m_deviceOrientation(parameters.deviceOrientation)
    , m_keyboardIsAttached(parameters.hardwareKeyboardState.isAttached)
    , m_updateFocusedElementInformationTimer(*this, &WebPage::updateFocusedElementInformation, updateFocusedElementInformationDebounceInterval)
#endif
    , m_layerVolatilityTimer(*this, &WebPage::layerVolatilityTimerFired)
    , m_activityState(parameters.activityState)
    , m_userInterfaceLayoutDirection(parameters.userInterfaceLayoutDirection)
    , m_overrideContentSecurityPolicy { WTF::move(parameters.overrideContentSecurityPolicy) }
    , m_cpuLimit(parameters.cpuLimit)
#if USE(WPE_RENDERER)
    , m_hostFileDescriptor(WTF::move(parameters.hostFileDescriptor))
#endif
    , m_webPageProxyIdentifier(parameters.webPageProxyIdentifier)
#if ENABLE(TEXT_AUTOSIZING)
    , m_textAutoSizingAdjustmentTimer(*this, &WebPage::textAutoSizingAdjustmentTimerFired)
#endif
    , m_overriddenMediaType { WTF::move(parameters.overriddenMediaType) }
    , m_processDisplayName { WTF::move(parameters.processDisplayName) }
#if PLATFORM(GTK) || PLATFORM(WPE)
#if USE(GBM) || OS(ANDROID)
    , m_preferredBufferFormats(WTF::move(parameters.preferredBufferFormats))
#endif
#endif
#if ENABLE(APP_BOUND_DOMAINS)
    , m_limitsNavigationsToAppBoundDomains(parameters.limitsNavigationsToAppBoundDomains)
#endif
    , m_lastNavigationWasAppInitiated(parameters.lastNavigationWasAppInitiated)
#if PLATFORM(IOS_FAMILY)
    , m_updateLayoutViewportHeightExpansionTimer(*this, &WebPage::updateLayoutViewportHeightExpansionTimerFired, updateLayoutViewportHeightExpansionTimerInterval)
#endif
#if ENABLE(IPC_TESTING_API)
    , m_visitedLinkTableID(parameters.visitedLinkTableID)
#endif
#if ENABLE(APP_HIGHLIGHTS)
    , m_appHighlightsVisible(parameters.appHighlightsVisible)
#endif
    , m_historyItemClient(WebHistoryItemClient::create(*this))
#if ENABLE(WRITING_TOOLS)
    , m_textAnimationController(makeUniqueRef<TextAnimationController>(*this))
#endif
    , m_backgroundTextExtractionEnabled(parameters.backgroundTextExtractionEnabled)
    , m_isPopup(parameters.isPopup)
#if ENABLE(MODEL_ELEMENT_IMMERSIVE)
    , m_allowsImmersiveEnvironments(parameters.allowsImmersiveEnvironments)
#endif
{
    WEBPAGE_RELEASE_LOG(Loading, "constructor:");

#if PLATFORM(COCOA)
#if HAVE(SANDBOX_STATE_FLAGS)
    auto auditToken = WebProcess::singleton().auditTokenForSelf();
    auto unifiedPDFEnabled = parameters.store.getBoolValueForKey(WebPreferencesKey::unifiedPDFEnabledKey());
    if (unifiedPDFEnabled)
        sandbox_enable_state_flag("UnifiedPDFEnabled", *auditToken);
#if PLATFORM(MAC)
    auto shouldAllowInstalledFonts = parameters.store.getBoolValueForKey(WebPreferencesKey::shouldAllowUserInstalledFontsKey());
    if (!shouldAllowInstalledFonts || !WTF::MacApplication::isAppleMail())
        sandbox_enable_state_flag("BlockUserInstalledFonts", *auditToken);
#endif // PLATFORM(MAC)
#endif // HAVE(SANDBOX_STATE_FLAGS)
    auto shouldBlockIOKit = parameters.store.getBoolValueForKey(WebPreferencesKey::blockIOKitInWebContentSandboxKey())
#if ENABLE(WEBGL)
        && m_shouldRenderWebGLInGPUProcess
#if ENABLE(TILED_CA_DRAWING_AREA)
        && m_drawingAreaType == DrawingAreaType::RemoteLayerTree
#endif
#endif
        && m_shouldRenderCanvasInGPUProcess
        && m_shouldRenderDOMInGPUProcess
        && m_shouldPlayMediaInGPUProcess;

    if (shouldBlockIOKit) {
#if HAVE(SANDBOX_STATE_FLAGS) && !ENABLE(WEBCONTENT_GPU_SANDBOX_EXTENSIONS_BLOCKING)
        sandbox_enable_state_flag("BlockIOKitInWebContentSandbox", *auditToken);
#endif
        ProcessCapabilities::setHardwareAcceleratedDecodingDisabled(true);
        ProcessCapabilities::setCanUseAcceleratedBuffers(false);
        static bool disabled { false };
        if (!std::exchange(disabled, true)) {
            OSStatus ok = CGImageSourceDisableHardwareDecoding();
            ASSERT_UNUSED(ok, ok == noErr);
        }
    }
#endif

    auto frameType = parameters.remotePageParameters ? Frame::FrameType::Remote : Frame::FrameType::Local;
    ASSERT(!parameters.remotePageParameters || parameters.remotePageParameters->frameTreeParameters.frameID == parameters.mainFrameIdentifier);

    PageConfiguration pageConfiguration(
        pageID,
        WebProcess::singleton().sessionID(),
        makeUniqueRef<WebEditorClient>(*this),
        WebSocketProvider::create(parameters.webPageProxyIdentifier),
        createLibWebRTCProvider(*this),
        WebProcess::singleton().cacheStorageProvider(),
        m_userContentController,
        WebBackForwardListProxy::create(*this),
        WebProcess::singleton().cookieJar(),
        makeUniqueRef<WebProgressTrackerClient>(*this),
        mainFrameCreationParameters(m_mainFrame.copyRef(), frameType, parameters.initialSandboxFlags, parameters.initialReferrerPolicy),
        m_mainFrame->frameID(),
        frameFromIdentifier(parameters.mainFrameOpenerIdentifier),
        makeUniqueRef<WebSpeechRecognitionProvider>(pageID),
        WebProcess::singleton().broadcastChannelRegistry(),
        makeUniqueRef<WebStorageProvider>(WebProcess::singleton().mediaKeysStorageDirectory(), WebProcess::singleton().mediaKeysStorageSalt()),
        WebModelPlayerProvider::create(*this),
        WebProcess::singleton().badgeClient(),
        m_historyItemClient.copyRef(),
#if ENABLE(CONTEXT_MENUS)
        makeUniqueRef<WebContextMenuClient>(this),
#endif
#if ENABLE(APPLE_PAY)
        WebPaymentCoordinator::create(*this),
#endif
        makeUniqueRef<WebChromeClient>(*this),
        makeUniqueRef<WebCryptoClient>(this->identifier()),
        makeUniqueRef<WebDocumentSyncClient>(*this)
#if ENABLE(WEB_AUTHN)
        , DigitalCredentialsCoordinator::create(*this)
#endif
    );

#if ENABLE(DRAG_SUPPORT)
    pageConfiguration.dragClient = makeUnique<WebDragClient>(this);
#endif
    pageConfiguration.inspectorBackendClient = makeUnique<WebInspectorBackendClient>(this);
#if USE(AUTOCORRECTION_PANEL)
    pageConfiguration.alternativeTextClient = makeUnique<WebAlternativeTextClient>(this);
#endif

    pageConfiguration.diagnosticLoggingClient = makeUnique<WebDiagnosticLoggingClient>(*this);
    pageConfiguration.performanceLoggingClient = makeUnique<WebPerformanceLoggingClient>(*this);
    pageConfiguration.screenOrientationManager = m_screenOrientationManager.get();

#if ENABLE(SPEECH_SYNTHESIS) && !USE(GSTREAMER)
    pageConfiguration.speechSynthesisClient = WebSpeechSynthesisClient::create(*this);
#endif

#if PLATFORM(COCOA) || PLATFORM(GTK)
    pageConfiguration.validationMessageClient = makeUnique<WebValidationMessageClient>(*this);
#endif

    pageConfiguration.databaseProvider = WebDatabaseProvider::getOrCreate(m_pageGroup->pageGroupID());
    pageConfiguration.pluginInfoProvider = WebPluginInfoProvider::singleton();
    pageConfiguration.storageNamespaceProvider = WebStorageNamespaceProvider::getOrCreate();
    pageConfiguration.visitedLinkStore = VisitedLinkTableController::getOrCreate(parameters.visitedLinkTableID);

#if ENABLE(WEB_AUTHN)
    pageConfiguration.authenticatorCoordinatorClient = makeUnique<WebAuthenticatorCoordinator>(*this);
#endif

#if ENABLE(APPLICATION_MANIFEST)
    pageConfiguration.applicationManifest = WTF::move(parameters.applicationManifest);
#endif

#if PLATFORM(IOS_FAMILY) && ENABLE(DEVICE_ORIENTATION)
    pageConfiguration.deviceOrientationUpdateProvider = WebDeviceOrientationUpdateProvider::create(*this);
#endif

#if ENABLE(WK_WEB_EXTENSIONS) && PLATFORM(COCOA)
    if (parameters.webExtensionControllerParameters)
        m_webExtensionController = WebExtensionControllerProxy::getOrCreate(parameters.webExtensionControllerParameters.value(), this);
#endif

    m_corsDisablingPatterns = WTF::move(parameters.corsDisablingPatterns);
    if (!m_corsDisablingPatterns.isEmpty())
        synchronizeCORSDisablingPatternsWithNetworkProcess();
    pageConfiguration.corsDisablingPatterns = parseAndAllowAccessToCORSDisablingPatterns(m_corsDisablingPatterns);

    pageConfiguration.maskedURLSchemes = WTF::move(parameters.maskedURLSchemes);
    pageConfiguration.loadsSubresources = parameters.loadsSubresources;
    pageConfiguration.allowedNetworkHosts = WTF::move(parameters.allowedNetworkHosts);
    pageConfiguration.shouldRelaxThirdPartyCookieBlocking = parameters.shouldRelaxThirdPartyCookieBlocking;
    pageConfiguration.httpsUpgradeEnabled = parameters.httpsUpgradeEnabled;
    pageConfiguration.portsForUpgradingInsecureSchemeForTesting = parameters.portsForUpgradingInsecureSchemeForTesting;

    if (!parameters.crossOriginAccessControlCheckEnabled)
        CrossOriginAccessControlCheckDisabler::singleton().setCrossOriginAccessControlCheckEnabled(false);

#if ENABLE(ATTACHMENT_ELEMENT)
    pageConfiguration.attachmentElementClient = makeUnique<WebAttachmentElementClient>(*this);
#endif

    pageConfiguration.contentSecurityPolicyModeForExtension = parameters.contentSecurityPolicyModeForExtension;

#if PLATFORM(COCOA)
    static bool hasConsumedGPUExtensionHandles = false;
    if (!hasConsumedGPUExtensionHandles) {
        SandboxExtension::consumePermanently(parameters.gpuIOKitExtensionHandles);
        SandboxExtension::consumePermanently(parameters.gpuMachExtensionHandles);
        hasConsumedGPUExtensionHandles = true;
    }
#endif

#if HAVE(STATIC_FONT_REGISTRY)
    if (parameters.fontMachExtensionHandles.size())
        WebProcess::singleton().switchFromStaticFontRegistryToUserFontRegistry(WTF::move(parameters.fontMachExtensionHandles));
#endif

#if PLATFORM(IOS_FAMILY)
    pageConfiguration.canShowWhileLocked = parameters.canShowWhileLocked;
#endif

#if PLATFORM(VISION) && ENABLE(GAMEPAD)
    pageConfiguration.gamepadAccessRequiresExplicitConsent = parameters.gamepadAccessRequiresExplicitConsent;
#endif

#if HAVE(AUDIT_TOKEN)
    pageConfiguration.presentingApplicationAuditToken = parameters.presentingApplicationAuditToken ? std::optional(parameters.presentingApplicationAuditToken->auditToken()) : std::nullopt;
#endif

#if PLATFORM(COCOA)
    pageConfiguration.presentingApplicationBundleIdentifier = WTF::move(parameters.presentingApplicationBundleIdentifier);
#endif

#if ENABLE(IMAGE_ANALYSIS)
    pageConfiguration.imageTranslationLanguageIdentifiers = WTF::move(parameters.imageTranslationLanguageIdentifiers);
#endif

    if (parameters.textManipulationParameters) {
        m_textManipulationIncludesSubframes = parameters.textManipulationParameters->includeSubframes;
        m_internals->textManipulationExclusionRules = WTF::move(parameters.textManipulationParameters->exclusionRules);
    }

#if ENABLE(VIDEO) || ENABLE(WEB_AUDIO)
    if (parameters.store.getBoolValueForKey(WebPreferencesKey::remoteMediaSessionManagerEnabledKey()) || parameters.store.getBoolValueForKey(WebPreferencesKey::siteIsolationSharedProcessEnabledKey())) {
        pageConfiguration.mediaSessionManagerFactory = [weakThis = WeakPtr { *this }](PageIdentifier) -> RefPtr<MediaSessionManagerInterface> {

            RefPtr protectedThis = weakThis.get();
            if (!protectedThis)
                return nullptr;

            // FIXME: This is often null with site isolation enabled. It seems like this is not what was intended.
            RefPtr topDocument = protectedThis->localTopDocument();
            if (!topDocument)
                return nullptr;

            RefPtr topCorePage = topDocument->page();
            if (!topCorePage)
                return nullptr;

            RefPtr topWebPage = WebPage::fromCorePage(*topCorePage);
            if (!topWebPage)
                return nullptr;

            RefPtr<PlatformMediaSessionManager> manager = RemoteMediaSessionManager::create(*topWebPage, *protectedThis);
            manager->resetRestrictions();

            return manager;
        };
    }
#endif

    Ref page = Page::create(WTF::move(pageConfiguration));
    m_page = page.copyRef();

    updateAfterDrawingAreaCreation(parameters);

    if (parameters.displayID)
        windowScreenDidChange(*parameters.displayID, parameters.nominalFramesPerSecond);

    WebStorageNamespaceProvider::incrementUseCount(sessionStorageNamespaceIdentifier());

    if (parameters.shouldForceSiteIsolationAlwaysOnForTesting)
        WebPreferences::forceSiteIsolationAlwaysOnForTesting();

    updatePreferences(parameters.store);
    if (page->settings().siteIsolationEnabled()) {
        if (RefPtr frame = page->localMainFrame())
            frame->inspectorController().siteIsolationFirstEnabled();
    }

#if PLATFORM(IOS_FAMILY) || ENABLE(ROUTING_ARBITRATION)
    DeprecatedGlobalSettings::setShouldManageAudioSessionCategory(true);
#endif

    m_backgroundColor = parameters.backgroundColor;

    // We need to set the device scale factor before creating the drawing area
    // to ensure it's created with the right size.
    page->setDeviceScaleFactor(parameters.deviceScaleFactor);

#if USE(GRAPHICS_LAYER_WC) || USE(GRAPHICS_LAYER_TEXTURE_MAPPER)
    setIntrinsicDeviceScaleFactor(parameters.intrinsicDeviceScaleFactor);
#endif

#if USE(SKIA)
    FontRenderOptions::singleton().setUseSubpixelPositioning(parameters.deviceScaleFactor >= 2.);
#endif

    RefPtr drawingArea = m_drawingArea;
#if USE(COORDINATED_GRAPHICS) || USE(TEXTURE_MAPPER)
    if (drawingArea->enterAcceleratedCompositingModeIfNeeded() && !parameters.isProcessSwap)
        drawingArea->sendEnterAcceleratedCompositingModeIfNeeded();
#endif
    drawingArea->setShouldScaleViewToFitDocument(parameters.shouldScaleViewToFitDocument);

    if (parameters.isProcessSwap)
        freezeLayerTree(LayerTreeFreezeReason::ProcessSwap);

#if ENABLE(ASYNC_SCROLLING)
    m_useAsyncScrolling = parameters.store.getBoolValueForKey(WebPreferencesKey::threadedScrollingEnabledKey());
    if (!drawingArea->supportsAsyncScrolling())
        m_useAsyncScrolling = false;
    page->settings().setScrollingCoordinatorEnabled(m_useAsyncScrolling);
#endif

    // Disable Back/Forward cache expiration in the WebContent process since management happens in the UIProcess
    // in modern WebKit.
    page->settings().setBackForwardCacheExpirationInterval(Seconds::infinity());

    m_mainFrame->initWithCoreMainFrame(*this, protect(page->mainFrame()));

    for (const auto& iterator : parameters.urlSchemeHandlers)
        registerURLSchemeHandler(iterator.value, iterator.key);
    for (auto& scheme : parameters.urlSchemesWithLegacyCustomProtocolHandlers)
        LegacySchemeRegistry::registerURLSchemeAsHandledBySchemeHandler({ scheme });

    if (auto& remotePageParameters = parameters.remotePageParameters) {
        m_mainFrame->coreFrame()->tree().setSpecifiedName(AtomString { remotePageParameters->frameTreeParameters.frameName });

        Ref frameTreeSyncData = remotePageParameters->frameTreeParameters.frameTreeSyncData;
        protect(page->mainFrame())->updateFrameTreeSyncData(WTF::move(frameTreeSyncData));

        for (auto& childParameters : remotePageParameters->frameTreeParameters.children)
            constructFrameTree(m_mainFrame.get(), childParameters);

        page->setMainFrameURLAndOrigin(remotePageParameters->initialMainDocumentURL, nullptr);

        if (auto websitePolicies = remotePageParameters->websitePoliciesData) {
            if (auto* remoteMainFrameClient = m_mainFrame->remoteFrameClient())
                remoteMainFrameClient->applyWebsitePolicies(WTF::move(*remotePageParameters->websitePoliciesData));
        }
    }
    if (auto&& provisionalFrameCreationParameters = parameters.provisionalFrameCreationParameters) {
        ASSERT(page->settings().siteIsolationEnabled());
        createProvisionalFrame(WTF::move(*provisionalFrameCreationParameters));
    }

    drawingArea->updatePreferences(parameters.store);

    setBackgroundExtendsBeyondPage(parameters.backgroundExtendsBeyondPage);
    didSetPageZoomFactor(parameters.pageZoomFactor);
    didSetTextZoomFactor(parameters.textZoomFactor);

#if ENABLE(GEOLOCATION)
    WebCore::provideGeolocationTo(page.ptr(), WebGeolocationClient::create(*this));
#endif
    // FIXME: These should use makeUnique and makeUniqueRef instead of new.
#if ENABLE(NOTIFICATIONS)
    WebCore::provideNotification(page.ptr(), new WebNotificationClient(this));
#endif
#if ENABLE(MEDIA_STREAM)
    WebCore::provideUserMediaTo(page.ptr(), WebUserMediaClient::create(*this));
#endif
#if ENABLE(ENCRYPTED_MEDIA)
    WebCore::provideMediaKeySystemTo(page, WebMediaKeySystemClient::create(*this));
#endif

#if PLATFORM(DRIFTSTACK)
    // V-AUTOMATION-TELL-CHOKEPOINT: a real iPhone is never automation-controlled.
    // WebContent must always observe Page::isControlledByAutomation()==false so the
    // entire web-observable automation-tell surface collapses to the normal-browser
    // branch in one place: navigator.webdriver (NavigatorWebDriver.cpp), navigator.share
    // (Navigator.cpp), window.print (LocalDOMWindow.cpp), focus relinquish
    // (FocusController.cpp), scroll-to-text-fragment indicator (LocalFrameView.cpp),
    // and the editor smart-substitution toggles in WebEditorClientMac.mm (automatic
    // quote/dash/text-replacement/smart-lists/spelling-correction — all forced off
    // under automation, an observable iOS-divergence in editable text). The UIProcess
    // WebPageProxy keeps its own m_controlledByAutomation, so automation driving (input
    // simulation, dialog handling) is unaffected.
    page->setControlledByAutomation(false);
#else
    page->setControlledByAutomation(parameters.controlledByAutomation);
#endif
    page->setHasResourceLoadClient(parameters.hasResourceLoadClient);

    page->setCanStartMedia(false);
    m_mayStartMediaWhenInWindow = parameters.mayStartMediaWhenInWindow;
    if (parameters.mediaPlaybackIsSuspended)
        page->suspendAllMediaPlayback();

    if (parameters.openedByDOM)
        page->setOpenedByDOM();

    page->setGroupName(m_pageGroup->identifier());
    page->setUserInterfaceLayoutDirection(m_userInterfaceLayoutDirection);
#if PLATFORM(IOS_FAMILY)
    // Set hardware keyboard attached status
    page->didUpdateHardwareKeyboardAttachment(m_keyboardIsAttached);

    page->setTextAutosizingWidth(parameters.textAutosizingWidth);
    setOverrideViewportArguments(parameters.overrideViewportArguments);
#endif

    platformInitialize(parameters);

    setUseFixedLayout(parameters.useFixedLayout);

    setDefaultUnobscuredSize(parameters.defaultUnobscuredSize);
    setMinimumUnobscuredSize(parameters.minimumUnobscuredSize);
    setMaximumUnobscuredSize(parameters.maximumUnobscuredSize);

    setUnderlayColor(parameters.underlayColor);

    setPaginationMode(parameters.paginationMode);
    setPaginationBehavesLikeColumns(parameters.paginationBehavesLikeColumns);
    setPageLength(parameters.pageLength);
    setGapBetweenPages(parameters.gapBetweenPages);

    setUseColorAppearance(parameters.useDarkAppearance, parameters.useElevatedUserInterfaceLevel);

    if (parameters.isEditable)
        setEditable(true);

    inheritAccessibilityMode(parameters.accessibilityMode);

    WebCore::AXObjectCache::setSyncModeToOtherProcessesCallback([weakPage = WeakPtr { *this }](WebCore::AccessibilityMode mode) {
        if (RefPtr page = weakPage.get())
            page->send(Messages::WebPageProxy::SetAccessibilityMode(mode));
    });

#if PLATFORM(MAC)
    if (WebCore::AXObjectCache::shouldForceAccessibilityEnabled())
        WebCore::AXObjectCache::enableAccessibility(WebCore::AXObjectCache::ForceAXThreadMode::Yes);
#endif // PLATFORM(MAC)

#if PLATFORM(MAC)
    setUseFormSemanticContext(parameters.useFormSemanticContext);
    setHeaderBannerHeight(parameters.headerBannerHeight);
    setFooterBannerHeight(parameters.footerBannerHeight);
    if (parameters.viewWindowCoordinates)
        windowAndViewFramesChanged(*parameters.viewWindowCoordinates);
#endif

#if PLATFORM(DRIFTSTACK)
    // V-FOREGROUND-CHOKEPOINT: present as a foreground+focused iPhone tab from construction (avoids
    // the initial hidden/prerender/unfocused state on a non-foreground fleet window). See helper.
    m_activityState = driftstackForceForeground(m_activityState);
#endif
    // If the page is created off-screen, its visibilityState should be prerender.
    page->setActivityState(m_activityState);
    if (!isVisible())
        page->setIsPrerender();

    updateIsInWindow(true);

    setMinimumSizeForAutoLayout(parameters.minimumSizeForAutoLayout);
    setSizeToContentAutoSizeMaximumSize(parameters.sizeToContentAutoSizeMaximumSize);
    setAutoSizingShouldExpandToViewHeight(parameters.autoSizingShouldExpandToViewHeight);
    setViewportSizeForCSSViewportUnits(parameters.viewportSizeForCSSViewportUnits);

    setScrollPinningBehavior(parameters.scrollPinningBehavior);
    if (parameters.scrollbarOverlayStyle)
        m_scrollbarOverlayStyle = static_cast<ScrollbarOverlayStyle>(parameters.scrollbarOverlayStyle.value());
    else
        m_scrollbarOverlayStyle = std::optional<ScrollbarOverlayStyle>();

    setObscuredContentInsets(parameters.obscuredContentInsets);

#if ENABLE(BANNER_VIEW_OVERLAYS)
    setHasBannerViewOverlay(parameters.hasBannerViewOverlay);
#endif

    m_userAgent = WTF::move(parameters.userAgent);

    setMediaVolume(parameters.mediaVolume);

    setMuted(parameters.muted, [] { });

    // We use the DidFirstVisuallyNonEmptyLayout milestone to determine when to unfreeze the layer tree.
    // We use LayoutMilestone::DidFirstMeaningfulPaint to generte WKPageLoadTiming.
    page->addLayoutMilestones({ WebCore::LayoutMilestone::DidFirstLayout, WebCore::LayoutMilestone::DidFirstVisuallyNonEmptyLayout, LayoutMilestone::DidFirstMeaningfulPaint });

    auto& webProcess = WebProcess::singleton();
    webProcess.addMessageReceiver(Messages::WebPage::messageReceiverName(), m_identifier, *this);

    // FIXME: This should be done in the object constructors, and the objects themselves should be message receivers.
    webProcess.addMessageReceiver(Messages::WebInspectorBackend::messageReceiverName(), m_identifier, *this);
    webProcess.addMessageReceiver(Messages::WebInspectorUI::messageReceiverName(), m_identifier, *this);
    webProcess.addMessageReceiver(Messages::RemoteWebInspectorUI::messageReceiverName(), m_identifier, *this);
#if ENABLE(FULLSCREEN_API)
    webProcess.addMessageReceiver(Messages::WebFullScreenManager::messageReceiverName(), m_identifier, *this);
#endif

#if ENABLE(SCROLLING_THREAD)
    if (m_useAsyncScrolling)
        drawingArea->registerScrollingTree();
#endif

    for (auto& mimeType : parameters.mimeTypesWithCustomContentProviders)
        m_mimeTypesWithCustomContentProviders.add(mimeType);

    if (parameters.viewScaleFactor != 1)
        scaleView(parameters.viewScaleFactor);

    page->addLayoutMilestones(parameters.observedLayoutMilestones);

#if PLATFORM(COCOA)
    setSmartInsertDeleteEnabled(parameters.smartInsertDeleteEnabled);
#endif

#if HAVE(APP_ACCENT_COLORS)
    setAccentColor(parameters.accentColor);
#if PLATFORM(MAC)
    setAppUsesCustomAccentColor(parameters.appUsesCustomAccentColor);
#endif
#endif

    m_needsFontAttributes = parameters.needsFontAttributes;

    setNeedsScrollGeometryUpdates(parameters.needsScrollGeometryUpdates);

#if ENABLE(WEB_RTC)
    if (!parameters.iceCandidateFilteringEnabled)
        page->disableICECandidateFiltering();
#if USE(LIBWEBRTC)
    if (parameters.enumeratingAllNetworkInterfacesEnabled)
        downcast<LibWebRTCProvider>(page->webRTCProvider()).enableEnumeratingAllNetworkInterfaces();
    if (parameters.store.getBoolValueForKey(WebPreferencesKey::enumeratingVisibleNetworkInterfacesEnabledKey()))
        downcast<LibWebRTCProvider>(page->webRTCProvider()).enableEnumeratingVisibleNetworkInterfaces();
#endif
#endif

#if PLATFORM(IOS_FAMILY)
    setViewportConfigurationViewLayoutSize(parameters.viewportConfigurationViewLayoutSize, parameters.viewportConfigurationLayoutSizeScaleFactorFromClient, parameters.viewportConfigurationMinimumEffectiveDeviceWidth);
#endif

#if HAVE(VISIBILITY_PROPAGATION_VIEW)
    LayerHostingContextID contextID = 0;
#if !HAVE(NON_HOSTING_VISIBILITY_PROPAGATION_VIEW)
    m_contextForVisibilityPropagation = LayerHostingContext::create({
        canShowWhileLocked()
    });
    WEBPAGE_RELEASE_LOG(Process, "WebPage: Created context with ID %u for visibility propagation from UIProcess", m_contextForVisibilityPropagation->contextID());
    contextID = m_contextForVisibilityPropagation->cachedContextID();
#endif // !HAVE(NON_HOSTING_VISIBILITY_PROPAGATION_VIEW)
    send(Messages::WebPageProxy::DidCreateContextInWebProcessForVisibilityPropagation(contextID));
#endif // HAVE(VISIBILITY_PROPAGATION_VIEW) && !HAVE(NON_HOSTING_VISIBILITY_PROPAGATION_VIEW)

#if ENABLE(VP9) && PLATFORM(COCOA)
    VP9TestingOverrides::singleton().setShouldEnableVP9Decoder(parameters.shouldEnableVP9Decoder);
#endif

    page->setCanUseCredentialStorage(parameters.canUseCredentialStorage);

#if HAVE(SANDBOX_STATE_FLAGS)
    auto experimentalSandbox = parameters.store.getBoolValueForKey(WebPreferencesKey::experimentalSandboxEnabledKey());
    if (experimentalSandbox)
        sandbox_enable_state_flag("EnableExperimentalSandbox", *auditToken);

#if HAVE(MACH_BOOTSTRAP_EXTENSION)
    SandboxExtension::consumePermanently(parameters.machBootstrapHandle);
#endif
#endif // HAVE(SANDBOX_STATE_FLAGS)

    updateThrottleState();
#if ENABLE(ACCESSIBILITY_ANIMATION_CONTROL)
    updateImageAnimationEnabled();
#endif
#if ENABLE(ACCESSIBILITY_NON_BLINKING_CURSOR)
    updatePrefersNonBlinkingCursor();
#endif
#if ENABLE(ADVANCED_PRIVACY_PROTECTIONS)
    setLinkDecorationFilteringData(WTF::move(parameters.linkDecorationFilteringData));
    setAllowedQueryParametersForAdvancedPrivacyProtections(WTF::move(parameters.allowedQueryParametersForAdvancedPrivacyProtections));
#endif
    if (parameters.windowFeatures) {
        page->applyWindowFeatures(*parameters.windowFeatures);
        page->chrome().show();
        page->setOpenedByDOM();
    }

    if (parameters.allowPostingLegacySynchronousMessages)
        InjectedBundleScriptWorld::normalWorldSingleton().setAllowPostingLegacySynchronousMessages();

#if PLATFORM(IOS_FAMILY)
    RELEASE_ASSERT_IMPLIES(m_backgroundTextExtractionEnabled, isParentProcessAWebBrowser());
#endif
}

void WebPage::updateAfterDrawingAreaCreation(const WebPageCreationParameters& parameters)
{
#if PLATFORM(COCOA)
    m_page->settings().setForceCompositingMode(true);
#endif
#if ENABLE(TILED_CA_DRAWING_AREA)
    if (parameters.drawingAreaType == DrawingAreaType::TiledCoreAnimation) {
        if (auto viewExposedRect = parameters.viewExposedRect)
            protect(drawingArea())->setViewExposedRect(viewExposedRect);
    }
#endif
}

void WebPage::constructFrameTree(WebFrame& parent, const FrameTreeCreationParameters& treeCreationParameters)
{
    auto frame = WebFrame::createRemoteSubframe(*this, parent, treeCreationParameters.frameID, treeCreationParameters.frameName, treeCreationParameters.openerFrameID, Ref { treeCreationParameters.frameTreeSyncData });
    for (auto& parameters : treeCreationParameters.children)
        constructFrameTree(frame, parameters);
}

void WebPage::createRemoteSubframe(WebCore::FrameIdentifier parentID, WebCore::FrameIdentifier newChildID, const String& newChildFrameName, Ref<WebCore::FrameTreeSyncData>&& frameTreeSyncData)
{
    RefPtr parentFrame = WebProcess::singleton().webFrame(parentID);
    if (!parentFrame) {
        ASSERT_NOT_REACHED();
        return;
    }
    WebFrame::createRemoteSubframe(*this, *parentFrame, newChildID, newChildFrameName, std::nullopt, WTF::move(frameTreeSyncData));
}

Awaitable<std::optional<FrameTreeNodeData>> WebPage::getFrameTree()
{
    co_return m_mainFrame->frameTreeData();
}

void WebPage::didFinishLoadInAnotherProcess(WebCore::FrameIdentifier frameID)
{
    RefPtr frame = WebProcess::singleton().webFrame(frameID);
    if (!frame)
        return;
    ASSERT(frame->page() == this);
    frame->didFinishLoadInAnotherProcess();
}

void WebPage::frameWasRemovedInAnotherProcess(WebCore::FrameIdentifier frameID)
{
    RefPtr frame = WebProcess::singleton().webFrame(frameID);
    if (!frame)
        return;
    ASSERT(frame->page() == this);
    frame->markAsRemovedInAnotherProcess();
    frame->removeFromTree();
}

void WebPage::topDocumentSyncDataChangedInAnotherProcess(const WebCore::DocumentSyncSerializationData& data)
{
    if (RefPtr page = corePage())
        page->updateTopDocumentSyncData(data);
}

void WebPage::allTopDocumentSyncDataChangedInAnotherProcess(Ref<WebCore::DocumentSyncData>&& data)
{
    if (RefPtr page = corePage())
        page->updateTopDocumentSyncData(WTF::move(data));
}

void WebPage::frameTreeSyncDataChangedInAnotherProcess(FrameIdentifier frameID, const WebCore::FrameTreeSyncSerializationData& data)
{
    ASSERT(m_page->settings().siteIsolationEnabled());

    RefPtr frame = WebProcess::singleton().webFrame(frameID);
    if (!frame)
        return;

    ASSERT(frame->page() == this);

    RefPtr coreFrame = frame->coreFrame();
    if (coreFrame) {
        coreFrame->updateFrameTreeSyncData(data);

        if (data.type == FrameTreeSyncDataType::FrameRect)
            frame->updateFrameRectFromRemote(coreFrame->frameTreeSyncData().frameRect);
    }
}

void WebPage::allFrameTreeSyncDataChangedInAnotherProcess(FrameIdentifier frameID, Ref<WebCore::FrameTreeSyncData>&& data)
{
    ASSERT(m_page->settings().siteIsolationEnabled());

    RefPtr frame = WebProcess::singleton().webFrame(frameID);
    if (!frame)
        return;

    ASSERT(frame->page() == this);

    RefPtr coreFrame = frame->coreFrame();
    if (coreFrame)
        coreFrame->updateFrameTreeSyncData(WTF::move(data));
}

#if ENABLE(GPU_PROCESS)
void WebPage::gpuProcessConnectionDidBecomeAvailable(GPUProcessConnection& gpuProcessConnection)
{
    UNUSED_PARAM(gpuProcessConnection);

#if HAVE(VISIBILITY_PROPAGATION_VIEW)
    gpuProcessConnection.createVisibilityPropagationContextForPage(*this);
#endif

#if ENABLE(EXTENSION_CAPABILITIES)
    if (!mediaPlaybackEnvironment().isEmpty())
        gpuProcessConnection.setMediaPlaybackEnvironment(identifier(), mediaPlaybackEnvironment());

    if (!displayCaptureEnvironment().isEmpty())
        gpuProcessConnection.setDisplayCaptureEnvironment(identifier(), displayCaptureEnvironment());
#endif
}

void WebPage::gpuProcessConnectionWasDestroyed()
{
#if PLATFORM(COCOA)
    if (RefPtr remoteLayerTreeDrawingArea = dynamicDowncast<RemoteLayerTreeDrawingArea>(protect(drawingArea())))
        remoteLayerTreeDrawingArea->gpuProcessConnectionWasDestroyed();
#endif
}

#endif

#if ENABLE(MODEL_PROCESS)
void WebPage::modelProcessConnectionDidBecomeAvailable(ModelProcessConnection& modelProcessConnection)
{
#if HAVE(VISIBILITY_PROPAGATION_VIEW)
    modelProcessConnection.createVisibilityPropagationContextForPage(*this);
#else
    UNUSED_PARAM(modelProcessConnection);
#endif
}
#endif

void WebPage::requestMediaPlaybackState(CompletionHandler<void(WebKit::MediaPlaybackState)>&& completionHandler)
{
    RefPtr page = m_page;
    if (!page->mediaPlaybackExists())
        return completionHandler(MediaPlaybackState::NoMediaPlayback);
    if (page->mediaPlaybackIsPaused())
        return completionHandler(MediaPlaybackState::MediaPlaybackPaused);
    if (page->mediaPlaybackIsSuspended())
        return completionHandler(MediaPlaybackState::MediaPlaybackSuspended);

    completionHandler(MediaPlaybackState::MediaPlaybackPlaying);
}

void WebPage::pauseAllMediaPlayback(CompletionHandler<void()>&& completionHandler)
{
    protect(corePage())->pauseAllMediaPlayback();
    completionHandler();
}

void WebPage::suspendAllMediaPlayback(CompletionHandler<void()>&& completionHandler)
{
    protect(corePage())->suspendAllMediaPlayback();
    completionHandler();
}

void WebPage::resumeAllMediaPlayback(CompletionHandler<void()>&& completionHandler)
{
    protect(corePage())->resumeAllMediaPlayback();
    completionHandler();
}

void WebPage::suspendAllMediaBuffering()
{
    protect(corePage())->suspendAllMediaBuffering();
}

void WebPage::resumeAllMediaBuffering()
{
    protect(corePage())->resumeAllMediaBuffering();
}

static void addRootFramesToNewDrawingArea(WebFrame& frame, DrawingArea& drawingArea)
{
    if (frame.isRootFrame() || (frame.provisionalFrame() && protect(frame.provisionalFrame())->isRootFrame()))
        drawingArea.addRootFrame(frame.frameID());
    if (!frame.coreFrame())
        return;
    for (RefPtr child = frame.coreFrame()->tree().firstChild(); child; child = child->tree().nextSibling()) {
        if (RefPtr childWebFrame = WebFrame::fromCoreFrame(*child))
            addRootFramesToNewDrawingArea(*childWebFrame, drawingArea);
    }
}

void WebPage::reinitializeWebPage(WebPageCreationParameters&& parameters)
{
    ASSERT(m_drawingArea);

    setSize(parameters.viewSize);

    // If the UIProcess created a new DrawingArea, then we need to do the same.
    if (m_drawingArea->identifier() != parameters.drawingAreaIdentifier) {
        RefPtr oldDrawingArea = std::exchange(m_drawingArea, nullptr);
        oldDrawingArea->removeMessageReceiverIfNeeded();

        m_drawingArea = DrawingArea::create(*this, parameters);
        RefPtr drawingArea = m_drawingArea;
        updateAfterDrawingAreaCreation(parameters);
        addRootFramesToNewDrawingArea(m_mainFrame.get(), *drawingArea);

        drawingArea->setShouldScaleViewToFitDocument(parameters.shouldScaleViewToFitDocument);
        drawingArea->updatePreferences(parameters.store);

#if USE(COORDINATED_GRAPHICS) || USE(TEXTURE_MAPPER)
        if (drawingArea->enterAcceleratedCompositingModeIfNeeded() && !parameters.isProcessSwap)
            drawingArea->sendEnterAcceleratedCompositingModeIfNeeded();
#endif

        drawingArea->adoptLayersFromDrawingArea(*oldDrawingArea);
        drawingArea->adoptDisplayRefreshMonitorsFromDrawingArea(*oldDrawingArea);

        unfreezeLayerTree(LayerTreeFreezeReason::PageSuspended);
    }

    setMinimumSizeForAutoLayout(parameters.minimumSizeForAutoLayout);
    setSizeToContentAutoSizeMaximumSize(parameters.sizeToContentAutoSizeMaximumSize);

    if (m_activityState != parameters.activityState)
        setActivityState(parameters.activityState, ActivityStateChangeAsynchronous, [] { });

#if HAVE(APP_ACCENT_COLORS)
    setAccentColor(parameters.accentColor);
#if PLATFORM(MAC)
    setAppUsesCustomAccentColor(parameters.appUsesCustomAccentColor);
#endif
#endif

    setUseColorAppearance(parameters.useDarkAppearance, parameters.useElevatedUserInterfaceLevel);

    if (auto&& provisionalFrameCreationParameters = parameters.provisionalFrameCreationParameters) {
        ASSERT(m_page->settings().siteIsolationEnabled());
        createProvisionalFrame(WTF::move(*provisionalFrameCreationParameters));
    }

    platformReinitializeAccessibilityToken();
}

void WebPage::updateThrottleState()
{
    bool isThrottleable = this->isThrottleable();

    // The UserActivity prevents App Nap. So if we want to allow App Nap of the page, stop the activity.
    // If the page should not be app nap'd, start it.
    if (isThrottleable)
        m_internals->userActivity.stop();
    else
        m_internals->userActivity.start();

    if (m_page && m_page->settings().serviceWorkersEnabled()) {
        RunLoop::mainSingleton().dispatch([isThrottleable] {
            WebServiceWorkerProvider::singleton().updateThrottleState(isThrottleable);
        });
    }
}

bool WebPage::isThrottleable() const
{
    bool isActive = m_activityState.containsAny({ ActivityState::IsLoading, ActivityState::IsAudible, ActivityState::IsCapturingMedia, ActivityState::WindowIsActive });
    bool isVisuallyIdle = m_activityState.contains(ActivityState::IsVisuallyIdle);

    return m_isAppNapEnabled && !isActive && isVisuallyIdle;
}

WebPage::~WebPage()
{
    ASSERT(!m_page);
    WEBPAGE_RELEASE_LOG(Loading, "destructor:");

    if (!m_corsDisablingPatterns.isEmpty()) {
        m_corsDisablingPatterns.clear();
        synchronizeCORSDisablingPatternsWithNetworkProcess();
    }

    platformDetach();

    m_sandboxExtensionTracker.invalidate();

#if ENABLE(PDF_PLUGIN)
    for (auto& pluginView : m_pluginViews)
        pluginView.webPageDestroyed();
#endif

#if !PLATFORM(IOS_FAMILY)
    if (RefPtr headerBanner = m_headerBanner)
        headerBanner->detachFromPage();
    if (RefPtr footerBanner = m_footerBanner)
        footerBanner->detachFromPage();
#endif

    WebStorageNamespaceProvider::decrementUseCount(sessionStorageNamespaceIdentifier());

#if ENABLE(GPU_PROCESS) && HAVE(VISIBILITY_PROPAGATION_VIEW)
    if (RefPtr gpuProcessConnection = WebProcess::singleton().existingGPUProcessConnection())
        gpuProcessConnection->destroyVisibilityPropagationContextForPage(*this);
#endif // ENABLE(GPU_PROCESS)

#if ENABLE(MODEL_PROCESS) && HAVE(VISIBILITY_PROPAGATION_VIEW)
    if (RefPtr modelProcessConnection = WebProcess::singleton().existingModelProcessConnection())
        modelProcessConnection->destroyVisibilityPropagationContextForPage(*this);
#endif // ENABLE(MODEL_PROCESS) && HAVE(VISIBILITY_PROPAGATION_VIEW)

#if ENABLE(VIDEO_PRESENTATION_MODE)
    if (RefPtr playbackSessionManager = m_playbackSessionManager)
        playbackSessionManager->invalidate();

    if (RefPtr videoPresentationManager = m_videoPresentationManager)
        videoPresentationManager->invalidate();
#endif

    for (auto& completionHandler : std::exchange(m_markLayersAsVolatileCompletionHandlers, { }))
        completionHandler(false);

#if ENABLE(EXTENSION_CAPABILITIES)
    setMediaPlaybackEnvironment({ });
    setDisplayCaptureEnvironment({ });
#endif
}

IPC::Connection* WebPage::messageSenderConnection() const
{
    return WebProcess::singleton().parentProcessConnection();
}

uint64_t WebPage::messageSenderDestinationID() const
{
    return identifier().toUInt64();
}

#if ENABLE(CONTEXT_MENUS)
void WebPage::setInjectedBundleContextMenuClient(std::unique_ptr<API::InjectedBundle::PageContextMenuClient>&& contextMenuClient)
{
    if (!contextMenuClient) {
        m_contextMenuClient = makeUnique<API::InjectedBundle::PageContextMenuClient>();
        return;
    }

    m_contextMenuClient = WTF::move(contextMenuClient);
}
#endif

void WebPage::setInjectedBundleEditorClient(std::unique_ptr<API::InjectedBundle::EditorClient>&& editorClient)
{
    if (!editorClient) {
        m_editorClient = makeUnique<API::InjectedBundle::EditorClient>();
        return;
    }

    m_editorClient = WTF::move(editorClient);
}

void WebPage::setInjectedBundleFormClient(std::unique_ptr<API::InjectedBundle::FormClient>&& formClient)
{
    if (!formClient) {
        m_formClient = makeUnique<API::InjectedBundle::FormClient>();
        return;
    }

    m_formClient = WTF::move(formClient);
}

void WebPage::setInjectedBundlePageLoaderClient(std::unique_ptr<API::InjectedBundle::PageLoaderClient>&& loaderClient)
{
    if (!loaderClient) {
        m_loaderClient = makeUnique<API::InjectedBundle::PageLoaderClient>();
        return;
    }

    m_loaderClient = WTF::move(loaderClient);

    // It would be nice to get rid of this code and transition all clients to using didLayout instead of
    // didFirstLayoutInFrame and didFirstVisuallyNonEmptyLayoutInFrame. In the meantime, this is required
    // for backwards compatibility.
    if (auto milestones = m_loaderClient->layoutMilestones())
        listenForLayoutMilestones(milestones);
}

void WebPage::setInjectedBundleResourceLoadClient(std::unique_ptr<API::InjectedBundle::ResourceLoadClient>&& client)
{
    if (!m_resourceLoadClient)
        m_resourceLoadClient = makeUnique<API::InjectedBundle::ResourceLoadClient>();
    else
        m_resourceLoadClient = WTF::move(client);
}

void WebPage::setInjectedBundleUIClient(std::unique_ptr<API::InjectedBundle::PageUIClient>&& uiClient)
{
    if (!uiClient) {
        m_uiClient = makeUnique<API::InjectedBundle::PageUIClient>();
        return;
    }

    m_uiClient = WTF::move(uiClient);
}

bool WebPage::hasPendingEditorStateUpdate() const
{
    return m_pendingEditorStateUpdateStatus != PendingEditorStateUpdateStatus::NotScheduled;
}

EditorState WebPage::editorState(ShouldPerformLayout shouldPerformLayout) const
{
    // Always return an EditorState with a valid identifier or it will fail to decode and this process will be terminated.
    EditorState result;
    result.identifier = m_internals->lastEditorStateIdentifier.increment();

    // Ref the frame because this function may perform layout, which may cause frame destruction.
    RefPtr frame = corePage()->focusController().focusedOrMainFrame();
    if (!frame)
        return result;

    auto sanitizeEditorStateOnceCreated = makeScopeExit([&result] {
        result.clipOwnedRectExtentsToNumericLimits();
    });

#if ENABLE(PDF_PLUGIN)
    if (RefPtr pluginView = focusedPluginViewForFrame(*frame); pluginView && pluginView->populateEditorStateIfNeeded(result))
        return result;
#endif

    const VisibleSelection& selection = frame->selection().selection();
    Ref editor = frame->editor();

    result.selectionType = selection.type();
    result.isContentEditable = selection.hasEditableStyle();
    result.isContentRichlyEditable = selection.isContentRichlyEditable();
    result.isInPasswordField = selection.isInPasswordField();
    result.hasComposition = editor->hasComposition();
    result.shouldIgnoreSelectionChanges = editor->ignoreSelectionChanges() || (editor->client() && !protect(editor->client())->shouldRevealCurrentSelectionAfterInsertion());
    result.triggeredByAccessibilitySelectionChange = m_pendingEditorStateUpdateStatus == PendingEditorStateUpdateStatus::ScheduledDuringAccessibilitySelectionChange || m_isChangingSelectionForAccessibility;

    Ref<Document> document = *frame->document();

    if (result.selectionType == WebCore::SelectionType::Range) {
        auto selectionRange = selection.range();
        result.selectionIsRangeInsideImageOverlay = selectionRange && ImageOverlay::isInsideOverlay(*selectionRange);
        result.selectionIsRangeInAutoFilledAndViewableField = selection.isInAutoFilledAndViewableField();
    }

    m_lastEditorStateWasContentEditable = result.isContentEditable ? EditorStateIsContentEditable::Yes : EditorStateIsContentEditable::No;

    if (shouldAvoidComputingPostLayoutDataForEditorState()) {
        getPlatformEditorState(*frame, result);
        return result;
    }

    if (shouldPerformLayout == ShouldPerformLayout::Yes || requiresPostLayoutDataForEditorState(*frame))
        document->updateLayout(); // May cause document destruction

    if (RefPtr frameView = document->view(); frameView && !frameView->needsLayout() && !document->hasNodesWithMissingStyle()) {
        if (!result.postLayoutData)
            result.postLayoutData = std::optional<EditorState::PostLayoutData> { EditorState::PostLayoutData { } };
        result.postLayoutData->canCut = editor->canCut();
        result.postLayoutData->canCopy = editor->canCopy();
        result.postLayoutData->canPaste = editor->canEdit();

        if (!result.visualData)
            result.visualData = std::optional<EditorState::VisualData> { EditorState::VisualData { } };
    }

    getPlatformEditorState(*frame, result);

    return result;
}

void WebPage::changeFontAttributes(WebCore::FontAttributeChanges&& changes)
{
    RefPtr frame = corePage()->focusController().focusedOrMainFrame();
    if (!frame)
        return;

    if (frame->selection().selection().isContentEditable())
        protect(frame->editor())->applyStyleToSelection(changes.createEditingStyle(), changes.editAction(), Editor::ColorFilterMode::InvertColor);
}

void WebPage::changeFont(WebCore::FontChanges&& changes)
{
    RefPtr frame = corePage()->focusController().focusedOrMainFrame();
    if (!frame)
        return;

    if (frame->selection().selection().isContentEditable())
        protect(frame->editor())->applyStyleToSelection(changes.createEditingStyle(), EditAction::SetFont, Editor::ColorFilterMode::InvertColor);
}

void WebPage::executeEditCommandWithCallback(const String& commandName, const String& argument, CompletionHandler<void()>&& completionHandler)
{
    executeEditCommand(commandName, argument);
    completionHandler();
}

void WebPage::selectAll()
{
    executeEditingCommand("SelectAll"_s, { });
    platformDidSelectAll();
}

bool WebPage::shouldDispatchSyntheticMouseEventsWhenModifyingSelection() const
{
    RefPtr localTopDocument = protect(corePage())->localTopDocument();
    return localTopDocument && localTopDocument->quirks().shouldDispatchSyntheticMouseEventsWhenModifyingSelection();
}

#if !PLATFORM(IOS_FAMILY)

void WebPage::platformDidSelectAll()
{
}

#endif // !PLATFORM(IOS_FAMILY)

#if !PLATFORM(COCOA)
std::pair<URL, WebCore::DidFilterLinkDecoration> WebPage::applyLinkDecorationFilteringWithResult(const URL& url, WebCore::LinkDecorationFilteringTrigger)
{
    return { url, WebCore::DidFilterLinkDecoration::No };
}

void WebPage::bindRemoteAccessibilityFrames(int, WebCore::FrameIdentifier, WebCore::AccessibilityRemoteToken, CompletionHandler<void(WebCore::AccessibilityRemoteToken, int)>&& completionHandler)
{
    completionHandler({ }, { });
}

void WebPage::resolveAccessibilityHitTestForTesting(WebCore::FrameIdentifier, const WebCore::IntPoint&, CompletionHandler<void(String)>&& completionHandler)
{
    completionHandler({ });
}

void WebPage::updateRemotePageAccessibilityOffset(WebCore::FrameIdentifier, WebCore::IntPoint)
{
}

#endif

#if ENABLE(ACCESSIBILITY_LOCAL_FRAME)
void WebPage::updateRemotePageAccessibilityInheritedState(WebCore::FrameIdentifier frameID, const WebCore::InheritedFrameState& state)
{
    RefPtr frame = WebProcess::singleton().webFrame(frameID);
    if (!frame)
        return;

    RefPtr coreFrame = frame->coreLocalFrame();
    if (!coreFrame)
        return;

    RefPtr document = coreFrame->document();
    if (!document)
        return;

    WeakPtr cache = document->axObjectCache();
    if (!cache)
        return;

    cache->setFrameInheritedState(*coreFrame, state);
}

void WebPage::updateRemotePageAccessibilityScreenPosition(WebCore::FrameIdentifier frameID, const WebCore::AXFrameGeometry& geometry)
{
    RefPtr frame = WebProcess::singleton().webFrame(frameID);
    RefPtr coreFrame = frame ? frame->coreLocalFrame() : nullptr;
    RefPtr document = coreFrame ? coreFrame->document() : nullptr;
    if (WeakPtr cache = document ? document->axObjectCache() : nullptr)
        cache->setFrameGeometry(*coreFrame, geometry);
}
#endif // ENABLE(ACCESSIBILITY_LOCAL_FRAME)

void WebPage::updateEditorStateAfterLayoutIfEditabilityChanged()
{
    // FIXME: We should update EditorStateIsContentEditable to track whether the state is richly
    // editable or plainttext-only.
    if (m_lastEditorStateWasContentEditable == EditorStateIsContentEditable::Unset)
        return;

    if (hasPendingEditorStateUpdate())
        return;

    RefPtr frame = corePage()->focusController().focusedOrMainFrame();
    if (!frame)
        return;

    auto isEditable = frame->selection().selection().hasEditableStyle() ? EditorStateIsContentEditable::Yes : EditorStateIsContentEditable::No;
    if (m_lastEditorStateWasContentEditable != isEditable)
        scheduleFullEditorStateUpdate();
}

static OptionSet<RenderAsTextFlag> NODELETE toRenderAsTextFlags(unsigned options)
{
    OptionSet<RenderAsTextFlag> flags;

    if (options & RenderTreeShowAllLayers)
        flags.add(RenderAsTextFlag::ShowAllLayers);
    if (options & RenderTreeShowLayerNesting)
        flags.add(RenderAsTextFlag::ShowLayerNesting);
    if (options & RenderTreeShowCompositedLayers)
        flags.add(RenderAsTextFlag::ShowCompositedLayers);
    if (options & RenderTreeShowOverflow)
        flags.add(RenderAsTextFlag::ShowOverflow);
    if (options & RenderTreeShowSVGGeometry)
        flags.add(RenderAsTextFlag::ShowSVGGeometry);
    if (options & RenderTreeShowLayerFragments)
        flags.add(RenderAsTextFlag::ShowLayerFragments);

    return flags;
}

String WebPage::renderTreeExternalRepresentation(unsigned options) const
{
    return externalRepresentation(protect(m_mainFrame->coreLocalFrame()).get(), toRenderAsTextFlags(options));
}

String WebPage::renderTreeExternalRepresentationForPrinting() const
{
    return externalRepresentation(protect(m_mainFrame->coreLocalFrame()).get(), { RenderAsTextFlag::PrintingMode });
}

uint64_t WebPage::renderTreeSize() const
{
    if (RefPtr page = m_page)
        return page->renderTreeSize();
    return 0;
}

void WebPage::setHasResourceLoadClient(bool has)
{
    if (m_page)
        m_page->setHasResourceLoadClient(has);
}

void WebPage::setCanUseCredentialStorage(bool has)
{
    if (m_page)
        m_page->setCanUseCredentialStorage(has);
}

bool WebPage::isTrackingRepaints() const
{
    if (RefPtr view = localMainFrameView())
        return view->isTrackingRepaints();

    return false;
}

Ref<API::Array> WebPage::trackedRepaintRects()
{
    RefPtr view = localMainFrameView();
    if (!view)
        return API::Array::create();

    auto repaintRects = view->trackedRepaintRects().map([](auto& repaintRect) -> RefPtr<API::Object> {
        return API::Rect::create(toAPI(repaintRect));
    });
    return API::Array::create(WTF::move(repaintRects));
}

#if ENABLE(PDF_PLUGIN)

PluginView* WebPage::focusedPluginViewForFrame(LocalFrame& frame)
{
    auto* pluginDocument = dynamicDowncast<PluginDocument>(frame.document());
    if (!pluginDocument)
        return nullptr;

    if (pluginDocument->focusedElement() != pluginDocument->pluginElement())
        return nullptr;

    return pluginViewForFrame(&frame);
}

PluginView* WebPage::pluginViewForFrame(LocalFrame* frame)
{
    if (!frame)
        return nullptr;
    auto* document = dynamicDowncast<PluginDocument>(frame->document());
    if (!document)
        return nullptr;
    return downcast<PluginView>(document->pluginWidget());
}

PluginView* WebPage::mainFramePlugIn() const
{
    RefPtr localMainFrame = this->localMainFrame();
    return pluginViewForFrame(localMainFrame.get());
}

#endif

void WebPage::executeEditingCommand(const String& commandName, const String& argument)
{
    platformWillPerformEditingCommand();

    RefPtr frame = corePage()->focusController().focusedOrMainFrame();
    if (!frame)
        return;

#if ENABLE(PDF_PLUGIN)
    if (RefPtr pluginView = focusedPluginViewForFrame(*frame)) {
        pluginView->handleEditingCommand(commandName, argument);
        return;
    }
#endif

    protect(frame->editor())->command(commandName).execute(argument);
}

void WebPage::setEditable(bool editable)
{
    protect(corePage())->setEditable(editable);
    corePage()->setTabKeyCyclesThroughElements(!editable);
    RefPtr frame = corePage()->focusController().focusedOrMainFrame();
    if (!frame)
        return;

    if (editable) {
        protect(frame->editor())->applyEditingStyleToBodyElement();
        // If the page is made editable and the selection is empty, set it to something.
        if (frame->selection().isNone())
            protect(frame->selection())->setSelectionFromNone();
    }
}

void WebPage::increaseListLevel()
{
    RefPtr frame = corePage()->focusController().focusedOrMainFrame();
    if (!frame)
        return;

    protect(frame->editor())->increaseSelectionListLevel();
}

void WebPage::decreaseListLevel()
{
    RefPtr frame = corePage()->focusController().focusedOrMainFrame();
    if (!frame)
        return;

    protect(frame->editor())->decreaseSelectionListLevel();
}

void WebPage::changeListType()
{
    RefPtr frame = corePage()->focusController().focusedOrMainFrame();
    if (!frame)
        return;

    protect(frame->editor())->changeSelectionListType();
}

void WebPage::setBaseWritingDirection(WritingDirection direction)
{
    RefPtr frame = corePage()->focusController().focusedOrMainFrame();
    if (!frame)
        return;

    protect(frame->editor())->setBaseWritingDirection(direction);
}

void WebPage::enterAcceleratedCompositingMode(WebCore::Frame& frame, GraphicsLayer* layer)
{
    protect(drawingArea())->setRootCompositingLayer(frame, layer);
}

void WebPage::exitAcceleratedCompositingMode(WebCore::Frame& frame)
{
    protect(drawingArea())->setRootCompositingLayer(frame, nullptr);
}

void WebPage::close()
{
    if (m_isClosed)
        return;

    flushDeferredDidReceiveMouseEvent();

    WEBPAGE_RELEASE_LOG_FORWARDABLE(Loading, WebPageClose);

    if (RefPtr networkProcessConnection = WebProcess::singleton().existingNetworkProcessConnection())
        networkProcessConnection->connection().send(Messages::NetworkConnectionToWebProcess::ClearPageSpecificData(m_identifier), 0);

    m_isClosed = true;

    // If there is still no URL, then we never loaded anything in this page, so nothing to report.
    if (!m_mainFrame->url().isEmpty())
        reportUsedFeatures();

    if (WebProcess::singleton().injectedBundle())
        WebProcess::singleton().injectedBundle()->willDestroyPage(Ref { *this });

    if (RefPtr inspector = std::exchange(m_inspector, nullptr))
        inspector->disconnectFromPage();

    m_page->inspectorController().disconnectAllFrontends();

#if ENABLE(FULLSCREEN_API)
    if (auto manager = std::exchange(m_fullScreenManager, { }))
        manager->invalidate();
#endif

    if (RefPtr activePopupMenu = std::exchange(m_activePopupMenu, nullptr))
        activePopupMenu->disconnectFromPage();

    if (RefPtr activeOpenPanelResultListener = std::exchange(m_activeOpenPanelResultListener, nullptr))
        activeOpenPanelResultListener->disconnectFromPage();

    if (auto* activeColorChooser = m_activeColorChooser.get()) {
        activeColorChooser->disconnectFromPage();
        m_activeColorChooser = nullptr;
    }

#if PLATFORM(GTK)
    m_printOperation = nullptr;
#endif

    m_sandboxExtensionTracker.invalidate();

#if ENABLE(TEXT_AUTOSIZING)
    m_textAutoSizingAdjustmentTimer.stop();
#endif

#if PLATFORM(IOS_FAMILY)
    invokePendingSyntheticClickCallback(SyntheticClickResult::PageInvalid);
    m_updateFocusedElementInformationTimer.stop();
#endif

#if ENABLE(CONTEXT_MENUS)
    m_contextMenuClient = makeUnique<API::InjectedBundle::PageContextMenuClient>();
#endif
    m_editorClient = makeUnique<API::InjectedBundle::EditorClient>();
    m_formClient = makeUnique<API::InjectedBundle::FormClient>();
    m_loaderClient = makeUnique<API::InjectedBundle::PageLoaderClient>();
    m_resourceLoadClient = makeUnique<API::InjectedBundle::ResourceLoadClient>();
    m_uiClient = makeUnique<API::InjectedBundle::PageUIClient>();

    m_printContext = nullptr;
    if (RefPtr localFrame = m_mainFrame->coreLocalFrame())
        localFrame->loader().detachFromParent();

    if (RefPtr provisionalFrame = m_mainFrame->provisionalFrame())
        provisionalFrame->loader().detachFromParent();

#if ENABLE(SCROLLING_THREAD)
    if (m_useAsyncScrolling)
        protect(drawingArea())->unregisterScrollingTree();
#endif

    protect(corePage())->destroyRenderTrees();

    m_drawingArea = nullptr;
    m_webPageTesting = nullptr;
    m_page = nullptr;

    bool isRunningModal = m_isRunningModal;
    m_isRunningModal = false;

#if PLATFORM(COCOA)
    if (RefPtr remoteObjectRegistry = m_remoteObjectRegistry.get())
        remoteObjectRegistry->close();
    ASSERT(!m_remoteObjectRegistry);
#endif

    auto& webProcess = WebProcess::singleton();
    webProcess.removeMessageReceiver(Messages::WebPage::messageReceiverName(), m_identifier);
    // FIXME: This should be done in the object destructors, and the objects themselves should be message receivers.
    webProcess.removeMessageReceiver(Messages::WebInspectorBackend::messageReceiverName(), m_identifier);
    webProcess.removeMessageReceiver(Messages::WebInspectorUI::messageReceiverName(), m_identifier);
    webProcess.removeMessageReceiver(Messages::RemoteWebInspectorUI::messageReceiverName(), m_identifier);
#if ENABLE(FULLSCREEN_API)
    webProcess.removeMessageReceiver(Messages::WebFullScreenManager::messageReceiverName(), m_identifier);
#endif
#if PLATFORM(COCOA) || PLATFORM(GTK)
    m_viewGestureGeometryCollector = nullptr;
#endif

    stopObservingNowPlayingMetadata();

    String processDisplayName = m_processDisplayName;

    // The WebPage can be destroyed by this call.
    WebProcess::singleton().removeWebPage(m_identifier);

    WebProcess::singleton().updateActivePages(processDisplayName);

    if (isRunningModal)
        RunLoop::mainSingleton().stop();
}

void WebPage::tryClose(CompletionHandler<void(bool)>&& completionHandler)
{
    RefPtr coreFrame = m_mainFrame->coreLocalFrame();
    if (!coreFrame) {
        completionHandler(false);
        return;
    }
    completionHandler(coreFrame->loader().shouldClose());
}

void WebPage::sendClose()
{
    send(Messages::WebPageProxy::ClosePage());
}

void WebPage::suspendForProcessSwap(CompletionHandler<void(std::optional<bool>)>&& completionHandler)
{
    flushDeferredDidReceiveMouseEvent();

    // FIXME: Make this work if the main frame is not a LocalFrame.
    RefPtr currentHistoryItem = m_mainFrame->coreLocalFrame()->loader().history().currentItem();
    if (!currentHistoryItem)
        return completionHandler(false);

    if (!BackForwardCache::singleton().addIfCacheable(*currentHistoryItem, protect(corePage()).get()))
        return completionHandler(false);

    // Back/forward cache does not break the opener link for the main frame (only does so for the subframes) because the
    // main frame is normally re-used for the navigation. However, in the case of process-swapping, the main frame
    // is now hosted in another process and the one in this process is in the cache.
    if (RefPtr frame = m_mainFrame->coreLocalFrame())
        frame->detachFromAllOpenedFrames();

    completionHandler(true);
}

void WebPage::loadURLInFrame(URL&& url, const String& referrer, FrameIdentifier frameID)
{
    RefPtr frame = WebProcess::singleton().webFrame(frameID);
    if (!frame)
        return;

    RefPtr coreLocalFrame = frame->coreLocalFrame();
    coreLocalFrame->loader().load(FrameLoadRequest(*coreLocalFrame, ResourceRequest(URL { url }, referrer)));
}

void WebPage::loadDataInFrame(std::span<const uint8_t> data, String&& type, String&& encodingName, URL&& baseURL, FrameIdentifier frameID)
{
    RefPtr frame = WebProcess::singleton().webFrame(frameID);
    if (!frame)
        return;
    ASSERT(&mainWebFrame() != frame);

    Ref sharedBuffer = SharedBuffer::create(data);
    ResourceResponse response(URL { baseURL }, WTF::move(type), sharedBuffer->size(), WTF::move(encodingName));
    SubstituteData substituteData(WTF::move(sharedBuffer), URL { baseURL }, WTF::move(response), SubstituteData::SessionHistoryVisibility::Hidden);
    frame->coreLocalFrame()->loader().load(FrameLoadRequest(*frame->coreLocalFrame(), ResourceRequest(WTF::move(baseURL)), WTF::move(substituteData)));
}

#if !PLATFORM(COCOA)
void WebPage::platformDidReceiveLoadParameters(const LoadParameters& loadParameters)
{
}
#endif

void WebPage::createProvisionalFrame(ProvisionalFrameCreationParameters&& parameters)
{
    RefPtr frame = WebProcess::singleton().webFrame(parameters.frameID);
    if (!frame)
        return;
    ASSERT(frame->page() == this);
    frame->createProvisionalFrame(WTF::move(parameters));
}

void WebPage::loadDidCommitInAnotherProcess(WebCore::FrameIdentifier frameID, std::optional<WebCore::LayerHostingContextIdentifier> layerHostingContextIdentifier, RefPtr<WebCore::DocumentSyncData>&& topDocumentSyncData)
{
    RefPtr frame = WebProcess::singleton().webFrame(frameID);
    if (!frame)
        return;
    ASSERT(frame->page() == this);
    frame->loadDidCommitInAnotherProcess(layerHostingContextIdentifier);

    if (topDocumentSyncData) {
        if (RefPtr page = corePage())
            page->updateTopDocumentSyncData(topDocumentSyncData.releaseNonNull());
    }
}

void WebPage::loadRequest(LoadParameters&& loadParameters)
{
    WEBPAGE_RELEASE_LOG_FORWARDABLE(Loading, WebPageLoadRequest, loadParameters.navigationID ? loadParameters.navigationID->toUInt64() : 0, static_cast<unsigned>(loadParameters.shouldTreatAsContinuingLoad), loadParameters.request.isAppInitiated(), loadParameters.existingNetworkResourceLoadIdentifierToResume ? loadParameters.existingNetworkResourceLoadIdentifierToResume->toUInt64() : 0);

    RefPtr frame = loadParameters.frameIdentifier ? WebProcess::singleton().webFrame(*loadParameters.frameIdentifier) : m_mainFrame.ptr();
    if (!frame) {
        ASSERT_NOT_REACHED();
        return;
    }
    RefPtr localFrame = frame->coreLocalFrame() ? frame->coreLocalFrame() : frame->provisionalFrame();
    if (!localFrame) {
        ASSERT_NOT_REACHED();
        return;
    }

    setLastNavigationWasAppInitiated(loadParameters.request.isAppInitiated());

#if ENABLE(APP_BOUND_DOMAINS)
    setIsNavigatingToAppBoundDomain(loadParameters.isNavigatingToAppBoundDomain, *frame);
#endif

    WebProcess::singleton().webLoaderStrategy().setExistingNetworkResourceLoadIdentifierToResume(loadParameters.existingNetworkResourceLoadIdentifierToResume);
    auto resumingLoadScope = makeScopeExit([] {
        WebProcess::singleton().webLoaderStrategy().setExistingNetworkResourceLoadIdentifierToResume(std::nullopt);
    });

    SendStopResponsivenessTimer stopper;

    m_pendingNavigationID = loadParameters.navigationID;
    m_internals->pendingWebsitePolicies = WTF::move(loadParameters.websitePolicies);

    m_sandboxExtensionTracker.beginLoad(WTF::move(loadParameters.sandboxExtensionHandle));

    // Let the InjectedBundle know we are about to start the load, passing the user data from the UIProcess
    // to all the client to set up any needed state.
    m_loaderClient->willLoadURLRequest(*this, loadParameters.request, WebProcess::singleton().transformHandlesToObjects(protect(loadParameters.userData.object()).get()).get());

    platformDidReceiveLoadParameters(loadParameters);

    if (loadParameters.originatingFrame && !loadParameters.frameIdentifier)
        m_mainFrameNavigationInitiator = makeUnique<FrameInfoData>(*loadParameters.originatingFrame);

    // Initate the load in WebCore.
    ASSERT(localFrame->document());
    FrameLoadRequest frameLoadRequest { *localFrame, WTF::move(loadParameters.request) };
    frameLoadRequest.setShouldOpenExternalURLsPolicy(loadParameters.shouldOpenExternalURLsPolicy);
    frameLoadRequest.setShouldTreatAsContinuingLoad(loadParameters.shouldTreatAsContinuingLoad);
    frameLoadRequest.setLockHistory(loadParameters.lockHistory);
    frameLoadRequest.setLockBackForwardList(loadParameters.lockBackForwardList);
    frameLoadRequest.setClientRedirectSourceForHistory(WTF::move(loadParameters.clientRedirectSourceForHistory));
    frameLoadRequest.setIsHandledByAboutSchemeHandler(loadParameters.isHandledByAboutSchemeHandler);
    if (loadParameters.isRequestFromClientOrUserInput)
        frameLoadRequest.setIsRequestFromClientOrUserInput();
    if (loadParameters.advancedPrivacyProtections)
        frameLoadRequest.setAdvancedPrivacyProtections(*loadParameters.advancedPrivacyProtections);
    if (loadParameters.originalRequest)
        frameLoadRequest.setOriginalResourceRequest(*loadParameters.originalRequest);

    if (loadParameters.effectiveSandboxFlags)
        localFrame->updateSandboxFlags(loadParameters.effectiveSandboxFlags, Frame::NotifyUIProcess::No);

    if (auto ownerPermissionsPolicy = std::exchange(loadParameters.ownerPermissionsPolicy, { }))
        localFrame->setOwnerPermissionsPolicy(WTF::move(*ownerPermissionsPolicy));

    localFrame->loader().setNavigationUpgradeToHTTPSBehavior(loadParameters.navigationUpgradeToHTTPSBehavior);
    localFrame->loader().setRequiredCookiesVersion(loadParameters.requiredCookiesVersion);

    std::optional<UserGestureIndicator> userGestureIndicator;
    if (loadParameters.hadUserGesture && loadParameters.shouldTreatAsContinuingLoad != ShouldTreatAsContinuingLoad::No)
        userGestureIndicator.emplace(IsProcessingUserGesture::Yes);

    localFrame->loader().load(WTF::move(frameLoadRequest), WTF::move(loadParameters.requester));

    ASSERT(!m_pendingNavigationID);
    ASSERT(!m_internals->pendingWebsitePolicies);
}

// LoadRequestWaitingForProcessLaunch should never be sent to the WebProcess. It must always be converted to a LoadRequest message.
void WebPage::loadRequestWaitingForProcessLaunch(LoadParameters&&, URL&&, WebPageProxyIdentifier, bool)
{
    RELEASE_ASSERT_NOT_REACHED();
}

void WebPage::loadDataImpl(std::optional<WebCore::NavigationIdentifier> navigationID, ShouldTreatAsContinuingLoad shouldTreatAsContinuingLoad, std::optional<WebsitePoliciesData>&& websitePolicies, Ref<FragmentedSharedBuffer>&& sharedBuffer, ResourceRequest&& request, ResourceResponse&& response, URL&& unreachableURL, const UserData& userData, std::optional<NavigatingToAppBoundDomain> isNavigatingToAppBoundDomain, SubstituteData::SessionHistoryVisibility sessionHistoryVisibility, ShouldOpenExternalURLsPolicy shouldOpenExternalURLsPolicy)
{
#if ENABLE(APP_BOUND_DOMAINS)
    Ref mainFrame = m_mainFrame.copyRef();
    setIsNavigatingToAppBoundDomain(isNavigatingToAppBoundDomain, mainFrame.get());
    mainFrame->setIsSafeBrowsingCheckOngoing(SafeBrowsingCheckOngoing::No);
#else
    UNUSED_PARAM(isNavigatingToAppBoundDomain);
#endif

    SendStopResponsivenessTimer stopper;

    m_pendingNavigationID = navigationID;
    m_internals->pendingWebsitePolicies = WTF::move(websitePolicies);

    SubstituteData substituteData(WTF::move(sharedBuffer), WTF::move(unreachableURL), WTF::move(response), sessionHistoryVisibility);

    // Let the InjectedBundle know we are about to start the load, passing the user data from the UIProcess
    // to all the client to set up any needed state.
    m_loaderClient->willLoadDataRequest(*this, request, substituteData.content(), substituteData.mimeType(), substituteData.textEncoding(), substituteData.failingURL(), WebProcess::singleton().transformHandlesToObjects(protect(userData.object()).get()).get());

    RefPtr localFrame = m_mainFrame->coreLocalFrame() ? m_mainFrame->coreLocalFrame() : m_mainFrame->provisionalFrame();
    if (!localFrame) {
        ASSERT_NOT_REACHED();
        return;
    }

    // Initate the load in WebCore.
    FrameLoadRequest frameLoadRequest(*localFrame, WTF::move(request), WTF::move(substituteData));
    frameLoadRequest.setShouldOpenExternalURLsPolicy(shouldOpenExternalURLsPolicy);
    frameLoadRequest.setShouldTreatAsContinuingLoad(shouldTreatAsContinuingLoad);
    frameLoadRequest.setIsRequestFromClientOrUserInput();
    localFrame->loader().load(WTF::move(frameLoadRequest));
}

void WebPage::loadData(LoadParameters&& loadParameters)
{
    WEBPAGE_RELEASE_LOG(Loading, "loadData: navigationID=%" PRIu64 ", shouldTreatAsContinuingLoad=%u", loadParameters.navigationID ? loadParameters.navigationID->toUInt64() : 0, static_cast<unsigned>(loadParameters.shouldTreatAsContinuingLoad));

    platformDidReceiveLoadParameters(loadParameters);

    RefPtr sharedBuffer = loadParameters.data;
    if (!sharedBuffer) {
        ASSERT_NOT_REACHED();
        return;
    }

    URL baseURL;
    if (loadParameters.baseURLString.isEmpty())
        baseURL = aboutBlankURL();
    else {
        baseURL = URL { WTF::move(loadParameters.baseURLString) };
        if (baseURL.isValid() && !baseURL.protocolIsInHTTPFamily())
            LegacySchemeRegistry::registerURLSchemeAsHandledBySchemeHandler(baseURL.protocol().toString());
    }

    if (loadParameters.isServiceWorkerLoad && corePage())
        corePage()->markAsServiceWorkerPage();

    ResourceResponse response(URL(), WTF::move(loadParameters.MIMEType), sharedBuffer->size(), WTF::move(loadParameters.encodingName));
    loadDataImpl(loadParameters.navigationID, loadParameters.shouldTreatAsContinuingLoad, WTF::move(loadParameters.websitePolicies), sharedBuffer.releaseNonNull(), ResourceRequest(WTF::move(baseURL)), WTF::move(response), URL(), loadParameters.userData, loadParameters.isNavigatingToAppBoundDomain, loadParameters.sessionHistoryVisibility, loadParameters.shouldOpenExternalURLsPolicy);
}

void WebPage::loadAlternateHTML(LoadParameters&& loadParameters)
{
    platformDidReceiveLoadParameters(loadParameters);

    URL baseURL = loadParameters.baseURLString.isEmpty() ? aboutBlankURL() : URL { WTF::move(loadParameters.baseURLString) };
    URL unreachableURL = loadParameters.unreachableURLString.isEmpty() ? URL() : URL { WTF::move(loadParameters.unreachableURLString) };
    URL provisionalLoadErrorURL = loadParameters.provisionalLoadErrorURLString.isEmpty() ? URL() : URL { WTF::move(loadParameters.provisionalLoadErrorURLString) };
    RefPtr sharedBuffer = loadParameters.data;
    if (!sharedBuffer) {
        ASSERT_NOT_REACHED();
        return;
    }
    m_mainFrame->coreLocalFrame()->loader().setProvisionalLoadErrorBeingHandledURL(provisionalLoadErrorURL);

    ResourceResponse response(URL(), WTF::move(loadParameters.MIMEType), sharedBuffer->size(), WTF::move(loadParameters.encodingName));
    loadDataImpl(loadParameters.navigationID, loadParameters.shouldTreatAsContinuingLoad, WTF::move(loadParameters.websitePolicies), sharedBuffer.releaseNonNull(), ResourceRequest(WTF::move(baseURL)), WTF::move(response), WTF::move(unreachableURL), loadParameters.userData, loadParameters.isNavigatingToAppBoundDomain, WebCore::SubstituteData::SessionHistoryVisibility::Hidden);
    m_mainFrame->coreLocalFrame()->loader().setProvisionalLoadErrorBeingHandledURL({ });
}

void WebPage::loadSimulatedRequestAndResponse(LoadParameters&& loadParameters, ResourceResponse&& simulatedResponse)
{
    setLastNavigationWasAppInitiated(loadParameters.request.isAppInitiated());
    RefPtr sharedBuffer = loadParameters.data;
    if (!sharedBuffer) {
        ASSERT_NOT_REACHED();
        return;
    }
    loadDataImpl(loadParameters.navigationID, loadParameters.shouldTreatAsContinuingLoad, WTF::move(loadParameters.websitePolicies), sharedBuffer.releaseNonNull(), WTF::move(loadParameters.request), WTF::move(simulatedResponse), URL(), loadParameters.userData, loadParameters.isNavigatingToAppBoundDomain, SubstituteData::SessionHistoryVisibility::Visible);
}

void WebPage::stopLoading()
{
    if (!m_page || !m_mainFrame->coreLocalFrame())
        return;

    SendStopResponsivenessTimer stopper;

    Ref coreFrame = *m_mainFrame->coreLocalFrame();
    coreFrame->loader().stopForUserCancel();
    coreFrame->loader().completePageTransitionIfNeeded();
}

void WebPage::stopLoadingDueToProcessSwap()
{
    SetForScope isStoppingLoadingDueToProcessSwap(m_isStoppingLoadingDueToProcessSwap, true);
    stopLoading();
}

void WebPage::keepBlobURLAliveForNewWindowNavigation(URL&& blobURL, std::optional<SecurityOriginData>&& topOrigin)
{
    m_blobURLLifetimeExtensionForNewWindowNavigation = URLKeepingBlobAlive(blobURL, topOrigin);
}

void WebPage::releaseKeptBlobURLForNewWindowNavigation()
{
    m_blobURLLifetimeExtensionForNewWindowNavigation.clear();
}

bool WebPage::defersLoading() const
{
    return m_page->defersLoading();
}

void WebPage::reload(WebCore::NavigationIdentifier navigationID, OptionSet<WebCore::ReloadOption> reloadOptions, SandboxExtension::Handle&& sandboxExtensionHandle)
{
    SendStopResponsivenessTimer stopper;

    ASSERT(!m_mainFrame->coreLocalFrame()->loader().frameHasLoaded() || !m_pendingNavigationID);
    m_pendingNavigationID = navigationID;

    Ref mainFrame = m_mainFrame;
    m_sandboxExtensionTracker.beginReload(mainFrame.ptr(), WTF::move(sandboxExtensionHandle));
    if (m_page && mainFrame->coreLocalFrame()) {
        bool isRequestFromClientOrUserInput = true;
        mainFrame->coreLocalFrame()->loader().reload(reloadOptions, isRequestFromClientOrUserInput);
    } else
        ASSERT_NOT_REACHED();

    if (m_pendingNavigationID) {
        // This can happen if FrameLoader::reload() returns early because the document URL is empty.
        // The reload does nothing so we need to reset the pending navigation. See webkit.org/b/153210.
        m_pendingNavigationID = std::nullopt;
    }
}

void WebPage::goToBackForwardItem(GoToBackForwardItemParameters&& parameters)
{
    WEBPAGE_RELEASE_LOG(Loading, "goToBackForwardItem: navigationID=%" PRIu64 ", backForwardItemID=%s, shouldTreatAsContinuingLoad=%u, lastNavigationWasAppInitiated=%d, existingNetworkResourceLoadIdentifierToResume=%" PRIu64, parameters.navigationID.toUInt64(), parameters.frameState->itemID->toString().utf8().data(), static_cast<unsigned>(parameters.shouldTreatAsContinuingLoad), parameters.lastNavigationWasAppInitiated, parameters.existingNetworkResourceLoadIdentifierToResume ? parameters.existingNetworkResourceLoadIdentifierToResume->toUInt64() : 0);
    SendStopResponsivenessTimer stopper;

    m_sandboxExtensionTracker.beginLoad(WTF::move(parameters.sandboxExtensionHandle));

    m_lastNavigationWasAppInitiated = parameters.lastNavigationWasAppInitiated;
    if (auto* localMainFrame = corePage()->localMainFrame()) {
        if (auto* documentLoader = localMainFrame->loader().documentLoader())
            documentLoader->setLastNavigationWasAppInitiated(parameters.lastNavigationWasAppInitiated);
    }

    WebProcess::singleton().webLoaderStrategy().setExistingNetworkResourceLoadIdentifierToResume(parameters.existingNetworkResourceLoadIdentifierToResume);
    auto resumingLoadScope = makeScopeExit([] {
        WebProcess::singleton().webLoaderStrategy().setExistingNetworkResourceLoadIdentifierToResume(std::nullopt);
    });

    ASSERT(isBackForwardLoadType(parameters.backForwardType));

    RefPtr<HistoryItem> item;
    {
        auto ignoreHistoryItemChangesForScope = m_historyItemClient->ignoreChangesForScope();
        ASSERT(!corePage()->settings().useUIProcessForBackForwardItemLoading() || parameters.frameState->children.isEmpty());
        item = toHistoryItem(m_historyItemClient, parameters.frameState);
        if (RefPtr localMainFrame = corePage()->localMainFrame(); localMainFrame && item)
            localMainFrame->loader().setNavigationUpgradeToHTTPSBehavior(item->url().protocolIs("http"_s) ? NavigationUpgradeToHTTPSBehavior::Disabled : NavigationUpgradeToHTTPSBehavior::BasedOnPolicy);
    }

    LOG(Loading, "In WebProcess pid %i, WebPage %" PRIu64 " is navigating to back/forward URL %s", getCurrentProcessID(), m_identifier.toUInt64(), item->url().string().utf8().data());

#if PLATFORM(COCOA)
    WebCore::PublicSuffixStore::singleton().addPublicSuffix(parameters.publicSuffix);
#endif

    m_pendingNavigationID = parameters.navigationID;
    m_internals->pendingWebsitePolicies = WTF::move(parameters.websitePolicies);

    Ref targetFrame = m_mainFrame;
    if (RefPtr historyItemFrame = WebProcess::singleton().webFrame(item->frameID()); historyItemFrame && historyItemFrame->page() == this)
        targetFrame = historyItemFrame.releaseNonNull();

    if (RefPtr targetLocalFrame = targetFrame->provisionalFrame() ? targetFrame->provisionalFrame() : targetFrame->coreLocalFrame()) {
        if (!targetLocalFrame->loader().shouldProceedWithAsyncBackForwardNavigation()) {
            WEBPAGE_RELEASE_LOG(Loading, "goToBackForwardItem: Skipping because pending async back/forward traversal was cancelled");
            return;
        }
        protect(corePage())->goToItem(*targetLocalFrame, *item, parameters.backForwardType, parameters.shouldTreatAsContinuingLoad);
    }
}

// GoToBackForwardItemWaitingForProcessLaunch should never be sent to the WebProcess. It must always be converted to a GoToBackForwardItem message.
void WebPage::goToBackForwardItemWaitingForProcessLaunch(GoToBackForwardItemParameters&&, WebKit::WebPageProxyIdentifier)
{
    RELEASE_ASSERT_NOT_REACHED();
}

void WebPage::tryRestoreScrollPosition()
{
    if (RefPtr localMainFrame = this->localMainFrame())
        localMainFrame->loader().history().restoreScrollPositionAndViewState();
}

WebPage* WebPage::fromCorePage(Page& page)
{
    auto& client = page.chrome().client();
    return client.isEmptyChromeClient() ? nullptr : downcast<WebChromeClient>(client).page();
}

void WebPage::setSize(const WebCore::IntSize& viewSize)
{
    if (m_viewSize == viewSize)
        return;

    m_viewSize = viewSize;
    RefPtr view = protect(protect(corePage())->mainFrame())->virtualView();
    if (!view) {
        ASSERT_NOT_REACHED();
        return;
    }

    view->resize(viewSize);
    protect(drawingArea())->setNeedsDisplay();

#if ENABLE(ACCESSIBILITY_ISOLATED_TREE)
    cacheAXSize(m_viewSize);
#endif
}

void WebPage::drawRect(GraphicsContext& graphicsContext, const IntRect& rect)
{
#if PLATFORM(MAC)
    RefPtr localMainFrame = this->localMainFrame();
    if (!localMainFrame)
        return;
    RefPtr mainFrameView = localMainFrame->view();
    LocalDefaultSystemAppearance localAppearance(mainFrameView && mainFrameView->useDarkAppearance());
#endif

    GraphicsContextStateSaver stateSaver(graphicsContext);
    graphicsContext.clip(rect);

    protect(m_mainFrame->coreLocalFrame()->view())->paint(graphicsContext, rect);

#if PLATFORM(GTK) || PLATFORM(WIN) || PLATFORM(PLAYSTATION) || PLATFORM(WPE)
    if (!m_page->settings().acceleratedCompositingEnabled() && m_page->inspectorController().enabled() && m_page->inspectorController().shouldShowOverlay()) {
        graphicsContext.beginTransparencyLayer(1);
        m_page->inspectorController().drawHighlight(graphicsContext);
        graphicsContext.endTransparencyLayer();
    }
#endif
}

double WebPage::textZoomFactor() const
{
#if ENABLE(PDF_PLUGIN)
    if (RefPtr pluginView = mainFramePlugIn(); pluginView && pluginView->pluginHandlesPageScaleFactor())
        return pluginView->pageScaleFactor();
#endif

    RefPtr frame = m_mainFrame->coreLocalFrame();
    if (!frame)
        return 1;
    return frame->textZoomFactor();
}

void WebPage::didSetTextZoomFactor(double zoomFactor)
{
#if ENABLE(PDF_PLUGIN)
    if (RefPtr pluginView = mainFramePlugIn(); pluginView && pluginView->pluginHandlesPageScaleFactor())
        return pluginView->setPageScaleFactor(zoomFactor, std::nullopt);
#endif

    if (!m_page)
        return;

    for (WeakRef frame : m_page->rootFrames())
        frame->setTextZoomFactor(static_cast<float>(zoomFactor));
}

double WebPage::pageZoomFactor() const
{
#if ENABLE(PDF_PLUGIN)
    if (RefPtr pluginView = mainFramePlugIn(); pluginView && pluginView->pluginHandlesPageScaleFactor()) {
        // Note that this maps page *scale* factor to page *zoom* factor.
        return pluginView->pageScaleFactor();
    }
#endif

    RefPtr frame = m_mainFrame->coreLocalFrame();
    if (!frame)
        return 1;
    return frame->pageZoomFactor();
}

void WebPage::didSetPageZoomFactor(double zoomFactor)
{
#if ENABLE(PDF_PLUGIN)
    if (RefPtr pluginView = mainFramePlugIn(); pluginView && pluginView->pluginHandlesPageScaleFactor()) {
        // Note that this maps page *zoom* factor to page *scale* factor.
        pluginView->setPageScaleFactor(zoomFactor, std::nullopt);
        return;
    }
#endif

    if (!m_page)
        return;

    for (WeakRef frame : m_page->rootFrames())
        frame->setPageZoomFactor(static_cast<float>(zoomFactor));
}

static void dumpHistoryItem(HistoryItem& item, size_t indent, bool isCurrentItem, StringBuilder& stringBuilder, const String& directoryName)
{
    if (isCurrentItem)
        stringBuilder.append("curr->  "_s);
    else {
        for (size_t i = 0; i < indent; ++i)
            stringBuilder.append(' ');
    }

    auto url = item.url();
    if (url.protocolIsFile()) {
        size_t start = url.string().find(directoryName);
        if (start == WTF::notFound)
            start = 0;
        else
            start += directoryName.length();
        stringBuilder.append("(file test):"_s, StringView { url.string() }.substring(start));
    } else
        stringBuilder.append(url.string());

    auto& target = item.target();
    if (target.length())
        stringBuilder.append(" (in frame \""_s, target, "\")"_s);

    stringBuilder.append('\n');

    auto children = item.children();
    std::ranges::stable_sort(children, [](auto& a, auto& b) {
        return codePointCompare(a->target(), b->target()) < 0;
    });
    for (auto& child : children)
        dumpHistoryItem(child, indent + 4, false, stringBuilder, directoryName);
}

String WebPage::dumpHistoryForTesting(const String& directory)
{
    if (!m_page)
        return { };

    CheckedRef list = m_page->backForward();

    StringBuilder builder;
    int begin = -list->backCount();
    if (list->itemAtIndex(begin)->url() == aboutBlankURL())
        ++begin;
    for (int i = begin; i <= static_cast<int>(list->forwardCount()); ++i)
        dumpHistoryItem(*list->itemAtIndex(i), 8, !i, builder, directory);
    return builder.toString();
}

String WebPage::frameTextForTestingIncludingSubframes(bool includeSubframes)
{
    return m_mainFrame->frameTextForTesting(includeSubframes);
}

void WebPage::windowScreenDidChange(PlatformDisplayID displayID, std::optional<unsigned> nominalFramesPerSecond)
{
    m_page->chrome().windowScreenDidChange(displayID, nominalFramesPerSecond);

#if PLATFORM(MAC)
    WebProcess::singleton().updatePageScreenProperties();
#endif
}

void WebPage::didScalePage(double scale, const IntPoint& origin)
{
    double totalScale = scale * viewScaleFactor();
    bool willChangeScaleFactor = totalScale != totalScaleFactor();
    auto platformDidScalePageIfNeeded = makeScopeExit([willChangeScaleFactor, this, protectedThis = Ref { *this }] {
        if (willChangeScaleFactor)
            platformDidScalePage();
    });

#if PLATFORM(IOS_FAMILY)
    if (willChangeScaleFactor) {
        if (!m_inDynamicSizeUpdate)
            m_internals->dynamicSizeUpdateHistory.clear();
        m_scaleWasSetByUIProcess = false;
    }
#endif

    RefPtr page = m_page;
#if ENABLE(PDF_PLUGIN)
    if (RefPtr pluginView = mainFramePlugIn(); pluginView && pluginView->pluginHandlesPageScaleFactor()) {
        // Whenever the PDF plug-in handles the page scale factor, make sure to reset WebCore's page scale.
        // Otherwise, we can end up with an immutable but non-1 page scale applied by WebCore on top of whatever the plugin does.
        if (page->pageScaleFactor() != 1)
            page->setPageScaleFactor(1, origin);
        pluginView->setPageScaleFactor(totalScale, { origin });
        return;
    }
#endif

    page->setPageScaleFactor(totalScale, origin);

    // We can't early return before setPageScaleFactor because the origin might be different.
    if (!willChangeScaleFactor)
        return;

#if ENABLE(PDF_PLUGIN)
    for (Ref pluginView : m_pluginViews) {
        if (pluginView->pluginHandlesPageScaleFactor())
            pluginView->setPageScaleFactor(totalScale, { origin });
    }
#endif
}

void WebPage::didScalePageInViewCoordinates(double scale, const IntPoint& origin)
{
    RefPtr frameView = localMainFrameView();
    if (!frameView)
        return;
    auto adjustedOrigin = frameView->rootViewToContents(-origin);
    double scaleRatio = scale / pageScaleFactor();
    adjustedOrigin.scale(scaleRatio);

    didScalePage(scale, adjustedOrigin);
}

void WebPage::didScalePageRelativeToScrollPosition(double scale, const IntPoint& origin)
{
    RefPtr frameView = localMainFrameView();
    if (!frameView)
        return;
    auto unscrolledOrigin = origin;
    IntRect unobscuredContentRect = frameView->unobscuredContentRectIncludingScrollbars();
    unscrolledOrigin.moveBy(-unobscuredContentRect.location());

    didScalePage(scale, -unscrolledOrigin);
}

#if !PLATFORM(IOS_FAMILY)

void WebPage::platformDidScalePage()
{
}

#endif

void WebPage::scalePage(double scale, const IntPoint& origin)
{
    didScalePage(scale, origin);
    send(Messages::WebPageProxy::PageScaleFactorDidChange(scale));
}

double WebPage::totalScaleFactor() const
{
#if ENABLE(PDF_PLUGIN)
    if (RefPtr pluginView = mainFramePlugIn(); pluginView && pluginView->pluginHandlesPageScaleFactor())
        return pluginView->pageScaleFactor();
#endif
    return m_page->pageScaleFactor();
}

double WebPage::pageScaleFactor() const
{
    return totalScaleFactor() / viewScaleFactor();
}

double WebPage::viewScaleFactor() const
{
    return m_page->viewScaleFactor();
}

void WebPage::didScaleView(double scale)
{
    if (viewScaleFactor() == scale)
        return;

    float pageScale = pageScaleFactor();

    RefPtr page = m_page;
    IntPoint scrollPositionAtNewScale;
    if (RefPtr mainFrameView = protect(page->mainFrame())->virtualView()) {
        double scaleRatio = scale / viewScaleFactor();
        scrollPositionAtNewScale = mainFrameView->scrollPosition();
        scrollPositionAtNewScale.scale(scaleRatio);
    }

    page->setViewScaleFactor(scale);
    didScalePage(pageScale, scrollPositionAtNewScale);
}

void WebPage::scaleView(double scale)
{
    if (scale == viewScaleFactor())
        return;
    didScaleView(scale);
    send(Messages::WebPageProxy::ViewScaleFactorDidChange(scale));
}

void WebPage::setDeviceScaleFactor(float scaleFactor)
{
    RefPtr page = m_page;
    if (scaleFactor == page->deviceScaleFactor())
        return;

    page->setDeviceScaleFactor(scaleFactor);

    // Tell all our plug-in views that the device scale factor changed.
#if PLATFORM(MAC)
    for (Ref pluginView : m_pluginViews)
        pluginView->setDeviceScaleFactor(scaleFactor);

    updateHeaderAndFooterLayersForDeviceScaleChange(scaleFactor);
#endif

#if USE(SKIA)
    FontRenderOptions::singleton().setUseSubpixelPositioning(scaleFactor >= 2.);
#endif

    if (findController().isShowingOverlay()) {
        // We must have updated layout to get the selection rects right.
        layoutIfNeeded();
        findController().deviceScaleFactorDidChange();
    }
}

float WebPage::deviceScaleFactor() const
{
    return m_page->deviceScaleFactor();
}

void WebPage::accessibilitySettingsDidChange()
{
    protect(corePage())->accessibilitySettingsDidChange();
}

void WebPage::inheritAccessibilityMode(WebCore::AccessibilityMode mode)
{
    if (WebCore::isAccessibilityModeOff(mode)) {
        // Accessibility may already be enabled process-wide (e.g. a prior
        // WebPage in this process received a non-Off mode, or
        // shouldForceAccessibilityEnabled() triggered enableAccessibility).
        // Receiving Off for a new page is normal in that case — just no-op.
        //
        // In the future, we may add a way to disable accessibility in
        // production (i.e. the user turns off their AT), in which case
        // this function will need to change.
        return;
    }

    auto forceAXThreadMode = mode == WebCore::AccessibilityMode::AXThread
        ? WebCore::AXObjectCache::ForceAXThreadMode::Yes
        : WebCore::AXObjectCache::ForceAXThreadMode::No;

    WebCore::AXObjectCache::enableAccessibility(forceAXThreadMode);
}

void WebPage::screenPropertiesDidChange(bool affectsStyle)
{
    protect(corePage())->screenPropertiesDidChange(affectsStyle);
}

void WebPage::setUseFixedLayout(bool fixed)
{
    // Do not overwrite current settings if initially setting it to false.
    if (m_useFixedLayout == fixed)
        return;
    m_useFixedLayout = fixed;

#if !PLATFORM(IOS_FAMILY)
    m_page->settings().setFixedElementsLayoutRelativeToFrame(fixed);
#endif

    RefPtr view = localMainFrameView();
    if (!view)
        return;

    view->setUseFixedLayout(fixed);
    if (!fixed)
        setFixedLayoutSize(IntSize());

    send(Messages::WebPageProxy::UseFixedLayoutDidChange(fixed));
}

bool WebPage::setFixedLayoutSize(const IntSize& size)
{
    RefPtr view = localMainFrameView();
    if (!view || view->fixedLayoutSize() == size)
        return false;

    LOG_WITH_STREAM(VisibleRects, stream << "WebPage " << m_identifier.toUInt64() << " setFixedLayoutSize " << size);
    view->setFixedLayoutSize(size);

    send(Messages::WebPageProxy::FixedLayoutSizeDidChange(size));
    return true;
}

IntSize WebPage::fixedLayoutSize() const
{
    RefPtr view = localMainFrameView();
    if (!view)
        return IntSize();
    return view->fixedLayoutSize();
}

void WebPage::setDefaultUnobscuredSize(const FloatSize& defaultUnobscuredSize)
{
    if (defaultUnobscuredSize == m_defaultUnobscuredSize)
        return;

    m_defaultUnobscuredSize = defaultUnobscuredSize;

    updateSizeForCSSDefaultViewportUnits();
}

void WebPage::updateSizeForCSSDefaultViewportUnits()
{
    RefPtr mainFrameView = this->localMainFrameView();
    if (!mainFrameView)
        return;

    auto defaultUnobscuredSize = m_defaultUnobscuredSize;
#if ENABLE(META_VIEWPORT)
    if (defaultUnobscuredSize.isEmpty())
        defaultUnobscuredSize = m_viewportConfiguration.viewLayoutSize();
    defaultUnobscuredSize.scale(1 / m_viewportConfiguration.initialScaleIgnoringContentSize());
#endif
    mainFrameView->setSizeForCSSDefaultViewportUnits(defaultUnobscuredSize);
}

void WebPage::setMinimumUnobscuredSize(const FloatSize& minimumUnobscuredSize)
{
    if (minimumUnobscuredSize == m_minimumUnobscuredSize)
        return;

    m_minimumUnobscuredSize = minimumUnobscuredSize;

    updateSizeForCSSSmallViewportUnits();
}

void WebPage::updateSizeForCSSSmallViewportUnits()
{
    RefPtr mainFrameView = this->localMainFrameView();
    if (!mainFrameView)
        return;

    auto minimumUnobscuredSize = m_minimumUnobscuredSize;
#if ENABLE(META_VIEWPORT)
    if (minimumUnobscuredSize.isEmpty())
        minimumUnobscuredSize = m_viewportConfiguration.viewLayoutSize();
    minimumUnobscuredSize.scale(1 / m_viewportConfiguration.initialScaleIgnoringContentSize());
#endif
    mainFrameView->setSizeForCSSSmallViewportUnits(minimumUnobscuredSize);
}

void WebPage::setMaximumUnobscuredSize(const FloatSize& maximumUnobscuredSize)
{
    if (maximumUnobscuredSize == m_maximumUnobscuredSize)
        return;

    m_maximumUnobscuredSize = maximumUnobscuredSize;

    updateSizeForCSSLargeViewportUnits();
}

void WebPage::updateSizeForCSSLargeViewportUnits()
{
    RefPtr mainFrameView = this->localMainFrameView();
    if (!mainFrameView)
        return;

    auto maximumUnobscuredSize = m_maximumUnobscuredSize;
#if ENABLE(META_VIEWPORT)
    if (maximumUnobscuredSize.isEmpty())
        maximumUnobscuredSize = m_viewportConfiguration.viewLayoutSize();
    maximumUnobscuredSize.scale(1 / m_viewportConfiguration.initialScaleIgnoringContentSize());
#endif
    mainFrameView->setSizeForCSSLargeViewportUnits(maximumUnobscuredSize);
}

void WebPage::disabledAdaptationsDidChange(const OptionSet<DisabledAdaptations>& disabledAdaptations)
{
#if PLATFORM(IOS_FAMILY)
    if (m_viewportConfiguration.setDisabledAdaptations(disabledAdaptations))
        viewportConfigurationChanged();
#else
    UNUSED_PARAM(disabledAdaptations);
#endif
}

void WebPage::viewportPropertiesDidChange(const ViewportArguments& viewportArguments)
{
#if PLATFORM(IOS_FAMILY)
    if (m_viewportConfiguration.setViewportArguments(viewportArguments))
        viewportConfigurationChanged();
#elif PLATFORM(GTK) || PLATFORM(WPE)
    // Adjust view dimensions when using fixed layout.
    RefPtr localMainFrame = this->localMainFrame();
    RefPtr view = localMainFrame ? localMainFrame->view() : nullptr;
    if (view && view->useFixedLayout() && !m_viewSize.isEmpty()) {
        Settings& settings = m_page->settings();
        int deviceWidth = (settings.deviceWidth() > 0) ? settings.deviceWidth() : m_viewSize.width();
        int deviceHeight = (settings.deviceHeight() > 0) ? settings.deviceHeight() : m_viewSize.height();
        int minimumLayoutFallbackWidth = std::max<int>(settings.layoutFallbackWidth(), m_viewSize.width());
        ViewportAttributes attr = computeViewportAttributes(viewportArguments, minimumLayoutFallbackWidth, deviceWidth, deviceHeight, 1, m_viewSize);
        setFixedLayoutSize(roundedIntSize(attr.layoutSize));
        scaleView(deviceWidth / attr.layoutSize.width());
    }
#else
    UNUSED_PARAM(viewportArguments);
#endif
}

#if !PLATFORM(IOS_FAMILY)

FloatSize WebPage::screenSizeForFingerprintingProtections(const LocalFrame& frame, FloatSize defaultSize) const
{
    return frame.view() ? FloatSize { protect(frame.view())->unobscuredContentRectIncludingScrollbars().size() } : defaultSize;
}

#endif // !PLATFORM(IOS_FAMILY)

void WebPage::listenForLayoutMilestones(OptionSet<WebCore::LayoutMilestone> milestones)
{
    if (auto* page = m_page.get())
        page->addLayoutMilestones(milestones);
}

void WebPage::setSuppressScrollbarAnimations(bool suppressAnimations)
{
    protect(corePage())->setShouldSuppressScrollbarAnimations(suppressAnimations);
}

void WebPage::setEnableVerticalRubberBanding(bool enableVerticalRubberBanding)
{
    protect(corePage())->setVerticalScrollElasticity(enableVerticalRubberBanding ? ScrollElasticity::Allowed : ScrollElasticity::None);
}

void WebPage::setEnableHorizontalRubberBanding(bool enableHorizontalRubberBanding)
{
    protect(corePage())->setHorizontalScrollElasticity(enableHorizontalRubberBanding ? ScrollElasticity::Allowed : ScrollElasticity::None);
}

void WebPage::setBackgroundExtendsBeyondPage(bool backgroundExtendsBeyondPage)
{
    if (m_page->settings().backgroundShouldExtendBeyondPage() != backgroundExtendsBeyondPage)
        m_page->settings().setBackgroundShouldExtendBeyondPage(backgroundExtendsBeyondPage);
}

void WebPage::setPaginationMode(Pagination::Mode mode)
{
    RefPtr page = m_page;
    Pagination pagination = page->pagination();
    pagination.mode = static_cast<Pagination::Mode>(mode);
    page->setPagination(pagination);
}

void WebPage::setPaginationBehavesLikeColumns(bool behavesLikeColumns)
{
    RefPtr page = m_page;
    Pagination pagination = page->pagination();
    pagination.behavesLikeColumns = behavesLikeColumns;
    page->setPagination(pagination);
}

void WebPage::setPageLength(double pageLength)
{
    RefPtr page = m_page;
    Pagination pagination = page->pagination();
    pagination.pageLength = pageLength;
    page->setPagination(pagination);
}

void WebPage::setGapBetweenPages(double gap)
{
    RefPtr page = m_page;
    Pagination pagination = page->pagination();
    pagination.gap = gap;
    page->setPagination(pagination);
}

void WebPage::postInjectedBundleMessage(const String& messageName, const UserData& userData)
{
    auto& webProcess = WebProcess::singleton();
    RefPtr injectedBundle = webProcess.injectedBundle();
    if (!injectedBundle)
        return;

    injectedBundle->didReceiveMessageToPage(Ref { *this }, messageName, webProcess.transformHandlesToObjects(protect(userData.object()).get()));
}

void WebPage::setUnderPageBackgroundColorOverride(WebCore::Color&& underPageBackgroundColorOverride)
{
    protect(corePage())->setUnderPageBackgroundColorOverride(WTF::move(underPageBackgroundColorOverride));
}

void WebPage::setShouldSuppressHDR(bool shouldSuppressHDR)
{
    protect(corePage())->setShouldSuppressHDR(shouldSuppressHDR);
}

#if !PLATFORM(IOS_FAMILY)

void WebPage::setHeaderPageBanner(PageBanner* pageBanner)
{
    if (RefPtr headerBanner = m_headerBanner)
        headerBanner->detachFromPage();

    m_headerBanner = pageBanner;

    if (RefPtr headerBanner = m_headerBanner)
        headerBanner->addToPage(PageBanner::Header, this);
}

PageBanner* WebPage::headerPageBanner()
{
    return m_headerBanner.get();
}

void WebPage::setFooterPageBanner(PageBanner* pageBanner)
{
    if (RefPtr footerBanner = m_footerBanner)
        footerBanner->detachFromPage();

    m_footerBanner = pageBanner;

    if (RefPtr footerBanner = m_footerBanner)
        footerBanner->addToPage(PageBanner::Footer, this);
}

PageBanner* WebPage::footerPageBanner()
{
    return m_footerBanner.get();
}

void WebPage::hidePageBanners()
{
    if (RefPtr headerBanner = m_headerBanner)
        headerBanner->hide();
    if (RefPtr footerBanner = m_footerBanner)
        footerBanner->hide();
}

void WebPage::showPageBanners()
{
    if (RefPtr headerBanner = m_headerBanner)
        headerBanner->showIfHidden();
    if (RefPtr footerBanner = m_footerBanner)
        footerBanner->showIfHidden();
}

#endif // !PLATFORM(IOS_FAMILY)

#if PLATFORM(MAC)
void WebPage::setHeaderBannerHeight(int height)
{
    protect(corePage())->setHeaderHeight(height);
}

void WebPage::setFooterBannerHeight(int height)
{
    protect(corePage())->setFooterHeight(height);
}
#endif

RefPtr<ShareableBitmap> WebPage::shareableBitmapSnapshotForNode(Node& node)
{
    // Ensure that the image contains at most 600K pixels, so that it is not too big.
    if (auto snapshot = snapshotNode(node, SnapshotOption::Shareable, 600 * 1024))
        return snapshot->bitmap();
    return nullptr;
}

void WebPage::takeRemoteSnapshot(IntRect snapshotRect, IntSize bitmapSize, SnapshotOptions snapshotOptions, RemoteSnapshotIdentifier snapshotIdentifier, CompletionHandler<void(bool)>&& completionHandler)
{
#if ENABLE(GPU_PROCESS)
    ASSERT(m_page->settings().remoteSnapshottingEnabled());

    RefPtr coreFrame = m_mainFrame->coreLocalFrame();
    if (!coreFrame) {
        completionHandler(false);
        return;
    }

    RefPtr frameView = coreFrame->view();
    if (!frameView) {
        completionHandler(false);
        return;
    }

    Ref remoteRenderingBackend = ensureRemoteRenderingBackendProxy();
    m_remoteSnapshotState = {
        snapshotIdentifier,
        remoteRenderingBackend->createSnapshotRecorder(snapshotIdentifier),
        MainRunLoopSuccessCallbackAggregator::create(WTF::move(completionHandler))
    };

    auto originalLayoutViewportOverrideRect = frameView->layoutViewportOverrideRect();

    auto originalPaintBehavior = frameView->paintBehavior();
    auto paintBehavior = originalPaintBehavior;

    preSnapshotSetup(snapshotRect, bitmapSize, snapshotOptions, paintBehavior, *frameView);
    paintSnapshotAtSize(snapshotRect, bitmapSize, snapshotOptions, *coreFrame, *frameView, m_remoteSnapshotState->recorder);
    postSnapshotTakedown(originalPaintBehavior, paintBehavior, originalLayoutViewportOverrideRect, *frameView);

    remoteRenderingBackend->sinkSnapshotRecorderIntoSnapshotFrame(WTF::move(m_remoteSnapshotState->recorder), coreFrame->frameID(), Ref { m_remoteSnapshotState->callback }->chain());
    m_remoteSnapshotState = std::nullopt;

#else
    UNUSED_PARAM(snapshotRect);
    UNUSED_PARAM(bitmapSize);
    UNUSED_PARAM(snapshotOptions);
    UNUSED_PARAM(snapshotIdentifier);
    UNUSED_PARAM(completionHandler);
#endif
}

void WebPage::preSnapshotSetup(IntRect& snapshotRect, IntSize& bitmapSize, SnapshotOptions& snapshotOptions, OptionSet<PaintBehavior>& paintBehavior, LocalFrameView& frameView)
{
    snapshotOptions.add(SnapshotOption::Shareable);

    auto originalPaintBehavior = frameView.paintBehavior();

    if (snapshotOptions.contains(SnapshotOption::VisibleContentRect))
        snapshotRect = frameView.visibleContentRect();
    else if (snapshotOptions.contains(SnapshotOption::FullContentRect)) {
        snapshotRect = IntRect({ 0, 0 }, frameView.contentsSize());
        frameView.setLayoutViewportOverrideRect(LayoutRect(snapshotRect));
        paintBehavior.add(PaintBehavior::AnnotateLinks);
    }

#if HAVE(SUPPORT_HDR_DISPLAY)
    if (snapshotOptions.contains(SnapshotOption::AllowHDR) && protect(corePage())->drawsHDRContent())
        paintBehavior.add(PaintBehavior::DrawsHDRContent);
#endif

    if (originalPaintBehavior != paintBehavior)
        frameView.setPaintBehavior(paintBehavior);

    if (bitmapSize.isEmpty()) {
        bitmapSize = snapshotRect.size();
        if (!snapshotOptions.contains(SnapshotOption::ExcludeDeviceScaleFactor))
            bitmapSize.scale(corePage()->deviceScaleFactor());
    }
}

void WebPage::postSnapshotTakedown(OptionSet<PaintBehavior> originalPaintBehavior, OptionSet<PaintBehavior> paintBehavior, std::optional<LayoutRect> originalLayoutViewportOverrideRect, LocalFrameView& frameView)
{
    if (originalPaintBehavior != paintBehavior) {
        frameView.setLayoutViewportOverrideRect(originalLayoutViewportOverrideRect);
        frameView.setPaintBehavior(originalPaintBehavior);
    }
}

void WebPage::takeSnapshot(IntRect snapshotRect, IntSize bitmapSize, SnapshotOptions snapshotOptions, CompletionHandler<void(std::optional<ImageBufferBackendHandle>&&, Headroom)>&& completionHandler)
{
    std::optional<ImageBufferBackendHandle> handle;
    RefPtr coreFrame = m_mainFrame->coreLocalFrame();
    if (!coreFrame) {
        completionHandler(WTF::move(handle), Headroom::None);
        return;
    }

    RefPtr frameView = coreFrame->view();
    if (!frameView) {
        completionHandler(WTF::move(handle), Headroom::None);
        return;
    }

    auto originalLayoutViewportOverrideRect = frameView->layoutViewportOverrideRect();

    auto originalPaintBehavior = frameView->paintBehavior();
    auto paintBehavior = originalPaintBehavior;

    preSnapshotSetup(snapshotRect, bitmapSize, snapshotOptions, paintBehavior, *frameView);

    Headroom headroom = Headroom::None;
    if (auto image = snapshotAtSize(snapshotRect, bitmapSize, snapshotOptions, *coreFrame, *frameView)) {
        handle = image->createImageBufferBackendHandle(SharedMemory::Protection::ReadOnly);
#if HAVE(SUPPORT_HDR_DISPLAY)
        if (image->context())
            headroom = Headroom(image->context()->maxPaintedEDRHeadroom());
#endif
    }

    postSnapshotTakedown(originalPaintBehavior, paintBehavior, originalLayoutViewportOverrideRect, *frameView);
    completionHandler(WTF::move(handle), headroom);
}

RefPtr<WebImage> WebPage::scaledSnapshotWithOptions(const IntRect& rect, double additionalScaleFactor, SnapshotOptions options)
{
    RefPtr coreFrame = m_mainFrame->coreLocalFrame();
    if (!coreFrame)
        return nullptr;

    RefPtr frameView = coreFrame->view();
    if (!frameView)
        return nullptr;

    IntRect snapshotRect = rect;
    IntSize bitmapSize = snapshotRect.size();
    if (options.contains(SnapshotOption::Printing)) {
        ASSERT(additionalScaleFactor == 1);
        bitmapSize.setHeight(PrintContext::numberOfPages(*coreFrame, bitmapSize) * (bitmapSize.height() + 1) - 1);
    } else {
        double scaleFactor = additionalScaleFactor;
        if (!options.contains(SnapshotOption::ExcludeDeviceScaleFactor))
            scaleFactor *= corePage()->deviceScaleFactor();
        bitmapSize.scale(scaleFactor);
    }

    return snapshotAtSize(rect, bitmapSize, options, *coreFrame, *frameView);
}

void WebPage::paintSnapshotAtSize(const IntRect& rect, const IntSize& bitmapSize, SnapshotOptions options, LocalFrame& frame, LocalFrameView& frameView, GraphicsContext& graphicsContext)
{
    TraceScope snapshotScope(PaintSnapshotStart, PaintSnapshotEnd, options.toRaw());

    IntRect snapshotRect = rect;
    float horizontalScaleFactor = static_cast<float>(bitmapSize.width()) / rect.width();
    float verticalScaleFactor = static_cast<float>(bitmapSize.height()) / rect.height();
    float scaleFactor = std::max(horizontalScaleFactor, verticalScaleFactor);

    if (options.contains(SnapshotOption::Printing)) {
        PrintContext::spoolAllPagesWithBoundaries(frame, graphicsContext, snapshotRect.size());
        return;
    }

    Color backgroundColor;
    Color savedBackgroundColor;
    if (options.contains(SnapshotOption::TransparentBackground)) {
        backgroundColor = Color::transparentBlack;
        savedBackgroundColor = frameView.baseBackgroundColor();
        frameView.setBaseBackgroundColor(backgroundColor);
    } else {
        Color documentBackgroundColor = frameView.documentBackgroundColor();
        backgroundColor = (frame.settings().backgroundShouldExtendBeyondPage() && documentBackgroundColor.isValid()) ? documentBackgroundColor : frameView.baseBackgroundColor();
    }
    graphicsContext.fillRect(IntRect(IntPoint(), bitmapSize), backgroundColor);

    if (!options.contains(SnapshotOption::ExcludeDeviceScaleFactor)) {
        double deviceScaleFactor = frame.page()->deviceScaleFactor();
        graphicsContext.applyDeviceScaleFactor(deviceScaleFactor);
        scaleFactor /= deviceScaleFactor;
    }

    graphicsContext.scale(scaleFactor);
    graphicsContext.translate(-snapshotRect.location());

    LocalFrameView::SelectionInSnapshot shouldPaintSelection = LocalFrameView::IncludeSelection;
    if (options.contains(SnapshotOption::ExcludeSelectionHighlighting))
        shouldPaintSelection = LocalFrameView::ExcludeSelection;

    LocalFrameView::CoordinateSpaceForSnapshot coordinateSpace = LocalFrameView::DocumentCoordinates;
    if (options.contains(SnapshotOption::InViewCoordinates))
        coordinateSpace = LocalFrameView::ViewCoordinates;

    frameView.paintContentsForSnapshot(graphicsContext, snapshotRect, shouldPaintSelection, coordinateSpace);

    if (options.contains(SnapshotOption::PaintSelectionRectangle)) {
        FloatRect selectionRectangle = protect(frame.selection())->selectionBounds();
        graphicsContext.setStrokeColor(Color::red);
        graphicsContext.strokeRect(selectionRectangle, 1);
    }

    if (options.contains(SnapshotOption::TransparentBackground))
        frameView.setBaseBackgroundColor(savedBackgroundColor);
}

static DestinationColorSpace snapshotColorSpace(SnapshotOptions options, WebPage& page)
{
#if USE(CG)
    if (options.contains(SnapshotOption::UseScreenColorSpace)) {
        auto screenColorSpace = WebCore::screenColorSpace(protect(protect(protect(page.corePage())->mainFrame())->virtualView()).get());
#if HAVE(SUPPORT_HDR_DISPLAY)
        if (options.contains(SnapshotOption::AllowHDR) && protect(page.corePage())->drawsHDRContent()) {
            if (auto extendedScreenColorSpace = screenColorSpace.asExtended())
                return *extendedScreenColorSpace;
        }
#endif
        return screenColorSpace;
    }
#endif

#if HAVE(SUPPORT_HDR_DISPLAY)
    if (options.contains(SnapshotOption::AllowHDR) && protect(page.corePage())->drawsHDRContent())
        return DestinationColorSpace::ExtendedSRGB();
#endif

    return DestinationColorSpace::SRGB();
}

RefPtr<WebImage> WebPage::snapshotAtSize(const IntRect& rect, const IntSize& bitmapSize, SnapshotOptions options, LocalFrame& frame, LocalFrameView& frameView)
{
#if ENABLE(PDF_PLUGIN)
    ImageOptions imageOptions = m_pluginViews.computeSize() ? ImageOption::Local : ImageOption::Shareable;
#else
    ImageOptions imageOptions = ImageOption::Shareable;
#endif

    if (options.contains(SnapshotOption::Accelerated))
        imageOptions.add(ImageOption::Accelerated);
    if (options.contains(SnapshotOption::AllowHDR))
        imageOptions.add(ImageOption::AllowHDR);

    auto snapshot = WebImage::create(bitmapSize, imageOptions, snapshotColorSpace(options, *this), &m_page->chrome().client());
    if (!snapshot->context())
        return nullptr;

    auto& graphicsContext = *snapshot->context();
#if HAVE(SUPPORT_HDR_DISPLAY)
    graphicsContext.setMaxEDRHeadroom(maxEDRHeadroomForDisplay(m_page->displayID()));
#endif
    paintSnapshotAtSize(rect, bitmapSize, options, frame, frameView, graphicsContext);

    return snapshot;
}

RefPtr<WebImage> WebPage::snapshotNode(WebCore::Node& node, SnapshotOptions options, unsigned maximumPixelCount)
{
    RefPtr coreFrame = m_mainFrame->coreLocalFrame();
    if (!coreFrame)
        return nullptr;

    RefPtr frameView = coreFrame->view();
    if (!frameView)
        return nullptr;

    if (!node.renderer())
        return nullptr;

    LayoutRect topLevelRect;
    IntRect snapshotRect = snappedIntRect(protect(node.renderer())->paintingRootRect(topLevelRect));
    if (snapshotRect.isEmpty())
        return nullptr;

    double scaleFactor = 1;
    IntSize snapshotSize = snapshotRect.size();
    unsigned maximumHeight = maximumPixelCount / snapshotSize.width();
    if (maximumHeight < static_cast<unsigned>(snapshotSize.height())) {
        scaleFactor = static_cast<double>(maximumHeight) / snapshotSize.height();
        snapshotSize = IntSize(snapshotSize.width() * scaleFactor, maximumHeight);
    }

    auto snapshot = WebImage::create(snapshotSize, snapshotOptionsToImageOptions(options), snapshotColorSpace(options, *this), &m_page->chrome().client());
    if (!snapshot->context())
        return nullptr;

    auto& graphicsContext = *snapshot->context();

    if (!options.contains(SnapshotOption::ExcludeDeviceScaleFactor)) {
        double deviceScaleFactor = corePage()->deviceScaleFactor();
        graphicsContext.applyDeviceScaleFactor(deviceScaleFactor);
        scaleFactor /= deviceScaleFactor;
    }

    graphicsContext.scale(scaleFactor);
    graphicsContext.translate(-snapshotRect.location());

    Color savedBackgroundColor = frameView->baseBackgroundColor();
    frameView->setBaseBackgroundColor(Color::transparentBlack);
    frameView->setNodeToDraw(&node);

    frameView->paintContentsForSnapshot(graphicsContext, snapshotRect, LocalFrameView::ExcludeSelection, LocalFrameView::DocumentCoordinates);

    frameView->setBaseBackgroundColor(savedBackgroundColor);
    frameView->setNodeToDraw(nullptr);

    return snapshot;
}

void WebPage::pageDidScroll()
{
#if PLATFORM(IOS_FAMILY)
    if (!m_inDynamicSizeUpdate)
        m_internals->dynamicSizeUpdateHistory.clear();
#endif
    m_pageScrolledHysteresis.impulse();

    if (RefPtr view = protect(protect(corePage())->mainFrame())->virtualView())
        send(Messages::WebPageProxy::PageDidScroll(view->scrollPosition()));
}

void WebPage::pageStoppedScrolling()
{
    // Maintain the current history item's scroll position up-to-date.
    if (RefPtr frame = m_mainFrame->coreLocalFrame())
        frame->loader().history().saveScrollPositionAndViewStateToItem(protect(frame->loader().history().currentItem()).get());
}

void WebPage::setHasActiveAnimatedScrolls(bool hasActiveAnimatedScrolls)
{
    send(Messages::WebPageProxy::SetHasActiveAnimatedScrolls(hasActiveAnimatedScrolls));
}

#if ENABLE(CONTEXT_MENUS)
WebContextMenu& WebPage::contextMenu()
{
    if (!m_contextMenu)
        m_contextMenu = WebContextMenu::create(*this);
    return *m_contextMenu;
}

RefPtr<WebContextMenu> WebPage::contextMenuAtPointInWindow(FrameIdentifier frameID, const DoublePoint& point)
{
    RefPtr frame = WebProcess::singleton().webFrame(frameID);
    if (!frame)
        return nullptr;

    RefPtr coreFrame = frame->coreLocalFrame();
    if (!coreFrame)
        return nullptr;

    corePage()->contextMenuController().clearContextMenu();

    // Simulate a mouse click to generate the correct menu.
    PlatformMouseEvent mousePressEvent(point, point, MouseButton::Right, PlatformEvent::Type::MousePressed, 1, { }, MonotonicTime::now(), WebCore::ForceAtClick, WebCore::SyntheticClickType::NoTap, MouseEventInputSource::UserDriven);
    coreFrame->eventHandler().handleMousePressEvent(mousePressEvent);
    bool handled = coreFrame->eventHandler().sendContextMenuEvent(mousePressEvent);
    RefPtr menu = handled ? &contextMenu() : nullptr;
    PlatformMouseEvent mouseReleaseEvent(point, point, MouseButton::Right, PlatformEvent::Type::MouseReleased, 1, { }, MonotonicTime::now(), WebCore::ForceAtClick, WebCore::SyntheticClickType::NoTap, MouseEventInputSource::UserDriven);
    coreFrame->eventHandler().handleMouseReleaseEvent(mouseReleaseEvent);

    return menu;
}
#endif

// Events

static const WebEvent* g_currentEvent = 0;

// FIXME: WebPage::currentEvent is used by the plug-in code to avoid having to convert from DOM events back to
// WebEvents. When we get the event handling sorted out, this should go away and the Widgets should get the correct
// platform events passed to the event handler code.
const WebEvent* WebPage::currentEvent()
{
    return g_currentEvent;
}

void WebPage::freezeLayerTree(LayerTreeFreezeReason reason)
{
    auto oldReasons = m_layerTreeFreezeReasons.toRaw();
    UNUSED_PARAM(oldReasons);
    m_layerTreeFreezeReasons.add(reason);
    WEBPAGE_RELEASE_LOG_FORWARDABLE(ProcessSuspension, WebPageFreezeLayerTree, static_cast<unsigned>(reason), m_layerTreeFreezeReasons.toRaw(), oldReasons);
    updateDrawingAreaLayerTreeFreezeState();
}

void WebPage::unfreezeLayerTree(LayerTreeFreezeReason reason)
{
    auto oldReasons = m_layerTreeFreezeReasons.toRaw();
    UNUSED_PARAM(oldReasons);
    m_layerTreeFreezeReasons.remove(reason);
    WEBPAGE_RELEASE_LOG_FORWARDABLE(ProcessSuspension, WebPageUnfreezeLayerTree, static_cast<unsigned>(reason), m_layerTreeFreezeReasons.toRaw(), oldReasons);
    updateDrawingAreaLayerTreeFreezeState();
}

void WebPage::updateDrawingAreaLayerTreeFreezeState()
{
    RefPtr drawingArea = m_drawingArea;
    if (!drawingArea)
        return;

#if ENABLE(VIDEO_PRESENTATION_MODE)
    // When the browser is in the background, we should not freeze the layer tree
    // if the page has a video playing in picture-in-picture.
    RefPtr videoPresentationManager = m_videoPresentationManager;
    if (videoPresentationManager && videoPresentationManager->hasVideoPlayingInPictureInPicture() && m_layerTreeFreezeReasons.hasExactlyOneBitSet() && m_layerTreeFreezeReasons.contains(LayerTreeFreezeReason::BackgroundApplication)) {
        drawingArea->setLayerTreeStateIsFrozen(false);
        return;
    }
#endif

    drawingArea->setLayerTreeStateIsFrozen(!!m_layerTreeFreezeReasons);
}

void WebPage::updateFrameScrollingMode(FrameIdentifier frameID, ScrollbarMode scrollingMode)
{
    if (!m_page)
        return;

    ASSERT(m_page->settings().siteIsolationEnabled());
    RefPtr webFrame = WebProcess::singleton().webFrame(frameID);
    if (!webFrame)
        return;

    RefPtr frame = webFrame->coreLocalFrame();
    if (!frame)
        return;

    frame->setScrollingMode(scrollingMode);
}

void WebPage::tryMarkLayersVolatile(CompletionHandler<void(bool)>&& completionHandler)
{
    RefPtr drawingArea = m_drawingArea;
    if (!drawingArea) {
        completionHandler(false);
        return;
    }

    drawingArea->tryMarkLayersVolatile(WTF::move(completionHandler));
}

void WebPage::callVolatilityCompletionHandlers(bool succeeded)
{
    auto completionHandlers = std::exchange(m_markLayersAsVolatileCompletionHandlers, { });
    for (auto& completionHandler : completionHandlers)
        completionHandler(succeeded);
}

void WebPage::layerVolatilityTimerFired()
{
    m_layerVolatilityTimerInterval *= 2;
    markLayersVolatileOrRetry(m_layerVolatilityTimerInterval > maximumLayerVolatilityTimerInterval ? MarkLayersVolatileDontRetryReason::TimedOut : MarkLayersVolatileDontRetryReason::None);
}

void WebPage::markLayersVolatile(CompletionHandler<void(bool)>&& completionHandler)
{
    WEBPAGE_RELEASE_LOG_FORWARDABLE(Layers, WebPageMarkLayersVolatile);

    if (m_layerVolatilityTimer.isActive())
        m_layerVolatilityTimer.stop();

    if (completionHandler)
        m_markLayersAsVolatileCompletionHandlers.append(WTF::move(completionHandler));

    m_layerVolatilityTimerInterval = initialLayerVolatilityTimerInterval;
    markLayersVolatileOrRetry(m_isSuspendedUnderLock ? MarkLayersVolatileDontRetryReason::SuspendedUnderLock : MarkLayersVolatileDontRetryReason::None);
}

void WebPage::markLayersVolatileOrRetry(MarkLayersVolatileDontRetryReason dontRetryReason)
{
    tryMarkLayersVolatile([dontRetryReason, protectedThis = Ref { *this }](bool didSucceed) {
        protectedThis->tryMarkLayersVolatileCompletionHandler(dontRetryReason, didSucceed);
    });
}

void WebPage::tryMarkLayersVolatileCompletionHandler(MarkLayersVolatileDontRetryReason dontRetryReason, bool didSucceed)
{
    if (m_isClosed)
        return;

    if (didSucceed || dontRetryReason != MarkLayersVolatileDontRetryReason::None) {
        m_layerVolatilityTimer.stop();
        if (didSucceed)
            WEBPAGE_RELEASE_LOG(Layers, "markLayersVolatile: Succeeded in marking layers as volatile");
        else {
            switch (dontRetryReason) {
            case MarkLayersVolatileDontRetryReason::None:
                break;
            case MarkLayersVolatileDontRetryReason::SuspendedUnderLock:
                WEBPAGE_RELEASE_LOG(Layers, "markLayersVolatile: Did what we could to mark IOSurfaces as purgeable after locking the screen");
                break;
            case MarkLayersVolatileDontRetryReason::TimedOut:
                WEBPAGE_RELEASE_LOG(Layers, "markLayersVolatile: Failed to mark layers as volatile within %gms", maximumLayerVolatilityTimerInterval.milliseconds());
                break;
            }
        }
        callVolatilityCompletionHandlers(didSucceed);
        return;
    }

    if (m_markLayersAsVolatileCompletionHandlers.isEmpty()) {
        WEBPAGE_RELEASE_LOG(Layers, "markLayersVolatile: Failed to mark all layers as volatile, but will not retry because the operation was cancelled");
        return;
    }

    WEBPAGE_RELEASE_LOG_FORWARDABLE(Layers, WebPageFailedToMarkAllLayersVolatile, m_layerVolatilityTimerInterval.milliseconds());
    m_layerVolatilityTimer.startOneShot(m_layerVolatilityTimerInterval);
}

void WebPage::cancelMarkLayersVolatile()
{
    WEBPAGE_RELEASE_LOG(Layers, "cancelMarkLayersVolatile:");
    m_layerVolatilityTimer.stop();
    callVolatilityCompletionHandlers(false);
}

class CurrentEvent {
public:
    explicit CurrentEvent(const WebEvent& event)
        : m_previousCurrentEvent(g_currentEvent)
    {
        g_currentEvent = &event;
    }

    ~CurrentEvent()
    {
        g_currentEvent = m_previousCurrentEvent.get();
    }

private:
    CheckedPtr<const WebEvent> m_previousCurrentEvent;
};

#if ENABLE(CONTEXT_MENUS)

void WebPage::didDismissContextMenu()
{
    corePage()->contextMenuController().didDismissContextMenu();
}

void WebPage::showContextMenuFromFrame(const FrameInfoData& frameInfo, const ContextMenuContextData& contextMenuContextData, const UserData& userData)
{
    flushPendingEditorStateUpdate();
    send(Messages::WebPageProxy::ShowContextMenuFromFrame(frameInfo, contextMenuContextData, userData));
    m_hasEverDisplayedContextMenu = true;
    scheduleFullEditorStateUpdate();
}

#endif // ENABLE(CONTEXT_MENUS)

#if ENABLE(CONTEXT_MENU_EVENT)
void WebPage::contextMenuForKeyEvent()
{
#if ENABLE(CONTEXT_MENUS)
    corePage()->contextMenuController().clearContextMenu();
#endif

    RefPtr frame = corePage()->focusController().focusedOrMainFrame();
    if (!frame)
        return;

    bool handled = frame->eventHandler().sendContextMenuEventForKey();
#if ENABLE(CONTEXT_MENUS)
    if (handled)
        protect(contextMenu())->show();
#else
    UNUSED_PARAM(handled);
#endif
}
#endif

void WebPage::mouseEvent(FrameIdentifier frameID, const WebMouseEvent& mouseEvent, std::optional<Vector<SandboxExtension::Handle>>&& sandboxExtensions)
{
    SetForScope userIsInteractingChange { m_userIsInteracting, true };

    m_internals->userActivity.impulse();

    bool shouldHandleEvent = true;
#if ENABLE(DRAG_SUPPORT)
    if (m_isStartingDrag)
        shouldHandleEvent = false;
#endif

    if (!shouldHandleEvent) {
        send(Messages::WebPageProxy::DidReceiveEventIPC(mouseEvent.type(), false, std::nullopt));
        return;
    }

    Vector<Ref<SandboxExtension>> mouseEventSandboxExtensions;
    if (sandboxExtensions)
        mouseEventSandboxExtensions = consumeSandboxExtensions(WTF::move(*sandboxExtensions));

    bool handled = false;

#if !PLATFORM(IOS_FAMILY)
    if (!handled && m_headerBanner)
        handled = Ref { *m_headerBanner }->mouseEvent(mouseEvent);
    if (!handled && m_footerBanner)
        handled = Ref { *m_footerBanner }->mouseEvent(mouseEvent);
#endif // !PLATFORM(IOS_FAMILY)

    if (RefPtr frame = WebProcess::singleton().webFrame(frameID); !handled && frame) {
        CurrentEvent currentEvent(mouseEvent);
        auto mouseEventResult = frame->handleMouseEvent(mouseEvent);
        if (auto remoteMouseEventData = mouseEventResult.remoteUserInputEventData()) {
            revokeSandboxExtensions(mouseEventSandboxExtensions);
            send(Messages::WebPageProxy::DidReceiveEventIPC(mouseEvent.type(), false, *remoteMouseEventData));
            return;
        }
        handled = mouseEventResult.wasHandled();
    }

    revokeSandboxExtensions(mouseEventSandboxExtensions);

    RefPtr drawingArea = m_drawingArea;
    bool shouldDeferDidReceiveEvent = [&] {
        if (!drawingArea)
            return false;

        if (mouseEvent.type() != WebEventType::MouseMove)
            return false;

        if (mouseEvent.button() != WebMouseEventButton::None)
            return false;

        if (mouseEvent.force())
            return false;

        return true;
    }();

    flushDeferredDidReceiveMouseEvent();

    if (shouldDeferDidReceiveEvent) {
        // For mousemove events where the user is only hovering (not clicking and dragging),
        // we defer sending the DidReceiveEvent() IPC message until the end of the rendering
        // update to throttle the rate of these events to the rendering update frequency.
        // This logic works in tandem with the mouse event queue in the UI process, which
        // coalesces mousemove events until the DidReceiveEvent() message is received after
        // the rendering update.
        m_deferredDidReceiveMouseEvent = { { mouseEvent.type(), handled } };
        protect(corePage())->scheduleRenderingUpdate({ });
        return;
    }

    send(Messages::WebPageProxy::DidReceiveEventIPC(mouseEvent.type(), handled, std::nullopt));

#if PLATFORM(IOS_FAMILY)
    if (mouseEvent.type() == WebEventType::MouseUp)
        removeTextInteractionSources(TextInteractionSource::Mouse);
#endif
}

void WebPage::setLastKnownMousePosition(WebCore::FrameIdentifier frameID, const DoublePoint& eventPoint, const DoublePoint& globalPoint, std::optional<WebCore::LastKnownMousePositionSource>&& source)
{
    RefPtr frame = WebProcess::singleton().webFrame(frameID);
    if (!frame || !frame->coreLocalFrame() || !frame->coreLocalFrame()->view())
        return;

    frame->coreLocalFrame()->eventHandler().setLastKnownMousePosition(eventPoint, globalPoint, WTF::move(source));
}

void WebPage::startDeferringResizeEvents()
{
    corePage()->startDeferringResizeEvents();
}

void WebPage::flushDeferredResizeEvents()
{
    protect(corePage())->flushDeferredResizeEvents();
}

void WebPage::startDeferringScrollEvents()
{
    corePage()->startDeferringScrollEvents();
}

void WebPage::flushDeferredScrollEvents()
{
    protect(corePage())->flushDeferredScrollEvents();
}

void WebPage::startDeferringIntersectionObservations()
{
    corePage()->startDeferringIntersectionObservations();
}

void WebPage::flushDeferredIntersectionObservations()
{
    protect(corePage())->flushDeferredIntersectionObservations();
}

void WebPage::flushDeferredDidReceiveMouseEvent()
{
    if (auto info = std::exchange(m_deferredDidReceiveMouseEvent, std::nullopt))
        send(Messages::WebPageProxy::DidReceiveEventIPC(*info->type, info->handled, std::nullopt));
}

void WebPage::performHitTestForMouseEvent(const WebMouseEvent& event, CompletionHandler<void(WebHitTestResultData&&, OptionSet<WebEventModifier>)>&& completionHandler)
{
    auto modifiers = event.modifiers();
    RefPtr localMainFrame = dynamicDowncast<WebCore::LocalFrame>(corePage()->mainFrame());
    if (!localMainFrame || !localMainFrame->view())
        return completionHandler({ }, modifiers);

    auto hitTestResult = localMainFrame->eventHandler().getHitTestResultForMouseEvent(platform(event));

    String toolTip;
    TextDirection toolTipDirection;
    corePage()->chrome().getToolTip(hitTestResult, toolTip, toolTipDirection);

    WebHitTestResultData hitTestResultData { hitTestResult, toolTip };

    completionHandler(WTF::move(hitTestResultData), modifiers);
}

void WebPage::handleWheelEvent(FrameIdentifier frameID, const WebWheelEvent& event, const OptionSet<WheelEventProcessingSteps>& processingSteps, std::optional<bool> willStartSwipe, CompletionHandler<void(std::optional<WebCore::ScrollingNodeID>, std::optional<WebCore::WheelScrollGestureState>, bool, std::optional<RemoteUserInputEventData>)>&& completionHandler)
{
#if ENABLE(ASYNC_SCROLLING)
    RefPtr remoteScrollingCoordinator = dynamicDowncast<RemoteScrollingCoordinator>(scrollingCoordinator());
    if (remoteScrollingCoordinator)
        remoteScrollingCoordinator->setCurrentWheelEventWillStartSwipe(willStartSwipe);
#else
    UNUSED_PARAM(willStartSwipe);
#endif

    auto [handleWheelEventResult, _] = wheelEvent(frameID, event, processingSteps);
#if ENABLE(ASYNC_SCROLLING)
    if (remoteScrollingCoordinator) {
        auto gestureInfo = remoteScrollingCoordinator->takeCurrentWheelGestureInfo();
        completionHandler(gestureInfo.wheelGestureNode, gestureInfo.wheelGestureState, handleWheelEventResult.wasHandled(), handleWheelEventResult.remoteUserInputEventData());
        return;
    }
#endif
    completionHandler({ }, { }, handleWheelEventResult.wasHandled(), handleWheelEventResult.remoteUserInputEventData());
}

std::pair<HandleUserInputEventResult, OptionSet<EventHandling>> WebPage::wheelEvent(const FrameIdentifier& frameID, const WebWheelEvent& wheelEvent, OptionSet<WheelEventProcessingSteps> processingSteps)
{
    m_internals->userActivity.impulse();

    CurrentEvent currentEvent(wheelEvent);

    auto dispatchWheelEvent = [&](const WebWheelEvent& wheelEvent, OptionSet<WheelEventProcessingSteps> processingSteps) {
        RefPtr frame = WebProcess::singleton().webFrame(frameID);
        if (!frame || !frame->coreLocalFrame() || !frame->coreLocalFrame()->view())
            return std::pair { HandleUserInputEventResult { false }, OptionSet<EventHandling> { } };

        auto platformWheelEvent = platform(wheelEvent);
        return frame->coreLocalFrame()->eventHandler().handleWheelEvent(platformWheelEvent, processingSteps);
    };

    auto [result, handling] = dispatchWheelEvent(wheelEvent, processingSteps);
    LOG_WITH_STREAM(WheelEvents, stream << "WebPage::wheelEvent - processing steps " << processingSteps << " handled " << result.wasHandled());
    return { result, handling };
}

#if PLATFORM(IOS_FAMILY)
void WebPage::dispatchWheelEventWithoutScrolling(FrameIdentifier frameID, const WebWheelEvent& wheelEvent, CompletionHandler<void(bool, std::optional<RemoteUserInputEventData>)>&& completionHandler)
{
#if ENABLE(KINETIC_SCROLLING)
    RefPtr frame = WebProcess::singleton().webFrame(frameID);
    RefPtr localFrame = frame ? frame->coreLocalFrame() : nullptr;
    auto gestureState = localFrame ? localFrame->eventHandler().wheelScrollGestureState() : std::nullopt;
    bool isCancelable = !gestureState || gestureState == WheelScrollGestureState::Blocking || wheelEvent.phase() == WebWheelEvent::Phase::Began;
#else
    bool isCancelable = true;
#endif
    auto [result, handling] = this->wheelEvent(frameID, wheelEvent, { isCancelable ? WheelEventProcessingSteps::BlockingDOMEventDispatch : WheelEventProcessingSteps::NonBlockingDOMEventDispatch });
    // The caller of dispatchWheelEventWithoutScrolling never cares about DidReceiveEvent being sent back.
    completionHandler(result.wasHandled() && handling.contains(EventHandling::DefaultPrevented), result.remoteUserInputEventData());
}
#endif

void WebPage::keyEvent(FrameIdentifier frameID, const WebKeyboardEvent& keyboardEvent)
{
    SetForScope userIsInteractingChange { m_userIsInteracting, true };

    m_internals->userActivity.impulse();

    PlatformKeyboardEvent::setCurrentModifierState(platform(keyboardEvent).modifiers());

    CurrentEvent currentEvent(keyboardEvent);

    bool handled = false;
    if (RefPtr frame = WebProcess::singleton().webFrame(frameID))
        handled = frame->handleKeyEvent(keyboardEvent);

    send(Messages::WebPageProxy::DidReceiveEventIPC(keyboardEvent.type(), handled, std::nullopt));
}

bool WebPage::handleKeyEventByRelinquishingFocusToChrome(const KeyboardEvent& event)
{
    if (m_page->tabKeyCyclesThroughElements())
        return false;

    if (event.charCode() != '\t')
        return false;

    if (!event.shiftKey() || event.ctrlKey() || event.metaKey())
        return false;

    ASSERT(event.type() == eventNames().keypressEvent);
    // Allow a shift-tab keypress event to relinquish focus even if we don't allow tab to cycle between
    // elements inside the view. We can only do this for shift-tab, not tab itself because
    // tabKeyCyclesThroughElements is used to make tab character insertion work in editable web views.
    return corePage()->focusController().relinquishFocusToChrome(FocusDirection::Backward);
}

void WebPage::validateCommand(const String& commandName, CompletionHandler<void(bool, int32_t)>&& completionHandler)
{
    bool isEnabled = false;
    int32_t state = 0;
    RefPtr frame = corePage()->focusController().focusedOrMainFrame();
    if (!frame)
        return completionHandler({ }, { });

#if ENABLE(PDF_PLUGIN)
    if (RefPtr pluginView = focusedPluginViewForFrame(*frame))
        isEnabled = pluginView->isEditingCommandEnabled(commandName);
    else
#endif
    {
        auto command = protect(frame->editor())->command(commandName);
        state = (command.state() != TriState::False);
        isEnabled = command.isSupported() && command.isEnabled();
    }

    completionHandler(isEnabled, state);
}

void WebPage::executeEditCommand(const String& commandName, const String& argument)
{
    executeEditingCommand(commandName, argument);
}

void WebPage::setNeedsFontAttributes(bool needsFontAttributes)
{
    if (m_needsFontAttributes == needsFontAttributes)
        return;

    m_needsFontAttributes = needsFontAttributes;

    if (m_needsFontAttributes)
        scheduleFullEditorStateUpdate();
}

void WebPage::setCurrentHistoryItemForReattach(Ref<FrameState>&& mainFrameState)
{
    if (RefPtr localMainFrame = m_mainFrame->provisionalFrame() ? m_mainFrame->provisionalFrame() : m_mainFrame->coreLocalFrame())
        localMainFrame->loader().history().setCurrentItem(toHistoryItem(m_historyItemClient, mainFrameState));
}

void WebPage::requestFontAttributesAtSelectionStart(CompletionHandler<void(const WebCore::FontAttributes&)>&& completionHandler)
{
    RefPtr focusedOrMainFrame = corePage()->focusController().focusedOrMainFrame();
    if (!focusedOrMainFrame)
        return completionHandler({ });
    completionHandler(protect(focusedOrMainFrame->editor())->fontAttributesAtSelectionStart());
}

void WebPage::cancelCurrentInteractionInformationRequest()
{
#if PLATFORM(IOS_FAMILY)
    if (auto reply = WTF::move(m_pendingSynchronousPositionInformationReply))
        reply(InteractionInformationAtPosition::invalidInformation());
#endif
}

#if ENABLE(TOUCH_EVENTS) || ENABLE(DRIFTSTACK_TOUCH_STUBS)
static Expected<bool, WebCore::RemoteFrameGeometryTransformer> handleTouchEvent(FrameIdentifier frameID, const WebTouchEvent& touchEvent, Page* page)
{
    RefPtr frame = WebProcess::singleton().webFrame(frameID);
    if (!frame)
        return false;

    RefPtr localFrame = frame->coreLocalFrame();
    if (!localFrame || !localFrame->view())
        return false;

    WeakPtr weakPage = page;
    if (weakPage)
        weakPage->pointerCaptureController().resetPointerDownDefaultPrevention();

    auto result = localFrame->eventHandler().handleTouchEvent(platform(touchEvent));

#if ENABLE(IOS_TOUCH_EVENTS)
    bool canPreventNativeGestures = touchEvent.canPreventNativeGestures();
#else
    bool canPreventNativeGestures = false;
#endif

    // If a page has active (non-passive) touch listeners and calls pointerdown.preventDefault()
    // but not touchstart.preventDefault(), scrolling will no longer be suppressed on the
    // preventable path.
    if (!canPreventNativeGestures && weakPage && !result.value_or(false) && weakPage->pointerCaptureController().wasPointerDownDefaultPrevented())
        return true;

    return result;
}
#endif

RefPtr<WebCore::LocalFrame> WebPage::localRootFrame(std::optional<WebCore::FrameIdentifier> frameID)
{
    if (RefPtr webFrame = WebProcess::singleton().webFrame(frameID)) {
        ASSERT(webFrame->coreLocalFrame());
        ASSERT(webFrame->coreLocalFrame()->isRootFrame());
        return webFrame->coreLocalFrame();
    }
    ASSERT(m_page);
    ASSERT(m_page->localMainFrame());
    RefPtr page = m_page;
    return page ? page->localMainFrame() : nullptr;
}

#if ENABLE(IOS_TOUCH_EVENTS)
Expected<bool, WebCore::RemoteFrameGeometryTransformer> WebPage::dispatchTouchEvent(FrameIdentifier frameID, const WebTouchEvent& touchEvent)
{
    SetForScope userIsInteractingChange { m_userIsInteracting, true };
    m_lastInteractionLocation = touchEvent.position();
    CurrentEvent currentEvent(touchEvent);
    auto handleTouchEventResult = handleTouchEvent(frameID, touchEvent, m_page.get());
    updatePotentialTapSecurityOrigin(touchEvent, handleTouchEventResult.value_or(false));
    return handleTouchEventResult;
}

void WebPage::didBeginTouchPoint(FloatPoint locationInRootView)
{
    m_hasAnyActiveTouchPoints = true;
    m_potentialTapSecurityOrigin = nullptr;
    m_lastTouchLocationBeforeTap = locationInRootView;
}

void WebPage::updatePotentialTapSecurityOrigin(const WebTouchEvent& touchEvent, bool wasHandled)
{
    if (wasHandled)
        return;

    if (!touchEvent.isPotentialTap())
        return;

    if (touchEvent.type() != WebEventType::TouchStart)
        return;

    RefPtr localMainFrame = this->localMainFrame();
    if (!localMainFrame)
        return;

    RefPtr document = localMainFrame->document();
    if (!document)
        return;

    if (!document->handlingTouchEvent())
        return;

    RefPtr touchEventTargetFrame = localMainFrame;
    while (RefPtr localSubframe = dynamicDowncast<LocalFrame>(touchEventTargetFrame->eventHandler().touchEventTargetSubframe()))
        touchEventTargetFrame = WTF::move(localSubframe);

    auto& touches = touchEventTargetFrame->eventHandler().touches();
    if (touches.isEmpty())
        return;

    ASSERT(touches.size() == 1);

    if (auto targetDocument = touchEventTargetFrame->document())
        m_potentialTapSecurityOrigin = targetDocument->securityOrigin();
}
#elif ENABLE(TOUCH_EVENTS) || ENABLE(DRIFTSTACK_TOUCH_STUBS)
void WebPage::touchEvent(const WebTouchEvent& touchEvent, CompletionHandler<void(std::optional<WebEventType>, bool)>&& completionHandler)
{
    RefPtr localMainFrame = this->localMainFrame();
    if (!localMainFrame)
        return;

    CurrentEvent currentEvent(touchEvent);

    bool handled = handleTouchEvent(localMainFrame->frameID(), touchEvent, m_page.get()).value_or(false);

#if PLATFORM(DRIFTSTACK)
    driftstackSynthesizeTapClickIfNeeded(touchEvent, handled);
#endif

    completionHandler(touchEvent.type(), handled);
}

#if PLATFORM(DRIFTSTACK)
// W1405 (founder #1 "taps don't act"): the fork injects native touch (WebAutomationSessionMac →
// NativeWebTouchEvent) so touchstart/touchend fire with iPhone geometry — but Mac has no UIKit
// tap-gesture recognizer (iOS's _WKTouchEventGenerator path) to synthesize the CLICK that activates a
// button/link. Replicate iOS's commitPotentialTap (WebPageIOS.mm): track the tap; on its touchend, if
// the finger didn't move past the tap slop AND the page did not preventDefault the touch (a consumed
// touch suppresses the compatibility click, matching real browsers), hit-test the point and
// completeSyntheticClick(OneFingerTap) — firing the mousedown/mouseup/click a real iPhone tap produces.
void WebPage::driftstackSynthesizeTapClickIfNeeded(const WebTouchEvent& touchEvent, bool touchWasHandled)
{
    // W2740: scroll-commit threshold — a touch drifting more than this from the START is a drag/scroll,
    // not a tap. Raised 10→18: a GUI/trackpad "tap" relayed as touch events often wobbles ~10-15px
    // (pointer acceleration, packet jitter, a mis-fired GUI momentum fling) which the old 10px slop
    // mis-committed to an IRREVERSIBLE scroll (founder: "taps still scroll instead of tapping, often").
    // 18 is a jitter dead-band: real scrolls are well past it (agent behavioralScroll deltas are 28px+),
    // and sub-18px scrolls are the accepted tradeoff for robust taps. The PRIMARY tap/scroll fix is
    // GUI-side gesture classification (A2 — send a clean tap [down+up, no moves] vs a scroll); this is
    // the engine backstop so residual jitter can never spuriously scroll.
    constexpr double tapSlop = 18; // px (was 10)
    // W2780 (audit wf4v2iohk finding #5): re-anchor window. A genuine continuous touch-drag samples at
    // ~16ms (trackpad/converter cadence) — and even a slow human drag that PAUSES mid-gesture resumes with
    // the finger essentially where it stopped, so re-anchoring on resume scrolls the small genuine
    // post-pause delta (no fling, no suppressed scroll). An inter-gesture orphan TouchMove (after a DROPPED
    // touchEnd) only arrives once the human starts a NEW gesture, which is far more than this window later.
    // 250ms cleanly separates the two: well above the ~16ms intra-drag cadence (with huge margin for jitter,
    // GC pauses, or a momentarily-stalled finger), and well below any plausible inter-gesture interval. The
    // re-anchor is a no-op for normal scrolling (gap is always <250ms) and only neutralizes a stale fling.
    constexpr WTF::Seconds reanchorWindow = 250_ms;
    // W2961 (founder "slide like a new iPhone", hunt #3 — Step B kinetic momentum): gate the ENTIRE
    // momentum path behind DRIFTSTACK_SCROLL_MOMENTUM. Unset or "0" → momentum is fully inert and the
    // touch handling below is byte-identical to the prior strict-1:1 drag-only behavior. Read once.
    static const bool s_driftstackScrollMomentum = [] {
        const char* e = getenv("DRIFTSTACK_SCROLL_MOMENTUM");
        return e && e[0] && e[0] != '0'; // unset / "" / "0…" → off (fork env idiom; avoids -Wunsafe strcmp)
    }();
    // W3010 (founder "behave exactly like iPhone" — rubber-band over-scroll). Gate the ENTIRE over-scroll
    // bounce behind DRIFTSTACK_RUBBERBAND_IOS. Unset or "0" → the boundary stays HARD-CLAMPED (byte-identical
    // to the prior behavior); only when set does a drag/coast past the edge stretch + spring back (τ=191ms).
    static const bool s_driftstackRubberBand = [] {
        const char* e = getenv("DRIFTSTACK_RUBBERBAND_IOS");
        return e && e[0] && e[0] != '0';
    }();
    auto pos = touchEvent.position();
    auto now = WTF::MonotonicTime::now();
    switch (touchEvent.type()) {
    case WebEventType::TouchStart:
        m_driftstackPotentialTap = true;
        m_driftstackTouchActive = true;   // W2770: a finger is now down — TouchMoves may scroll.
        m_driftstackTapStartPoint = pos;
        m_driftstackLastTouchPoint = pos;
        m_driftstackLastTouchTime = now;  // W2780: anchor the drag clock at press.
        // W2761 (A2 W2754/W2760 Step A): start each drag with a clean sub-pixel remainder so a prior
        // drag's leftover fraction can't seed a phantom first-move scroll.
        m_driftstackScrollRemainderX = 0;
        m_driftstackScrollRemainderY = 0;
        // W2961: a new finger down cancels any in-flight momentum coast (iOS: touching the screen mid-glide
        // catches and stops the scroll). Also zero the tracked velocity so a stale lift-off can't seed the
        // next gesture. No-op when momentum is gated off (the timer is never started).
        if (s_driftstackScrollMomentum) {
            if (m_driftstackScrollCoastTimer && m_driftstackScrollCoastTimer->isActive())
                m_driftstackScrollCoastTimer->stop();
            m_driftstackScrollVelocity = { };
            m_driftstackPendingLiftoffVelocity = std::nullopt; // W3020: a fresh press drops any stale lift-off hint.
        }
        // W3010: a new finger down catches an in-flight rubber-band spring-back (iOS: touching the bouncing
        // content stops it where it is so the new drag continues from there). Stop the relaxation timer but
        // KEEP the current stretch — the new drag's moves continue stretching from it / pulling it back.
        if (s_driftstackRubberBand && m_driftstackRubberBandTimer && m_driftstackRubberBandTimer->isActive())
            m_driftstackRubberBandTimer->stop();
        return;
    case WebEventType::TouchMove: {
        // W2770 (founder "scrolls me back up"): ignore a TouchMove with no finger down (a stray/orphan move
        // with no preceding TouchStart — the GUI converter's post-touchEnd momentum tail / edge re-anchor).
        // Without this it scrolled by the delta from the PRIOR gesture's stale last-point → the page jerked
        // backward. Proven by operations/scripts/scroll-test (a down-less move scrolled 650 -> 0).
        if (!m_driftstackTouchActive)
            return;
        // W2780 (audit finding #5): if a touchEnd was DROPPED, m_driftstackTouchActive is stuck true and this
        // could be the FIRST move of a NEW gesture — scrolling by (stale last-point − pos) would fling the
        // page by the inter-gesture jump. If the gap since the last touch exceeds the re-anchor window, treat
        // this move as a fresh anchor: adopt pos as the new reference + reset the sub-pixel remainders (a
        // stale fraction must not seed a phantom scroll), and skip scrolling THIS move. The very next move
        // then scrolls by its own small (pos_next − pos) delta. A legit >250ms mid-drag pause-then-continue
        // hits this path too, but the paused finger barely moved, so the skipped delta is ~0 and scrolling
        // resumes seamlessly. (The clean-tap / W2740 slop math below keys off m_driftstackTapStartPoint, which
        // is unchanged, so re-anchoring never converts a held drag back into a tap.)
        if (now - m_driftstackLastTouchTime > reanchorWindow) {
            // W2780b (audit wf4v2iohk follow-up): the clock is anchored at TouchStart (line ~4270), so the
            // FIRST move of a deliberately SLOW gesture (long-press-then-drag, or a first sample landing
            // >250ms after touch-down) hits this same re-anchor path as an inter-gesture orphan would. We
            // must NOT scroll the stale/large delta here (that is the whole point of the re-anchor), but we
            // MUST still classify tap-vs-scroll: m_driftstackTapStartPoint is the original press point and is
            // NOT touched by the re-anchor, so evaluate the slop against it before returning. Without this a
            // slow far first-move that is the ONLY move of the gesture left m_driftstackPotentialTap set →
            // TouchEnd synthesized a spurious tap-click at the press point for what was really a drag. A
            // paused-then-resumed finger barely moved (still within slop) so this is a no-op for that case
            // (R2 regression test), and an actual inter-gesture orphan is far from the OLD start point so
            // clearing the flag is harmless (that gesture's tap already fired). Still skip scrolling THIS
            // move and re-anchor the point/remainders exactly as before.
            auto rdx = pos.x() - m_driftstackTapStartPoint.x();
            auto rdy = pos.y() - m_driftstackTapStartPoint.y();
            if (m_driftstackPotentialTap && (rdx * rdx + rdy * rdy) > tapSlop * tapSlop)
                m_driftstackPotentialTap = false;
            m_driftstackLastTouchPoint = pos;
            m_driftstackLastTouchTime = now;
            m_driftstackScrollRemainderX = 0;
            m_driftstackScrollRemainderY = 0;
            return;
        }
        // W2961: capture the inter-move interval BEFORE overwriting m_driftstackLastTouchTime — used to
        // build the lift-off velocity EWMA below (px/s = scroll delta / dt).
        WTF::Seconds dtMove = now - m_driftstackLastTouchTime;
        m_driftstackLastTouchTime = now;
        auto dx = pos.x() - m_driftstackTapStartPoint.x();
        auto dy = pos.y() - m_driftstackTapStartPoint.y();
        if (m_driftstackPotentialTap && (dx * dx + dy * dy) > tapSlop * tapSlop)
            m_driftstackPotentialTap = false;
        // W1453 (founder directive — NATIVE touch-drag scroll, NOT a JS executeScript scrollBy): once
        // the finger has moved past the tap slop it's a SCROLL, not a tap. macOS WebKit has no UIKit
        // pan-gesture recognizer driving the scrolling tree from injected touches, so synthetic
        // touchmove fires but the page doesn't move. Scroll it HERE in the WebProcess by this move's
        // delta (finger up → content down) — an engine-level scroll firing a genuine trusted scroll
        // event, no page-side JS, no `wheel` event (iPhone touch-scroll fires neither). The injected
        // touchmove above stays the realistic touch SIGNAL; this is the 1:1 native consequence (scroll
        // analogue of the W1405 tap→click synthesis). (First cut: the MAIN frame view — the dominant
        // page-scroll case; per-element overflow scrollers via hit-test→enclosingScrollableArea are a
        // refinement to land with A1, who owns the scrolling engine.)
        if (!m_driftstackPotentialTap) {
            if (RefPtr localMainFrame = this->localMainFrame()) {
                if (auto* view = localMainFrame->view()) {
                    // W2761 (A2 W2754/W2760 Step A — sub-pixel delta accumulation): the per-move delta was
                    // std::lround'd to an int and dropped when zero (the `if (sdx||sdy)` gate), so a slow or
                    // sub-pixel drag rounded each move to 0 → nothing moved, then a later move crossing the
                    // 0.5px rounding boundary LURCHED by the accumulated amount = the founder's "scroll barely
                    // moves then jerks / wrong-way" every session. Carry the fractional remainder across moves
                    // (doubles, reset per drag in TouchStart): apply the integer part, keep the fraction for the
                    // next move. static_cast<int> TRUNCATES TOWARD ZERO, so the carried fraction keeps the
                    // delta's sign and a sub-pixel move can never flip scroll direction. (Step B — routing
                    // injected touches through the native ScrollAnimator + capture-grounded momentum on TouchEnd
                    // — is the A1-paired follow-up; this is the cheap dead-zone/lurch/wrong-way kill.)
                    double rawDx = static_cast<double>(m_driftstackLastTouchPoint.x() - pos.x()) + m_driftstackScrollRemainderX;
                    double rawDy = static_cast<double>(m_driftstackLastTouchPoint.y() - pos.y()) + m_driftstackScrollRemainderY;
                    int sdx = static_cast<int>(rawDx);
                    int sdy = static_cast<int>(rawDy);
                    m_driftstackScrollRemainderX = rawDx - sdx;
                    m_driftstackScrollRemainderY = rawDy - sdy;
                    if (sdx || sdy) {
                        // W2402 (A1, per A3's W1453b hand-off — the scrolling engine is A1's domain):
                        // native touch-drag scroll targets the LOCKED enclosing scrollable area of the
                        // touch-START point, not always the main frame. A3's first cut re-hit-tested the
                        // CURRENT point each move → as the finger left an inner div the target switched to
                        // the page → BOTH scrolled (the W1453b "scroller-lock bug"). Fix: hit-test the FIXED
                        // start point (m_driftstackTapStartPoint — locked for the whole drag, can't switch
                        // mid-drag) → its enclosing scrollable area; scroll THAT inner overflow:scroll
                        // element, OR if there is none the main frame view (A3's W1453 page-scroll, preserved
                        // exactly). SINGLE target — never both. (Overscroll CHAINING div→page at the inner
                        // limit is a documented follow-up: it needs a scroll-RANGE check, because
                        // scrollPosition() is NOT synchronously updated after scrollToPositionWithoutAnimation
                        // — a post-scroll-delta "consumed" chain leaves remaining==full and over-scrolls the
                        // page, which was this fix's own first cut.) Coordinate space (W2448, fixing the
                        // A3-W1863 regression my W2439 introduced): m_driftstackTapStartPoint is now WINDOW-
                        // space — W2439 added obscuredContentInsets to the WD touch injection so that
                        // EventHandler::handleTouchEvent's windowToContents (EventHandler.cpp:5486) lands taps
                        // correctly. But hitTestResultAtPoint → document->hitTest operates in CONTENT space, so
                        // this start point must be windowToContents-converted (the SAME conversion WebCore
                        // applies to the touch). Pre-W2439 position() was content-space so this was a direct
                        // pass; W2439 flipped the space → the locked-scroller hit-test landed on the wrong
                        // element → the W1453b over-scroll regressed (div + page both scrolled). The synthetic
                        // mouse events (tap path) keep window-space since handleMousePress/Release do their own
                        // windowToContents. The scroll DELTAS (sdx/sdy) are space-agnostic (the inset cancels).
                        WebCore::ScrollableArea* area = nullptr;
                        auto htr = localMainFrame->eventHandler().hitTestResultAtPoint(
                            view->windowToContents(WebCore::flooredIntPoint(m_driftstackTapStartPoint)),
                            { WebCore::HitTestRequest::Type::ReadOnly, WebCore::HitTestRequest::Type::Active, WebCore::HitTestRequest::Type::DisallowUserAgentShadowContent });
                        if (RefPtr node = htr.innerNode())
                            area = localMainFrame->eventHandler().enclosingScrollableArea(node.get());
                        if (area && area != static_cast<WebCore::ScrollableArea*>(view)) {
                            // W2790 (audit #19 / wp0viuubh — over-scroll CHAINING inner→page): clamp the delta to
                            // the inner area's REMAINING scroll range and pass the leftover (the over-scroll) to the
                            // main frame, like a real iPhone (inner scroller bottoms out → the page continues). Use the
                            // scroll RANGE (min/max) BEFORE applying — NOT the post-scroll position, which
                            // scrollToPositionWithoutAnimation does NOT update synchronously (the W2402 caveat: a
                            // post-delta "consumed" check leaves remaining==full → it over-scrolled the page). Within
                            // range → leftover is 0 (no chain, inner scrolls only); at the limit → all of the delta
                            // chains to the page. Per-axis so a vertical over-scroll doesn't drag the page horizontally.
                            auto cur = area->scrollPosition();
                            auto minP = area->minimumScrollPosition();
                            auto maxP = area->maximumScrollPosition();
                            int wantX = cur.x() + sdx, wantY = cur.y() + sdy;
                            int clampX = std::max(minP.x(), std::min(maxP.x(), wantX));
                            int clampY = std::max(minP.y(), std::min(maxP.y(), wantY));
                            area->scrollToPositionWithoutAnimation(WebCore::FloatPoint(clampX, clampY));
                            int leftX = wantX - clampX, leftY = wantY - clampY;
                            if (leftX || leftY) {
                                // W3010: scroll the chained leftover into the PAGE, capturing the page's own
                                // unconsumed over-boundary delta (if the page is also at its edge) for the
                                // rubber-band stretch. driftstackScrollMainFrameWithOverscroll consumes what it
                                // can and returns the px the page couldn't (over its boundary); when the gate is
                                // off it's a plain view->scrollBy and returns 0.
                                driftstackScrollMainFrameWithOverscroll(*view, leftX, leftY, s_driftstackRubberBand);
                            }
                        } else
                            driftstackScrollMainFrameWithOverscroll(*view, sdx, sdy, s_driftstackRubberBand); // W1453 native MAIN-frame scroll + W3010 over-scroll
                    }
                }
            }
        }
        // W2961 (Step B): track the lift-off velocity from the recent finger motion. The scroll delta this
        // move applied (finger up → content scrolls down/positive) is (last − pos), the same vector the 1:1
        // scroll above used; velocity is that delta / dt in content px/s. Use an EWMA weighted toward the
        // most recent moves so the velocity at TouchEnd reflects the lift-off, not the whole drag (a flick
        // that slows before lift coasts less; a flick released at speed coasts far). Skip degenerate dt
        // (first move after re-anchor, or a duplicated timestamp) to avoid div-by-zero / spikes. Gated:
        // when momentum is off this is never read by TouchEnd, so it is pure dead state.
        if (s_driftstackScrollMomentum && !m_driftstackPotentialTap
            && dtMove > 0_s && dtMove < reanchorWindow) {
            // W3000 (defense-in-depth vs the W2962 EWMA over-read): floor the inter-move dt at 8ms
            // before the Δpos/dt velocity divide. A real iPhone samples touchmoves at ~display
            // cadence (~8–16ms apart), but injected/coalesced touchmoves can arrive with a
            // micro-dt (sub-millisecond) — a small but real Δpos divided by a tiny dt yields a
            // spuriously huge px/s, which the EWMA then carries to lift-off and over-triggers a
            // fling on what was a slow drag. Clamping dtMove to a minimum of 8ms (the fastest a
            // genuine 120Hz iOS sample arrives) caps that per-sample velocity to a physical
            // ceiling. The kMinLiftoffSpeed=205 gate is the primary slow-drag/flick separator;
            // this floor is the secondary guard so micro-dt coalescing can't manufacture speed.
            double dtSeconds = std::max(dtMove.seconds(), 0.008);
            double vx = static_cast<double>(m_driftstackLastTouchPoint.x() - pos.x()) / dtSeconds;
            double vy = static_cast<double>(m_driftstackLastTouchPoint.y() - pos.y()) / dtSeconds;
            // EWMA: 0.45 of the new sample, 0.55 of history — recent moves dominate without a single noisy
            // last sample throwing the coast off. (First contributing move: history is 0, so v ≈ 0.45·v0,
            // which the next moves quickly converge upward — fine for a multi-move flick.)
            constexpr double kAlpha = 0.45;
            m_driftstackScrollVelocity = WebCore::FloatSize(
                kAlpha * vx + (1 - kAlpha) * m_driftstackScrollVelocity.width(),
                kAlpha * vy + (1 - kAlpha) * m_driftstackScrollVelocity.height());
        }
        m_driftstackLastTouchPoint = pos;
        return;
    }
    case WebEventType::TouchEnd:
        m_driftstackTouchActive = false;   // W2770: finger lifted — later orphan moves must not scroll.
        // W2961 (Step B): if the finger lifted with meaningful velocity, start the momentum coast. The
        // glide scrolls the SAME locked scrollable area the drag used (re-resolved from the fixed locked
        // start point at each tick — never a moving re-hit-test, so it can't switch targets mid-coast),
        // decaying the velocity ~0.998/ms until it falls below a rest threshold. A flick coasts past the
        // last touch point; a slow drag (low lift-off velocity) does NOT fling. Cancelled on the next
        // TouchStart. Entirely gated — no momentum when DRIFTSTACK_SCROLL_MOMENTUM is unset/0.
        if (s_driftstackScrollMomentum) {
            // W3020 (the 3-revert CRUX fix): the lift-off velocity SOURCE. Prefer the harness-PASSED velocity
            // (m_driftstackPendingLiftoffVelocity, set by SetDriftstackPendingScrollMomentum just before this
            // touchEnd) over the fork's own Δpos/dt EWMA. The EWMA over-reads because the WD touch path delivers
            // moves BURST (sub-ms apart, the W3C move `duration` discarded) → its dt is bogus → a SLOW drag
            // over-flings (the failure that bit 3 reverts; the 8ms dt-floor + 205 gate were band-aids on a
            // corrupt dt). The harness is the ONLY place that sees the REAL wall-clock spacing of the moves, so
            // it computes the velocity from the genuine receive-timing and (already) zeroes it below the flick
            // threshold. CONSUME + CLEAR the hint here so it can never bleed into a later gesture. When NO hint
            // was sent (old harness / non-momentum WD caller) fall back to the EWMA — gated, byte-identical to
            // the prior W3000 behavior — so this is strictly additive.
            WebCore::FloatSize liftoff = m_driftstackScrollVelocity; // EWMA fallback
            if (m_driftstackPendingLiftoffVelocity) {
                liftoff = *m_driftstackPendingLiftoffVelocity;       // harness receive-timing velocity (the truth)
                m_driftstackPendingLiftoffVelocity = std::nullopt;   // consume — never carries to the next gesture
            }
            // Lift-off gate: below ~205 px/s the release is a slow drag, not a flick; starting a coast
            // would add a detectable micro-creep / fling on a deliberate slow drag. iOS likewise does
            // not fling a slow release. (The harness ALSO gates at 205 and sends 0 below it; this is the
            // fork-side re-gate so a near-threshold passed value, or an EWMA fallback, can't sneak a coast.)
            // W2995/W3000: thresholds/decay live in Shared/DriftstackScrollCoastMath.h so the live coast
            // and its unit test share one source of truth (kMinLiftoffSpeed = 205 px/s — raised from 80
            // on A1's real-device fling-begin capture to separate slow-drag ~190 from flick ~1187).
            m_driftstackScrollVelocity = liftoff; // the coast tick reads m_driftstackScrollVelocity as the live velocity
            double speed = std::hypot(m_driftstackScrollVelocity.width(), m_driftstackScrollVelocity.height());
            if (WebKit::DriftstackScrollCoast::shouldStartCoast(speed)) {
                if (!m_driftstackScrollCoastTimer) {
                    m_driftstackScrollCoastTimer = makeUnique<RunLoop::Timer>(RunLoop::mainSingleton(),
                        "WebPage::DriftstackScrollCoastTimer"_s, this, &WebPage::driftstackScrollCoastTick);
                }
                m_driftstackCoastLastTick = WTF::MonotonicTime::now();
                // ~60 Hz glide ticks (matches the display refresh the drag samples at). The decay is
                // frame-rate-normalized in the tick via pow(0.998, dt_ms), so an occasional dropped/late
                // tick decelerates proportionally and never jumps.
                m_driftstackScrollCoastTimer->startRepeating(WTF::Seconds(1.0 / 60.0));
            } else
                m_driftstackScrollVelocity = { };
        }
        // W3010: if the finger lifted while the page was over-scrolled past its boundary (a stretch is
        // accumulated), spring it back to the edge with the iOS τ=191ms exponential relaxation. A new
        // TouchStart-started coast does NOT pre-empt this (the coast re-resolves the boundary each tick and
        // re-feeds the stretch); but a pure drag-to-edge-and-release lands here. Gated — no-op when the gate is
        // off (the stretch is never accumulated, so this is dead state).
        if (s_driftstackRubberBand && (m_driftstackRubberStretchX || m_driftstackRubberStretchY))
            driftstackBeginRubberBandRelax();
        break;
    case WebEventType::TouchCancel:
        // W1418: a cancelled touch (system gesture / scroll-takeover) is definitively NOT a tap —
        // clear the pending-tap state so a later touchEnd can't synthesize a spurious click on the
        // cancelled sequence. (Without this, TouchCancel fell through to `default` leaving the flag set.)
        m_driftstackPotentialTap = false;
        m_driftstackTouchActive = false;   // W2770: cancelled sequence — no active finger.
        // W2961: a cancelled sequence stops any in-flight coast too (system gesture / scroll-takeover).
        if (s_driftstackScrollMomentum) {
            if (m_driftstackScrollCoastTimer && m_driftstackScrollCoastTimer->isActive())
                m_driftstackScrollCoastTimer->stop();
            m_driftstackScrollVelocity = { };
            m_driftstackPendingLiftoffVelocity = std::nullopt; // W3020: a cancelled sequence drops the lift-off hint.
        }
        // W3010: a cancelled sequence (system gesture / scroll-takeover) springs any accumulated stretch back
        // to the boundary (don't leave the page parked off-edge). Same relaxation as a normal lift-off.
        if (s_driftstackRubberBand && (m_driftstackRubberStretchX || m_driftstackRubberStretchY))
            driftstackBeginRubberBandRelax();
        return;
    default:
        return;
    }
    bool wasTap = m_driftstackPotentialTap;
    m_driftstackPotentialTap = false;
    if (!wasTap || touchWasHandled)
        return;
    RefPtr localMainFrame = this->localMainFrame();
    if (!localMainFrame)
        return;
    // Fire the compatibility mouse sequence (mousedown→mouseup→click) a real iPhone tap produces — the
    // same handleMousePress/ReleaseEvent calls completeSyntheticClick makes internally, but inline (its
    // wrapper is iOS-only). EventHandler hit-tests at the point and dispatches the click on the target,
    // so a button/link finally activates. SyntheticClickType::OneFingerTap + ForceAtClick + UserDriven
    // mirror a genuine tap's click (UserDriven, not Automation — no detection tell).
    // W2743: fire the click at the gesture's START point, NOT the current `pos` (= the TouchEnd lift-off).
    // `pos` drifts up to tapSlop (18px) from the touch-down within a single tap (finger settlement / trackpad
    // jitter), so using it landed the click offset from where the user touched — and hit the wrong element near
    // boundaries (worsened by raising tapSlop 10→18, W2740). Real iOS commitPotentialTap activates the element
    // under the recognized START point, not the lift-off. m_driftstackTapStartPoint is window-space (W2448) and
    // handleMousePress/Release do their own windowToContents — same as the old path; it is also coherent with the
    // scroll-lock hit-test, which already keys off m_driftstackTapStartPoint (line 4298). Clean taps (start==end)
    // are unaffected.
    auto tapPoint = WebCore::flooredIntPoint(m_driftstackTapStartPoint);
    auto synthMouseEvent = [&](WebCore::PlatformEvent::Type type) {
        return WebCore::PlatformMouseEvent { tapPoint, tapPoint, WebCore::MouseButton::Left, type, 1, { },
            WTF::MonotonicTime::now(), WebCore::ForceAtClick, WebCore::SyntheticClickType::OneFingerTap,
            WebCore::MouseEventInputSource::UserDriven };
    };
    localMainFrame->eventHandler().handleMousePressEvent(synthMouseEvent(WebCore::PlatformEvent::Type::MousePressed));
    localMainFrame->eventHandler().handleMouseReleaseEvent(synthMouseEvent(WebCore::PlatformEvent::Type::MouseReleased));
}

// W2961 (founder "slide like a new iPhone", hunt #3 — Step B kinetic momentum coast). One decel-glide
// step, fired at ~60 Hz from TouchEnd until the velocity decays below rest. Defined INSIDE the
// PLATFORM(DRIFTSTACK) block so the symbol co-locates with its only caller (the cont.⁵ build-failure
// lesson: a bare-IOS_TOUCH_EVENTS def didn't link). This path runs ONLY when DRIFTSTACK_SCROLL_MOMENTUM
// is set — the timer is never started otherwise. It is a SCROLL-FEEL change, not a fingerprint surface:
// the coast scrolls via the same trusted engine path the drag uses (view->scrollBy /
// scrollToPositionWithoutAnimation) — no synthetic wheel, no JS, no isTrusted=false event.
void WebPage::driftstackScrollCoastTick()
{
    auto now = WTF::MonotonicTime::now();
    WTF::Seconds rawDt = now - m_driftstackCoastLastTick;
    m_driftstackCoastLastTick = now;
    // Guard a degenerate/zero or absurd dt (timer reschedule jitter, debugger pause) — cap to ~50ms so a
    // long stall can never lurch the page by a huge single step; skip a non-positive dt entirely.
    // W2995: the cap + decay + thresholds are the PURE math in Shared/DriftstackScrollCoastMath.h, shared
    // verbatim with the unit test (DriftstackScrollCoastMathTests). Behavior is byte-identical to the prior
    // inline form: clampTickSeconds bounds only the upper end (50ms), the <=0 skip is unchanged.
    if (rawDt <= 0_s)
        return;
    double dtSeconds = WebKit::DriftstackScrollCoast::clampTickSeconds(rawDt.seconds());
    double dtMs = dtSeconds * 1000.0;

    // Distance to scroll this frame = current velocity (px/s) × dt. Carry sub-pixel via static_cast<int>
    // truncation-toward-zero (sign-preserving, like the W2761 drag remainder); the fractional part is
    // re-derived next tick from the velocity, so no separate remainder accumulator is needed.
    double stepX = WebKit::DriftstackScrollCoast::offsetForTick(m_driftstackScrollVelocity.width(), dtSeconds);
    double stepY = WebKit::DriftstackScrollCoast::offsetForTick(m_driftstackScrollVelocity.height(), dtSeconds);
    int sdx = static_cast<int>(stepX);
    int sdy = static_cast<int>(stepY);

    // Decay the velocity. iOS UIScrollView.DecelerationRate.normal ≈ 0.998 per ms; frame-rate-normalize
    // via pow(0.998, dt_ms) so a 16.7ms tick decays by ~0.998^16.7 and an occasional late tick decays
    // proportionally (never a discontinuity). NOTE: the exact decay constant is a behavioral TELL and is
    // anchored on Apple's published 0.998/ms — re-validate against a fresh multi-flick iOS capture before
    // flipping the gate on (per project_perfect_scroll_stepB_design).
    double decay = WebKit::DriftstackScrollCoast::decayFactorForTickMs(dtMs);
    m_driftstackScrollVelocity = WebCore::FloatSize(
        m_driftstackScrollVelocity.width() * decay,
        m_driftstackScrollVelocity.height() * decay);

    // Stop once the coast slows below ~30 px/s (sub-perceptible drift) — like iOS settling to rest.
    if (WebKit::DriftstackScrollCoast::isAtRest(std::hypot(m_driftstackScrollVelocity.width(), m_driftstackScrollVelocity.height()))) {
        if (m_driftstackScrollCoastTimer)
            m_driftstackScrollCoastTimer->stop();
        m_driftstackScrollVelocity = { };
        return;
    }

    if (!sdx && !sdy)
        return; // this frame's sub-pixel step truncated to 0; the velocity carries to the next tick.

    RefPtr localMainFrame = this->localMainFrame();
    if (!localMainFrame) {
        if (m_driftstackScrollCoastTimer)
            m_driftstackScrollCoastTimer->stop();
        m_driftstackScrollVelocity = { };
        return;
    }
    RefPtr view = localMainFrame->view();
    if (!view) {
        if (m_driftstackScrollCoastTimer)
            m_driftstackScrollCoastTimer->stop();
        m_driftstackScrollVelocity = { };
        return;
    }

    // Resolve the coast target from the FIXED locked start point (m_driftstackTapStartPoint) — the SAME
    // hit-test the drag used (W2402). Re-resolving the fixed point each tick yields the same scrollable
    // area (it can't switch mid-coast since the point never moves), while avoiding a dangling WeakPtr to a
    // scroller torn down during the glide. Inner overflow scroller → scroll it (clamped to its range, with
    // over-scroll chaining to the page, mirroring the W2790 drag behavior); else the main frame view.
    WebCore::ScrollableArea* area = nullptr;
    auto htr = localMainFrame->eventHandler().hitTestResultAtPoint(
        view->windowToContents(WebCore::flooredIntPoint(m_driftstackTapStartPoint)),
        { WebCore::HitTestRequest::Type::ReadOnly, WebCore::HitTestRequest::Type::Active, WebCore::HitTestRequest::Type::DisallowUserAgentShadowContent });
    if (RefPtr node = htr.innerNode())
        area = localMainFrame->eventHandler().enclosingScrollableArea(node.get());

    if (area && area != static_cast<WebCore::ScrollableArea*>(view.get())) {
        auto cur = area->scrollPosition();
        auto minP = area->minimumScrollPosition();
        auto maxP = area->maximumScrollPosition();
        int wantX = cur.x() + sdx, wantY = cur.y() + sdy;
        int clampX = std::max(minP.x(), std::min(maxP.x(), wantX));
        int clampY = std::max(minP.y(), std::min(maxP.y(), wantY));
        area->scrollToPositionWithoutAnimation(WebCore::FloatPoint(clampX, clampY));
        int leftX = wantX - clampX, leftY = wantY - clampY;
        if (leftX || leftY)
            driftstackScrollMainFrameWithOverscroll(*view, leftX, leftY, s_driftstackRubberBandCoast()); // W3010: chain + bounce
    } else
        driftstackScrollMainFrameWithOverscroll(*view, sdx, sdy, s_driftstackRubberBandCoast()); // W3010

    // W3010: a momentum coast that drove the page past its boundary leaves a stretch; once that happens, end
    // the velocity coast and let the τ=191ms relaxation spring it back (iOS: a flick into the edge bounces).
    if (s_driftstackRubberBandCoast() && (m_driftstackRubberStretchX || m_driftstackRubberStretchY)) {
        if (m_driftstackScrollCoastTimer)
            m_driftstackScrollCoastTimer->stop();
        m_driftstackScrollVelocity = { };
        driftstackBeginRubberBandRelax();
    }
}

// W3020 (the 3-revert crux fix — RECEIVE-TIMING lift-off velocity): IPC handler for the harness's
// SetDriftstackPendingScrollMomentum. The harness, having recorded the REAL wall-clock spacing of the
// drag's touchMoves (which the fork's burst-delivered WD path cannot see), computes the lift-off velocity
// and sends it here IMMEDIATELY BEFORE the touchEnd. We simply STASH it; the very next TouchEnd consumes +
// clears it (and re-gates it at kMinLiftoffSpeed). An explicit (0,0) is a valid value (a slow drag the
// harness classified as no-coast) and correctly arms no coast. Fully gated: when DRIFTSTACK_SCROLL_MOMENTUM
// is off, TouchEnd never reads this field — so even a stray hint is inert. NaN/Inf-guarded so a malformed
// IPC value can't seed a runaway coast.
void WebPage::setDriftstackPendingScrollMomentum(float vx, float vy)
{
    if (!std::isfinite(vx) || !std::isfinite(vy)) {
        m_driftstackPendingLiftoffVelocity = std::nullopt;
        return;
    }
    m_driftstackPendingLiftoffVelocity = WebCore::FloatSize(vx, vy);
}

// W3010: read the DRIFTSTACK_RUBBERBAND_IOS gate once (the coast tick is not the touch handler, so it can't
// see the touch handler's static). Same env idiom; default-OFF.
bool WebPage::s_driftstackRubberBandCoast()
{
    static const bool enabled = [] {
        const char* e = getenv("DRIFTSTACK_RUBBERBAND_IOS");
        return e && e[0] && e[0] != '0';
    }();
    return enabled;
}

// W3010: scroll the main FRAME VIEW by (dx,dy); when rubberBandOn, the px past the page's own boundary that
// the view couldn't consume is absorbed into the over-scroll STRETCH and the content is pushed past the edge
// (unclamped) so it visibly translates (the iOS rubber-band). When off, this is a plain clamped view->scrollBy
// (byte-identical to the prior behavior). The stretch is signed per-axis (+ past max, - past min) and is
// relaxed back to the boundary by driftstackRubberBandTick on lift-off / coast-end.
void WebPage::driftstackScrollMainFrameWithOverscroll(WebCore::LocalFrameView& view, int dx, int dy, bool rubberBandOn)
{
    if (!rubberBandOn) {
        view.scrollBy(WebCore::IntSize(dx, dy)); // unchanged hard-clamped behavior
        return;
    }

    // ── 1) If a stretch is already accumulated, a delta in the OPPOSITE direction cancels it FIRST (the
    //       finger pulling the stretched content back toward the boundary), before any real-content scroll.
    //       Per-axis, sign-aware. scrollBy uses screen-delta convention (finger up → positive delta → content
    //       up → scrollPosition increases), so a stretch past max (positive) is reduced by a positive delta's
    //       opposite, i.e. a NEGATIVE dx/dy reduces a positive stretch. We treat dx/dy in scroll-position
    //       space (same as scrollBy): positive grows a positive (past-max) stretch.
    auto applyAxisToStretch = [](double& stretch, int& delta) {
        if (!stretch || !delta)
            return;
        // Opposite-sign delta shrinks the stretch toward 0; same-sign grows it (handled in step 3).
        if ((stretch > 0 && delta < 0) || (stretch < 0 && delta > 0)) {
            double absorb = std::min(std::abs(static_cast<double>(delta)), std::abs(stretch));
            stretch += (stretch > 0 ? -absorb : absorb);
            delta -= (delta > 0 ? static_cast<int>(absorb) : -static_cast<int>(absorb));
        }
    };
    int dX = dx, dY = dy;
    applyAxisToStretch(m_driftstackRubberStretchX, dX);
    applyAxisToStretch(m_driftstackRubberStretchY, dY);

    // ── 2) Move the real content by whatever delta remains, clamped to range; capture the px past the page's
    //       own boundary (the over-boundary leftover) — signed.
    auto minP = view.minimumScrollPosition();
    auto maxP = view.maximumScrollPosition();
    auto cur = view.scrollPosition();
    int baseX = std::max(minP.x(), std::min(maxP.x(), cur.x())); // strip any current stretch overshoot
    int baseY = std::max(minP.y(), std::min(maxP.y(), cur.y()));
    int wantX = baseX + dX, wantY = baseY + dY;
    int clampX = std::max(minP.x(), std::min(maxP.x(), wantX));
    int clampY = std::max(minP.y(), std::min(maxP.y(), wantY));
    int overX = wantX - clampX; // px past the page boundary this delta wants (signed)
    int overY = wantY - clampY;
    view.scrollToPositionWithoutAnimation(WebCore::FloatPoint(clampX, clampY), WebCore::ScrollClamping::Clamped);
    m_driftstackRubberBoundaryPos = WebCore::FloatPoint(clampX, clampY);

    // ── 3) Grow the stretch with the over-boundary leftover via the iOS resistance curve (diminishing return).
    if (overX || overY) {
        auto visible = view.visibleSize();
        double incX = WebKit::DriftstackRubberBand::resistedStretchIncrement(std::abs(overX), std::abs(m_driftstackRubberStretchX), visible.width());
        double incY = WebKit::DriftstackRubberBand::resistedStretchIncrement(std::abs(overY), std::abs(m_driftstackRubberStretchY), visible.height());
        m_driftstackRubberStretchX += (overX < 0 ? -incX : incX);
        m_driftstackRubberStretchY += (overY < 0 ? -incY : incY);
    }

    // ── 4) Render: if any stretch remains, push the view past the edge (unclamped); else snap to the boundary
    //       and drop the unclamped override. setAllowsUnclampedScrollPositionForTesting is the supported hook
    //       that lets scrollToPositionWithoutAnimation(..., Unclamped) keep an off-edge offset for a frame.
    if (m_driftstackRubberStretchX || m_driftstackRubberStretchY) {
        if (!m_driftstackRubberHadUnclamped) {
            view.setAllowsUnclampedScrollPositionForTesting(true);
            m_driftstackRubberHadUnclamped = true;
        }
        view.scrollToPositionWithoutAnimation(
            WebCore::FloatPoint(clampX + std::lround(m_driftstackRubberStretchX), clampY + std::lround(m_driftstackRubberStretchY)),
            WebCore::ScrollClamping::Unclamped);
    } else if (m_driftstackRubberHadUnclamped) {
        view.setAllowsUnclampedScrollPositionForTesting(false);
        m_driftstackRubberHadUnclamped = false;
    }
}

// W3010: start the τ=191ms exponential spring-back of the current over-boundary stretch to the boundary.
void WebPage::driftstackBeginRubberBandRelax()
{
    if (!m_driftstackRubberStretchX && !m_driftstackRubberStretchY) {
        driftstackEndRubberBand();
        return;
    }
    if (!m_driftstackRubberBandTimer) {
        m_driftstackRubberBandTimer = makeUnique<RunLoop::Timer>(RunLoop::mainSingleton(),
            "WebPage::DriftstackRubberBandTimer"_s, this, &WebPage::driftstackRubberBandTick);
    }
    m_driftstackRubberLastTick = WTF::MonotonicTime::now();
    // ~60 Hz relaxation ticks (display refresh). The decay is frame-rate-normalized in the tick via
    // exp(-dt/τ), so an occasional late tick relaxes proportionally (never a discontinuity).
    m_driftstackRubberBandTimer->startRepeating(WTF::Seconds(1.0 / 60.0));
}

// W3010: clean up the rubber-band state — snap the view exactly to the boundary, restore the unclamped flag,
// stop the timer, zero the stretch. Idempotent.
void WebPage::driftstackEndRubberBand()
{
    if (m_driftstackRubberBandTimer && m_driftstackRubberBandTimer->isActive())
        m_driftstackRubberBandTimer->stop();
    if (RefPtr localMainFrame = this->localMainFrame()) {
        if (RefPtr view = localMainFrame->view()) {
            // Snap exactly to the boundary the stretch was measured from (clamped), then drop the unclamped
            // override so subsequent normal scrolls stay hard-clamped.
            view->scrollToPositionWithoutAnimation(m_driftstackRubberBoundaryPos, WebCore::ScrollClamping::Clamped);
            if (m_driftstackRubberHadUnclamped)
                view->setAllowsUnclampedScrollPositionForTesting(false);
        }
    }
    m_driftstackRubberHadUnclamped = false;
    m_driftstackRubberStretchX = 0;
    m_driftstackRubberStretchY = 0;
}

// W3010: one relaxation step of the rubber-band spring-back, fired at ~60Hz from driftstackBeginRubberBandRelax
// until the stretch settles below kRestPx. Relaxes the stretch as e(t)=e0*exp(-t/τ) with τ=191ms (the
// BS-captured iOS engine constant), pushing the view to boundary+stretch (unclamped) each tick. Behavioral
// (scroll-feel) only — scrolls via the same trusted engine path the drag uses.
void WebPage::driftstackRubberBandTick()
{
    auto now = WTF::MonotonicTime::now();
    WTF::Seconds rawDt = now - m_driftstackRubberLastTick;
    m_driftstackRubberLastTick = now;
    if (rawDt <= 0_s)
        return;
    double dtSeconds = WebKit::DriftstackRubberBand::clampTickSeconds(rawDt.seconds());

    // Relax the stretch toward zero: stretch *= exp(-dt/τ). Frame-rate-normalized.
    double factor = WebKit::DriftstackRubberBand::relaxFactorForTick(dtSeconds);
    m_driftstackRubberStretchX *= factor;
    m_driftstackRubberStretchY *= factor;

    double mag = std::hypot(m_driftstackRubberStretchX, m_driftstackRubberStretchY);
    if (WebKit::DriftstackRubberBand::isAtRest(mag)) {
        driftstackEndRubberBand(); // settled — snap to the boundary, restore clamping
        return;
    }

    RefPtr localMainFrame = this->localMainFrame();
    if (!localMainFrame) {
        driftstackEndRubberBand();
        return;
    }
    RefPtr view = localMainFrame->view();
    if (!view) {
        driftstackEndRubberBand();
        return;
    }
    // Push the view to boundary + the relaxed stretch (unclamped so it can stay past the edge this frame).
    view->scrollToPositionWithoutAnimation(
        WebCore::FloatPoint(m_driftstackRubberBoundaryPos.x() + std::lround(m_driftstackRubberStretchX),
            m_driftstackRubberBoundaryPos.y() + std::lround(m_driftstackRubberStretchY)),
        WebCore::ScrollClamping::Unclamped);
}
#endif // PLATFORM(DRIFTSTACK)
#endif

void WebPage::cancelPointer(WebCore::PointerID pointerId, const WebCore::IntPoint& documentPoint)
{
    m_page->pointerCaptureController().cancelPointer(pointerId, documentPoint);
}

void WebPage::touchWithIdentifierWasRemoved(WebCore::PointerID pointerId)
{
    m_page->pointerCaptureController().touchWithIdentifierWasRemoved(pointerId);
}

void WebPage::resetPointerCapture()
{
    m_page->pointerCaptureController().reset();
}

#if ENABLE(MAC_GESTURE_EVENTS)
static HandleUserInputEventResult handleGestureEvent(FrameIdentifier frameID, const WebGestureEvent& event, Page* page)
{
    RefPtr frame = WebProcess::singleton().webFrame(frameID);
    if (!frame)
        return false;

    RefPtr coreLocalFrame = frame->coreLocalFrame();
    if (!coreLocalFrame)
        return false;
    return coreLocalFrame->eventHandler().handleGestureEvent(platform(event));
}

void WebPage::gestureEvent(FrameIdentifier frameID, const WebGestureEvent& gestureEvent, CompletionHandler<void(std::optional<WebEventType>, bool, std::optional<RemoteUserInputEventData>)>&& completionHandler)
{
    CurrentEvent currentEvent(gestureEvent);
    auto result = handleGestureEvent(frameID, gestureEvent, m_page.get());
    completionHandler(gestureEvent.type(), result.wasHandled(), result.remoteUserInputEventData());
}
#endif

bool WebPage::scroll(Page* page, ScrollDirection direction, ScrollGranularity granularity)
{
    RefPtr focusedOrMainFrame = page->focusController().focusedOrMainFrame();
    if (!focusedOrMainFrame)
        return false;
    return focusedOrMainFrame->eventHandler().scrollRecursively(direction, granularity);
}

bool WebPage::logicalScroll(Page* page, ScrollLogicalDirection direction, ScrollGranularity granularity)
{
    RefPtr focusedOrMainFrame = page->focusController().focusedOrMainFrame();
    if (!focusedOrMainFrame)
        return false;
    return focusedOrMainFrame->eventHandler().logicalScrollRecursively(direction, granularity);
}

bool WebPage::scrollBy(WebCore::ScrollDirection scrollDirection, WebCore::ScrollGranularity scrollGranularity)
{
    return scroll(m_page.get(), static_cast<ScrollDirection>(scrollDirection), static_cast<ScrollGranularity>(scrollGranularity));
}

void WebPage::centerSelectionInVisibleArea()
{
    RefPtr frame = corePage()->focusController().focusedOrMainFrame();
    if (!frame)
        return;
    protect(frame->selection())->revealSelection({ SelectionRevealMode::Reveal, ScrollAlignment::alignCenterAlways });
    findController().showFindIndicatorInSelection();
}

bool WebPage::isControlledByAutomation() const
{
    return m_page->isControlledByAutomation();
}

void WebPage::setControlledByAutomation(bool controlled)
{
#if PLATFORM(DRIFTSTACK)
    // V-AUTOMATION-TELL-CHOKEPOINT (see WebPage construction): WebContent's Page must
    // never observe automation control, regardless of later UIProcess toggles, so the
    // web-observable automation-tell surface stays neutralized. UIProcess automation
    // state (WebPageProxy::m_controlledByAutomation) is tracked separately.
    UNUSED_PARAM(controlled);
    m_page->setControlledByAutomation(false);
#else
    m_page->setControlledByAutomation(controlled);
#endif
}

CheckedRef<PageInspectorTarget> WebPage::ensureInspectorTarget()
{
    if (!m_inspectorTarget)
        m_inspectorTarget = makeUnique<PageInspectorTarget>(*this);
    return *m_inspectorTarget;
}

void WebPage::connectInspector(Inspector::FrontendChannel::ConnectionType connectionType)
{
    ensureInspectorTarget()->connect(connectionType);
}

void WebPage::disconnectInspector()
{
    ensureInspectorTarget()->disconnect();
}

void WebPage::sendMessageToTargetBackend(const String& message)
{
    ensureInspectorTarget()->sendMessageToTargetBackend(message);
}

void WebPage::insertNewlineInQuotedContent()
{
    RefPtr frame = corePage()->focusController().focusedOrMainFrame();
    if (!frame)
        return;
    if (frame->selection().isNone())
        return;
    protect(frame->editor())->insertParagraphSeparatorInQuotedContent();
}

#if ENABLE(REMOTE_INSPECTOR)
void WebPage::setIndicating(bool indicating)
{
    m_page->inspectorController().setIndicating(indicating);
}
#endif

void WebPage::setBackgroundColor(const std::optional<WebCore::Color>& backgroundColor)
{
    if (m_backgroundColor == backgroundColor)
        return;

    m_backgroundColor = backgroundColor;

    if (RefPtr frameView = localMainFrameView())
        frameView->updateBackgroundRecursively(backgroundColor);

    RefPtr drawingArea = m_drawingArea;
#if USE(COORDINATED_GRAPHICS) || USE(TEXTURE_MAPPER)
    drawingArea->backgroundColorDidChange();
#endif
    drawingArea->setNeedsDisplay();
}

void WebPage::setObscuredContentInsets(const FloatBoxExtent& obscuredContentInsets)
{
    RefPtr page = m_page;
    if (obscuredContentInsets == page->obscuredContentInsets())
        return;

    page->setObscuredContentInsets(obscuredContentInsets);

#if ENABLE(PDF_PLUGIN)
    for (Ref pluginView : m_pluginViews)
        pluginView->obscuredContentInsetsDidChange();
#endif
}

#if ENABLE(BANNER_VIEW_OVERLAYS)
void WebPage::setHasBannerViewOverlay(bool hasBannerViewOverlay)
{
    m_page->setHasBannerViewOverlay(hasBannerViewOverlay);
}
#endif

void WebPage::viewWillStartLiveResize()
{
    if (!m_page)
        return;

    // FIXME: This should propagate to all ScrollableAreas.
    RefPtr frame = corePage()->focusController().focusedOrMainFrame();
    if (!frame)
        return;

    if (RefPtr view = frame->view())
        view->willStartLiveResize();
}

void WebPage::viewWillEndLiveResize()
{
    if (!m_page)
        return;

    // FIXME: This should propagate to all ScrollableAreas.
    RefPtr frame = corePage()->focusController().focusedOrMainFrame();
    if (!frame)
        return;

    if (RefPtr view = frame->view())
        view->willEndLiveResize();
}

void WebPage::setInitialFocus(bool forward, bool isKeyboardEventValid, const std::optional<WebKeyboardEvent>& event, CompletionHandler<void()>&& completionHandler)
{
    if (!m_page)
        return completionHandler();

    SetForScope userIsInteractingChange { m_userIsInteracting, true };

    CheckedRef focusController { m_page->focusController() };
    RefPtr frame = focusController->focusedOrMainFrame();
    if (!frame)
        return completionHandler();
    protect(frame->document())->setFocusedElement(nullptr);

    if (isKeyboardEventValid && event && event->type() == WebEventType::KeyDown) {
        PlatformKeyboardEvent platformEvent(platform(CheckedRef { *event }));
        platformEvent.disambiguateKeyDownEvent(PlatformEvent::Type::RawKeyDown);
        focusController->setInitialFocus(forward ? FocusDirection::Forward : FocusDirection::Backward, &KeyboardEvent::create(platformEvent, &frame->windowProxy()).get());
        completionHandler();
        return;
    }

    focusController->setInitialFocus(forward ? FocusDirection::Forward : FocusDirection::Backward, nullptr);
    completionHandler();
}

void WebPage::setCanStartMediaTimerFired()
{
    if (RefPtr page = m_page)
        page->setCanStartMedia(true);
}

void WebPage::updateIsInWindow(bool isInitialState)
{
    bool isInWindow = m_activityState.contains(WebCore::ActivityState::IsInWindow);

    if (!isInWindow) {
        m_setCanStartMediaTimer.stop();
        protect(corePage())->setCanStartMedia(false);

        // The WebProcess does not yet know about this page; no need to tell it we're leaving the window.
        if (!isInitialState)
            WebProcess::singleton().pageWillLeaveWindow(m_identifier);
    } else {
        // Defer the call to Page::setCanStartMedia() since it ends up sending a synchronous message to the UI process
        // in order to get plug-in connections, and the UI process will be waiting for the Web process to update the backing
        // store after moving the view into a window, until it times out and paints white. See <rdar://problem/9242771>.
        if (m_mayStartMediaWhenInWindow)
            m_setCanStartMediaTimer.startOneShot(0_s);

        WebProcess::singleton().pageDidEnterWindow(m_identifier);
    }

    if (isInWindow)
        layoutIfNeeded();

#if ENABLE(PDF_PLUGIN)
    for (Ref pluginView : m_pluginViews)
        pluginView->didChangeIsInWindow();
#endif
}

void WebPage::visibilityDidChange()
{
    bool isVisible = m_activityState.contains(ActivityState::IsVisible);
    if (!isVisible) {
        // We save the document / scroll state when backgrounding a tab so that we are able to restore it
        // if it gets terminated while in the background.
        if (RefPtr frame = m_mainFrame->coreLocalFrame())
            frame->loader().history().saveDocumentAndScrollState();
    }
}

void WebPage::windowActivityDidChange()
{
#if ENABLE(PDF_PLUGIN)
    for (Ref pluginView : m_pluginViews)
        pluginView->windowActivityDidChange();
#endif
}

void WebPage::setActivityState(OptionSet<ActivityState> activityState, ActivityStateChangeID activityStateChangeID, CompletionHandler<void()>&& callback)
{
    LOG_WITH_STREAM(ActivityState, stream << "WebPage " << identifier().toUInt64() << " setActivityState to " << activityState);

#if PLATFORM(DRIFTSTACK)
    // V-FOREGROUND-CHOKEPOINT: keep the page foreground+focused regardless of the UIProcess window
    // state (see helper above), so a non-foreground fleet window never flips visibilityState→hidden
    // / pauses rAF / drops hasFocus mid-session.
    activityState = driftstackForceForeground(activityState);
#endif

    auto changed = m_activityState ^ activityState;
    m_activityState = activityState;

    if (changed)
        updateThrottleState();

    ASSERT_WITH_MESSAGE(m_page, "setActivityState called on %" PRIu64 " but WebCore page was null", identifier().toUInt64());
    if (RefPtr page = m_page) {
        SetForScope currentlyChangingActivityState { m_lastActivityStateChanges, changed };
        page->setActivityState(activityState);
    }

    protect(drawingArea())->activityStateDidChange(changed, activityStateChangeID, WTF::move(callback));
    WebProcess::singleton().pageActivityStateDidChange(m_identifier, changed);

    if (changed & ActivityState::IsInWindow)
        updateIsInWindow();

    if (changed & ActivityState::IsVisible)
        visibilityDidChange();

    if (changed & ActivityState::WindowIsActive)
        windowActivityDidChange();
}

void WebPage::didStartPageTransition()
{
    freezeLayerTree(LayerTreeFreezeReason::PageTransition);

#if HAVE(TOUCH_BAR)
    bool hasPreviouslyFocusedDueToUserInteraction = m_userInteractionsSincePageTransition.contains(UserInteractionFlag::FocusedElement);
    m_userInteractionsSincePageTransition = { };
#endif
    m_lastEditorStateWasContentEditable = EditorStateIsContentEditable::Unset;

#if PLATFORM(MAC)
    if (hasPreviouslyFocusedDueToUserInteraction)
        send(Messages::WebPageProxy::SetHasFocusedElementWithUserInteraction(false));
#endif

#if HAVE(TOUCH_BAR)
    if (m_isTouchBarUpdateSuppressedForHiddenContentEditable) {
        m_isTouchBarUpdateSuppressedForHiddenContentEditable = false;
        send(Messages::WebPageProxy::SetIsTouchBarUpdateSuppressedForHiddenContentEditable(m_isTouchBarUpdateSuppressedForHiddenContentEditable));
    }

    if (m_isNeverRichlyEditableForTouchBar) {
        m_isNeverRichlyEditableForTouchBar = false;
        send(Messages::WebPageProxy::SetIsNeverRichlyEditableForTouchBar(m_isNeverRichlyEditableForTouchBar));
    }
#endif

#if PLATFORM(IOS_FAMILY)
    m_isShowingInputViewForFocusedElement = false;
    // This is used to enable a first-tap quirk.
    m_hasHandledSyntheticClick = false;
#endif
}

void WebPage::didCompletePageTransition()
{
    unfreezeLayerTree(LayerTreeFreezeReason::PageTransition);
}

void WebPage::setMainFrameDocumentVisualUpdatesAllowed(bool allowed)
{
    if (allowed)
        unfreezeLayerTree(LayerTreeFreezeReason::DocumentVisualUpdatesNotAllowed);
    else
        freezeLayerTree(LayerTreeFreezeReason::DocumentVisualUpdatesNotAllowed);
}

void WebPage::show()
{
    send(Messages::WebPageProxy::ShowPage());
}

void WebPage::setIsTakingSnapshotsForApplicationSuspension(bool isTakingSnapshotsForApplicationSuspension)
{
    WEBPAGE_RELEASE_LOG(Resize, "setIsTakingSnapshotsForApplicationSuspension(%d)", isTakingSnapshotsForApplicationSuspension);

    if (m_page)
        m_page->setIsTakingSnapshotsForApplicationSuspension(isTakingSnapshotsForApplicationSuspension);
}

void WebPage::setNeedsDOMWindowResizeEvent()
{
    RefPtr page = m_page;
    if (!page)
        return;

    if (RefPtr localTopDocument = page->localTopDocument())
        localTopDocument->setNeedsDOMWindowResizeEvent();
}

String WebPage::userAgent(const URL& webCoreURL) const
{
    String userAgent = platformUserAgent(webCoreURL);
    if (!userAgent.isEmpty())
        return userAgent;
    return m_userAgent;
}

void WebPage::setUserAgent(String&& userAgent)
{
    if (m_userAgent == userAgent)
        return;

    m_userAgent = WTF::move(userAgent);

    if (RefPtr page = m_page)
        page->userAgentChanged();
}

void WebPage::setHasCustomUserAgent(bool hasCustomUserAgent)
{
    m_hasCustomUserAgent = hasCustomUserAgent;
}

void WebPage::suspendActiveDOMObjectsAndAnimations()
{
    protect(corePage())->suspendActiveDOMObjectsAndAnimations();
}

void WebPage::resumeActiveDOMObjectsAndAnimations()
{
    protect(corePage())->resumeActiveDOMObjectsAndAnimations();
}

void WebPage::suspend(CompletionHandler<void(bool)>&& completionHandler)
{
    RefPtr page = m_page;
    WEBPAGE_RELEASE_LOG(Loading, "suspend: m_page=%p", page.get());
    if (!page)
        return completionHandler(false);

    freezeLayerTree(LayerTreeFreezeReason::PageSuspended);

    m_cachedPage = BackForwardCache::singleton().suspendPage(*page);
    ASSERT(m_cachedPage);
    if (RefPtr mainFrame = m_mainFrame->coreLocalFrame())
        mainFrame->detachFromAllOpenedFrames();
    completionHandler(true);
}

void WebPage::resume(CompletionHandler<void(bool)>&& completionHandler)
{
    RefPtr page = m_page;
    WEBPAGE_RELEASE_LOG(Loading, "resume: m_page=%p", page.get());
    if (!page)
        return completionHandler(false);

    auto cachedPage = std::exchange(m_cachedPage, nullptr);
    ASSERT(cachedPage);
    if (!cachedPage)
        return completionHandler(false);

    cachedPage->restore(*page);
    unfreezeLayerTree(LayerTreeFreezeReason::PageSuspended);
    completionHandler(true);
}

IntPoint WebPage::screenToRootView(const IntPoint& point)
{
    auto sendResult = sendSync(Messages::WebPageProxy::ScreenToRootView(point));
    auto [windowPoint] = sendResult.takeReplyOr(IntPoint { });
    return windowPoint;
}

IntPoint WebPage::rootViewToScreen(const IntPoint& point)
{
    auto sendResult = sendSync(Messages::WebPageProxy::RootViewPointToScreen(point));
    auto [screenPoint] = sendResult.takeReplyOr(IntPoint { });
    return screenPoint;
}

IntRect WebPage::rootViewToScreen(const IntRect& rect)
{
    auto sendResult = sendSync(Messages::WebPageProxy::RootViewRectToScreen(rect.toRectWithExtentsClippedToNumericLimits()));
    auto [screenRect] = sendResult.takeReplyOr(IntRect { });
    return screenRect;
}

IntPoint WebPage::accessibilityScreenToRootView(const IntPoint& point)
{
    auto sendResult = sendSync(Messages::WebPageProxy::AccessibilityScreenToRootView(point));
    auto [windowPoint] = sendResult.takeReplyOr(IntPoint { });
    return windowPoint;
}

IntRect WebPage::rootViewToAccessibilityScreen(const IntRect& rect)
{
    auto sendResult = sendSync(Messages::WebPageProxy::RootViewToAccessibilityScreen(rect));
    auto [screenRect] = sendResult.takeReplyOr(IntRect { });
    return screenRect;
}

#if ENABLE(ACCESSIBILITY_LOCAL_FRAME)
void WebPage::requestFrameScreenPosition(FrameIdentifier frameID)
{
    send(Messages::WebPageProxy::RequestFrameScreenPosition(frameID));
}

void WebPage::scheduleAccessibilityFrameGeometryUpdate()
{
    send(Messages::WebPageProxy::ScheduleAccessibilityFrameGeometryUpdate());
}
#endif

KeyboardUIMode WebPage::keyboardUIMode()
{
    bool fullKeyboardAccessEnabled = WebProcess::singleton().fullKeyboardAccessEnabled();
    return static_cast<KeyboardUIMode>((fullKeyboardAccessEnabled ? KeyboardAccessFull : KeyboardAccessDefault) | (m_tabToLinks ? KeyboardAccessTabsToLinks : 0));
}

void WebPage::runJavaScript(WebFrame* frame, RunJavaScriptParameters&& parameters, ContentWorldIdentifier worldIdentifier, bool wantsResult, CompletionHandler<void(Expected<JavaScriptEvaluationResult, std::optional<WebCore::ExceptionDetails>>)>&& completionHandler)
{
    // NOTE: We need to be careful when running scripts that the objects we depend on don't
    // disappear during script execution.

    if (!frame || !frame->coreLocalFrame()) {
        completionHandler(makeUnexpected(ExceptionDetails { "Unable to execute JavaScript: Target frame could not be found in the page"_s, 0, 0, ExceptionDetails::Type::InvalidTargetFrame }));
        return;
    }

    RefPtr world = m_userContentController->worldForIdentifier(worldIdentifier);
    if (!world) {
        completionHandler(makeUnexpected(ExceptionDetails { "Unable to execute JavaScript: Cannot find specified content world"_s }));
        return;
    }

#if ENABLE(APP_BOUND_DOMAINS)
    if (frame->shouldEnableInAppBrowserPrivacyProtections()) {
        completionHandler(makeUnexpected(ExceptionDetails { "Unable to execute JavaScript in a frame that is not in an app-bound domain"_s, 0, 0, ExceptionDetails::Type::AppBoundDomain }));
        if (RefPtr localTopDocument = protect(corePage())->localTopDocument())
            localTopDocument->addConsoleMessage(MessageSource::Security, MessageLevel::Warning, "Ignoring user script injection for non-app bound domain."_s);
        WEBPAGE_RELEASE_LOG_ERROR(Loading, "runJavaScript: Ignoring user script injection for non app-bound domain");
        return;
    }
#endif
    auto source = WTF::move(parameters.source).release();
    if (!source) {
        completionHandler(makeUnexpected(ExceptionDetails { "Unable to execute JavaScript: out of memory"_s }));
        return;
    }

    bool shouldAllowUserInteraction = [&] {
        if (m_userIsInteracting)
            return true;

        if (parameters.forceUserGesture == ForceUserGesture::No)
            return false;

#if PLATFORM(COCOA)
        if (linkedOnOrAfterSDKWithBehavior(SDKAlignedBehavior::ProgrammaticFocusDuringUserScriptShowsInputViews))
            return true;
#endif

        return false;
    }();

    SetForScope userIsInteractingChange { m_userIsInteracting, shouldAllowUserInteraction };
    auto resolveFunction = [world = Ref { *world }, frame = Ref { *frame }, coreFrame = Ref { *frame->coreLocalFrame() }, wantsResult, completionHandler = WTF::move(completionHandler)] (ValueOrException result) mutable {
        if (!result)
            return completionHandler(makeUnexpected(result.error()));

        if (!wantsResult)
            return completionHandler(makeUnexpected(std::nullopt));

        JSGlobalContextRef context = frame->jsContextForWorld(world.ptr());
        JSValueRef jsValue = toRef(protect(coreFrame->script())->globalObject(Ref { world->coreWorld() }), result.value());
        if (auto result = JavaScriptEvaluationResult::extract(context, jsValue))
            return completionHandler(WTF::move(*result));
        return completionHandler(makeUnexpected(std::nullopt));
    };

    auto mapArguments = [] (auto&& vector) -> std::optional<HashMap<String, Function<JSC::JSValue(JSC::JSGlobalObject&)>>> {
        if (!vector)
            return std::nullopt;
        HashMap<String, Function<JSC::JSValue(JSC::JSGlobalObject&)>> map;
        for (auto&& [key, result] : WTF::move(*vector)) {
            map.set(key, [result = WTF::move(result)] (JSC::JSGlobalObject& globalObject) mutable -> JSC::JSValue {
                return toJS(&globalObject, result.toJS(JSContextGetGlobalContext(toRef(&globalObject))).get());
            });
        }
        return { WTF::move(map) };
    };

    WebCore::RunJavaScriptParameters coreParameters {
        WTF::move(*source),
        WTF::move(parameters.taintedness),
        WTF::move(parameters.sourceURL),
        parameters.runAsAsyncFunction == WebCore::RunAsAsyncFunction::Yes,
        mapArguments(WTF::move(parameters.arguments)),
        parameters.forceUserGesture == WebCore::ForceUserGesture::Yes,
        parameters.removeTransientActivation
    };

    JSLockHolder lock(commonVM());
    protect(protect(frame->coreLocalFrame())->script())->executeAsynchronousUserAgentScriptInWorld(protect(world->coreWorld()), WTF::move(coreParameters), WTF::move(resolveFunction));
}

void WebPage::runJavaScriptInFrameInScriptWorld(RunJavaScriptParameters&& parameters, std::optional<WebCore::FrameIdentifier> frameID, const ContentWorldData& worldData, bool wantsResult, CompletionHandler<void(Expected<JavaScriptEvaluationResult, std::optional<WebCore::ExceptionDetails>>)>&& completionHandler)
{
    WEBPAGE_RELEASE_LOG(Process, "runJavaScriptInFrameInScriptWorld: frameID=%" PRIu64, frameID ? frameID->toUInt64() : 0);
    RefPtr webFrame = frameID ? WebProcess::singleton().webFrame(*frameID) : &mainWebFrame();

    m_userContentController->addContentWorldIfNecessary(worldData);

    runJavaScript(webFrame.get(), WTF::move(parameters), worldData.identifier, wantsResult, [this, protectedThis = Ref { *this }, completionHandler = WTF::move(completionHandler)](auto&& result) mutable {
#if RELEASE_LOG_DISABLED
        UNUSED_PARAM(this);
#endif
        if (!result && result.error())
            WEBPAGE_RELEASE_LOG_ERROR(Process, "runJavaScriptInFrameInScriptWorld: Request to run JavaScript failed with error %" PRIVATE_LOG_STRING, result.error()->message.utf8().data());
        else
            WEBPAGE_RELEASE_LOG(Process, "runJavaScriptInFrameInScriptWorld: Request to run JavaScript succeeded");
        completionHandler(WTF::move(result));
    });
}

void WebPage::getContentsAsString(ContentAsStringIncludesChildFrames includeChildFrames, CompletionHandler<void(const String&)>&& callback)
{
    switch (includeChildFrames) {
    case ContentAsStringIncludesChildFrames::No:
        callback(m_mainFrame->contentsAsString());
        break;
    case ContentAsStringIncludesChildFrames::Yes:
        StringBuilder builder;
        for (RefPtr<Frame> frame = m_mainFrame->coreLocalFrame(); frame; frame = frame->tree().traverseNextRendered()) {
            if (RefPtr webFrame = WebFrame::fromCoreFrame(*frame))
                builder.append(builder.isEmpty() ? ""_s : "\n\n"_s, webFrame->contentsAsString());
        }
        callback(builder.toString());
        break;
    }
}

#if ENABLE(MHTML)
void WebPage::getContentsAsMHTMLData(CompletionHandler<void(const IPC::SharedBufferReference&)>&& callback)
{
    callback(IPC::SharedBufferReference(MHTMLArchive::generateMHTMLData(m_page.get())));
}
#endif

void WebPage::getRenderTreeExternalRepresentation(CompletionHandler<void(const String&)>&& callback)
{
    callback(renderTreeExternalRepresentation());
}

static RefPtr<LocalFrame> frameWithSelection(Page* page)
{
    for (RefPtr frame = page->mainFrame(); frame; frame = frame->tree().traverseNext()) {
        auto* localFrame = dynamicDowncast<LocalFrame>(*frame);
        if (!localFrame)
            continue;
        if (localFrame->selection().isRange())
            return localFrame;
    }
    return nullptr;
}

void WebPage::copyLinkWithHighlight()
{
    RefPtr page = m_page;
    auto url = page->fragmentDirectiveURLForSelectedText();
    RefPtr frame = page->focusController().focusedOrMainFrame();
    if (!frame)
        return;

    if (url.isValid())
        protect(frame->editor())->copyURL(url, { });
}

void WebPage::getSelectionOrContentsAsString(CompletionHandler<void(const String&)>&& callback)
{
    RefPtr focusedOrMainCoreFrame = corePage()->focusController().focusedOrMainFrame();
    RefPtr focusedOrMainFrame = focusedOrMainCoreFrame ? WebFrame::fromCoreFrame(*focusedOrMainCoreFrame) : nullptr;

#if ENABLE(PDF_PLUGIN)
    if (RefPtr pluginView = pluginViewForFrame(focusedOrMainCoreFrame.get())) {
        auto result = pluginView->selectionString();
        if (result.isEmpty())
            result = pluginView->fullDocumentString();
        return callback(WTF::move(result));
    }
#endif

    String resultString = focusedOrMainFrame->selectionAsString();
    if (resultString.isEmpty())
        resultString = focusedOrMainFrame->contentsAsString();
    callback(resultString);
}

void WebPage::getSourceForFrame(FrameIdentifier frameID, CompletionHandler<void(const String&)>&& callback)
{
    String resultString;
    if (RefPtr frame = WebProcess::singleton().webFrame(frameID))
       resultString = frame->source();

    callback(resultString);
}

void WebPage::getMainResourceDataOfFrame(FrameIdentifier frameID, CompletionHandler<void(const std::optional<IPC::SharedBufferReference>&)>&& callback)
{
    RefPtr<FragmentedSharedBuffer> buffer;
    if (RefPtr frame = WebProcess::singleton().webFrame(frameID)) {
        RefPtr coreFrame = frame->coreLocalFrame();
#if ENABLE(PDF_PLUGIN)
        if (RefPtr pluginView = pluginViewForFrame(coreFrame.get()))
            buffer = pluginView->liveResourceData();
        if (!buffer)
#endif
        {
            if (RefPtr loader = coreFrame->loader().documentLoader())
                buffer = loader->mainResourceData();
        }
    }

    callback(IPC::SharedBufferReference(WTF::move(buffer)));
}

static RefPtr<FragmentedSharedBuffer> resourceDataForFrame(LocalFrame* frame, const URL& resourceURL)
{
    RefPtr loader = frame->loader().documentLoader();
    if (!loader)
        return nullptr;

    RefPtr<ArchiveResource> subresource = loader->subresource(resourceURL);
    if (!subresource)
        return nullptr;

    return &subresource->data();
}

void WebPage::getResourceDataFromFrame(FrameIdentifier frameID, const String& resourceURLString, CompletionHandler<void(const std::optional<IPC::SharedBufferReference>&)>&& callback)
{
    RefPtr<FragmentedSharedBuffer> buffer;
    if (RefPtr frame = WebProcess::singleton().webFrame(frameID)) {
        URL resourceURL { resourceURLString };
        buffer = resourceDataForFrame(protect(frame->coreLocalFrame()).get(), resourceURL);
    }

    callback(IPC::SharedBufferReference(WTF::move(buffer)));
}

void WebPage::getWebArchiveOfFrameWithFileName(WebCore::FrameIdentifier frameID, const Vector<WebCore::MarkupExclusionRule>& exclusionRules, const String& fileName, CompletionHandler<void(const std::optional<IPC::SharedBufferReference>&)>&& completionHandler)
{
    std::optional<IPC::SharedBufferReference> result;
#if PLATFORM(COCOA)
    if (RefPtr frame = WebProcess::singleton().webFrame(frameID)) {
        if (RetainPtr<CFDataRef> data = frame->webArchiveData(nullptr, nullptr, exclusionRules, fileName))
            result = IPC::SharedBufferReference(SharedBuffer::create(data.get()));
    }
#else
    UNUSED_PARAM(frameID);
#endif
    completionHandler(result);
}

void WebPage::getAccessibilityTreeData(CompletionHandler<void(const std::optional<IPC::SharedBufferReference>&)>&& callback)
{
    IPC::SharedBufferReference dataBuffer;
#if PLATFORM(COCOA)
    if (auto treeData = protect(corePage())->accessibilityTreeData(IncludeDOMInfo::Yes)) {
        auto stream = adoptCF(CFWriteStreamCreateWithAllocatedBuffers(0, 0));
        CFWriteStreamOpen(stream.get());

        auto writeTreeToStream = [&stream](auto& tree) {
            auto utf8 = tree.utf8();
            auto utf8Span = utf8.span();
            CFWriteStreamWrite(stream.get(), byteCast<UInt8>(utf8Span.data()), utf8Span.size());
        };
        writeTreeToStream(treeData->liveTree);
        writeTreeToStream(treeData->isolatedTree);

        auto data = adoptCF(checked_cf_cast<CFDataRef>(CFWriteStreamCopyProperty(stream.get(), kCFStreamPropertyDataWritten)));
        CFWriteStreamClose(stream.get());

        dataBuffer = IPC::SharedBufferReference(SharedBuffer::create(data.get()));
    }
#endif
    callback(dataBuffer);
}

void WebPage::updateRenderingWithForcedRepaintWithoutCallback()
{
    protect(drawingArea())->updateRenderingWithForcedRepaint();
}

void WebPage::updateRenderingWithForcedRepaint(CompletionHandler<void()>&& completionHandler)
{
    protect(drawingArea())->updateRenderingWithForcedRepaintAsync(*this, WTF::move(completionHandler));
}

void WebPage::preferencesDidChange(const WebPreferencesStore& store, std::optional<uint64_t> sharedPreferencesVersion)
{
#if ENABLE(GPU_PROCESS)
    if (sharedPreferencesVersion) {
        ASSERT(*sharedPreferencesVersion);
        auto sendResult = protect(WebProcess::singleton().parentProcessConnection())->sendSync(Messages::WebProcessProxy::WaitForSharedPreferencesForWebProcessToSync { *sharedPreferencesVersion }, 0);
        auto [success] = sendResult.takeReplyOr(false);
        if (!success)
            return; // Sync IPC has timed out or WebProcessProxy is getting destroyed
    }
#else
    UNUSED_PARAM(sharedPreferencesVersion);
#endif
    WebPreferencesStore::removeTestRunnerOverrides();
    updatePreferences(store);
}

bool WebPage::isParentProcessAWebBrowser() const
{
#if HAVE(AUDIT_TOKEN)
    return isParentProcessAFullWebBrowser(WebProcess::singleton());
#endif
    return false;
}

void WebPage::adjustSettingsForLockdownMode(Settings& settings, const WebPreferencesStore* store)
{
    bool originalSiteIsolationEnabled = settings.siteIsolationEnabled();
    // Disable unstable Experimental settings, even if the user enabled them for local use.
    settings.disableUnstableFeaturesForModernWebKit();
    Settings::disableGlobalUnstableFeaturesForModernWebKit();
    settings.disableFeaturesForLockdownMode();

    if (WebPreferences::forcedSiteIsolationAlwaysOnForTesting() && originalSiteIsolationEnabled)
        settings.setSiteIsolationEnabled(true);

#if PLATFORM(COCOA)
    if (settings.downloadableBinaryFontTrustedTypes() != DownloadableBinaryFontTrustedTypes::None) {
        auto downloadableBinaryFontTrustedTypes = DownloadableBinaryFontTrustedTypes::Restricted;
#if HAVE(CTFONTMANAGER_CREATEMEMORYSAFEFONTDESCRIPTORFROMDATA)
        if (settings.lockdownFontParserEnabled())
            downloadableBinaryFontTrustedTypes = DownloadableBinaryFontTrustedTypes::SafeFontParser;
#endif
        settings.setDownloadableBinaryFontTrustedTypes(downloadableBinaryFontTrustedTypes);
    }
#endif

    // FIXME: This seems like an odd place to put logic for setting global state in CoreGraphics.
#if HAVE(LOCKDOWN_MODE_PDF_ADDITIONS)
    CGEnterLockdownModeForPDF();
#endif

    if (store) {
        settings.setAllowedMediaContainerTypes(store->getStringValueForKey(WebPreferencesKey::mediaContainerTypesAllowedInLockdownModeKey()));
        settings.setAllowedMediaCodecTypes(store->getStringValueForKey(WebPreferencesKey::mediaCodecTypesAllowedInLockdownModeKey()));
        settings.setAllowedMediaVideoCodecIDs(store->getStringValueForKey(WebPreferencesKey::mediaVideoCodecIDsAllowedInLockdownModeKey()));
        settings.setAllowedMediaAudioCodecIDs(store->getStringValueForKey(WebPreferencesKey::mediaAudioCodecIDsAllowedInLockdownModeKey()));
        settings.setAllowedMediaCaptionFormatTypes(store->getStringValueForKey(WebPreferencesKey::mediaCaptionFormatTypesAllowedInLockdownModeKey()));
    }
}

#if PLATFORM(DRIFTSTACK)
// Parse the Safari major.minor from the DRIFTSTACK_ARCHETYPE env slug (e.g. "..._safari26_4"),
// read once per WebContent process. Used to version-key globals Apple added at a specific Safari
// version (e.g. window.Origin at 26.5). Mirrors driftstackWebGLUniformBlocksV265Plus() in
// WebGL2RenderingContext.cpp. No archetype env (default) = the 26.4 launch target → false.
static bool driftstackArchetypeSafariAtLeast(int wantMajor, int wantMinor)
{
    const char* archetype = getenv("DRIFTSTACK_ARCHETYPE");
    if (!archetype)
        return false;
    std::string_view sv(archetype);
    auto pos = sv.find("safari");
    if (pos == std::string_view::npos)
        return false;
    sv.remove_prefix(pos + 6);
    int major = 0, minor = 0;
    size_t i = 0;
    while (i < sv.size() && sv[i] >= '0' && sv[i] <= '9') { major = major * 10 + (sv[i] - '0'); ++i; }
    if (i < sv.size() && (sv[i] == '_' || sv[i] == '.')) ++i;
    while (i < sv.size() && sv[i] >= '0' && sv[i] <= '9') { minor = minor * 10 + (sv[i] - '0'); ++i; }
    return major > wantMajor || (major == wantMajor && minor >= wantMinor);
}
#endif

void WebPage::updatePreferences(const WebPreferencesStore& store)
{
    updatePreferencesGenerated(store);

    Settings& settings = m_page->settings();

    updateSettingsGenerated(store, settings);

#if PLATFORM(DRIFTSTACK)
    // Wave 29-403 Q1 lifecycle fix (root cause located 2026-05-19): the
    // Settings-layer Family A archetype gate previously lived in Page::Page
    // body, but WebPageUpdatePreferences.cpp:958 runs AFTER Page::Page
    // returns and unconditionally overwrites webGPUEnabled (and every other
    // [sharedPreferenceForWebProcess: true] setting) from the UIProcess
    // preference store, blowing away the Page::Page hook. This is the
    // CORRECT hook point: per-archetype overrides applied AFTER both
    // updatePreferencesGenerated() and updateSettingsGenerated() sync the
    // store, so they stick until the next updatePreferences() call (at
    // which point this block re-applies them — idempotent).
    //
    // WebGPU gate (this `s_isFamilyAArchetype` lambda, defined below): the hide
    // fires for PRE-Safari-26 archetypes only (slug contains safari17_…safari25_),
    // so navigator.gpu is undefined on Safari ≤25 and DEFINED on ALL Safari 26.x
    // (26.0 / 26.3 / 26.4). NOTE: this WebGPU boundary (pre-26 vs 26.0+) is NOT the
    // canvas Family-A/B boundary (≤26.3 vs ≥26.4) — they differ; do not conflate.
    // Founder-research-confirmed 2026-05-19 the gate is Safari-VERSION-keyed (not
    // per-GPU-model). [Open verification: the empirical basis was Pro-model captures
    // (16 Pro 18.6 = no WebGPU, 17 26.4 = WebGPU); WebGPU presence on a NON-Pro
    // A15/A16 model at Safari 26.4 is extrapolated, not directly captured — see the
    // W2301 matrix surface.] When undefined: navigator.gpu must be undefined, not null.
    // IDL [EnabledBySetting=WebGPUEnabled] in JSNavigatorPrototype::
    // finishCreation reads Document::settingsValues().webGPUEnabled and
    // deletes the accessor when false. With this setter applied here,
    // finishCreation sees false → accessor is removed from prototype →
    // 'gpu' in navigator === false, typeof navigator.gpu === 'undefined'.
    //
    // See docs/internal/wave-29-402-settings-layer-archetype-gate-pattern.md
    // for the full pattern. All future Safari-26-only feature hides on
    // Family A follow this same pattern: add the per-archetype override
    // here after updateSettingsGenerated().
    // 2026-06-27 (silently-inert-gate sweep): read getenv LIVE — NOT a static cache.
    // A `static const` lambda caches at FIRST call, which can fire during early process
    // init BEFORE the per-band DRIFTSTACK_ARCHETYPE env is applied → it caches the
    // launch/26.4 default for ALL archetypes (gate silently inert). Mirror the C1
    // RenderThemeMac.mm driftstackArchetypeSafariAtLeast live-getenv pattern.
    const bool s_isFamilyAArchetype = []() {
        const char* archetype = getenv("DRIFTSTACK_ARCHETYPE");
        if (!archetype)
            return false;
        // Founder research-confirmed 2026-05-19: WebGPU enabled by default
        // Safari 26.0+ (iOS 26.0 release Sept 2025). Pre-Safari-26 (any
        // Safari 17.x / 18.x / 19.x major) = Family A; WebGPU undefined.
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
    // Wave 29-406 §11.A.9 — MediaSource hide (both Family A AND Family B).
    // Empirical BS Automate 2026-05-19: real iPhone Safari 18.6 AND 26.4
    // both hide window.MediaSource and window.SourceBuffer (iOS standardized
    // on ManagedMediaSource since iOS 17.1). Mac fork upstream exposes
    // MediaSource — must hide on iPhone archetypes (which is default
    // and all FA/FB cases on this fork).
    settings.setMediaSourceEnabled(false);

    // Wave 29-406 §11.A.10 — DigitalCredentials enable on Family B.
    // Empirical: iPhone Safari 26.4 exposes window.DigitalCredential.
    // Mac fork upstream may or may not have it enabled by default.
    if (!s_isFamilyAArchetype)
        settings.setDigitalCredentialsEnabled(true);

    // Wave 29-406 §11.A.11 — global iPhone hides (all archetypes).
    // Empirical BS Automate 2026-05-19 across Safari 18.4/18.6/26.2/26.3/26.4
    // (5 captures): document.exitFullscreen absent + CSS.supports
    // ('overflow-anchor: auto') === false on ALL real iPhone Safari versions.
    // Mac fork upstream enables both. Apply globally for iPhone fidelity.
    settings.setFullScreenEnabled(false);
    settings.setCSSScrollAnchoringEnabled(false);

    // W313 (2026-06-02) — ReadableStream async iteration hide (all archetypes).
    // The fork's WebKit ships ReadableStreamIterableEnabled (yaml status:stable
    // default:true) so ReadableStream.prototype[Symbol.asyncIterator] is a
    // function, but SHIPPED Safari has NOT enabled it: real iPhone 17 returns
    // typeof ReadableStream.prototype[Symbol.asyncIterator] !== 'function' on
    // ALL 17 BS captures (8×26.4 + 9×26.5). Disable globally for iPhone fidelity
    // (the fork upstream is ahead of shipped Safari on this feature). Same
    // pattern as the FullScreen/CSSScrollAnchoring global hides above.
    settings.setReadableStreamIterableEnabled(false);

    // W349 (2026-06-02) — ReadableStream.from (static) is likewise fork-too-new:
    // Safari STP 238+ exposes it but SHIPPED iOS 26.4/26.5 does NOT. Real
    // iPhone-17 static.ReadableStream = [length, name, prototype] only (no
    // `from`) on BOTH Safari 26.4 and 26.5 (verified vs /aio captures). Disable
    // via the same EnabledBySetting gate (ReadableStreamFromEnabled) as W313.
    settings.setReadableStreamFromEnabled(false);

    // W2575 (2026-06-15, env-gated default-OFF diagnostic) — the browserleaks glyphHash block-div +1 is the fork
    // ROUNDING a fractional line-box height where a real iPhone FLOORS it (sim-verified w2575: line-height:23.5px →
    // div.offsetHeight = fork 24, iOS-26.5 sim 23; explicit CSS height:23.5px matches both → the divergence is the
    // line-box → block-content-height path specifically). SHIPPED iOS appears to run inline layout in INTEGER mode
    // (subpixelInlineLayoutEnabled=false) — NOT reflected in the OSS UnifiedWebPreferences default (true on all of
    // WebCore/WebKit/WebKitLegacy), so this Mac-built fork inherited the wrong fractional behavior. Force integer
    // inline layout to test floor=match-iOS. Gated for cumrig / W2569-inline / measureText blast-radius verification
    // before any default-on flip.
    if (getenv("DRIFTSTACK_INT_INLINE_LAYOUT"))
        settings.setSubpixelInlineLayoutEnabled(false);

    // W353 (2026-06-02) — two more fork-too-new attributes the full-enumeration apiEnum surface caught, both
    // ABSENT on real iPhone-17 (W349) and gated here via new EnabledBySetting settings (the IDL preprocessor
    // cannot see PLATFORM(DRIFTSTACK), so a runtime setting is the only working hide):
    //   - RTCRtpReceiver.jitterBufferTarget — Safari STP 242 only, not in shipped iOS 26.4/26.5.
    //   - GPUDevice.onuncapturederror — WebGPU error-handling still evolving; real GPUDevice has zero on* handlers.
    settings.setPeerConnectionJitterBufferTargetEnabled(false);
    settings.setWebGPUUncapturedErrorEventEnabled(false);

    // W379 (2026-06-02) — #28 Batch A: three more fork-too-new prototype members the exhaustive apiEnum diff
    // caught, all ABSENT on real iPhone-17 (verified on 2 /aio captures, W372/W374/W377), each gated via a NEW
    // EnabledBySetting setting the fork disables here (none re-enabled elsewhere, unlike TrackConfiguration W378):
    //   - HTMLTemplateElement.shadowRootSlotAssignment (recent declarative-shadow-DOM addition)
    //   - PerformanceResourceTiming.{workerRouterEvaluationStart, workerCacheLookupStart, workerMatchedRouterSource,
    //     workerFinalRouterSource} (Service-Worker static-routing timings)
    //   - WebKitNamespace.evaluateScript (upstream method shipped iOS Safari does not expose; Driftstack unused)
    settings.setHTMLTemplateShadowRootSlotAssignmentEnabled(false);
    settings.setPerformanceResourceTimingWorkerRoutingEnabled(false);
    settings.setWebKitNamespaceEvaluateScriptEnabled(false);

    // W388 (2026-06-03) — #28 Notification: ServiceWorkerRegistration.{getNotifications, showNotification} (+ the SW-scope
    // NotificationEvent / onnotificationclick surface) are ABSENT on real iPhone-17 Safari-tab (W387 full-JS-surface diff:
    // fork ServiceWorkerRegistration 12 vs real-26.4 10). These are ALL gated by the EXISTING NotificationEventEnabled
    // setting, whose UnifiedWebPreferences default is `ENABLE(NOTIFICATION_EVENT) && !PLATFORM(IOS_FAMILY)` → TRUE on this
    // macOS fork but FALSE on real iOS. So real iOS turns this whole surface off via its own platform default; the Mac-fork
    // exposed it only because it builds as !IOS_FAMILY. Disabling here makes the fork iOS-faithful (replicates iOS's own
    // default) — NOT an over-hide: window.Notification is a SEPARATE setting (NotificationsEnabled, left ON, iOS has it),
    // and no code re-enables NotificationEventEnabled (grep-verified, unlike TrackConfiguration W378).
    settings.setNotificationEventEnabled(false);

    // W391 (2026-06-03) — #28 Batch B ADD: HTMLVideoElement.showCaptionDisplaySettings is PRESENT on real iPhone-17
    // (drillOwn vs real Safari 26.5: real HTMLVideoElement.prototype own=26 incl showCaptionDisplaySettings, fork=25 lacked
    // it). Both the IDL (HTMLVideoElement+CaptionDisplaySettings.idl) and the C++ impl (HTMLVideoElementCaptionDisplaySettings
    // .cpp) already exist — gated by EnabledBySetting=CaptionDisplaySettingsEnabled, whose Cocoa default
    // (defaultCaptionDisplaySettingsEnabled()) is `false` BUT is defaultsOverridable, and real iOS Safari (MobileSafari)
    // overrides it ON. Enabling here replicates MobileSafari (no new C++/IDL, the impl is dormant-present). The setting gates
    // ONLY showCaptionDisplaySettings (single IDL hit, grep-verified) so this adds exactly the 1 missing member — no over-expose.
    settings.setCaptionDisplaySettingsEnabled(true);

    // W378 (2026-06-02) — #28: AudioTrack.configuration + VideoTrack.configuration (gated by
    // TrackConfigurationEnabled) are ABSENT on real iPhone-17 (verified on TWO /aio captures, W372/W374/W377).
    // The disable is applied LATER (after the developerExtrasEnabled() block below re-enables it), see W378b.

    // Wave 29-4xx mobile-shape DROP — desktop-only APIs a real iPhone Safari does NOT expose
    // (verified vs real iPhone-17 /aio 2026-06-01: the mobileAuth probe reports these present on
    // the fork but ABSENT on a real iPhone; version-invariant per W45). Both are setting-gated, so
    // disabling the setting removes the API surface via the IDL [EnabledBySetting] gate — same
    // pattern as the hides above, no IDL change needed:
    //  - getDisplayMedia is [EnabledBySetting=ScreenCaptureEnabled]; iOS Safari has no screen
    //    capture. This is ALSO the lone cross-signal-coherence failure (W30).
    //  - the GamepadHapticActuator interface is [EnabledBySetting=GamepadVibrationActuatorEnabled].
    //  - the whole Pointer Lock surface (Element.requestPointerLock + Document.exitPointerLock/
    //    pointerLockElement/onpointerlockchange/onpointerlockerror) is [EnabledBySetting=PointerLockEnabled];
    //    its default is already false on PLATFORM(IOS_FAMILY) but true on this fork (DRIFTSTACK), so force false.
#if ENABLE(MEDIA_STREAM)
    settings.setScreenCaptureEnabled(false);
#endif
#if ENABLE(GAMEPAD)
    settings.setGamepadVibrationActuatorEnabled(false);
#endif
#if ENABLE(POINTER_LOCK)
    settings.setPointerLockEnabled(false);
#endif
    // #17 (founder green-lit 2026-06-02): drop the fork-extra window globals that a real iPhone
    // 26.4 (the launch target) does NOT expose — both verified absent vs real iPhone (W279/W280).
    //  - window.Origin is [EnabledBySetting=OriginAPIEnabled]: Apple ADDED it at Safari 26.5 (absent on
    //    real 26.4, present on real 26.5 — W280). VERSION-KEYED: enable only for 26.5+ archetypes, disable
    //    for the 26.4 launch target and earlier (so per-iOS-version profiles stay bit-identical, W295).
    //  - HTMLSelectedContentElement + the whole customizable-<select> surface is
    //    [EnabledBySetting=HTMLEnhancedSelectParsingEnabled & HTMLEnhancedSelectEnabled]: absent on real
    //    26.4 AND 26.5 (pure fork-extra, both versions); the feature ships as a unit — disable both flags
    //    unconditionally (no version-keying needed).
    settings.setOriginAPIEnabled(driftstackArchetypeSafariAtLeast(26, 5));
    settings.setHTMLEnhancedSelectEnabled(false);
    settings.setHTMLEnhancedSelectParsingEnabled(false);
    // Sweep whag2hew5 (2026-06-26): Animation.prototype.overallProgress landed at Safari 26.2.
    // Real iPhone serves it undefined at 18.6 AND at 26.0/26.0.1, function at 26.2+. The IDL
    // attribute was ungated (always exposed), leaking on <26.2 (18.x + 26.0/26.1). Gate it via
    // [EnabledBySetting=WebAnimationsOverallProgressEnabled] (YAML default true) and version-key
    // it here exactly like OriginAPIEnabled: enabled only for >=26.2 archetypes, so the 26.4
    // launch target keeps it and <26.2 archetypes report it undefined.
    settings.setWebAnimationsOverallProgressEnabled(driftstackArchetypeSafariAtLeast(26, 2));
    // W546 (#17): ToggleEvent.prototype.source (STP 237) + SVGAnimationElement.prototype.onend
    // ("added the missing onend handler") are Safari-26.5-era prototype members — ABSENT real 26.4,
    // PRESENT real 26.5 (verified vs real iPhone-17, W533/W534). Version-key like Origin so the fork
    // matches the real per-minor surface (26.4 hides both; 26.5 exposes them). Only `onend` is gated —
    // onbegin/onrepeat pre-existed in 26.4 (W534).
    settings.setSafari265PrototypeMembersEnabled(driftstackArchetypeSafariAtLeast(26, 5));
#if ENABLE(TEXT_AUTOSIZING)
    // -webkit-text-size-adjust is enable-if ENABLE_TEXT_AUTOSIZING (on for Cocoa) + settings-flag
    // textAutosizingEnabled, which defaults TRUE on PLATFORM(IOS_FAMILY) but FALSE off-iOS — so the
    // Mac fork's getComputedStyle omits the property, while a real iPhone exposes
    // -webkit-text-size-adjust:auto on every UA-styled element. Force-enable so the property is
    // recognized + enumerated like iOS (closes the lone remaining mobile-shape -webkit- CSS prop).
    // textAutosizingWindowSizeOverride defaults 0 → autosizing does NOT inflate text on a normal
    // render, so canvas/measureText Text fingerprints stay unchanged (Text-arc gate — verify post-build).
    settings.setTextAutosizingEnabled(true);
#endif
    // textAreasAreResizable defaults true off-iOS (PLATFORM(IOS_FAMILY):false in
    // UnifiedWebPreferences.yaml) — so the Mac fork's `<textarea>` resolves the UA stylesheet's
    // `resize: -internal-textarea-auto` to Resize::Both (StyleResize.cpp:43), exposing a desktop
    // `resize: both` computed value; a real iPhone has the setting false → Resize::None. Force OFF
    // so getComputedStyle(textarea).resize === 'none', matching iOS (close-list §1 textarea item).
    settings.setTextAreasAreResizable(false);

    // Wave 29-406 §11.A.13 — Touch event DOM attributes (ontouchstart etc.).
    // Mac fork DRIFTSTACK_TOUCH_STUBS gate makes the IDL accessors compile;
    // TouchEventDOMAttributesEnabled defaults to screenHasTouchDevice()
    // which returns false on Mac. Force-enable globally so 'ontouchstart' in
    // window === true on iPhone archetypes (5/5 BS captures confirm this).
    settings.setTouchEventDOMAttributesEnabled(true);

    // Wave 29-499.9 §80 — setTimeout(0) clamp Safari pipeline split.
    // Empirical n=22 BS Safari 26.4 captures + n=13 Safari 26.3 + n=5 founder
    // physical iOS 26.5 (V-2026-05-20-W29-499-CANONICAL-BASELINES):
    //   Family A (Safari 18.6 / 26.3 OLD pipeline): setTimeout(0) p50 = 5 ms
    //   Family B (Safari 26.4+ NEW pipeline):       setTimeout(0) p50 = 8 ms
    // WebKit default `DOMTimer::defaultMinimumInterval()` = 4 ms; we override
    // the per-page `minimumDOMTimerInterval` to match the iPhone canonical
    // clamp for the active archetype's Safari pipeline. setTimeout actual-
    // delay = max(clamp, scheduler_overhead); these constants make setTimeout
    // (fn, 0).p50 match iPhone canonical at 5 or 8 ms.
    if (s_isFamilyAArchetype)
        settings.setMinimumDOMTimerInterval(5_ms);
    else
        settings.setMinimumDOMTimerInterval(8_ms);

    // W2556 (API-version audit): the W2532 WebGPU MODEL-gate hid navigator.gpu only by returning
    // nullptr from Navigator::gpu() (→ navigator.gpu === null, 'gpu' in navigator === true, accessor
    // still installed) — but a real non-WebGPU-capable iPhone shows navigator.gpu === undefined +
    // 'gpu' in navigator === false. The Navigator.cpp comment itself requires "undefined, not null".
    // Route the model-gate through the SAME [EnabledBySetting=WebGPUEnabled] deletion path Family-A
    // uses, so the accessor is DELETED (genuine undefined) and the GPU* window-global cascade also
    // goes undefined. Capability boundary CORRECTED W2557 from A17+ to A16+ (iphone15/16/17 + their
    // Pro variants): BS captured a device-profile-accurate iPhone 15 (A16, screen 393x852) @ Safari
    // 26.2 with a REAL WebGPU adapter (vendor/arch/device/desc all "apple") — so navigator.gpu IS
    // present on the non-Pro iPhone 15, NOT just 15 Pro. file-122's "15 Pro and newer" baseline was a
    // claim about iOS behavior now falsified by capture (CLAUDE.md "reality wins"). find("iphone15")
    // matches iphone15/iphone15plus/iphone15pro/iphone15promax (all A16/A17). iphone14pro/iphone14promax
    // (ALSO A16) are capable too.
    // ⚠️ STALE-COMMENT RETRACTION: the prior "iphone13*/iphone14/iphone14plus (A15) stays NON-capable"
    // line is FALSIFIED by capture aio-iPhone_14-1782162865630 (real A15, "apple a15 gpu") @ Safari 26.2:
    // navigator.gpu === 'object', GPUAdapter/GPUDevice defined, isFallbackAdapter=false → A15 HAS WebGPU
    // on 26.x. So A15-non-Pro (iphone14/iphone14plus/iphone13/iphone13mini) is now capable. CAVEAT: A15
    // WebGPU is capture-confirmed at 26.2 ONLY (no A15@26.0 capture exists) → A15 capability is gated
    // conservatively to Safari minor >= 2 (26.0/26.1 NEEDS-CAPTURE). A16+ stay capable at all 26.x
    // (unchanged). 18.x A15 archetypes never reach here — s_isFamilyAArchetype hides them above.
    // 2026-06-27 sweep: live getenv, NOT static-cached (see s_isFamilyAArchetype above).
    const bool s_webGPUNonCapableModel = []() {
        const char* a = getenv("DRIFTSTACK_ARCHETYPE");
        if (!a || !a[0])
            return false; // no archetype env = iphone17 launch = WebGPU-capable
        std::string_view sv(a);
        bool capableA16 = sv.find("iphone17") == 0 || sv.find("iphone16") == 0
            || sv.find("iphone15") == 0 || sv.find("iphone14pro") == 0; // A16+ : 14 Pro/Pro Max, 15*, 16*, 17*
        bool a15NonPro = sv.find("iphone14") == 0 || sv.find("iphone13") == 0; // A15: 14/14 Plus, 13/13 mini
        bool a15Capable = false;
        if (a15NonPro) {
            // Parse safari major.minor; A15 capable only on 26.2+ (capture-confirmed at 26.2).
            auto pos = sv.find("safari");
            if (pos != std::string_view::npos) {
                std::string_view v = sv.substr(pos + 6);
                int maj = 0, min = 0; size_t i = 0;
                while (i < v.size() && v[i] >= '0' && v[i] <= '9') { maj = maj * 10 + (v[i] - '0'); ++i; }
                if (i < v.size() && (v[i] == '_' || v[i] == '.')) ++i;
                while (i < v.size() && v[i] >= '0' && v[i] <= '9') { min = min * 10 + (v[i] - '0'); ++i; }
                a15Capable = maj > 26 || (maj == 26 && min >= 2);
            }
        }
        return !(capableA16 || a15Capable);
    }();
    if (s_webGPUNonCapableModel)
        settings.setWebGPUEnabled(false);

    if (s_isFamilyAArchetype) {
        // Wave 29-403 §11.A: WebGPU cascade hides navigator.gpu + GPU*
        // window globals + GPUSupportedFeatures/Limits + WGSLLanguageFeatures.
        // Empirical BS capture iPhone 16 Pro Safari 18.6 2026-05-19.
        settings.setWebGPUEnabled(false);

        // Wave 29-404 §11.A.3: Family A feature-inventory BS capture
        // 2026-05-19 shows the following additional features must be
        // hidden so 'feature' in window / navigator === false. Each was
        // empirically confirmed undefined on iPhone 16 Pro Safari 18.6
        // (Family A) and defined on iPhone 17 Safari 26.4 (Family B).

        // navigator.navigation, NavigationCurrentEntryChangeEvent
        settings.setNavigationAPIEnabled(false);
        // CommandEvent
        settings.setCommandAttributesEnabled(false);
        // EventCounts, PerformanceEventTiming
        settings.setEventTimingEnabled(false);
        // WebTransport, WebTransportDatagramDuplexStream
        settings.setWebTransportEnabled(false);
        // document.caretPositionFromPoint
        settings.setCaretPositionFromPointEnabled(false);
        // CSS.supports('top: anchor(top)')
        settings.setCSSAnchorPositioningEnabled(false);
        // CSS.supports('field-sizing: content')
        settings.setCSSFieldSizingEnabled(false);
        // CSS.supports('text-wrap: pretty')
        settings.setCSSTextWrapPrettyEnabled(false);
        // ScrollTimeline + ViewTimeline (Wave 29-404 §11.A.4: gate added
        // to ScrollTimeline.idl + ViewTimeline.idl since upstream WebKit
        // doesn't gate them at IDL level).
        settings.setScrollDrivenAnimationsEnabled(false);

        // Wave 29-406 §11.A.7 — WebCodecs Audio hide on Family A.
        // Empirical BS Automate 2026-05-19: AudioData, AudioDecoder,
        // AudioEncoder, EncodedAudioChunk all undefined on real iPhone
        // Safari 18.6 but defined on 26.4.
        settings.setWebCodecsAudioEnabled(false);

        // Wave 29-406 §11.A.10 (cont'd) — DigitalCredentials hide on Family A.
        settings.setDigitalCredentialsEnabled(false);

        // Wave 29-406 §11.A.14 — Mac fork hides MutationEvent + OverflowEvent
        // (deprecated APIs removed in WebKit upstream) but real iPhone Safari
        // 18.6 STILL exposes them. Force-enable on Family A archetype to
        // restore parity. Empirical 2026-05-19 BS Automate: iPhone Safari 18.6
        // window.MutationEvent === function (Mac fork = undefined).
        settings.setMutationEventsEnabled(true);

        // Wave 29-406 §11.A.15 — URLPattern hide on Family A. Mac fork
        // upstream exposes window.URLPattern; iPhone Safari 18.6 hides it.
        // (New ScrollDrivenAnimations-style gate added in Wave 29-406:
        // URLPattern.idl has [EnabledBySetting=URLPatternEnabled] + yaml.)
        settings.setURLPatternEnabled(false);

        // Wave 29-407.1 — CSSOM descriptor blocks hide on Family A.
        // Empirical BS Automate: 5/5 real iPhone Safari 18.6 captures have
        // window.CSSStyleProperties / CSSFontFaceDescriptors / CSSPageDescriptors
        // === undefined. Safari 26.4 has them. Wave 29-406 §11.A.16 r41
        // attempt failed because WebCoreBuiltinNames lacked PublicName
        // entries; this wave adds the 3 macro registrations (commit prior
        // to this build) then re-applies the IDL gate.
        settings.setCSSDescriptorBlocksEnabled(false);

        // Wave 29-408.1 — REVERTED Wave 29-407.6 ViewTransitions Family A
        // hide. Empirical re-verification 2026-05-20 vs the actual canonical
        // BS Automate captures shows real iPhone Safari 18.4 / 18.6 / 26.2 /
        // 26.3 / 26.4 ALL expose ViewTransition / ViewTransitionTypeSet /
        // CSSViewTransitionRule / document.startViewTransition / activeView-
        // Transition. The Wave 29-407.6 "hide on Family A" patch was based
        // on a misread of an FA-vs-FB audit; the surfaces are NOT FB-only.
        // ViewTransitionsEnabled Setting + 5 IDL gates kept in tree as
        // generic infrastructure but Family A flip removed — default true
        // matches both archetypes.

        // Wave 29-408.2 — OverflowEvent restoration on Family A.
        // Real iPhone Safari 18.4 / 18.6 still expose window.OverflowEvent
        // as `function`; upstream WebKit removed the impl after a Q1 2024
        // cleanup. Driftstack restored a minimal modern-spec OverflowEvent
        // (constructor + 3 const enums + orient / horizontalOverflow /
        // verticalOverflow attrs). Setting default off; Family A flips on
        // so the JSC constructor installs. Family B (Safari 26.4) leaves it
        // off — that's what real Safari 26.4 does.
        settings.setOverflowEventEnabled(true);

        // Wave 29-406 §11.A.8 — additional Family A hides empirically
        // confirmed via Mac fork vs iPhone Safari 18.6 v2 diff 2026-05-19:
        // - FileSystemWritableFileStream undefined
        settings.setFileSystemWritableStreamEnabled(false);
        // - LargestContentfulPaint undefined
        settings.setLargestContentfulPaintEnabled(false);
        // - ReadableByteStreamController / ReadableStreamBYOBReader undefined
        settings.setReadableByteStreamAPIEnabled(false);
        // - document.customElementRegistry undefined
        settings.setScopedCustomElementRegistryEnabled(false);
        // - document.event_handlers.onbeforematch undefined
        settings.setHiddenUntilFoundEnabled(false);
        // - document.event_handlers.onscrollend undefined
        settings.setScrollendEventEnabled(false);
        // - CSS.supports scrollbar-color: false
        settings.setCSSScrollbarColorEnabled(false);

        // apiEnum.cssProperties EXPOSURE gate (computed-style enumeration). The
        // built fork ships ONE WebKit binary whose CSS property table reflects
        // Safari 26.x, so getComputedStyle(documentElement) over-enumerates three
        // properties that real iPhone Safari 18.6 lacks. Boundary VERIFIED across
        // real /aio captures (present on EVERY 26.x minor — 26.0/26.2/26.3/26.4 —
        // and absent ONLY on Family-A 18.6, so this is the FA/FB boundary, NOT a
        // 26-minor boundary):
        //   real aio-iPhone_16_Pro_Max (Safari 18.6) cssProperties LACKS:
        //     dynamic-range-limit, overflow-block, overflow-inline
        //   real aio-iPhone_17_Pro_Max (Safari 26.0/26.2/26.3/26.4) HAS all three.
        // Each property's enumeration is the indexed entry of a computed style, which
        // CSSPropertyNames isExposed() gates by a Settings flag. dynamic-range-limit
        // reads supportHDRDisplayEnabled (force-true ON by ENABLE_SUPPORT_HDR_DISPLAY_-
        // BY_DEFAULT on macOS 26 builds); overflow-block/overflow-inline read the new
        // cssLogicalOverflowEnabled flag (Driftstack-added settings-flag on those two
        // CSSProperties.json entries, default-true so 26.x stays exact). Family B (the
        // else branch below) leaves both flags at their 26.x-correct defaults.
        // dynamic-range-limit (css-color-hdr) — real 18.6 lacks it.
        settings.setSupportHDRDisplayEnabled(false);
        // overflow-block / overflow-inline (css-overflow-3 logical longhands) — real 18.6 lacks them.
        settings.setCSSLogicalOverflowEnabled(false);

        // Family-A over-exposure cluster (2026-06-26 fork-as-18.6 vs real-18.6 same-probe
        // sweep). The fork's ONE 26.x WebKit binary exposes these newer JS/Web-API members
        // on the 18.6 archetype; real iPhone Safari 18.6 LACKS each. Every one is a verified
        // FA/FB boundary (present on real aio-iPhone_17_Pro_Max Safari 26.4, absent on BOTH
        // real aio-iPhone_16_Pro_Max Safari 18.6 captures). Each is gated by an EnabledBySetting
        // flag (existing or Driftstack-added) the Family-A branch turns off; Family B (the else
        // branch / unset 26.4 launch) keeps the 26.x-correct default.
        //
        // Trusted Types — TrustedHTML/TrustedScript/TrustedScriptURL/TrustedTypePolicy/
        // TrustedTypePolicyFactory window globals + the window.trustedTypes accessor (all gated
        // by EnabledBySetting=TrustedTypesEnabled). The version-coherence probe flags the leak
        // directly (window.trustedTypes:INCOHERENT-present(object)). Real 18.6 → all undefined.
        settings.setTrustedTypesEnabled(false);
        // Element.currentCSSZoom / HTMLElement.currentCSSZoom (Element+CSSOMView.idl,
        // EnabledBySetting=EnableElementCurrentCSSZoom; COCOA-default true). Real 18.6 lacks it
        // on Element/HTMLElement and every HTML*Element prototype.
        settings.setEnableElementCurrentCSSZoom(false);
        // HTMLMediaElement.setSinkId / .sinkId (audio-output routing, HTMLMediaElement+AudioOutput
        // .idl, EnabledBySetting=ExposeSpeakersEnabled&PerElementSpeakerSelectionEnabled). Both
        // flags COCOA-default true and gate ONLY this AudioOutput partial-interface (grep-verified),
        // so disabling the per-element one cleanly hides both members with no collateral. Real 18.6
        // lacks them on HTMLMediaElement/HTMLAudioElement/HTMLVideoElement.
        settings.setPerElementSpeakerSelectionEnabled(false);
        // IntersectionObserver.prototype.scrollMargin — upstream IntersectionObserver.idl had NO
        // settings gate (unconditionally compiled). Driftstack-added IntersectionObserverScrollMargin-
        // Enabled flag (default true so 26.x stays exact) wired as EnabledBySetting on the attribute.
        // Real 18.6 lacks scrollMargin (root/rootMargin/thresholds only).
        settings.setIntersectionObserverScrollMarginEnabled(false);
        // PublicKeyCredential.signalAllAcceptedCredentials / signalCurrentUserDetails /
        // signalUnknownCredential (WebAuthn credential-signal statics) — upstream PublicKeyCredential
        // .idl had NO settings gate. Driftstack-added WebAuthnSignalMethodsEnabled flag (default true
        // so 26.x stays exact) wired as EnabledBySetting on the 3 static methods. Real 18.6 lacks all
        // three (statics: getClientCapabilities/isUVPAA/parse*FromJSON only).
        settings.setWebAuthnSignalMethodsEnabled(false);
    } else {
        // P0 named-timeline CSS-property EXPOSURE fix (CSS.supports gate).
        // The named scroll/view timeline CSS *properties* (scroll-timeline-name,
        // view-timeline-name, timeline-scope) are gated by cssNamedTimelineProperties-
        // Enabled, which defaults FALSE in UnifiedWebPreferences.yaml on every archetype.
        // Real iPhone Safari 26.x SHIPS these properties:
        //   aio-iPhone_17_Pro_Max (Safari 26.4, LAUNCH archetype) →
        //     CSS.supports('scroll-timeline-name: --foo') === true
        //     CSS.supports('view-timeline-name: --foo')   === true
        //     CSS.supports('timeline-scope: --foo')       === true
        // while Family A (aio-iPhone_16_Pro_Max, Safari 18.6) serves all three === false.
        //
        // The earlier fix (e7e0e8911c) force-enabled the flag only on the CSS *parser
        // context* (CSSParserContext::propertySettings). But CSS.supports routes through
        // DOMCSSNamespace::supports → the longhand-declaration form whose gate is
        // isExposed(propertyID, &document.settings()) — it reads the DOCUMENT Settings,
        // which the parser-context override does NOT reach. So production CSS.supports
        // stayed false on 26.4 (A3 box-confirmed). FIX: set the document Setting itself
        // here in the non-Family-A (Safari 26.x, incl 26.4 launch) branch, mirroring the
        // per-archetype document Settings the Family-A block sets above. CSSPropertySettings
        // then derives true from the document setting directly, and isExposed(…&document.
        // settings()) returns true.
        //
        // Family A (the s_isFamilyAArchetype branch above) deliberately does NOT call this,
        // so the YAML default-false stands → all three serve false on 18.x, matching real
        // iPhone. The e7e0e8911c CSSParserContext force-true is left in place (additive,
        // harmless; this document-Settings call is the one that reaches CSS.supports).
        settings.setCSSNamedTimelinePropertiesEnabled(true);
    }

    // ── 26.0/26.3 per-minor DOM-API surface (Class C/F, master closure ledger) ──
    // The s_isFamilyAArchetype block above covers ONLY pre-26 (safari17_..25_), so
    // safari26_0/26_3 currently fall through to the Family-B 26.4 defaults and OVER-
    // expose members Apple added at a LATER 26.x minor. Real-capture triangulated
    // (15× real 26.0 + 1× 26.3 + 26.2 + 26.4 aio captures): boundaries are PER-MEMBER.
    // GUARDRAIL (the landmine): driftstackArchetypeSafariAtLeast() returns false when
    // DRIFTSTACK_ARCHETYPE is UNSET, so each block MUST also require dsHasArch — else
    // it would fire on the unset 26.4 launch default and regress it.
    // See docs/internal/26-0-26-3-master-closure-ledger.md.
    {
        const char* dsArch = getenv("DRIFTSTACK_ARCHETYPE");
        const bool dsHasArch = dsArch && dsArch[0];
        // <26.4 — absent on BOTH 26.0 AND 26.3 (real 26.0==26.3 lack; real 26.4 has):
        if (dsHasArch && !driftstackArchetypeSafariAtLeast(26, 4)) {
            settings.setWebTransportEnabled(false);           // window.WebTransport + 10 stream interfaces (VERIFIED 26.4 boundary)
            settings.setCaptionDisplaySettingsEnabled(false); // HTMLVideoElement.showCaptionDisplaySettings
            // NEW 2026-06-20 (verified 26.4 boundary, both 26.0 AND 26.3 lack these):
            settings.setReadableByteStreamAPIEnabled(false);  // window.ReadableByteStreamController/ReadableStreamBYOBReader/BYOBRequest
            settings.setCSSMathDepthEnabled(false);           // CSS 'math-depth' property (apiEnum.cssProperties + CSS.supports)
            settings.setDriftstackSafari264MembersEnabled(false); // PRT deliveryType/finalResponseHeadersStart/firstInterimResponseStart + CSS flow-tolerance + window.webkit.buffers
            // Element.currentCSSZoom / HTMLElement.currentCSSZoom (EnableElementCurrentCSSZoom,
            // COCOA-default true). Real iPhone ships it ONLY >=26.4 (GT 0/27 <26.4 [18.6 0/5,
            // 26.0 0/16, 26.2 0/5, 26.3 0/1], 40/40 >=26.4). The Family-A block (~L5918) already
            // hides it for 18.x; this closes the 26.0/26.2/26.3 over-exposure that was falling
            // through to the Family-B 26.4 Cocoa-default true. (residual-hunt a88cc34b; the
            // 26-0-26-3-master-closure-ledger:379 "non-issue/default-FALSE" note was mistaken —
            // the real default is true/Cocoa, so the <26.4 gate was never added until now.)
            settings.setEnableElementCurrentCSSZoom(false);       // typeof Element.prototype.currentCSSZoom (+ every HTML*Element prototype)
        }
        // <26.2 — absent on 26.0 ONLY (26.3 >= 26.2 HAS them; Apple added at 26.2). Boundary
        // VERIFIED across real 26.0/26.2/26.3/26.4/26.5 /aio (apiEnum + cssSupports, 2026-06-19).
        if (dsHasArch && !driftstackArchetypeSafariAtLeast(26, 2)) {
            settings.setNavigationAPIEnabled(false);          // window.Navigation/NavigateEvent/… (26.0 undefined)
            settings.setEventTimingEnabled(false);            // Performance.eventCounts/interactionCount, EventCounts, PerformanceEventTiming
            settings.setLargestContentfulPaintEnabled(false); // LargestContentfulPaint + perfObs entry types (26.0=5, 26.2+=8)
            // FIX 2026-06-19: these two were wrongly in the <26.4 block — real /aio shows
            // field-sizing + scrollbar-color present FROM 26.2, so the <26.4 gate hid them on
            // the 26.3 archetype (26.3 HAS them). Correct boundary is 26.2.
            settings.setCSSFieldSizingEnabled(false);         // CSS.supports('field-sizing') (26.0=false, 26.2+=true)
            settings.setCSSScrollbarColorEnabled(false);      // CSS.supports('scrollbar-color') (26.0=false, 26.2+=true)
            // NEW 2026-06-19 (all False@26.0, True@26.2; each setting gates BOTH the window
            // global AND the member, so one flag closes the whole surface):
            settings.setSpeculationRulesPrefetchEnabled(false); // HTMLScriptElement.supports('speculationrules')
            settings.setCaretPositionFromPointEnabled(false);   // window.CaretPosition + document.caretPositionFromPoint
            settings.setCommandAttributesEnabled(false);        // window.CommandEvent + GlobalEventHandlers.oncommand
            settings.setHiddenUntilFoundEnabled(false);         // GlobalEventHandlers.onbeforematch (+ document)
            settings.setScrollendEventEnabled(false);           // GlobalEventHandlers.onscrollend (+ document)
            settings.setSafari262PrototypeMembersEnabled(false); // SVGAnimationElement.onbegin/onrepeat (added 26.2)
            // Apple REMOVED OverflowEvent + CanvasRenderingContext2D.drawImageFromRect at 26.2
            // (both present 26.0/26.1, absent 26.2+) — force the legacy forms ON for <26.2:
            settings.setOverflowEventEnabled(true);
            settings.setDriftstackLegacyCanvasDrawImageFromRectEnabled(true);
            // Class E (WebGPU 26.0): Apple removed the 4 per-stage storage limits at 26.2
            // (real 26.0 reports 36 limits incl maxStorage{Buffers,Textures}In{Fragment,Vertex}-
            // Stage = 4294967295; 26.2+ report 32). Re-expose them for <26.2 (safari26_0 band).
            // Only observable on WebGPU-capable models (18.x has no WebGPU). 26.3 keeps 32.
            settings.setDriftstackLegacyWebGPUPerStageLimitsEnabled(true);
        }
        // GPUDevice.adapterInfo added at Safari 26.2 (real 26.0 lacks it, 26.2+ have it; corrected
        // from 26.3 — adapterInfo is the single member 26.0→26.2 gains on GPUDevice). 26.0 hidden,
        // 26.3 keeps it (both correct). Only observable on WebGPU-capable models (18.x has no WebGPU).
        if (dsHasArch && !driftstackArchetypeSafariAtLeast(26, 2))
            settings.setWebGPUAdapterInfoEnabled(false);
    }
#endif

#if !PLATFORM(GTK) && !PLATFORM(WIN) && !PLATFORM(PLAYSTATION) && !PLATFORM(WPE)
    if (!settings.acceleratedCompositingEnabled()) {
        WEBPAGE_RELEASE_LOG(Layers, "updatePreferences: acceleratedCompositingEnabled setting was false. WebKit cannot function in this mode; changing setting to true");
        settings.setAcceleratedCompositingEnabled(true);
    }
#endif

    bool requiresUserGestureForMedia = store.getBoolValueForKey(WebPreferencesKey::requiresUserGestureForMediaPlaybackKey());
    settings.setRequiresUserGestureForVideoPlayback(requiresUserGestureForMedia || store.getBoolValueForKey(WebPreferencesKey::requiresUserGestureForVideoPlaybackKey()));
    settings.setRequiresUserGestureForAudioPlayback(requiresUserGestureForMedia || store.getBoolValueForKey(WebPreferencesKey::requiresUserGestureForAudioPlaybackKey()));
    settings.setUserInterfaceDirectionPolicy(static_cast<WebCore::UserInterfaceDirectionPolicy>(store.getUInt32ValueForKey(WebPreferencesKey::userInterfaceDirectionPolicyKey())));
    settings.setSystemLayoutDirection(static_cast<TextDirection>(store.getUInt32ValueForKey(WebPreferencesKey::systemLayoutDirectionKey())));
    settings.setJavaScriptRuntimeFlags(static_cast<RuntimeFlags>(store.getUInt32ValueForKey(WebPreferencesKey::javaScriptRuntimeFlagsKey())));
    settings.setStorageBlockingPolicy(static_cast<StorageBlockingPolicy>(store.getUInt32ValueForKey(WebPreferencesKey::storageBlockingPolicyKey())));
    settings.setEditableLinkBehavior(static_cast<WebCore::EditableLinkBehavior>(store.getUInt32ValueForKey(WebPreferencesKey::editableLinkBehaviorKey())));
#if ENABLE(DATA_DETECTION)
    settings.setDataDetectorTypes(static_cast<DataDetectorType>(store.getUInt32ValueForKey(WebPreferencesKey::dataDetectorTypesKey())));
#endif
    settings.setPitchCorrectionAlgorithm(static_cast<MediaPlayerEnums::PitchCorrectionAlgorithm>(store.getUInt32ValueForKey(WebPreferencesKey::pitchCorrectionAlgorithmKey())));

    DatabaseManager::singleton().setIsAvailable(store.getBoolValueForKey(WebPreferencesKey::databasesEnabledKey()));

    m_tabToLinks = store.getBoolValueForKey(WebPreferencesKey::tabsToLinksKey());

    bool isAppNapEnabled = store.getBoolValueForKey(WebPreferencesKey::pageVisibilityBasedProcessSuppressionEnabledKey());
    if (m_isAppNapEnabled != isAppNapEnabled) {
        m_isAppNapEnabled = isAppNapEnabled;
        updateThrottleState();
    }

#if PLATFORM(COCOA)
    m_pdfPluginEnabled = store.getBoolValueForKey(WebPreferencesKey::pdfPluginEnabledKey());

    m_selectionFlippingEnabled = store.getBoolValueForKey(WebPreferencesKey::selectionFlippingEnabledKey());
#endif
#if ENABLE(PAYMENT_REQUEST)
    settings.setPaymentRequestEnabled(store.getBoolValueForKey(WebPreferencesKey::applePayEnabledKey()));
#endif

#if PLATFORM(IOS_FAMILY)
    setForceAlwaysUserScalable(m_forceAlwaysUserScalable || store.getBoolValueForKey(WebPreferencesKey::forceAlwaysUserScalableKey()));
#endif

    if (store.getBoolValueForKey(WebPreferencesKey::serviceWorkerEntitlementDisabledForTestingKey()))
        disableServiceWorkerEntitlement();
#if ENABLE(APP_BOUND_DOMAINS)
    bool shouldAllowServiceWorkersForAppBoundViews = m_limitsNavigationsToAppBoundDomains;
#else
    bool shouldAllowServiceWorkersForAppBoundViews = false;
#endif

    if (store.getBoolValueForKey(WebPreferencesKey::serviceWorkersEnabledKey())) {
        ASSERT(parentProcessHasServiceWorkerEntitlement() || shouldAllowServiceWorkersForAppBoundViews);
        if (!parentProcessHasServiceWorkerEntitlement() && !shouldAllowServiceWorkersForAppBoundViews)
            settings.setServiceWorkersEnabled(false);
    }

#if ENABLE(APP_BOUND_DOMAINS)
    m_needsInAppBrowserPrivacyQuirks = store.getBoolValueForKey(WebPreferencesKey::needsInAppBrowserPrivacyQuirksKey());
#endif

    settings.setPrivateClickMeasurementEnabled(store.getBoolValueForKey(WebPreferencesKey::privateClickMeasurementEnabledKey()));

    if (RefPtr drawingArea = m_drawingArea)
        drawingArea->updatePreferences(store);

    WebProcess::singleton().setChildProcessDebuggabilityEnabled(store.getBoolValueForKey(WebPreferencesKey::childProcessDebuggabilityEnabledKey()));

#if ENABLE(GPU_PROCESS)
    downcast<WebMediaStrategy>(platformStrategies()->mediaStrategy()).setUseGPUProcess(m_shouldPlayMediaInGPUProcess);
#if ENABLE(VIDEO)
    protect(WebProcess::singleton().remoteMediaPlayerManager())->setUseGPUProcess(m_shouldPlayMediaInGPUProcess);
#if PLATFORM(COCOA)
    platformStrategies()->mediaStrategy()->enableRemoteRenderer(MediaPlayerMediaEngineIdentifier::CocoaWebM, settings.mediaContainmentEnabled());
    platformStrategies()->mediaStrategy()->enableRemoteRenderer(MediaPlayerMediaEngineIdentifier::AVFoundationMSE, settings.mediaContainmentEnabled());
#endif
#endif
#if HAVE(AVASSETREADER)
    protect(WebProcess::singleton().remoteImageDecoderAVFManager())->setUseGPUProcess(m_shouldPlayMediaInGPUProcess);
#endif
    WebProcess::singleton().setUseGPUProcessForCanvasRendering(m_shouldRenderCanvasInGPUProcess);
    bool usingGPUProcessForDOMRendering = m_shouldRenderDOMInGPUProcess
#if ENABLE(TILED_CA_DRAWING_AREA)
        && DrawingArea::supportsGPUProcessRendering(m_drawingAreaType);
#else
        && DrawingArea::supportsGPUProcessRendering();
#endif
    WebProcess::singleton().setUseGPUProcessForDOMRendering(usingGPUProcessForDOMRendering);
    WebProcess::singleton().setUseGPUProcessForMedia(m_shouldPlayMediaInGPUProcess);
#if ENABLE(WEBGL)
    WebProcess::singleton().setUseGPUProcessForWebGL(m_shouldRenderWebGLInGPUProcess);
#endif
#endif // ENABLE(GPU_PROCESS)

#if ENABLE(IPC_TESTING_API)
    m_ipcTestingAPIEnabled = store.getBoolValueForKey(WebPreferencesKey::ipcTestingAPIEnabledKey());

    protect(WebProcess::singleton().parentProcessConnection())->setIgnoreInvalidMessageForTesting();
    if (auto* gpuProcessConnection = WebProcess::singleton().existingGPUProcessConnection())
        gpuProcessConnection->connection().setIgnoreInvalidMessageForTesting();
#if ENABLE(MODEL_PROCESS)
    if (auto* modelProcessConnection = WebProcess::singleton().existingModelProcessConnection())
        modelProcessConnection->connection().setIgnoreInvalidMessageForTesting();
#endif // ENABLE(MODEL_PROCESS)
#endif // ENABLE(IPC_TESTING_API)

#if ENABLE(VP9) && PLATFORM(COCOA)
    VP9TestingOverrides::singleton().setSWVPDecodersAlwaysEnabled(store.getBoolValueForKey(WebPreferencesKey::sWVPDecodersAlwaysEnabledKey()));
#endif

    // FIXME: This should be automated by adding a new field in WebPreferences*.yaml
    // that indicates override state for Lockdown mode. https://webkit.org/b/233100.
    if (WebProcess::singleton().isLockdownModeEnabled())
        adjustSettingsForLockdownMode(settings, &store);
    if (settings.forceLockdownFontParserEnabled())
        settings.setDownloadableBinaryFontTrustedTypes(DownloadableBinaryFontTrustedTypes::SafeFontParser);

    if (settings.developerExtrasEnabled()) {
        settings.setShowMediaStatsContextMenuItemEnabled(true);
        settings.setTrackConfigurationEnabled(true);
    }

    // W378b (2026-06-02) — #28 fork-EXTRA hide, applied AFTER the developerExtrasEnabled() block above which
    // unconditionally re-enables TrackConfigurationEnabled (that masked the W378 disable in dev/inspector
    // builds; production has dev-extras OFF so it worked there, but this placement makes the fork hide
    // AudioTrack.configuration / VideoTrack.configuration ALWAYS, matching real iPhone-17 in every build).
    // TrackConfigurationEnabled gates ONLY those two attributes (W377 scope check — no over-hide).
    settings.setTrackConfigurationEnabled(false);

#if ENABLE(WIRELESS_PLAYBACK_MEDIA_PLAYER)
    platformStrategies()->mediaStrategy()->setWirelessPlaybackMediaPlayerEnabled(store.getBoolValueForKey(WebPreferencesKey::wirelessPlaybackMediaPlayerEnabledKey()));
#endif

#if ENABLE(PDF_PLUGIN)
    for (Ref pluginView : m_pluginViews)
        pluginView->didChangeSettings();
#endif

    WebProcess::singleton().updateSharedPreferencesForWebProcess(WebKit::sharedPreferencesForWebProcess(store, WebProcess::singleton().isLockdownModeEnabled()));

    protect(corePage())->settingsDidChange();
}

#if ENABLE(DATA_DETECTION)

void WebPage::setDataDetectionResults(NSArray *detectionResults)
{
    DataDetectionResult dataDetectionResult;
    dataDetectionResult.setResults(detectionResults);
    send(Messages::WebPageProxy::SetDataDetectionResult(dataDetectionResult));
}

void WebPage::removeDataDetectedLinks(CompletionHandler<void(DataDetectionResult&&)>&& completionHandler)
{
    for (RefPtr frame = m_page->mainFrame(); frame; frame = frame->tree().traverseNext()) {
        RefPtr localFrame = dynamicDowncast<LocalFrame>(frame.get());
        if (!localFrame)
            continue;
        RefPtr document = localFrame->document();
        if (!document)
            continue;

        DataDetection::removeDataDetectedLinksInDocument(*document);

        if (auto* results = localFrame->dataDetectionResultsIfExists()) {
            // FIXME: It seems odd that we're clearing out all data detection results here,
            // instead of only data detectors that correspond to links.
            results->setDocumentLevelResults(nullptr);
        }
    }
    completionHandler({ });
}

static void detectDataInFrame(const Ref<Frame>& frame, OptionSet<WebCore::DataDetectorType> dataDetectorTypes, const std::optional<double>& dataDetectionReferenceDate, UniqueRef<DataDetectionResult>&& mainFrameResult, CompletionHandler<void(DataDetectionResult&&)>&& completionHandler)
{
    RefPtr localFrame = dynamicDowncast<LocalFrame>(frame.get());
    if (!localFrame) {
        completionHandler(WTF::move(mainFrameResult.get()));
        return;
    }

    DataDetection::detectContentInFrame(localFrame.get(), dataDetectorTypes, dataDetectionReferenceDate, [localFrame, mainFrameResult = WTF::move(mainFrameResult), dataDetectionReferenceDate, completionHandler = WTF::move(completionHandler), dataDetectorTypes](NSArray *results) mutable {
        localFrame->dataDetectionResults().setDocumentLevelResults(results);
        if (localFrame->isMainFrame())
            mainFrameResult->setResults(results);

        RefPtr next = localFrame->tree().traverseNext();
        if (!next) {
            completionHandler(WTF::move(mainFrameResult.get()));
            return;
        }

        detectDataInFrame(Ref { *next }, dataDetectorTypes, dataDetectionReferenceDate, WTF::move(mainFrameResult), WTF::move(completionHandler));
    });
}

void WebPage::detectDataInAllFrames(OptionSet<WebCore::DataDetectorType> dataDetectorTypes, CompletionHandler<void(DataDetectionResult&&)>&& completionHandler)
{
    auto mainFrameResult = makeUniqueRef<DataDetectionResult>();
    detectDataInFrame(Ref { corePage()->mainFrame() }, dataDetectorTypes, m_dataDetectionReferenceDate, WTF::move(mainFrameResult), WTF::move(completionHandler));
}

#endif // ENABLE(DATA_DETECTION)

void WebPage::layoutIfNeeded()
{
    protect(corePage())->layoutIfNeeded();
}

void WebPage::updateRendering()
{
    protect(corePage())->updateRendering();

#if PLATFORM(IOS_FAMILY)
    findController().redraw();
    foundTextRangeController().redraw();
#endif
}

bool WebPage::hasRootFrames()
{
    bool result = m_page && !m_page->rootFrames().isEmpty();
#if ASSERT_ENABLED
    if (!result)
        ASSERT(m_page->settings().siteIsolationEnabled());
#endif
    return result;
}

String WebPage::rootFrameOriginString()
{
    auto rootFrameURL = [&] () -> URL {
        if (!m_page)
            return { };
        if (m_page->rootFrames().isEmpty())
            return { };
        RefPtr documentLoader = m_page->rootFrames().begin()->get().loader().documentLoader();
        if (!documentLoader)
            return { };
        return documentLoader->url();
    } ();

    Ref<SecurityOrigin> origin = SecurityOrigin::create(rootFrameURL);
    if (!origin->isOpaque())
        return origin->toRawString();

    // toRawString() is not supposed to work with opaque origins, and would just return "://".
    return makeString(rootFrameURL.protocol(), ':');
}

void WebPage::didUpdateRendering(OptionSet<DidUpdateRenderingFlags> flags)
{
    if (flags & DidUpdateRenderingFlags::PaintedLayers) {
#if ENABLE(GPU_PROCESS)
        if (RefPtr proxy = m_remoteRenderingBackendProxy)
            proxy->didPaintLayers();
#endif
    }

    if (flags & DidUpdateRenderingFlags::NotifyUIProcess) {
        if (m_didUpdateRenderingAfterCommittingLoad)
            return;

        m_didUpdateRenderingAfterCommittingLoad = true;
        send(Messages::WebPageProxy::DidUpdateRenderingAfterCommittingLoad());
    }

    protect(corePage())->didUpdateRendering();
}

bool WebPage::shouldTriggerRenderingUpdate(unsigned rescheduledRenderingUpdateCount) const
{
#if ENABLE(GPU_PROCESS)
    static constexpr unsigned maxRescheduledRenderingUpdateCount = FullSpeedFramesPerSecond;
    if (rescheduledRenderingUpdateCount >= maxRescheduledRenderingUpdateCount)
        return true;

    static constexpr unsigned maxDelayedRenderingUpdateCount = 2;
    auto* proxy = m_remoteRenderingBackendProxy.get();
    if (proxy && proxy->delayedRenderingUpdateCount() > maxDelayedRenderingUpdateCount)
        return false;
#endif
    return true;
}

void WebPage::finalizeRenderingUpdate(OptionSet<FinalizeRenderingUpdateFlags> flags)
{
#if !PLATFORM(COCOA)
    WTFBeginSignpost(this, FinalizeRenderingUpdate);
#endif

    protect(corePage())->finalizeRenderingUpdate(flags);
#if ENABLE(GPU_PROCESS)
    if (RefPtr proxy = m_remoteRenderingBackendProxy)
        proxy->finalizeRenderingUpdate();
#endif
    flushDeferredDidReceiveMouseEvent();

#if !PLATFORM(COCOA)
    WTFEndSignpost(this, FinalizeRenderingUpdate);
#endif
}

void WebPage::willStartRenderingUpdateDisplay()
{
    if (m_isClosed)
        return;
    protect(corePage())->willStartRenderingUpdateDisplay();
}

void WebPage::didCompleteRenderingUpdateDisplay()
{
    if (m_isClosed)
        return;
    protect(corePage())->didCompleteRenderingUpdateDisplay();
}

void WebPage::didCompleteRenderingFrame()
{
    if (m_isClosed)
        return;
    protect(corePage())->didCompleteRenderingFrame();
}

void WebPage::releaseMemory(Critical)
{
#if ENABLE(GPU_PROCESS)
    if (RefPtr renderingBackend = m_remoteRenderingBackendProxy)
        renderingBackend->releaseMemory();
#endif

    m_foundTextRangeController->clearCachedRanges();
}

void WebPage::willDestroyDecodedDataForAllImages()
{
}

unsigned WebPage::remoteImagesCountForTesting() const
{
#if ENABLE(GPU_PROCESS)
    if (auto* renderingBackend = m_remoteRenderingBackendProxy.get())
        return renderingBackend->nativeImageCountForTesting();
#endif
    return 0;
}

WebInspectorBackend* WebPage::inspector(LazyCreationPolicy behavior)
{
    if (m_isClosed)
        return nullptr;
    if (!m_inspector && behavior == LazyCreationPolicy::CreateIfNeeded)
        m_inspector = WebInspectorBackend::create(*this);
    return m_inspector.get();
}

WebInspectorUI* WebPage::inspectorUI()
{
    if (m_isClosed)
        return nullptr;
    if (!m_inspectorUI)
        m_inspectorUI = WebInspectorUI::create(*this);
    return m_inspectorUI.get();
}

RemoteWebInspectorUI* WebPage::remoteInspectorUI()
{
    if (m_isClosed)
        return nullptr;
    if (!m_remoteInspectorUI)
        m_remoteInspectorUI = RemoteWebInspectorUI::create(*this);
    return m_remoteInspectorUI.get();
}

void WebPage::inspectorFrontendCountChanged(unsigned count)
{
    send(Messages::WebPageProxy::DidChangeInspectorFrontendCount(count));
}

#if ENABLE(VIDEO_PRESENTATION_MODE)
PlaybackSessionManager& WebPage::playbackSessionManager()
{
    if (!m_playbackSessionManager)
        m_playbackSessionManager = PlaybackSessionManager::create(*this);
    return *m_playbackSessionManager;
}

VideoPresentationManager& WebPage::videoPresentationManager()
{
    if (!m_videoPresentationManager)
        m_videoPresentationManager = VideoPresentationManager::create(*this, protect(playbackSessionManager()));
    return *m_videoPresentationManager;
}

void WebPage::videoControlsManagerDidChange()
{
#if ENABLE(FULLSCREEN_API)
    protect(fullScreenManager())->videoControlsManagerDidChange();
#endif
}

void WebPage::startPlayingPredominantVideo(CompletionHandler<void(bool)>&& completion)
{
    RefPtr mainFrame = m_mainFrame->coreLocalFrame();
    if (!mainFrame) {
        completion(false);
        return;
    }

    RefPtr view = mainFrame->view();
    if (!view) {
        completion(false);
        return;
    }

    RefPtr document = mainFrame->document();
    if (!document) {
        completion(false);
        return;
    }

    Vector<Ref<HTMLMediaElement>> candidates;
    document->updateLayoutIgnorePendingStylesheets();
    document->forEachMediaElement([&candidates](auto& element) {
        if (!element.canPlay())
            return;

        if (!element.isVisibleInViewport())
            return;

        candidates.append(element);
    });

    RefPtr<HTMLMediaElement> largestElement;
    float largestArea = 0;
    auto unobscuredContentRect = view->unobscuredContentRect();
    auto unobscuredArea = unobscuredContentRect.area<RecordOverflow>();
    if (unobscuredArea.hasOverflowed()) {
        completion(false);
        return;
    }

    constexpr auto minimumViewportRatioForLargestMediaElement = 0.25;
    float minimumAreaForLargestElement = minimumViewportRatioForLargestMediaElement * unobscuredArea.value();
    for (auto& candidate : candidates) {
        auto intersectionRect = intersection(unobscuredContentRect, candidate->boundingBoxInRootViewCoordinates());
        if (intersectionRect.isEmpty())
            continue;

        auto area = intersectionRect.area<RecordOverflow>();
        if (area.hasOverflowed())
            continue;

        if (area <= largestArea)
            continue;

        if (area < minimumAreaForLargestElement)
            continue;

        largestArea = area;
        largestElement = candidate.ptr();
    }

    if (!largestElement) {
        completion(false);
        return;
    }

    UserGestureIndicator userGesture { IsProcessingUserGesture::Yes, document.get() };
    largestElement->play();
    completion(true);
}

#endif // ENABLE(VIDEO_PRESENTATION_MODE)

#if PLATFORM(IOS_FAMILY)
void WebPage::setSceneIdentifier(String&& sceneIdentifier)
{
    AudioSession::singleton().setSceneIdentifier(sceneIdentifier);
    protect(m_page)->setSceneIdentifier(WTF::move(sceneIdentifier));
}

void WebPage::setAllowsMediaDocumentInlinePlayback(bool allows)
{
    protect(m_page)->setAllowsMediaDocumentInlinePlayback(allows);
}
#endif

#if ENABLE(FULLSCREEN_API)
WebFullScreenManager& WebPage::fullScreenManager()
{
    if (!m_fullScreenManager)
        m_fullScreenManager = WebFullScreenManager::create(*this);
    return *m_fullScreenManager;
}

void WebPage::isInFullscreenChanged(IsInFullscreenMode isInFullscreenMode)
{
    if (m_isInFullscreenMode == isInFullscreenMode)
        return;
    m_isInFullscreenMode = isInFullscreenMode;

#if ENABLE(META_VIEWPORT)
    resetViewportDefaultConfiguration(m_mainFrame.ptr(), m_isMobileDoctype);
#endif
}

void WebPage::closeFullScreen()
{
    removeReasonsToDisallowLayoutViewportHeightExpansion(DisallowLayoutViewportHeightExpansionReason::ElementFullScreen);

    send(Messages::WebFullScreenManagerProxy::Close());
}

void WebPage::prepareToEnterElementFullScreen()
{
    addReasonsToDisallowLayoutViewportHeightExpansion(DisallowLayoutViewportHeightExpansionReason::ElementFullScreen);
}

void WebPage::prepareToExitElementFullScreen()
{
    removeReasonsToDisallowLayoutViewportHeightExpansion(DisallowLayoutViewportHeightExpansionReason::ElementFullScreen);
}

#endif // ENABLE(FULLSCREEN_API)

void WebPage::addConsoleMessage(FrameIdentifier frameID, MessageSource messageSource, MessageLevel messageLevel, const String& message, std::optional<WebCore::ResourceLoaderIdentifier> requestID)
{
    if (RefPtr frame = WebProcess::singleton().webFrame(frameID))
        frame->addConsoleMessage(messageSource, messageLevel, message, requestID ? requestID->toUInt64() : 0);
}

void WebPage::enqueueSecurityPolicyViolationEvent(FrameIdentifier frameID, SecurityPolicyViolationEventInit&& eventInit)
{
    RefPtr frame = WebProcess::singleton().webFrame(frameID);
    if (!frame)
        return;
    RefPtr coreFrame = frame->coreLocalFrame();
    if (!coreFrame)
        return;
    if (RefPtr document = coreFrame->document())
        document->enqueueSecurityPolicyViolationEvent(WTF::move(eventInit));
}

void WebPage::notifyReportObservers(FrameIdentifier frameID, Ref<WebCore::Report>&& report)
{
    RefPtr frame = WebProcess::singleton().webFrame(frameID);
    if (!frame)
        return;
    RefPtr coreFrame = frame->coreLocalFrame();
    if (!coreFrame)
        return;
    if (RefPtr document = coreFrame->document())
        protect(document->reportingScope())->notifyReportObservers(WTF::move(report));
}

void WebPage::sendReportToEndpoints(FrameIdentifier frameID, URL&& baseURL, const Vector<String>& endpointURIs, const Vector<String>& endpointTokens, IPC::FormDataReference&& reportData, WebCore::ViolationReportType reportType)
{
    auto report = reportData.takeData();
    if (!report)
        return;

    RefPtr frame = WebProcess::singleton().webFrame(frameID);
    if (!frame)
        return;

    RefPtr localFrame = frame->coreLocalFrame();
    if (!localFrame) {
        localFrame = frame->provisionalFrame();
        if (!localFrame)
            return;

        // With site isolation, the frame is still provisional at the time of a
        // CSP frame-ancestors violation, so its outgoingReferrerURL is not yet
        // set. Recover it from the provisional DocumentLoader's request so that
        // PingLoader produces the correct HTTP Referer header on the report POST.
        if (RefPtr docLoader = localFrame->loader().provisionalDocumentLoader()) {
            auto referrer = docLoader->request().httpReferrer();
            if (!referrer.isEmpty())
                localFrame->loader().setOutgoingReferrer(URL { referrer });
        }
    }

    for (auto& url : endpointURIs)
        PingLoader::sendViolationReport(*localFrame, URL { baseURL, url }, Ref { *report }, reportType);

    RefPtr document = localFrame->document();
    if (!document)
        return;

    for (auto& token : endpointTokens) {
        if (auto url = document->endpointURIForToken(token); !url.isEmpty())
            PingLoader::sendViolationReport(*localFrame, URL { baseURL, url }, Ref { *report }, reportType);
    }
}

NotificationPermissionRequestManager* WebPage::notificationPermissionRequestManager()
{
    if (m_notificationPermissionRequestManager)
        return m_notificationPermissionRequestManager.get();

    m_notificationPermissionRequestManager = NotificationPermissionRequestManager::create(this);
    return m_notificationPermissionRequestManager.get();
}

#if ENABLE(DRAG_SUPPORT)

#if PLATFORM(GTK)
void WebPage::performDragControllerAction(DragControllerAction action, const IntPoint& clientPosition, const IntPoint& globalPosition, OptionSet<DragOperation> draggingSourceOperationMask, SelectionData&& selectionData, OptionSet<DragApplicationFlags> flags, CompletionHandler<void(std::optional<DragOperation>, DragHandlingMethod, bool, unsigned, IntRect, IntRect, std::optional<RemoteUserInputEventData>)>&& completionHandler)
{
    if (!m_page)
        return completionHandler(std::nullopt, DragHandlingMethod::None, false, 0, { }, { }, std::nullopt);

    RefPtr localMainFrame = this->localMainFrame();
    if (!localMainFrame)
        return;

    DragData dragData(&selectionData, clientPosition, globalPosition, draggingSourceOperationMask, flags, anyDragDestinationAction(), m_identifier);
    switch (action) {
    case DragControllerAction::Entered:
    case DragControllerAction::Updated: {
        auto resolvedDragAction = m_page->dragController().dragEnteredOrUpdated(*localMainFrame, WTF::move(dragData));
        if (std::holds_alternative<RemoteUserInputEventData>(resolvedDragAction))
            return completionHandler(std::nullopt, DragHandlingMethod::None, false, 0, { }, { }, std::get<RemoteUserInputEventData>(resolvedDragAction));
        auto dragOperation = std::get<std::optional<DragOperation>>(resolvedDragAction);
        return completionHandler(dragOperation, m_page->dragController().dragHandlingMethod(), m_page->dragController().mouseIsOverFileInput(), m_page->dragController().numberOfItemsToBeAccepted(), { }, { }, std::nullopt);
    }
    case DragControllerAction::Exited:
        m_page->dragController().dragExited(*localMainFrame, WTF::move(dragData));
        return completionHandler(std::nullopt, DragHandlingMethod::None, false, 0, { }, { }, std::nullopt);

    case DragControllerAction::PerformDragOperation: {
        m_page->dragController().performDragOperation(WTF::move(dragData), *localMainFrame);
        return completionHandler(std::nullopt, DragHandlingMethod::None, false, 0, { }, { }, std::nullopt);
    }
    }
    ASSERT_NOT_REACHED();
}
#else
void WebPage::performDragControllerAction(std::optional<FrameIdentifier> frameID, DragControllerAction action, DragData&& dragData, CompletionHandler<void(std::optional<DragOperation>, DragHandlingMethod, bool, unsigned, IntRect, IntRect, std::optional<RemoteUserInputEventData>)>&& completionHandler)
{
    if (!m_page)
        return completionHandler(std::nullopt, DragHandlingMethod::None, false, 0, { }, { }, std::nullopt);

    RefPtr frame = frameID ? WebProcess::singleton().webFrame(*frameID) : &mainWebFrame();
    if (!frame) {
        ASSERT_NOT_REACHED();
        return;
    }

    RefPtr localFrame = frame->coreLocalFrame();
    if (!localFrame) {
        ASSERT_NOT_REACHED();
        return;
    }

    switch (action) {
    case DragControllerAction::Entered:
    case DragControllerAction::Updated: {
        auto resolvedDragAction = m_page->dragController().dragEnteredOrUpdated(*localFrame, WTF::move(dragData));
        if (std::holds_alternative<RemoteUserInputEventData>(resolvedDragAction))
            return completionHandler(std::nullopt, DragHandlingMethod::None, false, 0, { }, { }, std::get<RemoteUserInputEventData>(resolvedDragAction));
        auto dragOperation = std::get<std::optional<DragOperation>>(resolvedDragAction);
        return completionHandler(dragOperation, m_page->dragController().dragHandlingMethod(), m_page->dragController().mouseIsOverFileInput(), m_page->dragController().numberOfItemsToBeAccepted(), m_page->dragCaretController().caretRectInRootViewCoordinates(), m_page->dragCaretController().editableElementRectInRootViewCoordinates(), std::nullopt);
    }
    case DragControllerAction::Exited:
        m_page->dragController().dragExited(*localFrame, WTF::move(dragData));
        return completionHandler(std::nullopt, DragHandlingMethod::None, false, 0, { }, { }, std::nullopt);
    case DragControllerAction::PerformDragOperation:
        break;
    }
    ASSERT_NOT_REACHED();
}

void WebPage::performDragOperation(std::optional<WebCore::FrameIdentifier> frameID, WebCore::DragData&& dragData, SandboxExtension::Handle&& sandboxExtensionHandle, Vector<SandboxExtension::Handle>&& sandboxExtensionsForUpload, CompletionHandler<void(DragOperationResult dragOperationResult)>&& completionHandler)
{
    m_pendingDropSandboxExtensionHandle = WTF::move(sandboxExtensionHandle);
    m_pendingDropExtensionHandlesForFileUpload = WTF::move(sandboxExtensionsForUpload);

    RefPtr frame = frameID ? WebProcess::singleton().webFrame(*frameID) : &mainWebFrame();
    if (!frame) {
        ASSERT_NOT_REACHED();
        completionHandler(false);
        return;
    }

    RefPtr localFrame = frame->coreLocalFrame();
    if (!localFrame) {
        ASSERT_NOT_REACHED();
        completionHandler(false);
        return;
    }

    DragEventTargetData dragEventTargetData = m_page->dragController().performDragOperation(WTF::move(dragData), *localFrame);

    WTF::switchOn(dragEventTargetData, [&](WebCore::DragEventHandled handled) {
        completionHandler(handled == WebCore::DragEventHandled::Yes);
    }, [&](WebCore::FrameIdentifier targetFrameID) {
        if (targetFrameID != *frameID && m_pendingDropSandboxExtensionHandle && m_pendingDropExtensionHandlesForFileUpload) {
            DragEventForwardingData result {
                targetFrameID,
                WTF::move(*m_pendingDropSandboxExtensionHandle),
                WTF::move(*m_pendingDropExtensionHandlesForFileUpload)
            };
            completionHandler(WTF::move(result));
            return;
        }
        completionHandler(false);
    });
}
#endif

void WebPage::dragEnded(std::optional<FrameIdentifier> frameID, IntPoint clientPosition, IntPoint globalPosition, OptionSet<DragOperation> dragOperationMask, CompletionHandler<void(std::optional<RemoteUserInputEventData>)>&& completionHandler)
{
    IntPoint adjustedGlobalPosition(globalPosition.x() + m_page->dragController().dragOffset().x(), globalPosition.y() + m_page->dragController().dragOffset().y());

    m_page->dragController().dragEnded();
    RefPtr frame = frameID ? WebProcess::singleton().webFrame(*frameID) : &mainWebFrame();
    if (!frame)
        return completionHandler(std::nullopt);

    RefPtr localFrame = frame->coreLocalFrame();
    if (!localFrame)
        return completionHandler(std::nullopt);

    RefPtr view = localFrame->view();
    if (!view)
        return completionHandler(std::nullopt);

    // FIXME: These are fake modifier keys here, but they should be real ones instead.
    PlatformMouseEvent event(clientPosition, adjustedGlobalPosition, MouseButton::Left, PlatformEvent::Type::MouseMoved, 0, { }, MonotonicTime::now(), 0, WebCore::SyntheticClickType::NoTap, MouseEventInputSource::UserDriven);
    auto remoteUserInputEventData = localFrame->eventHandler().dragSourceEndedAt(event, dragOperationMask);

    completionHandler(remoteUserInputEventData);

    m_isStartingDrag = false;
}

void WebPage::willPerformLoadDragDestinationAction()
{
    if (auto pendingDropSandboxExtensionHandle = std::exchange(m_pendingDropSandboxExtensionHandle, std::nullopt))
        m_sandboxExtensionTracker.willPerformLoadDragDestinationAction(SandboxExtension::create(WTF::move(pendingDropSandboxExtensionHandle.value())));
}

void WebPage::mayPerformUploadDragDestinationAction()
{
    if (!m_pendingDropExtensionHandlesForFileUpload)
        return;

    for (auto& extensionHandle : *m_pendingDropExtensionHandlesForFileUpload) {
        if (auto extension = SandboxExtension::create(WTF::move(extensionHandle)))
            extension->consumePermanently();
    }

    m_pendingDropExtensionHandlesForFileUpload = std::nullopt;
}

void WebPage::didStartDrag(std::optional<FrameIdentifier> frameID)
{
    m_isStartingDrag = false;

    if (RefPtr frame = frameID ? WebProcess::singleton().webFrame(*frameID) : &mainWebFrame()) {
        if (auto* localFrame = frame->coreLocalFrame())
            localFrame->eventHandler().didStartDrag();
    }
}

void WebPage::dragCancelled()
{
    m_isStartingDrag = false;
    if (RefPtr localMainFrame = this->localMainFrame())
        localMainFrame->eventHandler().dragCancelled();
}

#if ENABLE(MODEL_PROCESS)
void WebPage::modelDragEnded(NodeIdentifier nodeIdentifier)
{
    RefPtr node = Node::fromIdentifier(nodeIdentifier);
    if (!node)
        return;

    RefPtr modelElement = dynamicDowncast<HTMLModelElement>(node);
    if (!modelElement)
        return;

    modelElement->resetModelTransformAfterDrag();
}
#endif

#endif // ENABLE(DRAG_SUPPORT)

#if ENABLE(MODEL_PROCESS)
void WebPage::requestInteractiveModelElementAtPoint(IntPoint clientPosition)
{
    if (RefPtr localMainFrame = dynamicDowncast<LocalFrame>(m_page->mainFrame())) {
        auto nodeID = localMainFrame->eventHandler().requestInteractiveModelElementAtPoint(clientPosition);
        send(Messages::WebPageProxy::DidReceiveInteractiveModelElement(nodeID));
    } else
        send(Messages::WebPageProxy::DidReceiveInteractiveModelElement(std::nullopt));
}

void WebPage::stageModeSessionDidUpdate(std::optional<NodeIdentifier> nodeID, const TransformationMatrix& transform)
{
    if (RefPtr localMainFrame = dynamicDowncast<LocalFrame>(m_page->mainFrame()))
        localMainFrame->eventHandler().stageModeSessionDidUpdate(nodeID, transform);
}

void WebPage::stageModeSessionDidEnd(std::optional<NodeIdentifier> nodeID)
{
    if (RefPtr localMainFrame = dynamicDowncast<LocalFrame>(m_page->mainFrame()))
        localMainFrame->eventHandler().stageModeSessionDidEnd(nodeID);
}
#endif

WebUndoStep* WebPage::webUndoStep(WebUndoStepID stepID)
{
    return m_undoStepMap.get(stepID);
}

void WebPage::addWebUndoStep(WebUndoStepID stepID, Ref<WebUndoStep>&& entry)
{
    auto addResult = m_undoStepMap.set(stepID, WTF::move(entry));
    ASSERT_UNUSED(addResult, addResult.isNewEntry);
}

void WebPage::removeWebEditCommand(WebUndoStepID stepID)
{
    if (auto undoStep = m_undoStepMap.take(stepID))
        undoStep->didRemoveFromUndoManager();
}

void WebPage::unapplyEditCommand(uint32_t undoVersion, WebUndoStepID stepID, CompletionHandler<void()>&& completionHandler)
{
    if (undoVersion < m_currentUndoVersion)
        return completionHandler();

    m_currentUndoVersion = undoVersion;

    RefPtr step = webUndoStep(stepID);
    if (!step)
        return completionHandler();

    protect(step->step())->unapply();
    completionHandler();
}

void WebPage::reapplyEditCommand(uint32_t undoVersion, WebUndoStepID stepID, CompletionHandler<void()>&& completionHandler)
{
    if (undoVersion < m_currentUndoVersion)
        return completionHandler();

    m_currentUndoVersion = undoVersion;

    RefPtr step = webUndoStep(stepID);
    if (!step)
        return completionHandler();

    setIsInRedo(true);
    protect(step->step())->reapply();
    setIsInRedo(false);
    completionHandler();
}

void WebPage::didRemoveEditCommand(WebUndoStepID commandID)
{
    removeWebEditCommand(commandID);
}

void WebPage::closeCurrentTypingCommand()
{
    RefPtr frame = corePage()->focusController().focusedOrMainFrame();
    if (!frame)
        return;

    if (RefPtr document = frame->document())
        protect(document->editor())->closeTyping();
}

void WebPage::setActivePopupMenu(WebPopupMenu* menu)
{
    m_activePopupMenu = menu;
}

WebColorChooser* WebPage::activeColorChooser() const
{
    return m_activeColorChooser.get();
}

void WebPage::setActiveColorChooser(WebColorChooser* colorChooser)
{
    m_activeColorChooser = colorChooser;
}

void WebPage::didEndColorPicker()
{
    if (RefPtr activeColorChooser = m_activeColorChooser.get())
        activeColorChooser->didEndChooser();
}

void WebPage::didChooseColor(const WebCore::Color& color)
{
    if (RefPtr activeColorChooser = m_activeColorChooser.get())
        activeColorChooser->didChooseColor(color);
}

void WebPage::setActiveDataListSuggestionPicker(WebDataListSuggestionPicker& dataListSuggestionPicker)
{
    m_activeDataListSuggestionPicker = dataListSuggestionPicker;
}

void WebPage::didSelectDataListOption(const String& selectedOption)
{
    if (RefPtr activeDataListSuggestionPicker = m_activeDataListSuggestionPicker.get())
        activeDataListSuggestionPicker->didSelectOption(selectedOption);
}

void WebPage::didCloseSuggestions()
{
    if (RefPtr picker = std::exchange(m_activeDataListSuggestionPicker, nullptr).get())
        picker->didCloseSuggestions();
}

void WebPage::setActiveDateTimeChooser(WebDateTimeChooser& dateTimeChooser)
{
    m_activeDateTimeChooser = dateTimeChooser;
}

void WebPage::didChooseDate(const String& date)
{
    if (RefPtr activeDateTimeChooser = m_activeDateTimeChooser.get())
        activeDateTimeChooser->didChooseDate(date);
}

void WebPage::didEndDateTimePicker()
{
    if (auto chooser = std::exchange(m_activeDateTimeChooser, nullptr))
        chooser->didEndChooser();
}

void WebPage::setActiveOpenPanelResultListener(Ref<WebOpenPanelResultListener>&& openPanelResultListener)
{
    m_activeOpenPanelResultListener = WTF::move(openPanelResultListener);
}

void WebPage::setTextIndicator(RefPtr<WebCore::TextIndicator>&& textIndicator)
{
    send(Messages::WebPageProxy::SetTextIndicatorFromFrame(m_mainFrame->frameID(), WTF::move(textIndicator), WebCore::TextIndicatorLifetime::Temporary));
}

void WebPage::updateTextIndicator(RefPtr<WebCore::TextIndicator>&& textIndicator)
{
    send(Messages::WebPageProxy::UpdateTextIndicatorFromFrame(m_mainFrame->frameID(), WTF::move(textIndicator)));
}

void WebPage::replaceStringMatchesFromInjectedBundle(const Vector<uint32_t>& matchIndices, const String& replacementText, bool selectionOnly)
{
    findController().replaceMatches(matchIndices, replacementText, selectionOnly);
}

void WebPage::findString(const String& string, OptionSet<FindOptions> options, uint32_t maxMatchCount, CompletionHandler<void(std::optional<FrameIdentifier>, Vector<IntRect>&&, uint32_t, int32_t, bool)>&& completionHandler)
{
    findController().findString(string, options, maxMatchCount, WTF::move(completionHandler));
}

#if ENABLE(IMAGE_ANALYSIS)
void WebPage::findStringIncludingImages(const String& string, OptionSet<FindOptions> options, uint32_t maxMatchCount, CompletionHandler<void(std::optional<FrameIdentifier>, Vector<IntRect>&&, uint32_t, int32_t, bool)>&& completionHandler)
{
    findController().findStringIncludingImages(string, options, maxMatchCount, WTF::move(completionHandler));
}
#endif

void WebPage::findStringMatches(const String& string, OptionSet<FindOptions> options, uint32_t maxMatchCount, CompletionHandler<void(Vector<Vector<WebCore::IntRect>>, int32_t)>&& completionHandler)
{
    findController().findStringMatches(string, options, maxMatchCount, WTF::move(completionHandler));
}

void WebPage::findTextRangesForStringMatches(const String& string, OptionSet<FindOptions> options, uint32_t maxMatchCount, CompletionHandler<void(HashMap<WebCore::FrameIdentifier, Vector<WebFoundTextRange>>&&)>&& completionHandler)
{
    foundTextRangeController().findTextRangesForStringMatches(string, options, maxMatchCount, WTF::move(completionHandler));
}

void WebPage::replaceFoundTextRangeWithString(const WebFoundTextRange& range, const String& string)
{
    foundTextRangeController().replaceFoundTextRangeWithString(range, string);
}

void WebPage::decorateTextRangeWithStyle(const WebFoundTextRange& range, WebKit::FindDecorationStyle style)
{
    foundTextRangeController().decorateTextRangeWithStyle(range, style);
}

void WebPage::scrollTextRangeToVisible(const WebFoundTextRange& range)
{
    foundTextRangeController().scrollTextRangeToVisible(range);
}

void WebPage::clearAllDecoratedFoundText()
{
    hideFindUI();
    foundTextRangeController().clearAllDecoratedFoundText();
}

void WebPage::didBeginTextSearchOperation()
{
    foundTextRangeController().didBeginTextSearchOperation();
}

void WebPage::requestRectForFoundTextRange(const WebFoundTextRange& range, CompletionHandler<void(WebCore::FloatRect)>&& completionHandler)
{
    foundTextRangeController().requestRectForFoundTextRange(range, WTF::move(completionHandler));
}

void WebPage::addLayerForFindOverlay(CompletionHandler<void(std::optional<WebCore::PlatformLayerIdentifier>)>&& completionHandler)
{
    foundTextRangeController().addLayerForFindOverlay(WTF::move(completionHandler));
}

void WebPage::removeLayerForFindOverlay(CompletionHandler<void()>&& completionHandler)
{
    foundTextRangeController().removeLayerForFindOverlay();
    completionHandler();
}

void WebPage::getImageForFindMatch(uint32_t matchIndex)
{
    findController().getImageForFindMatch(matchIndex);
}

void WebPage::selectFindMatch(uint32_t matchIndex)
{
    findController().selectFindMatch(matchIndex);
}

void WebPage::indicateFindMatch(uint32_t matchIndex)
{
    findController().indicateFindMatch(matchIndex);
}

void WebPage::hideFindUI()
{
    findController().hideFindUI();
}

void WebPage::countStringMatches(const String& string, OptionSet<FindOptions> options, uint32_t maxMatchCount, CompletionHandler<void(uint32_t)>&& completionHandler)
{
    findController().countStringMatches(string, options, maxMatchCount, WTF::move(completionHandler));
}

void WebPage::replaceMatches(const Vector<uint32_t>& matchIndices, const String& replacementText, bool selectionOnly, CompletionHandler<void(uint64_t)>&& completionHandler)
{
    auto numberOfReplacements = findController().replaceMatches(matchIndices, replacementText, selectionOnly);
    completionHandler(numberOfReplacements);
}

#if !PLATFORM(IOS_FAMILY)
void WebPage::didChangeSelectedIndexForActivePopupMenu(int32_t newIndex)
{
    changeSelectedIndex(newIndex);
    m_activePopupMenu = nullptr;
}

void WebPage::changeSelectedIndex(int32_t index)
{
    if (RefPtr menu = m_activePopupMenu)
        menu->didChangeSelectedIndex(index);
}
#endif

#if PLATFORM(IOS_FAMILY)
void WebPage::didChooseFilesForOpenPanelWithDisplayStringAndIcon(const Vector<String>& files, const String& displayString, std::span<const uint8_t> iconData)
{
    RefPtr activeOpenPanelResultListener = m_activeOpenPanelResultListener;
    if (!activeOpenPanelResultListener)
        return;

    RefPtr<Icon> icon;
    if (!iconData.empty()) {
        RetainPtr<CFDataRef> dataRef = adoptCF(CFDataCreate(nullptr, iconData.data(), iconData.size()));
        RetainPtr<CGDataProviderRef> imageProviderRef = adoptCF(CGDataProviderCreateWithCFData(dataRef.get()));
        RetainPtr<CGImageRef> imageRef = adoptCF(CGImageCreateWithPNGDataProvider(imageProviderRef.get(), nullptr, true, kCGRenderingIntentDefault));
        if (!imageRef)
            imageRef = adoptCF(CGImageCreateWithJPEGDataProvider(imageProviderRef.get(), nullptr, true, kCGRenderingIntentDefault));
        icon = Icon::create(WTF::move(imageRef));
    }

    activeOpenPanelResultListener->didChooseFilesWithDisplayStringAndIcon(files, displayString, icon.get());
    m_activeOpenPanelResultListener = nullptr;
}
#endif

void WebPage::didChooseFilesForOpenPanel(const Vector<String>& files, const Vector<String>& replacementFiles)
{
    if (RefPtr activeOpenPanelResultListener = std::exchange(m_activeOpenPanelResultListener, nullptr))
        activeOpenPanelResultListener->didChooseFiles(files, replacementFiles);
}

void WebPage::didCancelForOpenPanel()
{
    if (RefPtr activeOpenPanelResultListener = std::exchange(m_activeOpenPanelResultListener, nullptr))
        activeOpenPanelResultListener->didCancelFileChoosing();
}

#if ENABLE(SANDBOX_EXTENSIONS)
void WebPage::extendSandboxForFilesFromOpenPanel(Vector<SandboxExtension::Handle>&& handles)
{
    bool result = SandboxExtension::consumePermanently(handles);
    if (!result) {
        // We have reports of cases where this fails for some unknown reason, <rdar://problem/10156710>.
        WTFLogAlways("WebPage::extendSandboxForFileFromOpenPanel(): Could not consume a sandbox extension");
    }
}
#endif

#if ENABLE(GEOLOCATION)
void WebPage::didReceiveGeolocationPermissionDecision(GeolocationIdentifier geolocationID, const String& authorizationToken)
{
    m_geolocationPermissionRequestManager->didReceiveGeolocationPermissionDecision(geolocationID, authorizationToken);
}
#endif

#if ENABLE(MEDIA_STREAM)

void WebPage::userMediaAccessWasGranted(UserMediaRequestIdentifier userMediaID, WebCore::CaptureDevice&& audioDevice, WebCore::CaptureDevice&& videoDevice, WebCore::MediaDeviceHashSalts&& mediaDeviceIdentifierHashSalts, Vector<SandboxExtension::Handle>&& handles, CompletionHandler<void()>&& completionHandler)
{
    SandboxExtension::consumePermanently(handles);

    m_userMediaPermissionRequestManager->userMediaAccessWasGranted(userMediaID, WTF::move(audioDevice), WTF::move(videoDevice), WTF::move(mediaDeviceIdentifierHashSalts), WTF::move(completionHandler));
}

void WebPage::userMediaAccessWasDenied(UserMediaRequestIdentifier userMediaID, uint64_t reason, String&& message, WebCore::MediaConstraintType invalidConstraint)
{
    m_userMediaPermissionRequestManager->userMediaAccessWasDenied(userMediaID, static_cast<MediaAccessDenialReason>(reason), WTF::move(message), invalidConstraint);
}

void WebPage::captureDevicesChanged()
{
    m_userMediaPermissionRequestManager->captureDevicesChanged();
}

void WebPage::voiceActivityDetected()
{
    protect(corePage())->voiceActivityDetected();
}

#if USE(GSTREAMER)
void WebPage::setOrientationForMediaCapture(uint64_t rotation)
{
    m_page->forEachDocument([&](auto& document) {
        document.orientationChanged(rotation);
    });
}

void WebPage::setMockCaptureDevicesInterrupted(bool isCameraInterrupted, bool isMicrophoneInterrupted)
{
    MockRealtimeMediaSourceCenter::setMockCaptureDevicesInterrupted(isCameraInterrupted, isMicrophoneInterrupted);
}

void WebPage::triggerMockCaptureConfigurationChange(bool forCamera, bool forMicrophone, bool forDisplay)
{
    MockRealtimeMediaSourceCenter::singleton().triggerMockCaptureConfigurationChange(forCamera, forMicrophone, forDisplay);
}
#endif // USE(GSTREAMER)

#endif // ENABLE(MEDIA_STREAM)

#if ENABLE(ENCRYPTED_MEDIA)
void WebPage::mediaKeySystemWasGranted(MediaKeySystemRequestIdentifier mediaKeySystemID, String&& mediaKeysHashSalt)
{
    m_mediaKeySystemPermissionRequestManager->mediaKeySystemWasGranted(mediaKeySystemID, WTF::move(mediaKeysHashSalt));
}

void WebPage::mediaKeySystemWasDenied(MediaKeySystemRequestIdentifier mediaKeySystemID, String&& message)
{
    m_mediaKeySystemPermissionRequestManager->mediaKeySystemWasDenied(mediaKeySystemID, WTF::move(message));
}
#endif

#if !PLATFORM(IOS_FAMILY)
void WebPage::advanceToNextMisspelling(bool startBeforeSelection)
{
    RefPtr frame = corePage()->focusController().focusedOrMainFrame();
    if (!frame)
        return;

    protect(frame->editor())->advanceToNextMisspelling(startBeforeSelection);
}
#endif

bool WebPage::hasRichlyEditableSelection() const
{
    RefPtr frame = corePage()->focusController().focusedOrMainFrame();
    if (!frame)
        return false;

    if (m_page->dragCaretController().isContentRichlyEditable())
        return true;

    return frame->selection().selection().isContentRichlyEditable();
}

void WebPage::changeSpellingToWord(const String& word)
{
    replaceSelectionWithText(protect(corePage()->focusController().focusedOrMainFrame()).get(), word);
}

void WebPage::unmarkAllMisspellings()
{
    for (RefPtr frame = m_page->mainFrame(); frame; frame = frame->tree().traverseNext()) {
        RefPtr localFrame = dynamicDowncast<LocalFrame>(*frame);
        if (!localFrame)
            continue;
        if (RefPtr document = localFrame->document())
            protect(document->markers())->removeMarkers(DocumentMarkerType::Spelling);
    }
}

void WebPage::unmarkAllBadGrammar()
{
    for (RefPtr frame = m_page->mainFrame(); frame; frame = frame->tree().traverseNext()) {
        RefPtr localFrame = dynamicDowncast<LocalFrame>(*frame);
        if (!localFrame)
            continue;
        if (RefPtr document = localFrame->document())
            protect(document->markers())->removeMarkers(DocumentMarkerType::Grammar);
    }
}

#if USE(APPKIT)
void WebPage::uppercaseWord(FrameIdentifier frameID)
{
    RefPtr frame = WebProcess::singleton().webFrame(frameID);
    if (!frame)
        return;

    RefPtr coreFrame = frame->coreLocalFrame();
    if (!coreFrame)
        return;

    protect(coreFrame->editor())->uppercaseWord();
}

void WebPage::lowercaseWord(FrameIdentifier frameID)
{
    RefPtr frame = WebProcess::singleton().webFrame(frameID);
    if (!frame)
        return;

    RefPtr coreFrame = frame->coreLocalFrame();
    if (!coreFrame)
        return;

    protect(coreFrame->editor())->lowercaseWord();
}

void WebPage::capitalizeWord(FrameIdentifier frameID)
{
    RefPtr frame = WebProcess::singleton().webFrame(frameID);
    if (!frame)
        return;

    RefPtr coreFrame = frame->coreLocalFrame();
    if (!coreFrame)
        return;


    protect(coreFrame->editor())->capitalizeWord();
}

void WebPage::convertToTraditionalChinese(FrameIdentifier frameID)
{
    RefPtr frame = WebProcess::singleton().webFrame(frameID);
    if (!frame)
        return;

    RefPtr coreFrame = frame->coreLocalFrame();
    if (!coreFrame)
        return;

    protect(coreFrame->editor())->convertToTraditionalChinese();
}

void WebPage::convertToSimplifiedChinese(FrameIdentifier frameID)
{
    RefPtr frame = WebProcess::singleton().webFrame(frameID);
    if (!frame)
        return;

    RefPtr coreFrame = frame->coreLocalFrame();
    if (!coreFrame)
        return;

    protect(coreFrame->editor())->convertToSimplifiedChinese();
}
#endif

#if !PLATFORM(COCOA)
void WebPage::setTextForActivePopupMenu(int32_t index)
{
    if (RefPtr menu = m_activePopupMenu)
        menu->setTextForIndex(index);
}
#endif

#if PLATFORM(GTK)
void WebPage::failedToShowPopupMenu()
{
    if (!m_activePopupMenu)
        return;

    m_activePopupMenu->client()->popupDidHide();
}
#endif

#if ENABLE(CONTEXT_MENUS)
void WebPage::didSelectItemFromActiveContextMenu(const WebContextMenuItemData& item)
{
    if (auto contextMenu = std::exchange(m_contextMenu, nullptr))
        contextMenu->itemSelected(item);
}
#endif

void WebPage::replaceSelectionWithText(LocalFrame* frame, const String& text)
{
    return protect(frame->editor())->replaceSelectionWithText(text, WebCore::Editor::SelectReplacement::Yes, WebCore::Editor::SmartReplace::No);
}

#if !PLATFORM(IOS_FAMILY)
void WebPage::clearSelection()
{
    RefPtr frame = corePage()->focusController().focusedOrMainFrame();
    if (!frame)
        return;

    protect(frame->selection())->clear();
}
#endif

void WebPage::restoreSelectionInFocusedEditableElement()
{
    RefPtr frame = corePage()->focusController().focusedOrMainFrame();
    if (!frame)
        return;

    if (!frame->selection().isNone())
        return;

    if (RefPtr document = frame->document()) {
        if (RefPtr element = document->focusedElement())
            element->updateFocusAppearance(SelectionRestorationMode::RestoreOrSelectAll, SelectionRevealMode::DoNotReveal);
    }
}

bool WebPage::mainFrameHasCustomContentProvider() const
{
    if (RefPtr frame = localMainFrame()) {
        auto* webFrameLoaderClient = dynamicDowncast<WebLocalFrameLoaderClient>(frame->loader().client());
        ASSERT(webFrameLoaderClient);
        return webFrameLoaderClient->frameHasCustomContentProvider();
    }

    return false;
}

void WebPage::updateMainFrameScrollOffsetPinning()
{
    RefPtr frameView = localMainFrameView();
    if (!frameView)
        return;

    auto pinnedState = frameView->edgePinnedState();
    if (pinnedState != m_cachedMainFramePinnedState) {
        send(Messages::WebPageProxy::DidChangeScrollOffsetPinningForMainFrame(pinnedState));
        m_cachedMainFramePinnedState = pinnedState;
    }
}

void WebPage::mainFrameDidLayout()
{
    ScriptDisallowedScope::InMainThread scriptDisallowedScope;

    unsigned pageCount = protect(corePage())->pageCountAssumingLayoutIsUpToDate();
    if (pageCount != m_cachedPageCount) {
        send(Messages::WebPageProxy::DidChangePageCount(pageCount));
        m_cachedPageCount = pageCount;
    }

#if PLATFORM(COCOA) || PLATFORM(GTK)
    if (RefPtr viewGestureGeometryCollector = m_viewGestureGeometryCollector)
        viewGestureGeometryCollector->mainFrameDidLayout();
#endif
#if PLATFORM(IOS_FAMILY)
    if (RefPtr frameView = localMainFrameView()) {
        IntSize newContentSize = frameView->contentsSize();
        LOG_WITH_STREAM(VisibleRects, stream << "WebPage " << m_identifier.toUInt64() << " mainFrameDidLayout setting content size to " << newContentSize);
        if (m_viewportConfiguration.setContentsSize(newContentSize))
            viewportConfigurationChanged();
    }
#endif
}

#if ENABLE(PDF_PLUGIN)

void WebPage::addPluginView(PluginView& pluginView)
{
    ASSERT(!m_pluginViews.contains(pluginView));
    m_pluginViews.add(pluginView);
}

void WebPage::removePluginView(PluginView& pluginView)
{
    ASSERT(m_pluginViews.contains(pluginView));
    m_pluginViews.remove(pluginView);
}

#endif // ENABLE(PDF_PLUGIN)

void WebPage::sendSetWindowFrame(const FloatRect& windowFrame)
{
#if PLATFORM(COCOA)
    m_hasCachedWindowFrame = false;
#endif
    send(Messages::WebPageProxy::SetWindowFrame(windowFrame));
}

#if PLATFORM(COCOA)

void WebPage::windowAndViewFramesChanged(const ViewWindowCoordinates& coordinates, CompletionHandler<void()>&& completionHandler)
{
    m_windowFrameInScreenCoordinates = coordinates.windowFrameInScreenCoordinates;
    m_windowFrameInUnflippedScreenCoordinates = coordinates.windowFrameInUnflippedScreenCoordinates;
    m_viewFrameInWindowCoordinates = coordinates.viewFrameInWindowCoordinates;

    m_accessibilityPosition = coordinates.accessibilityViewCoordinates;
#if ENABLE(ACCESSIBILITY_ISOLATED_TREE)
    cacheAXPosition(m_accessibilityPosition);
#endif

    m_hasCachedWindowFrame = !m_windowFrameInUnflippedScreenCoordinates.isEmpty();

    if (completionHandler)
        completionHandler();
}

void WebPage::updateMouseEventTargetAfterWindowAndViewFramesChanged(const DoublePoint& mousePositionInView, const DoublePoint& currentMouseGlobalPosition)
{
    RefPtr localMainFrame = m_mainFrame->coreLocalFrame();
    if (!localMainFrame)
        return;

    setLastKnownMousePosition(localMainFrame->frameID(), mousePositionInView, currentMouseGlobalPosition);
    localMainFrame->eventHandler().updateMouseEventTargetAfterLayoutIfNeeded();
}

#endif

void WebPage::setMainFrameIsScrollable(bool isScrollable)
{
    m_mainFrameIsScrollable = isScrollable;
    protect(drawingArea())->mainFrameScrollabilityChanged(isScrollable);

    if (RefPtr frameView = m_mainFrame->coreLocalFrame()->view()) {
        frameView->setCanHaveScrollbars(isScrollable);
        frameView->setProhibitsScrolling(!isScrollable);
    }
}

bool WebPage::windowIsFocused() const
{
    return m_page->focusController().isActive();
}

bool WebPage::windowAndWebPageAreFocused() const
{
    return isVisible() && m_page->focusController().isFocused() && m_page->focusController().isActive();
}

bool WebPage::dispatchMessage(IPC::Connection& connection, IPC::Decoder& decoder)
{
    if (decoder.messageReceiverName() == Messages::WebInspectorBackend::messageReceiverName()) {
        if (RefPtr inspector = this->inspector())
            inspector->didReceiveMessage(connection, decoder);
        return true;
    }

    if (decoder.messageReceiverName() == Messages::WebInspectorUI::messageReceiverName()) {
        if (RefPtr inspectorUI = this->inspectorUI())
            inspectorUI->didReceiveMessage(connection, decoder);
        return true;
    }

    if (decoder.messageReceiverName() == Messages::RemoteWebInspectorUI::messageReceiverName()) {
        if (RefPtr remoteInspectorUI = this->remoteInspectorUI())
            remoteInspectorUI->didReceiveMessage(connection, decoder);
        return true;
    }

#if ENABLE(FULLSCREEN_API)
    if (decoder.messageReceiverName() == Messages::WebFullScreenManager::messageReceiverName()) {
        protect(fullScreenManager())->didReceiveMessage(connection, decoder);
        return true;
    }
#endif
    return false;
}

#if ENABLE(ASYNC_SCROLLING)
ScrollingCoordinator* WebPage::scrollingCoordinator() const
{
    return protect(corePage())->scrollingCoordinator();
}

#endif

WebPage::SandboxExtensionTracker::~SandboxExtensionTracker()
{
    invalidate();
}

void WebPage::SandboxExtensionTracker::invalidate()
{
    m_pendingProvisionalSandboxExtension = nullptr;

    if (RefPtr extension = std::exchange(m_provisionalSandboxExtension, nullptr))
        extension->revoke();

    if (RefPtr extension = std::exchange(m_committedSandboxExtension, nullptr))
        extension->revoke();
}

void WebPage::SandboxExtensionTracker::willPerformLoadDragDestinationAction(RefPtr<SandboxExtension>&& pendingDropSandboxExtension)
{
    setPendingProvisionalSandboxExtension(WTF::move(pendingDropSandboxExtension));
}

void WebPage::SandboxExtensionTracker::beginLoad(SandboxExtension::Handle&& handle)
{
    setPendingProvisionalSandboxExtension(SandboxExtension::create(WTF::move(handle)));
}

void WebPage::SandboxExtensionTracker::beginReload(WebFrame* frame, SandboxExtension::Handle&& handle)
{
    ASSERT_UNUSED(frame, frame->isMainFrame());

    // Maintain existing provisional SandboxExtension in case of a reload, if the new handle is null. This is needed
    // because the UIProcess sends us a null handle if it already sent us a handle for this path in the past.
    if (auto sandboxExtension = SandboxExtension::create(WTF::move(handle)))
        setPendingProvisionalSandboxExtension(WTF::move(sandboxExtension));
}

void WebPage::SandboxExtensionTracker::setPendingProvisionalSandboxExtension(RefPtr<SandboxExtension>&& pendingProvisionalSandboxExtension)
{
    m_pendingProvisionalSandboxExtension = WTF::move(pendingProvisionalSandboxExtension);
}

bool WebPage::SandboxExtensionTracker::shouldReuseCommittedSandboxExtension(WebFrame* frame)
{
    ASSERT(frame->isMainFrame());

    FrameLoader& frameLoader = frame->coreLocalFrame()->loader();
    FrameLoadType frameLoadType = frameLoader.loadType();

    // If the page is being reloaded, it should reuse whatever extension is committed.
    if (isReload(frameLoadType))
        return true;

    if (m_pendingProvisionalSandboxExtension)
        return false;

    RefPtr documentLoader = frameLoader.documentLoader();
    RefPtr provisionalDocumentLoader = frameLoader.provisionalDocumentLoader();
    if (!documentLoader || !provisionalDocumentLoader)
        return false;

    if (documentLoader->url().protocolIsFile() && provisionalDocumentLoader->url().protocolIsFile())
        return true;

    return false;
}

void WebPage::SandboxExtensionTracker::didStartProvisionalLoad(WebFrame* frame)
{
    if (!frame->isMainFrame())
        return;

    // We should only reuse the commited sandbox extension if it is not null. It can be
    // null if the last load was for an error page.
    if (m_committedSandboxExtension && shouldReuseCommittedSandboxExtension(frame))
        m_pendingProvisionalSandboxExtension = m_committedSandboxExtension;

    ASSERT(!m_provisionalSandboxExtension);

    m_provisionalSandboxExtension = WTF::move(m_pendingProvisionalSandboxExtension);
    if (RefPtr extension = m_provisionalSandboxExtension)
        extension->consume();
}

void WebPage::SandboxExtensionTracker::didCommitProvisionalLoad(WebFrame* frame)
{
    if (!frame->isMainFrame())
        return;

    if (RefPtr committedSandboxExtension = m_committedSandboxExtension)
        committedSandboxExtension->revoke();

    m_committedSandboxExtension = WTF::move(m_provisionalSandboxExtension);

    // We can also have a non-null m_pendingProvisionalSandboxExtension if a new load is being started.
    // This extension is not cleared, because it does not pertain to the failed load, and will be needed.
}

void WebPage::SandboxExtensionTracker::didFailProvisionalLoad(WebFrame* frame)
{
    if (!frame->isMainFrame())
        return;

    if (RefPtr extension = std::exchange(m_provisionalSandboxExtension, nullptr))
        extension->revoke();

    // We can also have a non-null m_pendingProvisionalSandboxExtension if a new load is being started
    // (notably, if the current one fails because the new one cancels it). This extension is not cleared,
    // because it does not pertain to the failed load, and will be needed.
}

void WebPage::setCustomTextEncodingName(const String& encoding)
{
    if (RefPtr localMainFrame = this->localMainFrame())
        localMainFrame->loader().reloadWithOverrideEncoding(encoding);
}

void WebPage::didRemoveBackForwardItem(BackForwardFrameItemIdentifier frameItemID)
{
    WebBackForwardListProxy::removeItem(frameItemID);
}

#if PLATFORM(MAC)
void WebPage::setCaretAnimatorType(WebCore::CaretAnimatorType caretType)
{
    RefPtr frame = corePage()->focusController().focusedOrMainFrame();
    if (!frame)
        return;

    protect(frame->selection())->caretAnimatorInvalidated(caretType);
}

void WebPage::setCaretBlinkingSuspended(bool suspended)
{
    RefPtr frame = corePage()->focusController().focusedOrMainFrame();
    if (!frame)
        return;

    protect(frame->selection())->setCaretBlinkingSuspended(suspended);
}

#endif

void WebPage::setUseColorAppearance(bool useDarkAppearance, bool useElevatedUserInterfaceLevel)
{
    protect(corePage())->setUseColorAppearance(useDarkAppearance, useElevatedUserInterfaceLevel);

    if (RefPtr inspectorUI = m_inspectorUI)
        inspectorUI->effectiveAppearanceDidChange(useDarkAppearance ? WebCore::InspectorFrontendClient::Appearance::Dark : WebCore::InspectorFrontendClient::Appearance::Light);

#if ENABLE(PDF_PLUGIN)
    for (Ref pluginView : m_pluginViews)
        pluginView->effectiveAppearanceDidChange();
#endif
}

void WebPage::swipeAnimationDidStart()
{
    freezeLayerTree(LayerTreeFreezeReason::SwipeAnimation);
    corePage()->setIsInSwipeAnimation(true);
}

void WebPage::swipeAnimationDidEnd()
{
    unfreezeLayerTree(LayerTreeFreezeReason::SwipeAnimation);
    corePage()->setIsInSwipeAnimation(false);
}

void WebPage::beginPrinting(FrameIdentifier frameID, const PrintInfo& printInfo)
{
    RELEASE_LOG(Printing, "Begin printing.");

    PrintContextAccessScope scope { *this };

    RefPtr frame = WebProcess::singleton().webFrame(frameID);
    if (!frame)
        return;

    RefPtr coreFrame = frame->coreLocalFrame();
    if (!coreFrame)
        return;

#if PLATFORM(COCOA)
    if (pdfDocumentForPrintingFrame(coreFrame.get()))
        return;
#endif

    if (!m_printContext) {
        m_printContext = PrintContext::create(coreFrame.get());
        protect(corePage())->dispatchBeforePrintEvent();
    }
    RefPtr printContext = m_printContext;

    freezeLayerTree(LayerTreeFreezeReason::Printing);

    auto computedPageSize = printContext->computedPageSize(FloatSize(printInfo.availablePaperWidth, printInfo.availablePaperHeight), printInfo.margin);

    printContext->begin(computedPageSize.width(), computedPageSize.height());

    // PrintContext::begin() performed a synchronous layout which might have executed a
    // script that closed the WebPage, clearing m_printContext.
    // See <rdar://problem/49731211> for cases of this happening.
    printContext = m_printContext;
    if (!printContext) {
        unfreezeLayerTree(LayerTreeFreezeReason::Printing);
        return;
    }

    float fullPageHeight;
    printContext->computePageRects(FloatRect(0, 0, computedPageSize.width(), computedPageSize.height()), 0, 0, printInfo.pageSetupScaleFactor, fullPageHeight, true);

#if PLATFORM(GTK)
    if (!m_printOperation)
        m_printOperation = makeUnique<WebPrintOperationGtk>(printInfo);
#endif
}

void WebPage::endPrinting(CompletionHandler<void()>&& completionHandler)
{
    RELEASE_LOG(Printing, "End printing.");

    if (m_inActivePrintContextAccessScope) {
        m_shouldEndPrintingImmediately = true;
        completionHandler();
        return;
    }
    endPrintingImmediately();
    completionHandler();
}

void WebPage::endPrintingImmediately()
{
    RELEASE_ASSERT(!m_inActivePrintContextAccessScope);
    m_shouldEndPrintingImmediately = false;

    unfreezeLayerTree(LayerTreeFreezeReason::Printing);

    if (m_printContext) {
        m_printContext = nullptr;
        protect(corePage())->dispatchAfterPrintEvent();
    }
}

void WebPage::computePagesForPrinting(FrameIdentifier frameID, const PrintInfo& printInfo, CompletionHandler<void(const Vector<WebCore::IntRect>&, double, const WebCore::FloatBoxExtent&)>&& completionHandler)
{
    PrintContextAccessScope scope { *this };
    Vector<IntRect> resultPageRects;
    double resultTotalScaleFactorForPrinting = 1;
    auto computedPageMargin = printInfo.margin;
    computePagesForPrintingImpl(frameID, printInfo, resultPageRects, resultTotalScaleFactorForPrinting, computedPageMargin);
    completionHandler(resultPageRects, resultTotalScaleFactorForPrinting, computedPageMargin);
}

void WebPage::computePagesForPrintingImpl(FrameIdentifier frameID, const PrintInfo& printInfo, Vector<WebCore::IntRect>& resultPageRects, double& resultTotalScaleFactorForPrinting, FloatBoxExtent& computedPageMargin)
{
    ASSERT(resultPageRects.isEmpty());

    beginPrinting(frameID, printInfo);

    if (RefPtr printContext = m_printContext) {
        PrintContextAccessScope scope { *this };
        resultPageRects = printContext->pageRects();
        computedPageMargin = printContext->computedPageMargin(printInfo.margin);
        auto computedPageSize = printContext->computedPageSize(FloatSize(printInfo.availablePaperWidth, printInfo.availablePaperHeight), printInfo.margin);
        resultTotalScaleFactorForPrinting = printContext->computeAutomaticScaleFactor(computedPageSize) * printInfo.pageSetupScaleFactor;
    }
#if PLATFORM(COCOA)
    else
        computePagesForPrintingPDFDocument(frameID, printInfo, resultPageRects);
#endif // PLATFORM(COCOA)

    // If we're asked to print, we should actually print at least a blank page.
    if (resultPageRects.isEmpty())
        resultPageRects.append(IntRect(0, 0, 1, 1));
}

void WebPage::paintRemoteFrameContents(FrameIdentifier frameID, const IntRect& rect, GraphicsContext& context)
{
#if ENABLE(GPU_PROCESS)
    // Painting remote frames supported only for snapshot purposes.
    if (!m_remoteSnapshotState || m_remoteSnapshotState->recorder.ptr() != &context)
        return;
    sendWithAsyncReply(Messages::WebPageProxy::DrawFrameToSnapshot(frameID, rect, m_remoteSnapshotState->identifier), Ref { m_remoteSnapshotState->callback }->chain());
    m_remoteSnapshotState->recorder->drawSnapshotFrame(frameID);
#else
    UNUSED_PARAM(frameID);
    UNUSED_PARAM(rect);
    UNUSED_PARAM(context);
#endif
}

void WebPage::drawToSnapshot(const std::optional<FloatRect>& rect, bool allowTransparentBackground, RemoteSnapshotIdentifier snapshotIdentifier, CompletionHandler<void(std::optional<IntSize>)>&& completionHandler)
{
#if ENABLE(GPU_PROCESS)
    ASSERT(m_page->settings().remoteSnapshottingEnabled());

    RefPtr localMainFrame = this->localMainFrame();

    if (!localMainFrame) {
        completionHandler(std::nullopt);
        return;
    }

    Ref frameView = *localMainFrame->view();
    auto snapshotRect = IntRect { rect.value_or(FloatRect { { }, frameView->contentsSize() }) };
    auto snapshotSize = snapshotRect.size();

    Ref remoteRenderingBackend = ensureRemoteRenderingBackendProxy();
    m_remoteSnapshotState = {
        snapshotIdentifier,
        remoteRenderingBackend->createSnapshotRecorder(snapshotIdentifier),
        MainRunLoopSuccessCallbackAggregator::create([completionHandler = WTF::move(completionHandler), snapshotSize] (bool success) mutable {
            completionHandler(success ? std::optional<IntSize>(snapshotSize) : std::nullopt);
        })
    };

    drawMainFrameToPDF(*localMainFrame, m_remoteSnapshotState->recorder, snapshotRect, allowTransparentBackground);

    remoteRenderingBackend->sinkSnapshotRecorderIntoSnapshotFrame(WTF::move(m_remoteSnapshotState->recorder), localMainFrame->frameID(), Ref { m_remoteSnapshotState->callback }->chain());
    m_remoteSnapshotState = std::nullopt;
#else
    UNUSED_PARAM(rect);
    UNUSED_PARAM(allowTransparentBackground);
    UNUSED_PARAM(snapshotIdentifier);
    UNUSED_PARAM(completionHandler);
#endif
}

void WebPage::drawFrameToSnapshot(FrameIdentifier frameID, const IntRect& rect, RemoteSnapshotIdentifier snapshotIdentifier, CompletionHandler<void(bool)>&& completionHandler)
{
#if ENABLE(GPU_PROCESS)
    ASSERT(m_page->settings().siteIsolationEnabled());

    // FIXME: Error handling, so that the GPUP doesn't wait for something not coming.

    RefPtr webFrame = WebProcess::singleton().webFrame(frameID);
    if (!webFrame) {
        ASSERT_NOT_REACHED();
        completionHandler(false);
        return;
    }

    RefPtr coreLocalFrame = webFrame->coreLocalFrame();
    if (!coreLocalFrame) {
        ASSERT_NOT_REACHED();
        completionHandler(false);
        return;
    }

    RefPtr frameView = coreLocalFrame->view();
    if (!frameView) {
        completionHandler(false);
        return;
    }

    Ref remoteRenderingBackend = ensureRemoteRenderingBackendProxy();
    m_remoteSnapshotState = { snapshotIdentifier, remoteRenderingBackend->createSnapshotRecorder(snapshotIdentifier), MainRunLoopSuccessCallbackAggregator::create(WTF::move(completionHandler)) };

    LocalFrameView::SelectionInSnapshot shouldPaintSelection = LocalFrameView::IncludeSelection;
    LocalFrameView::CoordinateSpaceForSnapshot coordinateSpace = LocalFrameView::DocumentCoordinates;

    frameView->paintContentsForSnapshot(m_remoteSnapshotState->recorder, rect, shouldPaintSelection, coordinateSpace);

    remoteRenderingBackend->sinkSnapshotRecorderIntoSnapshotFrame(WTF::move(m_remoteSnapshotState->recorder), frameID, Ref { m_remoteSnapshotState->callback }->chain());

    m_remoteSnapshotState = std::nullopt;
#else
    UNUSED_PARAM(frameID);
    UNUSED_PARAM(rect);
    UNUSED_PARAM(snapshotIdentifier);
    UNUSED_PARAM(completionHandler);
#endif
}

void WebPage::drawMainFrameToPDF(LocalFrame& localMainFrame, GraphicsContext& context, IntRect& snapshotRect, bool allowTransparentBackground)
{
    Ref frameView = *localMainFrame.view();

    auto originalLayoutViewportOverrideRect = frameView->layoutViewportOverrideRect();
    frameView->setLayoutViewportOverrideRect(LayoutRect(snapshotRect));
    auto originalPaintBehavior = frameView->paintBehavior();

    frameView->setPaintBehavior(originalPaintBehavior | PaintBehavior::AnnotateLinks);

    auto originalColor = frameView->baseBackgroundColor();
    if (allowTransparentBackground) {
        frameView->setTransparent(true);
        frameView->setBaseBackgroundColor(Color::transparentBlack);
    }

    pdfSnapshotAtSize(localMainFrame, context, snapshotRect, { });

    if (allowTransparentBackground) {
        frameView->setTransparent(false);
        frameView->setBaseBackgroundColor(originalColor);
    }

    frameView->setLayoutViewportOverrideRect(originalLayoutViewportOverrideRect);
    frameView->setPaintBehavior(originalPaintBehavior);
}

void WebPage::pdfSnapshotAtSize(LocalFrame& localMainFrame, GraphicsContext& context, const IntRect& snapshotRect, SnapshotOptions options)
{
    Ref frameView = *localMainFrame.view();

    auto rect = snapshotRect;
    auto bitmapSize = rect.size();

    int64_t remainingHeight = bitmapSize.height();
    int64_t nextRectY = rect.y();
    while (remainingHeight > 0) {
        // PDFs have a per-page height limit of 200 inches at 72dpi.
        // We'll export one PDF page at a time, up to that maximum height.
        static const int64_t maxPageHeight = 72 * 200;
        bitmapSize.setHeight(std::min(remainingHeight, maxPageHeight));
        rect.setHeight(bitmapSize.height());
        rect.setY(nextRectY);

        context.beginPage(FloatRect { { }, bitmapSize });
        context.scale({ 1, -1 });
        context.translate(0, -bitmapSize.height());

        paintSnapshotAtSize(rect, bitmapSize, options, localMainFrame, frameView, context);

        context.endPage();

        nextRectY += bitmapSize.height();
        remainingHeight -= maxPageHeight;
    }
}

#if PLATFORM(GTK)
void WebPage::drawPagesForPrinting(FrameIdentifier frameID, const PrintInfo& printInfo, CompletionHandler<void(std::optional<SharedMemory::Handle>&&, WebCore::ResourceError&&)>&& completionHandler)
{
    beginPrinting(frameID, printInfo);
    if (RefPtr printContext = m_printContext; printContext && m_printOperation) {
        m_printOperation->startPrint(printContext.get(), [this, protectedThis = Ref { *this }, completionHandler = WTF::move(completionHandler)] (RefPtr<WebCore::FragmentedSharedBuffer>&& data, WebCore::ResourceError&& error) mutable {
            m_printOperation = nullptr;
            std::optional<SharedMemory::Handle> ipcHandle;
            if (error.isNull()) {
                auto sharedMemory = SharedMemory::copyBuffer(*data);
                ipcHandle = sharedMemory->createHandle(SharedMemory::Protection::ReadOnly);
            }
            completionHandler(WTF::move(ipcHandle), WTF::move(error));
        });
        return;
    }
    completionHandler(std::nullopt, { });
}
#endif

void WebPage::addResourceRequest(WebCore::ResourceLoaderIdentifier identifier, const WebCore::ResourceRequest& request, const DocumentLoader* loader, LocalFrame* frame)
{
    bool isHTTPRequest = request.url().protocolIsInHTTPFamily();

    // Ignore main resource loads here, since they can start in one process and end up in another.
    // See 283102@main for an explanation for how we handle main resource loads. We also ignore
    // very low priority loads like ping and beacon requests to match previous PLT heuristics.
    // We consider file requests as part of the PLT network heuristic for ease of API testing.
    if (frame && request.requester() != ResourceRequestRequester::Main && request.priority() != WebCore::ResourceLoadPriority::VeryLow && (isHTTPRequest || request.url().protocolIsFile())) {
        auto frameID = frame->frameID();
        auto& identifiers = m_networkResourceRequestIdentifiersForPageLoadTiming.ensure(frameID, [] {
            return HashSet<WebCore::ResourceLoaderIdentifier> { };
        }).iterator->value;
        if (identifiers.isEmpty())
            send(Messages::WebPageProxy::StartNetworkRequestsForPageLoadTiming(frameID));
        identifiers.add(identifier);
    }

    if (!isHTTPRequest)
        return;

    if (m_mainFrameProgressCompleted && !UserGestureIndicator::processingUserGesture())
        return;

    ASSERT(!m_trackedNetworkResourceRequestIdentifiers.contains(identifier));
    bool wasEmpty = m_trackedNetworkResourceRequestIdentifiers.isEmpty();
    m_trackedNetworkResourceRequestIdentifiers.add(identifier);
    if (wasEmpty)
        send(Messages::WebPageProxy::SetNetworkRequestsInProgress(true));
}

void WebPage::removeResourceRequest(WebCore::ResourceLoaderIdentifier identifier, LocalFrame* frame)
{
    if (frame) {
        auto frameID = frame->frameID();
        if (auto it = m_networkResourceRequestIdentifiersForPageLoadTiming.find(frameID); it != m_networkResourceRequestIdentifiersForPageLoadTiming.end()) {
            if (it->value.remove(identifier) && it->value.isEmpty())
                send(Messages::WebPageProxy::EndNetworkRequestsForPageLoadTiming(frameID, WallTime::now()));
        }
    }

    if (!m_trackedNetworkResourceRequestIdentifiers.remove(identifier))
        return;

    if (m_trackedNetworkResourceRequestIdentifiers.isEmpty())
        send(Messages::WebPageProxy::SetNetworkRequestsInProgress(false));
}

void WebPage::setMediaVolume(float volume)
{
    protect(corePage())->setMediaVolume(volume);
}

void WebPage::setMuted(MediaProducerMutedStateFlags state, CompletionHandler<void()>&& completionHandler)
{
    protect(corePage())->setMuted(state);
    completionHandler();
}

void WebPage::stopMediaCapture(MediaProducerMediaCaptureKind kind, CompletionHandler<void()>&& completionHandler)
{
#if ENABLE(MEDIA_STREAM)
    protect(corePage())->stopMediaCapture(kind);
#endif
    completionHandler();
}

void WebPage::processWillSuspend()
{
    if (RefPtr manager = mediaSessionManagerIfExists())
        manager->processWillSuspend();
}

void WebPage::processDidResume()
{
    if (RefPtr manager = mediaSessionManagerIfExists())
        manager->processDidResume();
}

void WebPage::didReceiveRemoteCommand(PlatformMediaSession::RemoteControlCommandType type, const PlatformMediaSession::RemoteCommandArgument& argument)
{
    if (RefPtr manager = mediaSessionManagerIfExists())
        manager->processDidReceiveRemoteControlCommand(type, argument);
}

void WebPage::setMayStartMediaWhenInWindow(bool mayStartMedia)
{
    if (mayStartMedia == m_mayStartMediaWhenInWindow)
        return;

    m_mayStartMediaWhenInWindow = mayStartMedia;
    if (m_mayStartMediaWhenInWindow && m_page->isInWindow())
        m_setCanStartMediaTimer.startOneShot(0_s);
}

void WebPage::runModal()
{
    if (m_isClosed)
        return;
    if (m_isRunningModal)
        return;

    m_isRunningModal = true;
    send(Messages::WebPageProxy::RunModal());
#if ASSERT_ENABLED
    Ref<WebPage> protector(*this);
#endif
    RunLoop::run();
}

bool WebPage::canHandleRequest(const WebCore::ResourceRequest& request)
{
    if (LegacySchemeRegistry::shouldLoadURLSchemeAsEmptyDocument(request.url().protocol()))
        return true;

    if (request.url().protocolIsBlob())
        return true;

    return platformCanHandleRequest(request);
}

void WebPage::setCompositionForTesting(const String& compositionString, uint64_t from, uint64_t length, bool suppressUnderline, const Vector<CompositionHighlight>& highlights, const HashMap<String, Vector<WebCore::CharacterRange>>& annotations)
{
    RefPtr frame = corePage()->focusController().focusedOrMainFrame();
    if (!frame)
        return;

    Ref editor = frame->editor();
    if (!editor->canEdit())
        return;

    Vector<CompositionUnderline> underlines;
    if (!suppressUnderline)
        underlines.append(CompositionUnderline(0, compositionString.length(), CompositionUnderlineColor::TextColor, Color(Color::black), false));

    editor->setComposition(compositionString, underlines, highlights, annotations, from, from + length);
}

bool WebPage::hasCompositionForTesting()
{
    RefPtr frame = corePage()->focusController().focusedOrMainFrame();
    if (!frame)
        return false;

    return frame->editor().hasComposition();
}

void WebPage::confirmCompositionForTesting(const String& compositionString)
{
    RefPtr frame = corePage()->focusController().focusedOrMainFrame();
    if (!frame)
        return;

    Ref editor = frame->editor();
    if (!editor->canEdit())
        return;

    if (compositionString.isNull())
        editor->confirmComposition();
    editor->confirmComposition(compositionString);
}

void WebPage::wheelEventHandlersChanged(bool hasHandlers)
{
    if (m_hasWheelEventHandlers == hasHandlers)
        return;

    m_hasWheelEventHandlers = hasHandlers;
    recomputeShortCircuitHorizontalWheelEventsState();
}

static bool hasEnabledHorizontalScrollbar(ScrollableArea* scrollableArea)
{
    RefPtr scrollbar = scrollableArea->horizontalScrollbar();
    return scrollbar && scrollbar->enabled();
}

bool WebPage::pageContainsAnyHorizontalScrollbars() const
{
    RefPtr page = m_page;
    if (!page)
        return false;

    for (RefPtr frame = page->mainFrame(); frame; frame = frame->tree().traverseNext()) {
        RefPtr localFrame = dynamicDowncast<LocalFrame>(*frame);
        if (!localFrame)
            continue;

        RefPtr frameView = localFrame->view();
        if (!frameView)
            continue;

        if (hasEnabledHorizontalScrollbar(frameView.get()))
            return true;

        auto scrollableAreas = frameView->scrollableAreas();
        if (!scrollableAreas)
            continue;

        for (CheckedRef scrollableArea : *scrollableAreas) {
            if (!scrollableArea->scrollbarsCanBeActive())
                continue;

            if (hasEnabledHorizontalScrollbar(scrollableArea.ptr()))
                return true;
        }
    }

    return false;
}

void WebPage::recomputeShortCircuitHorizontalWheelEventsState()
{
    bool canShortCircuitHorizontalWheelEvents = !m_hasWheelEventHandlers;

    if (canShortCircuitHorizontalWheelEvents) {
        // Check if we have any horizontal scroll bars on the page.
        if (pageContainsAnyHorizontalScrollbars())
            canShortCircuitHorizontalWheelEvents = false;
    }

    if (m_canShortCircuitHorizontalWheelEvents == canShortCircuitHorizontalWheelEvents)
        return;

    m_canShortCircuitHorizontalWheelEvents = canShortCircuitHorizontalWheelEvents;
    send(Messages::WebPageProxy::SetCanShortCircuitHorizontalWheelEvents(m_canShortCircuitHorizontalWheelEvents));
}

Frame* WebPage::mainFrame() const
{
    return m_page ? &m_page->mainFrame() : nullptr;
}

RefPtr<WebCore::LocalFrame> WebPage::localMainFrame() const
{
    if (auto* page = m_page.get())
        return page->localMainFrame();
    return nullptr;
}

RefPtr<WebCore::Document> WebPage::localTopDocument() const
{
    if (RefPtr page = m_page)
        return page->localTopDocument();
    return nullptr;
}

FrameView* WebPage::mainFrameView() const
{
    if (RefPtr frame = mainFrame())
        return frame->virtualView();
    return nullptr;
}

LocalFrameView* WebPage::localMainFrameView() const
{
    return dynamicDowncast<LocalFrameView>(mainFrameView());
}

bool WebPage::shouldUseCustomContentProviderForResponse(const ResourceResponse& response)
{
    auto& mimeType = response.mimeType();
    if (mimeType.isNull())
        return false;

    return m_mimeTypesWithCustomContentProviders.contains(mimeType);
}

#if PLATFORM(GTK) || PLATFORM(WPE)

static RefPtr<LocalFrame> targetFrameForEditing(WebPage& page)
{
    RefPtr targetFrame = page.corePage()->focusController().focusedOrMainFrame();
    if (!targetFrame)
        return nullptr;

    Editor& editor = targetFrame->editor();
    if (!editor.canEdit())
        return nullptr;

    if (editor.hasComposition()) {
        // We should verify the parent node of this IME composition node are
        // editable because JavaScript may delete a parent node of the composition
        // node. In this case, WebKit crashes while deleting texts from the parent
        // node, which doesn't exist any longer.
        if (auto range = editor.compositionRange()) {
            if (!range->startContainer().isContentEditable())
                return nullptr;
        }
    }
    return targetFrame;
}

void WebPage::cancelComposition(const String& compositionString)
{
    if (RefPtr targetFrame = targetFrameForEditing(*this))
        protect(targetFrame->editor())->confirmComposition(compositionString);
}

void WebPage::deleteSurrounding(int64_t offset, unsigned characterCount)
{
    RefPtr targetFrame = targetFrameForEditing(*this);
    if (!targetFrame)
        return;

    auto& selection = targetFrame->selection().selection();
    if (selection.isNone())
        return;

    auto selectionStart = selection.visibleStart();
    auto surroundingRange = makeSimpleRange(startOfEditableContent(selectionStart), selectionStart);
    if (!surroundingRange)
        return;

    Ref rootNode = surroundingRange->start.container->treeScope().rootNode();
    auto characterRange = WebCore::CharacterRange(WebCore::characterCount(*surroundingRange) + offset, characterCount);
    auto selectionRange = resolveCharacterRange(makeRangeSelectingNodeContents(rootNode), characterRange);

    targetFrame->editor().setIgnoreSelectionChanges(true);
    protect(targetFrame->selection())->setSelection(VisibleSelection(selectionRange));
    targetFrame->editor().deleteSelectionWithSmartDelete(false);
    targetFrame->editor().setIgnoreSelectionChanges(false);
    sendEditorStateUpdate();
}

#endif

void WebPage::didApplyStyle()
{
    sendEditorStateUpdate();
}

void WebPage::didChangeContents()
{
    sendEditorStateUpdate();
}

void WebPage::didScrollSelection()
{
    didChangeSelectionOrOverflowScrollPosition();
}

void WebPage::didChangeSelection(LocalFrame& frame)
{
    didChangeSelectionOrOverflowScrollPosition();

    if (m_userIsInteracting && frame.selection().isRange())
        m_userInteractionsSincePageTransition.add(UserInteractionFlag::SelectedRange);

#if ENABLE(WRITING_TOOLS)
    protect(corePage())->updateStateForSelectedSuggestionIfNeeded();
#endif

#if PLATFORM(IOS_FAMILY)
    resetLastSelectedReplacementRangeIfNeeded();

    if (!std::exchange(m_sendAutocorrectionContextAfterFocusingElement, false))
        return;

    callOnMainRunLoop([protectedThis = Ref { *this }, frame = Ref { frame }] {
        if (!frame->document() || !frame->document()->hasLivingRenderTree() || frame->selection().isNone()) [[unlikely]]
            return;

        protectedThis->preemptivelySendAutocorrectionContext();
    });
#endif // PLATFORM(IOS_FAMILY)
}

void WebPage::didChangeSelectionOrOverflowScrollPosition()
{
    RefPtr frame = corePage()->focusController().focusedOrMainFrame();
    if (!frame)
        return;

    // The act of getting Dictionary Popup info can make selection changes that we should not propagate to the UIProcess.
    // Specifically, if there is a caret selection, it will change to a range selection of the word around the caret. And
    // then it will change back.
    if (frame->editor().isGettingDictionaryPopupInfo())
        return;

    // Similarly, we don't want to propagate changes to the web process when inserting text asynchronously, since we will
    // end up with a range selection very briefly right before inserting the text.
    if (m_isSelectingTextWhileInsertingAsynchronously)
        return;

#if HAVE(TOUCH_BAR)
    bool hasPreviouslyFocusedDueToUserInteraction = m_userInteractionsSincePageTransition.contains(UserInteractionFlag::FocusedElement);
    if (m_userIsInteracting && m_focusedElement)
        m_userInteractionsSincePageTransition.add(UserInteractionFlag::FocusedElement);

    if (!hasPreviouslyFocusedDueToUserInteraction && m_userInteractionsSincePageTransition.contains(UserInteractionFlag::FocusedElement)) {
        RefPtr document = frame->document();
        if (document->quirks().isTouchBarUpdateSuppressedForHiddenContentEditable()) {
            m_isTouchBarUpdateSuppressedForHiddenContentEditable = true;
            send(Messages::WebPageProxy::SetIsTouchBarUpdateSuppressedForHiddenContentEditable(m_isTouchBarUpdateSuppressedForHiddenContentEditable));
        }

        if (document->quirks().isNeverRichlyEditableForTouchBar()) {
            m_isNeverRichlyEditableForTouchBar = true;
            send(Messages::WebPageProxy::SetIsNeverRichlyEditableForTouchBar(m_isNeverRichlyEditableForTouchBar));
        }

        send(Messages::WebPageProxy::SetHasFocusedElementWithUserInteraction(true));
    }

    // Abandon the current inline input session if selection changed for any other reason but an input method direct action.
    // FIXME: This logic should be in WebCore.
    // FIXME: Many changes that affect composition node do not go through didChangeSelection(). We need to do something when DOM manipulation affects the composition, because otherwise input method's idea about it will be different from Editor's.
    // FIXME: We can't cancel composition when selection changes to NoSelection, but we probably should.
    Ref editor = frame->editor();
    if (editor->hasComposition() && !frame->editor().ignoreSelectionChanges() && !frame->selection().isNone()) {
        editor->cancelComposition();
        if (RefPtr document = frame->document())
            discardedComposition(*document);
        return;
    }
#endif // HAVE(TOUCH_BAR)

    scheduleFullEditorStateUpdate();
}

void WebPage::resetFocusedElementForFrame(WebFrame* frame)
{
#if PLATFORM(GTK) || PLATFORM(WPE)
    if (frame->isMainFrame() || corePage()->focusController().focusedOrMainFrame() == frame->coreLocalFrame())
        m_page->editorClient().setInputMethodState(nullptr);
#endif

    if (!m_focusedElement)
        return;

    if (frame->isMainFrame() || m_focusedElement->document().frame() == frame->coreLocalFrame()) {
#if PLATFORM(IOS_FAMILY)
        m_sendAutocorrectionContextAfterFocusingElement = false;
        send(Messages::WebPageProxy::ElementDidBlur());
#elif PLATFORM(MAC)
        send(Messages::WebPageProxy::SetEditableElementIsFocused(false));
#endif
        m_focusedElement = nullptr;
    }
}

void WebPage::elementDidRefocus(Element& element, const FocusOptions& options)
{
    elementDidFocus(element, options);

    if (m_userIsInteracting)
        scheduleFullEditorStateUpdate();
}

bool WebPage::shouldDispatchUpdateAfterFocusingElement(const Element& element) const
{
    if (m_focusedElement == &element || m_recentlyBlurredElement == &element) {
#if PLATFORM(IOS_FAMILY)
        return !m_isShowingInputViewForFocusedElement;
#else
        return false;
#endif
    }
    return true;
}

static bool isTextFormControlOrEditableContent(const WebCore::Element& element)
{
    return is<HTMLTextFormControlElement>(element) || element.hasEditableStyle();
}

#if PLATFORM(IOS_FAMILY) && ENABLE(FULLSCREEN_API)
static bool shouldExitFullscreenAfterFocusingElement(const WebCore::Element& element)
{
    if (!protect(protect(element.document())->fullscreen())->isFullscreen())
        return false;

    if (RefPtr input = dynamicDowncast<const HTMLInputElement>(element))
        return input->isTextField();

    return is<HTMLTextAreaElement>(element) || element.hasEditableStyle();
}
#endif

#if PLATFORM(DRIFTSTACK)
// #6 (founder keyboard auto-show, W3019) — emit a dedicated stderr focus token when an
// editable element gains/loses focus, so the harness stamps inputFocused on the page_state
// frame and the GUI auto-shows/hides the iOS keyboard (this is the exact point WebKit
// decides to raise/dismiss the on-screen keyboard). Gated by DRIFTSTACK_NAV_PAGESTATE
// (default-OFF → byte-identical). stderr only — never the page/JS surface — fingerprint-safe.
static void driftstackEmitInputFocus(bool focused)
{
    static const bool enabled = [] {
        const char* e = getenv("DRIFTSTACK_NAV_PAGESTATE");
        return e && e[0] == '1';
    }();
    if (!enabled)
        return;
    fprintf(stderr, "DRIFTSTACK_INPUT_FOCUS {\"focused\":%s}\n", focused ? "true" : "false");
    fflush(stderr);
}
#endif

void WebPage::elementDidFocus(Element& element, const FocusOptions& options)
{
#if PLATFORM(IOS_FAMILY)
    m_updateFocusedElementInformationTimer.stop();
#endif

    if (!shouldDispatchUpdateAfterFocusingElement(element)) {
        updateInputContextAfterBlurringAndRefocusingElementIfNeeded(element);
        m_focusedElement = element;
        m_recentlyBlurredElement = nullptr;
        return;
    }

    if (is<HTMLSelectElement>(element) || isTextFormControlOrEditableContent(element)) {
#if PLATFORM(IOS_FAMILY)
        bool isChangingFocusedElement = m_focusedElement != &element;
#endif
        m_focusedElement = element;
        m_hasPendingInputContextUpdateAfterBlurringAndRefocusingElement = false;
#if PLATFORM(DRIFTSTACK)
        // #6 keyboard: an editable text field gained focus → the GUI raises the iOS keyboard.
        // Exclude <select> (this block also handles it, but it raises a picker, not a keyboard).
        if (isTextFormControlOrEditableContent(element))
            driftstackEmitInputFocus(true);
#endif

#if PLATFORM(IOS_FAMILY)

#if ENABLE(FULLSCREEN_API)
    if (shouldExitFullscreenAfterFocusingElement(element))
        protect(protect(element.document())->fullscreen())->fullyExitFullscreen();
#endif
        if (isChangingFocusedElement && (m_userIsInteracting || m_keyboardIsAttached))
            m_sendAutocorrectionContextAfterFocusingElement = true;

        auto information = focusedElementInformation();
        if (!information)
            return;

        RefPtr<API::Object> userData;

        m_formClient->willBeginInputSession(this, &element, protect(WebFrame::fromCoreFrame(*protect(element.document().frame()))).get(), m_userIsInteracting, userData);

        if (!userData) {
            auto userInfo = element.userInfo();
            if (!userInfo.isNull()) {
                if (auto data = JSON::Value::parseJSON(element.userInfo()))
                    userData = userDataFromJSONData(*data);
            }
        }

        information->preventScroll = options.preventScroll;
        send(Messages::WebPageProxy::ElementDidFocus(information.value(), m_userIsInteracting, m_recentlyBlurredElement, m_lastActivityStateChanges, UserData(WebProcess::singleton().transformObjectsToHandles(userData.get()).get())));
#elif PLATFORM(MAC)
        // FIXME: This can be unified with the iOS code above by bringing ElementDidFocus to macOS.
        // This also doesn't take other noneditable controls into account, such as input type color.
        send(Messages::WebPageProxy::SetEditableElementIsFocused(!element.hasTagName(WebCore::HTMLNames::selectTag)));
#endif
        m_recentlyBlurredElement = nullptr;
    }
}

void WebPage::elementDidBlur(WebCore::Element& element)
{
    if (m_focusedElement == &element) {
#if PLATFORM(DRIFTSTACK)
        // #6 keyboard: the focused editable element blurred → the GUI dismisses the keyboard.
        driftstackEmitInputFocus(false);
#endif
        m_recentlyBlurredElement = WTF::move(m_focusedElement);
        callOnMainRunLoop([protectedThis = Ref { *this }] {
            if (protectedThis->m_recentlyBlurredElement) {
#if PLATFORM(IOS_FAMILY)
                protectedThis->send(Messages::WebPageProxy::ElementDidBlur());
#elif PLATFORM(MAC)
                protectedThis->send(Messages::WebPageProxy::SetEditableElementIsFocused(false));
#endif
            }
            protectedThis->m_recentlyBlurredElement = nullptr;
        });
        m_hasPendingInputContextUpdateAfterBlurringAndRefocusingElement = false;
#if PLATFORM(IOS_FAMILY)
        m_sendAutocorrectionContextAfterFocusingElement = false;
#endif
    }
}

void WebPage::focusedElementDidChangeInputMode(WebCore::Element& element, WebCore::InputMode mode)
{
    if (m_focusedElement != &element)
        return;

#if PLATFORM(IOS_FAMILY)
    ASSERT(is<HTMLElement>(element));
    ASSERT(downcast<HTMLElement>(element).canonicalInputMode() == mode);

    if (!isTextFormControlOrEditableContent(element))
        return;

    send(Messages::WebPageProxy::FocusedElementDidChangeInputMode(mode));
#else
    UNUSED_PARAM(mode);
#endif
}

void WebPage::focusedSelectElementDidChangeOptions(const WebCore::HTMLSelectElement& element)
{
#if PLATFORM(IOS_FAMILY)
    if (m_focusedElement != &element)
        return;

    m_updateFocusedElementInformationTimer.restart();
#else
    UNUSED_PARAM(element);
#endif
}

void WebPage::didUpdateComposition()
{
    sendEditorStateUpdate();
}

void WebPage::didEndUserTriggeredSelectionChanges()
{
    RefPtr frame = corePage()->focusController().focusedOrMainFrame();
    if (!frame)
        return;

    if (!frame->editor().ignoreSelectionChanges())
        sendEditorStateUpdate();
}

void WebPage::discardedComposition(const Document& document)
{
    send(Messages::WebPageProxy::CompositionWasCanceled());
    if (!document.hasLivingRenderTree())
        return;

    sendEditorStateUpdate();
}

void WebPage::canceledComposition()
{
    send(Messages::WebPageProxy::CompositionWasCanceled());
    sendEditorStateUpdate();
}

void WebPage::navigateServiceWorkerClient(ScriptExecutionContextIdentifier documentIdentifier, const URL& url, CompletionHandler<void(WebCore::ScheduleLocationChangeResult)>&& callback)
{
    RefPtr document = Document::allDocumentsMap().get(documentIdentifier);
    if (!document) {
        callback(WebCore::ScheduleLocationChangeResult::Stopped);
        return;
    }
    document->navigateFromServiceWorker(url, WTF::move(callback));
}

void WebPage::setAlwaysShowsHorizontalScroller(bool alwaysShowsHorizontalScroller)
{
    if (alwaysShowsHorizontalScroller == m_alwaysShowsHorizontalScroller)
        return;

    m_alwaysShowsHorizontalScroller = alwaysShowsHorizontalScroller;

    RefPtr view = protect(protect(corePage())->mainFrame())->virtualView();
    if (!alwaysShowsHorizontalScroller)
        view->setHorizontalScrollbarLock(false);
    view->setHorizontalScrollbarMode(alwaysShowsHorizontalScroller ? ScrollbarMode::AlwaysOn : m_mainFrameIsScrollable ? ScrollbarMode::Auto : ScrollbarMode::AlwaysOff, alwaysShowsHorizontalScroller || !m_mainFrameIsScrollable);
}

void WebPage::setAlwaysShowsVerticalScroller(bool alwaysShowsVerticalScroller)
{
    if (alwaysShowsVerticalScroller == m_alwaysShowsVerticalScroller)
        return;

    m_alwaysShowsVerticalScroller = alwaysShowsVerticalScroller;

    RefPtr view = protect(protect(corePage())->mainFrame())->virtualView();
    if (!alwaysShowsVerticalScroller)
        view->setVerticalScrollbarLock(false);
    view->setVerticalScrollbarMode(alwaysShowsVerticalScroller ? ScrollbarMode::AlwaysOn : m_mainFrameIsScrollable ? ScrollbarMode::Auto : ScrollbarMode::AlwaysOff, alwaysShowsVerticalScroller || !m_mainFrameIsScrollable);
}

void WebPage::setMinimumSizeForAutoLayout(const IntSize& size)
{
    if (m_minimumSizeForAutoLayout == size)
        return;

    m_minimumSizeForAutoLayout = size;

    RefPtr localMainFrame = dynamicDowncast<WebCore::LocalFrame>(corePage()->mainFrame());
    if (!localMainFrame)
        return;

    RefPtr view = localMainFrame->view();
    if (size.width() <= 0) {
        view->enableFixedWidthAutoSizeMode(false, { });
        return;
    }

    view->enableFixedWidthAutoSizeMode(true, { size.width(), std::max(size.height(), 1) });
}

void WebPage::setSizeToContentAutoSizeMaximumSize(const IntSize& size)
{
    if (m_sizeToContentAutoSizeMaximumSize == size)
        return;

    m_sizeToContentAutoSizeMaximumSize = size;

    RefPtr localMainFrame = dynamicDowncast<WebCore::LocalFrame>(corePage()->mainFrame());
    if (!localMainFrame)
        return;

    RefPtr view = localMainFrame->view();
    if (size.width() <= 0 || size.height() <= 0) {
        view->enableSizeToContentAutoSizeMode(false, { });
        return;
    }

    view->enableSizeToContentAutoSizeMode(true, size);
}

void WebPage::setAutoSizingShouldExpandToViewHeight(bool shouldExpand)
{
    if (m_autoSizingShouldExpandToViewHeight == shouldExpand)
        return;

    m_autoSizingShouldExpandToViewHeight = shouldExpand;

    if (RefPtr localMainFrame = dynamicDowncast<WebCore::LocalFrame>(corePage()->mainFrame()))
        protect(localMainFrame->view())->setAutoSizeFixedMinimumHeight(shouldExpand ? m_viewSize.height() : 0);
}

void WebPage::setViewportSizeForCSSViewportUnits(std::optional<WebCore::FloatSize> viewportSize)
{
    if (m_viewportSizeForCSSViewportUnits == viewportSize)
        return;

    m_viewportSizeForCSSViewportUnits = viewportSize;
    if (m_viewportSizeForCSSViewportUnits) {
        if (RefPtr localMainFrame = dynamicDowncast<WebCore::LocalFrame>(corePage()->mainFrame()))
            protect(localMainFrame->view())->setSizeForCSSDefaultViewportUnits(*m_viewportSizeForCSSViewportUnits);
    }
}

bool WebPage::isIOSurfaceLosslessCompressionEnabled() const
{
    return m_page->settings().iOSurfaceLosslessCompressionEnabled();
}

bool WebPage::isSmartInsertDeleteEnabled()
{
    return m_page->settings().smartInsertDeleteEnabled();
}

void WebPage::setSmartInsertDeleteEnabled(bool enabled)
{
    if (m_page->settings().smartInsertDeleteEnabled() != enabled) {
        m_page->settings().setSmartInsertDeleteEnabled(enabled);
        setSelectTrailingWhitespaceEnabled(!enabled);
    }
}

bool WebPage::isSelectTrailingWhitespaceEnabled() const
{
    return m_page->settings().selectTrailingWhitespaceEnabled();
}

void WebPage::setSelectTrailingWhitespaceEnabled(bool enabled)
{
    if (m_page->settings().selectTrailingWhitespaceEnabled() != enabled) {
        m_page->settings().setSelectTrailingWhitespaceEnabled(enabled);
        setSmartInsertDeleteEnabled(!enabled);
    }
}

bool WebPage::canShowResponse(const WebCore::ResourceResponse& response) const
{
    return canShowMIMEType(response.mimeType(), [&](auto& mimeType, auto allowedPlugins) {
        return protect(corePage())->pluginData().supportsWebVisibleMimeTypeForURL(mimeType, allowedPlugins, response.url());
    });
}

bool WebPage::canShowMIMEType(const String& mimeType) const
{
    return canShowMIMEType(mimeType, [&](auto& mimeType, auto allowedPlugins) {
        return protect(corePage())->pluginData().supportsWebVisibleMimeType(mimeType, allowedPlugins);
    });
}

bool WebPage::canShowMIMEType(const String& mimeType, NOESCAPE const Function<bool(const String&, PluginData::AllowedPluginTypes)>& pluginsSupport) const
{
    if (MIMETypeRegistry::canShowMIMEType(mimeType))
        return true;

    if (!mimeType.isNull() && m_mimeTypesWithCustomContentProviders.contains(mimeType))
        return true;

    // We can use application plugins even if plugins aren't enabled.
    if (pluginsSupport(mimeType, PluginData::OnlyApplicationPlugins))
        return true;

#if ENABLE(PDFJS)
    if (m_page->settings().pdfJSViewerEnabled() && MIMETypeRegistry::isPDFMIMEType(mimeType))
        return true;
#endif

    return false;
}

void WebPage::addTextCheckingRequest(TextCheckerRequestID requestID, Ref<TextCheckingRequest>&& request)
{
    m_pendingTextCheckingRequestMap.add(requestID, WTF::move(request));
}

void WebPage::didFinishCheckingText(TextCheckerRequestID requestID, const Vector<TextCheckingResult>& result)
{
    RefPtr<TextCheckingRequest> request = m_pendingTextCheckingRequestMap.take(requestID);
    if (!request)
        return;

    request->didSucceed(result);
}

void WebPage::didCancelCheckingText(TextCheckerRequestID requestID)
{
    RefPtr<TextCheckingRequest> request = m_pendingTextCheckingRequestMap.take(requestID);
    if (!request)
        return;

    request->didCancel();
}

void WebPage::willReplaceMultipartContent(const WebFrame& frame)
{
#if PLATFORM(IOS_FAMILY)
    if (!frame.isMainFrame())
        return;

    m_previousExposedContentRect = protect(drawingArea())->exposedContentRect();
#endif
}

void WebPage::didReplaceMultipartContent(const WebFrame& frame)
{
#if PLATFORM(IOS_FAMILY)
    if (!frame.isMainFrame())
        return;

    // Restore the previous exposed content rect so that it remains fixed when replacing content
    // from multipart/x-mixed-replace streams.
    protect(drawingArea())->setExposedContentRect(m_previousExposedContentRect);
#endif
}

#if ENABLE(META_VIEWPORT)
static void setCanIgnoreViewportArgumentsToAvoidExcessiveZoomIfNeeded(ViewportConfiguration& configuration, LocalFrame* frame, bool shouldIgnoreMetaViewport)
{
    if (RefPtr document = frame ? frame->document() : nullptr; document && document->quirks().shouldIgnoreViewportArgumentsToAvoidExcessiveZoom())
        configuration.setCanIgnoreViewportArgumentsToAvoidExcessiveZoom(shouldIgnoreMetaViewport);
}

static void setCanIgnoreViewportArgumentsToAvoidEnlargedViewIfNeeded(ViewportConfiguration& configuration, LocalFrame* frame)
{
    if (RefPtr document = frame ? frame->document() : nullptr; document && document->quirks().shouldIgnoreViewportArgumentsToAvoidEnlargedView())
        configuration.setCanIgnoreViewportArgumentsToAvoidEnlargedView(true);
}

static void setUseDynamicViewportUnitsAsDefaultIfNeeded(LocalFrame* frame)
{
    if (RefPtr document = frame ? frame->document() : nullptr; document && document->quirks().shouldUseDynamicViewportUnitsAsDefault()) {
        if (RefPtr view = frame->view())
            view->setShouldUseDynamicViewportUnitsAsDefault(true);
    }
}
#endif

void WebPage::didCommitLoad(WebFrame* frame)
{
#if PLATFORM(IOS_FAMILY)
    auto firstTransactionIDAfterDidCommitLoad = downcast<RemoteLayerTreeDrawingArea>(*protect(drawingArea())).nextTransactionID();
    frame->setFirstLayerTreeTransactionIDAfterDidCommitLoad(firstTransactionIDAfterDidCommitLoad);
    cancelPotentialTapInFrame(*frame);
#endif

    resetFocusedElementForFrame(frame);

    if (frame->isMainFrame())
        m_textManipulationIncludesSubframes = false;
    else if (m_textManipulationIncludesSubframes)
        startTextManipulationForFrame(*protect(frame->coreLocalFrame()));

    if (!frame->isRootFrame())
        return;

#if ENABLE(VIEWPORT_RESIZING)
    m_lastShrinkToFitLayoutWidth = 0;
#endif

    if (RefPtr drawingArea = m_drawingArea)
        drawingArea->sendEnterAcceleratedCompositingModeIfNeeded();

    ASSERT(!frame->coreLocalFrame()->loader().stateMachine().creatingInitialEmptyDocument());
    unfreezeLayerTree(LayerTreeFreezeReason::ProcessSwap);

#if ENABLE(IMAGE_ANALYSIS)
    for (auto& [element, completionHandlers] : borrow(m_elementsPendingTextRecognition).get()) {
        for (auto& completionHandler : completionHandlers)
            completionHandler({ });
    }
    m_elementsPendingTextRecognition.clear();
#endif

    clearLoadedSubresourceDomains();

    // If previous URL is invalid, then it's not a real page that's being navigated away from.
    // Most likely, this is actually the first load to be committed in this page.
    if (frame->coreLocalFrame()->loader().previousURL().isValid())
        reportUsedFeatures();

    // Only restore the scale factor for standard frame loads (of the main frame).
    if (frame->coreLocalFrame()->loader().loadType() == FrameLoadType::Standard) {
        RefPtr page = frame->coreLocalFrame()->page();

#if PLATFORM(MAC)
        // As a very special case, we disable non-default layout modes in WKView for main-frame PluginDocuments.
        // Ideally we would only worry about this in WKView or the WKViewLayoutStrategies, but if we allow
        // a round-trip to the UI process, you'll see the wrong scale temporarily. So, we reset it here, and then
        // again later from the UI process.
        if (frame->coreLocalFrame()->document()->isPluginDocument()) {
            scaleView(1);
            setUseFixedLayout(false);
        }
#endif

        if (page && page->pageScaleFactor() != 1)
            scalePage(1, IntPoint());
    }

    // This timer can race with loading and clobber the scroll position saved on the current history item.
    m_pageScrolledHysteresis.cancel();

    m_didUpdateRenderingAfterCommittingLoad = false;

#if PLATFORM(IOS_FAMILY)
    if (auto scope = std::exchange(m_ignoreSelectionChangeScopeForDictation, nullptr))
        scope->invalidate();
    m_sendAutocorrectionContextAfterFocusingElement = false;
    m_hasReceivedVisibleContentRectsAfterDidCommitLoad = false;
    m_hasRestoredExposedContentRectAfterDidCommitLoad = false;
    m_internals->lastTransactionIDWithScaleChange = firstTransactionIDAfterDidCommitLoad;
    m_scaleWasSetByUIProcess = false;
    m_userHasChangedPageScaleFactor = false;
    m_previousViewportConfigurationMinimumScale = { };
    m_estimatedLatency = Seconds(1.0 / 60);
    m_shouldRevealCurrentSelectionAfterInsertion = true;
    m_internals->lastLayerTreeTransactionIdAndPageScaleBeforeScalingPage = std::nullopt;
    m_lastSelectedReplacementRange = { };
    m_bidiSelectionFlippingState = BidiSelectionFlippingState::NotFlipping;

    invokePendingSyntheticClickCallback(SyntheticClickResult::PageInvalid);

#if ENABLE(IOS_TOUCH_EVENTS)
    auto queuedEvents = makeUniqueRef<EventDispatcher::TouchEventQueue>();
    WebProcess::singleton().eventDispatcher().takeQueuedTouchEventsForPage(*this, queuedEvents);
    cancelAsynchronousTouchEvents(WTF::move(queuedEvents));
#endif
    m_lastTouchLocationBeforeTap = { };
    m_hasAnyActiveTouchPoints = false;
    m_activeTextInteractionSources = { };
#endif // PLATFORM(IOS_FAMILY)

    RefPtr coreFrame = frame->coreLocalFrame();
#if ENABLE(META_VIEWPORT)
    resetViewportDefaultConfiguration(frame);

    bool viewportChanged = false;

    setCanIgnoreViewportArgumentsToAvoidExcessiveZoomIfNeeded(m_viewportConfiguration, coreFrame.get(), shouldIgnoreMetaViewport());
    setCanIgnoreViewportArgumentsToAvoidEnlargedViewIfNeeded(m_viewportConfiguration, coreFrame.get());
    setUseDynamicViewportUnitsAsDefaultIfNeeded(coreFrame.get());

    m_viewportConfiguration.setPrefersHorizontalScrollingBelowDesktopViewportWidths(shouldEnableViewportBehaviorsForResizableWindows());

    LOG_WITH_STREAM(VisibleRects, stream << "WebPage " << m_identifier.toUInt64() << " didCommitLoad setting content size to " << coreFrame->view()->contentsSize());
    if (m_viewportConfiguration.setContentsSize(protect(coreFrame->view())->contentsSize()))
        viewportChanged = true;

    if (m_viewportConfiguration.setViewportArguments(protect(coreFrame->document())->viewportArguments()))
        viewportChanged = true;

    if (m_viewportConfiguration.setIsKnownToLayOutWiderThanViewport(false))
        viewportChanged = true;

    if (viewportChanged)
        viewportConfigurationChanged();
#endif // ENABLE(META_VIEWPORT)

#if ENABLE(TEXT_AUTOSIZING)
    m_textAutoSizingAdjustmentTimer.stop();
#endif

#if USE(OS_STATE)
    m_loadCommitTime = WallTime::now();
#endif

#if PLATFORM(IOS_FAMILY)
    m_updateLayoutViewportHeightExpansionTimer.stop();
    m_shouldRescheduleLayoutViewportHeightExpansionTimer = false;
#endif
    removeReasonsToDisallowLayoutViewportHeightExpansion(m_disallowLayoutViewportHeightExpansionReasons);

#if ENABLE(ADVANCED_PRIVACY_PROTECTIONS)
    if (coreFrame->isMainFrame() && !usesEphemeralSession()) {
        if (RefPtr loader = coreFrame->document()->loader(); loader
            && loader->advancedPrivacyProtections().contains(AdvancedPrivacyProtections::BaselineProtections))
            WEBPAGE_RELEASE_LOG(AdvancedPrivacyProtections, "didCommitLoad: advanced privacy protections enabled in non-ephemeral session");
    }
#endif

    themeColorChanged();

    m_lastNodeBeforeWritingSuggestions = { };

    WebProcess::singleton().updateActivePages(m_processDisplayName);

    updateMainFrameScrollOffsetPinning();

    updateMockAccessibilityElementAfterCommittingLoad();

#if ENABLE(IMAGE_ANALYSIS_ENHANCEMENTS)
    m_elementsToExcludeFromRemoveBackground.clear();
#endif

#if USE(UICONTEXTMENU)
    m_hasActiveContextMenuInteraction = false;
#endif

    m_needsFixedContainerEdgesUpdate = true;

    flushDeferredDidReceiveMouseEvent();

#if ENABLE(MODEL_ELEMENT_IMMERSIVE)
    exitImmersive([] { });
#endif

    if (frame && frame->isMainFrame())
        m_networkResourceRequestIdentifiersForPageLoadTiming.clear();
}

void WebPage::didFinishDocumentLoad(WebFrame& frame)
{
    if (!frame.isMainFrame())
        return;

#if ENABLE(VIEWPORT_RESIZING)
    shrinkToFitContent(ZoomToInitialScale::Yes);
#endif
}

void WebPage::didFinishLoad(WebFrame& frame)
{
    if (!frame.isMainFrame())
        return;

    WebProcess::singleton().sendPrewarmInformation(frame.url());

#if ENABLE(VIEWPORT_RESIZING)
    shrinkToFitContent(ZoomToInitialScale::Yes);
#endif

#if ENABLE(WEB_PAGE_SPATIAL_BACKDROP)
    spatialBackdropSourceChanged();
#endif
}

void WebPage::didSameDocumentNavigationForFrame(WebFrame& frame)
{
    RefPtr<API::Object> userData;

    auto navigationID = frame.coreLocalFrame()->loader().documentLoader()->navigationID();

    if (frame.isMainFrame())
        m_pendingNavigationID = std::nullopt;

    // Notify the bundle client.
    injectedBundleLoaderClient().didSameDocumentNavigationForFrame(*this, frame, SameDocumentNavigationType::AnchorNavigation, userData);

    // Notify the UIProcess.
    send(Messages::WebPageProxy::DidSameDocumentNavigationForFrame(frame.frameID(), navigationID, SameDocumentNavigationType::AnchorNavigation, protect(frame.coreLocalFrame()->document())->url(), UserData(WebProcess::singleton().transformObjectsToHandles(userData.get()).get())));

#if ENABLE(PDF_PLUGIN)
    for (Ref pluginView : m_pluginViews)
        pluginView->didSameDocumentNavigationForFrame(frame);
#endif
}

void WebPage::didNavigateWithinPageForFrame(WebFrame& frame)
{
    if (frame.isMainFrame())
        m_pendingNavigationID = std::nullopt;
}

void WebPage::testProcessIncomingSyncMessagesWhenWaitingForSyncReply(CompletionHandler<void(bool)>&& reply)
{
    RELEASE_ASSERT(IPC::UnboundedSynchronousIPCScope::hasOngoingUnboundedSyncIPC());
    reply(true);
}

std::optional<SimpleRange> WebPage::currentSelectionAsRange()
{
    RefPtr frame = frameWithSelection(m_page.get());
    if (!frame)
        return std::nullopt;

    return frame->selection().selection().toNormalizedRange();
}

void WebPage::reportUsedFeatures()
{
    Vector<String> namedFeatures;
    m_loaderClient->featuresUsedInPage(*this, namedFeatures);
}

void WebPage::sendEditorStateUpdate()
{
    m_needsEditorStateVisualDataUpdate = true;

    RefPtr frame = corePage()->focusController().focusedOrMainFrame();
    if (!frame)
        return;

    if (frame->editor().ignoreSelectionChanges() || !frame->document() || !frame->document()->hasLivingRenderTree())
        return;

    m_pendingEditorStateUpdateStatus = PendingEditorStateUpdateStatus::NotScheduled;

    // If we immediately dispatch an EditorState update to the UI process, layout may not be up to date yet.
    // If that is the case, just send what we have (i.e. don't include post-layout data) and wait until the
    // next layer tree commit to compute and send the complete EditorState over.
    auto state = editorState();
    send(Messages::WebPageProxy::EditorStateChanged(state));
    if (!state.hasPostLayoutData() && !shouldAvoidComputingPostLayoutDataForEditorState())
        scheduleFullEditorStateUpdate();
}

void WebPage::scheduleFullEditorStateUpdate()
{
    m_needsEditorStateVisualDataUpdate = true;

    if (hasPendingEditorStateUpdate()) {
        if (m_isChangingSelectionForAccessibility)
            m_pendingEditorStateUpdateStatus = PendingEditorStateUpdateStatus::ScheduledDuringAccessibilitySelectionChange;
        return;
    }

    if (m_isChangingSelectionForAccessibility)
        m_pendingEditorStateUpdateStatus = PendingEditorStateUpdateStatus::ScheduledDuringAccessibilitySelectionChange;
    else
        m_pendingEditorStateUpdateStatus = PendingEditorStateUpdateStatus::Scheduled;

    protect(corePage())->scheduleRenderingUpdate(RenderingUpdateStep::LayerFlush);
}

void WebPage::loadAndDecodeImage(WebCore::ResourceRequest&& request, std::optional<WebCore::FloatSize> sizeConstraint, uint64_t maximumBytesFromNetwork, CompletionHandler<void(Expected<Ref<WebCore::ShareableBitmap>, WebCore::ResourceError>&&)>&& completionHandler)
{
    URL url = request.url();
    WebProcess::singleton().ensureNetworkProcessConnection().connection().sendWithAsyncReply(Messages::NetworkConnectionToWebProcess::LoadImageForDecoding(WTF::move(request), m_webPageProxyIdentifier, maximumBytesFromNetwork), [completionHandler = WTF::move(completionHandler), sizeConstraint, url] (Expected<Ref<WebCore::FragmentedSharedBuffer>, WebCore::ResourceError>&& result) mutable {
        if (!result)
            return completionHandler(makeUnexpected(WTF::move(result.error())));

        Ref bitmapImage = WebCore::BitmapImage::create(nullptr);
        bitmapImage->setData(result->ptr(), true);
        RefPtr nativeImage = bitmapImage->primaryNativeImage();
        if (!nativeImage)
            return completionHandler(makeUnexpected(decodeError(url)));

        FloatSize sourceSize = nativeImage->size();
        FloatSize destinationSize = sourceSize;
        if (sizeConstraint)
            destinationSize = largestRectWithAspectRatioInsideRect(sourceSize.aspectRatio(), FloatRect({ }, sizeConstraint->shrunkTo(sourceSize))).size();

        IntSize roundedDestinationSize = flooredIntSize(destinationSize);
        auto sourceColorSpace = nativeImage->colorSpace();
        auto destinationColorSpace = sourceColorSpace.supportsOutput() ? sourceColorSpace : DestinationColorSpace::SRGB();
        auto bitmap = ShareableBitmap::create({ roundedDestinationSize, destinationColorSpace });
        if (!bitmap)
            return completionHandler(makeUnexpected<ResourceError>({ }));

        auto context = bitmap->createGraphicsContext();
        if (!context)
            return completionHandler(makeUnexpected<ResourceError>({ }));

        context->drawNativeImage(*nativeImage, FloatRect({ }, roundedDestinationSize), FloatRect({ }, sourceSize), { CompositeOperator::Copy });

        completionHandler(bitmap.releaseNonNull());
    });
}

#if PLATFORM(MAC) || PLATFORM(WPE) || PLATFORM(GTK)
void WebPage::flushPendingThemeColorChange()
{
    if (!m_pendingThemeColorChange)
        return;

    m_pendingThemeColorChange = false;

    send(Messages::WebPageProxy::ThemeColorChanged(protect(corePage())->themeColor()));
}
#endif

void WebPage::flushPendingPageExtendedBackgroundColorChange()
{
    if (!m_pendingPageExtendedBackgroundColorChange)
        return;

    m_pendingPageExtendedBackgroundColorChange = false;

    send(Messages::WebPageProxy::PageExtendedBackgroundColorDidChange(protect(corePage())->pageExtendedBackgroundColor()));
}

void WebPage::flushPendingSampledPageTopColorChange()
{
    if (!m_pendingSampledPageTopColorChange)
        return;

    m_pendingSampledPageTopColorChange = false;

    send(Messages::WebPageProxy::SampledPageTopColorChanged(protect(corePage())->sampledPageTopColor()));
}

#if ENABLE(WEB_PAGE_SPATIAL_BACKDROP)
void WebPage::spatialBackdropSourceChanged()
{
    RefPtr page = m_page;
    if (page->settings().webPageSpatialBackdropEnabled())
        send(Messages::WebPageProxy::SpatialBackdropSourceChanged(page->spatialBackdropSource()));
}
#endif

#if ENABLE(MODEL_ELEMENT_IMMERSIVE)
void WebPage::allowImmersiveElement(CompletionHandler<void(bool)>&& completion)
{
    sendWithAsyncReply(Messages::WebPageProxy::AllowImmersiveElement(), WTF::move(completion));
}

void WebPage::presentImmersiveElement(const LayerHostingContextIdentifier contextID, CompletionHandler<void(bool)>&& completion)
{
    sendWithAsyncReply(Messages::WebPageProxy::PresentImmersiveElement(contextID), WTF::move(completion));
}

void WebPage::dismissImmersiveElement(CompletionHandler<void()>&& completion)
{
    sendWithAsyncReply(Messages::WebPageProxy::DismissImmersiveElement(), WTF::move(completion));
}

void WebPage::exitImmersive(CompletionHandler<void()>&& completion)
{
    if (RefPtr localTopDocument = this->localTopDocument(); RefPtr protectedImmersive = localTopDocument->immersiveIfExists())
        protectedImmersive->exitImmersiveIfNeeded(WTF::move(completion));
    else
        completion();
}

bool WebPage::allowsImmersiveEnvironments() const
{
    return m_allowsImmersiveEnvironments;
}
#endif

void WebPage::flushPendingEditorStateUpdate()
{
    if (!hasPendingEditorStateUpdate())
        return;

    RefPtr frame = corePage()->focusController().focusedOrMainFrame();
    if (!frame)
        return;

    if (frame->editor().ignoreSelectionChanges())
        return;

    sendEditorStateUpdate();
}

void WebPage::updateWebsitePolicies(WebsitePoliciesData&& websitePolicies)
{
    RefPtr page = m_page;
    if (!page)
        return;

    if (auto* remoteMainFrameClient = m_mainFrame->remoteFrameClient()) {
        remoteMainFrameClient->applyWebsitePolicies(WTF::move(websitePolicies));
        return;
    }

    RefPtr localMainFrame = this->localMainFrame();
    RefPtr documentLoader = localMainFrame ? localMainFrame->loader().documentLoader() : nullptr;
    if (!documentLoader)
        return;

    m_allowsContentJavaScriptFromMostRecentNavigation = websitePolicies.allowsContentJavaScript;
    WebsitePoliciesData::applyToDocumentLoader(WTF::move(websitePolicies), *documentLoader);

#if ENABLE(VIDEO)
    page->updateMediaElementRateChangeRestrictions();
#endif

#if ENABLE(META_VIEWPORT)
    setCanIgnoreViewportArgumentsToAvoidExcessiveZoomIfNeeded(m_viewportConfiguration, localMainFrame.get(), shouldIgnoreMetaViewport());
    setCanIgnoreViewportArgumentsToAvoidEnlargedViewIfNeeded(m_viewportConfiguration, localMainFrame.get());
#endif
}

WebCore::ScrollPinningBehavior WebPage::scrollPinningBehavior()
{
    return m_internals->scrollPinningBehavior;
}

void WebPage::setScrollPinningBehavior(WebCore::ScrollPinningBehavior pinning)
{
    m_internals->scrollPinningBehavior = pinning;
    if (RefPtr localMainFrame = this->localMainFrame())
        protect(localMainFrame->view())->setScrollPinningBehavior(m_internals->scrollPinningBehavior);
}

void WebPage::setScrollbarOverlayStyle(std::optional<WebCore::ScrollbarOverlayStyle> scrollbarStyle)
{
    m_scrollbarOverlayStyle = scrollbarStyle;

    if (RefPtr localMainFrame = this->localMainFrame())
        protect(localMainFrame->view())->recalculateScrollbarOverlayStyle();
}

Ref<DocumentLoader> WebPage::createDocumentLoader(LocalFrame& frame, ResourceRequest&& request, SubstituteData&& substituteData, ResourceRequest&& originalRequest)
{
    auto documentLoader = DocumentLoader::create(WTF::move(request), WTF::move(substituteData), WTF::move(originalRequest));

    documentLoader->setLastNavigationWasAppInitiated(m_lastNavigationWasAppInitiated);

    if (frame.isMainFrame() || m_page->settings().siteIsolationEnabled()) {
        if (m_pendingNavigationID) {
            documentLoader->setNavigationID(*m_pendingNavigationID);
            m_pendingNavigationID = std::nullopt;
        }

        if (m_internals->pendingWebsitePolicies && frame.isMainFrame()) {
            m_allowsContentJavaScriptFromMostRecentNavigation = m_internals->pendingWebsitePolicies->allowsContentJavaScript;
            WebsitePoliciesData::applyToDocumentLoader(*std::exchange(m_internals->pendingWebsitePolicies, std::nullopt), documentLoader);
        }
    }

    return documentLoader;
}

Ref<DocumentLoader> WebPage::createDocumentLoader(LocalFrame& frame, ResourceRequest&& request, SubstituteData&& substituteData)
{
    return createDocumentLoader(frame, WTF::move(request), WTF::move(substituteData), { });
}

void WebPage::updateCachedDocumentLoader(DocumentLoader& documentLoader, LocalFrame& frame)
{
    if (m_pendingNavigationID && frame.isMainFrame()) {
        documentLoader.setNavigationID(*m_pendingNavigationID);
        m_pendingNavigationID = std::nullopt;
    }
}

void WebPage::getBytecodeProfile(CompletionHandler<void(const String&)>&& callback)
{
    if (!commonVM().m_perBytecodeProfiler) [[likely]]
        return callback({ });

    String result = commonVM().m_perBytecodeProfiler->toJSON()->toJSONString();
    ASSERT(result.length());
    callback(result);
}

void WebPage::getSamplingProfilerOutput(CompletionHandler<void(const String&)>&& callback)
{
#if ENABLE(SAMPLING_PROFILER)
    RefPtr samplingProfiler = commonVM().samplingProfiler();
    if (!samplingProfiler)
        return callback({ });

    StringPrintStream result;
    samplingProfiler->reportTopFunctions(result);
    samplingProfiler->reportTopBytecodes(result);
    callback(result.toString());
#else
    callback({ });
#endif
}

void WebPage::didChangeScrollOffsetForFrame(LocalFrame& frame)
{
    // If this is called when tearing down a FrameView, the WebCore::Frame's
    // current FrameView will be null.
    if (!frame.view())
        return;

#if ENABLE(ACCESSIBILITY_LOCAL_FRAME)
    // When any frame scrolls, the frame's screenPosition (content-origin-based)
    // changes and needs to be recomputed for correct accessibility geometry.
    scheduleAccessibilityFrameGeometryUpdate();
#endif

    if (!frame.isMainFrame())
        return;

    updateMainFrameScrollOffsetPinning();
}

void WebPage::postMessage(const String& messageName, API::Object* messageBody)
{
    send(Messages::WebPageProxy::HandleMessage(messageName, UserData(WebProcess::singleton().transformObjectsToHandles(messageBody))));
}

void WebPage::postMessageIgnoringFullySynchronousMode(const String& messageName, API::Object* messageBody)
{
    send(Messages::WebPageProxy::HandleMessage(messageName, UserData(WebProcess::singleton().transformObjectsToHandles(messageBody))), IPC::SendOption::DispatchMessageEvenWhenWaitingForSyncReply);
}

void WebPage::postSynchronousMessageForTesting(const String& messageName, API::Object* messageBody, RefPtr<API::Object>& returnData)
{
    auto& webProcess = WebProcess::singleton();

    auto sendResult = sendSync(Messages::WebPageProxy::HandleSynchronousMessage(messageName, UserData(webProcess.transformObjectsToHandles(messageBody))), Seconds::infinity(), IPC::SendSyncOption::UseFullySynchronousModeForTesting);
    if (sendResult.succeeded()) {
        auto& [returnUserData] = sendResult.reply();
        returnData = webProcess.transformHandlesToObjects(protect(returnUserData.object()).get());
    } else
        returnData = nullptr;
}

void WebPage::setShouldScaleViewToFitDocument(bool shouldScaleViewToFitDocument)
{
    if (RefPtr drawingArea = m_drawingArea)
        drawingArea->setShouldScaleViewToFitDocument(shouldScaleViewToFitDocument);
}

void WebPage::imageOrMediaDocumentSizeChanged(const IntSize& newSize)
{
    send(Messages::WebPageProxy::ImageOrMediaDocumentSizeChanged(newSize));
}

void WebPage::addUserScript(String&& source, InjectedBundleScriptWorld& world, WebCore::UserContentInjectedFrames injectedFrames, WebCore::UserScriptInjectionTime injectionTime, WebCore::UserContentMatchParentFrame matchParentFrame)
{
    WebCore::UserScript userScript { WTF::move(source), URL(aboutBlankURL()), Vector<String>(), Vector<String>(), injectionTime, injectedFrames, matchParentFrame };

    Ref { m_userContentController }->addUserScript(world, WTF::move(userScript));
}

void WebPage::addUserStyleSheet(const String& source, WebCore::UserContentInjectedFrames injectedFrames)
{
    WebCore::UserStyleSheet userStyleSheet { source, aboutBlankURL(), Vector<String>(), Vector<String>(), injectedFrames };

    Ref { m_userContentController }->addUserStyleSheet(InjectedBundleScriptWorld::normalWorldSingleton(), WTF::move(userStyleSheet));
}

void WebPage::removeAllUserContent()
{
    Ref { m_userContentController }->removeAllUserContent();
}

void WebPage::updateIntrinsicContentSizeIfNeeded(const WebCore::IntSize& size)
{
    m_pendingIntrinsicContentSize = std::nullopt;
    if (!minimumSizeForAutoLayout().width() && !sizeToContentAutoSizeMaximumSize().width() && !sizeToContentAutoSizeMaximumSize().height())
        return;
    ASSERT(localMainFrameView());
    ASSERT(localMainFrameView()->isFixedWidthAutoSizeEnabled() || localMainFrameView()->isSizeToContentAutoSizeEnabled());
    ASSERT(!localMainFrameView()->needsLayout());
    if (m_lastSentIntrinsicContentSize == size)
        return;
    m_lastSentIntrinsicContentSize = size;
    send(Messages::WebPageProxy::DidChangeIntrinsicContentSize(size));
}

void WebPage::flushPendingIntrinsicContentSizeUpdate()
{
    if (auto pendingSize = std::exchange(m_pendingIntrinsicContentSize, std::nullopt))
        updateIntrinsicContentSizeIfNeeded(*pendingSize);
}

void WebPage::scheduleIntrinsicContentSizeUpdate(const IntSize& size)
{
    if (!minimumSizeForAutoLayout().width() && !sizeToContentAutoSizeMaximumSize().width() && !sizeToContentAutoSizeMaximumSize().height())
        return;
    ASSERT(localMainFrameView());
    ASSERT(localMainFrameView()->isFixedWidthAutoSizeEnabled() || localMainFrameView()->isSizeToContentAutoSizeEnabled());
    ASSERT(!localMainFrameView()->needsLayout());
    m_pendingIntrinsicContentSize = size;
}

void WebPage::dispatchDidReachLayoutMilestone(OptionSet<WebCore::LayoutMilestone> milestones)
{
    RefPtr<API::Object> userData;
    injectedBundleLoaderClient().didReachLayoutMilestone(*this, milestones, userData);

    // Clients should not set userData for this message, and it won't be passed through.
    ASSERT(!userData);

    // The drawing area might want to defer dispatch of didLayout to the UI process.
    if (RefPtr drawingArea = m_drawingArea) {
        static auto paintMilestones = OptionSet<WebCore::LayoutMilestone> { WebCore::LayoutMilestone::DidHitRelevantRepaintedObjectsAreaThreshold, WebCore::LayoutMilestone::DidFirstPaintAfterSuppressedIncrementalRendering, WebCore::LayoutMilestone::DidRenderSignificantAmountOfText, WebCore::LayoutMilestone::DidFirstMeaningfulPaint };
        auto drawingAreaRelatedMilestones = milestones & paintMilestones;
        if (drawingAreaRelatedMilestones && drawingArea->addMilestonesToDispatch(drawingAreaRelatedMilestones))
            milestones.remove(drawingAreaRelatedMilestones);
        if (milestones.isEmpty())
            return;
    }
    if (milestones.contains(WebCore::LayoutMilestone::DidFirstLayout) && localMainFrameView()) {
        // Ensure we never send DidFirstLayout milestone without updating the intrinsic size.
        updateIntrinsicContentSizeIfNeeded(localMainFrameView()->autoSizingIntrinsicContentSize());
    }

    send(Messages::WebPageProxy::DidReachLayoutMilestone(milestones, WallTime::now()));
}

void WebPage::didRestoreScrollPosition()
{
    send(Messages::WebPageProxy::DidRestoreScrollPosition());
}

void WebPage::setUserInterfaceLayoutDirection(uint32_t direction)
{
    m_userInterfaceLayoutDirection = static_cast<WebCore::UserInterfaceLayoutDirection>(direction);
    protect(corePage())->setUserInterfaceLayoutDirection(m_userInterfaceLayoutDirection);
}

#if ENABLE(GAMEPAD)

void WebPage::gamepadActivity(const Vector<std::optional<GamepadData>>& gamepadDatas, EventMakesGamepadsVisible eventVisibilty)
{
    WebGamepadProvider::singleton().gamepadActivity(gamepadDatas, eventVisibilty);
}

void WebPage::gamepadsRecentlyAccessed()
{
    send(Messages::WebPageProxy::GamepadsRecentlyAccessed());
}

#if PLATFORM(VISION)
void WebPage::allowGamepadAccess()
{
    corePage()->allowGamepadAccess();
}
#endif

#endif // ENABLE(GAMEPAD)

#if ENABLE(POINTER_LOCK)
void WebPage::didAcquirePointerLock()
{
    corePage()->pointerLockController().didAcquirePointerLock();
}

void WebPage::didNotAcquirePointerLock()
{
    corePage()->pointerLockController().didNotAcquirePointerLock();
}

void WebPage::didLosePointerLock()
{
    corePage()->pointerLockController().didLosePointerLock();
}
#endif

void WebPage::didGetLoadDecisionForIcon(bool decision, CallbackID loadIdentifier, CompletionHandler<void(const IPC::SharedBufferReference&)>&& completionHandler)
{
    RefPtr localMainFrame = dynamicDowncast<WebCore::LocalFrame>(corePage()->mainFrame());
    if (!localMainFrame)
        return completionHandler({ });
    RefPtr documentLoader = localMainFrame->loader().documentLoader();
    if (!documentLoader)
        return completionHandler({ });

    documentLoader->didGetLoadDecisionForIcon(decision, loadIdentifier.toInteger(), [completionHandler = WTF::move(completionHandler)] (WebCore::FragmentedSharedBuffer* iconData) mutable {
        completionHandler(IPC::SharedBufferReference(RefPtr { iconData }));
    });
}

WebURLSchemeHandlerProxy* WebPage::urlSchemeHandlerForScheme(StringView scheme)
{
    return m_schemeToURLSchemeHandlerProxyMap.get<StringViewHashTranslator>(scheme);
}

void WebPage::stopAllURLSchemeTasks()
{
    HashSet<Ref<WebURLSchemeHandlerProxy>> handlers;
    for (auto& handler : m_schemeToURLSchemeHandlerProxyMap.values())
        handlers.add(handler);

    for (auto& handler : handlers)
        handler->stopAllTasks();
}

void WebPage::registerURLSchemeHandler(WebURLSchemeHandlerIdentifier handlerIdentifier, const String& scheme)
{
    WEBPAGE_RELEASE_LOG(Process, "registerURLSchemeHandler: Registered handler %" PRIu64 " for the '%s' scheme", handlerIdentifier.toUInt64(), scheme.utf8().data());
    WebCore::LegacySchemeRegistry::registerURLSchemeAsHandledBySchemeHandler(scheme);
    WebCore::LegacySchemeRegistry::registerURLSchemeAsCORSEnabled(scheme);
    auto schemeResult = m_schemeToURLSchemeHandlerProxyMap.add(scheme, WebURLSchemeHandlerProxy::create(*this, handlerIdentifier));
    m_identifierToURLSchemeHandlerProxyMap.add(handlerIdentifier, Ref { schemeResult.iterator->value }.get());
}

void WebPage::urlSchemeTaskWillPerformRedirection(WebURLSchemeHandlerIdentifier handlerIdentifier, WebCore::ResourceLoaderIdentifier taskIdentifier, ResourceResponse&& response, ResourceRequest&& request, CompletionHandler<void(WebCore::ResourceRequest&&)>&& completionHandler)
{
    RefPtr handler = m_identifierToURLSchemeHandlerProxyMap.get(handlerIdentifier);
    ASSERT(handler);

    auto actualNewRequest = request;
    handler->taskDidPerformRedirection(taskIdentifier, WTF::move(response), WTF::move(request), WTF::move(completionHandler));
}

void WebPage::urlSchemeTaskDidPerformRedirection(WebURLSchemeHandlerIdentifier handlerIdentifier, WebCore::ResourceLoaderIdentifier taskIdentifier, ResourceResponse&& response, ResourceRequest&& request)
{
    RefPtr handler = m_identifierToURLSchemeHandlerProxyMap.get(handlerIdentifier);
    ASSERT(handler);

    handler->taskDidPerformRedirection(taskIdentifier, WTF::move(response), WTF::move(request), [] (ResourceRequest&&) {});
}

void WebPage::urlSchemeTaskDidReceiveResponse(WebURLSchemeHandlerIdentifier handlerIdentifier, WebCore::ResourceLoaderIdentifier taskIdentifier, ResourceResponse&& response)
{
    RefPtr handler = m_identifierToURLSchemeHandlerProxyMap.get(handlerIdentifier);
    ASSERT(handler);

    handler->taskDidReceiveResponse(taskIdentifier, WTF::move(response));
}

void WebPage::urlSchemeTaskDidReceiveData(WebURLSchemeHandlerIdentifier handlerIdentifier, WebCore::ResourceLoaderIdentifier taskIdentifier, Ref<WebCore::SharedBuffer>&& data)
{
    RefPtr handler = m_identifierToURLSchemeHandlerProxyMap.get(handlerIdentifier);
    ASSERT(handler);

    handler->taskDidReceiveData(taskIdentifier, WTF::move(data));
}

void WebPage::urlSchemeTaskDidComplete(WebURLSchemeHandlerIdentifier handlerIdentifier, WebCore::ResourceLoaderIdentifier taskIdentifier, const ResourceError& error)
{
    RefPtr handler = m_identifierToURLSchemeHandlerProxyMap.get(handlerIdentifier);
    ASSERT(handler);

    handler->taskDidComplete(taskIdentifier, error);
}

void WebPage::setIsSuspended(bool suspended, CompletionHandler<void(std::optional<bool>)>&& completionHandler)
{
    if (m_isSuspended == suspended)
        return completionHandler({ });

    m_isSuspended = suspended;

    if (!suspended)
        return completionHandler({ });

    // Unfrozen on drawing area reset.
    freezeLayerTree(LayerTreeFreezeReason::PageSuspended);

    // Only the committed WebPage gets application visibility notifications from the UIProcess, so make sure
    // we don't hold a BackgroundApplication freeze reason when transitioning from committed to suspended.
    unfreezeLayerTree(LayerTreeFreezeReason::BackgroundApplication);

    WebProcess::singleton().sendPrewarmInformation(m_mainFrame->url());

    suspendForProcessSwap(WTF::move(completionHandler));
}

void WebPage::setSubframesSuspended(bool suspended, BackForwardFrameItemIdentifier identifier, CompletionHandler<void(bool)>&& completionHandler)
{
    if (m_isSuspended == suspended)
        return completionHandler(true);
    m_isSuspended = suspended;

    if (!suspended) {
        // FIXME: Restore path (follow-up patch).
        return completionHandler(true);
    }

    freezeLayerTree(LayerTreeFreezeReason::PageSuspended);
    unfreezeLayerTree(LayerTreeFreezeReason::BackgroundApplication);
    flushDeferredDidReceiveMouseEvent();

    RefPtr page = corePage();
    if (!page) {
        WEBPAGE_RELEASE_LOG_ERROR(ProcessSwapping, "setSubframesSuspended: No corePage");
        return completionHandler(false);
    }

    if (!BackForwardCache::singleton().addIfCacheable(identifier, *page)) {
        WEBPAGE_RELEASE_LOG_ERROR(ProcessSwapping, "setSubframesSuspended: addIfCacheable failed");
        return completionHandler(false);
    }

    WEBPAGE_RELEASE_LOG(ProcessSwapping, "setSubframesSuspended: Successfully cached page");
    completionHandler(true);
}

void WebPage::hasStorageAccess(RegistrableDomain&& subFrameDomain, RegistrableDomain&& topFrameDomain, WebFrame& frame, CompletionHandler<void(bool)>&& completionHandler)
{
    if (hasPageLevelStorageAccess(topFrameDomain, subFrameDomain)) {
        completionHandler(true);
        return;
    }

    WebProcess::singleton().ensureNetworkProcessConnection().connection().sendWithAsyncReply(Messages::NetworkConnectionToWebProcess::HasStorageAccess(WTF::move(subFrameDomain), WTF::move(topFrameDomain), frame.frameID(), m_identifier), WTF::move(completionHandler));
}

void WebPage::requestStorageAccess(RegistrableDomain&& subFrameDomain, RegistrableDomain&& topFrameDomain, WebFrame& frame, StorageAccessScope scope, HasOrShouldIgnoreUserGesture hasOrShouldIgnoreUserGesture, CompletionHandler<void(WebCore::RequestStorageAccessResult)>&& completionHandler)
{
    WebProcess::singleton().ensureNetworkProcessConnection().connection().sendWithAsyncReply(Messages::NetworkConnectionToWebProcess::RequestStorageAccess(WTF::move(subFrameDomain), WTF::move(topFrameDomain), frame.frameID(), m_identifier, m_webPageProxyIdentifier, scope, hasOrShouldIgnoreUserGesture), [this, protectedThis = Ref { *this }, completionHandler = WTF::move(completionHandler), frame = Ref { frame }, pageID = m_identifier, frameID = frame.frameID()](RequestStorageAccessResult result) mutable {
        if (result.wasGranted == StorageAccessWasGranted::Yes) {
            switch (result.scope) {
            case StorageAccessScope::PerFrame:
                if (RefPtr localFrameLoaderClient = frame->localFrameLoaderClient())
                    localFrameLoaderClient->setHasFrameSpecificStorageAccess({ frameID, pageID });
                break;
            case StorageAccessScope::PerPage:
                addDomainWithPageLevelStorageAccess(result.topFrameDomain, result.subFrameDomain);
                break;
            }
        }
        completionHandler(result);
    });
}

void WebPage::setLoginStatus(RegistrableDomain&& domain, IsLoggedIn loggedInStatus, CompletionHandler<void()>&& completionHandler)
{
    RefPtr page = corePage();
    if (!page)
        return completionHandler();
    auto lastAuthentication = page->lastAuthentication() ? std::optional(*page->lastAuthentication()) : std::nullopt;
    WebProcess::singleton().ensureNetworkProcessConnection().connection().sendWithAsyncReply(Messages::NetworkConnectionToWebProcess::SetLoginStatus(WTF::move(domain), loggedInStatus, lastAuthentication), WTF::move(completionHandler));
}

void WebPage::isLoggedIn(RegistrableDomain&& domain, CompletionHandler<void(bool)>&& completionHandler)
{
    WebProcess::singleton().ensureNetworkProcessConnection().connection().sendWithAsyncReply(Messages::NetworkConnectionToWebProcess::IsLoggedIn(WTF::move(domain)), WTF::move(completionHandler));
}

void WebPage::addDomainWithPageLevelStorageAccess(const RegistrableDomain& topLevelDomain, const RegistrableDomain& resourceDomain)
{
    m_internals->domainsWithPageLevelStorageAccess.add(topLevelDomain, HashSet<RegistrableDomain> { }).iterator->value.add(resourceDomain);

    // Some sites have quirks where multiple login domains require storage access.
    if (auto additionalLoginDomain = NetworkStorageSession::findAdditionalLoginDomain(topLevelDomain, resourceDomain))
        m_internals->domainsWithPageLevelStorageAccess.add(topLevelDomain, HashSet<RegistrableDomain> { }).iterator->value.add(*additionalLoginDomain);
}

bool WebPage::hasPageLevelStorageAccess(const RegistrableDomain& topLevelDomain, const RegistrableDomain& resourceDomain) const
{
    auto it = m_internals->domainsWithPageLevelStorageAccess.find(topLevelDomain);
    return it != m_internals->domainsWithPageLevelStorageAccess.end() && it->value.contains(resourceDomain);
}

void WebPage::clearPageLevelStorageAccess()
{
    m_internals->domainsWithPageLevelStorageAccess.clear();
}

void WebPage::revokeFrameSpecificStorageAccess()
{
    for (RefPtr frame = m_mainFrame->coreFrame(); frame; frame = frame->tree().traverseNext()) {
        RefPtr localFrame = dynamicDowncast<LocalFrame>(frame);
        if (!localFrame)
            continue;
        if (auto* client = dynamicDowncast<WebLocalFrameLoaderClient>(localFrame->loader().client()))
            client->revokeFrameSpecificStorageAccess();
    }
}

void WebPage::wasLoadedWithDataTransferFromPrevalentResource()
{
    if (RefPtr localTopDocument = this->localTopDocument())
        localTopDocument->wasLoadedWithDataTransferFromPrevalentResource();
}

void WebPage::didLoadFromRegistrableDomain(RegistrableDomain&& targetDomain)
{
    if (targetDomain != RegistrableDomain(m_mainFrame->url()))
        m_internals->loadedSubresourceDomains.add(targetDomain);
}

void WebPage::getLoadedSubresourceDomains(CompletionHandler<void(Vector<RegistrableDomain>)>&& completionHandler)
{
    completionHandler(copyToVector(m_internals->loadedSubresourceDomains));
}

void WebPage::clearLoadedSubresourceDomains()
{
    m_internals->loadedSubresourceDomains.clear();
}

const HashSet<WebCore::RegistrableDomain>& WebPage::loadedSubresourceDomains() const
{
    return m_internals->loadedSubresourceDomains;
}

#if ENABLE(DEVICE_ORIENTATION)
void WebPage::shouldAllowDeviceOrientationAndMotionAccess(FrameIdentifier frameID, FrameInfoData&& frameInfo, bool mayPrompt, CompletionHandler<void(DeviceOrientationOrMotionPermissionState)>&& completionHandler)
{
#if PLATFORM(DRIFTSTACK)
    // A real iPhone with a granted DeviceOrientation/Motion permission returns
    // Granted without any UIProcess prompt round-trip. When the synthetic-sensor
    // gate (DRIFTSTACK_DEVICEMOTION_GRANTED, the SAME flag that installs the
    // synthetic clients in Page::Page) is on, short-circuit to Granted so the
    // grant->listen chain (DeviceOrientationAndMotionAccessController -> LocalDOMWindow
    // -> DeviceController::addDeviceEventListener -> client.startUpdating) actually
    // starts the synthetic stream. Read the env once.
    // ⚠️ -Werror=unreachable-code (the LEAK-1/2 lesson): the upstream
    // sendWithAsyncReply fall-through MUST be #else-wrapped, NOT left after an
    // unconditional return, so a build with the gate compiled-in does not see dead
    // code after a constant-true branch.
    static const bool s_driftstackDeviceMotionGranted = []() {
        const char* env = getenv("DRIFTSTACK_DEVICEMOTION_GRANTED");
        return env && env[0] == '1';
    }();
    if (s_driftstackDeviceMotionGranted) {
        completionHandler(DeviceOrientationOrMotionPermissionState::Granted);
        return;
    }
    sendWithAsyncReply(Messages::WebPageProxy::ShouldAllowDeviceOrientationAndMotionAccess(frameID, WTF::move(frameInfo), mayPrompt), WTF::move(completionHandler));
#else
    sendWithAsyncReply(Messages::WebPageProxy::ShouldAllowDeviceOrientationAndMotionAccess(frameID, WTF::move(frameInfo), mayPrompt), WTF::move(completionHandler));
#endif
}
#endif

void WebPage::showShareSheet(ShareDataWithParsedURL&& shareData, WTF::CompletionHandler<void(bool)>&& callback)
{
    sendWithAsyncReply(Messages::WebPageProxy::ShowShareSheet(WTF::move(shareData)), WTF::move(callback));
}

void WebPage::showContactPicker(WebCore::ContactsRequestData&& requestData, CompletionHandler<void(std::optional<Vector<WebCore::ContactInfo>>&&)>&& callback)
{
    sendWithAsyncReply(Messages::WebPageProxy::ShowContactPicker(WTF::move(requestData)), WTF::move(callback));
}

#if ENABLE(WEB_AUTHN)
void WebPage::showDigitalCredentialsPicker(const WebCore::DigitalCredentialsRequestData& requestData, CompletionHandler<void(Expected<WebCore::DigitalCredentialsResponseData, WebCore::ExceptionData>&&)>&& completionHandler)
{
    sendWithAsyncReply(Messages::WebPageProxy::ShowDigitalCredentialsPicker(requestData), WTF::move(completionHandler));
}

void WebPage::dismissDigitalCredentialsPicker(CompletionHandler<void(bool)>&& completionHandler)
{
    sendWithAsyncReply(Messages::WebPageProxy::DismissDigitalCredentialsPicker(), WTF::move(completionHandler));
}
#endif

WebCore::DOMPasteAccessResponse WebPage::requestDOMPasteAccess(DOMPasteAccessCategory pasteAccessCategory, FrameIdentifier frameID, const String& originIdentifier)
{
#if PLATFORM(IOS_FAMILY)
    // FIXME: Computing and sending an autocorrection context is a workaround for the fact that autocorrection context
    // requests on iOS are currently synchronous in the web process. This allows us to immediately fulfill pending
    // autocorrection context requests in the UI process on iOS before handling the DOM paste request. This workaround
    // should be removed once <rdar://problem/16207002> is resolved.
    preemptivelySendAutocorrectionContext();
#endif

    AXRelayProcessSuspendedNotification(*this);

    auto sendResult = sendSyncWithDelayedReply(Messages::WebPageProxy::RequestDOMPasteAccess(pasteAccessCategory, frameID, rectForElementAtInteractionLocation(), originIdentifier));
    auto [response] = sendResult.takeReplyOr(WebCore::DOMPasteAccessResponse::DeniedForGesture);
    return response;
}

void WebPage::simulateDeviceMotionChange(double xAcceleration, double yAcceleration, double zAcceleration, double xAccelerationIncludingGravity, double yAccelerationIncludingGravity, double zAccelerationIncludingGravity, double xRotationRate, double yRotationRate, double zRotationRate)
{
#if ENABLE(DEVICE_ORIENTATION) && PLATFORM(IOS_FAMILY)
    for (RefPtr frame = mainFrame(); frame; frame = frame->tree().traverseNext()) {
        RefPtr localFrame = dynamicDowncast<LocalFrame>(frame.get());
        if (!localFrame)
            continue;

        if (RefPtr document = localFrame->document())
            document->simulateDeviceMotionChange(xAcceleration, yAcceleration, zAcceleration, xAccelerationIncludingGravity, yAccelerationIncludingGravity, zAccelerationIncludingGravity, xRotationRate, yRotationRate, zRotationRate);
    }
#endif
}

void WebPage::simulateDeviceOrientationChange(double alpha, double beta, double gamma)
{
#if ENABLE(DEVICE_ORIENTATION) && PLATFORM(IOS_FAMILY)
    for (RefPtr frame = mainFrame(); frame; frame = frame->tree().traverseNext()) {
        RefPtr localFrame = dynamicDowncast<LocalFrame>(frame.get());
        if (!localFrame)
            continue;

        if (RefPtr document = localFrame->document())
            document->simulateDeviceOrientationChange(alpha, beta, gamma);
    }
#endif
}

#if USE(SYSTEM_PREVIEW)
void WebPage::systemPreviewActionTriggered(WebCore::SystemPreviewInfo previewInfo, const String& message)
{
    RefPtr document = Document::allDocumentsMap().get(*previewInfo.element.documentIdentifier);
    if (!document)
        return;

    auto pageID = document->pageID();
    if (!pageID || previewInfo.element.webPageIdentifier != pageID.value())
        return;

    document->dispatchSystemPreviewActionEvent(previewInfo, message);
}
#endif

#if ENABLE(SPEECH_SYNTHESIS)
void WebPage::speakingErrorOccurred()
{
    if (auto observer = corePage()->speechSynthesisClient()->observer())
        observer->speakingErrorOccurred();
}

void WebPage::boundaryEventOccurred(bool wordBoundary, unsigned charIndex, unsigned charLength)
{
    if (auto observer = corePage()->speechSynthesisClient()->observer())
        observer->boundaryEventOccurred(wordBoundary, charIndex, charLength);
}

void WebPage::voicesDidChange()
{
    if (auto observer = corePage()->speechSynthesisClient()->observer())
        observer->voicesChanged();
}
#endif

#if ENABLE(ATTACHMENT_ELEMENT)

void WebPage::insertAttachment(const String& identifier, std::optional<uint64_t>&& fileSize, const String& fileName, const String& contentType, CompletionHandler<void()>&& callback)
{
    RefPtr frame = corePage()->focusController().focusedOrMainFrame();
    if (!frame)
        return callback();

    protect(frame->editor())->insertAttachment(identifier, WTF::move(fileSize), AtomString { fileName }, AtomString { contentType });
    callback();
}

void WebPage::updateAttachmentAttributes(const String& identifier, std::optional<uint64_t>&& fileSize, const String& contentType, const String& fileName, const IPC::SharedBufferReference& associatedElementData, CompletionHandler<void()>&& callback)
{
    if (RefPtr attachment = attachmentElementWithIdentifier(identifier)) {
        protect(attachment->document())->updateLayout();
        attachment->updateAttributes(WTF::move(fileSize), AtomString { contentType }, AtomString { fileName });
        attachment->updateAssociatedElementWithData(contentType, associatedElementData.isNull() ? WebCore::SharedBuffer::create() : associatedElementData.unsafeBuffer().releaseNonNull());
    }
    callback();
}

void WebPage::updateAttachmentIcon(const String& identifier, std::optional<ShareableBitmap::Handle>&& iconHandle, const WebCore::FloatSize& size)
{
    if (RefPtr attachment = attachmentElementWithIdentifier(identifier)) {
        if (auto icon = iconHandle ? ShareableBitmap::create(WTF::move(*iconHandle)) : nullptr) {
            if (attachment->isWideLayout()) {
                if (auto imageBuffer = ImageBuffer::create(icon->size(), RenderingMode::Unaccelerated, RenderingPurpose::Unspecified, 1.0, DestinationColorSpace::SRGB(), PixelFormat::BGRA8)) {
                    icon->paint(imageBuffer->context(), IntPoint::zero(), IntRect(IntPoint::zero(), icon->size()));
                    attachment->updateIconForWideLayout(encodeData(WTF::move(imageBuffer), "image/png"_s));
                    return;
                }
            } else {
                attachment->updateIconForNarrowLayout(icon->createImage(), size);
                return;
            }
        }

        if (attachment->isWideLayout())
            attachment->updateIconForWideLayout({ });
        else
            attachment->updateIconForNarrowLayout({ }, size);
    }
}

void WebPage::requestAttachmentIcon(const String& identifier, const WebCore::FloatSize& size)
{
    if (RefPtr attachment = attachmentElementWithIdentifier(identifier)) {
        String fileName;
        if (RefPtr file = attachment->file())
            fileName = file->path();
        send(Messages::WebPageProxy::RequestAttachmentIcon(identifier, attachment->attachmentType(), fileName, attachment->attachmentTitle(), size));
    }
}

RefPtr<HTMLAttachmentElement> WebPage::attachmentElementWithIdentifier(const String& identifier) const
{
    // FIXME: Handle attachment elements in subframes too as well.
    if (RefPtr localTopDocument = this->localTopDocument())
        return localTopDocument->attachmentForIdentifier(identifier);

    return nullptr;
}

#endif // ENABLE(ATTACHMENT_ELEMENT)

#if ENABLE(APPLICATION_MANIFEST)

void WebPage::getApplicationManifest(CompletionHandler<void(const std::optional<WebCore::ApplicationManifest>&)>&& completionHandler)
{
    RefPtr mainFrameDocument = m_mainFrame->coreLocalFrame()->document();
    RefPtr loader = mainFrameDocument ? mainFrameDocument->loader() : nullptr;
    if (!loader)
        return completionHandler(std::nullopt);

    loader->loadApplicationManifest(WTF::move(completionHandler));
}

#endif // ENABLE(APPLICATION_MANIFEST)

void WebPage::getTextFragmentMatch(CompletionHandler<void(const String&)>&& completionHandler)
{
    if (!m_mainFrame->coreLocalFrame()) {
        completionHandler({ });
        return;
    }

    RefPtr document = m_mainFrame->coreLocalFrame()->document();
    if (!document) {
        completionHandler({ });
        return;
    }

    auto fragmentDirective = document->fragmentDirective();
    if (fragmentDirective.isEmpty()) {
        completionHandler({ });
        return;
    }
    FragmentDirectiveParser fragmentDirectiveParser(fragmentDirective);
    if (!fragmentDirectiveParser.isValid()) {
        completionHandler({ });
        return;
    }

    auto parsedTextDirectives = fragmentDirectiveParser.parsedTextDirectives();
    auto highlightRanges = FragmentDirectiveRangeFinder::findRangesFromTextDirectives(parsedTextDirectives, *document);
    if (highlightRanges.isEmpty()) {
        completionHandler({ });
        return;
    }

    completionHandler(plainText(highlightRanges.first()));
}

void WebPage::updateCurrentModifierState(OptionSet<PlatformEvent::Modifier> modifiers)
{
    PlatformKeyboardEvent::setCurrentModifierState(modifiers);
}

#if !PLATFORM(IOS_FAMILY)

WebCore::IntRect WebPage::rectForElementAtInteractionLocation() const
{
    return { };
}

void WebPage::updateInputContextAfterBlurringAndRefocusingElementIfNeeded(Element&)
{
}

#endif // !PLATFORM(IOS_FAMILY)

void WebPage::setCanShowPlaceholder(const WebCore::ElementContext& elementContext, bool canShowPlaceholder)
{
    RefPtr<Element> element = elementForContext(elementContext);
    if (RefPtr textFormControl = dynamicDowncast<HTMLTextFormControlElement>(element))
        textFormControl->setCanShowPlaceholder(canShowPlaceholder);
}

RefPtr<Element> WebPage::elementForContext(const ElementContext& elementContext) const
{
    if (elementContext.webPageIdentifier != m_identifier)
        return nullptr;

    RefPtr element = elementContext.nodeIdentifier ? dynamicDowncast<Element>(Node::fromIdentifier(*elementContext.nodeIdentifier)) : nullptr;
    if (!element)
        return nullptr;

    if (!element->isConnected() || element->document().identifier() != elementContext.documentIdentifier || element->document().page() != m_page.get())
        return nullptr;

    return element;
}

std::optional<WebCore::ElementContext> WebPage::contextForElement(const WebCore::Element& element) const
{
    Ref document = element.document();
    if (!m_page || document->page() != m_page.get())
        return std::nullopt;

    RefPtr frame = document->frame();
    if (!frame)
        return std::nullopt;

    return WebCore::ElementContext { element.boundingBoxInRootViewCoordinates(), m_identifier, document->identifier(), element.nodeIdentifier() };
}

void WebPage::startTextManipulations(Vector<WebCore::TextManipulationController::ExclusionRule>&& exclusionRules, bool includeSubframes, CompletionHandler<void()>&& completionHandler)
{
    if (!m_page)
        return completionHandler();

    m_internals->textManipulationExclusionRules = WTF::move(exclusionRules);
    m_textManipulationIncludesSubframes = includeSubframes;
    if (m_textManipulationIncludesSubframes) {
        for (RefPtr<Frame> frame = m_mainFrame->coreFrame(); frame; frame = frame->tree().traverseNext())
            startTextManipulationForFrame(*frame);
    } else if (RefPtr frame = m_mainFrame->coreLocalFrame())
        startTextManipulationForFrame(*frame);

    // For now, we assume startObservingParagraphs find all paragraphs synchronously at once.
    completionHandler();
}

void WebPage::startTextManipulationForFrame(WebCore::Frame& frame)
{
    RefPtr localFrame = dynamicDowncast<LocalFrame>(frame);
    RefPtr document = localFrame ? localFrame->document() : nullptr;
    if (!document || document->textManipulationControllerIfExists())
        return;

    auto exclusionRules = *m_internals->textManipulationExclusionRules;
    protect(document->textManipulationController())->startObservingParagraphs([webPage = WeakPtr { *this }] (Document& document, const Vector<WebCore::TextManipulationItem>& items) {
        RefPtr frame = document.frame();
        if (!webPage || !frame)
            return;

        RefPtr webFrame = WebFrame::fromCoreFrame(*frame);
        if (!webFrame)
            return;

        webPage->send(Messages::WebPageProxy::DidFindTextManipulationItems(items));
    }, WTF::move(exclusionRules));
}

void WebPage::completeTextManipulation(const Vector<WebCore::TextManipulationItem>& items,
    CompletionHandler<void(const WebCore::TextManipulationController::ManipulationResult&)>&& completionHandler)
{
    if (!m_page) {
        completionHandler({ });
        return;
    }

    if (items.isEmpty()) {
        completionHandler({ });
        return;
    }

    auto currentFrameID = items[0].frameID;

    auto completeManipulationForItems = [&](const Vector<WebCore::TextManipulationItem>& items) -> WebCore::TextManipulationController::ManipulationResult {
        ASSERT(!items.isEmpty());
        RefPtr frame = WebProcess::singleton().webFrame(currentFrameID);
        if (!frame)
            return { };

        RefPtr coreFrame = frame->coreLocalFrame();
        if (!coreFrame)
            return { };

        CheckedPtr controller = coreFrame->document()->textManipulationControllerIfExists();
        if (!controller)
            return { };

        return controller->completeManipulation(items);
    };

    bool containsItemsForMultipleFrames = std::ranges::any_of(items, [&](auto& item) {
        return currentFrameID != item.frameID;
    });
    if (!containsItemsForMultipleFrames)
        return completionHandler(completeManipulationForItems(items));

    WebCore::TextManipulationController::ManipulationResult resultForAllItems;

    auto completeManipulationForCurrentFrame = [&](uint64_t startIndexForCurrentFrame, Vector<WebCore::TextManipulationItem> itemsForCurrentFrame) {
        auto result = completeManipulationForItems(std::exchange(itemsForCurrentFrame, { }));
        for (auto& failure : result.failures)
            failure.index += startIndexForCurrentFrame;
        for (auto& index : result.succeededIndexes)
            index += startIndexForCurrentFrame;
        resultForAllItems.failures.appendVector(WTF::move(result.failures));
        resultForAllItems.succeededIndexes.appendVector(WTF::move(result.succeededIndexes));
    };

    uint64_t indexForCurrentItem = 0;
    uint64_t itemCount = 0;
    for (auto& item : items) {
        if (currentFrameID != item.frameID) {
            RELEASE_ASSERT(indexForCurrentItem >= itemCount);
            completeManipulationForCurrentFrame(indexForCurrentItem - itemCount, items.subspan(indexForCurrentItem - itemCount, itemCount));
            currentFrameID = item.frameID;
            itemCount = 0;
        }
        ++indexForCurrentItem;
        ++itemCount;
    }
    RELEASE_ASSERT(indexForCurrentItem >= itemCount);
    completeManipulationForCurrentFrame(indexForCurrentItem - itemCount, items.subspan(indexForCurrentItem - itemCount, itemCount));

    completionHandler(resultForAllItems);
}

PAL::SessionID WebPage::sessionID() const
{
    return WebProcess::singleton().sessionID();
}

bool WebPage::usesEphemeralSession() const
{
    return sessionID().isEphemeral();
}

void WebPage::configureLoggingChannel(const String& channelName, WTFLogChannelState state, WTFLogLevel level)
{
#if ENABLE(GPU_PROCESS)
    if (RefPtr gpuProcessConnection = WebProcess::singleton().existingGPUProcessConnection())
        gpuProcessConnection->configureLoggingChannel(channelName, state, level);
#endif

#if ENABLE(MODEL_PROCESS)
    if (auto* modelProcessConnection = WebProcess::singleton().existingModelProcessConnection())
        modelProcessConnection->configureLoggingChannel(channelName, state, level);
#endif

    send(Messages::WebPageProxy::ConfigureLoggingChannel(channelName, state, level));
}

#if !PLATFORM(COCOA)

void WebPage::getPDFFirstPageSize(WebCore::FrameIdentifier, CompletionHandler<void(WebCore::FloatSize)>&& completionHandler)
{
    completionHandler({ });
}

void WebPage::getProcessDisplayName(CompletionHandler<void(String&&)>&& completionHandler)
{
    completionHandler({ });
}

void WebPage::updateMockAccessibilityElementAfterCommittingLoad()
{
}

#endif

#if !PLATFORM(IOS_FAMILY) || !ENABLE(DRAG_SUPPORT)

void WebPage::didFinishLoadingImageForElement(WebCore::HTMLImageElement&)
{
}

#endif

#if ENABLE(MODEL_PROCESS)
void WebPage::setHasModelElement(bool hasModelElement)
{
    send(Messages::WebPageProxy::SetHasModelElement(hasModelElement));
}
#endif

#if ENABLE(TEXT_AUTOSIZING)
void WebPage::textAutoSizingAdjustmentTimerFired()
{
    protect(corePage())->recomputeTextAutoSizingInAllFrames();
}

void WebPage::textAutosizingUsesIdempotentModeChanged()
{
    if (!m_page->settings().textAutosizingUsesIdempotentMode())
        m_textAutoSizingAdjustmentTimer.stop();
}
#endif // ENABLE(TEXT_AUTOSIZING)

#if ENABLE(WEBXR)
PlatformXRSystemProxy& WebPage::xrSystemProxy()
{
    if (!m_xrSystemProxy)
        lazyInitialize(m_xrSystemProxy, makeUniqueWithoutRefCountedCheck<PlatformXRSystemProxy>(*this));
    return *m_xrSystemProxy;
}
#endif

void WebPage::setOverriddenMediaType(const String& mediaType)
{
    if (mediaType == m_overriddenMediaType)
        return;

    m_overriddenMediaType = AtomString(mediaType);
    protect(corePage())->updateStyleAfterChangeInEnvironment();
}

void WebPage::updateCORSDisablingPatterns(Vector<String>&& patterns)
{
    RefPtr page = m_page;
    if (!page)
        return;

    m_corsDisablingPatterns = WTF::move(patterns);
    synchronizeCORSDisablingPatternsWithNetworkProcess();
    page->setCORSDisablingPatterns(parseAndAllowAccessToCORSDisablingPatterns(m_corsDisablingPatterns));
}

void WebPage::synchronizeCORSDisablingPatternsWithNetworkProcess()
{
    // FIXME: We should probably have this mechanism done between UIProcess and NetworkProcess directly.
    WebProcess::singleton().ensureNetworkProcessConnection().connection().send(Messages::NetworkConnectionToWebProcess::SetCORSDisablingPatterns(m_identifier, m_corsDisablingPatterns), 0);
}

#if ENABLE(ACCESSIBILITY_ANIMATION_CONTROL)
void WebPage::isAnyAnimationAllowedToPlayDidChange(bool anyAnimationCanPlay)
{
    send(Messages::WebPageProxy::IsAnyAnimationAllowedToPlayDidChange(anyAnimationCanPlay));
}
#endif

void WebPage::isPlayingMediaDidChange(WebCore::MediaProducerMediaStateFlags state)
{
    send(Messages::WebPageProxy::IsPlayingMediaDidChange(state));
}

#if ENABLE(MEDIA_USAGE)
void WebPage::addMediaUsageManagerSession(MediaSessionIdentifier identifier, const String& bundleIdentifier, const URL& pageURL)
{
    send(Messages::WebPageProxy::AddMediaUsageManagerSession(identifier, bundleIdentifier, pageURL));
}

void WebPage::updateMediaUsageManagerSessionState(MediaSessionIdentifier identifier, const MediaUsageInfo& usage)
{
    send(Messages::WebPageProxy::UpdateMediaUsageManagerSessionState(identifier, usage));
}

void WebPage::removeMediaUsageManagerSession(MediaSessionIdentifier identifier)
{
    send(Messages::WebPageProxy::RemoveMediaUsageManagerSession(identifier));
}
#endif // ENABLE(MEDIA_USAGE)

#if ENABLE(IMAGE_ANALYSIS)

void WebPage::requestTextRecognition(Element& element, TextRecognitionOptions&& options, CompletionHandler<void(RefPtr<Element>&&)>&& completion)
{
    RefPtr htmlElement = dynamicDowncast<HTMLElement>(element);
    if (!htmlElement) {
        if (completion)
            completion({ });
        return;
    }

    if (corePage()->hasCachedTextRecognitionResult(*htmlElement)) {
        if (completion) {
            RefPtr<Element> imageOverlayHost;
            if (ImageOverlay::hasOverlay(*htmlElement))
                imageOverlayHost = element;
            completion(WTF::move(imageOverlayHost));
        }
        return;
    }

    auto matchIndex = m_elementsPendingTextRecognition.findIf([&] (auto& elementAndCompletionHandlers) {
        return elementAndCompletionHandlers.first == &element;
    });

    if (matchIndex != notFound) {
        if (completion)
            m_elementsPendingTextRecognition[matchIndex].second.append(WTF::move(completion));
        return;
    }

    CheckedPtr renderImage = dynamicDowncast<RenderImage>(element.renderer());
    if (!renderImage) {
        if (completion)
            completion({ });
        return;
    }

    Vector<CompletionHandler<void(RefPtr<Element>&&)>> completionHandlers;
    if (completion)
        completionHandlers.append(WTF::move(completion));
    m_elementsPendingTextRecognition.append({ WeakPtr { element }, WTF::move(completionHandlers) });

    auto bitmap = createShareableBitmapAsync(*renderImage, {
        std::nullopt,
        AllowAnimatedImages::No,
        options.allowSnapshots == TextRecognitionOptions::AllowSnapshots::Yes ? UseSnapshotForTransparentImages::Yes : UseSnapshotForTransparentImages::No
    })->whenSettled(RunLoop::mainSingleton(), [weakThis = WeakPtr { *this }, weakElement = WeakPtr { *htmlElement }, options = WTF::move(options)](auto&& result) mutable {

        auto resolveAndRemoveHandlerFollowingError = [weakPage = weakThis](WeakPtr<WebCore::HTMLElement, WebCore::WeakPtrImplWithEventTargetData>& originalElement) {
            RefPtr page = weakPage.get();
            if (!page)
                return;

            page->m_elementsPendingTextRecognition.removeAllMatching([&] (auto& elementAndCompletionHandlers) {
                auto& [element, completionHandlers] = elementAndCompletionHandlers;
                if (element.get() && originalElement != element)
                    return false;

                for (auto& completionHandler : completionHandlers) {
                    if (completionHandler)
                        completionHandler({ });
                }
                return true;
            });
        };

        if (!weakThis || !result || !weakElement) {
            resolveAndRemoveHandlerFollowingError(weakElement);
            return;
        }

        auto bitmapHandle = (*result)->createHandle();
        if (!bitmapHandle) {
            resolveAndRemoveHandlerFollowingError(weakElement);
            return;
        }

        CheckedPtr renderImage = dynamicDowncast<RenderImage>(weakElement->renderer());
        if (!renderImage) {
            resolveAndRemoveHandlerFollowingError(weakElement);
            return;
        }

        RefPtr protectedThis = weakThis.get();
        if (!protectedThis)
            return;

        RefPtr cachedImage = renderImage->cachedImage();
        auto imageURL = cachedImage ? protect(weakElement->document())->completeURL(cachedImage->url().string()) : URL { };
        protectedThis->sendWithAsyncReply(Messages::WebPageProxy::RequestTextRecognition(WTF::move(imageURL), WTF::move(*bitmapHandle), options.sourceLanguageIdentifier, options.targetLanguageIdentifier), [weakThis, weakElement, resolveAndRemoveHandlerFollowingError = WTF::move(resolveAndRemoveHandlerFollowingError)] (auto&& result) mutable {
            RefPtr protectedThis = weakThis.get();
            if (!protectedThis)
                return;

            RefPtr htmlElement = weakElement.get();
            if (!htmlElement) {
                resolveAndRemoveHandlerFollowingError(weakElement);
                return;
            }

            ImageOverlay::updateWithTextRecognitionResult(*htmlElement, result);

            auto matchIndex = protectedThis->m_elementsPendingTextRecognition.findIf([&] (auto& elementAndCompletionHandlers) {
                return elementAndCompletionHandlers.first == htmlElement.get();
            });

            if (matchIndex == notFound)
                return;

            RefPtr imageOverlayHost = ImageOverlay::hasOverlay(*htmlElement) ? htmlElement.get() : nullptr;
            for (auto& completionHandler : protectedThis->m_elementsPendingTextRecognition[matchIndex].second)
                completionHandler(imageOverlayHost.copyRef());

            protectedThis->m_elementsPendingTextRecognition.removeAt(matchIndex);
        });
    });
}

void WebPage::updateWithTextRecognitionResult(const TextRecognitionResult& result, const ElementContext& context, const FloatPoint& location, CompletionHandler<void(TextRecognitionUpdateResult)>&& completionHandler)
{
    auto elementToUpdate = elementForContext(context);
    RefPtr htmlElementToUpdate = dynamicDowncast<HTMLElement>(elementToUpdate);
    if (!htmlElementToUpdate) {
        completionHandler(TextRecognitionUpdateResult::NoText);
        return;
    }

    RefPtr localMainFrame = dynamicDowncast<WebCore::LocalFrame>(corePage()->mainFrame());
    if (!localMainFrame) {
        completionHandler(TextRecognitionUpdateResult::NoText);
        return;
    }

    ImageOverlay::updateWithTextRecognitionResult(*htmlElementToUpdate, result);
    auto hitTestResult = localMainFrame->eventHandler().hitTestResultAtPoint(roundedIntPoint(location), {
        HitTestRequest::Type::ReadOnly,
        HitTestRequest::Type::Active,
        HitTestRequest::Type::AllowVisibleChildFrameContentOnly,
    });

    RefPtr nodeAtLocation = hitTestResult.innerNonSharedNode();
    auto updateResult = ([&] {
        if (!nodeAtLocation || nodeAtLocation->shadowHost() != elementToUpdate || !ImageOverlay::isInsideOverlay(*nodeAtLocation))
            return TextRecognitionUpdateResult::NoText;

#if ENABLE(DATA_DETECTION)
        if (DataDetection::findDataDetectionResultElementInImageOverlay(location, *htmlElementToUpdate))
            return TextRecognitionUpdateResult::DataDetector;
#endif

        if (ImageOverlay::isOverlayText(*nodeAtLocation))
            return TextRecognitionUpdateResult::Text;

        return TextRecognitionUpdateResult::NoText;
    })();

    completionHandler(updateResult);
}

void WebPage::startVisualTranslation(const String& sourceLanguageIdentifier, const String& targetLanguageIdentifier)
{
    RefPtr frame = m_mainFrame->coreFrame();
    if (!frame)
        return;

    protect(protect(corePage())->imageAnalysisQueue())->enqueueAllImagesIfNeeded(*frame, sourceLanguageIdentifier, targetLanguageIdentifier);
}

#endif // ENABLE(IMAGE_ANALYSIS)

void WebPage::requestImageBitmap(const ElementContext& context, CompletionHandler<void(std::optional<ShareableBitmap::Handle>&&, const String& sourceMIMEType)>&& completion)
{
    RefPtr element = elementForContext(context);
    if (!element) {
        completion({ }, { });
        return;
    }

    CheckedPtr renderImage = dynamicDowncast<RenderImage>(element->renderer());
    if (!renderImage) {
        completion({ }, { });
        return;
    }

    auto bitmap = createShareableBitmap(*renderImage);
    if (!bitmap) {
        completion({ }, { });
        return;
    }

    auto handle = bitmap->createHandle();
    if (!handle) {
        completion({ }, { });
        return;
    }

    String mimeType;
    if (RefPtr cachedImage = renderImage->cachedImage()) {
        if (RefPtr image = cachedImage->image())
            mimeType = image->mimeType();
    }
    ASSERT(!mimeType.isEmpty());
    completion(WTF::move(*handle), mimeType);
}

#if ENABLE(MEDIA_CONTROLS_CONTEXT_MENUS) && USE(UICONTEXTMENU)
void WebPage::showMediaControlsContextMenu(FloatRect&& targetFrame, Vector<MediaControlsContextMenuItem>&& items, WebCore::HTMLMediaElementIdentifier identifier, CompletionHandler<void(MediaControlsContextMenuItem::ID)>&& completionHandler)
{
    RefPtr frame = m_mainFrame->coreFrame();
    if (!frame) {
        completionHandler(MediaControlsContextMenuItem::invalidID);
        return;
    }

    sendWithAsyncReply(Messages::WebPageProxy::ShowMediaControlsContextMenu(WTF::move(targetFrame), WTF::move(items), protect(WebFrame::fromCoreFrame(*frame))->info(), identifier), completionHandler);
}
#endif // ENABLE(MEDIA_CONTROLS_CONTEXT_MENUS) && USE(UICONTEXTMENU)

#if !PLATFORM(IOS_FAMILY)

void WebPage::animationDidFinishForElement(const WebCore::Element&)
{
}

#endif

#if ENABLE(APP_BOUND_DOMAINS)
void WebPage::setIsNavigatingToAppBoundDomain(std::optional<NavigatingToAppBoundDomain> isNavigatingToAppBoundDomain, WebFrame& frame)
{
    frame.setIsNavigatingToAppBoundDomain(isNavigatingToAppBoundDomain);

    m_navigationHasOccured = true;
}

void WebPage::notifyPageOfAppBoundBehavior()
{
    if (!m_navigationHasOccured && !m_limitsNavigationsToAppBoundDomains)
        send(Messages::WebPageProxy::SetHasExecutedAppBoundBehaviorBeforeNavigation());
}
#endif

#if ENABLE(GPU_PROCESS)
RemoteRenderingBackendProxy& WebPage::ensureRemoteRenderingBackendProxy()
{
    if (!m_remoteRenderingBackendProxy)
        m_remoteRenderingBackendProxy = RemoteRenderingBackendProxy::create(*this);
    return *m_remoteRenderingBackendProxy;
}
#endif

Vector<Ref<SandboxExtension>> WebPage::consumeSandboxExtensions(Vector<SandboxExtension::Handle>&& sandboxExtensions)
{
    return WTF::compactMap(WTF::move(sandboxExtensions), [](SandboxExtension::Handle&& sandboxExtension) -> RefPtr<SandboxExtension> {
        auto extension = SandboxExtension::create(WTF::move(sandboxExtension));
        if (!extension)
            return nullptr;
        bool ok = extension->consume();
        ASSERT_UNUSED(ok, ok);
        return extension;
    });
}

void WebPage::revokeSandboxExtensions(Vector<Ref<SandboxExtension>>& sandboxExtensions)
{
    for (auto& sandboxExtension : sandboxExtensions)
        sandboxExtension->revoke();
    sandboxExtensions.clear();
}

void WebPage::createTextFragmentDirectiveFromSelection(CompletionHandler<void(URL&&)>&& completionHandler)
{
    auto url = protect(corePage())->fragmentDirectiveURLForSelectedText();
    completionHandler(WTF::move(url));
}

void WebPage::getTextFragmentRanges(CompletionHandler<void(const Vector<EditingRange>&&)>&& completionHandler)
{
    RefPtr focusedOrMainFrame = corePage()->focusController().focusedOrMainFrame();
    if (!focusedOrMainFrame) {
        completionHandler({ });
        return;
    }
    RefPtr document = focusedOrMainFrame->document();

    RefPtr frame = document->frame();
    if (!frame) {
        completionHandler({ });
        return;
    }

    Vector<EditingRange> editingRanges;
    if (RefPtr highlightRegistry = document->fragmentHighlightRegistryIfExists()) {
        for (auto& highlight : highlightRegistry->map()) {
            for (auto& highlightRange : highlight.value->highlightRanges()) {
                Ref<AbstractRange> range = highlightRange->range();
                editingRanges.append(EditingRange::fromRange(*frame, makeSimpleRange(range)));
            }
        }
    }

    completionHandler(WTF::move(editingRanges));
}

#if ENABLE(APP_HIGHLIGHTS)
WebCore::CreateNewGroupForHighlight WebPage::highlightIsNewGroup() const
{
    return m_internals->highlightIsNewGroup;
}

WebCore::HighlightRequestOriginatedInApp WebPage::highlightRequestOriginatedInApp() const
{
    return m_internals->highlightRequestOriginatedInApp;
}

void WebPage::createAppHighlightInSelectedRange(WebCore::CreateNewGroupForHighlight createNewGroup, WebCore::HighlightRequestOriginatedInApp requestOriginatedInApp, CompletionHandler<void(WebCore::AppHighlight&&)>&& completionHandler)
{
    SetForScope highlightIsNewGroupScope { m_internals->highlightIsNewGroup, createNewGroup };
    SetForScope highlightRequestOriginScope { m_internals->highlightRequestOriginatedInApp, requestOriginatedInApp };

    RefPtr focusedOrMainFrame = corePage()->focusController().focusedOrMainFrame();
    if (!focusedOrMainFrame)
        return;
    RefPtr document = focusedOrMainFrame->document();

    RefPtr frame = document->frame();
    if (!frame)
        return;

    auto selectionRange = frame->selection().selection().toNormalizedRange();
    if (!selectionRange)
        return;

    protect(document->appHighlightRegistry())->addAnnotationHighlightWithRange(StaticRange::create(selectionRange.value()));
    document->appHighlightStorage().storeAppHighlight(StaticRange::create(selectionRange.value()), [completionHandler = WTF::move(completionHandler), protectedThis = Ref { *this }, this] (WebCore::AppHighlight&& highlight) mutable {
        highlight.isNewGroup = m_internals->highlightIsNewGroup;
        highlight.requestOriginatedInApp = m_internals->highlightRequestOriginatedInApp;
        completionHandler(WTF::move(highlight));
    });
}

void WebPage::restoreAppHighlightsAndScrollToIndex(Vector<SharedMemory::Handle>&& memoryHandles, const std::optional<unsigned> index)
{
    RefPtr focusedOrMainFrame = corePage()->focusController().focusedOrMainFrame();
    if (!focusedOrMainFrame)
        return;
    RefPtr document = focusedOrMainFrame->document();

    unsigned i = 0;
    for (auto&& handle : memoryHandles) {
        auto sharedMemory = SharedMemory::map(WTF::move(handle), SharedMemory::Protection::ReadOnly);
        if (!sharedMemory)
            continue;

        document->appHighlightStorage().restoreAndScrollToAppHighlight(sharedMemory->createSharedBuffer(handle.size()), i == index ? ScrollToHighlight::Yes : ScrollToHighlight::No);
        i++;
    }
}

void WebPage::setAppHighlightsVisibility(WebCore::HighlightVisibility appHighlightVisibility)
{
    m_appHighlightsVisible = appHighlightVisibility;
    for (RefPtr<Frame> frame = m_mainFrame->coreLocalFrame(); frame; frame = frame->tree().traverseNextRendered()) {
        RefPtr localFrame = dynamicDowncast<LocalFrame>(frame.get());
        if (!localFrame)
            continue;
        if (RefPtr document = localFrame->document())
            protect(document->appHighlightRegistry())->setHighlightVisibility(appHighlightVisibility);
    }
}

#endif

#if ENABLE(MEDIA_SESSION_COORDINATOR)
void WebPage::createMediaSessionCoordinator(const String& identifier, CompletionHandler<void(bool)>&& completionHandler)
{
    RefPtr document = m_mainFrame->coreLocalFrame()->document();
    if (!document || !document->window()) {
        completionHandler(false);
        return;
    }

    protect(corePage())->setMediaSessionCoordinator(RemoteMediaSessionCoordinator::create(*this, identifier));
    completionHandler(true);
}
#endif

void WebPage::lastNavigationWasAppInitiated(CompletionHandler<void(bool)>&& completionHandler)
{
    RefPtr localTopDocument = this->localTopDocument();
    if (!localTopDocument)
        return completionHandler(false);
    return completionHandler(localTopDocument->loader()->lastNavigationWasAppInitiated());
}

#if HAVE(TRANSLATION_UI_SERVICES) && ENABLE(CONTEXT_MENUS)

void WebPage::handleContextMenuTranslation(const TranslationContextMenuInfo& info)
{
    send(Messages::WebPageProxy::HandleContextMenuTranslation(info));
}
#endif

void WebPage::scrollToRect(const WebCore::FloatRect& targetRect, const WebCore::FloatPoint&)
{
    RefPtr frameView = localMainFrameView();
    if (!frameView)
        return;
    frameView->setScrollPosition(IntPoint(targetRect.minXMinYCorner()));
}

void WebPage::setContentOffset(std::optional<int> x, std::optional<int> y, WebCore::ScrollIsAnimated animated)
{
    RefPtr frameView = localMainFrameView();
    if (!frameView)
        return;

    auto options = WebCore::ScrollPositionChangeOptions::createProgrammatic();
    options.animated = animated;

    frameView->setScrollOffsetWithOptions(x, y, options);
}

void WebPage::scrollToEdge(WebCore::RectEdges<bool> edges, WebCore::ScrollIsAnimated animated)
{
    RefPtr frameView = localMainFrameView();
    if (!frameView)
        return;

    auto options = WebCore::ScrollPositionChangeOptions::createProgrammatic();
    options.animated = animated;

    frameView->scrollToEdgeWithOptions(edges, options);
}

#if ENABLE(IMAGE_ANALYSIS) && ENABLE(VIDEO)
void WebPage::beginTextRecognitionForVideoInElementFullScreen(const HTMLVideoElement& element)
{
    CheckedPtr renderer = element.renderer();
    if (!renderer)
        return;

    auto rectInRootView = renderer->videoBoxInRootView();
    if (rectInRootView.isEmpty())
        return;

    m_elementIsPerformingTextRecognitionInElementFullScreen = element.identifier();
    element.bitmapImageForCurrentTime()->whenSettled(RunLoop::mainSingleton(), [weakThis = WeakPtr { *this }, rectInRootView, identifier = element.identifier()](auto&& result) {
        if (!result)
            return;
        RefPtr protectedThis = weakThis.get();
        if (!protectedThis || protectedThis->m_elementIsPerformingTextRecognitionInElementFullScreen != identifier)
            return;
        if (auto handle = (*result)->createHandle())
            protectedThis->send(Messages::WebPageProxy::BeginTextRecognitionForVideoInElementFullScreen(processQualify(identifier), WTF::move(*handle), rectInRootView));
        protectedThis->m_elementIsPerformingTextRecognitionInElementFullScreen.reset();
    });
}

void WebPage::cancelTextRecognitionForVideoInElementFullScreen()
{
    m_elementIsPerformingTextRecognitionInElementFullScreen.reset();
    send(Messages::WebPageProxy::CancelTextRecognitionForVideoInElementFullScreen());
}
#endif // ENABLE(IMAGE_ANALYSIS) && ENABLE(VIDEO)


#if ENABLE(IMAGE_ANALYSIS_ENHANCEMENTS)

void WebPage::shouldAllowRemoveBackground(const ElementContext& context, CompletionHandler<void(bool)>&& completion) const
{
    auto element = elementForContext(context);
    completion(element && !m_elementsToExcludeFromRemoveBackground.contains(*element));
}

#endif

#if HAVE(UIKIT_RESIZABLE_WINDOWS)

void WebPage::setIsWindowResizingEnabled(bool value)
{
    if (m_isWindowResizingEnabled == value)
        return;

    m_isWindowResizingEnabled = value;
    m_viewportConfiguration.setPrefersHorizontalScrollingBelowDesktopViewportWidths(shouldEnableViewportBehaviorsForResizableWindows());
}

#endif // HAVE(UIKIT_RESIZABLE_WINDOWS)

#if ENABLE(INTERACTION_REGIONS_IN_EVENT_REGION)

void WebPage::setInteractionRegionsEnabled(bool enable)
{
    WEBPAGE_RELEASE_LOG(Process, "setInteractionRegionsEnabled: enable state = %d for page %p", (int)enable, (void*)m_page.get());
    if (!m_page)
        return;

    m_page->setInteractionRegionsEnabled(enable);
}

#endif // ENABLE(INTERACTION_REGIONS_IN_EVENT_REGION)

bool WebPage::handlesPageScaleGesture()
{
#if !ENABLE(PDF_PLUGIN)
    return false;
#else
    RefPtr plugin = mainFramePlugIn();
    return plugin && plugin->pluginHandlesPageScaleFactor();
#endif
}

void WebPage::generateTestReport(String&& message, String&& group)
{
    if (RefPtr localTopDocument = this->localTopDocument())
        protect(localTopDocument->reportingScope())->generateTestReport(WTF::move(message), WTF::move(group));
}

#if ENABLE(ACCESSIBILITY_ANIMATION_CONTROL)
void WebPage::updateImageAnimationEnabled()
{
    protect(corePage())->setImageAnimationEnabled(WebProcess::singleton().imageAnimationEnabled());
}

void WebPage::pauseAllAnimations(CompletionHandler<void()>&& completionHandler)
{
    protect(corePage())->setImageAnimationEnabled(false);
    completionHandler();
}

void WebPage::playAllAnimations(CompletionHandler<void()>&& completionHandler)
{
    protect(corePage())->setImageAnimationEnabled(true);
    completionHandler();
}
#endif // ENABLE(ACCESSIBILITY_ANIMATION_CONTROL)

#if ENABLE(ACCESSIBILITY_NON_BLINKING_CURSOR)
void WebPage::updatePrefersNonBlinkingCursor()
{
    if (RefPtr page = corePage()) {
        page->setPrefersNonBlinkingCursor(WebProcess::singleton().prefersNonBlinkingCursor());
        page->forEachDocument([&](auto& document) {
            document.selection().setPrefersNonBlinkingCursor(WebProcess::singleton().prefersNonBlinkingCursor());
        });
    }
}
#endif

bool WebPage::isUsingUISideCompositing() const
{
#if ENABLE(TILED_CA_DRAWING_AREA)
    return m_drawingAreaType == DrawingAreaType::RemoteLayerTree;
#elif PLATFORM(COCOA)
    return true;
#else
    return false;
#endif
}

#if ENABLE(ADVANCED_PRIVACY_PROTECTIONS)

void WebPage::setLinkDecorationFilteringData(Vector<WebCore::LinkDecorationFilteringData>&& strings)
{
    m_internals->linkDecorationFilteringData.clear();

    for (auto& data : strings) {
        if (!m_internals->linkDecorationFilteringData.isValidKey(data.linkDecoration)) {
            WEBPAGE_RELEASE_LOG_ERROR(ResourceLoadStatistics, "Unable to set link decoration filtering data (invalid key)");
            ASSERT_NOT_REACHED();
            continue;
        }

        auto it = m_internals->linkDecorationFilteringData.ensure(data.linkDecoration, [] {
            return Internals::LinkDecorationFilteringConditionals { };
        }).iterator;

        if (!data.domain.isEmpty()) {
            if (auto& domains = it->value.domains; domains.isValidValue(data.domain))
                domains.add(data.domain);
            else
                ASSERT_NOT_REACHED();
        }

        if (!data.path.isEmpty())
            it->value.paths.append(data.path);
    }
}

void WebPage::setAllowedQueryParametersForAdvancedPrivacyProtections(Vector<LinkDecorationFilteringData>&& allowStrings)
{
    m_internals->allowedQueryParametersForAdvancedPrivacyProtections.clear();
    for (auto& data : allowStrings) {
        if (!m_internals->allowedQueryParametersForAdvancedPrivacyProtections.isValidKey(data.domain))
            continue;

        m_internals->allowedQueryParametersForAdvancedPrivacyProtections.ensure(data.domain, [&] {
            return HashSet<String> { };
        }).iterator->value.add(data.linkDecoration);
    }
}

#endif // ENABLE(ADVANCED_PRIVACY_PROTECTIONS)

bool WebPage::shouldSkipDecidePolicyForResponse(const WebCore::ResourceResponse& response) const
{
    if (!m_skipDecidePolicyForResponseIfPossible)
        return false;

    auto statusCode = response.httpStatusCode();
    if (statusCode == httpStatus204NoContent || statusCode >= httpStatus400BadRequest)
        return false;

    if (!equalIgnoringASCIICase(response.mimeType(), "text/html"_s))
        return false;

    if (response.url().protocolIsFile())
        return false;

    if (auto components = response.httpHeaderField(HTTPHeaderName::ContentDisposition).split(';'); !components.isEmpty() && equalIgnoringASCIICase(components[0].trim(isASCIIWhitespaceWithoutFF<char16_t>), "attachment"_s))
        return false;

    return true;
}

const Logger& WebPage::logger() const
{
    if (!m_logger) {
        m_logger = Logger::create(this);
        m_logger->setEnabled(this, isAlwaysOnLoggingAllowed());
    }

    return *m_logger;
}

uint64_t WebPage::logIdentifier() const
{
    return intHash(m_identifier.toUInt64());
}

void WebPage::useRedirectionForCurrentNavigation(WebCore::ResourceResponse&& response)
{
    RefPtr localMainFrame = this->localMainFrame();
    if (!localMainFrame) {
        WEBPAGE_RELEASE_LOG_ERROR(Loading, "WebPage::useRedirectionForCurrentNavigation failed without frame");
        return;
    }

    RefPtr loader = localMainFrame->loader().policyDocumentLoader();
    if (!loader)
        loader = localMainFrame->loader().provisionalDocumentLoader();

    if (!loader) {
        WEBPAGE_RELEASE_LOG_ERROR(Loading, "WebPage::useRedirectionForCurrentNavigation failed without loader");
        return;
    }

    if (RefPtr resourceLoader = loader->mainResourceLoader()) {
        WEBPAGE_RELEASE_LOG(Loading, "WebPage::useRedirectionForCurrentNavigation to network process");
        WebProcess::singleton().ensureNetworkProcessConnection().connection().send(Messages::NetworkConnectionToWebProcess::UseRedirectionForCurrentNavigation(*resourceLoader->identifier(), response), 0);
        return;
    }

    WEBPAGE_RELEASE_LOG(Loading, "WebPage::useRedirectionForCurrentNavigation as substiute data");
    loader->setRedirectionAsSubstituteData(WTF::move(response));
}

void WebPage::dispatchLoadEventToFrameOwnerElement(WebCore::FrameIdentifier frameID)
{
    RefPtr frame = WebProcess::singleton().webFrame(frameID);
    if (!frame)
        return;

    RefPtr coreRemoteFrame = frame->coreRemoteFrame();
    if (!coreRemoteFrame)
        return;

    if (RefPtr ownerElement = coreRemoteFrame->ownerElement())
        ownerElement->dispatchEvent(Event::create(eventNames().loadEvent, Event::CanBubble::No, Event::IsCancelable::No));
}

void WebPage::addResourceTimingFromSubframe(WebCore::FrameIdentifier parentFrameID, WebCore::ResourceTiming&& resourceTiming)
{
    RefPtr frame = WebProcess::singleton().webFrame(parentFrameID);
    if (!frame)
        return;

    RefPtr localFrame = frame->coreLocalFrame();
    if (!localFrame || !localFrame->document())
        return;

    WebCore::ResourceTimingInformation::addResourceTimingToDocument(*protect(localFrame->document()), WTF::move(resourceTiming));
}

void WebPage::elementWasFocusedInAnotherProcess(WebCore::FrameIdentifier frameID, WebCore::FocusOptions options)
{
    RefPtr frame = WebProcess::singleton().webFrame(frameID);
    if (!frame)
        return;
    protect(corePage())->focusController().setFocusedElement(nullptr, protect(frame->coreFrame()).get(), options, WebCore::BroadcastFocusedElement::No);
}

void WebPage::frameWasFocusedInAnotherProcess(std::optional<WebCore::FrameIdentifier>&& frameID)
{
    RefPtr frame = frameID ? WebProcess::singleton().webFrame(*frameID) : nullptr;
    RefPtr coreFrame = frame ? frame->coreFrame() : nullptr;
    corePage()->focusController().setFocusedFrame(coreFrame.get(), WebCore::BroadcastFocusedFrame::No);
}

void WebPage::remotePostMessage(WebCore::FrameIdentifier source, const WebCore::SecurityOriginData& sourceOrigin, WebCore::FrameIdentifier target, std::optional<WebCore::SecurityOriginData>&& targetOrigin, const WebCore::MessageWithMessagePorts& message)
{
    RefPtr targetFrame = WebProcess::singleton().webFrame(target);
    if (!targetFrame)
        return;

    if (!targetFrame->coreLocalFrame())
        return;

    RefPtr targetWindow = targetFrame->coreLocalFrame()->window();
    if (!targetWindow)
        return;

    RefPtr targetCoreFrame = targetWindow->frame();
    if (!targetCoreFrame)
        return;

    RefPtr sourceFrame = WebProcess::singleton().webFrame(source);
    RefPtr sourceWindow = sourceFrame && sourceFrame->coreFrame() ? &sourceFrame->coreFrame()->windowProxy() : nullptr;

    CheckedRef script = targetCoreFrame->script();
    auto globalObject = script->globalObject(WebCore::mainThreadNormalWorldSingleton());
    if (!globalObject)
        return;

    targetWindow->postMessageFromRemoteFrame(*globalObject, WTF::move(sourceWindow), sourceOrigin, WTF::move(targetOrigin), message);
}

void WebPage::renderTreeAsTextForTesting(WebCore::FrameIdentifier frameID, uint64_t baseIndent, OptionSet<WebCore::RenderAsTextFlag> behavior, CompletionHandler<void(String&&)>&& completionHandler)
{
    RefPtr webFrame = WebProcess::singleton().webFrame(frameID);
    if (!webFrame) {
        ASSERT_NOT_REACHED();
        return completionHandler("Test Error - WebFrame missing in web process"_s);
    }

    RefPtr coreLocalFrame = webFrame->coreLocalFrame();
    if (!coreLocalFrame) {
        ASSERT_NOT_REACHED();
        return completionHandler("Test Error - WebFrame missing LocalFrame in web process"_s);
    }

    CheckedPtr renderer = coreLocalFrame->contentRenderer();
    if (!renderer) {
        ASSERT_NOT_REACHED();
        return completionHandler("Test Error - WebFrame missing RenderView in web process"_s);
    }

    auto ts = WebCore::createTextStream(*renderer);
    ts.setIndent(baseIndent);
    WebCore::externalRepresentationForLocalFrame(ts, *coreLocalFrame, behavior);
    completionHandler(ts.release());
}

void WebPage::layerTreeAsTextForTesting(WebCore::FrameIdentifier frameID, uint64_t baseIndent, OptionSet<WebCore::LayerTreeAsTextOptions> options, CompletionHandler<void(String&&)>&& completionHandler)
{
    RefPtr webFrame = WebProcess::singleton().webFrame(frameID);
    if (!webFrame) {
        ASSERT_NOT_REACHED();
        return completionHandler("Test Error - WebFrame missing in web process"_s);
    }

    RefPtr coreLocalFrame = webFrame->coreLocalFrame();
    if (!coreLocalFrame) {
        ASSERT_NOT_REACHED();
        return completionHandler("Test Error - WebFrame missing LocalFrame in web process"_s);
    }

    CheckedPtr renderer = coreLocalFrame->contentRenderer();
    if (!renderer) {
        ASSERT_NOT_REACHED();
        return completionHandler("Test Error - WebFrame missing RenderView in web process"_s);
    }

    auto ts = WebCore::createTextStream(*renderer);
    ts << protect(protect(coreLocalFrame->contentRenderer())->compositor())->layerTreeAsText(options, baseIndent);
    completionHandler(ts.release());
}

void WebPage::frameTextForTesting(WebCore::FrameIdentifier frameID, CompletionHandler<void(String&&)>&& completionHandler)
{
    RefPtr webFrame = WebProcess::singleton().webFrame(frameID);
    if (!webFrame) {
        ASSERT_NOT_REACHED();
        return completionHandler("Test Error - WebFrame missing in web process"_s);
    }
    constexpr bool includeSubframes { true };
    completionHandler(webFrame->frameTextForTesting(includeSubframes));
}

void WebPage::requestAllTextAndRects(CompletionHandler<void(Vector<std::pair<String, WebCore::FloatRect>>&&)>&& completion)
{
    RefPtr page = corePage();
    if (!page)
        return completion({ });

    completion(TextExtraction::extractAllTextAndRects(*page));
}

void WebPage::requestTargetedElement(TargetedElementRequest&& request, CompletionHandler<void(Vector<WebCore::TargetedElementInfo>&&)>&& completion)
{
    RefPtr page = corePage();
    if (!page)
        return completion({ });

    completion(protect(page->elementTargetingController())->findTargets(WTF::move(request)));
}

void WebPage::requestAllTargetableElements(float hitTestInterval, CompletionHandler<void(Vector<Vector<WebCore::TargetedElementInfo>>&&)>&& completion)
{
    RefPtr page = corePage();
    if (!page)
        return completion({ });

    completion(protect(page->elementTargetingController())->findAllTargets(hitTestInterval));
}

void WebPage::hasTextExtractionFilterRules(CompletionHandler<void(bool)>&& completion)
{
    completion(!m_textExtractionFilterRules.isEmpty());
}

void WebPage::updateTextExtractionFilterRules(Vector<WebCore::TextExtraction::FilterRuleData>&& ruleData)
{
    m_textExtractionFilterRules = TextExtraction::extractRules(WTF::move(ruleData));
}

void WebPage::applyTextExtractionFilter(const String& input, std::optional<NodeIdentifier>&& containerNodeID, CompletionHandler<void(const String&)>&& completion)
{
    TextExtraction::applyRules(input, WTF::move(containerNodeID), m_textExtractionFilterRules, Ref { *corePage() }, WTF::move(completion));
}

template<typename T> T WebPage::contentsToRootView(WebCore::FrameIdentifier frameID, T geometry)
{
    RefPtr webFrame = WebProcess::singleton().webFrame(frameID);
    if (!webFrame)
        return geometry;

    RefPtr coreFrame = webFrame->coreFrame();
    if (!coreFrame) {
        ASSERT_NOT_REACHED();
        return geometry;
    }

    RefPtr view = coreFrame->virtualView();
    if (!view) {
        ASSERT_NOT_REACHED();
        return geometry;
    }

    return view->contentsToRootView(geometry);
}

template<typename T> T WebPage::rootViewToContents(WebCore::FrameIdentifier frameID, T geometry)
{
    RefPtr webFrame = WebProcess::singleton().webFrame(frameID);
    if (!webFrame)
        return geometry;

    RefPtr coreFrame = webFrame->coreFrame();
    if (!coreFrame) {
        ASSERT_NOT_REACHED();
        return geometry;
    }

    RefPtr view = coreFrame->virtualView();
    if (!view) {
        ASSERT_NOT_REACHED();
        return geometry;
    }

    return view->rootViewToContents(geometry);
}

void WebPage::contentsToRootViewRect(FrameIdentifier frameID, FloatRect rect, CompletionHandler<void(FloatRect)>&& completionHandler)
{
    completionHandler(contentsToRootView(frameID, rect));
}

void WebPage::contentsToRootViewRects(FrameIdentifier frameID, Vector<FloatRect> rects, CompletionHandler<void(Vector<FloatRect>)>&& completionHandler)
{
    for (auto& rect : rects)
        rect = contentsToRootView(frameID, rect);
    completionHandler(WTF::move(rects));
}

void WebPage::contentsToRootViewPoint(FrameIdentifier frameID, FloatPoint point, CompletionHandler<void(FloatPoint)>&& completionHandler)
{
    completionHandler(contentsToRootView(frameID, point));
}

void WebPage::remoteDictionaryPopupInfoToRootView(WebCore::FrameIdentifier frameID, WebCore::DictionaryPopupInfo popupInfo, CompletionHandler<void(WebCore::DictionaryPopupInfo)>&& completionHandler)
{
    RefPtr textIndicator = popupInfo.textIndicator;
    popupInfo.origin = contentsToRootView<FloatPoint>(frameID, popupInfo.origin);
    if (!textIndicator)
        return completionHandler(popupInfo);
#if PLATFORM(COCOA)
    auto textIndicatorData = textIndicator->data();
    textIndicatorData.selectionRectInRootViewCoordinates = contentsToRootView<FloatRect>(frameID, popupInfo.textIndicator->selectionRectInRootViewCoordinates());
    textIndicatorData.textBoundingRectInRootViewCoordinates = contentsToRootView<FloatRect>(frameID, popupInfo.textIndicator->textBoundingRectInRootViewCoordinates());
    textIndicatorData.contentImageWithoutSelectionRectInRootViewCoordinates = contentsToRootView<FloatRect>(frameID, popupInfo.textIndicator->contentImageWithoutSelectionRectInRootViewCoordinates());

    for (auto& textRect : textIndicatorData.textRectsInBoundingRectCoordinates)
        textRect = contentsToRootView<FloatRect>(frameID, textRect);
#endif
    completionHandler(popupInfo);
}

void WebPage::hitTestAtPoint(WebCore::FrameIdentifier frameID, WebCore::FloatPoint point, CompletionHandler<void(NodeHitTestResult)>&& completionHandler)
{
    RefPtr frame = WebFrame::webFrame(frameID);
    if (!frame)
        return completionHandler({ });

    auto options = WebFrame::defaultHitTestRequestTypes();
    options.remove(HitTestRequest::Type::AllowChildFrameContent);
    options.add(HitTestRequest::Type::SkipTransformToRootFrameCoordinates);
    RefPtr result = frame->hitTest(roundedIntPoint(point), options);
    if (!result)
        return completionHandler({ });

    RefPtr node = result->coreHitTestResult().innerNonSharedNode();
    if (!node)
        return completionHandler({ });

    if (RefPtr frameOwner = dynamicDowncast<HTMLFrameOwnerElement>(node.get())) {
        if (RefPtr contentFrame = frameOwner->contentFrame()) {
            auto transformedCoordinates = rootViewToContents(contentFrame->frameID(), contentsToRootView(frameID, point));
            switch (contentFrame->frameType()) {
            case Frame::FrameType::Remote:
                return completionHandler( { NodeHitTestResult::RemoteFrameInfo { contentFrame->frameID(), transformedCoordinates } });
            case Frame::FrameType::Local:
                return hitTestAtPoint(contentFrame->frameID(), transformedCoordinates, WTF::move(completionHandler));
            }
        }
    }

    RefPtr nodeFrame = node->document().frame();
    if (!nodeFrame)
        return completionHandler({ });

    RefPtr nodeWebFrame = WebFrame::fromCoreFrame(*nodeFrame);
    if (!nodeWebFrame)
        return completionHandler({ });

    auto [handle, info] = nodeWebFrame->createAndPrepareToSendJSHandle(*node);
    completionHandler({ WTF::move(info) });
}

void WebPage::adjustVisibilityForTargetedElements(Vector<TargetedElementAdjustment>&& adjustments, CompletionHandler<void(bool)>&& completion)
{
    RefPtr page = corePage();
    completion(page && protect(page->elementTargetingController())->adjustVisibility(WTF::move(adjustments)));
}

void WebPage::resetVisibilityAdjustmentsForTargetedElements(const Vector<TargetedElementIdentifiers>& identifiers, CompletionHandler<void(bool)>&& completion)
{
    RefPtr page = corePage();
    completion(page && protect(page->elementTargetingController())->resetVisibilityAdjustments(identifiers));
}

void WebPage::takeSnapshotForTargetedElement(NodeIdentifier nodeID, ScriptExecutionContextIdentifier documentID, CompletionHandler<void(std::optional<ShareableBitmapHandle>&&)>&& completion)
{
    RefPtr page = corePage();
    if (!page)
        return completion({ });

    RefPtr image = protect(page->elementTargetingController())->snapshotIgnoringVisibilityAdjustment(nodeID, documentID);
    if (!image)
        return completion({ });

    auto bitmap = ShareableBitmap::create({ IntSize { image->size() } });
    if (!bitmap)
        return completion({ });

    auto context = bitmap->createGraphicsContext();
    if (!context)
        return completion({ });

    context->drawImage(*image, FloatPoint::zero());
    completion(bitmap->createHandle(SharedMemory::Protection::ReadOnly));
}

void WebPage::numberOfVisibilityAdjustmentRects(CompletionHandler<void(uint64_t)>&& completion)
{
    RefPtr page = corePage();
    completion(page ? protect(page->elementTargetingController())->numberOfVisibilityAdjustmentRects() : 0);
}

#if HAVE(SPATIAL_TRACKING_LABEL)
void WebPage::setDefaultSpatialTrackingLabel(const String& label)
{
    if (RefPtr page = corePage())
        page->setDefaultSpatialTrackingLabel(label);
}
#endif

void WebPage::startObservingNowPlayingMetadata()
{
#if ENABLE(VIDEO) || ENABLE(WEB_AUDIO)
    RefPtr sessionManager = mediaSessionManager();
    if (!sessionManager || m_nowPlayingMetadataObserver)
        return;

    m_nowPlayingMetadataObserver = NowPlayingMetadataObserver::create([weakThis = WeakPtr { *this }](auto& metadata) {
        if (RefPtr protectedThis = weakThis.get())
            protectedThis->send(Messages::WebPageProxy::NowPlayingMetadataChanged { metadata });
    });

    sessionManager->addNowPlayingMetadataObserver(Ref { *m_nowPlayingMetadataObserver });
#endif
}

void WebPage::stopObservingNowPlayingMetadata()
{
#if ENABLE(VIDEO) || ENABLE(WEB_AUDIO)
    RefPtr nowPlayingMetadataObserver = std::exchange(m_nowPlayingMetadataObserver, nullptr);
    if (!nowPlayingMetadataObserver)
        return;

    if (RefPtr sessionManager = mediaSessionManager())
        sessionManager->removeNowPlayingMetadataObserver(*nowPlayingMetadataObserver);
#endif
}

void WebPage::didAdjustVisibilityWithSelectors(Vector<String>&& selectors)
{
    send(Messages::WebPageProxy::DidAdjustVisibilityWithSelectors(WTF::move(selectors)));
}

void WebPage::frameNameWasChangedInAnotherProcess(FrameIdentifier frameID, const String& frameName)
{
    RefPtr webFrame = WebProcess::singleton().webFrame(frameID);
    if (!webFrame)
        return;
    if (RefPtr coreFrame = webFrame->coreFrame())
        coreFrame->tree().setSpecifiedName(AtomString(frameName));
}

void WebPage::updateLastNodeBeforeWritingSuggestions(const KeyboardEvent& event)
{
    if (event.type() != eventNames().keydownEvent)
        return;

    if (RefPtr frame = corePage()->focusController().focusedOrMainFrame())
        m_lastNodeBeforeWritingSuggestions = protect(frame->editor())->nodeBeforeWritingSuggestions();
}

void WebPage::didAddOrRemoveViewportConstrainedObjects()
{
    m_needsFixedContainerEdgesUpdate = true;

#if PLATFORM(IOS_FAMILY)
    scheduleLayoutViewportHeightExpansionUpdate();
#endif
}

void WebPage::addReasonsToDisallowLayoutViewportHeightExpansion(OptionSet<DisallowLayoutViewportHeightExpansionReason> reasons)
{
    bool wasEmpty = m_disallowLayoutViewportHeightExpansionReasons.isEmpty();
    m_disallowLayoutViewportHeightExpansionReasons.add(reasons);

    if (!m_page->settings().layoutViewportHeightExpansionFactor())
        return;

    if (wasEmpty && !m_disallowLayoutViewportHeightExpansionReasons.isEmpty())
        send(Messages::WebPageProxy::SetAllowsLayoutViewportHeightExpansion(false));
}

void WebPage::removeReasonsToDisallowLayoutViewportHeightExpansion(OptionSet<DisallowLayoutViewportHeightExpansionReason> reasons)
{
    bool wasEmpty = m_disallowLayoutViewportHeightExpansionReasons.isEmpty();
    m_disallowLayoutViewportHeightExpansionReasons.remove(reasons);

    if (!m_page->settings().layoutViewportHeightExpansionFactor())
        return;

    if (!wasEmpty && m_disallowLayoutViewportHeightExpansionReasons.isEmpty())
        send(Messages::WebPageProxy::SetAllowsLayoutViewportHeightExpansion(true));
}

void WebPage::hasActiveNowPlayingSessionChanged(bool hasActiveNowPlayingSession)
{
    send(Messages::WebPageProxy::HasActiveNowPlayingSessionChanged(hasActiveNowPlayingSession));
}

void WebPage::simulateClickOverFirstMatchingTextInViewportWithUserInteraction(const String& targetText, CompletionHandler<void(bool)>&& completion)
{
    ASSERT(!targetText.isEmpty());

    RefPtr localMainFrame = m_mainFrame->coreLocalFrame();
    if (!localMainFrame)
        return completion(false);

    RefPtr view = localMainFrame->view();
    if (!view)
        return completion(false);

    RefPtr document = localMainFrame->document();
    if (!document)
        return completion(false);

    RefPtr bodyElement = document->body();
    if (!bodyElement)
        return completion(false);

    struct Candidate {
        Ref<HTMLElement> target;
        IntPoint location;
    };

    Vector<Candidate> candidates;

    auto removeNonHitTestableCandidates = [&] {
        candidates.removeAllMatching([&](auto& targetAndLocation) {
            auto& [target, location] = targetAndLocation;
            auto result = localMainFrame->eventHandler().hitTestResultAtPoint(location, {
                HitTestRequest::Type::ReadOnly,
                HitTestRequest::Type::Active,
            });
            RefPtr innerNode = result.innerNonSharedNode();
            return !innerNode || !target->isShadowIncludingInclusiveAncestorOf(innerNode.get());
        });
    };

    static constexpr OptionSet findOptions = {
        FindOption::CaseInsensitive,
        FindOption::AtWordStarts,
        FindOption::TreatMedialCapitalAsWordStart,
        FindOption::DoNotRevealSelection,
        FindOption::DoNotSetSelection,
    };

    auto unobscuredContentRect = view->unobscuredContentRect();
    auto searchRange = makeRangeSelectingNodeContents(*bodyElement);
    while (is_lt(treeOrder<ComposedTree>(searchRange.start, searchRange.end))) {
        auto range = findPlainText(searchRange, targetText, findOptions);

        if (range.collapsed())
            break;

        searchRange.start = range.end;

        RefPtr target = [&] -> RefPtr<HTMLElement> {
            for (RefPtr ancestor = range.start.container.ptr(); ancestor; ancestor = ancestor->parentElementInComposedTree()) {
                RefPtr element = dynamicDowncast<HTMLElement>(*ancestor);
                if (!element)
                    continue;

                if (element->willRespondToMouseClickEvents() || element->isLink())
                    return element;
            }
            return { };
        }();

        if (!target)
            continue;

        auto textRects = RenderObject::absoluteBorderAndTextRects(range, {
            RenderObject::BoundingRectBehavior::RespectClipping,
            RenderObject::BoundingRectBehavior::UseVisibleBounds,
            RenderObject::BoundingRectBehavior::IgnoreTinyRects,
            RenderObject::BoundingRectBehavior::IgnoreEmptyTextSelections,
        });

        auto indexOfFirstRelevantTextRect = textRects.findIf([&](auto& textRect) {
            return unobscuredContentRect.intersects(enclosingIntRect(textRect));
        });

        if (indexOfFirstRelevantTextRect == notFound)
            continue;

        candidates.append({ target.releaseNonNull(), roundedIntPoint(textRects[indexOfFirstRelevantTextRect].center()) });
    }

    removeNonHitTestableCandidates();
    WEBPAGE_RELEASE_LOG(MouseHandling, "Simulating click - found %zu candidate(s) from visible text", candidates.size());

    if (candidates.isEmpty()) {
        // Fall back to checking DOM attributes and accessibility labels.
        auto hitTestResult = HitTestResult { LayoutRect { unobscuredContentRect } };
        document->hitTest({ HitTestSource::User, { HitTestRequest::Type::ReadOnly, HitTestRequest::Type::CollectMultipleElements } }, hitTestResult);
        for (auto& node : hitTestResult.listBasedTestResult()) {
            RefPtr element = dynamicDowncast<HTMLElement>(node);
            if (!element)
                continue;

            bool isCandidate = false;
            if (auto ariaLabel = element->attributeWithoutSynchronization(HTMLNames::aria_labelAttr); !ariaLabel.isEmpty())
                isCandidate = containsPlainText(ariaLabel.string(), targetText, findOptions);

            if (!isCandidate) {
                if (RefPtr input = dynamicDowncast<HTMLInputElement>(element); input && (input->isSubmitButton() || input->isTextButton())) {
                    if (auto value = input->visibleValue(); !value.isEmpty())
                        isCandidate = containsPlainText(value, targetText, findOptions);
                }
            }

            if (!isCandidate)
                continue;

            if (auto rendererAndBounds = element->boundingAbsoluteRectWithoutLayout())
                candidates.append({ element.releaseNonNull(), enclosingIntRect(rendererAndBounds->second).center() });
        }

        removeNonHitTestableCandidates();
        WEBPAGE_RELEASE_LOG(MouseHandling, "Simulating click - found %zu candidate(s) from DOM attributes", candidates.size());
    }

    if (candidates.isEmpty()) {
        WEBPAGE_RELEASE_LOG(MouseHandling, "Simulating click - no matches found");
        return completion(false);
    }

    if (candidates.size() > 1) {
        WEBPAGE_RELEASE_LOG(MouseHandling, "Simulating click - too many matches found (%zu)", candidates.size());
        // FIXME: We'll want to add a way to disambiguate between multiple matches in the future. For now, just exit without
        // trying to simulate a click.
        return completion(false);
    }

    auto& [target, location] = candidates.first();

    SetForScope userIsInteractingChange { m_userIsInteracting, true };

    auto locationInWindow = view->contentsToWindow(location);
    auto makeSyntheticEvent = [&](PlatformEvent::Type type) -> PlatformMouseEvent {
        return { locationInWindow, locationInWindow, MouseButton::Left, type, 1, { }, MonotonicTime::now(), ForceAtClick, SyntheticClickType::OneFingerTap, MouseEventInputSource::UserDriven, mousePointerID };
    };

    WEBPAGE_RELEASE_LOG(MouseHandling, "Simulating click - dispatching events");
    localMainFrame->eventHandler().handleMousePressEvent(makeSyntheticEvent(PlatformEvent::Type::MousePressed)).wasHandled();
    if (m_isClosed)
        return completion(false);

    localMainFrame->eventHandler().handleMouseReleaseEvent(makeSyntheticEvent(PlatformEvent::Type::MouseReleased)).wasHandled();
    completion(true);
}

#if ENABLE(MEDIA_STREAM)
void WebPage::updateCaptureState(const WebCore::Document& document, bool isActive, WebCore::MediaProducerMediaCaptureKind kind, CompletionHandler<void(std::optional<WebCore::Exception>&&)>&& completionHandler)
{
    RefPtr frame = document.frame();
    if (!frame) {
        completionHandler(WebCore::Exception { ExceptionCode::InvalidStateError, "no frame available"_s });
        return;
    }

    RefPtr webFrame = WebFrame::fromCoreFrame(*frame);
    ASSERT(webFrame);

    sendWithAsyncReply(Messages::WebPageProxy::ValidateCaptureStateUpdate(UserMediaRequestIdentifier::generate(), document.clientOrigin(), webFrame->info(), isActive, kind), [weakThis = WeakPtr { *this }, isActive, kind, completionHandler = WTF::move(completionHandler)] (auto&& error) mutable {
        completionHandler(WTF::move(error));
        if (error)
            return;

        RefPtr webPage = weakThis.get();
        RefPtr page = webPage ? webPage->corePage() : nullptr;
        if (page)
            page->updateCaptureState(isActive, kind);
    });
}
#endif

void WebPage::updateOpener(WebCore::FrameIdentifier frameID, std::optional<WebCore::FrameIdentifier> newOpenerIdentifier)
{
    RefPtr frame = WebProcess::singleton().webFrame(frameID);
    if (!frame)
        return;
    RefPtr coreFrame = frame->coreFrame();
    if (!coreFrame)
        return;

    if (!newOpenerIdentifier) {
        coreFrame->disownOpener(WebCore::Frame::NotifyUIProcess::No);
        if (RefPtr provisionalFrame = frame->provisionalFrame())
            provisionalFrame->disownOpener(WebCore::Frame::NotifyUIProcess::No);
        return;
    }

    RefPtr newOpener = WebProcess::singleton().webFrame(newOpenerIdentifier);
    if (!newOpener)
        return;
    RefPtr coreNewOpener = newOpener->coreFrame();
    if (!coreNewOpener)
        return;

    coreFrame->updateOpener(*coreNewOpener, WebCore::Frame::NotifyUIProcess::No);
    if (RefPtr provisionalFrame = frame->provisionalFrame())
        provisionalFrame->updateOpener(*coreNewOpener, WebCore::Frame::NotifyUIProcess::No);
}

void WebPage::setFramePrinting(WebCore::FrameIdentifier frameID, bool printing, FloatSize pageSize, FloatSize originalPageSize, float maximumShrinkRatio, AdjustViewSize shouldAdjustViewSize)
{
    RefPtr frame = WebProcess::singleton().webFrame(frameID);
    if (!frame)
        return;
    RefPtr coreFrame = frame->coreFrame();
    if (!coreFrame)
        return;
    coreFrame->setPrinting(printing, pageSize, originalPageSize, maximumShrinkRatio, shouldAdjustViewSize, WebCore::Frame::NotifyUIProcess::No);
}

bool WebPage::isAlwaysOnLoggingAllowed() const
{
    RefPtr page { protect(corePage()) };
    return page && page->isAlwaysOnLoggingAllowed();
}

#if PLATFORM(IOS_FAMILY)

bool WebPage::canShowWhileLocked() const
{
    return m_page && m_page->canShowWhileLocked();
}

#else

void WebPage::callAfterPendingSyntheticClick(CompletionHandler<void(SyntheticClickResult)>&& completion)
{
    completion(SyntheticClickResult::Failed);
}

#endif

#if HAVE(AUDIT_TOKEN)
void WebPage::setPresentingApplicationAuditTokenAndBundleIdentifier(CoreIPCAuditToken&& auditToken, String&& bundleIdentifier)
{
    RefPtr page = corePage();
    if (!page)
        return;

    page->setPresentingApplicationAuditToken(auditToken.auditToken());
    page->setPresentingApplicationBundleIdentifier(WTF::move(bundleIdentifier));
}
#endif

void WebPage::frameViewLayoutOrVisualViewportChanged(const LocalFrameView& frameView)
{
#if ENABLE(PDF_PLUGIN)
    Ref frame = frameView.frame();
    if (RefPtr plugin = pluginViewForFrame(frame.ptr()))
        plugin->frameViewLayoutOrVisualViewportChanged(frameView.unobscuredContentRect());
#else
    UNUSED_PARAM(frameView);
#endif
}

RefPtr<MediaSessionManagerInterface> WebPage::mediaSessionManager() const
{
    RefPtr page { corePage() };
    return page ? page->mediaSessionManager() : nullptr;

}

MediaSessionManagerInterface* WebPage::mediaSessionManagerIfExists() const
{
    auto* page = corePage();
    return page ? page->mediaSessionManagerIfExists() : nullptr;

}

#if ENABLE(MODEL_ELEMENT)
bool WebPage::shouldDisableModelLoadDelaysForTesting() const
{
    return m_page && m_page->shouldDisableModelLoadDelaysForTesting();
}
#endif

std::unique_ptr<FrameInfoData> WebPage::takeMainFrameNavigationInitiator()
{
    return std::exchange(m_mainFrameNavigationInitiator, nullptr);
}

#if !PLATFORM(IOS_FAMILY)
bool WebPage::hasAccessoryMousePointingDevice() const
{
    return true;
}
#endif

#if ENABLE(VIDEO)
void WebPage::setCaptionDisplaySettingsPreviewProfileID(const String& profileID)
{
    if (RefPtr captionPreferences = m_pageGroup->corePageGroup()->captionPreferences())
        captionPreferences->setCaptionPreviewProfileID(profileID);
}

void WebPage::showCaptionDisplaySettingsPreview(HTMLMediaElementIdentifier identifier)
{
#if PLATFORM(IOS_FAMILY) || (PLATFORM(MAC) && ENABLE(VIDEO_PRESENTATION_MODE))
    if (RefPtr mediaElement = protect(playbackSessionManager())->mediaElementWithContextId(identifier))
        mediaElement->showCaptionDisplaySettingsPreview();
#else
    UNUSED_PARAM(identifier);
#endif
}

void WebPage::hideCaptionDisplaySettingsPreview(HTMLMediaElementIdentifier identifier)
{
#if PLATFORM(IOS_FAMILY) || (PLATFORM(MAC) && ENABLE(VIDEO_PRESENTATION_MODE))
    if (RefPtr mediaElement = protect(playbackSessionManager())->mediaElementWithContextId(identifier))
        mediaElement->hideCaptionDisplaySettingsPreview();
#else
    UNUSED_PARAM(identifier);
#endif
}
#endif

void WebPage::updateRemoteIntersectionObservers()
{
    if (RefPtr page = m_page) {
        page->forEachDocument([] (Document& document) {
            document.updateRemoteIntersectionObservers();
        });
    }
}

} // namespace WebKit

#undef WEBPAGE_RELEASE_LOG
#undef WEBPAGE_RELEASE_LOG_ERROR
