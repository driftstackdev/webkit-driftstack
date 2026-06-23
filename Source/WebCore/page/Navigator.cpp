/*
 *  Copyright (C) 2000 Harri Porten (porten@kde.org)
 *  Copyright (c) 2000 Daniel Molkentin (molkentin@kde.org)
 *  Copyright (c) 2000 Stefan Schimanski (schimmi@kde.org)
 *  Copyright (C) 2003-2025 Apple Inc. All rights reserved.
 *  Copyright (C) 2008 Nokia Corporation and/or its subsidiary(-ies)
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include "config.h"
#include "Navigator.h"

#if PLATFORM(DRIFTSTACK)
#include "DriftstackArchetypeConfig.h"
#endif

#include "BadgeClient.h"
#include "Chrome.h"
#include "CookieJar.h"
#include "DOMMimeType.h"
#include "DOMMimeTypeArray.h"
#include "DOMPlugin.h"
#include "DOMPluginArray.h"
#include "DocumentPage.h"
#include "DocumentQuirks.h"
#include "FrameInlines.h"
#include "FrameLoader.h"
#include "GPU.h"
#include "Geolocation.h"
#include "JSDOMPromiseDeferred.h"
#include "LoaderStrategy.h"
#include "LocalFrameInlines.h"
#include "LocalFrameLoaderClient.h"
#include "LocalizedStrings.h"
#include "NavigatorUAData.h"
#include "PermissionsPolicy.h"
#include "PlatformStrategies.h"
#include "PluginData.h"
#include "ResourceLoadObserver.h"
#include "ScriptController.h"
#include "ScriptWrappableInlines.h"
#include "SecurityOrigin.h"
#include "Settings.h"
#include "ShareData.h"
#include "ShareDataReader.h"
#include "SharedBuffer.h"
#include "UserAgentStringData.h"
#include "UserAgentStringParser.h"
#include "inspector/InspectorInstrumentation.h"
#include <JavaScriptCore/ConsoleTypes.h>
#include <optional>
#include <wtf/Language.h>
#include <wtf/RunLoop.h>
#include <wtf/StdLibExtras.h>
#include <wtf/TZoneMallocInlines.h>
#include <wtf/WeakPtr.h>

namespace WebCore {

WTF_MAKE_TZONE_ALLOCATED_IMPL(Navigator);

Navigator::Navigator(ScriptExecutionContext* context, LocalDOMWindow& window)
    : NavigatorBase(context)
    , LocalDOMWindowProperty(&window)
{
}

Navigator::~Navigator() = default;

String Navigator::appVersion() const
{
    RefPtr frame = this->frame();
    if (!frame)
        return String();
    if (frame->settings().webAPIStatisticsEnabled())
        ResourceLoadObserver::singleton().logNavigatorAPIAccessed(*protect(frame->document()), NavigatorAPIsAccessed::AppVersion);
    return NavigatorBase::appVersion();
}

const String& Navigator::userAgent() const
{
    RefPtr frame = this->frame();
    if (!frame || !frame->page())
        return m_userAgent;
    if (frame->settings().webAPIStatisticsEnabled())
        ResourceLoadObserver::singleton().logNavigatorAPIAccessed(*protect(frame->document()), NavigatorAPIsAccessed::UserAgent);

#if PLATFORM(DRIFTSTACK)
    // Wave 29-360 item 1 + Wave 29-389 (Config singleton migration):
    // 3-layer UA resolution priority:
    //   1. DriftstackArchetypeConfig singleton (Phase 2 archetype JSON load)
    //   2. DRIFTSTACK_ARCHETYPE_UA_FULL env-var fallback (Wave 29-360 path,
    //      preserved for back-compat with production harness scripts)
    //   3. V-202 / Wave 1.2 hardcoded launch-archetype default (cumrig invariant)
    //
    // Config singleton became cross-module-reachable Wave 29-366.6 Xcode regen.
    // Pre-29-366.6 the env-var path was the only option due to cross-module
    // visibility limits. Now Config is preferred — env-var stays as fallback
    // for scripts that don't set DRIFTSTACK_ARCHETYPE_CONFIG_PATH.
    // First-call cache: Config singleton then env-var. Both can be empty;
    // in either case fall through to hardcoded default below.
    // Function signature returns `const String&` so the cache must outlive
    // the function — static NeverDestroyed.
    static NeverDestroyed<String> driftstackResolvedUA = []() {
        auto& cfg = DriftstackArchetypeConfig::singleton();
        if (cfg.isValid()) {
            String s = cfg.userAgentFull();
            if (!s.isEmpty())
                return s;
        }
        const char* env = getenv("DRIFTSTACK_ARCHETYPE_UA_FULL");
        if (env && env[0])
            return String::fromUTF8(env);
        // Wave 29-404 §11.A.5 (2026-05-19): direct archetype-slug-to-UA
        // fallback for v1.0 supported archetypes. Lets harness scripts
        // pass DRIFTSTACK_ARCHETYPE alone (without separate UA_FULL) and
        // get the matching UA. v1.0 supported set:
        //   iphone16pro_ios18_6_safari18_6 (Family A)
        //   iphone17_ios18_7_safari26_4 (Family B launch)
        //   iphone16pro_ios18_7_safari26_4 (second supported)
        const char* slug = getenv("DRIFTSTACK_ARCHETYPE");
        if (slug && slug[0]) {
            std::string_view sv(slug);
            if (sv == "iphone16pro_ios18_6_safari18_6")
                return String("Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.6 Mobile/15E148 Safari/604.1"_s);
            if (sv == "iphone17_ios18_7_safari26_4")
                return String("Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.4 Mobile/15E148 Safari/604.1"_s);
            if (sv == "iphone16pro_ios18_7_safari26_4")
                return String("Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.4 Mobile/15E148 Safari/604.1"_s);
        }
        return String();
    }();
    if (!driftstackResolvedUA.get().isEmpty())
        return driftstackResolvedUA.get();
    static NeverDestroyed<String> driftstackDefaultUA = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.4 Mobile/15E148 Safari/604.1"_s;
    return driftstackDefaultUA.get();
#endif

#if PLATFORM(IOS_FAMILY)
    if (RefPtr document = frame->document(); document && document->quirks().needsChromeOSNavigatorUserAgentQuirk(*document)) {
        static NeverDestroyed<String> chromeOSUserAgent = "Mozilla/5.0 (X11; CrOS x86_64 15917.71.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36"_s;
        return chromeOSUserAgent.get();
    }
#endif

    if (m_userAgent.isNull())
        m_userAgent = frame->loader().userAgent(frame->document()->url());
    return m_userAgent;
}

String Navigator::platform() const
{
    RefPtr frame = this->frame();
    if (!frame || !frame->page())
        return m_platform;

    if (m_platform.isNull())
        m_platform = frame->loader().navigatorPlatform();

    if (m_platform.isNull())
        m_platform = NavigatorBase::platform();
    return m_platform;
}

void Navigator::userAgentChanged()
{
    m_userAgent = String();
}

bool Navigator::onLine() const
{
    return platformStrategies()->loaderStrategy()->isOnLine();
}

static std::optional<URL> shareableURLForShareData(ScriptExecutionContext& context, const ShareData& data)
{
    if (data.url.isNull())
        return std::nullopt;

    auto url = context.completeURL(data.url);
    if (!url.isValid())
        return std::nullopt;
    if (!url.protocolIsInHTTPFamily())
        return std::nullopt;

    return url;
}

static bool validateWebSharePolicy(Document& document)
{
    return PermissionsPolicy::isFeatureEnabled(PermissionsPolicy::Feature::WebShare, document);
}

bool Navigator::canShare(Document& document, const ShareData& data)
{
    if (!document.isFullyActive() || !validateWebSharePolicy(document))
        return false;

    bool hasShareableFiles = document.settings().webShareFileAPIEnabled() && !data.files.isEmpty();

    if (data.title.isNull() && data.text.isNull() && data.url.isNull() && !hasShareableFiles)
        return false;

    return data.url.isNull() || shareableURLForShareData(document, data);
}

void Navigator::share(Document& document, const ShareData& data, Ref<DeferredPromise>&& promise)
{
    if (!document.isFullyActive()) {
        promise->reject(ExceptionCode::InvalidStateError);
        return;
    }

    if (!validateWebSharePolicy(document)) {
        promise->reject(ExceptionCode::NotAllowedError, "Third-party iframes are not allowed to call share() unless explicitly allowed via Feature-Policy (web-share)"_s);
        return;
    }

    if (m_hasPendingShare) {
        promise->reject(ExceptionCode::InvalidStateError, "share() is already in progress"_s);
        return;
    }

    RefPtr window = this->window();
    if (!window || !window->consumeTransientActivation()) {
        promise->reject(ExceptionCode::NotAllowedError);
        return;
    }

    if (!canShare(document, data)) {
        promise->reject(ExceptionCode::TypeError);
        return;
    }

    std::optional<URL> url = shareableURLForShareData(document, data);
    ShareDataWithParsedURL shareData = {
        data,
        url,
        { },
        ShareDataOriginator::Web,
    };
    if (document.settings().webShareFileAPIEnabled() && !data.files.isEmpty()) {
        RefPtr loader = m_loader;
        if (loader)
            loader->cancel();

        loader = ShareDataReader::create([this, protectedThis = Ref { *this }, promise = WTF::move(promise)](ExceptionOr<ShareDataWithParsedURL&> readData) mutable {
            showShareData(readData, WTF::move(promise));
        });
        m_loader = loader.copyRef();
        loader->start(&document, WTF::move(shareData));
        return;
    }
    this->showShareData(shareData, WTF::move(promise));
}

void Navigator::showShareData(ExceptionOr<ShareDataWithParsedURL&> readData, Ref<DeferredPromise>&& promise)
{
    if (readData.hasException()) {
        promise->reject(readData.releaseException());
        return;
    }

    RefPtr frame = this->frame();
    if (!frame || !frame->page())
        return;

#if PLATFORM(DRIFTSTACK)
    // LAUNCH-SECURITY (isolation audit wi8z2sdot / planning 146): a customer session must NEVER reach the SHARED
    // WORKER's NSSharingService (the macOS share sheet — a Mac-app/UI reach + a tell a real iPhone never shows).
    // navigator.share / navigator.canShare stay PRESENT + iPhone-correct (the API surface + canShare() above are
    // untouched); only the INVOCATION is gated: resolve as the iPhone-faithful "user dismissed the share sheet"
    // (AbortError) — NEVER chrome().showShareSheet(). Covers BOTH the direct and the file-share (ShareDataReader)
    // funnels since both reach here. AbortError = a real cancel outcome, not a silent fake-success (which is a tell).
    m_hasPendingShare = true;
    RunLoop::mainSingleton().dispatch([promise = WTF::move(promise), weakThis = WeakPtr { *this }] {
        if (weakThis)
            weakThis->m_hasPendingShare = false;
        promise->reject(Exception { ExceptionCode::AbortError, "Abort due to cancellation of share."_s });
    });
#else
    m_hasPendingShare = true;

    if (frame->page()->isControlledByAutomation()) {
        RunLoop::mainSingleton().dispatch([promise = WTF::move(promise), weakThis = WeakPtr { *this }] {
            if (weakThis)
                weakThis->m_hasPendingShare = false;
            promise->resolve();
        });
        return;
    }

    auto shareData = readData.returnValue();

    frame->page()->chrome().showShareSheet(WTF::move(shareData), [promise = WTF::move(promise), weakThis = WeakPtr { *this }](bool completed) {
        if (weakThis)
            weakThis->m_hasPendingShare = false;
        if (completed) {
            promise->resolve();
            return;
        }
        promise->reject(Exception { ExceptionCode::AbortError, "Abort due to cancellation of share."_s });
    });
#endif
}

// https://html.spec.whatwg.org/multipage/system-state.html#pdf-viewing-support
// Section 8.9.1.6 states that if pdfViewerEnabled is true, we must return a list
// of exactly five PDF view plugins, in a particular order.
constexpr ASCIILiteral genericPDFViewerName { "PDF Viewer"_s };

static const Vector<String>& dummyPDFPluginNames()
{
    static NeverDestroyed<Vector<String>> dummyPluginNames(std::initializer_list<String> {
        genericPDFViewerName,
        "Chrome PDF Viewer"_s,
        "Chromium PDF Viewer"_s,
        "Microsoft Edge PDF Viewer"_s,
        "WebKit built-in PDF"_s,
    });
    return dummyPluginNames;
}

void Navigator::initializePluginAndMimeTypeArrays()
{
    if (m_plugins)
        return;

    RefPtr frame = this->frame();
    bool needsEmptyNavigatorPluginsQuirk = frame && frame->document() && protect(frame->document())->quirks().shouldNavigatorPluginsBeEmpty();
    if (!frame || !frame->page() || needsEmptyNavigatorPluginsQuirk) {
        if (needsEmptyNavigatorPluginsQuirk)
            protect(frame->document())->addConsoleMessage(MessageSource::Other, MessageLevel::Info, "QUIRK: Navigator plugins / mimeTypes empty on marcus.com. More information at https://bugs.webkit.org/show_bug.cgi?id=248798"_s);
        m_plugins = DOMPluginArray::create(*this);
        m_mimeTypes = DOMMimeTypeArray::create(*this);
        return;
    }

#if PLATFORM(DRIFTSTACK)
    // Real iOS Safari shows PDFs inline → navigator.pdfViewerEnabled = true and navigator.plugins
    // returns the 5 spec-mandated dummy PDF plugins (HTML §8.9.1.6). Force it host-INDEPENDENTLY:
    // the host path below (canShowMIMEType "application/pdf") reflects the fleet WebKit build's PDF
    // support (PDFKit / unified-PDF) — a build that disables it would silently flip pdfViewerEnabled
    // to false + empty navigator.plugins/mimeTypes = an instant iPhone tell. The dummy-plugin
    // population that follows uses PluginData::dummyPDFPluginInfo(), so it needs no real host plugin
    // and yields the exact iPhone-Safari plugin set regardless of the fleet build. (Host-read guard
    // class — same pattern as hardwareConcurrency/platform/colorDepth per W2227.)
    m_pdfViewerEnabled = true;
#else
    m_pdfViewerEnabled = frame->loader().client().canShowMIMEType("application/pdf"_s);
#endif
    if (!m_pdfViewerEnabled) {
        m_plugins = DOMPluginArray::create(*this);
        m_mimeTypes = DOMMimeTypeArray::create(*this);
        return;
    }

    // macOS uses a PDF Plugin (which may be disabled). Other ports handle PDF's through native
    // platform views outside the engine, or use pdf.js.
    PluginInfo pdfPluginInfo = protect(frame->page())->pluginData().builtInPDFPlugin().value_or(PluginData::dummyPDFPluginInfo());

    Vector<Ref<DOMPlugin>> domPlugins;
    Vector<Ref<DOMMimeType>> domMimeTypes;

    // https://html.spec.whatwg.org/multipage/system-state.html#pdf-viewing-support
    // Section 8.9.1.6 states that if pdfViewerEnabled is true, we must return a list
    // of exactly five PDF view plugins, in a particular order. They also must return
    // a specific plain English string for 'Navigator.plugins[x].description':
    constexpr auto navigatorPDFDescription = "Portable Document Format"_s;
    for (auto& currentDummyName : dummyPDFPluginNames()) {
        pdfPluginInfo.name = currentDummyName;
        pdfPluginInfo.desc = navigatorPDFDescription;
        domPlugins.append(DOMPlugin::create(*this, pdfPluginInfo));

        // Register the copy of the PluginInfo using the generic 'PDF Viewer' name
        // as the handler for PDF MIME type to match the specification.
        if (currentDummyName == genericPDFViewerName)
            domMimeTypes.appendVector(domPlugins.last()->mimeTypes());
    }

    m_plugins = DOMPluginArray::create(*this, WTF::move(domPlugins));
    m_mimeTypes = DOMMimeTypeArray::create(*this, WTF::move(domMimeTypes));
}

DOMPluginArray& Navigator::plugins()
{
    if (RefPtr frame = this->frame(); frame && frame->settings().webAPIStatisticsEnabled())
        ResourceLoadObserver::singleton().logNavigatorAPIAccessed(*protect(frame->document()), NavigatorAPIsAccessed::Plugins);

    initializePluginAndMimeTypeArrays();
    return *m_plugins;
}

DOMMimeTypeArray& Navigator::mimeTypes()
{
    if (RefPtr frame = this->frame(); frame && frame->settings().webAPIStatisticsEnabled())
        ResourceLoadObserver::singleton().logNavigatorAPIAccessed(*protect(frame->document()), NavigatorAPIsAccessed::MimeTypes);

    initializePluginAndMimeTypeArrays();
    return *m_mimeTypes;
}

bool Navigator::pdfViewerEnabled()
{
    // https://html.spec.whatwg.org/multipage/system-state.html#pdf-viewing-support
    initializePluginAndMimeTypeArrays();
    return m_pdfViewerEnabled;
}

bool Navigator::cookieEnabled() const
{
    RefPtr frame = this->frame();
    if (!frame)
        return false;

    if (frame->settings().webAPIStatisticsEnabled())
        ResourceLoadObserver::singleton().logNavigatorAPIAccessed(*protect(frame->document()), NavigatorAPIsAccessed::CookieEnabled);

    RefPtr page = frame->page();
    if (!page)
        return false;

    if (!page->settings().cookieEnabled())
        return false;

    RefPtr document = frame->document();
    if (!document)
        return false;

    return page->cookieJar().cookiesEnabled(*document);
}

#if ENABLE(NAVIGATOR_STANDALONE)

bool Navigator::standalone() const
{
    auto* frame = this->frame();
    return frame && frame->settings().standalone();
}

#endif

GPU* Navigator::gpu()
{
#if HAVE(WEBGPU_IMPLEMENTATION)
#if PLATFORM(DRIFTSTACK)
    // Wave 29-402 v1.0 navigator.gpu Family A hide (founder verdict
    // 2026-05-19 "everything perfect in v1.0"). iPhone Safari ≤26.3
    // (Family A) does NOT expose WebGPU — `navigator.gpu === undefined`.
    // Empirical capture 2026-05-19 BS Family A 3 sessions confirms
    // gpu_err='navigator.gpu undefined'. For Family A archetype dispatch,
    // return nullptr so the IDL binding emits undefined. Family B
    // (Safari 26.4+) keeps native exposure. Static init reads
    // DRIFTSTACK_ARCHETYPE env var (forwarded via ProcessLauncherCocoa
    // allowlist Wave 29-400 §8.A).
    static bool s_isFamilyA = []() {
        const char* archetype = getenv("DRIFTSTACK_ARCHETYPE");
        if (!archetype) return false;  // default Family B (launch archetype)
        // Family A archetype identifiers (per CLAUDE.md launch verdict 2026-05-17):
        //   iphone16pro_ios18_6_safari18_6 — canonical Family A
        //   iphone16pro_ios18_*_safari18_* — Family A sub-variants
        //   any *_safari18_* — Safari major 18 = pre-26 = Family A
        // Use std::string_view::find to avoid -Wunsafe-buffer-usage flag on strstr.
        return std::string_view(archetype).find("safari18_") != std::string_view::npos;
    }();
    if (s_isFamilyA)
        return nullptr;
    // W2532 (#56): within Family B (Safari 26+), WebGPU requires an A16+ GPU. navigator.gpu is
    // otherwise gated by Safari VERSION only (model-blind), so an A15 model running 26.x (iphone13/14
    // /14plus) would FALSELY expose WebGPU. Hide it for those; the A16+ models keep native exposure.
    // ⚠️ W2557: boundary CORRECTED A17+→A16+ — BS captured the non-Pro iPhone 15 (A16, 393x852) @
    // Safari 26.2 with a REAL "apple" WebGPU adapter, falsifying file-122's "15 Pro and newer".
    // iphone14pro/promax are the SAME A16 chip. This gate + the WebPage.cpp settings gate + the
    // WorkerNavigator.cpp worker gate MUST stay byte-identical (else navigator.gpu===null or a
    // main/worker incoherence tell). A15 iphone13*/iphone14/iphone14plus stay non-capable.
    static bool s_hideWebGPUNonCapableModel = []() {
        const char* archetype = getenv("DRIFTSTACK_ARCHETYPE");
        if (!archetype)
            return false;
        std::string_view a(archetype);
        bool capable = (a.find("iphone17") == 0) || (a.find("iphone16") == 0)
            || (a.find("iphone15") == 0) || (a.find("iphone14pro") == 0); // A16+ : 14 Pro/Pro Max, 15*, 16*, 17*
        return !capable;
    }();
    if (s_hideWebGPUNonCapableModel)
        return nullptr;
#endif
    if (!m_gpuForWebGPU) {
        RefPtr frame = this->frame();
        if (!frame)
            return nullptr;
        if (!frame->settings().webGPUEnabled())
            return nullptr;
        RefPtr page = frame->page();
        if (!page)
            return nullptr;
        RefPtr gpu = page->chrome().createGPUForWebGPU();
        if (!gpu)
            return nullptr;

        m_gpuForWebGPU = GPU::create(*gpu);
    }
#endif

    return m_gpuForWebGPU.get();
}

Page* Navigator::page()
{
    auto* frame = this->frame();
    return frame ? frame->page() : nullptr;
}

const Document* Navigator::document() const
{
    auto* frame = this->frame();
    return frame ? frame->document() : nullptr;
}

Document* Navigator::document()
{
    auto* frame = this->frame();
    return frame ? frame->document() : nullptr;
}

void Navigator::setAppBadge(std::optional<unsigned long long> badge, Ref<DeferredPromise>&& promise)
{
    RefPtr frame = this->frame();
    if (!frame) {
        promise->reject(ExceptionCode::InvalidStateError);
        return;
    }

    RefPtr page = frame->page();
    if (!page) {
        promise->reject(ExceptionCode::InvalidStateError);
        return;
    }

    RefPtr document = frame->document();
    if (document && !document->isFullyActive()) {
        promise->reject(ExceptionCode::InvalidStateError);
        return;
    }

    page->badgeClient().setAppBadge(frame.get(), SecurityOriginData::fromLocalFrame(frame.get()), badge);
    promise->resolve();
}

void Navigator::clearAppBadge(Ref<DeferredPromise>&& promise)
{
    setAppBadge(0, WTF::move(promise));
}

int Navigator::maxTouchPoints() const
{
#if (ENABLE(IOS_TOUCH_EVENTS) && !PLATFORM(MACCATALYST)) || PLATFORM(DRIFTSTACK) /* V-MAXTOUCH-DS5: the || PLATFORM(DRIFTSTACK) forces navigator.maxTouchPoints=5 (iPhone); a Mac lacks IOS_TOUCH_EVENTS so dropping it returns 0 = desktop tell. Source-pinned (W2508). */
    RefPtr document = this->document();
    if (!document || !document->quirks().needsZeroMaxTouchPointsQuirk())
        return 5;
#endif

    return 0;
}

NavigatorUAData& Navigator::userAgentData() const
{
    RefPtr frame = this->frame();
    if (frame && frame->page()) {
        RefPtr client = frame->loader().client();
        if (client->hasCustomUserAgent() || (frame->document() && protect(frame->document())->quirks().needsCustomUserAgentData())) {
            auto userAgentString = frame->loader().userAgent({ });
            Ref parser = UserAgentStringParser::create(userAgentString);
            std::optional userAgentStringData = parser->parse();
            if (userAgentStringData) {
                m_navigatorUAData = NavigatorUAData::create(WTF::move(*userAgentStringData));
                return *m_navigatorUAData;
            }
        }
    }

    m_navigatorUAData = NavigatorUAData::create();
    return *m_navigatorUAData;
};

} // namespace WebCore
