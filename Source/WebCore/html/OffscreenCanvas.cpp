/*
 * Copyright (C) 2017-2025 Apple Inc. All rights reserved.
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
#include "OffscreenCanvas.h"

#if ENABLE(OFFSCREEN_CANVAS)

#if PLATFORM(DRIFTSTACK)
#include "CanvasRenderingContext2DBase.h"
#include "DriftstackCanvasFingerprint10xOverride.h"
#include "DriftstackCanvasFingerprint10xRGBA.h"
#include "../platform/graphics/coreml/DriftstackLayerB.h"
#include <wtf/text/Base64.h>
#endif
#include "BitmapImage.h"
#include "CSSValuePool.h"
#include "CanvasRenderingContext.h"
#include "ContextDestructionObserverInlines.h"
#include "Chrome.h"
#include "Document.h"
#include "EventDispatcher.h"
#include "GPU.h"
#include "GPUCanvasContext.h"
#include "HTMLCanvasElement.h"
#include "ImageBitmap.h"
#include "ImageBitmapRenderingContext.h"
#include "ImageData.h"
#include "ImageUtilities.h"
#include "JSBlob.h"
#include "JSDOMConvertDictionary.h"
#include "JSDOMConvertInterface.h"
#include "JSDOMPromiseDeferred.h"
#include "MIMETypeRegistry.h"
#include "OffscreenCanvasRenderingContext2D.h"
#include "Page.h"
#include "PlaceholderRenderingContext.h"
#include "ScriptTrackingPrivacyCategory.h"
#include "WorkerClient.h"
#include "WorkerGlobalScope.h"
#include "WorkerNavigator.h"
#include <JavaScriptCore/HeapCellInlines.h>
#include <JavaScriptCore/JSCJSValueInlines.h>
#include <wtf/TZoneMallocInlines.h>

#if ENABLE(WEBGL)
#include "Settings.h"
#include "WebGLRenderingContext.h"
#include "WebGL2RenderingContext.h"
#endif // ENABLE(WEBGL)

#if HAVE(WEBGPU_IMPLEMENTATION)
#include "LocalDOMWindow.h"
#include "Navigator.h"
#endif

namespace WebCore {

WTF_MAKE_TZONE_ALLOCATED_IMPL(DetachedOffscreenCanvas);
WTF_MAKE_TZONE_ALLOCATED_IMPL(OffscreenCanvas);

DetachedOffscreenCanvas::DetachedOffscreenCanvas(const IntSize& size, bool originClean, RefPtr<PlaceholderRenderingContextSource>&& placeholderSource)
    : m_placeholderSource(WTF::move(placeholderSource))
    , m_size(size)
    , m_originClean(originClean)
{
}

DetachedOffscreenCanvas::~DetachedOffscreenCanvas() = default;

RefPtr<PlaceholderRenderingContextSource> DetachedOffscreenCanvas::takePlaceholderSource()
{
    return WTF::move(m_placeholderSource);
}

bool OffscreenCanvas::enabledForContext(ScriptExecutionContext& context)
{
    UNUSED_PARAM(context);

#if ENABLE(OFFSCREEN_CANVAS_IN_WORKERS)
    if (context.isWorkerGlobalScope())
        return context.settingsValues().offscreenCanvasInWorkersEnabled;
#endif

    ASSERT(context.isDocument());
    return true;
}

Ref<OffscreenCanvas> OffscreenCanvas::create(ScriptExecutionContext& scriptExecutionContext, unsigned width, unsigned height)
{
    auto canvas = adoptRef(*new OffscreenCanvas(scriptExecutionContext, { static_cast<int>(width), static_cast<int>(height) }, nullptr));
    canvas->suspendIfNeeded();
    return canvas;
}

Ref<OffscreenCanvas> OffscreenCanvas::create(ScriptExecutionContext& scriptExecutionContext, std::unique_ptr<DetachedOffscreenCanvas>&& detachedCanvas)
{
    Ref<OffscreenCanvas> clone = adoptRef(*new OffscreenCanvas(scriptExecutionContext, detachedCanvas->size(), detachedCanvas->takePlaceholderSource()));
    if (!detachedCanvas->originClean())
        clone->setOriginTainted();
    clone->suspendIfNeeded();
    return clone;
}

Ref<OffscreenCanvas> OffscreenCanvas::create(ScriptExecutionContext& scriptExecutionContext, PlaceholderRenderingContext& placeholder)
{
    auto offscreen = adoptRef(*new OffscreenCanvas(scriptExecutionContext, placeholder.size(), &placeholder.source()));
    offscreen->suspendIfNeeded();
    return offscreen;
}

OffscreenCanvas::OffscreenCanvas(ScriptExecutionContext& scriptExecutionContext, IntSize size, RefPtr<PlaceholderRenderingContextSource>&& placeholderSource)
    : ActiveDOMObject(&scriptExecutionContext)
    , CanvasBase(WTF::move(size), scriptExecutionContext)
    , m_placeholderSource(WTF::move(placeholderSource))
{
}

OffscreenCanvas::~OffscreenCanvas()
{
    notifyObserversCanvasDestroyed();
    removeCanvasNeedingPreparationForDisplayOrFlush();
}

void OffscreenCanvas::setWidth(unsigned newWidth)
{
    if (m_detached)
        return;
    IntSize newSize(newWidth, height());
    bool sizeChanged = newSize != size();
    if (sizeChanged)
        setSize(newSize);
    didUpdateSizeProperties(sizeChanged);
}

void OffscreenCanvas::setHeight(unsigned newHeight)
{
    if (m_detached)
        return;
    IntSize newSize(width(), newHeight);
    bool sizeChanged = newSize != size();
    if (sizeChanged)
        setSize(newSize);
    didUpdateSizeProperties(sizeChanged);
}

void OffscreenCanvas::setSizeForControllingContext(IntSize newSize)
{
    // Controlling context size change semantics are different to width, height assignment.
    if (size() == newSize)
        return;
    setSize(newSize);
    didUpdateSizeProperties(true);
}

void OffscreenCanvas::didUpdateSizeProperties(bool sizeChanged)
{
    clearCopiedImage();
    if (m_context)
        m_context->didUpdateCanvasSizeProperties(sizeChanged);
    notifyObserversCanvasResized();
    scheduleCommitToPlaceholderCanvas();
}

ExceptionOr<std::optional<OffscreenRenderingContext>> OffscreenCanvas::getContext(JSC::JSGlobalObject& state, RenderingContextType contextType, FixedVector<JSC::Strong<JSC::Unknown>>&& arguments)
{
    if (m_detached)
        return Exception { ExceptionCode::InvalidStateError };

    if (contextType == RenderingContextType::_2d) {
        if (!m_context) {
            auto scope = DECLARE_THROW_SCOPE(state.vm());

            auto settings = convert<IDLDictionary<CanvasRenderingContext2DSettings>>(state, arguments.isEmpty() ? JSC::jsUndefined() : (arguments[0].isObject() ? arguments[0].get() : JSC::jsNull()));
            if (settings.hasException(scope)) [[unlikely]]
                return Exception { ExceptionCode::ExistingExceptionError };

            m_context = OffscreenCanvasRenderingContext2D::create(*this, settings.releaseReturnValue());
        }
        if (RefPtr context = dynamicDowncast<OffscreenCanvasRenderingContext2D>(m_context.get()))
            return { { context.releaseNonNull() } };
        return { { std::nullopt } };
    }
    if (contextType == RenderingContextType::Bitmaprenderer) {
        if (!m_context) {
            auto scope = DECLARE_THROW_SCOPE(state.vm());

            auto settings = convert<IDLDictionary<ImageBitmapRenderingContextSettings>>(state, arguments.isEmpty() ? JSC::jsUndefined() : (arguments[0].isObject() ? arguments[0].get() : JSC::jsNull()));
            if (settings.hasException(scope)) [[unlikely]]
                return Exception { ExceptionCode::ExistingExceptionError };

            m_context = ImageBitmapRenderingContext::create(*this, settings.releaseReturnValue());
            downcast<ImageBitmapRenderingContext>(m_context.get())->transferFromImageBitmap(nullptr);
        }
        if (RefPtr context = dynamicDowncast<ImageBitmapRenderingContext>(m_context.get()))
            return { { context.releaseNonNull() } };
        return { { std::nullopt } };
    }
    if (contextType == RenderingContextType::Webgpu) {
#if HAVE(WEBGPU_IMPLEMENTATION)
        if (!m_context) {
            auto scope = DECLARE_THROW_SCOPE(state.vm());
            RETURN_IF_EXCEPTION(scope, Exception { ExceptionCode::ExistingExceptionError });
            Ref scriptExecutionContext = *this->scriptExecutionContext();
            if (RefPtr globalScope = dynamicDowncast<WorkerGlobalScope>(scriptExecutionContext)) {
                if (RefPtr gpu = protect(globalScope->navigator())->gpu())
                    m_context = GPUCanvasContext::create(*this, *gpu, nullptr);
            } else if (RefPtr document = dynamicDowncast<Document>(scriptExecutionContext)) {
                if (RefPtr window = document->window()) {
                    if (RefPtr gpu = protect(window->navigator())->gpu())
                        m_context = GPUCanvasContext::create(*this, *gpu, document.get());
                }
            }
        }
        if (RefPtr context = dynamicDowncast<GPUCanvasContext>(m_context.get()))
            return { { context.releaseNonNull() } };
#endif
        return { { std::nullopt } };
    }
#if ENABLE(WEBGL)
    if (contextType == RenderingContextType::Webgl || contextType == RenderingContextType::Webgl2) {
        auto webGLVersion = contextType == RenderingContextType::Webgl ? WebGLVersion::WebGL1 : WebGLVersion::WebGL2;
        if (!m_context) {
            auto scope = DECLARE_THROW_SCOPE(state.vm());

            auto attributes = convert<IDLDictionary<WebGLContextAttributes>>(state, arguments.isEmpty() ? JSC::jsUndefined() : (arguments[0].isObject() ? arguments[0].get() : JSC::jsNull()));
            if (attributes.hasException(scope)) [[unlikely]]
                return Exception { ExceptionCode::ExistingExceptionError };

            RefPtr scriptExecutionContext = this->scriptExecutionContext();
            if (scriptExecutionContext) {
                auto& settings = scriptExecutionContext->settingsValues();
                if (settings.webGLEnabled && (!is<WorkerGlobalScope>(scriptExecutionContext) || settings.allowWebGLInWorkers))
                    m_context = WebGLRenderingContextBase::create(*this, attributes.releaseReturnValue(), webGLVersion);
            }
        }
        if (webGLVersion == WebGLVersion::WebGL1) {
            if (RefPtr context = dynamicDowncast<WebGLRenderingContext>(m_context.get()))
                return { { context.releaseNonNull() } };
        } else {
            if (RefPtr context = dynamicDowncast<WebGL2RenderingContext>(m_context.get()))
                return { { context.releaseNonNull() } };
        }
        return { { std::nullopt } };
    }
#endif

    return Exception { ExceptionCode::TypeError };
}

ExceptionOr<RefPtr<ImageBitmap>> OffscreenCanvas::transferToImageBitmap()
{
    if (m_detached || !m_context)
        return Exception { ExceptionCode::InvalidStateError };
    if (size().isEmpty())
        return { RefPtr<ImageBitmap> { nullptr } };
    clearCopiedImage();
    bool bitmapOriginClean = originClean();
    RefPtr buffer = m_context->transferToImageBuffer();
    if (!buffer)
        return Exception { ExceptionCode::UnknownError }; // UnknownError is used for DOM out-of-memory.
    return { ImageBitmap::create(buffer.releaseNonNull(), bitmapOriginClean) };
}

static String toEncodingMimeType(const String& mimeType)
{
    if (!MIMETypeRegistry::isSupportedImageMIMETypeForEncoding(mimeType))
        return "image/png"_s;
    return mimeType.convertToASCIILowercase();
}

static std::optional<double> NODELETE qualityFromDouble(double qualityNumber)
{
    if (!(qualityNumber >= 0 && qualityNumber <= 1))
        return std::nullopt;

    return qualityNumber;
}

void OffscreenCanvas::convertToBlob(ImageEncodeOptions&& options, Ref<DeferredPromise>&& promise)
{
    if (!originClean()) {
        promise->reject(ExceptionCode::SecurityError);
        return;
    }
    if (m_detached) {
        promise->reject(ExceptionCode::InvalidStateError);
        return;
    }
    if (size().isEmpty()) {
        promise->reject(ExceptionCode::IndexSizeError);
        return;
    }

    auto encodingMIMEType = toEncodingMimeType(options.type);
    auto quality = qualityFromDouble(options.quality);

    RefPtr context = canvasBaseScriptExecutionContext();
    Vector<uint8_t> blobData;
    if (context && context->requiresScriptTrackingPrivacyProtection(ScriptTrackingPrivacyCategory::Canvas))
        blobData = encodeData(createImageForNoiseInjection(), encodingMIMEType, quality);
    else
        blobData = encodeData(makeRenderingResultsAvailable(), encodingMIMEType, quality);

#if PLATFORM(DRIFTSTACK)
    // Wave 29-400 §9 (founder Tier-3 verdict 2026-05-19): mirrors
    // HTMLCanvasElement::toBlob — gates §1 AFP fallback below on this flag
    // so V510 / Layer B v2 substituted bytes are NOT overwritten by AFP
    // when atlas hits succeed.
    bool atlasSubstituted = false;
    // Wave 29-347: cross-context V-241/V-510 dispatch parity. Per Wave 29-345
    // empirical finding (operations/verification-log.md), HTMLCanvasElement
    // ::toDataURL applies V-241/V-510 canonical-PNG substitution when
    // FP10X_OVERRIDE=1, but OffscreenCanvas::convertToBlob did NOT, creating
    // a P1 cross-context fingerprint detection vector. Mirror the dispatch
    // here so Worker-context PNG output gets the same iPhone-canonical
    // substitution as main-thread toDataURL. v510AtlasLookup is defined
    // (non-static) in HTMLCanvasElement.cpp without a header declaration —
    // forward-declared in this TU for cross-TU linkage.
    static bool s_canvasFp10xOverrideEnabled = []() {
        const char* env = getenv("DRIFTSTACK_CANVAS_FP10X_OVERRIDE");
        return env && env[0] == '1';
    }();
    if (s_canvasFp10xOverrideEnabled && !blobData.isEmpty()
        && encodingMIMEType.containsIgnoringASCIICase("png"_s)) {
        // Wave 29-349: V-510 atlas lookup via the public Driftstack::
        // wrapper, falling back to V-241 canonical table on miss. Mirrors
        // HTMLCanvasElement.cpp:1078-1199 dispatch logic.
        String opSeqSha;
        if (RefPtr ctx2D = dynamicDowncast<CanvasRenderingContext2DBase>(m_context.get())) {
            uint16_t w = static_cast<uint16_t>(std::min<unsigned>(width(), 0xffff));
            uint16_t h = static_cast<uint16_t>(std::min<unsigned>(height(), 0xffff));
            opSeqSha = ctx2D->driftstackOpSequenceSHA256(w, h);
        }
        auto macForkDataURL = makeString("data:image/png;base64,"_s, base64Encoded(blobData.span()));
        auto substitute = Driftstack::v510AtlasLookupPublic(macForkDataURL, opSeqSha);
        bool fromV510 = !substitute.isNull();
        if (substitute.isNull()) {
            const char* canonical = lookupCanvasFp10xCanonicalWithText(width(), height(), lastFillText());
            if (!canonical)
                canonical = lookupCanvasFp10xCanonical(width(), height());
            if (canonical)
                substitute = String::fromUTF8(canonical);
        }
        static constexpr ASCIILiteral kPNGPrefix = "data:image/png;base64,"_s;
        if (!substitute.isNull() && substitute.startsWith(kPNGPrefix)) {
            auto b64View = StringView(substitute).substring(kPNGPrefix.length());
            if (auto decoded = base64Decode(b64View)) {
                blobData = std::move(*decoded);
                atlasSubstituted = true;  // §9: gate §1 AFP fallback below
                WTFLogAlways("[Driftstack-%s-Worker] canvas-fp blob substitution FIRED (%dx%d, lastFillText=%u chars)",
                    fromV510 ? "V510" : "V241", width(), height(), lastFillText().length());
            }
        }
    }
    // V-790.V2 §3.1.3 Layer B v2 ML Worker-context hook (wave 29-398).
    // Mirrors main-thread toDataURL/toBlob dispatch: gated on env var +
    // Rule Q canary bypass. Layer B v2 is per-WebProcess singleton; same
    // singleton serves Worker context (main thread + Workers share the
    // WebContent process). Inference is synchronous; Worker thread
    // blocks for ≤5ms which respects Rule O v2 HARD cap.
    static bool s_layerBV2EnabledWorker = []() {
        const char* env = getenv("DRIFTSTACK_LAYER_B_V2_ENABLED");
        return env && env[0] == '1';
    }();
    if (s_layerBV2EnabledWorker && !blobData.isEmpty()
        && encodingMIMEType.containsIgnoringASCIICase("png"_s)) {
        // Worker context: document URL lookup is via ScriptExecutionContext.
        WTF::String host;
        if (context)
            host = context->url().host().toString();
        if (!Driftstack::isCanaryFingerprintHost(host)) {
            auto blobSpan = blobData.span();
            if (auto macTile = Driftstack::macForkRGBAFromPNGBytes(blobSpan, width(), height())) {
                if (auto pred = Driftstack::LayerB::shared().predictV2(*macTile)) {
                    auto substituted = Driftstack::pngBytesFromIPhoneRGBA(pred->tile, width(), height());
                    if (!substituted.isEmpty()) {
                        blobData = WTF::move(substituted);
                        atlasSubstituted = true;  // §9: gate §1 AFP fallback below
                        WTFLogAlways("[Driftstack-LayerBV2-Worker] canvas-level RGBA substitution "
                                     "FIRED (%ux%u, inference_ms=%.3f, ane=%d)",
                                     width(), height(), pred->inference_ms, pred->ane_routed);
                    }
                }
            }
        }
    }
    // Wave 29-399 §2 probe signature emission (Worker context) — mirrors
    // toDataURL/toBlob.
    static bool s_probeSigEmitEnabledWorker = []() {
        const char* env = getenv("DRIFTSTACK_PROBE_SIGNATURE_EMIT");
        return env && env[0] == '1';
    }();
    if (s_probeSigEmitEnabledWorker && !blobData.isEmpty()
        && encodingMIMEType.containsIgnoringASCIICase("png"_s)) {
        String opSeqShaSigWorker;
        String opSeqBytesB64SigWorker;
        if (RefPtr ctx2D = dynamicDowncast<CanvasRenderingContext2DBase>(m_context.get())) {
            uint16_t wSig = static_cast<uint16_t>(std::min<unsigned>(width(), 0xffff));
            uint16_t hSig = static_cast<uint16_t>(std::min<unsigned>(height(), 0xffff));
            opSeqShaSigWorker = ctx2D->driftstackOpSequenceSHA256(wSig, hSig);
            opSeqBytesB64SigWorker = ctx2D->driftstackOpSequenceBytesBase64(wSig, hSig);
        }
        auto lastTextSigWorker = lastFillText();
        // Wave 29-400 §8.A observability: per-session + customer + page_url
        // attribution (mirrors HTMLCanvasElement toDataURL/toBlob sites).
        // In Worker context, page_url is the ScriptExecutionContext URL
        // (worker script URL OR document URL for main-thread offscreen).
        // Re-uses existing `RefPtr context = canvasBaseScriptExecutionContext()`
        // declared at the top of convertToBlob (line ~320).
        static const char* s_sessionIdWorker = getenv("DRIFTSTACK_SESSION_ID");
        static const char* s_customerIdWorker = getenv("DRIFTSTACK_CUSTOMER_ID");
        String pageURLWorker;
        if (context)
            pageURLWorker = context->url().string();
        WTFLogAlways("[Driftstack-W29399-S2-ProbeSig-Worker] "
            "w=%u h=%u opSeqSha=%s lastFillText=\"%s\" "
            "archetype=iphone17_ios18_7_safari26_4 ts=%lld mime=%s mac_len=%zu "
            "opSeqBytesB64=%s session_id=%s customer_id=%s page_url=\"%s\"",
            width(), height(),
            opSeqShaSigWorker.isEmpty() ? "<empty>" : opSeqShaSigWorker.utf8().data(),
            lastTextSigWorker.left(80).utf8().data(),
            static_cast<long long>(WTF::WallTime::now().secondsSinceEpoch().milliseconds()),
            encodingMIMEType.utf8().data(),
            blobData.size(),
            opSeqBytesB64SigWorker.isEmpty() ? "<empty>" : opSeqBytesB64SigWorker.utf8().data(),
            s_sessionIdWorker ? s_sessionIdWorker : "<unset>",
            s_customerIdWorker ? s_customerIdWorker : "<unset>",
            pageURLWorker.left(256).utf8().data());
    }
    // Wave 29-399 §1 AFP fallback (Worker context) — mirrors toDataURL/toBlob.
    // After all atlas substitution paths miss, AFP fires to replace natural
    // Mac CG bytes with randomized output. Gated DRIFTSTACK_AFP_FALLBACK_ENABLED=1.
    static bool s_afpFallbackEnabledWorker = []() {
        const char* env = getenv("DRIFTSTACK_AFP_FALLBACK_ENABLED");
        return env && env[0] == '1';
    }();
    // §9: gate AFP on !atlasSubstituted — same fix as HTMLCanvasElement::toBlob
    // to prevent AFP from overwriting V510/Layer B v2 substituted bytes.
    if (s_afpFallbackEnabledWorker && !atlasSubstituted && !blobData.isEmpty()
        && encodingMIMEType.containsIgnoringASCIICase("png"_s)) {
        if (RefPtr noiseImage = createImageForNoiseInjection()) {
            auto afpBlobData = encodeData(noiseImage.get(), encodingMIMEType, quality);
            if (!afpBlobData.isEmpty()) {
                blobData = WTF::move(afpBlobData);
                WTFLogAlways("[Driftstack-AFP-Fallback-Fired] context=Worker atlas-miss FIRED (%ux%u)",
                    width(), height());
            }
        }
    }
#endif

    if (blobData.isEmpty()) {
        promise->reject(ExceptionCode::EncodingError);
        return;
    }
    Ref<Blob> blob = Blob::create(context.get(), WTF::move(blobData), encodingMIMEType);
    promise->resolveWithNewlyCreated<IDLInterface<Blob>>(WTF::move(blob));
}

void OffscreenCanvas::didDraw(const std::optional<FloatRect>& rect, ShouldApplyPostProcessingToDirtyRect shouldApplyPostProcessingToDirtyRect)
{
    clearCopiedImage();
    scheduleCommitToPlaceholderCanvas();
    CanvasBase::didDraw(rect, shouldApplyPostProcessingToDirtyRect);
}

Image* OffscreenCanvas::copiedImage() const
{
    if (m_detached)
        return nullptr;

    if (!m_copiedImage) {
        RefPtr buffer = const_cast<OffscreenCanvas*>(this)->makeRenderingResultsAvailable(ShouldApplyPostProcessingToDirtyRect::No);
        if (buffer)
            m_copiedImage = BitmapImage::create(buffer->copyNativeImage());
    }
    return m_copiedImage.get();
}

void OffscreenCanvas::clearCopiedImage() const
{
    m_copiedImage = nullptr;
}

SecurityOrigin* OffscreenCanvas::securityOrigin() const
{
    Ref scriptExecutionContext = *canvasBaseScriptExecutionContext();
    if (auto* globalScope = dynamicDowncast<WorkerGlobalScope>(scriptExecutionContext.get()))
        return &globalScope->topOrigin();

    return &downcast<Document>(scriptExecutionContext)->securityOrigin();
}

bool OffscreenCanvas::canDetach() const
{
    return !m_detached && !m_context;
}

std::unique_ptr<DetachedOffscreenCanvas> OffscreenCanvas::detach()
{
    if (!canDetach())
        return nullptr;

    removeCanvasNeedingPreparationForDisplayOrFlush();

    m_detached = true;

    auto detached = makeUnique<DetachedOffscreenCanvas>(size(), originClean(), WTF::move(m_placeholderSource));
    setSize(IntSize(0, 0));
    return detached;
}

void OffscreenCanvas::commitToPlaceholderCanvas()
{
    if (!m_placeholderSource)
        return;
    if  (!m_context)
        return;
    if (m_context->compositingResultsNeedUpdating())
        m_context->prepareForDisplay();
    RefPtr imageBuffer = m_context->surfaceBufferToImageBuffer(CanvasRenderingContext::SurfaceBuffer::DisplayBuffer);
    if (!imageBuffer)
        return;
    m_placeholderSource->setPlaceholderBuffer(*imageBuffer, m_context->canvasBase().originClean(), m_context->isOpaque());
}

void OffscreenCanvas::scheduleCommitToPlaceholderCanvas()
{
    RefPtr scriptContext = scriptExecutionContext();
    if (scriptContext && !m_hasScheduledCommit && m_placeholderSource) {
        m_hasScheduledCommit = true;
        scriptContext->postTask([protectedThis = Ref { *this }, this] (ScriptExecutionContext&) {
            m_hasScheduledCommit = false;
            commitToPlaceholderCanvas();
        });
    }
}

void OffscreenCanvas::queueTaskKeepingObjectAlive(TaskSource source, Function<void(CanvasBase&)>&& task)
{
    ActiveDOMObject::queueTaskKeepingObjectAlive(*this, source, [task = WTF::move(task)](auto& canvas) mutable {
        task(canvas);
    });
}

void OffscreenCanvas::dispatchEvent(Event& event)
{
    EventDispatcher::dispatchEvent(std::initializer_list<EventTarget*>({ this }), event);
}

std::unique_ptr<CSSParserContext> OffscreenCanvas::createCSSParserContext() const
{
    // FIXME: Rather than using a default CSSParserContext, there should be one exposed via ScriptExecutionContext.
    return makeUnique<CSSParserContext>(HTMLStandardMode);
}

ScriptExecutionContext* OffscreenCanvas::scriptExecutionContext() const
{
    return ContextDestructionObserver::scriptExecutionContext();
}

ScriptExecutionContext* OffscreenCanvas::canvasBaseScriptExecutionContext() const
{
    return ContextDestructionObserver::scriptExecutionContext();
}

}

#endif
