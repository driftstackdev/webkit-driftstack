/*
 * Copyright (C) 2004-2023 Apple Inc. All rights reserved.
 * Copyright (C) 2007 Alp Toker <alp@atoker.com>
 * Copyright (C) 2010 Torch Mobile (Beijing) Co. Ltd. All rights reserved.
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
#include "HTMLCanvasElement.h"

#include "BitmapImage.h"
#include "Blob.h"
#include "BlobCallback.h"
#include "ByteArrayPixelBuffer.h"
#include "CanvasGradient.h"
#include "CanvasPattern.h"
#include "CanvasRenderingContext2D.h"
#include "CanvasRenderingContext2DSettings.h"
#include "ContainerNodeInlines.h"
#include "DocumentQuirks.h"
#if PLATFORM(DRIFTSTACK)
#include "DriftstackCanvasFingerprint10xOverride.h"
#include "DriftstackCanvasFingerprint10xRGBA.h"
// V-581 Phase C-3.A: forward declaration to avoid cross-dir header visibility
// (OpSequenceRecorder.h lives in html/canvas/ and isn't currently registered
// in WebCore.xcodeproj's Headers build phase that flat-namespaces .h files).
// HTMLCanvasElement.cpp only invokes the standalone self-test entry point;
// no class-type visibility needed here. Phase C-3.B will register the header
// when CanvasRenderingContext2DBase.h needs to declare an OpSequenceRecorder
// member (which is same-dir, so include resolves there without xcodeproj).
namespace WebCore { void runOpSequenceRecorderSelfTestIfRequested(); }
#if PLATFORM(DRIFTSTACK)
#include <CommonCrypto/CommonDigest.h>
#include <CoreGraphics/CoreGraphics.h>
#include <ImageIO/ImageIO.h>
#include <array>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <span>
#include <string>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <wtf/RetainPtr.h>
#include <wtf/StdLibExtras.h>
#include <wtf/Vector.h>
#include <wtf/text/Base64.h>
#include <wtf/text/CString.h>
#include <wtf/text/MakeString.h>
#endif
#endif
#include "DocumentView.h"
#include "ElementInlines.h"
#include "EventNames.h"
#include "EventTargetInlines.h"
#include "FrameDestructionObserverInlines.h"
#include "GPU.h"
#include "GPUBasedCanvasRenderingContext.h"
#include "GPUCanvasContext.h"
#include "GeometryUtilities.h"
#include "GraphicsContext.h"
#include "HTMLNames.h"
#include "HTMLParserIdioms.h"
#include "HostWindow.h"
#include "ImageBitmapRenderingContext.h"
#include "ImageBitmapRenderingContextSettings.h"
#include "ImageBuffer.h"
#include "ImageData.h"
#include "ImageUtilities.h"
#include "InspectorInstrumentation.h"
#include "JSDOMConvertDictionary.h"
#include "JSNodeCustomInlines.h"
#include "LocalFrame.h"
#include "LocalFrameLoaderClient.h"
#include "Logging.h"
#include "MIMETypeRegistry.h"
#include "Navigator.h"
#include "NodeInlines.h"
#include "OffscreenCanvas.h"
#include "PlaceholderRenderingContext.h"
#include "RenderBoxInlines.h"
#include "RenderElement.h"
#include "RenderHTMLCanvas.h"
#include "ResourceLoadObserver.h"
#include "ScriptController.h"
#include "ScriptTrackingPrivacyCategory.h"
#include "Settings.h"
#include "StringAdaptors.h"
#include "WebCoreOpaqueRoot.h"
#include <JavaScriptCore/JSCInlines.h>
#include <math.h>
#include <wtf/RAMSize.h>
#include <wtf/TZoneMallocInlines.h>
#include <wtf/text/StringBuilder.h>

#if ENABLE(MEDIA_STREAM)
#include "CanvasCaptureMediaStreamTrack.h"
#include "MediaStream.h"
#endif

#if ENABLE(WEBGL)
#include "WebGLContextAttributes.h"
#include "WebGLRenderingContext.h"
#include "WebGL2RenderingContext.h"
#endif

#if ENABLE(WEBXR)
#include "LocalDOMWindow.h"
#include "Navigator.h"
#include "NavigatorWebXR.h"
#include "WebXRSystem.h"
#endif

#if USE(GSTREAMER)
#include "VideoFrameGStreamer.h"
#endif

#if PLATFORM(COCOA)
#include "VideoFrameCV.h"
#include <pal/cf/CoreMediaSoftLink.h>
#endif

namespace WebCore {

WTF_MAKE_TZONE_ALLOCATED_IMPL(HTMLCanvasElement);

using namespace HTMLNames;

// These values come from the WhatWG/W3C HTML spec.
const int defaultWidth = 300;
const int defaultHeight = 150;

#if PLATFORM(DRIFTSTACK)
// Wave 29-499.8 Task #79 — initV510AtlasOnce lives in anonymous namespace
// below (line 814+). Forward-declare here since HTMLCanvasElement ctor
// needs to call it for the eager-init path that eliminates the
// canvas_stripe 266ms first-paint outlier (the dominant 6.8× detection
// vector). The anonymous namespace itself is internal to this TU so the
// forward decl needs to participate; using `namespace` re-entry below
// resolves scope.
namespace { void initV510AtlasOnce(); }
#endif

HTMLCanvasElement::HTMLCanvasElement(const QualifiedName& tagName, Document& document)
    : HTMLElement(tagName, document, TypeFlag::HasDidMoveToNewDocument)
    , ActiveDOMObject(document)
    , CanvasBase(IntSize(defaultWidth, defaultHeight), document)
{
    ASSERT(hasTagName(canvasTag));
#if PLATFORM(DRIFTSTACK)
    // Wave 29-499.8 Task #79 — eager atlas init at first canvas creation
    // (cold-cache 266ms outlier closure). Once-flag prevents repeat work.
    static bool s_eagerInitDone = false;
    if (!s_eagerInitDone) {
        const char* eager = getenv("DRIFTSTACK_EAGER_INIT_ATLAS");
        if (eager && eager[0] == '1') {
            initV510AtlasOnce();
            WTFLogAlways("[Driftstack-EG-WK-1.10/Task#79/EagerInit] V510 atlas eagerly initialized at first HTMLCanvasElement creation — cold-cache 266ms outlier eliminated for subsequent canvas reads (DRIFTSTACK_EAGER_INIT_ATLAS=1)");
        }
        s_eagerInitDone = true;
    }
#endif
}

Ref<HTMLCanvasElement> HTMLCanvasElement::create(Document& document)
{
    auto canvas = adoptRef(*new HTMLCanvasElement(canvasTag, document));
    canvas->suspendIfNeeded();
    return canvas;
}

Ref<HTMLCanvasElement> HTMLCanvasElement::create(const QualifiedName& tagName, Document& document)
{
    auto canvas = adoptRef(*new HTMLCanvasElement(tagName, document));
    canvas->suspendIfNeeded();
    return canvas;
}

HTMLCanvasElement::~HTMLCanvasElement()
{
    // FIXME: This has to be called here because Style::CanvasImage::canvasDestroyed()
    // downcasts the CanvasBase object to HTMLCanvasElement. That invokes virtual methods, which should be
    // avoided in destructors, but works as long as it's done before HTMLCanvasElement destructs completely.
    notifyObserversCanvasDestroyed();
    removeCanvasNeedingPreparationForDisplayOrFlush();
}

bool HTMLCanvasElement::hasPresentationalHintsForAttribute(const QualifiedName& name) const
{
    if (name == widthAttr || name == heightAttr)
        return true;
    return HTMLElement::hasPresentationalHintsForAttribute(name);
}

void HTMLCanvasElement::collectPresentationalHintsForAttribute(const QualifiedName& name, const AtomString& value, MutableStyleProperties& style)
{
    if (name == widthAttr)
        applyAspectRatioWithoutDimensionalRulesFromWidthAndHeightAttributesToStyle(value, attributeWithoutSynchronization(heightAttr), style);
    else if (name == heightAttr)
        applyAspectRatioWithoutDimensionalRulesFromWidthAndHeightAttributesToStyle(attributeWithoutSynchronization(widthAttr), value, style);
    else
        HTMLElement::collectPresentationalHintsForAttribute(name, value, style);
}

void HTMLCanvasElement::attributeChanged(const QualifiedName& name, const AtomString& oldValue, const AtomString& newValue, AttributeModificationReason attributeModificationReason)
{
    if (name == widthAttr || name == heightAttr) {
        if (!isControlledByOffscreen())
            didUpdateSizeProperties();
    }
    HTMLElement::attributeChanged(name, oldValue, newValue, attributeModificationReason);
}

RenderPtr<RenderElement> HTMLCanvasElement::createElementRenderer(RenderStyle&& style, const RenderTreePosition& insertionPosition)
{
    RefPtr frame = document().frame();
    if (frame && protect(frame->script())->canExecuteScripts(ReasonForCallingCanExecuteScripts::NotAboutToExecuteScript))
        return createRenderer<RenderHTMLCanvas>(*this, WTF::move(style));
    return HTMLElement::createElementRenderer(WTF::move(style), insertionPosition);
}

bool HTMLCanvasElement::isReplaced(const RenderStyle*) const
{
    RefPtr frame = document().frame();
    return frame && protect(frame->script())->canExecuteScripts(ReasonForCallingCanExecuteScripts::NotAboutToExecuteScript);
}

bool HTMLCanvasElement::canContainRangeEndPoint() const
{
    return false;
}

bool HTMLCanvasElement::canStartSelection() const
{
    return false;
}

ExceptionOr<void> HTMLCanvasElement::setHeight(unsigned value)
{
    if (isControlledByOffscreen())
        return Exception { ExceptionCode::InvalidStateError };
    setAttributeWithoutSynchronization(heightAttr, AtomString::number(limitToOnlyHTMLNonNegative(value, defaultHeight)));
    return { };
}

ExceptionOr<void> HTMLCanvasElement::setWidth(unsigned value)
{
    if (isControlledByOffscreen())
        return Exception { ExceptionCode::InvalidStateError };
    setAttributeWithoutSynchronization(widthAttr, AtomString::number(limitToOnlyHTMLNonNegative(value, defaultWidth)));
    return { };
}

void HTMLCanvasElement::setSizeForControllingContext(IntSize newSize)
{
    if (newSize == size())
        return;
    m_ignoreDidUpdateSizeProperties = true;
    setAttributeWithoutSynchronization(widthAttr, AtomString::number(limitToOnlyHTMLNonNegative(newSize.width(), defaultWidth)));
    setAttributeWithoutSynchronization(heightAttr, AtomString::number(limitToOnlyHTMLNonNegative(newSize.height(), defaultHeight)));
    m_ignoreDidUpdateSizeProperties = false;
    didUpdateSizeProperties();
}

ExceptionOr<std::optional<RenderingContext>> HTMLCanvasElement::getContext(JSC::JSGlobalObject& state, const String& contextId, FixedVector<JSC::Strong<JSC::Unknown>>&& arguments)
{
    if (m_context) {
        if (m_context->isPlaceholder())
            return Exception { ExceptionCode::InvalidStateError };

        if (RefPtr context = dynamicDowncast<CanvasRenderingContext2D>(*m_context)) {
            if (!is2dType(contextId))
                return std::optional<RenderingContext> { std::nullopt };
            return std::optional<RenderingContext> { context.releaseNonNull() };
        }

        if (RefPtr context = dynamicDowncast<ImageBitmapRenderingContext>(*m_context)) {
            if (!isBitmapRendererType(contextId))
                return std::optional<RenderingContext> { std::nullopt };
            return std::optional<RenderingContext> { context.releaseNonNull() };
        }

#if ENABLE(WEBGL)
        if (m_context->isWebGL()) {
            if (!isWebGLType(contextId))
                return std::optional<RenderingContext> { std::nullopt };
            auto version = toWebGLVersion(contextId);
            if ((version == WebGLVersion::WebGL1) != m_context->isWebGL1())
                return std::optional<RenderingContext> { std::nullopt };
            if (RefPtr context = dynamicDowncast<WebGLRenderingContext>(*m_context))
                return std::optional<RenderingContext> { context.releaseNonNull() };
            return std::optional<RenderingContext> { downcast<WebGL2RenderingContext>(*m_context) };
        }
#endif

        if (RefPtr context = dynamicDowncast<GPUCanvasContext>(m_context.get())) {
            if (!isWebGPUType(contextId))
                return { std::nullopt };
            return { context.releaseNonNull() };
        }

        ASSERT_NOT_REACHED();
        return std::optional<RenderingContext> { std::nullopt };
    }

    if (is2dType(contextId)) {
        Ref vm = state.vm();
        auto scope = DECLARE_THROW_SCOPE(vm);

        auto settings = convert<IDLDictionary<CanvasRenderingContext2DSettings>>(state, arguments.isEmpty() ? JSC::jsUndefined() : (arguments[0].isObject() ? arguments[0].get() : JSC::jsNull()));
        if (settings.hasException(scope)) [[unlikely]]
            return Exception { ExceptionCode::ExistingExceptionError };

        RefPtr context = createContext2d(contextId, settings.releaseReturnValue());
        if (!context)
            return std::optional<RenderingContext> { std::nullopt };
        return std::optional<RenderingContext> { context.releaseNonNull() };
    }

    if (isBitmapRendererType(contextId)) {
        Ref vm = state.vm();
        auto scope = DECLARE_THROW_SCOPE(vm);

        auto settings = convert<IDLDictionary<ImageBitmapRenderingContextSettings>>(state, arguments.isEmpty() ? JSC::jsUndefined() : (arguments[0].isObject() ? arguments[0].get() : JSC::jsNull()));
        if (settings.hasException(scope)) [[unlikely]]
            return Exception { ExceptionCode::ExistingExceptionError };

        RefPtr context = createContextBitmapRenderer(contextId, settings.releaseReturnValue());
        if (!context)
            return std::optional<RenderingContext> { std::nullopt };
        return std::optional<RenderingContext> { context.releaseNonNull() };
    }

#if ENABLE(WEBGL)
    if (isWebGLType(contextId)) {
        Ref vm = state.vm();
        auto scope = DECLARE_THROW_SCOPE(vm);

        auto attributes = convert<IDLDictionary<WebGLContextAttributes>>(state, arguments.isEmpty() ? JSC::jsUndefined() : (arguments[0].isObject() ? arguments[0].get() : JSC::jsNull()));
        if (attributes.hasException(scope)) [[unlikely]]
            return Exception { ExceptionCode::ExistingExceptionError };

        RefPtr context = createContextWebGL(toWebGLVersion(contextId), attributes.releaseReturnValue());
        if (!context)
            return std::optional<RenderingContext> { std::nullopt };

        if (RefPtr webGLContext = dynamicDowncast<WebGLRenderingContext>(context))
            return { webGLContext.releaseNonNull() };

        return std::optional<RenderingContext> { downcast<WebGL2RenderingContext>(context.releaseNonNull()) };
    }
#endif

    if (isWebGPUType(contextId)) {
        RefPtr<GPU> gpu;
        if (RefPtr window = document().window()) {
            // FIXME: Should we be instead getting this through dynamicDowncast<JSDOMWindow>(state)->wrapped().navigator().gpu()?
            gpu = protect(window->navigator())->gpu();
        }
        RefPtr context = createContextWebGPU(contextId, gpu.get());
        if (!context)
            return { std::nullopt };
        return { context.releaseNonNull() };
    }

    return std::optional<RenderingContext> { std::nullopt };
}

RefPtr<CanvasRenderingContext> HTMLCanvasElement::getContext(const String& type)
{
    if (HTMLCanvasElement::is2dType(type))
        return getContext2d(type, { });

    if (HTMLCanvasElement::isBitmapRendererType(type))
        return getContextBitmapRenderer(type, { });

#if ENABLE(WEBGL)
    if (HTMLCanvasElement::isWebGLType(type))
        return getContextWebGL(HTMLCanvasElement::toWebGLVersion(type));
#endif

    if (HTMLCanvasElement::isWebGPUType(type))
        return getContextWebGPU(type, nullptr);

    return nullptr;
}

bool HTMLCanvasElement::is2dType(const String& type)
{
    return type == "2d"_s;
}

CanvasRenderingContext2D* HTMLCanvasElement::createContext2d(const String& type, CanvasRenderingContext2DSettings&& settings)
{
    ASSERT_UNUSED(HTMLCanvasElement::is2dType(type), type);
    ASSERT(!m_context);

    m_context = CanvasRenderingContext2D::create(*this, WTF::move(settings), document().inQuirksMode());
    if (!m_context)
        return nullptr;

#if ENABLE(PIXEL_FORMAT_RGBA16F) && HAVE(SUPPORT_HDR_DISPLAY)
    if (m_context->pixelFormat() == PixelFormat::RGBA16F)
        protect(document())->setHasHDRContent();
#endif

#if USE(CA) || USE(SKIA)
    // Need to make sure a RenderLayer and compositing layer get created for the Canvas.
    invalidateStyleAndLayerComposition();
#endif

    return downcast<CanvasRenderingContext2D>(m_context.get());
}

CanvasRenderingContext2D* HTMLCanvasElement::getContext2d(const String& type, CanvasRenderingContext2DSettings&& settings)
{
    ASSERT_UNUSED(HTMLCanvasElement::is2dType(type), type);

    if (!m_context)
        return createContext2d(type, WTF::move(settings));
    return dynamicDowncast<CanvasRenderingContext2D>(m_context.get());
}

#if ENABLE(WEBGL)

bool HTMLCanvasElement::isWebGLType(const String& type)
{
    // Retain support for the legacy "webkit-3d" name.
    return type == "webgl"_s || type == "experimental-webgl"_s
        || type == "webgl2"_s
        || type == "webkit-3d"_s;
}

WebGLVersion HTMLCanvasElement::toWebGLVersion(const String& type)
{
    ASSERT(isWebGLType(type));
    if (type == "webgl2"_s)
        return WebGLVersion::WebGL2;
    return WebGLVersion::WebGL1;
}

WebGLRenderingContextBase* HTMLCanvasElement::createContextWebGL(WebGLVersion type, WebGLContextAttributes&& attrs)
{
    ASSERT(!m_context);
    if (!document().settings().webGLEnabled())
        return nullptr;

#if ENABLE(WEBXR)
    // https://immersive-web.github.io/webxr/#xr-compatible
    if (attrs.xrCompatible) {
        if (RefPtr window = document().window()) {
            // FIXME: how to make this sync without blocking the main thread?
            // For reference: https://immersive-web.github.io/webxr/#ref-for-dom-webglcontextattributes-xrcompatible
            NavigatorWebXR::xr(window->navigator()).ensureImmersiveXRDeviceIsSelected([]() { });
        }
    }
#endif

    // TODO(WEBXR): ensure the context is created in a compatible graphics
    // adapter when there is an active immersive device.
    m_context = WebGLRenderingContextBase::create(*this, attrs, type);
    if (m_context) {
        // Need to make sure a RenderLayer and compositing layer get created for the Canvas.
        invalidateStyleAndLayerComposition();
        if (CheckedPtr box = renderBox())
            box->contentChanged(ContentChangeType::Canvas);
#if ENABLE(WEBXR)
        ASSERT(!attrs.xrCompatible || downcast<WebGLRenderingContextBase>(*m_context).isXRCompatible());
#endif
    }

    return downcast<WebGLRenderingContextBase>(m_context.get());
}

RefPtr<WebGLRenderingContextBase> HTMLCanvasElement::getContextWebGL(WebGLVersion type, WebGLContextAttributes&& attrs)
{
    if (!m_context)
        return createContextWebGL(type, WTF::move(attrs));

    RefPtr glContext = dynamicDowncast<WebGLRenderingContextBase>(*m_context);
    if (!glContext)
        return nullptr;

    if ((type == WebGLVersion::WebGL1) != glContext->isWebGL1())
        return nullptr;

    return glContext;
}

#endif // ENABLE(WEBGL)

bool HTMLCanvasElement::isBitmapRendererType(const String& type)
{
    return type == "bitmaprenderer"_s;
}

ImageBitmapRenderingContext* HTMLCanvasElement::createContextBitmapRenderer(const String& type, ImageBitmapRenderingContextSettings&& settings)
{
    ASSERT_UNUSED(type, HTMLCanvasElement::isBitmapRendererType(type));
    ASSERT(!m_context);

    auto context = ImageBitmapRenderingContext::create(*this, WTF::move(settings));
    WeakPtr weakContext = *context;
    m_context = WTF::move(context);
    weakContext->transferFromImageBitmap(nullptr);

#if USE(CA) || USE(SKIA)
    // Need to make sure a RenderLayer and compositing layer get created for the Canvas.
    invalidateStyleAndLayerComposition();
#endif

    return weakContext.get();
}

ImageBitmapRenderingContext* HTMLCanvasElement::getContextBitmapRenderer(const String& type, ImageBitmapRenderingContextSettings&& settings)
{
    ASSERT_UNUSED(type, HTMLCanvasElement::isBitmapRendererType(type));

    if (!m_context)
        return createContextBitmapRenderer(type, WTF::move(settings));
    return dynamicDowncast<ImageBitmapRenderingContext>(m_context.get());
}

bool HTMLCanvasElement::isWebGPUType(const String& type)
{
    return type == "webgpu"_s;
}

GPUCanvasContext* HTMLCanvasElement::createContextWebGPU(const String& type, GPU* gpu)
{
    ASSERT_UNUSED(type, HTMLCanvasElement::isWebGPUType(type));
    ASSERT(!m_context);

    if (!document().settings().webGPUEnabled() || !gpu)
        return nullptr;

    Ref document = this->document();
    m_context = GPUCanvasContext::create(*this, *gpu, document.ptr());

    if (m_context) {
        // Need to make sure a RenderLayer and compositing layer get created for the Canvas.
        invalidateStyleAndLayerComposition();
#if ENABLE(PIXEL_FORMAT_RGBA16F)
        m_context->setDynamicRangeLimit(m_dynamicRangeLimit);
#endif // ENABLE(PIXEL_FORMAT_RGBA16F)
    }

    return downcast<GPUCanvasContext>(m_context.get());
}

GPUCanvasContext* HTMLCanvasElement::getContextWebGPU(const String& type, GPU* gpu)
{
    ASSERT_UNUSED(type, HTMLCanvasElement::isWebGPUType(type));

    if (!document().settings().webGPUEnabled())
        return nullptr;

    if (!m_context)
        return createContextWebGPU(type, gpu);

    return dynamicDowncast<GPUCanvasContext>(m_context.get());
}

std::optional<FloatRect> HTMLCanvasElement::computeDirtyRectangleIfNeeded(const std::optional<FloatRect>& rect) const
{
    if (!rect)
        return std::nullopt;

#if ENABLE(DAMAGE_TRACKING)
    if (usesContentsAsLayerContents() && !document().settings().propagateDamagingInformation())
        return std::nullopt;
#else
    if (usesContentsAsLayerContents())
        return std::nullopt;
#endif

    FloatRect destRect;
    CheckedPtr renderer = renderBox();
    if (CheckedPtr renderReplaced = dynamicDowncast<RenderReplaced>(*renderer))
        destRect = renderReplaced->replacedContentRect();
    else
        destRect = renderer->contentBoxRect();

    FloatRect dirtyRect = mapRect(*rect, FloatRect { { }, size() }, destRect);
    dirtyRect.intersect(destRect);
    if (dirtyRect.isEmpty())
        return std::nullopt;

    return dirtyRect;
}

void HTMLCanvasElement::didDraw(const std::optional<FloatRect>& rect, ShouldApplyPostProcessingToDirtyRect shouldApplyPostProcessingToDirtyRect)
{
    clearCopiedImage();
    if (CheckedPtr renderer = renderBox()) {
        const std::optional<FloatRect> dirtyRect = computeDirtyRectangleIfNeeded(rect);
        if (usesContentsAsLayerContents())
            renderer->contentChanged(ContentChangeType::CanvasPixels, dirtyRect);
        else if (dirtyRect)
            renderer->repaintRectangle(enclosingIntRect(*dirtyRect));
    }
    CanvasBase::didDraw(rect, shouldApplyPostProcessingToDirtyRect);
}

void HTMLCanvasElement::didUpdateSizeProperties()
{
    if (m_ignoreDidUpdateSizeProperties)
        return;

    int w = limitToOnlyHTMLNonNegative(attributeWithoutSynchronization(widthAttr), defaultWidth);
    int h = limitToOnlyHTMLNonNegative(attributeWithoutSynchronization(heightAttr), defaultHeight);

    IntSize oldSize = size();
    IntSize newSize(w, h);
    bool sizeChanged = oldSize != newSize;
    CanvasBase::setSize(newSize);
    clearCopiedImage();
    if (m_context)
        m_context->didUpdateCanvasSizeProperties(sizeChanged);
    if (CheckedPtr canvasRenderer = dynamicDowncast<RenderHTMLCanvas>(renderer())) {
        if (sizeChanged) {
            canvasRenderer->canvasSizeChanged();
            if (canvasRenderer->hasAcceleratedCompositing())
                canvasRenderer->contentChanged(ContentChangeType::Canvas);
        }
        canvasRenderer->repaint();
    }
    notifyObserversCanvasResized();
}

bool HTMLCanvasElement::usesContentsAsLayerContents() const
{
    CheckedPtr renderBox = this->renderBox();
    if (!renderBox)
        return false;
    if (!m_context)
        return false;
    return renderBox->hasAcceleratedCompositing() && m_context->delegatesDisplay();
}

void HTMLCanvasElement::paint(GraphicsContext& context, const LayoutRect& r)
{
    if (!m_context)
        return;
    m_context->clearAccumulatedDirtyRect();

    if (!context.paintingDisabled()) {
        if (!usesContentsAsLayerContents() || protect(document())->printing() || m_isSnapshotting) {
            if (m_context->compositingResultsNeedUpdating())
                m_context->prepareForDisplay();
            if (m_context->isSurfaceBufferTransparentBlack(CanvasRenderingContext::SurfaceBuffer::DisplayBuffer)) {
                const bool skipTransparentBlackDraw = context.compositeMode() == CompositeMode { CompositeOperator::SourceOver, BlendMode::Normal };
                if (!skipTransparentBlackDraw)
                    context.fillRect(snappedIntRect(r), Color::transparentBlack);
            } else {
                RefPtr buffer = m_context->surfaceBufferToImageBuffer(CanvasRenderingContext::SurfaceBuffer::DisplayBuffer);
                if (buffer)
                    context.drawImageBuffer(*buffer, snappedIntRect(r), { context.compositeOperation() });
            }
        }
    }

    if (m_context->hasActiveInspectorCanvasCallTracer()) [[unlikely]]
        InspectorInstrumentation::didFinishRecordingCanvasFrame(*m_context);
}

static String toEncodingMimeType(const String& mimeType)
{
    if (!MIMETypeRegistry::isSupportedImageMIMETypeForEncoding(mimeType))
        return "image/png"_s;
    return mimeType.convertToASCIILowercase();
}

#if PLATFORM(DRIFTSTACK)
// V-507/V-510 V-405-A Option C atlas substitution — inline reader for
// DSCFA v1 binary atlas (mmap'd on first use). Hashes Mac fork's encoded
// dataURL via SHA-256 trunc-16, binary-searches lexicographic index, returns
// substitute String on hit; null String on miss. Header file approach was
// abandoned after build #5 confirmed SourcesCocoa.txt unified-source layout
// shift broke IOSurface/HTMLMediaElement upstream symbol resolution; inline
// here keeps build entirely within HTMLCanvasElement.cpp's TU.
//
// File format ('DSCF' magic):
//   header[32]: 4 magic + 2 version + 1 reserved + 1 keyHashAlgo + 4 numEntries
//               + 4 indexOffset + 4 dataOffset + 12 reserved
//   index[numEntries × 28]: 16 macSha256Prefix + 4 dataOffset + 4 dataLen + 4 reserved
//   data[]: concatenated UTF-8 dataURL strings
//
// Per V-510 atlas pre-capture (3998/4000 entries iPhone 17 / iOS 18.7 /
// Safari 26.4 via BS Automate). Closes V-405 fuzzer Strokes 0% / Text 0%
// architectural divergence per V-506 Rule C empirical proof.
namespace {
struct V510AtlasState {
    int fd { -1 };
    const uint8_t* mmapBase { nullptr };
    size_t mmapSize { 0 };
    std::span<const uint8_t> indexSpan;
    std::span<const uint8_t> dataPayloadSpan;
    size_t numEntries { 0 };
    uint16_t formatVersion { 1 };  // V-578: 1 = full PNG dataURL strings, 2 = pixel-delta encoding
    bool initialized { false };
    bool available { false };
};

V510AtlasState& v510AtlasState()
{
    static V510AtlasState* s_state = new V510AtlasState();
    return *s_state;
}

// Wave 29-399 §6.A (founder Tier-3 verdict 2026-05-19): priority-bin slot
// loaded alongside the main atlas. Auto-learn pipeline (§4) appends
// BS-captured iPhone canonical bytes here, keyed on opSequenceSHA256.
// v510AtlasLookup checks this slot FIRST — most-recent captures override
// the main atlas. Same DSCFA v3 format; same mmap pattern as main; same
// applyV2DeltaAndReEncode data path on hit. Hot-reload at WebContent
// session boundary works identically (§5 verified).
V510AtlasState& v510AtlasStatePriority()
{
    static V510AtlasState* s_state = new V510AtlasState();
    return *s_state;
}

// Wave 29-399 §6.A: per-state loader extracted so main + priority share
// the same mmap + header parse + magic check. isPriority drives the slot
// tag in logs so empirical verification can distinguish hits per atlas;
// also softens the open-failed log for priority (expected pre-launch).
static void loadAtlasIntoState(V510AtlasState& state, const char* path, bool isPriority)
{
    constexpr size_t kHeaderBytes = 32;
    constexpr size_t kIndexEntryStride = 28;
    const char* slot = isPriority ? "priority" : "main";

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        // Priority slot missing is expected pre-launch (no §4 chain runs
        // captured iPhone bytes yet); softened log distinguishes from
        // main-atlas misconfiguration which is a real issue.
        if (isPriority)
            WTFLogAlways("[Driftstack] V510Atlas[%s]: not present at %s — disabled (auto-learn pre-seeded)", slot, path);
        else
            WTFLogAlways("[Driftstack] V510Atlas[%s]: open failed for %s (errno=%d) — disabled", slot, path, errno);
        return;
    }
    struct stat st;
    if (fstat(fd, &st) < 0 || st.st_size < static_cast<off_t>(kHeaderBytes)) {
        WTFLogAlways("[Driftstack] V510Atlas[%s]: fstat failed or file too small", slot);
        close(fd);
        return;
    }
    void* base = mmap(nullptr, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (base == MAP_FAILED) {
        WTFLogAlways("[Driftstack] V510Atlas[%s]: mmap failed (errno=%d)", slot, errno);
        close(fd);
        return;
    }
    auto bytesSpan = unsafeMakeSpan(static_cast<const uint8_t*>(base), static_cast<size_t>(st.st_size));
    if (bytesSpan[0] != 'D' || bytesSpan[1] != 'S' || bytesSpan[2] != 'C' || bytesSpan[3] != 'F') {
        WTFLogAlways("[Driftstack] V510Atlas[%s]: bad magic at %s", slot, path);
        munmap(base, st.st_size); close(fd); return;
    }
    auto readU16 = [&](size_t off) { return uint16_t(bytesSpan[off]) | (uint16_t(bytesSpan[off+1]) << 8); };
    auto readU32 = [&](size_t off) {
        return uint32_t(bytesSpan[off]) | (uint32_t(bytesSpan[off+1]) << 8)
             | (uint32_t(bytesSpan[off+2]) << 16) | (uint32_t(bytesSpan[off+3]) << 24);
    };
    uint16_t version = readU16(4);
    uint8_t keyAlgo = bytesSpan[7];
    // V-581: accept v1/v2 (algo=1, Mac-output sha) and v3 (algo=2, op-seq sha).
    // Wave 29-399 §7 Q2 (founder Tier-3 verdict 2026-05-19): also accept v4
    // (algo=2 op-seq sha, but data section = full UTF-8 dataURL strings
    // instead of pixel-delta encoding). v4 closes the §4-chain format
    // mismatch: atlas-priority-append.py writes full iPhone dataURL bytes
    // per priority entry; v3 path dispatched through applyV2DeltaAndReEncode
    // which expected (W, H, numDeltas, N×deltas) layout and silently dropped
    // the substitution. v4 dispatches directly to String::fromUTF8.
    bool accept = (version == 1 && keyAlgo == 1)
        || (version == 2 && keyAlgo == 1)
        || (version == 3 && keyAlgo == 2)
        || (version == 4 && keyAlgo == 2);
    if (!accept) {
        WTFLogAlways("[Driftstack] V510Atlas[%s]: unsupported version=%u/algo=%u", slot, version, keyAlgo);
        munmap(base, st.st_size); close(fd); return;
    }
    state.formatVersion = version;
    uint32_t numEntries = readU32(8);
    uint32_t indexOffset = readU32(12);
    uint32_t dataOffset = readU32(16);
    if (indexOffset < kHeaderBytes
        || dataOffset != indexOffset + numEntries * kIndexEntryStride
        || dataOffset > bytesSpan.size()) {
        WTFLogAlways("[Driftstack] V510Atlas[%s]: header invalid", slot);
        munmap(base, st.st_size); close(fd); return;
    }
    state.fd = fd;
    state.mmapBase = static_cast<const uint8_t*>(base);
    state.mmapSize = st.st_size;
    state.indexSpan = bytesSpan.subspan(indexOffset, numEntries * kIndexEntryStride);
    state.dataPayloadSpan = bytesSpan.subspan(dataOffset);
    state.numEntries = numEntries;
    state.available = true;
    // Wave 29-399 §5 mtime log line (per-slot tagged so hot-reload
    // verification distinguishes priority + main reload events).
    WTFLogAlways("[Driftstack] V510Atlas[%s]: mapped %lld bytes from %s; %u entries; format=v%u; file_mtime=%lld",
        slot, (long long)st.st_size, path, numEntries, state.formatVersion,
        (long long)st.st_mtimespec.tv_sec);
}

void initV510AtlasOnce()
{
    auto& state = v510AtlasState();
    if (state.initialized)
        return;
    state.initialized = true;
    v510AtlasStatePriority().initialized = true;

    // Wave 29-499.8 Task #79 (cold-cache 6.8× slowdown closure):
    // initV510AtlasOnce is called lazily on first canvas paint of a session
    // — that first canvas pays 257ms of mmap + parse cost vs iPhone's 8ms,
    // a 32× detection signal. To eliminate the cold-cache outlier, callers
    // (WebProcess startup, document construction, etc.) eagerly invoke
    // this function via DRIFTSTACK_EAGER_INIT_ATLAS=1 + the constructor
    // hook below. Subsequent first-canvas calls become 0-cost (state
    // already initialized — early return above).

    // V-581 Phase C-3.A: run OpSequenceRecorder canonical-serializer self-test
    // exactly once if DRIFTSTACK_TEST_OPSEQ=1. Placed before the atlas-file
    // checks so a missing/unreadable atlas does not skip the test. No-ops when
    // env var unset; logs PASS/FAIL via WTFLogAlways; never aborts startup.
    runOpSequenceRecorderSelfTestIfRequested();

    // Wave 29-392: main atlas default path = Wave 29-378 family-B-supplemented
    // atlas (3084 entries / 30.09 MB / git-tracked) at the correctly-named
    // driftstack_canvas_fuzz_atlas/ directory. Replaces pre-Wave-29-378
    // default at driftstack_audio_atlas/ which held a Family-A-polluted
    // 25.81 MB atlas accumulated through Waves 29-272 → 29-280. Production
    // sessions that don't set DRIFTSTACK_CANVAS_FUZZ_ATLAS_PATH now use
    // the launch-archetype-clean atlas by default.
    // V-211: the dev-default paths derive from the environment
    // (DRIFTSTACK_DATA_ROOT, else $HOME/code/driftstack) instead of a
    // hardcoded build-machine home directory. One-time strdup, process lifetime.
    auto fuzzAtlasDefaultPath = [](const char* fileName) -> const char* {
        const char* root = getenv("DRIFTSTACK_DATA_ROOT");
        const char* home = getenv("HOME");
        std::string p = (root && *root) ? std::string(root) : std::string(home ? home : "") + "/code/driftstack";
        p += "/reference/driftstack_canvas_fuzz_atlas/";
        p += fileName;
        return strdup(p.c_str());
    };
    static const char* kDefaultPath = fuzzAtlasDefaultPath("driftstack-canvas-fuzz-atlas-family-b-supplemented.bin");
    // Wave 29-399 §6.A: priority bin default path matches atlas-priority-append.py
    // DEFAULT_OUTPUT_BIN. Same directory as main atlas. atlas-priority-append.py
    // builds this from §4 chain captures (BS-side iPhone canonical bytes for
    // probe signatures emitted in §2). Pre-launch this file may not exist
    // (auto-learn hasn't run yet) — loadAtlasIntoState silently disables.
    static const char* kDefaultPriorityPath = fuzzAtlasDefaultPath("driftstack-canvas-fuzz-atlas-wave29-399-priority.bin");

    // V-511 multi-archetype foundation: orchestrator sets DRIFTSTACK_CANVAS_FUZZ_ATLAS_PATH
    // explicitly per archetype. WebKit dispatch reads single env var; archetype
    // dispatch happens above the WebKit layer (harness / GUI / agent service
    // per file 04 architecture).
    const char* envPath = getenv("DRIFTSTACK_CANVAS_FUZZ_ATLAS_PATH");
    const char* path = envPath ? envPath : kDefaultPath;
    loadAtlasIntoState(state, path, /*isPriority*/ false);

    // Wave 29-399 §6.A: priority bin override env. Same archetype-dispatch
    // pattern — orchestrator passes per-archetype priority path if needed.
    const char* envPriorityPath = getenv("DRIFTSTACK_CANVAS_FUZZ_ATLAS_PRIORITY_PATH");
    const char* priorityPath = envPriorityPath ? envPriorityPath : kDefaultPriorityPath;
    loadAtlasIntoState(v510AtlasStatePriority(), priorityPath, /*isPriority*/ true);
}

// Wave 29-499.8 Task #79 — eager atlas init is hooked into the
// HTMLCanvasElement constructor (line 161+) when env
// DRIFTSTACK_EAGER_INIT_ATLAS=1 is set, eliminating the
// canvas_stripe_400x60 first-call 266ms outlier (vs iPhone 8.33ms)
// that is the dominant component of the Mac fork's 6.8× suite-total
// slowdown detection vector. The constructor's static once-flag
// ensures only the FIRST canvas element pays the ~250ms cost; all
// subsequent canvas elements and first-canvas-read paths are 0-cost.

// V-578: apply delta-pixel substitution to a Mac dataURL.
//
// For DSCFA v2 entries: instead of replacing the entire dataURL with iPhone bytes,
// the atlas stores only the pixel locations where Mac and iPhone diverge (~50 pixels
// per ~95k pixel canvas, per V-573 empirical). We:
//   1. Decode the Mac PNG dataURL to a raw RGBA pixel buffer
//   2. Apply the delta list (overwrite divergent pixels with iPhone RGBA values)
//   3. Re-encode through Mac CG with kCGImageAlphaLast + sRGB (the V-578 mode that
//      empirically reproduces iPhone Safari's PNG byte stream exactly)
//
// V-578 round-trip empirically validated 10/10 bit-identical at the Python level.
// Per V-578 verifier: kCGImageAlphaLast (non-premultiplied) is the only mode that
// produces iPhone-byte-identical PNG; premultipliedLast/premultipliedFirst etc.
// produce different byte sequences.
static String applyV2DeltaAndReEncode(const String& macForkDataURL, std::span<const uint8_t> entryBytes)
{
    // 1. Parse v2 entry header: u16 W + u16 H + u32 numDeltas + N×8-byte deltas
    if (entryBytes.size() < 8)
        return String();
    uint16_t canvasW = uint16_t(entryBytes[0]) | (uint16_t(entryBytes[1]) << 8);
    uint16_t canvasH = uint16_t(entryBytes[2]) | (uint16_t(entryBytes[3]) << 8);
    uint32_t numDeltas = uint32_t(entryBytes[4]) | (uint32_t(entryBytes[5]) << 8)
                       | (uint32_t(entryBytes[6]) << 16) | (uint32_t(entryBytes[7]) << 24);
    if (entryBytes.size() != size_t(8) + size_t(numDeltas) * 8)
        return String();

    // 2. Strip "data:image/png;base64," prefix and base64-decode
    static constexpr ASCIILiteral kPrefix = "data:image/png;base64,"_s;
    if (!macForkDataURL.startsWith(kPrefix))
        return String();
    auto b64View = StringView(macForkDataURL).substring(kPrefix.length());
    auto pngBytesOpt = base64Decode(b64View);
    if (!pngBytesOpt)
        return String();
    auto pngBytes = *pngBytesOpt;

    // 3. Decode PNG via CGImageSource
    auto cfData = adoptCF(CFDataCreate(kCFAllocatorDefault,
        pngBytes.span().data(), static_cast<CFIndex>(pngBytes.size())));
    if (!cfData)
        return String();
    auto imageSource = adoptCF(CGImageSourceCreateWithData(cfData.get(), nullptr));
    if (!imageSource || CGImageSourceGetCount(imageSource.get()) == 0)
        return String();
    auto cgImage = adoptCF(CGImageSourceCreateImageAtIndex(imageSource.get(), 0, nullptr));
    if (!cgImage)
        return String();

    size_t imgW = CGImageGetWidth(cgImage.get());
    size_t imgH = CGImageGetHeight(cgImage.get());
    if (imgW != canvasW || imgH != canvasH) {
        WTFLogAlways("[Driftstack-V578] dim mismatch: dataURL=%zux%zu, atlas=%ux%u",
            imgW, imgH, canvasW, canvasH);
        return String();
    }

    // 4. Render the CGImage into a non-premultiplied RGBA buffer.
    //    CGBitmapContext doesn't support kCGImageAlphaLast (non-premultiplied), so
    //    we render into a premultipliedLast buffer first, then un-premultiply
    //    to recover canonical RGBA bytes. Empirically (V-578 round-trip), this
    //    matches the bytes that produce iPhone-byte-identical re-encoded PNG.
    Vector<uint8_t> pmBuffer(imgW * imgH * 4);
    auto srgb = adoptCF(CGColorSpaceCreateWithName(kCGColorSpaceSRGB));
    auto bitmapCtx = adoptCF(CGBitmapContextCreate(pmBuffer.mutableSpan().data(), imgW, imgH, 8, imgW * 4,
        srgb.get(),
        static_cast<uint32_t>(kCGImageAlphaPremultipliedLast) | static_cast<uint32_t>(kCGBitmapByteOrder32Big)));
    if (!bitmapCtx)
        return String();
    CGContextSetBlendMode(bitmapCtx.get(), kCGBlendModeCopy);
    CGContextDrawImage(bitmapCtx.get(), CGRectMake(0, 0, imgW, imgH), cgImage.get());

    // Un-premultiply to canonical RGBA
    Vector<uint8_t> rgbaBuffer(imgW * imgH * 4);
    for (size_t i = 0; i < imgW * imgH; ++i) {
        uint8_t r = pmBuffer[i*4 + 0];
        uint8_t g = pmBuffer[i*4 + 1];
        uint8_t b = pmBuffer[i*4 + 2];
        uint8_t a = pmBuffer[i*4 + 3];
        if (a == 0) {
            rgbaBuffer[i*4 + 0] = 0;
            rgbaBuffer[i*4 + 1] = 0;
            rgbaBuffer[i*4 + 2] = 0;
            rgbaBuffer[i*4 + 3] = 0;
        } else {
            rgbaBuffer[i*4 + 0] = uint8_t((uint32_t(r) * 255 + (a / 2)) / a);
            rgbaBuffer[i*4 + 1] = uint8_t((uint32_t(g) * 255 + (a / 2)) / a);
            rgbaBuffer[i*4 + 2] = uint8_t((uint32_t(b) * 255 + (a / 2)) / a);
            rgbaBuffer[i*4 + 3] = a;
        }
    }

    // 5. Apply deltas
    for (uint32_t i = 0; i < numDeltas; ++i) {
        size_t off = 8 + size_t(i) * 8;
        uint16_t x = uint16_t(entryBytes[off]) | (uint16_t(entryBytes[off+1]) << 8);
        uint16_t y = uint16_t(entryBytes[off+2]) | (uint16_t(entryBytes[off+3]) << 8);
        uint8_t r = entryBytes[off+4];
        uint8_t g = entryBytes[off+5];
        uint8_t b = entryBytes[off+6];
        uint8_t a = entryBytes[off+7];
        if (x >= canvasW || y >= canvasH)
            continue;
        size_t pixIdx = (size_t(y) * canvasW + x) * 4;
        rgbaBuffer[pixIdx + 0] = r;
        rgbaBuffer[pixIdx + 1] = g;
        rgbaBuffer[pixIdx + 2] = b;
        rgbaBuffer[pixIdx + 3] = a;
    }

    // 6. Re-encode patched RGBA via CGImage with kCGImageAlphaLast + sRGB.
    //    Per V-578 empirical: this is the unique mode that produces iPhone-byte-
    //    identical PNG output for the same RGBA bytes. Using a CGDataProvider
    //    (not a CGBitmapContext) because CGBitmapContext doesn't support .last.
    auto rgbaCFData = adoptCF(CFDataCreate(kCFAllocatorDefault, rgbaBuffer.span().data(),
        static_cast<CFIndex>(rgbaBuffer.size())));
    if (!rgbaCFData)
        return String();
    auto provider = adoptCF(CGDataProviderCreateWithCFData(rgbaCFData.get()));
    if (!provider)
        return String();
    auto patchedImage = adoptCF(CGImageCreate(canvasW, canvasH, 8, 32, canvasW * 4,
        srgb.get(),
        static_cast<uint32_t>(kCGImageAlphaLast),
        provider.get(), nullptr, false, kCGRenderingIntentDefault));
    if (!patchedImage)
        return String();

    auto outCFData = adoptCF(CFDataCreateMutable(kCFAllocatorDefault, 0));
    auto destination = adoptCF(CGImageDestinationCreateWithData(outCFData.get(),
        CFSTR("public.png"), 1, nullptr));
    if (!destination)
        return String();
    CGImageDestinationAddImage(destination.get(), patchedImage.get(), nullptr);
    if (!CGImageDestinationFinalize(destination.get()))
        return String();

    // 7. Wrap as base64 dataURL
    auto encodedSpan = unsafeMakeSpan(CFDataGetBytePtr(outCFData.get()),
        static_cast<size_t>(CFDataGetLength(outCFData.get())));
    auto b64Out = base64Encoded(encodedSpan);
    return makeString("data:image/png;base64,"_s, b64Out);
}

// Wave 29-399 §6.A: per-state binary-search lookup extracted from
// v510AtlasLookup so priority + main slots share the same code path.
// slot tag drives the [Driftstack-V510-HIT] log so empirical verification
// can distinguish where a hit came from.
static String v510AtlasLookupInState(const V510AtlasState& state, const String& macForkDataURL, const String& opSequenceSHA256Hex, const char* slot)
{
    if (!state.available || !state.numEntries)
        return String();

    constexpr size_t kIndexEntryStride = 28;
    constexpr size_t kHashBytes = 16;

    // V-581 Phase C-3.C: dispatch by atlas format version.
    //   v1/v2 atlas (keyHashAlgo=1, formatVersion=1|2): key = first 16 bytes
    //     of CC_SHA256(macForkDataURL.utf8()) — backwards compatible.
    //   v3 atlas (keyHashAlgo=2, formatVersion=3): key = first 16 bytes of
    //     opSequenceSHA256Hex (the JS-side / C++-side op-sequence canonical hash).
    //     Data section = pixel-delta encoded (W, H, numDeltas, N×8B deltas).
    //   v4 atlas (keyHashAlgo=2, formatVersion=4): SAME key derivation as v3
    //     (op-seq sha first 16 bytes) BUT data section = full UTF-8 dataURL
    //     strings (no delta encoding). Used by §4 auto-learn chain priority
    //     bin where storing the full iPhone canonical dataURL is simpler
    //     than computing pixel deltas Mac↔iPhone.
    //     If opSeqSha is empty (e.g. no canvas ops were recorded, or the canvas
    //     context is not 2D), v3/v4 lookup is skipped and atlas miss returned.
    std::array<uint8_t, CC_SHA256_DIGEST_LENGTH> fullDigest;
    if (state.formatVersion == 3 || state.formatVersion == 4) {
        if (opSequenceSHA256Hex.length() < 32)
            return String();  // need at least 16 bytes (32 hex chars) of key
        // Decode first 16 bytes from hex.
        for (size_t i = 0; i < kHashBytes; ++i) {
            char hi = opSequenceSHA256Hex[i * 2];
            char lo = opSequenceSHA256Hex[i * 2 + 1];
            auto fromHex = [](char c) -> int {
                if (c >= '0' && c <= '9') return c - '0';
                if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                return -1;
            };
            int hiV = fromHex(hi), loV = fromHex(lo);
            if (hiV < 0 || loV < 0)
                return String();
            fullDigest[i] = static_cast<uint8_t>((hiV << 4) | loV);
        }
        // Zero-fill remaining bytes (only first 16 used for index lookup).
        for (size_t i = kHashBytes; i < CC_SHA256_DIGEST_LENGTH; ++i)
            fullDigest[i] = 0;
    } else {
        auto utf8 = macForkDataURL.utf8();
        CC_SHA256(utf8.data(), static_cast<CC_LONG>(utf8.length()), fullDigest.data());
    }

    size_t lo = 0, hi = state.numEntries;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        auto entrySpan = state.indexSpan.subspan(mid * kIndexEntryStride, kIndexEntryStride);
        int cmp = 0;
        for (size_t b = 0; b < kHashBytes; ++b) {
            if (entrySpan[b] < fullDigest[b]) { cmp = -1; break; }
            if (entrySpan[b] > fullDigest[b]) { cmp = +1; break; }
        }
        if (cmp < 0) lo = mid + 1;
        else if (cmp > 0) hi = mid;
        else {
            uint32_t dataOff = uint32_t(entrySpan[16]) | (uint32_t(entrySpan[17]) << 8)
                             | (uint32_t(entrySpan[18]) << 16) | (uint32_t(entrySpan[19]) << 24);
            uint32_t dataLen = uint32_t(entrySpan[20]) | (uint32_t(entrySpan[21]) << 8)
                             | (uint32_t(entrySpan[22]) << 16) | (uint32_t(entrySpan[23]) << 24);
            // W2530: compute dataOff+dataLen in 64-bit — both are uint32 read straight from the
            // atlas file, so a 32-bit add WRAPS on a malformed/corrupt atlas (e.g. dataOff=0xFFFFFF00,
            // dataLen=0x200 → 0x100), passing this bound while the subspan below reads ~4GB past the
            // payload = WebContent crash. Promoting to uint64 makes the bound exact (cf. the already-
            // correct DriftstackAudioAtlas.mm / DriftstackWebGPUAtlas.mm per-entry checks).
            if (static_cast<uint64_t>(dataOff) + static_cast<uint64_t>(dataLen) > state.dataPayloadSpan.size())
                return String();
            auto entry = state.dataPayloadSpan.subspan(dataOff, dataLen);
            static unsigned hits = 0;
            if (++hits <= 50)
                WTFLogAlways("[Driftstack-V510-HIT] slot=%s entry=%zu/%zu off=%u len=%u format=v%u",
                    slot, mid, state.numEntries, dataOff, dataLen, state.formatVersion);
            // V-578 / V-581: dispatch by atlas format version. v2 (Mac-output-sha
            // keyed) and v3 (op-seq-sha keyed) both use the same delta-pixel
            // data section layout, so applyV2DeltaAndReEncode handles both.
            if (state.formatVersion == 2 || state.formatVersion == 3)
                return applyV2DeltaAndReEncode(macForkDataURL, entry);
            auto charSpan = unsafeMakeSpan(reinterpret_cast<const char*>(entry.data()), entry.size());
            return String::fromUTF8(charSpan);
        }
    }
    return String();
}

String v510AtlasLookup(const String& macForkDataURL, const String& opSequenceSHA256Hex = String())
{
    initV510AtlasOnce();
    // Wave 29-399 §6.A: priority slot checked FIRST. Auto-learn captures
    // (BS-side iPhone canonical bytes for novel probe signatures) override
    // the main atlas. Most-recent capture wins.
    auto& priorityState = v510AtlasStatePriority();
    if (priorityState.available && priorityState.numEntries) {
        String hit = v510AtlasLookupInState(priorityState, macForkDataURL, opSequenceSHA256Hex, "priority");
        if (!hit.isEmpty())
            return hit;
    }
    // Fall through to main atlas on priority-miss.
    return v510AtlasLookupInState(v510AtlasState(), macForkDataURL, opSequenceSHA256Hex, "main");
}
} // anonymous namespace

// Wave 29-349: public Driftstack:: wrapper for v510AtlasLookup so cross-TU
// callers (OffscreenCanvas::convertToBlob, HTMLCanvasElement::toBlob) can
// reach V-510 atlas substitution. Declaration in DriftstackCanvasFingerprint10xRGBA.h.
namespace Driftstack {
String v510AtlasLookupPublic(const String& macForkDataURL, const String& opSequenceSHA256Hex)
{
    return v510AtlasLookup(macForkDataURL, opSequenceSHA256Hex);
}
} // namespace Driftstack
#endif // PLATFORM(DRIFTSTACK)

// https://html.spec.whatwg.org/multipage/canvas.html#a-serialisation-of-the-bitmap-as-a-file
static std::optional<double> NODELETE qualityFromJSValue(JSC::JSValue qualityValue)
{
    if (!qualityValue.isNumber())
        return std::nullopt;

    double qualityNumber = qualityValue.asNumber();
    if (qualityNumber < 0 || qualityNumber > 1)
        return std::nullopt;

    return qualityNumber;
}

ExceptionOr<UncachedString> HTMLCanvasElement::toDataURL(const String& mimeType, JSC::JSValue qualityValue)
{
    if (!originClean())
        return Exception { ExceptionCode::SecurityError };

    if (size().isEmpty())
        return UncachedString { "data:,"_s };
    Ref document = this->document();
    if (document->settings().webAPIStatisticsEnabled())
        ResourceLoadObserver::singleton().logCanvasRead(document);

    auto encodingMIMEType = toEncodingMimeType(mimeType);
    auto quality = qualityFromJSValue(qualityValue);

#if PLATFORM(DRIFTSTACK)
    // V-185 (founder Tier-2 ack 2026-05-04 V-171 Path 2 fallback): canvas-fp
    // canonical-probe substitution. The cumulative-rig canvas.fingerprint10x
    // probe creates a 220x30 canvas, fillRects #069, fillText('Cwm fjordbank
    // glyphs vext quiz, 😃🍕'), then toDataURL. Mac fork's V-141 ASCII atlas +
    // F.1.B-2 emoji atlas dispatch produce a near-iPhone-equivalent canvas
    // (V-183: 83% pixel match) but the residual ~17% AA-edge differences
    // hash-differ from iPhone (V-127 4-variant subpixel quantization is the
    // root cause; finer-subpixel atlas recapture is the architectural fix).
    // For Phase 2 closure, this hook detects the canonical-probe shape via
    // (canvas size, last fillText content) and substitutes iPhone's
    // canonical dataURL bytes. Closes 13 canvas.fingerprint10x surfaces
    // (hashes[0..9] + sampleDataUrls[0..2]). Probe-shape-specific; arbitrary
    // canvas content falls through to native encoding.
    static bool s_canvasFp10xOverrideEnabled = []() {
        const char* env = getenv("DRIFTSTACK_CANVAS_FP10X_OVERRIDE");
        return env && env[0] == '1';
    }();
    // V-236 (2026-05-06): multi-shape dispatch. lookupCanvasFp10xCanonical
    // returns the iPhone canonical dataURL for known canvas-fp probe shapes
    // (tracker-probe 240×50, FP-library variants, tracker-detector-suite, tracker-script-substitution, etc.) or
    // nullptr for unknown shapes. Dispatch on (width, height) — collisions
    // go to first-match (220x30 → text_2line_emoji_220x30 wins over text_2line_220x30).
    // Per founder overnight direction: bit-identical iPhone canvas across
    // every vendor by per-shape iPhone-byte substitution. iOS 18.4/18.6
    // captures (BS Automate) cover the iOS-pre-26.4 archetype class.
    // V-241 (2026-05-06 overnight): content-aware dispatch via
    // lastFillText() (now always-tracked on PLATFORM(DRIFTSTACK) per
    // CanvasBase::recordLastFillText V-241 patch). Closes the V-236
    // text_2line_220x30 vs text_2line_emoji_220x30 collision: same dimensions
    // but different fillText content → different table entries.
    // V-510-precedence reordering (wave 29-200/29-201): compute Mac
    // fork's encoded dataURL FIRST, then try V-510 atlas. Only fall back
    // to V-241 legacy canonical table when V-510 misses. This gives the
    // modern atlas (keyed on sha256(macForkDataURL), per-render
    // deterministic, covers vendor probe extensions) precedence over
    // V-241's hardcoded iOS 18.6-era canonical bytes. The cost: every
    // toDataURL pays the encode+sha256 work upfront; that work was
    // already done for V-510 atlas lookup later, so we just move it.
    // Per founder direction "bit identical on any canvas/font test ...
    // for any randomized test any site might make".
    if (s_canvasFp10xOverrideEnabled && encodingMIMEType.containsIgnoringASCIICase("png"_s)) {
        // Try V-510 atlas first via a tentative encode. We compute the
        // op-sequence sha + Mac fork dataURL, look up, return iPhone
        // bytes on hit. Only on V-510 miss do we proceed to V-241.
        String opSeqSha_early;
        if (RefPtr ctx2D = dynamicDowncast<CanvasRenderingContext2DBase>(m_context.get())) {
            uint16_t w = static_cast<uint16_t>(std::min<unsigned>(width(), 0xffff));
            uint16_t h = static_cast<uint16_t>(std::min<unsigned>(height(), 0xffff));
            opSeqSha_early = ctx2D->driftstackOpSequenceSHA256(w, h);
        }
        // We don't have `encoded` yet; compute it lazily only if V-510
        // is enabled (else skip the early-encode cost).
        static bool s_v510EnabledEarly = []() {
            const char* env = getenv("DRIFTSTACK_CANVAS_FUZZ_ATLAS");
            return env && env[0] == '1';
        }();
        if (s_v510EnabledEarly) {
            auto encodedEarly = encodeDataURL(makeRenderingResultsAvailable(), encodingMIMEType, quality);
            auto substituteEarly = v510AtlasLookup(encodedEarly, opSeqSha_early);
            if (!substituteEarly.isNull()) {
                WTFLogAlways("[Driftstack-V510-EARLY] CanvasFuzzAtlas substitution FIRED (%dx%d, mac-len=%u, ip-len=%u) — pre-V-241",
                    width(), height(), encodedEarly.length(), substituteEarly.length());
                return UncachedString { substituteEarly };
            }
            // V-510 miss → fall through to V-241 + later atlas paths.
            // Note: encodedEarly is discarded; later code re-encodes via
            // its own path. Could cache for perf but keeping the flow
            // simple — V-510 atlas hits short-circuit anyway.
        }
        auto fillText = lastFillText();
        // Exact (dims + lastFillText) match ONLY. The dimension-only fallback
        // substituted ANOTHER canvas's canonical for uncovered (width,height)
        // states — a 100%-WRONG canvas (proven by the rigcanvas test: a 200x100
        // 'cumrig-cr2d-0' canvas got a black-bg squiggle+circle). Under the
        // bit-identical bar that's a detectable defect; native rendering is
        // device-exact for uncovered content, so on a miss we fall through.
        const char* canonical = lookupCanvasFp10xCanonicalWithText(width(), height(), fillText);
        if (canonical) {
            WTFLogAlways("[Driftstack-V241] canvas-fp canonical substitution FIRED (%dx%d PNG, lastFillText=%d chars) — V-510 atlas miss",
                width(), height(), fillText.length());
            return UncachedString { String::fromLatin1(canonical) };
        }
    }
#endif

    if (document->requiresScriptTrackingPrivacyProtection(ScriptTrackingPrivacyCategory::Canvas))
        return UncachedString { encodeDataURL(createImageForNoiseInjection(), encodingMIMEType, quality) };

    // Wave 29-399 §2 (founder Tier-3 verdict 2026-05-19): probe signature
    // emission moved to final atlas-miss point (after V-510 post-encode
    // check at ~line 1250). Layer B v2 hoist at this location DROPPED per
    // Wave 29-398 §3.1.7 HALT verdict — see HTMLCanvasElement.cpp end of
    // toDataURL for §2 emission + §1 AFP fallback combined block.

#if USE(CG)
    // Try to get ImageData first, as that may avoid lossy conversions.
    if (auto imageData = getImageData())
        return UncachedString { encodeDataURL(imageData->byteArrayPixelBuffer().get(), encodingMIMEType, quality) };
#endif

    if (auto url = document->quirks().advancedPrivacyProtectionSubstituteDataURLForScriptWithFeatures(lastFillText(), width(), height()); !url.isNull()) {
        RELEASE_LOG(FingerprintingMitigation, "HTMLCanvasElement::toDataURL: Quirking returned URL for identified fingerprinting script");
        auto consoleMessage = "Detected fingerprinting script. Quirking value returned from HTMLCanvasElement.toDataURL()"_s;
        protect(canvasBaseScriptExecutionContext())->addConsoleMessage(MessageSource::Rendering, MessageLevel::Info, consoleMessage);
        return UncachedString { url };
    }
    auto encoded = encodeDataURL(makeRenderingResultsAvailable(), encodingMIMEType, quality);
#if PLATFORM(DRIFTSTACK)
    // V-507/V-510 V-405-A Option C atlas substitution: hash Mac fork's
    // encoded dataURL via SHA-256 (truncated 16 bytes), look up in
    // DriftstackCanvasFuzzAtlas (DSCFA v1). On hit, return iPhone-canonical
    // dataURL. Closes V-405 fuzzer Strokes 0% / Text 0% architectural
    // divergence (sub-WebKit Apple-private CG sub-pixel rasterizer per
    // V-506 empirical proof). Atlas captured iPhone 17 / iOS 18.7 /
    // Safari 26.4 via BS Automate (V-510); 3998 entries cover 4000
    // deterministic seeds (strokes+text). Substitution-critical: 2000.
    // Already-identical: 2000 (no-op return passthrough).
    // V-581 diagnostic log + dump-canvas: fire on EVERY toDataURL regardless of
    // whether atlas is enabled. Needed for rendering-pipeline divergence
    // analysis (per founder Rule N: native parity is the bar; atlas is safety
    // net). If DRIFTSTACK_DUMP_CANVAS_DIR is set, write the Mac fork's rendered
    // dataURL to <dir>/<key>.b64 so we can pixel-diff vs iPhone reference and
    // identify the C++ render path responsible for divergent pixels.
    String opSeqSha;
    if (RefPtr ctx2D = dynamicDowncast<CanvasRenderingContext2DBase>(m_context.get())) {
        uint16_t w = static_cast<uint16_t>(std::min<unsigned>(width(), 0xffff));
        uint16_t h = static_cast<uint16_t>(std::min<unsigned>(height(), 0xffff));
        opSeqSha = ctx2D->driftstackOpSequenceSHA256(w, h);
    }
    {
        std::array<uint8_t, CC_SHA256_DIGEST_LENGTH> macFullDigest;
        auto utf8 = encoded.utf8();
        CC_SHA256(utf8.data(), static_cast<CC_LONG>(utf8.length()), macFullDigest.data());
        std::array<char, 32> macHexArr;
        static constexpr std::array<char, 16> kLowerHex {{'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'}};
        for (size_t i = 0; i < 16; ++i) {
            macHexArr[i * 2] = kLowerHex[(macFullDigest[i] >> 4) & 0xf];
            macHexArr[i * 2 + 1] = kLowerHex[macFullDigest[i] & 0xf];
        }
        String macHexStr(std::span<const char> { macHexArr });
        WTFLogAlways("[Driftstack-V581-DIAG] toDataURL %ux%u opSeq=%s mac=%s mac-len=%u",
            width(), height(),
            opSeqSha.isEmpty() ? "<empty>" : opSeqSha.utf8().data(),
            macHexStr.utf8().data(),
            encoded.length());
        const char* dumpDir = std::getenv("DRIFTSTACK_DUMP_CANVAS_DIR");
        if (dumpDir) {
            String key = opSeqSha.isEmpty() ? macHexStr : opSeqSha;
            String fname = makeString(StringView::fromLatin1(dumpDir), '/', key, ".b64"_s);
            auto fnameUtf8 = fname.utf8();
            int fd = open(fnameUtf8.data(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (fd >= 0) {
                auto b64Utf8 = encoded.utf8();
                auto b64Span = unsafeMakeSpan(b64Utf8.data(), b64Utf8.length());
                write(fd, b64Span.data(), b64Span.size());
                close(fd);
            }
        }
    }
    static bool s_canvasFuzzAtlasEnabled = []() {
        const char* env = getenv("DRIFTSTACK_CANVAS_FUZZ_ATLAS");
        return env && env[0] == '1';
    }();
    if (s_canvasFuzzAtlasEnabled) {
        auto substitute = v510AtlasLookup(encoded, opSeqSha);
        if (!substitute.isNull()) {
            WTFLogAlways("[Driftstack-V510] CanvasFuzzAtlas substitution FIRED (%dx%d, mac-len=%u, ip-len=%u, opSeq=%s)",
                width(), height(), encoded.length(), substitute.length(),
                opSeqSha.isEmpty() ? "<v1/v2>" : opSeqSha.left(16).utf8().data());
            return UncachedString { substitute };
        }
    }
    // Layer B v2 ML canvas substitution REMOVED 2026-05-29 (founder: "drop the
    // ML"). Superseded by the finite-phase text atlas: BS-confirmed that CG
    // quantizes glyph sub-pixel position to a SMALL FINITE set (3 x-phases at
    // thirds + 2 y-phases) on both iPhone and the fork, so the "infinite phases"
    // premise the ML existed to predict was false — a finite phase-keyed atlas
    // closes it exactly, without approximate (and never-bit-exact) ML inference.
    // See operations/verification-log.md V-TEXT-* (2026-05-28/29).
    // Wave 29-399 §2 probe signature emission (founder Tier-3 verdict
    // 2026-05-19) — atlas growth pipeline. Fires at atlas-miss point
    // (after V-510 post-encode check above). Mac-side log collector
    // harvests these lines + POSTs to control plane priority queue
    // (§3 Agent 2 dep — endpoint POST /v1/internal/atlas-priority/
    // probe-signature). Priority queue → BS Automate iPhone 17 capture
    // (§4) → atlas update (§5) → next session sees atlas hit →
    // bit-identical iPhone bytes substituted.
    //
    // Signature: (canvas_w, canvas_h, opSeqSha, lastFillText, archetype_id,
    // timestamp_ms, mime). opSeqSha is canonical (vendor-randomness
    // stripped via existing driftstackOpSequenceSHA256 byte-spec serialization).
    //
    // Gated env DRIFTSTACK_PROBE_SIGNATURE_EMIT=1 (independent of AFP
    // fallback so each can be enabled separately for testing).
    static bool s_probeSigEmitEnabledToDataURL = []() {
        const char* env = getenv("DRIFTSTACK_PROBE_SIGNATURE_EMIT");
        return env && env[0] == '1';
    }();
    if (s_probeSigEmitEnabledToDataURL && encodingMIMEType.containsIgnoringASCIICase("png"_s)) {
        String opSeqShaSig;
        String opSeqBytesB64Sig;
        if (RefPtr ctx2D = dynamicDowncast<CanvasRenderingContext2DBase>(m_context.get())) {
            uint16_t wSig = static_cast<uint16_t>(std::min<unsigned>(width(), 0xffff));
            uint16_t hSig = static_cast<uint16_t>(std::min<unsigned>(height(), 0xffff));
            opSeqShaSig = ctx2D->driftstackOpSequenceSHA256(wSig, hSig);
            opSeqBytesB64Sig = ctx2D->driftstackOpSequenceBytesBase64(wSig, hSig);
        }
        auto lastTextSig = lastFillText();
        // Wave 29-400 §8.A observability: per-session + per-customer +
        // per-document attribution. session_id + customer_id from env
        // (ProcessLauncherCocoa forwards on WebContent spawn; harness
        // injects per-session). page_url from document->url() at the
        // hook site — already accessed elsewhere in the function so
        // re-using `document` local. Statics initialize once per process.
        // Wave 29-402 Fix 2 (founder verdict 2026-05-19 "everything perfect
        // in v1.0"): archetype reads from DRIFTSTACK_ARCHETYPE env (forwarded
        // via ProcessLauncherCocoa allowlist §8.A). Default to Family B
        // launch archetype if unset (cumrig / dev sessions).
        static const char* s_sessionId = getenv("DRIFTSTACK_SESSION_ID");
        static const char* s_customerId = getenv("DRIFTSTACK_CUSTOMER_ID");
        static const char* s_archetype = []() {
            const char* env = getenv("DRIFTSTACK_ARCHETYPE");
            return env ? env : "iphone17_ios18_7_safari26_4";
        }();
        RefPtr mainDocDU = document->mainFrameDocument();
        auto pageURL = (mainDocDU ? mainDocDU->url() : document->url()).string();
        WTFLogAlways("[Driftstack-W29399-S2-ProbeSig-toDataURL] "
            "w=%u h=%u opSeqSha=%s lastFillText=\"%s\" "
            "archetype=%s ts=%lld mime=%s mac_len=%u "
            "opSeqBytesB64=%s session_id=%s customer_id=%s page_url=\"%s\"",
            width(), height(),
            opSeqShaSig.isEmpty() ? "<empty>" : opSeqShaSig.utf8().data(),
            lastTextSig.left(80).utf8().data(),
            s_archetype,
            static_cast<long long>(WTF::WallTime::now().secondsSinceEpoch().milliseconds()),
            encodingMIMEType.utf8().data(),
            encoded.length(),
            opSeqBytesB64Sig.isEmpty() ? "<empty>" : opSeqBytesB64Sig.utf8().data(),
            s_sessionId ? s_sessionId : "<unset>",
            s_customerId ? s_customerId : "<unset>",
            pageURL.left(256).utf8().data());
    }
    // Wave 29-399 §1 AFP fallback (founder Tier-3 verdict 2026-05-19): when
    // every atlas substitution path (V-510 EARLY + V-241 canonical + V-510
    // post-encode) has missed, AFP fires to replace the natural Mac CG-
    // rendered bytes with randomized output. Vendors see randomized output
    // (not Mac-CG-detectable 1.1% match); §2 above has already emitted the
    // probe signature for atlas growth.
    //
    // createImageForNoiseInjection() generates a solid-color buffer derived
    // from noiseInjectionHashSalt (which is per-canvas via CanvasBase ctor).
    // If salt is 0 (Document policy off), we still call it — produces a
    // deterministic-but-non-Mac-CG-matching color, which is the minimum
    // viable AFP firing semantic (per founder paste: "Mac CG natural 1.1%
    // match = worst detectable signal" — anything not Mac CG is improvement).
    //
    // Gated env DRIFTSTACK_AFP_FALLBACK_ENABLED=1 (default OFF for safety;
    // flip ON after §3+§4 atlas-growth pipeline lands per founder paste).
    static bool s_afpFallbackEnabled = []() {
        const char* env = getenv("DRIFTSTACK_AFP_FALLBACK_ENABLED");
        return env && env[0] == '1';
    }();
    // §9 (Wave 29-400): toDataURL substitution paths already early-return
    // (V-510 EARLY at ~1195, V-241 at ~1209, V-510 post-encode at ~1298,
    // Layer B v2 at ~1336). Reaching here means NO substitution succeeded,
    // so atlasSubstituted is implicitly false. AFP fires correctly as
    // intended (atlas-miss path). Tag standardized to [Driftstack-AFP-
    // Fallback-Fired] across all 3 hook sites.
    // Non-text cold-miss (empty lastFillText = shapes/gradients/composite, no
    // glyph dispatch) must NOT collapse to the content-blind AFP solid color:
    // native CG render is bit-identical Mac==iPhone for non-text (13/13 canonical
    // ops hash-match the real-device /aio ref), so fall through to `encoded`.
    // Text still routes the fallback until the per-glyph iOS atlas covers it.
    if (s_afpFallbackEnabled && !lastFillText().isEmpty() && encodingMIMEType.containsIgnoringASCIICase("png"_s)) {
        if (RefPtr noiseImage = createImageForNoiseInjection()) {
            auto afpEncoded = encodeDataURL(noiseImage.get(), encodingMIMEType, quality);
            if (!afpEncoded.isEmpty()) {
                WTFLogAlways("[Driftstack-AFP-Fallback-Fired] context=toDataURL atlas-miss FIRED (%ux%u, mac-len=%u, afp-len=%u, salt-present=%d)",
                    width(), height(), encoded.length(), afpEncoded.length(),
                    canvasBaseScriptExecutionContext() && canvasBaseScriptExecutionContext()->noiseInjectionHashSalt().has_value());
                return UncachedString { afpEncoded };
            }
        }
    }
#endif
    return UncachedString { encoded };
}

ExceptionOr<UncachedString> HTMLCanvasElement::toDataURL(const String& mimeType)
{
    return toDataURL(mimeType, { });
}

ExceptionOr<void> HTMLCanvasElement::toBlob(Ref<BlobCallback>&& callback, const String& mimeType, JSC::JSValue qualityValue)
{
    if (!originClean())
        return Exception { ExceptionCode::SecurityError };

    Ref document = this->document();
    if (size().isEmpty()) {
        callback->scheduleCallback(document, nullptr);
        return { };
    }
    if (document->settings().webAPIStatisticsEnabled())
        ResourceLoadObserver::singleton().logCanvasRead(document);

    auto encodingMIMEType = toEncodingMimeType(mimeType);
#if PLATFORM(DRIFTSTACK)
    // Wave 29-499 §91.D (2026-05-20 Task #91): Family A archetype canvas.toBlob
    // with image/avif or image/heic falls back to PNG, AND the resulting Blob's
    // type field is normalized to "image/png" (not the originally-requested
    // type). Empirical: BS iPhone 16 Pro Safari 18.6 n=3 cumrig captures show
    // canvas.toBlobMIMETypes['image/avif'] = {type: 'image/png', size: 304}.
    // ImageUtilitiesCG.cpp encoder already redirects avif/heic → png bytes
    // (V-090 Track 6); this patch matches Family A's Blob.type normalization.
    // Family B (Safari 26.4+) emits image/avif natively, so leaves type intact.
    static const bool s_isFamilyAArchetypeToBlob = []() {
        const char* archetype = getenv("DRIFTSTACK_ARCHETYPE");
        if (!archetype) return false;
        std::string_view sv(archetype);
        return sv.find("safari17_") != std::string_view::npos
            || sv.find("safari18_") != std::string_view::npos
            || sv.find("safari19_") != std::string_view::npos
            || sv.find("safari26_0") != std::string_view::npos
            || sv.find("safari26_1") != std::string_view::npos
            || sv.find("safari26_2") != std::string_view::npos
            || sv.find("safari26_3") != std::string_view::npos;
    }();
    // image/avif only (Family A Safari 18.6 supports image/heic natively but
    // not image/avif). Empirical FA REF: image/heic → type=image/heic;
    // image/avif → type=image/png.
    if (s_isFamilyAArchetypeToBlob
        && equalLettersIgnoringASCIICase(encodingMIMEType, "image/avif"_s)) {
        encodingMIMEType = "image/png"_s;
    }
#endif
    auto quality = qualityFromJSValue(qualityValue);
    Vector<uint8_t> blobData;
    if (document->requiresScriptTrackingPrivacyProtection(ScriptTrackingPrivacyCategory::Canvas))
        blobData = encodeData(createImageForNoiseInjection(), encodingMIMEType, quality);
#if USE(CG)
    else if (auto imageData = getImageData())
        blobData = encodeData(imageData->byteArrayPixelBuffer().get(), encodingMIMEType, quality);
#endif
    else
        blobData = encodeData(makeRenderingResultsAvailable(), encodingMIMEType, quality);

#if PLATFORM(DRIFTSTACK)
    // Wave 29-400 §9 (founder Tier-3 verdict 2026-05-19): track whether ANY
    // atlas/substitution hook successfully overrode the natural Mac CG
    // output. Gates §1 AFP fallback below — without this flag, AFP fires
    // unconditionally after V510 substitution and overwrites the substituted
    // iPhone bytes. Surfaced empirically during §8.D verification when
    // cumrig reproduced 1593/2 instead of 1595/0 despite V510-HIT events.
    // See V-log §9 entry for full diagnosis.
    bool atlasSubstituted = false;
    // Wave 29-347: sibling gap to OffscreenCanvas::convertToBlob (per Wave
    // 29-345). HTMLCanvasElement::toBlob produces PNG bytes but the V-241/
    // V-510 dispatch lives only at toDataURL above (line ~1078). Vendor
    // probing via canvas.toBlob() vs canvas.toDataURL() would see natural
    // Mac fork vs iPhone-canonical respectively — detectable inconsistency.
    // Mirror dispatch here so toBlob output matches toDataURL canonical
    // substitution. Gated on FP10X_OVERRIDE=1 (same gate as toDataURL).
    static bool s_canvasFp10xOverrideToBlob = []() {
        const char* env = getenv("DRIFTSTACK_CANVAS_FP10X_OVERRIDE");
        return env && env[0] == '1';
    }();
    if (s_canvasFp10xOverrideToBlob && !blobData.isEmpty()
        && encodingMIMEType.containsIgnoringASCIICase("png"_s)) {
        // Wave 29-349: V-510 atlas lookup (in-TU direct call) +
        // V-241 fallback. Mirrors toDataURL dispatch above.
        String opSeqSha;
        if (RefPtr ctx2D = dynamicDowncast<CanvasRenderingContext2DBase>(m_context.get())) {
            uint16_t w = static_cast<uint16_t>(std::min<unsigned>(width(), 0xffff));
            uint16_t h = static_cast<uint16_t>(std::min<unsigned>(height(), 0xffff));
            opSeqSha = ctx2D->driftstackOpSequenceSHA256(w, h);
        }
        auto macForkDataURL = makeString("data:image/png;base64,"_s, base64Encoded(blobData.span()));
        auto substitute = v510AtlasLookup(macForkDataURL, opSeqSha);
        bool fromV510 = !substitute.isNull();
        if (substitute.isNull()) {
            // Exact (dims+lastFillText) match only — dim-only fallback removed (it
            // returned a wrong canvas for uncovered states; native is device-exact).
            const char* canonical = lookupCanvasFp10xCanonicalWithText(width(), height(), lastFillText());
            if (canonical)
                substitute = String::fromUTF8(canonical);
        }
        static constexpr ASCIILiteral kPNGPrefix = "data:image/png;base64,"_s;
        if (!substitute.isNull() && substitute.startsWith(kPNGPrefix)) {
            auto b64View = StringView(substitute).substring(kPNGPrefix.length());
            if (auto decoded = base64Decode(b64View)) {
                blobData = std::move(*decoded);
                atlasSubstituted = true;  // §9: gate §1 AFP fallback below
                WTFLogAlways("[Driftstack-%s-toBlob] canvas-fp blob substitution FIRED (%dx%d, lastFillText=%u chars)",
                    fromV510 ? "V510" : "V241", width(), height(), lastFillText().length());
            }
        }
    }
    // Layer B v2 ML toBlob hook REMOVED 2026-05-29 (founder: "drop the ML";
    // superseded by the finite-phase text atlas — see toDataURL note above).
    // Wave 29-399 §2 probe signature emission (toBlob) — mirrors toDataURL.
    static bool s_probeSigEmitEnabledToBlob = []() {
        const char* env = getenv("DRIFTSTACK_PROBE_SIGNATURE_EMIT");
        return env && env[0] == '1';
    }();
    if (s_probeSigEmitEnabledToBlob && !blobData.isEmpty()
        && encodingMIMEType.containsIgnoringASCIICase("png"_s)) {
        String opSeqShaSigBlob;
        String opSeqBytesB64SigBlob;
        if (RefPtr ctx2D = dynamicDowncast<CanvasRenderingContext2DBase>(m_context.get())) {
            uint16_t wSig = static_cast<uint16_t>(std::min<unsigned>(width(), 0xffff));
            uint16_t hSig = static_cast<uint16_t>(std::min<unsigned>(height(), 0xffff));
            opSeqShaSigBlob = ctx2D->driftstackOpSequenceSHA256(wSig, hSig);
            opSeqBytesB64SigBlob = ctx2D->driftstackOpSequenceBytesBase64(wSig, hSig);
        }
        auto lastTextSigBlob = lastFillText();
        // Wave 29-400 §8.A observability: per-session + customer + page_url
        // attribution (mirrors toDataURL site). Re-uses the toBlob function's
        // existing `Ref document = this->document();` at line ~1444.
        // Wave 29-402 Fix 2: archetype from DRIFTSTACK_ARCHETYPE env.
        static const char* s_sessionIdBlob = getenv("DRIFTSTACK_SESSION_ID");
        static const char* s_customerIdBlob = getenv("DRIFTSTACK_CUSTOMER_ID");
        static const char* s_archetypeBlob = []() {
            const char* env = getenv("DRIFTSTACK_ARCHETYPE");
            return env ? env : "iphone17_ios18_7_safari26_4";
        }();
        RefPtr mainDocBlob = document->mainFrameDocument();
        auto pageURLBlob = (mainDocBlob ? mainDocBlob->url() : document->url()).string();
        WTFLogAlways("[Driftstack-W29399-S2-ProbeSig-toBlob] "
            "w=%u h=%u opSeqSha=%s lastFillText=\"%s\" "
            "archetype=%s ts=%lld mime=%s mac_len=%zu "
            "opSeqBytesB64=%s session_id=%s customer_id=%s page_url=\"%s\"",
            width(), height(),
            opSeqShaSigBlob.isEmpty() ? "<empty>" : opSeqShaSigBlob.utf8().data(),
            lastTextSigBlob.left(80).utf8().data(),
            s_archetypeBlob,
            static_cast<long long>(WTF::WallTime::now().secondsSinceEpoch().milliseconds()),
            encodingMIMEType.utf8().data(),
            blobData.size(),
            opSeqBytesB64SigBlob.isEmpty() ? "<empty>" : opSeqBytesB64SigBlob.utf8().data(),
            s_sessionIdBlob ? s_sessionIdBlob : "<unset>",
            s_customerIdBlob ? s_customerIdBlob : "<unset>",
            pageURLBlob.left(256).utf8().data());
    }
    // Wave 29-399 §1 AFP fallback (toBlob) — mirrors toDataURL behavior:
    // after all atlas substitution paths miss, AFP fires to replace natural
    // Mac CG bytes with randomized output. Gated DRIFTSTACK_AFP_FALLBACK_ENABLED=1.
    static bool s_afpFallbackEnabledToBlob = []() {
        const char* env = getenv("DRIFTSTACK_AFP_FALLBACK_ENABLED");
        return env && env[0] == '1';
    }();
    // §9: gate AFP on !atlasSubstituted — without this, AFP overwrites
    // V510/Layer B v2 substituted bytes and priority-bin atlas hits don't
    // reach the customer's blob (cumrig stays 1593/2 instead of 1595/0).
    // Non-text cold-miss (empty lastFillText) falls through to the native
    // blobData (bit-identical Mac==iPhone for non-text); only text routes the
    // content-blind AFP fallback, until the per-glyph iOS atlas covers it.
    if (s_afpFallbackEnabledToBlob && !atlasSubstituted && !blobData.isEmpty()
        && !lastFillText().isEmpty()
        && encodingMIMEType.containsIgnoringASCIICase("png"_s)) {
        if (RefPtr noiseImage = createImageForNoiseInjection()) {
            auto afpBlobData = encodeData(noiseImage.get(), encodingMIMEType, quality);
            if (!afpBlobData.isEmpty()) {
                blobData = WTF::move(afpBlobData);
                // §9: standardized tag [Driftstack-AFP-Fallback-Fired] across
                // all 3 hook sites (toDataURL / toBlob / Worker). context=
                // distinguishes call site. Future verification scripts grep
                // this tag uniformly.
                WTFLogAlways("[Driftstack-AFP-Fallback-Fired] context=toBlob atlas-miss FIRED (%ux%u)",
                    width(), height());
            }
        }
    }
#endif

    RefPtr<Blob> blob;
    if (!blobData.isEmpty())
        blob = Blob::create(document.ptr(), WTF::move(blobData), encodingMIMEType);
    callback->scheduleCallback(document, WTF::move(blob));
    return { };
}

#if ENABLE(OFFSCREEN_CANVAS)
ExceptionOr<Ref<OffscreenCanvas>> HTMLCanvasElement::transferControlToOffscreen()
{
    if (m_context)
        return Exception { ExceptionCode::InvalidStateError };

    std::unique_ptr placeholderContext = PlaceholderRenderingContext::create(*this);
    Ref offscreen = OffscreenCanvas::create(protect(document()).get(), *placeholderContext);
    m_context = WTF::move(placeholderContext);
    if (m_context->delegatesDisplay())
        invalidateStyleAndLayerComposition();
    return offscreen;
}
#endif

RefPtr<ImageData> HTMLCanvasElement::getImageData()
{
#if ENABLE(WEBGL)
    RefPtr context = dynamicDowncast<WebGLRenderingContextBase>(m_context.get());
    if (!context)
        return nullptr;

    Ref document = this->document();
    if (document->settings().webAPIStatisticsEnabled())
        ResourceLoadObserver::singleton().logCanvasRead(document.get());

    RefPtr pixelBuffer = context->drawingBufferToPixelBuffer();
    if (!pixelBuffer)
        return nullptr;

    postProcessPixelBufferResults(*pixelBuffer);
    return ImageData::create(pixelBuffer.releaseNonNull());
#else
    return nullptr;
#endif
}

#if ENABLE(MEDIA_STREAM) || ENABLE(WEB_CODECS)

RefPtr<VideoFrame> HTMLCanvasElement::toVideoFrame()
{
#if PLATFORM(COCOA) || USE(GSTREAMER)
    Ref document = this->document();
#if ENABLE(WEBGL)
    if (RefPtr context = dynamicDowncast<WebGLRenderingContextBase>(m_context.get())) {
        if (document->settings().webAPIStatisticsEnabled())
            ResourceLoadObserver::singleton().logCanvasRead(document.get());
        return context->surfaceBufferToVideoFrame(CanvasRenderingContext::SurfaceBuffer::DrawingBuffer);
    }
#endif

    if (document->settings().webAPIStatisticsEnabled())
        ResourceLoadObserver::singleton().logCanvasRead(document.get());

    RefPtr imageBuffer = makeRenderingResultsAvailable();
    if (!imageBuffer)
        return nullptr;

    // FIXME: This can likely be optimized quite a bit, especially in the cases where
    // the ImageBuffer is backed by GPU memory already and/or is in the GPU process by
    // specializing toVideoFrame() in ImageBufferBackend to not use getPixelBuffer().
    auto pixelBuffer = imageBuffer->getPixelBuffer({ AlphaPremultiplication::Unpremultiplied, PixelFormat::BGRA8, DestinationColorSpace::SRGB() }, { { }, imageBuffer->truncatedLogicalSize() });
    if (!pixelBuffer)
        return nullptr;

#if PLATFORM(DRIFTSTACK)
    // Wave 29-402 §10 2D toVideoFrame chokepoint (founder 2026-05-28): captureStream /
    // WebCodecs read the 2D canvas as a VideoFrame here (getPixelBuffer above),
    // bypassing the toDataURL/getImageData hooks → leaked Mac-CG pixels. §2 emission
    // (2D op-sequence key) + §1 AFP-on-miss salt fill. Env-gated, cumrig-safe.
    {
        static bool s_emitVF = []() { const char* e = getenv("DRIFTSTACK_PROBE_SIGNATURE_EMIT"); return e && e[0] == '1'; }();
        if (s_emitVF) {
            String opSeqShaVF, opSeqBytesVF;
            if (RefPtr ctx2D = dynamicDowncast<CanvasRenderingContext2DBase>(m_context.get())) {
                uint16_t wS = static_cast<uint16_t>(std::min<unsigned>(width(), 0xffff));
                uint16_t hS = static_cast<uint16_t>(std::min<unsigned>(height(), 0xffff));
                opSeqShaVF = ctx2D->driftstackOpSequenceSHA256(wS, hS);
                opSeqBytesVF = ctx2D->driftstackOpSequenceBytesBase64(wS, hS);
            }
            static const char* s_archVF = []() { const char* e = getenv("DRIFTSTACK_ARCHETYPE"); return e ? e : "iphone17_ios18_7_safari26_4"; }();
            static const char* s_sidVF = getenv("DRIFTSTACK_SESSION_ID");
            static const char* s_cidVF = getenv("DRIFTSTACK_CUSTOMER_ID");
            RefPtr mainDocVF = document->mainFrameDocument();
            String pageURLVF = (mainDocVF ? mainDocVF->url() : document->url()).string();
            WTFLogAlways("[Driftstack-W29399-S2-ProbeSig-toVideoFrame] "
                "w=%u h=%u opSeqSha=%s lastFillText=\"%s\" archetype=%s ts=%lld mime=%s mac_len=%u "
                "opSeqBytesB64=%s session_id=%s customer_id=%s page_url=\"%s\"",
                width(), height(),
                opSeqShaVF.isEmpty() ? "<empty>" : opSeqShaVF.utf8().data(),
                lastFillText().left(80).utf8().data(), s_archVF,
                static_cast<long long>(WTF::WallTime::now().secondsSinceEpoch().milliseconds()),
                "videoframe/bgra8", static_cast<unsigned>(width() * height() * 4),
                opSeqBytesVF.isEmpty() ? "<empty>" : opSeqBytesVF.utf8().data(),
                s_sidVF ? s_sidVF : "<unset>", s_cidVF ? s_cidVF : "<unset>",
                pageURLVF.left(256).utf8().data());
        }
        // W2482: V-510 atlas SERVE for toVideoFrame (cross-surface coherence). The
        // emission above puts this surface in the auto-learn pipeline, but without a
        // serve a canvas in the V-510 atlas got the §1 AFP salt fill here while
        // toDataURL/getImageData served the iPhone-canonical bytes → captureStream /
        // WebCodecs read pixels INCOHERENT with toDataURL on the SAME canvas (an FPJS
        // cross-surface coherence tell). Fetch the op-seq-keyed atlas RGBA8 and, since
        // the pixelBuffer is unpremultiplied BGRA8 (line ~1732), swap R<->B in-place so
        // the VideoFrame carries the same bytes. On hit, skip the AFP miss-fill.
        // Env-gated DRIFTSTACK_VIDEOFRAME_ATLAS (default OFF until verified bit-exact,
        // mirrors the W2480 getImageData rollout). Verified E2E by
        // verify-videoframe-atlas-coherence.sh (new VideoFrame(canvas) -> copyTo RGBA).
        bool servedFromAtlasVF = false;
        static bool s_vfAtlas = []() { const char* e = getenv("DRIFTSTACK_VIDEOFRAME_ATLAS"); return e && e[0] == '1'; }();
        if (s_vfAtlas) {
            if (RefPtr ctx2DV = dynamicDowncast<CanvasRenderingContext2DBase>(m_context.get())) {
                if (RefPtr bapV = dynamicDowncast<ByteArrayPixelBuffer>(pixelBuffer.get())) {
                    uint16_t wSV = static_cast<uint16_t>(std::min<unsigned>(width(), 0xffff));
                    uint16_t hSV = static_cast<uint16_t>(std::min<unsigned>(height(), 0xffff));
                    String opSeqShaV = ctx2DV->driftstackOpSequenceSHA256(wSV, hSV);
                    Vector<uint8_t> rgbaV;
                    if (Driftstack::getV510AtlasRGBAForOpSeq(opSeqShaV, width(), height(), rgbaV)) {
                        auto bytesV = bapV->bytes();
                        if (rgbaV.size() == bytesV.size() && !(rgbaV.size() % 4)) {
                            // atlas RGBA8 -> pixelBuffer BGRA8 (both unpremultiplied): swap B<->R.
                            for (size_t i = 0; i + 4 <= rgbaV.size(); i += 4) {
                                bytesV[i + 0] = rgbaV[i + 2];
                                bytesV[i + 1] = rgbaV[i + 1];
                                bytesV[i + 2] = rgbaV[i + 0];
                                bytesV[i + 3] = rgbaV[i + 3];
                            }
                            servedFromAtlasVF = true;
                            WTFLogAlways("[Driftstack-V510-toVideoFrame] HIT (%ux%u opSeq=%s)",
                                width(), height(), opSeqShaV.left(12).utf8().data());
                        }
                    }
                }
            }
        }
        static bool s_afpVF = []() { const char* e = getenv("DRIFTSTACK_AFP_FALLBACK_ENABLED"); return e && e[0] == '1'; }();
        if (!servedFromAtlasVF && s_afpVF) {
            if (RefPtr bapVF = dynamicDowncast<ByteArrayPixelBuffer>(pixelBuffer.get())) {
                auto bytesVF = bapVF->bytes();
                if (bytesVF.size() >= 4) {
                    RefPtr sctxVF = canvasBaseScriptExecutionContext();
                    uint64_t salt = (sctxVF && sctxVF->noiseInjectionHashSalt()) ? *sctxVF->noiseInjectionHashSalt() : 0;
                    uint64_t mix = salt ^ 0x9E3779B97F4A7C15ull; mix ^= mix >> 29; mix *= 0xBF58476D1CE4E5B9ull; mix ^= mix >> 32;
                    const uint8_t v[4] = { static_cast<uint8_t>(mix & 0xff), static_cast<uint8_t>((mix >> 8) & 0xff),
                        static_cast<uint8_t>((mix >> 16) & 0xff), static_cast<uint8_t>((mix >> 24) & 0xff) };
                    for (size_t i = 0; i + 4 <= bytesVF.size(); i += 4) { bytesVF[i] = v[0]; bytesVF[i + 1] = v[1]; bytesVF[i + 2] = v[2]; bytesVF[i + 3] = v[3]; }
                    WTFLogAlways("[Driftstack-AFP-Fallback-Fired] context=toVideoFrame atlas-miss FIRED (%ux%u)", width(), height());
                }
            }
        }
    }
#endif

    // FIXME: Set color space.
    return VideoFrame::createFromPixelBuffer(pixelBuffer.releaseNonNull());
#else
    return nullptr;
#endif
}

#endif // ENABLE(MEDIA_STREAM) || ENABLE(WEB_CODECS)

#if ENABLE(MEDIA_STREAM)

ExceptionOr<Ref<MediaStream>> HTMLCanvasElement::captureStream(std::optional<double>&& frameRequestRate)
{
    if (!originClean())
        return Exception(ExceptionCode::SecurityError, "Canvas is tainted"_s);
    Ref document = this->document();
    if (document->settings().webAPIStatisticsEnabled())
        ResourceLoadObserver::singleton().logCanvasRead(document.get());

    if (frameRequestRate && frameRequestRate.value() < 0)
        return Exception(ExceptionCode::NotSupportedError, "frameRequestRate is negative"_s);

    auto track = CanvasCaptureMediaStreamTrack::create(document.get(), *this, WTF::move(frameRequestRate));
    auto stream = MediaStream::create(document.get());
    stream->addTrack(track);
    return stream;
}
#endif

SecurityOrigin* HTMLCanvasElement::securityOrigin() const
{
    return &protect(document())->securityOrigin();
}

Image* HTMLCanvasElement::copiedImage() const
{
    if (!m_copiedImage) {
        RefPtr buffer = const_cast<HTMLCanvasElement*>(this)->makeRenderingResultsAvailable(ShouldApplyPostProcessingToDirtyRect::No);
        if (buffer)
            m_copiedImage = BitmapImage::create(buffer->copyNativeImage());
    }
    return m_copiedImage.get();
}

void HTMLCanvasElement::clearCopiedImage() const
{
    m_copiedImage = nullptr;
}

bool HTMLCanvasElement::virtualHasPendingActivity() const
{
#if ENABLE(WEBGL)
    if (m_hasRelevantWebGLEventListener) {
        // This runs on a GC thread.
        SUPPRESS_UNCOUNTED_LOCAL auto* context = dynamicDowncast<WebGLRenderingContextBase>(m_context.get());
        // WebGL rendering context may fire contextlost / contextrestored events at any point.
        return context && !context->isContextUnrecoverablyLost();
    }
#endif

    return false;
}

void HTMLCanvasElement::eventListenersDidChange()
{
#if ENABLE(WEBGL)
    auto& eventNames = WebCore::eventNames();
    m_hasRelevantWebGLEventListener = hasEventListeners(eventNames.webglcontextlostEvent)
        || hasEventListeners(eventNames.webglcontextrestoredEvent);
#endif
}

void HTMLCanvasElement::didMoveToNewDocument(Document& oldDocument, Document& newDocument)
{
    ActiveDOMObject::didMoveToNewDocument(newDocument);
    if (RefPtr context = renderingContext()) {
        oldDocument.removeCanvasNeedingPreparationForDisplayOrFlush(*context);
        newDocument.addCanvasNeedingPreparationForDisplayOrFlush(*context);
    }
    HTMLElement::didMoveToNewDocument(oldDocument, newDocument);
}

bool HTMLCanvasElement::needsPreparationForDisplay()
{
    return m_context && m_context->needsPreparationForDisplay();
}

void HTMLCanvasElement::prepareForDisplay()
{
    ASSERT(needsPreparationForDisplay());

    bool shouldPrepare = true;
#if ENABLE(WEBGL)
    // FIXME: Currently the below prepare skip logic is conservative and applies only to
    // WebGL elements.
    if (is<WebGLRenderingContextBase>(m_context)) {
        // If the canvas is not in the document body, then it won't be
        // composited and thus doesn't need preparation. Unfortunately
        // it can't tell at the time it was added to the list, since it
        // could be inserted or removed from the document body afterwards.
        shouldPrepare = isInTreeScope() || hasDisplayBufferObservers();
    }
#endif
    if (!shouldPrepare)
        return;
    if (m_context)
        m_context->prepareForDisplay();
    notifyObserversCanvasDisplayBufferPrepared();
}

void HTMLCanvasElement::dynamicRangeLimitDidChange(PlatformDynamicRangeLimit dynamicRangeLimit)
{
    if (m_dynamicRangeLimit == dynamicRangeLimit)
        return;

    m_dynamicRangeLimit = dynamicRangeLimit;
#if ENABLE(PIXEL_FORMAT_RGBA16F)
    if (m_context)
        m_context->setDynamicRangeLimit(dynamicRangeLimit);
#endif // ENABLE(PIXEL_FORMAT_RGBA16F)
}

std::optional<double> HTMLCanvasElement::getContextEffectiveDynamicRangeLimitValue() const
{
    if (m_context)
        return m_context->getEffectiveDynamicRangeLimitValue();
    return std::nullopt;
}

bool HTMLCanvasElement::isControlledByOffscreen() const
{
    return m_context && m_context->isPlaceholder();
}

void HTMLCanvasElement::queueTaskKeepingObjectAlive(TaskSource source, Function<void(CanvasBase&)>&& task)
{
    ActiveDOMObject::queueTaskKeepingObjectAlive(*this, source, [task = WTF::move(task)](auto& element) mutable {
        task(element);
    });
}

void HTMLCanvasElement::dispatchEvent(Event& event)
{
    Node::dispatchEvent(event);
}

std::unique_ptr<CSSParserContext> HTMLCanvasElement::createCSSParserContext() const
{
    return makeUnique<CSSParserContext>(protect(document()).get());
}

WebCoreOpaqueRoot root(HTMLCanvasElement* canvas)
{
    return root(static_cast<Node*>(canvas));
}

}
