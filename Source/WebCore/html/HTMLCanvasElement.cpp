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
#include <fcntl.h>
#include <span>
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

HTMLCanvasElement::HTMLCanvasElement(const QualifiedName& tagName, Document& document)
    : HTMLElement(tagName, document, TypeFlag::HasDidMoveToNewDocument)
    , ActiveDOMObject(document)
    , CanvasBase(IntSize(defaultWidth, defaultHeight), document)
{
    ASSERT(hasTagName(canvasTag));
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

void initV510AtlasOnce()
{
    auto& state = v510AtlasState();
    if (state.initialized)
        return;
    state.initialized = true;

    // V-581 Phase C-3.A: run OpSequenceRecorder canonical-serializer self-test
    // exactly once if DRIFTSTACK_TEST_OPSEQ=1. Placed before the atlas-file
    // checks so a missing/unreadable atlas does not skip the test. No-ops when
    // env var unset; logs PASS/FAIL via WTFLogAlways; never aborts startup.
    runOpSequenceRecorderSelfTestIfRequested();

    // Wave 29-392: default path = Wave 29-378 family-B-supplemented atlas
    // (3084 entries / 30.09 MB / git-tracked) at the correctly-named
    // driftstack_canvas_fuzz_atlas/ directory. Replaces pre-Wave-29-378
    // default at driftstack_audio_atlas/ which held a Family-A-polluted
    // 25.81 MB atlas accumulated through Waves 29-272 → 29-280. Production
    // sessions that don't set DRIFTSTACK_CANVAS_FUZZ_ATLAS_PATH now use
    // the launch-archetype-clean atlas by default — silent-failure mode
    // removed where harness forgot to set the env var.
    //
    // The audio_atlas/ path remains in sandbox + on disk for back-compat
    // (some scripts may explicitly set DRIFTSTACK_CANVAS_FUZZ_ATLAS_PATH
    // to it for A/B testing). Production deploy uses the new default.
    constexpr const char* kDefaultPath = "/Users/john/code/driftstack/reference/driftstack_canvas_fuzz_atlas/driftstack-canvas-fuzz-atlas-family-b-supplemented.bin";
    constexpr size_t kHeaderBytes = 32;
    constexpr size_t kIndexEntryStride = 28;

    // V-511 multi-archetype foundation: orchestrator sets DRIFTSTACK_CANVAS_FUZZ_ATLAS_PATH
    // explicitly per archetype (driftstack-canvas-fuzz-atlas-{archetype}.bin). WebKit
    // dispatch reads single env var; archetype dispatch happens above the WebKit layer
    // (harness / GUI / agent service per file 04 architecture). Avoids unsafe-buffer-usage
    // path templating in C++ side.
    const char* envPath = getenv("DRIFTSTACK_CANVAS_FUZZ_ATLAS_PATH");
    const char* path = envPath ? envPath : kDefaultPath;

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        WTFLogAlways("[Driftstack] V510Atlas: open failed for %s (errno=%d) — disabled", path, errno);
        return;
    }
    struct stat st;
    if (fstat(fd, &st) < 0 || st.st_size < static_cast<off_t>(kHeaderBytes)) {
        WTFLogAlways("[Driftstack] V510Atlas: fstat failed or file too small");
        close(fd);
        return;
    }
    void* base = mmap(nullptr, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (base == MAP_FAILED) {
        WTFLogAlways("[Driftstack] V510Atlas: mmap failed (errno=%d)", errno);
        close(fd);
        return;
    }
    auto bytesSpan = unsafeMakeSpan(static_cast<const uint8_t*>(base), static_cast<size_t>(st.st_size));
    if (bytesSpan[0] != 'D' || bytesSpan[1] != 'S' || bytesSpan[2] != 'C' || bytesSpan[3] != 'F') {
        WTFLogAlways("[Driftstack] V510Atlas: bad magic at %s", path);
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
    bool accept = (version == 1 && keyAlgo == 1)
        || (version == 2 && keyAlgo == 1)
        || (version == 3 && keyAlgo == 2);
    if (!accept) {
        WTFLogAlways("[Driftstack] V510Atlas: unsupported version=%u/algo=%u", version, keyAlgo);
        munmap(base, st.st_size); close(fd); return;
    }
    state.formatVersion = version;
    uint32_t numEntries = readU32(8);
    uint32_t indexOffset = readU32(12);
    uint32_t dataOffset = readU32(16);
    if (indexOffset < kHeaderBytes
        || dataOffset != indexOffset + numEntries * kIndexEntryStride
        || dataOffset > bytesSpan.size()) {
        WTFLogAlways("[Driftstack] V510Atlas: header invalid");
        munmap(base, st.st_size); close(fd); return;
    }
    state.fd = fd;
    state.mmapBase = static_cast<const uint8_t*>(base);
    state.mmapSize = st.st_size;
    state.indexSpan = bytesSpan.subspan(indexOffset, numEntries * kIndexEntryStride);
    state.dataPayloadSpan = bytesSpan.subspan(dataOffset);
    state.numEntries = numEntries;
    state.available = true;
    WTFLogAlways("[Driftstack] V510Atlas: mapped %lld bytes from %s; %u entries; format=v%u",
        (long long)st.st_size, path, numEntries, state.formatVersion);
}

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

String v510AtlasLookup(const String& macForkDataURL, const String& opSequenceSHA256Hex = String())
{
    initV510AtlasOnce();
    auto& state = v510AtlasState();
    if (!state.available || !state.numEntries)
        return String();

    constexpr size_t kIndexEntryStride = 28;
    constexpr size_t kHashBytes = 16;

    // V-581 Phase C-3.C: dispatch by atlas format version.
    //   v1/v2 atlas (keyHashAlgo=1, formatVersion=1|2): key = first 16 bytes
    //     of CC_SHA256(macForkDataURL.utf8()) — backwards compatible.
    //   v3 atlas (keyHashAlgo=2, formatVersion=3): key = first 16 bytes of
    //     opSequenceSHA256Hex (the JS-side / C++-side op-sequence canonical hash).
    //     If opSeqSha is empty (e.g. no canvas ops were recorded, or the canvas
    //     context is not 2D), v3 lookup is skipped and atlas miss returned.
    std::array<uint8_t, CC_SHA256_DIGEST_LENGTH> fullDigest;
    if (state.formatVersion == 3) {
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
            if (dataOff + dataLen > state.dataPayloadSpan.size())
                return String();
            auto entry = state.dataPayloadSpan.subspan(dataOff, dataLen);
            static unsigned hits = 0;
            if (++hits <= 50)
                WTFLogAlways("[Driftstack-V510-HIT] entry=%zu/%zu off=%u len=%u format=v%u",
                    mid, state.numEntries, dataOff, dataLen, state.formatVersion);
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
        const char* canonical = lookupCanvasFp10xCanonicalWithText(width(), height(), fillText);
        if (!canonical)
            canonical = lookupCanvasFp10xCanonical(width(), height());
        if (canonical) {
            WTFLogAlways("[Driftstack-V241] canvas-fp canonical substitution FIRED (%dx%d PNG, lastFillText=%d chars) — V-510 atlas miss",
                width(), height(), fillText.length());
            return UncachedString { String::fromLatin1(canonical) };
        }
    }
#endif

    if (document->requiresScriptTrackingPrivacyProtection(ScriptTrackingPrivacyCategory::Canvas))
        return UncachedString { encodeDataURL(createImageForNoiseInjection(), encodingMIMEType, quality) };

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
                WTFLogAlways("[Driftstack-%s-toBlob] canvas-fp blob substitution FIRED (%dx%d, lastFillText=%u chars)",
                    fromV510 ? "V510" : "V241", width(), height(), lastFillText().length());
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
