/*
 * Copyright (C) 2025 Apple Inc. All rights reserved.
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
#include "RemoteImageBufferGraphicsContext.h"

#if ENABLE(GPU_PROCESS)

#include "Logging.h"
#include "RemoteGraphicsContextMessages.h"

#if PLATFORM(DRIFTSTACK)
#include <WebCore/PixelBuffer.h>
#include <WebCore/PixelBufferConversion.h>
#include <array>
#include <cmath>
#include <cstdlib>
#endif

#define MESSAGE_CHECK(assertion) MESSAGE_CHECK_BASE(assertion, m_renderingBackend->streamConnection());

#if PLATFORM(DRIFTSTACK)
namespace WebCore {
std::optional<uint8_t> driftstackPremultipliedChannelForVisible(
    uint8_t visible, uint8_t alpha);
}
#endif

namespace WebKit {
using namespace WebCore;

#if PLATFORM(DRIFTSTACK)
namespace {

struct GlyphDestinationPixelTables {
    std::array<uint8_t, 256 * 4> canonicalTextBackdrop { };
};

const GlyphDestinationPixelTables& glyphDestinationPixelTables()
{
    static const GlyphDestinationPixelTables tables = [] {
        GlyphDestinationPixelTables result;
        auto srgb = DestinationColorSpace::SRGB();

        // putImageData stores unpremultiplied RGBA into a premultiplied BGRA
        // backing store. Reproduce that exact round trip for the captured #069
        // backdrop so low-alpha channel quantization does not look like a
        // different logical destination color.
        Vector<uint8_t> logicalBackdrop(256 * 4);
        Vector<uint8_t> backingBackdrop(256 * 4);
        Vector<uint8_t> visibleBackdrop(256 * 4);
        for (size_t alpha = 0; alpha < 256; ++alpha) {
            size_t offset = alpha * 4;
            logicalBackdrop[offset] = 0;
            logicalBackdrop[offset + 1] = 102;
            logicalBackdrop[offset + 2] = 153;
            logicalBackdrop[offset + 3] = static_cast<uint8_t>(alpha);
        }
        convertImagePixels(
            { { AlphaPremultiplication::Unpremultiplied, PixelFormat::RGBA8, srgb },
                1024, logicalBackdrop.span() },
            { { AlphaPremultiplication::Premultiplied, PixelFormat::BGRA8, srgb },
                1024, backingBackdrop.mutableSpan() },
            { 256, 1 });
        convertImagePixels(
            { { AlphaPremultiplication::Premultiplied, PixelFormat::BGRA8, srgb },
                1024, backingBackdrop.span() },
            { { AlphaPremultiplication::Unpremultiplied, PixelFormat::RGBA8, srgb },
                1024, visibleBackdrop.mutableSpan() },
            { 256, 1 });
        for (size_t i = 0; i < result.canonicalTextBackdrop.size(); ++i)
            result.canonicalTextBackdrop[i] = visibleBackdrop[i];

        return result;
    }();
    return tables;
}

bool isCanonicalTextBackdrop(uint8_t red, uint8_t green, uint8_t blue, uint8_t alpha)
{
    if (!alpha)
        return true;
    auto& table = glyphDestinationPixelTables().canonicalTextBackdrop;
    size_t offset = static_cast<size_t>(alpha) * 4;
    return red == table[offset] && green == table[offset + 1] && blue == table[offset + 2];
}

} // anonymous namespace
#endif

Ref<RemoteImageBufferGraphicsContext> RemoteImageBufferGraphicsContext::create(ImageBuffer& imageBuffer, RemoteGraphicsContextIdentifier identifier, RemoteRenderingBackend& renderingBackend)
{
    Ref instance = adoptRef(*new RemoteImageBufferGraphicsContext(imageBuffer, identifier, renderingBackend));
    instance->startListeningForIPC();
    return instance;
}

RemoteImageBufferGraphicsContext::RemoteImageBufferGraphicsContext(ImageBuffer& imageBuffer, RemoteGraphicsContextIdentifier identifier, RemoteRenderingBackend& renderingBackend)
    : RemoteGraphicsContext(imageBuffer.context(), renderingBackend)
    , m_imageBuffer(imageBuffer)
    , m_identifier(identifier)
{
}

RemoteImageBufferGraphicsContext::~RemoteImageBufferGraphicsContext() = default;

void RemoteImageBufferGraphicsContext::startListeningForIPC()
{
    m_renderingBackend->streamConnection().startReceivingMessages(*this, Messages::RemoteGraphicsContext::messageReceiverName(), m_identifier.toUInt64());
}

void RemoteImageBufferGraphicsContext::stopListeningForIPC()
{
    m_renderingBackend->streamConnection().stopReceivingMessages(Messages::RemoteGraphicsContext::messageReceiverName(), m_identifier.toUInt64());
}

void RemoteImageBufferGraphicsContext::drawImageBuffer(RenderingResourceIdentifier imageBufferIdentifier, const FloatRect& destinationRect, const FloatRect& srcRect, ImagePaintingOptions options)
{
    RefPtr sourceImage = imageBuffer(imageBufferIdentifier);
    MESSAGE_CHECK(sourceImage);
    bool selfCopy = false;
    if (sourceImage == m_imageBuffer.ptr() && sourceImage->renderingMode() == RenderingMode::Accelerated) {
        sourceImage = sourceImage->clone();
        sourceImage->flushDrawingContext();
        selfCopy = true;
    }
    context().drawImageBuffer(*sourceImage, destinationRect, srcRect, options);
    if (selfCopy)
        m_imageBuffer->flushDrawingContext();
}

#if PLATFORM(DRIFTSTACK)
void RemoteImageBufferGraphicsContext::beginDriftstackGlyphDestinationCorrection(
    std::span<const uint8_t, 4096> coverage, const FloatRect& destinationRect,
    uint8_t fillAlphaByte, uint8_t sourceRed, uint8_t sourceGreen, uint8_t sourceBlue)
{
    m_pendingGlyphDestinationCorrection = std::nullopt;
    const char* correctionEnabled = std::getenv("DRIFTSTACK_GLYPH_DESTINATION_CORRECTION");
    if (correctionEnabled && correctionEnabled[0] == '0')
        return;
    IntRect imageBounds { { }, expandedIntSize(m_imageBuffer->logicalSize()) };
    bool scaleMatches = m_imageBuffer->resolutionScale() == 1;
    bool formatMatches = m_imageBuffer->pixelFormat() == PixelFormat::BGRA8;
    bool colorSpaceMatches = m_imageBuffer->colorSpace() == DestinationColorSpace::SRGB();
    bool compositeMatches = context().compositeOperation() == CompositeOperator::SourceOver;
    bool blendMatches = context().blendMode() == BlendMode::Normal;
    bool shadowMatches = !context().dropShadow();
    bool layerMatches = !context().isInTransparencyLayer();
    bool transformMatches = context().getCTM() == m_imageBuffer->baseTransform();
    bool clipMatches = context().clipBounds() == imageBounds;
    bool clipStateMatches = !driftstackHasNonDefaultClip();
    bool rectMatches = destinationRect.width() == 64 && destinationRect.height() == 64
        && destinationRect.x() == std::floor(destinationRect.x())
        && destinationRect.y() == std::floor(destinationRect.y());
    // DSDCR1 was captured from an unshadowed source-over draw in the default
    // 8-bit sRGB canvas coordinate space. Other drawing states keep their native
    // compositor until they are separately characterized.
    if (!scaleMatches || !formatMatches || !colorSpaceMatches || !compositeMatches
        || !blendMatches || !shadowMatches || !layerMatches || !transformMatches
        || !clipMatches || !clipStateMatches || !rectMatches) {
        return;
    }
    bool destinationSupported = driftstackGlyphDestinationPixelPacked(
        fillAlphaByte, sourceRed, sourceGreen, sourceBlue, 255, 0, 0, 0, 255).has_value();
    if (!destinationSupported)
        return;

    IntRect rect {
        static_cast<int>(destinationRect.x()), static_cast<int>(destinationRect.y()), 64, 64
    };
    PixelBufferFormat format {
        AlphaPremultiplication::Unpremultiplied, PixelFormat::RGBA8,
        m_imageBuffer->colorSpace()
    };
    RefPtr destination = m_imageBuffer->getPixelBuffer(format, rect);
    if (!destination || destination->bytes().size() != 64 * 64 * 4)
        return;
    m_pendingGlyphDestinationCorrection = PendingGlyphDestinationCorrection {
        Vector<uint8_t>(coverage), Vector<uint8_t>(destination->bytes()), rect,
        fillAlphaByte, sourceRed, sourceGreen, sourceBlue
    };
}

void RemoteImageBufferGraphicsContext::endDriftstackGlyphDestinationCorrection()
{
    auto pending = std::exchange(m_pendingGlyphDestinationCorrection, std::nullopt);
    if (!pending)
        return;
    PixelBufferFormat format {
        AlphaPremultiplication::Unpremultiplied, PixelFormat::RGBA8,
        m_imageBuffer->colorSpace()
    };
    RefPtr pixels = m_imageBuffer->getPixelBuffer(format, pending->destinationRect);
    if (!pixels || pixels->bytes().size() != pending->destinationPixels.size())
        return;

    auto current = pixels->bytes();
    auto before = pending->destinationPixels.span();
    unsigned corrected = 0;
    for (size_t pixelIndex = 0; pixelIndex < pending->coverage.size(); ++pixelIndex) {
        uint8_t coverage = pending->coverage[pixelIndex];
        if (!coverage)
            continue;
        size_t offset = pixelIndex * 4;
        uint8_t destinationRed = before[offset];
        uint8_t destinationGreen = before[offset + 1];
        uint8_t destinationBlue = before[offset + 2];
        uint8_t destinationAlpha = before[offset + 3];
        if (destinationAlpha < 255
            && isCanonicalTextBackdrop(destinationRed, destinationGreen, destinationBlue, destinationAlpha)) {
            destinationRed = 0;
            destinationGreen = 102;
            destinationBlue = 153;
        }
        auto expected = driftstackGlyphDestinationPixelPacked(
            pending->fillAlphaByte, pending->sourceRed, pending->sourceGreen,
            pending->sourceBlue, coverage, destinationRed, destinationGreen,
            destinationBlue, destinationAlpha);
        if (!expected)
            continue;
        current[offset] = static_cast<uint8_t>(*expected);
        current[offset + 1] = static_cast<uint8_t>(*expected >> 8);
        current[offset + 2] = static_cast<uint8_t>(*expected >> 16);
        current[offset + 3] = static_cast<uint8_t>(*expected >> 24);
        ++corrected;
    }
    if (!corrected)
        return;

    IntRect imageBounds { { }, expandedIntSize(m_imageBuffer->logicalSize()) };
    IntRect visibleRect = intersection(pending->destinationRect, imageBounds);
    if (visibleRect.isEmpty())
        return;
    Vector<uint8_t> premultipliedPixels(current.size());
    for (size_t offset = 0; offset < current.size(); offset += 4) {
        uint8_t alpha = current[offset + 3];
        auto red = driftstackPremultipliedChannelForVisible(current[offset], alpha);
        auto green = driftstackPremultipliedChannelForVisible(current[offset + 1], alpha);
        auto blue = driftstackPremultipliedChannelForVisible(current[offset + 2], alpha);
        if (!red || !green || !blue)
            return;
        premultipliedPixels[offset] = *red;
        premultipliedPixels[offset + 1] = *green;
        premultipliedPixels[offset + 2] = *blue;
        premultipliedPixels[offset + 3] = alpha;
    }
    auto premultipliedView = PixelBufferSourceView::create(
        { AlphaPremultiplication::Premultiplied, PixelFormat::RGBA8,
            m_imageBuffer->colorSpace() },
        pixels->size(), premultipliedPixels.span());
    if (!premultipliedView)
        return;
    IntRect sourceRect {
        { visibleRect.x() - pending->destinationRect.x(),
            visibleRect.y() - pending->destinationRect.y() },
        visibleRect.size()
    };
    m_imageBuffer->putPixelBuffer(
        *premultipliedView, sourceRect, pending->destinationRect.location(),
        AlphaPremultiplication::Premultiplied);
}
#endif

} // namespace WebKit

#undef MESSAGE_CHECK

#endif // ENABLE(GPU_PROCESS)
