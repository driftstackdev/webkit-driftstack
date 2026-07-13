/*
 * Copyright (C) 2020 Apple Inc. All rights reserved.
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
#include "SourceBufferParser.h"

#if ENABLE(MEDIA_SOURCE)

#include "ContentType.h"
#include "MediaSourceConfiguration.h"
#include "SharedBuffer.h"
#include "SourceBufferParserAVFObjC.h"
#include "SourceBufferParserWebM.h"
#if PLATFORM(DRIFTSTACK)
#include "DriftstackArchetypeConfig.h"
#endif
#include <pal/spi/cocoa/MediaToolboxSPI.h>
#include <wtf/text/WTFString.h>

#include <pal/cocoa/MediaToolboxSoftLink.h>

namespace WebCore {

MediaPlayerEnums::SupportsType SourceBufferParser::isContentTypeSupported(const ContentType& type)
{
#if PLATFORM(DRIFTSTACK)
    // Shared Family-A VP9 pin — the SINGLE convergence point for both parsers (mp4 via
    // SourceBufferParserAVFObjC, webm via SourceBufferParserWebM) and the lower-level path that
    // SourceBuffer::changeType reaches via canSwitchToType → supportsTypeAndCodecs. Pinning here
    // (rather than re-inlining the predicate) makes changeType(vp09)→NotSupportedError coherent with
    // MediaSource::isTypeSupported(vp09)=false on Family A, using the SAME helper so they cannot drift.
    // The raw OS parsers below (AVStreamDataParserMIMETypeCache / isVP9DecoderAvailable) carry no
    // version gate — the Mac decodes VP9 so they LEAK IsSupported for Family A; this restores the
    // real iPhone 18.6 verdict. Family B (launch 26.4) has no pin → unchanged (both accept).
    if (driftstackFamilyAVP9MSEUnsupported(type.parameter(ContentType::codecsParameter())))
        return MediaPlayerEnums::SupportsType::IsNotSupported;
    // Pin both sides of the MP4 AV1 hardware boundary before the host parser:
    // A15/A16 are unsupported and A17Pro+ are supported. Without the subtractive
    // side an AV1-capable Mac leaks true into an iPhone 14 archetype.
    if (type.containerType() == "video/mp4"_s) {
        auto codecs = type.parameter(ContentType::codecsParameter());
        if (driftstackArchetypeMP4AV1MSEUnsupported(codecs))
            return MediaPlayerEnums::SupportsType::IsNotSupported;
        if (driftstackArchetypeMP4AV1MSESupported(codecs))
            return MediaPlayerEnums::SupportsType::IsSupported;
    }
#endif
    MediaPlayerEnums::SupportsType supports = SourceBufferParserWebM::isContentTypeSupported(type);
    if (supports == MediaPlayerEnums::SupportsType::IsSupported)
        return supports;
    return std::max(supports, SourceBufferParserAVFObjC::isContentTypeSupported(type));
}

RefPtr<SourceBufferParser> SourceBufferParser::create(const ContentType& type, const MediaSourceConfiguration& configuration)
{
#if PLATFORM(DRIFTSTACK)
    if (type.containerType() == "video/mp4"_s) {
        auto codecs = type.parameter(ContentType::codecsParameter());
        if (driftstackArchetypeMP4AV1MSEUnsupported(codecs))
            return nullptr;
        if (driftstackArchetypeMP4AV1MSESupported(codecs))
            return adoptRef(new SourceBufferParserAVFObjC(configuration));
    }
#endif
    if (SourceBufferParserWebM::isContentTypeSupported(type) != MediaPlayerEnums::SupportsType::IsNotSupported)
        return SourceBufferParserWebM::create();

    if (SourceBufferParserAVFObjC::isContentTypeSupported(type) != MediaPlayerEnums::SupportsType::IsNotSupported)
        return adoptRef(new SourceBufferParserAVFObjC(configuration));

    return nullptr;
}

static SourceBufferParser::CallOnClientThreadCallback callOnMainThreadCallback()
{
    return [](Function<void()>&& function) {
        callOnMainThread(WTF::move(function));
    };
}

void SourceBufferParser::setCallOnClientThreadCallback(CallOnClientThreadCallback&& callback)
{
    ASSERT(callback);
    m_callOnClientThreadCallback = WTF::move(callback);
}

SourceBufferParser::SourceBufferParser()
    : m_callOnClientThreadCallback(callOnMainThreadCallback())
{
}

void SourceBufferParser::setMinimumAudioSampleDuration(float)
{
}

} // namespace WebCore

#endif // ENABLE(MEDIA_SOURCE)
