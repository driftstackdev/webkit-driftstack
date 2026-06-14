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
#include "PlatformMediaEngineConfigurationFactoryCocoa.h"

#if PLATFORM(COCOA)

#include "AV1Utilities.h"
#include "AV1UtilitiesCocoa.h"
#include "HEVCUtilitiesCocoa.h"
#include "MediaPlayer.h"
#include "PlatformMediaCapabilitiesDecodingInfo.h"
#include "PlatformMediaDecodingConfiguration.h"
#include "PlatformMediaEngineConfigurationFactory.h"
#include "SpatialAudioPlaybackHelper.h"
#include "VP9UtilitiesCocoa.h"
#include <pal/avfoundation/OutputContext.h>
#include <pal/avfoundation/OutputDevice.h>

#include "VideoToolboxSoftLink.h"
#include <pal/cf/AudioToolboxSoftLink.h>

namespace WebCore {

static CMVideoCodecType videoCodecTypeFromRFC4281Type(StringView type)
{
    if (type.startsWith("mp4v"_s))
        return kCMVideoCodecType_MPEG4Video;
    if (type.startsWith("avc1"_s) || type.startsWith("avc3"_s))
        return kCMVideoCodecType_H264;
    if (type.startsWith("hvc1"_s) || type.startsWith("hev1"_s))
        return kCMVideoCodecType_HEVC;
#if ENABLE(VP9)
    if (type.startsWith("vp09"_s))
        return kCMVideoCodecType_VP9;
#endif
    return 0;
}

static std::optional<PlatformMediaCapabilitiesInfo> computeMediaCapabilitiesInfo(const PlatformMediaDecodingConfiguration& configuration)
{
    PlatformMediaCapabilitiesInfo info;

    if (configuration.video) {
        if (configuration.type == PlatformMediaDecodingType::MediaStream) {
            ASSERT_NOT_REACHED();
            return std::nullopt;
        }
        auto& videoConfiguration = configuration.video.value();
        MediaEngineSupportParameters parameters {
            .platformType = configuration.type,
            .type = ContentType(videoConfiguration.contentType),
            .allowedMediaContainerTypes = configuration.allowedMediaContainerTypes,
            .allowedMediaCodecTypes = configuration.allowedMediaCodecTypes
        };

        if (MediaPlayer::supportsType(parameters) != MediaPlayer::SupportsType::IsSupported)
            return std::nullopt;

        auto codecs = parameters.type.codecs();
        if (codecs.size() != 1)
            return std::nullopt;

        info.supported = true;
        auto& codec = codecs[0];
        auto videoCodecType = videoCodecTypeFromRFC4281Type(codec);

        bool hdrSupported = videoConfiguration.colorGamut || videoConfiguration.hdrMetadataType || videoConfiguration.transferFunction;
        bool alphaChannel = videoConfiguration.alphaChannel && videoConfiguration.alphaChannel.value();

        if (videoCodecType == kCMVideoCodecType_HEVC) {
            auto parameters = parseHEVCCodecParameters(codec);
            if (!parameters)
                return std::nullopt;
            auto parsedInfo = validateHEVCParameters(*parameters, alphaChannel, hdrSupported);
            if (!parsedInfo)
                return std::nullopt;
            info = *parsedInfo;
        } else if (codec.startsWith("dvh1"_s) || codec.startsWith("dvhe"_s)) {
            auto parameters = parseDoViCodecParameters(codec);
            if (!parameters)
                return std::nullopt;
            auto parsedInfo = validateDoViParameters(*parameters, alphaChannel, hdrSupported);
            if (!parsedInfo)
                return std::nullopt;
            info = *parsedInfo;
#if ENABLE(VP9)
        } else if (videoCodecType == kCMVideoCodecType_VP9) {
            if (!configuration.canExposeVP9)
                return std::nullopt;
            auto parameters = parseVPCodecParameters(codec);
            if (!parameters)
                return std::nullopt;
            auto parsedInfo = validateVPParameters(*parameters, videoConfiguration);
            if (!parsedInfo)
                return std::nullopt;
            info = *parsedInfo;
        } else if (codec.startsWith("vp8"_s) || codec.startsWith("vp08"_s)) {
#if PLATFORM(DRIFTSTACK)
            // V-VP8-DECODINGINFO-ONLY (founder item #19, commit 27859fb6fc; verified live W542,
            // bit-exact W2362, re-reconciled W2523). SCOPE: this function (computeMediaCapabilitiesInfo)
            // is reached ONLY via MediaCapabilities::decodingInfo -> gatherDecodingInfo ->
            // createDecodingConfiguration (the JS navigator.mediaCapabilities.decodingInfo API). It does
            // NOT affect HTMLMediaElement.canPlayType (MediaPlayer::supportsType -> SourceBufferParserWebM,
            // ungated), MediaRecorder.isTypeSupported, or WebCodecs VideoDecoder.isConfigSupported — those
            // stay native and report VP8 supported.
            // Real iPhone-17 is API-SPLIT for VP8 (NOT a measurement artifact — it is genuine Apple
            // behaviour, identical to VP9): canPlayType='probably', WebCodecs vp8.decode=true,
            // MediaRecorder=true, WebRTC video/VP8 present — BUT mediaCapabilities.decodingInfo
            // video/webm;codecs="vp8" supported=FALSE (every real-device aio capture that tests it; never
            // true). On the Mac fork isVP8DecoderAvailable()=VideoDecoder::isVPXSupported()=true (it ships a
            // VPX software decoder), so WITHOUT this gate decodingInfo would return VP8 supported=true,
            // diverging from the iPhone's false. Force unsupported HERE ONLY to reproduce the device's
            // decodingInfo value. DO NOT "fix" this to match canPlayType ('probably') — the real-device
            // divergence is decodingInfo-specific; deleting this re-opens a self-vs-real leak (the W2376
            // inversion: forcing a value backward away from ground truth). Opus-in-WebM audio is unaffected.
            return std::nullopt;
#endif
            if (!isVP8DecoderAvailable())
                return std::nullopt;
            auto parameters = parseVPCodecParameters(codec);
            if (!parameters)
                return std::nullopt;
            if (!isVPCodecConfigurationRecordSupported(*parameters))
                return std::nullopt;
            if (alphaChannel || hdrSupported)
                return std::nullopt;
            info.supported = true;
            info.powerEfficient = false;
            info.smooth = isVPSoftwareDecoderSmooth(videoConfiguration);
#endif
#if ENABLE(AV1)
        } else if (codec.startsWith("av01"_s)) {
            auto parameters = parseAV1CodecParameters(codec);
            if (!parameters)
                return std::nullopt;
            auto parsedInfo = validateAV1Parameters(*parameters, videoConfiguration);
            if (!parsedInfo)
                return std::nullopt;
            info = *parsedInfo;
#endif
        } else if (videoCodecType) {
            if (alphaChannel || hdrSupported)
                return std::nullopt;

#if PLATFORM(DRIFTSTACK)
            // W2557 (#84): pin decodingInfo.powerEfficient HOST-INDEPENDENT for the generic
            // videoCodecType path. This branch handles H.264 (avc1/avc3) and mp4v (HEVC is
            // handled explicitly above; VP8/AV1 in their own branches). The native code reads
            // VTIsHardwareDecodeSupported() = the HOST Mac's VideoToolbox — coincidentally correct
            // on the Apple-Silicon fleet (every M-series Mac hardware-decodes H.264 → true; legacy
            // mp4v has no hw decoder → false) BUT it's a host-derived value (a latent fleet-variance
            // / host-leak if any fleet host ever differs). Pin to the real iPhone-17 /aio capture so
            // it's fleet-invariant + device-exact, behavior-PRESERVING on the launch fleet:
            //   avc1.42E01E (H.264): supported/smooth/powerEfficient = true (captured decodingInfo[0])
            //   mp4v (MPEG-4 Part 2 Visual): legacy, no hardware decode on iPhone → powerEfficient=false
            // smooth stays true (mirrors the native generic-path default + the captured H.264 smooth).
            info.smooth = true;
            info.powerEfficient = (videoCodecType == kCMVideoCodecType_H264);
#else
            if (canLoad_VideoToolbox_VTIsHardwareDecodeSupported()) {
                info.powerEfficient = VTIsHardwareDecodeSupported(videoCodecType);
                info.smooth = true;
            }
#endif
        } else
            return std::nullopt;
    }

    if (!configuration.audio)
        return info;

    MediaEngineSupportParameters parameters {
        .platformType = configuration.type,
        .type = ContentType(configuration.audio.value().contentType),
        .allowedMediaContainerTypes = configuration.allowedMediaContainerTypes,
        .allowedMediaCodecTypes = configuration.allowedMediaCodecTypes,
    };

    if (MediaPlayer::supportsType(parameters) != MediaPlayer::SupportsType::IsSupported)
        return std::nullopt;

    info.supported = true;
    if (!configuration.audio->spatialRendering.value_or(false))
        return info;

    info.supported = SpatialAudioPlaybackHelper::supportsSpatialAudioPlaybackForConfiguration(configuration);

    return info;
}

void createMediaPlayerDecodingConfigurationCocoa(PlatformMediaDecodingConfiguration&& configuration, Function<void(PlatformMediaCapabilitiesDecodingInfo&&)>&& callback)
{
    auto info = computeMediaCapabilitiesInfo(configuration);
    if (!info)
        callback({ { }, WTF::move(configuration) });
    else {
        PlatformMediaCapabilitiesDecodingInfo infoWithConfiguration = { WTF::move(*info), WTF::move(configuration) };
        callback(WTF::move(infoWithConfiguration));
    }
}

}
#endif
