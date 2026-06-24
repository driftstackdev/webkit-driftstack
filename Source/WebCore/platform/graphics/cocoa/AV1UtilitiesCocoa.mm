/*
 * Copyright (C) 2023 Apple Inc. All rights reserved.
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
#include "AV1UtilitiesCocoa.h"

#if PLATFORM(COCOA) && ENABLE(AV1)

#import "AV1Utilities.h"
#import "BitReader.h"
#import "CMUtilities.h"
#import "PlatformMediaCapabilitiesInfo.h"
#import "PlatformMediaCapabilitiesVideoConfiguration.h"
#import <wtf/cf/TypeCastsCF.h>
#import <wtf/cf/VectorCF.h>
#import <wtf/cocoa/TypeCastsCocoa.h>
#import <wtf/text/StringToIntegerConversion.h>

#import "VideoToolboxSoftLink.h"
#import <pal/cf/CoreMediaSoftLink.h>

namespace WebCore {

#if PLATFORM(DRIFTSTACK)
// W2561: per-archetype AV1 hardware-decode capability. AV1 hardware decode exists only on Apple
// A17 Pro and later (iPhone 15 Pro / 15 Pro Max, all iPhone 16, all iPhone 17). On the A15/A16
// archetypes (iphone13*, iphone14/14plus, iphone14pro/promax, iphone15/15plus) a REAL iPhone reports
// AV1 UNSUPPORTED — BS captures (W2560) confirm av01 canPlayType="" on iPhone 14 / 14 Pro / 15 vs
// "probably" on iPhone 15 Pro Max / 17. But the M3-class fleet HAS an AV1 hardware decoder, so the
// host VideoToolbox over-reports AV1 supported for the A15/A16 archetypes — a per-archetype
// fingerprint tell across canPlayType / MediaSource.isTypeSupported / MediaCapabilities.decodingInfo.
// Force AV1 unsupported for non-A17Pro+ archetypes so the fork matches the real device it emulates.
// (project_codec_capability_perchip_hostderived_w2560.)
static bool driftstackArchetypeHasAV1Decode()
{
    static const bool hasAV1 = [] {
        const char* env = getenv("DRIFTSTACK_ARCHETYPE");
        if (!env || !env[0])
            return true; // no archetype set => default fleet behavior (host passthrough)
        std::string_view sv { env };
        // A17 Pro+: "iphone15pro" matches iphone15pro AND iphone15promax (NOT iphone15/iphone15plus,
        // which have no "pro"); "iphone16"/"iphone17" match all of those families.
        return sv.find("iphone15pro") == 0 || sv.find("iphone16") == 0 || sv.find("iphone17") == 0;
    }();
    return hasAV1;
}
// True ONLY when an A17Pro+ archetype is EXPLICITLY set (env present + matches). Distinct from
// driftstackArchetypeHasAV1Decode() which ALSO returns true for no-env (host passthrough). A real
// iPhone 17 reports canPlayType('av01')='probably' + WebCodecs/MSE AV1 supported regardless of the
// host Mac's AV1 HW (M2 fleet box LACKS hardware AV1 → host VTIsHardwareDecodeSupported('av01')=false
// → would wrongly flip the whole AV1 surface to unsupported; M4 dev HAS it → true by luck). Pin
// HW-decode-available TRUE for an explicit A17Pro+ archetype so M2==M3==M4==iPhone (host-independent).
static bool driftstackArchetypeExplicitlyA17ProPlus()
{
    static const bool v = [] {
        const char* env = getenv("DRIFTSTACK_ARCHETYPE");
        if (!env || !env[0])
            return false;
        std::string_view sv { env };
        return sv.find("iphone15pro") == 0 || sv.find("iphone16") == 0 || sv.find("iphone17") == 0;
    }();
    return v;
}
#endif

#if !PLATFORM(DRIFTSTACK)
// Only referenced by the host-VideoToolbox validateAV1Parameters() path below, which is #else'd
// out under PLATFORM(DRIFTSTACK) (decodingInfo(av1) is forced nullopt to match the iPhone split).
static bool NODELETE isConfigurationRecordHDR(const AV1CodecConfigurationRecord& record)
{
    if (record.bitDepth < 10)
        return false;

    if (record.colorPrimaries != static_cast<uint8_t>(AV1ConfigurationColorPrimaries::BT_2020_Nonconstant_Luminance))
        return false;

    if (record.transferCharacteristics != static_cast<uint8_t>(AV1ConfigurationTransferCharacteristics::BT_2020_10bit)
        && record.transferCharacteristics != static_cast<uint8_t>(AV1ConfigurationTransferCharacteristics::BT_2020_12bit)
        && record.transferCharacteristics != static_cast<uint8_t>(AV1ConfigurationTransferCharacteristics::SMPTE_ST_2084)
        && record.transferCharacteristics != static_cast<uint8_t>(AV1ConfigurationTransferCharacteristics::BT_2100_HLG))
        return false;

    if (record.matrixCoefficients != static_cast<uint8_t>(AV1ConfigurationMatrixCoefficients::BT_2020_Nonconstant_Luminance)
        && record.matrixCoefficients != static_cast<uint8_t>(AV1ConfigurationMatrixCoefficients::BT_2020_Constant_Luminance)
        && record.matrixCoefficients != static_cast<uint8_t>(AV1ConfigurationMatrixCoefficients::BT_2100_ICC))
        return false;

    return true;
}
#endif // !PLATFORM(DRIFTSTACK)

std::optional<PlatformMediaCapabilitiesInfo> validateAV1Parameters(const AV1CodecConfigurationRecord& record, const PlatformMediaCapabilitiesVideoConfiguration& configuration)
{
#if PLATFORM(DRIFTSTACK)
    // #115: AV1 MediaCapabilities.decodingInfo is CONFIG-DEPENDENT on A17Pro+ — NOT "always false".
    // The earlier all-false override was based only on a BASIC config; the av1-decinfo-matrix capture
    // (real iPhone 17 / Safari 26.4, aio-iPhone_17-1782256826126) shows the boundary is the STANDARD AV1
    // record + per-level (resolution/framerate/bitrate/tier) validation, clamped to the iPhone AV1-HW
    // max level 5.3. Reproduced points: 13M/15M@4K60=true, 12M-&-below & 16M(6.0)@4K60=false,
    // 720..2160@13M=true, fps 24/30/60=true, bitrate 1M/5M=true / 50M=false, 10-bit=true. A15/A16 have
    // no AV1 HW → false. Computed HOST-INDEPENDENTLY (no VTCopyAV1DecoderCapabilitiesDictionary read,
    // which would track the fleet box's M3/M4 max level/bitrate, not the iPhone's) so every box matches
    // the real iPhone. canPlayType/MSE/WebCodecs still report supported via the av1HardwareDecoder pins.
    if (!driftstackArchetypeExplicitlyA17ProPlus()) {
        UNUSED_PARAM(record);
        UNUSED_PARAM(configuration);
        return std::nullopt;
    }
    if (!validateAV1ConfigurationRecord(record))
        return std::nullopt;
    if (!validateAV1PerLevelConstraints(record, configuration))
        return std::nullopt;
    // iPhone AV1-HW max level = 5.3 (matrix: 15M/level-5.3=true, 16M/level-6.0=false). The host VT path
    // would use the box's own maxDecodeLevel here; pin the iPhone's so M3/M4 don't over-support.
    if (static_cast<uint8_t>(record.level) > static_cast<uint8_t>(AV1ConfigurationLevel::Level_5_3))
        return std::nullopt;
    PlatformMediaCapabilitiesInfo info;
    info.supported = true;
    info.smooth = true;
    info.powerEfficient = true;
    return info;
#else

    if (!validateAV1ConfigurationRecord(record))
        return std::nullopt;

    if (!validateAV1PerLevelConstraints(record, configuration))
        return std::nullopt;

    if (!canLoad_VideoToolbox_VTCopyAV1DecoderCapabilitiesDictionary()
        || !canLoad_VideoToolbox_kVTDecoderCodecCapability_SupportedProfiles()
        || !canLoad_VideoToolbox_kVTDecoderCodecCapability_PerProfileSupport()
        || !canLoad_VideoToolbox_kVTDecoderProfileCapability_IsHardwareAccelerated()
        || !canLoad_VideoToolbox_kVTDecoderProfileCapability_MaxDecodeLevel()
        || !canLoad_VideoToolbox_kVTDecoderProfileCapability_MaxPlaybackLevel()
        || !canLoad_VideoToolbox_kVTDecoderCapability_ChromaSubsampling()
        || !canLoad_VideoToolbox_kVTDecoderCapability_ColorDepth())
        return std::nullopt;

    auto capabilities = adoptCF(softLink_VideoToolbox_VTCopyAV1DecoderCapabilitiesDictionary());
    if (!capabilities)
        return std::nullopt;

    RetainPtr supportedProfiles = dynamic_cf_cast<CFArrayRef>(CFDictionaryGetValue(capabilities.get(), kVTDecoderCodecCapability_SupportedProfiles));
    if (!supportedProfiles)
        return std::nullopt;

    int16_t profile = static_cast<int16_t>(record.profile);
    auto cfProfile = adoptCF(CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt16Type, &profile));
    auto searchRange = CFRangeMake(0, CFArrayGetCount(supportedProfiles.get()));
    if (!CFArrayContainsValue(supportedProfiles.get(), searchRange, cfProfile.get()))
        return std::nullopt;

    RetainPtr perProfileSupport = dynamic_cf_cast<CFDictionaryRef>(CFDictionaryGetValue(capabilities.get(), kVTDecoderCodecCapability_PerProfileSupport));
    if (!perProfileSupport)
        return std::nullopt;

    auto profileString = String::number(profile).createCFString();
    RetainPtr profileSupport = dynamic_cf_cast<CFDictionaryRef>(CFDictionaryGetValue(perProfileSupport.get(), profileString.get()));
    if (!profileSupport)
        return std::nullopt;

    PlatformMediaCapabilitiesInfo info;

    info.supported = true;

    info.powerEfficient = CFDictionaryGetValue(profileSupport.get(), kVTDecoderProfileCapability_IsHardwareAccelerated) == kCFBooleanTrue;

    if (RetainPtr cfMaxDecodeLevel = dynamic_cf_cast<CFNumberRef>(CFDictionaryGetValue(profileSupport.get(), kVTDecoderProfileCapability_MaxDecodeLevel))) {
        int16_t maxDecodeLevel = 0;
        if (!CFNumberGetValue(cfMaxDecodeLevel.get(), kCFNumberSInt16Type, &maxDecodeLevel))
            return std::nullopt;

        if (static_cast<int16_t>(record.level) > maxDecodeLevel)
            return std::nullopt;
    }

    if (RetainPtr cfSupportedChromaSubsampling = dynamic_cf_cast<CFArrayRef>(CFDictionaryGetValue(profileSupport.get(), kVTDecoderCapability_ChromaSubsampling))) {
        auto supportedChromaSubsampling = makeVector(cfSupportedChromaSubsampling.get(), [](CFStringRef chromaSubsamplingString) {
            return parseInteger<uint8_t>(String(chromaSubsamplingString));
        });

        // CoreMedia defines the kVTDecoderCapability_ChromaSubsampling value as
        // three decimal digits consisting of, in order from highest digit to lowest:
        // [subsampling_x, subsampling_y, mono_chrome]. This conflicts with AV1's
        // definition of chromaSubsampling in the Codecs Parameter String:
        // "The chromaSubsampling parameter value, represented by a three-digit decimal,
        // SHALL have its first digit equal to subsampling_x and its second digit equal to
        // subsampling_y. If both subsampling_x and subsampling_y are set to 1, then the third
        // digit SHALL be equal to chroma_sample_position, otherwise it SHALL be set to 0."

        // CoreMedia supports all values of chroma_sample_position, so to reconcile this
        // discrepency, construct a "chroma subsampling" query out of the high-order digits
        // of the AV1CodecConfigurationRecord.chromaSubsampling field, and use the
        // AV1CodecConfigurationRecord.monochrome field as the low-order digit.

        uint8_t subsamplingXandY = record.chromaSubsampling - (record.chromaSubsampling % 10);
        uint8_t subsamplingQuery = subsamplingXandY + (record.monochrome ? 1 : 0);

        if (!supportedChromaSubsampling.contains(subsamplingQuery))
            return std::nullopt;
    }

    if (RetainPtr cfSupportedColorDepths = dynamic_cf_cast<CFArrayRef>(CFDictionaryGetValue(profileSupport.get(), kVTDecoderCapability_ColorDepth))) {
        auto supportedColorDepths = makeVector(cfSupportedColorDepths.get(), [](CFStringRef colorDepthString) {
            return parseInteger<uint8_t>(String(colorDepthString));
        });
        if (!supportedColorDepths.contains(static_cast<uint8_t>(record.bitDepth)))
            return std::nullopt;
    }

    if (RetainPtr cfMaxPlaybackLevel = dynamic_cf_cast<CFNumberRef>(CFDictionaryGetValue(profileSupport.get(), kVTDecoderProfileCapability_MaxPlaybackLevel))) {
        int16_t maxPlaybackLevel = 0;
        if (!CFNumberGetValue(cfMaxPlaybackLevel.get(), kCFNumberSInt16Type, &maxPlaybackLevel))
            return std::nullopt;

        info.smooth = static_cast<int16_t>(record.level) <= maxPlaybackLevel;
    }

    if (canLoad_VideoToolbox_kVTDecoderProfileCapability_MaxHDRPlaybackLevel() && isConfigurationRecordHDR(record)) {
        if (RetainPtr cfMaxHDRPlaybackLevel = dynamic_cf_cast<CFNumberRef>(CFDictionaryGetValue(profileSupport.get(), kVTDecoderProfileCapability_MaxHDRPlaybackLevel))) {
            int16_t maxHDRPlaybackLevel = 0;
            if (!CFNumberGetValue(cfMaxHDRPlaybackLevel.get(), kCFNumberSInt16Type, &maxHDRPlaybackLevel))
                return std::nullopt;

            info.smooth = static_cast<int16_t>(record.level) <= maxHDRPlaybackLevel;
        }
    }

    return info;
#endif
}

static std::optional<bool> s_av1HardwareDecoderAvailable = { };
void setAV1HardwareDecoderAvailable(bool value)
{
    ASSERT(isMainThread());

    ASSERT(!s_av1HardwareDecoderAvailable || *s_av1HardwareDecoderAvailable == value);
    s_av1HardwareDecoderAvailable = value;
}

bool av1HardwareDecoderAvailable()
{
#if PLATFORM(DRIFTSTACK)
    // W2561: force AV1 unsupported on A15/A16 archetypes BEFORE the settable cache — the GPU process
    // calls setAV1HardwareDecoderAvailable() with the M3 fleet's host value (true), which would
    // otherwise bypass an in-process gate. This is the authoritative AV1-capability gate used by the
    // canPlayType (supportsTypeAndCodecs) + MSE (SourceBufferParserWebM) paths.
    if (!driftstackArchetypeHasAV1Decode())
        return false;
    if (driftstackArchetypeExplicitlyA17ProPlus())
        return true; // A17Pro+: HW AV1 decode present on the real iPhone → pin TRUE host-independently (before the GPU-fed cache, which carries the M2/M3 host value)
#endif

    ASSERT(isMainThread() || !!s_av1HardwareDecoderAvailable);

    if (s_av1HardwareDecoderAvailable)
        return *s_av1HardwareDecoderAvailable;
    return av1HardwareDecoderAvailableInProcess();
}

static std::optional<bool> s_av1HardwareDecoderAvailableInProcess = { };
bool av1HardwareDecoderAvailableInProcess()
{
#if PLATFORM(DRIFTSTACK)
    // W2568: the SAME A15/A16 gate as av1HardwareDecoderAvailable() must apply here too. The GPU
    // process feeds THIS value into hasAV1HardwareDecoder (GPUConnectionToWebProcess) →
    // LibWebRTCCodecs::setHasAV1HardwareDecoder → setWebCodecsAV1Enabled(true), which is the SOLE
    // flip that exposes the WebCodecs/VideoDecoder AV1 path (a software dav1d decoder). Without this
    // guard, A15/A16 archetypes report VideoDecoder.isConfigSupported('av01').supported=true while the
    // now-gated canPlayType/MSE/decodingInfo all return false — a per-chip cross-API incoherence that
    // contradicts the real device (A16 = false on every AV1 API; W2560 captures). DRIFTSTACK_ARCHETYPE
    // is forwarded to the GPU process, so this getenv-backed check is correct in-process there too.
    if (!driftstackArchetypeHasAV1Decode())
        return false;
    if (driftstackArchetypeExplicitlyA17ProPlus())
        return true; // A17Pro+: pin HW AV1 decode TRUE host-independently → WebCodecs/VideoDecoder AV1 supported (the iPhone 17 reports decodeHW/decodeSW supported); bypasses the host VTIsHardwareDecodeSupported below (false on M2 fleet)
#endif

    ASSERT(isMainThread() || !!s_av1HardwareDecoderAvailableInProcess);

    if (!s_av1HardwareDecoderAvailableInProcess)
        s_av1HardwareDecoderAvailableInProcess = canLoad_VideoToolbox_VTIsHardwareDecodeSupported() && VTIsHardwareDecodeSupported('av01');
    return *s_av1HardwareDecoderAvailableInProcess;
}

}

#endif
