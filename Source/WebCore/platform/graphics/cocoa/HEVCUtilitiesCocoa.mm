/*
 * Copyright (C) 2018 Apple Inc. All rights reserved.
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

#import "config.h"
#import "HEVCUtilitiesCocoa.h"

#if PLATFORM(COCOA)

#import "FourCC.h"
#import "HEVCUtilities.h"
#import "PlatformMediaCapabilitiesInfo.h"
#import <wtf/cf/TypeCastsCF.h>
#import <wtf/cocoa/TypeCastsCocoa.h>
#import <wtf/cocoa/VectorCocoa.h>
#import <wtf/text/StringToIntegerConversion.h>

#import "VideoToolboxSoftLink.h"
#import <pal/cocoa/AVFoundationSoftLink.h>

namespace WebCore {

#if PLATFORM(DRIFTSTACK)
// Per-chip HEVC hardware-decode LEVEL ceiling. The fork's MediaCapabilities.decodingInfo path
// (validateHEVCParameters below) reads the fleet Mac's VideoToolbox kVTHEVCDecoderProfileCapability_
// MaxDecodeLevel, which on an Apple-Silicon Mac advertises HEVC Level 6.2 (generalLevelIDC 186 =
// 8K). But the real iPhone HEVC decoder ceiling is chip-bound and BELOW 6.2 on A15/A16:
//   BS real-device ground truth (hevc-levels-probe across the L90..L186 ladder x 5 res/fps):
//     A15  (iPhone 14, Safari 18.3 / 26.2 / 26.4, 3 caps): L186 sup=false/pe=false, L180 sup=true  -> ceiling L180 (6.0)
//     A16  (iPhone 14 Pro, Safari 26.4, captured 2026-06-30): L186 sup=false/pe=false, L180 sup=true -> ceiling L180 (6.0)
//     A17Pro (iPhone 15 Pro Max), A18 (iPhone 16 Plus), A18Pro (16 Pro), A19 (iPhone 17): L186 sup=true -> no clamp
// So on an A15/A16 archetype the host VT over-reports HEVC decodingInfo(hvc1.*.L186).supported=true/
// powerEfficient=true where the real device returns supported=false/powerEfficient=false — a per-chip
// MediaCapabilities fingerprint tell across exactly the L186 row (every lower level matches byte-identically).
// The chip boundary is IDENTICAL to driftstackArchetypeHasAV1Decode (A17Pro+ = iphone15pro / iphone15promax /
// iphone16* / iphone17*); registered in operations/boundary-registry.json (surface hevc_decode_level_ceiling).
// Returns the max generalLevelIDC the emulated chip decodes (a level above it -> info.supported=false).
// (project_codec_capability_perchip_hostderived_w2560; the same per-chip-clamp class as the host-GPU
// MAX_SAMPLES / WebGL max-params host-leak.)
static uint16_t driftstackArchetypeHEVCMaxDecodeLevel()
{
    // Read getenv LIVE (NOT a static cache — a static initializes during early process init when
    // DRIFTSTACK_ARCHETYPE may still be unset, caching the wrong ceiling; same fix-class as the AV1 gate / Kefa / C1).
    const char* env = getenv("DRIFTSTACK_ARCHETYPE");
    if (!env || !env[0])
        return 255; // no archetype set => default fleet behavior (host passthrough, no clamp)
    std::string_view sv { env };
    // A17 Pro+ legitimately decodes HEVC Level 6.2: "iphone15pro" matches iphone15pro AND iphone15promax
    // (NOT iphone15 / iphone15plus, which have no "pro"); "iphone16"/"iphone17" match all of those families.
    if (sv.find("iphone15pro") == 0 || sv.find("iphone16") == 0 || sv.find("iphone17") == 0)
        return 255; // no clamp — these chips report L186 supported (matches the real device)
    // A15 / A16 (iphone13*, iphone14, iphone14plus, iphone14pro, iphone14promax, iphone15, iphone15plus):
    // real-device ceiling is HEVC Level 6.0 (generalLevelIDC 180); anything above (L186 = 6.2) is unsupported.
    return 180;
}
#endif

std::optional<PlatformMediaCapabilitiesInfo> validateHEVCParameters(const HEVCParameters& parameters, bool hasAlphaChannel, bool hdrSupport)
{
    CMVideoCodecType codec = kCMVideoCodecType_HEVC;
    if (hasAlphaChannel) {
        if (!PAL::isAVFoundationFrameworkAvailable() || !PAL::canLoad_AVFoundation_AVVideoCodecTypeHEVCWithAlpha())
            return std::nullopt;

        auto codecCode = FourCC::fromString(String { AVVideoCodecTypeHEVCWithAlpha });
        if (!codecCode)
            return std::nullopt;

        codec = codecCode.value().value;
    }

    if (hdrSupport) {
        // Platform supports HDR playback of HEVC Main10 Profile, as defined by ITU-T H.265 v6 (06/2019).
        bool isMain10 = parameters.generalProfileSpace == 0
            && (parameters.generalProfileIDC == 2 || parameters.generalProfileCompatibilityFlags == 1);
        if (!isMain10)
            return std::nullopt;
    }

    OSStatus status = VTSelectAndCreateVideoDecoderInstance(codec, kCFAllocatorDefault, nullptr, nullptr);
    if (status != noErr)
        return std::nullopt;

    if (!canLoad_VideoToolbox_VTCopyHEVCDecoderCapabilitiesDictionary()
        || !canLoad_VideoToolbox_kVTHEVCDecoderCapability_SupportedProfiles()
        || !canLoad_VideoToolbox_kVTHEVCDecoderCapability_PerProfileSupport()
        || !canLoad_VideoToolbox_kVTHEVCDecoderProfileCapability_IsHardwareAccelerated()
        || !canLoad_VideoToolbox_kVTHEVCDecoderProfileCapability_MaxDecodeLevel()
        || !canLoad_VideoToolbox_kVTHEVCDecoderProfileCapability_MaxPlaybackLevel())
        return std::nullopt;

    auto capabilities = adoptCF(VTCopyHEVCDecoderCapabilitiesDictionary());
    if (!capabilities)
        return std::nullopt;

    RetainPtr supportedProfiles = dynamic_cf_cast<CFArrayRef>(CFDictionaryGetValue(capabilities.get(), kVTHEVCDecoderCapability_SupportedProfiles));
    if (!supportedProfiles)
        return std::nullopt;

    int16_t generalProfileIDC = parameters.generalProfileIDC;
    auto cfGeneralProfileIDC = adoptCF(CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt16Type, &generalProfileIDC));
    auto searchRange = CFRangeMake(0, CFArrayGetCount(supportedProfiles.get()));
    if (!CFArrayContainsValue(supportedProfiles.get(), searchRange, cfGeneralProfileIDC.get()))
        return std::nullopt;

    RetainPtr perProfileSupport = dynamic_cf_cast<CFDictionaryRef>(CFDictionaryGetValue(capabilities.get(), kVTHEVCDecoderCapability_PerProfileSupport));
    if (!perProfileSupport)
        return std::nullopt;

    auto generalProfileIDCString = String::number(generalProfileIDC).createCFString();
    RetainPtr profileSupport = dynamic_cf_cast<CFDictionaryRef>(CFDictionaryGetValue(perProfileSupport.get(), generalProfileIDCString.get()));
    if (!profileSupport)
        return std::nullopt;

    PlatformMediaCapabilitiesInfo info;

    info.supported = true;

    info.powerEfficient = CFDictionaryGetValue(profileSupport.get(), kVTHEVCDecoderProfileCapability_IsHardwareAccelerated) == kCFBooleanTrue;

    if (RetainPtr cfMaxDecodeLevel = dynamic_cf_cast<CFNumberRef>(CFDictionaryGetValue(profileSupport.get(), kVTHEVCDecoderProfileCapability_MaxDecodeLevel))) {
        int16_t maxDecodeLevel = 0;
        if (!CFNumberGetValue(cfMaxDecodeLevel.get(), kCFNumberSInt16Type, &maxDecodeLevel))
            return std::nullopt;

        if (parameters.generalLevelIDC > maxDecodeLevel)
            return std::nullopt;
    }

    if (RetainPtr cfMaxPlaybackLevel = dynamic_cf_cast<CFNumberRef>(CFDictionaryGetValue(profileSupport.get(), kVTHEVCDecoderProfileCapability_MaxPlaybackLevel))) {
        int16_t maxPlaybackLevel = 0;
        if (!CFNumberGetValue(cfMaxPlaybackLevel.get(), kCFNumberSInt16Type, &maxPlaybackLevel))
            return std::nullopt;

        info.smooth = parameters.generalLevelIDC <= maxPlaybackLevel;
    }

#if PLATFORM(DRIFTSTACK)
    // Per-chip HEVC LEVEL ceiling (see driftstackArchetypeHEVCMaxDecodeLevel above). The host VT
    // MaxDecodeLevel check at line ~112 used the FLEET Mac's ceiling (HEVC L6.2 / generalLevelIDC 186),
    // so an A15/A16 archetype over-reported decodingInfo(hvc1.*.L186)=supported where the real iPhone
    // returns unsupported. Clamp to the emulated chip's ceiling so the L186 row matches the real device
    // (A17Pro+ returns 255 = no clamp; A15/A16 return 180 = HEVC L6.0). BS-grounded, version-invariant
    // (A15 L186=false captured identically on Safari 18.3 / 26.2 / 26.4 — the ceiling is a chip property).
    if (parameters.generalLevelIDC > driftstackArchetypeHEVCMaxDecodeLevel())
        return std::nullopt;

    // W2741 host-leak audit + BS real-device (iPhone 17, 45 HEVC configs across the level ladder x
    // resolution x framerate, 2 captures): real iPhone MediaCapabilities.decodingInfo(HEVC).smooth is
    // ALWAYS false (supported/powerEfficient stay true). Cause: iOS VideoToolbox does NOT expose
    // kVTHEVCDecoderProfileCapability_MaxPlaybackLevel for HEVC, so info.smooth keeps its default
    // (false); the Mac fork's VT DOES expose it → smooth=true above (a host-leak, fleet-axis varying).
    // H.264 is a separate path and correctly reports smooth=true on iPhone — only HEVC is pinned here.
    info.smooth = false;
    // host-leak sweep acf8db98 residual #1: info.powerEfficient above reads the host VT
    // kVTHEVCDecoderProfileCapability_IsHardwareAccelerated → fleet-chip-varying host-passthrough.
    // BS real-device ground truth (aio iPhone 15 Pro Max / 16 Pro Max / 14, 2026-06-28; hevcLevels
    // all pe:true, hvc1 decodingInfo powerEfficient:true, decodingInfoPosture.hevc_4k60="s=true,sm=false,pe=true"):
    // iPhones (A9+) have dedicated HEVC HW decode → powerEfficient is ALWAYS true once supported. Pin it.
    info.powerEfficient = true;
#endif

    return info;
}

static CMVideoCodecType NODELETE codecType(DoViParameters::Codec codec)
{
    switch (codec) {
    case DoViParameters::Codec::AVC1:
    case DoViParameters::Codec::AVC3:
        return kCMVideoCodecType_H264;
    case DoViParameters::Codec::HEV1:
    case DoViParameters::Codec::HVC1:
        return kCMVideoCodecType_HEVC;
    }
}

static std::optional<Vector<uint16_t>> parseStringArrayFromDictionaryToUInt16Vector(CFDictionaryRef dictionary, const void* key)
{
    RetainPtr array = dynamic_cf_cast<CFArrayRef>(CFDictionaryGetValue(dictionary, key));
    if (!array)
        return std::nullopt;
    bool parseFailed = false;
    auto result = makeVector(bridge_cast(array.get()), [&] (id value) {
        auto parseResult = parseInteger<uint16_t>(String(dynamic_objc_cast<NSString>(value)));
        parseFailed |= !parseResult;
        return parseResult;
    });
    if (parseFailed)
        return std::nullopt;
    return result;
}

std::optional<PlatformMediaCapabilitiesInfo> validateDoViParameters(const DoViParameters& parameters, bool hasAlphaChannel, bool hdrSupport)
{
    if (hasAlphaChannel)
        return std::nullopt;

#if PLATFORM(DRIFTSTACK)
    // Driftstack: the real iPhone (17 / iOS 18.7 / Safari 26.x) MediaCapabilities.decodingInfo reports
    // Dolby Vision supported ONLY for the dvh1 (HVC1) brand at profile 5. BS-captured (decinfo-iPhone_17,
    // 5 configs): dvh1.05.06 + dvh1.05.09 = {supported,smooth,powerEfficient} all true; dvhe.05.06 /
    // dvhe.08.07 / dvh1.08.07 = all false. The fleet Mac's VideoToolbox supports the broader DoVi set
    // (dvhe brand + profile 8), so without this gate the fork over-reports those = a DoVi decodingInfo
    // fingerprint tell (A3-confirmed live on daemon 48920: fork dvhe.08.07=true vs iPhone false).
    if (!(parameters.codec == DoViParameters::Codec::HVC1 && parameters.bitstreamProfileID == 5))
        return std::nullopt;
    // The real iPhone-17 / iOS-18.7 / Safari-26.x reports dvh1 (HVC1) profile-5 DoVi
    // {supported, smooth, powerEfficient} = all TRUE (decinfo-iPhone_17: dvh1.05.06 + dvh1.05.09). FORCE it
    // and RETURN here — do NOT fall through to the host VideoToolbox capability check below
    // (VTCopyHEVCDecoderCapabilitiesDictionary + supportedProfiles/supportedLevels + isHardwareAccelerated),
    // which is HOST-DEPENDENT: a fleet Mac whose VT lacks a dvh1-p5 DoVi decoder (e.g. a headless M-series
    // box) UNDER-reports supported=false, and even on the success path powerEfficient=isHardwareAccelerated
    // leaks the host's hardware-vs-software DoVi decode path — both diverge from the iPhone's unconditional
    // true (A3 box-confirmed 2026-07-03: dovi_dvh1_p5_1080p expected true, host-VT returned false on the
    // M2-Pro box). The gate just above already removed the OVER-report (dvhe brand / profile-8); this closes
    // the UNDER-report + the powerEfficient host-leak so dvh1-p5 DoVi decodingInfo is host-independent and
    // byte-matches the device on any fleet chip.
    return { { true, true, true } };
#endif

    if (hdrSupport) {
        // Platform supports HDR playback of HEVC Main10 Profile, which is signalled by DoVi profiles 4, 5, 7, & 8.
        switch (parameters.bitstreamProfileID) {
        case 4:
        case 5:
        case 7:
        case 8:
            break;
        default:
            return std::nullopt;
        }
    }

    OSStatus status = VTSelectAndCreateVideoDecoderInstance(codecType(parameters.codec), kCFAllocatorDefault, nullptr, nullptr);
    if (status != noErr)
        return std::nullopt;

    if (!canLoad_VideoToolbox_VTCopyHEVCDecoderCapabilitiesDictionary()
        || !canLoad_VideoToolbox_kVTDolbyVisionDecoderCapability_SupportedProfiles()
        || !canLoad_VideoToolbox_kVTDolbyVisionDecoderCapability_SupportedLevels()
        || !canLoad_VideoToolbox_kVTDolbyVisionDecoderCapability_IsHardwareAccelerated())
        return std::nullopt;

    auto capabilities = adoptCF(VTCopyHEVCDecoderCapabilitiesDictionary());
    if (!capabilities)
        return std::nullopt;

    auto supportedProfiles = parseStringArrayFromDictionaryToUInt16Vector(capabilities.get(), kVTDolbyVisionDecoderCapability_SupportedProfiles);
    if (!supportedProfiles)
        return std::nullopt;

    auto supportedLevels = parseStringArrayFromDictionaryToUInt16Vector(capabilities.get(), kVTDolbyVisionDecoderCapability_SupportedLevels);
    if (!supportedLevels)
        return std::nullopt;

    bool isHardwareAccelerated = CFDictionaryGetValue(capabilities.get(), kVTDolbyVisionDecoderCapability_IsHardwareAccelerated) == kCFBooleanTrue;

    if (!supportedProfiles.value().contains(parameters.bitstreamProfileID) || !supportedLevels.value().contains(parameters.bitstreamLevelID))
        return std::nullopt;

    return { { true, true, isHardwareAccelerated } };
}

}

#endif // PLATFORM(COCOA)
