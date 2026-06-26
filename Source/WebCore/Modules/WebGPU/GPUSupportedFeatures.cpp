/*
 * Copyright (C) 2021-2023 Apple Inc. All rights reserved.
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
#include "GPUSupportedFeatures.h"
#include "IDLTypes.h"

#if PLATFORM(DRIFTSTACK)
#include <cstdlib>
#include <string_view>
#endif

namespace WebCore {

#if PLATFORM(DRIFTSTACK)
// The Mac M-series adapter passes through the full desktop WebGPU feature set; real iPhones expose
// a chip/version-trimmed subset. Capture-grounded per-archetype truth (BS /aio):
//   A15/A16 (iPhone 14 / 14 Pro / 15) @26.2 = 15 features — LACK the desktop BC family
//       (texture-compression-bc, texture-compression-bc-sliced-3d, float32-filterable).
//   A19    (iPhone 17 Pro / Pro Max)  @26.0 = 17 features — has the BC family, LACKS
//       texture-formats-tier1 (a 26.1+ addition).
//   A19    (iPhone 17 / 17 Pro)       @26.2+ = 18 features (full set; launch baseline @26.4).

// True for archetypes whose GPU is A16 or earlier — the SAME chip line as the WebGL extension filter
// (archetypeIsOlderGpuExtensionTier in DriftstackWebGLExtensionAllowlist.cpp, which drops
// EXT_texture_compression_bptc/rgtc + WEBGL_compressed_texture_s3tc* + OES_texture_float_linear —
// the WebGL spelling of this exact BC/float32-filterable family). Kept byte-identical here (the
// header isn't visible to the WebGPU module's unified unit) so both surfaces stay coherent.
static bool driftstackArchetypeIsOlderGpuTier()
{
    const char* archetype = getenv("DRIFTSTACK_ARCHETYPE");
    if (!archetype)
        return false; // no archetype env = launch default iPhone 17 (A19) = newer-GPU tier
    std::string_view a(archetype);
    if (a.find("iphone13") != std::string_view::npos)
        return true; // A15
    if (a.find("iphone14") != std::string_view::npos)
        return true; // A15 (14/14 Plus) / A16 (14 Pro/Pro Max)
    if (a.find("iphone15pro") != std::string_view::npos)
        return false; // iPhone 15 Pro / 15 Pro Max = A17 Pro = newer-GPU tier
    if (a.find("iphone15") != std::string_view::npos)
        return true; // iPhone 15 / 15 Plus = A16
    return false; // iphone16* / iphone17* = A18 / A19 = newer-GPU tier
}

// True only for Safari 26.0 (incl. 26.0.x) archetypes — mirrors the version-keying in
// GPUSupportedLimits.cpp (driftstackWebGPUBufferCap). texture-formats-tier1 is absent on 26.0
// and present from 26.1+; unset (the 26.4 launch default) keeps it.
static bool driftstackArchetypeIsSafari26_0()
{
    const char* a = getenv("DRIFTSTACK_ARCHETYPE");
    if (!a || !a[0])
        return false; // no archetype env = iphone17 launch (26.4) = keep tier1
    std::string_view sv(a);
    auto pos = sv.find("safari");
    if (pos == std::string_view::npos)
        return false;
    sv.remove_prefix(pos + 6);
    int maj = 0, min = 0;
    size_t i = 0;
    while (i < sv.size() && sv[i] >= '0' && sv[i] <= '9') { maj = maj * 10 + (sv[i] - '0'); ++i; }
    if (i < sv.size() && (sv[i] == '_' || sv[i] == '.'))
        ++i;
    while (i < sv.size() && sv[i] >= '0' && sv[i] <= '9') { min = min * 10 + (sv[i] - '0'); ++i; }
    return maj == 26 && min == 0;
}
#endif

void GPUSupportedFeatures::initializeSetLike(DOMSetAdapter& set) const
{
#if PLATFORM(DRIFTSTACK)
    const bool olderGpuTier = driftstackArchetypeIsOlderGpuTier();
    const bool stripTier1 = driftstackArchetypeIsSafari26_0();
#endif
    for (const auto& feature : m_backing->features()) {
#if PLATFORM(DRIFTSTACK)
        // V-072 cumulative rig finding: Mac exposes "clip-distances" in
        // the GPU adapter feature set; iPhone 16 Pro / iOS 26.4 does not.
        // Filter it out on Driftstack to match the iPhone feature list.
        if (feature == "clip-distances"_s)
            continue;
        // Older-GPU-tier (A15/A16) iPhones lack the desktop BC compression family + float32-filterable.
        if (olderGpuTier && (feature == "texture-compression-bc"_s
            || feature == "texture-compression-bc-sliced-3d"_s
            || feature == "float32-filterable"_s))
            continue;
        // Safari 26.0 predates texture-formats-tier1.
        if (stripTier1 && feature == "texture-formats-tier1"_s)
            continue;
#endif
        set.add<IDLDOMString>(feature);
    }
}

}
