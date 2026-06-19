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
#include "GPUSupportedLimits.h"

namespace WebCore {

uint32_t GPUSupportedLimits::maxTextureDimension1D() const
{
    return m_backing->maxTextureDimension1D();
}

uint32_t GPUSupportedLimits::maxTextureDimension2D() const
{
    return m_backing->maxTextureDimension2D();
}

uint32_t GPUSupportedLimits::maxTextureDimension3D() const
{
    return m_backing->maxTextureDimension3D();
}

uint32_t GPUSupportedLimits::maxTextureArrayLayers() const
{
    return m_backing->maxTextureArrayLayers();
}

uint32_t GPUSupportedLimits::maxBindGroups() const
{
    return m_backing->maxBindGroups();
}

uint32_t GPUSupportedLimits::maxBindGroupsPlusVertexBuffers() const
{
    return m_backing->maxBindGroupsPlusVertexBuffers();
}

uint32_t GPUSupportedLimits::maxBindingsPerBindGroup() const
{
    return m_backing->maxBindingsPerBindGroup();
}

uint32_t GPUSupportedLimits::maxDynamicUniformBuffersPerPipelineLayout() const
{
    return m_backing->maxDynamicUniformBuffersPerPipelineLayout();
}

uint32_t GPUSupportedLimits::maxDynamicStorageBuffersPerPipelineLayout() const
{
    return m_backing->maxDynamicStorageBuffersPerPipelineLayout();
}

uint32_t GPUSupportedLimits::maxSampledTexturesPerShaderStage() const
{
    return m_backing->maxSampledTexturesPerShaderStage();
}

uint32_t GPUSupportedLimits::maxSamplersPerShaderStage() const
{
    return m_backing->maxSamplersPerShaderStage();
}

uint32_t GPUSupportedLimits::maxStorageBuffersPerShaderStage() const
{
    return m_backing->maxStorageBuffersPerShaderStage();
}

uint32_t GPUSupportedLimits::maxStorageTexturesPerShaderStage() const
{
    return m_backing->maxStorageTexturesPerShaderStage();
}

uint32_t GPUSupportedLimits::maxUniformBuffersPerShaderStage() const
{
    return m_backing->maxUniformBuffersPerShaderStage();
}

#if PLATFORM(DRIFTSTACK)
// Per-minor WebGPU large-buffer cap: real iPhone Safari 26.0 reports 644245092 for
// maxBufferSize / maxUniformBufferBindingSize / maxStorageBufferBindingSize; 26.3/26.4+
// report 1073741824 (webgpu capture). 26.0 ONLY — 26.3 keeps the 26.4 value. Unset
// (the 26.4 launch default) returns 1073741824. (NOTE: the 26.0 limits-COUNT delta —
// 36 vs 32 — needs a separate runtime mechanism and is tracked in the closure ledger.)
static uint64_t driftstackWebGPUBufferCap()
{
    const char* a = getenv("DRIFTSTACK_ARCHETYPE");
    if (!a || !a[0])
        return 1073741824ULL;
    std::string_view sv(a);
    auto pos = sv.find("safari");
    if (pos == std::string_view::npos)
        return 1073741824ULL;
    sv.remove_prefix(pos + 6);
    int maj = 0, min = 0;
    size_t i = 0;
    while (i < sv.size() && sv[i] >= '0' && sv[i] <= '9') { maj = maj * 10 + (sv[i] - '0'); ++i; }
    if (i < sv.size() && (sv[i] == '_' || sv[i] == '.'))
        ++i;
    while (i < sv.size() && sv[i] >= '0' && sv[i] <= '9') { min = min * 10 + (sv[i] - '0'); ++i; }
    return (maj == 26 && min == 0) ? 644245092ULL : 1073741824ULL;
}
#endif

uint64_t GPUSupportedLimits::maxUniformBufferBindingSize() const
{
#if PLATFORM(DRIFTSTACK)
    return std::min<uint64_t>(m_backing->maxUniformBufferBindingSize(), driftstackWebGPUBufferCap());
#endif
    return m_backing->maxUniformBufferBindingSize();
}

uint64_t GPUSupportedLimits::maxStorageBufferBindingSize() const
{
#if PLATFORM(DRIFTSTACK)
    return std::min<uint64_t>(m_backing->maxStorageBufferBindingSize(), driftstackWebGPUBufferCap());
#endif
    return m_backing->maxStorageBufferBindingSize();
}

uint32_t GPUSupportedLimits::minUniformBufferOffsetAlignment() const
{
    return m_backing->minUniformBufferOffsetAlignment();
}

uint32_t GPUSupportedLimits::minStorageBufferOffsetAlignment() const
{
    return m_backing->minStorageBufferOffsetAlignment();
}

uint32_t GPUSupportedLimits::maxVertexBuffers() const
{
    return m_backing->maxVertexBuffers();
}

uint64_t GPUSupportedLimits::maxBufferSize() const
{
#if PLATFORM(DRIFTSTACK)
    return std::min<uint64_t>(m_backing->maxBufferSize(), driftstackWebGPUBufferCap());
#endif
    return m_backing->maxBufferSize();
}

uint32_t GPUSupportedLimits::maxVertexAttributes() const
{
    return m_backing->maxVertexAttributes();
}

uint32_t GPUSupportedLimits::maxVertexBufferArrayStride() const
{
    return m_backing->maxVertexBufferArrayStride();
}

uint32_t GPUSupportedLimits::maxInterStageShaderVariables() const
{
#if PLATFORM(DRIFTSTACK)
    // V-072 cumulative rig finding: iPhone 16 Pro reports 124, Mac
    // reports 31. Report iPhone-equivalent value. Real Mac GPU may
    // not support all 124 in actual use; pages that probe this for
    // fingerprinting see iPhone value, pages that allocate >31
    // inter-stage variables will fail at shader compile time
    // (acceptable trade-off for archetype matching).
    return 124;
#endif
    return m_backing->maxInterStageShaderVariables();
}

uint32_t GPUSupportedLimits::maxInterStageShaderComponents() const
{
#if PLATFORM(DRIFTSTACK)
    // Wave 29-408.3 (Driftstack 2026-05-20): empirical BS Automate iPhone 17
    // Safari 26.4 exposes the legacy `maxInterStageShaderComponents`
    // alongside the new `maxInterStageShaderVariables`, both reporting 124.
    // Upstream WebKit removed the legacy attribute (CL ~2024-Q4) but iOS
    // Safari 26.4 — built from a slightly older WebCore branch — still
    // ships it. Mirror the Variables value so Family B reports both keys
    // and the byte-for-byte iPhone surface inventory match holds.
    return maxInterStageShaderVariables();
#endif
    return m_backing->maxInterStageShaderVariables();
}

uint32_t GPUSupportedLimits::maxColorAttachments() const
{
    return m_backing->maxColorAttachments();
}

uint32_t GPUSupportedLimits::maxColorAttachmentBytesPerSample() const
{
    return m_backing->maxColorAttachmentBytesPerSample();
}

uint32_t GPUSupportedLimits::maxComputeWorkgroupStorageSize() const
{
    return m_backing->maxComputeWorkgroupStorageSize();
}

uint32_t GPUSupportedLimits::maxComputeInvocationsPerWorkgroup() const
{
    return m_backing->maxComputeInvocationsPerWorkgroup();
}

uint32_t GPUSupportedLimits::maxComputeWorkgroupSizeX() const
{
    return m_backing->maxComputeWorkgroupSizeX();
}

uint32_t GPUSupportedLimits::maxComputeWorkgroupSizeY() const
{
    return m_backing->maxComputeWorkgroupSizeY();
}

uint32_t GPUSupportedLimits::maxComputeWorkgroupSizeZ() const
{
    return m_backing->maxComputeWorkgroupSizeZ();
}

uint32_t GPUSupportedLimits::maxComputeWorkgroupsPerDimension() const
{
    return m_backing->maxComputeWorkgroupsPerDimension();
}

}
