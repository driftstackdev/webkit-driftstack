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

#if PLATFORM(DRIFTSTACK)
// N1 defensive fleet-invariance pin (Driftstack 2026-06-29): every JS-facing
// GPUSupportedLimits accessor that previously passed the host Metal backing value
// straight through is now pinned to the captured iPhone gold-truth. The backing
// values come from WebGPU/HardwareCapabilities.mm, which selects a GPU-FAMILY
// profile (apple7/apple8/mac2/...) by the host MTLDevice feature set + a few
// device-scaled values (maxBufferSize from device.maxBufferLength). On today's
// all-M3-Ultra fleet these coincide with the A-series iPhone, but they are
// host-VARIABLE: an M2/M4/Intel Mac (or a future Metal revision) could select a
// different profile and leak the host chip. Rather than rely on the fleet staying
// M3, pin the JS surface to the iPhone values captured across A15..A19 / Safari
// 17.1.1..26.5 (driftstack reference/realdevice-bs/aio-iPhone_* webgpu.adapter.limits
// — byte-identical across all 8 device models; see captures/v1/webgpu-supported-limits-gate.sh).
// The 3 buffer-size limits (version-keyed clamp) + maxInterStageShaderVariables (124)
// keep their existing dedicated overrides below; these constants cover the rest.
//
// CHIP/VERSION-INVARIANT iPhone gold-truth (27 of 31; the other 4 = the 3 buffer
// caps + interStage handled separately):
static constexpr uint32_t kDriftstackGPULimit_maxTextureDimension1D = 16384;
static constexpr uint32_t kDriftstackGPULimit_maxTextureDimension2D = 16384;
static constexpr uint32_t kDriftstackGPULimit_maxTextureDimension3D = 2048;
static constexpr uint32_t kDriftstackGPULimit_maxTextureArrayLayers = 2048;
static constexpr uint32_t kDriftstackGPULimit_maxBindGroups = 11;
static constexpr uint32_t kDriftstackGPULimit_maxBindGroupsPlusVertexBuffers = 30;
static constexpr uint32_t kDriftstackGPULimit_maxBindingsPerBindGroup = 65535;
static constexpr uint32_t kDriftstackGPULimit_maxDynamicUniformBuffersPerPipelineLayout = 65535;
static constexpr uint32_t kDriftstackGPULimit_maxDynamicStorageBuffersPerPipelineLayout = 65535;
static constexpr uint32_t kDriftstackGPULimit_maxSampledTexturesPerShaderStage = 44;
static constexpr uint32_t kDriftstackGPULimit_maxSamplersPerShaderStage = 22;
static constexpr uint32_t kDriftstackGPULimit_maxStorageBuffersPerShaderStage = 44;
static constexpr uint32_t kDriftstackGPULimit_maxStorageTexturesPerShaderStage = 44;
static constexpr uint32_t kDriftstackGPULimit_maxUniformBuffersPerShaderStage = 44;
static constexpr uint32_t kDriftstackGPULimit_minUniformBufferOffsetAlignment = 32;
static constexpr uint32_t kDriftstackGPULimit_minStorageBufferOffsetAlignment = 32;
static constexpr uint32_t kDriftstackGPULimit_maxVertexBuffers = 12;
static constexpr uint32_t kDriftstackGPULimit_maxVertexAttributes = 30;
static constexpr uint32_t kDriftstackGPULimit_maxVertexBufferArrayStride = 65532;
static constexpr uint32_t kDriftstackGPULimit_maxColorAttachments = 8;
static constexpr uint32_t kDriftstackGPULimit_maxColorAttachmentBytesPerSample = 64;
static constexpr uint32_t kDriftstackGPULimit_maxComputeWorkgroupStorageSize = 32768;
static constexpr uint32_t kDriftstackGPULimit_maxComputeInvocationsPerWorkgroup = 1024;
static constexpr uint32_t kDriftstackGPULimit_maxComputeWorkgroupSizeX = 1024;
static constexpr uint32_t kDriftstackGPULimit_maxComputeWorkgroupSizeY = 1024;
static constexpr uint32_t kDriftstackGPULimit_maxComputeWorkgroupSizeZ = 1024;
static constexpr uint32_t kDriftstackGPULimit_maxComputeWorkgroupsPerDimension = 65535;
#endif

uint32_t GPUSupportedLimits::maxTextureDimension1D() const
{
#if PLATFORM(DRIFTSTACK)
    return kDriftstackGPULimit_maxTextureDimension1D;
#endif
    return m_backing->maxTextureDimension1D();
}

uint32_t GPUSupportedLimits::maxTextureDimension2D() const
{
#if PLATFORM(DRIFTSTACK)
    return kDriftstackGPULimit_maxTextureDimension2D;
#endif
    return m_backing->maxTextureDimension2D();
}

uint32_t GPUSupportedLimits::maxTextureDimension3D() const
{
#if PLATFORM(DRIFTSTACK)
    return kDriftstackGPULimit_maxTextureDimension3D;
#endif
    return m_backing->maxTextureDimension3D();
}

uint32_t GPUSupportedLimits::maxTextureArrayLayers() const
{
#if PLATFORM(DRIFTSTACK)
    return kDriftstackGPULimit_maxTextureArrayLayers;
#endif
    return m_backing->maxTextureArrayLayers();
}

uint32_t GPUSupportedLimits::maxBindGroups() const
{
#if PLATFORM(DRIFTSTACK)
    return kDriftstackGPULimit_maxBindGroups;
#endif
    return m_backing->maxBindGroups();
}

uint32_t GPUSupportedLimits::maxBindGroupsPlusVertexBuffers() const
{
#if PLATFORM(DRIFTSTACK)
    return kDriftstackGPULimit_maxBindGroupsPlusVertexBuffers;
#endif
    return m_backing->maxBindGroupsPlusVertexBuffers();
}

uint32_t GPUSupportedLimits::maxBindingsPerBindGroup() const
{
#if PLATFORM(DRIFTSTACK)
    return kDriftstackGPULimit_maxBindingsPerBindGroup;
#endif
    return m_backing->maxBindingsPerBindGroup();
}

uint32_t GPUSupportedLimits::maxDynamicUniformBuffersPerPipelineLayout() const
{
#if PLATFORM(DRIFTSTACK)
    return kDriftstackGPULimit_maxDynamicUniformBuffersPerPipelineLayout;
#endif
    return m_backing->maxDynamicUniformBuffersPerPipelineLayout();
}

uint32_t GPUSupportedLimits::maxDynamicStorageBuffersPerPipelineLayout() const
{
#if PLATFORM(DRIFTSTACK)
    return kDriftstackGPULimit_maxDynamicStorageBuffersPerPipelineLayout;
#endif
    return m_backing->maxDynamicStorageBuffersPerPipelineLayout();
}

uint32_t GPUSupportedLimits::maxSampledTexturesPerShaderStage() const
{
#if PLATFORM(DRIFTSTACK)
    return kDriftstackGPULimit_maxSampledTexturesPerShaderStage;
#endif
    return m_backing->maxSampledTexturesPerShaderStage();
}

uint32_t GPUSupportedLimits::maxSamplersPerShaderStage() const
{
#if PLATFORM(DRIFTSTACK)
    return kDriftstackGPULimit_maxSamplersPerShaderStage;
#endif
    return m_backing->maxSamplersPerShaderStage();
}

uint32_t GPUSupportedLimits::maxStorageBuffersPerShaderStage() const
{
#if PLATFORM(DRIFTSTACK)
    return kDriftstackGPULimit_maxStorageBuffersPerShaderStage;
#endif
    return m_backing->maxStorageBuffersPerShaderStage();
}

uint32_t GPUSupportedLimits::maxStorageTexturesPerShaderStage() const
{
#if PLATFORM(DRIFTSTACK)
    return kDriftstackGPULimit_maxStorageTexturesPerShaderStage;
#endif
    return m_backing->maxStorageTexturesPerShaderStage();
}

uint32_t GPUSupportedLimits::maxUniformBuffersPerShaderStage() const
{
#if PLATFORM(DRIFTSTACK)
    return kDriftstackGPULimit_maxUniformBuffersPerShaderStage;
#endif
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
#if PLATFORM(DRIFTSTACK)
    return kDriftstackGPULimit_minUniformBufferOffsetAlignment;
#endif
    return m_backing->minUniformBufferOffsetAlignment();
}

uint32_t GPUSupportedLimits::minStorageBufferOffsetAlignment() const
{
#if PLATFORM(DRIFTSTACK)
    return kDriftstackGPULimit_minStorageBufferOffsetAlignment;
#endif
    return m_backing->minStorageBufferOffsetAlignment();
}

uint32_t GPUSupportedLimits::maxVertexBuffers() const
{
#if PLATFORM(DRIFTSTACK)
    return kDriftstackGPULimit_maxVertexBuffers;
#endif
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
#if PLATFORM(DRIFTSTACK)
    return kDriftstackGPULimit_maxVertexAttributes;
#endif
    return m_backing->maxVertexAttributes();
}

uint32_t GPUSupportedLimits::maxVertexBufferArrayStride() const
{
#if PLATFORM(DRIFTSTACK)
    return kDriftstackGPULimit_maxVertexBufferArrayStride;
#endif
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
#if PLATFORM(DRIFTSTACK)
    return kDriftstackGPULimit_maxColorAttachments;
#endif
    return m_backing->maxColorAttachments();
}

uint32_t GPUSupportedLimits::maxColorAttachmentBytesPerSample() const
{
#if PLATFORM(DRIFTSTACK)
    return kDriftstackGPULimit_maxColorAttachmentBytesPerSample;
#endif
    return m_backing->maxColorAttachmentBytesPerSample();
}

uint32_t GPUSupportedLimits::maxComputeWorkgroupStorageSize() const
{
#if PLATFORM(DRIFTSTACK)
    return kDriftstackGPULimit_maxComputeWorkgroupStorageSize;
#endif
    return m_backing->maxComputeWorkgroupStorageSize();
}

uint32_t GPUSupportedLimits::maxComputeInvocationsPerWorkgroup() const
{
#if PLATFORM(DRIFTSTACK)
    return kDriftstackGPULimit_maxComputeInvocationsPerWorkgroup;
#endif
    return m_backing->maxComputeInvocationsPerWorkgroup();
}

uint32_t GPUSupportedLimits::maxComputeWorkgroupSizeX() const
{
#if PLATFORM(DRIFTSTACK)
    return kDriftstackGPULimit_maxComputeWorkgroupSizeX;
#endif
    return m_backing->maxComputeWorkgroupSizeX();
}

uint32_t GPUSupportedLimits::maxComputeWorkgroupSizeY() const
{
#if PLATFORM(DRIFTSTACK)
    return kDriftstackGPULimit_maxComputeWorkgroupSizeY;
#endif
    return m_backing->maxComputeWorkgroupSizeY();
}

uint32_t GPUSupportedLimits::maxComputeWorkgroupSizeZ() const
{
#if PLATFORM(DRIFTSTACK)
    return kDriftstackGPULimit_maxComputeWorkgroupSizeZ;
#endif
    return m_backing->maxComputeWorkgroupSizeZ();
}

uint32_t GPUSupportedLimits::maxComputeWorkgroupsPerDimension() const
{
#if PLATFORM(DRIFTSTACK)
    return kDriftstackGPULimit_maxComputeWorkgroupsPerDimension;
#endif
    return m_backing->maxComputeWorkgroupsPerDimension();
}

#if PLATFORM(DRIFTSTACK)
// Class E (26.0/26.3 closure ledger): real iPhone Safari 26.0 reports these 4 per-stage
// storage limits as the constant UINT32_MAX (4294967295) sentinel; Apple removed them at
// 26.2 (26.0 = 36 limits, 26.2+ = 32). The IDL gate (DriftstackLegacyWebGPUPerStageLimits-
// Enabled, default false) keeps them OFF for 26.3/26.4(launch)/26.5; the WebPage.cpp <26.2
// block enables them for the safari26_0 band. Constant — no backing/IPC dependency.
uint32_t GPUSupportedLimits::maxStorageBuffersInFragmentStage() const
{
    return 4294967295u;
}

uint32_t GPUSupportedLimits::maxStorageTexturesInFragmentStage() const
{
    return 4294967295u;
}

uint32_t GPUSupportedLimits::maxStorageBuffersInVertexStage() const
{
    return 4294967295u;
}

uint32_t GPUSupportedLimits::maxStorageTexturesInVertexStage() const
{
    return 4294967295u;
}
#endif

}
