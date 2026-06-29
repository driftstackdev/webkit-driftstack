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
#include "GPUAdapter.h"

#include "Exception.h"
#include "JSDOMPromiseDeferred.h"
#include "JSGPUAdapterInfo.h"
#include "JSGPUDevice.h"

#include <wtf/HashSet.h>
#include <wtf/HashTraits.h>
#include <wtf/SortedArrayMap.h>

namespace WebCore {

String GPUAdapter::name() const
{
    return m_backing->name();
}

GPUAdapter::GPUAdapter(Ref<WebGPU::Adapter>&& backing)
    : m_backing(WTF::move(backing))
    , m_features(GPUSupportedFeatures::create(WebGPU::SupportedFeatures::clone(m_backing->features())))
    , m_limits(GPUSupportedLimits::create(WebGPU::SupportedLimits::clone(m_backing->limits())))
    , m_info(GPUAdapterInfo::create(name()))
{
}

Ref<GPUSupportedFeatures> GPUAdapter::features() const
{
    return m_features;
}

Ref<GPUSupportedLimits> GPUAdapter::limits() const
{
    return m_limits;
}

bool GPUAdapter::isFallbackAdapter() const
{
    return m_backing->isFallbackAdapter();
}

static WebGPU::DeviceDescriptor convertToBacking(const std::optional<GPUDeviceDescriptor>& options)
{
    if (!options)
        return { };

    return options->convertToBacking();
}

#if !PLATFORM(DRIFTSTACK)
static GPUFeatureName convertFeatureNameToEnum(const String& stringValue)
{
    static constexpr SortedArrayMap enumerationMapping { std::to_array<std::pair<ComparableASCIILiteral, GPUFeatureName>>({
        { "bgra8unorm-storage"_s, GPUFeatureName::Bgra8unormStorage },
        { "clip-distances"_s, GPUFeatureName::ClipDistances },
        { "core-features-and-limits"_s, GPUFeatureName::CoreFeaturesAndLimits },
        { "depth-clip-control"_s, GPUFeatureName::DepthClipControl },
        { "depth32float-stencil8"_s, GPUFeatureName::Depth32floatStencil8 },
        { "dual-source-blending"_s, GPUFeatureName::DualSourceBlending },
        { "float16-renderable"_s, GPUFeatureName::Float16Renderable },
        { "float32-blendable"_s, GPUFeatureName::Float32Blendable },
        { "float32-filterable"_s, GPUFeatureName::Float32Filterable },
        { "float32-renderable"_s, GPUFeatureName::Float32Renderable },
        { "indirect-first-instance"_s, GPUFeatureName::IndirectFirstInstance },
        { "rg11b10ufloat-renderable"_s, GPUFeatureName::Rg11b10ufloatRenderable },
        { "shader-f16"_s, GPUFeatureName::ShaderF16 },
        { "texture-compression-astc"_s, GPUFeatureName::TextureCompressionAstc },
        { "texture-compression-astc-sliced-3d"_s, GPUFeatureName::TextureCompressionAstcSliced3d },
        { "texture-compression-bc"_s, GPUFeatureName::TextureCompressionBc },
        { "texture-compression-bc-sliced-3d"_s, GPUFeatureName::TextureCompressionBcSliced3d },
        { "texture-compression-etc2"_s, GPUFeatureName::TextureCompressionEtc2 },
        { "texture-formats-tier1"_s, GPUFeatureName::TextureFormatsTier1 },
        { "timestamp-query"_s, GPUFeatureName::TimestampQuery },
    }) };
    if (auto* enumerationValue = enumerationMapping.tryGet(stringValue); enumerationValue) [[likely]]
        return *enumerationValue;

    RELEASE_ASSERT_NOT_REACHED();
}

static bool isSubset(const Vector<GPUFeatureName>& expectedSubset, const Vector<String>& expectedSuperset)
{
    HashSet<uint32_t, DefaultHash<uint32_t>, WTF::UnsignedWithZeroKeyHashTraits<uint32_t>> expectedSupersetHashSet;
    for (auto& featureName : expectedSuperset)
        expectedSupersetHashSet.add(static_cast<uint32_t>(convertFeatureNameToEnum(featureName)));

    for (auto& featureName : expectedSubset) {
        if (!expectedSupersetHashSet.contains(static_cast<uint32_t>(featureName)))
            return false;
    }

    return true;
}
#endif // !PLATFORM(DRIFTSTACK)

#if PLATFORM(DRIFTSTACK)
// Inverse of convertFeatureNameToEnum, using the SAME canonical spec strings — the requiredFeatures
// arrive as GPUFeatureName enums but the shared archetype filter (GPUSupportedFeatures::
// isFeatureFilteredOutForCurrentArchetype) keys on the spec string the adapter.features list
// exposes, so we map enum -> spec string here. Only the names the driftstack filter inspects need
// to be precise; every other case returns its spec string for completeness (no drift).
static String featureNameToCanonicalString(GPUFeatureName featureName)
{
    switch (featureName) {
    case GPUFeatureName::Bgra8unormStorage: return "bgra8unorm-storage"_s;
    case GPUFeatureName::ClipDistances: return "clip-distances"_s;
    case GPUFeatureName::CoreFeaturesAndLimits: return "core-features-and-limits"_s;
    case GPUFeatureName::DepthClipControl: return "depth-clip-control"_s;
    case GPUFeatureName::Depth32floatStencil8: return "depth32float-stencil8"_s;
    case GPUFeatureName::DualSourceBlending: return "dual-source-blending"_s;
    case GPUFeatureName::Float16Renderable: return "float16-renderable"_s;
    case GPUFeatureName::Float32Blendable: return "float32-blendable"_s;
    case GPUFeatureName::Float32Filterable: return "float32-filterable"_s;
    case GPUFeatureName::Float32Renderable: return "float32-renderable"_s;
    case GPUFeatureName::IndirectFirstInstance: return "indirect-first-instance"_s;
    case GPUFeatureName::Rg11b10ufloatRenderable: return "rg11b10ufloat-renderable"_s;
    case GPUFeatureName::ShaderF16: return "shader-f16"_s;
    case GPUFeatureName::TextureCompressionAstc: return "texture-compression-astc"_s;
    case GPUFeatureName::TextureCompressionAstcSliced3d: return "texture-compression-astc-sliced-3d"_s;
    case GPUFeatureName::TextureCompressionBc: return "texture-compression-bc"_s;
    case GPUFeatureName::TextureCompressionBcSliced3d: return "texture-compression-bc-sliced-3d"_s;
    case GPUFeatureName::TextureCompressionEtc2: return "texture-compression-etc2"_s;
    case GPUFeatureName::TextureFormatsTier1: return "texture-formats-tier1"_s;
    case GPUFeatureName::TimestampQuery: return "timestamp-query"_s;
    }
    return emptyString();
}

// Returns the driftstack-PINNED value of the named limit — the EXACT value adapter.limits exposes
// (m_limits routes through GPUSupportedLimits, which caps maxBufferSize/binding sizes to
// driftstackWebGPUBufferCap and pins maxInterStageShaderVariables=124). std::nullopt = a name not
// recognised as a limit (left to the backing, which surfaces an OperationError). `betterIsLower`
// out-param distinguishes the spec's min-type limits (request LOWER than supported = unsupported)
// from the common max-type limits (request HIGHER than supported = unsupported).
static std::optional<uint64_t> driftstackPinnedLimit(const GPUSupportedLimits& limits, const String& name, bool& betterIsLower)
{
    betterIsLower = false;
    if (name == "maxTextureDimension1D"_s) return limits.maxTextureDimension1D();
    if (name == "maxTextureDimension2D"_s) return limits.maxTextureDimension2D();
    if (name == "maxTextureDimension3D"_s) return limits.maxTextureDimension3D();
    if (name == "maxTextureArrayLayers"_s) return limits.maxTextureArrayLayers();
    if (name == "maxBindGroups"_s) return limits.maxBindGroups();
    if (name == "maxBindGroupsPlusVertexBuffers"_s) return limits.maxBindGroupsPlusVertexBuffers();
    if (name == "maxBindingsPerBindGroup"_s) return limits.maxBindingsPerBindGroup();
    if (name == "maxDynamicUniformBuffersPerPipelineLayout"_s) return limits.maxDynamicUniformBuffersPerPipelineLayout();
    if (name == "maxDynamicStorageBuffersPerPipelineLayout"_s) return limits.maxDynamicStorageBuffersPerPipelineLayout();
    if (name == "maxSampledTexturesPerShaderStage"_s) return limits.maxSampledTexturesPerShaderStage();
    if (name == "maxSamplersPerShaderStage"_s) return limits.maxSamplersPerShaderStage();
    if (name == "maxStorageBuffersPerShaderStage"_s) return limits.maxStorageBuffersPerShaderStage();
    if (name == "maxStorageTexturesPerShaderStage"_s) return limits.maxStorageTexturesPerShaderStage();
    if (name == "maxUniformBuffersPerShaderStage"_s) return limits.maxUniformBuffersPerShaderStage();
    if (name == "maxUniformBufferBindingSize"_s) return limits.maxUniformBufferBindingSize();
    if (name == "maxStorageBufferBindingSize"_s) return limits.maxStorageBufferBindingSize();
    if (name == "minUniformBufferOffsetAlignment"_s) { betterIsLower = true; return limits.minUniformBufferOffsetAlignment(); }
    if (name == "minStorageBufferOffsetAlignment"_s) { betterIsLower = true; return limits.minStorageBufferOffsetAlignment(); }
    if (name == "maxVertexBuffers"_s) return limits.maxVertexBuffers();
    if (name == "maxBufferSize"_s) return limits.maxBufferSize();
    if (name == "maxVertexAttributes"_s) return limits.maxVertexAttributes();
    if (name == "maxVertexBufferArrayStride"_s) return limits.maxVertexBufferArrayStride();
    if (name == "maxInterStageShaderVariables"_s) return limits.maxInterStageShaderVariables();
    if (name == "maxInterStageShaderComponents"_s) return limits.maxInterStageShaderComponents();
    if (name == "maxColorAttachments"_s) return limits.maxColorAttachments();
    if (name == "maxColorAttachmentBytesPerSample"_s) return limits.maxColorAttachmentBytesPerSample();
    if (name == "maxComputeWorkgroupStorageSize"_s) return limits.maxComputeWorkgroupStorageSize();
    if (name == "maxComputeInvocationsPerWorkgroup"_s) return limits.maxComputeInvocationsPerWorkgroup();
    if (name == "maxComputeWorkgroupSizeX"_s) return limits.maxComputeWorkgroupSizeX();
    if (name == "maxComputeWorkgroupSizeY"_s) return limits.maxComputeWorkgroupSizeY();
    if (name == "maxComputeWorkgroupSizeZ"_s) return limits.maxComputeWorkgroupSizeZ();
    if (name == "maxComputeWorkgroupsPerDimension"_s) return limits.maxComputeWorkgroupsPerDimension();
    return std::nullopt;
}
#endif

void GPUAdapter::requestDevice(ScriptExecutionContext& scriptExecutionContext, const std::optional<GPUDeviceDescriptor>& deviceDescriptor, RequestDevicePromise&& promise)
{
#if PLATFORM(DRIFTSTACK)
    // ASYMMETRY CLOSURE (accessor-vs-list audit round2): validate requiredFeatures + requiredLimits
    // against the SAME driftstack-filtered/pinned values adapter.features + adapter.limits EXPOSE —
    // never the raw Mac backing (m_backing->features()/m_capabilities). Validating against the raw
    // backing let a page request a feature the fork hides (clip-distances) or a limit above the
    // advertised cap and have it RESOLVE on the Mac's real headroom — a trivial fork tell. Matches
    // the captured iPhone 17 / Safari 26.5: clip-distances -> reject(TypeError), >cap buffer ->
    // reject, advertised ISV(124, Mac backing=31) -> resolve.
    if (deviceDescriptor) {
        // requiredFeatures: reject (TypeError) any feature the shared filter drops from adapter.features.
        for (auto& feature : deviceDescriptor->requiredFeatures) {
            if (GPUSupportedFeatures::isFeatureFilteredOutForCurrentArchetype(featureNameToCanonicalString(feature))) {
                promise.reject(Exception(ExceptionCode::TypeError));
                return;
            }
        }
        // requiredLimits: reject (OperationError) any request that exceeds the PINNED limit value.
        // Validate against m_limits (== adapter.limits), NOT m_capabilities — the advertised 124 ISV
        // must RESOLVE even though the Mac backing reports 31 (do NOT over-reject).
        for (auto& requiredLimit : deviceDescriptor->requiredLimits) {
            bool betterIsLower = false;
            auto pinned = driftstackPinnedLimit(m_limits.get(), requiredLimit.key, betterIsLower);
            if (!pinned)
                continue; // unknown limit name: let the backing surface the OperationError.
            const bool unsupported = betterIsLower ? (requiredLimit.value < *pinned) : (requiredLimit.value > *pinned);
            if (unsupported) {
                promise.reject(Exception(ExceptionCode::OperationError));
                return;
            }
        }
    }
#else
    auto& existingFeatures = m_backing->features().features();
    if (deviceDescriptor && !isSubset(deviceDescriptor->requiredFeatures, existingFeatures)) {
        promise.reject(Exception(ExceptionCode::TypeError));
        return;
    }
#endif

    m_backing->requestDevice(convertToBacking(deviceDescriptor), [protectedThis = protect(*this), deviceDescriptor, promise = WTF::move(promise), scriptExecutionContextRef = protect(scriptExecutionContext)](RefPtr<WebGPU::Device>&& device) mutable {
        if (!device.get())
            promise.reject(Exception(ExceptionCode::OperationError));
        else {
            auto queueLabel = deviceDescriptor->defaultQueue.label;
            Ref<GPUDevice> gpuDevice = GPUDevice::create(scriptExecutionContextRef.ptr(), device.releaseNonNull(), deviceDescriptor ? WTF::move(queueLabel) : ""_s, GPUAdapterInfo::create(protectedThis->name()));
            gpuDevice->suspendIfNeeded();
            promise.resolve(WTF::move(gpuDevice));
        }
    });
}

Ref<GPUAdapterInfo> GPUAdapter::info()
{
    return m_info;
}

}
