/*
 * Copyright (c) 2021-2023 Apple Inc. All rights reserved.
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

#import "config.h"
#import "Adapter.h"

#import "APIConversions.h"
#import "Device.h"
#import "Instance.h"
#import <algorithm>
#import <ranges>
#import <wtf/StdLibExtras.h>
#import <wtf/TZoneMallocInlines.h>

#if PLATFORM(DRIFTSTACK)
#import <cstdlib>
#import <string_view>
#endif

namespace WebGPU {

WTF_MAKE_TZONE_ALLOCATED_IMPL(Adapter);

#if PLATFORM(DRIFTSTACK)
// DEFENSE-IN-DEPTH mirror of the WebCore requestDevice validation (GPUAdapter.cpp). The WebCore
// path runs in WebContent and already rejects against the driftstack-filtered/pinned adapter
// values BEFORE this IPC fires, so this gate is the redundant second wall: it caps the reference
// limits + filters the reference features to the SAME advertised values, so a requiredLimit above
// the pinned buffer cap or a filtered-out requiredFeature is rejected here too even if some caller
// reaches the GPU process directly. Kept byte-coherent with GPUSupportedLimits.cpp
// (driftstackWebGPUBufferCap = 644245092 on 26.0, else 1GiB; ISV pinned to 124) and
// GPUSupportedFeatures.cpp (clip-distances always; BC family + float32-filterable on older-GPU
// tier; texture-formats-tier1 on 26.0).
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

static bool driftstackArchetypeIsOlderGpuTier()
{
    const char* archetype = getenv("DRIFTSTACK_ARCHETYPE");
    if (!archetype)
        return false;
    std::string_view a(archetype);
    if (a.find("iphone13") != std::string_view::npos)
        return true;
    if (a.find("iphone14") != std::string_view::npos)
        return true;
    if (a.find("iphone15pro") != std::string_view::npos)
        return false;
    if (a.find("iphone15") != std::string_view::npos)
        return true;
    return false;
}

static bool driftstackArchetypeIsSafari26_0()
{
    const char* a = getenv("DRIFTSTACK_ARCHETYPE");
    if (!a || !a[0])
        return false;
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

// Returns a copy of the reference limits capped to the advertised (pinned) driftstack values, so
// anyLimitIsBetterThan rejects an over-cap requiredLimit but ACCEPTS the advertised ISV (124).
static WGPULimits driftstackPinnedReferenceLimits(const WGPULimits& raw)
{
    WGPULimits pinned = raw;
    const uint64_t cap = driftstackWebGPUBufferCap();
    pinned.maxBufferSize = std::min<uint64_t>(pinned.maxBufferSize, cap);
    pinned.maxUniformBufferBindingSize = std::min<uint64_t>(pinned.maxUniformBufferBindingSize, cap);
    pinned.maxStorageBufferBindingSize = std::min<uint64_t>(pinned.maxStorageBufferBindingSize, cap);
    pinned.maxInterStageShaderVariables = 124; // pinned advertised value (raw Mac backing = 31)
    return pinned;
}

static bool driftstackFeatureIsFilteredOut(WGPUFeatureName feature)
{
    if (feature == WGPUFeatureName_ClipDistances)
        return true;
    if (driftstackArchetypeIsOlderGpuTier() && (feature == WGPUFeatureName_TextureCompressionBC
        || feature == WGPUFeatureName_TextureCompressionBCSliced3D
        || feature == WGPUFeatureName_Float32Filterable))
        return true;
    if (driftstackArchetypeIsSafari26_0() && feature == WGPUFeatureName_TextureFormatsTier1)
        return true;
    return false;
}
#endif

Adapter::Adapter(id<MTLDevice> device, Instance& instance, bool xrCompatible, HardwareCapabilities&& capabilities)
    : m_device(device)
    , m_instance(&instance)
    , m_capabilities(WTF::move(capabilities))
    , m_xrCompatible(xrCompatible)
{
}

Adapter::Adapter(Instance& instance)
    : m_instance(&instance)
{
}

Adapter::~Adapter() = default;

size_t Adapter::enumerateFeatures(WGPUFeatureName* features)
{
    // The API contract for this requires that sufficient space has already been allocated for the output.
    // This requires the caller calling us twice: once to get the amount of space to allocate, and once to fill the space.
    if (features)
        std::ranges::copy(m_capabilities.features, features);
    return m_capabilities.features.size();
}

bool Adapter::getLimits(WGPUSupportedLimits& limits)
{
    limits.limits = m_capabilities.limits;
    return true;
}

void Adapter::getProperties(WGPUAdapterProperties& properties)
{
    // FIXME: What should the vendorID and deviceID be?
    properties.vendorID = 0;
    properties.deviceID = 0;
    properties.name = m_device.name.UTF8String;
    properties.driverDescription = "";
    properties.adapterType = m_device.hasUnifiedMemory ? WGPUAdapterType_IntegratedGPU : WGPUAdapterType_DiscreteGPU;
    properties.backendType = WGPUBackendType_Metal;
}

bool Adapter::hasFeature(WGPUFeatureName feature)
{
    return m_capabilities.features.contains(feature);
}

void Adapter::requestDevice(const WGPUDeviceDescriptor& descriptor, CompletionHandler<void(WGPURequestDeviceStatus, Ref<Device>&&, String&&)>&& callback)
{
    if (m_deviceRequested) {
        callback(WGPURequestDeviceStatus_Error, Device::createInvalid(*this), "Adapter can only request one device"_s);
        makeInvalid();
        return;
    }

    WGPULimits limits { };

#if PLATFORM(DRIFTSTACK)
    // Defense-in-depth: validate against the PINNED reference (the advertised adapter.limits), not
    // the raw Mac caps — so an over-cap requiredLimit is rejected and the advertised ISV (124, raw
    // backing 31) is accepted. WebCore already enforces this before the IPC; this is the redundant wall.
    const WGPULimits referenceLimits = driftstackPinnedReferenceLimits(m_capabilities.limits);
#else
    const WGPULimits& referenceLimits = m_capabilities.limits;
#endif

    if (descriptor.requiredLimits) {

        if (!WebGPU::isValid(descriptor.requiredLimits->limits)) {
            callback(WGPURequestDeviceStatus_Error, Device::createInvalid(*this), "Device does not support requested limits"_s);
            return;
        }

        if (anyLimitIsBetterThan(descriptor.requiredLimits->limits, referenceLimits)) {
            callback(WGPURequestDeviceStatus_Error, Device::createInvalid(*this), "Device does not support requested limits"_s);
            return;
        }

        limits = descriptor.requiredLimits->limits;
    } else
        limits = defaultLimits();

    Vector<WGPUFeatureName> features(descriptor.requiredFeaturesSpan());
#if PLATFORM(DRIFTSTACK)
    // Reject (mirror of GPUSupportedFeatures filter) any requiredFeature the fork hides from
    // adapter.features for this archetype, regardless of raw Mac support.
    for (auto feature : features) {
        if (driftstackFeatureIsFilteredOut(feature)) {
            callback(WGPURequestDeviceStatus_Error, Device::createInvalid(*this), "Device does not support requested features"_s);
            return;
        }
    }
#endif
    if (includesUnsupportedFeatures(features, m_capabilities.features)) {
        callback(WGPURequestDeviceStatus_Error, Device::createInvalid(*this), "Device does not support requested features"_s);
        return;
    }

    HardwareCapabilities capabilities {
        limits,
        WTF::move(features),
        m_capabilities.baseCapabilities,
    };

    auto label = fromAPI(descriptor.label);
    m_deviceRequested = true;
    // FIXME: this should be asynchronous - https://bugs.webkit.org/show_bug.cgi?id=233621
    callback(WGPURequestDeviceStatus_Success, Device::create(this->m_device, WTF::move(label), WTF::move(capabilities), *this), { });
}

bool Adapter::isXRCompatible() const
{
    return m_xrCompatible;
}

} // namespace WebGPU

#pragma mark WGPU Stubs

void NODELETE wgpuAdapterReference(WGPUAdapter adapter)
{
    WebGPU::fromAPI(adapter).ref();
}

void wgpuAdapterRelease(WGPUAdapter adapter)
{
    WebGPU::fromAPI(adapter).deref();
}

size_t wgpuAdapterEnumerateFeatures(WGPUAdapter adapter, WGPUFeatureName* features)
{
    return protect(WebGPU::fromAPI(adapter))->enumerateFeatures(features);
}

WGPUBool wgpuAdapterGetLimits(WGPUAdapter adapter, WGPUSupportedLimits* limits)
{
    return WebGPU::fromAPI(adapter).getLimits(*limits);
}

void wgpuAdapterGetProperties(WGPUAdapter adapter, WGPUAdapterProperties* properties)
{
    protect(WebGPU::fromAPI(adapter))->getProperties(*properties);
}

WGPUBool wgpuAdapterHasFeature(WGPUAdapter adapter, WGPUFeatureName feature)
{
    return protect(WebGPU::fromAPI(adapter))->hasFeature(feature);
}

void wgpuAdapterRequestDevice(WGPUAdapter adapter, const WGPUDeviceDescriptor* descriptor, WGPURequestDeviceCallback callback, void* userdata)
{
    protect(WebGPU::fromAPI(adapter))->requestDevice(*descriptor, [callback, userdata](WGPURequestDeviceStatus status, Ref<WebGPU::Device>&& device, String&& message) {
        callback(status, WebGPU::releaseToAPI(WTF::move(device)), message.utf8().data(), userdata);
    });
}

void wgpuAdapterRequestDeviceWithBlock(WGPUAdapter adapter, WGPUDeviceDescriptor const * descriptor, WGPURequestDeviceBlockCallback callback)
{
    protect(WebGPU::fromAPI(adapter))->requestDevice(*descriptor, [callback = WebGPU::fromAPI(WTF::move(callback))](WGPURequestDeviceStatus status, Ref<WebGPU::Device>&& device, String&& message) {
        callback(status, WebGPU::releaseToAPI(WTF::move(device)), message.utf8().data());
    });
}

WGPUBool wgpuAdapterXRCompatible(WGPUAdapter adapter)
{
    return WebGPU::fromAPI(adapter).isXRCompatible();
}
