/*
 * Copyright (C) 2026 Driftstack. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#pragma once

#if PLATFORM(DRIFTSTACK) && ENABLE(DEVICE_ORIENTATION)

#include "DeviceMotionClient.h"
#include "Timer.h"
#include <wtf/CheckedRef.h>
#include <wtf/RefPtr.h>
#include <wtf/TZoneMalloc.h>
#include <wtf/WeakRandom.h>

namespace WebCore {

class DeviceMotionController;
class DeviceMotionData;
class Page;

// Installs synthetic DeviceMotion + DeviceOrientation clients on the Page so the
// GRANTED-state sensor surface matches a real iPhone (which always has motion
// sensors; a Mac fleet host has none → a granted page would otherwise see 0 events
// because DeviceMotionController::from(page) is null, itself a tell).
//
// Mechanism (mirrors upstream provideGeolocationTo and the DeviceOrientationClientMock
// embedder-owns-client pattern): an owning Supplement<Page> holds the two synthetic
// clients; for each, a real DeviceMotion/DeviceOrientationController is provided as
// its own Page supplement under the controller's name so
// DeviceMotion/OrientationController::from(page) resolves (the non-IOS_FAMILY /
// Page-supplement path LocalDOMWindow uses). The controller ctor calls
// client.setController(this); the grant->listen chain
// (LocalDOMWindow::startListeningFor...IfNecessary -> DeviceController::
// addDeviceEventListener -> client.startUpdating) then starts the 60 Hz stream.
//
// Gated by DRIFTSTACK_DEVICEMOTION_GRANTED at the WebCore Page ctor call site; this
// function unconditionally installs (the caller owns the gate). Idempotent-safe: the
// caller must only invoke it once per Page.
WEBCORE_EXPORT void driftstackProvideSyntheticSensorsTo(Page&);

// Driftstack-only synthetic DeviceMotion source. A real iPhone always has a
// motion sensor; a Mac fleet host does not. When the page is granted
// DeviceOrientation/Motion permission (DRIFTSTACK_DEVICEMOTION_GRANTED=1) this
// client feeds the standard DeviceMotionController a 60 Hz synthetic stream that
// is distributionally indistinguishable from a stationary iPhone (per the A1
// real-device value model, DEVICEMOTION-SYNTH-PLAN.md "VALUE MODEL LOCKED"):
//
//  - interval = Float32(1/60) = 0.01666666753590107 (the exact iOS double cast)
//  - per-session-fixed resting attitude, |gravity| normalized to ~9.80
//  - accelerationIncludingGravity = baseGravity + per-axis correlated noise
//  - acceleration = accelerationIncludingGravity - gravityVec (ONE shared draw)
//  - rotationRate = small per-axis noise
//
// Timer-driven (WebCore::Timer on the main thread), NOT CoreMotion: the host has
// no sensors and CoreMotion on macOS would either be empty or expose the host.
class DriftstackDeviceMotionClient final : public DeviceMotionClient, public CanMakeCheckedPtr<DriftstackDeviceMotionClient> {
    WTF_MAKE_TZONE_ALLOCATED(DriftstackDeviceMotionClient);
    WTF_OVERRIDE_DELETE_FOR_CHECKED_PTR(DriftstackDeviceMotionClient);
public:
    DriftstackDeviceMotionClient();
    ~DriftstackDeviceMotionClient() override;

    // DeviceMotionClient.
    void setController(DeviceMotionController*) override;
    DeviceMotionData* lastMotion() const override;
    void deviceMotionControllerDestroyed() override;

    // DeviceClient.
    void startUpdating() override;
    void stopUpdating() override;

    // CanMakeCheckedPtr.
    uint32_t checkedPtrCount() const final { return CanMakeCheckedPtr::checkedPtrCount(); }
    uint32_t checkedPtrCountWithoutThreadCheck() const final { return CanMakeCheckedPtr::checkedPtrCountWithoutThreadCheck(); }
    void incrementCheckedPtrCount() const final { CanMakeCheckedPtr::incrementCheckedPtrCount(); }
    void decrementCheckedPtrCount() const final { CanMakeCheckedPtr::decrementCheckedPtrCount(); }
    void setDidBeginCheckedPtrDeletion() final { CanMakeCheckedPtr::setDidBeginCheckedPtrDeletion(); }

private:
    void timerFired();
    void initializeSessionModel();
    double gaussian(WeakRandom&); // standard-normal draw via Box-Muller.

    DeviceMotionController* m_controller { nullptr };
    Timer m_timer;
    RefPtr<DeviceMotionData> m_currentDeviceMotionData;
    bool m_updating { false };

    // Per-session deterministic RNG (seeded once in initializeSessionModel).
    WeakRandom m_random;
    bool m_sessionInitialized { false };

    // Per-session-fixed resting attitude (the constant component of the gravity
    // vector). |gravity| is normalized to ~9.80. Drawn once per session.
    double m_gravityX { 0 };
    double m_gravityY { 0 };
    double m_gravityZ { 0 };

    // Per-session noise standard deviations (drawn once from the captured range),
    // so two sessions present different (but plausible) noise envelopes.
    double m_accelNoiseStdX { 0 };
    double m_accelNoiseStdY { 0 };
    double m_accelNoiseStdZ { 0 };
    double m_rotationNoiseStdAlpha { 0 };
    double m_rotationNoiseStdBeta { 0 };
    double m_rotationNoiseStdGamma { 0 };

    // Lag-1 sample correlation: keep the previous noise sample per axis so the
    // stream is non-white (mild AR(1)) rather than i.i.d. Gaussian.
    double m_prevAccelNoiseX { 0 };
    double m_prevAccelNoiseY { 0 };
    double m_prevAccelNoiseZ { 0 };

    bool m_hasGaussianSpare { false };
    double m_gaussianSpare { 0 };
};

} // namespace WebCore

#endif // PLATFORM(DRIFTSTACK) && ENABLE(DEVICE_ORIENTATION)
