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

#include "DeviceOrientationClient.h"
#include "Timer.h"
#include <wtf/CheckedRef.h>
#include <wtf/RefPtr.h>
#include <wtf/TZoneMalloc.h>
#include <wtf/WeakRandom.h>

namespace WebCore {

class DeviceOrientationController;
class DeviceOrientationData;
class Page;

// (The single combined entry point that installs BOTH synthetic sensor clients is
// driftstackProvideSyntheticSensorsTo(Page&) in DriftstackDeviceMotionClient.h.)

// Driftstack-only synthetic DeviceOrientation source (see
// DriftstackDeviceMotionClient.h for the rationale). When granted, feeds the
// standard DeviceOrientationController a 60 Hz synthetic pose stream matching a
// stationary iPhone (DEVICEMOTION-SYNTH-PLAN.md "VALUE MODEL LOCKED"):
//
//  - per-session-fixed base pose {alpha, beta, gamma}, varies per session (DM2)
//  - bounded slow OU/random-walk DRIFT on the pose (lag-1 ACF 0.96-0.99,
//    0.01-0.04 deg / 4s) + per-sample pose noise std ~0.003-0.015 deg (DM6:
//    NOT perfectly still — a static constant pose is itself the tell)
//  - compassHeading per-session-constant after sample 0
//  - compassAccuracy = 89 steady; event 0 is the -1 uncalibrated transient (DM5)
//  - absolute = null (iOS shape; the DRIFTSTACK DeviceOrientationData carve-out
//    carries compassHeading/compassAccuracy, never `absolute`)
class DriftstackDeviceOrientationClient final : public DeviceOrientationClient, public CanMakeCheckedPtr<DriftstackDeviceOrientationClient> {
    WTF_MAKE_TZONE_ALLOCATED(DriftstackDeviceOrientationClient);
    WTF_OVERRIDE_DELETE_FOR_CHECKED_PTR(DriftstackDeviceOrientationClient);
public:
    DriftstackDeviceOrientationClient();
    ~DriftstackDeviceOrientationClient() override;

    // DeviceOrientationClient.
    void setController(DeviceOrientationController*) override;
    DeviceOrientationData* lastOrientation() const override;
    void deviceOrientationControllerDestroyed() override;

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

    DeviceOrientationController* m_controller { nullptr };
    Timer m_timer;
    RefPtr<DeviceOrientationData> m_currentOrientation;
    bool m_updating { false };

    WeakRandom m_random;
    bool m_sessionInitialized { false };
    uint64_t m_sampleCount { 0 };

    // Per-session-fixed base pose (degrees) and a slow OU random walk around it.
    double m_baseAlpha { 0 };
    double m_baseBeta { 0 };
    double m_baseGamma { 0 };
    double m_driftAlpha { 0 };
    double m_driftBeta { 0 };
    double m_driftGamma { 0 };

    // Per-sample noise std (deg) + OU parameters, drawn per session.
    double m_poseNoiseStd { 0 };
    double m_driftStepStd { 0 };  // per-sample innovation std of the OU drift.
    double m_driftDecay { 0 };    // OU mean-reversion (lag-1 ACF), in [0.96, 0.99].

    double m_compassHeading { 0 };  // per-session constant after sample 0.
    static constexpr double kCompassAccuracyGranted = 89.0;
    static constexpr double kCompassAccuracyUncalibrated = -1.0; // sample-0 transient.

    bool m_hasGaussianSpare { false };
    double m_gaussianSpare { 0 };
};

} // namespace WebCore

#endif // PLATFORM(DRIFTSTACK) && ENABLE(DEVICE_ORIENTATION)
