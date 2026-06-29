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

#include "config.h"
#include "platform/driftstack/DriftstackDeviceOrientationClient.h"

#if PLATFORM(DRIFTSTACK) && ENABLE(DEVICE_ORIENTATION)

#include "DeviceOrientationController.h"
#include "DeviceOrientationData.h"
#include "platform/driftstack/DriftstackSensorSession.h"
#include <cmath>
#include <numbers>
#include <wtf/TZoneMallocInlines.h>

namespace WebCore {

WTF_MAKE_TZONE_ALLOCATED_IMPL(DriftstackDeviceOrientationClient);

// Same interval as DeviceMotion (60 Hz); deviceorientation events fire at the
// same cadence on a real iPhone.
static constexpr double kDriftstackOrientationInterval = static_cast<double>(static_cast<float>(1.0 / 60.0));

DriftstackDeviceOrientationClient::DriftstackDeviceOrientationClient()
    : m_timer(*this, &DriftstackDeviceOrientationClient::timerFired)
{
}

DriftstackDeviceOrientationClient::~DriftstackDeviceOrientationClient() = default;

void DriftstackDeviceOrientationClient::setController(DeviceOrientationController* controller)
{
    m_controller = controller;
}

DeviceOrientationData* DriftstackDeviceOrientationClient::lastOrientation() const
{
    return m_currentOrientation.get();
}

void DriftstackDeviceOrientationClient::deviceOrientationControllerDestroyed()
{
    m_timer.stop();
    m_controller = nullptr;
}

void DriftstackDeviceOrientationClient::startUpdating()
{
    if (m_updating)
        return;
    m_updating = true;

    if (!m_sessionInitialized)
        initializeSessionModel();

    timerFired();
    m_timer.startRepeating(Seconds { kDriftstackOrientationInterval });
}

void DriftstackDeviceOrientationClient::stopUpdating()
{
    m_updating = false;
    m_timer.stop();
}

double DriftstackDeviceOrientationClient::gaussian(WeakRandom& random)
{
    if (m_hasGaussianSpare) {
        m_hasGaussianSpare = false;
        return m_gaussianSpare;
    }
    double u1 = random.get();
    double u2 = random.get();
    if (u1 < 1e-12)
        u1 = 1e-12;
    double mag = std::sqrt(-2.0 * std::log(u1));
    m_gaussianSpare = mag * std::sin(2.0 * std::numbers::pi * u2);
    m_hasGaussianSpare = true;
    return mag * std::cos(2.0 * std::numbers::pi * u2);
}

void DriftstackDeviceOrientationClient::initializeSessionModel()
{
    m_random.setSeed(driftstackSensorSessionSeed() ^ 0x6f7269656eu /* "orien" low bits */);

    // DM2 POSE: base pose varies per session (captured attitudes ranged widely,
    // e.g. alpha ~0.08, beta ~0.73, gamma ~-11.71, compass 59.7/348.7/187.5/183.8).
    // Draw within plausible stationary-hold ranges.
    m_baseAlpha = 360.0 * m_random.get();          // [0, 360)
    m_baseBeta = -25.0 + 50.0 * m_random.get();    // [-25, 25] (held roughly flat)
    m_baseGamma = -25.0 + 50.0 * m_random.get();   // [-25, 25]
    m_compassHeading = 360.0 * m_random.get();     // [0, 360), constant after sample 0.

    // DM6 MICRO-MOTION: pose is a slow OU random walk (not perfectly still).
    // ACF in [0.96, 0.99]; head->tail drift 0.01-0.04 deg over ~4s (240 samples).
    m_driftDecay = 0.96 + 0.03 * m_random.get();   // [0.96, 0.99]
    // Per-sample pose observation noise: std ~0.003-0.015 deg.
    m_poseNoiseStd = 0.003 + 0.012 * m_random.get();
    // OU innovation std chosen so the stationary drift std stays small and the
    // head->tail walk over 240 samples lands in ~0.01-0.04 deg.
    m_driftStepStd = 0.0008 + 0.0016 * m_random.get();

    m_driftAlpha = 0;
    m_driftBeta = 0;
    m_driftGamma = 0;
    m_sampleCount = 0;
    m_sessionInitialized = true;
}

void DriftstackDeviceOrientationClient::timerFired()
{
    if (!m_updating || !m_controller)
        return;

    // OU mean-reverting random walk on each pose component (bounded drift).
    m_driftAlpha = m_driftDecay * m_driftAlpha + m_driftStepStd * gaussian(m_random);
    m_driftBeta = m_driftDecay * m_driftBeta + m_driftStepStd * gaussian(m_random);
    m_driftGamma = m_driftDecay * m_driftGamma + m_driftStepStd * gaussian(m_random);

    double alpha = m_baseAlpha + m_driftAlpha + m_poseNoiseStd * gaussian(m_random);
    double beta = m_baseBeta + m_driftBeta + m_poseNoiseStd * gaussian(m_random);
    double gamma = m_baseGamma + m_driftGamma + m_poseNoiseStd * gaussian(m_random);

    // Wrap alpha into [0, 360).
    alpha = std::fmod(alpha, 360.0);
    if (alpha < 0)
        alpha += 360.0;

    // DM5: compassAccuracy granted = 89 steady; event 0 is the -1 uncalibrated
    // transient. compassHeading is per-session-constant after sample 0.
    double compassAccuracy = (m_sampleCount == 0) ? kCompassAccuracyUncalibrated : kCompassAccuracyGranted;

    // absolute = null on the DRIFTSTACK shape: DeviceOrientationData carries
    // compassHeading/compassAccuracy and never exposes `absolute`.
    m_currentOrientation = DeviceOrientationData::create(alpha, beta, gamma, m_compassHeading, compassAccuracy);

    ++m_sampleCount;
    m_controller->didChangeDeviceOrientation(m_currentOrientation.get());
}

} // namespace WebCore

#endif // PLATFORM(DRIFTSTACK) && ENABLE(DEVICE_ORIENTATION)
