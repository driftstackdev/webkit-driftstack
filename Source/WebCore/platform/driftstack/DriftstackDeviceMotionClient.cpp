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
#include "platform/driftstack/DriftstackDeviceMotionClient.h"

#if PLATFORM(DRIFTSTACK) && ENABLE(DEVICE_ORIENTATION)

#include "DeviceMotionController.h"
#include "DeviceMotionData.h"
#include "DeviceOrientationController.h"
#include "platform/driftstack/DriftstackDeviceOrientationClient.h"
#include "platform/driftstack/DriftstackSensorSession.h"
#include "Page.h"
#include "Supplementable.h"
#include <cmath>
#include <memory>
#include <numbers>
#include <wtf/TZoneMallocInlines.h>

namespace WebCore {

WTF_MAKE_TZONE_ALLOCATED_IMPL(DriftstackDeviceMotionClient);

// The interval JS observes via DeviceMotionEvent.interval. A real iPhone returns
// the double cast of the float (1.0f/60.0f) = 0.01666666753590107 (DM5 LOCKED).
// iOS computes this from WebCoreMotionManager kMotionUpdateInterval (a float);
// we reproduce the identical bit pattern by casting through float here.
static constexpr double kDriftstackMotionInterval = static_cast<double>(static_cast<float>(1.0 / 60.0));

DriftstackDeviceMotionClient::DriftstackDeviceMotionClient()
    : m_timer(*this, &DriftstackDeviceMotionClient::timerFired)
{
}

DriftstackDeviceMotionClient::~DriftstackDeviceMotionClient() = default;

void DriftstackDeviceMotionClient::setController(DeviceMotionController* controller)
{
    m_controller = controller;
}

DeviceMotionData* DriftstackDeviceMotionClient::lastMotion() const
{
    return m_currentDeviceMotionData.get();
}

void DriftstackDeviceMotionClient::deviceMotionControllerDestroyed()
{
    m_timer.stop();
    m_controller = nullptr;
}

void DriftstackDeviceMotionClient::startUpdating()
{
    if (m_updating)
        return;
    m_updating = true;

    if (!m_sessionInitialized)
        initializeSessionModel();

    // Emit a first sample immediately so listeners that subscribe and read the
    // last event get data without waiting a frame, then run at ~60 Hz.
    timerFired();
    m_timer.startRepeating(Seconds { kDriftstackMotionInterval });
}

void DriftstackDeviceMotionClient::stopUpdating()
{
    m_updating = false;
    m_timer.stop();
}

double DriftstackDeviceMotionClient::gaussian(WeakRandom& random)
{
    // Box-Muller, mean 0 / std 1. Cache the spare normal to halve get() calls.
    if (m_hasGaussianSpare) {
        m_hasGaussianSpare = false;
        return m_gaussianSpare;
    }
    double u1 = random.get();
    double u2 = random.get();
    // Avoid log(0): WeakRandom::get() is in [0,1); clamp the low tail.
    if (u1 < 1e-12)
        u1 = 1e-12;
    double mag = std::sqrt(-2.0 * std::log(u1));
    m_gaussianSpare = mag * std::sin(2.0 * std::numbers::pi * u2);
    m_hasGaussianSpare = true;
    return mag * std::cos(2.0 * std::numbers::pi * u2);
}

void DriftstackDeviceMotionClient::initializeSessionModel()
{
    m_random.setSeed(driftstackSensorSessionSeed() ^ 0x6d6f7469u /* "moti" */);

    // DM2 POSE / |gravity| INVARIANT: draw a plausible resting attitude, then
    // normalize the gravity vector magnitude to ~9.80 (captured 9.795-9.811).
    // The captured resting attitudes had small x/y and a dominant -z (screen-up,
    // roughly flat-ish), e.g. {-1.98, -0.13, -9.60}. Draw within that envelope.
    double gx = -3.0 + 6.0 * m_random.get();   // [-3.0, 3.0]
    double gy = -3.0 + 6.0 * m_random.get();   // [-3.0, 3.0]
    double gz = -9.81 + 1.6 * m_random.get();  // [-9.81, -8.21] (screen mostly up)
    double mag = std::sqrt(gx * gx + gy * gy + gz * gz);
    if (mag < 1e-6)
        mag = 1.0;
    double targetMag = 9.795 + 0.016 * m_random.get(); // [9.795, 9.811]
    double scale = targetMag / mag;
    m_gravityX = gx * scale;
    m_gravityY = gy * scale;
    m_gravityZ = gz * scale;

    // DM4 NOISE: per-axis std drawn per-session from the captured range
    // [0.011, 0.037]; non-white via lag-1 correlation applied in timerFired.
    auto drawStd = [&]() { return 0.011 + 0.026 * m_random.get(); };
    m_accelNoiseStdX = drawStd();
    m_accelNoiseStdY = drawStd();
    m_accelNoiseStdZ = drawStd();

    // rotationRate per-axis noise (deg/s); captured stationary stds ~0.16-0.28.
    auto drawRotStd = [&]() { return 0.15 + 0.15 * m_random.get(); };
    m_rotationNoiseStdAlpha = drawRotStd();
    m_rotationNoiseStdBeta = drawRotStd();
    m_rotationNoiseStdGamma = drawRotStd();

    m_prevAccelNoiseX = 0;
    m_prevAccelNoiseY = 0;
    m_prevAccelNoiseZ = 0;
    m_sessionInitialized = true;
}

void DriftstackDeviceMotionClient::timerFired()
{
    if (!m_updating || !m_controller)
        return;

    // DM4: mild lag-1 AR(1) so the stream is non-white. corr ~0.5 keeps the
    // marginal std close to the per-session draw while introducing serial
    // correlation (real CoreMotion noise is non-white with no fixed spectrum).
    constexpr double kCorr = 0.5;
    double innovationScale = std::sqrt(1.0 - kCorr * kCorr);

    double nx = kCorr * m_prevAccelNoiseX + innovationScale * gaussian(m_random) * m_accelNoiseStdX;
    double ny = kCorr * m_prevAccelNoiseY + innovationScale * gaussian(m_random) * m_accelNoiseStdY;
    double nz = kCorr * m_prevAccelNoiseZ + innovationScale * gaussian(m_random) * m_accelNoiseStdZ;
    m_prevAccelNoiseX = nx;
    m_prevAccelNoiseY = ny;
    m_prevAccelNoiseZ = nz;

    // DM3 CORRELATION: accelerationIncludingGravity = gravity + noise, and
    // acceleration = accelerationIncludingGravity - gravityVec derived from the
    // SAME noise draw (so corr(accel, accelIncludingGravity) -> ~1.0 and the
    // residual is the constant gravity vector). NOT two independent streams.
    double aigX = m_gravityX + nx;
    double aigY = m_gravityY + ny;
    double aigZ = m_gravityZ + nz;

    // acceleration (gravity removed): the leftover is the noise itself plus a
    // tiny constant residual (CoreMotion's gravity estimate is imperfect; the
    // captured residual std was 1e-5..2.5e-3). Here acceleration == noise, which
    // is acc-including-gravity minus the per-session-constant gravity vector.
    double aX = nx;
    double aY = ny;
    double aZ = nz;

    // rotationRate: small zero-mean per-axis noise (deg/s).
    double rAlpha = gaussian(m_random) * m_rotationNoiseStdAlpha;
    double rBeta = gaussian(m_random) * m_rotationNoiseStdBeta;
    double rGamma = gaussian(m_random) * m_rotationNoiseStdGamma;

    auto accelerationIncludingGravity = DeviceMotionData::Acceleration::create(aigX, aigY, aigZ);
    RefPtr<DeviceMotionData::Acceleration> acceleration = DeviceMotionData::Acceleration::create(aX, aY, aZ);
    RefPtr<DeviceMotionData::RotationRate> rotationRate = DeviceMotionData::RotationRate::create(rAlpha, rBeta, rGamma);

    m_currentDeviceMotionData = DeviceMotionData::create(WTF::move(acceleration), WTF::move(accelerationIncludingGravity), WTF::move(rotationRate), kDriftstackMotionInterval);
    m_controller->didChangeDeviceMotion(m_currentDeviceMotionData.get());
}

// Owning Page supplement that keeps the two synthetic sensor clients alive for the
// life of the Page. The controllers (which only weak-ref their client) are provided
// as their own Page supplements under their canonical names; this holder owns the
// clients. The clients' timers are stopped in their own destructors, and nothing
// dereferences a controller's weak-client during Page teardown (the only deref
// paths — DeviceController::getLastEvent/hasLastData — run from an active-listener
// timer, which is stopped via stopUpdating before teardown), so cross-supplement
// destruction order is benign. (Mirrors InternalSettingsWrapper, the canonical
// owning-Supplement<Page> with the from()/provideTo() idempotent pattern.)
class DriftstackSensorClientsHolder final : public Supplement<Page> {
    WTF_MAKE_TZONE_ALLOCATED_INLINE(DriftstackSensorClientsHolder);
public:
    DriftstackSensorClientsHolder(std::unique_ptr<DriftstackDeviceMotionClient>&& motion, std::unique_ptr<DriftstackDeviceOrientationClient>&& orientation)
        : m_motionClient(WTF::move(motion))
        , m_orientationClient(WTF::move(orientation))
    {
    }

    static ASCIILiteral supplementName() { return "DriftstackSensorClientsHolder"_s; }

private:
    std::unique_ptr<DriftstackDeviceMotionClient> m_motionClient;
    std::unique_ptr<DriftstackDeviceOrientationClient> m_orientationClient;
};

void driftstackProvideSyntheticSensorsTo(Page& page)
{
    // Already provided? Bail (idempotent guard; the caller should only call once).
    if (Supplement<Page>::from(&page, DriftstackSensorClientsHolder::supplementName()))
        return;

    auto motionClient = makeUnique<DriftstackDeviceMotionClient>();
    auto orientationClient = makeUnique<DriftstackDeviceOrientationClient>();

    DriftstackDeviceMotionClient& motionRef = *motionClient;
    DriftstackDeviceOrientationClient& orientationRef = *orientationClient;

    // Own the clients on the Page (lifetime == Page).
    Supplement<Page>::provideTo(&page, DriftstackSensorClientsHolder::supplementName(),
        makeUnique<DriftstackSensorClientsHolder>(WTF::move(motionClient), WTF::move(orientationClient)));

    // Provide the controllers under their canonical supplement names so
    // DeviceMotionController::from(&page) / DeviceOrientationController::from(&page)
    // resolve (the ASCIILiteral key is content-hashed, so a separate "..."_s instance
    // matches the controller's own supplementName()). Each ctor calls
    // client.setController(this).
    Supplement<Page>::provideTo(&page, "DeviceMotionController"_s, makeUnique<DeviceMotionController>(motionRef));
    Supplement<Page>::provideTo(&page, "DeviceOrientationController"_s, makeUnique<DeviceOrientationController>(orientationRef));
}

} // namespace WebCore

#endif // PLATFORM(DRIFTSTACK) && ENABLE(DEVICE_ORIENTATION)
