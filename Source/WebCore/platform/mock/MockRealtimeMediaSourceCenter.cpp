/*
 * Copyright (C) 2013 Google Inc. All rights reserved.
 * Copyright (C) 2013-2023 Apple Inc. All rights reserved.
 * Copyright (C) 2013 Nokia Corporation and/or its subsidiary(-ies).
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

#include "config.h"
#include "MockRealtimeMediaSourceCenter.h"

#if ENABLE(MEDIA_STREAM)

#include "CaptureDevice.h"
#include "Logging.h"
#include "MediaConstraints.h"
#include "MockRealtimeAudioSource.h"
#include "MockRealtimeVideoSource.h"
#include "NativeImage.h"
#include "NotImplemented.h"
#include "RealtimeMediaSourceSettings.h"
#include <math.h>
#include <wtf/NeverDestroyed.h>
#include <wtf/text/StringView.h>

#if PLATFORM(DRIFTSTACK)
#include <cstdlib> // getenv for the DRIFTSTACK_GETUSERMEDIA_GRANTED gate
#endif

#if PLATFORM(COCOA)
#include "CoreAudioCaptureSource.h"
#include "DisplayCaptureSourceCocoa.h"
#include "MockAudioCaptureUnit.h"
#include "MockRealtimeVideoSourceCocoa.h"
#endif

#if PLATFORM(IOS_FAMILY)
#include "CoreAudioCaptureSourceIOS.h"
#endif

#if USE(GSTREAMER)
#include "GStreamerMockDeviceProvider.h"
#include "MockDisplayCaptureSourceGStreamer.h"
#include "MockRealtimeVideoSourceGStreamer.h"
#endif

namespace WebCore {

#if PLATFORM(DRIFTSTACK)
// GRANTED-state getUserMedia iPhone 9-device set (DRIFTSTACK_GETUSERMEDIA_GRANTED). Real-device
// captured by A1 (probe getusermedia-granted-full, iPhone 17 / iOS 18.7 / Safari 26.4): 1 mic +
// 5 cameras + 3 speakers (the 3rd audiooutput is the system-default speaker re-exposed as the
// literal-"default" entry by createDefaultSpeakerAsSpecificDevice). The native per-origin SHA-1
// salt path (RealtimeMediaSourceCenter::hashStringWithSalt, applied in MediaDevices::exposeDevices)
// produces the 40-hex deviceId/groupId, so we only set the PRE-hash persistentId + groupId here.
//
// groupId model (A1 2026-06-29 CORRECTION, gUM-G3): ALL 4 AUDIO devices (mic + 3 speakers) share
// ONE pre-hash group; EACH of the 5 cameras has its OWN distinct group → 6 groups total. The mock
// CaptureDevice ctor uses the 4th arg as groupId (MockMediaDevice::captureDevice): for microphones
// it passes persistentId, for speakers it passes relatedMicrophoneId. So to coalesce all audio we
// give the mic a persistentId that doubles as the shared audio group AND set every speaker's
// relatedMicrophoneId to that SAME id; exposeDevices() then hashes that one pre-hash group →
// one 40-hex audio groupId. Each camera passes its own persistentId as groupId → 5 distinct hashes.
//
// per-camera (A1 gUM-G1): all 5 = 640x480 / 30fps / aspectRatio 1.3333 (getSettings derives
// width/height) / zoom 1 / wb continuous / bgBlur false / powerEff false. Front Ultra Wide + Front
// = facingMode user, NO torch; Back Dual Wide + Back Ultra Wide + Back = facingMode environment,
// torch:false (capability present, value false). Caps width/height {1,4032} aspectRatio
// {1/4032,4032} frameRate {1,60} zoom {1,10} focusDistance {0.2,..} (all derived from the preset
// set + the gated MockRealtimeVideoSource overrides). Presets reach 4032 in BOTH dimensions so
// updateCapabilities() yields max width=max height=4032 (aspectRatio min = 1/4032 = ~0.000248).
//
// Default speaker: 'Default - Speaker' deviceId = literal "default" (NOT salted) — emitted by
// createDefaultSpeakerAsSpecificDevice when ExposeDefaultSpeakerAsSpecificDeviceEnabled (default
// true) sees a speaker whose group has a microphone. We make the first speaker the default
// (label "Speaker", isDefault) so makeString("Default", " - ", "Speaker") == "Default - Speaker".
static const String& driftstackSharedAudioGroupId()
{
    // One pre-hash group id shared by the mic + all speakers. Also serves as the mic persistentId
    // (mic ctor passes persistentId as its groupId) and each speaker's relatedMicrophoneId.
    static NeverDestroyed<String> id { "driftstack-iphone-audio-group"_s };
    return id;
}

// iPhone camera preset set: settings size is 640x480 @30 (the iPhone gUM default the captured
// settings show); the larger presets exist ONLY to widen the derived capabilities (width/height
// up to 4032, frameRate up to 60, zoom 1..10). minZoom=1/maxZoom=10 makes zoom supported; NO
// preset is isEfficient (so canBePowerEfficient()==false → settings.powerEfficient stays false +
// caps powerEfficient==[false]). Frame-rate ranges include 60 so caps frameRate max==60.
static Vector<VideoPresetData> driftstackIPhoneCameraPresets()
{
    return Vector<VideoPresetData> {
        // 640x480 first → bestSupportedSizeFrameRateAndZoom default + setting size (aspectRatio 4:3 = 1.3333).
        { { 640, 480 },   { { 1, 60 } }, 1, 10, false },
        { { 1280, 720 },  { { 1, 60 } }, 1, 10, false },
        { { 1920, 1080 }, { { 1, 60 } }, 1, 10, false },
        { { 4032, 3024 }, { { 1, 30 } }, 1, 10, false }, // max width 4032
        { { 3024, 4032 }, { { 1, 30 } }, 1, 10, false }, // max height 4032 → aspectRatio min = 1/4032
    };
}

static MockCameraProperties driftstackCameraProps(VideoFacingMode facingMode, bool hasTorch)
{
    MockCameraProperties props;
    props.defaultFrameRate = 30;
    props.facingMode = facingMode;
    props.presets = driftstackIPhoneCameraPresets();
    props.fillColor = Color::black;
    // whiteBalanceMode caps = ['manual','continuous'] (current value 'continuous' set in
    // MockRealtimeVideoSource under the gate). Order matches the captured caps sequence.
    props.whiteBalanceMode = { MeteringMode::Manual, MeteringMode::Continuous };
    props.hasTorch = hasTorch;
    props.hasBackgroundBlur = false;
    return props;
}

static Vector<MockMediaDevice> driftstackIPhoneDevices()
{
    auto& audioGroup = driftstackSharedAudioGroupId();
    return Vector<MockMediaDevice> {
        // --- 1 microphone (sampleRate 48000, echoCancellation: nullopt → settings true + caps
        // [t,f]; volume defaults to 1). Its persistentId IS the shared audio pre-hash group. ---
        MockMediaDevice { audioGroup, "iPhone Microphone"_s, { }, true, MockMicrophoneProperties { 48000, std::nullopt, 1 } },

        // --- 5 cameras, EACH its own pre-hash group (persistentId used as groupId by the ctor). ---
        MockMediaDevice { "driftstack-iphone-cam-front-ultrawide"_s, "Front Ultra Wide Camera"_s, { }, true,
            driftstackCameraProps(VideoFacingMode::User, false) },
        MockMediaDevice { "driftstack-iphone-cam-back-dualwide"_s, "Back Dual Wide Camera"_s, { }, false,
            driftstackCameraProps(VideoFacingMode::Environment, false) },
        MockMediaDevice { "driftstack-iphone-cam-back-ultrawide"_s, "Back Ultra Wide Camera"_s, { }, false,
            driftstackCameraProps(VideoFacingMode::Environment, false) },
        MockMediaDevice { "driftstack-iphone-cam-back"_s, "Back Camera"_s, { }, false,
            driftstackCameraProps(VideoFacingMode::Environment, false) },
        // W3096 (divergence-hunt-2 2026-07-06): the Front (non-ultrawide) camera enumerates LAST on a real
        // iPhone, not 2nd — gumgrantedfull-iPhone_17 devicesAfterGrantFull videoinput order = [Front Ultra Wide,
        // Back Dual Wide, Back Ultra Wide, Back Camera, Front Camera]. enumerateDevices preserves the mock
        // insertion (Vector) order, so the Front Camera entry must be last. (Non-prod today: DRIFTSTACK_GETUSER-
        // MEDIA_GRANTED is default-OFF in launch-env, but reorder for reverse-gate correctness + future enablement.)
        MockMediaDevice { "driftstack-iphone-cam-front"_s, "Front Camera"_s, { }, false,
            driftstackCameraProps(VideoFacingMode::User, false) },

        // --- 3 speakers, ALL sharing the audio pre-hash group (relatedMicrophoneId == audioGroup).
        // The first is the default → re-exposed as 'Default - Speaker' (deviceId literal "default")
        // by createDefaultSpeakerAsSpecificDevice AND as 'Speaker' (40-hex). 'Receiver' is the 3rd. ---
        MockMediaDevice { "driftstack-iphone-spk-speaker"_s, "Speaker"_s, { }, true, MockSpeakerProperties { audioGroup, 48000 } },
        MockMediaDevice { "driftstack-iphone-spk-receiver"_s, "Receiver"_s, { }, false, MockSpeakerProperties { audioGroup, 48000 } },
    };
}

bool MockRealtimeMediaSourceCenter::driftstackGetUserMediaGranted()
{
    static const bool granted = []() {
        const char* env = getenv("DRIFTSTACK_GETUSERMEDIA_GRANTED");
        return env && env[0] == '1';
    }();
    return granted;
}

void MockRealtimeMediaSourceCenter::driftstackEnableGetUserMediaSynthesis()
{
    if (!driftstackGetUserMediaGranted())
        return;
    // Load the iPhone set first so any device-list consumer activated by enabling the mock center
    // sees the canonical 9 devices, then flip the capture-factory overrides on.
    setDevices(driftstackIPhoneDevices());
    setMockRealtimeMediaSourceCenterEnabled(true);
}
#endif // PLATFORM(DRIFTSTACK)

static inline Vector<MockMediaDevice> defaultDevices()
{
#if PLATFORM(DRIFTSTACK)
    // When the gUM-granted gate is on, the canonical default device list IS the iPhone set, so any
    // process that enables the mock center (or calls resetDevices) gets it without extra plumbing.
    if (MockRealtimeMediaSourceCenter::driftstackGetUserMediaGranted())
        return driftstackIPhoneDevices();
#endif
    return Vector<MockMediaDevice> {
        MockMediaDevice { "239c24b0-2b15-11e3-8224-0800200c9a66"_s, "Mock audio device 1"_s, { }, true, MockMicrophoneProperties { 44100 , { }, 1 } },
        MockMediaDevice { "239c24b1-2b15-11e3-8224-0800200c9a66"_s, "Mock audio device 2"_s, { }, false, MockMicrophoneProperties { 48000, { false }, 2 } },
        MockMediaDevice { "239c24b1-3b15-11e3-8224-0800200c9a66"_s, "Mock audio device 3"_s, { }, false, MockMicrophoneProperties { 96000, { true }, 3 } },
        MockMediaDevice { "239c24b1-3b15-21e3-8224-0800200c9a66"_s, "Mock audio device 4"_s, { }, true, MockMicrophoneProperties { 44100 , { }, 4 } },

        MockMediaDevice { "239c24b0-2b15-11e3-8224-0800200c9a67"_s, "Mock speaker device 1"_s, { }, true, MockSpeakerProperties { "239c24b0-2b15-11e3-8224-0800200c9a66"_s, 44100 } },
        MockMediaDevice { "239c24b1-2b15-11e3-8224-0800200c9a67"_s, "Mock speaker device 2"_s, { }, false, MockSpeakerProperties { "239c24b1-2b15-11e3-8224-0800200c9a66"_s, 48000 } },
        MockMediaDevice { "239c24b2-2b15-11e3-8224-0800200c9a67"_s, "Mock speaker device 3"_s, { }, false, MockSpeakerProperties { String { }, 48000 } },

        MockMediaDevice { "239c24b2-2b15-11e3-8224-0800200c9a66"_s, "Mock video device 1"_s, { }, true,
            MockCameraProperties {
                30,
                VideoFacingMode::User, {
                    { { 2560, 1440 }, { { 10, 10 }, { 7.5, 7.5 }, { 5, 5 } }, 1, 1, true },
                    { { 1280, 720 }, { { 30, 30 }, { 27.5, 27.5 }, { 25, 25 }, { 22.5, 22.5 }, { 20, 20 }, { 17.5, 17.5 }, { 15, 15 }, { 12.5, 12.5 }, { 10, 10 }, { 7.5, 7.5 }, { 5, 5 } }, 1, 1, true },
                    { { 640, 480 },  { { 30, 30 }, { 27.5, 27.5 }, { 25, 25 }, { 22.5, 22.5 }, { 20, 20 }, { 17.5, 17.5 }, { 15, 15 }, { 12.5, 12.5 }, { 10, 10 }, { 7.5, 7.5 }, { 5, 5 } }, 1, 1, true },
                    { { 112, 112 },  { { 30, 30 }, { 27.5, 27.5 }, { 25, 25 }, { 22.5, 22.5 }, { 20, 20 }, { 17.5, 17.5 }, { 15, 15 }, { 12.5, 12.5 }, { 10, 10 }, { 7.5, 7.5 }, { 5, 5 } }, 1, 1, true },
                },
                Color::black,
                { }, // whiteBalanceModes
                false, // supportsTorch
                false, // background blur enabled
            } },

        MockMediaDevice { "239c24b3-2b15-11e3-8224-0800200c9a66"_s, "Mock video device 2"_s, { }, false,
            MockCameraProperties {
                15,
                VideoFacingMode::Environment, {
                    { { 3840, 2160 }, { { 2, 30 } }, 1, 4, false },
                    { { 1920, 1080 }, { { 2, 30 } }, 1, 4, true },
                    { { 1280, 720 },  { { 3, 120 } }, 1, 4, false },
                    { { 960, 540 },   { { 3, 60 } }, 1, 4, false },
                    { { 640, 480 },   { { 2, 30 } }, 1, 4, false },
                    { { 352, 288 },   { { 2, 30 } }, 1, 4, false },
                    { { 320, 240 },   { { 2, 30 } }, 1, 4, false },
                    { { 160, 120 },   { { 2, 30 } }, 1, 4, false },
                },
                Color::darkGray,
                { MeteringMode::Manual, MeteringMode::SingleShot, MeteringMode::Continuous },
                true,
                true, // background blur enabled
            } },

        MockMediaDevice { "SCREEN-1"_s, "Mock screen device 1"_s, { }, true, MockDisplayProperties { CaptureDevice::DeviceType::Screen, Color::lightGray, { 1920, 1080 } } },
        MockMediaDevice { "SCREEN-2"_s, "Mock screen device 2"_s, { }, false, MockDisplayProperties { CaptureDevice::DeviceType::Screen, Color::yellow, { 3840, 2160 } } },

        MockMediaDevice { "WINDOW-1"_s, "Mock window device 1"_s, { }, true, MockDisplayProperties { CaptureDevice::DeviceType::Window, SRGBA<uint8_t> { 255, 241, 181 }, { 640, 480 } } },
        MockMediaDevice { "WINDOW-2"_s, "Mock window device 2"_s, { }, false, MockDisplayProperties { CaptureDevice::DeviceType::Window, SRGBA<uint8_t> { 255, 208, 181 }, { 1280, 600 } } },
    };
}

class MockRealtimeVideoSourceFactory : public VideoCaptureFactory {
public:
    CaptureSourceOrError createVideoCaptureSource(const CaptureDevice& device, MediaDeviceHashSalts&& hashSalts, const MediaConstraints* constraints, std::optional<PageIdentifier> pageIdentifier) final
    {
        ASSERT(device.type() == CaptureDevice::DeviceType::Camera);
        if (!MockRealtimeMediaSourceCenter::captureDeviceWithPersistentID(CaptureDevice::DeviceType::Camera, device.persistentId()))
            return CaptureSourceOrError({ "Unable to find mock camera device with given persistentID"_s, MediaAccessDenialReason::PermissionDenied });

        auto mock = MockRealtimeMediaSourceCenter::mockDeviceWithPersistentID(device.persistentId());
        ASSERT(mock);
        if (mock->flags.contains(MockMediaDevice::Flag::Invalid))
            return CaptureSourceOrError({ "Invalid mock camera device"_s, MediaAccessDenialReason::PermissionDenied });

        return MockRealtimeVideoSource::create(String { device.persistentId() }, AtomString { device.label() }, WTF::move(hashSalts), constraints, pageIdentifier);
    }

private:
    CaptureDeviceManager& videoCaptureDeviceManager() final { return MockRealtimeMediaSourceCenter::singleton().videoCaptureDeviceManager(); }
};

#if PLATFORM(COCOA)
class MockDisplayCapturer final
    : public DisplayCaptureSourceCocoa::Capturer
    , public CanMakeWeakPtr<MockDisplayCapturer> {
public:
    MockDisplayCapturer(CapturerObserver&, const CaptureDevice&, std::optional<PageIdentifier>);

    void triggerMockCaptureConfigurationChange();

private:
    bool start() final;
    void stop() final;
    DisplayCaptureSourceCocoa::DisplayFrameType generateFrame() final;
    DisplaySurfaceType surfaceType() const final { return DisplaySurfaceType::Monitor; }
    void commitConfiguration(const RealtimeMediaSourceSettings&) final;
    CaptureDevice::DeviceType deviceType() const final { return CaptureDevice::DeviceType::Screen; }
    IntSize intrinsicSize() const final;
#if !RELEASE_LOG_DISABLED
    ASCIILiteral logClassName() const final { return "MockDisplayCapturer"_s; }
#endif
    void whenReady(CompletionHandler<void(CaptureSourceError&&)>&&) final;

    void readyTimerFired();

    Ref<MockRealtimeVideoSource> m_source;
    RealtimeMediaSourceSettings m_settings;
    Timer m_readyTimer;
    bool m_isRunning { false };
    CompletionHandler<void(CaptureSourceError&&)> m_whenReadyCallback;
};

MockDisplayCapturer::MockDisplayCapturer(CapturerObserver& observer, const CaptureDevice& device, std::optional<PageIdentifier> pageIdentifier)
    : DisplayCaptureSourceCocoa::Capturer(observer)
    , m_source(MockRealtimeVideoSourceMac::createForMockDisplayCapturer(String { device.persistentId() }, AtomString { device.label() }, MediaDeviceHashSalts { "persistent"_s, "ephemeral"_s }, pageIdentifier))
    , m_readyTimer(*this, &MockDisplayCapturer::readyTimerFired)
{
}

bool MockDisplayCapturer::start()
{
    ASSERT(m_settings.frameRate());

    ASSERT(!m_whenReadyCallback);
    ASSERT(!m_isRunning);

    m_isRunning = true;
    protect(m_source)->start();
    return true;
}

void MockDisplayCapturer::stop()
{
    ASSERT(!m_whenReadyCallback);

    m_isRunning = false;
    protect(m_source)->stop();
}

void MockDisplayCapturer::whenReady(CompletionHandler<void(CaptureSourceError&&)>&& callback)
{
    ASSERT(!m_isRunning);

    m_whenReadyCallback = WTF::move(callback);
    m_readyTimer.startOneShot(50_ms);
}

void MockDisplayCapturer::readyTimerFired()
{
    ASSERT(!m_isRunning);

    configurationChanged();
    m_whenReadyCallback({ });
}

void MockDisplayCapturer::commitConfiguration(const RealtimeMediaSourceSettings& settings)
{
    // FIXME: Update m_source width, height and frameRate according settings
    m_settings = settings;
}

DisplayCaptureSourceCocoa::DisplayFrameType MockDisplayCapturer::generateFrame()
{
    if (RefPtr imageBuffer = protect(m_source)->imageBuffer())
        return imageBuffer->copyNativeImage();
    return { };
}

IntSize MockDisplayCapturer::intrinsicSize() const
{
    auto device = MockRealtimeMediaSourceCenter::mockDeviceWithPersistentID(m_source->persistentID());
    ASSERT(device);
    if (!device)
        return { };

    ASSERT(device->isDisplay());
    if (!device->isDisplay())
        return { };

    auto& properties = std::get<MockDisplayProperties>(device->properties);
    return properties.defaultSize;
}

void MockDisplayCapturer::triggerMockCaptureConfigurationChange()
{
    Ref source = m_source;
    auto deviceId = source->persistentID();
    auto device = MockRealtimeMediaSourceCenter::mockDeviceWithPersistentID(deviceId.startsWith("WINDOW"_s) ? "WINDOW-2"_s : "SCREEN-2"_s);
    ASSERT(device);
    if (!device)
        return;

    bool isStarted = source->isProducingData();
    auto pageIdentifier = source->pageIdentifier();
    source = MockRealtimeVideoSourceMac::createForMockDisplayCapturer(String { device->persistentId }, AtomString { device->label }, MediaDeviceHashSalts { "persistent"_s, "ephemeral"_s }, pageIdentifier);
    m_source = source.copyRef();
    if (isStarted)
        source->start();

    configurationChanged();
}
#endif // PLATFORM(COCOA)

class MockRealtimeDisplaySourceFactory : public DisplayCaptureFactory {
public:
    static MockRealtimeDisplaySourceFactory& singleton();

    CaptureSourceOrError createDisplayCaptureSource(const CaptureDevice& device, MediaDeviceHashSalts&& hashSalts, const MediaConstraints* constraints, std::optional<PageIdentifier> pageIdentifier) final
    {
        if (!MockRealtimeMediaSourceCenter::captureDeviceWithPersistentID(device.type(), device.persistentId()))
            return CaptureSourceOrError({ "Unable to find mock display device with given persistentID"_s, MediaAccessDenialReason::PermissionDenied });

        switch (device.type()) {
        case CaptureDevice::DeviceType::Screen:
        case CaptureDevice::DeviceType::Window: {
#if PLATFORM(COCOA)
            return DisplayCaptureSourceCocoa::create([this, &device, pageIdentifier] (auto& observer) {
                auto capturer = makeUniqueRefWithoutRefCountedCheck<MockDisplayCapturer>(observer, device, pageIdentifier);
                m_capturer = capturer.get();
                return capturer;
            }, device, WTF::move(hashSalts), constraints, pageIdentifier);
#elif USE(GSTREAMER)
            return MockDisplayCaptureSourceGStreamer::create(device, WTF::move(hashSalts), constraints, pageIdentifier);
#else
            return MockRealtimeVideoSource::create(String { device.persistentId() }, AtomString { device.label() }, WTF::move(hashSalts), constraints, pageIdentifier);
#endif
            break;
        }
        case CaptureDevice::DeviceType::Microphone:
        case CaptureDevice::DeviceType::Speaker:
        case CaptureDevice::DeviceType::Camera:
        case CaptureDevice::DeviceType::SystemAudio:
        case CaptureDevice::DeviceType::Unknown:
            ASSERT_NOT_REACHED();
            break;
        }

        return { };
    }

#if PLATFORM(COCOA)
    WeakPtr<MockDisplayCapturer> NODELETE latestCapturer() { return m_capturer; }
#endif

private:
    DisplayCaptureManager& displayCaptureDeviceManager() final { return MockRealtimeMediaSourceCenter::singleton().displayCaptureDeviceManager(); }
#if PLATFORM(COCOA)
    WeakPtr<MockDisplayCapturer> m_capturer;
#endif
};

class MockRealtimeAudioSourceFactory final
#if PLATFORM(COCOA)
    : public CoreAudioCaptureSourceFactory
#else
    : public AudioCaptureFactory, public RefCounted<MockRealtimeAudioSourceFactory>
#endif

{
public:
    static Ref<MockRealtimeAudioSourceFactory> create()
    {
        return adoptRef(*new MockRealtimeAudioSourceFactory);
    }

    CaptureSourceOrError createAudioCaptureSource(const CaptureDevice& device, MediaDeviceHashSalts&& hashSalts, const MediaConstraints* constraints, std::optional<PageIdentifier> pageIdentifier) final
    {
        ASSERT(device.type() == CaptureDevice::DeviceType::Microphone);
        if (!MockRealtimeMediaSourceCenter::captureDeviceWithPersistentID(device.type(), device.persistentId()))
            return CaptureSourceOrError({ "Unable to find mock microphone device with given persistentID"_s, MediaAccessDenialReason::PermissionDenied });

        auto mock = MockRealtimeMediaSourceCenter::mockDeviceWithPersistentID(device.persistentId());
        ASSERT(mock);
        if (mock->flags.contains(MockMediaDevice::Flag::Invalid))
            return CaptureSourceOrError({ "Invalid mock microphone device"_s, MediaAccessDenialReason::PermissionDenied });

        return MockRealtimeAudioSource::create(String { device.persistentId() }, AtomString { device.label() }, WTF::move(hashSalts), constraints, pageIdentifier);
    }
private:
    MockRealtimeAudioSourceFactory() = default;

    CaptureDeviceManager& audioCaptureDeviceManager() final { return MockRealtimeMediaSourceCenter::singleton().audioCaptureDeviceManager(); }
    const Vector<CaptureDevice>& speakerDevices() const final { return MockRealtimeMediaSourceCenter::speakerDevices(); }
};

static Vector<MockMediaDevice>& devices()
{
    static NeverDestroyed devices = defaultDevices();
    return devices;
}

static HashMap<String, MockMediaDevice>& deviceMap()
{
    static NeverDestroyed map = [] {
        HashMap<String, MockMediaDevice> map;
        for (auto& device : devices())
            map.add(device.persistentId, device);
        return map;
    }();
    return map;
}

static inline Vector<CaptureDevice>& deviceListForDevice(const MockMediaDevice& device)
{
    if (device.isMicrophone())
        return MockRealtimeMediaSourceCenter::microphoneDevices();
    if (device.isSpeaker())
        return MockRealtimeMediaSourceCenter::speakerDevices();
    if (device.isCamera())
        return MockRealtimeMediaSourceCenter::videoDevices();

    ASSERT(device.isDisplay());
    return MockRealtimeMediaSourceCenter::displayDevices();
}

MockRealtimeMediaSourceCenter& MockRealtimeMediaSourceCenter::singleton()
{
    static NeverDestroyed<MockRealtimeMediaSourceCenter> center;
    return center;
}

void MockRealtimeMediaSourceCenter::setMockRealtimeMediaSourceCenterEnabled(bool enabled)
{
    MockRealtimeMediaSourceCenter& mock = singleton();

    if (mock.m_isEnabled == enabled)
        return;

    mock.m_isEnabled = enabled;
    RealtimeMediaSourceCenter& center = RealtimeMediaSourceCenter::singleton();

    if (mock.m_isEnabled) {
        if (mock.m_isMockAudioCaptureEnabled) {
#if PLATFORM(COCOA)
            MockAudioCaptureUnit::enable();
#endif
            center.setAudioCaptureFactory(mock.audioCaptureFactory());
        }
        if (mock.m_isMockVideoCaptureEnabled)
            center.setVideoCaptureFactory(mock.videoCaptureFactory());
        if (mock.m_isMockDisplayCaptureEnabled)
            center.setDisplayCaptureFactory(mock.displayCaptureFactory());
        return;
    }

    if (mock.m_isMockAudioCaptureEnabled) {
#if PLATFORM(COCOA)
        MockAudioCaptureUnit::disable();
#endif
        center.unsetAudioCaptureFactory(mock.audioCaptureFactory());
    }
    if (mock.m_isMockVideoCaptureEnabled)
        center.unsetVideoCaptureFactory(mock.videoCaptureFactory());
    if (mock.m_isMockDisplayCaptureEnabled)
        center.unsetDisplayCaptureFactory(mock.displayCaptureFactory());
}

bool MockRealtimeMediaSourceCenter::mockRealtimeMediaSourceCenterEnabled()
{
    return singleton().m_isEnabled;
}

static CaptureDevice toCaptureDevice(const MockMediaDevice& device)
{
    auto captureDevice = device.captureDevice();
    captureDevice.setEnabled(true);
    captureDevice.setIsMockDevice(true);

    return captureDevice;
}

static void createMockDevice(const MockMediaDevice& device, bool isDefault)
{
    if (isDefault)
        deviceListForDevice(device).insert(0, toCaptureDevice(device));
    else
        deviceListForDevice(device).append(toCaptureDevice(device));
}

void MockRealtimeMediaSourceCenter::resetDevices()
{
    setDevices(defaultDevices());
    RealtimeMediaSourceCenter::singleton().captureDevicesChanged();
}

void MockRealtimeMediaSourceCenter::setMockCaptureDevicesInterrupted(bool isCameraInterrupted, bool isMicrophoneInterrupted)
{
    MockRealtimeVideoSource::setIsInterrupted(isCameraInterrupted);
    MockRealtimeAudioSource::setIsInterrupted(isMicrophoneInterrupted);
}

void MockRealtimeMediaSourceCenter::triggerMockCaptureConfigurationChange(bool forCamera, bool forMicrophone, bool forDisplay)
{
    if (forCamera)
        MockRealtimeVideoSource::triggerCameraConfigurationChange();

#if PLATFORM(COCOA)
    if (forMicrophone) {
        auto devices = audioCaptureDeviceManager().captureDevices();
        if (devices.size() > 1) {
            MockAudioCaptureUnit::increaseBufferSize();
            CoreAudioCaptureUnit::forEach([&devices](auto& unit) {
                unit.handleNewCurrentMicrophoneDevice(devices[1]);
            });
        }
    }
    if (forDisplay) {
        if (auto capturer = MockRealtimeDisplaySourceFactory::singleton().latestCapturer())
            capturer->triggerMockCaptureConfigurationChange();
    }
#elif USE(GSTREAMER)
    if (forMicrophone) {
        auto devices = audioCaptureDeviceManager().captureDevices();
        if (devices.size() > 1)
            webkitGstMockDeviceProviderSwitchDefaultDevice(devices[0], devices[1]);
    }
    UNUSED_PARAM(forDisplay);
#else
    UNUSED_PARAM(forMicrophone);
    UNUSED_PARAM(forDisplay);
#endif
}

void MockRealtimeMediaSourceCenter::setDevices(Vector<MockMediaDevice>&& newMockDevices)
{
    microphoneDevices().clear();
    speakerDevices().clear();
    videoDevices().clear();
    displayDevices().clear();

    auto& mockDevices = devices();
    for (auto& device : mockDevices) {
        auto& persistentId = device.persistentId;
        if (!newMockDevices.containsIf([&persistentId](auto& newDevice) -> bool {
            return newDevice.persistentId == persistentId;
        }))
            RealtimeMediaSourceCenter::singleton().captureDeviceWillBeRemoved(persistentId);
    }
    mockDevices = WTF::move(newMockDevices);

    auto& map = deviceMap();
    map.clear();

    for (const auto& device : mockDevices) {
        map.add(device.persistentId, device);
        createMockDevice(device, false);
    }
    RealtimeMediaSourceCenter::singleton().captureDevicesChanged();
}

static bool shouldBeDefaultDevice(const MockMediaDevice& device)
{
    auto* cameraProperties = device.cameraProperties();
    return cameraProperties && cameraProperties->facingMode == VideoFacingMode::Unknown;
}

void MockRealtimeMediaSourceCenter::addDevice(const MockMediaDevice& newDevice)
{
    auto device = newDevice;

    if (device.isMicrophone())
        std::get<MockMicrophoneProperties>(device.properties).deviceID = microphoneDevices().size() + 1;

    bool isDefault = device.isDefault || shouldBeDefaultDevice(device);

    if (isDefault)
        devices().insert(0, device);
    else
        devices().append(device);
    deviceMap().set(device.persistentId, device);
    createMockDevice(device, isDefault);
    RealtimeMediaSourceCenter::singleton().captureDevicesChanged();
}

void MockRealtimeMediaSourceCenter::removeDevice(const String& persistentId)
{
    auto& map = deviceMap();
    auto iterator = map.find(persistentId);
    if (iterator == map.end())
        return;

    RealtimeMediaSourceCenter::singleton().captureDeviceWillBeRemoved(persistentId);
    devices().removeFirstMatching([&persistentId](const auto& device) {
        return device.persistentId == persistentId;
    });

    deviceListForDevice(iterator->value).removeFirstMatching([&persistentId](const auto& device) {
        return device.persistentId() == persistentId;
    });

    map.remove(iterator);
    RealtimeMediaSourceCenter::singleton().captureDevicesChanged();
}

void MockRealtimeMediaSourceCenter::setDeviceIsEphemeral(const String& persistentId, bool isEphemeral)
{
    ASSERT(!persistentId.isEmpty());

    auto& map = deviceMap();
    auto iterator = map.find(persistentId);
    if (iterator == map.end())
        return;

    MockMediaDevice device = iterator->value;
    if (isEphemeral)
        device.flags.add(MockMediaDevice::Flag::Ephemeral);
    else
        device.flags.remove(MockMediaDevice::Flag::Ephemeral);

    removeDevice(persistentId);
    addDevice(device);
}

std::optional<MockMediaDevice> MockRealtimeMediaSourceCenter::mockDeviceWithPersistentID(const String& id)
{
    ASSERT(!id.isEmpty());

    auto& map = deviceMap();
    auto iterator = map.find(id);
    if (iterator == map.end())
        return std::nullopt;

    return iterator->value;
}

std::optional<MockMediaDevice> MockRealtimeMediaSourceCenter::mockMicrophoneFromDeviceID(uint32_t deviceID)
{
    for (auto& device : deviceMap().values()) {
        if (device.isMicrophone() && std::get<MockMicrophoneProperties>(device.properties).deviceID == deviceID)
            return device;
    }
    return { };
}

std::optional<CaptureDevice> MockRealtimeMediaSourceCenter::captureDeviceWithPersistentID(CaptureDevice::DeviceType type, const String& id)
{
    ASSERT(!id.isEmpty());

    auto& map = deviceMap();
    auto iterator = map.find(id);
    if (iterator == map.end() || iterator->value.type() != type)
        return std::nullopt;

    return toCaptureDevice(iterator->value);
}

Vector<CaptureDevice>& MockRealtimeMediaSourceCenter::microphoneDevices()
{
    static NeverDestroyed microphoneDevices = [] {
        Vector<CaptureDevice> microphoneDevices;
        for (const auto& device : devices()) {
            if (device.isMicrophone())
                microphoneDevices.append(toCaptureDevice(device));
        }
        return microphoneDevices;
    }();
    return microphoneDevices;
}

Vector<CaptureDevice>& MockRealtimeMediaSourceCenter::speakerDevices()
{
    static NeverDestroyed speakerDevices = [] {
        Vector<CaptureDevice> speakerDevices;
        for (const auto& device : devices()) {
            if (device.isSpeaker())
                speakerDevices.append(toCaptureDevice(device));
        }
        return speakerDevices;
    }();
    return speakerDevices;
}

Vector<CaptureDevice>& MockRealtimeMediaSourceCenter::videoDevices()
{
    static NeverDestroyed videoDevices = [] {
        Vector<CaptureDevice> videoDevices;
        for (const auto& device : devices()) {
            if (device.isCamera())
                videoDevices.append(toCaptureDevice(device));
        }
        return videoDevices;
    }();
    return videoDevices;
}

Vector<CaptureDevice>& MockRealtimeMediaSourceCenter::displayDevices()
{
    static NeverDestroyed displayDevices = [] {
        Vector<CaptureDevice> displayDevices;
        for (const auto& device : devices()) {
            if (device.isDisplay())
                displayDevices.append(toCaptureDevice(device));
        }
        return displayDevices;
    }();
    return displayDevices;
}

AudioCaptureFactory& MockRealtimeMediaSourceCenter::audioCaptureFactory()
{
    static NeverDestroyed<Ref<MockRealtimeAudioSourceFactory>> factory = MockRealtimeAudioSourceFactory::create();
    return factory.get();
}

VideoCaptureFactory& MockRealtimeMediaSourceCenter::videoCaptureFactory()
{
    static NeverDestroyed<MockRealtimeVideoSourceFactory> factory;
    return factory.get();
}

DisplayCaptureFactory& MockRealtimeMediaSourceCenter::displayCaptureFactory()
{
    return MockRealtimeDisplaySourceFactory::singleton();
}

MockRealtimeDisplaySourceFactory& MockRealtimeDisplaySourceFactory::singleton()
{
    static NeverDestroyed<MockRealtimeDisplaySourceFactory> factory;
    return factory.get();
}

} // namespace WebCore

#endif // ENABLE(MEDIA_STREAM)
