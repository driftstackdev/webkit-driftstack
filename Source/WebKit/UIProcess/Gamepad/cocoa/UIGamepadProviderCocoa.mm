/*
 * Copyright (C) 2016 Apple Inc. All rights reserved.
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

#import "config.h"
#import "UIGamepadProvider.h"

#if ENABLE(GAMEPAD)

#import <WebCore/GameControllerGamepadProvider.h>
#import <WebCore/HIDGamepadProvider.h>
#import <WebCore/MockGamepadProvider.h>
#import <WebCore/MultiGamepadProvider.h>

#if PLATFORM(DRIFTSTACK)
#import <wtf/CompletionHandler.h>
#import <wtf/NeverDestroyed.h>
#import <wtf/Vector.h>
#endif

namespace WebKit {
using namespace WebCore;

#if PLATFORM(DRIFTSTACK)
// W2875 (#35 isolation, audit wd32aqm12 — the one confirmed per-session leak): a LOCAL empty gamepad provider.
// WebCore's purpose-built EmptyGamepadProvider is neither header- nor symbol-exported to WebKit, so define an
// identical one here (mirrors WebCore::EmptyGamepadProvider): zero gamepads, never opens IOHIDManager /
// GCController. The fleet worker is macOS, so the default cocoa providers (GameController/Multi/HID) would
// enumerate the HOST Mac's HID/GameController devices — a controller plugged into the SHARED worker would be
// visible to EVERY customer session + reveal the host. This keeps navigator.getGamepads() PRESENT (returns []
// — A1's fingerprint surface, NOT removed), matching a controller-less iPhone.
class DriftstackEmptyGamepadProvider final : public GamepadProvider {
public:
    void startMonitoringGamepads(GamepadProviderClient&) final { }
    void stopMonitoringGamepads(GamepadProviderClient&) final { }
    const Vector<WeakPtr<PlatformGamepad>>& platformGamepads() final
    {
        static NeverDestroyed<Vector<WeakPtr<PlatformGamepad>>> emptyGamepads;
        return emptyGamepads;
    }
    void playEffect(unsigned, const String&, GamepadHapticEffectType, const GamepadEffectParameters&, CompletionHandler<void(bool)>&& completionHandler) final { completionHandler(false); }
    void stopEffects(unsigned, const String&, CompletionHandler<void()>&& completionHandler) final { completionHandler(); }
};
#endif

#if HAVE(WIDE_GAMECONTROLLER_SUPPORT)
static bool useGameControllerFramework = true;
#else
static bool useGameControllerFramework = false;
#endif

void UIGamepadProvider::setUsesGameControllerFramework()
{
    useGameControllerFramework = true;
}

void UIGamepadProvider::platformSetDefaultGamepadProvider()
{
    if (GamepadProvider::singleton().isMockGamepadProvider())
        return;

#if PLATFORM(DRIFTSTACK)
    static NeverDestroyed<DriftstackEmptyGamepadProvider> driftstackEmptyGamepadProvider;
    GamepadProvider::setSharedProvider(driftstackEmptyGamepadProvider.get());
    return;
#endif

#if PLATFORM(IOS_FAMILY)
    GamepadProvider::setSharedProvider(GameControllerGamepadProvider::singleton());
#else
    if (useGameControllerFramework)
        GamepadProvider::setSharedProvider(GameControllerGamepadProvider::singleton());
    else {
#if HAVE(MULTIGAMEPADPROVIDER_SUPPORT)
        GamepadProvider::setSharedProvider(MultiGamepadProvider::singleton());
#else
        GamepadProvider::setSharedProvider(HIDGamepadProvider::singleton());
#endif // HAVE(MULTIGAMEPADPROVIDER_SUPPORT)
    }
#endif // PLATFORM(IOS_FAMILY)
}

void UIGamepadProvider::platformStopMonitoringInput()
{
#if PLATFORM(MAC)
    if (!useGameControllerFramework)
        HIDGamepadProvider::singleton().stopMonitoringInput();
#endif
}

void UIGamepadProvider::platformStartMonitoringInput()
{
#if PLATFORM(MAC)
    if (!useGameControllerFramework)
        HIDGamepadProvider::singleton().startMonitoringInput();
#endif
}

}

#endif // ENABLE(GAMEPAD)
