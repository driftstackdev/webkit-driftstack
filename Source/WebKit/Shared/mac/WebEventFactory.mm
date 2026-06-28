/*
 * Copyright (C) 2010-2022 Apple Inc. All rights reserved.
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
#import "WebEventFactory.h"

#if USE(APPKIT)

#import "WebEventConversion.h"
#import <WebCore/KeyboardEvent.h>
#import <WebCore/PlatformEventFactoryMac.h>
#import <WebCore/Scrollbar.h>
#import <WebCore/WindowsKeyboardCodes.h>
#import <pal/spi/cg/CoreGraphicsSPI.h>
#import <pal/spi/mac/NSEventSPI.h>
#import <pal/spi/mac/NSMenuSPI.h>
#import <wtf/ASCIICType.h>
#import <wtf/UUID.h>

namespace WebKit {

static WebWheelEvent::Phase phaseForEvent(NSEvent *event)
{
    using enum WebWheelEvent::Phase;

    auto phase = None;
    if ([event phase] & NSEventPhaseBegan)
        phase = Began;
    if ([event phase] & NSEventPhaseStationary)
        phase = Stationary;
    if ([event phase] & NSEventPhaseChanged)
        phase = Changed;
    if ([event phase] & NSEventPhaseEnded)
        phase = Ended;
    if ([event phase] & NSEventPhaseCancelled)
        phase = Cancelled;
    if ([event phase] & NSEventPhaseMayBegin)
        phase = MayBegin;

    return phase;
}

static WebWheelEvent::Phase momentumPhaseForEvent(NSEvent *event)
{
    using enum WebWheelEvent::Phase;
    auto phase = None;

    if ([event momentumPhase] & NSEventPhaseBegan)
        phase = Began;
    if ([event momentumPhase] & NSEventPhaseStationary)
        phase = Stationary;
    if ([event momentumPhase] & NSEventPhaseChanged)
        phase = Changed;
    if ([event momentumPhase] & NSEventPhaseEnded)
        phase = Ended;
    if ([event momentumPhase] & NSEventPhaseCancelled)
        phase = Cancelled;

    return phase;
}

static int typeForEvent(NSEvent *event)
{
    return static_cast<int>([NSMenu menuTypeForEvent:event]);
}

bool WebEventFactory::shouldBeHandledAsContextClick(const WebCore::PlatformMouseEvent& event)
{
    return (static_cast<NSMenuType>(event.menuTypeForEvent()) == NSMenuTypeContextMenu);
}

WebMouseEvent WebEventFactory::createWebMouseEvent(NSEvent *event, NSEvent *lastPressureEvent, NSView *windowView, WebEventInputSource inputSource, WebCore::PlatformMouseEvent::CanInitiateDrag canInitiateDrag)
{
    NSPoint position = WebCore::pointForEvent(event, windowView);
    NSPoint globalPosition = WebCore::globalPointForEvent(event);

    WebEventType type = kit(WebCore::mouseEventTypeForEvent(event));
    if ([event type] == NSEventTypePressure) {
        // Since AppKit doesn't send mouse events for force down or force up, we have to use the current pressure
        // event and lastPressureEvent to detect if this is MouseForceDown, MouseForceUp, or just MouseForceChanged.
        if (lastPressureEvent.stage == 1 && event.stage == 2)
            type = WebEventType::MouseForceDown;
        else if (lastPressureEvent.stage == 2 && event.stage == 1)
            type = WebEventType::MouseForceUp;
        else
            type = WebEventType::MouseForceChanged;
    }

    WebMouseEventButton button = kit(WebCore::mouseButtonForEvent(event));
    unsigned short buttons = WebCore::currentlyPressedMouseButtons();
    float deltaX = [event deltaX];
    float deltaY = [event deltaY];
    float deltaZ = [event deltaZ];
    int clickCount = WebCore::clickCountForEvent(event);
    auto modifiers = kit(WebCore::modifiersForEvent(event));
    auto timestamp = MonotonicTime::fromRawSeconds(event.timestamp);
    int eventNumber = [event eventNumber];
    int menuTypeForEvent = typeForEvent(event);

    int stage = [event type] == NSEventTypePressure ? event.stage : lastPressureEvent.stage;
    double pressure = [event type] == NSEventTypePressure ? event.pressure : lastPressureEvent.pressure;
    double force = pressure + stage;

    auto unadjustedMovementDelta = WebCore::unadjustedMovementForEvent(event);

    return WebMouseEvent({ type, modifiers, timestamp, WTF::UUID::createVersion4() }, button, buttons, WebCore::DoublePoint(position), WebCore::DoublePoint(globalPosition), deltaX, deltaY, deltaZ, clickCount, force, inputSource, canInitiateDrag, WebMouseEventSyntheticClickType::NoTap, eventNumber, menuTypeForEvent, GestureWasCancelled::No, unadjustedMovementDelta);
}

WebWheelEvent WebEventFactory::createWebWheelEvent(NSEvent *event, NSView *windowView)
{
    NSPoint position = WebCore::pointForEvent(event, windowView);
    NSPoint globalPosition = WebCore::globalPointForEvent(event);

    BOOL continuous;
    float deltaX = 0;
    float deltaY = 0;
    float wheelTicksX = 0;
    float wheelTicksY = 0;

    WebCore::getWheelEventDeltas(event, deltaX, deltaY, continuous);
    
    if (continuous) {
        // smooth scroll events
        wheelTicksX = deltaX / static_cast<float>(WebCore::Scrollbar::pixelsPerLineStep());
        wheelTicksY = deltaY / static_cast<float>(WebCore::Scrollbar::pixelsPerLineStep());
    } else {
        // plain old wheel events
        wheelTicksX = deltaX;
        wheelTicksY = deltaY;
        deltaX *= static_cast<float>(WebCore::Scrollbar::pixelsPerLineStep());
        deltaY *= static_cast<float>(WebCore::Scrollbar::pixelsPerLineStep());
    }

    WebWheelEvent::Granularity granularity  = WebWheelEvent::Granularity::ScrollByPixelWheelEvent;
    bool directionInvertedFromDevice        = [event isDirectionInvertedFromDevice];
    WebWheelEvent::Phase phase              = phaseForEvent(event);
    WebWheelEvent::Phase momentumPhase      = momentumPhaseForEvent(event);
    bool hasPreciseScrollingDeltas          = continuous;

    uint32_t scrollCount;
    WebCore::FloatSize unacceleratedScrollingDelta;

    static bool nsEventSupportsScrollCount = [NSEvent instancesRespondToSelector:@selector(_scrollCount)];
    if (nsEventSupportsScrollCount) {
        scrollCount = [event _scrollCount];
        unacceleratedScrollingDelta = WebCore::FloatSize([event _unacceleratedScrollingDeltaX], [event _unacceleratedScrollingDeltaY]);
    } else {
        scrollCount = 0;
        unacceleratedScrollingDelta = WebCore::FloatSize(deltaX, deltaY);
    }

    auto modifiers = kit(WebCore::modifiersForEvent(event));
    auto timestamp = MonotonicTime::fromRawSeconds(event.timestamp);

    auto ioHIDEventTimestamp = timestamp;

    std::optional<WebCore::FloatSize> rawPlatformDelta;
    auto momentumEndType = WebWheelEvent::MomentumEndType::Unknown;
    
    ([&] {
        RetainPtr<CGEventRef> cgEvent = event.CGEvent;
        if (!cgEvent)
            return;

        auto ioHIDEvent = adoptCF(CGEventCopyIOHIDEvent(cgEvent.get()));
        if (!ioHIDEvent)
            return;

        auto ioHIDEventTimestampMachAbsoluteTime = IOHIDEventGetTimeStamp(ioHIDEvent.get());
        ioHIDEventTimestamp = MonotonicTime::fromMachAbsoluteTime(ioHIDEventTimestampMachAbsoluteTime);
        
        rawPlatformDelta = { WebCore::FloatSize(-IOHIDEventGetFloatValue(ioHIDEvent.get(), kIOHIDEventFieldScrollX), -IOHIDEventGetFloatValue(ioHIDEvent.get(), kIOHIDEventFieldScrollY)) };

        if (IOHIDEventGetScrollMomentum(ioHIDEvent.get()) & kIOHIDEventScrollMomentumWillBegin) {
            ASSERT(momentumPhase == WebWheelEvent::Phase::None && phase == WebWheelEvent::Phase::Ended);
            momentumPhase = WebWheelEvent::Phase::WillBegin;
        }

        bool momentumWasInterrupted = IOHIDEventGetScrollMomentum(ioHIDEvent.get()) & kIOHIDEventScrollMomentumInterrupted;
        momentumEndType = momentumWasInterrupted ? WebWheelEvent::MomentumEndType::Interrupted : WebWheelEvent::MomentumEndType::Natural;
    })();

    if (phase == WebWheelEvent::Phase::Cancelled) {
        deltaX = 0;
        deltaY = 0;
        wheelTicksX = 0;
        wheelTicksY = 0;
        unacceleratedScrollingDelta = { };
        rawPlatformDelta = std::nullopt;
    }

    return WebWheelEvent({ WebEventType::Wheel, modifiers, timestamp, WTF::UUID::createVersion4() }, WebCore::IntPoint(position), WebCore::IntPoint(globalPosition), WebCore::FloatSize(deltaX, deltaY), WebCore::FloatSize(wheelTicksX, wheelTicksY),
        granularity, directionInvertedFromDevice, phase, momentumPhase, hasPreciseScrollingDeltas,
        scrollCount, unacceleratedScrollingDelta, ioHIDEventTimestamp, rawPlatformDelta, momentumEndType);
}

WebKeyboardEvent WebEventFactory::createWebKeyboardEvent(NSEvent *event, bool handledByInputMethod, bool replacesSoftSpace, const Vector<WebCore::KeypressCommand>& commands)
{
    WebEventType type = WebCore::isKeyUpEvent(event) ? WebEventType::KeyUp : WebEventType::KeyDown;
    String text = WebCore::textFromEvent(event, replacesSoftSpace);
    String unmodifiedText = WebCore::unmodifiedTextFromEvent(event, replacesSoftSpace);
    String key = WebCore::keyForKeyEvent(event);
    String code = WebCore::codeForKeyEvent(event);
    String keyIdentifier = WebCore::keyIdentifierForKeyEvent(event);
    int windowsVirtualKeyCode = WebCore::windowsKeyCodeForKeyEvent(event);
    int nativeVirtualKeyCode = [event keyCode];
    int macCharCode = WebCore::keyCharForEvent(event);
    bool autoRepeat = [event type] != NSEventTypeFlagsChanged && [event isARepeat];
    bool isKeypad = WebCore::isKeypadEvent(event);
    bool isSystemKey = false; // SystemKey is always false on the Mac.
    auto modifiers = kit(WebCore::modifiersForEvent(event));
    auto timestamp = MonotonicTime::fromRawSeconds(event.timestamp);

    // Always use 13 for Enter/Return -- we don't want to use AppKit's different character for Enter.
    if (windowsVirtualKeyCode == VK_RETURN) {
        text = "\r"_s;
        unmodifiedText = text;
    }

    // AppKit sets text to "\x7F" for backspace, but the correct KeyboardEvent character code is 8.
    if (windowsVirtualKeyCode == VK_BACK) {
        text = "\x8"_s;
        unmodifiedText = text;
    }

    // Always use 9 for Tab -- we don't want to use AppKit's different character for shift-tab.
    if (windowsVirtualKeyCode == VK_TAB) {
        text = "\x9"_s;
        unmodifiedText = text;
    }

    // Driftstack iOS soft-keyboard KeyboardEvent shape (anti-detection fingerprint surface).
    //
    // This Mac WebKit runs as an iPhone archetype and is driven by WebDriver synthetic keys
    // (WebAutomationSession::platformSimulateKeyboardInteraction / platformSimulateKeySequence
    // → AppKit NSEvent → here). On a desktop Mac that yields the PHYSICAL-keyboard JS shape
    // (e.g. typing 'q' → KeyboardEvent.code "KeyQ", keyCode/which 81). Real iPhone Safari has no
    // physical keyboard: its on-screen soft keyboard inputs characters through the IME/text-input
    // path, so for a character key the JS KeyboardEvent reports an EMPTY code (no physical key),
    // keyCode/which 229 (VK_PROCESSKEY, the IME "process" code) on keydown/keyup, and the keypress
    // carries the character code (matching Mac). Control keys keep their iOS keyCodes (Enter 13,
    // Backspace 8, Tab 9, Space 32, ArrowLeft/Up/Right/Down 37/38/39/40) but also report an empty
    // code. Fingerprinters read code/keyCode/which to tell a desktop keyboard from an iOS soft
    // keyboard, so emitting the desktop shape is a tell. Mirror PlatformEventFactoryIOS.mm: iOS
    // never reports the "KeyX" physical code for soft-keyboard input.
    //
    // Gated default-ON via DRIFTSTACK_IOS_KEYBOARD_EVENT (disabled only when explicitly "0"); applies
    // only to KeyDown/KeyUp (not FlagsChanged, which iOS uses for bare modifier keys). The shape is
    // applied to the JS-visible fields (code/keyIdentifier and, for character keys, windowsVirtualKeyCode
    // == JS keyCode/which). nativeVirtualKeyCode/macCharCode/text are left intact so editing/IME and the
    // keypress character path keep working exactly as before.
    static const bool driftstackIOSKeyboardEvent = [] {
        const char* env = getenv("DRIFTSTACK_IOS_KEYBOARD_EVENT");
        return !env || env[0] != '0'; // default-ON
    }();
    if (driftstackIOSKeyboardEvent && (type == WebEventType::KeyDown || type == WebEventType::KeyUp)) {
        // Control/navigation keys that real iOS keeps with their own keyCode (but still empty code).
        bool isNamedControlKey = false;
        switch (windowsVirtualKeyCode) {
        case VK_RETURN:   // Enter / Return -> 13
        case VK_BACK:     // Backspace -> 8
        case VK_TAB:      // Tab -> 9
        case VK_SPACE:    // Space -> 32 (a character, but a named key)
        case VK_LEFT:     // ArrowLeft -> 37
        case VK_UP:       // ArrowUp -> 38
        case VK_RIGHT:    // ArrowRight -> 39
        case VK_DOWN:     // ArrowDown -> 40
        case VK_ESCAPE:   // Escape -> 27
            isNamedControlKey = true;
            break;
        default:
            break;
        }

        // iOS soft-keyboard input never carries a physical-key `code`; KeyboardEvent.code is "".
        code = emptyString();
        // keyIdentifier is the legacy sibling of code; iOS reports it empty for the same reason.
        keyIdentifier = emptyString();

        if (!isNamedControlKey) {
            // Character keys (letters/digits/symbols): the soft keyboard routes through the IME, so
            // keydown/keyup report the "process" keyCode 229. The keypress (Char type, dispatched
            // downstream from `text`) is unaffected and still carries the character code, matching iOS.
            windowsVirtualKeyCode = VK_PROCESSKEY; // 0xE5 == 229
        }
        // Named control keys keep their existing windowsVirtualKeyCode (13/8/9/32/37-40/27) — that already
        // matches real iOS — and only their code/keyIdentifier are emptied above.
    }

    return WebKeyboardEvent({ type, modifiers, timestamp, WTF::UUID::createVersion4() }, text, unmodifiedText, key, code, keyIdentifier, windowsVirtualKeyCode, nativeVirtualKeyCode, macCharCode, handledByInputMethod, commands, autoRepeat, isKeypad, isSystemKey);
}

NSEventModifierFlags WebEventFactory::toNSEventModifierFlags(OptionSet<WebKit::WebEventModifier> modifiers)
{
    NSEventModifierFlags modifierFlags = 0;
    if (modifiers.contains(WebKit::WebEventModifier::CapsLockKey))
        modifierFlags |= NSEventModifierFlagCapsLock;
    if (modifiers.contains(WebKit::WebEventModifier::ShiftKey))
        modifierFlags |= NSEventModifierFlagShift;
    if (modifiers.contains(WebKit::WebEventModifier::ControlKey))
        modifierFlags |= NSEventModifierFlagControl;
    if (modifiers.contains(WebKit::WebEventModifier::AltKey))
        modifierFlags |= NSEventModifierFlagOption;
    if (modifiers.contains(WebKit::WebEventModifier::MetaKey))
        modifierFlags |= NSEventModifierFlagCommand;
    return modifierFlags;
}

NSInteger WebEventFactory::toNSButtonNumber(WebKit::WebMouseEventButton mouseButton)
{
    switch (mouseButton) {
    case WebKit::WebMouseEventButton::None:
        return 0;
    case WebKit::WebMouseEventButton::Left:
        return 1 << 0;
    case WebKit::WebMouseEventButton::Right:
        return 1 << 1;
    case WebKit::WebMouseEventButton::Middle:
        return 1 << 2;
    case WebKit::WebMouseEventButton::Back:
        return 1 << 3;
    case WebKit::WebMouseEventButton::Forward:
        return 1 << 4;
    }
    ASSERT_NOT_REACHED();
    return 0;
}

} // namespace WebKit

#endif // USE(APPKIT)
