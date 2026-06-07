/*
 * WebDriverServiceCocoa.cpp — Driftstack item-9: the cocoa platform implementation of WebDriverService.
 *
 * The GLib/WPE/Win/PlayStation ports each provide these platform hooks; the cocoa port never did
 * (WebDriver is normally GTK/socket-only upstream). When the WD service is compiled into MiniBrowser
 * for the in-process drive-bridge, the linker needs a cocoa definition of each. This is intentionally
 * minimal: Driftstack drives an ALREADY-RUNNING MiniBrowser in-process (the session is bound to the
 * window's WKWebView via _WKAutomationSession), so there is no browser to launch/validate/configure.
 * Mirrors the trivial branches of WebDriverServiceGtk.cpp + WebDriverServiceGLib.cpp.
 */

#include "config.h"
#include "WebDriverService.h"

#include "Capabilities.h"
#include <wtf/JSONValues.h>

namespace WebDriver {

void WebDriverService::platformInit()
{
}

Capabilities WebDriverService::platformCapabilities()
{
    Capabilities capabilities;
    capabilities.platformName = String("mac"_s);
    capabilities.setWindowRect = true;
    return capabilities;
}

bool WebDriverService::platformValidateCapability(const String&, const Ref<JSON::Value>&) const
{
    // No Driftstack-specific browserOptions to validate (we don't launch a browser).
    return true;
}

bool WebDriverService::platformMatchCapability(const String&, const Ref<JSON::Value>&) const
{
    return true;
}

void WebDriverService::platformParseCapabilities(const JSON::Object&, Capabilities&) const
{
    // Driftstack drives an already-running in-process MiniBrowser; nothing to launch/configure.
}

bool WebDriverService::platformCompareBrowserVersions(const String&, const String&)
{
    // Single launch archetype; accept any requested version (matching is the caller's concern).
    return true;
}

bool WebDriverService::platformSupportBidi() const
{
    // BIDI is disabled for the classic in-process drive (ENABLE_WEBDRIVER_BIDI=0).
    return false;
}

bool WebDriverService::platformSupportProxyType(const String&) const
{
    return true;
}

} // namespace WebDriver
