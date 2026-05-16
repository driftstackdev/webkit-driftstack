/*
 * DriftstackArchetypeConfig.mm — implementation of per-iOS profile loader.
 * See header for design context.
 */

#include "config.h"
#include "DriftstackArchetypeConfig.h"

#if PLATFORM(DRIFTSTACK)

#import <Foundation/Foundation.h>
#include <wtf/JSONValues.h>
#include <wtf/NeverDestroyed.h>
#include <wtf/StdLibExtras.h>
#include <wtf/text/WTFString.h>

namespace WebCore {

DriftstackArchetypeConfig& DriftstackArchetypeConfig::singleton()
{
    static NeverDestroyed<DriftstackArchetypeConfig> s_instance;
    return s_instance.get();
}

DriftstackArchetypeConfig::DriftstackArchetypeConfig()
{
    loadFromEnv();
}

void DriftstackArchetypeConfig::reload()
{
    m_loaded = false;
    m_archetypeId = String();
    loadFromEnv();
}

void DriftstackArchetypeConfig::loadFromEnv()
{
    const char* envPath = getenv("DRIFTSTACK_ARCHETYPE_CONFIG_PATH");
    if (!envPath || !envPath[0]) {
        // Backwards-compat: silently no-op. Existing individual env vars
        // (DRIFTSTACK_FONTS_DIR etc.) remain authoritative.
        return;
    }

    NSString* nsPath = [NSString stringWithUTF8String:envPath];
    if (![[NSFileManager defaultManager] fileExistsAtPath:nsPath]) {
        NSLog(@"[Driftstack-ArchetypeConfig] file not found: %s", envPath);
        return;
    }

    NSError* error = nil;
    NSString* nsContents = [NSString stringWithContentsOfFile:nsPath encoding:NSUTF8StringEncoding error:&error];
    if (!nsContents) {
        NSLog(@"[Driftstack-ArchetypeConfig] read failed: %@", error.localizedDescription);
        return;
    }

    String jsonText { nsContents };
    if (!parseJSON(jsonText)) {
        NSLog(@"[Driftstack-ArchetypeConfig] JSON parse failed for %s", envPath);
        return;
    }

    m_loaded = true;
    NSLog(@"[Driftstack-ArchetypeConfig] loaded archetype='%s' iOS=%s Safari=%s device='%s'",
        m_archetypeId.utf8().data(),
        m_iosVersion.utf8().data(),
        m_safariVersion.utf8().data(),
        m_deviceModel.utf8().data());
}

static String getString(JSON::Object& obj, ASCIILiteral key)
{
    auto v = obj.getValue(key);
    if (!v)
        return String();
    if (auto s = v->asString())
        return *s;
    return String();
}

static int getInt(JSON::Object& obj, ASCIILiteral key, int defaultVal = 0)
{
    auto v = obj.getValue(key);
    if (!v)
        return defaultVal;
    if (auto n = v->asInteger())
        return *n;
    if (auto n = v->asDouble())
        return static_cast<int>(*n);
    return defaultVal;
}

static double getDouble(JSON::Object& obj, ASCIILiteral key, double defaultVal = 0.0)
{
    auto v = obj.getValue(key);
    if (!v)
        return defaultVal;
    if (auto n = v->asDouble())
        return *n;
    if (auto n = v->asInteger())
        return static_cast<double>(*n);
    return defaultVal;
}

bool DriftstackArchetypeConfig::parseJSON(const String& jsonText)
{
    auto rootValue = JSON::Value::parseJSON(StringView { jsonText });
    if (!rootValue)
        return false;
    auto rootObj = rootValue->asObject();
    if (!rootObj)
        return false;

    m_archetypeId = getString(*rootObj, "archetype_id"_s);

    // os {...}
    if (auto osValue = rootObj->getValue("os"_s)) {
        if (auto os = osValue->asObject()) {
            m_iosVersion = getString(*os, "ios_version"_s);
            m_iosBuild = getString(*os, "ios_build"_s);
            m_safariVersion = getString(*os, "safari_version"_s);
            m_webkitVersion = getString(*os, "webkit_version"_s);
        }
    }

    // device {...}
    if (auto deviceValue = rootObj->getValue("device"_s)) {
        if (auto device = deviceValue->asObject()) {
            m_deviceModel = getString(*device, "model"_s);
            m_deviceClass = getString(*device, "device_class"_s);
            m_screenWidth = getInt(*device, "screen_width"_s);
            m_screenHeight = getInt(*device, "screen_height"_s);
            m_devicePixelRatio = getDouble(*device, "device_pixel_ratio"_s);
            m_hardwareConcurrency = getInt(*device, "hardware_concurrency"_s);
            m_memoryGB = getInt(*device, "memory_gb"_s);
            m_screenColorDepth = getInt(*device, "screen_color_depth"_s);
            m_screenColorDepthPerComponent = getInt(*device, "screen_color_depth_per_component"_s);
        }
    }

    // user_agent {...}
    if (auto uaValue = rootObj->getValue("user_agent"_s)) {
        if (auto ua = uaValue->asObject()) {
            m_userAgentFull = getString(*ua, "value"_s);
            if (auto chValue = ua->getValue("client_hints"_s)) {
                if (auto ch = chValue->asObject()) {
                    m_clientHintsPlatform = getString(*ch, "platform"_s);
                    m_clientHintsPlatformVersion = getString(*ch, "platform_version"_s);
                    m_clientHintsMobile = getString(*ch, "mobile"_s);
                }
            }
        }
    }

    // locale {...}
    if (auto localeValue = rootObj->getValue("locale"_s)) {
        if (auto locale = localeValue->asObject()) {
            m_lang = getString(*locale, "lang"_s);
            m_timezone = getString(*locale, "tz"_s);
            m_timezoneDisplay = getString(*locale, "tz_display"_s);
            m_lcAll = getString(*locale, "lc_all"_s);
        }
    }

    // safe_area_inset {...}
    if (auto saValue = rootObj->getValue("safe_area_inset"_s)) {
        if (auto sa = saValue->asObject()) {
            m_safeAreaInsetTop = getInt(*sa, "top"_s);
            m_safeAreaInsetRight = getInt(*sa, "right"_s);
            m_safeAreaInsetBottom = getInt(*sa, "bottom"_s);
            m_safeAreaInsetLeft = getInt(*sa, "left"_s);
        }
    }

    // webgpu {...}
    if (auto wgpuValue = rootObj->getValue("webgpu"_s)) {
        if (auto wgpu = wgpuValue->asObject()) {
            m_webgpuVendor = getString(*wgpu, "vendor"_s);
            m_webgpuArchitecture = getString(*wgpu, "architecture"_s);
            m_webgpuDevice = getString(*wgpu, "device"_s);
            m_webgpuDescription = getString(*wgpu, "description"_s);
        }
    }

    // apple_pay { set_up: true/false } — Slice 244.2 / file 99 V2 correction.
    // Per-session Phase 2 value. JSON may omit (defaults false). Future:
    // seed via probability distribution per archetype (~60-70% set_up for
    // consumer iPhone). Env var DRIFTSTACK_APPLE_PAY_SET_UP=1 forces true
    // (test override).
    if (auto apValue = rootObj->getValue("apple_pay"_s)) {
        if (auto ap = apValue->asObject()) {
            if (auto v = ap->getValue("set_up"_s)) {
                if (auto b = v->asBoolean())
                    m_applePaySetUp = *b;
            }
        }
    }
    if (const char* env = getenv("DRIFTSTACK_APPLE_PAY_SET_UP")) {
        if (env[0] == '1') m_applePaySetUp = true;
        else if (env[0] == '0') m_applePaySetUp = false;
    }

    // storage { quota_bytes, quota_variance_percent } — Slice 244.9 /
    // file 99 S11 / file 110 § Storage quota. Per-session value seeded
    // from archetype profile (60% × disk-size-class). Defaults to 0
    // (inherit existing V-072 fallback halving).
    if (auto stValue = rootObj->getValue("storage"_s)) {
        if (auto st = stValue->asObject()) {
            if (auto v = st->getValue("quota_bytes"_s)) {
                if (auto n = v->asInteger())
                    m_storageQuotaBytes = static_cast<uint64_t>(*n);
            }
            m_storageQuotaVariancePercent = getInt(*st, "quota_variance_percent"_s);
        }
    }

    // fonts {...}
    if (auto fontsValue = rootObj->getValue("fonts"_s)) {
        if (auto fonts = fontsValue->asObject()) {
            m_fontsDir = getString(*fonts, "stage_b_install_path"_s);
            m_voicesListPath = getString(*fonts, "voices_list_path"_s);
        }
    }

    // v185_atlas_archetype_key (top-level)
    m_v185AtlasKey = getString(*rootObj, "v185_atlas_archetype_key"_s);

    // _source / capture_source (best-effort)
    m_captureSource = getString(*rootObj, "_source"_s);
    if (m_captureSource.isEmpty())
        m_captureSource = getString(*rootObj, "_v_log"_s);

    return true;
}

} // namespace WebCore

#endif // PLATFORM(DRIFTSTACK)
