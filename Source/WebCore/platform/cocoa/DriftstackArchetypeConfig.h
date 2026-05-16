/*
 * DriftstackArchetypeConfig.h — per-iOS profile (Phase 2) configuration loader.
 *
 * Loads the JSON archetype config (e.g. operations/archetypes/
 * iphone16pro_ios18_7_safari26_4.json) at WebProcess startup via the
 * DRIFTSTACK_ARCHETYPE_CONFIG_PATH env var. Provides typed accessors
 * for every Phase 2 surface (per docs/planning/105-three-phase-injection-architecture.md):
 *   - User-Agent components
 *   - Device model + screen + DPR
 *   - Navigator properties (maxTouchPoints, hardwareConcurrency, deviceMemory)
 *   - WebGPU adapter.info + adapter.limits
 *   - WebGL renderer + extensions
 *   - Speech voices list
 *   - MediaCapabilities support matrix
 *   - safe-area-inset values
 *   - Atlas paths (per-archetype binary)
 *
 * Backwards-compat: when env var unset or parse fails, every accessor
 * returns a sentinel (empty string / 0). Existing individual DRIFTSTACK_*
 * env vars (e.g. DRIFTSTACK_FONTS_DIR) remain authoritative — this loader
 * supplies values for surfaces not yet wired through env vars.
 *
 * Per CLAUDE.md three-phase injection architecture: this is Phase 2
 * (process-startup, per-session-stable). Build-time (Phase 1) values
 * live in DriftstackBuildConstants.h. Runtime (Phase 3) per-call values
 * live in AFP / behavioral model code.
 *
 * Spec: docs/planning/101-archetype-configuration-system.md
 *       docs/planning/105-three-phase-injection-architecture.md
 *       docs/planning/99-complete-signal-implementation-matrix.md
 */

#pragma once

#if PLATFORM(DRIFTSTACK)

#include <wtf/Forward.h>
#include <wtf/text/WTFString.h>

namespace WebCore {

class DriftstackArchetypeConfig {
public:
    static DriftstackArchetypeConfig& singleton();

    bool isLoaded() const { return m_loaded; }
    bool isValid() const { return m_loaded && !m_archetypeId.isEmpty(); }

    // Identification
    String archetypeId() const { return m_archetypeId; }
    String captureSource() const { return m_captureSource; }

    // OS / Safari versions
    String iosVersion() const { return m_iosVersion; }      // e.g. "18.7"
    String iosBuild() const { return m_iosBuild; }          // e.g. "22F75"
    String safariVersion() const { return m_safariVersion; } // e.g. "26.4"
    String webkitVersion() const { return m_webkitVersion; } // e.g. "625.1.16"

    // Device
    String deviceModel() const { return m_deviceModel; }    // e.g. "iPhone 16 Pro"
    String deviceClass() const { return m_deviceClass; }    // e.g. "phone"
    int screenWidth() const { return m_screenWidth; }       // CSS px
    int screenHeight() const { return m_screenHeight; }     // CSS px
    double devicePixelRatio() const { return m_devicePixelRatio; }
    int hardwareConcurrency() const { return m_hardwareConcurrency; }
    int memoryGB() const { return m_memoryGB; }
    int screenColorDepth() const { return m_screenColorDepth; }
    int screenColorDepthPerComponent() const { return m_screenColorDepthPerComponent; }

    // User-Agent
    String userAgentFull() const { return m_userAgentFull; }
    String clientHintsPlatform() const { return m_clientHintsPlatform; }
    String clientHintsPlatformVersion() const { return m_clientHintsPlatformVersion; }
    String clientHintsMobile() const { return m_clientHintsMobile; }

    // Locale
    String lang() const { return m_lang; }                  // e.g. "en-US"
    String timezone() const { return m_timezone; }          // e.g. "Europe/Istanbul"
    String timezoneDisplay() const { return m_timezoneDisplay; }
    String lcAll() const { return m_lcAll; }

    // safe-area-inset
    int safeAreaInsetTop() const { return m_safeAreaInsetTop; }
    int safeAreaInsetRight() const { return m_safeAreaInsetRight; }
    int safeAreaInsetBottom() const { return m_safeAreaInsetBottom; }
    int safeAreaInsetLeft() const { return m_safeAreaInsetLeft; }

    // WebGPU
    String webgpuVendor() const { return m_webgpuVendor; }          // "apple"
    String webgpuArchitecture() const { return m_webgpuArchitecture; } // "apple"
    String webgpuDevice() const { return m_webgpuDevice; }          // "apple"
    String webgpuDescription() const { return m_webgpuDescription; } // "apple"

    // Apple Pay (Slice 244.2 / file 99 V2 / file 110 § Apple Pay):
    // canMakePayments() varies per real iPhone user — true if Apple Pay
    // set up (iCloud + Wallet has card), false otherwise. Per-session
    // Phase 2 value seeded from archetype profile probability distribution.
    bool applePaySetUp() const { return m_applePaySetUp; }

    // Resource paths (per-archetype binaries)
    String fontsDir() const { return m_fontsDir; }
    String voicesListPath() const { return m_voicesListPath; }
    String v185AtlasKey() const { return m_v185AtlasKey; }

    // Re-load (e.g. after env var change). Generally not needed; called from constructor.
    void reload();

    DriftstackArchetypeConfig();

private:
    ~DriftstackArchetypeConfig() = default;
    DriftstackArchetypeConfig(const DriftstackArchetypeConfig&) = delete;
    DriftstackArchetypeConfig& operator=(const DriftstackArchetypeConfig&) = delete;

    void loadFromEnv();
    bool parseJSON(const String&);

    bool m_loaded { false };

    // Identification
    String m_archetypeId;
    String m_captureSource;

    // OS / Safari
    String m_iosVersion;
    String m_iosBuild;
    String m_safariVersion;
    String m_webkitVersion;

    // Device
    String m_deviceModel;
    String m_deviceClass;
    int m_screenWidth { 0 };
    int m_screenHeight { 0 };
    double m_devicePixelRatio { 0.0 };
    int m_hardwareConcurrency { 0 };
    int m_memoryGB { 0 };
    int m_screenColorDepth { 0 };
    int m_screenColorDepthPerComponent { 0 };

    // UA
    String m_userAgentFull;
    String m_clientHintsPlatform;
    String m_clientHintsPlatformVersion;
    String m_clientHintsMobile;

    // Locale
    String m_lang;
    String m_timezone;
    String m_timezoneDisplay;
    String m_lcAll;

    // safe-area
    int m_safeAreaInsetTop { 0 };
    int m_safeAreaInsetRight { 0 };
    int m_safeAreaInsetBottom { 0 };
    int m_safeAreaInsetLeft { 0 };

    // WebGPU
    String m_webgpuVendor;
    String m_webgpuArchitecture;
    String m_webgpuDevice;
    String m_webgpuDescription;

    // Apple Pay (Slice 244.2)
    bool m_applePaySetUp { false };

    // Resource paths
    String m_fontsDir;
    String m_voicesListPath;
    String m_v185AtlasKey;
};

} // namespace WebCore

#endif // PLATFORM(DRIFTSTACK)
