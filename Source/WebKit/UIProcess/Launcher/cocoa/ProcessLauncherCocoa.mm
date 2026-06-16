/*
 * Copyright (C) 2010-2025 Apple Inc. All rights reserved.
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
#import "ProcessLauncher.h"

#import "AuxiliaryProcess.h"
#import "Logging.h"
#import "MachPort.h"
#import "WebPreferencesDefaultValues.h"
#import "WebProcessPool.h"
#import "XPCUtilities.h"
#import <crt_externs.h>
#import <mach-o/dyld.h>
#import <mach/mach_error.h>
#import <mach/mach_init.h>
#import <mach/mach_traps.h>
#import <mach/machine.h>
#import <pal/spi/cocoa/ServersSPI.h>
#import <spawn.h>
#import <string>
#import <sys/param.h>
#import <sys/stat.h>
#import <wtf/BlockPtr.h>
#import <wtf/FileSystem.h>
#import <wtf/MachSendRight.h>
#import <wtf/RunLoop.h>
#import <wtf/RuntimeApplicationChecks.h>
#import <wtf/SoftLinking.h>
#import <wtf/Threading.h>
#import <wtf/cocoa/RuntimeApplicationChecksCocoa.h>
#import <wtf/darwin/DispatchExtras.h>
#import <wtf/darwin/XPCExtras.h>
#import <wtf/spi/cf/CFBundleSPI.h>
#import <wtf/text/CString.h>
#import <wtf/text/WTFString.h>

#if PLATFORM(MAC)
#import "CodeSigning.h"
#endif

#if USE(EXTENSIONKIT)
#import "AssertionCapability.h"
#import "ExtensionKitSPI.h"
#import <BrowserEngineKit/BENetworkingProcess.h>
#import <BrowserEngineKit/BERenderingProcess.h>
#import <BrowserEngineKit/BEWebContentProcess.h>
#endif // USE(EXTENSIONKIT)

namespace WebKit {

#if USE(EXTENSIONKIT)
static std::pair<ASCIILiteral, RetainPtr<NSString>> serviceNameAndIdentifier(ProcessLauncher::ProcessType processType, ProcessLauncher::Client* client, bool isRetryingLaunch)
{
    bool hasExtensionsInAppBundle = ProcessLauncher::hasExtensionsInAppBundle();
    switch (processType) {
    case ProcessLauncher::ProcessType::Web: {
        bool useCaptivePortal = client && client->shouldEnableLockdownMode();
        bool useEnhancedSecurity = client && client->shouldEnableEnhancedSecurity();
        if (!hasExtensionsInAppBundle) {
            if (!useCaptivePortal && !useEnhancedSecurity)
                return { "com.apple.WebKit.WebContent"_s, @"com.apple.WebKit.WebContent" };

            if (useEnhancedSecurity)
                return { "com.apple.WebKit.WebContent"_s, @"com.apple.WebKit.WebContent.EnhancedSecurity" };

            return { "com.apple.WebKit.WebContent"_s, @"com.apple.WebKit.WebContent.CaptivePortal" };
        }
        NSString *webContentAppex = nil;

        if (useCaptivePortal)
            webContentAppex = @"WebContentCaptivePortalExtension";
        else if (useEnhancedSecurity)
            webContentAppex = @"WebContentEnhancedSecurityExtension";
        else
            webContentAppex = @"WebContentExtension";

        return { "com.apple.WebKit.WebContent"_s, [NSString stringWithFormat:@"%@.%@", [[NSBundle mainBundle] bundleIdentifier], webContentAppex] };
    }
    case ProcessLauncher::ProcessType::Network:
        if (!hasExtensionsInAppBundle)
            return { "com.apple.WebKit.Networking"_s, @"com.apple.WebKit.Networking" };
        return { "com.apple.WebKit.Networking"_s, [NSString stringWithFormat:@"%@.NetworkingExtension", [[NSBundle mainBundle] bundleIdentifier]] };
#if ENABLE(GPU_PROCESS)
    case ProcessLauncher::ProcessType::GPU:
        if (!hasExtensionsInAppBundle)
            return { "com.apple.WebKit.GPU"_s, @"com.apple.WebKit.GPU" };
        return { "com.apple.WebKit.GPU"_s, [NSString stringWithFormat:@"%@.GPUExtension", [[NSBundle mainBundle] bundleIdentifier]] };
#endif
    }
}

bool ProcessLauncher::hasExtensionsInAppBundle()
{
#if PLATFORM(IOS)
    static bool hasExtensions = [[NSBundle mainBundle] pathForResource:@"WebContentExtension" ofType:@"appex" inDirectory:@"Extensions"]
            && [[NSBundle mainBundle] pathForResource:@"NetworkingExtension" ofType:@"appex" inDirectory:@"Extensions"]
            && [[NSBundle mainBundle] pathForResource:@"GPUExtension" ofType:@"appex" inDirectory:@"Extensions"];
    return hasExtensions;
#else
    return false;
#endif
}

static void launchWithExtensionKit(ProcessLauncher& processLauncher, ProcessLauncher::ProcessType processType, ProcessLauncher::Client* client, WTF::Function<void(ThreadSafeWeakPtr<ProcessLauncher> weakProcessLauncher, ExtensionProcess&& process, ASCIILiteral name, NSError *error)>&& handler)
{
    auto [name, identifier] = serviceNameAndIdentifier(processType, client, processLauncher.isRetryingLaunch());

    switch (processType) {
    case ProcessLauncher::ProcessType::Web: {
        auto block = makeBlockPtr([handler = WTF::move(handler), weakProcessLauncher = ThreadSafeWeakPtr { processLauncher }, name = name](BEWebContentProcess *_Nullable process, NSError *_Nullable error) mutable {
            handler(WTF::move(weakProcessLauncher), process, name, error);
        });
        [BEWebContentProcess webContentProcessWithBundleID:identifier.get() interruptionHandler:^{ } completion:block.get()];
        break;
    }
    case ProcessLauncher::ProcessType::Network: {
        auto block = makeBlockPtr([handler = WTF::move(handler), weakProcessLauncher = ThreadSafeWeakPtr { processLauncher }, name = name](BENetworkingProcess *_Nullable process, NSError *_Nullable error) mutable {
            handler(WTF::move(weakProcessLauncher), process, name, error);
        });
        [BENetworkingProcess networkProcessWithBundleID:identifier.get() interruptionHandler:^{ } completion:block.get()];
        break;
    }
    case ProcessLauncher::ProcessType::GPU: {
        auto block = makeBlockPtr([handler = WTF::move(handler), weakProcessLauncher = ThreadSafeWeakPtr { processLauncher }, name = name](BERenderingProcess *_Nullable process, NSError *_Nullable error) mutable {
            handler(WTF::move(weakProcessLauncher), process, name, error);
        });
        [BERenderingProcess renderingProcessWithBundleID:identifier.get() interruptionHandler:^{ } completion:block.get()];
        break;
    }
    }
}
#endif // USE(EXTENSIONKIT)

#if !USE(EXTENSIONKIT) || !PLATFORM(IOS)
static ASCIILiteral webContentServiceName(const ProcessLauncher::LaunchOptions& launchOptions, ProcessLauncher::Client* client)
{
    bool useCaptivePortal = client && client->shouldEnableLockdownMode();
    bool useEnhancedSecurity = client && client->shouldEnableEnhancedSecurity();

    if (useCaptivePortal)
        return "com.apple.WebKit.WebContent.CaptivePortal"_s;

    if (useEnhancedSecurity)
        return "com.apple.WebKit.WebContent.EnhancedSecurity"_s;

    return launchOptions.nonValidInjectedCodeAllowed ? "com.apple.WebKit.WebContent.Development"_s : "com.apple.WebKit.WebContent"_s;
}

static ASCIILiteral serviceName(const ProcessLauncher::LaunchOptions& launchOptions, ProcessLauncher::Client* client)
{
    switch (launchOptions.processType) {
    case ProcessLauncher::ProcessType::Web:
        return webContentServiceName(launchOptions, client);
    case ProcessLauncher::ProcessType::Network:
        return "com.apple.WebKit.Networking"_s;
#if ENABLE(GPU_PROCESS)
    case ProcessLauncher::ProcessType::GPU:
        return "com.apple.WebKit.GPU"_s;
#endif
#if ENABLE(MODEL_PROCESS)
    case ProcessLauncher::ProcessType::Model:
        return "com.apple.WebKit.Model"_s;
#endif
    }
}
#endif // !USE(EXTENSIONKIT) || !PLATFORM(IOS)

#if USE(EXTENSIONKIT)
Ref<LaunchGrant> LaunchGrant::create(ExtensionProcess& process)
{
    return adoptRef(*new LaunchGrant(process));
}

LaunchGrant::LaunchGrant(ExtensionProcess& process)
{
    AssertionCapability capability(emptyString(), "com.apple.webkit"_s, "Foreground"_s);
    auto grant = process.grantCapability(capability.platformCapability());
    m_grant.setPlatformGrant(WTF::move(grant));
}

LaunchGrant::~LaunchGrant()
{
    m_grant.invalidate();
}
#endif

void ProcessLauncher::platformDestroy()
{
#if USE(EXTENSIONKIT)
    if (m_process)
        m_process->invalidate();
#endif
}

void ProcessLauncher::launchProcess()
{
    ASSERT(!m_xpcConnection);

#if USE(EXTENSIONKIT)
    auto handler = [](ThreadSafeWeakPtr<ProcessLauncher> weakProcessLauncher, ExtensionProcess&& process, ASCIILiteral name, NSError *error)
    {
        if (error) {
            RELEASE_LOG_FAULT(Process, "Error launching process, description '%s', reason '%s'", String([error localizedDescription]).utf8().data(), String([error localizedFailureReason]).utf8().data());
#if PLATFORM(IOS)
            // Fallback to legacy extension identifiers
            // FIXME: this fallback is temporary and should be removed when possible. See rdar://120793705.
            callOnMainRunLoop([weakProcessLauncher = weakProcessLauncher] {
                auto launcher = weakProcessLauncher.get();
                if (!launcher || launcher->isRetryingLaunch())
                    return;
                launcher->setIsRetryingLaunch();
                launcher->launchProcess();
            });
#else
            // Fallback to XPC service launch
            callOnMainRunLoop([weakProcessLauncher = weakProcessLauncher] {
                auto launcher = weakProcessLauncher.get();
                if (!launcher)
                    return;
                auto name = serviceName(launcher->m_launchOptions, launcher->m_client);
                // FIXME: This is a false positive. <rdar://164843889>
                SUPPRESS_RETAINPTR_CTOR_ADOPT launcher->m_xpcConnection = adoptOSObject(xpc_connection_create(name, nullptr));
                launcher->finishLaunchingProcess(name);
            });
#endif
            process.invalidate();
            return;
        }

        Ref launchGrant = LaunchGrant::create(process);

        callOnMainRunLoop([weakProcessLauncher, name, process = WTF::move(process), launchGrant = WTF::move(launchGrant)] () mutable {
            RefPtr launcher = weakProcessLauncher.get();
            // If m_client is null, the Process launcher has been invalidated, and we should not proceed with the launch.
            if (!launcher || !launcher->m_client) {
                process.invalidate();
                return;
            }

            auto xpcConnection = process.makeLibXPCConnection();

            if (!xpcConnection) {
                RELEASE_LOG_ERROR(Process, "Failed to make libxpc connection for process");
                process.invalidate();
                launcher->didFinishLaunchingProcess(0, { });
                return;
            }

            launcher->m_xpcConnection = WTF::move(xpcConnection);
            launcher->m_process = WTF::move(process);
            launcher->m_launchGrant = WTF::move(launchGrant);
            launcher->finishLaunchingProcess(name);
        });
    };

    launchWithExtensionKit(*this, m_launchOptions.processType, m_client.get(), WTF::move(handler));
#else
    auto name = serviceName(m_launchOptions, m_client.get());
    // FIXME: This is a false positive. <rdar://164843889>
    SUPPRESS_RETAINPTR_CTOR_ADOPT m_xpcConnection = adoptOSObject(xpc_connection_create(name, nullptr));
    finishLaunchingProcess(name);
#endif
}

void ProcessLauncher::finishLaunchingProcess(ASCIILiteral name, int retriesRemaining)
{
    tryFinishLaunchingProcess(name, [weakThis = ThreadSafeWeakPtr { *this }, name, retriesRemaining]() mutable {
        // FIXME(rdar://173715411): optional workaround for intermittent launch failures
        // if binaries are huge (for example if code coverage has been enabled)
#if !USE(EXTENSIONKIT) && ENABLE(RETRY_LAUNCHES)
        if (retriesRemaining > 0) {
            RefPtr processLauncher = weakThis.get();
            if (!processLauncher)
                return;
            LOG_ERROR("Retrying launch of %s (%d retries remaining)", name.characters(), retriesRemaining - 1);
            // Each new launch requires a new XPC connection. tryFinishLaunchingProcess destroyed
            // the previous one.
            // FIXME: This is a false positive. <rdar://164843889>
            SUPPRESS_RETAINPTR_CTOR_ADOPT processLauncher->m_xpcConnection = adoptOSObject(xpc_connection_create(name, nullptr));
            processLauncher->finishLaunchingProcess(name, retriesRemaining - 1);
            return;
        }
#else
        UNUSED_PARAM(retriesRemaining);
        UNUSED_PARAM(name);
#endif
        RefPtr processLauncher = weakThis.get();
        if (!processLauncher)
            return;
        processLauncher->didFinishLaunchingProcess(0, IPC::Connection::Identifier());
    });
}

void ProcessLauncher::tryFinishLaunchingProcess(ASCIILiteral name, Function<void()>&& onFailure)
{
    uuid_t uuid;
    uuid_generate(uuid);

    xpc_connection_set_oneshot_instance(m_xpcConnection.get(), uuid);

    // Inherit UI process localization. It can be different from child process default localization:
    // 1. When the application and system frameworks simply have different localized resources available, we should match the application.
    // 1.1. An important case is WebKitTestRunner, where we should use English localizations for all system frameworks.
    // 2. When AppleLanguages is passed as command line argument for UI process, or set in its preferences, we should respect it in child processes.
#if !USE(EXTENSIONKIT)
    // FIXME: This is a false positive. <rdar://164843889>
    SUPPRESS_RETAINPTR_CTOR_ADOPT auto initializationMessage = adoptOSObject(xpc_dictionary_create(nullptr, nullptr, 0));
    _CFBundleSetupXPCBootstrap(initializationMessage.get());
    xpc_connection_set_bootstrap(m_xpcConnection.get(), initializationMessage.get());
#endif

    // Create the listening port.
    mach_port_t listeningPort = MACH_PORT_NULL;
    auto kr = IPC::allocateImmovableConnectionPort(&listeningPort);
    if (kr != KERN_SUCCESS) {
        RELEASE_LOG_ERROR(IPC, "Could not allocate mach port, error: %{private}s (%x)", mach_error_string(kr), kr);
        CRASH();
    }

    // Insert a send right so we can send to it.
    mach_port_insert_right(mach_task_self(), listeningPort, listeningPort, MACH_MSG_TYPE_MAKE_SEND);

    mach_port_t previousNotificationPort = MACH_PORT_NULL;
    auto mc = mach_port_request_notification(mach_task_self(), listeningPort, MACH_NOTIFY_NO_SENDERS, 0, listeningPort, MACH_MSG_TYPE_MAKE_SEND_ONCE, &previousNotificationPort);
    ASSERT(!previousNotificationPort);
    ASSERT(mc == KERN_SUCCESS);
    if (mc != KERN_SUCCESS) {
        // If mach_port_request_notification fails, 'previousNotificationPort' will be uninitialized.
        LOG_ERROR("mach_port_request_notification failed: (%x) %s", mc, mach_error_string(mc));
    }

    String clientIdentifier;
#if PLATFORM(MAC)
    clientIdentifier = codeSigningIdentifierForCurrentProcess();
#endif
    if (clientIdentifier.isNull())
        clientIdentifier = [[NSBundle mainBundle] bundleIdentifier];

    // FIXME: Switch to xpc_connection_set_bootstrap once it's available everywhere we need.
    // FIXME: This is a false positive. <rdar://164843889>
    SUPPRESS_RETAINPTR_CTOR_ADOPT auto bootstrapMessage = adoptOSObject(xpc_dictionary_create(nullptr, nullptr, 0));

#if PLATFORM(MAC) || PLATFORM(MACCATALYST)
    xpc_dictionary_set_string(bootstrapMessage.get(), "WebKitBundleVersion", WEBKIT_BUNDLE_VERSION);
#endif

    auto languagesIterator = m_launchOptions.extraInitializationData.find<HashTranslatorASCIILiteral>("OverrideLanguages"_s);
    if (languagesIterator != m_launchOptions.extraInitializationData.end()) {
        LOG_WITH_STREAM(Language, stream << "Process Launcher is copying OverrideLanguages into initialization message: " << languagesIterator->value);
        // FIXME: This is a false positive. <rdar://164843889>
        SUPPRESS_RETAINPTR_CTOR_ADOPT auto languages = adoptOSObject(xpc_array_create(nullptr, 0));
        for (auto language : StringView(languagesIterator->value).split(','))
            xpc_array_set_string(languages.get(), XPC_ARRAY_APPEND, language.utf8().data());
        xpc_dictionary_set_value(bootstrapMessage.get(), "OverrideLanguages", languages.get());
    }

#if PLATFORM(IOS_FAMILY) || PLATFORM(DRIFTSTACK)
    bool isWebContentExtension = false;
#if USE(EXTENSIONKIT)
    isWebContentExtension = (m_launchOptions.processType == ProcessLauncher::ProcessType::Web);
#endif
    if (!isWebContentExtension) {
        // Clients that set these environment variables explicitly do not have the values automatically forwarded by libxpc.
        auto containerEnvironmentVariables = adoptOSObject(xpc_dictionary_create(nullptr, nullptr, 0));
#if PLATFORM(IOS_FAMILY)
        if (const char* environmentHOME = getenv("HOME"))
            xpc_dictionary_set_string(containerEnvironmentVariables.get(), "HOME", environmentHOME);
        if (const char* environmentCFFIXED_USER_HOME = getenv("CFFIXED_USER_HOME"))
            xpc_dictionary_set_string(containerEnvironmentVariables.get(), "CFFIXED_USER_HOME", environmentCFFIXED_USER_HOME);
        if (const char* environmentTMPDIR = getenv("TMPDIR"))
            xpc_dictionary_set_string(containerEnvironmentVariables.get(), "TMPDIR", environmentTMPDIR);
#endif
#if PLATFORM(DRIFTSTACK)
        // Wave 1.8: forward locale + timezone env vars to WebContent process
        // so JSC's Intl + Date implementations honor them. Without this, TZ
        // set in MiniBrowser's parent shell doesn't propagate to the XPC
        // child where JS executes (V-072 cumulative-rig finding: 4
        // date.behavior diffs traced to TZ not propagating).
        const char* environmentTZ = getenv("TZ");
        const char* environmentLANG = getenv("LANG");
        const char* environmentLCALL = getenv("LC_ALL");
        // V-433.Z P-track #46 (wave 29-222): forward log-gate env vars to
        // WebContent process so static-init `getenv("DRIFTSTACK_LOG_*")`
        // gates in inline layout, font init, etc. see the founder-set
        // value. WebContent XPC services don't inherit parent shell env
        // automatically.
        // V-433.Z P-track #46 + TD-V-NNN-J.1 + #41 wave 29-222: forward
        // ALL DRIFTSTACK_* runtime gates. Any new DRIFTSTACK_* env-gated
        // static init in renderer-side code (font/layout/paint/JS/atlas/ML)
        // MUST be added here too, else gate silently no-ops in WebContent.
        struct { const char* name; const char* value; } dsEnv[] = {
            { "DRIFTSTACK_LOG_INLINE_BOX_GEOMETRY", getenv("DRIFTSTACK_LOG_INLINE_BOX_GEOMETRY") },
            { "DRIFTSTACK_LOG_LINE_BOX_HEIGHT", getenv("DRIFTSTACK_LOG_LINE_BOX_HEIGHT") },
            { "DRIFTSTACK_V602_SUBSTITUTE", getenv("DRIFTSTACK_V602_SUBSTITUTE") },
            { "DRIFTSTACK_V433Z_COMBINING_MARK_ZERO", getenv("DRIFTSTACK_V433Z_COMBINING_MARK_ZERO") },
            { "DRIFTSTACK_LAYER_B_ENABLED", getenv("DRIFTSTACK_LAYER_B_ENABLED") },
            { "DRIFTSTACK_LAYER_B_V2_ENABLED", getenv("DRIFTSTACK_LAYER_B_V2_ENABLED") },
            { "DRIFTSTACK_ARCHETYPE_SLUG", getenv("DRIFTSTACK_ARCHETYPE_SLUG") },
            { "DRIFTSTACK_ARCHETYPE_CONFIG_PATH", getenv("DRIFTSTACK_ARCHETYPE_CONFIG_PATH") },
            { "DRIFTSTACK_REFERENCE_DIR", getenv("DRIFTSTACK_REFERENCE_DIR") },
            { "DRIFTSTACK_TEXT_RUN_ATLAS_PATH", getenv("DRIFTSTACK_TEXT_RUN_ATLAS_PATH") },
            { "DRIFTSTACK_TEXT_RUN_ATLAS_DIAG", getenv("DRIFTSTACK_TEXT_RUN_ATLAS_DIAG") },
            { "DRIFTSTACK_CANVAS_FUZZ_ATLAS", getenv("DRIFTSTACK_CANVAS_FUZZ_ATLAS") },
            { "DRIFTSTACK_CANVAS_FP10X_OVERRIDE", getenv("DRIFTSTACK_CANVAS_FP10X_OVERRIDE") },
            { "DRIFTSTACK_GETIMAGEDATA_ATLAS", getenv("DRIFTSTACK_GETIMAGEDATA_ATLAS") },
            // Wave 29-390 (production launch gap closure): forward atlas
            // path + SOCKS5 env vars to WebContent/Network child processes.
            // The harness sets these at MiniBrowser launch; WebContent XPC
            // didn't inherit them so production behavior diverged from
            // cumrig (which uses __XPC_DRIFTSTACK_* shadow vars).
            { "DRIFTSTACK_CANVAS_FUZZ_ATLAS_PATH", getenv("DRIFTSTACK_CANVAS_FUZZ_ATLAS_PATH") },
            { "DRIFTSTACK_SOCKS5_PROXY", getenv("DRIFTSTACK_SOCKS5_PROXY") },
            { "DRIFTSTACK_DIRECT_BROWSE", getenv("DRIFTSTACK_DIRECT_BROWSE") },
            { "DRIFTSTACK_DIRECT_EGRESS", getenv("DRIFTSTACK_DIRECT_EGRESS") },
            { "DRIFTSTACK_REQUIRE_PROXY", getenv("DRIFTSTACK_REQUIRE_PROXY") },
            { "DRIFTSTACK_CUSTOM_SOCKS5", getenv("DRIFTSTACK_CUSTOM_SOCKS5") },
            // Wave 29-396 sub-1.7.3: RFC 1929 user/pass for custom SOCKS5.
            { "DRIFTSTACK_SOCKS5_USER", getenv("DRIFTSTACK_SOCKS5_USER") },
            { "DRIFTSTACK_SOCKS5_PASS", getenv("DRIFTSTACK_SOCKS5_PASS") },
            { "DRIFTSTACK_ARCHETYPE_UA_FULL", getenv("DRIFTSTACK_ARCHETYPE_UA_FULL") },
            { "DRIFTSTACK_APPLE_PAY_SET_UP", getenv("DRIFTSTACK_APPLE_PAY_SET_UP") },
            { "DRIFTSTACK_STORAGE_QUOTA_BYTES", getenv("DRIFTSTACK_STORAGE_QUOTA_BYTES") },
            // Wave 29-390.B comprehensive audit: 30+ DRIFTSTACK_ env vars
            // consumed in fork code but never forwarded. Cumrig didn't catch
            // because cumrig uses __XPC_DRIFTSTACK_* shadow vars; production
            // harness uses unprefixed. Forwarding all production-critical
            // fingerprint env vars per audit Wave 29-390.
            // Atlas binaries:
            { "DRIFTSTACK_AUDIO_ATLAS", getenv("DRIFTSTACK_AUDIO_ATLAS") },
            { "DRIFTSTACK_AUDIO_ATLAS_PATH", getenv("DRIFTSTACK_AUDIO_ATLAS_PATH") },
            { "DRIFTSTACK_ADVANCE_ATLAS_PATH", getenv("DRIFTSTACK_ADVANCE_ATLAS_PATH") },
            { "DRIFTSTACK_ASCII_ATLAS_PATH", getenv("DRIFTSTACK_ASCII_ATLAS_PATH") },
            { "DRIFTSTACK_EMOJI_ATLAS_PATH", getenv("DRIFTSTACK_EMOJI_ATLAS_PATH") },
            { "DRIFTSTACK_COMPOSITE_ATLAS_PATH", getenv("DRIFTSTACK_COMPOSITE_ATLAS_PATH") },
            { "DRIFTSTACK_PER_GLYPH_ATLAS_PATH", getenv("DRIFTSTACK_PER_GLYPH_ATLAS_PATH") },
            { "DRIFTSTACK_TEXT_GLYPH_ATLAS_PATH", getenv("DRIFTSTACK_TEXT_GLYPH_ATLAS_PATH") },
            { "DRIFTSTACK_TEXT_ATLAS", getenv("DRIFTSTACK_TEXT_ATLAS") },
            // Fingerprint overrides:
            { "DRIFTSTACK_MEASURE_TEXT_OVERRIDE", getenv("DRIFTSTACK_MEASURE_TEXT_OVERRIDE") },
            { "DRIFTSTACK_UNICODE_RENDERING_OVERRIDE", getenv("DRIFTSTACK_UNICODE_RENDERING_OVERRIDE") },
            // W2569 (#22 inline-offsetHeight): the snap-fix gate + its instrumentation. Read via
            // getenv in WebContent (RenderInline.cpp); must be in this explicit allowlist to reach
            // the sandboxed WebContent (the __XPC_ shadow path does not forward these). Both default-off.
            { "DRIFTSTACK_INLINE_OFFSET_SNAP", getenv("DRIFTSTACK_INLINE_OFFSET_SNAP") },
            { "DRIFTSTACK_LOG_INLINE_BBOX", getenv("DRIFTSTACK_LOG_INLINE_BBOX") },
            { "DRIFTSTACK_LOG_FONT_METRIC", getenv("DRIFTSTACK_LOG_FONT_METRIC") },
            { "DRIFTSTACK_INT_INLINE_LAYOUT", getenv("DRIFTSTACK_INT_INLINE_LAYOUT") }, // W2575 integer inline layout (glyphHash floor)
            { "DRIFTSTACK_GLYPHHASH_GEOM_SERVE", getenv("DRIFTSTACK_GLYPHHASH_GEOM_SERVE") }, // W2589 glyphHash DOM-geometry serve (orphan combining marks + mono exotics)
            { "DRIFTSTACK_LOG_FONT_RESOLVE", getenv("DRIFTSTACK_LOG_FONT_RESOLVE") }, // W2590 gate for the V-145 per-resolution diagnostic (default-off)
            // Locale: forward to BOTH WebContent (navigator.language via the
            // AppleLanguages override) AND NetworkProcess (Accept-Language), so
            // the JS language and the HTTP header never diverge.
            { "DRIFTSTACK_APPLELANGUAGES", getenv("DRIFTSTACK_APPLELANGUAGES") },
            { "DRIFTSTACK_RAF_FIRST_FRAME_CLAMP", getenv("DRIFTSTACK_RAF_FIRST_FRAME_CLAMP") },
            // Wave 29-397 V-MacCT-Realign.B.1.d.3 — env-var forwarding for
            // generic-font-keyword override (serif/sans-serif/monospace →
            // iOS-style defaults). Consumed by SystemFontDatabaseCoreText.
            { "DRIFTSTACK_GENERIC_FONT_OVERRIDE", getenv("DRIFTSTACK_GENERIC_FONT_OVERRIDE") },
            // Wave 29-397 V-LockdownMode — process-global CG private SPIs.
            // CGEnterLockdownModeForFonts() + CGFontSetShouldUseMulticache(false).
            { "DRIFTSTACK_CG_LOCKDOWN_FONTS", getenv("DRIFTSTACK_CG_LOCKDOWN_FONTS") },
            { "DRIFTSTACK_CG_MULTICACHE_OFF", getenv("DRIFTSTACK_CG_MULTICACHE_OFF") },
            { "DRIFTSTACK_CF_IOS_DEVICE_FAMILY_OVERRIDE", getenv("DRIFTSTACK_CF_IOS_DEVICE_FAMILY_OVERRIDE") },
            { "DRIFTSTACK_FORCE_IOSURFACE_BACKED", getenv("DRIFTSTACK_FORCE_IOSURFACE_BACKED") },
            { "DRIFTSTACK_SF_PRO_PLUS_ONE", getenv("DRIFTSTACK_SF_PRO_PLUS_ONE") },
            { "DRIFTSTACK_FONT_CANONICAL_OVERRIDE", getenv("DRIFTSTACK_FONT_CANONICAL_OVERRIDE") },
            { "DRIFTSTACK_FONT_CANONICAL_PATH", getenv("DRIFTSTACK_FONT_CANONICAL_PATH") },
            { "DRIFTSTACK_REALTIME_ANALYSER_OVERRIDE", getenv("DRIFTSTACK_REALTIME_ANALYSER_OVERRIDE") },
            // Audio:
            { "DRIFTSTACK_AUDIO_FLOAT16", getenv("DRIFTSTACK_AUDIO_FLOAT16") },
            { "DRIFTSTACK_AUDIO_GRAPH_HASH_DISPATCH", getenv("DRIFTSTACK_AUDIO_GRAPH_HASH_DISPATCH") },
            // WebRTC:
            { "DRIFTSTACK_FORCE_ICE_RELAY", getenv("DRIFTSTACK_FORCE_ICE_RELAY") },
            // Behavioral:
            { "DRIFTSTACK_BEHAVIORAL_MODEL_PATH", getenv("DRIFTSTACK_BEHAVIORAL_MODEL_PATH") },
            { "DRIFTSTACK_BEHAVIORAL_SYNTHESIS", getenv("DRIFTSTACK_BEHAVIORAL_SYNTHESIS") },
            // Layer B ML:
            { "DRIFTSTACK_LAYER_B_OFFSCREEN_RENDER", getenv("DRIFTSTACK_LAYER_B_OFFSCREEN_RENDER") },
            { "DRIFTSTACK_LAYER_B_SUBSTITUTE", getenv("DRIFTSTACK_LAYER_B_SUBSTITUTE") },
            // Wave 29-399 §1 AFP fallback (founder Tier-3 verdict 2026-05-19):
            // AFP fires on atlas-miss to replace natural Mac CG bytes with
            // randomized output. Vendor probes see randomized (not Mac-CG-
            // detectable) output; probe signature emitted async for atlas growth.
            { "DRIFTSTACK_AFP_FALLBACK_ENABLED", getenv("DRIFTSTACK_AFP_FALLBACK_ENABLED") },
            // Wave 29-399 §2 probe signature emission gate. When ENABLED,
            // atlas-miss codepath emits (canvas_w, h, opSeqSha, lastFillText,
            // archetype_id, ts, mime) via WTFLogAlways for Mac-side log
            // collector → control plane priority queue POST.
            { "DRIFTSTACK_PROBE_SIGNATURE_EMIT", getenv("DRIFTSTACK_PROBE_SIGNATURE_EMIT") },
            // Wave 29-400 §8.A observability attribution: session_id +
            // customer_id forwarded into WebContent so §2 ProbeSig log
            // lines + AFP fallback log lines can attribute per-session
            // and per-customer. Harness/SessionManager injects these on
            // WebContent spawn (one process per session).
            { "DRIFTSTACK_SESSION_ID", getenv("DRIFTSTACK_SESSION_ID") },
            { "DRIFTSTACK_CUSTOMER_ID", getenv("DRIFTSTACK_CUSTOMER_ID") },
            // Resources:
            { "DRIFTSTACK_FONTS_DIR", getenv("DRIFTSTACK_FONTS_DIR") },
            { "DRIFTSTACK_ARCHETYPE", getenv("DRIFTSTACK_ARCHETYPE") },
            // GPU:
            { "DRIFTSTACK_FORCE_CPU_CANVAS", getenv("DRIFTSTACK_FORCE_CPU_CANVAS") },
            // Layout text-rendering fix:
            { "DRIFTSTACK_HALFLEADING_ROUND", getenv("DRIFTSTACK_HALFLEADING_ROUND") },
            // V-433.Z text-rendering specials:
            { "DRIFTSTACK_V433Z_MN_OVERRIDE", getenv("DRIFTSTACK_V433Z_MN_OVERRIDE") },
            // Atlas dispatch flag:
            { "DRIFTSTACK_DISPATCH_PER_GLYPH", getenv("DRIFTSTACK_DISPATCH_PER_GLYPH") },
            // Wave 29-390.D additions per audit-driftstack-env-forwarding.sh:
            { "DRIFTSTACK_WEBGPU_ATLAS", getenv("DRIFTSTACK_WEBGPU_ATLAS") },
            { "DRIFTSTACK_WEBGPU_ATLAS_PATH", getenv("DRIFTSTACK_WEBGPU_ATLAS_PATH") },
            { "DRIFTSTACK_WEBGL_READPIXELS_OVERRIDE", getenv("DRIFTSTACK_WEBGL_READPIXELS_OVERRIDE") },
            { "DRIFTSTACK_V770_MASK_TINT", getenv("DRIFTSTACK_V770_MASK_TINT") },
            { "DRIFTSTACK_V790L_MULTI_SUB", getenv("DRIFTSTACK_V790L_MULTI_SUB") },
            { "DRIFTSTACK_V790L_N1_SUB", getenv("DRIFTSTACK_V790L_N1_SUB") },
            // Wave 29-499.242 — PathB v2 HTTP/3 + smoke test gates.
            { "DRIFTSTACK_PATHB_V2_H3", getenv("DRIFTSTACK_PATHB_V2_H3") },
            { "DRIFTSTACK_PATHB_V2_H3_SMOKE", getenv("DRIFTSTACK_PATHB_V2_H3_SMOKE") },
            // Wave 29-499.250 — smoke force gate (production-safe; only fires
            // when explicitly set due to .247 crash investigation).
            { "DRIFTSTACK_PATHB_V2_H3_SMOKE_FORCE", getenv("DRIFTSTACK_PATHB_V2_H3_SMOKE_FORCE") },
            // Wave 29-499.321 — Path B v2 egress activator + h3 discovery + h2
            // connection pooling flags. Forwarded explicitly so the NetworkProcess
            // (where DriftstackNetworkLoader runs) sees them.
            { "DRIFTSTACK_PATHB_V2", getenv("DRIFTSTACK_PATHB_V2") },
            { "DRIFTSTACK_PATHB_V2_H3_FORCE", getenv("DRIFTSTACK_PATHB_V2_H3_FORCE") },
            { "DRIFTSTACK_PATHB_V2_H3_DNSRR", getenv("DRIFTSTACK_PATHB_V2_H3_DNSRR") },
            { "DRIFTSTACK_H2_POOL", getenv("DRIFTSTACK_H2_POOL") },
            // iPhone-byte-exact TLS 1.3 ClientHello (DriftstackTLS13Client). Without
            // this Path B v2 uses BoringSSL's ClientHello (NOT iPhone-exact). Also
            // required for h2 connection pooling (the session adopts the custom-TLS
            // connection). Forward (unprefixed) so production NetworkProcess sees it.
            { "DRIFTSTACK_PATHB_V2_CUSTOM_TLS", getenv("DRIFTSTACK_PATHB_V2_CUSTOM_TLS") },
            // W2200: server-cert validation gate (DriftstackTLS13Client SecTrust,
            // W2191). The TLS client runs in the NetworkProcess, which does NOT get
            // the __XPC_ mirror (that reaches WebContent/GPU) — so this MUST be in
            // the explicit dsEnv[] list, exactly like PATHB_V2_CUSTOM_TLS above, or
            // the founder's launch-env flip silently never reaches getenv() and the
            // MITM defense stays off in production.
            { "DRIFTSTACK_PATHB_TLS_CERT_VALIDATE", getenv("DRIFTSTACK_PATHB_TLS_CERT_VALIDATE") },
            // W2203: RFC 8441 WS-over-h2 opt-in gate (WebSocketTaskCocoa, the (B)
            // egress arc). Same class as the cert-validate gate above — consumed in
            // the NetworkProcess (getenv at WebSocketTaskCocoa.mm), which does NOT
            // get the __XPC_ mirror. Off by default; forwarded now so the founder's
            // eventual launch-env flip actually activates WS-over-h2 in production
            // instead of silently staying on the h1.1 path.
            { "DRIFTSTACK_WS_PATHB", getenv("DRIFTSTACK_WS_PATHB") },
            // W2532 (#52): the custom-h3 / QUIC PathB gates. Consumed in the NetworkProcess
            // (static getenv() in DriftstackHttp3.mm), which does NOT get the __XPC_ mirror —
            // so they MUST be in this explicit dsEnv[] list (same class as the cert-validate +
            // WS_PATHB gates above), or production h3/QUIC stays on the non-iPhone-exact path
            // because the launch-env flip silently never reaches getenv().
            { "DRIFTSTACK_H3_POOL", getenv("DRIFTSTACK_H3_POOL") },
            { "DRIFTSTACK_QUIC_CUSTOM_TLS", getenv("DRIFTSTACK_QUIC_CUSTOM_TLS") },
        };
        WTFLogAlways("[Driftstack] ProcessLauncher forwarding env: TZ=%s LANG=%s LC_ALL=%s "
                     "LOG_IBG=%s LOG_LBH=%s V602=%s LAYER_B=%s LAYER_B_V2=%s ARCHETYPE=%s",
                environmentTZ ?: "(unset)",
                environmentLANG ?: "(unset)",
                environmentLCALL ?: "(unset)",
                dsEnv[0].value ?: "(unset)",
                dsEnv[1].value ?: "(unset)",
                dsEnv[2].value ?: "(unset)",
                dsEnv[3].value ?: "(unset)",
                dsEnv[4].value ?: "(unset)",
                dsEnv[5].value ?: "(unset)");
        if (environmentTZ)
            xpc_dictionary_set_string(containerEnvironmentVariables.get(), "TZ", environmentTZ);
        if (environmentLANG)
            xpc_dictionary_set_string(containerEnvironmentVariables.get(), "LANG", environmentLANG);
        if (environmentLCALL)
            xpc_dictionary_set_string(containerEnvironmentVariables.get(), "LC_ALL", environmentLCALL);
        for (const auto& kv : dsEnv) {
            if (kv.value)
                xpc_dictionary_set_string(containerEnvironmentVariables.get(), kv.name, kv.value);
        }
        // Wave 29-397 Slice 16.4.b.5: DYLD_INSERT_LIBRARIES injection for the
        // (future) DriftstackQuicInterpose dylib. When DRIFTSTACK_CUSTOM_SOCKS5=1
        // AND the dylib is built + present at the expected path, append it to
        // the child process's DYLD_INSERT_LIBRARIES so dyld processes its
        // __DATA,__interpose section BEFORE CFNetwork loads. This rewires
        // nw_connection_create globally for the NetworkProcess binary (Slice
        // 16.4.b.6 will populate the dylib's createRelayConnectionForQuic
        // body).
        //
        // Current state (Wave 29-397 close): dylib target NOT YET in
        // xcodeproj — Slice 16.4.b.3 source skeleton + Slice 16.4.b.4
        // parametersUseQuic inspector are in the WebKit framework binary,
        // but the standalone dylib target needs Xcode project surgery
        // (separate atomic slice 16.4.b.5.b). This injection code lands
        // NOW + remains DORMANT until the dylib path exists; the
        // conditional file-exists check below ensures no harm to current
        // builds.
        const char* customSocks5 = getenv("DRIFTSTACK_CUSTOM_SOCKS5");
        if (customSocks5 && customSocks5[0] == '1') {
            // Probe for the dylib at the standard build product location.
            // Path is constructed from the WebKit build dir + the dylib
            // target name (DriftstackQuicInterpose); when Slice 16.4.b.5.b
            // adds the target, the dylib lands here.
            // V-211: the dev build-products dir derives from the environment
            // (DRIFTSTACK_BUILD_DIR, else $HOME/code/webkit-driftstack/
            // WebKitBuild/Release) instead of a hardcoded build-machine home.
            static const char* dylibPath = [] {
                const char* dir = getenv("DRIFTSTACK_BUILD_DIR");
                const char* home = getenv("HOME");
                std::string p = (dir && *dir) ? std::string(dir) : std::string(home ? home : "") + "/code/webkit-driftstack/WebKitBuild/Release";
                p += "/libDriftstackQuicInterpose.dylib";
                return strdup(p.c_str());
            }();
            if (access(dylibPath, R_OK) == 0) {
                const char* existing = getenv("DYLD_INSERT_LIBRARIES");
                String combined;
                if (existing && existing[0])
                    combined = makeString(StringView::fromLatin1(existing), ':', StringView::fromLatin1(dylibPath));
                else
                    combined = String::fromUTF8(dylibPath);
                xpc_dictionary_set_string(containerEnvironmentVariables.get(),
                    "DYLD_INSERT_LIBRARIES", combined.utf8().data());
                WTFLogAlways("[Driftstack-EG-WK-1.10/Task#16] ProcessLauncher: DYLD_INSERT_LIBRARIES injected — %s",
                    dylibPath);
            } else {
                static bool loggedAbsenceOnce = false;
                if (!loggedAbsenceOnce) {
                    loggedAbsenceOnce = true;
                    WTFLogAlways("[Driftstack-EG-WK-1.10/Task#16] ProcessLauncher: DRIFTSTACK_CUSTOM_SOCKS5=1 but %s missing — Slice 16.4.b.5.b dylib target not yet built; QUIC interpose dormant",
                        dylibPath);
                }
            }
        }
#endif
        xpc_dictionary_set_value(bootstrapMessage.get(), "ContainerEnvironmentVariables", containerEnvironmentVariables.get());
    }
#endif

    CheckedPtr client = m_client;
    if (client) {
        if (client->shouldConfigureJSCForTesting())
            xpc_dictionary_set_bool(bootstrapMessage.get(), "configure-jsc-for-testing", true);
        if (!client->isJITEnabled())
            xpc_dictionary_set_bool(bootstrapMessage.get(), "disable-jit", true);
        if (client->shouldEnableSharedArrayBuffer())
            xpc_dictionary_set_bool(bootstrapMessage.get(), "enable-shared-array-buffer", true);
        if (client->shouldDisableJITCage())
            xpc_dictionary_set_bool(bootstrapMessage.get(), "disable-jit-cage", true);
    }

    xpc_dictionary_set_string(bootstrapMessage.get(), "message-name", "bootstrap");

    xpc_dictionary_set_mach_send(bootstrapMessage.get(), "server-port", listeningPort);

    xpc_dictionary_set_string(bootstrapMessage.get(), "client-identifier", !clientIdentifier.isEmpty() ? clientIdentifier.utf8().data() : *_NSGetProgname());
    xpc_dictionary_set_string(bootstrapMessage.get(), "client-bundle-identifier", applicationBundleIdentifier().utf8().data());
    xpc_dictionary_set_string(bootstrapMessage.get(), "process-identifier", String::number(m_launchOptions.processIdentifier.toUInt64()).utf8().data());
    RetainPtr processName = [&]() -> RetainPtr<NSString> {
#if PLATFORM(MAC)
        if (RetainPtr<NSString> name = NSRunningApplication.currentApplication.localizedName; name.get().length)
            return name;
#endif
        return NSProcessInfo.processInfo.processName;
    }();
    xpc_dictionary_set_string(bootstrapMessage.get(), "ui-process-name", [processName UTF8String]);
    xpc_dictionary_set_string(bootstrapMessage.get(), "service-name", name);

    if (m_launchOptions.processType == ProcessLauncher::ProcessType::Web) {
#if ENABLE(LOGD_BLOCKING_IN_WEBCONTENT)
        bool disableLogging = true;
#else
        bool disableLogging = false;
#endif
        xpc_dictionary_set_bool(bootstrapMessage.get(), "disable-logging", disableLogging);
    }

    if (!AuxiliaryProcess::isSystemWebKit()) {
        xpc_dictionary_set_fd(bootstrapMessage.get(), "stdout", STDOUT_FILENO);
        xpc_dictionary_set_fd(bootstrapMessage.get(), "stderr", STDERR_FILENO);
    }
    
    auto sdkBehaviors = sdkAlignedBehaviors();
    auto sdkBehaviorBytes = sdkBehaviors.storageBytes();
    xpc_dictionary_set_data(bootstrapMessage.get(), "client-sdk-aligned-behaviors", sdkBehaviorBytes.data(), sdkBehaviorBytes.size());

    // FIXME: This is a false positive. <rdar://164843889>
    SUPPRESS_RETAINPTR_CTOR_ADOPT auto extraInitializationData = adoptOSObject(xpc_dictionary_create(nullptr, nullptr, 0));

    for (const auto& keyValuePair : m_launchOptions.extraInitializationData)
        xpc_dictionary_set_string(extraInitializationData.get(), keyValuePair.key.utf8().data(), keyValuePair.value.utf8().data());

    xpc_dictionary_set_value(bootstrapMessage.get(), "extra-initialization-data", extraInitializationData.get());

    Function<void(xpc_object_t)> errorHandlerImpl = [weakProcessLauncher = ThreadSafeWeakPtr { *this }, listeningPort, logName = CString(name), onFailure = WTF::move(onFailure)] (xpc_object_t event) mutable {
        ASSERT(!event || xpc_get_type(event) == XPC_TYPE_ERROR);

        auto processLauncher = weakProcessLauncher.get();
        if (!processLauncher)
            return;

        if (!processLauncher->isLaunching())
            return;

#if ERROR_DISABLED
        UNUSED_PARAM(logName);
#endif

        if (event)
            LOG_ERROR("Error while launching %s: %s", logName.data(), xpcDictionaryGetString(event, xpcErrorDescriptionKey).utf8().data());
        else
            LOG_ERROR("Error while launching %s: No xpc_object_t event available.", logName.data());

#if ASSERT_ENABLED
        mach_port_urefs_t sendRightCount = 0;
        mach_port_get_refs(mach_task_self(), listeningPort, MACH_PORT_RIGHT_SEND, &sendRightCount);
        ASSERT(sendRightCount >= 1);
#endif

        // We failed to launch. Release the send right.
        deallocateSendRightSafely(listeningPort);

        // And the receive right.
        mach_port_mod_refs(mach_task_self(), listeningPort, MACH_PORT_RIGHT_RECEIVE, -1);

        if (processLauncher->m_xpcConnection)
            xpc_connection_cancel(processLauncher->m_xpcConnection.get());
        processLauncher->m_xpcConnection = nullptr;

        onFailure();
    };

    Function<void(xpc_object_t)> eventHandler = [errorHandlerImpl = WTF::move(errorHandlerImpl), xpcEventHandler = client->xpcEventHandler()] (xpc_object_t event) mutable {

        if (!event || xpc_get_type(event) == XPC_TYPE_ERROR) {
            RunLoop::mainSingleton().dispatch([errorHandlerImpl = std::exchange(errorHandlerImpl, nullptr), event = OSObjectPtr<xpc_object_t> { event }] {
                if (errorHandlerImpl)
                    errorHandlerImpl(event.get());
                else if (event.get() != XPC_ERROR_CONNECTION_INVALID)
                    LOG_ERROR("Multiple errors while launching: %@", event.get());
            });
            return;
        }

        if (xpcEventHandler) {
            RunLoop::mainSingleton().dispatch([xpcEventHandler = xpcEventHandler, event = OSObjectPtr<xpc_object_t> { event }] {
                xpcEventHandler->handleXPCEvent(event.get());
            });
        }
    };

    auto eventHandlerBlock = makeBlockPtr(WTF::move(eventHandler));
    xpc_connection_set_event_handler(m_xpcConnection.get(), eventHandlerBlock.get());

    xpc_connection_resume(m_xpcConnection.get());

    if (m_launchOptions.shouldMakeProcessLaunchFailForTesting) [[unlikely]] {
        eventHandlerBlock(nullptr);
        return;
    }

    ref();
    xpc_connection_send_message_with_reply(m_xpcConnection.get(), bootstrapMessage.get(), mainDispatchQueueSingleton(), ^(xpc_object_t reply) {
        // Errors are handled in the event handler.
        // It is possible for this block to be called after the error event handler, in which case we're no longer
        // launching and we already took care of cleaning things up.
        if (isLaunching() && xpc_get_type(reply) != XPC_TYPE_ERROR) {
            ASSERT(xpc_get_type(reply) == XPC_TYPE_DICTIONARY);
            ASSERT(xpcDictionaryGetString(reply, "message-name"_s) == "process-finished-launching"_s);

#if ASSERT_ENABLED
            mach_port_urefs_t sendRightCount = 0;
            mach_port_get_refs(mach_task_self(), listeningPort, MACH_PORT_RIGHT_SEND, &sendRightCount);
            ASSERT(sendRightCount >= 1);
#endif

            deallocateSendRightSafely(listeningPort);

            if (!m_xpcConnection) {
                // The process was terminated.
                didFinishLaunchingProcess(0, IPC::Connection::Identifier());
                return;
            }

            // The process has finished launching, grab the pid from the connection.
            pid_t processIdentifier = xpc_connection_get_pid(m_xpcConnection.get());

            didFinishLaunchingProcess(processIdentifier, IPC::Connection::Identifier(listeningPort, m_xpcConnection));
            m_xpcConnection = nullptr;
        }

        deref();
    });
}

void ProcessLauncher::terminateProcess()
{
#if USE(EXTENSIONKIT)
    if (m_process)
        m_process->invalidate();
#endif

    terminateXPCConnection();

    m_processID = 0;
}

void ProcessLauncher::platformInvalidate()
{
#if USE(EXTENSIONKIT)
    releaseLaunchGrant();
    if (m_process)
        m_process->invalidate();
#endif

    terminateXPCConnection();
}

void ProcessLauncher::terminateXPCConnection()
{
    if (!m_xpcConnection)
        return;

    xpc_connection_cancel(m_xpcConnection.get());
#if !USE(EXTENSIONKIT)
    terminateWithReason(m_xpcConnection.get(), WebKit::ReasonCode::Invalidation, "ProcessLauncher::platformInvalidate");
#endif
    m_xpcConnection = nullptr;
}

} // namespace WebKit
