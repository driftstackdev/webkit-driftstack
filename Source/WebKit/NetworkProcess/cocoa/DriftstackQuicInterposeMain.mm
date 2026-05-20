/*
 * DriftstackQuicInterposeMain.mm — DYLD_INSERT_LIBRARIES dylib entry point
 * for Task #16 EG-WK-1.10 HTTP/3 NSURLSession interception.
 *
 * Wave 29-397 Slice 16.4.b.2 source skeleton (xcodeproj target wiring +
 * DYLD_INSERT_LIBRARIES injection deferred to subsequent atomic slices).
 *
 * Build target: separate dylib loaded via DYLD_INSERT_LIBRARIES into
 * NetworkProcess.app at launch. Sits before Network.framework in the
 * load order, so its __DATA,__interpose section rewires
 * nw_connection_create globally for the NetworkProcess binary.
 *
 * When `parametersUseQuic(parameters)` returns true AND
 * `isCustomSocks5Active()` returns true, the interpose redirects to
 * `DriftstackQuic::createRelayConnectionForQuic` (binds to SOCKS5 BND.
 * ADDR:BND.PORT). Otherwise falls through to the original symbol via
 * dlsym(RTLD_NEXT, ...) — preserves CFNetwork's standard QUIC path for
 * non-bridge sessions + non-QUIC connections.
 *
 * Symbol resolution caveat: replacement function MUST NOT call
 * nw_connection_create directly (would recurse through the interpose).
 * dlsym(RTLD_NEXT, "nw_connection_create") returns the original. Cache
 * the lookup at first call.
 *
 * Per Slice 16.4.b.1 research: same-binary DYLD_INTERPOSE only affects
 * the interposing binary's own symbol bindings. A separate dylib +
 * DYLD_INSERT_LIBRARIES is required to intercept CFNetwork's internal
 * calls (CFNetwork resolves its symbols at framework load time, not
 * WebKit's). This file is the dylib's main entry.
 */

#if PLATFORM(DRIFTSTACK)

#import <Foundation/Foundation.h>
#import <Network/Network.h>
#include <dlfcn.h>

// Wave 29-499 Slice 16.6.c PRODUCTION FIX VERIFICATION: constructor-time
// NSLog fires when the dylib is LOADED by dyld, before any interpose
// activity. Definitively answers "did the dylib actually load?" — the
// failure mode where DYLD_INSERT_LIBRARIES is set but the dylib silently
// fails to load (entitlements / SIP / hardened-runtime / library
// validation) is otherwise invisible. Without this constructor log, the
// dlsym-success log only fires if nw_connection_create is called, which
// itself depends on the dylib having loaded.
// Wave 29-499 Slice 16.6.e (Task #16 EG-WK-1.10) — fast-path no-op gate.
// The dylib is now always loaded via Info.plist EnvironmentVariables
// (Slice 16.6.d Path A). For cumrig + any session where
// DRIFTSTACK_CUSTOM_SOCKS5 is unset, the interpose should be a near-zero-
// overhead pass-through to the original nw_connection_create. Cache the
// flag at constructor time to avoid repeated getenv() calls on the hot
// data path.
static bool g_driftstackCustomSocks5GatedAtLoad = false;

__attribute__((constructor))
static void driftstackQuicInterposeDylibLoaded(void)
{
    // Slice 16.6.c: dylib-load anchor. NSLog may not work in the
    // dyld-constructor phase if CoreFoundation hasn't initialized yet —
    // use fprintf(stderr) as the primary signal (always works from C
    // stdio); NSLog as a secondary signal that should fire once CF is up.
    fprintf(stderr, "[Driftstack-EG-WK-1.10/Task#16/Slice16.6.c] libDriftstackQuicInterpose.dylib CONSTRUCTOR fired — dylib loaded into process (pid=%d). DYLD_INTERPOSE section active.\n",
        getpid());
    fflush(stderr);

    // Slice 16.6.e: cache the gate flag at constructor time.
    const char* customSocks5 = getenv("DRIFTSTACK_CUSTOM_SOCKS5");
    g_driftstackCustomSocks5GatedAtLoad = (customSocks5 && customSocks5[0] == '1');
    fprintf(stderr, "[Driftstack-EG-WK-1.10/Task#16/Slice16.6.e] gate flag at load: DRIFTSTACK_CUSTOM_SOCKS5=%s (interpose %s)\n",
        customSocks5 ?: "(unset)",
        g_driftstackCustomSocks5GatedAtLoad ? "ACTIVE" : "INERT (fast-pass-through)");
    fflush(stderr);

    NSLog(@"[Driftstack-EG-WK-1.10/Task#16/Slice16.6.c] CONSTRUCTOR NSLog (secondary, post-CF) — pid=%d gated=%d", getpid(), g_driftstackCustomSocks5GatedAtLoad);
}

// Slice 16.4.b.5.b: NO direct include of DriftstackQuicSocks5Bridge.h —
// the interpose dylib loads BEFORE WebKit framework, so WebKit's symbols
// are not statically linkable. The bridge functions are reached via
// dlsym(RTLD_DEFAULT, "driftstack_quic_*") at runtime after WebKit has
// loaded. extern "C" wrappers in DriftstackQuicSocks5Bridge.mm expose
// stable unmangled names.
typedef bool (*DriftstackQuicIsActiveFn)(void);
typedef bool (*DriftstackQuicParamsUseQuicFn)(nw_parameters_t);
typedef nw_connection_t (*DriftstackQuicCreateRelayFn)(nw_endpoint_t, nw_parameters_t);

// Canonical DYLD_INTERPOSE macro (matches Apple's dyld-interposing.h).
// Same shape as the ANGLE precedent at
// Source/ThirdParty/ANGLE/.../shader_cache_file_hooking.cpp.
#define DYLD_INTERPOSE(_replacment, _replacee)                                  \
    __attribute__((used)) static struct                                         \
    {                                                                           \
        const void *replacment;                                                 \
        const void *replacee;                                                   \
    } _interpose_##_replacee __attribute__((section("__DATA,__interpose"))) = { \
        (const void *)(unsigned long)&_replacment, (const void *)(unsigned long)&_replacee};

// Cached pointer to original nw_connection_create resolved at first call.
// Function-pointer typedef avoids the ARC void* ↔ nw_connection_t bridge
// cast confusion — we never store the result as nw_connection_t.
typedef nw_connection_t (*NwConnectionCreateFn)(nw_endpoint_t, nw_parameters_t);
static NwConnectionCreateFn originalNwConnectionCreate = nullptr;

static void resolveOriginalNwConnectionCreate()
{
    if (originalNwConnectionCreate != nullptr)
        return;
    // Wave 29-499 Slice 16.6.f INFINITE RECURSION FIX: dlsym(RTLD_NEXT, ...)
    // on macOS with DYLD_INTERPOSE returns the address of our OWN interpose
    // function — not Apple's original. The interpose binding propagates
    // through RTLD_NEXT lookups too. Calling our cached pointer recurses
    // infinitely → stack overflow → crash (verified empirically via crash
    // dump, depth 3325).
    //
    // Fix: explicitly open Network.framework by absolute path and dlsym
    // from that specific handle. Network.framework's own image table is
    // untouched by our interpose binding; the symbol resolves to Apple's
    // real implementation.
    void* networkHandle = dlopen("/System/Library/Frameworks/Network.framework/Network", RTLD_LAZY | RTLD_LOCAL);
    if (!networkHandle) {
        fprintf(stderr, "[Driftstack-EG-WK-1.10/Task#16/Slice16.6.f] dlopen(Network.framework) returned nil — interpose dead-ends. dlerror: %s\n",
            dlerror() ?: "(unset)");
        fflush(stderr);
        NSLog(@"[Driftstack-EG-WK-1.10/Task#16/Slice16.6.f] dlopen(Network.framework) returned nil — interpose dead-ends");
        return;
    }
    void* sym = dlsym(networkHandle, "nw_connection_create");
    if (!sym) {
        fprintf(stderr, "[Driftstack-EG-WK-1.10/Task#16/Slice16.6.f] dlsym(Network.framework, nw_connection_create) returned nil — interpose dead-ends. dlerror: %s\n",
            dlerror() ?: "(unset)");
        fflush(stderr);
        NSLog(@"[Driftstack-EG-WK-1.10/Task#16/Slice16.6.f] dlsym(Network.framework, nw_connection_create) returned nil — interpose dead-ends");
        return;
    }
    originalNwConnectionCreate = reinterpret_cast<NwConnectionCreateFn>(sym);
    fprintf(stderr, "[Driftstack-EG-WK-1.10/Task#16/Slice16.6.f] dlsym resolved original nw_connection_create via Network.framework handle: %p\n",
        sym);
    fflush(stderr);
}

// Cached pointers to bridge symbols resolved at first use via
// dlsym(RTLD_DEFAULT, ...) — WebKit framework must be loaded into the
// process before these resolve (loaded right after the interpose dylib
// during NetworkProcess launch).
static DriftstackQuicIsActiveFn bridgeIsActive = nullptr;
static DriftstackQuicParamsUseQuicFn bridgeParamsUseQuic = nullptr;
static DriftstackQuicCreateRelayFn bridgeCreateRelay = nullptr;

static void resolveBridgeSymbols()
{
    if (bridgeIsActive && bridgeParamsUseQuic && bridgeCreateRelay)
        return;
    bridgeIsActive = reinterpret_cast<DriftstackQuicIsActiveFn>(dlsym(RTLD_DEFAULT, "driftstack_quic_isCustomSocks5Active"));
    bridgeParamsUseQuic = reinterpret_cast<DriftstackQuicParamsUseQuicFn>(dlsym(RTLD_DEFAULT, "driftstack_quic_parametersUseQuic"));
    bridgeCreateRelay = reinterpret_cast<DriftstackQuicCreateRelayFn>(dlsym(RTLD_DEFAULT, "driftstack_quic_createRelayConnection"));
    if (!bridgeIsActive || !bridgeParamsUseQuic || !bridgeCreateRelay) {
        static bool loggedAbsenceOnce = false;
        if (!loggedAbsenceOnce) {
            loggedAbsenceOnce = true;
            NSLog(@"[Driftstack-EG-WK-1.10/Task#16] resolveBridgeSymbols: dlsym(RTLD_DEFAULT) for one or more driftstack_quic_* failed — WebKit framework may not be loaded yet OR symbols missing. Interpose falls through.");
        }
    } else {
        // Wave 29-499 Slice 16.6.b PRODUCTION FIX VERIFICATION: log dlsym
        // success on first resolution so smoke tests can confirm the
        // visibility-fix arc closure (symbols exported + dlsym resolves).
        // Without this log, smoke could pass with all 3 dlsym calls
        // returning non-NULL but no observable evidence.
        static bool loggedSuccessOnce = false;
        if (!loggedSuccessOnce) {
            loggedSuccessOnce = true;
            NSLog(@"[Driftstack-EG-WK-1.10/Task#16/Slice16.6.b] resolveBridgeSymbols: ALL THREE dlsym(RTLD_DEFAULT) RESOLVED — bridge active. Interpose ACTIVE on subsequent nw_connection_create calls. isActive=%p paramsUseQuic=%p createRelay=%p",
                (void*)bridgeIsActive, (void*)bridgeParamsUseQuic, (void*)bridgeCreateRelay);
        }
    }
}

extern "C" nw_connection_t driftstack_nw_connection_create(nw_endpoint_t endpoint, nw_parameters_t parameters)
{
    resolveOriginalNwConnectionCreate();
    if (!originalNwConnectionCreate)
        return nullptr;

    // Slice 16.6.e: fast-path no-op when SOCKS5 unset at process launch.
    // Avoids per-call dlsym + WebKit bridge symbol resolution overhead for
    // the majority of sessions (cumrig, dev sessions without SOCKS5). The
    // gate flag is cached at constructor time so the only hot-path cost
    // is one bool load + branch.
    if (!g_driftstackCustomSocks5GatedAtLoad)
        return originalNwConnectionCreate(endpoint, parameters);

    resolveBridgeSymbols();
    if (!bridgeIsActive || !bridgeParamsUseQuic || !bridgeCreateRelay)
        return originalNwConnectionCreate(endpoint, parameters);

    if (!bridgeIsActive())
        return originalNwConnectionCreate(endpoint, parameters);

    if (!bridgeParamsUseQuic(parameters))
        return originalNwConnectionCreate(endpoint, parameters);

    static bool loggedOnce = false;
    if (!loggedOnce) {
        loggedOnce = true;
        NSLog(@"[Driftstack-EG-WK-1.10/Task#16] driftstack_nw_connection_create: FIRST QUIC interpose match — redirecting to driftstack_quic_createRelayConnection. Slice 16.4.b interpose ACTIVE.");
    }

    nw_connection_t relayConnection = bridgeCreateRelay(endpoint, parameters);
    if (relayConnection)
        return relayConnection;

    // Bridge returned nil → fall through to original (relay-establish
    // failure path; Slice 16.4.b.5 ProcessLauncher injection paired
    // with DRIFTSTACK_REQUIRE_PROXY=1 will hard-block at socket-open
    // time when proxy unreachable).
    return originalNwConnectionCreate(endpoint, parameters);
}

DYLD_INTERPOSE(driftstack_nw_connection_create, nw_connection_create)

#endif // PLATFORM(DRIFTSTACK)
