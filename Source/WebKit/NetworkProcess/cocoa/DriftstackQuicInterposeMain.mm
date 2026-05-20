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
__attribute__((constructor))
static void driftstackQuicInterposeDylibLoaded(void)
{
    NSLog(@"[Driftstack-EG-WK-1.10/Task#16/Slice16.6.c] libDriftstackQuicInterpose.dylib CONSTRUCTOR fired — dylib loaded into process (pid=%d). DYLD_INTERPOSE section should now be active. Subsequent nw_connection_create calls will reach driftstack_nw_connection_create.",
        getpid());
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
    void* sym = dlsym(RTLD_NEXT, "nw_connection_create");
    if (!sym) {
        NSLog(@"[Driftstack-EG-WK-1.10/Task#16] dlsym(RTLD_NEXT, nw_connection_create) returned nil — interpose dead-ends");
        return;
    }
    originalNwConnectionCreate = reinterpret_cast<NwConnectionCreateFn>(sym);
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
