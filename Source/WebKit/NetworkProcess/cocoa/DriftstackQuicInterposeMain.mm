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

#import "DriftstackQuicSocks5Bridge.h"

#import <Foundation/Foundation.h>
#import <Network/Network.h>
#include <dlfcn.h>
#include <wtf/Assertions.h>

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
// std::atomic load/CAS protects against the rare race where two threads
// both miss the cache on first interpose-trip.
static nw_connection_t (*originalNwConnectionCreate)(nw_endpoint_t, nw_parameters_t) = nullptr;

static nw_connection_t resolveOriginalNwConnectionCreate()
{
    if (originalNwConnectionCreate != nullptr)
        return reinterpret_cast<nw_connection_t>(reinterpret_cast<void*>(originalNwConnectionCreate));
    void* sym = dlsym(RTLD_NEXT, "nw_connection_create");
    if (!sym) {
        WTFLogAlways("[Driftstack-EG-WK-1.10/Task#16] dlsym(RTLD_NEXT, nw_connection_create) returned nil — falling through breaks; QUIC will NOT route through SOCKS5");
        return nullptr;
    }
    originalNwConnectionCreate = reinterpret_cast<nw_connection_t (*)(nw_endpoint_t, nw_parameters_t)>(sym);
    return nullptr; // caller checks originalNwConnectionCreate
}

extern "C" nw_connection_t driftstack_nw_connection_create(nw_endpoint_t endpoint, nw_parameters_t parameters)
{
    resolveOriginalNwConnectionCreate();
    if (!originalNwConnectionCreate)
        return nullptr;

    if (!WebKit::DriftstackQuic::isCustomSocks5Active())
        return originalNwConnectionCreate(endpoint, parameters);

    if (!WebKit::DriftstackQuic::parametersUseQuic(parameters))
        return originalNwConnectionCreate(endpoint, parameters);

    static bool loggedOnce = false;
    if (!loggedOnce) {
        loggedOnce = true;
        WTFLogAlways("[Driftstack-EG-WK-1.10/Task#16] driftstack_nw_connection_create: FIRST QUIC interpose match — redirecting to createRelayConnectionForQuic. Slice 16.4.b interpose ACTIVE.");
    }

    RetainPtr<nw_connection_t> relayConnection = WebKit::DriftstackQuic::createRelayConnectionForQuic(endpoint, parameters);
    if (relayConnection)
        return relayConnection.leakRef();

    // Phase A scaffold returns nullptr → fall through to original
    // (leak; Slice 16.4.b.6 implements relay connection).
    return originalNwConnectionCreate(endpoint, parameters);
}

DYLD_INTERPOSE(driftstack_nw_connection_create, nw_connection_create)

#endif // PLATFORM(DRIFTSTACK)
