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
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <string.h>

// Wave 29-499 Slice 16.6.g (Task #16 EG-WK-1.10) — Mach-O symbol-table walker
// for the un-interposed original `nw_connection_create` address.
//
// Background: Apple's dyld interposition redirects function-pointer calls
// based on caller-image binding tables, even when the address was obtained
// via dlsym (RTLD_NEXT, RTLD_DEFAULT, or dlopen handle). The
// `originalNwConnectionCreate(...)` call from inside our interpose function
// recursed infinitely → SIGBUS at stack depth 3325.
//
// G1 fix: register a `_dyld_register_func_for_add_image` callback at
// constructor time. When Apple's Network.framework loads, the callback
// fires with the framework's mach_header in memory + slide. We then walk
// the Mach-O LC_SYMTAB load command directly to find the `_nw_connection_
// create` symbol and compute its address as `n_value + slide`. That
// address is the framework's RAW symbol — never subject to interpose
// binding redirection. Calling it via function pointer is a direct
// branch with no recursion.
//
// Mach-O walking: LC_SYMTAB gives file offsets for symtab + strtab. To
// convert to memory addresses, we use the __LINKEDIT segment's
// vmaddr/fileoff mapping (LC_SEGMENT_64). Standard pattern from
// Apple's "Iterating the Mach-O Symbol Table" docs.

typedef struct {
    const char* targetSymbol;   // e.g. "_nw_connection_create"
    const char* targetImage;    // partial path match, e.g. "Network.framework/Versions/A/Network"
    void* resolvedAddress;      // OUT — set when found
} SymbolLookupRequest;

static SymbolLookupRequest g_nwConnectionCreateRequest = {
    "_nw_connection_create",
    "Network.framework/Versions/A/Network",
    nullptr
};

// Walk a loaded Mach-O image's LC_SYMTAB for a named external symbol.
// Returns the in-memory address of the symbol, or nullptr if not found.
static void* lookupSymbolInImage(const struct mach_header_64* header,
                                  intptr_t slide,
                                  const char* targetSymbol)
{
    if (!header || header->magic != MH_MAGIC_64)
        return nullptr;

    const struct load_command* cmd = (const struct load_command*)((const char*)header + sizeof(struct mach_header_64));
    const struct symtab_command* symtabCmd = nullptr;
    const struct segment_command_64* linkeditSeg = nullptr;

    for (uint32_t i = 0; i < header->ncmds; i++) {
        if (cmd->cmd == LC_SYMTAB)
            symtabCmd = (const struct symtab_command*)cmd;
        else if (cmd->cmd == LC_SEGMENT_64) {
            const struct segment_command_64* seg = (const struct segment_command_64*)cmd;
            if (strcmp(seg->segname, "__LINKEDIT") == 0)
                linkeditSeg = seg;
        }
        cmd = (const struct load_command*)((const char*)cmd + cmd->cmdsize);
    }

    if (!symtabCmd || !linkeditSeg)
        return nullptr;

    // __LINKEDIT in memory = linkeditSeg->vmaddr + slide
    // Symtab/strtab file offsets convert to memory: linkeditBase + (fileoff - linkedit.fileoff)
    uintptr_t linkeditBase = linkeditSeg->vmaddr + slide;
    uintptr_t fileoffBase = linkeditSeg->fileoff;
    const struct nlist_64* symtab = (const struct nlist_64*)(linkeditBase + (symtabCmd->symoff - fileoffBase));
    const char* strtab = (const char*)(linkeditBase + (symtabCmd->stroff - fileoffBase));

    for (uint32_t i = 0; i < symtabCmd->nsyms; i++) {
        const struct nlist_64* sym = &symtab[i];
        if (sym->n_un.n_strx == 0) continue;
        const char* name = strtab + sym->n_un.n_strx;
        if (strcmp(name, targetSymbol) == 0) {
            // External, defined symbol — return its address with slide applied.
            if ((sym->n_type & N_TYPE) == N_SECT && sym->n_value != 0)
                return (void*)(sym->n_value + slide);
        }
    }
    return nullptr;
}

// _dyld_register_func_for_add_image callback. Fires once per loaded image
// (existing at registration time + each new load thereafter). We watch for
// Network.framework's load and capture nw_connection_create's address.
static void driftstackQuicDyldAddImageCallback(const struct mach_header* mh, intptr_t slide)
{
    if (g_nwConnectionCreateRequest.resolvedAddress)
        return; // already found

    // Find the image's path via dyld. We need to scan dyld's image list
    // to match mh against an image name. Use _dyld_get_image_header(i) +
    // _dyld_get_image_name(i) to find the index whose header == mh.
    uint32_t imageCount = _dyld_image_count();
    const char* imageName = nullptr;
    for (uint32_t i = 0; i < imageCount; i++) {
        if (_dyld_get_image_header(i) == mh) {
            imageName = _dyld_get_image_name(i);
            break;
        }
    }
    if (!imageName)
        return;

    if (!strstr(imageName, g_nwConnectionCreateRequest.targetImage))
        return; // not Network.framework

    void* addr = lookupSymbolInImage((const struct mach_header_64*)mh, slide,
                                     g_nwConnectionCreateRequest.targetSymbol);
    if (addr) {
        g_nwConnectionCreateRequest.resolvedAddress = addr;
        fprintf(stderr, "[Driftstack-EG-WK-1.10/Task#16/Slice16.6.g] G1 captured original nw_connection_create from Network.framework Mach-O symtab: addr=%p (image=%s, slide=0x%lx). Interpose recursion bypass armed.\n",
            addr, imageName, (long)slide);
        fflush(stderr);
    } else {
        fprintf(stderr, "[Driftstack-EG-WK-1.10/Task#16/Slice16.6.g] G1 found Network.framework image but %s symbol not in LC_SYMTAB. Mach-O parse failed.\n",
            g_nwConnectionCreateRequest.targetSymbol);
        fflush(stderr);
    }
}

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

    // Slice 16.6.g: register the dyld add-image callback. Fires once per
    // existing image immediately + once per newly-loaded image thereafter.
    // We use it to capture Network.framework's nw_connection_create
    // address from its Mach-O symbol table — bypassing dyld's interpose
    // binding mechanism that redirects dlsym-returned function pointers.
    _dyld_register_func_for_add_image(driftstackQuicDyldAddImageCallback);
    fprintf(stderr, "[Driftstack-EG-WK-1.10/Task#16/Slice16.6.g] _dyld_register_func_for_add_image callback registered for Network.framework symbol capture\n");
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
typedef bool (*DriftstackQuicParamsUseUdpFn)(nw_parameters_t);
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
    // Wave 29-499 Slice 16.6.g G1 FIX (recursion bypass):
    // Use the address captured by the _dyld_register_func_for_add_image
    // callback from Network.framework's Mach-O symbol table. This bypasses
    // dyld's interpose binding mechanism that redirects dlsym-returned
    // function pointers. Slice 16.6.f's dlopen+dlsym still recursed
    // because the BINDING for the function pointer call site honors the
    // interpose table; only the raw symbol-table address bypasses it.
    if (!g_nwConnectionCreateRequest.resolvedAddress) {
        static bool loggedAbsenceOnce = false;
        if (!loggedAbsenceOnce) {
            loggedAbsenceOnce = true;
            fprintf(stderr, "[Driftstack-EG-WK-1.10/Task#16/Slice16.6.g] G1 captured address not yet populated. Network.framework may not be loaded yet. Interpose falls through (returning nullptr will fail this connection).\n");
            fflush(stderr);
            NSLog(@"[Driftstack-EG-WK-1.10/Task#16/Slice16.6.g] G1 address unavailable — Network.framework not yet loaded");
        }
        return;
    }
    originalNwConnectionCreate = reinterpret_cast<NwConnectionCreateFn>(g_nwConnectionCreateRequest.resolvedAddress);
    fprintf(stderr, "[Driftstack-EG-WK-1.10/Task#16/Slice16.6.g] originalNwConnectionCreate populated from G1 Mach-O lookup: %p\n",
        g_nwConnectionCreateRequest.resolvedAddress);
    fflush(stderr);
}

// Cached pointers to bridge symbols resolved at first use via
// dlsym(RTLD_DEFAULT, ...) — WebKit framework must be loaded into the
// process before these resolve (loaded right after the interpose dylib
// during NetworkProcess launch).
static DriftstackQuicIsActiveFn bridgeIsActive = nullptr;
static DriftstackQuicParamsUseQuicFn bridgeParamsUseQuic = nullptr;
static DriftstackQuicParamsUseUdpFn bridgeParamsUseUdp = nullptr;
static DriftstackQuicCreateRelayFn bridgeCreateRelay = nullptr;

static void resolveBridgeSymbols()
{
    if (bridgeIsActive && bridgeParamsUseQuic && bridgeCreateRelay)
        return;
    bridgeIsActive = reinterpret_cast<DriftstackQuicIsActiveFn>(dlsym(RTLD_DEFAULT, "driftstack_quic_isCustomSocks5Active"));
    bridgeParamsUseQuic = reinterpret_cast<DriftstackQuicParamsUseQuicFn>(dlsym(RTLD_DEFAULT, "driftstack_quic_parametersUseQuic"));
    // Slice 16.7.b: optional UDP-transport predicate (may be nullptr if
    // the framework was built before the symbol was added; fall through
    // to QUIC-only check in that case).
    bridgeParamsUseUdp = reinterpret_cast<DriftstackQuicParamsUseUdpFn>(dlsym(RTLD_DEFAULT, "driftstack_quic_parametersUseUdpTransport"));
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

    // Wave 29-499 Slice 16.7.b — broader gate: route any UDP-transport
    // nw_connection through SOCKS5 relay (covers QUIC HTTP/3, WebRTC ICE,
    // raw-datagram UDP, future protocols). The relay infrastructure
    // (createRelayConnectionForQuic + nw_framer §7 wrap/unwrap) handles
    // both QUIC and plain UDP identically since SOCKS5 UDP_ASSOCIATE is
    // payload-agnostic at the relay framing layer.
    bool needsRelay = false;
    if (bridgeParamsUseUdp && bridgeParamsUseUdp(parameters))
        needsRelay = true;
    else if (bridgeParamsUseQuic(parameters))
        needsRelay = true;
    if (!needsRelay)
        return originalNwConnectionCreate(endpoint, parameters);

    static bool loggedOnce = false;
    if (!loggedOnce) {
        loggedOnce = true;
        NSLog(@"[Driftstack-EG-WK-1.10/Task#16] driftstack_nw_connection_create: FIRST UDP/QUIC interpose match — redirecting to driftstack_quic_createRelayConnection. Slice 16.7.b broader UDP-transport gate ACTIVE.");
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
