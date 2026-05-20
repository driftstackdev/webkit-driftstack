/*
 * DriftstackQuicSocks5Exports.h
 *
 * Wave 29-499 §92 Slice 16.6.b PRODUCTION FIX — extern "C" declarations
 * for the SOCKS5 QUIC interpose mechanism's dlsym-resolvable symbols.
 *
 * This header MUST be installed as a PrivateHeader in the WebKit
 * framework's Headers Copy phase. Without an installed declaration, TAPI
 * (GenerateTAPI / InstallAPI verification) on Release builds rejects the
 * corresponding exported symbols with:
 *
 *     error: no declaration found for exported symbol
 *     '_driftstack_quic_*' in dynamic library
 *
 * Background — the interpose mechanism:
 *
 *   libDriftstackQuicInterpose.dylib is loaded into NetworkProcess via
 *   DYLD_INSERT_LIBRARIES BEFORE WebKit framework. The dylib cannot
 *   statically link WebKit (circular load order). Instead, it resolves
 *   WebKit-provided bridge functions at runtime via:
 *
 *     dlsym(RTLD_DEFAULT, "driftstack_quic_isCustomSocks5Active")
 *     dlsym(RTLD_DEFAULT, "driftstack_quic_parametersUseQuic")
 *     dlsym(RTLD_DEFAULT, "driftstack_quic_createRelayConnection")
 *
 *   plus the 12 Slice 16.6 observability counters used by the harness
 *   telemetry daemon for dashboard panels.
 *
 * For dlsym to find these symbols, they MUST be exported from the WebKit
 * framework binary. WebKit framework builds with -fvisibility=hidden by
 * default, which strips un-annotated extern "C" symbols at link time.
 * The DRIFTSTACK_QUIC_EXPORT macro applies
 * __attribute__((visibility("default"))) so the symbols are visible in
 * the framework's exported symbol table.
 *
 * Pre-fix audit (V-820.B.1.l + Slice 16.6 nm -gU check):
 *   `nm -gU WebKit.framework/Versions/A/WebKit | grep driftstack_quic`
 *   returned (no output) — confirming silent inert state where the
 *   interpose dylib's dlsym calls returned NULL → fallthrough to
 *   original nw_connection_create → QUIC packets bypass SOCKS5 relay
 *   → real IP leak for HTTP/3 + WebTransport in production.
 *
 * Post-fix (this header installed + visibility annotations applied):
 *   All 15 symbols present in `nm -gU` output. The audit-triangle's
 *   V-820.B.1.l nm -gU check guards against regression for any future
 *   interpose patch.
 *
 * Naming convention: driftstack_quic_<lowercased_camel_case> matches the
 * dylib's dlsym lookup table. Stable across WebKit framework releases.
 */

#pragma once

#if defined(PLATFORM_DRIFTSTACK) || defined(__APPLE__)

#import <Network/Network.h>
#include <stdint.h>
#include <stdbool.h>

#define DRIFTSTACK_QUIC_EXPORT __attribute__((visibility("default")))

#ifdef __cplusplus
extern "C" {
#endif

// Wave 29-397 Slice 16.4.b.5.b — functional bridge accessors used by
// libDriftstackQuicInterpose.dylib at runtime to gate / build the QUIC
// SOCKS5 routing path.
DRIFTSTACK_QUIC_EXPORT bool driftstack_quic_isCustomSocks5Active(void);
DRIFTSTACK_QUIC_EXPORT bool driftstack_quic_parametersUseQuic(nw_parameters_t parameters);
DRIFTSTACK_QUIC_EXPORT nw_connection_t driftstack_quic_createRelayConnection(nw_endpoint_t endpoint, nw_parameters_t parameters);

// Wave 29-499 Slice 16.7.b — broader UDP-transport detector to catch WebRTC
// + raw-datagram UDP nw_connections so they route through createRelayConnection
// (the existing SOCKS5 UDP_ASSOCIATE relay).
DRIFTSTACK_QUIC_EXPORT bool driftstack_quic_parametersUseUdpTransport(nw_parameters_t parameters);

// Wave 29-397 Slice 16.6 — production observability counters polled by
// harness telemetry daemon for dashboard panels.
DRIFTSTACK_QUIC_EXPORT uint64_t driftstack_quic_counter_wrap_fires(void);
DRIFTSTACK_QUIC_EXPORT uint64_t driftstack_quic_counter_wrap_failures(void);
DRIFTSTACK_QUIC_EXPORT uint64_t driftstack_quic_counter_unwrap_fires(void);
DRIFTSTACK_QUIC_EXPORT uint64_t driftstack_quic_counter_unwrap_failures(void);
DRIFTSTACK_QUIC_EXPORT uint64_t driftstack_quic_counter_framer_output_fires(void);
DRIFTSTACK_QUIC_EXPORT uint64_t driftstack_quic_counter_framer_input_fires(void);
DRIFTSTACK_QUIC_EXPORT uint64_t driftstack_quic_counter_framer_without_destination(void);
DRIFTSTACK_QUIC_EXPORT uint64_t driftstack_quic_counter_framer_wrap_failures(void);
DRIFTSTACK_QUIC_EXPORT uint64_t driftstack_quic_counter_relay_establish_failures(void);
DRIFTSTACK_QUIC_EXPORT uint64_t driftstack_quic_counter_relay_connection_create_failures(void);
DRIFTSTACK_QUIC_EXPORT uint64_t driftstack_quic_counter_attach_framer_failures(void);
DRIFTSTACK_QUIC_EXPORT uint64_t driftstack_quic_counter_endpoint_extract_failures(void);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // PLATFORM_DRIFTSTACK || __APPLE__
