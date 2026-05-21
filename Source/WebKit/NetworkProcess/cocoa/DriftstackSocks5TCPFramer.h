/*
 * DriftstackSocks5TCPFramer.h — Wave 29-499.112 (Task #104)
 *
 * Custom nw_framer_definition_t that injects SOCKS5 CONNECT handshake at
 * TCP connection start, then transparently forwards bytes between
 * CFNetwork and the relay (gost). Lets us bypass Apple's modern
 * nw_proxy_config_create_socksv5 (which triggers h3-disable gate) while
 * still routing TCP through SOCKS5 with auth.
 *
 * Flow:
 *   1. CFNetwork calls nw_connection_create(dest_endpoint, params)
 *   2. Our DYLD interpose catches it. For TCP path:
 *      - Replace dest_endpoint with gost SOCKS5 endpoint
 *      - Attach this framer to params' protocol stack
 *      - Save dest_endpoint in framer-local destination state
 *   3. nw_connection establishes TCP to gost (transparent to CFNetwork)
 *   4. Framer start_handler fires:
 *      - Sends SOCKS5 greeting (VER=5, NMETHODS=2, METHODS=[no-auth, user/pass])
 *      - Reads server response
 *      - If auth required, sends RFC 1929 user/pass auth
 *      - Sends CONNECT request to original dest (ATYP=0x01 IP or 0x03 domain)
 *      - Reads BND.ADDR+PORT response
 *      - On success: framer becomes transparent (no-op input/output handlers)
 *      - CFNetwork now sees a connected TCP stream to dest, sends app data
 *
 * Compared to nw_proxy_config_create_socksv5:
 *   - Same end-result for HTTPS / HTTP-2 routing
 *   - CFNetwork doesn't know there's a proxy → h3 not blocked
 *   - We control auth, can do RFC 1929 reliably
 */

#pragma once

#if PLATFORM(DRIFTSTACK)

#import <Network/Network.h>
#include <wtf/RetainPtr.h>
#include <wtf/text/WTFString.h>

namespace WebKit {
namespace DriftstackSocks5TCPFramer {

// Get the framer definition. Lazy-initialized; same instance reused for all
// connections. Returns nullptr if framer creation failed at definition time.
nw_protocol_definition_t getFramerDefinition();

// Stash destination metadata (host + port + auth creds) before
// nw_connection_create. The framer's start_handler reads from this stash
// for the SOCKS5 CONNECT request. Process-wide LIFO; current implementation
// supports one in-flight handshake per thread.
void setPendingTcpDestination(const String& destHost, uint16_t destPort,
                              const String& proxyUser, const String& proxyPass);

} // namespace DriftstackSocks5TCPFramer
} // namespace WebKit

#endif // PLATFORM(DRIFTSTACK)
