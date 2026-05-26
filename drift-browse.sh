#!/usr/bin/env zsh
# Driftstack MiniBrowser launcher.
# Sources the canonical production env (Path B v2 loader + custom QUIC engine + h3 +
# DNSRR + iPhone TLS) then launches via run-minibrowser (forwards DYLD_FRAMEWORK_PATH to
# the web processes so they load the local build — raw-binary launch renders white).
# DRIFTSTACK_PATHB_V2=1 is what activates DriftstackNetworkLoader, whose driftstackHttp3Execute
# tunnels HTTP/3 through the SOCKS5 §7 UDP relay. Without it the browser uses CFNetwork's
# native QUIC, which can't use SOCKS5 UDP → no QUIC through the proxy.
# Proxy creds auto-source from ~/.driftstack-secrets.env via ~/.zshenv.
cd "${0:A:h}"
source ~/code/driftstack/operations/scripts/production-env/launch-env-v1.sh
exec Tools/Scripts/run-minibrowser --release "${@:-https://example.com/}"
