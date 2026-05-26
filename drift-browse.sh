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
# run-minibrowser's `#!/usr/bin/env python3` resolves to Homebrew python@3.14,
# whose pyexpat can't link the system libexpat (missing _XML_SetAllocTracker…
# symbol) → webkitpy's port factory crashes on import. Pin an interpreter whose
# expat works: system /usr/bin/python3 (3.9) first, then Homebrew 3.10.
DRIFT_PY=""
for _py in /usr/bin/python3 /opt/homebrew/bin/python3.10; do
  if "$_py" -c "import xml.parsers.expat" >/dev/null 2>&1; then DRIFT_PY="$_py"; break; fi
done
: ${DRIFT_PY:=python3}
exec "$DRIFT_PY" Tools/Scripts/run-minibrowser --release "${@:-https://example.com/}"
