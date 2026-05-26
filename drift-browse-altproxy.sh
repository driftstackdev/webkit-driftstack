#!/usr/bin/env zsh
# Alternate-proxy test launcher (e.g. TCP-ONLY / no-UDP proxies). Sources the
# canonical production env, then OVERRIDES the SOCKS5 proxy from
# ~/.driftstack-altproxy.env (OUTSIDE the repo — never committed, per the
# credentials-via-env-only policy). Create that file with three lines:
#   export DRIFTSTACK_SOCKS5_PROXY=host:port
#   export DRIFTSTACK_SOCKS5_USER=...
#   export DRIFTSTACK_SOCKS5_PASS=...
# The UDP_ASSOCIATE probe (Slice16.7.a) auto-detects whether the proxy supports
# UDP; a TCP-only proxy → h3/WebRTC-UDP auto-disabled, everything runs over h2/TCP.
cd "${0:A:h}"
source ~/code/driftstack/operations/scripts/production-env/launch-env-v1.sh
if [[ -f ~/.driftstack-altproxy.env ]]; then
  source ~/.driftstack-altproxy.env
  # mirror to the XPC-forwarded names so the WebProcess/Networking process sees them
  export __XPC_DRIFTSTACK_SOCKS5_PROXY="$DRIFTSTACK_SOCKS5_PROXY"
  export __XPC_DRIFTSTACK_SOCKS5_USER="$DRIFTSTACK_SOCKS5_USER"
  export __XPC_DRIFTSTACK_SOCKS5_PASS="$DRIFTSTACK_SOCKS5_PASS"
  echo "[altproxy] using override proxy host=${DRIFTSTACK_SOCKS5_PROXY%%:*} (creds from ~/.driftstack-altproxy.env)"
else
  echo "[altproxy] WARNING: ~/.driftstack-altproxy.env not found — using default proxy"
fi
DRIFT_PY=""
for _py in /usr/bin/python3 /opt/homebrew/bin/python3.10; do
  if "$_py" -c "import xml.parsers.expat" >/dev/null 2>&1; then DRIFT_PY="$_py"; break; fi
done
: ${DRIFT_PY:=python3}
exec "$DRIFT_PY" Tools/Scripts/run-minibrowser --release "${@:-https://browserleaks.com/ip}"
