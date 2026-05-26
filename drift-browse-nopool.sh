#!/usr/bin/env zsh
# Temporary variant: connection pooling OFF. Use for heavy concurrent-resource SPAs
# (e.g. networktest.twilio.com) that currently garble under the H2-pool header-demux race.
# WebRTC/STUN are unaffected by this flag. Production launcher is drift-browse.sh (pools on).
cd "${0:A:h}"
source ~/code/driftstack/operations/scripts/production-env/launch-env-v1.sh
export DRIFTSTACK_H2_POOL=0 __XPC_DRIFTSTACK_H2_POOL=0 DRIFTSTACK_H3_POOL=0 __XPC_DRIFTSTACK_H3_POOL=0
# See drift-browse.sh: Homebrew python@3.14 broke run-minibrowser's expat import.
DRIFT_PY=""
for _py in /usr/bin/python3 /opt/homebrew/bin/python3.10; do
  if "$_py" -c "import xml.parsers.expat" >/dev/null 2>&1; then DRIFT_PY="$_py"; break; fi
done
: ${DRIFT_PY:=python3}
exec "$DRIFT_PY" Tools/Scripts/run-minibrowser --release "${@:-https://networktest.twilio.com/}"
