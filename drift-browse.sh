#!/usr/bin/env zsh
# Driftstack MiniBrowser launcher.
# Uses Tools/Scripts/run-minibrowser, which sets DYLD_FRAMEWORK_PATH to the local
# WebKit build AND forwards it to the WebContent/GPU/Networking XPC processes.
# Launching the raw MiniBrowser binary directly does NOT forward that env, so the
# web processes can't load the local framework and every page renders white.
# Proxy creds (DRIFTSTACK_SOCKS5_*) are auto-sourced from ~/.driftstack-secrets.env
# via ~/.zshenv; this enables the SOCKS5 customer-proxy path.
cd "${0:A:h}"
export DRIFTSTACK_CUSTOM_SOCKS5=1
exec Tools/Scripts/run-minibrowser --release "${@:-https://example.com/}"
