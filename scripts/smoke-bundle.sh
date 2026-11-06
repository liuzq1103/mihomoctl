#!/bin/sh
# User-scope native acceptance of a locally built/reviewed offline bundle.
# Requires ordinary Linux shell utilities, no Go/Python/Docker/systemd runtime.
set -eu
archive=${1:?reviewed offline bundle path}
basic_archive=${2:-}
case "$archive" in /*) ;; *) echo 'absolute bundle path required' >&2; exit 1;; esac
[ "$(id -u)" -ne 0 ] || { echo 'user-scope smoke requires a non-root user' >&2; exit 1; }
work=$(mktemp -d "$HOME/.mihomoctl-go-smoke.XXXXXXXX")
case "$work" in "$HOME"/.mihomoctl-go-smoke.*) ;; *) exit 1;; esac
started=no
cleanup(){
    if [ "$started" = yes ]; then
        "$work/bundle/bin/mihomoctl" stop --json >/dev/null 2>&1 || true
    fi
    rm -rf -- "$work"
}
trap cleanup EXIT HUP INT TERM
chmod 700 "$work"
mkdir -m 700 "$work/bundle"
tar -xzf "$archive" -C "$work/bundle"
export PATH=/usr/bin:/bin
export XDG_DATA_HOME="$work/data" XDG_STATE_HOME="$work/state" XDG_CONFIG_HOME="$work/config" XDG_CACHE_HOME="$work/cache" XDG_RUNTIME_DIR="$work/runtime"
export HTTP_PROXY=http://127.0.0.1:1 HTTPS_PROXY=http://127.0.0.1:1 ALL_PROXY=http://127.0.0.1:1
export http_proxy=$HTTP_PROXY https_proxy=$HTTPS_PROXY all_proxy=$ALL_PROXY
sh "$work/bundle/install.sh" --bin-dir "$work/bin"
cli="$work/bin/mihomoctl"
"$cli" version --json
"$cli" installation status --json
"$cli" installation recover --json
case "$(uname -m)" in
    x86_64) variant=amd64-compatible; sha=386508bfb1c72c43b6a0eda73708ecdce82546581b0ebcb16366c53757c622b6;;
    aarch64) variant=arm64; sha=ba408b317080ee265c46cb923a50018c1b82cbd708551cdd46a1e3e307396187;;
    *) exit 1;;
esac
asset="$work/bundle/core/mihomo-linux-$variant-v1.19.33.gz"
chmod u+x "$work/bundle/bin/deliveryctl"
"$work/bundle/bin/deliveryctl" core install --version v1.19.33 --asset "$asset"
"$cli" core list --json
core="$XDG_DATA_HOME/mihomoctl-go/cores/v1.19.33-$(printf %.16s "$sha")/mihomo"
"$core" -v
generation=$(cat "$XDG_DATA_HOME/mihomoctl-go/install/current")
bundled_core="$XDG_DATA_HOME/mihomoctl-go/install/generations/$generation/core/mihomo"
"$cli" init --core "$bundled_core" --json
"$cli" start --json
started=yes
bundled_pid=$("$cli" status --json | sed -n 's/.*"pid":\([0-9][0-9]*\).*/\1/p')
if "$cli" installation uninstall --json > "$work/refused-uninstall.json"; then
    echo 'Uninstall incorrectly removed a configured bundled core' >&2
    exit 1
fi
grep 'uninstall-core-inside-program-root' "$work/refused-uninstall.json"
[ -x "$bundled_core" ]
[ "$bundled_pid" = "$("$cli" status --json | sed -n 's/.*"pid":\([0-9][0-9]*\).*/\1/p')" ]
"$cli" stop --json
started=no
"$cli" core adopt --path "$core" --json
"$cli" config validate --json
"$cli" start --json
started=yes
pid_before=$("$cli" status --json | sed -n 's/.*"pid":\([0-9][0-9]*\).*/\1/p')
case "$pid_before" in ''|0|*[!0-9]*) exit 1;; esac
before=$(sha256sum "$XDG_CONFIG_HOME/mihomoctl-go/manager.yaml" "$core")
previous_generation=$(cat "$XDG_DATA_HOME/mihomoctl-go/install/current")
update_source="$work/bundle"
if [ -n "$basic_archive" ]; then
    mkdir -m 700 "$work/basic"
    tar -xzf "$basic_archive" -C "$work/basic"
    update_source="$work/basic"
fi
"$cli" update "$update_source" --allow-same-version --dry-run --json
"$cli" update "$update_source" --allow-same-version --json
after=$(sha256sum "$XDG_CONFIG_HOME/mihomoctl-go/manager.yaml" "$core")
[ "$before" = "$after" ]
pid_after=$("$cli" status --json | sed -n 's/.*"pid":\([0-9][0-9]*\).*/\1/p')
[ "$pid_before" = "$pid_after" ]
if [ -n "$basic_archive" ]; then
    [ "$previous_generation" != "$(cat "$XDG_DATA_HOME/mihomoctl-go/install/current")" ]
fi
"$cli" stop --json
started=no
"$cli" installation uninstall --dry-run --json
"$cli" installation uninstall --json
[ ! -e "$cli" ]
[ ! -e "$XDG_DATA_HOME/mihomoctl-go/install" ]
[ -f "$core" ]
[ -f "$XDG_CONFIG_HOME/mihomoctl-go/manager.yaml" ]
"$work/bundle/bin/deliveryctl" installation status
"$work/bundle/bin/deliveryctl" installation uninstall
sh "$work/bundle/install.sh" --bin-dir "$work/bin"
"$cli" version --json
"$cli" installation uninstall --json
[ ! -e "$XDG_DATA_HOME/mihomoctl-go/install" ]
[ -f "$core" ]
echo 'native offline bundle smoke: verified CLI/core, same-PID update, full program uninstall, repeat uninstall and reinstall; config/independent core preserved'
