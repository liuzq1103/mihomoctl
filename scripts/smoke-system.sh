#!/bin/sh
# Real systemd acceptance on a disposable privileged GitHub Linux runner.
set -eu
[ "${GITHUB_ACTIONS:-}" = true ] || { echo 'disposable GitHub runner required' >&2; exit 1; }
[ "$(id -u)" -eq 0 ]
[ "$(cat /proc/1/comm)" = systemd ]
archive=${1:?reviewed offline bundle}
[ ! -e /var/lib/mihomoctl-go/install ]
[ ! -e /etc/mihomoctl-go/manager.yaml ]
work=$(mktemp -d /tmp/mihomoctl-go-system.XXXXXXXX)
case "$work" in /tmp/mihomoctl-go-system.*) ;; *) exit 1;; esac
cli="$work/bin/mihomoctl"
started=no
cleanup(){
    if [ -x "$cli" ]; then
        if [ "$started" = yes ]; then "$cli" --system service stop --json >/dev/null 2>&1 || true; fi
        "$cli" --system service uninstall --json >/dev/null 2>&1 || true
        "$cli" --system installation uninstall --json >/dev/null 2>&1 || true
    fi
    rm -rf -- "$work"
}
trap cleanup EXIT HUP INT TERM
mkdir -m 700 "$work/bundle"
tar -xzf "$archive" -C "$work/bundle"
sh "$work/bundle/install.sh" --system --bin-dir "$work/bin"
case "$(uname -m)" in
    x86_64) variant=amd64-compatible; sha=386508bfb1c72c43b6a0eda73708ecdce82546581b0ebcb16366c53757c622b6;;
    aarch64) variant=arm64; sha=ba408b317080ee265c46cb923a50018c1b82cbd708551cdd46a1e3e307396187;;
    *) exit 1;;
esac
"$cli" --system core install --version v1.19.33 --asset "$work/bundle/core/mihomo-linux-$variant-v1.19.33.gz" --json
core="/var/lib/mihomoctl-go/cores/v1.19.33-$(printf %.16s "$sha")/mihomo"
"$cli" --system core list --json
"$cli" --system init --core "$core" --json
"$cli" --system config validate --json
"$cli" --system service install --json
"$cli" --system service start --json
started=yes
"$cli" --system service status --json
"$cli" --system health --json
"$cli" --system update "$work/bundle" --allow-same-version --dry-run --json
"$cli" --system service stop --json
started=no
# A percent sign in a managed path is literal in systemd's path-list settings:
# systemd does not expand specifiers there (verified on systemd 249 and 255),
# while it does expand them in the command line, where the unit escapes the
# percent. A core that lives at such a path has to load and its mounts have to
# resolve, on the systemd that runs this job.
pctcore=/var/lib/mihomoctl-go/cores/100%/mihomo
mkdir -p "$(dirname "$pctcore")"
install -m 0700 "$core" "$pctcore"
"$cli" --system core adopt --path "$pctcore" --json
"$cli" --system service start --json
started=yes
"$cli" --system service status --json
"$cli" --system health --json
"$cli" --system service stop --json
started=no
"$cli" --system service uninstall --json
"$cli" --system installation uninstall --json
[ -f "$core" ]
echo 'privileged systemd bundle acceptance passed'
