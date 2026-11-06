#!/bin/sh
# Called with sudo only by disposable Ubuntu systemd acceptance jobs.
set -eu
[ "${GITHUB_ACTIONS:-}" = true ]
[ "$(id -u)" -eq 0 ]
[ "$(cat /proc/1/comm)" = systemd ]
archive=${1:?reviewed offline bundle}
testbin=${2:?compiled native runtimecore test binary}
test -x "$testbin"
# The fixture refuses pre-existing namespaces and binds cleanup to its receipt
# and random token. Run it before installation smoke creates any scope state.
for p in /etc/mihomoctl-go /var/lib/mihomoctl-go /var/cache/mihomoctl-go /run/mihomoctl-go /run/mihomoctl-go-core /etc/systemd/system/mihomoctl-go.service; do
    test ! -e "$p"
done
core_root=/root/mihomoctl-go-ci-core
test ! -e "$core_root"
install -d -o root -g root -m 0755 "$core_root"
trap 'rm -f -- "$core_root/mihomo" "$core_root/core.gz" "$core_root/privileged.log"; rmdir -- "$core_root"' EXIT HUP INT TERM
tar -xOf "$archive" core/mihomo-linux-amd64-compatible-v1.19.33.gz > "$core_root/core.gz"
printf '%s\n' '386508bfb1c72c43b6a0eda73708ecdce82546581b0ebcb16366c53757c622b6  core.gz' | (cd "$core_root" && sha256sum -c -)
# Derive executable bytes directly from the reviewed archive, rather than trust
# an unrelated extracted executable. Ancestors and candidate stay root-owned.
gzip -dc "$core_root/core.gz" > "$core_root/mihomo"
chown root:root "$core_root/mihomo"
chmod 0755 "$core_root/mihomo"
"$testbin" -test.list '^TestPrivilegedSystemdTunAndSSH$' | grep -x TestPrivilegedSystemdTunAndSSH
if env MIHOMOCTL_GO_PRIVILEGED=1 MIHOMOCTL_GO_TEST_CORE="$core_root/mihomo" \
    "$testbin" -test.run '^TestPrivilegedSystemdTunAndSSH$' -test.v -test.timeout 20m \
    > "$core_root/privileged.log" 2>&1; then
    cat "$core_root/privileged.log"
else
    cat "$core_root/privileged.log"
    exit 1
fi
grep '^--- PASS: TestPrivilegedSystemdTunAndSSH ' "$core_root/privileged.log"
# newPrivilegedFixture/cleanup removes these only after verifying its own
# namespace/token receipt. Refuse to proceed to smoke if any cleanup is pending.
for p in /etc/mihomoctl-go /var/lib/mihomoctl-go /var/cache/mihomoctl-go /run/mihomoctl-go /run/mihomoctl-go-core /etc/systemd/system/mihomoctl-go.service; do
    test ! -e "$p"
done
