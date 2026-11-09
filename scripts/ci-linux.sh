#!/bin/sh
# Execute on the requested architecture, directly or inside an explicit QEMU VM/container.
set -eu
expected=${1:?expected Go architecture}
[ "$(go env GOARCH)" = "$expected" ]
case "$expected:$(uname -m)" in amd64:x86_64|arm64:aarch64) ;; *) echo 'architecture execution mismatch' >&2; exit 1;; esac
race_flag=
if [ "$expected" = amd64 ]; then
    race_flag=-race
else
    echo 'arm64 QEMU: ThreadSanitizer VMA layout is unsupported; race testing is NOT executed here. amd64 CI supplies race coverage.' >&2
    # The emulated process group carries no stable kernel start time, so the
    # /proc ownership proof cannot bind to a process identity under emulation.
    # The tests that are about that proof are skipped here and are covered by
    # the native amd64 job; the gate states the gap instead of hiding it.
    MIHOMOCTL_GO_TEST_EMULATED=1
    export MIHOMOCTL_GO_TEST_EMULATED
    echo 'arm64 QEMU: the emulated kernel exposes no stable process identity; the kernel ownership proof is NOT exercised here. amd64 CI supplies that coverage.' >&2
fi
go vet ./...
go build -o /tmp/mihomoctl-go-ci .
go build -o /tmp/mihomoctl-go-delivery ./scripts/deliveryctl
# Product dispatch is part of acceptance: this fails if the root is still only a TUI.
/tmp/mihomoctl-go-ci version --json > /tmp/mihomoctl-go-version.json
grep '"version"[[:space:]]*:[[:space:]]*"0.2.0"' /tmp/mihomoctl-go-version.json
grep 'mihomoctl-go' /tmp/mihomoctl-go-version.json
if [ "$expected" = amd64 ]; then
    /tmp/mihomoctl-go-delivery core install --version v1.19.33 --dry-run > /tmp/mihomoctl-go-core.json
    grep '"activated":false' /tmp/mihomoctl-go-core.json
else
    /tmp/mihomoctl-go-delivery core install --version v1.19.33 --dry-run > /tmp/mihomoctl-go-core.json
    grep 'ba408b317080ee265c46cb923a50018c1b82cbd708551cdd46a1e3e307396187' /tmp/mihomoctl-go-core.json
fi
go run ./scripts/release -arch "$expected" -offline -out /tmp/mihomoctl-go-candidate
for kind in basic offline; do
    archive="/tmp/mihomoctl-go-candidate/mihomoctl-go-0.2.0-$kind-linux-$expected.tar.gz"
    digest=$(sha256sum "$archive")
    go run ./scripts/verifyrelease -archive "$archive" -sha256 "${digest%% *}" -execute
done
offline="/tmp/mihomoctl-go-candidate/mihomoctl-go-0.2.0-offline-linux-$expected.tar.gz"
basic="/tmp/mihomoctl-go-candidate/mihomoctl-go-0.2.0-basic-linux-$expected.tar.gz"
if [ "$(id -u)" -eq 0 ]; then
    # A root-only test run skips the user-scope mutation fixtures. Run root
    # ownership tests first, then the full suite under a distinct account
    # with a reviewed core of the architecture actually being executed.
    go test $race_flag -count=1 ./...
    useradd --create-home --user-group go-acceptance
    runuser -u go-acceptance -- git config --global --add safe.directory "$PWD"
    install -d -o go-acceptance -g go-acceptance -m 0700 /home/go-acceptance/core
    tar -xOf "$offline" core/mihomo > /home/go-acceptance/core/mihomo
    chown go-acceptance:go-acceptance /home/go-acceptance/core/mihomo
    chmod 0700 /home/go-acceptance/core/mihomo
    runuser -u go-acceptance -- env PATH="$PATH" \
        GOPATH=/home/go-acceptance/go \
        GOCACHE=/home/go-acceptance/.cache/go-build \
        GOMODCACHE=/home/go-acceptance/go/pkg/mod \
        MIHOMOCTL_GO_TEST_CORE=/home/go-acceptance/core/mihomo \
        go test $race_flag -count=1 -timeout 15m ./...
    useradd --create-home --user-group bundle-smoke
    install -o bundle-smoke -g bundle-smoke -m 600 "$offline" /home/bundle-smoke/offline.tar.gz
    install -o bundle-smoke -g bundle-smoke -m 600 "$basic" /home/bundle-smoke/basic.tar.gz
    su -s /bin/sh bundle-smoke -c "sh /work/scripts/smoke-bundle.sh /home/bundle-smoke/offline.tar.gz /home/bundle-smoke/basic.tar.gz"
else
    core_work=$(mktemp -d "$HOME/.mihomoctl-go-ci-core.XXXXXXXX")
    # Only this newly allocated directory is eligible for cleanup.
    trap 'rm -f -- "$core_work/mihomo"; rmdir -- "$core_work"' EXIT HUP INT TERM
    chmod 0700 "$core_work"
    tar -xOf "$offline" core/mihomo > "$core_work/mihomo"
    chmod 0700 "$core_work/mihomo"
    MIHOMOCTL_GO_TEST_CORE="$core_work/mihomo" go test $race_flag -count=1 -timeout 15m ./...
    sh scripts/smoke-bundle.sh "$offline" "$basic"
fi
mkdir /tmp/mihomoctl-go-bundle
tar -xzf "/tmp/mihomoctl-go-candidate/mihomoctl-go-0.2.0-basic-linux-$expected.tar.gz" -C /tmp/mihomoctl-go-bundle
export XDG_DATA_HOME=/tmp/mihomoctl-go-xdg/data XDG_STATE_HOME=/tmp/mihomoctl-go-xdg/state XDG_CONFIG_HOME=/tmp/mihomoctl-go-xdg/config
scope=
if [ "$(id -u)" -eq 0 ]; then
    # Root tests must use --system. Do not touch host /var: this branch runs only
    # in disposable CI containers (the workflow mounts the checkout, nothing else).
    scope=--system
fi
sh /tmp/mihomoctl-go-bundle/install.sh $scope --bin-dir /tmp/mihomoctl-go-bin
/tmp/mihomoctl-go-bin/mihomoctl version --json
chmod u+x /tmp/mihomoctl-go-bundle/bin/deliveryctl
/tmp/mihomoctl-go-bundle/bin/deliveryctl installation status $scope
/tmp/mihomoctl-go-bundle/bin/deliveryctl update $scope --source /tmp/mihomoctl-go-bundle --reinstall --dry-run
sh /tmp/mihomoctl-go-bundle/uninstall.sh $scope
[ ! -e /tmp/mihomoctl-go-bin/mihomoctl ]
