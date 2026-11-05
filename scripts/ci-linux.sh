#!/bin/sh
# Execute on the requested architecture, directly or inside an explicit QEMU VM/container.
set -eu
expected=${1:?expected Go architecture}
[ "$(go env GOARCH)" = "$expected" ]
case "$expected:$(uname -m)" in amd64:x86_64|arm64:aarch64) ;; *) echo 'architecture execution mismatch' >&2; exit 1;; esac
go vet ./...
go test -race -count=1 ./...
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
    useradd --create-home --user-group bundle-smoke
    install -o bundle-smoke -g bundle-smoke -m 600 "$offline" /home/bundle-smoke/offline.tar.gz
    install -o bundle-smoke -g bundle-smoke -m 600 "$basic" /home/bundle-smoke/basic.tar.gz
    su -s /bin/sh bundle-smoke -c "sh /work/scripts/smoke-bundle.sh /home/bundle-smoke/offline.tar.gz /home/bundle-smoke/basic.tar.gz"
else
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
