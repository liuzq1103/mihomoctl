#!/bin/sh
# Run from a locally reviewed, extracted mihomoctl-go basic/offline bundle.
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
helper="$root/bin/deliveryctl"
[ -f "$root/release-manifest.json" ] || { echo 'Use a complete reviewed release bundle.' >&2; exit 1; }
[ -f "$helper" ] && [ ! -L "$helper" ] || { echo 'Missing installation helper.' >&2; exit 1; }
# No download or checksum fetched alongside this script can establish trust.
chmod u+x "$helper"
exec "$helper" installation install --source "$root" "$@"
