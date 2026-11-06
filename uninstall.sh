#!/bin/sh
# Removes receipt-owned program code and launcher; configuration and independent cores remain.
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
helper="$root/bin/deliveryctl"
if [ -f "$helper" ] && [ ! -L "$helper" ]; then
    chmod u+x "$helper"
    exec "$helper" installation uninstall "$@"
fi
exec mihomoctl installation uninstall "$@"
