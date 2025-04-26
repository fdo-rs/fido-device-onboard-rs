#!/bin/bash

install_and_enable_unit() {
    unit="$1"; shift
    target="$1"; shift
    inst_simple "$moddir/$unit" "$systemdsystemunitdir/$unit"
    # note we `|| exit 1` here so we error out if e.g. the units are missing
    # see https://github.com/coreos/fedora-coreos-config/issues/799
    systemctl -q --root="$initdir" add-requires "$target" "$unit" || exit 1
}

install() {
    inst /usr/libexec/fdo/fdo-manufacturing-client /usr/bin/fdo-manufacturing-client

    inst_simple "$moddir/manufacturing-client-generator" \
        "$systemdutildir/system-generators/manufacturing-client-generator"

    inst_script "$moddir/manufacturing-client-service" \
        "/usr/libexec/manufacturing-client-service"

    install_and_enable_unit "manufacturing-client.service" \
        "initrd.target"
}
