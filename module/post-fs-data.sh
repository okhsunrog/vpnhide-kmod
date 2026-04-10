#!/system/bin/sh
# Runs early in boot, before apps start. Loads the kernel module.
# KernelSU bypasses vermagic check, so no patching needed.

MODDIR="${0%/*}"
KO="$MODDIR/vpnhide_kmod.ko"

# Skip if already loaded
if grep -q vpnhide_kmod /proc/modules 2>/dev/null; then
    exit 0
fi

if [ ! -f "$KO" ]; then
    log -t vpnhide "vpnhide_kmod.ko not found at $KO"
    exit 1
fi

insmod "$KO" && log -t vpnhide "kernel module loaded"
