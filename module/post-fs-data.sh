#!/system/bin/sh
# Runs early in boot, before apps start.
# Patches vermagic in the .ko to match the running kernel, then loads it.

MODDIR="${0%/*}"
KO="$MODDIR/vpnhide_kmod.ko"
PATCHED="/data/adb/vpnhide_kmod/vpnhide_kmod.ko"
PERSIST_DIR="/data/adb/vpnhide_kmod"

# Skip if already loaded
if grep -q vpnhide_kmod /proc/modules 2>/dev/null; then
    exit 0
fi

if [ ! -f "$KO" ]; then
    exit 1
fi

mkdir -p "$PERSIST_DIR"

# Get the running kernel's vermagic components
KVER="$(uname -r)"
# Full vermagic as the kernel expects it:
# "<uname -r> SMP preempt mod_unload modversions aarch64"
VERMAGIC="$KVER SMP preempt mod_unload modversions aarch64"

# The .ko contains a vermagic string in the .modinfo section.
# We replace whatever placeholder vermagic was compiled in with
# the actual running kernel's vermagic. Both are null-terminated
# strings inside an ELF section, so we overwrite byte-for-byte
# and pad with nulls.
#
# Strategy: copy the .ko, find the vermagic= offset, overwrite.
cp "$KO" "$PATCHED"

# Use a small sed trick: find "vermagic=" in the binary, replace
# everything until the next null byte with our vermagic.
# This works because the .modinfo section stores key=value\0 pairs.
python3 -c "
import sys
data = open('$PATCHED', 'rb').read()
marker = b'vermagic='
idx = data.find(marker)
if idx < 0:
    sys.exit(1)
start = idx + len(marker)
# Find the null terminator of the old vermagic
end = data.index(b'\x00', start)
old_len = end - start
new_val = b'$VERMAGIC'
if len(new_val) > old_len:
    # Truncate if new is longer (shouldn't happen with our padding)
    new_val = new_val[:old_len]
# Pad with nulls to fill the old space
new_val = new_val + b'\x00' * (old_len - len(new_val))
data = data[:start] + new_val + data[end:]
open('$PATCHED', 'wb').write(data)
" 2>/dev/null

if [ $? -ne 0 ]; then
    # Fallback: try loading without patching (might work if vermagic matches)
    PATCHED="$KO"
fi

insmod "$PATCHED" && log -t vpnhide "kernel module loaded for $KVER"
