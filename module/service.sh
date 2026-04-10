#!/system/bin/sh
# Runs after boot-completed, when PackageManager is available.
# Resolves package names → UIDs and writes to /proc/vpnhide_targets.

PERSIST_DIR="/data/adb/vpnhide_kmod"
TARGETS_FILE="$PERSIST_DIR/targets.txt"
PROC_TARGETS="/proc/vpnhide_targets"

# Wait for the proc entry to appear (module must be loaded)
for i in 1 2 3 4 5; do
    [ -f "$PROC_TARGETS" ] && break
    sleep 1
done

if [ ! -f "$PROC_TARGETS" ]; then
    log -t vpnhide "kernel module not loaded, skipping UID resolution"
    exit 0
fi

if [ ! -f "$TARGETS_FILE" ]; then
    exit 0
fi

# Resolve package names to UIDs
UIDS=""
while IFS= read -r line; do
    line="$(echo "$line" | sed 's/^[[:space:]]*//' | sed 's/[[:space:]]*$//')"
    [ -z "$line" ] && continue
    echo "$line" | grep -q '^#' && continue

    uid="$(pm list packages -U "$line" 2>/dev/null | grep "^package:$line " | sed 's/.*uid://')"
    if [ -n "$uid" ]; then
        UIDS="$UIDS$uid
"
    fi
done < "$TARGETS_FILE"

if [ -n "$UIDS" ]; then
    echo "$UIDS" > "$PROC_TARGETS"
    count="$(echo "$UIDS" | grep -c .)"
    log -t vpnhide "loaded $count target UIDs into kernel module"
fi
