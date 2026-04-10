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

# Get all packages with UIDs in one call
ALL_PACKAGES="$(pm list packages -U 2>/dev/null)"

# Resolve each target package name to its UID
UIDS=""
while IFS= read -r line || [ -n "$line" ]; do
    # Trim whitespace
    pkg="$(echo "$line" | tr -d '[:space:]')"
    [ -z "$pkg" ] && continue
    # Skip comments
    case "$pkg" in \#*) continue ;; esac

    # Find UID: pm list packages -U outputs "package:<name> uid:<uid>"
    uid="$(echo "$ALL_PACKAGES" | grep "^package:${pkg} " | sed 's/.*uid://')"
    if [ -n "$uid" ]; then
        if [ -z "$UIDS" ]; then
            UIDS="$uid"
        else
            UIDS="${UIDS}
${uid}"
        fi
    else
        log -t vpnhide "package not found: $pkg"
    fi
done < "$TARGETS_FILE"

if [ -n "$UIDS" ]; then
    echo "$UIDS" > "$PROC_TARGETS"
    count="$(echo "$UIDS" | wc -l)"
    log -t vpnhide "loaded $count target UIDs into kernel module"
else
    log -t vpnhide "no UIDs resolved from targets.txt"
fi
