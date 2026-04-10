# Building vpnhide-kmod for a new device

This guide walks through building the kernel module for any Android
device with a GKI 2.0 kernel (Android 12+, kernel 5.10+). The process
was developed and tested on Pixel 8 Pro (android14-6.1) and applies
identically to any GKI generation — only the kernel branch and
Module.symvers change.

Total time: ~15 minutes once toolchain is set up.
Download size: ~500 MB (shallow kernel clone) + ~100 MB (toolchain if
not already available).

## Prerequisites

- A rooted Android device with KernelSU or Magisk (for adb root shell)
- Linux host (Arch, Ubuntu, Debian — anything with make, clang, git)
- `adb` connected to the device
- `modprobe` on the host (for extracting CRCs from .ko files)

## Step 1: Identify the GKI generation

```bash
adb shell uname -r
```

Example outputs and what they mean:

| `uname -r` output | GKI generation | Kernel branch |
|---|---|---|
| `5.10.xxx-android13-4-g...` | android13-5.10 | `android13-5.10` |
| `5.15.xxx-android14-6-g...` | android14-5.15 | `android14-5.15` |
| `6.1.xxx-android14-11-g...` | android14-6.1 | `android14-6.1` |
| `6.1.xxx-android15-8-g...` | android15-6.1 | `android15-6.1` |
| `6.6.xxx-android15-...` | android15-6.6 | `android15-6.6` |

The `androidXX` part is the GKI generation (kernel branch name), NOT
the Android version running on the device. A Pixel 7 Pro running
Android 16 still has an `android13-5.10` kernel because the generation
is frozen at manufacturing time.

## Step 2: Clone the kernel source (shallow, ~500 MB)

```bash
BRANCH="android13-5.10"  # ← replace with your generation from step 1

git clone --depth=1 -b $BRANCH \
    https://android.googlesource.com/kernel/common \
    ~/kernel-source
```

This clones only the needed branch with no history — fast and small.

## Step 3: Get the Android clang toolchain

If you already have a Pixel kernel tree with prebuilts (e.g. from
building for another device), reuse it:

```bash
CLANG=~/kernel-tree/prebuilts/clang/host/linux-x86/clang-r*/bin
```

Otherwise, download the standalone toolchain. Google publishes them
at https://android.googlesource.com/platform/prebuilts/clang/host/linux-x86/
— clone the branch matching your kernel:

```bash
# This is large (~2 GB). If you already have it, skip.
git clone --depth=1 \
    https://android.googlesource.com/platform/prebuilts/clang/host/linux-x86 \
    ~/android-clang
CLANG=~/android-clang/clang-r*/bin
```

Or use the version bundled with the Pixel kernel tree if you have one.

## Step 4: Pull .config from the device

```bash
adb shell "su -c 'gzip -d < /proc/config.gz'" > ~/kernel-source/.config
```

If `/proc/config.gz` doesn't exist, the kernel was built without
`CONFIG_IKCONFIG_PROC`. In that case, use the GKI defconfig:

```bash
cd ~/kernel-source
make ARCH=arm64 LLVM=1 CC=$CLANG/clang gki_defconfig
```

## Step 5: Generate Module.symvers from device's .ko files

The Module.symvers file contains CRC checksums for every exported
kernel symbol. These must match the running kernel exactly
(CONFIG_MODVERSIONS). Extract them from the prebuilt .ko modules
on the device:

```bash
# Pull all vendor modules from the device
mkdir -p /tmp/device-modules
adb shell "su -c 'ls /vendor/lib/modules/*.ko'" | tr -d '\r' | while read ko; do
    adb shell "su -c 'cat $ko'" > "/tmp/device-modules/$(basename $ko)"
done

# Extract CRCs from all modules and build Module.symvers
for ko in /tmp/device-modules/*.ko; do
    modprobe --dump-modversions "$ko" 2>/dev/null
done | sort -u -k2 | \
    awk '{printf "%s\t%s\tvmlinux\tEXPORT_SYMBOL\t\n", $1, $2}' \
    > ~/kernel-source/Module.symvers

echo "Generated Module.symvers with $(wc -l < ~/kernel-source/Module.symvers) symbols"
```

Expect 3000-5000 symbols. If you get 0, check that `modprobe` is
installed on your host (`apt install kmod` or `pacman -S kmod`).

Alternative: if the device's ROM has a `-kernels` repo on GitHub
(e.g. `crdroidandroid/android_device_google_shusky-kernels`), you can
download the .ko files from there instead of pulling from device.

## Step 6: Prepare the kernel source

```bash
cd ~/kernel-source

# Create empty ABI symbol list (GKI build expects it)
touch abi_symbollist.raw

# Generate headers
make ARCH=arm64 LLVM=1 LLVM_IAS=1 \
    CC=$CLANG/clang LD=$CLANG/ld.lld AR=$CLANG/llvm-ar \
    NM=$CLANG/llvm-nm OBJCOPY=$CLANG/llvm-objcopy \
    OBJDUMP=$CLANG/llvm-objdump STRIP=$CLANG/llvm-strip \
    CROSS_COMPILE=aarch64-linux-gnu- \
    olddefconfig prepare
```

**Common issue:** `make prepare` may fail on `tools/bpf/resolve_btfids`
due to host clang version mismatch. This is fine — the module can
still build without BTF. Ignore this error.

## Step 7: Generate scripts/module.lds

```bash
cd ~/kernel-source

$CLANG/clang -E -Wp,-MD,scripts/.module.lds.d -nostdinc \
    -I arch/arm64/include -I arch/arm64/include/generated \
    -I include -I include/generated \
    -include include/linux/kconfig.h \
    -D__KERNEL__ -DCC_USING_PATCHABLE_FUNCTION_ENTRY \
    --target=aarch64-linux-gnu -x c scripts/module.lds.S \
    2>/dev/null | grep -v '^#' > scripts/module.lds

# Fix ARM64 page-size literal that ld.lld can't parse
sed -i 's/((1UL) << 12)/4096/g' scripts/module.lds
```

## Step 8: Set UTS_RELEASE (vermagic)

KernelSU bypasses vermagic checks, so any value works if using KSU.
For Magisk or manual insmod, the vermagic must match `uname -r`.

```bash
cd ~/kernel-source

# For KernelSU users (any placeholder works):
PLACEHOLDER="6.1.999-placeholder-$(printf 'x%.0s' {1..100})"
echo "#define UTS_RELEASE \"$PLACEHOLDER\"" \
    > include/generated/utsrelease.h
echo -n "$PLACEHOLDER" > include/config/kernel.release

# For Magisk users (must match exactly):
KVER="$(adb shell uname -r | tr -d '\r')"
echo "#define UTS_RELEASE \"$KVER\"" \
    > include/generated/utsrelease.h
echo -n "$KVER" > include/config/kernel.release
```

## Step 9: Build the module

```bash
cd /path/to/vpnhide-kmod

make -C ~/kernel-source M=$(pwd) \
    ARCH=arm64 LLVM=1 LLVM_IAS=1 \
    CC=$CLANG/clang LD=$CLANG/ld.lld \
    AR=$CLANG/llvm-ar NM=$CLANG/llvm-nm \
    OBJCOPY=$CLANG/llvm-objcopy \
    OBJDUMP=$CLANG/llvm-objdump \
    STRIP=$CLANG/llvm-strip \
    CROSS_COMPILE=aarch64-linux-gnu- \
    modules
```

Output: `vpnhide_kmod.ko`

If build fails with "undefined symbol" errors, your Module.symvers
is missing some symbols. Re-extract with more .ko files from the
device, or check that you pulled from the right kernel version.

## Step 10: Package as KSU module

```bash
cp vpnhide_kmod.ko module/
./build-zip.sh
# Output: vpnhide-kmod.zip
```

## Step 11: Install and test

```bash
adb push vpnhide-kmod.zip /sdcard/Download/
# Install via KernelSU-Next manager → Modules → Install from storage
# Reboot
```

After reboot, verify:

```bash
# Module loaded?
adb shell "su -c 'lsmod | grep vpnhide'"

# kretprobes registered?
adb shell "su -c 'dmesg | grep vpnhide'"

# UIDs loaded?
adb shell "su -c 'cat /proc/vpnhide_targets'"
```

Pick target apps via the WebUI in KernelSU-Next manager.

## Quick reference: one-shot build script

For repeat builds (e.g. after code changes), once the kernel source
is prepared:

```bash
#!/bin/bash
KSRC=~/kernel-source
CLANG=~/android-clang/clang-r*/bin  # adjust path
cd /path/to/vpnhide-kmod
make -C "$KSRC" M=$(pwd) \
    ARCH=arm64 LLVM=1 LLVM_IAS=1 \
    CC=$CLANG/clang LD=$CLANG/ld.lld \
    AR=$CLANG/llvm-ar NM=$CLANG/llvm-nm \
    OBJCOPY=$CLANG/llvm-objcopy \
    OBJDUMP=$CLANG/llvm-objdump \
    STRIP=$CLANG/llvm-strip \
    CROSS_COMPILE=aarch64-linux-gnu- \
    modules
cp vpnhide_kmod.ko module/
./build-zip.sh
adb push vpnhide-kmod.zip /sdcard/Download/
```

## Troubleshooting

**`insmod: Exec format error`**
- Vermagic mismatch (Magisk doesn't bypass it). Set UTS_RELEASE to
  exact `uname -r` value (step 8, Magisk variant).
- Or Module.symvers CRCs don't match — re-extract from device .ko files.

**`insmod: File exists`**
- Module already loaded. `rmmod vpnhide_kmod` first.

**`modprobe --dump-modversions: no output`**
- .ko files might be stripped. Try pulling from a different path
  (`/vendor/lib/modules/`, `/system/lib/modules/`,
  `/lib/modules/$(uname -r)/`).

**`make prepare` fails on resolve_btfids**
- Ignore — BTF is optional. The module builds without it.

**No `/proc/config.gz`**
- Use `make gki_defconfig` instead (step 4 alternative).

**kretprobe not firing (ioctl not filtered)**
- Check `dmesg | grep vpnhide` for registration messages.
- Check `/proc/vpnhide_targets` has the right UIDs.
- The target app's UID changes on reinstall — re-resolve via WebUI.

**NFC payment broken with module active**
- Remove the banking app from targets. The kernel module's ioctl
  filtering can trigger MIR SDK's silent integrity degradation on
  some apps. Use system_server hooks (vpnhide LSPosed) for Java-side
  coverage instead.
