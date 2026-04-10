obj-m += vpnhide_kmod.o

# Pixel 8 Pro (shusky) kernel source and toolchain paths.
# Adjust these if your kernel tree is elsewhere.
KERNEL_SRC ?= /home/okhsunrog/tmp_zfs/kernel_pixel_8pro/aosp
CLANG_DIR  ?= /home/okhsunrog/tmp_zfs/kernel_pixel_8pro/prebuilts/clang/host/linux-x86/clang-r487747c

# Cross-compilation for aarch64 Android using the kernel's own clang.
ARCH       := arm64
CROSS_COMPILE := aarch64-linux-gnu-
CC         := $(CLANG_DIR)/bin/clang
LD         := $(CLANG_DIR)/bin/ld.lld
AR         := $(CLANG_DIR)/bin/llvm-ar
NM         := $(CLANG_DIR)/bin/llvm-nm
OBJCOPY    := $(CLANG_DIR)/bin/llvm-objcopy
OBJDUMP    := $(CLANG_DIR)/bin/llvm-objdump
STRIP      := $(CLANG_DIR)/bin/llvm-strip

all:
	$(MAKE) -C $(KERNEL_SRC) M=$(PWD) \
		ARCH=$(ARCH) \
		CROSS_COMPILE=$(CROSS_COMPILE) \
		CC=$(CC) LD=$(LD) AR=$(AR) NM=$(NM) \
		OBJCOPY=$(OBJCOPY) OBJDUMP=$(OBJDUMP) STRIP=$(STRIP) \
		modules

clean:
	$(MAKE) -C $(KERNEL_SRC) M=$(PWD) \
		ARCH=$(ARCH) \
		clean
