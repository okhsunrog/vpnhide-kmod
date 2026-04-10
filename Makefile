obj-m += vpnhide_kmod.o

# When invoked from the kernel build system (make -C <ksrc> M=...),
# KERNELRELEASE is set. Only obj-m above matters in that case.
# The rest is for direct invocation (make all / make clean).
ifeq ($(KERNELRELEASE),)

KERNEL_SRC ?= /home/okhsunrog/tmp_zfs/kernel_pixel_8pro/aosp
CLANG_DIR  ?= /home/okhsunrog/tmp_zfs/kernel_pixel_8pro/prebuilts/clang/host/linux-x86/clang-r487747c

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

endif
