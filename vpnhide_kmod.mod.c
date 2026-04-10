#include <linux/module.h>
#define INCLUDE_VERMAGIC
#include <linux/build-salt.h>
#include <linux/elfnote-lto.h>
#include <linux/export-internal.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

BUILD_SALT;
BUILD_LTO_INFO;

MODULE_INFO(vermagic, VERMAGIC_STRING);
MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(".gnu.linkonce.this_module") = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

#ifdef CONFIG_RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif


static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0x79345cb9, "register_kretprobe" },
	{ 0x92997ed8, "_printk" },
	{ 0x524767b, "proc_create" },
	{ 0xce01cfc4, "proc_remove" },
	{ 0xce598ef2, "unregister_kretprobe" },
	{ 0x1348649e, "alt_cb_patch_nops" },
	{ 0x4b0a3f52, "gic_nonsecure_priorities" },
	{ 0x2be0c009, "__arch_copy_from_user" },
	{ 0x1e6d26a8, "strstr" },
	{ 0xc2c193d2, "__stack_chk_fail" },
	{ 0x79e4c52b, "cpu_hwcaps" },
	{ 0xba8fbd64, "_raw_spin_lock" },
	{ 0xb5b54b34, "_raw_spin_unlock" },
	{ 0x4adb51eb, "single_open" },
	{ 0xeb233a45, "__kmalloc" },
	{ 0x88db9f48, "__check_object_size" },
	{ 0x5c3c7387, "kstrtoull" },
	{ 0x349cba85, "strchr" },
	{ 0x4829a47e, "memcpy" },
	{ 0x37a0cba, "kfree" },
	{ 0xdcb764ad, "memset" },
	{ 0xcbd4898c, "fortify_panic" },
	{ 0x4be4820, "seq_printf" },
	{ 0xd963f308, "seq_read" },
	{ 0x11f8a681, "seq_lseek" },
	{ 0xe8f7183d, "single_release" },
	{ 0xea759d7f, "module_layout" },
};

MODULE_INFO(depends, "");

