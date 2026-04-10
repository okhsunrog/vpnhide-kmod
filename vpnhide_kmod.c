// SPDX-License-Identifier: GPL-2.0
/*
 * vpnhide_kmod — kernel module that hides VPN network interfaces from
 * selected Android apps by filtering ioctl responses based on the
 * calling process's UID.
 *
 * Uses kretprobes so no modification of the running kernel is needed;
 * works on stock Android GKI kernels with CONFIG_KPROBES=y and
 * CONFIG_MODULES=y.
 *
 * Target UIDs are written to /proc/vpnhide_targets from userspace
 * (one numeric UID per line). A helper script resolves package names
 * to UIDs and writes them after boot.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/slab.h>
#include <linux/cred.h>
#include <linux/uidgid.h>
#include <linux/string.h>
#include <linux/net.h>
#include <linux/if.h>
#include <linux/uaccess.h>
#include <linux/seq_file.h>
#include <linux/proc_fs.h>
#include <linux/version.h>

#define MODNAME "vpnhide"
#define MAX_TARGET_UIDS 64

/* ------------------------------------------------------------------ */
/*  VPN interface name matching (same prefixes as the Rust module)    */
/* ------------------------------------------------------------------ */

static const char * const vpn_prefixes[] = {
	"tun", "ppp", "tap", "wg", "ipsec", "xfrm", "utun", "l2tp", "gre",
};

static bool is_vpn_ifname(const char *name)
{
	int i;

	if (!name || !*name)
		return false;

	for (i = 0; i < ARRAY_SIZE(vpn_prefixes); i++) {
		if (strncmp(name, vpn_prefixes[i],
			    strlen(vpn_prefixes[i])) == 0)
			return true;
	}
	if (strstr(name, "vpn") || strstr(name, "VPN"))
		return true;

	return false;
}

/* ------------------------------------------------------------------ */
/*  Target UID list                                                   */
/* ------------------------------------------------------------------ */

static uid_t target_uids[MAX_TARGET_UIDS];
static int nr_target_uids;
static DEFINE_SPINLOCK(uids_lock);

static bool is_target_uid(void)
{
	uid_t uid = from_kuid(&init_user_ns, current_uid());
	int i;

	if (READ_ONCE(nr_target_uids) == 0)
		return false;

	spin_lock(&uids_lock);
	for (i = 0; i < nr_target_uids; i++) {
		if (target_uids[i] == uid) {
			spin_unlock(&uids_lock);
			return true;
		}
	}
	spin_unlock(&uids_lock);
	return false;
}

/* ------------------------------------------------------------------ */
/*  /proc/vpnhide_targets — write UIDs from userspace                 */
/*                                                                    */
/*  Format: one UID per line, # comments, blank lines ignored.        */
/*  Writing replaces the entire list atomically.                      */
/*  Example from shell:                                               */
/*    echo -e "10421\n10422\n10423" > /proc/vpnhide_targets           */
/* ------------------------------------------------------------------ */

static ssize_t targets_write(struct file *file, const char __user *ubuf,
			     size_t count, loff_t *ppos)
{
	char *buf, *line, *next;
	int new_count = 0;
	uid_t new_uids[MAX_TARGET_UIDS];

	if (count > PAGE_SIZE)
		return -EINVAL;

	buf = kmalloc(count + 1, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	if (copy_from_user(buf, ubuf, count)) {
		kfree(buf);
		return -EFAULT;
	}
	buf[count] = '\0';

	for (line = buf; line && *line && new_count < MAX_TARGET_UIDS;
	     line = next) {
		unsigned long uid;

		next = strchr(line, '\n');
		if (next)
			*next++ = '\0';

		while (*line == ' ' || *line == '\t')
			line++;
		if (!*line || *line == '#')
			continue;

		if (kstrtoul(line, 10, &uid) == 0)
			new_uids[new_count++] = (uid_t)uid;
	}

	spin_lock(&uids_lock);
	memcpy(target_uids, new_uids, new_count * sizeof(uid_t));
	nr_target_uids = new_count;
	spin_unlock(&uids_lock);

	kfree(buf);
	pr_info(MODNAME ": loaded %d target UIDs\n", new_count);
	return count;
}

static int targets_show(struct seq_file *m, void *v)
{
	int i;

	spin_lock(&uids_lock);
	for (i = 0; i < nr_target_uids; i++)
		seq_printf(m, "%u\n", target_uids[i]);
	spin_unlock(&uids_lock);
	return 0;
}

static int targets_open(struct inode *inode, struct file *file)
{
	return single_open(file, targets_show, NULL);
}

static const struct proc_ops targets_proc_ops = {
	.proc_open    = targets_open,
	.proc_read    = seq_read,
	.proc_write   = targets_write,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
};

/* ------------------------------------------------------------------ */
/*  Kretprobe: dev_ioctl                                              */
/*                                                                    */
/*  Intercepts network device ioctls. For SIOCGIFFLAGS / SIOCGIFNAME, */
/*  checks if the result references a VPN interface and the caller is */
/*  a target UID. If so, overwrites the return value to -ENODEV.      */
/* ------------------------------------------------------------------ */

struct dev_ioctl_data {
	unsigned int cmd;
	void __user *arg;
};

static int dev_ioctl_entry(struct kretprobe_instance *ri,
			   struct pt_regs *regs)
{
	struct dev_ioctl_data *data = (void *)ri->data;

	/*
	 * dev_ioctl(struct net *net, unsigned int cmd, struct ifreq __user *arg)
	 * arm64 ABI: x0=net, x1=cmd, x2=arg
	 */
	data->cmd = (unsigned int)regs->regs[1];
	data->arg = (void __user *)regs->regs[2];

	if (!is_target_uid())
		data->cmd = 0; /* skip filtering in ret handler */

	return 0;
}

static int dev_ioctl_ret(struct kretprobe_instance *ri,
			 struct pt_regs *regs)
{
	struct dev_ioctl_data *data = (void *)ri->data;
	struct ifreq ifr;
	long ret = regs_return_value(regs);

	if (data->cmd == 0)
		return 0;

	if (ret != 0)
		return 0;

	switch (data->cmd) {
	case SIOCGIFFLAGS:
		if (!data->arg)
			break;
		if (copy_from_user(&ifr, data->arg, sizeof(ifr)))
			break;
		ifr.ifr_name[IFNAMSIZ - 1] = '\0';
		if (is_vpn_ifname(ifr.ifr_name))
			regs_set_return_value(regs, -ENODEV);
		break;

	case SIOCGIFNAME:
		if (!data->arg)
			break;
		if (copy_from_user(&ifr, data->arg, sizeof(ifr)))
			break;
		ifr.ifr_name[IFNAMSIZ - 1] = '\0';
		if (is_vpn_ifname(ifr.ifr_name))
			regs_set_return_value(regs, -ENODEV);
		break;
	}

	return 0;
}

static struct kretprobe dev_ioctl_kretprobe = {
	.handler	= dev_ioctl_ret,
	.entry_handler	= dev_ioctl_entry,
	.data_size	= sizeof(struct dev_ioctl_data),
	.maxactive	= 20,
	.kp.symbol_name	= "dev_ioctl",
};

/* ------------------------------------------------------------------ */
/*  Module init / exit                                                */
/* ------------------------------------------------------------------ */

static struct proc_dir_entry *targets_entry;

static int __init vpnhide_init(void)
{
	int ret;

	ret = register_kretprobe(&dev_ioctl_kretprobe);
	if (ret < 0) {
		pr_err(MODNAME ": register_kretprobe(dev_ioctl) failed: %d\n",
		       ret);
		return ret;
	}

	targets_entry = proc_create("vpnhide_targets", 0600, NULL,
				    &targets_proc_ops);

	pr_info(MODNAME ": loaded — write UIDs to /proc/vpnhide_targets\n");
	return 0;
}

static void __exit vpnhide_exit(void)
{
	if (targets_entry)
		proc_remove(targets_entry);

	unregister_kretprobe(&dev_ioctl_kretprobe);

	pr_info(MODNAME ": unloaded (dev_ioctl missed %d)\n",
		dev_ioctl_kretprobe.nmissed);
}

module_init(vpnhide_init);
module_exit(vpnhide_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("okhsunrog");
MODULE_DESCRIPTION("Hide VPN interfaces from selected apps via ioctl filtering");
