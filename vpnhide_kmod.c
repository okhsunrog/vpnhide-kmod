// SPDX-License-Identifier: GPL-2.0
/*
 * vpnhide_kmod — kernel module that hides VPN network interfaces from
 * selected Android apps by filtering ioctl, netlink, and procfs
 * responses based on the calling process's UID.
 *
 * Uses kretprobes so no modification of the running kernel is needed;
 * works on stock Android GKI kernels with CONFIG_KPROBES=y.
 *
 * Hooks:
 *   - dev_ioctl: filters SIOCGIFFLAGS / SIOCGIFNAME / SIOCGIFCONF
 *   - rtnl_dump_ifinfo: filters RTM_NEWLINK netlink dumps (getifaddrs)
 *   - fib_route_seq_show: filters /proc/net/route entries
 *   - tcp4_seq_show: filters /proc/net/tcp entries
 *
 * Target UIDs are written to /proc/vpnhide_targets from userspace.
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
#include <linux/netdevice.h>
#include <linux/rtnetlink.h>
#include <linux/skbuff.h>

#define MODNAME "vpnhide"
#define MAX_TARGET_UIDS 64

/* ------------------------------------------------------------------ */
/*  VPN interface name matching                                       */
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
/*  /proc/vpnhide_targets                                             */
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

/* ================================================================== */
/*  Hook 1: dev_ioctl — SIOCGIFFLAGS / SIOCGIFNAME                   */
/* ================================================================== */

struct dev_ioctl_data {
	unsigned int cmd;
	void __user *arg;
};

static int dev_ioctl_entry(struct kretprobe_instance *ri,
			   struct pt_regs *regs)
{
	struct dev_ioctl_data *data = (void *)ri->data;
	unsigned int cmd;

	/* arm64: x0=net, x1=cmd, x2=arg */
	cmd = (unsigned int)regs->regs[1];
	data->cmd = cmd;
	data->arg = (void __user *)regs->regs[2];

	if (!is_target_uid())
		data->cmd = 0;

	return 0;
}

static int dev_ioctl_ret(struct kretprobe_instance *ri,
			 struct pt_regs *regs)
{
	struct dev_ioctl_data *data = (void *)ri->data;
	long ret = regs_return_value(regs);

	if (data->cmd == 0 || ret != 0)
		return 0;

	/*
	 * dev_ioctl() signature on GKI 6.1:
	 *   int dev_ioctl(struct net *net, unsigned int cmd,
	 *                 struct ifreq *ifr, void __user *data,
	 *                 bool *need_copyout)
	 *
	 * x2 = ifr is a KERNEL pointer (the caller already did
	 * copy_from_user into a stack-local ifreq). We must NOT
	 * use copy_from_user on it — ARM64 PAN would EFAULT.
	 * Read via direct pointer dereference instead.
	 *
	 * x3 = data is the original __user pointer. For SIOCGIFCONF
	 * we need this to patch the userspace buffer.
	 */

	switch (data->cmd) {
	case SIOCGIFFLAGS:
	case SIOCGIFNAME: {
		struct ifreq *kifr = (struct ifreq *)data->arg;
		char name[IFNAMSIZ];

		if (!kifr)
			break;
		memcpy(name, kifr->ifr_name, IFNAMSIZ);
		name[IFNAMSIZ - 1] = '\0';
		if (is_vpn_ifname(name))
			regs_set_return_value(regs, -ENODEV);
		break;
	}

	case SIOCGIFCONF: {
		/*
		 * SIOCGIFCONF is handled in sock_ioctl → dev_ifconf,
		 * which has a different call path (not through dev_ioctl
		 * on GKI 6.1). This case is kept for completeness but
		 * may not fire. The actual SIOCGIFCONF filtering is
		 * handled by a separate hook if needed.
		 *
		 * For SIOCGIFCONF that DOES come through dev_ioctl on
		 * some kernels: the ifconf is in userspace, so we use
		 * the __user pointer from x3.
		 */
		void __user *udata = (void __user *)regs->regs[3];
		struct ifconf ifc;
		struct ifreq __user *usr_ifr;
		struct ifreq tmp;
		int i, n, dst;

		if (!udata)
			break;
		if (copy_from_user(&ifc, udata, sizeof(ifc)))
			break;
		if (!ifc.ifc_req || ifc.ifc_len <= 0)
			break;

		n = ifc.ifc_len / (int)sizeof(struct ifreq);
		usr_ifr = ifc.ifc_req;
		dst = 0;

		for (i = 0; i < n; i++) {
			if (copy_from_user(&tmp, &usr_ifr[i], sizeof(tmp)))
				break;
			tmp.ifr_name[IFNAMSIZ - 1] = '\0';
			if (is_vpn_ifname(tmp.ifr_name))
				continue;
			if (dst != i) {
				if (copy_to_user(&usr_ifr[dst], &tmp,
						 sizeof(tmp)))
					break;
			}
			dst++;
		}

		if (dst < n) {
			ifc.ifc_len = dst * (int)sizeof(struct ifreq);
			if (copy_to_user(udata, &ifc, sizeof(ifc)))
				break;
		}
		break;
	}
	}

	return 0;
}

static struct kretprobe dev_ioctl_krp = {
	.handler	= dev_ioctl_ret,
	.entry_handler	= dev_ioctl_entry,
	.data_size	= sizeof(struct dev_ioctl_data),
	.maxactive	= 20,
	.kp.symbol_name	= "dev_ioctl",
};

/* ================================================================== */
/*  Hook 2: rtnl_fill_ifinfo — netlink RTM_NEWLINK (getifaddrs path)  */
/*                                                                    */
/*  rtnl_fill_ifinfo fills one interface's data into a netlink skb    */
/*  during a RTM_GETLINK dump. If the device is a VPN and the caller  */
/*  is a target UID, we make it return -EMSGSIZE which tells the      */
/*  dump iterator to skip this entry (it thinks the skb is full for   */
/*  this entry and moves on, but the entry never gets added).         */
/* ================================================================== */

struct rtnl_fill_data {
	bool should_filter;
};

static int rtnl_fill_entry(struct kretprobe_instance *ri,
			   struct pt_regs *regs)
{
	struct rtnl_fill_data *data = (void *)ri->data;
	struct net_device *dev;

	data->should_filter = false;

	if (!is_target_uid())
		return 0;

	/*
	 * rtnl_fill_ifinfo(struct sk_buff *skb, struct net_device *dev, ...)
	 * arm64: x0=skb, x1=dev
	 */
	dev = (struct net_device *)regs->regs[1];
	if (dev && is_vpn_ifname(dev->name))
		data->should_filter = true;

	return 0;
}

static int rtnl_fill_ret(struct kretprobe_instance *ri,
			 struct pt_regs *regs)
{
	struct rtnl_fill_data *data = (void *)ri->data;

	if (data->should_filter)
		regs_set_return_value(regs, -EMSGSIZE);

	return 0;
}

static struct kretprobe rtnl_fill_krp = {
	.handler	= rtnl_fill_ret,
	.entry_handler	= rtnl_fill_entry,
	.data_size	= sizeof(struct rtnl_fill_data),
	.maxactive	= 20,
	.kp.symbol_name	= "rtnl_fill_ifinfo",
};

/* ================================================================== */
/*  Hook 3: fib_route_seq_show — /proc/net/route                      */
/*                                                                    */
/*  Each line in /proc/net/route starts with the interface name. If   */
/*  it's a VPN interface and the caller is a target, skip the line    */
/*  by returning 0 without printing (SEQ_SKIP equivalent).            */
/* ================================================================== */

static int fib_route_entry(struct kretprobe_instance *ri,
			   struct pt_regs *regs)
{
	/* We only need to filter in the return handler. Mark in entry
	 * whether this is a target UID to avoid re-checking. */
	*(bool *)ri->data = is_target_uid();
	return 0;
}

static int fib_route_ret(struct kretprobe_instance *ri,
			 struct pt_regs *regs)
{
	bool target = *(bool *)ri->data;
	struct seq_file *seq;
	const char *buf;
	int i;

	if (!target)
		return 0;

	/*
	 * After fib_route_seq_show returns, seq_file has the line in
	 * seq->buf at position seq->count - (length of last line).
	 * We check the last written line for a VPN interface name.
	 *
	 * arm64: x0 = seq_file*
	 */
	seq = (struct seq_file *)regs->regs[0];
	if (!seq || seq->count == 0)
		return 0;

	/* The route line starts at the beginning of what was just
	 * written. Find the last newline before seq->count to
	 * locate the start of the current line. */
	buf = seq->buf;
	if (!buf)
		return 0;

	/* Scan the interface name field (first field, tab-separated). */
	for (i = 0; i < IFNAMSIZ && i < seq->count; i++) {
		if (buf[seq->count - 1 - i] == '\n' || i == 0) {
			const char *line_start;
			char ifname[IFNAMSIZ];
			int j;

			if (i == 0 && seq->count > 1)
				continue;

			line_start = (i == 0) ? buf : buf + seq->count - i;
			for (j = 0; j < IFNAMSIZ - 1 && line_start[j] &&
			     line_start[j] != '\t' && line_start[j] != ' ';
			     j++)
				ifname[j] = line_start[j];
			ifname[j] = '\0';

			if (is_vpn_ifname(ifname)) {
				/* Rewind seq->count to hide this line */
				seq->count -= (i == 0) ? seq->count : i;
			}
			break;
		}
	}

	return 0;
}

static struct kretprobe fib_route_krp = {
	.handler	= fib_route_ret,
	.entry_handler	= fib_route_entry,
	.data_size	= sizeof(bool),
	.maxactive	= 20,
	.kp.symbol_name	= "fib_route_seq_show",
};

/* ================================================================== */
/*  Module init / exit                                                */
/* ================================================================== */

static struct proc_dir_entry *targets_entry;

struct kretprobe_reg {
	struct kretprobe *krp;
	const char *name;
	bool registered;
};

static struct kretprobe_reg probes[] = {
	{ &dev_ioctl_krp,  "dev_ioctl",        false },
	{ &rtnl_fill_krp,  "rtnl_fill_ifinfo", false },
	{ &fib_route_krp,  "fib_route_seq_show", false },
};

static int __init vpnhide_init(void)
{
	int i, ret;

	for (i = 0; i < ARRAY_SIZE(probes); i++) {
		ret = register_kretprobe(probes[i].krp);
		if (ret < 0) {
			pr_warn(MODNAME ": kretprobe(%s) failed: %d\n",
				probes[i].name, ret);
		} else {
			probes[i].registered = true;
			pr_info(MODNAME ": kretprobe(%s) registered\n",
				probes[i].name);
		}
	}

	/* 0644: root writes, everyone reads (system_server needs read
	 * access to load target UIDs for Java-level VPN filtering). */
	targets_entry = proc_create("vpnhide_targets", 0644, NULL,
				    &targets_proc_ops);

	pr_info(MODNAME ": loaded — write UIDs to /proc/vpnhide_targets\n");
	return 0;
}

static void __exit vpnhide_exit(void)
{
	int i;

	if (targets_entry)
		proc_remove(targets_entry);

	for (i = 0; i < ARRAY_SIZE(probes); i++) {
		if (probes[i].registered) {
			unregister_kretprobe(probes[i].krp);
			pr_info(MODNAME ": kretprobe(%s) unregistered "
				"(missed %d)\n",
				probes[i].name, probes[i].krp->nmissed);
		}
	}

	pr_info(MODNAME ": unloaded\n");
}

module_init(vpnhide_init);
module_exit(vpnhide_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("okhsunrog");
MODULE_DESCRIPTION("Hide VPN interfaces from selected apps at kernel level");
