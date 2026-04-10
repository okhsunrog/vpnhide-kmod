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
 *   - rtnl_fill_ifinfo: filters RTM_NEWLINK netlink dumps (getifaddrs)
 *   - fib_route_seq_show: filters /proc/net/route entries
 *   - ipv6_route_seq_show: filters /proc/net/ipv6_route entries
 *   - if6_seq_show: filters /proc/net/if_inet6 entries
 *   - tcp4_seq_show: filters /proc/net/tcp by VPN-bound addresses
 *   - tcp6_seq_show: filters /proc/net/tcp6 by VPN-bound addresses
 *   - fib_dump_info: filters RTM_GETROUTE netlink dumps (best-effort)
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
#include <linux/inetdevice.h>
#include <net/addrconf.h>
#include <net/ip_fib.h>

#define MODNAME "vpnhide"
#define MAX_TARGET_UIDS 64

/* ------------------------------------------------------------------ */
/*  VPN interface name matching                                       */
/* ------------------------------------------------------------------ */

static const char * const vpn_prefixes[] = {
	"tun", "ppp", "tap", "wg", "ipsec", "xfrm", "utun", "l2tp", "gre",
};

/* Case-insensitive substring search — kernel has no strcasestr. */
static bool strnstr_nocase(const char *haystack, const char *needle,
			   size_t hlen)
{
	size_t nlen = strlen(needle);
	size_t i;

	if (nlen > hlen)
		return false;

	for (i = 0; i <= hlen - nlen; i++) {
		if (strncasecmp(haystack + i, needle, nlen) == 0)
			return true;
	}
	return false;
}

static bool is_vpn_ifname(const char *name)
{
	int i;

	if (!name || !*name)
		return false;

	for (i = 0; i < ARRAY_SIZE(vpn_prefixes); i++) {
		if (strncasecmp(name, vpn_prefixes[i],
				strlen(vpn_prefixes[i])) == 0)
			return true;
	}
	if (strnstr_nocase(name, "vpn", strlen(name)))
		return true;

	return false;
}

/* ------------------------------------------------------------------ */
/*  VPN address matching (for /proc/net/tcp filtering)                */
/* ------------------------------------------------------------------ */

/*
 * Check if an IPv4 address is assigned to any VPN interface.
 * Caller must hold rcu_read_lock (kretprobe handlers do).
 */
static bool is_vpn_local_addr4(__be32 addr)
{
	struct net *net = current->nsproxy->net_ns;
	struct net_device *dev;

	for_each_netdev_rcu(net, dev) {
		const struct in_ifaddr *ifa;
		struct in_device *in_dev;

		if (!is_vpn_ifname(dev->name))
			continue;

		in_dev = __in_dev_get_rcu(dev);
		if (!in_dev)
			continue;

		for (ifa = rcu_dereference(in_dev->ifa_list); ifa;
		     ifa = rcu_dereference(ifa->ifa_next)) {
			if (ifa->ifa_local == addr)
				return true;
		}
	}
	return false;
}

/*
 * Check if an IPv6 address is assigned to any VPN interface.
 */
static bool is_vpn_local_addr6(const struct in6_addr *addr)
{
	struct net *net = current->nsproxy->net_ns;
	struct net_device *dev;

	for_each_netdev_rcu(net, dev) {
		struct inet6_dev *idev;
		struct inet6_ifaddr *ifa6;

		if (!is_vpn_ifname(dev->name))
			continue;

		idev = __in6_dev_get(dev);
		if (!idev)
			continue;

		list_for_each_entry_rcu(ifa6, &idev->addr_list, if_list) {
			if (ipv6_addr_equal(&ifa6->addr, addr))
				return true;
		}
	}
	return false;
}

/* ------------------------------------------------------------------ */
/*  Common seq_file kretprobe data                                    */
/* ------------------------------------------------------------------ */

struct seq_hide_data {
	bool is_target;
	size_t old_count;
};

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
/*  fib_route_seq_show(struct seq_file *seq, void *v) is called once  */
/*  per routing table entry. Each call appends one tab-separated      */
/*  line to seq->buf (first field = interface name).                  */
/*                                                                    */
/*  Strategy: save seq->count BEFORE the call in the entry handler.   */
/*  In the return handler, the new line lives at buf[old_count..].    */
/*  Parse the interface name from there; if it's a VPN, rewind        */
/*  seq->count back to old_count — erasing only that one line.        */
/* ================================================================== */

static int fib_route_ret(struct kretprobe_instance *ri,
			 struct pt_regs *regs)
{
	struct seq_hide_data *data = (void *)ri->data;
	struct seq_file *seq;
	const char *line_start;
	char ifname[IFNAMSIZ];
	int j;

	if (!data->is_target)
		return 0;

	/* arm64: x0 = seq_file* */
	seq = (struct seq_file *)regs->regs[0];
	if (!seq || !seq->buf || seq->count <= data->old_count)
		return 0;

	/* The line just written starts at buf + old_count.
	 * First field is the interface name, terminated by '\t'. */
	line_start = seq->buf + data->old_count;

	for (j = 0; j < IFNAMSIZ - 1; j++) {
		size_t pos = data->old_count + j;

		if (pos >= seq->count)
			break;
		if (line_start[j] == '\t' || line_start[j] == ' ' ||
		    line_start[j] == '\n' || line_start[j] == '\0')
			break;
		ifname[j] = line_start[j];
	}
	ifname[j] = '\0';

	if (is_vpn_ifname(ifname))
		seq->count = data->old_count;

	return 0;
}

/* ================================================================== */
/*  Shared seq_file entry handler — saves is_target + old seq->count  */
/*  Reused by hooks 3–7 which all follow the same pattern.            */
/* ================================================================== */

static int seq_hide_entry(struct kretprobe_instance *ri,
			  struct pt_regs *regs)
{
	struct seq_hide_data *data = (void *)ri->data;
	struct seq_file *seq;

	data->is_target = is_target_uid();
	data->old_count = 0;

	if (!data->is_target)
		return 0;

	seq = (struct seq_file *)regs->regs[0];
	if (seq)
		data->old_count = seq->count;

	return 0;
}

static struct kretprobe fib_route_krp = {
	.handler	= fib_route_ret,
	.entry_handler	= seq_hide_entry,
	.data_size	= sizeof(struct seq_hide_data),
	.maxactive	= 20,
	.kp.symbol_name	= "fib_route_seq_show",
};

/*
 * Helper: extract the last whitespace-delimited field from a line.
 * Used by ipv6_route and if_inet6 hooks (interface name is last).
 */
static int extract_last_field(const char *line, size_t len,
			      char *out, int outsz)
{
	int end = (int)len;
	int start, flen;

	while (end > 0 && (line[end - 1] == '\n' || line[end - 1] == ' '
			   || line[end - 1] == '\t'))
		end--;
	if (end == 0) {
		out[0] = '\0';
		return 0;
	}

	start = end;
	while (start > 0 && line[start - 1] != ' ' && line[start - 1] != '\t')
		start--;

	flen = end - start;
	if (flen >= outsz)
		flen = outsz - 1;
	memcpy(out, line + start, flen);
	out[flen] = '\0';
	return flen;
}

/* ================================================================== */
/*  Hook 4: ipv6_route_seq_show — /proc/net/ipv6_route                */
/*                                                                    */
/*  Format: 32-char-dest pfxlen 32-char-src ... metric ... ifname     */
/*  Interface name is the LAST field on each line.                    */
/* ================================================================== */

static int ipv6_route_ret(struct kretprobe_instance *ri,
			  struct pt_regs *regs)
{
	struct seq_hide_data *data = (void *)ri->data;
	struct seq_file *seq;
	char ifname[IFNAMSIZ];

	if (!data->is_target)
		return 0;

	seq = (struct seq_file *)regs->regs[0];
	if (!seq || !seq->buf || seq->count <= data->old_count)
		return 0;

	extract_last_field(seq->buf + data->old_count,
			   seq->count - data->old_count,
			   ifname, sizeof(ifname));

	if (is_vpn_ifname(ifname))
		seq->count = data->old_count;

	return 0;
}

static struct kretprobe ipv6_route_krp = {
	.handler	= ipv6_route_ret,
	.entry_handler	= seq_hide_entry,
	.data_size	= sizeof(struct seq_hide_data),
	.maxactive	= 20,
	.kp.symbol_name	= "ipv6_route_seq_show",
};

/* ================================================================== */
/*  Hook 5: if6_seq_show — /proc/net/if_inet6                        */
/*                                                                    */
/*  Format: addr ifidx pfxlen scope flags ifname                      */
/*  Interface name is the LAST field (may have leading whitespace).   */
/* ================================================================== */

static int if6_seq_ret(struct kretprobe_instance *ri,
		       struct pt_regs *regs)
{
	struct seq_hide_data *data = (void *)ri->data;
	struct seq_file *seq;
	char ifname[IFNAMSIZ];

	if (!data->is_target)
		return 0;

	seq = (struct seq_file *)regs->regs[0];
	if (!seq || !seq->buf || seq->count <= data->old_count)
		return 0;

	extract_last_field(seq->buf + data->old_count,
			   seq->count - data->old_count,
			   ifname, sizeof(ifname));

	if (is_vpn_ifname(ifname))
		seq->count = data->old_count;

	return 0;
}

static struct kretprobe if6_seq_krp = {
	.handler	= if6_seq_ret,
	.entry_handler	= seq_hide_entry,
	.data_size	= sizeof(struct seq_hide_data),
	.maxactive	= 20,
	.kp.symbol_name	= "if6_seq_show",
};

/* ================================================================== */
/*  Hook 6: tcp4_seq_show — /proc/net/tcp                             */
/*                                                                    */
/*  Format:  sl local_address:port remote_address:port st ...         */
/*  local_address is 8 hex chars of __be32, after the ": " separator. */
/*  If the address belongs to a VPN interface, hide the entry.        */
/* ================================================================== */

static int tcp4_seq_ret(struct kretprobe_instance *ri,
			struct pt_regs *regs)
{
	struct seq_hide_data *data = (void *)ri->data;
	struct seq_file *seq;
	const char *line, *p;
	size_t line_len;
	unsigned long val;
	char hex[9];

	if (!data->is_target)
		return 0;

	seq = (struct seq_file *)regs->regs[0];
	if (!seq || !seq->buf || seq->count <= data->old_count)
		return 0;

	line = seq->buf + data->old_count;
	line_len = seq->count - data->old_count;

	/* Header line starts with "  sl"; skip it. */
	p = strnstr(line, ": ", line_len);
	if (!p || (p - line + 10) > line_len)
		return 0;

	p += 2; /* skip ": " → now at hex IP */
	memcpy(hex, p, 8);
	hex[8] = '\0';

	if (kstrtoul(hex, 16, &val) == 0) {
		rcu_read_lock();
		if (is_vpn_local_addr4((__be32)val))
			seq->count = data->old_count;
		rcu_read_unlock();
	}

	return 0;
}

static struct kretprobe tcp4_seq_krp = {
	.handler	= tcp4_seq_ret,
	.entry_handler	= seq_hide_entry,
	.data_size	= sizeof(struct seq_hide_data),
	.maxactive	= 20,
	.kp.symbol_name	= "tcp4_seq_show",
};

/* ================================================================== */
/*  Hook 7: tcp6_seq_show — /proc/net/tcp6                            */
/*                                                                    */
/*  Same as tcp4 but the local address is 32 hex chars (4 × %08X).   */
/* ================================================================== */

static int tcp6_seq_ret(struct kretprobe_instance *ri,
			struct pt_regs *regs)
{
	struct seq_hide_data *data = (void *)ri->data;
	struct seq_file *seq;
	const char *line, *p;
	size_t line_len;
	struct in6_addr addr;
	unsigned long val;
	char hex[9];
	int i;

	if (!data->is_target)
		return 0;

	seq = (struct seq_file *)regs->regs[0];
	if (!seq || !seq->buf || seq->count <= data->old_count)
		return 0;

	line = seq->buf + data->old_count;
	line_len = seq->count - data->old_count;

	p = strnstr(line, ": ", line_len);
	if (!p || (p - line + 34) > line_len)
		return 0;

	p += 2;
	for (i = 0; i < 4; i++) {
		memcpy(hex, p + i * 8, 8);
		hex[8] = '\0';
		if (kstrtoul(hex, 16, &val))
			return 0;
		addr.s6_addr32[i] = (__be32)val;
	}

	rcu_read_lock();
	if (is_vpn_local_addr6(&addr))
		seq->count = data->old_count;
	rcu_read_unlock();

	return 0;
}

static struct kretprobe tcp6_seq_krp = {
	.handler	= tcp6_seq_ret,
	.entry_handler	= seq_hide_entry,
	.data_size	= sizeof(struct seq_hide_data),
	.maxactive	= 20,
	.kp.symbol_name	= "tcp6_seq_show",
};

/* ================================================================== */
/*  Hook 8: fib_dump_info — netlink RTM_GETROUTE                      */
/*                                                                    */
/*  fib_dump_info(struct sk_buff *skb, u32 portid, u32 seq,           */
/*                int event, const struct fib_rt_info *fri,            */
/*                unsigned int flags)                                  */
/*  Non-static on GKI 6.1. arm64: x4 = fri.                          */
/*                                                                    */
/*  Path to output device (confirmed for kernel 6.1):                 */
/*    fri→fi→fib_nh[0].nh_common.nhc_dev→name                        */
/*  (when fi→nh == NULL; otherwise nexthop objects are used — we      */
/*  skip filtering for those since they're rare on Android).          */
/*                                                                    */
/*  Same -EMSGSIZE trick as rtnl_fill_ifinfo.                         */
/* ================================================================== */

static int fib_dump_entry(struct kretprobe_instance *ri,
			  struct pt_regs *regs)
{
	struct rtnl_fill_data *data = (void *)ri->data;
	struct fib_rt_info *fri;
	struct fib_info *fi;
	struct net_device *dev;

	data->should_filter = false;

	if (!is_target_uid())
		return 0;

	/* arm64: x4 = fri */
	fri = (struct fib_rt_info *)regs->regs[4];
	if (!fri)
		return 0;

	fi = fri->fi;
	if (!fi || fi->fib_nhs < 1 || fi->nh)
		return 0; /* nexthop objects — skip */

	dev = fi->fib_nh[0].nh_common.nhc_dev;
	if (dev && is_vpn_ifname(dev->name))
		data->should_filter = true;

	return 0;
}

static int fib_dump_ret(struct kretprobe_instance *ri,
			struct pt_regs *regs)
{
	struct rtnl_fill_data *data = (void *)ri->data;

	if (data->should_filter)
		regs_set_return_value(regs, -EMSGSIZE);

	return 0;
}

static struct kretprobe fib_dump_krp = {
	.handler	= fib_dump_ret,
	.entry_handler	= fib_dump_entry,
	.data_size	= sizeof(struct rtnl_fill_data),
	.maxactive	= 20,
	.kp.symbol_name	= "fib_dump_info",
};

/* ================================================================== */
/*  Hooks 9–10: inet_fill_ifaddr / inet6_fill_ifaddr                  */
/*              — netlink RTM_GETADDR (best-effort)                   */
/*                                                                    */
/*  These fill one address entry into a netlink skb for an            */
/*  RTM_GETADDR dump. Same -EMSGSIZE trick as rtnl_fill_ifinfo.      */
/*                                                                    */
/*  These symbols are static in many kernel builds. If registration   */
/*  fails the module continues without these hooks.                   */
/* ================================================================== */

/*
 * Reuse rtnl_fill_data (bool should_filter) for these hooks.
 */

/*
 * inet_fill_ifaddr(struct sk_buff *skb, const struct in_ifaddr *ifa,
 *                  struct inet_fill_args *args)
 * arm64: x1 = ifa (struct in_ifaddr *)
 *   → ifa→ifa_dev→dev→name is the interface name.
 */
static int inet_fill_ifaddr_entry(struct kretprobe_instance *ri,
				  struct pt_regs *regs)
{
	struct rtnl_fill_data *data = (void *)ri->data;
	struct in_ifaddr *ifa;

	data->should_filter = false;

	if (!is_target_uid())
		return 0;

	ifa = (struct in_ifaddr *)regs->regs[1];
	if (ifa && ifa->ifa_dev && ifa->ifa_dev->dev &&
	    is_vpn_ifname(ifa->ifa_dev->dev->name))
		data->should_filter = true;

	return 0;
}

static int inet_fill_ifaddr_ret(struct kretprobe_instance *ri,
				struct pt_regs *regs)
{
	struct rtnl_fill_data *data = (void *)ri->data;

	if (data->should_filter)
		regs_set_return_value(regs, -EMSGSIZE);

	return 0;
}

static struct kretprobe inet_fill_ifaddr_krp = {
	.handler	= inet_fill_ifaddr_ret,
	.entry_handler	= inet_fill_ifaddr_entry,
	.data_size	= sizeof(struct rtnl_fill_data),
	.maxactive	= 20,
	.kp.symbol_name	= "inet_fill_ifaddr",
};

/*
 * inet6_fill_ifaddr(struct sk_buff *skb,
 *                   const struct inet6_ifaddr *ifa,
 *                   struct inet6_fill_args *args)
 * arm64: x1 = ifa (struct inet6_ifaddr *)
 *   → ifa→idev→dev→name is the interface name.
 */
static int inet6_fill_ifaddr_entry(struct kretprobe_instance *ri,
				   struct pt_regs *regs)
{
	struct rtnl_fill_data *data = (void *)ri->data;
	struct inet6_ifaddr *ifa;

	data->should_filter = false;

	if (!is_target_uid())
		return 0;

	ifa = (struct inet6_ifaddr *)regs->regs[1];
	if (ifa && ifa->idev && ifa->idev->dev &&
	    is_vpn_ifname(ifa->idev->dev->name))
		data->should_filter = true;

	return 0;
}

static int inet6_fill_ifaddr_ret(struct kretprobe_instance *ri,
				 struct pt_regs *regs)
{
	struct rtnl_fill_data *data = (void *)ri->data;

	if (data->should_filter)
		regs_set_return_value(regs, -EMSGSIZE);

	return 0;
}

static struct kretprobe inet6_fill_ifaddr_krp = {
	.handler	= inet6_fill_ifaddr_ret,
	.entry_handler	= inet6_fill_ifaddr_entry,
	.data_size	= sizeof(struct rtnl_fill_data),
	.maxactive	= 20,
	.kp.symbol_name	= "inet6_fill_ifaddr",
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
	{ &dev_ioctl_krp,    "dev_ioctl",           false },
	{ &rtnl_fill_krp,    "rtnl_fill_ifinfo",    false },
	{ &fib_route_krp,    "fib_route_seq_show",  false },
	{ &ipv6_route_krp,   "ipv6_route_seq_show", false },
	{ &if6_seq_krp,      "if6_seq_show",        false },
	{ &tcp4_seq_krp,     "tcp4_seq_show",       false },
	{ &tcp6_seq_krp,     "tcp6_seq_show",       false },
	{ &fib_dump_krp,     "fib_dump_info",       false },
	{ &inet_fill_ifaddr_krp,  "inet_fill_ifaddr",  false },
	{ &inet6_fill_ifaddr_krp, "inet6_fill_ifaddr", false },
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
