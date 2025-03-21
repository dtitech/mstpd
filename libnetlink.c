/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * libnetlink.c	RTnetlink service routines.
 *
 * Authors:	Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <net/if_arp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/uio.h>
#include <linux/fib_rules.h>
#include <linux/if_addrlabel.h>
#include <linux/if_bridge.h>
#include <linux/nexthop.h>

#include "log.h"
#include "libnetlink.h"

#ifndef __aligned
#define __aligned(x)		__attribute__((aligned(x)))
#endif

#ifndef SOL_NETLINK
#define SOL_NETLINK 270
#endif

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif

int rcvbuf = 1024 * 1024;

#ifdef HAVE_LIBMNL
#include <libmnl/libmnl.h>

static const enum mnl_attr_data_type extack_policy[NLMSGERR_ATTR_MAX + 1] = {
	[NLMSGERR_ATTR_MSG]	= MNL_TYPE_NUL_STRING,
	[NLMSGERR_ATTR_OFFS]	= MNL_TYPE_U32,
};

static int err_attr_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	uint16_t type;

	if (mnl_attr_type_valid(attr, NLMSGERR_ATTR_MAX) < 0) {
		ERROR("Invalid extack attribute");
		return MNL_CB_ERROR;
	}

	type = mnl_attr_get_type(attr);
	if (mnl_attr_validate(attr, extack_policy[type]) < 0) {
		ERROR("extack attribute %d failed validation", type);
		return MNL_CB_ERROR;
	}

	tb[type] = attr;
	return MNL_CB_OK;
}

static void print_ext_ack_msg(bool is_err, const char *msg)
{
	ERROR("%s: %s%s", is_err ? "Error" : "Warning", msg,
		(msg[strlen(msg) - 1] != '.') ? "." : "");
}

/* dump netlink extended ack error message */
int nl_dump_ext_ack(const struct nlmsghdr *nlh, nl_ext_ack_fn_t errfn)
{
	struct nlattr *tb[NLMSGERR_ATTR_MAX + 1] = {};
	const struct nlmsgerr *err = mnl_nlmsg_get_payload(nlh);
	const struct nlmsghdr *err_nlh = NULL;
	unsigned int hlen = sizeof(*err);
	const char *msg = NULL;
	uint32_t off = 0;

	/* no TLVs, nothing to do here */
	if (!(nlh->nlmsg_flags & NLM_F_ACK_TLVS))
		return 0;

	/* if NLM_F_CAPPED is set then the inner err msg was capped */
	if (!(nlh->nlmsg_flags & NLM_F_CAPPED))
		hlen += mnl_nlmsg_get_payload_len(&err->msg);

	if (mnl_attr_parse(nlh, hlen, err_attr_cb, tb) != MNL_CB_OK)
		return 0;

	if (tb[NLMSGERR_ATTR_MSG])
		msg = mnl_attr_get_str(tb[NLMSGERR_ATTR_MSG]);

	if (tb[NLMSGERR_ATTR_OFFS]) {
		off = mnl_attr_get_u32(tb[NLMSGERR_ATTR_OFFS]);

		if (off > nlh->nlmsg_len) {
			ERROR("Invalid offset for NLMSGERR_ATTR_OFFS");
			off = 0;
		} else if (!(nlh->nlmsg_flags & NLM_F_CAPPED))
			err_nlh = &err->msg;
	}

	if (tb[NLMSGERR_ATTR_MISS_TYPE])
		ERROR("Missing required attribute type %u",
			mnl_attr_get_u32(tb[NLMSGERR_ATTR_MISS_TYPE]));

	if (errfn)
		return errfn(msg, off, err_nlh);

	if (msg && *msg != '\0') {
		bool is_err = !!err->error;

		print_ext_ack_msg(is_err, msg);
		return is_err ? 1 : 0;
	}

	return 0;
}

int nl_dump_ext_ack_done(const struct nlmsghdr *nlh, unsigned int offset, int error)
{
	struct nlattr *tb[NLMSGERR_ATTR_MAX + 1] = {};
	const char *msg = NULL;

	if (mnl_attr_parse(nlh, offset, err_attr_cb, tb) != MNL_CB_OK)
		return 0;

	if (tb[NLMSGERR_ATTR_MSG])
		msg = mnl_attr_get_str(tb[NLMSGERR_ATTR_MSG]);

	if (msg && *msg != '\0') {
		bool is_err = !!error;

		print_ext_ack_msg(is_err, msg);
		return is_err ? 1 : 0;
	}

	return 0;
}
#else
#warning "libmnl required for error support"

/* No extended error ack without libmnl */
int nl_dump_ext_ack(const struct nlmsghdr *nlh, nl_ext_ack_fn_t errfn)
{
	return 0;
}

int nl_dump_ext_ack_done(const struct nlmsghdr *nlh, unsigned int offset, int error)
{
	return 0;
}
#endif

/* Older kernels may not support strict dump and filtering */
void rtnl_set_strict_dump(struct rtnl_handle *rth)
{
	int one = 1;

	if (setsockopt(rth->fd, SOL_NETLINK, NETLINK_GET_STRICT_CHK,
		       &one, sizeof(one)) < 0)
		return;

	rth->flags |= RTNL_HANDLE_F_STRICT_CHK;
}

int rtnl_add_nl_group(struct rtnl_handle *rth, unsigned int group)
{
	return setsockopt(rth->fd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP,
			  &group, sizeof(group));
}

void rtnl_close(struct rtnl_handle *rth)
{
	if (rth->fd >= 0) {
		close(rth->fd);
		rth->fd = -1;
	}
}

int rtnl_open_byproto(struct rtnl_handle *rth, unsigned int subscriptions,
		      int protocol)
{
	socklen_t addr_len;
	int sndbuf = 32768;
	int one = 1;

	memset(rth, 0, sizeof(*rth));

	rth->proto = protocol;
	rth->fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, protocol);
	if (rth->fd < 0) {
		ERROR("Cannot open netlink socket");
		return -1;
	}

	if (setsockopt(rth->fd, SOL_SOCKET, SO_SNDBUF,
		       &sndbuf, sizeof(sndbuf)) < 0) {
		ERROR("SO_SNDBUF");
		goto err;
	}

	if (setsockopt(rth->fd, SOL_SOCKET, SO_RCVBUF,
		       &rcvbuf, sizeof(rcvbuf)) < 0) {
		ERROR("SO_RCVBUF");
		goto err;
	}

	/* Older kernels may no support extended ACK reporting */
	setsockopt(rth->fd, SOL_NETLINK, NETLINK_EXT_ACK,
		   &one, sizeof(one));

	memset(&rth->local, 0, sizeof(rth->local));
	rth->local.nl_family = AF_NETLINK;
	rth->local.nl_groups = subscriptions;

	if (bind(rth->fd, (struct sockaddr *)&rth->local,
		 sizeof(rth->local)) < 0) {
		ERROR("Cannot bind netlink socket");
		goto err;
	}
	addr_len = sizeof(rth->local);
	if (getsockname(rth->fd, (struct sockaddr *)&rth->local,
			&addr_len) < 0) {
		ERROR("Cannot getsockname");
		goto err;
	}
	if (addr_len != sizeof(rth->local)) {
		ERROR("Wrong address length %d", addr_len);
		goto err;
	}
	if (rth->local.nl_family != AF_NETLINK) {
		ERROR("Wrong address family %d",
			rth->local.nl_family);
		goto err;
	}
	rth->seq = time(NULL);
	return 0;
err:
	rtnl_close(rth);
	return -1;
}

int rtnl_open(struct rtnl_handle *rth, unsigned int subscriptions)
{
	return rtnl_open_byproto(rth, subscriptions, NETLINK_ROUTE);
}

int rtnl_nexthopdump_req(struct rtnl_handle *rth, int family,
			 req_filter_fn_t filter_fn)
{
	struct {
		struct nlmsghdr nlh;
		struct nhmsg nhm;
		char buf[128];
	} req = {
		.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct nhmsg)),
		.nlh.nlmsg_type = RTM_GETNEXTHOP,
		.nlh.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST,
		.nlh.nlmsg_seq = rth->dump = ++rth->seq,
		.nhm.nh_family = family,
	};

	if (filter_fn) {
		int err;

		err = filter_fn(&req.nlh, sizeof(req));
		if (err)
			return err;
	}

	return send(rth->fd, &req, sizeof(req), 0);
}

int rtnl_nexthop_bucket_dump_req(struct rtnl_handle *rth, int family,
				 req_filter_fn_t filter_fn)
{
	struct {
		struct nlmsghdr nlh;
		struct nhmsg nhm;
		char buf[128];
	} req = {
		.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct nhmsg)),
		.nlh.nlmsg_type = RTM_GETNEXTHOPBUCKET,
		.nlh.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST,
		.nlh.nlmsg_seq = rth->dump = ++rth->seq,
		.nhm.nh_family = family,
	};

	if (filter_fn) {
		int err;

		err = filter_fn(&req.nlh, sizeof(req));
		if (err)
			return err;
	}

	return send(rth->fd, &req, sizeof(req), 0);
}

int rtnl_addrdump_req(struct rtnl_handle *rth, int family,
		      req_filter_fn_t filter_fn)
{
	struct {
		struct nlmsghdr nlh;
		struct ifaddrmsg ifm;
		char buf[128];
	} req = {
		.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg)),
		.nlh.nlmsg_type = RTM_GETADDR,
		.nlh.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST,
		.nlh.nlmsg_seq = rth->dump = ++rth->seq,
		.ifm.ifa_family = family,
	};

	if (filter_fn) {
		int err;

		err = filter_fn(&req.nlh, sizeof(req));
		if (err)
			return err;
	}

	return send(rth->fd, &req, sizeof(req), 0);
}

int rtnl_addrlbldump_req(struct rtnl_handle *rth, int family)
{
	struct {
		struct nlmsghdr nlh;
		struct ifaddrlblmsg ifal;
	} req = {
		.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrlblmsg)),
		.nlh.nlmsg_type = RTM_GETADDRLABEL,
		.nlh.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST,
		.nlh.nlmsg_seq = rth->dump = ++rth->seq,
		.ifal.ifal_family = family,
	};

	return send(rth->fd, &req, sizeof(req), 0);
}

int rtnl_routedump_req(struct rtnl_handle *rth, int family,
		       req_filter_fn_t filter_fn)
{
	struct {
		struct nlmsghdr nlh;
		struct rtmsg rtm;
		char buf[128];
	} req = {
		.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg)),
		.nlh.nlmsg_type = RTM_GETROUTE,
		.nlh.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST,
		.nlh.nlmsg_seq = rth->dump = ++rth->seq,
		.rtm.rtm_family = family,
	};

	if (filter_fn) {
		int err;

		err = filter_fn(&req.nlh, sizeof(req));
		if (err)
			return err;
	}

	return send(rth->fd, &req, sizeof(req), 0);
}

int rtnl_ruledump_req(struct rtnl_handle *rth, int family)
{
	struct {
		struct nlmsghdr nlh;
		struct fib_rule_hdr frh;
	} req = {
		.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct fib_rule_hdr)),
		.nlh.nlmsg_type = RTM_GETRULE,
		.nlh.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST,
		.nlh.nlmsg_seq = rth->dump = ++rth->seq,
		.frh.family = family
	};

	return send(rth->fd, &req, sizeof(req), 0);
}

int rtnl_neighdump_req(struct rtnl_handle *rth, int family,
		       req_filter_fn_t filter_fn)
{
	struct {
		struct nlmsghdr nlh;
		struct ndmsg ndm;
		char buf[256];
	} req = {
		.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg)),
		.nlh.nlmsg_type = RTM_GETNEIGH,
		.nlh.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST,
		.nlh.nlmsg_seq = rth->dump = ++rth->seq,
		.ndm.ndm_family = family,
	};

	if (filter_fn) {
		int err;

		err = filter_fn(&req.nlh, sizeof(req));
		if (err)
			return err;
	}

	return send(rth->fd, &req, sizeof(req), 0);
}

int rtnl_neightbldump_req(struct rtnl_handle *rth, int family)
{
	struct {
		struct nlmsghdr nlh;
		struct ndtmsg ndtmsg;
	} req = {
		.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ndtmsg)),
		.nlh.nlmsg_type = RTM_GETNEIGHTBL,
		.nlh.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST,
		.nlh.nlmsg_seq = rth->dump = ++rth->seq,
		.ndtmsg.ndtm_family = family,
	};

	return send(rth->fd, &req, sizeof(req), 0);
}

int rtnl_mdbdump_req(struct rtnl_handle *rth, int family)
{
	struct {
		struct nlmsghdr nlh;
		struct br_port_msg bpm;
	} req = {
		.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct br_port_msg)),
		.nlh.nlmsg_type = RTM_GETMDB,
		.nlh.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST,
		.nlh.nlmsg_seq = rth->dump = ++rth->seq,
		.bpm.family = family,
	};

	return send(rth->fd, &req, sizeof(req), 0);
}

int rtnl_brvlandump_req(struct rtnl_handle *rth, int family, __u32 dump_flags)
{
	struct {
		struct nlmsghdr nlh;
		struct br_vlan_msg bvm;
		char buf[256];
	} req = {
		.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct br_vlan_msg)),
		.nlh.nlmsg_type = RTM_GETVLAN,
		.nlh.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST,
		.nlh.nlmsg_seq = rth->dump = ++rth->seq,
		.bvm.family = family,
	};

	addattr32(&req.nlh, sizeof(req), BRIDGE_VLANDB_DUMP_FLAGS, dump_flags);

	return send(rth->fd, &req, sizeof(req), 0);
}

int rtnl_netconfdump_req(struct rtnl_handle *rth, int family)
{
	struct {
		struct nlmsghdr nlh;
		struct netconfmsg ncm;
		char buf[0] __aligned(NLMSG_ALIGNTO);
	} req = {
		.nlh.nlmsg_len = NLMSG_LENGTH(NLMSG_ALIGN(sizeof(struct netconfmsg))),
		.nlh.nlmsg_type = RTM_GETNETCONF,
		.nlh.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST,
		.nlh.nlmsg_seq = rth->dump = ++rth->seq,
		.ncm.ncm_family = family,
	};

	return send(rth->fd, &req, sizeof(req), 0);
}

int rtnl_nsiddump_req_filter_fn(struct rtnl_handle *rth, int family,
				req_filter_fn_t filter_fn)
{
	struct {
		struct nlmsghdr nlh;
		struct rtgenmsg rtm;
		char buf[1024];
	} req = {
		.nlh.nlmsg_len = NLMSG_LENGTH(NLMSG_ALIGN(sizeof(struct rtgenmsg))),
		.nlh.nlmsg_type = RTM_GETNSID,
		.nlh.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST,
		.nlh.nlmsg_seq = rth->dump = ++rth->seq,
		.rtm.rtgen_family = family,
	};
	int err;

	if (!filter_fn)
		return -EINVAL;

	err = filter_fn(&req.nlh, sizeof(req));
	if (err)
		return err;

	return send(rth->fd, &req, req.nlh.nlmsg_len, 0);
}

static int __rtnl_linkdump_req(struct rtnl_handle *rth, int family)
{
	struct {
		struct nlmsghdr nlh;
		struct ifinfomsg ifm;
	} req = {
		.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg)),
		.nlh.nlmsg_type = RTM_GETLINK,
		.nlh.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST,
		.nlh.nlmsg_seq = rth->dump = ++rth->seq,
		.ifm.ifi_family = family,
	};

	return send(rth->fd, &req, sizeof(req), 0);
}

int rtnl_linkdump_req(struct rtnl_handle *rth, int family)
{
	if (family == AF_UNSPEC)
		return rtnl_linkdump_req_filter(rth, family, RTEXT_FILTER_VF);

	return __rtnl_linkdump_req(rth, family);
}

int rtnl_linkdump_req_filter(struct rtnl_handle *rth, int family,
			    __u32 filt_mask)
{
	if (family == AF_UNSPEC || family == AF_BRIDGE) {
		struct {
			struct nlmsghdr nlh;
			struct ifinfomsg ifm;
			/* attribute has to be NLMSG aligned */
			struct rtattr ext_req __aligned(NLMSG_ALIGNTO);
			__u32 ext_filter_mask;
		} req = {
			.nlh.nlmsg_len = sizeof(req),
			.nlh.nlmsg_type = RTM_GETLINK,
			.nlh.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST,
			.nlh.nlmsg_seq = rth->dump = ++rth->seq,
			.ifm.ifi_family = family,
			.ext_req.rta_type = IFLA_EXT_MASK,
			.ext_req.rta_len = RTA_LENGTH(sizeof(__u32)),
			.ext_filter_mask = filt_mask,
		};

		return send(rth->fd, &req, sizeof(req), 0);
	}

	return __rtnl_linkdump_req(rth, family);
}

int rtnl_linkdump_req_filter_fn(struct rtnl_handle *rth, int family,
				req_filter_fn_t filter_fn)
{
	if (family == AF_UNSPEC || family == AF_PACKET) {
		struct {
			struct nlmsghdr nlh;
			struct ifinfomsg ifm;
			char buf[1024];
		} req = {
			.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg)),
			.nlh.nlmsg_type = RTM_GETLINK,
			.nlh.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST,
			.nlh.nlmsg_seq = rth->dump = ++rth->seq,
			.ifm.ifi_family = family,
		};
		int err;

		if (!filter_fn)
			return -EINVAL;

		err = filter_fn(&req.nlh, sizeof(req));
		if (err)
			return err;

		return send(rth->fd, &req, req.nlh.nlmsg_len, 0);
	}

	return __rtnl_linkdump_req(rth, family);
}

int rtnl_fdb_linkdump_req_filter_fn(struct rtnl_handle *rth,
				    req_filter_fn_t filter_fn)
{
	struct {
		struct nlmsghdr nlh;
		struct ifinfomsg ifm;
		char buf[128];
	} req = {
		.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg)),
		.nlh.nlmsg_type = RTM_GETNEIGH,
		.nlh.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST,
		.nlh.nlmsg_seq = rth->dump = ++rth->seq,
		.ifm.ifi_family = PF_BRIDGE,
	};
	int err;

	err = filter_fn(&req.nlh, sizeof(req));
	if (err)
		return err;

	return send(rth->fd, &req, sizeof(req), 0);
}

int rtnl_statsdump_req_filter(struct rtnl_handle *rth, int fam,
			      __u32 filt_mask,
			      int (*filter_fn)(struct ipstats_req *req,
					       void *data),
			      void *filter_data)
{
	struct ipstats_req req;

	memset(&req, 0, sizeof(req));
	req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct if_stats_msg));
	req.nlh.nlmsg_type = RTM_GETSTATS;
	req.nlh.nlmsg_flags = NLM_F_DUMP|NLM_F_REQUEST;
	req.nlh.nlmsg_pid = 0;
	req.nlh.nlmsg_seq = rth->dump = ++rth->seq;
	req.ifsm.family = fam;
	req.ifsm.filter_mask = filt_mask;

	if (filter_fn) {
		int err;

		err = filter_fn(&req, filter_data);
		if (err)
			return err;
	}

	return send(rth->fd, &req, sizeof(req), 0);
}

int rtnl_send(struct rtnl_handle *rth, const void *buf, int len)
{
	return send(rth->fd, buf, len, 0);
}

int rtnl_send_check(struct rtnl_handle *rth, const void *buf, int len)
{
	struct nlmsghdr *h;
	int status;
	char resp[1024];

	status = send(rth->fd, buf, len, 0);
	if (status < 0)
		return status;

	/* Check for immediate errors */
	status = recv(rth->fd, resp, sizeof(resp), MSG_DONTWAIT|MSG_PEEK);
	if (status < 0) {
		if (errno == EAGAIN)
			return 0;
		return -1;
	}

	for (h = (struct nlmsghdr *)resp; NLMSG_OK(h, status);
	     h = NLMSG_NEXT(h, status)) {
		if (h->nlmsg_type == NLMSG_ERROR) {
			struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(h);

			if (h->nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr)))
				ERROR("ERROR truncated");
			else
				errno = -err->error;
			return -1;
		}
	}

	return 0;
}

int rtnl_dump_request(struct rtnl_handle *rth, int type, void *req, int len)
{
	struct nlmsghdr nlh = {
		.nlmsg_len = NLMSG_LENGTH(len),
		.nlmsg_type = type,
		.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST,
		.nlmsg_seq = rth->dump = ++rth->seq,
	};
	struct sockaddr_nl nladdr = { .nl_family = AF_NETLINK };
	struct iovec iov[2] = {
		{ .iov_base = &nlh, .iov_len = sizeof(nlh) },
		{ .iov_base = req, .iov_len = len }
	};
	struct msghdr msg = {
		.msg_name = &nladdr,
		.msg_namelen = sizeof(nladdr),
		.msg_iov = iov,
		.msg_iovlen = 2,
	};

	return sendmsg(rth->fd, &msg, 0);
}

int rtnl_dump_request_n(struct rtnl_handle *rth, struct nlmsghdr *n)
{
	struct sockaddr_nl nladdr = { .nl_family = AF_NETLINK };
	struct iovec iov = {
		.iov_base = n,
		.iov_len = n->nlmsg_len
	};
	struct msghdr msg = {
		.msg_name = &nladdr,
		.msg_namelen = sizeof(nladdr),
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};

	n->nlmsg_flags = NLM_F_DUMP|NLM_F_REQUEST;
	n->nlmsg_pid = 0;
	n->nlmsg_seq = rth->dump = ++rth->seq;

	return sendmsg(rth->fd, &msg, 0);
}

static int rtnl_dump_done(struct nlmsghdr *h,
			  const struct rtnl_dump_filter_arg *a)
{
	int len;

	if (h->nlmsg_len < NLMSG_LENGTH(sizeof(int))) {
		ERROR("DONE truncated");
		return -1;
	}

	len = *(int *)NLMSG_DATA(h);

	if (len < 0) {
		errno = -len;

		if (a->errhndlr && (a->errhndlr(h, a->arg2) & RTNL_SUPPRESS_NLMSG_DONE_NLERR))
			return 0;

		/* check for any messages returned from kernel */
		if (nl_dump_ext_ack_done(h, sizeof(int), len))
			return len;

		switch (errno) {
		case ENOENT:
		case EOPNOTSUPP:
			return -1;
		case EMSGSIZE:
			ERROR("Error: Buffer too small for object.");
			break;
		default:
			ERROR("RTNETLINK answers");
		}
		return len;
	}

	/* check for any messages returned from kernel */
	nl_dump_ext_ack(h, NULL);

	return 0;
}

static int rtnl_dump_error(const struct rtnl_handle *rth,
			    struct nlmsghdr *h,
			    const struct rtnl_dump_filter_arg *a)
{

	if (h->nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr))) {
		ERROR("ERROR truncated");
	} else {
		const struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(h);

		errno = -err->error;
		if (rth->proto == NETLINK_SOCK_DIAG &&
		    (errno == ENOENT ||
		     errno == EOPNOTSUPP))
			return -1;

		if (a->errhndlr && (a->errhndlr(h, a->arg2) & RTNL_SUPPRESS_NLMSG_ERROR_NLERR))
			return 0;

		if (!(rth->flags & RTNL_HANDLE_F_SUPPRESS_NLERR))
			ERROR("RTNETLINK answers");
	}

	return -1;
}

static int __rtnl_recvmsg(int fd, struct msghdr *msg, int flags)
{
	int len;

	do {
		len = recvmsg(fd, msg, flags);
	} while (len < 0 && (errno == EINTR || errno == EAGAIN));

	if (len < 0) {
		ERROR("netlink receive error %s (%d)",
			strerror(errno), errno);
		return -errno;
	}

	if (len == 0) {
		ERROR("EOF on netlink");
		return -ENODATA;
	}

	return len;
}

static int rtnl_recvmsg(int fd, struct msghdr *msg, char **answer)
{
	struct iovec *iov = msg->msg_iov;
	char *buf;
	int len;

	iov->iov_base = NULL;
	iov->iov_len = 0;

	len = __rtnl_recvmsg(fd, msg, MSG_PEEK | MSG_TRUNC);
	if (len < 0)
		return len;

	if (len < 32768)
		len = 32768;
	buf = malloc(len);
	if (!buf) {
		ERROR("malloc error: not enough buffer");
		return -ENOMEM;
	}

	iov->iov_base = buf;
	iov->iov_len = len;

	len = __rtnl_recvmsg(fd, msg, 0);
	if (len < 0) {
		free(buf);
		return len;
	}

	if (answer)
		*answer = buf;
	else
		free(buf);

	return len;
}

static int rtnl_dump_filter_l(struct rtnl_handle *rth,
			      const struct rtnl_dump_filter_arg *arg)
{
	struct sockaddr_nl nladdr;
	struct iovec iov;
	struct msghdr msg = {
		.msg_name = &nladdr,
		.msg_namelen = sizeof(nladdr),
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};
	char *buf;
	int dump_intr = 0;

	while (1) {
		int status;
		const struct rtnl_dump_filter_arg *a;
		int found_done = 0;
		int msglen = 0;

		status = rtnl_recvmsg(rth->fd, &msg, &buf);
		if (status < 0)
			return status;

		if (rth->dump_fp)
			fwrite(buf, 1, NLMSG_ALIGN(status), rth->dump_fp);

		for (a = arg; a->filter; a++) {
			struct nlmsghdr *h = (struct nlmsghdr *)buf;

			msglen = status;

			while (NLMSG_OK(h, msglen)) {
				int err = 0;

				h->nlmsg_flags &= ~a->nc_flags;

				if (nladdr.nl_pid != 0 ||
				    h->nlmsg_pid != rth->local.nl_pid ||
				    h->nlmsg_seq != rth->dump)
					goto skip_it;

				if (h->nlmsg_flags & NLM_F_DUMP_INTR)
					dump_intr = 1;

				if (h->nlmsg_type == NLMSG_DONE) {
					err = rtnl_dump_done(h, a);
					if (err < 0) {
						free(buf);
						return -1;
					}

					found_done = 1;
					break; /* process next filter */
				}

				if (h->nlmsg_type == NLMSG_ERROR) {
					err = rtnl_dump_error(rth, h, a);
					if (err < 0) {
						free(buf);
						return -1;
					}

					goto skip_it;
				}

				if (!rth->dump_fp) {
					err = a->filter(h, a->arg1);
					if (err < 0) {
						free(buf);
						return err;
					}
				}

skip_it:
				h = NLMSG_NEXT(h, msglen);
			}
		}
		free(buf);

		if (found_done) {
			if (dump_intr)
				ERROR("Dump was interrupted and may be inconsistent.");
			return 0;
		}

		if (msg.msg_flags & MSG_TRUNC) {
			ERROR("Message truncated");
			continue;
		}
		if (msglen) {
			ERROR("!!!Remnant of size %d", msglen);
			exit(1);
		}
	}
}

int rtnl_dump_filter_nc(struct rtnl_handle *rth,
			rtnl_filter_t filter,
			void *arg1, __u16 nc_flags)
{
	const struct rtnl_dump_filter_arg a[] = {
		{
			.filter = filter, .arg1 = arg1,
			.nc_flags = nc_flags,
		},
		{ },
	};

	return rtnl_dump_filter_l(rth, a);
}

int rtnl_dump_filter_errhndlr_nc(struct rtnl_handle *rth,
		     rtnl_filter_t filter,
		     void *arg1,
		     rtnl_err_hndlr_t errhndlr,
		     void *arg2,
		     __u16 nc_flags)
{
	const struct rtnl_dump_filter_arg a[] = {
		{
			.filter = filter, .arg1 = arg1,
			.errhndlr = errhndlr, .arg2 = arg2,
			.nc_flags = nc_flags,
		},
		{ },
	};

	return rtnl_dump_filter_l(rth, a);
}

static void rtnl_talk_error(struct nlmsghdr *h, struct nlmsgerr *err,
			    nl_ext_ack_fn_t errfn)
{
	if (nl_dump_ext_ack(h, errfn))
		return;

	ERROR("RTNETLINK answers: %s", strerror(-err->error));
}


static int __rtnl_talk_iov(struct rtnl_handle *rtnl, struct iovec *iov,
			   size_t iovlen, struct nlmsghdr **answer,
			   bool show_rtnl_err, nl_ext_ack_fn_t errfn)
{
	struct sockaddr_nl nladdr = { .nl_family = AF_NETLINK };
	struct iovec riov;
	struct msghdr msg = {
		.msg_name = &nladdr,
		.msg_namelen = sizeof(nladdr),
		.msg_iov = iov,
		.msg_iovlen = iovlen,
	};
	unsigned int seq = 0;
	struct nlmsghdr *h;
	int i, status;
	char *buf;

	for (i = 0; i < iovlen; i++) {
		h = iov[i].iov_base;
		h->nlmsg_seq = seq = ++rtnl->seq;
		if (answer == NULL)
			h->nlmsg_flags |= NLM_F_ACK;
	}

	status = sendmsg(rtnl->fd, &msg, 0);
	if (status < 0) {
		ERROR("Cannot talk to rtnetlink");
		return -1;
	}

	/* change msg to use the response iov */
	msg.msg_iov = &riov;
	msg.msg_iovlen = 1;
	i = 0;
	while (1) {
next:
		status = rtnl_recvmsg(rtnl->fd, &msg, &buf);
		++i;

		if (status < 0)
			return status;

		if (msg.msg_namelen != sizeof(nladdr)) {
			ERROR("sender address length == %d",
				msg.msg_namelen);
			exit(1);
		}
		for (h = (struct nlmsghdr *)buf; status >= sizeof(*h); ) {
			int len = h->nlmsg_len;
			int l = len - sizeof(*h);

			if (l < 0 || len > status) {
				if (msg.msg_flags & MSG_TRUNC) {
					ERROR("Truncated message");
					free(buf);
					return -1;
				}
				ERROR("!!!malformed message: len=%d", len);
				exit(1);
			}

			if (nladdr.nl_pid != 0 ||
			    h->nlmsg_pid != rtnl->local.nl_pid ||
			    h->nlmsg_seq > seq || h->nlmsg_seq < seq - iovlen) {
				/* Don't forget to skip that message. */
				status -= NLMSG_ALIGN(len);
				h = (struct nlmsghdr *)((char *)h + NLMSG_ALIGN(len));
				continue;
			}

			if (h->nlmsg_type == NLMSG_ERROR) {
				struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(h);
				int error = err->error;

				if (l < sizeof(struct nlmsgerr)) {
					ERROR("ERROR truncated");
					free(buf);
					return -1;
				}

				if (!error) {
					/* check messages from kernel */
					nl_dump_ext_ack(h, errfn);
				} else {
					errno = -error;

					if (rtnl->proto != NETLINK_SOCK_DIAG &&
					    show_rtnl_err)
						rtnl_talk_error(h, err, errfn);
				}

				if (i < iovlen) {
					free(buf);
					goto next;
				}

				if (error) {
					free(buf);
					return -i;
				}

				if (answer)
					*answer = (struct nlmsghdr *)buf;
				else
					free(buf);
				return 0;
			}

			if (answer) {
				*answer = (struct nlmsghdr *)buf;
				return 0;
			}

			ERROR("Unexpected reply!!!");

			status -= NLMSG_ALIGN(len);
			h = (struct nlmsghdr *)((char *)h + NLMSG_ALIGN(len));
		}
		free(buf);

		if (msg.msg_flags & MSG_TRUNC) {
			ERROR("Message truncated");
			continue;
		}

		if (status) {
			ERROR("!!!Remnant of size %d", status);
			exit(1);
		}
	}
}

static int __rtnl_talk(struct rtnl_handle *rtnl, struct nlmsghdr *n,
		       struct nlmsghdr **answer,
		       bool show_rtnl_err, nl_ext_ack_fn_t errfn)
{
	struct iovec iov = {
		.iov_base = n,
		.iov_len = n->nlmsg_len
	};

	return __rtnl_talk_iov(rtnl, &iov, 1, answer, show_rtnl_err, errfn);
}

/*int rtnl_echo_talk(struct rtnl_handle *rtnl, struct nlmsghdr *n, int json,
		   int (*print_info)(struct nlmsghdr *n, void *arg))
{
	struct nlmsghdr *answer;
	int ret;

	n->nlmsg_flags |= NLM_F_ECHO | NLM_F_ACK;

	ret = rtnl_talk(rtnl, n, &answer);
	if (ret)
		return ret;

	new_json_obj(json);
	open_json_object(NULL);
	print_info(answer, stdout);
	close_json_object();
	delete_json_obj();
	free(answer);

	return 0;
}*/

int rtnl_talk(struct rtnl_handle *rtnl, struct nlmsghdr *n,
	      struct nlmsghdr **answer)
{
	return __rtnl_talk(rtnl, n, answer, true, NULL);
}

int rtnl_talk_suppress_rtnl_errmsg(struct rtnl_handle *rtnl, struct nlmsghdr *n,
				   struct nlmsghdr **answer)
{
	return __rtnl_talk(rtnl, n, answer, false, NULL);
}

int rtnl_listen_all_nsid(struct rtnl_handle *rth)
{
	unsigned int on = 1;

	if (setsockopt(rth->fd, SOL_NETLINK, NETLINK_LISTEN_ALL_NSID, &on,
		       sizeof(on)) < 0) {
		ERROR("NETLINK_LISTEN_ALL_NSID");
		return -1;
	}
	rth->flags |= RTNL_HANDLE_F_LISTEN_ALL_NSID;
	return 0;
}

int rtnl_listen(struct rtnl_handle *rtnl,
		rtnl_listen_filter_t handler,
		void *jarg)
{
	int status;
	struct nlmsghdr *h;
	struct sockaddr_nl nladdr = { .nl_family = AF_NETLINK };
	struct iovec iov;
	struct msghdr msg = {
		.msg_name = &nladdr,
		.msg_namelen = sizeof(nladdr),
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};
	char   buf[16384];
	char   cmsgbuf[BUFSIZ];

	iov.iov_base = buf;
	while (1) {
		struct rtnl_ctrl_data ctrl;
		struct cmsghdr *cmsg;

		if (rtnl->flags & RTNL_HANDLE_F_LISTEN_ALL_NSID) {
			msg.msg_control = &cmsgbuf;
			msg.msg_controllen = sizeof(cmsgbuf);
		}

		iov.iov_len = sizeof(buf);
		status = recvmsg(rtnl->fd, &msg, 0);

		if (status < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN)
				return 0;
			ERROR("netlink receive error %s (%d)",
				strerror(errno), errno);
			if (errno == ENOBUFS)
				continue;
			return -1;
		}
		if (status == 0) {
			ERROR("EOF on netlink");
			return -1;
		}
		if (msg.msg_namelen != sizeof(nladdr)) {
			ERROR("Sender address length == %d",
				msg.msg_namelen);
			exit(1);
		}

		if (rtnl->flags & RTNL_HANDLE_F_LISTEN_ALL_NSID) {
			memset(&ctrl, 0, sizeof(ctrl));
			ctrl.nsid = -1;
			for (cmsg = CMSG_FIRSTHDR(&msg); cmsg;
			     cmsg = CMSG_NXTHDR(&msg, cmsg))
				if (cmsg->cmsg_level == SOL_NETLINK &&
				    cmsg->cmsg_type == NETLINK_LISTEN_ALL_NSID &&
				    cmsg->cmsg_len == CMSG_LEN(sizeof(int))) {
					int *data = (int *)CMSG_DATA(cmsg);

					ctrl.nsid = *data;
				}
		}

		for (h = (struct nlmsghdr *)buf; status >= sizeof(*h); ) {
			int err;
			int len = h->nlmsg_len;
			int l = len - sizeof(*h);

			if (l < 0 || len > status) {
				if (msg.msg_flags & MSG_TRUNC) {
					ERROR("Truncated message");
					return -1;
				}
				ERROR("!!!malformed message: len=%d", len);
				exit(1);
			}

			err = handler(&ctrl, h, jarg);
			if (err < 0)
				return err;

			status -= NLMSG_ALIGN(len);
			h = (struct nlmsghdr *)((char *)h + NLMSG_ALIGN(len));
		}
		if (msg.msg_flags & MSG_TRUNC) {
			ERROR("Message truncated");
			continue;
		}
		if (status) {
			ERROR("!!!Remnant of size %d", status);
			exit(1);
		}
	}
}

int rtnl_from_file(FILE *rtnl, rtnl_listen_filter_t handler,
		   void *jarg)
{
	size_t status;
	char buf[16384];
	struct nlmsghdr *h = (struct nlmsghdr *)buf;

	while (1) {
		int err, len;
		int l;

		status = fread(&buf, 1, sizeof(*h), rtnl);

		if (status == 0 && feof(rtnl))
			return 0;
		if (status != sizeof(*h)) {
			if (ferror(rtnl))
				ERROR("rtnl_from_file: fread");
			if (feof(rtnl))
				ERROR("rtnl-from_file: truncated message");
			return -1;
		}

		len = h->nlmsg_len;
		l = len - sizeof(*h);

		if (l < 0 || len > sizeof(buf)) {
			ERROR("!!!malformed message: len=%d @%lu",
				len, ftell(rtnl));
			return -1;
		}

		status = fread(NLMSG_DATA(h), 1, NLMSG_ALIGN(l), rtnl);

		if (status != NLMSG_ALIGN(l)) {
			if (ferror(rtnl))
				ERROR("rtnl_from_file: fread");
			if (feof(rtnl))
				ERROR("rtnl-from_file: truncated message");
			return -1;
		}

		err = handler(NULL, h, jarg);
		if (err < 0)
			return err;
	}
}

int addattr(struct nlmsghdr *n, int maxlen, int type)
{
	return addattr_l(n, maxlen, type, NULL, 0);
}

int addattr8(struct nlmsghdr *n, int maxlen, int type, __u8 data)
{
	return addattr_l(n, maxlen, type, &data, sizeof(__u8));
}

int addattr16(struct nlmsghdr *n, int maxlen, int type, __u16 data)
{
	return addattr_l(n, maxlen, type, &data, sizeof(__u16));
}

int addattr32(struct nlmsghdr *n, int maxlen, int type, __u32 data)
{
	return addattr_l(n, maxlen, type, &data, sizeof(__u32));
}

int addattr64(struct nlmsghdr *n, int maxlen, int type, __u64 data)
{
	return addattr_l(n, maxlen, type, &data, sizeof(__u64));
}

int addattrstrz(struct nlmsghdr *n, int maxlen, int type, const char *str)
{
	return addattr_l(n, maxlen, type, str, strlen(str)+1);
}

int addattr_l(struct nlmsghdr *n, int maxlen, int type, const void *data,
	      int alen)
{
	int len = RTA_LENGTH(alen);
	struct rtattr *rta;

	if (NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len) > maxlen) {
		ERROR("addattr_l ERROR: message exceeded bound of %d",
			maxlen);
		return -1;
	}
	rta = NLMSG_TAIL(n);
	rta->rta_type = type;
	rta->rta_len = len;
	if (alen)
		memcpy(RTA_DATA(rta), data, alen);
	n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len);
	return 0;
}

int addraw_l(struct nlmsghdr *n, int maxlen, const void *data, int len)
{
	if (NLMSG_ALIGN(n->nlmsg_len) + NLMSG_ALIGN(len) > maxlen) {
		ERROR("addraw_l ERROR: message exceeded bound of %d",
			maxlen);
		return -1;
	}

	memcpy(NLMSG_TAIL(n), data, len);
	memset((void *) NLMSG_TAIL(n) + len, 0, NLMSG_ALIGN(len) - len);
	n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + NLMSG_ALIGN(len);
	return 0;
}

struct rtattr *addattr_nest(struct nlmsghdr *n, int maxlen, int type)
{
	struct rtattr *nest = NLMSG_TAIL(n);

	addattr_l(n, maxlen, type, NULL, 0);
	return nest;
}

int addattr_nest_end(struct nlmsghdr *n, struct rtattr *nest)
{
	nest->rta_len = (void *)NLMSG_TAIL(n) - (void *)nest;
	return n->nlmsg_len;
}

struct rtattr *addattr_nest_compat(struct nlmsghdr *n, int maxlen, int type,
				   const void *data, int len)
{
	struct rtattr *start = NLMSG_TAIL(n);

	addattr_l(n, maxlen, type, data, len);
	addattr_nest(n, maxlen, type);
	return start;
}

int addattr_nest_compat_end(struct nlmsghdr *n, struct rtattr *start)
{
	struct rtattr *nest = (void *)start + NLMSG_ALIGN(start->rta_len);

	start->rta_len = (void *)NLMSG_TAIL(n) - (void *)start;
	addattr_nest_end(n, nest);
	return n->nlmsg_len;
}

int rta_addattr32(struct rtattr *rta, int maxlen, int type, __u32 data)
{
	int len = RTA_LENGTH(4);
	struct rtattr *subrta;

	if (RTA_ALIGN(rta->rta_len) + len > maxlen) {
		ERROR("rta_addattr32: Error! max allowed bound %d exceeded",
			maxlen);
		return -1;
	}
	subrta = (struct rtattr *)(((char *)rta) + RTA_ALIGN(rta->rta_len));
	subrta->rta_type = type;
	subrta->rta_len = len;
	memcpy(RTA_DATA(subrta), &data, 4);
	rta->rta_len = NLMSG_ALIGN(rta->rta_len) + len;
	return 0;
}

int rta_addattr_l(struct rtattr *rta, int maxlen, int type,
		  const void *data, int alen)
{
	struct rtattr *subrta;
	int len = RTA_LENGTH(alen);

	if (RTA_ALIGN(rta->rta_len) + RTA_ALIGN(len) > maxlen) {
		ERROR("rta_addattr_l: Error! max allowed bound %d exceeded",
			maxlen);
		return -1;
	}
	subrta = (struct rtattr *)(((char *)rta) + RTA_ALIGN(rta->rta_len));
	subrta->rta_type = type;
	subrta->rta_len = len;
	if (alen)
		memcpy(RTA_DATA(subrta), data, alen);
	rta->rta_len = NLMSG_ALIGN(rta->rta_len) + RTA_ALIGN(len);
	return 0;
}

int rta_addattr8(struct rtattr *rta, int maxlen, int type, __u8 data)
{
	return rta_addattr_l(rta, maxlen, type, &data, sizeof(__u8));
}

int rta_addattr16(struct rtattr *rta, int maxlen, int type, __u16 data)
{
	return rta_addattr_l(rta, maxlen, type, &data, sizeof(__u16));
}

int rta_addattr64(struct rtattr *rta, int maxlen, int type, __u64 data)
{
	return rta_addattr_l(rta, maxlen, type, &data, sizeof(__u64));
}

struct rtattr *rta_nest(struct rtattr *rta, int maxlen, int type)
{
	struct rtattr *nest = RTA_TAIL(rta);

	rta_addattr_l(rta, maxlen, type, NULL, 0);
	nest->rta_type |= NLA_F_NESTED;

	return nest;
}

int rta_nest_end(struct rtattr *rta, struct rtattr *nest)
{
	nest->rta_len = (void *)RTA_TAIL(rta) - (void *)nest;

	return rta->rta_len;
}

int parse_rtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len)
{
	return parse_rtattr_flags(tb, max, rta, len, 0);
}

int parse_rtattr_flags(struct rtattr *tb[], int max, struct rtattr *rta,
		       int len, unsigned short flags)
{
	unsigned short type;

	memset(tb, 0, sizeof(struct rtattr *) * (max + 1));
	while (RTA_OK(rta, len)) {
		type = rta->rta_type & ~flags;
		if ((type <= max) && (!tb[type]))
			tb[type] = rta;
		rta = RTA_NEXT(rta, len);
	}
	if (len)
		ERROR("!!!Deficit %d, rta_len=%d",
			len, rta->rta_len);
	return 0;
}

struct rtattr *parse_rtattr_one(int type, struct rtattr *rta, int len)
{
	while (RTA_OK(rta, len)) {
		if (rta->rta_type == type)
			return rta;
		rta = RTA_NEXT(rta, len);
	}

	if (len)
		ERROR("!!!Deficit %d, rta_len=%d",
			len, rta->rta_len);
	return NULL;
}

int __parse_rtattr_nested_compat(struct rtattr *tb[], int max,
				 struct rtattr *rta,
				 int len)
{
	if (RTA_PAYLOAD(rta) < len)
		return -1;
	if (RTA_PAYLOAD(rta) >= RTA_ALIGN(len) + sizeof(struct rtattr)) {
		rta = RTA_DATA(rta) + RTA_ALIGN(len);
		return parse_rtattr_nested(tb, max, rta);
	}
	memset(tb, 0, sizeof(struct rtattr *) * (max + 1));
	return 0;
}

static const char *get_nla_type_str(unsigned int attr)
{
	switch (attr) {
#define C(x) case NL_ATTR_TYPE_ ## x: return #x
	C(U8);
	C(U16);
	C(U32);
	C(U64);
	C(STRING);
	C(FLAG);
	C(NESTED);
	C(NESTED_ARRAY);
	C(NUL_STRING);
	C(BINARY);
	C(S8);
	C(S16);
	C(S32);
	C(S64);
	C(BITFIELD32);
	default:
		return "unknown";
	}
}

void nl_print_policy(const struct rtattr *attr, FILE *fp)
{
	const struct rtattr *pos;

	rtattr_for_each_nested(pos, attr) {
		const struct rtattr *attr;

		fprintf(fp, " policy[%u]:", pos->rta_type & ~NLA_F_NESTED);

		rtattr_for_each_nested(attr, pos) {
			struct rtattr *tp[NL_POLICY_TYPE_ATTR_MAX + 1];

			parse_rtattr_nested(tp, ARRAY_SIZE(tp) - 1, attr);

			if (tp[NL_POLICY_TYPE_ATTR_TYPE])
				fprintf(fp, "attr[%u]: type=%s",
					attr->rta_type & ~NLA_F_NESTED,
					get_nla_type_str(rta_getattr_u32(tp[NL_POLICY_TYPE_ATTR_TYPE])));

			if (tp[NL_POLICY_TYPE_ATTR_POLICY_IDX])
				fprintf(fp, " policy:%u",
					rta_getattr_u32(tp[NL_POLICY_TYPE_ATTR_POLICY_IDX]));

			if (tp[NL_POLICY_TYPE_ATTR_POLICY_MAXTYPE])
				fprintf(fp, " maxattr:%u",
					rta_getattr_u32(tp[NL_POLICY_TYPE_ATTR_POLICY_MAXTYPE]));

			if (tp[NL_POLICY_TYPE_ATTR_MIN_VALUE_S] && tp[NL_POLICY_TYPE_ATTR_MAX_VALUE_S])
				fprintf(fp, " range:[%lld,%lld]",
					(signed long long)rta_getattr_u64(tp[NL_POLICY_TYPE_ATTR_MIN_VALUE_S]),
					(signed long long)rta_getattr_u64(tp[NL_POLICY_TYPE_ATTR_MAX_VALUE_S]));

			if (tp[NL_POLICY_TYPE_ATTR_MIN_VALUE_U] && tp[NL_POLICY_TYPE_ATTR_MAX_VALUE_U])
				fprintf(fp, " range:[%llu,%llu]",
					(unsigned long long)rta_getattr_u64(tp[NL_POLICY_TYPE_ATTR_MIN_VALUE_U]),
					(unsigned long long)rta_getattr_u64(tp[NL_POLICY_TYPE_ATTR_MAX_VALUE_U]));

			if (tp[NL_POLICY_TYPE_ATTR_MIN_LENGTH])
				fprintf(fp, " min len:%u",
					rta_getattr_u32(tp[NL_POLICY_TYPE_ATTR_MIN_LENGTH]));

			if (tp[NL_POLICY_TYPE_ATTR_MAX_LENGTH])
				fprintf(fp, " max len:%u",
					rta_getattr_u32(tp[NL_POLICY_TYPE_ATTR_MAX_LENGTH]));
		}
	}
}

int rtnl_tunneldump_req(struct rtnl_handle *rth, int family, int ifindex,
			__u8 flags)
{
	struct {
		struct nlmsghdr nlh;
		struct tunnel_msg tmsg;
		char buf[256];
	} req = {
		.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct tunnel_msg)),
		.nlh.nlmsg_type = RTM_GETTUNNEL,
		.nlh.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST,
		.nlh.nlmsg_seq = rth->dump = ++rth->seq,
		.tmsg.family = family,
		.tmsg.flags = flags,
		.tmsg.ifindex = ifindex,
	};

	return send(rth->fd, &req, sizeof(req), 0);
}
