#include "QoSimodo.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>

#include <libmnl/libmnl.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

#include <linux/netfilter/nf_conntrack_tcp.h>

static int data_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nf_conntrack *ct;
	struct flow_struct *flow = data;
	char buf[4096];
	int ret = MNL_CB_OK;

	ct = nfct_new();
	if (!ct)
		return(ret);

	nfct_nlmsg_parse(nlh, ct);
	if (nfct_get_attr_u32(ct, ATTR_ID) == flow->ctid) {
		nfct_snprintf(buf, sizeof(buf), ct, NFCT_T_UNKNOWN, NFCT_O_DEFAULT, 0);
		printf("%s\n", buf);
		ret = MNL_CB_STOP;
	}

	nfct_destroy(ct);

	return(ret);
}

int create_conntrack_socket(struct my_nl_socket *mynl)
{
	mynl->nl = mnl_socket_open(NETLINK_NETFILTER);
	if (!mynl->nl) {
		perror("mnl_socket_open");
		exit(EXIT_FAILURE);
	}

	if (mnl_socket_bind(mynl->nl, 0, MNL_SOCKET_AUTOPID) < 0) {
		perror("mnl_socket_bind");
		exit(EXIT_FAILURE);
	}
	mynl->portid = mnl_socket_get_portid(mynl->nl);
}

int close_conntrack_socket(struct my_nl_socket *mynl)
{
	mnl_socket_close(mynl->nl);
}

int find_conntrack_entry(struct flow_struct *flow, struct my_nl_socket *mynl)
{
	struct nlmsghdr *nlh;
	struct nfgenmsg *nfh;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	unsigned int seq;
	struct nf_conntrack *ct;
	int ret;
	struct in6_addr ipv6_addr1, ipv6_addr2;

	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = (NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_GET;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	nlh->nlmsg_seq = seq = time(NULL);

	nfh = mnl_nlmsg_put_extra_header(nlh, sizeof(struct nfgenmsg));
	nfh->nfgen_family = AF_INET;
	nfh->version = NFNETLINK_V0;
	nfh->res_id = 0;

	ct = nfct_new();
	if (!ct) {
		perror("nfct_new");
		return -2;
	}

/*
	switch (flow->ipversion) {
	case 4:
		if (flow->islocal) {
			printf("4L ");
			nfct_set_attr_u8(ct, ATTR_ORIG_L4PROTO, flow->ipprotocol);
			nfct_set_attr_u8(ct, ATTR_ORIG_L3PROTO, AF_INET);
			nfct_set_attr_u32(ct, ATTR_ORIG_IPV4_SRC, inet_addr(flow->srcip));
			nfct_set_attr_u32(ct, ATTR_ORIG_IPV4_DST, inet_addr(flow->dstip));
			nfct_set_attr_u16(ct, ATTR_ORIG_PORT_SRC, htons(flow->srcport));
			nfct_set_attr_u16(ct, ATTR_ORIG_PORT_DST, htons(flow->dstport));
		} else {
			printf("4R ");
			nfct_set_attr_u8(ct, ATTR_ORIG_L4PROTO, flow->ipprotocol);
			nfct_set_attr_u8(ct, ATTR_ORIG_L3PROTO, AF_INET);
			nfct_set_attr_u32(ct, ATTR_ORIG_IPV4_DST, inet_addr(flow->srcip));
			nfct_set_attr_u32(ct, ATTR_ORIG_IPV4_SRC, inet_addr(flow->dstip));
			nfct_set_attr_u16(ct, ATTR_ORIG_PORT_DST, htons(flow->srcport));
			nfct_set_attr_u16(ct, ATTR_ORIG_PORT_SRC, htons(flow->dstport));
		}
		break;
		;;
	case 6:
		printf("6 ");
		inet_pton(AF_INET6, flow->srcip, &ipv6_addr1);
		inet_pton(AF_INET6, flow->dstip, &ipv6_addr2);
		nfct_set_attr_u8(ct, ATTR_ORIG_L4PROTO, flow->ipprotocol);
		nfct_set_attr_u8(ct, ATTR_ORIG_L3PROTO, AF_INET6);
		nfct_set_attr(ct, ATTR_ORIG_IPV6_SRC, &ipv6_addr1);
		nfct_set_attr(ct, ATTR_ORIG_IPV6_DST, &ipv6_addr2);
		nfct_set_attr_u16(ct, ATTR_ORIG_PORT_SRC, htons(flow->srcport));
		nfct_set_attr_u16(ct, ATTR_ORIG_PORT_DST, htons(flow->dstport));
		break;
		;;
	default:
		return -3;
		;;
	}
	nfct_nlmsg_build(nlh, ct);
*/

	ret = mnl_socket_sendto(mynl->nl, nlh, nlh->nlmsg_len);
	if (ret == -1) {
		perror("mnl_socket_sendto");
	}

	ret = mnl_socket_recvfrom(mynl->nl, buf, sizeof(buf));
	while (ret > 0) {
		ret = mnl_cb_run(buf, ret, seq, mynl->portid, data_cb, (void *)flow);
		if (ret <= MNL_CB_STOP)
			break;
		ret = mnl_socket_recvfrom(mynl->nl, buf, sizeof(buf));
	}
/*	if (ret == -1) {
		perror("mnl_socket_recvfrom - probably not found");
	}*/

	nfct_destroy(ct);

	return(ret);
}
