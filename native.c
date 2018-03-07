// originally based upon (public domain):
// https://kristrev.github.io/2013/07/26/passive-monitoring-of-sockets-on-linux

#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/tcp.h>
#include <linux/sock_diag.h>
#include <linux/inet_diag.h>
#include <pwd.h>

ssize_t send_diag_msg(int sockfd, int family, int proto) {
	//To request information about unix sockets, this would be replaced with
	//unix_diag_req, packet-sockets packet_diag_req.

	//Address family and protocol we are interested in. sock_diag can also be
	struct inet_diag_req_v2 conn_req = {0};
	conn_req.sdiag_family = family;
	conn_req.sdiag_protocol = proto;
	conn_req.idiag_states = ~0;

	// Request extended TCP information
	conn_req.idiag_ext |= (1 << (INET_DIAG_INFO - 1));

	struct nlmsghdr nlh = {0};
	nlh.nlmsg_len = NLMSG_LENGTH(sizeof(conn_req));
	nlh.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;

	nlh.nlmsg_type = SOCK_DIAG_BY_FAMILY;

    struct iovec iov[2];
	iov[0].iov_base = (void *) &nlh;
	iov[0].iov_len = sizeof(nlh);
	iov[1].iov_base = (void *) &conn_req;
	iov[1].iov_len = sizeof(conn_req);

    //No need to specify groups or pid. This message only has one receiver and
    //pid 0 is kernel
    struct sockaddr_nl sa = {0};
    sa.nl_family = AF_NETLINK;

	struct msghdr msg = {0};
	msg.msg_name = (void *) &sa;
	msg.msg_namelen = sizeof(sa);
	msg.msg_iov = iov;
    msg.msg_iovlen = 2;

	return sendmsg(sockfd, &msg, 0);
}

static void parse_diag_msg(struct inet_diag_msg *diag_msg, int rtalen, void (*on_item)(struct inet_diag_msg *diag_msg)) {
	//(Try to) Get user info
	struct passwd *uid_info = getpwuid(diag_msg->idiag_uid);

    on_item(diag_msg);
    // on_user(uid_info);

	if (rtalen <= 0) {
	    return;
    }

	//Parse the attributes of the netlink message in search of the
	//INET_DIAG_INFO-attribute
    struct rtattr *attr = (struct rtattr *) (diag_msg + 1);

    while (RTA_OK(attr, rtalen)) {
        if (attr->rta_type == INET_DIAG_INFO) {
            struct tcp_info *tcpi = (struct tcp_info *) RTA_DATA(attr);
            // on_tcp(tcpi);
        }
        attr = RTA_NEXT(attr, rtalen);
    }
}

bool nlmsg_ok(struct nlmsghdr *nlh, size_t numbytes) {
    return NLMSG_OK(nlh, numbytes);
}

struct nlmsghdr *nlmsg_next(struct nlmsghdr *nlh, size_t *numbytes) {
    return NLMSG_NEXT(nlh, *numbytes);
}

struct nlmsghdr *nlmsg_data(struct nlmsghdr *nlh) {
    return NLMSG_DATA(nlh);
}

uint16_t nlmsg_type(struct nlmsghdr *nlh) {
    return nlh->nlmsg_type;
}

uint32_t nlmsg_len(struct nlmsghdr *nlh) {
    return nlh->nlmsg_len;
}
