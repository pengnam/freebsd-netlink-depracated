#ifndef _LINUX_NETLINK2_H
#define _LINUX_NETLINK2_H

#define AF_NETLINK 	38
#define PF_NETLINK 	38
/*
 * $FreeBSD$
 *
 * The user-visible API for netlink sockets.
 * These definitions are visible to userspace and kernel.
 * In linux similar content is in uapi/linux/netlink.h,
 * copied to /usr/include/linux/netlink.h with guard changed.
 * For simplicity, in FreeBSD we install both uapi_netlink.h and netlink.h
 * and kernel and userspace both include the latter.
 */

#include <sys/types.h>
#include <sys/socket.h>

struct sockaddr_nl {
	uint8_t		nl_len;		/* FreeBSD SPECIFIC */
	sa_family_t	nl_family;	/* AF_NETLINK */
	uint16_t	nl_pad;		/* keep it zero */
	uint32_t	nl_pid;		/* port ID. */
	uint32_t	nl_groups;	/* multicast groups mask */
};

#define NETLINK_GENERIC     16

#endif /*linux_netlink_h*/
