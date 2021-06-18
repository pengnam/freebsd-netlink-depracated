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
	uint16_t	nl_pad;		/* zero */
	uint32_t	nl_pid;		/* port ID */
	uint32_t	nl_groups;	/* multicast groups mask */
};

#define NETLINK_GENERIC     16

struct nlmsghdr {
	uint32_t    nlmsg_len;  /* Length of message including header */
	uint16_t    nlmsg_type; /* Message content */
	uint16_t    nlmsg_flags;    /* Additional flags */
	uint32_t    nlmsg_seq;  /* Sequence number */
	uint32_t    nlmsg_pid;  /* Sending process port ID */
};
struct nlmsgerr {
	int		error;
	struct nlmsghdr msg;
};

//COPIED FROM LINUX VERSION
/* Flags values */
#define NLM_F_REQUEST		0x01	/* It is request message. 	*/
#define NLM_F_MULTI		0x02	/* Multipart message, terminated by NLMSG_DONE */
#define NLM_F_ACK		0x04	/* Reply with ack, with zero or error code */
#define NLM_F_ECHO		0x08	/* Echo this request 		*/
#define NLM_F_DUMP_INTR		0x10	/* Dump was inconsistent due to sequence change */
#define NLM_F_DUMP_FILTERED	0x20	/* Dump was filtered as requested */

/* Modifiers to GET request */
#define NLM_F_ROOT	0x100	/* specify tree	root	*/
#define NLM_F_MATCH	0x200	/* return all matching	*/
#define NLM_F_ATOMIC	0x400	/* atomic GET		*/
#define NLM_F_DUMP	(NLM_F_ROOT|NLM_F_MATCH)

/* Modifiers to NEW request */
#define NLM_F_REPLACE	0x100	/* Override existing		*/
#define NLM_F_EXCL	0x200	/* Do not touch, if it exists	*/
#define NLM_F_CREATE	0x400	/* Create, if it does not exist	*/
#define NLM_F_APPEND	0x800	/* Add to end of list		*/

/* Modifiers to DELETE request */
#define NLM_F_NONREC	0x100	/* Do not delete recursively	*/

/* Flags for ACK message */
#define NLM_F_CAPPED	0x100	/* request was capped */
#define NLM_F_ACK_TLVS	0x200	/* extended ACK TVLs were included */


#define NLMSG_NOOP		0x1	/* Nothing.		*/
#define NLMSG_ERROR		0x2	/* Error		*/
#define NLMSG_DONE		0x3	/* End of a dump	*/
#define NLMSG_OVERRUN		0x4	/* Data lost		*/

#define NLMSG_MIN_TYPE		0x10	/* < 0x10: reserved control messages */



#define NLMSG_ALIGNTO	4U
#define NLMSG_ALIGN(len) ( ((len)+NLMSG_ALIGNTO-1) & ~(NLMSG_ALIGNTO-1) )
#define NLMSG_HDRLEN	 ((int) NLMSG_ALIGN(sizeof(struct nlmsghdr)))
#define NLMSG_LENGTH(len) ((len) + NLMSG_HDRLEN)

#endif /*linux_netlink_h*/