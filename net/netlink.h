#ifndef _NET_NETLINK_H
#define _NET_NETLINK_H

#include <sys/param.h>
#include <sys/types.h>
#include <sys/systm.h>

#include <linux/netlink.h>
/* Modified from: https://elixir.bootlin.com/linux/latest/source/include/net/netlink.h
 * ========================================================================
 *         Netlink Messages and Attributes Interface 
 * ------------------------------------------------------------------------
 *                          Messages Interface
 * ------------------------------------------------------------------------
 *
 * Message Format:
 *    <--- nlmsg_total_size(payload)  --->
 *    <-- nlmsg_msg_size(payload) ->
 *   +----------+- - -+-------------+- - -+-------- - -
 *   | nlmsghdr | Pad |   Payload   | Pad | nlmsghdr
 *   +----------+- - -+-------------+- - -+-------- - -
 *   nlmsg_data(nlh)---^                   ^
 *
 * Payload Format:
 *    <---------------------- nlmsg_payload_len(nlh) --------------------->
 *    <------ hdrlen ------>       <- nlmsg_attrlen(nlh, hdrlen) ->
 *   +----------------------+- - -+--------------------------------+
 *   |     Family Header    | Pad |           Attributes           |
 *   +----------------------+- - -+--------------------------------+
 *   nlmsg_attrdata(nlh, hdrlen)---^
 */

//TODO: Change to max netlink number
#define MAX_HANDLERS 100
typedef int (*nl_handler)(char *data);
#define nl_src_portid   so_fibnum
#define nl_dst_portid   so_user_cookie

/*Note that flowid only has 32 bits which is only enough for portid*/
#define NETLINK_CB_PORT(m) ((m)->m_pkthdr.flowid)

int 
nl_register_or_replace_handler(int proto, nl_handler handle);

/*---- nlmsg helpers ----*/
static inline int
nlmsg_msg_size(int payload) {
	return NLMSG_HDRLEN + payload;
}

static inline int
nlmsg_aligned_msg_size(int payload) {
	return NLMSG_ALIGN(nlmsg_msg_size(payload));
}
static inline void *
nlmsg_data(struct nlmsghdr *nlh)
{
	return (unsigned char *) nlh + NLMSG_HDRLEN;
}

static inline int
nlmsg_payload_len(const struct nlmsghdr *nlh)
{
	return nlh->nlmsg_len - NLMSG_HDRLEN;
}

static inline struct mbuf *
nlmsg_new(int payload, int flags)
{
	int size = nlmsg_aligned_msg_size(payload);
	printf("allocated : %d\n", size);
	//flags specify M_WAITOK or M_WAITNOTOK
	//TODO: Linear buffer 
	return m_getm(NULL, size, flags, MT_DATA);
}



static inline struct nlmsghdr *
nlmsg_put(struct mbuf* m, int portid, int seq, int type, int payload, int flags)
{
	struct nlmsghdr *nlh;
	int size = nlmsg_msg_size(payload);
	//TODO: Figure out why this code returns NULL
	//m = m_pullup(m, size);
	//if (m == NULL) {
	//	printf("Error linearizing size | payload: %d | size: %d\n", payload, size);
	//	return NULL;
	//}
	nlh = mtod(m, struct nlmsghdr *);
	if (nlh == NULL) {
		printf("Error at mtod");
		return NULL;
	}
	nlh->nlmsg_type = type;
	nlh->nlmsg_len = size;
	nlh->nlmsg_pid = portid;
	nlh->nlmsg_seq = seq;
	if (NLMSG_ALIGN(size) - size != 0)
		memset((char*)nlmsg_data(nlh) + payload, 0, NLMSG_ALIGN(size) - size);
	return nlh;
}

/*---- end nlmsg helpers ----*/
#endif
