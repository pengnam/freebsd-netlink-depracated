#ifndef _NET_NETLINK2_H
#define _NET_NETLINK2_H

#include <sys/param.h>
#include <sys/types.h>
#include <sys/systm.h>

#include <linux/netlink.h>
/* ========================================================================
 *         Netlink Messages and Attributes Interface (As Seen On TV)
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
 *   nlmsg_next(nlh)-----------------------+
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

/*Note that flowid only has 32 bits so for now skb is ONLY portid*/
#define NETLINK_CB_PORT(m) ((m)->m_pkthdr.flowid)
int 
register_or_replace_handler(int proto, nl_handler handle);

//NLMSG AHELPERS
//TODO: size_t
static inline struct mbuf *nlmsg_new(int payload, int flags)
{
	struct mbuf *m;
	//flags specify M_WAITOK or M_WAITNOTOK
	m = mget_m(NULL, payload, flags, MT_DATA);
	//TODO: Linear buffer 
	return m;
}

static inline int nlmsg_msg_size(int payload) {
	return NLMSG_HDRLEN + payload;
}
static inline int nlmsg_total_size(int payload) {
	return NLMSG_ALIGN(nlmsg_msg_size(payload));
}
static inline void *nlmsg_data(const struct nlmsghdr *nlh)
{
	return (unsigned char *) nlh + NLMSG_HDRLEN;
}


static inline int nlmsg_payload_len(const struct nlmsghdr *nlh)
{
	return nlh->nlmsg_len - NLMSG_HDRLEN;
}


static inline struct nlmsghdr *nlmsg_put(struct mbuf* m, u32 portid, u32 seq,
					 int type, int payload, int flags)
{
	struct nlmsghdr *nlh;
	int size = nlmsg_msg_size(payload);
	//TODO: Figure out if this is right for linear buffer
	m = m_pullup(m, size);
	if (m == NULL) {
		D("Error linearizing size");
		return;
	}
	nlh = mtod(m, (struct nlmsghdr));
	nlh->nlmsg_type = type;
	nlh->nlmsg_len = size;
	nlh->nlmsg_pid = portid;
	nlh->nlmsg_seq = seq;
	if (NLMSG_ALIGN(size) - size != 0)
		memset(nlmsg_data(nlh) + len, 0, NLMSG_ALIGN(size) - size);
	return nlh;
}

#endif
