#ifndef _NET_NETLINK_H
#define _NET_NETLINK_H

#include <sys/param.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/jail.h>
#include <sys/kernel.h>
#include <sys/domain.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/priv.h>
#include <sys/proc.h>
#include <sys/protosw.h>
#include <sys/rwlock.h>
#include <sys/signalvar.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sysctl.h>
#include <sys/systm.h>

#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/netisr.h>
#include <net/vnet.h>
#include <net/raw_cb.h>
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
#define NL_MAX_HANDLERS 100
typedef int (*nl_handler)(char *data);

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
struct nlpcb {
	struct rawcb rp; /*rawcb*/
	uint32_t			portid;
	uint32_t			dst_portid;
	uint32_t			dst_group;
	uint32_t			flags;
};
#define sotonlpcb(so)       ((struct nlpcb *)(so)->so_pcb)


#endif
