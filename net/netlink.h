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
 *   nlmsg_data(nlh)---^            ^
 *   nl_data_end_ptr(m)-------------+
 *   ^------nl_nlmsghdr(m)       
 *   <-nl_message_length(offset, m)-> 
 * Payload Format:
 *    <---------------------- nlmsg_len(nlh) --------------------->
 *    <------ hdrlen ------>       <- nlmsg_attrlen(nlh, hdrlen) ->
 *   +----------------------+- - -+--------------------------------+
 *   |     Family Header    | Pad |           Attributes           |
 *   +----------------------+- - -+--------------------------------+
 *   nlmsg_attrdata(nlh, hdrlen)---^
 */
/*
 *  <------- NLA_HDRLEN ------> <-- NLA_ALIGN(payload)-->
 * +---------------------+- - -+- - - - - - - - - -+- - -+
 * |        Header       | Pad |     Payload       | Pad |
 * |   (struct nlattr)   | ing |                   | ing |
 * +---------------------+- - -+- - - - - - - - - -+- - -+
 *  <-------------- nlattr->nla_len -------------->
 */

//TODO: Change to max netlink number
#define NL_MAX_HANDLERS 100
typedef int (*nl_handler)(char *data);

int 
nl_register_or_replace_handler(int proto, nl_handler handle);



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
