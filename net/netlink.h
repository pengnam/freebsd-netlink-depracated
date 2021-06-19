#ifndef _NET_NETLINK2_H
#define _NET_NETLINK2_H

#include <sys/param.h>
#include <sys/types.h>
#include <sys/systm.h>

#include <linux/netlink.h>

//TODO: Change to max netlink number
#define MAX_HANDLERS 100
typedef int (*nl_handler)(char *data);
#define nl_src_portid   so_fibnum
#define nl_dst_portid   so_user_cookie

/*Note that flowid only has 32 bits so for now skb is ONLY portid*/
#define NETLINK_CB_PORT(m) ((m)->m_pkthdr.flowid)
int 
register_or_replace_handler(int proto, nl_handler handle);

#endif
