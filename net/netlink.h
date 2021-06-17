#ifndef _NET_NETLINK2_H
#define _NET_NETLINK2_H

#include <sys/param.h>
#include <sys/types.h>
#include <sys/systm.h>

#include <linux/netlink.h>

#define MAX_HANDLERS 100
typedef int (*nl_handler)(char *data);
#define nl_src_portid   so_fibnum
 #define nl_dst_portid   so_user_cookie

#endif 
