
#include <sys/param.h>
#include <sys/jail.h>
#include <sys/kernel.h>
#include <sys/domain.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/priv.h>
#include <sys/proc.h>
#include <sys/protosw.h>
#include <sys/rmlock.h>
#include <sys/rwlock.h>
#include <sys/signalvar.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sysctl.h>
#include <sys/systm.h>

#include <net/if.h>
#include <net/if_var.h>
#include <net/if_dl.h>
#include <net/if_llatbl.h>
#include <net/if_types.h>
#include <net/netisr.h>
#include <net/raw_cb.h>
#include <net/route.h>
#include <net/vnet.h>

#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip_carp.h>
#ifdef INET6
#include <netinet6/ip6_var.h>
#include <netinet6/scope6_var.h>
#endif


#include <net/rtnetlink.h>


 #ifndef _SOCKADDR_UNION_DEFINED
 #define _SOCKADDR_UNION_DEFINED
 /*
  * The union of all possible address formats we handle.
  */
 union sockaddr_union {
     struct sockaddr     sa;
     struct sockaddr_in  sin;
     struct sockaddr_in6 sin6;
 };
 #endif /* _SOCKADDR_UNION_DEFINED */

struct walkarg {
    int family;
    int w_tmemsize;
    int w_op, w_arg;
    caddr_t w_tmem;
    struct sysctl_req *w_req;
    struct sockaddr *dst;
    struct sockaddr *mask;
};

	static int
rtnl_receive_message(void* data, struct socket *so)
{
//
//	//TODO:LOCK
//	struct rt_msghdr *rtm = NULL;
//	struct rtentry *rt = NULL;
//	struct rib_head *rnh;
//	struct rt_addrinfo info;
//	struct sockaddr_storage ss;
//	//TODO: INET6
//	int alloc_len = 0, len, error = 0, fibnum;
//	struct ifnet *ifp = NULL;
//	union sockaddr_union saun;
//	sa_family_t saf = AF_UNSPEC;
//	struct rawcb *rp = NULL;
//	struct walkarg w;
//
//	//TODO: Check if netlink uses fibnum
//	fibnum = so->so_fibnum;
//	
//	//--- start --
//	//Copies into new msgbuffer with rtmsghdr at the start, strips nlmsghdr
//	struct nlmsghdr * hdr = (struct nlmsghdr*) data;
//	// length to copy
//	len = hdr->nlmsg_len - NLMSG_HDRLEN;
//	char* source = data + NLMSG_HDRLEN;
//
//	alloc_len = roundup2(len + sizeof(struct rt_msghdr), 1024);
//	if ((rtm = malloc(alloc_len, M_TEMP, M_NOWAIT)) == NULL)
//		senderr(ENOBUFS);
//
//	memcpy((char*) rtm + sizeof(struct rt_msghdr),  source, len);
//
//	rtm->rtm_type = hdr->nlmsg_type;
//	rtm
//	
//	//-- end --
//
//	#define senderr(e) { error = e; goto flush;}
//	switch (rtm->rtm_type) {
//		struct rtentry *saved_nrt;
//
//	case RTM_ADD:
//	case RTM_CHANGE:
//		if (rtm->rtm_type == RTM_ADD) {
//			if (info.rti_info[RTAX_GATEWAY] == NULL)
//				senderr(EINVAL);
//		}
//		saved_nrt = NULL;
//
//		/* support for new ARP code */
//		if (info.rti_info[RTAX_GATEWAY] != NULL &&
//		    info.rti_info[RTAX_GATEWAY]->sa_family == AF_LINK &&
//		    (rtm->rtm_flags & RTF_LLDATA) != 0) {
//			error = lla_rt_output(rtm, &info);
//#ifdef INET6
//			if (error == 0)
//				rti_need_deembed = (V_deembed_scopeid) ? 1 : 0;
//#endif
//			break;
//		}
//		error = rtrequest1_fib(rtm->rtm_type, &info, &saved_nrt,
//		    fibnum);
//		if (error == 0 && saved_nrt != NULL) {
//#ifdef INET6
//			rti_need_deembed = (V_deembed_scopeid) ? 1 : 0;
//#endif
//			RT_LOCK(saved_nrt);
//			rtm->rtm_index = saved_nrt->rt_ifp->if_index;
//			RT_REMREF(saved_nrt);
//			RT_UNLOCK(saved_nrt);
//		}
//		break;
//
//	case RTM_DELETE:
//		saved_nrt = NULL;
//		/* support for new ARP code */
//		if (info.rti_info[RTAX_GATEWAY] && 
//		    (info.rti_info[RTAX_GATEWAY]->sa_family == AF_LINK) &&
//		    (rtm->rtm_flags & RTF_LLDATA) != 0) {
//			error = lla_rt_output(rtm, &info);
//#ifdef INET6
//			if (error == 0)
//				rti_need_deembed = (V_deembed_scopeid) ? 1 : 0;
//#endif
//			break;
//		}
//		error = rtrequest1_fib(RTM_DELETE, &info, &saved_nrt, fibnum);
//		if (error == 0) {
//			RT_LOCK(saved_nrt);
//			rt = saved_nrt;
//			goto report;
//		}
//#ifdef INET6
//		/* rt_msg2() will not be used when RTM_DELETE fails. */
//		rti_need_deembed = (V_deembed_scopeid) ? 1 : 0;
//#endif
//		break;
//
//	case RTM_GET:
//		rnh = rt_tables_get_rnh(fibnum, saf);
//		if (rnh == NULL)
//			senderr(EAFNOSUPPORT);
//
//		RIB_RLOCK(rnh);
//
//		if (info.rti_info[RTAX_NETMASK] == NULL &&
//		    rtm->rtm_type == RTM_GET) {
//			/*
//			 * Provide longest prefix match for
//			 * address lookup (no mask).
//			 * 'route -n get addr'
//			 */
//			rt = (struct rtentry *) rnh->rnh_matchaddr(
//			    info.rti_info[RTAX_DST], &rnh->head);
//		} else
//			rt = (struct rtentry *) rnh->rnh_lookup(
//			    info.rti_info[RTAX_DST],
//			    info.rti_info[RTAX_NETMASK], &rnh->head);
//
//		if (rt == NULL) {
//			RIB_RUNLOCK(rnh);
//			senderr(ESRCH);
//		}
//#ifdef RADIX_MPATH
//		/*
//		 * for RTM_CHANGE/LOCK, if we got multipath routes,
//		 * we require users to specify a matching RTAX_GATEWAY.
//		 *
//		 * for RTM_GET, gate is optional even with multipath.
//		 * if gate == NULL the first match is returned.
//		 * (no need to call rt_mpath_matchgate if gate == NULL)
//		 */
//		if (rt_mpath_capable(rnh) &&
//		    (rtm->rtm_type != RTM_GET || info.rti_info[RTAX_GATEWAY])) {
//			rt = rt_mpath_matchgate(rt, info.rti_info[RTAX_GATEWAY]);
//			if (!rt) {
//				RIB_RUNLOCK(rnh);
//				senderr(ESRCH);
//			}
//		}
//#endif
//		/*
//		 * If performing proxied L2 entry insertion, and
//		 * the actual PPP host entry is found, perform
//		 * another search to retrieve the prefix route of
//		 * the local end point of the PPP link.
//		 */
//		if (rtm->rtm_flags & RTF_ANNOUNCE) {
//			struct sockaddr laddr;
//
//			if (rt->rt_ifp != NULL && 
//			    rt->rt_ifp->if_type == IFT_PROPVIRTUAL) {
//				struct ifaddr *ifa;
//
//				NET_EPOCH_ENTER();
//				ifa = ifa_ifwithnet(info.rti_info[RTAX_DST], 1,
//						RT_ALL_FIBS);
//				if (ifa != NULL)
//					rt_maskedcopy(ifa->ifa_addr,
//						      &laddr,
//						      ifa->ifa_netmask);
//				NET_EPOCH_EXIT();
//			} else
//				rt_maskedcopy(rt->rt_ifa->ifa_addr,
//					      &laddr,
//					      rt->rt_ifa->ifa_netmask);
//			/* 
//			 * refactor rt and no lock operation necessary
//			 */
//			rt = (struct rtentry *)rnh->rnh_matchaddr(&laddr,
//			    &rnh->head);
//			if (rt == NULL) {
//				RIB_RUNLOCK(rnh);
//				senderr(ESRCH);
//			}
//		} 
//		RT_LOCK(rt);
//		RT_ADDREF(rt);
//		RIB_RUNLOCK(rnh);
//
//report:
//		RT_LOCK_ASSERT(rt);
//		if ((rt->rt_flags & RTF_HOST) == 0
//		    ? jailed_without_vnet(curthread->td_ucred)
//		    : prison_if(curthread->td_ucred,
//		    rt_key(rt)) != 0) {
//			RT_UNLOCK(rt);
//			senderr(ESRCH);
//		}
//		info.rti_info[RTAX_DST] = rt_key(rt);
//		info.rti_info[RTAX_GATEWAY] = rt->rt_gateway;
//		info.rti_info[RTAX_NETMASK] = rtsock_fix_netmask(rt_key(rt),
//		    rt_mask(rt), &ss);
//		info.rti_info[RTAX_GENMASK] = 0;
//		if (rtm->rtm_addrs & (RTA_IFP | RTA_IFA)) {
//			ifp = rt->rt_ifp;
//			if (ifp) {
//				info.rti_info[RTAX_IFP] =
//				    ifp->if_addr->ifa_addr;
//				error = rtm_get_jailed(&info, ifp, rt,
//				    &saun, curthread->td_ucred);
//				if (error != 0) {
//					RT_UNLOCK(rt);
//					senderr(error);
//				}
//				if (ifp->if_flags & IFF_POINTOPOINT)
//					info.rti_info[RTAX_BRD] =
//					    rt->rt_ifa->ifa_dstaddr;
//				rtm->rtm_index = ifp->if_index;
//			} else {
//				info.rti_info[RTAX_IFP] = NULL;
//				info.rti_info[RTAX_IFA] = NULL;
//			}
//		} else if ((ifp = rt->rt_ifp) != NULL) {
//			rtm->rtm_index = ifp->if_index;
//		}
//
//		/* Check if we need to realloc storage */
//		rtsock_msg_buffer(rtm->rtm_type, &info, NULL, &len);
//		if (len > alloc_len) {
//			struct rt_msghdr *new_rtm;
//			new_rtm = malloc(len, M_TEMP, M_NOWAIT);
//			if (new_rtm == NULL) {
//				RT_UNLOCK(rt);
//				senderr(ENOBUFS);
//			}
//			bcopy(rtm, new_rtm, rtm->rtm_msglen);
//			free(rtm, M_TEMP);
//			rtm = new_rtm;
//			alloc_len = len;
//		}
//
//		w.w_tmem = (caddr_t)rtm;
//		w.w_tmemsize = alloc_len;
//		rtsock_msg_buffer(rtm->rtm_type, &info, &w, &len);
//
//		if (rt->rt_flags & RTF_GWFLAG_COMPAT)
//			rtm->rtm_flags = RTF_GATEWAY | 
//				(rt->rt_flags & ~RTF_GWFLAG_COMPAT);
//		else
//			rtm->rtm_flags = rt->rt_flags;
//		rt_getmetrics(rt, &rtm->rtm_rmx);
//		rtm->rtm_addrs = info.rti_addrs;
//
//		RT_UNLOCK(rt);
//		break;
//
//	default:
//		senderr(EOPNOTSUPP);
//	}

	return 0;
}

	static void
rtnl_load(void *u __unused)
{
	//TODO: initialize
	nl_register_or_replace_handler(NETLINK_GENERIC, rtnl_receive_message);
	//TODO: initialize bsd nl
}

	static void
rtnl_unload(void *u __unused)
{

}

SYSINIT(rtnl_load, SI_SUB_PROTO_DOMAIN, SI_ORDER_THIRD, rtnl_load, NULL);
SYSINIT(rtnl_unload, SI_SUB_PROTO_DOMAIN, SI_ORDER_THIRD, rtnl_unload, NULL);
