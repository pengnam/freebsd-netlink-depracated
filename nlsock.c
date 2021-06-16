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
 #include <net/route.h>
#include <netlink2/net/netlink.h>
MALLOC_DEFINE(M_NETLINK, "netlink", "Memory used for netlink packets");


/*---- start debugging macros  */
#define ND(format, ...)
#define D(format, ...)                                          \
        do {                                                    \
                struct timeval __xxts;                          \
                microtime(&__xxts);                             \
                printf("%03d.%06d [%4d] %-25s " format "\n",    \
                (int)__xxts.tv_sec % 1000, (int)__xxts.tv_usec, \
                __LINE__, __FUNCTION__, ##__VA_ARGS__);         \
        } while (0)
/*end */


 static int
 netlink_attach(struct socket *so, int proto, struct thread *td)
 {
     D("");
     return 0;
 }
static int
 netlink_bind(struct socket *so, struct sockaddr *nam, struct thread *td)
 {

     D("");
     return EINVAL;
 }
 static int
 netlink_connect(struct socket *so, struct sockaddr *nam, struct thread *td)
 {
     D("");
     return 0;
 }

 static void
 netlink_detach(struct socket *so)
 {
    D("");
 }

 static int
 netlink_disconnect(struct socket *so)
 {

     return ENOTCONN; // XXX why ?
 }
 static int
 netlink_peeraddr(struct socket *so, struct sockaddr **nam)
 {

     D("");
     return ENOTCONN;
 }
static int
 netlink_send(struct socket *so, int flags, struct mbuf *m, struct sockaddr *   nam,
      struct mbuf *control, struct thread *td)
 {
     D("");
     return 0;
 }

 static int
 netlink_shutdown(struct socket *so)
 {

     D("");
     return (raw_usrreqs.pru_shutdown(so));
 }


/* fetch peer's address */
static int
 netlink_sockaddr(struct socket *so, struct sockaddr **nam)
 {
   D("");
   return 0;
 }




/* netlink usrreqs*/
 static struct pr_usrreqs netlink_usrreqs = {
     .pru_abort =        soisdisconnected,
     .pru_attach =       netlink_attach,
     .pru_bind =     netlink_bind,
     .pru_connect =      netlink_connect,   
     .pru_detach =       netlink_detach,
     .pru_disconnect =   netlink_disconnect,
     .pru_peeraddr =     netlink_peeraddr,   
     .pru_send =     netlink_send,
     .pru_shutdown =     netlink_shutdown,
     .pru_sockaddr =     netlink_sockaddr,
     .pru_close =        soisdisconnected
 };

/* Protosw*/
static int
netlink_ctloutput(struct socket *so, struct sockopt *sopt) {
	D("start");
	return 0;
}

static int
netlink_input(struct mbuf *m, struct socket *so, ...) {
	D("start");
	return 0;
}


static struct domain netlinkdomain; 

static struct protosw netlinksw[] = {
{
	.pr_type =		SOCK_RAW,
	.pr_domain =		&netlinkdomain,
	.pr_flags =		PR_ATOMIC|PR_ADDR,
	.pr_output =		netlink_input,
	.pr_init =		raw_init,
	.pr_usrreqs =		&netlink_usrreqs
}
};

static struct domain netlinkdomain = {
	.dom_family =		PF_NETLINK,
	.dom_name =		 "netlink2",
	.dom_protosw =		netlinksw,
	.dom_protoswNPROTOSW =	&netlinksw[sizeof(netlinksw)/sizeof(netlinksw[0])]
};


VNET_DOMAIN_SET(netlink);
