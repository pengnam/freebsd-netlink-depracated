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

nl_handler nl_handlers[MAX_HANDLERS];

/*Utility*/
static int 
verify_proto(int proto) {
	if (proto < 0 || proto >= MAX_HANDLERS) {
		return EINVAL;
	}
	int handler_defined = nl_handlers[proto] == NULL;
	return (handler_defined ? 0 : EPROTONOSUPPORT);
}

/*Start of usrreq struct handlers*/

	static void
nl_abort(struct socket *so)
{

	raw_usrreqs.pru_abort(so);
}


	static int
nl_attach(struct socket *so, int proto, struct thread *td)
{
	struct rawcb *rp;
	int error;

	KASSERT(so->so_pcb == NULL, ("rts_attach: so_pcb != NULL"));

	error = verify_proto(proto);
	if (error)
		return error;
	rp = malloc(sizeof *rp, M_PCB, M_WAITOK | M_ZERO);

	so->so_pcb = (caddr_t)rp;
	so->so_fibnum = td->td_proc->p_fibnum;
	error = raw_attach(so, proto);
	rp = sotorawcb(so);
	if (error) {
		so->so_pcb = NULL;
		free(rp, M_PCB);
		return error;
	}
	//TODO: Check if this is to be called.Maybe no because we don't implement connect?
	soisconnected(so);
	so->so_options |= SO_USELOOPBACK;
	return 0;
}
	static int
nl_bind(struct socket *so, struct sockaddr *nam, struct thread *td)
{
	return (raw_usrreqs.pru_bind(so, nam, td)); /* xxx just EINVAL */
}
	static int
nl_connect(struct socket *so, struct sockaddr *nam, struct thread *td)
{
	static uint32_t netlinkpids = 1; // XXX see above
	struct sockaddr_nl *nla = (struct sockaddr_nl *)nam;
	/* nam->sa_len is updated with the actual length in the syscall */

	if (nla->nl_len != sizeof(*nla))
		return EINVAL;

	so->nl_src_portid = atomic_fetchadd_32(&netlinkpids, 1);
	so->nl_dst_portid = nla->nl_pid; /* not used */

	ND("src_portid %d dst_portid %d", so->nl_src_portid, so->nl_dst_portid);
	soisconnected(so);

	return 0;
}

	static void
nl_detach(struct socket *so)
{

	raw_usrreqs.pru_detach(so);
}

	static int
nl_disconnect(struct socket *so)
{
	return (raw_usrreqs.pru_disconnect(so));
}
	static int
nl_peeraddr(struct socket *so, struct sockaddr **nam)
{

	D("");
	return ENOTCONN;
}
	static int
nl_send(struct socket *so, int flags, struct mbuf *m, struct sockaddr *   nam,
		struct mbuf *control, struct thread *td)
{
	D("");
	return 0;
}

	static int
nl_shutdown(struct socket *so)
{

	D("");
	return (raw_usrreqs.pru_shutdown(so));
}


/* fetch peer's address */
	static int
nl_sockaddr(struct socket *so, struct sockaddr **nam)
{
	D("");
	return 0;
}


	static void
nl_close(struct socket *so)
{

	raw_usrreqs.pru_close(so);
}


/* netlink usrreqs*/
static struct pr_usrreqs nl_usrreqs = {
	.pru_abort =        soisdisconnected,
	.pru_attach =       nl_attach,
	.pru_bind =     nl_bind,
	.pru_connect =      nl_connect,   
	.pru_detach =       nl_detach,//TODO
	.pru_disconnect =   nl_disconnect,//TODO
	.pru_peeraddr =     nl_peeraddr,//TODO   
	.pru_send =     nl_send,//TODO
	.pru_shutdown =     nl_shutdown,//TODO
	.pru_sockaddr =     nl_sockaddr,//TODO
	.pru_close =        nl_close 
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
		.pr_usrreqs =		&nl_usrreqs
	}
};

static struct domain netlinkdomain = {
	.dom_family =		PF_NETLINK,
	.dom_name =		 "netlink2",
	.dom_protosw =		netlinksw,
	.dom_protoswNPROTOSW =	&netlinksw[sizeof(netlinksw)/sizeof(netlinksw[0])]
};


VNET_DOMAIN_SET(netlink);
