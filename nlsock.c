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

#include <sys/malloc.h>
#include <sys/systm.h>
#include <sys/queue.h>


#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/netisr.h>
#include <net/vnet.h>
#include <net/raw_cb.h>
#include <net/route.h>
#include <netlink2/net/netlink.h>
MALLOC_DEFINE(M_NETLINK, "netlink", "Memory used for netlink packets");



//TODO: Change into proto to uint8 proto
/*---- start debugging macros --luigi */
#define ND(format, ...)
#define D(format, ...)                                          \
	do {                                                    \
		struct timeval __xxts;                          \
		microtime(&__xxts);                             \
		printf("%03d.%06d [%4d] %-25s " format "\n",    \
				(int)__xxts.tv_sec % 1000, (int)__xxts.tv_usec, \
				__LINE__, __FUNCTION__, ##__VA_ARGS__);         \
	} while (0)

nl_handler nl_handlers[NL_MAX_HANDLERS];
struct mtx nlsock_mtx;
#define	NLSOCK_LOCK()	mtx_lock(&nlsock_mtx)
#define	NLSOCK_UNLOCK()	mtx_unlock(&nlsock_mtx)
struct nl_portid {
	LIST_ENTRY(nl_portid)  next;
	uint32_t id;
};
LIST_HEAD(, nl_portid) nl_portid_list = LIST_HEAD_INITIALIZER(nl_portid_list);


	static int 
nl_verify_proto(int proto)
{
	if (proto < 0 || proto >= NL_MAX_HANDLERS) {
		return EINVAL;
	}
	int handler_defined = nl_handlers[proto] != NULL;
	return (handler_defined ? 0 : EPROTONOSUPPORT);
}

	int
nl_register_or_replace_handler(int proto, nl_handler handler)
{
	if (proto < 0 || proto >= NL_MAX_HANDLERS) {
		return EINVAL;
	}
	nl_handlers[proto] = handler;
	return 0;
}

/*--- usrreq struct handlers ----*/

	static void
nl_abort(struct socket *so)
{

	raw_usrreqs.pru_abort(so);
}


	static int
nl_attach(struct socket *so, int proto, struct thread *td)
{
	D("");
	struct nlpcb *rp;
	int error;

	KASSERT(so->so_pcb == NULL, ("rts_attach: so_pcb != NULL"));

	error = nl_verify_proto(proto);
	if (error)
		return error;
	rp = malloc(sizeof *rp, M_PCB, M_WAITOK | M_ZERO);

	so->so_pcb = (caddr_t)rp;

	error = raw_attach(so, proto);
	if (error) {
		so->so_pcb = NULL;
		free(rp, M_PCB);
		return error;
	}
	so->so_options |= SO_USELOOPBACK;


	return 0;
}

	static int
nl_bind(struct socket *so, struct sockaddr *nam, struct thread *td)
{
	//TODO: Multicast group binding, refer to netlink_bind
	return (raw_usrreqs.pru_bind(so, nam, td)); /* xxx just EINVAL */
}

//Lock needs to be claimed
	static struct
nl_portid * nl_portid_lookup(uint32_t portid)
{
	struct nl_portid * entry;
	LIST_FOREACH(entry, &nl_portid_list, next) {
		if (entry->id == portid) {
			return entry;
		}
	}
	return NULL;
}

//Lock needs to be claimed
	static bool
nl_portid_exists(uint32_t portid)
{
	return nl_portid_lookup(portid) != NULL;
}

	static int
nl_assign_port(struct nlpcb *rp, uint32_t portid)
{
	struct nl_portid *new_port;
	int error = 0;

	new_port = malloc(sizeof(struct nl_portid), M_NETLINK, M_NOWAIT|M_ZERO);
	if (!new_port) {
		return ENOMEM;
	}
	new_port->id = portid;

	NLSOCK_LOCK();
	if (nl_portid_exists(portid)) {
		error  = EADDRINUSE;
	} else {
		LIST_INSERT_HEAD(&nl_portid_list, new_port, next);
		rp->portid = portid;
	}
	NLSOCK_UNLOCK();
	D("port assign: %d, err: %d", portid, error);
	return error;
}


	static int
nl_bind_port(struct nlpcb *rp, uint32_t start) 
{
	uint32_t portid = start;
	bool exist;
	int error;

retry:
	NLSOCK_LOCK();
	exist = nl_portid_exists(portid);
	NLSOCK_UNLOCK();
	if (exist) {
		portid++;
		goto retry;

	}
	error = nl_assign_port(rp, portid);
	if (error == EADDRINUSE)
		goto retry;
	return error;

}

	static int
nl_connect(struct socket *so, struct sockaddr *nam, struct thread *td)
{

	//TODO: What about kernel sockets? Should they be reassigned?
	D("");
	struct nlpcb *rp;
	struct sockaddr_nl *nla = (struct sockaddr_nl *)nam;
	int error = 0;
	if (nla->nl_len != sizeof(*nla))
		return EINVAL;

	rp = sotonlpcb(so);
	error = nl_bind_port(rp, td->td_proc->p_pid);
	if (error == 0) {
		rp->dst_portid = nla->nl_pid;/*NOTE: This is not used, refer to comment in PR phase*/
		//TODO: Handle multicast and socket flags: refer to linux implementation
		soisconnected(so);
	}
	D("Portid: %d, Error: %d", rp->portid, error);

	return error;
}

	static void
nl_detach(struct socket *so)
{
	D("");
	raw_usrreqs.pru_detach(so);
}

	static int
nl_disconnect(struct socket *so)
{
	D("");
	return (raw_usrreqs.pru_disconnect(so));
}

	static int
nl_peeraddr(struct socket *so, struct sockaddr **nam)
{

	D("");
	return (raw_usrreqs.pru_peeraddr(so, nam));
}

	static int
nl_shutdown(struct socket *so)
{
	//NETLINK doesn't do much on shutdown, and mainly closes
	D("");
	return (raw_usrreqs.pru_shutdown(so));
}


	static int
nl_sockaddr(struct socket *so, struct sockaddr **nam)
{
	struct sockaddr_nl *snl = malloc(sizeof *snl, M_SONAME, M_WAITOK | M_ZERO);
	/* TODO: set other fields */
	snl->nl_pid = so->so_fibnum;
	snl->nl_len = sizeof(*snl);
	snl->nl_family = AF_NETLINK;

	*nam = (struct sockaddr *) snl;
	return 0;

}


	static void
nl_close(struct socket *so)
{
	D("");
	struct nl_portid *p;
	struct nlpcb *rp;

	rp = sotonlpcb(so);

	// Release the portid
	NLSOCK_LOCK();
	p = nl_portid_lookup(rp->portid);
	if (p == NULL) {
		D("Error: can't find portid in list");
		goto err;
	}
	LIST_REMOVE(p, next);
	free(p, M_NETLINK);
err:
	NLSOCK_UNLOCK();

	raw_usrreqs.pru_close(so);
}
/*--- end of usrreq struct handlers----*/


/*---- start of protosw struct handlers ----*/
static int
nl_ctloutput(struct socket *so, struct sockopt *sopt) {
	D("");
	int mgrp;
	switch (sopt->sopt_dir) {
		case SOPT_SET:
			switch (sopt->sopt_name) {
				case NETLINK_ADD_MEMBERSHIP:
					sooptcopyin(sopt, &mgrp, sizeof mgrp, sizeof mgrp);
					//TODO: modify nl_groups


					return 0;
				default:
					//TODO: 
					return 0; 
			}
		case SOPT_GET:
		default:
			return ENOPROTOOPT;
	}
	return 0;
}

/**
 * Retrieve the message length of a message 
 * @offset: offset in bytes of the start of the next message in mbuf
 *
 * Returns 0 if no valid message length can be found for message at offset,
 * message length otherwise
 */
	static int 
nl_message_length(int offset, struct mbuf *m)
{
	D("");
	int total_length, message_length;
	struct nlmsghdr hdr;
	struct nlmsghdr *h = &hdr;

	total_length = m_length(m, NULL);

	if (offset >= total_length || offset + NLMSG_HDRLEN > total_length) {
		return 0;
	}

	// Copy out netlink header data
	m_copydata(m, offset, sizeof(hdr), (caddr_t) h);
	message_length = h->nlmsg_len;

	//  Ensure that message_length is valid
	if (message_length < NLMSG_HDRLEN || offset + message_length > total_length) {
		return 0;
	}
	return message_length;
}


	static int
nl_send_msg(struct mbuf *m)
{
	// TODO: phase3: set to isrqueue
	return 0;
}


	static void
nl_ack(uint8_t proto, uint32_t portid, struct nlmsghdr * nlmsg, int err)
{
	D("");
	struct mbuf *m;
	struct nlmsghdr * repnlh;

	struct nlmsgerr *errmsg;
	int payload = sizeof(*errmsg);

	//TODO: handle NETLINK_F_EXT_ACK sockopt (linux impl)
	//TODO: handle NETLINK_F_CAP_ACK sockopt (linux impl)
	if (err)
		payload += (nlmsg->nlmsg_len);
	//TODO: handle cookies

	m = nlmsg_new(payload, M_WAITOK | M_ZERO);
	D("size of new mbuf: %d\n", m->m_len);
	D("size of new mbuf: %d\n", m->m_pkthdr.len);
	if (!m) {
		//TODO: handle error
		D("error allocating nlmsg");
		return;
	}

	repnlh = nlmsg_put( m, portid, nlmsg->nlmsg_seq, NLMSG_ERROR, payload, 0);
	if (repnlh == NULL) {
		D("error putting values in new nlmsg");
		return;
	}

	errmsg = (struct nlmsgerr *)nlmsg_data(repnlh);
	errmsg->error = err;
	/* In case of error copy the whole message, else just the header */
	memcpy(&errmsg->msg, nlmsg, err ? nlmsg->nlmsg_len : sizeof(*nlmsg));

	nlmsg_end(m, repnlh);
	nl_send_msg(m);
}

	static int 
reallocate_memory(char** buffer, int length, int* buffer_length)
{
	//TODO: Round bufferfer length to 1k?
	if (*buffer != NULL) {
		free(*buffer, M_NETLINK);
	}
	*buffer = malloc(length, M_NETLINK, M_NOWAIT|M_ZERO);
	if (*buffer == NULL)  {
		return ENOMEM;
	}
	*buffer_length = length; //TODO: Change if rounding buffer lenght up
	return 0;
}
/*
 * Processes an incoming packet
 * Assumes that every packet header is within a single mbuf
 */
	static int
nl_receive_packet(struct mbuf *m, struct socket *so, int proto)
{
	D("");
	char *buffer = NULL;
	int message_length = 0, offset = 0, buffer_length = 0, error = 0;
	struct nlmsghdr hdr;
	struct nlmsghdr *h = &hdr;
	struct nlpcb *rp;
	//TODO: Check that proto has a valid handler
	nl_handler handler = nl_handlers[proto];
	rp = sotonlpcb(so);
	while ((message_length = nl_message_length(offset, m))) {
		if (buffer_length < message_length) {
			if ((error = reallocate_memory(&buffer, message_length, &buffer_length))) {
				return error;
			}
		}
		D("Considering message with message length(%d) and buffer length(%d)", message_length, buffer_length);
		m_copydata(m, offset, message_length, buffer);
		h = (struct nlmsghdr *)buffer;
		if (h->nlmsg_flags & NLM_F_REQUEST && h->nlmsg_type >= NLMSG_MIN_TYPE) {
			D("inside with msg type: %d", h->nlmsg_type);

			error = handler((void *)h);
		}

		if (error != EINTR && (h->nlmsg_flags & NLM_F_ACK || error != 0))
			nl_ack(proto, rp->portid, h, error);

		offset += NLMSG_ALIGN(message_length);
	}
	return 0;
}


	static int
nl_msg_to_netlink(struct mbuf *m, struct socket *so, ...)
{
	D("");
	struct nlpcb *rp;
	int proto;

	if (m == NULL || ((m->m_len < sizeof(long)) &&
				(m = m_pullup(m, sizeof(long))) == NULL))
		return (ENOBUFS);
	if ((m->m_flags & M_PKTHDR) == 0)
		panic("nl_msg_to_netlink");

	rp = sotonlpcb(so);
	proto = rp->rp.rcb_proto.sp_protocol;
	//TODO: Decide whether saving it in the mbuf header is the best 
	nl_receive_packet(m, so, proto);
	return 0;
}


	static int
nl_send(struct socket *so, int flags, struct mbuf *m, struct sockaddr *nam,
		struct mbuf *control, struct thread *td)
{
	D("");
	return nl_msg_to_netlink(m, so);
}

void *
nl_data_end_ptr(struct mbuf * m) 
{
	return mtod(m, unsigned char *) + m->m_len;

}


/* netlink usrreqs*/
static struct pr_usrreqs nl_usrreqs = {
	.pru_abort =        nl_abort,
	.pru_attach =       nl_attach,
	.pru_bind =     nl_bind,
	.pru_connect =      nl_connect,   
	.pru_detach =       nl_detach,
	.pru_disconnect =   nl_disconnect,
	.pru_peeraddr =     nl_peeraddr,
	.pru_send =     nl_send,
	.pru_shutdown =     nl_shutdown,
	.pru_sockaddr =     nl_sockaddr,
	.pru_close =        nl_close 
};

static struct domain netlinkdomain; 

static struct protosw netlinksw[] = {
	{
		.pr_type =		SOCK_RAW,
		.pr_domain =		&netlinkdomain,
		.pr_flags =		PR_ATOMIC|PR_ADDR,
		.pr_output =		nl_msg_to_netlink,
		.pr_ctloutput =         nl_ctloutput,
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

	static int
netlink_modevent(module_t mod __unused, int what, void *priv __unused)
{
	int ret = 0;
	struct nl_portid *p;

	switch(what) {
		case MOD_LOAD:
			D("Loading");

			LIST_INIT(&nl_portid_list);
			break;

		case MOD_UNLOAD:
			D("Unloading");
			while (!LIST_EMPTY(&nl_portid_list))	{
				p = LIST_FIRST(&nl_portid_list);
				LIST_REMOVE(p, next);
				free(p, M_NETLINK);
			}
			break;

		default:
			ret = EOPNOTSUPP;
			break;
	}

	return ret;
}

static moduledata_t netlink_mod = {
	"netlink",
	netlink_modevent,
	NULL
};

DECLARE_MODULE(netlink_disc, netlink_mod, SI_SUB_PSEUDO, SI_ORDER_ANY);
MODULE_VERSION(netlink, 1);
