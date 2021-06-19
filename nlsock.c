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


//TODO: Change into proto to uint8 proto
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
//TODO: Consider shifting this to netlink socket
#define nl_src_portid   so_fibnum
#define nl_dst_portid   so_user_cookie

/*Utility*/
static int 
verify_proto(int proto) {
	if (proto < 0 || proto >= MAX_HANDLERS) {
		return EINVAL;
	}
	int handler_defined = nl_handlers[proto] != NULL;
	return (handler_defined ? 0 : EPROTONOSUPPORT);
}
int 
register_or_replace_handler(int proto, nl_handler handler) {
	if (proto < 0 || proto >= MAX_HANDLERS) {
		return EINVAL;
	}
	nl_handlers[proto] = handler;
	return 0;
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
	D("");
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
	D("");
	struct sockaddr_nl *nla = (struct sockaddr_nl *)nam;
	if (nla->nl_len != sizeof(*nla))
		return EINVAL;
	//if (nla->nl_family != AF_NETLINK)
	//	return EINVAL;

	//TODO: Look at autobind to see how linux handles port *source* id assignment https://elixir.bootlin.com/linux/latest/source/net/netlink/af_netlink.c
	// How source port ids should be addressed is here: https://man7.org/linux/man-pages/man7/netlink.7.html
	so->nl_src_portid = 1;
	so->nl_dst_portid = nla->nl_pid; 

	//TODO: Handle multicast and socket flags: refer to linux implementation

	soisconnected(so);
	return 0;
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
	//TODO: Currently using rtsock
	return (raw_usrreqs.pru_disconnect(so));
}
	static int
nl_peeraddr(struct socket *so, struct sockaddr **nam)
{

	D("");
	//TODO: Currently using rtsock
	return (raw_usrreqs.pru_peeraddr(so, nam));
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
	struct sockaddr_nl *snl;

	snl = malloc(sizeof *snl, M_SONAME, M_WAITOK | M_ZERO);
	D("socket %p", so);
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

	raw_usrreqs.pru_close(so);
}



/* Protosw*/
static int
nl_ctloutput(struct socket *so, struct sockopt *sopt) {
	D("");
	//TODO:
	return 0;
}

/**
 * off: offset for the start of next message
 */
static int 
retrieve_message_length(int offset, struct mbuf *m) {
	D("");
	int total_length = m_length(m, NULL), message_length;

	struct nlmsghdr hdr;
	struct nlmsghdr *h = &hdr;

	if (offset >= total_length || offset + NLMSG_HDRLEN > total_length) {
		D("exit 1; total_length: %d; offset: %d, hdrlen: %d", total_length, offset, NLMSG_HDRLEN);
		return 0;
	}

	// Copy data first 
	m_copydata(m, offset, sizeof(hdr), (caddr_t) h);

	message_length = h->nlmsg_len;

	//  Ensure that message is right sized
	if (message_length < NLMSG_HDRLEN || offset + message_length > total_length) {
		D("exit 2; total_length: %d; offset: %d; message_length: %d", total_length, offset, message_length);
		return 0;
	}
	return message_length;
}

static void
nl_ack(uint8_t proto, uint32_t portid, struct nlmsghdr * nlmsg, int err)
{
	D("");
	//struct mbuf *m;
	//struct nlmsghdr * repnlh;

	//struct nlmsgerr *errmsg;
	//int payloadsize = sizeof(*errmsg);

	//if (err)
	//	payloadsize += nlmsg->nlmsg_len;
	//
	////m = nlmsg_new(payloadsize, M_WAITOK); //TODO: Add
	//_M_NLPROTO(m) = proto;  //TODO: Check
	//repnlh = (struct nlmsghdr *)_M_CUR(m);
	//repnlh->nlmsg_type = NLMSG_ERROR;
	//repnlh->nlmsg_flags = 0;
	//repnlh->nlmsg_seq = nlmsg->nlmsg_seq;
	//repnlh->nlmsg_pid = portid;
	//m->m_pkthdr.len += NLMSG_HDRLEN;

	//errmsg = (struct nlmsgerr *)_M_CUR(m);
	//errmsg->error = err;
	//m->m_pkthdr.len +=
	//	NLMSG_ALIGN(err ?
	//	nlmsg->nlmsg_len + sizeof(*errmsg) - sizeof(*nlmsg):
	//	sizeof(*errmsg));
	/* In case of error copy the whole message */
	//memcpy(&errmsg->msg, nlmsg, err ? nlmsg->nlmsg_len : sizeof(*nlmsg));

	//nlmsg_end(m, repnlh);

	/* I should call unicast, but it's the same */
	//nlmsg_reply(m, NULL);
}

static int 
reallocate_memory(char** buffer, int length, int* buffer_length) {
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
	nl_handler handler = nl_handlers[proto];

	while ((message_length = retrieve_message_length(offset, m))) {
		if (buffer_length < message_length) {
			if ((error = reallocate_memory(&buffer, message_length, &buffer_length))) {
				return error;
			}
		}
		D("inside with meesage length(%d) and buffer length(%d)", message_length, buffer_length);
		m_copydata(m, offset, message_length, buffer);
		h = (struct nlmsghdr *)buffer;
		if (h->nlmsg_flags & NLM_F_REQUEST &&
				h->nlmsg_type >= NLMSG_MIN_TYPE) {
			D("inside with msg type: %d", h->nlmsg_type);
			error = handler((void *)h);
		}
		D("outside");

		if (error != EINTR && (h->nlmsg_flags & NLM_F_ACK || error != 0))
			nl_ack(proto, NETLINK_CB_PORT(m), h, error);

		offset += NLMSG_ALIGN(message_length);
	}
	return 0;
}


static int
nl_msg_to_netlink(struct mbuf *m, struct socket *so, ...) {
	D("");
	struct rawcb *rp;
	int proto;

	if (m == NULL || ((m->m_len < sizeof(long)) &&
				(m = m_pullup(m, sizeof(long))) == NULL))
		return (ENOBUFS);
	if ((m->m_flags & M_PKTHDR) == 0)
		panic("nl_msg_to_netlink");

	rp = sotorawcb(so);
	proto = rp->rcb_proto.sp_protocol;
	//TODO: Decide whether saving it in the mbuf header is the best 
	//TODO: Figure netlink_skb
	NETLINK_CB_PORT(m) = so->nl_src_portid;
	nl_receive_packet(m, so, proto);
	return 0;
}


	static int
nl_send(struct socket *so, int flags, struct mbuf *m, struct sockaddr *   nam,
		struct mbuf *control, struct thread *td)
{
	D("");
	return nl_msg_to_netlink(m, so);
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
	.pru_shutdown =     nl_shutdown,//TODO
	.pru_sockaddr =     nl_sockaddr,//TODO
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
