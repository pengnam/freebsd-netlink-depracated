#include <sys/param.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/priv.h>
#include <sys/mbuf.h>
#include <sys/queue.h>
#include <net/genetlink.h> 
static int
genetlink_receive_message(char *data)
{
	return EOPNOTSUPP;
}


static void
genetlinkload(void *u __unused)
{
	//TODO: initialize
	register_or_replace_handler(NETLINK_GENERIC, genetlink_receive_message);
	//TODO: initialize bsd nl
}

static void
genetlinkunload(void *u __unused)
{
}

SYSINIT(genetlinkload, SI_SUB_PROTO_DOMAIN, SI_ORDER_THIRD, genetlinkload, NULL);
SYSINIT(genetlinkunload, SI_SUB_PROTO_DOMAIN, SI_ORDER_THIRD, genetlinkunload, NULL);
