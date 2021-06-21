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
gnl__receive_message(char *data)
{
	return EOPNOTSUPP;
}


static void
gnl_load(void *u __unused)
{
	//TODO: initialize
	nl_register_or_replace_handler(NETLINK_GENERIC, gnl__receive_message);
	//TODO: initialize bsd nl
}

static void
gnl_unload(void *u __unused)
{
}

SYSINIT(gnl_load, SI_SUB_PROTO_DOMAIN, SI_ORDER_THIRD, gnl_load, NULL);
SYSINIT(gnl_unload, SI_SUB_PROTO_DOMAIN, SI_ORDER_THIRD, gnl_unload, NULL);
