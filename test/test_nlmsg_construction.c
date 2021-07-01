#include <stdio.h>
#include <stdlib.h>
#include <strings.h>	/* bzero */
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/mbuf.h>
#include <netlink2/linux/netlink.h>



/*---- start debugging macros --- luigi */
#define ND(format, ...)
#define D(format, ...)                                          \
        do {                                                    \
                struct timeval __xxts;                          \
                gettimeofday(&__xxts, NULL);                    \
                printf("%03d.%06d [%4d] %-25s " format "\n",    \
                (int)__xxts.tv_sec % 1000, (int)__xxts.tv_usec, \
                __LINE__, __FUNCTION__, ##__VA_ARGS__);         \
        } while (0)

int
main(int argc, char *argv[])
{
	int payload = 16;
	int portid = 20;
	int seq = 15;
	int type = 10;
	int flags = 4;
	struct mbuf *m = nlmsg_new(payload, 0);
	struct nlmsghdr* n = nlmsg_put(m, portid, seq, type, payload, flags);
	if (n == NULL){
		D("nlmsg_put returned NULL");
		return 1;
	}
	nlmsg_end(m, n);
	//Retrieving it again just to be sure
	struct nlmsghdr *nlh = nl_data_from_m(m);
	if (nlh->nlmsg_len != sizeof (struct nlmsghdr)) {
		D("nlmsg len wrong");
		return 1;
	}
	if (nlh->nlmsg_type!= type) {
		D("nlmsg type wrong");
		return 1;
	}
	if (nlh->nlmsg_flags!= flags) {
		D("nlmsg flags wrong");
		return 1;
	}
	if (nlh->nlmsg_flags!= flags) {
		D("nlmsg flags wrong");
		return 1;
	}
	if (nlh->nlmsg_seq!= seq) {
		D("nlmsg seq wrong");
		return 1;
	}
	if (nlh->nlmsg_pid!= portid) {
		D("nlmsg pid wrong");
		return 1;
	}



	return 0;
}
