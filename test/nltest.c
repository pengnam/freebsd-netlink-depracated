#include <stdio.h>
#include <stdlib.h>
#include <strings.h>	/* bzero */
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>
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

static int
do_open(int proto)
{
	struct sockaddr_nl a = { AF_NETLINK, 0 };
	int s = socket(AF_NETLINK, SOCK_RAW, proto);
	if (s < 0) {
		D("open %d fails with error %d", proto, errno);
		return s;
	}
	int i = connect(s, (struct sockaddr *)&a, sizeof(a));
	if (i < 0) {
		D("connect errno returns %d", errno);
	}
	D("connect returns %d pid %d", i, a.nl_pid);
	return s;
}

int
main(int argc, char *argv[])
{
	int s;
	int x = NETLINK_GENERIC;
	int i = 1; /* argument pointer */

	if (0 && argc > 1) {
		x = atoi(argv[1]);
		i++;
	}
	s = do_open(x);
	D("socket returns %d", s);

	return 0;
}
