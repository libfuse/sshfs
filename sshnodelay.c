#define _GNU_SOURCE
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

int connect(int sock, const struct sockaddr *addr, socklen_t addrlen)
{
	int (*next_connect)(int, const struct sockaddr *, socklen_t) =
		dlsym(RTLD_NEXT, "connect");
	int res = next_connect(sock, addr, addrlen);
	if (!res && addr->sa_family == AF_INET) {
		int opt = 1;
		setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
	}
	return res;
}
