#define _GNU_SOURCE
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#if __APPLE__

int custom_connect(int sock, const struct sockaddr *addr, socklen_t addrlen);

typedef struct interpose_s {
	void *new_func;
	void *orig_func;
} interpose_t;

static const interpose_t interposers[] \
	__attribute__ ((section("__DATA, __interpose"))) = {
	{ (void *)custom_connect,  (void *)connect  },
};

int custom_connect(int sock, const struct sockaddr *addr, socklen_t addrlen)
{
	int res = connect(sock, addr, addrlen);
	if (!res && addr->sa_family == AF_INET) {
		int opt = 1;
		setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
	}
	return res;
}

#else /* !__APPLE__ */

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

#endif /* !__APPLE__ */
