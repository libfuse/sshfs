#define _GNU_SOURCE
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

/* Wrapper around connect(2) to explicitly set TCP_NODELAY. */
static int nodelay_connect(
    int (*real_connect)(int, const struct sockaddr *, socklen_t),
    int sock, const struct sockaddr *addr, socklen_t addrlen)
{
	int res = real_connect(sock, addr, addrlen);
	if (!res && addr->sa_family == AF_INET) {
		int opt = 1;
		setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
	}
	return res;
}

#if __APPLE__

/* OS X does not have LD_PRELOAD but has DYLD_INSERT_LIBRARIES.  The right
 * environment variable is set by sshfs.c when attempting to load the
 * sshnodelay workaround.
 *
 * However, things are not that simple: DYLD_INSERT_LIBRARIES does not
 * behave exactly like LD_PRELOAD.  Instead, the dyld dynamic linker will
 * look for __DATA __interpose sections on the libraries given via the
 * DYLD_INSERT_LIBRARIES variable.  The contents of this section are pairs
 * of replacement functions and functions to be replaced, respectively.
 * Prepare such section here. */

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
	return nodelay_connect(connect, sock, addr, addrlen);
}

#else /* !__APPLE__ */

int connect(int sock, const struct sockaddr *addr, socklen_t addrlen)
{
	return nodelay_connect(dlsym(RTLD_NEXT, "connect"),
	                       sock, addr, addrlen);
}

#endif /* !__APPLE__ */
