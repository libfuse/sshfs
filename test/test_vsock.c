/* Exercise the real connection helper without a VSOCK device or FUSE mount. */
#define _GNU_SOURCE
#include <sys/socket.h>
#include <unistd.h>

static int test_socket(int domain, int type, int protocol);
static int test_connect(int fd, const struct sockaddr *addr, socklen_t len);
static int test_close(int fd);
int sshfs_main(int argc, char *argv[]);

#define socket test_socket
#define connect test_connect
#define close test_close
#define main sshfs_main
#include "../sshfs.c"
#undef main
#undef close
#undef connect
#undef socket

#define TEST_FD 42

enum failure {
	NO_FAILURE,
	SOCKET_FAILURE,
	CONNECT_FAILURE,
};

static enum failure failure;
static int socket_calls;
static int connect_calls;
static int close_calls;

static int test_socket(int domain, int type, int protocol)
{
	g_assert_cmpint(domain, ==, AF_VSOCK);
	g_assert_cmpint(type, ==, SOCK_STREAM);
	g_assert_cmpint(protocol, ==, 0);
	socket_calls++;
	if (failure == SOCKET_FAILURE && socket_calls == 1) {
		errno = EAFNOSUPPORT;
		return -1;
	}
	return TEST_FD;
}

static int test_connect(int fd, const struct sockaddr *addr, socklen_t len)
{
	const struct sockaddr_vm *vm = (const struct sockaddr_vm *) addr;

	g_assert_cmpint(fd, ==, TEST_FD);
	g_assert_cmpuint(len, ==, sizeof(*vm));
	g_assert_cmpint(vm->svm_family, ==, AF_VSOCK);
	g_assert_cmpuint(vm->svm_cid, ==, 3);
	g_assert_cmpuint(vm->svm_port, ==, 12345);
	connect_calls++;
	if (failure == CONNECT_FAILURE && connect_calls == 1) {
		errno = ECONNREFUSED;
		return -1;
	}
	return 0;
}

static int test_close(int fd)
{
	g_assert_cmpint(fd, ==, TEST_FD);
	close_calls++;
	return 0;
}

static void test_reuse_address(gconstpointer data)
{
	char address[] = "3:12345";
	struct conn first = { .rfd = -1, .wfd = -1 };
	struct conn second = { .rfd = -1, .wfd = -1 };
	int first_result;
	int second_result;

	failure = GPOINTER_TO_INT(data);
	socket_calls = connect_calls = close_calls = 0;
	first_result = connect_vsock(&first, address);
	second_result = connect_vsock(&second, address);

	g_assert_cmpint(first_result, ==, failure == NO_FAILURE ? 0 : -1);
	g_assert_cmpint(second_result, ==, 0);
	g_assert_cmpstr(address, ==, "3:12345");
	g_assert_cmpint(first.rfd, ==, failure == NO_FAILURE ? TEST_FD : -1);
	g_assert_cmpint(first.wfd, ==, first.rfd);
	g_assert_cmpint(second.rfd, ==, TEST_FD);
	g_assert_cmpint(second.wfd, ==, TEST_FD);
	g_assert_cmpint(socket_calls, ==, 2);
	g_assert_cmpint(connect_calls, ==, failure == SOCKET_FAILURE ? 1 : 2);
	g_assert_cmpint(close_calls, ==, failure == CONNECT_FAILURE ? 1 : 0);
}

int main(int argc, char *argv[])
{
	g_test_init(&argc, &argv, NULL);
	g_test_add_data_func("/vsock/reuse-after-success",
			     GINT_TO_POINTER(NO_FAILURE), test_reuse_address);
	g_test_add_data_func("/vsock/retry-after-socket-failure",
			     GINT_TO_POINTER(SOCKET_FAILURE), test_reuse_address);
	g_test_add_data_func("/vsock/retry-after-connect-failure",
			     GINT_TO_POINTER(CONNECT_FAILURE), test_reuse_address);
	return g_test_run();
}
