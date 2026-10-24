/*
 * DYLD_INSERT_LIBRARIES shim for test_macos_daemonize.py.
 *
 * macFUSE 5.3.3+ delays the real mount until the session is first used and
 * remembers that in a process-wide flag. Once it is set, fuse_daemonize()
 * refuses to fork. Replace fuse_daemonize() with a check of that flag, so a
 * test can run sshfs without -f and see whether anything started the mount
 * too early. No working mount is needed: a hosted runner can't finish one,
 * and the shim exits before the real fuse_daemonize() would fork. It also
 * stops fuse_session_fd(), the call that used to start the mount too early,
 * before it can try a real mount.
 *
 * Exit codes: 0 ok, 86 mount started before fuse_daemonize(), 87 fuse_daemonize()
 * called with foreground set, 88 fuse_daemonize() never reached, 89 watchdog
 * not installed.
 */

#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* not public API: the test fails to build the shim if libfuse3 lacks it */
extern bool fuse_darwin_mount_started(void);
extern int fuse_daemonize(int foreground);
struct fuse_session;
extern int fuse_session_fd(struct fuse_session *se);

#define WATCHDOG_SECS 25

/* dyld-interposing.h is not in the public SDK */
#define DYLD_INTERPOSE(replacement, replacee) \
	__attribute__((used)) static struct { const void *new; const void *old; } \
	interpose_##replacee __attribute__((section("__DATA,__interpose"))) = \
	{ (const void *) &replacement, (const void *) &replacee };

static void say(const char *msg)
{
	(void) write(2, msg, strlen(msg));
}

/*
 * If something starts the mount before fuse_daemonize() the call blocks,
 * since the runner can't finish a mount. Look at the same flag from a timer
 * so that still ends as a clear failure and not as a hang. A timer and not a
 * thread: macFUSE warns when a threaded process forks, and sshfs forks ssh.
 */
static void watchdog(int sig)
{
	(void) sig;
	if (fuse_darwin_mount_started()) {
		say("daemonize-shim: VIOLATION: mount started before fuse_daemonize (blocked)\n");
		_exit(86);
	}
	say("daemonize-shim: TIMEOUT: fuse_daemonize not reached, mount not started\n");
	_exit(88);
}

static int shim_daemonize(int foreground)
{
	if (fuse_darwin_mount_started()) {
		say("daemonize-shim: VIOLATION: mount started before fuse_daemonize\n");
		_exit(86);
	}
	if (foreground) {
		say("daemonize-shim: fuse_daemonize(foreground=1), fork path not exercised\n");
		_exit(87);
	}
	say("daemonize-shim: ok: fuse_daemonize(foreground=0) before mount start\n");
	_exit(0);
}

DYLD_INTERPOSE(shim_daemonize, fuse_daemonize)

/* shim_daemonize() never returns, so any call here is too early */
static int shim_session_fd(struct fuse_session *se)
{
	(void) se;
	say("daemonize-shim: VIOLATION: fuse_session_fd called before fuse_daemonize\n");
	_exit(86);
}

DYLD_INTERPOSE(shim_session_fd, fuse_session_fd)

__attribute__((constructor))
static void shim_init(void)
{
	struct sigaction sa;

	/* don't hand the shim on to ssh or the fake server */
	unsetenv("DYLD_INSERT_LIBRARIES");
	say("daemonize-shim: loaded\n");

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = watchdog;
	if (sigaction(SIGALRM, &sa, NULL) != 0) {
		say("daemonize-shim: cannot install the watchdog\n");
		_exit(89);
	}
	alarm(WATCHDOG_SECS);
}
