/*
  Unit tests for cache.c

  cache.c is #included so that its static helpers and the global cache state
  are reachable.  The backend is a small in-memory filesystem that counts the
  getattr, readlink and directory calls it gets, and time() is replaced by a
  clock the tests advance by hand,
  so nothing sleeps and nothing depends on thread timing.  A call that is in
  flight while something else happens is simulated by a hook that the fake
  backend runs after it has computed its reply and before it returns it.

  Output is one TAP-style line per case.  A case listed with an xfail reason
  documents a known gap in the cache: it passes the run while the gap is there
  and fails the run (XPASS) once it is closed.  Only the assertions written
  with XCHECK can be expected to fail; any other failed check is a plain
  failure.
*/

#include <errno.h>
#include <glib.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#include <fuse.h>
#include <fuse_opt.h>
#include "../cache.h"

#define T0 1000000

static time_t test_now = T0;

static time_t test_time(time_t *tp)
{
	if (tp)
		*tp = test_now;
	return test_now;
}

/*
 * Count the strings cache.c gets from g_strndup() that are still allocated,
 * so a missing g_free() shows up in every build and not only under LSan.  The
 * addresses are stored complemented so that LSan does not treat this table as
 * a reference to them.
 */
#define MAX_TRACKED 256
static uintptr_t tracked[MAX_TRACKED];
static int ntracked;

static char *test_strndup(const char *s, gsize n)
{
	char *p = g_strndup(s, n);

	if (ntracked == MAX_TRACKED)
		abort();
	tracked[ntracked++] = ~(uintptr_t) p;
	return p;
}

static void test_free(gpointer p)
{
	int i;

	for (i = 0; i < ntracked; i++) {
		if (tracked[i] == ~(uintptr_t) p) {
			tracked[i] = tracked[--ntracked];
			break;
		}
	}
	g_free(p);
}

#undef g_strndup
#undef g_free
#define g_strndup(s, n) test_strndup(s, n)
#define g_free(p) test_free(p)
#define time(tp) test_time(tp)
#include "../cache.c"
#undef time
#undef g_free
#undef g_strndup

/* ---- harness ---- */

static int cur_fails;		/* failed CHECKs in the running case */
static int cur_xfails;		/* failed XCHECKs in the running case */
static const char *cur_sub;	/* sub-case name, for loops over a table */

static void check_failed(int line, const char *expr, int known)
{
	if (cur_sub)
		printf("#   %s: line %d: %s\n", cur_sub, line, expr);
	else
		printf("#   line %d: %s\n", line, expr);
	if (known)
		cur_xfails++;
	else
		cur_fails++;
}

#define CHECK(cond) \
	do { if (!(cond)) check_failed(__LINE__, #cond, 0); } while (0)
/* the assertion that a known bug makes fail */
#define XCHECK(cond) \
	do { if (!(cond)) check_failed(__LINE__, #cond, 1); } while (0)
/* abandon the case if the setup did not work */
#define REQUIRE(cond) \
	do { if (!(cond)) { check_failed(__LINE__, #cond, 0); return; } } while (0)

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

/* ---- fake backend: a tiny in-memory filesystem that counts calls ---- */

#define MAX_ENT 32
#define PATH_LEN 64

struct fent {
	int used;
	char path[PATH_LEN];
	ino_t ino;		/* names with the same ino are hard links */
	mode_t mode;
	off_t size;
	uid_t uid;
	gid_t gid;
	time_t atime;
	time_t mtime;
	char link[PATH_LEN];
};

static struct fent ents[MAX_ENT];
static ino_t next_ino;

static struct {
	int init, getattr, readlink, opendir, readdir, releasedir;
} calls;

static void (*hook_getattr)(void);	/* runs once, inside the next getattr */
static void (*hook_readdir)(void);	/* runs once, inside the next readdir */
static void (*hook_readlink)(void);	/* runs once, inside the next readlink */
static int readdir_fail_at;		/* fail with EIO before this entry */
static int readdir_no_attrs;
static off_t last_readdir_offset;
static uint64_t last_readdir_fh;
static uint64_t last_releasedir_fh;
static int init_token;

static struct fuse_operations *ops;	/* what cache_wrap() returned */

static struct fent *ent_find(const char *path)
{
	int i;

	for (i = 0; i < MAX_ENT; i++)
		if (ents[i].used && strcmp(ents[i].path, path) == 0)
			return &ents[i];
	return NULL;
}

static struct fent *ent_get(const char *path)
{
	struct fent *e = ent_find(path);

	if (!e) {
		fprintf(stderr, "test bug: no entry %s\n", path);
		abort();
	}
	return e;
}

static struct fent *ent_add(const char *path, mode_t mode, off_t size)
{
	struct fent *e = ent_find(path);
	int i;

	if (!e) {
		for (i = 0; i < MAX_ENT && ents[i].used; i++)
			;
		if (i == MAX_ENT)
			abort();
		e = &ents[i];
	}
	memset(e, 0, sizeof(*e));
	e->used = 1;
	g_strlcpy(e->path, path, sizeof(e->path));
	e->ino = ++next_ino;
	e->mode = mode;
	e->size = size;
	return e;
}

static void mk_dir(const char *path)
{
	ent_add(path, S_IFDIR | 0755, 0);
}

static void mk_file(const char *path, off_t size)
{
	ent_add(path, S_IFREG | 0644, size);
}

static void mk_link(const char *path, const char *target)
{
	struct fent *e = ent_add(path, S_IFLNK | 0777, 0);

	g_strlcpy(e->link, target, sizeof(e->link));
}

static int ent_create(const char *path, mode_t mode)
{
	if (ent_find(path))
		return -EEXIST;
	ent_add(path, mode, 0);
	return 0;
}

static int ent_remove(const char *path)
{
	struct fent *e = ent_find(path);

	if (!e)
		return -ENOENT;
	e->used = 0;
	return 0;
}

static const char *base_name(const char *path)
{
	const char *s = strrchr(path, '/');

	return s ? s + 1 : path;
}

/* is path a direct child of the directory dir? */
static int is_child(const char *dir, const char *path)
{
	size_t n = strlen(dir);
	const char *rest;

	if (n == 1) {
		rest = path + 1;
		return path[0] == '/' && *rest && !strchr(rest, '/');
	}
	if (strncmp(path, dir, n) != 0 || path[n] != '/')
		return 0;
	rest = path + n + 1;
	return *rest && !strchr(rest, '/');
}

static nlink_t count_names(ino_t ino)
{
	nlink_t n = 0;
	int i;

	for (i = 0; i < MAX_ENT; i++)
		if (ents[i].used && ents[i].ino == ino)
			n++;
	return n;
}

/* a change made through one name of a file shows through its other names */
static void sync_inode(const struct fent *src)
{
	int i;

	for (i = 0; i < MAX_ENT; i++) {
		struct fent *o = &ents[i];

		if (!o->used || o == src || o->ino != src->ino)
			continue;
		o->mode = src->mode;
		o->size = src->size;
		o->uid = src->uid;
		o->gid = src->gid;
		o->atime = src->atime;
		o->mtime = src->mtime;
	}
}

static void fill_stat(struct stat *st, const struct fent *e)
{
	memset(st, 0, sizeof(*st));
	st->st_ino = e->ino;
	st->st_mode = e->mode;
	st->st_size = e->size;
	st->st_uid = e->uid;
	st->st_gid = e->gid;
	st->st_atime = e->atime;
	st->st_mtime = e->mtime;
	st->st_nlink = count_names(e->ino);
}

static void run_hook(void (**hook)(void))
{
	void (*h)(void) = *hook;

	*hook = NULL;
	if (h)
		h();
}

static void *fake_init(struct fuse_conn_info *conn, struct fuse_config *cfg)
{
	(void) conn;
	calls.init++;
	cfg->nullpath_ok = 1;
	return &init_token;
}

static int fake_getattr(const char *path, struct stat *st,
			struct fuse_file_info *fi)
{
	const struct fent *e;

	(void) fi;
	calls.getattr++;
	e = ent_find(path);
	if (!e)
		return -ENOENT;
	fill_stat(st, e);
	/* the reply is computed; anything that happens now comes too late */
	run_hook(&hook_getattr);
	return 0;
}

static int fake_readlink(const char *path, char *buf, size_t size)
{
	const struct fent *e;
	size_t n;

	calls.readlink++;
	e = ent_find(path);
	if (!e || !S_ISLNK(e->mode))
		return -EINVAL;
	n = strlen(e->link);
	if (n > size - 1)
		n = size - 1;
	memcpy(buf, e->link, n);
	buf[n] = '\0';
	/* the reply is computed; anything that happens now comes too late */
	run_hook(&hook_readlink);
	return 0;
}

static int fake_opendir(const char *path, struct fuse_file_info *fi)
{
	(void) path;
	calls.opendir++;
	fi->fh = 42;
	return 0;
}

static int fake_releasedir(const char *path, struct fuse_file_info *fi)
{
	(void) path;
	calls.releasedir++;
	last_releasedir_fh = fi->fh;
	return 0;
}

static int fake_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
			off_t offset, struct fuse_file_info *fi,
			enum fuse_readdir_flags flags)
{
	struct fent snap[MAX_ENT];
	int i, n = 0;

	(void) flags;
	calls.readdir++;
	last_readdir_offset = offset;
	last_readdir_fh = fi->fh;
	if (!ent_find(path))
		return -ENOENT;
	for (i = 0; i < MAX_ENT; i++)
		if (ents[i].used && is_child(path, ents[i].path))
			snap[n++] = ents[i];
	/* the listing is taken; changes from here on are not in it */
	run_hook(&hook_readdir);
	for (i = 0; i < n; i++) {
		struct stat st;

		if (i == readdir_fail_at)
			return -EIO;
		memset(&st, 0, sizeof(st));
		if (!readdir_no_attrs)
			fill_stat(&st, &snap[i]);
		if (filler(buf, base_name(snap[i].path), &st, 0, 0))
			break;
	}
	return 0;
}

static int fake_mknod(const char *path, mode_t mode, dev_t rdev)
{
	(void) rdev;
	return ent_create(path, mode);
}

static int fake_mkdir(const char *path, mode_t mode)
{
	return ent_create(path, S_IFDIR | mode);
}

static int fake_unlink(const char *path)
{
	return ent_remove(path);
}

static int fake_rmdir(const char *path)
{
	return ent_remove(path);
}

static int fake_symlink(const char *from, const char *to)
{
	if (ent_find(to))
		return -EEXIST;
	mk_link(to, from);
	return 0;
}

static int fake_rename(const char *from, const char *to, unsigned int flags)
{
	struct fent *src, *old;
	size_t n = strlen(from);
	int i;

	(void) flags;
	src = ent_find(from);
	if (!src)
		return -ENOENT;
	old = ent_find(to);
	if (old && old->ino == src->ino)	/* the same file: nothing to do */
		return 0;
	if (old)
		old->used = 0;
	for (i = 0; i < MAX_ENT; i++) {
		struct fent *e = &ents[i];
		char *np;

		if (!e->used || strncmp(e->path, from, n) != 0 ||
		    (e->path[n] != '\0' && e->path[n] != '/'))
			continue;
		np = g_strdup_printf("%s%s", to, e->path + n);
		g_strlcpy(e->path, np, sizeof(e->path));
		g_free(np);
	}
	return 0;
}

static int fake_link(const char *from, const char *to)
{
	const struct fent *e;
	struct fent *l;

	e = ent_find(from);
	if (!e)
		return -ENOENT;
	if (ent_find(to))
		return -EEXIST;
	l = ent_add(to, e->mode, e->size);
	l->ino = e->ino;
	g_strlcpy(l->link, e->link, sizeof(l->link));
	sync_inode(e);
	return 0;
}

static int fake_chmod(const char *path, mode_t mode, struct fuse_file_info *fi)
{
	struct fent *e;

	(void) fi;
	e = ent_find(path);
	if (!e)
		return -ENOENT;
	e->mode = (e->mode & S_IFMT) | (mode & 07777);
	sync_inode(e);
	return 0;
}

static int fake_chown(const char *path, uid_t uid, gid_t gid,
		      struct fuse_file_info *fi)
{
	struct fent *e;

	(void) fi;
	e = ent_find(path);
	if (!e)
		return -ENOENT;
	if (uid != (uid_t) -1)
		e->uid = uid;
	if (gid != (gid_t) -1)
		e->gid = gid;
	sync_inode(e);
	return 0;
}

static int fake_utimens(const char *path, const struct timespec tv[2],
			struct fuse_file_info *fi)
{
	struct fent *e;

	(void) fi;
	e = ent_find(path);
	if (!e)
		return -ENOENT;
	e->atime = tv[0].tv_sec;
	e->mtime = tv[1].tv_sec;
	sync_inode(e);
	return 0;
}

static int fake_truncate(const char *path, off_t size,
			 struct fuse_file_info *fi)
{
	struct fent *e;

	(void) fi;
	e = ent_find(path);
	if (!e)
		return -ENOENT;
	e->size = size;
	sync_inode(e);
	return 0;
}

static int fake_write(const char *path, const char *buf, size_t size,
		      off_t offset, struct fuse_file_info *fi)
{
	struct fent *e;

	(void) buf;
	(void) fi;
	e = ent_find(path);
	if (!e)
		return -ENOENT;
	if (offset + (off_t) size > e->size)
		e->size = offset + (off_t) size;
	sync_inode(e);
	return (int) size;
}

static int fake_create(const char *path, mode_t mode,
		       struct fuse_file_info *fi)
{
	(void) fi;
	return ent_create(path, S_IFREG | mode);
}

static int fake_access(const char *path, int mask)
{
	(void) path;
	(void) mask;
	return 0;
}

static struct fuse_operations fake_ops = {
	.init = fake_init,
	.getattr = fake_getattr,
	.readlink = fake_readlink,
	.opendir = fake_opendir,
	.releasedir = fake_releasedir,
	.readdir = fake_readdir,
	.mknod = fake_mknod,
	.mkdir = fake_mkdir,
	.unlink = fake_unlink,
	.rmdir = fake_rmdir,
	.symlink = fake_symlink,
	.rename = fake_rename,
	.link = fake_link,
	.chmod = fake_chmod,
	.chown = fake_chown,
	.utimens = fake_utimens,
	.truncate = fake_truncate,
	.write = fake_write,
	.create = fake_create,
	.access = fake_access,
};

/* ---- helpers for the tests ---- */

static void advance(time_t secs)
{
	test_now += secs;
}

static void reset_state(void)
{
	g_hash_table_remove_all(cache.table);
	memset(ents, 0, sizeof(ents));
	memset(&calls, 0, sizeof(calls));
	hook_getattr = NULL;
	hook_readdir = NULL;
	hook_readlink = NULL;
	readdir_fail_at = -1;
	readdir_no_attrs = 0;
	next_ino = 100;
	last_readdir_offset = -1;
	last_readdir_fh = 0;
	last_releasedir_fh = 0;
	test_now = T0;
	cache.stat_timeout_secs = 20;
	cache.dir_timeout_secs = 20;
	cache.link_timeout_secs = 20;
	cache.max_size = 10000;
	cache.clean_interval_secs = 60;
	cache.min_clean_interval_secs = 5;
	cache.last_cleaned = T0;
	cache.write_ctr = 0;
	mk_dir("/");
}

struct listing {
	int n;
	char name[MAX_ENT][32];
	mode_t mode[MAX_ENT];
	off_t size[MAX_ENT];
	ino_t ino[MAX_ENT];
	off_t max_off;
};

static int collect(void *buf, const char *name, const struct stat *st,
		   off_t off, enum fuse_fill_dir_flags flags)
{
	struct listing *l = buf;

	(void) flags;
	if (l->n < MAX_ENT) {
		g_strlcpy(l->name[l->n], name, sizeof(l->name[0]));
		l->mode[l->n] = st->st_mode;
		l->size[l->n] = st->st_size;
		l->ino[l->n] = st->st_ino;
	}
	l->n++;
	if (off > l->max_off)
		l->max_off = off;
	return 0;
}

static int listing_index(const struct listing *l, const char *name)
{
	int i;

	for (i = 0; i < l->n && i < MAX_ENT; i++)
		if (strcmp(l->name[i], name) == 0)
			return i;
	return -1;
}

static int listing_has(const struct listing *l, const char *name)
{
	return listing_index(l, name) >= 0;
}

/* list a directory the way the kernel does: open, read, release */
static int do_readdir(const char *path, off_t offset, struct listing *l)
{
	struct fuse_file_info fi;
	uint64_t dh;
	int err, rel;

	memset(l, 0, sizeof(*l));
	memset(&fi, 0, sizeof(fi));
	err = ops->opendir(path, &fi);
	if (err)
		return err;
	dh = fi.fh;
	err = ops->readdir(path, l, collect, offset, &fi, 0);
	fi.fh = dh;
	rel = ops->releasedir(path, &fi);
	return err ? err : rel;
}

static int do_getattr(const char *path, struct stat *st)
{
	memset(st, 0, sizeof(*st));
	return ops->getattr(path, st, NULL);
}

/* did looking up path go to the backend? */
static int probe(const char *path)
{
	struct stat st;
	int before = calls.getattr;

	(void) do_getattr(path, &st);
	return calls.getattr != before;
}

/* did listing path go to the backend? */
static int probe_dir(const char *path)
{
	struct listing l;
	int before = calls.readdir;

	(void) do_readdir(path, 0, &l);
	return calls.readdir != before;
}

/* did reading the link path go to the backend? */
static int probe_link(const char *path)
{
	char buf[64];
	int before = calls.readlink;

	(void) ops->readlink(path, buf, sizeof(buf));
	return calls.readlink != before;
}

/* look path up, then again: the second answer, left in st, must be cached */
static int get_cached(const char *path, struct stat *st)
{
	int before;

	if (do_getattr(path, st))
		return -1;
	before = calls.getattr;
	return (do_getattr(path, st) || calls.getattr != before) ? -1 : 0;
}

/* size or permission bits of path as cached, or -1 on error */
static off_t size_of(const char *path)
{
	struct stat st;

	return get_cached(path, &st) ? -1 : st.st_size;
}

static int perm_of(const char *path)
{
	struct stat st;

	return get_cached(path, &st) ? -1 : (int) (st.st_mode & 07777);
}

/* for each letter x, create the file /x (mk_files) or look it up (get_files) */
static void mk_files(const char *letters)
{
	char path[3] = { '/', 0, 0 };

	for (; *letters; letters++) {
		path[1] = *letters;
		mk_file(path, 1);
	}
}

static void get_files(const char *letters)
{
	char path[3] = { '/', 0, 0 };

	for (; *letters; letters++) {
		path[1] = *letters;
		(void) probe(path);
	}
}

/* ---- getattr ---- */

static void test_getattr_timeout(void)
{
	cache.stat_timeout_secs = 10;
	mk_file("/f", 100);

	CHECK(size_of("/f") == 100);
	ent_get("/f")->size = 200;	/* behind the cache's back */
	CHECK(size_of("/f") == 100);
	advance(10);			/* still valid in the last second */
	CHECK(size_of("/f") == 100);
	CHECK(calls.getattr == 1);

	advance(1);
	CHECK(size_of("/f") == 200);
	CHECK(size_of("/f") == 200);	/* and cached again */
	CHECK(calls.getattr == 2);
}

static void test_getattr_errors(void)
{
	struct stat st;

	CHECK(do_getattr("/missing", &st) == -ENOENT);
	CHECK(do_getattr("/missing", &st) == -ENOENT);
	CHECK(calls.getattr == 2);
	mk_file("/missing", 3);		/* seen at once when it appears */
	CHECK(size_of("/missing") == 3);
}

static void test_timeouts_per_kind(void)
{
	cache.stat_timeout_secs = 5;
	cache.dir_timeout_secs = 30;
	cache.link_timeout_secs = 15;
	mk_dir("/d");
	mk_file("/d/a", 1);
	mk_link("/d/l", "target");
	(void) probe_dir("/d");
	(void) probe_link("/d/l");

	advance(10);			/* only the attributes expired */
	CHECK(probe("/d/a"));
	CHECK(!probe_link("/d/l"));
	CHECK(!probe_dir("/d"));
	advance(10);			/* the link too */
	CHECK(probe_link("/d/l"));
	CHECK(!probe_dir("/d"));
	advance(11);			/* and then the listing */
	CHECK(probe_dir("/d"));
}

/* ---- invalidation by modifying operations ---- */

enum {
	OP_MKNOD, OP_MKDIR, OP_CREATE, OP_SYMLINK, OP_LINK, OP_UNLINK,
	OP_RMDIR, OP_RENAME, OP_CHMOD, OP_CHOWN, OP_UTIMENS, OP_TRUNCATE,
	OP_WRITE
};

static int run_op(int op)
{
	struct fuse_file_info fi;
	struct timespec tv[2];

	memset(&fi, 0, sizeof(fi));
	memset(tv, 0, sizeof(tv));
	switch (op) {
	case OP_MKNOD:    return ops->mknod("/d/new", S_IFREG | 0644, 0);
	case OP_MKDIR:    return ops->mkdir("/d/new", 0755);
	case OP_CREATE:   return ops->create("/d/new", 0644, &fi);
	case OP_SYMLINK:  return ops->symlink("target", "/d/new");
	case OP_LINK:     return ops->link("/d/f", "/d/new");
	case OP_UNLINK:   return ops->unlink("/d/f");
	case OP_RMDIR:    return ops->rmdir("/d/sub");
	case OP_RENAME:   return ops->rename("/d/f", "/d/h", 0);
	case OP_CHMOD:    return ops->chmod("/d/f", 0600, NULL);
	case OP_CHOWN:    return ops->chown("/d/f", 1000, 1000, NULL);
	case OP_UTIMENS:  return ops->utimens("/d/f", tv, NULL);
	case OP_TRUNCATE: return ops->truncate("/d/f", 0, NULL);
	case OP_WRITE:    return ops->write("/d/f", "x", 1, 0, NULL) == 1 ? 0 : -1;
	}
	abort();
}

static const struct inval_case {
	const char *name;
	int op;
	const char *target;	/* cached path that must be refetched, if any */
	int purges_parent;	/* the listing of /d must be refetched */
} inval_cases[] = {
	{ "mknod",    OP_MKNOD,    NULL,     1 },
	{ "mkdir",    OP_MKDIR,    NULL,     1 },
	{ "create",   OP_CREATE,   NULL,     1 },
	{ "symlink",  OP_SYMLINK,  NULL,     1 },
	{ "link",     OP_LINK,     "/d/f",   1 },
	{ "unlink",   OP_UNLINK,   "/d/f",   1 },
	{ "rmdir",    OP_RMDIR,    "/d/sub", 1 },
	{ "rename",   OP_RENAME,   "/d/f",   1 },
	{ "chmod",    OP_CHMOD,    "/d/f",   0 },
	{ "chown",    OP_CHOWN,    "/d/f",   0 },
	{ "utimens",  OP_UTIMENS,  "/d/f",   0 },
	{ "truncate", OP_TRUNCATE, "/d/f",   0 },
	{ "write",    OP_WRITE,    "/d/f",   0 },
};

static void test_invalidation(void)
{
	struct listing l;
	size_t i;

	for (i = 0; i < ARRAY_SIZE(inval_cases); i++) {
		const struct inval_case *c = &inval_cases[i];

		cur_sub = c->name;
		reset_state();
		mk_dir("/d");
		mk_file("/d/f", 1);
		mk_file("/d/g", 2);
		mk_dir("/d/sub");
		mk_file("/other", 3);

		/* the listing of /d also caches the attributes of its entries */
		REQUIRE(do_readdir("/d", 0, &l) == 0);
		(void) probe("/other");
		REQUIRE(!probe("/d/g"));
		REQUIRE(!probe_dir("/d"));
		if (c->target)
			REQUIRE(!probe(c->target));

		CHECK(run_op(c->op) == 0);

		if (c->target)
			CHECK(probe(c->target));
		if (c->purges_parent)
			CHECK(probe_dir("/d"));
		/* other entries are left alone */
		CHECK(!probe("/d/g"));
		CHECK(!probe("/other"));
	}
	cur_sub = NULL;
}

static void test_new_values_after_ops(void)
{
	struct stat st;
	struct timespec tv[2];

	mk_file("/f", 100);
	CHECK(size_of("/f") == 100);

	/* each modification shows in the next lookup, and in the cached copy */
	CHECK(ops->chmod("/f", 0600, NULL) == 0);
	CHECK(perm_of("/f") == 0600);
	CHECK(ops->truncate("/f", 7, NULL) == 0);
	CHECK(size_of("/f") == 7);
	CHECK(ops->write("/f", "abc", 3, 50, NULL) == 3);
	CHECK(size_of("/f") == 53);

	CHECK(ops->chown("/f", 1000, 2000, NULL) == 0);
	REQUIRE(get_cached("/f", &st) == 0);
	CHECK(st.st_uid == 1000 && st.st_gid == 2000);

	memset(tv, 0, sizeof(tv));
	tv[0].tv_sec = 111;
	tv[1].tv_sec = 222;
	CHECK(ops->utimens("/f", tv, NULL) == 0);
	REQUIRE(get_cached("/f", &st) == 0);
	CHECK(st.st_atime == 111 && st.st_mtime == 222);

	/* a second name raises the link count of the cached first one */
	CHECK(ops->link("/f", "/l") == 0);
	REQUIRE(get_cached("/f", &st) == 0);
	CHECK(st.st_nlink == 2);

	/* /l was never cached: a write through /f shows in it */
	CHECK(ops->write("/f", "x", 1, 500, NULL) == 1);
	CHECK(size_of("/l") == 501);
}

static void test_cache_invalidate(void)
{
	mk_file("/f", 1);
	mk_file("/g", 1);
	(void) probe("/f");
	(void) probe("/g");
	CHECK(!probe("/f"));

	cache_invalidate("/f");
	CHECK(probe("/f"));
	CHECK(!probe("/g"));
}

static void test_rename_moves_children(void)
{
	struct listing l;
	struct stat st;

	mk_dir("/a");
	mk_file("/a/f", 1);
	mk_dir("/a/sub");
	mk_file("/a/sub/g", 2);
	mk_file("/zz", 3);
	(void) probe_dir("/");
	(void) probe_dir("/a");
	(void) probe("/a/sub/g");

	REQUIRE(ops->rename("/a", "/b", 0) == 0);

	CHECK(!probe("/zz"));		/* unrelated, still cached */
	/* nothing under the old name is served any more */
	CHECK(do_getattr("/a", &st) == -ENOENT);
	CHECK(do_getattr("/a/f", &st) == -ENOENT);
	CHECK(do_getattr("/a/sub/g", &st) == -ENOENT);
	CHECK(do_readdir("/a", 0, &l) == -ENOENT);
	/* the listing of the parent was refetched */
	CHECK(do_readdir("/", 0, &l) == 0);
	CHECK(listing_has(&l, "b") && !listing_has(&l, "a"));
}

static void test_rename_nested(void)
{
	struct listing l;

	mk_dir("/d");
	mk_dir("/d/sub");
	mk_file("/d/f", 4);
	(void) probe_dir("/d");
	(void) probe_dir("/d/sub");

	REQUIRE(ops->rename("/d/f", "/d/sub/f2", 0) == 0);

	/* both parents were purged */
	CHECK(do_readdir("/d", 0, &l) == 0 && !listing_has(&l, "f"));
	CHECK(do_readdir("/d/sub", 0, &l) == 0 && listing_has(&l, "f2"));
}

static void test_rename_over_existing(void)
{
	mk_file("/x", 3);
	mk_file("/y", 7);
	CHECK(size_of("/y") == 7);
	REQUIRE(ops->rename("/x", "/y", 0) == 0);
	CHECK(size_of("/y") == 3);

	/* onto itself: nothing changes */
	CHECK(ops->rename("/y", "/y", 0) == 0);
	CHECK(size_of("/y") == 3);
}

static void test_failed_ops_keep_cache(void)
{
	struct listing l;
	uint64_t w;

	mk_dir("/d");
	mk_file("/d/f", 1);
	REQUIRE(do_readdir("/d", 0, &l) == 0);
	w = cache_get_write_ctr();

	CHECK(ops->mkdir("/d/f", 0755) == -EEXIST);
	CHECK(ops->unlink("/d/none") == -ENOENT);
	CHECK(ops->rmdir("/d/none") == -ENOENT);
	CHECK(ops->chmod("/d/none", 0600, NULL) == -ENOENT);
	CHECK(ops->truncate("/d/none", 0, NULL) == -ENOENT);
	CHECK(ops->write("/d/none", "x", 1, 0, NULL) == -ENOENT);
	CHECK(ops->rename("/d/none", "/d/f", 0) == -ENOENT);

	/* a write that failed does not count as one */
	CHECK(cache_get_write_ctr() == w);
	CHECK(!probe("/d/f"));
	CHECK(!probe_dir("/d"));
}

/* ---- readdir ---- */

static void test_readdir_cached(void)
{
	struct listing l;

	mk_dir("/d");
	mk_file("/d/a", 10);
	mk_file("/d/b", 20);
	mk_dir("/d/c");

	REQUIRE(do_readdir("/d", 0, &l) == 0);
	CHECK(l.n == 3);
	CHECK(listing_has(&l, "a") && listing_has(&l, "b") && listing_has(&l, "c"));
	CHECK(calls.readdir == 1 && calls.opendir == 1 && calls.releasedir == 1);
	CHECK(last_readdir_offset == 0);

	/* the listing also cached the attributes of its entries */
	CHECK(size_of("/d/a") == 10 && calls.getattr == 0);

	/* a second listing needs neither the backend listing nor its handle */
	mk_file("/d/late", 1);
	REQUIRE(do_readdir("/d", 0, &l) == 0);
	CHECK(l.n == 3 && !listing_has(&l, "late"));
	CHECK(calls.readdir == 1 && calls.opendir == 1 && calls.releasedir == 1);

	advance(20);			/* valid through dir_timeout */
	CHECK(!probe_dir("/d"));
	advance(1);
	REQUIRE(do_readdir("/d", 0, &l) == 0);
	CHECK(l.n == 4 && listing_has(&l, "late"));
	CHECK(calls.readdir == 2 && calls.opendir == 2 && calls.releasedir == 2);
}

/*
 * sshfs hands the whole listing to the filler with offset 0 and leaves the
 * slicing to libfuse, so an offset from the caller must neither cut the
 * listing short nor be passed on (upstream issue 338, PR 379).
 */
static void test_readdir_ignores_offset(void)
{
	struct listing l;

	mk_dir("/d");
	mk_file("/d/a", 1);
	mk_file("/d/b", 2);
	mk_file("/d/c", 3);

	/* cold cache: the backend is asked from 0 and the filler gets offset 0 */
	REQUIRE(do_readdir("/d", 2, &l) == 0);
	CHECK(l.n == 3 && l.max_off == 0 && last_readdir_offset == 0);

	/* warm cache, new handle, other offsets */
	REQUIRE(do_readdir("/d", 3, &l) == 0);
	CHECK(l.n == 3 && l.max_off == 0);
	REQUIRE(do_readdir("/d", 1000, &l) == 0);
	CHECK(l.n == 3 && calls.readdir == 1);

	advance(21);			/* expired: nonzero offset again */
	REQUIRE(do_readdir("/d", 5, &l) == 0);
	CHECK(l.n == 3 && last_readdir_offset == 0 && calls.readdir == 2);
}

static void test_readdir_root(void)
{
	struct listing l;

	mk_file("/x", 5);
	mk_dir("/d");

	REQUIRE(do_readdir("/", 0, &l) == 0);
	CHECK(l.n == 2 && listing_has(&l, "x") && listing_has(&l, "d"));
	/* entries of the root are cached as /x, not //x */
	CHECK(size_of("/x") == 5 && calls.getattr == 0);
}

static void test_readdir_without_attrs(void)
{
	struct listing l;

	readdir_no_attrs = 1;
	mk_dir("/d");
	mk_file("/d/a", 5);

	REQUIRE(do_readdir("/d", 0, &l) == 0);
	CHECK(listing_has(&l, "a"));
	/* an entry listed without attributes has to be looked up */
	CHECK(size_of("/d/a") == 5 && calls.getattr == 1);
	CHECK(!probe_dir("/d"));
}

static void test_readdir_error(void)
{
	struct listing l;

	mk_dir("/d");
	mk_file("/d/a", 1);
	mk_file("/d/b", 2);

	readdir_fail_at = 0;		/* the backend fails before any entry */
	CHECK(do_readdir("/d", 0, &l) == -EIO);
	CHECK(l.n == 0 && cache_lookup("/d") == NULL);

	readdir_fail_at = 1;		/* and after delivering "a" */
	CHECK(do_readdir("/d", 0, &l) == -EIO);
	CHECK(l.n == 1 && cache_lookup("/d") == NULL);
	/*
	 * "a" came with a valid reply and passed the write counter check, so
	 * its attributes stay cached, as they would after a getattr.
	 */
	CHECK(size_of("/d/a") == 1 && calls.getattr == 0);
	CHECK(cache_lookup("/d/b") == NULL);

	readdir_fail_at = -1;
	REQUIRE(do_readdir("/d", 0, &l) == 0);
	CHECK(l.n == 2 && calls.readdir == 3 && !probe_dir("/d"));
}

/* list /d through a directory handle that is already open */
static int readdir_on(uint64_t dh)
{
	struct fuse_file_info fi;
	struct listing l;

	memset(&l, 0, sizeof(l));
	memset(&fi, 0, sizeof(fi));
	fi.fh = dh;
	return ops->readdir("/d", &l, collect, 0, &fi, 0);
}

static void test_readdir_handle_reuse(void)
{
	struct fuse_file_info fi;
	uint64_t dh;

	mk_dir("/d");
	mk_file("/d/a", 1);
	memset(&fi, 0, sizeof(fi));
	REQUIRE(ops->opendir("/d", &fi) == 0);
	dh = fi.fh;
	CHECK(calls.opendir == 0);

	CHECK(readdir_on(dh) == 0);
	CHECK(calls.opendir == 1 && last_readdir_fh == 42);

	/* after expiry the backend handle is reused */
	advance(cache.dir_timeout_secs + 1);
	CHECK(readdir_on(dh) == 0);
	CHECK(calls.readdir == 2 && calls.opendir == 1 && last_readdir_fh == 42);

	fi.fh = dh;
	CHECK(ops->releasedir("/d", &fi) == 0);
	CHECK(calls.releasedir == 1 && last_releasedir_fh == 42);
}

static void test_readdir_attr_independent(void)
{
	mk_dir("/d");
	mk_file("/d/a", 1);
	mk_dir("/e");

	/* a listing says nothing about the attributes of the directory, and
	   caching them leaves the listing alone */
	(void) probe_dir("/d");
	CHECK(probe("/d"));
	CHECK(!probe_dir("/d"));
	/* attributes alone do not make a listing either */
	(void) probe("/e");
	CHECK(probe_dir("/e"));
}

/* ---- readlink ---- */

static void test_readlink_cached(void)
{
	char buf[64];

	cache.link_timeout_secs = 10;
	mk_link("/l", "target-1");
	mk_link("/m", "other");

	REQUIRE(ops->readlink("/l", buf, sizeof(buf)) == 0);
	CHECK(strcmp(buf, "target-1") == 0);
	g_strlcpy(ent_get("/l")->link, "target-2", PATH_LEN);
	advance(10);
	REQUIRE(ops->readlink("/l", buf, sizeof(buf)) == 0);
	CHECK(strcmp(buf, "target-1") == 0 && calls.readlink == 1);
	advance(1);
	REQUIRE(ops->readlink("/l", buf, sizeof(buf)) == 0);
	CHECK(strcmp(buf, "target-2") == 0 && calls.readlink == 2);

	/* cached attributes of a path do not stand in for its target */
	(void) probe("/m");
	CHECK(probe_link("/m"));

	/* a hard link to a symlink has the same target */
	CHECK(ops->link("/m", "/n") == 0);
	REQUIRE(ops->readlink("/n", buf, sizeof(buf)) == 0);
	CHECK(strcmp(buf, "other") == 0);
}

static void test_readlink_truncation(void)
{
	char buf[8];
	char small[5];
	char one[1];

	mk_link("/l", "0123456789");

	/* the backend fills a buffer of 5 and the cache keeps what fit */
	memset(small, 'X', sizeof(small));
	REQUIRE(ops->readlink("/l", small, sizeof(small)) == 0);
	CHECK(strcmp(small, "0123") == 0);
	CHECK(calls.readlink == 1);

	memset(small, 'X', sizeof(small));
	REQUIRE(ops->readlink("/l", small, sizeof(small)) == 0);
	CHECK(strcmp(small, "0123") == 0);
	CHECK(calls.readlink == 1);

	/* a smaller buffer gets a shorter, terminated string from the cache */
	memset(buf, 'X', sizeof(buf));
	REQUIRE(ops->readlink("/l", buf, 3) == 0);
	CHECK(strcmp(buf, "01") == 0);
	CHECK(buf[3] == 'X');
	CHECK(calls.readlink == 1);

	/* a buffer of one byte holds just the terminator */
	cache_invalidate("/l");
	one[0] = 'X';
	REQUIRE(ops->readlink("/l", one, sizeof(one)) == 0);
	CHECK(one[0] == '\0');
	one[0] = 'X';
	REQUIRE(ops->readlink("/l", one, sizeof(one)) == 0);
	CHECK(one[0] == '\0');
	CHECK(calls.readlink == 2);
}

static void test_readlink_freed(void)
{
	char buf[64];

	mk_link("/l", "target");
	CHECK(ntracked == 0);
	REQUIRE(ops->readlink("/l", buf, sizeof(buf)) == 0);
	CHECK(ntracked == 1);

	/* refreshing an expired link frees the old string */
	advance(cache.link_timeout_secs + 1);
	REQUIRE(ops->readlink("/l", buf, sizeof(buf)) == 0);
	CHECK(calls.readlink == 2);
	CHECK(ntracked == 1);

	/* dropping the node frees the string (free_node) */
	cache_invalidate("/l");
	CHECK(ntracked == 0);

	REQUIRE(ops->readlink("/l", buf, sizeof(buf)) == 0);
	CHECK(ntracked == 1);
	g_hash_table_remove_all(cache.table);
	CHECK(ntracked == 0);
}

/* ---- the write counter ---- */

static const char *hook_path;	/* what the write and chmod hooks act on */

static void hook_write(void)
{
	(void) ops->write(hook_path, "hello", 5, 100, NULL);
}

static void test_write_guard_getattr(void)
{
	struct stat st;
	uint64_t w;

	mk_file("/f", 10);
	hook_path = "/f";
	hook_getattr = hook_write;
	w = cache_get_write_ctr();

	REQUIRE(do_getattr("/f", &st) == 0);
	CHECK(st.st_size == 10);	/* the reply that was in flight */
	CHECK(cache_get_write_ctr() == w + 1);
	CHECK(cache_lookup("/f") == NULL);

	REQUIRE(do_getattr("/f", &st) == 0);
	CHECK(calls.getattr == 2);
	CHECK(st.st_size == 105);
}

static void test_write_guard_api(void)
{
	struct stat st, st2;
	uint64_t w;

	mk_file("/f", 1);
	memset(&st, 0, sizeof(st));
	st.st_mode = S_IFREG | 0644;
	st.st_size = 1;

	w = cache_get_write_ctr();
	REQUIRE(ops->write("/f", "x", 1, 0, NULL) == 1);
	cache_add_attr("/f", &st, w);
	CHECK(cache_lookup("/f") == NULL);

	cache_add_attr("/f", &st, cache_get_write_ctr());
	CHECK(cache_lookup("/f") != NULL);
	REQUIRE(do_getattr("/f", &st2) == 0);
	CHECK(calls.getattr == 0);
}

static void test_write_guard_readdir(void)
{
	struct listing l;
	struct stat st;
	ino_t ino_a, ino_b;
	int a, b;

	mk_dir("/d");
	mk_file("/d/a", 1);
	mk_file("/d/b", 2);
	ino_a = ent_get("/d/a")->ino;
	ino_b = ent_get("/d/b")->ino;
	hook_path = "/d/a";
	hook_readdir = hook_write;

	REQUIRE(do_readdir("/d", 0, &l) == 0);
	CHECK(l.n == 2);

	/* the attributes that came with the listing may predate the write */
	CHECK(cache_lookup("/d/a") == NULL);
	CHECK(cache_lookup("/d/b") == NULL);
	REQUIRE(do_getattr("/d/a", &st) == 0);
	CHECK(st.st_size == 105);

	/*
	 * The cached listing keeps each stat as the backend read it.  libfuse
	 * uses only the type and inode number, which must be right; the size of
	 * "a" is the old one today and may be refreshed.
	 */
	REQUIRE(do_readdir("/d", 0, &l) == 0);
	CHECK(calls.readdir == 1);
	CHECK(l.n == 2);
	a = listing_index(&l, "a");
	b = listing_index(&l, "b");
	REQUIRE(a >= 0 && b >= 0);
	CHECK(S_ISREG(l.mode[a]) && l.ino[a] == ino_a);
	CHECK(l.size[a] == 1 || l.size[a] == 105);
	CHECK(S_ISREG(l.mode[b]) && l.ino[b] == ino_b && l.size[b] == 2);
}

/* ---- calls in flight across operations that do not bump write_ctr ---- */

static void hook_mkdir_new(void)
{
	(void) ops->mkdir("/d/new", 0755);
}

static void hook_chmod(void)
{
	(void) ops->chmod(hook_path, 0600, NULL);
}

static void hook_replace_link(void)
{
	(void) ops->unlink("/l");
	(void) ops->symlink("target-B", "/l");
}

/*
 * A reply that is in flight when a modifying operation purges its path is
 * installed after the purge, and then served until its timeout.  Only
 * cache_write() advances write_ctr, and cache_add_dir() and cache_add_link()
 * do not check it at all.
 *
 * These are gaps in the cache layer, shown by running the two calls in an
 * order the cache cannot rule out.  Whether a mount can produce that order
 * differs: on one Linux mount the VFS locks serialise readdir and mkdir in a
 * directory, so that pair is probably out of reach there, while a getattr or a
 * readdir racing a chmod of an entry is plausibly reachable, with a window of
 * about one round trip.  None of this has been reproduced on a mount.
 */
static void test_race_readdir_mkdir(void)
{
	struct listing l;

	mk_dir("/d");
	mk_file("/d/a", 1);
	mk_file("/d/b", 2);
	hook_readdir = hook_mkdir_new;

	REQUIRE(do_readdir("/d", 0, &l) == 0);
	CHECK(l.n == 2);	/* the listing in flight predates the mkdir */
	REQUIRE(ent_find("/d/new") != NULL);

	REQUIRE(do_readdir("/d", 0, &l) == 0);
	CHECK(listing_has(&l, "a") && listing_has(&l, "b"));
	XCHECK(listing_has(&l, "new"));
}

static void test_race_getattr_chmod(void)
{
	struct stat st;
	int perm;

	mk_file("/f", 1);
	hook_path = "/f";
	hook_getattr = hook_chmod;

	REQUIRE(do_getattr("/f", &st) == 0);
	CHECK((st.st_mode & 07777) == 0644);	/* the reply in flight */
	REQUIRE((ent_get("/f")->mode & 07777) == 0600);

	perm = perm_of("/f");
	CHECK(perm == 0644 || perm == 0600);
	XCHECK(perm == 0600);
}

static void test_race_readdir_chmod(void)
{
	struct listing l;
	int perm;

	mk_dir("/d");
	mk_file("/d/a", 1);
	hook_path = "/d/a";
	hook_readdir = hook_chmod;

	REQUIRE(do_readdir("/d", 0, &l) == 0);
	REQUIRE((ent_get("/d/a")->mode & 07777) == 0600);

	perm = perm_of("/d/a");
	CHECK(perm == 0644 || perm == 0600);
	XCHECK(perm == 0600);
}

static void test_race_readlink(void)
{
	char buf[64];

	mk_link("/l", "target-A");
	hook_readlink = hook_replace_link;

	REQUIRE(ops->readlink("/l", buf, sizeof(buf)) == 0);
	CHECK(strcmp(buf, "target-A") == 0);	/* the reply in flight */
	REQUIRE(strcmp(ent_get("/l")->link, "target-B") == 0);

	REQUIRE(ops->readlink("/l", buf, sizeof(buf)) == 0);
	CHECK(strcmp(buf, "target-A") == 0 || strcmp(buf, "target-B") == 0);
	XCHECK(strcmp(buf, "target-B") == 0);
}

/*
 * The cache keeps attributes per path, and a change made through one name of
 * a file purges only that name, so another cached name of the same file is
 * served stale until it expires.
 */
static void test_stale_hard_link_alias(void)
{
	off_t size;

	mk_file("/a", 1);
	REQUIRE(ops->link("/a", "/b") == 0);
	REQUIRE(size_of("/b") == 1);		/* cache the second name */
	REQUIRE(ops->truncate("/a", 100, NULL) == 0);
	REQUIRE(ent_get("/b")->size == 100);

	size = size_of("/b");
	CHECK(size == 1 || size == 100);
	XCHECK(size == 100);
}

/* ---- cleaning ---- */

static void test_clean_interval(void)
{
	cache.stat_timeout_secs = 10;
	mk_files("abcd");

	get_files("ab");		/* valid until T0+10 */
	advance(55);
	get_files("c");			/* valid until T0+65 */
	/* a and b are expired but linger: the interval has not passed */
	CHECK(g_hash_table_size(cache.table) == 3);

	advance(6);			/* T0+61 */
	get_files("d");
	CHECK(g_hash_table_size(cache.table) == 2);
	CHECK(!cache_lookup("/a") && !cache_lookup("/b"));
	CHECK(cache_lookup("/c") && cache_lookup("/d"));
	CHECK(cache.last_cleaned == T0 + 61);
	CHECK(!probe("/c"));		/* what stayed is still served */
}

static void test_clean_by_size(void)
{
	cache.stat_timeout_secs = 4;
	cache.max_size = 3;
	cache.clean_interval_secs = 1000;
	mk_files("abcdefghi");

	get_files("abcd");
	/* over the limit, but the minimum interval has not passed */
	CHECK(g_hash_table_size(cache.table) == 4);
	advance(6);
	get_files("e");
	CHECK(g_hash_table_size(cache.table) == 1);
	CHECK(!cache_lookup("/a") && cache_lookup("/e"));

	/* the limit is soft: entries that are still valid stay */
	cache.stat_timeout_secs = 100;
	get_files("fgh");
	advance(6);
	get_files("i");
	CHECK(cache.last_cleaned == T0 + 12);
	CHECK(g_hash_table_size(cache.table) == 4);
	CHECK(!cache_lookup("/e") && !probe("/f"));
}

static void test_clean_keeps_node_with_valid_part(void)
{
	cache.stat_timeout_secs = 5;
	cache.dir_timeout_secs = 50;
	cache.clean_interval_secs = 10;
	cache.min_clean_interval_secs = 1;
	mk_dir("/d");
	mk_file("/d/a", 1);
	mk_files("x");

	(void) probe_dir("/d");
	advance(20);
	get_files("x");			/* runs a clean */

	CHECK(cache.last_cleaned == T0 + 20);
	CHECK(cache_lookup("/d/a") == NULL);	/* attributes expired */
	CHECK(cache_lookup("/d") != NULL);	/* listing still valid */
	CHECK(g_hash_table_size(cache.table) == 2);
	CHECK(!probe_dir("/d"));
}

/* ---- setup of the wrapped operations ---- */

/* run cache_parse_options on "sshfs -o opts"; returns the arguments left */
static int parse(const char *opts)
{
	char a0[] = "sshfs";
	char a1[] = "-o";
	char *a2 = opts ? g_strdup(opts) : NULL;
	char *argv[] = { a0, a1, a2, NULL };
	struct fuse_args args = FUSE_ARGS_INIT(opts ? 3 : 1, argv);
	int left = -1;

	if (cache_parse_options(&args) == 0)
		left = args.argc;
	fuse_opt_free_args(&args);
	g_free(a2);
	return left;
}

static void test_parse_options(void)
{
	/* the later, specific option wins over dcache_timeout */
	CHECK(parse("dcache_timeout=7,dcache_stat_timeout=3,dcache_max_size=50,"
		    "dcache_clean_interval=30,dcache_min_clean_interval=2") == 1);
	CHECK(cache.stat_timeout_secs == 3 && cache.dir_timeout_secs == 7 &&
	      cache.link_timeout_secs == 7);
	CHECK(cache.max_size == 50 && cache.clean_interval_secs == 30 &&
	      cache.min_clean_interval_secs == 2);

	/* the older names */
	CHECK(parse("cache_timeout=9,cache_dir_timeout=4,cache_link_timeout=5,"
		    "cache_max_size=8,cache_clean_interval=31,"
		    "cache_min_clean_interval=3") == 1);
	CHECK(cache.stat_timeout_secs == 9 && cache.dir_timeout_secs == 4 &&
	      cache.link_timeout_secs == 5);
	CHECK(cache.max_size == 8 && cache.clean_interval_secs == 31 &&
	      cache.min_clean_interval_secs == 3);

	/* without options the defaults are restored */
	CHECK(parse(NULL) == 1);
	CHECK(cache.stat_timeout_secs == 20 && cache.dir_timeout_secs == 20 &&
	      cache.link_timeout_secs == 20);
	CHECK(cache.max_size == 10000 && cache.clean_interval_secs == 60 &&
	      cache.min_clean_interval_secs == 5);
}

static void test_init(void)
{
	struct fuse_conn_info conn;
	struct fuse_config cfg;
	void *res;

	memset(&conn, 0, sizeof(conn));
	memset(&cfg, 0, sizeof(cfg));
	res = ops->init(&conn, &cfg);
	CHECK(calls.init == 1);
	CHECK(res == &init_token);
	/* the cache needs a path for every request */
	CHECK(cfg.nullpath_ok == 0);
}

static void test_fill(void)
{
	struct fuse_operations minimal, out;

	/* everything the backend has is wrapped, with the cache's own
	   directory handling */
	CHECK(ops->getattr == cache_getattr && ops->readlink == cache_readlink);
	CHECK(ops->readdir == cache_readdir && ops->write == cache_write);
	CHECK(ops->opendir == cache_opendir && ops->releasedir == cache_releasedir);
	CHECK(ops->init == cache_init && ops->access == fake_access);

	/* what the backend lacks stays missing */
	memset(&minimal, 0, sizeof(minimal));
	memset(&out, 0, sizeof(out));
	minimal.getattr = fake_getattr;
	cache_fill(&minimal, &out);
	CHECK(out.getattr == cache_getattr);
	CHECK(out.opendir == cache_opendir && out.releasedir == cache_releasedir);
	CHECK(!out.readdir && !out.readlink && !out.mkdir && !out.unlink);
	CHECK(!out.rename && !out.chmod && !out.write && !out.create);
	CHECK(!out.access);
}

/* ---- runner ---- */

struct tcase {
	const char *name;
	void (*fn)(void);
	const char *xfail;	/* why the case is expected to fail, if it is */
};

static const struct tcase cases[] = {
	{ "getattr: cached until stat_timeout", test_getattr_timeout, NULL },
	{ "getattr: errors are not cached", test_getattr_errors, NULL },
	{ "timeouts: stat, dir and link expire separately",
	  test_timeouts_per_kind, NULL },
	{ "invalidate: modifying ops purge the path and its parent",
	  test_invalidation, NULL },
	{ "invalidate: next getattr returns the new value",
	  test_new_values_after_ops, NULL },
	{ "invalidate: cache_invalidate drops one path",
	  test_cache_invalidate, NULL },
	{ "rename: children of the old name are dropped",
	  test_rename_moves_children, NULL },
	{ "rename: both parents are purged", test_rename_nested, NULL },
	{ "rename: an existing target is not served stale",
	  test_rename_over_existing, NULL },
	{ "invalidate: failed ops leave the cache alone",
	  test_failed_ops_keep_cache, NULL },
	{ "readdir: cached until dir_timeout, fills child attrs",
	  test_readdir_cached, NULL },
	{ "readdir: offset is ignored", test_readdir_ignores_offset, NULL },
	{ "readdir: root entries are cached as /name", test_readdir_root, NULL },
	{ "readdir: entries without attrs are not attr-cached",
	  test_readdir_without_attrs, NULL },
	{ "readdir: an error caches no listing, nor entries not yet delivered",
	  test_readdir_error, NULL },
	{ "readdir: backend handle is opened once per handle",
	  test_readdir_handle_reuse, NULL },
	{ "readdir: listing and attrs of a dir are separate",
	  test_readdir_attr_independent, NULL },
	{ "readlink: cached until link_timeout", test_readlink_cached, NULL },
	{ "readlink: cached target is cut to the buffer size",
	  test_readlink_truncation, NULL },
	{ "readlink: cached target is freed with its node",
	  test_readlink_freed, NULL },
	{ "write counter: getattr in flight across a write is not cached",
	  test_write_guard_getattr, NULL },
	{ "write counter: cache_add_attr drops a stale counter",
	  test_write_guard_api, NULL },
	{ "write counter: readdir in flight across a write drops child attrs",
	  test_write_guard_readdir, NULL },
	{ "stale install: readdir in flight across mkdir (cache layer only)",
	  test_race_readdir_mkdir,
	  "cache_add_dir has no generation check; one Linux mount serialises this pair" },
	{ "stale install: getattr in flight across chmod",
	  test_race_getattr_chmod,
	  "only write bumps write_ctr; chmod purges before cache_add_attr" },
	{ "stale install: readdir in flight across chmod of an entry",
	  test_race_readdir_chmod,
	  "only write bumps write_ctr; chmod purges before cache_dirfill" },
	{ "stale install: readlink in flight across a symlink replacement",
	  test_race_readlink,
	  "cache_add_link has no generation check; unlink+symlink purge before it" },
	{ "stale alias: hard link name cached across a change via another name",
	  test_stale_hard_link_alias,
	  "cache_truncate purges only the path it is given; the cache is keyed by path" },
	{ "clean: expired entries go after clean_interval",
	  test_clean_interval, NULL },
	{ "clean: expired entries go when over max_size, valid ones stay",
	  test_clean_by_size, NULL },
	{ "clean: a node with one valid part is kept",
	  test_clean_keeps_node_with_valid_part, NULL },
	{ "options: defaults, dcache_* and cache_* names", test_parse_options,
	  NULL },
	{ "init: forwards to the backend and requires paths", test_init, NULL },
	{ "wrap: only existing backend ops are wrapped", test_fill, NULL },
};

int main(void)
{
	int failed = 0;
	size_t i;

	setvbuf(stdout, NULL, _IOLBF, 0);

	ops = cache_wrap(&fake_ops);
	if (!ops) {
		printf("Bail out! cache_wrap failed\n");
		return 1;
	}

	printf("1..%d\n", (int) ARRAY_SIZE(cases));
	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		const struct tcase *tc = &cases[i];
		int n = (int) i + 1;

		reset_state();
		cur_fails = 0;
		cur_xfails = 0;
		cur_sub = NULL;
		ntracked = 0;

		tc->fn();

		/* dropping every node must free everything it holds */
		g_hash_table_remove_all(cache.table);
		if (ntracked) {
			printf("#   %d cached string(s) not freed\n", ntracked);
			cur_fails++;
		}

		if (cur_fails) {
			printf("not ok %d - %s\n", n, tc->name);
			failed++;
		} else if (!tc->xfail) {
			if (cur_xfails) {
				printf("not ok %d - %s\n", n, tc->name);
				failed++;
			} else {
				printf("ok %d - %s\n", n, tc->name);
			}
		} else if (cur_xfails) {
			printf("ok %d - %s # XFAIL %s\n", n, tc->name,
			       tc->xfail);
		} else {
			printf("not ok %d - %s # XPASS %s: no longer fails, "
			       "remove the xfail\n", n, tc->name, tc->xfail);
			failed++;
		}
	}

	g_hash_table_destroy(cache.table);
	cache.table = NULL;
	return failed ? 1 : 0;
}
