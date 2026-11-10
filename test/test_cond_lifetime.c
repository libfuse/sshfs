/*
 * Exercise the real SSHFS cleanup paths without a mount or SSH server.
 * Counting explicit init/destroy calls also detects the leak on platforms
 * where pthread_cond_t has no separately allocated resources (e.g. glibc).
 * On Cygwin, losing an initialized condition variable leaks Windows handles.
 */
#define _GNU_SOURCE
#include <pthread.h>
#include <glib.h>

static unsigned live_conditions;

static int tracked_cond_init(pthread_cond_t *cond,
                             const pthread_condattr_t *attr)
{
	int err = pthread_cond_init(cond, attr);
	if (!err)
		live_conditions++;
	return err;
}

static int tracked_cond_destroy(pthread_cond_t *cond)
{
	int err = pthread_cond_destroy(cond);
	g_assert_cmpint(err, ==, 0);
	g_assert_cmpuint(live_conditions, >, 0);
	live_conditions--;
	return err;
}

int sshfs_program_main(int argc, char *argv[]);
#define main sshfs_program_main
#define pthread_cond_init tracked_cond_init
#define pthread_cond_destroy tracked_cond_destroy
#include "../sshfs.c"
#undef pthread_cond_destroy
#undef pthread_cond_init
#undef main

static void check_clean(unsigned baseline)
{
	g_assert_cmpuint(live_conditions, ==, baseline);
	g_assert_cmpuint(g_hash_table_size(sshfs.reqtab), ==, 0);
	g_assert_cmpint(sshfs.conns[0].req_count, ==, 0);
}

static void init_handle(struct sshfs_file *sf)
{
	buf_init(&sf->handle, 0);
	buf_add_string(&sf->handle, "test-handle");
	buf_finish(&sf->handle);
}

static void test_read_chunk(void)
{
	unsigned baseline = live_conditions;
	struct sshfs_file sf = { .conn = &sshfs.conns[0] };
	init_handle(&sf);
	struct read_chunk *chunk = sshfs_send_read(&sf, 0, 0);
	chunk_put_locked(chunk);
	buf_free(&sf.handle);
	check_clean(baseline);
}

static void test_read_failure(void)
{
	unsigned baseline = live_conditions;
	struct sshfs_file sf = { .conn = &sshfs.conns[0] };
	init_handle(&sf);
	struct read_chunk *chunk = sshfs_send_read(&sf, 1, 0);
	g_assert_cmpint(chunk->sio.num_reqs, ==, 0);
	chunk_put_locked(chunk);
	buf_free(&sf.handle);
	check_clean(baseline);
}

static void test_open_failure(void)
{
	unsigned baseline = live_conditions;
	struct fuse_file_info fi = { .flags = O_RDONLY };
	g_assert_cmpint(sshfs_open_common("/missing", 0, &fi), ==, -EIO);
	check_clean(baseline);
}

static void test_release(void)
{
	unsigned baseline = live_conditions;
	struct sshfs_file *sf = g_new0(struct sshfs_file, 1);
	struct fuse_file_info fi = { .fh = (uintptr_t) sf };
	sf->conn = &sshfs.conns[0];
	init_handle(sf);
	/* A disconnected file must still release its local resources. */
	sf->connver = sf->conn->connver - 1;
	list_init(&sf->write_reqs);
	int err = tracked_cond_init(&sf->write_finished, NULL);
	g_assert_cmpint(err, ==, 0);
	sf->readahead = sshfs_send_read(sf, 0, 0);
	g_assert_cmpint(sshfs_release("/file", &fi), ==, 0);
	check_clean(baseline);
}

static void test_sync_write_empty(void)
{
	unsigned baseline = live_conditions;
	struct sshfs_file sf = { .conn = &sshfs.conns[0] };
	init_handle(&sf);
	g_assert_cmpint(sshfs_sync_write(&sf, "", 0, 0), ==, 0);
	buf_free(&sf.handle);
	check_clean(baseline);
}

static void test_sync_write_failure(void)
{
	unsigned baseline = live_conditions;
	struct sshfs_file sf = { .conn = &sshfs.conns[0] };
	init_handle(&sf);
	g_assert_cmpint(sshfs_sync_write(&sf, "x", 1, 0), ==, -EIO);
	buf_free(&sf.handle);
	check_clean(baseline);
}

int main(int argc, char *argv[])
{
	g_test_init(&argc, &argv, NULL);
	sshfs.max_conns = 1;
	sshfs.max_read = 4096;
	sshfs.max_write = 4096;
	sshfs.max_outstanding_len = UINT_MAX;
	sshfs.base_path = g_strdup("");
	sshfs.conns = g_new0(struct conn, 1);
	g_assert_cmpint(processing_init(), ==, 0);
	/* Fail writes immediately, without starting a transport or worker. */
	sshfs.conns[0].rfd = -1;
	sshfs.conns[0].wfd = -1;
	sshfs.conns[0].processing_thread_started = 1;

	g_test_add_func("/cond-lifetime/read-chunk", test_read_chunk);
	g_test_add_func("/cond-lifetime/read-failure", test_read_failure);
	g_test_add_func("/cond-lifetime/open-failure", test_open_failure);
	g_test_add_func("/cond-lifetime/release", test_release);
	g_test_add_func("/cond-lifetime/sync-write-empty", test_sync_write_empty);
	g_test_add_func("/cond-lifetime/sync-write-failure", test_sync_write_failure);
	int result = g_test_run();

	tracked_cond_destroy(&sshfs.outstanding_cond);
	g_assert_cmpuint(live_conditions, ==, 0);
	g_hash_table_destroy(sshfs.reqtab);
	pthread_mutex_destroy(&sshfs.lock);
	pthread_mutex_destroy(&sshfs.conns[0].lock_write);
	g_free(sshfs.conns);
	g_free(sshfs.base_path);
	return result;
}
