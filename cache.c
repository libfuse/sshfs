/*
    Caching file system proxy
    Copyright (C) 2004  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

#define FUSE_USE_VERSION 22
#include "cache.h"
#include <stdio.h>
#include <errno.h>
#include <glib.h>
#include <pthread.h>

#define CACHE_TIMEOUT 20
#define MAX_CACHE_SIZE 10000
#define CACHE_CLEAN_INTERVAL 60

struct node {
    struct stat stat;
    time_t stat_valid;
    char **dir;
    time_t dir_valid;
    time_t valid;
};

struct fuse_cache_dirhandle {
    const char *path;
    fuse_dirh_t h;
    fuse_dirfil_t filler;
    GPtrArray *dir;
};

static struct fuse_cache_operations *next_oper;
static GHashTable *cache;
static pthread_mutex_t cache_lock;
static time_t last_cleaned;

static void free_node(gpointer node_)
{
    struct node *node = (struct node *) node_;
    g_strfreev(node->dir);
    g_free(node);
}

static int cache_clean_entry(void *key_, struct node *node, time_t *now)
{
    (void) key_;
    if (*now > node->valid)
        return TRUE;
    else
        return FALSE;
}

static void cache_clean(void)
{
    time_t now = time(NULL);
    if (g_hash_table_size(cache) > MAX_CACHE_SIZE ||
        now > last_cleaned + CACHE_CLEAN_INTERVAL) {
        g_hash_table_foreach_remove(cache, (GHRFunc) cache_clean_entry, &now);
        last_cleaned = now;
    }
}

static struct node *cache_lookup(const char *path)
{
    return (struct node *) g_hash_table_lookup(cache, path);    
}

static void cache_remove(const char *path)
{
    pthread_mutex_lock(&cache_lock);
    g_hash_table_remove(cache, path);
    pthread_mutex_unlock(&cache_lock);
}

static void cache_invalidate(const char *path)
{
    cache_remove(path);
}

static void cache_do_rename(const char *from, const char *to)
{
    cache_remove(from);
    cache_remove(to);
}

static struct node *cache_get(const char *path)
{
    struct node *node = cache_lookup(path);
    if (node == NULL) {
        char *pathcopy = g_strdup(path);
        node = g_new0(struct node, 1);
        g_hash_table_insert(cache, pathcopy, node);
    }
    return node;
}

static void cache_add_attr(const char *path, const struct stat *stbuf)
{
    struct node *node;
    time_t now;

    pthread_mutex_lock(&cache_lock);
    node = cache_get(path);
    now = time(NULL);
    node->stat = *stbuf;
    node->stat_valid = time(NULL) + CACHE_TIMEOUT;
    if (node->stat_valid > node->valid)
        node->valid = node->stat_valid;
    cache_clean();
    pthread_mutex_unlock(&cache_lock);
}

static void cache_add_dir(const char *path, char **dir)
{
    struct node *node;
    time_t now;

    pthread_mutex_lock(&cache_lock);
    node = cache_get(path);
    now = time(NULL);
    g_strfreev(node->dir);
    node->dir = dir;
    node->dir_valid = time(NULL) + CACHE_TIMEOUT;
    if (node->dir_valid > node->valid)
        node->valid = node->dir_valid;
    cache_clean();
    pthread_mutex_unlock(&cache_lock);
}

static int cache_getattr(const char *path, struct stat *stbuf)
{
    struct node *node;
    int err;
    
    pthread_mutex_lock(&cache_lock);
    node = cache_lookup(path);
    if (node != NULL) {
        time_t now = time(NULL);
        if (node->stat_valid - now >= 0) {
            *stbuf = node->stat;
            pthread_mutex_unlock(&cache_lock);
            return 0;
        }
    }
    pthread_mutex_unlock(&cache_lock);
    err = next_oper->oper.getattr(path, stbuf);
    if (!err)
        cache_add_attr(path, stbuf);

    return err;
}

static int cache_dirfill(fuse_cache_dirh_t ch, const char *name,
                         const struct stat *stbuf)
{
    int err = ch->filler(ch->h, name, 0, 0);
    if (!err) {
        g_ptr_array_add(ch->dir, g_strdup(name));
        char *fullpath = g_strdup_printf("%s/%s",
                                         !ch->path[1] ? "" : ch->path, name);
        cache_add_attr(fullpath, stbuf);
        g_free(fullpath);
    }
    return err;
}

static int cache_getdir(const char *path, fuse_dirh_t h, fuse_dirfil_t filler)
{
    struct fuse_cache_dirhandle ch;
    int err;
    char **dir;
    struct node *node;

    pthread_mutex_lock(&cache_lock);
    node = cache_lookup(path);
    if (node != NULL && node->dir != NULL) {
        time_t now = time(NULL);
        if (node->dir_valid - now >= 0) {
            for(dir = node->dir; *dir != NULL; dir++)
                filler(h, *dir, 0, 0);
            pthread_mutex_unlock(&cache_lock);
            return 0;
        }
    }
    pthread_mutex_unlock(&cache_lock);
 
    ch.path = path;
    ch.h = h;
    ch.filler = filler;
    ch.dir = g_ptr_array_new();
    err = next_oper->cache_getdir(path, &ch, cache_dirfill);
    g_ptr_array_add(ch.dir, NULL);
    dir = (char **) ch.dir->pdata;
    if (!err)
        cache_add_dir(path, dir);
    else
        g_strfreev(dir);
    g_ptr_array_free(ch.dir, FALSE);
    return err;
}

static int cache_unlink(const char *path)
{
    int err = next_oper->oper.unlink(path);
    if (!err)
        cache_remove(path);
    return err;
}

static int cache_rmdir(const char *path)
{
    int err = next_oper->oper.rmdir(path);
    if (!err)
        cache_remove(path);
    return err;
}

static int cache_rename(const char *from, const char *to)
{
    int err = next_oper->oper.rename(from, to);
    if (!err)
        cache_do_rename(from, to);
    return err;
}

static int cache_chmod(const char *path, mode_t mode)
{
    int err = next_oper->oper.chmod(path, mode);
    if (!err)
        cache_invalidate(path);
    return err;
}

static int cache_chown(const char *path, uid_t uid, gid_t gid)
{
    int err = next_oper->oper.chown(path, uid, gid);
    if (!err)
        cache_invalidate(path);
    return err;
}

static int cache_truncate(const char *path, off_t size)
{
    int err = next_oper->oper.truncate(path, size);
    if (!err)
        cache_invalidate(path);
    return err;
}

static int cache_utime(const char *path, struct utimbuf *buf)
{
    int err = next_oper->oper.utime(path, buf);
    if (!err)
        cache_invalidate(path);
    return err;
}


struct fuse_operations *cache_init(struct fuse_cache_operations *oper)
{
    static struct fuse_operations cache_oper;
    next_oper = oper;

    cache_oper.getattr  = oper->oper.getattr ? cache_getattr : NULL;
    cache_oper.readlink = oper->oper.readlink;
    cache_oper.getdir   = oper->cache_getdir ? cache_getdir : oper->oper.getdir;
    cache_oper.mknod    = oper->oper.mknod;
    cache_oper.mkdir    = oper->oper.mkdir;
    cache_oper.symlink  = oper->oper.symlink;
    cache_oper.unlink   = oper->oper.unlink ? cache_unlink : NULL;
    cache_oper.rmdir    = oper->oper.rmdir ? cache_rmdir : NULL;
    cache_oper.rename   = oper->oper.rename ? cache_rename : NULL;
    cache_oper.link     = oper->oper.link;
    cache_oper.chmod    = oper->oper.chmod ? cache_chmod : NULL;
    cache_oper.chown    = oper->oper.chown ? cache_chown : NULL;
    cache_oper.truncate = oper->oper.truncate ? cache_truncate : NULL;
    cache_oper.utime    = oper->oper.utime ? cache_utime : NULL;
    cache_oper.open     = oper->oper.open;
    cache_oper.read     = oper->oper.read;
    cache_oper.write    = oper->oper.write;
    cache_oper.statfs   = oper->oper.statfs;
    cache_oper.release  = oper->oper.release;
    cache_oper.fsync    = oper->oper.fsync;
    cache_oper.setxattr = oper->oper.setxattr;
    cache_oper.getxattr = oper->oper.getxattr;
    cache_oper.listxattr = oper->oper.listxattr;
    cache_oper.removexattr = oper->oper.removexattr;
    pthread_mutex_init(&cache_lock, NULL);
    cache = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, free_node);
    if (cache == NULL) {
        fprintf(stderr, "failed to create cache\n");
        return NULL;
    }
    return &cache_oper;
}
