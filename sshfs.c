/*
    SSH file system
    Copyright (C) 2004  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

#include "config.h"

#include <fuse.h>
#include <fuse_opt.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <semaphore.h>
#include <pthread.h>
#include <netdb.h>
#include <signal.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <glib.h>

#include "cache.h"

#if FUSE_VERSION >= 23
#define SSHFS_USE_INIT
#endif

#define SSH_FXP_INIT                1
#define SSH_FXP_VERSION             2
#define SSH_FXP_OPEN                3
#define SSH_FXP_CLOSE               4
#define SSH_FXP_READ                5
#define SSH_FXP_WRITE               6
#define SSH_FXP_LSTAT               7
#define SSH_FXP_FSTAT               8
#define SSH_FXP_SETSTAT             9
#define SSH_FXP_FSETSTAT           10
#define SSH_FXP_OPENDIR            11
#define SSH_FXP_READDIR            12
#define SSH_FXP_REMOVE             13
#define SSH_FXP_MKDIR              14
#define SSH_FXP_RMDIR              15
#define SSH_FXP_REALPATH           16
#define SSH_FXP_STAT               17
#define SSH_FXP_RENAME             18
#define SSH_FXP_READLINK           19
#define SSH_FXP_SYMLINK            20
#define SSH_FXP_STATUS            101
#define SSH_FXP_HANDLE            102
#define SSH_FXP_DATA              103
#define SSH_FXP_NAME              104
#define SSH_FXP_ATTRS             105
#define SSH_FXP_EXTENDED          200
#define SSH_FXP_EXTENDED_REPLY    201

#define SSH_FILEXFER_ATTR_SIZE          0x00000001
#define SSH_FILEXFER_ATTR_UIDGID        0x00000002
#define SSH_FILEXFER_ATTR_PERMISSIONS   0x00000004
#define SSH_FILEXFER_ATTR_ACMODTIME     0x00000008
#define SSH_FILEXFER_ATTR_EXTENDED      0x80000000

#define SSH_FX_OK                            0
#define SSH_FX_EOF                           1
#define SSH_FX_NO_SUCH_FILE                  2
#define SSH_FX_PERMISSION_DENIED             3
#define SSH_FX_FAILURE                       4
#define SSH_FX_BAD_MESSAGE                   5
#define SSH_FX_NO_CONNECTION                 6
#define SSH_FX_CONNECTION_LOST               7
#define SSH_FX_OP_UNSUPPORTED                8

#define SSH_FXF_READ            0x00000001
#define SSH_FXF_WRITE           0x00000002
#define SSH_FXF_APPEND          0x00000004
#define SSH_FXF_CREAT           0x00000008
#define SSH_FXF_TRUNC           0x00000010
#define SSH_FXF_EXCL            0x00000020

#define PROTO_VERSION 3

#define MY_EOF 1

#define MAX_REPLY_LEN (1 << 17)

#define RENAME_TEMP_CHARS 8

#define SFTP_SERVER_PATH "/usr/lib/sftp-server"

#define SSHNODELAY_SO "sshnodelay.so"

struct buffer {
    uint8_t *p;
    size_t len;
    size_t size;
};

struct list_head {
    struct list_head *prev;
    struct list_head *next;
};

struct request;
typedef void (*request_func)(struct request *);

struct request {
    unsigned int want_reply;
    sem_t ready;
    uint8_t reply_type;
    int replied;
    int error;
    struct buffer reply;
    struct timeval start;
    void *data;
    request_func end_func;
    struct list_head list;
};

struct read_chunk {
    sem_t ready;
    off_t offset;
    size_t size;
    struct buffer data;
    int refs;
    int res;
    long modifver;
};

struct sshfs_file {
    struct buffer handle;
    struct list_head write_reqs;
    pthread_cond_t write_finished;
    int write_error;
    struct read_chunk *readahead;
    off_t next_pos;
    int is_seq;
    int connver;
    int modifver;
    int refs;
};

struct sshfs {
    char *directport;
    char *ssh_command;
    char *sftp_server;
    struct fuse_args ssh_args;
    char *workarounds;
    int rename_workaround;
    int nodelay_workaround;
    int nodelaysrv_workaround;
    int truncate_workaround;
    int transform_symlinks;
    int follow_symlinks;
    int no_check_root;
    int detect_uid;
    unsigned max_read;
    unsigned ssh_ver;
    int sync_write;
    int sync_read;
    int debug;
    int reconnect;
    char *host;
    char *base_path;
    GHashTable *reqtab;
    pthread_mutex_t lock;
    pthread_mutex_t lock_write;
    int processing_thread_started;
    unsigned int randseed;
    int fd;
    int connver;
    int server_version;
    unsigned remote_uid;
    unsigned local_uid;
    int remote_uid_detected;
    unsigned blksize;
    char *progname;
    long modifver;
};

static struct sshfs sshfs;

static const char *ssh_opts[] = {
    "AddressFamily",
    "BatchMode",
    "BindAddress",
    "ChallengeResponseAuthentication",
    "CheckHostIP",
    "Cipher",
    "Ciphers",
    "Compression",
    "CompressionLevel",
    "ConnectionAttempts",
    "ConnectTimeout",
    "GlobalKnownHostsFile",
    "GSSAPIAuthentication",
    "GSSAPIDelegateCredentials",
    "HostbasedAuthentication",
    "HostKeyAlgorithms",
    "HostKeyAlias",
    "HostName",
    "IdentityFile",
    "IdentitiesOnly",
    "LogLevel",
    "MACs",
    "NoHostAuthenticationForLocalhost",
    "NumberOfPasswordPrompts",
    "PasswordAuthentication",
    "Port",
    "PreferredAuthentications",
    "ProxyCommand",
    "PubkeyAuthentication",
    "RhostsRSAAuthentication",
    "RSAAuthentication",
    "ServerAliveInterval",
    "ServerAliveCountMax",
    "SmartcardDevice",
    "StrictHostKeyChecking",
    "TCPKeepAlive",
    "UsePrivilegedPort",
    "UserKnownHostsFile",
    "VerifyHostKeyDNS",
    NULL,
};

enum {
    KEY_PORT,
    KEY_COMPRESS,
    KEY_HELP,
    KEY_VERSION,
};

#define SSHFS_OPT(t, p, v) { t, offsetof(struct sshfs, p), v }

static struct fuse_opt sshfs_opts[] = {
    SSHFS_OPT("directport=%s",     directport, 0),
    SSHFS_OPT("ssh_command=%s",    ssh_command, 0),
    SSHFS_OPT("sftp_server=%s",    sftp_server, 0),
    SSHFS_OPT("max_read=%u",       max_read, 0),
    SSHFS_OPT("ssh_protocol=%u",   ssh_ver, 0),
    SSHFS_OPT("-1",                ssh_ver, 1),
    SSHFS_OPT("workaround=%s",     workarounds, 0),
    SSHFS_OPT("idmap=none",        detect_uid, 0),
    SSHFS_OPT("idmap=user",        detect_uid, 1),
    SSHFS_OPT("sshfs_sync",        sync_write, 1),
    SSHFS_OPT("no_readahead",      sync_read, 1),
    SSHFS_OPT("sshfs_debug",       debug, 1),
    SSHFS_OPT("reconnect",         reconnect, 1),
    SSHFS_OPT("transform_symlinks", transform_symlinks, 1),
    SSHFS_OPT("follow_symlinks",   follow_symlinks, 1),
    SSHFS_OPT("no_check_root",     no_check_root, 1),

    FUSE_OPT_KEY("-p ",            KEY_PORT),
    FUSE_OPT_KEY("-C",             KEY_COMPRESS),
    FUSE_OPT_KEY("-V",             KEY_VERSION),
    FUSE_OPT_KEY("--version",      KEY_VERSION),
    FUSE_OPT_KEY("-h",             KEY_HELP),
    FUSE_OPT_KEY("--help",         KEY_HELP),
    FUSE_OPT_END
};

static struct fuse_opt workaround_opts[] = {
    SSHFS_OPT("none",       rename_workaround, 0),
    SSHFS_OPT("none",       nodelay_workaround, 0),
    SSHFS_OPT("none",       nodelaysrv_workaround, 0),
    SSHFS_OPT("none",       truncate_workaround, 0),
    SSHFS_OPT("all",        rename_workaround, 1),
    SSHFS_OPT("all",        nodelay_workaround, 1),
    SSHFS_OPT("all",        truncate_workaround, 1),
    SSHFS_OPT("rename",     rename_workaround, 1),
    SSHFS_OPT("norename",   rename_workaround, 0),
    SSHFS_OPT("nodelay",    nodelay_workaround, 1),
    SSHFS_OPT("nonodelay",  nodelay_workaround, 0),
    SSHFS_OPT("nodelaysrv", nodelaysrv_workaround, 1),
    SSHFS_OPT("nonodelaysrv", nodelaysrv_workaround, 0),
    SSHFS_OPT("truncate",   truncate_workaround, 1),
    SSHFS_OPT("notruncate", truncate_workaround, 0),
    FUSE_OPT_END
};

#define DEBUG(format, args...) \
	do { if (sshfs.debug) fprintf(stderr, format, args); } while(0)

static const char *type_name(uint8_t type)
{
    switch(type) {
    case SSH_FXP_INIT:           return "INIT";
    case SSH_FXP_VERSION:        return "VERSION";
    case SSH_FXP_OPEN:           return "OPEN";
    case SSH_FXP_CLOSE:          return "CLOSE";
    case SSH_FXP_READ:           return "READ";
    case SSH_FXP_WRITE:          return "WRITE";
    case SSH_FXP_LSTAT:          return "LSTAT";
    case SSH_FXP_FSTAT:          return "FSTAT";
    case SSH_FXP_SETSTAT:        return "SETSTAT";
    case SSH_FXP_FSETSTAT:       return "FSETSTAT";
    case SSH_FXP_OPENDIR:        return "OPENDIR";
    case SSH_FXP_READDIR:        return "READDIR";
    case SSH_FXP_REMOVE:         return "REMOVE";
    case SSH_FXP_MKDIR:          return "MKDIR";
    case SSH_FXP_RMDIR:          return "RMDIR";
    case SSH_FXP_REALPATH:       return "REALPATH";
    case SSH_FXP_STAT:           return "STAT";
    case SSH_FXP_RENAME:         return "RENAME";
    case SSH_FXP_READLINK:       return "READLINK";
    case SSH_FXP_SYMLINK:        return "SYMLINK";
    case SSH_FXP_STATUS:         return "STATUS";
    case SSH_FXP_HANDLE:         return "HANDLE";
    case SSH_FXP_DATA:           return "DATA";
    case SSH_FXP_NAME:           return "NAME";
    case SSH_FXP_ATTRS:          return "ATTRS";
    case SSH_FXP_EXTENDED:       return "EXTENDED";
    case SSH_FXP_EXTENDED_REPLY: return "EXTENDED_REPLY";
    default:                     return "???";
    }
}

#define container_of(ptr, type, member) ({			\
        const typeof( ((type *)0)->member ) *__mptr = (ptr);	\
        (type *)( (char *)__mptr - offsetof(type,member) );})

#define list_entry(ptr, type, member) \
	container_of(ptr, type, member)

static void list_init(struct list_head *head)
{
    head->next = head;
    head->prev = head;
}

static void list_add(struct list_head *new, struct list_head *head)
{
    struct list_head *prev = head;
    struct list_head *next = head->next;
    next->prev = new;
    new->next = next;
    new->prev = prev;
    prev->next = new;
}

static void list_del(struct list_head *entry)
{
    struct list_head *prev = entry->prev;
    struct list_head *next = entry->next;
    next->prev = prev;
    prev->next = next;

}

static int list_empty(const struct list_head *head)
{
	return head->next == head;
}

static inline void buf_init(struct buffer *buf, size_t size)
{
    if (size) {
        buf->p = (uint8_t *) malloc(size);
        if (!buf->p) {
            fprintf(stderr, "sshfs: memory allocation failed\n");
            exit(1);
        }
    } else
        buf->p = NULL;
    buf->len = 0;
    buf->size = size;
}

static inline void buf_free(struct buffer *buf)
{
    free(buf->p);
}

static inline void buf_finish(struct buffer *buf)
{
    buf->len = buf->size;
}

static inline void buf_clear(struct buffer *buf)
{
    buf_free(buf);
    buf_init(buf, 0);
}

static void buf_resize(struct buffer *buf, size_t len)
{
    buf->size = (buf->len + len + 63) & ~31;
    buf->p = (uint8_t *) realloc(buf->p, buf->size);
    if (!buf->p) {
        fprintf(stderr, "sshfs: memory allocation failed\n");
        exit(1);
    }
}

static inline void buf_check_add(struct buffer *buf, size_t len)
{
    if (buf->len + len > buf->size)
        buf_resize(buf, len);
}

#define _buf_add_mem(b, d, l)    \
    buf_check_add(b, l);       \
    memcpy(b->p + b->len, d, l); \
    b->len += l;


static inline void buf_add_mem(struct buffer *buf, const void *data,
                               size_t len)
{
    _buf_add_mem(buf, data, len);
}

static inline void buf_add_buf(struct buffer *buf, const struct buffer *bufa)
{
    _buf_add_mem(buf, bufa->p, bufa->len);
}

static inline void buf_add_uint8(struct buffer *buf, uint8_t val)
{
    _buf_add_mem(buf, &val, 1);
}

static inline void buf_add_uint32(struct buffer *buf, uint32_t val)
{
    uint32_t nval = htonl(val);
    _buf_add_mem(buf, &nval, 4);
}

static inline void buf_add_uint64(struct buffer *buf, uint64_t val)
{
    buf_add_uint32(buf, val >> 32);
    buf_add_uint32(buf, val & 0xffffffff);
}

static inline void buf_add_data(struct buffer *buf, const struct buffer *data)
{
    buf_add_uint32(buf, data->len);
    buf_add_mem(buf, data->p, data->len);
}

static inline void buf_add_string(struct buffer *buf, const char *str)
{
    struct buffer data;
    data.p = (uint8_t *) str;
    data.len = strlen(str);
    buf_add_data(buf, &data);
}

static inline void buf_add_path(struct buffer *buf, const char *path)
{
    char *realpath =
        g_strdup_printf("%s%s", sshfs.base_path, path[1] ? path+1 : ".");
    buf_add_string(buf, realpath);
    g_free(realpath);
}

static int buf_check_get(struct buffer *buf, size_t len)
{
    if (buf->len + len > buf->size) {
        fprintf(stderr, "buffer too short\n");
        return -1;
    } else
        return 0;
}

static inline int buf_get_mem(struct buffer *buf, void *data, size_t len)
{
    if (buf_check_get(buf, len) == -1)
        return -1;
    memcpy(data, buf->p + buf->len, len);
    buf->len += len;
    return 0;
}

static inline int buf_get_uint8(struct buffer *buf, uint8_t *val)
{
    return buf_get_mem(buf, val, 1);
}

static inline int buf_get_uint32(struct buffer *buf, uint32_t *val)
{
    uint32_t nval;
    if (buf_get_mem(buf, &nval, 4) == -1)
        return -1;
    *val = ntohl(nval);
    return 0;
}

static inline int buf_get_uint64(struct buffer *buf, uint64_t *val)
{
    uint32_t val1;
    uint32_t val2;
    if (buf_get_uint32(buf, &val1) == -1 || buf_get_uint32(buf, &val2) == -1)
        return -1;
    *val = ((uint64_t) val1 << 32) + val2;
    return 0;
}

static inline int buf_get_data(struct buffer *buf, struct buffer *data)
{
    uint32_t len;
    if (buf_get_uint32(buf, &len) == -1 || len > buf->size - buf->len)
        return -1;
    buf_init(data, len + 1);
    data->size = len;
    if (buf_get_mem(buf, data->p, data->size) == -1) {
        buf_free(data);
        return -1;
    }
    return 0;
}

static inline int buf_get_string(struct buffer *buf, char **str)
{
    struct buffer data;
    if (buf_get_data(buf, &data) == -1)
        return -1;
    data.p[data.size] = '\0';
    *str = (char *) data.p;
    return 0;
}

static int buf_get_attrs(struct buffer *buf, struct stat *stbuf, int *flagsp)
{
    uint32_t flags;
    uint64_t size = 0;
    uint32_t uid = 0;
    uint32_t gid = 0;
    uint32_t atime = 0;
    uint32_t mtime = 0;
    uint32_t mode = S_IFREG | 0777;

    if (buf_get_uint32(buf, &flags) == -1)
        return -1;
    if (flagsp)
        *flagsp = flags;
    if ((flags & SSH_FILEXFER_ATTR_SIZE) &&
        buf_get_uint64(buf, &size) == -1)
        return -1;
    if ((flags & SSH_FILEXFER_ATTR_UIDGID) &&
        (buf_get_uint32(buf, &uid) == -1 ||
         buf_get_uint32(buf, &gid) == -1))
        return -1;
    if ((flags & SSH_FILEXFER_ATTR_PERMISSIONS) &&
        buf_get_uint32(buf, &mode) == -1)
        return -1;
    if ((flags & SSH_FILEXFER_ATTR_ACMODTIME)) {
        if (buf_get_uint32(buf, &atime) == -1 ||
            buf_get_uint32(buf, &mtime) == -1)
            return -1;
    }
    if ((flags & SSH_FILEXFER_ATTR_EXTENDED)) {
        uint32_t extcount;
        unsigned i;
        if (buf_get_uint32(buf, &extcount) == -1)
            return -1;
        for (i = 0; i < extcount; i++) {
            struct buffer tmp;
            if (buf_get_data(buf, &tmp) == -1)
                return -1;
            buf_free(&tmp);
            if (buf_get_data(buf, &tmp) == -1)
                return -1;
            buf_free(&tmp);
        }
    }

    if (sshfs.remote_uid_detected && uid == sshfs.remote_uid)
        uid = sshfs.local_uid;

    memset(stbuf, 0, sizeof(struct stat));
    stbuf->st_mode = mode;
    stbuf->st_nlink = 1;
    stbuf->st_size = size;
    if (sshfs.blksize) {
        stbuf->st_blksize = sshfs.blksize;
        stbuf->st_blocks =
            ((size + sshfs.blksize - 1) & ~(sshfs.blksize - 1)) >> 9;
    }
    stbuf->st_uid = uid;
    stbuf->st_gid = gid;
    stbuf->st_atime = atime;
    stbuf->st_mtime = mtime;
    return 0;
}

static int buf_get_entries(struct buffer *buf, fuse_cache_dirh_t h,
                           fuse_cache_dirfil_t filler)
{
    uint32_t count;
    unsigned i;

    if (buf_get_uint32(buf, &count) == -1)
        return -1;

    for (i = 0; i < count; i++) {
        int err = -1;
        char *name;
        char *longname;
        struct stat stbuf;
        if (buf_get_string(buf, &name) == -1)
            return -1;
        if (buf_get_string(buf, &longname) != -1) {
            free(longname);
            if (buf_get_attrs(buf, &stbuf, NULL) != -1) {
                if (sshfs.follow_symlinks && S_ISLNK(stbuf.st_mode))
                    stbuf.st_mode = 0;
                filler(h, name, &stbuf);
                err = 0;
            }
        }
        free(name);
        if (err)
            return err;
    }
    return 0;
}

static void ssh_add_arg(const char *arg)
{
    if (fuse_opt_add_arg(&sshfs.ssh_args, arg) == -1)
        _exit(1);
}

static int do_ssh_nodelay_workaround(void)
{
    char *oldpreload = getenv("LD_PRELOAD");
    char *newpreload;
    char sopath[PATH_MAX];
    int res;

    snprintf(sopath, sizeof(sopath), "%s/%s", LIBDIR, SSHNODELAY_SO);
    res = access(sopath, R_OK);
    if (res == -1) {
        char *s;
        if (!realpath(sshfs.progname, sopath))
            return -1;

        s = strrchr(sopath, '/');
        if (!s)
            s = sopath;
        else
            s++;

        if (s + strlen(SSHNODELAY_SO) >= sopath + sizeof(sopath))
            return -1;

        strcpy(s, SSHNODELAY_SO);
        res = access(sopath, R_OK);
        if (res == -1) {
            fprintf(stderr, "sshfs: cannot find %s\n", SSHNODELAY_SO);
            return -1;
        }
    }

    newpreload = g_strdup_printf("%s%s%s",
                                 oldpreload ? oldpreload : "",
                                 oldpreload ? " " : "",
                                 sopath);

    if (!newpreload || setenv("LD_PRELOAD", newpreload, 1) == -1)
        fprintf(stderr, "warning: failed set LD_PRELOAD for ssh nodelay workaround\n");
    g_free(newpreload);
    return 0;
}

static int start_ssh(void)
{
    int sockpair[2];
    int pid;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockpair) == -1) {
        perror("failed to create socket pair");
        return -1;
    }
    sshfs.fd = sockpair[0];

    pid = fork();
    if (pid == -1) {
        perror("failed to fork");
        return -1;
    } else if (pid == 0) {
        int devnull;

        if (sshfs.nodelay_workaround && do_ssh_nodelay_workaround() == -1)
            fprintf(stderr, "warning: ssh nodelay workaround disabled\n");

        if (sshfs.nodelaysrv_workaround) {
            /* Hack to work around missing TCP_NODELAY setting in sshd  */
            sshfs.ssh_args.argv[1] = "-X";
            setenv("DISPLAY", "", 1);
        }

        devnull = open("/dev/null", O_WRONLY);

        if (dup2(sockpair[1], 0) == -1 || dup2(sockpair[1], 1) == -1) {
            perror("failed to redirect input/output");
            _exit(1);
        }
        if (!sshfs.debug && devnull != -1)
            dup2(devnull, 2);

        close(devnull);
        close(sockpair[0]);
        close(sockpair[1]);

        switch (fork()) {
        case -1:
            perror("failed to fork");
            _exit(1);
        case 0:
            break;
        default:
            _exit(0);
        }
        chdir("/");

        execvp(sshfs.ssh_args.argv[0], sshfs.ssh_args.argv);
        perror("execvp");
        _exit(1);
    }
    waitpid(pid, NULL, 0);
    close(sockpair[1]);
    return 0;
}

static int connect_to(char *host, char *port)
{
    int err;
    int sock;
    int opt;
    struct addrinfo *ai;
    struct addrinfo hint;

    memset(&hint, 0, sizeof(hint));
    hint.ai_family = PF_INET;
    hint.ai_socktype = SOCK_STREAM;
    err = getaddrinfo(host, port, &hint, &ai);
    if (err) {
        fprintf(stderr, "failed to resolve %s:%s: %s\n", host, port,
                gai_strerror(err));
        return -1;
    }
    sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (sock == -1) {
        perror("failed to create socket");
        return -1;
    }
    err = connect(sock, ai->ai_addr, ai->ai_addrlen);
    if (err == -1) {
        perror("failed to connect");
        return -1;
    }
    opt = 1;
    err = setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
    if (err == -1)
        perror("warning: failed to set TCP_NODELAY");

    freeaddrinfo(ai);

    sshfs.fd = sock;
    return 0;
}

static int do_write(struct iovec *iov, size_t count)
{
    int res;
    while (count) {
        res = writev(sshfs.fd, iov, count);
        if (res == -1) {
            perror("write");
            return -1;
        } else if (res == 0) {
            fprintf(stderr, "zero write\n");
            return -1;
        }
        do {
            if ((unsigned) res < iov->iov_len) {
                iov->iov_len -= res;
                iov->iov_base += res;
                break;
            } else {
                res -= iov->iov_len;
                count --;
                iov ++;
            }
        } while(count);
    }
    return 0;
}

static uint32_t sftp_get_id(void)
{
    static uint32_t idctr;
    return idctr++;
}

static void buf_to_iov(const struct buffer *buf, struct iovec *iov)
{
    iov->iov_base = buf->p;
    iov->iov_len = buf->len;
}

static size_t iov_length(const struct iovec *iov, unsigned long nr_segs)
{
    unsigned long seg;
    size_t ret = 0;

    for (seg = 0; seg < nr_segs; seg++)
        ret += iov[seg].iov_len;
    return ret;
}

#define SFTP_MAX_IOV 3

static int sftp_send_iov(uint8_t type, uint32_t id, struct iovec iov[],
                         size_t count)
{
    int res;
    struct buffer buf;
    struct iovec iovout[SFTP_MAX_IOV];
    unsigned i;
    unsigned nout = 0;

    assert(count <= SFTP_MAX_IOV - 1);
    buf_init(&buf, 5);
    buf_add_uint32(&buf, iov_length(iov, count) + 5);
    buf_add_uint8(&buf, type);
    buf_add_uint32(&buf, id);
    buf_to_iov(&buf, &iovout[nout++]);
    for (i = 0; i < count; i++)
        iovout[nout++] = iov[i];
    pthread_mutex_lock(&sshfs.lock_write);
    res = do_write(iovout, nout);
    pthread_mutex_unlock(&sshfs.lock_write);
    buf_free(&buf);
    return res;
}

static int do_read(struct buffer *buf)
{
    int res;
    uint8_t *p = buf->p;
    size_t size = buf->size;
    while (size) {
        res = read(sshfs.fd, p, size);
        if (res == -1) {
            perror("read");
            return -1;
        } else if (res == 0) {
            fprintf(stderr, "remote host has disconnected\n");
            return -1;
        }
        size -= res;
        p += res;
    }
    return 0;
}

static int sftp_read(uint8_t *type, struct buffer *buf)
{
    int res;
    struct buffer buf2;
    uint32_t len;
    buf_init(&buf2, 5);
    res = do_read(&buf2);
    if (res != -1) {
        if (buf_get_uint32(&buf2, &len) == -1)
            return -1;
        if (len > MAX_REPLY_LEN) {
            fprintf(stderr, "reply len too large: %u\n", len);
            return -1;
        }
        if (buf_get_uint8(&buf2, type) == -1)
            return -1;
        buf_init(buf, len - 1);
        res = do_read(buf);
    }
    buf_free(&buf2);
    return res;
}

static void request_free(struct request *req)
{
    buf_free(&req->reply);
    sem_destroy(&req->ready);
    g_free(req);
}

static void chunk_free(struct read_chunk *chunk)
{
    buf_free(&chunk->data);
    sem_destroy(&chunk->ready);
    g_free(chunk);
}

static void chunk_put(struct read_chunk *chunk)
{
    if (chunk) {
        chunk->refs--;
        if (!chunk->refs)
            chunk_free(chunk);
    }
}

static void chunk_put_locked(struct read_chunk *chunk)
{
    pthread_mutex_lock(&sshfs.lock);
    chunk_put(chunk);
    pthread_mutex_unlock(&sshfs.lock);
}

static int clean_req(void *key_, struct request *req)
{
    (void) key_;

    req->error = -EIO;
    if (req->want_reply)
        sem_post(&req->ready);
    else {
        if (req->end_func)
            req->end_func(req);
        request_free(req);
    }
    return TRUE;
}

static void *process_requests(void *data_)
{
    int res;
    (void) data_;

    while (1) {
        struct buffer buf;
        uint8_t type;
        struct request *req;
        uint32_t id;

        buf_init(&buf, 0);
        res = sftp_read(&type, &buf);
        if (res == -1)
            break;
        if (buf_get_uint32(&buf, &id) == -1)
            break;

        pthread_mutex_lock(&sshfs.lock);
        req = (struct request *) g_hash_table_lookup(sshfs.reqtab,
                                                     GUINT_TO_POINTER(id));
        if (req == NULL)
            fprintf(stderr, "request %i not found\n", id);
        else
            g_hash_table_remove(sshfs.reqtab, GUINT_TO_POINTER(id));
        pthread_mutex_unlock(&sshfs.lock);
        if (req != NULL) {
            struct timeval now;
            unsigned int difftime;
            gettimeofday(&now, NULL);
            difftime = (now.tv_sec - req->start.tv_sec) * 1000;
            difftime += (now.tv_usec - req->start.tv_usec) / 1000;
            DEBUG("  [%05i] %14s %8ubytes (%ims)\n", id, type_name(type),
                  (unsigned) buf.size + 5, difftime);
            req->reply = buf;
            req->reply_type = type;
            req->replied = 1;
            if (req->want_reply)
                sem_post(&req->ready);
            else {
                if (req->end_func) {
                    pthread_mutex_lock(&sshfs.lock);
                    req->end_func(req);
                    pthread_mutex_unlock(&sshfs.lock);
                }
                request_free(req);
            }
        } else
            buf_free(&buf);
    }
    if (!sshfs.reconnect) {
        /* harakiri */
        kill(getpid(), SIGTERM);
    } else {
        pthread_mutex_lock(&sshfs.lock);
        sshfs.processing_thread_started = 0;
        close(sshfs.fd);
        sshfs.fd = -1;
        g_hash_table_foreach_remove(sshfs.reqtab, (GHRFunc) clean_req, NULL);
        sshfs.connver ++;
        pthread_mutex_unlock(&sshfs.lock);
    }
    return NULL;
}

static int sftp_init_reply_ok(struct buffer *buf, uint32_t *version)
{
    uint32_t len;
    uint8_t type;

    if (buf_get_uint32(buf, &len) == -1)
        return -1;

    if (len < 5 || len > MAX_REPLY_LEN)
        return 1;

    if (buf_get_uint8(buf, &type) == -1)
        return -1;

    if (type != SSH_FXP_VERSION)
        return 1;

    if (buf_get_uint32(buf, version) == -1)
        return -1;

    if (len > 5) {
        struct buffer buf2;
        buf_init(&buf2, len - 5);
        return do_read(&buf2);
    }
    return 0;
}

static int sftp_find_init_reply(uint32_t *version)
{
    int res;
    struct buffer buf;

    buf_init(&buf, 9);
    res = do_read(&buf);
    while (res != -1) {
        struct buffer buf2;

        res = sftp_init_reply_ok(&buf, version);
        if (res <= 0)
            break;

        /* Iterate over any rubbish until the version reply is found */
        DEBUG("%c", *buf.p);
        memmove(buf.p, buf.p + 1, buf.size - 1);
        buf.len = 0;
        buf2.p = buf.p + buf.size - 1;
        buf2.size = 1;
        res = do_read(&buf2);
    }
    buf_free(&buf);
    return res;
}

static int sftp_init()
{
    int res = -1;
    uint32_t version = 0;
    struct buffer buf;
    buf_init(&buf, 0);
    if (sftp_send_iov(SSH_FXP_INIT, PROTO_VERSION, NULL, 0) == -1)
        goto out;
    if (sftp_find_init_reply(&version) == -1)
        goto out;

    sshfs.server_version = version;
    DEBUG("Server version: %i\n", sshfs.server_version);
    if (version > PROTO_VERSION)
        fprintf(stderr, "Warning: server uses version: %i, we support: %i\n",
                version, PROTO_VERSION);
    res = 0;

 out:
    buf_free(&buf);
    return res;
}

static int sftp_error_to_errno(uint32_t error)
{
    switch (error) {
    case SSH_FX_OK:                return 0;
    case SSH_FX_NO_SUCH_FILE:      return ENOENT;
    case SSH_FX_PERMISSION_DENIED: return EACCES;
    case SSH_FX_FAILURE:           return EPERM;
    case SSH_FX_BAD_MESSAGE:       return EBADMSG;
    case SSH_FX_NO_CONNECTION:     return ENOTCONN;
    case SSH_FX_CONNECTION_LOST:   return ECONNABORTED;
    case SSH_FX_OP_UNSUPPORTED:    return EOPNOTSUPP;
    default:                       return EIO;
    }
}

static void sftp_detect_uid()
{
    int flags;
    uint32_t id = sftp_get_id();
    uint32_t replid;
    uint8_t type;
    struct buffer buf;
    struct stat stbuf;
    struct iovec iov[1];

    buf_init(&buf, 5);
    buf_add_string(&buf, ".");
    buf_to_iov(&buf, &iov[0]);
    if (sftp_send_iov(SSH_FXP_STAT, id, iov, 1) == -1)
        goto out;
    buf_clear(&buf);
    if (sftp_read(&type, &buf) == -1)
        goto out;
    if (type != SSH_FXP_ATTRS && type != SSH_FXP_STATUS) {
        fprintf(stderr, "protocol error\n");
        goto out;
    }
    if (buf_get_uint32(&buf, &replid) == -1)
        goto out;
    if (replid != id) {
        fprintf(stderr, "bad reply ID\n");
        goto out;
    }
    if (type == SSH_FXP_STATUS) {
        uint32_t serr;
        if (buf_get_uint32(&buf, &serr) == -1)
            goto out;

        fprintf(stderr, "failed to stat home directory (%i)\n", serr);
        goto out;
    }
    if (buf_get_attrs(&buf, &stbuf, &flags) == -1)
        goto out;

    if (!(flags & SSH_FILEXFER_ATTR_UIDGID))
        goto out;

    sshfs.remote_uid = stbuf.st_uid;
    sshfs.local_uid = getuid();
    sshfs.remote_uid_detected = 1;
    DEBUG("remote_uid = %i\n", sshfs.remote_uid);

 out:
    if (!sshfs.remote_uid_detected)
        fprintf(stderr, "failed to detect remote user ID\n");

    buf_free(&buf);
}

static int sftp_check_root(const char *base_path)
{
    int flags;
    uint32_t id = sftp_get_id();
    uint32_t replid;
    uint8_t type;
    struct buffer buf;
    struct stat stbuf;
    struct iovec iov[1];
    int err = -1;
    const char *remote_dir = base_path[0] ? base_path : ".";

    buf_init(&buf, 0);
    buf_add_string(&buf, remote_dir);
    buf_to_iov(&buf, &iov[0]);
    if (sftp_send_iov(SSH_FXP_STAT, id, iov, 1) == -1)
        goto out;
    buf_clear(&buf);
    if (sftp_read(&type, &buf) == -1)
        goto out;
    if (type != SSH_FXP_ATTRS && type != SSH_FXP_STATUS) {
        fprintf(stderr, "protocol error\n");
        goto out;
    }
    if (buf_get_uint32(&buf, &replid) == -1)
        goto out;
    if (replid != id) {
        fprintf(stderr, "bad reply ID\n");
        goto out;
    }
    if (type == SSH_FXP_STATUS) {
        uint32_t serr;
        if (buf_get_uint32(&buf, &serr) == -1)
            goto out;

        fprintf(stderr, "%s:%s: %s\n", sshfs.host, remote_dir,
                strerror(sftp_error_to_errno(serr)));

        goto out;
    }
    if (buf_get_attrs(&buf, &stbuf, &flags) == -1)
        goto out;

    if (!(flags & SSH_FILEXFER_ATTR_PERMISSIONS))
        goto out;

    if (!S_ISDIR(stbuf.st_mode)) {
        fprintf(stderr, "%s:%s: Not a directory\n", sshfs.host, remote_dir);
        goto out;
    }

    err = 0;

 out:
    buf_free(&buf);
    return err;
}

static int connect_remote(void)
{
    int err;

    if (sshfs.directport)
        err = connect_to(sshfs.host, sshfs.directport);
    else
        err = start_ssh();
    if (!err)
        err = sftp_init();

    return err;
}

static int start_processing_thread(void)
{
    int err;
    pthread_t thread_id;
    sigset_t oldset;
    sigset_t newset;

    if (sshfs.processing_thread_started)
        return 0;

    if (sshfs.fd == -1) {
        err = connect_remote();
        if (err)
            return -EIO;
    }

    sigemptyset(&newset);
    sigaddset(&newset, SIGTERM);
    sigaddset(&newset, SIGINT);
    sigaddset(&newset, SIGHUP);
    sigaddset(&newset, SIGQUIT);
    pthread_sigmask(SIG_BLOCK, &newset, &oldset);
    err = pthread_create(&thread_id, NULL, process_requests, NULL);
    if (err) {
        fprintf(stderr, "failed to create thread: %s\n", strerror(err));
        return -EIO;
    }
    pthread_detach(thread_id);
    pthread_sigmask(SIG_SETMASK, &oldset, NULL);
    sshfs.processing_thread_started = 1;
    return 0;
}

#ifdef SSHFS_USE_INIT
#if FUSE_VERSION >= 26
static void *sshfs_init(struct fuse_conn_info *conn)
#else
static void *sshfs_init(void)
#endif
{
#if FUSE_VERSION >= 26
    /* Readahead should be done by kernel or sshfs but not both */
    if (conn->async_read)
        sshfs.sync_read = 1;
#endif

    if (sshfs.detect_uid)
        sftp_detect_uid();

    start_processing_thread();
    return NULL;
}
#endif

static int sftp_request_wait(struct request *req, uint8_t type,
                             uint8_t expect_type, struct buffer *outbuf)
{
    int err;

    if (req->error) {
        err = req->error;
        goto out;
    }
    sem_wait(&req->ready);
    if (req->error) {
        err = req->error;
        goto out;
    }
    err = -EIO;
    if (req->reply_type != expect_type && req->reply_type != SSH_FXP_STATUS) {
        fprintf(stderr, "protocol error\n");
        goto out;
    }
    if (req->reply_type == SSH_FXP_STATUS) {
        uint32_t serr;
        if (buf_get_uint32(&req->reply, &serr) == -1)
            goto out;

        switch (serr) {
        case SSH_FX_OK:
            if (expect_type == SSH_FXP_STATUS)
                err = 0;
            else
                err = -EIO;
            break;

        case SSH_FX_EOF:
            if (type == SSH_FXP_READ || type == SSH_FXP_READDIR)
                err = MY_EOF;
            else
                err = -EIO;
            break;

        default:
            err = -sftp_error_to_errno(serr);
        }
    } else {
        buf_init(outbuf, req->reply.size - req->reply.len);
        buf_get_mem(&req->reply, outbuf->p, outbuf->size);
        err = 0;
    }

 out:
    if (req->end_func) {
        pthread_mutex_lock(&sshfs.lock);
        req->end_func(req);
        pthread_mutex_unlock(&sshfs.lock);
    }
    request_free(req);
    return err;
}

static int sftp_request_send(uint8_t type, struct iovec *iov, size_t count,
                             request_func begin_func, request_func end_func,
                             int want_reply, void *data,
                             struct request **reqp)
{
    int err;
    uint32_t id;
    struct request *req = g_new0(struct request, 1);

    req->want_reply = want_reply;
    req->end_func = end_func;
    req->data = data;
    sem_init(&req->ready, 0, 0);
    buf_init(&req->reply, 0);
    pthread_mutex_lock(&sshfs.lock);
    if (begin_func)
        begin_func(req);
    id = sftp_get_id();
    err = start_processing_thread();
    if (err) {
        pthread_mutex_unlock(&sshfs.lock);
        goto out;
    }
    g_hash_table_insert(sshfs.reqtab, GUINT_TO_POINTER(id), req);
    gettimeofday(&req->start, NULL);
    DEBUG("[%05i] %s\n", id, type_name(type));
    pthread_mutex_unlock(&sshfs.lock);

    err = -EIO;
    if (sftp_send_iov(type, id, iov, count) == -1) {
        pthread_mutex_lock(&sshfs.lock);
        g_hash_table_remove(sshfs.reqtab, GUINT_TO_POINTER(id));
        pthread_mutex_unlock(&sshfs.lock);
        goto out;
    }
    if (want_reply)
        *reqp = req;
    return 0;

 out:
    req->error = err;
    if (!want_reply)
        sftp_request_wait(req, type, 0, NULL);
    else
        *reqp = req;

    return err;
}


static int sftp_request_iov(uint8_t type, struct iovec *iov, size_t count,
                            uint8_t expect_type, struct buffer *outbuf)
{
    struct request *req;

    sftp_request_send(type, iov, count, NULL, NULL, expect_type, NULL, &req);
    if (expect_type == 0)
        return 0;

    return sftp_request_wait(req, type, expect_type, outbuf);
}

static int sftp_request(uint8_t type, const struct buffer *buf,
                        uint8_t expect_type, struct buffer *outbuf)
{
    struct iovec iov;

    buf_to_iov(buf, &iov);
    return sftp_request_iov(type, &iov, 1, expect_type, outbuf);
}

static int sshfs_getattr(const char *path, struct stat *stbuf)
{
    int err;
    struct buffer buf;
    struct buffer outbuf;
    buf_init(&buf, 0);
    buf_add_path(&buf, path);
    err = sftp_request(sshfs.follow_symlinks ? SSH_FXP_STAT : SSH_FXP_LSTAT,
                       &buf, SSH_FXP_ATTRS, &outbuf);
    if (!err) {
        if (buf_get_attrs(&outbuf, stbuf, NULL) == -1)
            err = -EIO;
        buf_free(&outbuf);
    }
    buf_free(&buf);
    return err;
}

static int count_components(const char *p)
{
    int ctr;

    for (; *p == '/'; p++);
    for (ctr = 0; *p; ctr++) {
        for (; *p && *p != '/'; p++);
        for (; *p == '/'; p++);
    }
    return ctr;
}

static void strip_common(const char **sp, const char **tp)
{
    const char *s = *sp;
    const char *t = *tp;
    do {
        for (; *s == '/'; s++);
        for (; *t == '/'; t++);
        *tp = t;
        *sp = s;
        for (; *s == *t && *s && *s != '/'; s++, t++);
    } while ((*s == *t && *s) || (!*s && *t == '/') || (*s == '/' && !*t));
}

static void transform_symlink(const char *path, char **linkp)
{
    const char *l = *linkp;
    const char *b = sshfs.base_path;
    char *newlink;
    char *s;
    int dotdots;
    int i;

    if (l[0] != '/' || b[0] != '/')
        return;

    strip_common(&l, &b);
    if (*b)
        return;

    strip_common(&l, &path);
    dotdots = count_components(path);
    if (!dotdots)
        return;
    dotdots--;

    newlink = malloc(dotdots * 3 + strlen(l) + 2);
    if (!newlink) {
        fprintf(stderr, "sshfs: memory allocation failed\n");
        exit(1);
    }
    for (s = newlink, i = 0; i < dotdots; i++, s += 3)
        strcpy(s, "../");

    if (l[0])
        strcpy(s, l);
    else if (!dotdots)
        strcpy(s, ".");
    else
        s[0] = '\0';

    free(*linkp);
    *linkp = newlink;
}

static int sshfs_readlink(const char *path, char *linkbuf, size_t size)
{
    int err;
    struct buffer buf;
    struct buffer name;

    assert(size > 0);

    if (sshfs.server_version < 3)
        return -EPERM;

    buf_init(&buf, 0);
    buf_add_path(&buf, path);
    err = sftp_request(SSH_FXP_READLINK, &buf, SSH_FXP_NAME, &name);
    if (!err) {
        uint32_t count;
        char *link;
        err = -EIO;
        if(buf_get_uint32(&name, &count) != -1 && count == 1 &&
           buf_get_string(&name, &link) != -1) {
            if (sshfs.transform_symlinks)
                transform_symlink(path, &link);
            strncpy(linkbuf, link, size - 1);
            linkbuf[size - 1] = '\0';
            free(link);
            err = 0;
        }
        buf_free(&name);
    }
    buf_free(&buf);
    return err;
}

static int sshfs_getdir(const char *path, fuse_cache_dirh_t h,
                        fuse_cache_dirfil_t filler)
{
    int err;
    struct buffer buf;
    struct buffer handle;
    buf_init(&buf, 0);
    buf_add_path(&buf, path);
    err = sftp_request(SSH_FXP_OPENDIR, &buf, SSH_FXP_HANDLE, &handle);
    if (!err) {
        int err2;
        buf_finish(&handle);
        do {
            struct buffer name;
            err = sftp_request(SSH_FXP_READDIR, &handle, SSH_FXP_NAME, &name);
            if (!err) {
                if (buf_get_entries(&name, h, filler) == -1)
                    err = -EIO;
                buf_free(&name);
            }
        } while (!err);
        if (err == MY_EOF)
            err = 0;

        err2 = sftp_request(SSH_FXP_CLOSE, &handle, 0, NULL);
        if (!err)
            err = err2;
        buf_free(&handle);
    }
    buf_free(&buf);
    return err;
}

static int sshfs_mkdir(const char *path, mode_t mode)
{
    int err;
    struct buffer buf;
    buf_init(&buf, 0);
    buf_add_path(&buf, path);
    buf_add_uint32(&buf, SSH_FILEXFER_ATTR_PERMISSIONS);
    buf_add_uint32(&buf, mode);
    err = sftp_request(SSH_FXP_MKDIR, &buf, SSH_FXP_STATUS, NULL);
    buf_free(&buf);
    return err;
}

static int sshfs_mknod(const char *path, mode_t mode, dev_t rdev)
{
    int err;
    struct buffer buf;
    struct buffer handle;
    (void) rdev;

    if ((mode & S_IFMT) != S_IFREG)
        return -EPERM;

    buf_init(&buf, 0);
    buf_add_path(&buf, path);
    buf_add_uint32(&buf, SSH_FXF_WRITE | SSH_FXF_CREAT | SSH_FXF_EXCL);
    buf_add_uint32(&buf, SSH_FILEXFER_ATTR_PERMISSIONS);
    buf_add_uint32(&buf, mode);
    err = sftp_request(SSH_FXP_OPEN, &buf, SSH_FXP_HANDLE, &handle);
    if (!err) {
        int err2;
        buf_finish(&handle);
        err2 = sftp_request(SSH_FXP_CLOSE, &handle, SSH_FXP_STATUS, NULL);
        if (!err)
            err = err2;
        buf_free(&handle);
    }
    buf_free(&buf);
    return err;
}

static int sshfs_symlink(const char *from, const char *to)
{
    int err;
    struct buffer buf;

    if (sshfs.server_version < 3)
        return -EPERM;

    /* openssh sftp server doesn't follow standard: link target and
       link name are mixed up, so we must also be non-standard :( */
    buf_init(&buf, 0);
    buf_add_string(&buf, from);
    buf_add_path(&buf, to);
    err = sftp_request(SSH_FXP_SYMLINK, &buf, SSH_FXP_STATUS, NULL);
    buf_free(&buf);
    return err;
}

static int sshfs_unlink(const char *path)
{
    int err;
    struct buffer buf;
    buf_init(&buf, 0);
    buf_add_path(&buf, path);
    err = sftp_request(SSH_FXP_REMOVE, &buf, SSH_FXP_STATUS, NULL);
    buf_free(&buf);
    return err;
}

static int sshfs_rmdir(const char *path)
{
    int err;
    struct buffer buf;
    buf_init(&buf, 0);
    buf_add_path(&buf, path);
    err = sftp_request(SSH_FXP_RMDIR, &buf, SSH_FXP_STATUS, NULL);
    buf_free(&buf);
    return err;
}

static int sshfs_do_rename(const char *from, const char *to)
{
    int err;
    struct buffer buf;
    buf_init(&buf, 0);
    buf_add_path(&buf, from);
    buf_add_path(&buf, to);
    err = sftp_request(SSH_FXP_RENAME, &buf, SSH_FXP_STATUS, NULL);
    buf_free(&buf);
    return err;
}

static void random_string(char *str, int length)
{
    int i;
    for (i = 0; i < length; i++)
        *str++ = (char)('0' + rand_r(&sshfs.randseed) % 10);
    *str = '\0';
}

static int sshfs_rename(const char *from, const char *to)
{
    int err;
    err = sshfs_do_rename(from, to);
    if (err == -EPERM && sshfs.rename_workaround) {
        size_t tolen = strlen(to);
        if (tolen + RENAME_TEMP_CHARS < PATH_MAX) {
            int tmperr;
            char totmp[PATH_MAX];
            strcpy(totmp, to);
            random_string(totmp + tolen, RENAME_TEMP_CHARS);
            tmperr = sshfs_do_rename(to, totmp);
            if (!tmperr) {
                err = sshfs_do_rename(from, to);
                if (!err)
                    err = sshfs_unlink(totmp);
                else
                    sshfs_do_rename(totmp, to);
            }
        }
    }
    return err;
}

static int sshfs_chmod(const char *path, mode_t mode)
{
    int err;
    struct buffer buf;
    buf_init(&buf, 0);
    buf_add_path(&buf, path);
    buf_add_uint32(&buf, SSH_FILEXFER_ATTR_PERMISSIONS);
    buf_add_uint32(&buf, mode);
    err = sftp_request(SSH_FXP_SETSTAT, &buf, SSH_FXP_STATUS, NULL);
    buf_free(&buf);
    return err;
}

static int sshfs_chown(const char *path, uid_t uid, gid_t gid)
{
    int err;
    struct buffer buf;
    buf_init(&buf, 0);
    buf_add_path(&buf, path);
    buf_add_uint32(&buf, SSH_FILEXFER_ATTR_UIDGID);
    buf_add_uint32(&buf, uid);
    buf_add_uint32(&buf, gid);
    err = sftp_request(SSH_FXP_SETSTAT, &buf, SSH_FXP_STATUS, NULL);
    buf_free(&buf);
    return err;
}

static int sshfs_truncate_workaround(const char *path, off_t size,
                                     struct fuse_file_info *fi);

static int sshfs_truncate(const char *path, off_t size)
{
    int err;
    struct buffer buf;

    sshfs.modifver ++;
    if (size == 0 || sshfs.truncate_workaround)
        return sshfs_truncate_workaround(path, size, NULL);

    buf_init(&buf, 0);
    buf_add_path(&buf, path);
    buf_add_uint32(&buf, SSH_FILEXFER_ATTR_SIZE);
    buf_add_uint64(&buf, size);
    err = sftp_request(SSH_FXP_SETSTAT, &buf, SSH_FXP_STATUS, NULL);
    buf_free(&buf);
    return err;
}

static int sshfs_utime(const char *path, struct utimbuf *ubuf)
{
    int err;
    struct buffer buf;
    buf_init(&buf, 0);
    buf_add_path(&buf, path);
    buf_add_uint32(&buf, SSH_FILEXFER_ATTR_ACMODTIME);
    buf_add_uint32(&buf, ubuf->actime);
    buf_add_uint32(&buf, ubuf->modtime);
    err = sftp_request(SSH_FXP_SETSTAT, &buf, SSH_FXP_STATUS, NULL);
    buf_free(&buf);
    return err;
}

static inline int sshfs_file_is_conn(struct sshfs_file *sf)
{
    return sf->connver == sshfs.connver;
}

static int sshfs_open_common(const char *path, mode_t mode,
                             struct fuse_file_info *fi)
{
    int err;
    int err2;
    struct buffer buf;
    struct buffer outbuf;
    struct stat stbuf;
    struct sshfs_file *sf;
    struct request *open_req;
    uint32_t pflags = 0;
    struct iovec iov;

    if ((fi->flags & O_ACCMODE) == O_RDONLY)
        pflags = SSH_FXF_READ;
    else if((fi->flags & O_ACCMODE) == O_WRONLY)
        pflags = SSH_FXF_WRITE;
    else if ((fi->flags & O_ACCMODE) == O_RDWR)
        pflags = SSH_FXF_READ | SSH_FXF_WRITE;
    else
        return -EINVAL;

    if (fi->flags & O_CREAT)
        pflags |= SSH_FXF_CREAT;

    if (fi->flags & O_EXCL)
        pflags |= SSH_FXF_EXCL;

    if (fi->flags & O_TRUNC)
        pflags |= SSH_FXF_TRUNC;

    sf = g_new0(struct sshfs_file, 1);
    list_init(&sf->write_reqs);
    pthread_cond_init(&sf->write_finished, NULL);
    /* Assume random read after open */
    sf->is_seq = 0;
    sf->refs = 1;
    sf->next_pos = 0;
    sf->modifver= sshfs.modifver;
    sf->connver = sshfs.connver;
    buf_init(&buf, 0);
    buf_add_path(&buf, path);
    buf_add_uint32(&buf, pflags);
    buf_add_uint32(&buf, SSH_FILEXFER_ATTR_PERMISSIONS);
    buf_add_uint32(&buf, mode);
    buf_to_iov(&buf, &iov);
    sftp_request_send(SSH_FXP_OPEN, &iov, 1, NULL, NULL, 1, NULL, &open_req);
    buf_clear(&buf);
    buf_add_path(&buf, path);
    err2 = sftp_request(sshfs.follow_symlinks ? SSH_FXP_STAT : SSH_FXP_LSTAT,
                        &buf, SSH_FXP_ATTRS, &outbuf);
    if (!err2 && buf_get_attrs(&outbuf, &stbuf, NULL) == -1)
        err2 = -EIO;
    err = sftp_request_wait(open_req, SSH_FXP_OPEN, SSH_FXP_HANDLE,
                            &sf->handle);
    if (!err && err2) {
        buf_finish(&sf->handle);
        sftp_request(SSH_FXP_CLOSE, &sf->handle, 0, NULL);
        buf_free(&sf->handle);
        err = err2;
    }

    if (!err) {
        cache_add_attr(path, &stbuf);
        buf_finish(&sf->handle);
        fi->fh = (unsigned long) sf;
    } else {
        cache_invalidate(path);
        g_free(sf);
    }
    buf_free(&buf);
    return err;
}

static int sshfs_open(const char *path, struct fuse_file_info *fi)
{
    return sshfs_open_common(path, 0, fi);
}

static inline struct sshfs_file *get_sshfs_file(struct fuse_file_info *fi)
{
    return (struct sshfs_file *) (uintptr_t) fi->fh;
}

static int sshfs_flush(const char *path, struct fuse_file_info *fi)
{
    int err;
    struct sshfs_file *sf = get_sshfs_file(fi);
    struct list_head write_reqs;
    struct list_head *curr_list;

    if (!sshfs_file_is_conn(sf))
        return -EIO;

    if (sshfs.sync_write)
        return 0;

    (void) path;
    pthread_mutex_lock(&sshfs.lock);
    if (!list_empty(&sf->write_reqs)) {
        curr_list = sf->write_reqs.prev;
        list_del(&sf->write_reqs);
        list_init(&sf->write_reqs);
        list_add(&write_reqs, curr_list);
        while (!list_empty(&write_reqs))
            pthread_cond_wait(&sf->write_finished, &sshfs.lock);
    }
    err = sf->write_error;
    sf->write_error = 0;
    pthread_mutex_unlock(&sshfs.lock);
    return err;
}

static int sshfs_fsync(const char *path, int isdatasync,
                       struct fuse_file_info *fi)
{
    (void) isdatasync;
    return sshfs_flush(path, fi);
}

static void sshfs_file_put(struct sshfs_file *sf)
{
    sf->refs--;
    if (!sf->refs)
        g_free(sf);
}

static struct sshfs_file *sshfs_file_get(struct sshfs_file *sf)
{
    sf->refs++;
    return sf;
}

static int sshfs_release(const char *path, struct fuse_file_info *fi)
{
    struct sshfs_file *sf = get_sshfs_file(fi);
    struct buffer *handle = &sf->handle;
    if (sshfs_file_is_conn(sf)) {
        sshfs_flush(path, fi);
        sftp_request(SSH_FXP_CLOSE, handle, 0, NULL);
    }
    buf_free(handle);
    chunk_put_locked(sf->readahead);
    sshfs_file_put(sf);
    return 0;
}

static int sshfs_sync_read(struct sshfs_file *sf, char *rbuf, size_t size,
                           off_t offset)
{
    int err;
    struct buffer buf;
    struct buffer data;
    struct buffer *handle = &sf->handle;
    buf_init(&buf, 0);
    buf_add_buf(&buf, handle);
    buf_add_uint64(&buf, offset);
    buf_add_uint32(&buf, size);
    err = sftp_request(SSH_FXP_READ, &buf, SSH_FXP_DATA, &data);
    if (!err) {
        uint32_t retsize;
        err = -EIO;
        if (buf_get_uint32(&data, &retsize) != -1) {
            if (retsize > size)
                fprintf(stderr, "long read\n");
            else {
                buf_get_mem(&data, rbuf, retsize);
                err = retsize;
            }
        }
        buf_free(&data);
    } else if (err == MY_EOF)
        err = 0;
    buf_free(&buf);
    return err;
}

static void sshfs_read_end(struct request *req)
{
    struct read_chunk *chunk = (struct read_chunk *) req->data;
    if (req->error)
        chunk->res = req->error;
    else if (req->replied) {
        chunk->res = -EIO;

        if (req->reply_type == SSH_FXP_STATUS) {
            uint32_t serr;
            if (buf_get_uint32(&req->reply, &serr) != -1) {
                if (serr == SSH_FX_EOF)
                    chunk->res = 0;
            }
        } else if (req->reply_type == SSH_FXP_DATA) {
            uint32_t retsize;
            if (buf_get_uint32(&req->reply, &retsize) != -1) {
                if (retsize > chunk->size)
                    fprintf(stderr, "long read\n");
                else {
                    chunk->res = retsize;
                    chunk->data = req->reply;
                    buf_init(&req->reply, 0);
                }
            }
        } else
            fprintf(stderr, "protocol error\n");
    } else
        chunk->res = -EIO;

    sem_post(&chunk->ready);
    chunk_put(chunk);
}

static void sshfs_read_begin(struct request *req)
{
    struct read_chunk *chunk = (struct read_chunk *) req->data;
    chunk->refs++;
}

static void sshfs_send_async_read(struct sshfs_file *sf,
                                  struct read_chunk *chunk)
{
    struct buffer buf;
    struct buffer *handle = &sf->handle;
    struct iovec iov;

    buf_init(&buf, 0);
    buf_add_buf(&buf, handle);
    buf_add_uint64(&buf, chunk->offset);
    buf_add_uint32(&buf, chunk->size);
    buf_to_iov(&buf, &iov);
    sftp_request_send(SSH_FXP_READ, &iov, 1, sshfs_read_begin, sshfs_read_end,
                       0, chunk, NULL);
    buf_free(&buf);
}

static void submit_read(struct sshfs_file *sf, size_t size, off_t offset,
                        struct read_chunk **chunkp)
{
    struct read_chunk *chunk = g_new0(struct read_chunk, 1);

    sem_init(&chunk->ready, 0, 0);
    buf_init(&chunk->data, 0);
    chunk->offset = offset;
    chunk->size = size;
    chunk->refs = 1;
    chunk->modifver = sshfs.modifver;
    sshfs_send_async_read(sf, chunk);
    pthread_mutex_lock(&sshfs.lock);
    chunk_put(*chunkp);
    *chunkp = chunk;
    pthread_mutex_unlock(&sshfs.lock);
}

static int wait_chunk(struct read_chunk *chunk, char *buf, size_t size)
{
    int res;
    sem_wait(&chunk->ready);
    res = chunk->res;
    if (res > 0) {
        if ((size_t) res > size)
            res = size;
        buf_get_mem(&chunk->data, buf, res);
        chunk->offset += res;
        chunk->size -= res;
        chunk->res -= res;
    }
    sem_post(&chunk->ready);
    chunk_put_locked(chunk);
    return res;
}

static struct read_chunk *search_read_chunk(struct sshfs_file *sf, off_t offset)
{
    struct read_chunk *ch = sf->readahead;
    if (ch && ch->offset == offset && ch->modifver == sshfs.modifver) {
        ch->refs++;
        return ch;
    } else
        return NULL;
}

static int sshfs_async_read(struct sshfs_file *sf, char *rbuf, size_t size,
                            off_t offset)
{
    int res = 0;
    size_t total = 0;
    struct read_chunk *chunk;
    struct read_chunk *chunk_prev = NULL;
    size_t origsize = size;
    int curr_is_seq;

    pthread_mutex_lock(&sshfs.lock);
    curr_is_seq = sf->is_seq;
    sf->is_seq = (sf->next_pos == offset && sf->modifver == sshfs.modifver);
    sf->next_pos = offset + size;
    sf->modifver = sshfs.modifver;
    chunk = search_read_chunk(sf, offset);
    pthread_mutex_unlock(&sshfs.lock);

    if (chunk && chunk->size < size) {
        chunk_prev = chunk;
        size -= chunk->size;
        offset += chunk->size;
        chunk = NULL;
    }

    if (!chunk)
        submit_read(sf, size, offset, &chunk);

    if (curr_is_seq && chunk && chunk->size <= size)
        submit_read(sf, origsize, offset + size, &sf->readahead);

    if (chunk_prev) {
        size_t prev_size = chunk_prev->size;
        res = wait_chunk(chunk_prev, rbuf, prev_size);
        if (res < (int) prev_size) {
            chunk_put_locked(chunk);
            return res;
        }
        rbuf += res;
        total += res;
    }
    res = wait_chunk(chunk, rbuf, size);
    if (res > 0)
        total += res;
    if (res < 0)
        return res;

    return total;
}

static int sshfs_read(const char *path, char *rbuf, size_t size, off_t offset,
                      struct fuse_file_info *fi)
{
    struct sshfs_file *sf = get_sshfs_file(fi);
    (void) path;

    if (!sshfs_file_is_conn(sf))
        return -EIO;

    if (sshfs.sync_read)
        return sshfs_sync_read(sf, rbuf, size, offset);
    else
        return sshfs_async_read(sf, rbuf, size, offset);
}

static void sshfs_write_begin(struct request *req)
{
    struct sshfs_file *sf = (struct sshfs_file *) req->data;
    list_add(&req->list, &sf->write_reqs);
}

static void sshfs_write_end(struct request *req)
{
    uint32_t serr;
    struct sshfs_file *sf = (struct sshfs_file *) req->data;

    if (req->error)
        sf->write_error = req->error;
    else if (req->replied) {
        if (req->reply_type != SSH_FXP_STATUS)
            fprintf(stderr, "protocol error\n");
        else if (buf_get_uint32(&req->reply, &serr) != -1 && serr != SSH_FX_OK)
            sf->write_error = -EIO;
    }
    list_del(&req->list);
    pthread_cond_broadcast(&sf->write_finished);
    sshfs_file_put(sf);
}

static int sshfs_write(const char *path, const char *wbuf, size_t size,
                       off_t offset, struct fuse_file_info *fi)
{
    int err;
    struct buffer buf;
    struct sshfs_file *sf = get_sshfs_file(fi);
    struct buffer *handle = &sf->handle;
    struct iovec iov[2];

    (void) path;

    if (!sshfs_file_is_conn(sf))
        return -EIO;

    sshfs.modifver ++;
    buf_init(&buf, 0);
    buf_add_buf(&buf, handle);
    buf_add_uint64(&buf, offset);
    buf_add_uint32(&buf, size);
    buf_to_iov(&buf, &iov[0]);
    iov[1].iov_base = (void *) wbuf;
    iov[1].iov_len = size;
    if (!sshfs.sync_write && !sf->write_error)
        err = sftp_request_send(SSH_FXP_WRITE, iov, 2, sshfs_write_begin,
                                 sshfs_write_end, 0, sshfs_file_get(sf), NULL);
    else
        err = sftp_request_iov(SSH_FXP_WRITE, iov, 2, SSH_FXP_STATUS, NULL);
    buf_free(&buf);
    return err ? err : (int) size;
}

#if FUSE_VERSION >= 25
static int sshfs_statfs(const char *path, struct statvfs *buf)
{
    (void) path;

    buf->f_namemax = 255;
    buf->f_bsize = sshfs.blksize;
    /* df seems to use f_bsize instead of f_frsize, so make them the same */
    buf->f_frsize = buf->f_bsize;
    buf->f_blocks = buf->f_bfree =  buf->f_bavail =
        1000ULL * 1024 * 1024 * 1024 / buf->f_frsize;
    buf->f_files = buf->f_ffree = 1000000000;
    return 0;
}
#else
static int sshfs_statfs(const char *path, struct statfs *buf)
{
    (void) path;

    buf->f_namelen = 255;
    buf->f_bsize = sshfs.blksize;
    buf->f_blocks = buf->f_bfree = buf->f_bavail =
        1000ULL * 1024 * 1024 * 1024 / buf->f_bsize;
    buf->f_files = buf->f_ffree = 1000000000;
    return 0;
}
#endif

#if FUSE_VERSION >= 25
static int sshfs_create(const char *path, mode_t mode,
                        struct fuse_file_info *fi)
{
    return sshfs_open_common(path, mode, fi);
}

static int sshfs_ftruncate(const char *path, off_t size,
                           struct fuse_file_info *fi)
{
    int err;
    struct buffer buf;
    struct sshfs_file *sf = get_sshfs_file(fi);

    (void) path;

    if (!sshfs_file_is_conn(sf))
        return -EIO;

    sshfs.modifver ++;
    if (sshfs.truncate_workaround)
        return sshfs_truncate_workaround(path, size, fi);

    buf_init(&buf, 0);
    buf_add_buf(&buf, &sf->handle);
    buf_add_uint32(&buf, SSH_FILEXFER_ATTR_SIZE);
    buf_add_uint64(&buf, size);
    err = sftp_request(SSH_FXP_FSETSTAT, &buf, SSH_FXP_STATUS, NULL);
    buf_free(&buf);

    return err;
}
#endif

static int sshfs_fgetattr(const char *path, struct stat *stbuf,
                           struct fuse_file_info *fi)
{
    int err;
    struct buffer buf;
    struct buffer outbuf;
    struct sshfs_file *sf = get_sshfs_file(fi);

    (void) path;

    if (!sshfs_file_is_conn(sf))
        return -EIO;

    buf_init(&buf, 0);
    buf_add_buf(&buf, &sf->handle);
    err = sftp_request(SSH_FXP_FSTAT, &buf, SSH_FXP_ATTRS, &outbuf);
    if (!err) {
        if (buf_get_attrs(&outbuf, stbuf, NULL) == -1)
            err = -EIO;
        buf_free(&outbuf);
    }
    buf_free(&buf);
    return err;
}

static int sshfs_truncate_zero(const char *path)
{
    int err;
    struct fuse_file_info fi;

    fi.flags = O_WRONLY | O_TRUNC;
    err = sshfs_open(path, &fi);
    if (!err)
        sshfs_release(path, &fi);

    return err;
}

static size_t calc_buf_size(off_t size, off_t offset)
{
    return offset + sshfs.max_read < size ? sshfs.max_read : size - offset;
}

static int sshfs_truncate_shrink(const char *path, off_t size)
{
    int res;
    char *data;
    off_t offset;
    struct fuse_file_info fi;

    data = calloc(size, 1);
    if (!data)
        return -ENOMEM;

    fi.flags = O_RDONLY;
    res = sshfs_open(path, &fi);
    if (res)
        goto out;

    for (offset = 0; offset < size; offset += res) {
        size_t bufsize = calc_buf_size(size, offset);
        res = sshfs_read(path, data + offset, bufsize, offset, &fi);
        if (res <= 0)
            break;
    }
    sshfs_release(path, &fi);
    if (res < 0)
        goto out;

    fi.flags = O_WRONLY | O_TRUNC;
    res = sshfs_open(path, &fi);
    if (res)
        goto out;

    for (offset = 0; offset < size; offset += res) {
        size_t bufsize = calc_buf_size(size, offset);
        res = sshfs_write(path, data + offset, bufsize, offset, &fi);
        if (res < 0)
            break;
    }
    if (res >= 0)
        res = sshfs_flush(path, &fi);
    sshfs_release(path, &fi);

 out:
    free(data);
    return res;
}

static int sshfs_truncate_extend(const char *path, off_t size,
                                 struct fuse_file_info *fi)
{
    int res;
    char c = 0;
    struct fuse_file_info tmpfi;
    struct fuse_file_info *openfi = fi;
    if (!fi) {
        openfi = &tmpfi;
        openfi->flags = O_WRONLY;
        res = sshfs_open(path, openfi);
        if (res)
            return res;
    }
    res = sshfs_write(path, &c, 1, size - 1, openfi);
    if (res == 1)
        res = sshfs_flush(path, openfi);
    if (!fi)
        sshfs_release(path, openfi);

    return res;
}

/*
 * Work around broken sftp servers which don't handle
 * SSH_FILEXFER_ATTR_SIZE in SETSTAT request.
 *
 * If new size is zero, just open the file with O_TRUNC.
 *
 * If new size is smaller than current size, then copy file locally,
 * then open/trunc and send it back.
 *
 * If new size is greater than current size, then write a zero byte to
 * the new end of the file.
 */
static int sshfs_truncate_workaround(const char *path, off_t size,
                                     struct fuse_file_info *fi)
{
    if (size == 0)
        return sshfs_truncate_zero(path);
    else {
        struct stat stbuf;
        int err;
        if (fi)
            err = sshfs_fgetattr(path, &stbuf, fi);
        else
            err = sshfs_getattr(path, &stbuf);
        if (err)
            return err;
        if (stbuf.st_size == size)
            return 0;
        else if (stbuf.st_size > size)
            return sshfs_truncate_shrink(path, size);
        else
            return sshfs_truncate_extend(path, size, fi);
    }
}

static int processing_init(void)
{
    pthread_mutex_init(&sshfs.lock, NULL);
    pthread_mutex_init(&sshfs.lock_write, NULL);
    sshfs.reqtab = g_hash_table_new(NULL, NULL);
    if (!sshfs.reqtab) {
        fprintf(stderr, "failed to create hash table\n");
        return -1;
    }
    return 0;
}

static struct fuse_cache_operations sshfs_oper = {
    .oper = {
#ifdef SSHFS_USE_INIT
        .init       = sshfs_init,
#endif
        .getattr    = sshfs_getattr,
        .readlink   = sshfs_readlink,
        .mknod      = sshfs_mknod,
        .mkdir      = sshfs_mkdir,
        .symlink    = sshfs_symlink,
        .unlink     = sshfs_unlink,
        .rmdir      = sshfs_rmdir,
        .rename     = sshfs_rename,
        .chmod      = sshfs_chmod,
        .chown      = sshfs_chown,
        .truncate   = sshfs_truncate,
        .utime      = sshfs_utime,
        .open       = sshfs_open,
        .flush      = sshfs_flush,
        .fsync      = sshfs_fsync,
        .release    = sshfs_release,
        .read       = sshfs_read,
        .write      = sshfs_write,
        .statfs     = sshfs_statfs,
#if FUSE_VERSION >= 25
        .create     = sshfs_create,
        .ftruncate  = sshfs_ftruncate,
        .fgetattr   = sshfs_fgetattr,
#endif
    },
    .cache_getdir = sshfs_getdir,
};

static void usage(const char *progname)
{
    fprintf(stderr,
"usage: %s [user@]host:[dir] mountpoint [options]\n"
"\n"
"general options:\n"
"    -o opt,[opt...]        mount options\n"
"    -h   --help            print help\n"
"    -V   --version         print version\n"
"\n"
"SSHFS options:\n"
"    -p PORT                equivalent to '-o port=PORT'\n"
"    -C                     equivalent to '-o compression=yes'\n"
"    -1                     equivalent to '-o ssh_protocol=1'\n"
"    -o reconnect           reconnect to server\n"
"    -o sshfs_sync          synchronous writes\n"
"    -o no_readahead        synchronous reads (no speculative readahead)\n"
"    -o sshfs_debug         print some debugging information\n"
"    -o cache=YESNO         enable caching {yes,no} (default: yes)\n"
"    -o cache_timeout=N     sets timeout for caches in seconds (default: 20)\n"
"    -o cache_X_timeout=N   sets timeout for {stat,dir,link} cache\n"
"    -o workaround=LIST     colon separated list of workarounds\n"
"             none             no workarounds enabled\n"
"             all              all workarounds enabled\n"
"             [no]rename       fix renaming to existing file (default: off)\n"
"             [no]nodelay      set nodelay tcp flag in ssh (default: on)\n"
"             [no]nodelaysrv   set nodelay tcp flag in sshd (default: on)\n"
"             [no]truncate     fix truncate for old servers (default: off)\n"
"    -o idmap=TYPE          user/group ID mapping, possible types are:\n"
"             none             no translation of the ID space (default)\n"
"             user             only translate UID of connecting user\n"
"    -o ssh_command=CMD     execute CMD instead of 'ssh'\n"
"    -o ssh_protocol=N      ssh protocol to use (default: 2)\n"
"    -o sftp_server=SERV    path to sftp server or subsystem (default: sftp)\n"
"    -o directport=PORT     directly connect to PORT bypassing ssh\n"
"    -o transform_symlinks  transform absolute symlinks to relative\n"
"    -o follow_symlinks     follow symlinks on the server\n"
"    -o no_check_root       don't check for existence of 'dir' on server\n"
"    -o SSHOPT=VAL          ssh options (see man ssh_config)\n"
"\n", progname);
}

static int is_ssh_opt(const char *arg)
{
    if (arg[0] != '-') {
        unsigned arglen = strlen(arg);
        const char **o;
        for (o = ssh_opts; *o; o++) {
            unsigned olen = strlen(*o);
            if (arglen > olen && arg[olen] == '=' &&
                strncasecmp(arg, *o, olen) == 0)
                return 1;
        }
    }
    return 0;
}

static int sshfs_fuse_main(struct fuse_args *args)
{
#if FUSE_VERSION >= 26
    return fuse_main(args->argc, args->argv, cache_init(&sshfs_oper), NULL);
#else
    return fuse_main(args->argc, args->argv, cache_init(&sshfs_oper));
#endif
}

static int sshfs_opt_proc(void *data, const char *arg, int key,
                          struct fuse_args *outargs)
{
    char *tmp;
    (void) data;

    switch (key) {
    case FUSE_OPT_KEY_OPT:
        if (is_ssh_opt(arg)) {
            tmp = g_strdup_printf("-o%s", arg);
            ssh_add_arg(tmp);
            g_free(tmp);
            return 0;
        }
        return 1;

    case FUSE_OPT_KEY_NONOPT:
        if (!sshfs.host && strchr(arg, ':')) {
            sshfs.host = strdup(arg);
            return 0;
        }
        return 1;

    case KEY_PORT:
        tmp = g_strdup_printf("-oPort=%s", arg + 2);
        ssh_add_arg(tmp);
        g_free(tmp);
        return 0;

    case KEY_COMPRESS:
        ssh_add_arg("-oCompression=yes");
        return 0;

    case KEY_HELP:
        usage(outargs->argv[0]);
        fuse_opt_add_arg(outargs, "-ho");
        sshfs_fuse_main(outargs);
        exit(1);

    case KEY_VERSION:
        fprintf(stderr, "SSHFS version %s\n", PACKAGE_VERSION);
#if FUSE_VERSION >= 25
        fuse_opt_add_arg(outargs, "--version");
        sshfs_fuse_main(outargs);
#endif
        exit(0);

    default:
        fprintf(stderr, "internal error\n");
        abort();
    }
}

static int workaround_opt_proc(void *data, const char *arg, int key,
                                struct fuse_args *outargs)
{
    (void) data; (void) key; (void) outargs;
    fprintf(stderr, "unknown workaround: '%s'\n", arg);
    return -1;
}

int parse_workarounds(void)
{
    int res;
    char *argv[] = { "", "-o", sshfs.workarounds, NULL };
    struct fuse_args args = FUSE_ARGS_INIT(3, argv);
    char *s = sshfs.workarounds;
    if (!s)
        return 0;

    while ((s = strchr(s, ':')))
           *s = ',';

    res = fuse_opt_parse(&args, &sshfs, workaround_opts, workaround_opt_proc);
    fuse_opt_free_args(&args);

    return res;
}

#if FUSE_VERSION == 25
static int fuse_opt_insert_arg(struct fuse_args *args, int pos,
                               const char *arg)
{
    assert(pos <= args->argc);
    if (fuse_opt_add_arg(args, arg) == -1)
        return -1;

    if (pos != args->argc - 1) {
        char *newarg = args->argv[args->argc - 1];
        memmove(&args->argv[pos + 1], &args->argv[pos],
                sizeof(char *) * (args->argc - pos - 1));
        args->argv[pos] = newarg;
    }
    return 0;
}
#endif

void check_large_read(struct fuse_args *args)
{
    struct utsname buf;
    int err = uname(&buf);
    if (!err && strcmp(buf.sysname, "Linux") == 0 &&
        strncmp(buf.release, "2.4.", 4) == 0)
        fuse_opt_insert_arg(args, 1, "-olarge_read");
}

int main(int argc, char *argv[])
{
    int res;
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
    char *tmp;
    char *fsname;
    char *base_path;
    const char *sftp_server;

    sshfs.blksize = 4096;
    sshfs.max_read = 65536;
    sshfs.nodelay_workaround = 1;
    sshfs.nodelaysrv_workaround = 1;
    sshfs.rename_workaround = 0;
    sshfs.truncate_workaround = 0;
    sshfs.ssh_ver = 2;
    sshfs.progname = argv[0];
    ssh_add_arg("ssh");
    ssh_add_arg("-x");
    ssh_add_arg("-a");
    ssh_add_arg("-oClearAllForwardings=yes");

    if (fuse_opt_parse(&args, &sshfs, sshfs_opts, sshfs_opt_proc) == -1 ||
        parse_workarounds() == -1)
        exit(1);

    if (!sshfs.host) {
        fprintf(stderr, "missing host\n");
        fprintf(stderr, "see `%s -h' for usage\n", argv[0]);
        exit(1);
    }

    fsname = g_strdup(sshfs.host);
    base_path = strchr(sshfs.host, ':');
    *base_path++ = '\0';
    if (base_path[0] && base_path[strlen(base_path)-1] != '/')
        sshfs.base_path = g_strdup_printf("%s/", base_path);
    else
        sshfs.base_path = g_strdup(base_path);

    if (sshfs.ssh_command) {
        free(sshfs.ssh_args.argv[0]);
        sshfs.ssh_args.argv[0] = sshfs.ssh_command;
    }

    tmp = g_strdup_printf("-%i", sshfs.ssh_ver);
    ssh_add_arg(tmp);
    g_free(tmp);
    ssh_add_arg(sshfs.host);
    if (sshfs.sftp_server)
        sftp_server = sshfs.sftp_server;
    else if (sshfs.ssh_ver == 1)
        sftp_server = SFTP_SERVER_PATH;
    else
        sftp_server = "sftp";

    if (sshfs.ssh_ver != 1 && strchr(sftp_server, '/') == NULL)
        ssh_add_arg("-s");

    ssh_add_arg(sftp_server);
    free(sshfs.sftp_server);

    res = processing_init();
    if (res == -1)
        exit(1);

    if (connect_remote() == -1)
        exit(1);

#ifndef SSHFS_USE_INIT
    if (sshfs.detect_uid)
        sftp_detect_uid();
#endif

    if (!sshfs.no_check_root && sftp_check_root(base_path) == -1)
        exit(1);

    res = cache_parse_options(&args);
    if (res == -1)
        exit(1);

    sshfs.randseed = time(0);

    if (sshfs.max_read > 65536)
        sshfs.max_read = 65536;

    if (fuse_is_lib_option("ac_attr_timeout="))
        fuse_opt_insert_arg(&args, 1, "-oauto_cache,ac_attr_timeout=0");
    tmp = g_strdup_printf("-omax_read=%u", sshfs.max_read);
    fuse_opt_insert_arg(&args, 1, tmp);
    g_free(tmp);
    tmp = g_strdup_printf("-ofsname=sshfs#%s", fsname);
    fuse_opt_insert_arg(&args, 1, tmp);
    check_large_read(&args);
    g_free(tmp);
    g_free(fsname);
    res = sshfs_fuse_main(&args);
    fuse_opt_free_args(&args);
    fuse_opt_free_args(&sshfs.ssh_args);
    free(sshfs.directport);

    return res;
}
