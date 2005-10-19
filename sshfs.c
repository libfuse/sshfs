/*
    SSH file system
    Copyright (C) 2004  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

#include "config.h"

#include <fuse.h>
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
#include <sys/time.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <glib.h>

#include "cache.h"
#include "opts.h"

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

static unsigned int randseed;

static int infd;
static int outfd;
static int connver;
static int server_version;
static int debug = 0;
static int reconnect = 0;
static int sync_write = 0;
static int sync_read = 0;
static int rename_workaround = 0;
static int detect_uid = 0;
static unsigned remote_uid;
static unsigned local_uid;
static int remote_uid_detected = 0;
static char *base_path;
static char *host;
static unsigned blksize = 4096;

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
};

static GHashTable *reqtab;
static pthread_mutex_t lock;
static int processing_thread_started;


static struct opt ssh_opts[] = {
    { .optname = "AddressFamily"                    },
    { .optname = "BatchMode"                        },
    { .optname = "BindAddress"                      },
    { .optname = "ChallengeResponseAuthentication"  },
    { .optname = "CheckHostIP"                      },
    { .optname = "Cipher"                           },
    { .optname = "Ciphers"                          },
    { .optname = "Compression"                      },
    { .optname = "CompressionLevel"                 },
    { .optname = "ConnectionAttempts"               },
    { .optname = "ConnectionTimeout"                },
    { .optname = "GlobalKnownHostsFile"             },
    { .optname = "GSSAPIAuthentication"             },
    { .optname = "GSSAPIDelegateCredentials"        },
    { .optname = "HostbasedAuthentication"          },
    { .optname = "HostKeyAlgorithms"                },
    { .optname = "HostKeyAlias"                     },
    { .optname = "HostName"                         },
    { .optname = "IdentityFile"                     },
    { .optname = "IdentitiesOnly"                   },
    { .optname = "LogLevel"                         },
    { .optname = "MACs"                             },
    { .optname = "NoHostAuthenticationForLocalhost" },
    { .optname = "NumberOfPasswordPrompts"          },
    { .optname = "PasswordAuthentication"           },
    { .optname = "Port"                             },
    { .optname = "PreferredAuthentications"         },
    { .optname = "Protocol"                         },
    { .optname = "ProxyCommand"                     },
    { .optname = "PubkeyAuthentication"             },
    { .optname = "RhostsRSAAuthentication"          },
    { .optname = "RSAAuthentication"                },
    { .optname = "ServerAliveInterval"              },
    { .optname = "ServerAliveCountMax"              },
    { .optname = "SmartcardDevice"                  },
    { .optname = "StrictHostKeyChecking"            },
    { .optname = "TCPKeepAlive"                     },
    { .optname = "UsePrivilegedPort"                },
    { .optname = "UserKnownHostsFile"               },
    { .optname = "VerifyHostKeyDNS"                 },
    { .optname = NULL                               }
};

enum {
    SOPT_DIRECTPORT,
    SOPT_SSHCMD,
    SOPT_SYNC_WRITE,
    SOPT_SYNC_READ,
    SOPT_MAX_READ,
    SOPT_DEBUG,
    SOPT_RECONNECT,
    SOPT_RENAME_FIX,
    SOPT_IDMAP,
    SOPT_LAST /* Last entry in this list! */
};

static struct opt sshfs_opts[] = {
    [SOPT_DIRECTPORT] = { .optname = "directport" },
    [SOPT_SSHCMD]     = { .optname = "ssh_command" },
    [SOPT_SYNC_WRITE] = { .optname = "sshfs_sync" },
    [SOPT_SYNC_READ]  = { .optname = "no_readahead" },
    [SOPT_MAX_READ]   = { .optname = "max_read" },
    [SOPT_DEBUG]      = { .optname = "sshfs_debug" },
    [SOPT_RECONNECT]  = { .optname = "reconnect" },
    [SOPT_RENAME_FIX] = { .optname = "rename_workaround" },
    [SOPT_IDMAP] =      { .optname = "idmap" },
    [SOPT_LAST]       = { .optname = NULL }
};

#define DEBUG(format, args...) \
	do { if (debug) fprintf(stderr, format, args); } while(0)

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
        if (!buf->p)
            exit(1);
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
    if (!buf->p)
        exit(1);
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
    char *realpath = g_strdup_printf("%s%s", base_path, path[1] ? path+1 : ".");
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

    if (remote_uid_detected && uid == remote_uid)
        uid = local_uid;

    memset(stbuf, 0, sizeof(struct stat));
    stbuf->st_mode = mode;
    stbuf->st_nlink = 1;
    stbuf->st_size = size;
    if (blksize) {
        stbuf->st_blksize = blksize;
        stbuf->st_blocks = ((size + blksize - 1) & ~(blksize - 1)) >> 9;
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

static int start_ssh(char *host)
{
    int inpipe[2];
    int outpipe[2];
    int i;
    int pid;

    if (pipe(inpipe) == -1 || pipe(outpipe) == -1) {
        perror("failed to create pipe");
        return -1;
    }
    infd = inpipe[0];
    outfd = outpipe[1];

    pid = fork();
    if (pid == -1) {
        perror("failed to fork");
        return -1;
    } else if (pid == 0) {
        int devnull;
        int argctr = 0;
        char *ssh_args[sizeof(ssh_opts)/sizeof(struct opt) + 32];
        char *ssh_cmd;

        devnull = open("/dev/null", O_WRONLY);

        if (sshfs_opts[SOPT_SSHCMD].present)
            ssh_cmd = sshfs_opts[SOPT_SSHCMD].value;
        else
            ssh_cmd = "ssh";

        if (dup2(outpipe[0], 0) == -1 || dup2(inpipe[1], 1) == -1) {
            perror("failed to redirect input/output");
            _exit(1);
        }
        if (!debug && devnull != -1)
            dup2(devnull, 2);

        close(devnull);
        close(inpipe[0]);
        close(inpipe[1]);
        close(outpipe[0]);
        close(outpipe[1]);

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

        ssh_args[argctr++] = ssh_cmd;
        ssh_args[argctr++] = "-2";
        ssh_args[argctr++] = "-x";
        ssh_args[argctr++] = "-a";
        ssh_args[argctr++] = "-oClearAllForwardings=yes";
        for (i = 0; ssh_opts[i].optname != NULL; i++) {
            if (ssh_opts[i].present) {
                char *val = ssh_opts[i].value;
                char *sopt = g_strdup_printf("-o%s=%s", ssh_opts[i].optname,
                                             val ? val : "");
                ssh_args[argctr++] = sopt;
            }
        }
        ssh_args[argctr++] = host;
        ssh_args[argctr++] = "-s";
        ssh_args[argctr++] = "sftp";
        ssh_args[argctr++] = NULL;

        execvp(ssh_cmd, ssh_args);
        _exit(1);
    }
    waitpid(pid, NULL, 0);
    close(inpipe[1]);
    close(outpipe[0]);
    return 0;
}

static int connect_to(char *host, char *port)
{
    int err;
    int sock;
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
    freeaddrinfo(ai);

    infd = sock;
    outfd = sock;
    return 0;
}

static int do_write(struct buffer *buf)
{
    uint8_t *p = buf->p;
    size_t size = buf->len;
    int res;
    while (size) {
        res = write(outfd, p, size);
        if (res == -1) {
            perror("write");
            return -1;
        } else if (res == 0) {
            fprintf(stderr, "zero write\n");
            return -1;
        }
        size -= res;
        p += res;
    }
    return 0;
}

static uint32_t sftp_get_id(void)
{
    static uint32_t idctr;
    return idctr++;
}

static int sftp_send(uint8_t type, struct buffer *buf)
{
    int res;
    struct buffer buf2;
    buf_init(&buf2, 5);
    buf_add_uint32(&buf2, buf->len + 1);
    buf_add_uint8(&buf2, type);
    res = do_write(&buf2);
    if (res != -1)
        res = do_write(buf);
    buf_free(&buf2);
    return res;
}

static int do_read(struct buffer *buf)
{
    int res;
    uint8_t *p = buf->p;
    size_t size = buf->size;
    while (size) {
        res = read(infd, p, size);
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
    pthread_mutex_lock(&lock);
    chunk_put(chunk);
    pthread_mutex_unlock(&lock);
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

        pthread_mutex_lock(&lock);
        req = (struct request *) g_hash_table_lookup(reqtab, (gpointer) id);
        if (req == NULL)
            fprintf(stderr, "request %i not found\n", id);
        else
            g_hash_table_remove(reqtab, (gpointer) id);
        pthread_mutex_unlock(&lock);
        if (req != NULL) {
            struct timeval now;
            unsigned int difftime;
            gettimeofday(&now, NULL);
            difftime = (now.tv_sec - req->start.tv_sec) * 1000;
            difftime += (now.tv_usec - req->start.tv_usec) / 1000;
            DEBUG("  [%05i] %14s %8ibytes (%ims)\n", id, type_name(type),
                  buf.size+5, difftime);
            req->reply = buf;
            req->reply_type = type;
            req->replied = 1;
            if (req->want_reply)
                sem_post(&req->ready);
            else {
                if (req->end_func) {
                    pthread_mutex_lock(&lock);
                    req->end_func(req);
                    pthread_mutex_unlock(&lock);
                }
                request_free(req);
            }
        } else
            buf_free(&buf);
    }
    if (!reconnect) {
        /* harakiri */
        kill(getpid(), SIGTERM);
    } else {
        pthread_mutex_lock(&lock);
        processing_thread_started = 0;
        close(infd);
        infd = -1;
        close(outfd);
        outfd = -1;
        g_hash_table_foreach_remove(reqtab, (GHRFunc) clean_req, NULL);
        connver ++;
        pthread_mutex_unlock(&lock);
    }
    return NULL;
}

static int sftp_init()
{
    int res = -1;
    uint8_t type;
    uint32_t version;
    struct buffer buf;
    buf_init(&buf, 4);
    buf_add_uint32(&buf, PROTO_VERSION);
    if (sftp_send(SSH_FXP_INIT, &buf) == -1)
        goto out;
    buf_clear(&buf);
    if (sftp_read(&type, &buf) == -1)
        goto out;
    if (type != SSH_FXP_VERSION) {
        fprintf(stderr, "protocol error\n");
        goto out;
    }
    if (buf_get_uint32(&buf, &version) == -1)
        goto out;

    server_version = version;
    DEBUG("Server version: %i\n", server_version);
    if (version > PROTO_VERSION)
        fprintf(stderr, "Warning: server uses version: %i, we support: %i\n",
                version, PROTO_VERSION);
    res = 0;

 out:
    buf_free(&buf);
    return res;
}

static void sftp_detect_uid()
{
    int flags;
    int id = sftp_get_id();
    int replid;
    uint8_t type;
    struct buffer buf;
    struct stat stbuf;

    buf_init(&buf, 9);
    buf_add_uint32(&buf, id);
    buf_add_string(&buf, ".");
    if (sftp_send(SSH_FXP_STAT, &buf) == -1)
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

    remote_uid = stbuf.st_uid;
    local_uid = getuid();
    remote_uid_detected = 1;
    DEBUG("remote_uid = %i\n", remote_uid);

 out:
    if (!remote_uid_detected)
        fprintf(stderr, "failed to detect remote user ID\n");

    buf_free(&buf);
}

static int connect_remote(void)
{
    int err;

    if (sshfs_opts[SOPT_DIRECTPORT].present)
        err = connect_to(host, sshfs_opts[SOPT_DIRECTPORT].value);
    else
        err = start_ssh(host);
    if (!err)
        err = sftp_init();

    return err;
}

static int start_processing_thread(void)
{
    int err;
    pthread_t thread_id;
    if (processing_thread_started)
        return 0;

    if (outfd == -1) {
        err = connect_remote();
        if (err)
            return -EIO;
    }

    err = pthread_create(&thread_id, NULL, process_requests, NULL);
    if (err) {
        fprintf(stderr, "failed to create thread: %s\n", strerror(err));
        return -EIO;
    }
    pthread_detach(thread_id);
    processing_thread_started = 1;
    return 0;
}

#ifdef SSHFS_USE_INIT
static void *sshfs_init(void)
{
    if (detect_uid)
        sftp_detect_uid();

    start_processing_thread();
    return NULL;
}
#endif

static int sftp_request_common(uint8_t type, const struct buffer *buf,
                               uint8_t expect_type, struct buffer *outbuf,
                               request_func begin_func, request_func end_func,
                               void *data)
{
    int err;
    struct buffer buf2;
    uint32_t id;
    struct request *req = g_new0(struct request, 1);

    req->want_reply = expect_type != 0 ? 1 : 0;
    req->end_func = end_func;
    req->data = data;
    sem_init(&req->ready, 0, 0);
    buf_init(&req->reply, 0);
    buf_init(&buf2, buf->len + 4);
    pthread_mutex_lock(&lock);
    if (begin_func)
        begin_func(req);
    id = sftp_get_id();
    buf_add_uint32(&buf2, id);
    buf_add_mem(&buf2, buf->p, buf->len);
    err = start_processing_thread();
    if (err) {
        pthread_mutex_unlock(&lock);
        goto out;
    }
    g_hash_table_insert(reqtab, (gpointer) id, req);
    gettimeofday(&req->start, NULL);
    DEBUG("[%05i] %s\n", id, type_name(type));

    err = -EIO;
    if (sftp_send(type, &buf2) == -1) {
        g_hash_table_remove(reqtab, (gpointer) id);
        pthread_mutex_unlock(&lock);
        goto out;
    }
    pthread_mutex_unlock(&lock);

    if (expect_type == 0) {
        buf_free(&buf2);
        return 0;
    }

    sem_wait(&req->ready);
    if (req->error) {
        err = req->error;
        goto out;
    }
    err = -EPROTO;
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
                err = -EPROTO;
            break;

        case SSH_FX_EOF:
            if (type == SSH_FXP_READ || type == SSH_FXP_READDIR)
                err = MY_EOF;
            else
                err = -EPROTO;
            break;

        case SSH_FX_NO_SUCH_FILE:      err = -ENOENT; break;
        case SSH_FX_PERMISSION_DENIED: err = -EACCES; break;
        case SSH_FX_FAILURE:           err = -EPERM;  break;
        case SSH_FX_BAD_MESSAGE:
        default:                       err = -EPROTO; break;
        }
    } else {
        buf_init(outbuf, req->reply.size - req->reply.len);
        buf_get_mem(&req->reply, outbuf->p, outbuf->size);
        err = 0;
    }

 out:
    if (end_func) {
        pthread_mutex_lock(&lock);
        end_func(req);
        pthread_mutex_unlock(&lock);
    }
    buf_free(&buf2);
    request_free(req);
    return err;
}

static int sftp_request(uint8_t type, const struct buffer *buf,
                        uint8_t expect_type, struct buffer *outbuf)
{
    return sftp_request_common(type, buf, expect_type, outbuf, NULL, NULL,
                               NULL);
}

static int sftp_request_async(uint8_t type, const struct buffer *buf,
                              request_func begin_func, request_func end_func,
                              void *data)
{
    return sftp_request_common(type, buf, 0, NULL, begin_func, end_func, data);
}

static int sshfs_getattr(const char *path, struct stat *stbuf)
{
    int err;
    struct buffer buf;
    struct buffer outbuf;
    buf_init(&buf, 0);
    buf_add_path(&buf, path);
    err = sftp_request(SSH_FXP_LSTAT, &buf, SSH_FXP_ATTRS, &outbuf);
    if (!err) {
        if (buf_get_attrs(&outbuf, stbuf, NULL) == -1)
            err = -EPROTO;
        buf_free(&outbuf);
    }
    buf_free(&buf);
    return err;
}

static int sshfs_readlink(const char *path, char *linkbuf, size_t size)
{
    int err;
    struct buffer buf;
    struct buffer name;

    if (server_version < 3)
        return -EPERM;

    buf_init(&buf, 0);
    buf_add_path(&buf, path);
    err = sftp_request(SSH_FXP_READLINK, &buf, SSH_FXP_NAME, &name);
    if (!err) {
        uint32_t count;
        char *link;
        err = -EPROTO;
        if(buf_get_uint32(&name, &count) != -1 && count == 1 &&
           buf_get_string(&name, &link) != -1) {
            strncpy(linkbuf, link, size-1);
            linkbuf[size-1] = '\0';
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
                    err = -EPROTO;
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

    if (server_version < 3)
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
        *str++ = (char)('0' + rand_r(&randseed) % 10);
    *str = '\0';
}

static int sshfs_rename(const char *from, const char *to)
{
    int err;
    err = sshfs_do_rename(from, to);
    if (err == -EPERM && rename_workaround) {
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

static int sshfs_truncate(const char *path, off_t size)
{
    int err;
    struct buffer buf;
    buf_init(&buf, 0);
    buf_add_path(&buf, path);
    if (size == 0) {
        /* If size is zero, use open(..., O_TRUNC), to work around
           broken sftp servers */
        struct buffer handle;
        buf_add_uint32(&buf, SSH_FXF_WRITE | SSH_FXF_TRUNC);
        buf_add_uint32(&buf, 0);
        err = sftp_request(SSH_FXP_OPEN, &buf, SSH_FXP_HANDLE, &handle);
        if (!err) {
            int err2;
            buf_finish(&handle);
            err2 = sftp_request(SSH_FXP_CLOSE, &handle, 0, NULL);
            if (!err)
                err = err2;
            buf_free(&handle);
        }
    } else {
        buf_add_uint32(&buf, SSH_FILEXFER_ATTR_SIZE);
        buf_add_uint64(&buf, size);
        err = sftp_request(SSH_FXP_SETSTAT, &buf, SSH_FXP_STATUS, NULL);
    }
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
    return sf->connver == connver;
}

static int sshfs_open_common(const char *path, mode_t mode,
                             struct fuse_file_info *fi)
{
    int err;
    struct buffer buf;
    struct sshfs_file *sf;
    uint32_t pflags = 0;
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

    sf = g_new0(struct sshfs_file, 1);
    list_init(&sf->write_reqs);
    pthread_cond_init(&sf->write_finished, NULL);
    /* Assume random read after open */
    sf->is_seq = 0;
    sf->next_pos = 0;
    sf->connver = connver;
    buf_init(&buf, 0);
    buf_add_path(&buf, path);
    buf_add_uint32(&buf, pflags);
    buf_add_uint32(&buf, SSH_FILEXFER_ATTR_PERMISSIONS);
    buf_add_uint32(&buf, mode);
    err = sftp_request(SSH_FXP_OPEN, &buf, SSH_FXP_HANDLE, &sf->handle);
    if (!err) {
        buf_finish(&sf->handle);
        fi->fh = (unsigned long) sf;
    } else
        g_free(sf);
    buf_free(&buf);
    return err;
}

static int sshfs_open(const char *path, struct fuse_file_info *fi)
{
    return sshfs_open_common(path, 0, fi);
}

static int sshfs_flush(const char *path, struct fuse_file_info *fi)
{
    int err;
    struct sshfs_file *sf = (struct sshfs_file *) fi->fh;
    struct list_head write_reqs;
    struct list_head *curr_list;

    if (!sshfs_file_is_conn(sf))
        return -EIO;

    if (sync_write)
        return 0;

    (void) path;
    pthread_mutex_lock(&lock);
    if (!list_empty(&sf->write_reqs)) {
        curr_list = sf->write_reqs.prev;
        list_del(&sf->write_reqs);
        list_init(&sf->write_reqs);
        list_add(&write_reqs, curr_list);
        while (!list_empty(&write_reqs))
            pthread_cond_wait(&sf->write_finished, &lock);
    }
    err = sf->write_error;
    sf->write_error = 0;
    pthread_mutex_unlock(&lock);
    return err;
}

static int sshfs_fsync(const char *path, int isdatasync,
                       struct fuse_file_info *fi)
{
    (void) isdatasync;
    return sshfs_flush(path, fi);
}

static int sshfs_release(const char *path, struct fuse_file_info *fi)
{
    struct sshfs_file *sf = (struct sshfs_file *) fi->fh;
    struct buffer *handle = &sf->handle;
    if (sshfs_file_is_conn(sf)) {
        sshfs_flush(path, fi);
        sftp_request(SSH_FXP_CLOSE, handle, 0, NULL);
    }
    buf_free(handle);
    chunk_put_locked(sf->readahead);
    g_free(sf);
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
        err = -EPROTO;
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
        chunk->res = -EPROTO;

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

static int sshfs_send_async_read(struct sshfs_file *sf,
                                 struct read_chunk *chunk)
{
    int err;
    struct buffer buf;
    struct buffer *handle = &sf->handle;
    buf_init(&buf, 0);
    buf_add_buf(&buf, handle);
    buf_add_uint64(&buf, chunk->offset);
    buf_add_uint32(&buf, chunk->size);
    err = sftp_request_async(SSH_FXP_READ, &buf, sshfs_read_begin,
                             sshfs_read_end, chunk);
    buf_free(&buf);
    return err;
}

static int submit_read(struct sshfs_file *sf, size_t size, off_t offset,
                       struct read_chunk **chunkp)
{
    int err;
    struct read_chunk *chunk = g_new0(struct read_chunk, 1);

    sem_init(&chunk->ready, 0, 0);
    buf_init(&chunk->data, 0);
    chunk->offset = offset;
    chunk->size = size;
    chunk->refs = 1;
    err = sshfs_send_async_read(sf, chunk);
    if (!err) {
        pthread_mutex_lock(&lock);
        chunk_put(*chunkp);
        *chunkp = chunk;
        pthread_mutex_unlock(&lock);
    } else
        chunk_put(chunk);

    return err;
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
    if (ch && ch->offset == offset) {
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

    pthread_mutex_lock(&lock);
    curr_is_seq = sf->is_seq;
    sf->is_seq = (sf->next_pos == offset);
    sf->next_pos = offset + size;
    chunk = search_read_chunk(sf, offset);
    pthread_mutex_unlock(&lock);

    if (chunk && chunk->size < size) {
        chunk_prev = chunk;
        size -= chunk->size;
        offset += chunk->size;
        chunk = NULL;
    }

    if (!chunk)
        res = submit_read(sf, size, offset, &chunk);

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
    struct sshfs_file *sf = (struct sshfs_file *) fi->fh;
    (void) path;

    if (!sshfs_file_is_conn(sf))
        return -EIO;

    if (sync_read)
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
}

static int sshfs_write(const char *path, const char *wbuf, size_t size,
                       off_t offset, struct fuse_file_info *fi)
{
    int err;
    struct buffer buf;
    struct buffer data;
    struct sshfs_file *sf = (struct sshfs_file *) fi->fh;
    struct buffer *handle = &sf->handle;

    (void) path;

    if (!sshfs_file_is_conn(sf))
        return -EIO;

    data.p = (uint8_t *) wbuf;
    data.len = size;
    buf_init(&buf, 0);
    buf_add_buf(&buf, handle);
    buf_add_uint64(&buf, offset);
    buf_add_data(&buf, &data);
    if (!sync_write && !sf->write_error)
        err = sftp_request_async(SSH_FXP_WRITE, &buf, sshfs_write_begin,
                                 sshfs_write_end, sf);
    else
        err = sftp_request(SSH_FXP_WRITE, &buf, SSH_FXP_STATUS, NULL);
    buf_free(&buf);
    return err ? err : (int) size;
}

static int processing_init(void)
{
    pthread_mutex_init(&lock, NULL);
    reqtab = g_hash_table_new(NULL, NULL);
    if (!reqtab) {
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
    },
    .cache_getdir = sshfs_getdir,
};

static void usage(const char *progname)
{
    const char *fusehelp[] = { progname, "-ho", NULL };

    fprintf(stderr,
"usage: %s [user@]host:[dir]] mountpoint [options]\n"
"\n"
"SSHFS Options:\n"
"    -V                     show version information\n"
"    -p PORT                equivalent to '-o port=PORT'\n"
"    -C                     equivalent to '-o compression=yes'\n"
"    -o reconnect           reconnect to server\n"
"    -o sshfs_sync          synchronous writes\n"
"    -o no_readahead        synchronous reads (no speculative readahead)\n"
"    -o sshfs_debug         print some debugging information\n"
"    -o cache=YESNO         enable caching {yes,no} (default: yes)\n"
"    -o cache_timeout=N     sets timeout for caches in seconds (default: 20)\n"
"    -o cache_X_timeout=N   sets timeout for {stat,dir,link} cache\n"
"    -o rename_workaround   work around problem renaming to existing file\n"
"    -o idmap=TYPE          user/group ID mapping, possible types are:\n"
"             none             no translation of the ID space (default)\n"
"             user             only translate ID of connecting user\n"
"    -o ssh_command=CMD     execute CMD instead of 'ssh'\n"
"    -o directport=PORT     directly connect to PORT bypassing ssh\n"
"    -o SSHOPT=VAL          ssh options (see man ssh_config)\n"
"\n", progname);
    fuse_main(2, (char **) fusehelp, &sshfs_oper.oper);
    exit(1);
}

int main(int argc, char *argv[])
{
    char *fsname;
    int res;
    int argctr;
    unsigned max_read = 65536;
    int newargc = 0;
    char **newargv = (char **) malloc((argc + 10) * sizeof(char *));
    newargv[newargc++] = argv[0];

    for (argctr = 1; argctr < argc; argctr++) {
        char *arg = argv[argctr];
        if (arg[0] == '-') {
            switch (arg[1]) {
            case '-':
                if (strcmp(arg+2, "help") == 0)
                    goto help;
                else if (strcmp(arg+2, "version") == 0)
                    goto version;
                break;

            case 'V':
            version:
                fprintf(stderr, "SSHFS version %s\n", PACKAGE_VERSION);
                exit(0);
                break;

            case 'h':
            help:
                usage(argv[0]);
                break;

            case 'C':
                if (!arg[2])
                    arg = "-oCompression=yes";
                break;

            case 'p':
                if (arg[2] || argctr + 1 < argc) {
                    char *newarg;
                    if (arg[2])
                        arg = arg + 2;
                    else
                        arg = argv[++argctr];
                    newarg = malloc(strlen(arg)+32);
                    sprintf(newarg, "-oPort=%s", arg);
                    arg = newarg;
                }
                break;
            }
            newargv[newargc++] = g_strdup(arg);
        } else if (!host && strchr(arg, ':'))
            host = g_strdup(arg);
        else
            newargv[newargc++] = g_strdup(arg);
    }
    if (!host) {
        fprintf(stderr, "missing host\n");
        fprintf(stderr, "see `%s -h' for usage\n", argv[0]);
        exit(1);
    }

    fsname = g_strdup(host);
    base_path = strchr(host, ':');
    *base_path++ = '\0';
    if (base_path[0] && base_path[strlen(base_path)-1] != '/')
        base_path = g_strdup_printf("%s/", base_path);
    else
        base_path = g_strdup(base_path);

    process_options(&newargc, newargv, sshfs_opts, 1);
    if (sshfs_opts[SOPT_SYNC_WRITE].present)
        sync_write = 1;
    if (sshfs_opts[SOPT_SYNC_READ].present)
        sync_read = 1;
    if (sshfs_opts[SOPT_DEBUG].present)
        debug = 1;
    if (sshfs_opts[SOPT_RENAME_FIX].present)
        rename_workaround = 1;
    if (sshfs_opts[SOPT_IDMAP].present) {
        struct opt *o = &sshfs_opts[SOPT_IDMAP];
        if (!o->value) {
            fprintf(stderr, "Missing value for '%s' option\n", o->optname);
            exit(1);
        }
        if (strcmp(o->value, "none") == 0)
            detect_uid = 0;
        else if (strcmp(o->value, "user") == 0)
            detect_uid = 1;
        else {
            fprintf(stderr, "Invalid value for '%s' option\n", o->optname);
            exit(1);
        }
    }
    if (sshfs_opts[SOPT_RECONNECT].present)
        reconnect = 1;
    if (sshfs_opts[SOPT_MAX_READ].present) {
        unsigned val;
        if (opt_get_unsigned(&sshfs_opts[SOPT_MAX_READ], &val) == -1)
            exit(1);

        if (val < max_read)
            max_read = val;
    }
    if (sshfs_opts[SOPT_DIRECTPORT].present)
        res = connect_to(host, sshfs_opts[SOPT_DIRECTPORT].value);
    else {
        process_options(&newargc, newargv, ssh_opts, 0);
        res = start_ssh(host);
    }
    if (res == -1)
        exit(1);

    res = sftp_init();
    if (res == -1)
        exit(1);

#ifndef SSHFS_USE_INIT
    if (detect_uid)
        sftp_detect_uid();
#endif

    res = processing_init();
    if (res == -1)
        exit(1);

    res = cache_parse_options(&newargc, newargv);
    if (res == -1)
        exit(1);

    randseed = time(0);

    newargv[newargc++] = g_strdup_printf("-omax_read=%u", max_read);
    newargv[newargc++] = g_strdup_printf("-ofsname=sshfs#%s", fsname);
    g_free(fsname);
    newargv[newargc] = NULL;
    return fuse_main(newargc, newargv, cache_init(&sshfs_oper));
}
