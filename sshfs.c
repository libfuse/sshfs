#include <fuse.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <netinet/in.h>

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

static int infd;
static int outfd;

struct buffer {
    uint8_t *p;
    size_t len;
    size_t size;
};

static inline void buf_init(struct buffer *buf, size_t size)
{
    if (size) {
        buf->p = malloc(size);
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

static int buf_get_attrs(struct buffer *buf, struct stat *stbuf)
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
    memset(stbuf, 0, sizeof(struct stat));
    stbuf->st_mode = mode;
    stbuf->st_nlink = 1;
    stbuf->st_size = size;
    stbuf->st_uid = uid;
    stbuf->st_gid = gid;
    stbuf->st_atime = atime;
    stbuf->st_mtime = mtime;
    return 0;
}

static int buf_get_entries(struct buffer *buf, fuse_dirh_t h,
                           fuse_dirfil_t filler)
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
            if (buf_get_attrs(buf, &stbuf) != -1) {
                filler(h, name, stbuf.st_mode >> 12);
                err = 0;
            }
        }
        free(name);
        if (err)
            return err;
    }
    return 0;
}

static int start_ssh(const char *host)
{
    int inpipe[2];
    int outpipe[2];
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
        if (dup2(outpipe[0], 0) == -1 || dup2(inpipe[1], 1) == -1) {
            perror("failed to redirect input/output");
            exit(1);
        }
        close(inpipe[0]);
        close(inpipe[1]);
        close(outpipe[0]);
        close(outpipe[1]);
        execlp("ssh", "ssh", "-2", "-x", "-a", "-oClearAllForwardings=yes",
               host, "-s", "sftp", NULL);
        exit(1);
    }
    close(inpipe[1]);
    close(outpipe[0]);
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
            fprintf(stderr, "end of file read\n");
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
        buf_get_uint32(&buf2, &len);
        buf_get_uint8(&buf2, type);
        buf_init(buf, len - 1);
        res = do_read(buf);
    }
    buf_free(&buf2);
    return res;
}

static int sftp_request(uint8_t type, const struct buffer *buf,
                        uint8_t expect_type, struct buffer *outbuf)
{
    int err;
    struct buffer buf2;
    uint32_t id = sftp_get_id();
    uint32_t idback;
    uint8_t typeback;

    buf_init(&buf2, buf->len + 4);
    buf_add_uint32(&buf2, id);
    buf_add_mem(&buf2, buf->p, buf->len);
    
    err = -EIO;
    if (sftp_send(type, &buf2) == -1)
        goto out;
    buf_clear(&buf2);
    if (sftp_read(&typeback, &buf2) == -1)
        goto out;
    err = -EPROTO;
    if (typeback != expect_type && typeback != SSH_FXP_STATUS) {
        fprintf(stderr, "protocol error\n");
        goto out;
    }
    if (buf_get_uint32(&buf2, &idback) == -1)
        goto out;
    if (idback != id) {
        fprintf(stderr, "Invalid ID received\n");
        goto out;
    }
    if (typeback == SSH_FXP_STATUS) {
        uint32_t serr;
        if (buf_get_uint32(&buf2, &serr) == -1)
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
        buf_init(outbuf, buf2.size - buf2.len);
        buf_get_mem(&buf2, outbuf->p, outbuf->size);
        err = 0;
    }

 out:
    buf_free(&buf2);
    return err;
        
}

static int sshfs_getattr(const char *path, struct stat *stbuf)
{
    int err;
    struct buffer buf;
    struct buffer outbuf;
    buf_init(&buf, 0);
    buf_add_string(&buf, path);
    err = sftp_request(SSH_FXP_LSTAT, &buf, SSH_FXP_ATTRS, &outbuf);
    if (!err) {
        if (buf_get_attrs(&outbuf, stbuf) == -1)
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
    buf_init(&buf, 0);
    buf_add_string(&buf, path);
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

static int sshfs_getdir(const char *path, fuse_dirh_t h, fuse_dirfil_t filler)
{
    int err;
    struct buffer buf;
    struct buffer handle;
    buf_init(&buf, 0);
    buf_add_string(&buf, path);
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
        
        
        err2 = sftp_request(SSH_FXP_CLOSE, &handle, SSH_FXP_STATUS, NULL);
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
    buf_add_string(&buf, path);
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
    buf_add_string(&buf, path);
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
    buf_init(&buf, 0);
    /* openssh sftp server doesn't follow standard: link target and
       link name are mixed up, so we must also be non-standard :( */
    buf_add_string(&buf, from);
    buf_add_string(&buf, to);
    err = sftp_request(SSH_FXP_SYMLINK, &buf, SSH_FXP_STATUS, NULL);
    buf_free(&buf);
    return err;
}

static int sshfs_unlink(const char *path)
{
    int err;
    struct buffer buf;
    buf_init(&buf, 0);
    buf_add_string(&buf, path);
    err = sftp_request(SSH_FXP_REMOVE, &buf, SSH_FXP_STATUS, NULL);
    buf_free(&buf);
    return err;
}

static int sshfs_rmdir(const char *path)
{
    int err;
    struct buffer buf;
    buf_init(&buf, 0);
    buf_add_string(&buf, path);
    err = sftp_request(SSH_FXP_RMDIR, &buf, SSH_FXP_STATUS, NULL);
    buf_free(&buf);
    return err;
}

static int sshfs_rename(const char *from, const char *to)
{
    int err;
    struct buffer buf;
    buf_init(&buf, 0);
    buf_add_string(&buf, from);
    buf_add_string(&buf, to);
    err = sftp_request(SSH_FXP_RENAME, &buf, SSH_FXP_STATUS, NULL);
    buf_free(&buf);
    return err;
}

static int sshfs_chmod(const char *path, mode_t mode)
{
    int err;
    struct buffer buf;
    buf_init(&buf, 0);
    buf_add_string(&buf, path);
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
    buf_add_string(&buf, path);
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
    buf_add_string(&buf, path);
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
    buf_add_string(&buf, path);
    buf_add_uint32(&buf, SSH_FILEXFER_ATTR_ACMODTIME);
    buf_add_uint32(&buf, ubuf->actime);
    buf_add_uint32(&buf, ubuf->modtime);
    err = sftp_request(SSH_FXP_SETSTAT, &buf, SSH_FXP_STATUS, NULL);
    buf_free(&buf);
    return err;
}

static int sshfs_open(const char *path, int flags)
{
    int err;
    struct buffer buf;
    struct buffer handle;
    uint32_t pflags;
    if ((flags & O_ACCMODE) == O_RDONLY)
        pflags = SSH_FXF_READ;
    else if((flags & O_ACCMODE) == O_WRONLY)
        pflags = SSH_FXF_WRITE;
    else 
        pflags = SSH_FXF_READ | SSH_FXF_WRITE;
     
    buf_init(&buf, 0);
    buf_add_string(&buf, path);
    buf_add_uint32(&buf, pflags);
    buf_add_uint32(&buf, 0);
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

static int sshfs_read(const char *path, char *rbuf, size_t size, off_t offset)
{
    int err;
    struct buffer buf;
    struct buffer handle;
    buf_init(&buf, 0);
    buf_add_string(&buf, path);
    buf_add_uint32(&buf, SSH_FXF_READ);
    buf_add_uint32(&buf, 0);
    err = sftp_request(SSH_FXP_OPEN, &buf, SSH_FXP_HANDLE, &handle);
    if (!err) {
        struct buffer data;
        int err2;
        buf_finish(&handle);
        buf_add_uint64(&handle, offset);
        buf_add_uint32(&handle, size);
        err = sftp_request(SSH_FXP_READ, &handle, SSH_FXP_DATA, &data);
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
        }
        err2 = sftp_request(SSH_FXP_CLOSE, &handle, SSH_FXP_STATUS, NULL);
        if (err2 && err >= 0)
            err = err2;
        buf_free(&handle);
    }
    buf_free(&buf);
    return err;    
}

static int sshfs_write(const char *path, const char *wbuf, size_t size,
                       off_t offset)
{
    int err;
    struct buffer buf;
    struct buffer handle;
    buf_init(&buf, 0);
    buf_add_string(&buf, path);
    buf_add_uint32(&buf, SSH_FXF_WRITE);
    buf_add_uint32(&buf, 0);
    err = sftp_request(SSH_FXP_OPEN, &buf, SSH_FXP_HANDLE, &handle);
    if (!err) {
        struct buffer data;
        int err2;
        data.p = (uint8_t *) wbuf;
        data.len = size;
        buf_finish(&handle);
        buf_add_uint64(&handle, offset);
        buf_add_data(&handle, &data);
        err = sftp_request(SSH_FXP_WRITE, &handle, SSH_FXP_STATUS, NULL);
        err2 = sftp_request(SSH_FXP_CLOSE, &handle, SSH_FXP_STATUS, NULL);
        if (err2 && err >= 0)
            err = err2;
        buf_free(&handle);
    }
    buf_free(&buf);
    return err;    
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
    if (version != PROTO_VERSION) {
        fprintf(stderr, "server version: %i, we need: %i\n",
                version, PROTO_VERSION);
        goto out;
    }
    res = 0;
 out:
    buf_free(&buf);
    return res;
}

static struct fuse_operations sshfs_oper = {
    .getattr	= sshfs_getattr,
    .readlink   = sshfs_readlink,
    .getdir	= sshfs_getdir,
    .mknod      = sshfs_mknod,
    .mkdir      = sshfs_mkdir,
    .symlink	= sshfs_symlink,
    .unlink     = sshfs_unlink,
    .rmdir      = sshfs_rmdir,
    .rename     = sshfs_rename,
    .chmod      = sshfs_chmod,
    .chown	= sshfs_chown,
    .truncate	= sshfs_truncate,
    .utime      = sshfs_utime,
    .open       = sshfs_open,
    .read       = sshfs_read,
    .write      = sshfs_write,
};

int main(int argc, char *argv[])
{
    char *host;
    int res;
    int argctr;
    char **newargv;
    

    if (argc < 3) {
        fprintf(stderr, "usage: %s [user@]host mountpoint [mount options]\n",
                argv[0]);
        exit(1);
    }

    host = argv[1];
    
    res = start_ssh(host);
    if (res == -1)
        exit(1);
    
    res = sftp_init();
    if (res == -1)
        exit(1);
    
    newargv = (char **) malloc((argc + 10) * sizeof(char *));
    newargv[0] = argv[0];
    for (argctr = 1; argctr < argc - 1; argctr++)
        newargv[argctr] = argv[argctr + 1];
    newargv[argctr++] = "-s";
    newargv[argctr++] = "-omax_read=65536";
    newargv[argctr] = NULL;
    return fuse_main(argctr, newargv, &sshfs_oper);
}
