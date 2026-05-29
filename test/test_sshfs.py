#!/usr/bin/env python3

if __name__ == "__main__":
    import pytest
    import sys

    sys.exit(pytest.main([__file__] + sys.argv[1:]))

import subprocess
import os
import sys
import pytest
import stat
import shutil
import filecmp
import errno
from tempfile import NamedTemporaryFile
from contextlib import contextmanager
from util import (
    wait_for_mount,
    umount,
    cleanup,
    base_cmdline,
    basename,
    fuse_test_marker,
    safe_sleep,
    os_create,
    os_open,
)
from os.path import join as pjoin

TEST_FILE = __file__

pytestmark = fuse_test_marker()

with open(TEST_FILE, "rb") as fh:
    TEST_DATA = fh.read()


def name_generator(__ctr=[0]) -> str:
    """Generate a fresh filename on each call"""

    __ctr[0] += 1
    return f"testfile_{__ctr[0]}"


@pytest.mark.parametrize(
    "debug",
    [pytest.param(False, id="debug=false"), pytest.param(True, id="debug=true")],
)
@pytest.mark.parametrize(
    "cache_timeout",
    [pytest.param(0, id="cache_timeout=0"), pytest.param(1, id="cache_timeout=1")],
)
@pytest.mark.parametrize(
    "sync_rd",
    [pytest.param(True, id="sync_rd=true"), pytest.param(False, id="sync_rd=false")],
)
@pytest.mark.parametrize(
    "multiconn",
    [
        pytest.param(True, id="multiconn=true"),
        pytest.param(False, id="multiconn=false"),
    ],
)
def test_sshfs(
    tmpdir, debug: bool, cache_timeout: int, sync_rd: bool, multiconn: bool, capfd
) -> None:

    # Avoid false positives from debug messages
    # if debug:
    #    capfd.register_output(r'^   unique: [0-9]+, error: -[0-9]+ .+$',
    #                          count=0)

    # Avoid false positives from storing key for localhost
    capfd.register_output(r"^Warning: Permanently added 'localhost' .+", count=0)

    # Test if we can ssh into localhost without password
    try:
        res = subprocess.call(
            [
                "ssh",
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "KbdInteractiveAuthentication=no",
                "-o",
                "ChallengeResponseAuthentication=no",
                "-o",
                "PasswordAuthentication=no",
                "localhost",
                "--",
                "true",
            ],
            stdin=subprocess.DEVNULL,
            timeout=10,
        )
    except subprocess.TimeoutExpired:
        res = 1
    if res != 0:
        pytest.fail("Unable to ssh into localhost without password prompt.")

    mnt_dir = str(tmpdir.mkdir("mnt"))
    src_dir = str(tmpdir.mkdir("src"))

    cmdline = base_cmdline + [
        pjoin(basename, "sshfs"),
        "-f",
        f"localhost:{src_dir}",
        mnt_dir,
    ]
    if debug:
        cmdline += ["-o", "sshfs_debug"]

    if sync_rd:
        cmdline += ["-o", "sync_readdir"]

    # SSHFS Cache
    if cache_timeout == 0:
        cmdline += ["-o", "dir_cache=no"]
    else:
        cmdline += ["-o", f"dcache_timeout={cache_timeout}", "-o", "dir_cache=yes"]

    # FUSE Cache
    cmdline += ["-o", "entry_timeout=0", "-o", "attr_timeout=0"]

    # Disable containment so tst_symlink can test absolute targets
    cmdline += ["-o", "no_contain_symlinks"]

    if multiconn:
        cmdline += ["-o", "max_conns=3"]

    new_env = dict(os.environ)  # copy, don't modify

    # Abort on warnings from glib
    new_env["G_DEBUG"] = "fatal-warnings"

    mount_process = subprocess.Popen(cmdline, env=new_env)
    try:
        wait_for_mount(mount_process, mnt_dir)

        tst_statvfs(src_dir, mnt_dir)
        tst_readdir(src_dir, mnt_dir)
        tst_open_read(src_dir, mnt_dir)
        tst_open_write(src_dir, mnt_dir)
        tst_append(src_dir, mnt_dir)
        tst_seek(src_dir, mnt_dir)
        tst_create(mnt_dir)
        tst_passthrough(src_dir, mnt_dir, cache_timeout)
        tst_mkdir(mnt_dir)
        tst_rmdir(src_dir, mnt_dir, cache_timeout)
        tst_rename(mnt_dir)
        tst_rename_over(mnt_dir)
        tst_chmod(mnt_dir)
        tst_fsync(src_dir, mnt_dir)
        tst_unlink(src_dir, mnt_dir, cache_timeout)
        tst_symlink(mnt_dir)
        if os.getuid() == 0:
            tst_chown(mnt_dir)

        # SSHFS only supports one second resolution when setting
        # file timestamps.
        tst_utimens(mnt_dir, tol=1)
        tst_utimens_now(mnt_dir)

        tst_link(mnt_dir, cache_timeout)
        tst_truncate_path(mnt_dir)
        tst_truncate_fd(mnt_dir)
        tst_open_unlink(mnt_dir)
        tst_open_writeonly_read(mnt_dir)
        tst_access(mnt_dir)
        tst_mkdir_exist(mnt_dir)
        tst_readdir_repeated(mnt_dir)
        tst_rename_sibling(mnt_dir)
        tst_rename_open_release(mnt_dir)
    except Exception as exc:
        cleanup(mount_process, mnt_dir)
        raise exc
    else:
        umount(mount_process, mnt_dir)


def tst_unlink(src_dir, mnt_dir, cache_timeout):
    name = name_generator()
    fullname = mnt_dir + "/" + name
    with open(pjoin(src_dir, name), "wb") as fh:
        fh.write(b"hello")
    if cache_timeout:
        safe_sleep(cache_timeout + 1)
    assert name in os.listdir(mnt_dir)
    os.unlink(fullname)
    with pytest.raises(OSError) as exc_info:
        os.stat(fullname)
    assert exc_info.value.errno == errno.ENOENT
    assert name not in os.listdir(mnt_dir)
    assert name not in os.listdir(src_dir)


def tst_mkdir(mnt_dir):
    dirname = name_generator()
    fullname = mnt_dir + "/" + dirname
    os.mkdir(fullname)
    fstat = os.stat(fullname)
    assert stat.S_ISDIR(fstat.st_mode)
    assert os.listdir(fullname) == []
    assert fstat.st_nlink in (1, 2)
    assert dirname in os.listdir(mnt_dir)


def tst_rmdir(src_dir, mnt_dir, cache_timeout):
    name = name_generator()
    fullname = mnt_dir + "/" + name
    os.mkdir(pjoin(src_dir, name))
    if cache_timeout:
        safe_sleep(cache_timeout + 1)
    assert name in os.listdir(mnt_dir)
    os.rmdir(fullname)
    with pytest.raises(OSError) as exc_info:
        os.stat(fullname)
    assert exc_info.value.errno == errno.ENOENT
    assert name not in os.listdir(mnt_dir)
    assert name not in os.listdir(src_dir)


def tst_rename(mnt_dir):
    src_name = pjoin(mnt_dir, name_generator())
    dst_name = pjoin(mnt_dir, name_generator())
    data = b"rename test data\n"

    with open(src_name, "wb") as fh:
        fh.write(data)
    assert os.path.exists(src_name)

    os.rename(src_name, dst_name)

    assert not os.path.exists(src_name)
    assert os.path.basename(src_name) not in os.listdir(mnt_dir)
    assert os.path.basename(dst_name) in os.listdir(mnt_dir)
    with open(dst_name, "rb") as fh:
        assert fh.read() == data

    os.unlink(dst_name)


def tst_rename_over(mnt_dir):
    src_name = pjoin(mnt_dir, name_generator())
    dst_name = pjoin(mnt_dir, name_generator())
    src_data = b"source content\n"
    dst_data = b"destination content\n"

    with open(src_name, "wb") as fh:
        fh.write(src_data)
    with open(dst_name, "wb") as fh:
        fh.write(dst_data)

    os.rename(src_name, dst_name)

    assert not os.path.exists(src_name)
    assert os.path.basename(src_name) not in os.listdir(mnt_dir)
    with open(dst_name, "rb") as fh:
        assert fh.read() == src_data

    os.unlink(dst_name)


def tst_chmod(mnt_dir):
    filename = pjoin(mnt_dir, name_generator())
    with open(filename, "wb") as fh:
        fh.write(b"chmod test\n")

    os.chmod(filename, 0o644)
    fstat = os.stat(filename)
    assert stat.S_IMODE(fstat.st_mode) == 0o644

    os.chmod(filename, 0o755)
    fstat = os.stat(filename)
    assert stat.S_IMODE(fstat.st_mode) == 0o755

    os.unlink(filename)


def tst_fsync(src_dir, mnt_dir):
    name = name_generator()
    mnt_name = pjoin(mnt_dir, name)
    src_name = pjoin(src_dir, name)
    data = b"fsync test data\n"

    fd = os.open(mnt_name, os.O_CREAT | os.O_WRONLY)
    try:
        os.write(fd, data)
        os.fsync(fd)
        # Read from backing store while fd is still open, before
        # close/release has a chance to flush
        with open(src_name, "rb") as fh:
            assert fh.read() == data
    finally:
        os.close(fd)

    os.unlink(mnt_name)


def tst_symlink(mnt_dir):
    linkname = name_generator()
    fullname = mnt_dir + "/" + linkname
    os.symlink("/imaginary/dest", fullname)
    fstat = os.lstat(fullname)
    assert stat.S_ISLNK(fstat.st_mode)
    assert os.readlink(fullname) == "/imaginary/dest"
    assert fstat.st_nlink == 1
    assert linkname in os.listdir(mnt_dir)

    # Relative symlink without .. should also work
    linkname2 = name_generator()
    fullname2 = mnt_dir + "/" + linkname2
    os.symlink("subdir/file", fullname2)
    assert os.readlink(fullname2) == "subdir/file"

    os.unlink(fullname)
    assert linkname not in os.listdir(mnt_dir)


def tst_create(mnt_dir):
    name = name_generator()
    fullname = pjoin(mnt_dir, name)
    with pytest.raises(OSError) as exc_info:
        os.stat(fullname)
    assert exc_info.value.errno == errno.ENOENT
    assert name not in os.listdir(mnt_dir)

    fd = os.open(fullname, os.O_CREAT | os.O_RDWR)
    os.close(fd)

    assert name in os.listdir(mnt_dir)
    fstat = os.lstat(fullname)
    assert stat.S_ISREG(fstat.st_mode)
    assert fstat.st_nlink == 1
    assert fstat.st_size == 0


def tst_chown(mnt_dir):
    filename = pjoin(mnt_dir, name_generator())
    os.mkdir(filename)
    fstat = os.lstat(filename)
    uid = fstat.st_uid
    gid = fstat.st_gid

    uid_new = uid + 1
    os.chown(filename, uid_new, -1)
    fstat = os.lstat(filename)
    assert fstat.st_uid == uid_new
    assert fstat.st_gid == gid

    gid_new = gid + 1
    os.chown(filename, -1, gid_new)
    fstat = os.lstat(filename)
    assert fstat.st_uid == uid_new
    assert fstat.st_gid == gid_new


def tst_open_read(src_dir, mnt_dir):
    name = name_generator()
    with open(pjoin(src_dir, name), "wb") as fh_out, open(TEST_FILE, "rb") as fh_in:
        shutil.copyfileobj(fh_in, fh_out)

    assert filecmp.cmp(pjoin(mnt_dir, name), TEST_FILE, False)


def tst_open_write(src_dir, mnt_dir):
    name = name_generator()
    fd = os.open(pjoin(src_dir, name), os.O_CREAT | os.O_RDWR)
    os.close(fd)
    fullname = pjoin(mnt_dir, name)
    with open(fullname, "wb") as fh_out, open(TEST_FILE, "rb") as fh_in:
        shutil.copyfileobj(fh_in, fh_out)

    assert filecmp.cmp(fullname, TEST_FILE, False)


def tst_append(src_dir, mnt_dir):
    name = name_generator()
    os_create(pjoin(src_dir, name))
    fullname = pjoin(mnt_dir, name)
    with os_open(fullname, os.O_WRONLY) as fd:
        os.write(fd, b"foo\n")
    with os_open(fullname, os.O_WRONLY | os.O_APPEND) as fd:
        os.write(fd, b"bar\n")

    with open(fullname, "rb") as fh:
        assert fh.read() == b"foo\nbar\n"


def tst_seek(src_dir, mnt_dir):
    name = name_generator()
    os_create(pjoin(src_dir, name))
    fullname = pjoin(mnt_dir, name)
    with os_open(fullname, os.O_WRONLY) as fd:
        os.lseek(fd, 1, os.SEEK_SET)
        os.write(fd, b"foobar\n")
    with os_open(fullname, os.O_WRONLY) as fd:
        os.lseek(fd, 4, os.SEEK_SET)
        os.write(fd, b"com")

    with open(fullname, "rb") as fh:
        assert fh.read() == b"\0foocom\n"


def tst_open_unlink(mnt_dir):
    name = pjoin(mnt_dir, name_generator())
    data1 = b"foo"
    data2 = b"bar"
    fullname = pjoin(mnt_dir, name)
    with open(fullname, "wb+", buffering=0) as fh:
        fh.write(data1)
        os.unlink(fullname)
        with pytest.raises(OSError) as exc_info:
            os.stat(fullname)
        assert exc_info.value.errno == errno.ENOENT
        assert name not in os.listdir(mnt_dir)
        fh.write(data2)
        fh.seek(0)
        assert fh.read() == data1 + data2


def tst_statvfs(src_dir, mnt_dir):
    vfs = os.statvfs(mnt_dir)
    ref = os.statvfs(src_dir)
    # When the server supports statvfs@openssh.com, values should
    # match the backing store. Otherwise sshfs returns synthetic
    # values that still pass the loose checks.
    if vfs.f_bsize == ref.f_bsize:
        assert vfs.f_frsize == ref.f_frsize
        assert vfs.f_blocks == ref.f_blocks
        assert vfs.f_namemax == ref.f_namemax
    else:
        assert vfs.f_bsize > 0
        assert vfs.f_blocks > 0
        assert vfs.f_namemax > 0


def tst_open_writeonly_read(mnt_dir):
    name = pjoin(mnt_dir, name_generator())
    fd = os.open(name, os.O_CREAT | os.O_WRONLY)
    try:
        os.write(fd, b"hello")
        with pytest.raises(OSError) as exc_info:
            os.read(fd, 10)
        assert exc_info.value.errno == errno.EBADF
    finally:
        os.close(fd)
    os.unlink(name)


def tst_access(mnt_dir):
    filename = pjoin(mnt_dir, name_generator())
    with open(filename, "wb") as fh:
        fh.write(b"test")
    os.chmod(filename, 0o644)
    assert os.access(filename, os.R_OK)
    if os.getuid() != 0:
        assert not os.access(filename, os.X_OK)
    os.unlink(filename)


def tst_mkdir_exist(mnt_dir):
    name = name_generator()
    fullname = pjoin(mnt_dir, name)
    os.mkdir(fullname)
    with pytest.raises(OSError) as exc_info:
        os.mkdir(fullname)
    assert exc_info.value.errno == errno.EEXIST
    os.rmdir(fullname)


def tst_readdir_repeated(mnt_dir):
    dirname = pjoin(mnt_dir, name_generator())
    os.mkdir(dirname)
    names = []
    for i in range(5):
        n = name_generator()
        names.append(n)
        with open(pjoin(dirname, n), "wb") as fh:
            fh.write(b"x")

    # Verify repeated directory listings return consistent results
    listing1 = sorted(os.listdir(dirname))
    listing2 = sorted(os.listdir(dirname))
    assert listing1 == sorted(names)
    assert listing1 == listing2

    for n in names:
        os.unlink(pjoin(dirname, n))
    os.rmdir(dirname)


def tst_rename_sibling(mnt_dir):
    # Verify renaming one file doesn't break access to a sibling
    name_a = pjoin(mnt_dir, name_generator())
    name_b = pjoin(mnt_dir, name_generator())
    name_c = pjoin(mnt_dir, name_generator())

    with open(name_a, "wb") as fh:
        fh.write(b"aaa")
    with open(name_b, "wb") as fh:
        fh.write(b"bbb")

    os.rename(name_a, name_c)

    assert not os.path.exists(name_a)
    assert os.path.exists(name_b)
    with open(name_b, "rb") as fh:
        assert fh.read() == b"bbb"

    os.unlink(name_b)
    os.unlink(name_c)


def tst_rename_open_release(mnt_dir):
    src = pjoin(mnt_dir, name_generator())
    dst = pjoin(mnt_dir, name_generator())

    fd = os.open(src, os.O_CREAT | os.O_RDWR)
    try:
        os.write(fd, b"data")
        os.rename(src, dst)
    finally:
        os.close(fd)

    assert not os.path.exists(src)
    with open(dst, "rb") as fh:
        assert fh.read() == b"data"
    os.unlink(dst)


def tst_link(mnt_dir, cache_timeout):
    name1 = pjoin(mnt_dir, name_generator())
    name2 = pjoin(mnt_dir, name_generator())
    shutil.copyfile(TEST_FILE, name1)
    assert filecmp.cmp(name1, TEST_FILE, False)

    fstat1 = os.lstat(name1)
    assert fstat1.st_nlink == 1

    os.link(name1, name2)

    # The link operation changes st_ctime, and if we're unlucky
    # the kernel will keep the old value cached for name1, and
    # retrieve the new value for name2 (at least, this is the only
    # way I can explain the test failure). To avoid this problem,
    # we need to wait until the cached value has expired.
    if cache_timeout:
        safe_sleep(cache_timeout)

    fstat1 = os.lstat(name1)
    fstat2 = os.lstat(name2)
    for attr in (
        "st_mode",
        "st_dev",
        "st_uid",
        "st_gid",
        "st_size",
        "st_atime",
        "st_mtime",
        "st_ctime",
    ):
        assert getattr(fstat1, attr) == getattr(fstat2, attr)
    assert os.path.basename(name2) in os.listdir(mnt_dir)
    assert filecmp.cmp(name1, name2, False)

    os.unlink(name2)

    assert os.path.basename(name2) not in os.listdir(mnt_dir)
    with pytest.raises(FileNotFoundError):
        os.lstat(name2)
    if cache_timeout:
        safe_sleep(cache_timeout + 1)
    fstat1 = os.lstat(name1)
    assert fstat1.st_nlink == 1

    os.unlink(name1)


def tst_readdir(src_dir, mnt_dir):
    newdir = name_generator()
    src_newdir = pjoin(src_dir, newdir)
    mnt_newdir = pjoin(mnt_dir, newdir)
    file_ = src_newdir + "/" + name_generator()
    subdir = src_newdir + "/" + name_generator()
    subfile = subdir + "/" + name_generator()

    os.mkdir(src_newdir)
    shutil.copyfile(TEST_FILE, file_)
    os.mkdir(subdir)
    shutil.copyfile(TEST_FILE, subfile)

    listdir_is = os.listdir(mnt_newdir)
    listdir_is.sort()
    listdir_should = [os.path.basename(file_), os.path.basename(subdir)]
    listdir_should.sort()
    assert listdir_is == listdir_should

    os.unlink(file_)
    os.unlink(subfile)
    os.rmdir(subdir)
    os.rmdir(src_newdir)


def tst_truncate_path(mnt_dir):
    assert len(TEST_DATA) > 1024

    filename = pjoin(mnt_dir, name_generator())
    with open(filename, "wb") as fh:
        fh.write(TEST_DATA)

    fstat = os.stat(filename)
    size = fstat.st_size
    assert size == len(TEST_DATA)

    # Add zeros at the end
    os.truncate(filename, size + 1024)
    assert os.stat(filename).st_size == size + 1024
    with open(filename, "rb") as fh:
        assert fh.read(size) == TEST_DATA
        assert fh.read(1025) == b"\0" * 1024

    # Truncate data
    os.truncate(filename, size - 1024)
    assert os.stat(filename).st_size == size - 1024
    with open(filename, "rb") as fh:
        assert fh.read(size) == TEST_DATA[: size - 1024]

    # Truncate to zero
    os.truncate(filename, 0)
    assert os.stat(filename).st_size == 0

    os.unlink(filename)


def tst_truncate_fd(mnt_dir):
    assert len(TEST_DATA) > 1024
    with NamedTemporaryFile("w+b", 0, dir=mnt_dir) as fh:
        fd = fh.fileno()
        fh.write(TEST_DATA)
        fstat = os.fstat(fd)
        size = fstat.st_size
        assert size == len(TEST_DATA)

        # Add zeros at the end
        os.ftruncate(fd, size + 1024)
        assert os.fstat(fd).st_size == size + 1024
        fh.seek(0)
        assert fh.read(size) == TEST_DATA
        assert fh.read(1025) == b"\0" * 1024

        # Truncate data
        os.ftruncate(fd, size - 1024)
        assert os.fstat(fd).st_size == size - 1024
        fh.seek(0)
        assert fh.read(size) == TEST_DATA[: size - 1024]

        # Truncate to zero via fd
        os.ftruncate(fd, 0)
        assert os.fstat(fd).st_size == 0


def tst_utimens(mnt_dir, tol=0):
    filename = pjoin(mnt_dir, name_generator())
    os.mkdir(filename)
    fstat = os.lstat(filename)

    atime = fstat.st_atime + 42.28
    mtime = fstat.st_mtime - 42.23
    if sys.version_info < (3, 3):
        os.utime(filename, (atime, mtime))
    else:
        atime_ns = fstat.st_atime_ns + int(42.28 * 1e9)
        mtime_ns = fstat.st_mtime_ns - int(42.23 * 1e9)
        os.utime(filename, None, ns=(atime_ns, mtime_ns))

    fstat = os.lstat(filename)

    assert abs(fstat.st_atime - atime) < tol
    assert abs(fstat.st_mtime - mtime) < tol
    if sys.version_info >= (3, 3):
        assert abs(fstat.st_atime_ns - atime_ns) < tol * 1e9
        assert abs(fstat.st_mtime_ns - mtime_ns) < tol * 1e9


def tst_utimens_now(mnt_dir):
    fullname = pjoin(mnt_dir, name_generator())

    fd = os.open(fullname, os.O_CREAT | os.O_RDWR)
    os.close(fd)
    os.utime(fullname, None)

    fstat = os.lstat(fullname)
    # We should get now-timestamps
    assert fstat.st_atime != 0
    assert fstat.st_mtime != 0


def tst_passthrough(src_dir, mnt_dir, cache_timeout):
    name = name_generator()
    src_name = pjoin(src_dir, name)
    mnt_name = pjoin(mnt_dir, name)
    assert name not in os.listdir(src_dir)
    assert name not in os.listdir(mnt_dir)
    with open(src_name, "w") as fh:
        fh.write("Hello, world")
    assert name in os.listdir(src_dir)
    if cache_timeout:
        safe_sleep(cache_timeout + 1)
    assert name in os.listdir(mnt_dir)
    src_st = os.stat(src_name)
    mnt_st = os.stat(mnt_name)
    assert src_st.st_size == mnt_st.st_size
    assert src_st.st_uid == mnt_st.st_uid
    assert src_st.st_gid == mnt_st.st_gid
    assert abs(src_st.st_mtime - mnt_st.st_mtime) <= 1

    name = name_generator()
    src_name = pjoin(src_dir, name)
    mnt_name = pjoin(mnt_dir, name)
    assert name not in os.listdir(src_dir)
    assert name not in os.listdir(mnt_dir)
    with open(mnt_name, "w") as fh:
        fh.write("Hello, world")
    assert name in os.listdir(src_dir)
    if cache_timeout:
        safe_sleep(cache_timeout + 1)
    assert name in os.listdir(mnt_dir)
    src_st = os.stat(src_name)
    mnt_st = os.stat(mnt_name)
    assert src_st.st_size == mnt_st.st_size
    assert src_st.st_uid == mnt_st.st_uid
    assert src_st.st_gid == mnt_st.st_gid
    assert abs(src_st.st_mtime - mnt_st.st_mtime) <= 1


def _check_ssh_localhost():
    try:
        res = subprocess.call(
            ["ssh", "-o", "StrictHostKeyChecking=no",
             "-o", "KbdInteractiveAuthentication=no",
             "-o", "ChallengeResponseAuthentication=no",
             "-o", "PasswordAuthentication=no",
             "localhost", "--", "true"],
            stdin=subprocess.DEVNULL, timeout=10,
        )
    except subprocess.TimeoutExpired:
        res = 1
    if res != 0:
        pytest.fail("Unable to ssh into localhost without password prompt.")


_mount_ctr = [0]


def _mount_sshfs(tmpdir, extra_opts=None):
    """Helper to mount sshfs with custom options. Returns (mount_process, mnt_dir, src_dir)."""
    _check_ssh_localhost()
    _mount_ctr[0] += 1
    mnt_dir = str(tmpdir.mkdir(f"mnt{_mount_ctr[0]}"))
    src_dir = str(tmpdir.mkdir(f"src{_mount_ctr[0]}"))

    cmdline = base_cmdline + [
        pjoin(basename, "sshfs"),
        "-f",
        f"localhost:{src_dir}",
        mnt_dir,
        "-o", "entry_timeout=0",
        "-o", "attr_timeout=0",
    ]
    if extra_opts:
        for opt in extra_opts:
            cmdline += ["-o", opt]

    new_env = dict(os.environ)
    new_env["G_DEBUG"] = "fatal-warnings"

    mount_process = subprocess.Popen(cmdline, env=new_env)
    try:
        wait_for_mount(mount_process, mnt_dir)
    except:
        cleanup(mount_process, mnt_dir)
        raise
    return mount_process, mnt_dir, src_dir


def test_disable_hardlink(tmpdir, capfd):
    capfd.register_output(r"^Warning: Permanently added 'localhost' .+", count=0)

    # Control: verify hardlinks work without disable_hardlink.
    # If the server lacks the extension, skip this test entirely.
    mount_process, mnt_dir, src_dir = _mount_sshfs(tmpdir, [])
    try:
        name1 = pjoin(mnt_dir, name_generator())
        name2 = pjoin(mnt_dir, name_generator())
        with open(name1, "wb") as fh:
            fh.write(b"test")
        try:
            os.link(name1, name2)
        except OSError:
            os.unlink(name1)
            pytest.skip("server does not support hardlink extension")
        os.unlink(name2)
        os.unlink(name1)
    except Exception:
        cleanup(mount_process, mnt_dir)
        raise
    else:
        umount(mount_process, mnt_dir)

    # Now test with disable_hardlink — links should fail
    mount_process, mnt_dir, src_dir = _mount_sshfs(tmpdir, ["disable_hardlink"])
    try:
        name1 = pjoin(mnt_dir, name_generator())
        name2 = pjoin(mnt_dir, name_generator())
        with open(name1, "wb") as fh:
            fh.write(b"test")
        with pytest.raises(OSError) as exc_info:
            os.link(name1, name2)
        assert exc_info.value.errno in (errno.ENOSYS, errno.EPERM)
        os.unlink(name1)
    except Exception:
        cleanup(mount_process, mnt_dir)
        raise
    else:
        umount(mount_process, mnt_dir)


def test_follow_symlinks(tmpdir, capfd):
    capfd.register_output(r"^Warning: Permanently added 'localhost' .+", count=0)
    mount_process, mnt_dir, src_dir = _mount_sshfs(tmpdir, ["follow_symlinks"])
    try:
        target_name = name_generator()
        target = pjoin(src_dir, target_name)
        with open(target, "wb") as fh:
            fh.write(b"symlink target data")

        link = pjoin(src_dir, name_generator())
        os.symlink(target_name, link)

        mnt_link = pjoin(mnt_dir, os.path.basename(link))
        # With follow_symlinks, stat should return the target's attributes
        # and the entry should appear as a regular file, not a symlink
        fstat = os.lstat(mnt_link)
        assert stat.S_ISREG(fstat.st_mode)
        with open(mnt_link, "rb") as fh:
            assert fh.read() == b"symlink target data"

        os.unlink(link)
        os.unlink(target)
    except Exception:
        cleanup(mount_process, mnt_dir)
        raise
    else:
        umount(mount_process, mnt_dir)


def test_direct_io(tmpdir, capfd):
    capfd.register_output(r"^Warning: Permanently added 'localhost' .+", count=0)
    mount_process, mnt_dir, src_dir = _mount_sshfs(tmpdir, ["direct_io"])
    try:
        name = name_generator()
        mnt_name = pjoin(mnt_dir, name)
        src_name = pjoin(src_dir, name)
        data = b"direct io test data\n" * 100

        with open(mnt_name, "wb") as fh:
            fh.write(data)
        with open(mnt_name, "rb") as fh:
            assert fh.read() == data
        with open(src_name, "rb") as fh:
            assert fh.read() == data

        os.unlink(mnt_name)
    except Exception:
        cleanup(mount_process, mnt_dir)
        raise
    else:
        umount(mount_process, mnt_dir)


def test_bad_sftp_reply_len(tmpdir):
    """sshfs must reject a zero-length SFTP reply instead of underflowing."""
    helper = tmpdir.join("bad_sftp.py")
    helper.write(
        '#!/usr/bin/env python3\n'
        'import os, struct, sys\n'
        'def read_pkt():\n'
        '    hdr = os.read(0, 4)\n'
        '    if len(hdr) < 4: sys.exit(0)\n'
        '    n = struct.unpack(">I", hdr)[0]\n'
        '    while n:\n'
        '        c = os.read(0, n)\n'
        '        if not c: sys.exit(0)\n'
        '        n -= len(c)\n'
        'read_pkt()\n'
        'os.write(1, struct.pack(">IBI", 5, 2, 3))\n'  # SSH_FXP_VERSION v3
        'read_pkt()\n'
        'os.write(1, struct.pack(">IB", 0, 0))\n'  # len=0 reply (5 bytes on wire)
    )
    helper.chmod(0o755)

    mnt_dir = str(tmpdir.mkdir("mnt"))
    cmdline = base_cmdline + [
        pjoin(basename, "sshfs"),
        "-f",
        "dummy:/",
        mnt_dir,
        "-o", f"ssh_command={helper}",
    ]
    res = subprocess.run(
        cmdline,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10,
        text=True,
    )
    assert res.returncode != 0
    assert "bad reply len: 0" in res.stderr


@contextmanager
def _sshfs_mount(src_dir, mnt_dir, extra_opts=None):
    """Mount src_dir via sshfs, yield, then unmount."""
    cmdline = base_cmdline + [
        pjoin(basename, "sshfs"), "-f",
        f"localhost:{src_dir}", mnt_dir,
        "-o", "entry_timeout=0", "-o", "attr_timeout=0",
    ]
    if extra_opts:
        for opt in extra_opts:
            cmdline += ["-o", opt]
    new_env = dict(os.environ)
    new_env["G_DEBUG"] = "fatal-warnings"
    mount_process = subprocess.Popen(cmdline, env=new_env)
    try:
        wait_for_mount(mount_process, mnt_dir)
        yield mnt_dir
    except Exception:
        cleanup(mount_process, mnt_dir)
        raise
    else:
        umount(mount_process, mnt_dir)


def test_contain_symlinks(tmpdir, capfd) -> None:
    """Default containment: safe symlinks resolve, dangerous ones get EPERM."""

    capfd.register_output(r"^Warning: Permanently added 'localhost' .+", count=0)
    _check_ssh_localhost()

    mnt_dir = str(tmpdir.mkdir("mnt"))
    src_dir = str(tmpdir.mkdir("src"))

    os.makedirs(pjoin(src_dir, "sub"))
    with open(pjoin(src_dir, "sub", "target"), "w") as f:
        f.write("hello")

    os.symlink("sub/target", pjoin(src_dir, "safe"))
    os.symlink("./sub/target", pjoin(src_dir, "safe_dot"))
    os.symlink("/etc/passwd", pjoin(src_dir, "abs"))
    os.symlink("../../../etc/passwd", pjoin(src_dir, "dotdot"))
    os.symlink("sub/../../etc/passwd", pjoin(src_dir, "interleaved"))
    os.symlink("..", pjoin(src_dir, "bare_dotdot"))

    with _sshfs_mount(src_dir, mnt_dir):
        # Safe symlinks pass through and resolve
        assert os.readlink(pjoin(mnt_dir, "safe")) == "sub/target"
        assert os.readlink(pjoin(mnt_dir, "safe_dot")) == "./sub/target"
        with open(pjoin(mnt_dir, "safe")) as f:
            assert f.read() == "hello"

        # Dangerous: readlink returns EPERM
        for name in ("abs", "dotdot", "interleaved", "bare_dotdot"):
            with pytest.raises(OSError) as exc_info:
                os.readlink(pjoin(mnt_dir, name))
            assert exc_info.value.errno == errno.EPERM

        # Dangerous: traversal (open/stat) also EPERM
        with pytest.raises(OSError) as exc_info:
            open(pjoin(mnt_dir, "abs"))
        assert exc_info.value.errno == errno.EPERM

        with pytest.raises(OSError) as exc_info:
            os.stat(pjoin(mnt_dir, "dotdot"))
        assert exc_info.value.errno == errno.EPERM


def test_no_contain_symlinks(tmpdir, capfd) -> None:
    """Opt-out: symlinks pass through and actually resolve."""

    capfd.register_output(r"^Warning: Permanently added 'localhost' .+", count=0)
    _check_ssh_localhost()

    mnt_dir = str(tmpdir.mkdir("mnt"))
    src_dir = str(tmpdir.mkdir("src"))

    os.symlink("/etc/passwd", pjoin(src_dir, "abs_link"))
    os.symlink("../../../etc/passwd", pjoin(src_dir, "rel_escape"))

    with _sshfs_mount(src_dir, mnt_dir, ["no_contain_symlinks"]):
        assert os.readlink(pjoin(mnt_dir, "abs_link")) == "/etc/passwd"
        assert os.readlink(pjoin(mnt_dir, "rel_escape")) == "../../../etc/passwd"

        # Absolute symlink actually resolves (reads local /etc/passwd)
        with open(pjoin(mnt_dir, "abs_link")) as f:
            assert "root" in f.read()

        # Relative escape: kernel must traverse the link (not EPERM).
        # Target won't exist on the test host, so we just assert that
        # sshfs didn't block it - any errno other than EPERM proves
        # containment is genuinely disabled.
        with pytest.raises(OSError) as exc_info:
            os.stat(pjoin(mnt_dir, "rel_escape"))
        assert exc_info.value.errno != errno.EPERM


def test_transform_with_contain(tmpdir, capfd) -> None:
    """transform_symlinks + default containment: transformed ../x is rejected."""

    capfd.register_output(r"^Warning: Permanently added 'localhost' .+", count=0)
    capfd.register_output(r"^warning: transform_symlinks.+", count=0)
    _check_ssh_localhost()

    mnt_dir = str(tmpdir.mkdir("mnt"))
    src_dir = str(tmpdir.mkdir("src"))

    os.makedirs(pjoin(src_dir, "other"))
    with open(pjoin(src_dir, "other", "file"), "w") as f:
        f.write("data")
    # Absolute in-base: transform rewrites to "other/file" (no ..)
    os.symlink(pjoin(src_dir, "other", "file"), pjoin(src_dir, "inbase"))
    # Absolute in-base but sibling: transform rewrites to "../other/file"
    os.makedirs(pjoin(src_dir, "sub"))
    os.symlink(pjoin(src_dir, "other", "file"), pjoin(src_dir, "sub", "sibling"))

    with _sshfs_mount(src_dir, mnt_dir, ["transform_symlinks"]):
        # Direct child: transform produces "other/file" - no .., passes
        link = os.readlink(pjoin(mnt_dir, "inbase"))
        assert ".." not in link.split("/")
        with open(pjoin(mnt_dir, "inbase")) as f:
            assert f.read() == "data"

        # Sibling: transform produces "../other/file" - has .., EPERM
        with pytest.raises(OSError) as exc_info:
            os.readlink(pjoin(mnt_dir, "sub", "sibling"))
        assert exc_info.value.errno == errno.EPERM

    # Same setup with no_contain_symlinks: sibling works
    with _sshfs_mount(src_dir, mnt_dir,
                      ["transform_symlinks", "no_contain_symlinks"]):
        link = os.readlink(pjoin(mnt_dir, "sub", "sibling"))
        assert ".." in link
        with open(pjoin(mnt_dir, "sub", "sibling")) as f:
            assert f.read() == "data"


def test_contain_symlinks_option_precedence(tmpdir, capfd) -> None:
    """Last option wins when contain_symlinks and no_contain_symlinks both set."""

    capfd.register_output(r"^Warning: Permanently added 'localhost' .+", count=0)
    _check_ssh_localhost()

    mnt_dir = str(tmpdir.mkdir("mnt"))
    src_dir = str(tmpdir.mkdir("src"))

    os.symlink("/etc/passwd", pjoin(src_dir, "abs"))

    # no_contain_symlinks last: containment disabled, readlink succeeds
    with _sshfs_mount(src_dir, mnt_dir,
                      ["contain_symlinks", "no_contain_symlinks"]):
        assert os.readlink(pjoin(mnt_dir, "abs")) == "/etc/passwd"

    # contain_symlinks last: containment enabled, EPERM
    with _sshfs_mount(src_dir, mnt_dir,
                      ["no_contain_symlinks", "contain_symlinks"]):
        with pytest.raises(OSError) as exc_info:
            os.readlink(pjoin(mnt_dir, "abs"))
        assert exc_info.value.errno == errno.EPERM
