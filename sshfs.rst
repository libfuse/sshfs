=======
 SSHFS
=======

---------------------------------------------
 filesystem client based on SSH
---------------------------------------------

:Manual section: 1
:Manual group: User Commands

Synopsis
========

To mount a filesystem::

   sshfs [user@]host:[dir] mountpoint [options]

If *host* is a numeric IPv6 address, it needs to be enclosed in square
brackets.

To unmount it::

  fusermount3 -u mountpoint   # Linux
  umount mountpoint           # OS X, FreeBSD

Description
===========

SSHFS allows you to mount a remote filesystem using SSH (more
precisely, the SFTP subsystem). Most SSH servers support and enable
this SFTP access by default, so SSHFS is very simple to use - there's
nothing to do on the server-side.

SSHFS uses FUSE (Filesystem in Userspace) and should work on any
operating system that provides a FUSE implementation. Currently,
this includes Linux, FreeBSD and Mac OS X.

It is recommended to run SSHFS as regular user (not as root).  For
this to work the mountpoint must be owned by the user.  If username is
omitted SSHFS will use the local username. If the directory is
omitted, SSHFS will mount the (remote) home directory.  If you need to
enter a password sshfs will ask for it (actually it just runs ssh
which ask for the password if needed).


Options
=======


-o opt,[opt...]
   mount options, see below for details. A a variety of SSH options can
   be given here as well, see the manual pages for *sftp(1)* and
   *ssh_config(5)*.

-h, --help
   print help and exit.

-V, --version
   print version information and exit.

-d, --debug
   print debugging information.

-p PORT
   equivalent to '-o port=PORT'

-f
   do not daemonize, stay in foreground.

-s
   Single threaded operation.

-C
   equivalent to '-o compression=yes'

-F ssh_configfile
   specifies alternative ssh configuration file

-1
   equivalent to '-o ssh_protocol=1'

-o reconnect
   automatically reconnect to server if connection is
   interrupted. Attempts to access files that were opened before the
   reconnection will give errors and need to be re-opened.

-o delay_connect
   Don't immediately connect to server, wait until mountpoint is first
   accessed.

-o sshfs_sync
   synchronous writes. This will slow things down, but may be useful
   in some situations.

-o no_readahead
   Only read exactly the data that was requested, instead of
   speculatively reading more to anticipate the next read request.

-o sync_readdir
   synchronous readdir. This will slow things down, but may be useful
   in some situations.

-o workaround=LIST
   Enable the specified workaround. See the `Caveats` section below
   for some additional information. Possible values are:

   :rename: Emulate overwriting an existing file by deleting and
        renaming.
   :truncate: Work around servers that don't support truncate by
        coping the whole file, truncating it locally, and sending it
        back.
   :fstat: Work around broken servers that don't support *fstat()* by
           using *stat* instead.
   :buflimit: Work around OpenSSH "buffer fillup" bug.

-o idmap=TYPE
   How to map remote UID/GIDs to local values. Possible values are:

   :none: no translation of the ID space (default).

   :user: map the UID/GID of the remote user to UID/GID of the
            mounting user.

   :file: translate UIDs/GIDs based upon the contents of `--uidfile`
            and `--gidfile`.

-o uidfile=FILE
   file containing ``username:uid`` mappings for `-o idmap=file`

-o gidfile=FILE
   file containing ``groupname:gid`` mappings for `-o idmap=file`

-o nomap=TYPE
   with idmap=file, how to handle missing mappings:

   :ignore: don't do any re-mapping
   :error:  return an error (default)

-o ssh_command=CMD
   execute CMD instead of 'ssh'

-o ssh_protocol=N
   ssh protocol to use (default: 2)

-o sftp_server=SERV
   path to sftp server or subsystem (default: sftp)

-o directport=PORT
   directly connect to PORT bypassing ssh

-o slave
   communicate over stdin and stdout bypassing network

-o disable_hardlink
   `link(2)` will return with errno set to ENOSYS.  Hard links
   don't currently work perfectly on sshfs, and this confuses some
   programs.  If that happens try disabling hard links with this
   option.

-o transform_symlinks
   transform absolute symlinks on remote side to relative
   symlinks. This means that if e.g. on the server side
   ``/foo/bar/com`` is a symlink to ``/foo/blub``, SSHFS will
   transform the link target to ``../blub`` on the client side.

-o follow_symlinks
   follow symlinks on the server, i.e. present them as regular
   files on the client. If a symlink is dangling (i.e, the target does
   not exist) the behavior depends on the remote server - the entry
   may appear as a symlink on the client, or it may appear as a
   regular file that cannot be accessed.

-o no_check_root
   don't check for existence of 'dir' on server

-o password_stdin
   read password from stdin (only for pam_mount!)

In addition, SSHFS accepts several options common to all FUSE file
systems. These are described in the `mount.fuse` manpage (look
for "general", "libfuse specific", and "high-level API" options).

Caveats / Workarounds
=====================

Hardlinks
~~~~~~~~~

If the SSH server supports the *hardlinks* extension, SSHFS will allow
you to create hardlinks. However, hardlinks will always appear as
individual files when seen through an SSHFS mount, i.e. they will
appear to have different inodes and an *st_nlink* value of 1.


Rename
~~~~~~

Some SSH servers do not support atomically overwriting the destination
when renaming a file. In this case you will get an error when you
attempt to rename a file and the destination already exists. A
workaround is to first remove the destination file, and then do the
rename. SSHFS can do this automatically if you call it with `-o
workaround=rename`. However, in this case it is still possible that
someone (or something) recreates the destination file after SSHFS has
removed it, but before SSHFS had the time to rename the old file. In
this case, the rename will still fail.


O_APPEND
~~~~~~~~

When writeback caching is enabled, SSHFS cannot reliably support the
``O_APPEND`` open flag and thus signals an error on open.  To enable
support for unreliable ``O_APPEND`` (which may overwrite data if the
file changes on the server at a bad time), mount the file system with
``-o unreliable_append``.


See also
========

The `mount.fuse(8)` manpage.

Getting Help
============

If you need help, please ask on the <fuse-sshfs@lists.sourceforge.net>
mailing list (subscribe at
https://lists.sourceforge.net/lists/listinfo/fuse-sshfs).

Please report any bugs on the GitHub issue tracker at
https://github.com/libfuse/libfuse/issues.


Authors
=======

SSHFS is currently maintained by Nikolaus Rath <Nikolaus@rath.org>,
and was created by Miklos Szeredi <miklos@szeredi.hu>.

This man page was originally written by Bartosz Fenski
<fenio@debian.org> for the Debian GNU/Linux distribution (but it may
be used by others).
