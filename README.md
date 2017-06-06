=======
 SSHFS
=======


About
=====

SSHFS allows you to mount a remote filesystem using SFTP. Most SSH
servers support and enable this SFTP access by default, so SSHFS is
very simple to use - there's nothing to do on the server-side.


How to use
==========

Once sshfs is installed (see next section) running it is very simple:

    sshfs [user@]hostname:[directory] mountpoint

It is recommended to run SSHFS as regular user (not as root).  For
this to work the mountpoint must be owned by the user.  If username is
omitted SSHFS will use the local username. If the directory is
omitted, SSHFS will mount the (remote) home directory.  If you need to
enter a password sshfs will ask for it (actually it just runs ssh
which ask for the password if needed).

Also many ssh options can be specified (see the manual pages for
*sftp(1)* and *ssh_config(5)*), including the remote port number
(`-oport=PORT`)

To unmount the filesystem:

    fusermount -u mountpoint

On BSD and OS-X, to unmount the filesystem:

    umount mountpoint


Installation
============

First, download the latest SSHFS release from
https://github.com/libfuse/sshfs/releases. On Linux and BSD, you will
also need to have [libfuse](http://github.com/libfuse/libfuse)
installed. On OS-X, you need [OSXFUSE](https://osxfuse.github.io/)
instead. Finally, you need the
[glib](https://developer.gnome.org/glib/stable/) development package
(which should be available from your operating system's package
manager).

To compile and install SSHFS, extract the tarball and run:

    ./configure
    make
    sudo make install

When checking out from git (instead of using a release tarball), you
will need to run `autoreconf -i` before `./configure`.

Getting Help
============

If you need help, please ask on the [SSHFS mailing
list](http://groups.google.com/group/sshfs). To post to the list,
please don't use the web interface but send an email to
<sshfs@googlegroups.com>.

Please report any bugs on the GitHub issue tracker at
https://github.com/libfuse/libfuse/issues.

