Abstract
========

This is a filesystem client based on the SSH File Transfer Protocol.
Since most SSH servers already support this protocol it is very easy
to set up: i.e. on the server side there's nothing to do.  On the
client side mounting the filesystem is as easy as logging into the
server with ssh.

The idea of sshfs was taken from the SSHFS filesystem distributed with
LUFS, which I found very useful.  There were some limitations of that
codebase, so I rewrote it.  Features of this implementation are:

  - Based on FUSE (the best userspace filesystem framework for Linux ;)

  - Multithreading: more than one request can be on it's way to the
    server

  - Allowing large reads (max 64k)

  - Caching directory contents

  - Reconnect on failure

Latest version
==============

The latest version and more information can be found on
http://github.com/libfuse/sshfs


How to mount a filesystem
=========================

Once sshfs is installed (see next section) running it is very simple:

    sshfs hostname: mountpoint

Note, that it's recommended to run it as user, not as root.  For this
to work the mountpoint must be owned by the user.  If the username is
different on the host you are connecting to, then use the
"username@host:" form.  If you need to enter a password sshfs will ask
for it (actually it just runs ssh which ask for the password if
needed).  You can also specify a directory after the ":".  The default
is the home directory.

Also many ssh options can be specified (see the manual pages for
sftp(1) and ssh_config(5)), including the remote port number
(`-oport=PORT`)

To unmount the filesystem:

    fusermount -u mountpoint


Installing
==========

First you need to download FUSE 2.2 or later from
http://github.com/libfuse/libfuse.

You also need to install the devel package for glib2.0.  After
installing FUSE, compile sshfs the usual way:

    ./configure
    make
    make install (as root)

And you are ready to go.

If checking out from git for the first time also do `autoreconf -i`
before doing `./configure`.
