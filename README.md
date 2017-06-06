SSHFS
=====


About
-----

SSHFS allows you to mount a remote filesystem using SFTP. Most SSH
servers support and enable this SFTP access by default, so SSHFS is
very simple to use - there's nothing to do on the server-side.


How to use
----------

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
------------

First, download the latest SSHFS release from
https://github.com/libfuse/sshfs/releases. On Linux and BSD, you will
also need to have [libfuse](http://github.com/libfuse/libfuse)
installed. On OS-X, you need [OSXFUSE](https://osxfuse.github.io/)
instead. Finally, you need the
[glib](https://developer.gnome.org/glib/stable/) development package
(which should be available from your operating system's package
manager).

To build and install, we recommend to use
[Meson](http://mesonbuild.com/) (version 0.38 or newer) and
[Ninja](https://ninja-build.org).  After extracting the sshfs tarball,
create a (temporary) build directory and run Meson and Ninja:

    $ md build; cd build
    $ meson ..
    $ ninja
    $ sudo ninja install

Normally, the default build options will work fine. If you
nevertheless want to adjust them, you can do so with the *mesonconf*
command:

    $ mesonconf                  # list options 
    $ mesonconf -D strip=true    # set an option
    $ ninja                      # rebuild


Alternate Installation
----------------------

If you are not able to use Meson and Ninja, please report this to the
sshfs mailing list. Until the problem is resolved, you may fall back
to an in-source build using autotools:

    $ ./configure
    $ make
    $ sudo make install

Note that support for building with autotools may disappear at some
point, so if you depend on using autotools for some reason please let
the sshfs developers know!


    ./configure
    make
    sudo make install


Caveats
-------

Some SSH servers do not support atomically overwriting the destination
when renaming a file. In this case you will get an error when you
attempt to rename a file and the destination already exists. A
workaround is to first remove the destination file, and then do the
rename. SSHFS can do this automatically if you call it with `-o
workaround=rename`. However, in this case it is still possible that
someone (or something) recreates the destination file after SSHFS has
removed it, but before SSHFS had the time to rename the old file. In
this case, the rename will still fail.

    
Getting Help
------------

If you need help, please ask on the [SSHFS mailing
list](http://groups.google.com/group/sshfs). To post to the list,
please don't use the web interface but send an email to
<sshfs@googlegroups.com>.

Please report any bugs on the GitHub issue tracker at
https://github.com/libfuse/libfuse/issues.

