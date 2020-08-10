SSHFS
=====


About
-----

SSHFS allows you to mount a remote filesystem using SFTP. Most SSH
servers support and enable this SFTP access by default, so SSHFS is
very simple to use - there's nothing to do on the server-side.


Development Status
------------------

SSHFS is shipped by all major Linux distributions and has been in
production use across a wide range of systems for many years. However,
at present SSHFS does not have any active, regular contributors, and
there are a number of known issues (see the bugtracker).  The current
maintainer continues to apply pull requests and makes regular
releases, but unfortunately has no capacity to do any development
beyond addressing high-impact issues. When reporting bugs, please
understand that unless you are including a pull request or are
reporting a critical issue, you will probably not get a response.


How to use
----------

Once sshfs is installed (see next section) running it is very simple::

    sshfs [user@]hostname:[directory] mountpoint

It is recommended to run SSHFS as regular user (not as root).  For
this to work the mountpoint must be owned by the user.  If username is
omitted SSHFS will use the local username. If the directory is
omitted, SSHFS will mount the (remote) home directory.  If you need to
enter a password sshfs will ask for it (actually it just runs ssh
which ask for the password if needed).

Also many ssh options can be specified (see the manual pages for
*sftp(1)* and *ssh_config(5)*), including the remote port number
(``-oport=PORT``)

To unmount the filesystem::

    fusermount -u mountpoint

On BSD and macOS, to unmount the filesystem::

    umount mountpoint


Installation
------------

First, download the latest SSHFS release from
https://github.com/libfuse/sshfs/releases. On Linux and BSD, you will
also need to install libfuse_ 3.1.0 or newer. On macOS, you need
OSXFUSE_ instead. Finally, you need the Glib_ library with development
headers (which should be available from your operating system's
package manager).

To build and install, we recommend to use Meson_ (version 0.38 or
newer) and Ninja_.  After extracting the sshfs tarball, create a
(temporary) build directory and run Meson::

    $ mkdir build; cd build
    $ meson ..

Normally, the default build options will work fine. If you
nevertheless want to adjust them, you can do so with the *mesonconf*
command::

    $ mesonconf                  # list options 
    $ mesonconf -D strip=true    # set an option

To build, test and install SSHFS, you then use Ninja (running the
tests requires the `py.test`_ Python module)::

    $ ninja
    $ python3 -m pytest test/    # optional, but recommended
    $ sudo ninja install

.. _libfuse: http://github.com/libfuse/libfuse
.. _OSXFUSE: https://osxfuse.github.io/
.. _Glib: https://developer.gnome.org/glib/stable/
.. _Meson: http://mesonbuild.com/
.. _Ninja: https://ninja-build.org/
.. _`py.test`: http://www.pytest.org/

Getting Help
------------

If you need help, please ask on the <fuse-sshfs@lists.sourceforge.net>
mailing list (subscribe at
https://lists.sourceforge.net/lists/listinfo/fuse-sshfs).

Please report any bugs on the GitHub issue tracker at
https://github.com/libfuse/libfuse/issues.
