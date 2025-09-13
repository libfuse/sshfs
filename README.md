
# SSHFS


## About

SSHFS allows you to mount a remote filesystem using SFTP. Most SSH
servers support and enable this SFTP access by default, so SSHFS is
very simple to use - there's nothing to do on the server-side.


## Development Status


SSHFS is shipped by all major Linux distributions and has been in
production use across a wide range of systems for many years. However,
at present SSHFS does not have any active, regular contributors, and
there are a number of known issues (see the [bugtracker](https://github.com/libfuse/sshfs/issues)).  
The current maintainer continues to apply pull requests and makes regular
releases, but unfortunately has no capacity to do any development
beyond addressing high-impact issues. When reporting bugs, please
understand that unless you are including a pull request or are
reporting a critical issue, you will probably not get a response.


## How to use


Once sshfs is installed (see next section) running it is very simple:

```
sshfs [user@]hostname:[directory] mountpoint
```

It is recommended to run SSHFS as regular user (not as root).  For
this to work the mountpoint must be owned by the user.  If username is
omitted SSHFS will use the local username. If the directory is
omitted, SSHFS will mount the (remote) home directory.  If you need to
enter a password sshfs will ask for it (actually it just runs ssh
which asks for the password if needed).

Also many ssh options can be specified (see the manual pages for
*sftp(1)* and *ssh_config(5)*), including the remote port number
(`-oport=PORT`)

To unmount the filesystem:

```
fusermount -u mountpoint
```

On BSD and macOS, to unmount the filesystem:

```
umount mountpoint
```

## Installation

First, you need to install the following dependencies:
- [libfuse](http://github.com/libfuse/libfuse) 3.1.0 or newer
- [Glib](https://developer.gnome.org/glib/stable/) library with development headers
- [Meson](http://mesonbuild.com/) version 0.40 or newer
- [Ninja](https://ninja-build.org/)

On a Debian-based system, you can install them with:
```
$ sudo apt-get install gcc meson ninja-build libglib2.0-dev libfuse3-dev
```

Once the dependencies are installed, you can build and install SSHFS with the
standard `./configure && make` process:

```
$ ./configure
$ make
$ make test          # optional, but recommended
$ sudo make install
```

The `configure` script is a wrapper around `meson` and accepts the same
arguments. For example, you can change the installation prefix:
`./configure --prefix=/usr/local`.

### Building with Meson

For a more fine-grained control over the build process, you can use `meson`
directly.

To configure the build, create a (temporary) build directory and run `meson`:
```
$ mkdir build; cd build
$ meson ..
```

Normally, the default build options will work fine. If you
nevertheless want to adjust them, you can do so with the `meson`
command:

```
$ meson configure             # list options
$ meson configure -D strip=true    # set an option
```

To build, test and install SSHFS, you then use `ninja` (running the
tests requires `pytest`):

```
$ ninja
$ python3 -m pytest test/    # optional, but recommended
$ sudo ninja install
```

## Getting Help


If you need help, please ask on the <fuse-sshfs@lists.sourceforge.net>
mailing list (subscribe at
https://lists.sourceforge.net/lists/listinfo/fuse-sshfs).

Please report any bugs on the GitHub issue tracker at
https://github.com/libfuse/sshfs/issues.

## Packaging Status


<a href="https://repology.org/project/fusefs:sshfs/versions">
    <img src="https://repology.org/badge/vertical-allrepos/fusefs:sshfs.svg" alt="Packaging status" >
</a>
