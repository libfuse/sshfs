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

## Installation

SSHFS is available from most operating system package managers.
```sh
# Debian / Ubuntu
sudo apt install sshfs

# Arch Linux
sudo pacman -S sshfs

# macOS with Homebrew
brew install sshfs

# FreeBSD
sudo pkg install fusefs-sshfs
```

### Building from source
SSHFS requires `libfuse` 3.1.0 or newer, GLib, Meson, Ninja, and a C compiler.

Download and extract the latest release from the https://github.com/libfuse/sshfs/releases page. After extracting the SSHFS tarball, create a temporary build directory and run Meson:
```sh
mkdir build; cd build
meson ..
ninja
sudo ninja install
```

To run the test suite:

```sh
python3 -m pytest test/
```

## How to use

To mount a filesystem:
```sh
sshfs [user@]hostname:[/directory] /mountpoint [options]
```
If host is a numeric IPv6 address, it needs to be enclosed in square brackets.

To un-mount it:
```sh
fusermount3 -u mountpoint   # Linux
umount mountpoint           # OS X, FreeBSD
```

It is recommended to run SSHFS as regular user (not as root).  For
this to work the mountpoint must be owned by the user.  If username is
omitted SSHFS will use the local username. If the directory is
omitted, SSHFS will mount the (remote) home directory.  If you need to
enter a password sshfs will ask for it (actually it just runs ssh
which asks for the password if needed).

### Common options

- `-o opt[,opt...]`: mount options. A variety of SSH and FUSE options can be given here as well; see the manual pages for *sftp(1)*, *ssh_config(5)* and *mount.fuse(8)*.
- `-p PORT`: equivalent to `-o port=PORT`.
- `-d`, `--debug`: print debugging information.
- `-h`, `--help`: print help and exit.
- `-V`, `--version`: print version information and exit.

## Mounting from /etc/fstab

To mount an SSHFS filesystem from ``/etc/fstab``, simply use ``sshfs``
as the file system type. (For backwards compatibility, you may also
use ``fuse.sshfs``).

See also the `mount.fuse(8)` manpage.

## Bypassing SSH

#### Using directport

Using direct connections to sftp-server to bypass SSH for performance is also possible. To do this, start a network service using sftp-server (part of OpenSSH) on a server, then connect directly using the `-o directport=PORT` option.

On server (listen on port 1234 using socat):

`socat tcp-listen:1234,reuseaddr,fork  exec:/usr/lib/openssh/sftp-server`

On client:

`sshfs -o directport=1234 127.0.0.1:/tmp /tmp/mnt`

Note that this is insecure as connection will happen without encryption. Only use this on localhost or trusted networks. This option is sometimes used by other projects to mount folders inside VMs.

IPv6 is also possible:

`socat tcp6-listen:1234,reuseaddr,fork exec:/usr/lib/openssh/sftp-server`

`sshfs -o directport=1234 [::1]:/tmp /tmp/mnt`

#### Using vsock

Similarly to above, Linux [vsock](https://man7.org/linux/man-pages/man7/vsock.7.html) can be used to connect directly to sockets within VMs using `-o vsock=CID:PORT`.

```
# on the host
socat VSOCK-LISTEN:12345 EXEC:"/usr/lib/openssh/sftp-server",nofork
# on the clientside
sshfs -o vsock=2:12345 unused_host: ./tmp
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
