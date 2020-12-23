# SSHFS


## About

SSHFS is part of the [libfuse](https://github.com/libfuse) project. 

SSHFS allows you to mount a remote filesystem using SFTP. Most SSH servers support and enable this
SFTP access by default, so SSHFS is very simple to use--there's nothing to do on the server-side.


## Development Status

SSHFS is shipped by all major Linux distributions and has been in production use across a wide range
of systems for many years. However, at present SSHFS does not have any active, regular contributors,
and there are a number of known issues (see all issues and bugs in the [SSHFS issue
tracker](https://github.com/libfuse/sshfs/issues)). The current maintainer continues to apply pull
requests and makes regular releases, but unfortunately has no capacity to do any development beyond
addressing high-impact issues. _When reporting bugs, please understand that unless you are including
a pull request or are reporting a critical issue, you will probably not get a response._


## How to use

Once `sshfs` is installed (see the "[Build and Install](#build)" section below) running it is very
simple.

### 1. To mount a remote filesystem with `sshfs`:

General command syntax:
```bash
sshfs [user@]hostname_or_ip:[directory] mountpoint
```

For example, to connect to the username "john" on a host at local IP `10.0.0.1`, mounting the host's
root directory (`/`) in your local `~/mnt/sshfs` directory, you would do the following:

```bash
mkdir -p ~/mnt/sshfs  # create the ~/mnt/sshfs directory, if it doesn't already exist 
sshfs john@10.0.0.1:/ ~/mnt/sshfs
```

### 2. To unmount the remote filesystem:

General syntax:
```bash
# For most systems, including Ubuntu
fusermount -u mountpoint

# For BSD and MacOS, and also works fine on Ubuntu
umount mountpoint
```

For the example above:
```bash
# For most systems, including Ubuntu
fusermount -u ~/mnt/sshfs

# For BSD and MacOS, and also works fine on Ubuntu
umount ~/mnt/sshfs
```

### 3. Notes:
1. It is recommended to run SSHFS as a regular user (NOT as root). For this to work, the mount point
   must be owned by the user. Therefore, mounting into a `mount` or `mnt` directory you create 
   inside your home directory is a good practice.  
1. If the username is omitted, SSHFS will use the local username. 
1. If the directory is omitted, SSHFS will mount the (remote) home directory.
1. If you need to enter a password, SSHFS will ask for it (actually, it just runs `ssh` which asks
   for the password if needed).

Also, many `ssh` options can be specified. See the manual pages for _sftp(1)_ (`man 1 sftp`) and
_ssh_config(5)_ (`man 5 ssh_config`). The remote port number (`-oport=PORT`) is one of the many
`ssh` options which works with `sshfs`.


<a id="build"></a>
## Build and Install

Tested 22 Dec. 2020 on Ubuntu 20.04. 

1. Download and `cd` into the source code
    1. To download the latest source code:
        ```bash
        git clone https://github.com/libfuse/sshfs.git
        cd sshfs
        ```
    1. OR (recommended): To download the latest `sshfs` _release_:
        1. Find the release you want here: https://github.com/libfuse/sshfs/releases.
        1. Find the link to the `*.tar.gz` file you want. Example: https://github.com/libfuse/sshfs/archive/sshfs-3.7.1.tar.gz.
        1. Download, extract, and `cd` into it:
            ```bash
            wget https://github.com/libfuse/sshfs/archive/sshfs-3.7.1.tar.gz
            tar -xvzf sshfs-3.7.1.tar.gz
            cd sshfs-sshfs-3.7.1
            ```
1. Install dependencies
    ```bash
    sudo apt update
    sudo apt install meson cmake fuse3 libfuse3-dev libglib2.0-dev
    ```
1. Create a **build** dir, `cd` into it, run `meson`, and build and link with `ninja`:
    ```bash
    mkdir build 
    cd build 
    meson ..
    ninja  # this builds and produces the new `sshfs` executable
    ```
<!-- Important: this HTML anchor is referenced inside "test_sshfs.py". If you change its name here,
change it there too. -->
<a id="sshkeygen"></a> 
1. (Optional, but recommended) test your new `sshfs` executable. 
    1. Note: ssh key generation notes come [from GitHub here](https://docs.github.com/en/free-pro-team@latest/github/authenticating-to-github/generating-a-new-ssh-key-and-adding-it-to-the-ssh-agent).
    ```bash
    # install the `pytest` python3 module in case you don't already have it
    pip3 install pytest  
    # install `sshd`
    sudo apt update 
    sudo apt install openssh-server

    # Configure passwordless ssh key-based login so you can ssh into yourself
    # (via `localhost`) for testing; see GitHub link above.
    # 1. Generate a new public-private key pair. 
    ssh-keygen -t ed25519 -C "your_email@example.com"
    eval "$(ssh-agent -s)"
    ssh-add ~/.ssh/id_ed25519
    # 2. Now add your new "~/.ssh/id_ed25519.pub" public key to your 
    # "~/.ssh/authorized_keys" file so you can have key-based password-less
    # ssh sessions into yourself via `localhost` for testing.
    cat ~/.ssh/id_ed25519.pub >> ~/.ssh/authorized_keys 

    # run the python3 tests in the "test" dir
    python3 -m pytest test/
    ```
1. 



First, download the latest SSHFS release from https://github.com/libfuse/sshfs/releases. On Linux
and BSD, you will also need to install [libfuse][libfuse] 3.1.0 or newer. On macOS, you need
[OSXFUSE][OSXFUSE] instead. Finally, you need the [Glib][Glib] library with development headers
(which should be available from your operating system's package manager).

To build and install, we recommend to use [Meson][Meson] (version 0.38 or newer) and [Ninja][Ninja].
 After extracting the sshfs tarball, create a (temporary) build directory and run Meson:

```bash
mkdir build; cd build
meson ..
```

Normally, the default build options will work fine. If you nevertheless want to adjust them, you can
do so with the *mesonconf* command:

```bash
mesonconf                  # list options 
mesonconf -D strip=true    # set an option
```

To build, test and install SSHFS, you then use Ninja (running the tests requires the
[`py.test`][py.test] Python module):

```bash
ninja
python3 -m pytest test/    # optional, but recommended
sudo ninja install
```


## Getting Help

If you need help, please ask on the <fuse-sshfs@lists.sourceforge.net> mailing list. Subscribe at
https://lists.sourceforge.net/lists/listinfo/fuse-sshfs.

Please report any bugs on the main parent project's (`libfuse`'s) GitHub issue tracker here:
https://github.com/libfuse/libfuse/issues.


  [libfuse]: http://github.com/libfuse/libfuse
  [OSXFUSE]: https://osxfuse.github.io/
  [Glib]: https://developer.gnome.org/glib/stable/
  [Meson]: http://mesonbuild.com/
  [Ninja]: https://ninja-build.org/
  [py.test]: http://www.pytest.org/
