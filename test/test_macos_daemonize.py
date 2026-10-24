#!/usr/bin/env python3
"""Check at run time that nothing starts the macFUSE mount before
fuse_daemonize(). No mount is needed: sshfs runs without -f under a small
DYLD shim (daemonize_shim.c) that looks at macFUSE's own "mount started" flag
when sshfs calls fuse_daemonize()."""

if __name__ == "__main__":
    import pytest
    import sys

    sys.exit(pytest.main([__file__] + sys.argv[1:]))

import os
import shlex
import subprocess

import pytest
from os.path import join as pjoin
from util import basename, libfuse3_path, run_isolated

SSHFS = pjoin(basename, "sshfs")
SHIM_SRC = pjoin(os.path.dirname(os.path.abspath(__file__)), "daemonize_shim.c")

# Just enough of an SFTP server for sshfs to connect: version reply to INIT,
# a directory for the LSTAT of the remote root, "unsupported" for the rest.
FAKE_SSH = """#!/usr/bin/env python3
import struct, sys

def read(n):
    data = b""
    while len(data) < n:
        chunk = sys.stdin.buffer.read(n - len(data))
        if not chunk:
            sys.exit(0)
        data += chunk
    return data

def send(kind, payload):
    sys.stdout.buffer.write(struct.pack(">IB", len(payload) + 1, kind) + payload)
    sys.stdout.buffer.flush()

while True:
    (size,) = struct.unpack(">I", read(4))
    pkt = read(size)
    if pkt[0] == 1:    # INIT
        send(2, struct.pack(">I", 3))
    elif pkt[0] == 7:  # LSTAT
        send(105, pkt[1:5] + struct.pack(">II", 4, 0o40755))
    else:
        send(101, pkt[1:5] + struct.pack(">I", 8) + struct.pack(">II", 0, 0))
"""

EXIT_MEANING = {
    86: "the mount was started before fuse_daemonize()",
    87: "sshfs ran in the foreground, so the fork path was not exercised",
    88: "sshfs never reached fuse_daemonize()",
    89: "the shim could not install its watchdog",
}


def signature():
    res = subprocess.run(
        ["codesign", "-dv", "--verbose=4", SSHFS],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    return res.stdout


@pytest.fixture(scope="module")
def shim(tmp_path_factory):
    lib = libfuse3_path()
    path = str(tmp_path_factory.mktemp("shim") / "daemonize_shim.dylib")
    res = subprocess.run(
        shlex.split(os.environ.get("CC", "cc"))
        + ["-dynamiclib", "-Wall", "-Wextra", "-Werror", "-o", path, SHIM_SRC, lib],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    if res.returncode != 0:
        pytest.fail("could not build the shim against %s:\n%s" % (lib, res.stdout))
    return path


def run_sshfs(shim, args, out_file, helper_dir=None, timeout=45):
    env = dict(os.environ, DYLD_INSERT_LIBRARIES=shim)
    if helper_dir:
        # a bare command name: sshfs splits ssh_command at spaces
        env["PATH"] = str(helper_dir) + os.pathsep + env["PATH"]
    rc, output = run_isolated([SSHFS] + args, out_file, timeout, env=env)
    if rc is None:
        pytest.fail("sshfs did not exit in %ds\noutput:\n%s" % (timeout, output))
    return rc, output


def test_shim_loads(shim, tmp_path):
    """DYLD_INSERT_LIBRARIES must work for the sshfs built here; if it does
    not (hardened runtime, SIP), the check below would prove nothing."""
    rc, err = run_sshfs(shim, ["--version"], tmp_path / "version.txt")
    assert "daemonize-shim: loaded" in err, (
        "shim was not loaded\nsignature:\n%s\noutput:\n%s" % (signature(), err)
    )
    assert rc == 0, err


def test_no_mount_before_daemonize(shim, tmp_path):
    fake_ssh = tmp_path / "fake-ssh"
    fake_ssh.write_text(FAKE_SSH)
    fake_ssh.chmod(0o755)
    # a file, not a directory: nothing can be mounted there, whatever runs
    mnt_dir = tmp_path / "not-a-directory"
    mnt_dir.write_text("")

    rc, err = run_sshfs(
        shim,
        ["-o", "ssh_command=fake-ssh", "localhost:/", str(mnt_dir)],
        tmp_path / "sshfs.txt",
        helper_dir=tmp_path,
    )
    assert rc == 0, "%s (exit %d)\noutput:\n%s" % (
        EXIT_MEANING.get(rc, "unexpected failure"),
        rc,
        err,
    )
    assert "daemonize-shim: ok: fuse_daemonize(foreground=0)" in err, err
