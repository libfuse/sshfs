#!/usr/bin/env python3
"""Startup tests: macFUSE 5.3.3+ needs no mount; other platforms require FUSE."""

import os
import subprocess
import sys
from os.path import join as pjoin

from util import base_cmdline, basename, fuse_test_marker, run_isolated

# Linux mounts before connecting to SSH, so it needs FUSE. macFUSE 5.3.3+ does
# not; conftest.py checks for it and runs these on macOS with TEST_WITH_MACFUSE=1.
if sys.platform != "darwin":
    pytestmark = fuse_test_marker()


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
        # a bare command name: sshfs splits ssh_command at spaces
        "-o", "ssh_command=bad_sftp.py",
    ]
    env = dict(os.environ, PATH=str(tmpdir) + os.pathsep + os.environ["PATH"])
    rc, output = run_isolated(cmdline, tmpdir.join("sshfs.txt"), timeout=10, env=env)
    assert rc == 1, output
    # Nothing may follow the rejection: a "remote host has disconnected" after
    # it means the bad length was read past instead of failing.
    assert output.rstrip().endswith("bad reply len: 0"), output


def test_backslash_escape(tmpdir, capfd):
    """Regression test for parsing backslash escape sequences in options"""

    cases = [
        (r"one two three", "<one> <two> <three>"),
        (r"one\\ two three", "<one two> <three>"),
        # fuse_opt_parse interprets "\ " as " ", so these are still separate
        (r"one two\ three", "<one> <two> <three>"),
    ]

    mnt_dir = str(tmpdir.mkdir("mnt"))
    # we can skip cleanup since the mount always fails

    for line, args in cases:
        cmdline = base_cmdline + [
            pjoin(basename, "sshfs"),
            "-f",
            "localhost:foo",
            mnt_dir,
            "-o",
            "sshfs_debug",
            "-o",
            "ssh_command=/dev/null " + line,
        ]
        assert subprocess.run(cmdline, timeout=10).returncode != 0

        captured = capfd.readouterr()
        assert "executing </dev/null> " + args in captured.err


def test_ssh_exec_failure(tmp_path):
    """An SSH exec error must report failure and exit promptly."""
    mnt_dir = tmp_path / "mnt"
    mnt_dir.mkdir()
    cmdline = base_cmdline + [
        pjoin(basename, "sshfs"), "-f", "-o", "ssh_command=/dev/null",
        "localhost:/", str(mnt_dir),
    ]

    rc, output = run_isolated(cmdline, tmp_path / "sshfs.txt", timeout=20)
    assert rc is not None, "startup did not finish within 20s\n" + output
    assert rc == 1, f"expected exit 1, got {rc}\n{output}"
    assert "failed to execute '/dev/null'" in output, output
