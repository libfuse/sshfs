#!/usr/bin/env python3
"""Tests for hostname validation — no FUSE mount required."""

if __name__ == "__main__":
    import pytest
    import sys

    sys.exit(pytest.main([__file__] + sys.argv[1:]))

import subprocess
from util import base_cmdline, basename
from os.path import join as pjoin


def test_reject_option_injection_in_hostname(tmpdir):
    """Bracketed source that resolves to a dash-prefixed host must be rejected."""

    mnt_dir = str(tmpdir.mkdir("mnt"))
    malicious = "[-oProxyCommand=echo pwned]:/path"

    cmdline = base_cmdline + [
        pjoin(basename, "sshfs"),
        "-f",
        malicious,
        mnt_dir,
    ]
    res = subprocess.run(
        cmdline,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10,
        text=True,
    )
    assert res.returncode != 0
    assert "invalid hostname" in res.stderr


def test_reject_dash_host_after_doubledash(tmpdir):
    """Non-bracketed dash-prefixed source after -- must also be rejected."""

    mnt_dir = str(tmpdir.mkdir("mnt"))

    cmdline = base_cmdline + [
        pjoin(basename, "sshfs"),
        "-f",
        "--",
        "-oProxyCommand=echo pwned:/path",
        mnt_dir,
    ]
    res = subprocess.run(
        cmdline,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10,
        text=True,
    )
    assert res.returncode != 0
    assert "invalid hostname" in res.stderr
