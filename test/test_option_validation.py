#!/usr/bin/env python3
"""Tests for option validation — no FUSE mount required."""

if __name__ == "__main__":
    import pytest
    import sys

    sys.exit(pytest.main([__file__] + sys.argv[1:]))

import subprocess
import pytest
from util import base_cmdline, basename
from os.path import join as pjoin


@pytest.mark.parametrize("opt", ["max_read", "max_write"])
def test_reject_zero_io_size(tmpdir, opt):
    """A zero max_read/max_write would make the I/O loops spin forever."""

    mnt_dir = str(tmpdir.mkdir("mnt"))

    cmdline = base_cmdline + [
        pjoin(basename, "sshfs"),
        "-f",
        "-o",
        f"{opt}=0",
        "nonexistent.invalid:/",
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
    assert f"value of {opt} option must be at least 1" in res.stderr
