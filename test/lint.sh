#!/bin/bash
set -e
pip3 install --user pre-commit
pre-commit run --all-files --show-diff-on-failure
