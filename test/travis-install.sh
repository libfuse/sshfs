#!/bin/sh

set -e

# Meson 0.45 requires Python 3.5 or newer
sudo python3 -m pip install pytest meson==0.44
valgrind --version
ninja --version
meson --version

# Setup ssh
ssh-keygen -b 1024 -t rsa -f ~/.ssh/id_rsa -P ''
cat ~/.ssh/id_rsa.pub >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
ssh -o "StrictHostKeyChecking=no" localhost echo "SSH connection succeeded"

