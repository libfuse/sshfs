#!/bin/sh
#
# Don't call this script. It is used internally by the Meson
# build system. Thank you for your cooperation.
#

set -e

bindir="$2"
sbindir="$1"
prefix="${MESON_INSTALL_DESTDIR_PREFIX}"

mkdir -p "${prefix}/${sbindir}"

ln -svf --relative "${prefix}/${bindir}/sshfs" \
   "${prefix}/${sbindir}/mount.sshfs"

ln -svf --relative "${prefix}/${bindir}/sshfs" \
   "${prefix}/${sbindir}/mount.fuse.sshfs"
