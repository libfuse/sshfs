## Process this file with automake to produce Makefile.in

bin_PROGRAMS = sshfs

if FUSE_OPT_COMPAT
compat_sources = compat/fuse_opt.c compat/fuse_opt.h
endif

sshfs_SOURCES = sshfs.c cache.c cache.h $(compat_sources)
sshfs_CPPFLAGS = -DFUSE_USE_VERSION=27
