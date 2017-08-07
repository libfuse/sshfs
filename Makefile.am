## Process this file with automake to produce Makefile.in

bin_PROGRAMS = sshfs

SUBDIRS = test

sshfs_SOURCES = sshfs.c cache.c cache.h
if FUSE_OPT_COMPAT
sshfs_SOURCES += compat/fuse_opt.c compat/fuse_opt.h
endif
if DARWIN_COMPAT
sshfs_SOURCES += compat/darwin_compat.c compat/darwin_compat.h
endif

sshfs_LDADD = $(SSHFS_LIBS)
sshfs_CFLAGS = $(SSHFS_CFLAGS)
sshfs_CPPFLAGS = -D_REENTRANT -DFUSE_USE_VERSION=31 -DLIBDIR=\"$(libdir)\" \
                 -DIDMAP_DEFAULT="\"$(IDMAP_DEFAULT)\""

EXTRA_DIST = sshfs.rst sshfs.1 meson.build ChangeLog.rst
CLEANFILES = sshfs.1

dist_man_MANS = sshfs.1

sshfs.1: sshfs.rst
	rst2man sshfs.rst sshfs.1
