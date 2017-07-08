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
sshfs_CPPFLAGS = -D_REENTRANT -DFUSE_USE_VERSION=26 -DLIBDIR=\"$(libdir)\" \
                 -DIDMAP_DEFAULT="\"$(IDMAP_DEFAULT)\""

EXTRA_DIST = sshfs.1.in meson.build
CLEANFILES = sshfs.1 sshfs.1.tmp

dist_man_MANS = sshfs.1

sshfs.1: sshfs.1.in
	$(AM_V_GEN)sed \
	    -e 's/[@]IDMAP_DEFAULT@/$(IDMAP_DEFAULT)/g' \
	    -e 's/[@]UNMOUNT_COMMAND@/$(UNMOUNT_COMMAND)/g' \
	    <$(srcdir)/sshfs.1.in >sshfs.1.tmp || exit 1; \
	mv sshfs.1.tmp sshfs.1
