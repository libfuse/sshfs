## Process this file with automake to produce Makefile.in

bin_PROGRAMS = sshfs

sshfs_SOURCES = sshfs.c cache.c cache.h
if FUSE_OPT_COMPAT
sshfs_SOURCES += compat/fuse_opt.c compat/fuse_opt.h
endif
if DARWIN_COMPAT
sshfs_SOURCES += compat/darwin_compat.c compat/darwin_compat.h
endif

sshfs_LDADD = $(SSHFS_LIBS)
sshfs_CFLAGS = $(SSHFS_CFLAGS)
sshfs_CPPFLAGS = -D_REENTRANT -DFUSE_USE_VERSION=26 -DLIBDIR=\"$(libdir)\"

EXTRA_DIST = sshnodelay.c FAQ.txt
CLEANFILES = sshnodelay.so sshfs.1

dist_man_MANS = sshfs.1

sshfs.1:
	$(CPP) $(CPPFLAGS) -P -xassembler-with-cpp sshfs.1.in | sed -e '/^$$/d' > sshfs.1

if SSH_NODELAY_SO
all-local: sshnodelay.so

install-exec-local: sshnodelay.so
	test -z "$(libdir)" || $(mkdir_p) "$(DESTDIR)$(libdir)"
	$(INSTALL) -m 755 sshnodelay.so "$(DESTDIR)$(libdir)/sshnodelay.so"

uninstall-local:
	rm -f "$(DESTDIR)$(libdir)/sshnodelay.so"

sshnodelay.so:
	$(CC) -Wall -W -s --shared -fPIC $(sshnodelay_libs) sshnodelay.c -o sshnodelay.so
endif
