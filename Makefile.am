## Process this file with automake to produce Makefile.in

bin_PROGRAMS = sshfs

sshfs_SOURCES = sshfs.c cache.c cache.h sshnodelay_so.c
if FUSE_OPT_COMPAT
sshfs_SOURCES += compat/fuse_opt.c compat/fuse_opt.h
endif

sshfs_CPPFLAGS = -DFUSE_USE_VERSION=26

EXTRA_DIST = sshnodelay.c bin2c.c
CLEANFILES = sshnodelay.so sshnodelay_so.c bin2c

sshnodelay_so.c: bin2c sshnodelay.so
	./bin2c sshnodelay_so < sshnodelay.so > sshnodelay_so.c

sshnodelay.so:
	$(CC) -Wall -W -s --shared -ldl sshnodelay.c -o sshnodelay.so
