AC_INIT(sshfs, 2.10)
AC_CANONICAL_TARGET
AM_INIT_AUTOMAKE([foreign subdir-objects])
AM_CONFIG_HEADER(config.h)

AC_PROG_CC
AM_PROG_CC_C_O
CFLAGS="$CFLAGS -Wall -W"
LIBS=
AC_SEARCH_LIBS(dlsym, [dl])
LIBS=

case "$target_os" in
    *linux*) osname=linux;;
    *darwin*) osname=darwin;;
    *) osname=unknown;;
esac

export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH
PKG_CHECK_MODULES([SSHFS], [fuse >= 2.3 glib-2.0 gthread-2.0])
have_fuse_opt_parse=no
oldlibs="$LIBS"
LIBS="$LIBS $SSHFS_LIBS"
AC_CHECK_FUNC([fuse_opt_parse], [have_fuse_opt_parse=yes])
LIBS="$oldlibs"
if test "$have_fuse_opt_parse" = no -o "$osname" = darwin; then
	CFLAGS="$CFLAGS -I${srcdir}/compat"
fi
AM_CONDITIONAL(FUSE_OPT_COMPAT, test "$have_fuse_opt_parse" = no)
AM_CONDITIONAL(DARWIN_COMPAT, test "$osname" = darwin)

AC_CHECK_PROG(UNMOUNT_COMMAND, fusermount, fusermount -u, umount)

# TODO: Figure out why we special-case this in Darwin.  Would be nice if
# the default setting was consistent across platforms so we wouldn't need
# to care about it here.
case "$osname" in
    darwin) IDMAP_DEFAULT=user ;;
    *) IDMAP_DEFAULT=none ;;
esac
AC_SUBST(IDMAP_DEFAULT)

AC_CONFIG_FILES([Makefile test/Makefile])
AC_OUTPUT
