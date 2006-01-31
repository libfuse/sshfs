AC_INIT(sshfs-fuse, 1.4)
AM_INIT_AUTOMAKE
AM_CONFIG_HEADER(config.h)

AC_PROG_CC
LIBS=
AC_SEARCH_LIBS(dlsym, [dl])
sshnodelay_libs=$LIBS
AC_SUBST(sshnodelay_libs)

export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH
PKG_CHECK_MODULES(SSHFS, [fuse >= 2.2 glib-2.0])
CFLAGS="$CFLAGS -Wall -W -D_REENTRANT $SSHFS_CFLAGS"
LIBS="$SSHFS_LIBS"
have_fuse_opt_parse=no
AC_CHECK_FUNC([fuse_opt_parse], [have_fuse_opt_parse=yes])
if test "$have_fuse_opt_parse" = no; then
	CFLAGS="$CFLAGS -Icompat"
fi
AM_CONDITIONAL(FUSE_OPT_COMPAT, test "$have_fuse_opt_parse" = no)

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
