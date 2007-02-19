AC_INIT(sshfs-fuse, 1.7)
AM_INIT_AUTOMAKE
AM_CONFIG_HEADER(config.h)

AC_PROG_CC
CFLAGS="$CFLAGS -Wall -W"
LIBS=
AC_SEARCH_LIBS(dlsym, [dl])
sshnodelay_libs=$LIBS
AC_SUBST(sshnodelay_libs)
LIBS=

AC_ARG_ENABLE(sshnodelay,
	[  --disable-sshnodelay    Don't compile NODELAY workaround for ssh])

if test "$enable_sshnodelay" != "no"; then
	AC_DEFINE(SSH_NODELAY_WORKAROUND, 1, [Compile ssh NODELAY workaround])
fi

AM_CONDITIONAL(SSH_NODELAY_SO, test "$enable_sshnodelay" != "no")

export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH
PKG_CHECK_MODULES(SSHFS, [fuse >= 2.2 glib-2.0])
have_fuse_opt_parse=no
AC_CHECK_FUNC([fuse_opt_parse], [have_fuse_opt_parse=yes])
if test "$have_fuse_opt_parse" = no; then
	CFLAGS="$CFLAGS -Icompat"
fi
AM_CONDITIONAL(FUSE_OPT_COMPAT, test "$have_fuse_opt_parse" = no)

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
