dnl Process this file with autoconf to produce a configure script

AC_INIT([est], [1.0.0],[estinfo@lounge.org])
AC_COPYRIGHT([Copyright (c) 2014 Dan Harkins, <dharkins@lounge.org>
This configure script may be copied, distributed and modified under
the terms of the license included with this distribution; see COPYING
for more details])

AC_CONFIG_SRCDIR(client/cest.c)
AC_CONFIG_SRCDIR(server/sest.c)
AC_CONFIG_SRCDIR(ca/ca.c)
AC_CONFIG_SRCDIR(ecca/ecca.c)
AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE

AC_PROG_CC

AC_ARG_WITH([curl],
	[AS_HELP_STRING([--with-curl=PATH], [location of libcurl])],
	[curldir="$withval" custom_curl="yes"],
	[curldir="/usr/lib" custom_curl="no"]
)

AC_ARG_WITH(ssl,
	AS_HELP_STRING([--with-ssl=PATH], [location of OpenSSL]),
	[ssldir="$withval" custom_ssl="yes"],
	[ssldir="/usr/local/ssl" custom_ssl="no"]
)

CFLAGS="$CFLAGS -Wall -I$curldir/include"
LDFLAGS="$LDFLAGS -L$curldir/lib -L$curldir/lib/.libs"

CFLAGS="$CFLAGS -Wall -I$ssldir/include"
LDFLAGS="$LDFLAGS -L$ssldir/lib -L$ssldir"

AC_MSG_CHECKING([enable-debugging])
AC_ARG_ENABLE(debug,
	AC_HELP_STRING([--enable-debug],[Enable debugging]) [],
[ case "$enableval" in
  yes)
	AC_MSG_RESULT(yes)
	CFLAGS="$CFLAGS -g"
	;;
  *)	AC_MSG_RESULT(no)
  	;;
  esac ],
       AC_MSG_RESULT(no)
)

AC_CANONICAL_HOST
case $host in
*-linux*)
	AC_CHECK_LIB([dl], [dlopen], [],
        	   [AC_MSG_FAILURE([can't find libdl])],
		   [])
	AC_CHECK_LIB([pthread], pthread_create, [],
		   [AC_MSG_FAILURE([can't find pthread])],
		   [])
	AC_ARG_ENABLE(static,
		AS_HELP_STRING([--enable-static], [build static]),
		LDFLAGS="$LDFLAGS -static",
		[givemsg="yes" ld_msg="LD_LIBRARY_PATH"]
	)
	;;
*-darwin*)
	dnl static building is not supported on OSX
	givemsg="yes"
	ld_msg="DYLD_LIBRARY_PATH"
	;;
*-freebsd*)
	AC_CHECK_LIB([z], [zlibVersion], [],
	           [AC_MSG_FAILURE([can't find libz])],
		   [])
	AC_CHECK_LIB([pthread], pthread_create, [],
		   [AC_MSG_FAILURE([can't find pthread])],
		   [])
	AC_ARG_ENABLE(static,
		AS_HELP_STRING([--enable-static], [build static]),
		LDFLAGS="$LDFLAGS -static",
		[givemsg="yes" ld_msg="LD_LIBRARY_PATH"]
	)
	;;
*)
	AC_MSG_ERROR([EST has not been ported to your OS yet])

esac

AC_CHECK_LIB([crypto], [X509_REQ_new], [],
           [AC_MSG_FAILURE([can't find libcrypto])],
	   [])
AC_CHECK_LIB([ssl], [TLSv1_2_server_method], [],
	   tls_version_bad=yes,
	   [])

if test "x$tls_version_bad" = 'xyes'; then
  AC_CHECK_LIB([ssl], [TLSv1_server_method], 
  	     AC_DEFINE(OPENSSL_VERSION_TLSV1, 1, [old TLS version])
	     AC_SUBST(OPENSSL_VERSION_TLSV1, [1]),
	     [AC_MSG_FAILURE([can't find libssl])],
	     [])
fi

AC_CHECK_LIB([curl], [curl_easy_setopt], [],
	   [AC_MSG_FAILURE([can't find libcurl])],
	   [])

AC_MSG_CHECKING([whether to include TLS-pwd support])
AC_ARG_ENABLE(tlspwd,
	AC_HELP_STRING([--enable-tlspwd],[Enable TLS-pwd support]) [],
[ case "$enableval" in
  yes)
	AC_MSG_RESULT(yes)
	AC_DEFINE(OPENSSL_HAS_TLS_PWD, 1, [to enable tlspwd])
	AC_SUBST(OPENSSL_HAS_TLS_PWD, [1])
	;;
  *)	AC_MSG_RESULT(no)
  	;;
  esac ],
       AC_MSG_RESULT(no)
)

AC_CONFIG_FILES([Makefile \
	client/Makefile \
	server/Makefile \
	ca/Makefile \
	ecca/Makefile
])
AC_OUTPUT

if test "x$givemsg" = 'xyes'; then
   AC_MSG_NOTICE([Be sure to set $ld_msg appropriately])
fi
