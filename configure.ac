AC_INIT([tbquic], [1.0], [remyknight1119@gmail.com])
AM_INIT_AUTOMAKE([-Wall -Werror])
AC_PROG_CC
LT_INIT
AC_PROG_LIBTOOL
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([config.h])

AC_ARG_WITH(libssl_includes,
			[  --with-libssl-includes=DIR    openssl include directory],
			[with_libssl_includes="$withval"],
			[with_libssl_includes=no])

AC_ARG_WITH(libssl_libraries,
			[  --with-libssl-libraries=DIR   openssl library directory],
			[with_libssl_libraries="$withval"],
			[with_libssl_libraries=no])

CPPFLAGS="${CPPFLAGS} -I/usr/local/include"

LIBS="${LIBS} -L/usr/local/lib"

if test "$with_libssl_libraries" != "no"; then
	LIBS="${LIBS} -L${with_libssl_libraries}"
fi

LSSL=""
AC_CHECK_LIB([crypto], [OPENSSL_config], , LSSL="no")
AC_CHECK_LIB([ssl], [SSL_new], , LSSL="no")
if test "$LSSL" = "no"; then
    echo
    echo "   ERROR!  openssl library not found, go get it from"
    echo "   http://www.openssl.org/source/"
    echo "   or use the --with-libssl-* options, if you have it installed"
    echo "   in unusual place"
    exit
fi

LSSL=""
AC_CHECK_HEADERS([openssl/ssl.h], , LSSL="no")
AC_CHECK_HEADERS([openssl/evp.h], , LSSL="no")
AC_CHECK_HEADERS([openssl/conf.h], , LSSL="no")
AC_CHECK_HEADERS([openssl/err.h], , LSSL="no")
AC_CHECK_HEADERS([openssl/engine.h], , LSSL="no")

if test "$LSSL" = "no"; then
    echo
    echo "   ERROR!  openssl headers not found, go get it from"
    echo "   http://www.openssl.org/source/"
    echo "   or use the --with-libssl-* options, if you have it installed"
    echo "   in unusual place"
    exit
fi

AC_CONFIG_FILES([
				 Makefile
				 quic/Makefile
				 test/Makefile
				 ])

AC_OUTPUT
