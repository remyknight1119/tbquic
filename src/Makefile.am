lib_LTLIBRARIES = libtbquic.la
libtbquic_la_SOURCES = core.c quic_lib.c mem.c stream_clnt.c stream_srvr.c \
											 methods.c
libtbquic_la_LDFLAGS = -version-info 1

AM_CPPFLAGS = -I$(srcdir)/../include -Istatem -Irecord
AM_CFLAGS = -Wall -Werror
AUTOMAKE_OPTIONS = foreign subdir-objects
