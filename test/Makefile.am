bin_PROGRAMS = quic_client quic_server quic_test
quic_client_SOURCES = quic_client.c
quic_server_SOURCES = quic_server.c
quic_test_SOURCES = quic_test.c format.c crypto.c
quic_client_LDADD = $(srcdir)/../quic/libtbquic.la
quic_server_LDADD = $(srcdir)/../quic/libtbquic.la
quic_test_LDADD = $(srcdir)/../quic/libtbquic.la

AM_CPPFLAGS = -I$(srcdir)/../include -I$(srcdir)/../quic -lm
AM_CFLAGS = -Wall -Werror
