bin_PROGRAMS = quic_client quic_server
quic_client_SOURCES = quic_client.c
quic_server_SOURCES = quic_server.c
quic_client_LDADD = $(srcdir)/../src/libtbquic.la
quic_server_LDADD = $(srcdir)/../src/libtbquic.la

AM_CPPFLAGS = -I$(srcdir)/../include -lm
AM_CFLAGS = -Wall -Werror
