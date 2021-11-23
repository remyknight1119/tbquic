lib_LTLIBRARIES = libtbquic.la
libtbquic_la_SOURCES = core.c quic_lib.c mem.c statem_clnt.c statem_srvr.c \
						methods.c statem.c datagram.c packet.c statem_lib.c \
						packet_format.c cipher.c crypto.c evp.c frame.c \
						buffer.c cert_and_key.c tls.c tls_clnt.c tls_srvr.c \
						rand_lib.c tls_cipher.c
libtbquic_la_LDFLAGS = -version-info 1

AM_CPPFLAGS = -I$(srcdir)/../include -DQUIC_TEST
AM_CFLAGS = -Wall -Werror
AUTOMAKE_OPTIONS = foreign subdir-objects
