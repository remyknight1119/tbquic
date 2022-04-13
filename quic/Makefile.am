lib_LTLIBRARIES = libtbquic.la
libtbquic_la_SOURCES = quic_lib.c mem.c statem_clnt.c statem_srvr.c  q_buff.c \
						methods.c statem.c datagram.c packet.c cert.c stream.c \
						format.c cipher.c crypto.c evp.c frame.c base.c core.c \
						buffer.c cert_and_key.c tls/tls.c tls/tls_clnt.c \
						tls/tls_srvr.c rand_lib.c tls/tls_cipher.c \
						tls/tls_msg.c tls/extension.c tls/extension_clnt.c \
						tls/extension_srvr.c tls/sig_alg.c transport.c \
						tls/tls_lib.c dispenser.c address.c connection.c \
						quic_time.c session.c asn1.c
libtbquic_la_LDFLAGS = -version-info 1

AM_CPPFLAGS = -I$(srcdir)/../include -I$(srcdir)/tls -DQUIC_TEST
AM_CFLAGS = -Wall -Werror
AUTOMAKE_OPTIONS = foreign subdir-objects
