bin_PROGRAMS = quic_client quic_server quic_test
quic_client_SOURCES = quic_client.c tls_msg.c quic_lib.c
quic_server_SOURCES = quic_server.c quic_lib.c
quic_test_SOURCES = quic_test.c format.c hkdf_extract_expand.c \
					hkdf_expand_label.c packet_message.c tls.c \
					tls_msg.c tls_enc.c session.c
quic_client_LDADD = $(srcdir)/../quic/libtbquic.la
quic_server_LDADD = $(srcdir)/../quic/libtbquic.la
quic_test_LDADD = $(srcdir)/../quic/libtbquic.la

AM_CPPFLAGS = -I$(srcdir)/../include -I$(srcdir)/../quic \
			  -I$(srcdir)/../quic/tls -DQUIC_TEST
AM_CFLAGS = -Wall -Werror
