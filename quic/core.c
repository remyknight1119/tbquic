/*
 * Remy Lewis(remyknight1119@gmail.com)
 */
#include <tbquic/quic.h>
#include <openssl/ssl.h>

#include "packet_format.h"
#include "log.h"

int QuicInit(void)
{
	if (OPENSSL_init_ssl(OPENSSL_INIT_LOAD_CONFIG, NULL) == 0) {
		QUIC_LOG("OpenSSL init failed!\n");
        return - 1;
	}
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();

	return 0;
}
