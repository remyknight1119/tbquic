/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include <tbquic/quic.h>

#include "cipher.h"
#include "log.h"

int QuicInit(void)
{
    if (QuicLoadCiphers() < 0) {
        return -1;
    }

	return 0;
}
