/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "rand.h"

#include <openssl/rand.h>

int QuicRandBytes(uint8_t *buf, size_t num)
{
    if (RAND_bytes((unsigned char *)buf, num) == 0) {
        return -1;
    }

    return 0;
}
