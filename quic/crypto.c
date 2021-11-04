/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "crypto.h"

#include <openssl/hmac.h>

uint8_t *HkdfExtract(const EVP_MD *evp_md, const uint8_t *salt, size_t salt_len,
                        const uint8_t *key, size_t key_len, uint8_t *prk,
                        size_t *prk_len)
{
    unsigned int tmp_len;

    if (!HMAC(evp_md, (const unsigned char *)salt, salt_len,
                (const unsigned char *)key, key_len,
                (unsigned char *)prk, &tmp_len)) {
        return NULL;
    }

    *prk_len = tmp_len;
    return prk;
}
