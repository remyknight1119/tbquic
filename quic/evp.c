/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "evp.h"

#include <openssl/evp.h>


int QuicEvpCipherInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
                        const uint8_t *key, const uint8_t *iv,
                        int enc)
{
    if (EVP_CipherInit(ctx, cipher, (const unsigned char *)key,
                (const unsigned char *)iv, enc) == 0) {
        return -1;
    }

    return 0;
}

int QuicEvpCipherUpdate(EVP_CIPHER_CTX *ctx, uint8_t *out, size_t *outl,
                        const uint8_t *in, size_t inl)
{
    if (EVP_CipherUpdate(ctx, (unsigned char *)out, (int *)outl,
                        (const unsigned char *)in, (int)inl) == 0) {
        return -1;
    }

    return 0;
}

int QuicEvpCipherFinal(EVP_CIPHER_CTX *ctx, uint8_t *out, size_t *outl)
{
    if (EVP_CipherFinal(ctx, (unsigned char *)out, (int *)outl) == 0) {
        return -1;
    }

    return 0;
}
