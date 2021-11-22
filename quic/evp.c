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

int QuicEvpCipher(EVP_CIPHER_CTX *ctx, uint8_t *out, const uint8_t *in,
                    size_t inl)
{
    if (EVP_Cipher(ctx, (unsigned char *)out, (const unsigned char *)in,
                        (unsigned int)inl) <= 0) {
        return -1;
    }

    return 0;
}

int QuicEvpCipherCtxCtrl(EVP_CIPHER_CTX *ctx, uint32_t type, int arg, void *ptr)
{
    if (EVP_CIPHER_CTX_ctrl(ctx, type, arg, ptr) == 0) {
        return -1; 
    }

    return 0;
}

int QUIC_EVP_CIPHER_set_iv_len(EVP_CIPHER_CTX *ctx, size_t len)
{
    return QuicEvpCipherCtxCtrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, (int)len, NULL);
}

int QUIC_EVP_CIPHER_gcm_set_tag(EVP_CIPHER_CTX *ctx, size_t tag_len,
                                uint8_t *data)
{
    return QuicEvpCipherCtxCtrl(ctx, EVP_CTRL_GCM_SET_TAG, (int)tag_len, data);
}

int QUIC_EVP_CIPHER_gcm_get_tag(EVP_CIPHER_CTX *ctx, size_t tag_len,
                                uint8_t *data)
{
    return QuicEvpCipherCtxCtrl(ctx, EVP_CTRL_GCM_GET_TAG, (int)tag_len, data);
}

