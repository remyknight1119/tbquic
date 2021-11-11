#ifndef TBQUIC_QUIC_EVP_H_
#define TBQUIC_QUIC_EVP_H_

#include <openssl/evp.h>

#define QUIC_EVP_DECRYPT    0
#define QUIC_EVP_ENCRYPT    1

int QuicEvpCipherInit(EVP_CIPHER_CTX *, const EVP_CIPHER *, const uint8_t *,
                        const uint8_t *, int);
int QuicEvpCipherUpdate(EVP_CIPHER_CTX *, uint8_t *, size_t *, const uint8_t *,
                        size_t);
int QuicEvpCipherFinal(EVP_CIPHER_CTX *, uint8_t *, size_t *);

#endif
