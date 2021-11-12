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
int QuicEvpCipher(EVP_CIPHER_CTX *, uint8_t *, const uint8_t *, size_t);
int QUIC_EVP_CIPHER_set_iv_len(EVP_CIPHER_CTX *, size_t);
int QUIC_EVP_CIPHER_gcm_set_tag(EVP_CIPHER_CTX *, size_t, uint8_t *);

#endif
