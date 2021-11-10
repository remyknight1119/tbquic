#ifndef TBQUIC_QUIC_CRYPTO_H_
#define TBQUIC_QUIC_CRYPTO_H_

#include <openssl/crypto.h>

#define HASH_MD5_LENGTH      16
#define HASH_SHA1_LENGTH     20
#define HASH_SHA2_224_LENGTH 28
#define HASH_SHA2_256_LENGTH 32
#define HASH_SHA2_384_LENGTH 48
#define HASH_SHA2_512_LENGTH 64

uint8_t *HkdfExtract(const EVP_MD *, const uint8_t *, size_t, const uint8_t *,
                        size_t, uint8_t *, size_t *);
uint8_t *HkdfExpand(const EVP_MD *, const uint8_t *, size_t, const uint8_t *,
                        size_t, uint8_t *, size_t);
int QuicTLS13HkdfExpandLabel(const EVP_MD *, const uint8_t *, size_t,
                        const uint8_t *, size_t, uint8_t *, size_t);

#endif
