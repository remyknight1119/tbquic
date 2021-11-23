#ifndef TBQUIC_QUIC_CIPHER_H_
#define TBQUIC_QUIC_CIPHER_H_

#include <stdint.h>
#include <stddef.h>
#include <openssl/evp.h>

#include <tbquic/types.h>

#define TLS13_AEAD_NONCE_LENGTH     12
#define AES_KEY_MAX_SIZE    32

enum {
    QUIC_DIGEST_SHA256,
    QUIC_DIGEST_SHA384,
    QUIC_DIGEST_MAX,
};


struct QuicCipher {
    uint32_t alg;
    int enc;
    EVP_CIPHER_CTX *ctx;
};

typedef struct {
    QUIC_CIPHER   cipher;  /**< Header protection cipher. */
} QuicHPCipher;

typedef struct {
    int nid;
    uint32_t tag_len;
    size_t (*get_cipher_len)(size_t, size_t);
} QuicCipherSuite;

typedef struct {
    QUIC_CIPHER   cipher;  /**< Packet protection cipher. */
    uint8_t       iv[TLS13_AEAD_NONCE_LENGTH];
} QuicPPCipher;

struct QuicCiphers {
    QuicHPCipher hp_cipher;
    QuicPPCipher pp_cipher;
};

int QuicCreateInitialDecoders(QUIC *, uint32_t);
void QuicCipherCtxFree(QUIC_CIPHERS *);
int QuicCipherNidFind(uint32_t);
size_t QuicCipherLenGet(uint32_t, size_t);
int QuicCipherGetTagLen(uint32_t);
int QuicDoCipher(QUIC_CIPHER *, uint8_t *, size_t *, size_t,
                    const uint8_t *, size_t);

#endif
