#ifndef TBQUIC_QUIC_CIPHER_H_
#define TBQUIC_QUIC_CIPHER_H_

#include <stdint.h>
#include <stddef.h>
#include <openssl/evp.h>

#include <tbquic/types.h>

#define TLS13_AEAD_NONCE_LENGTH     12
#define AES_KEY_MAX_SIZE    32

#define MASTER_SECRET_LABEL "CLIENT_RANDOM"
#define CLIENT_EARLY_LABEL "CLIENT_EARLY_TRAFFIC_SECRET"
#define CLIENT_HANDSHAKE_LABEL "CLIENT_HANDSHAKE_TRAFFIC_SECRET"
#define SERVER_HANDSHAKE_LABEL "SERVER_HANDSHAKE_TRAFFIC_SECRET"
#define CLIENT_APPLICATION_LABEL "CLIENT_TRAFFIC_SECRET_0"
#define SERVER_APPLICATION_LABEL "SERVER_TRAFFIC_SECRET_0"
#define EARLY_EXPORTER_SECRET_LABEL "EARLY_EXPORTER_SECRET"
#define EXPORTER_SECRET_LABEL "EXPORTER_SECRET"

enum {
    QUIC_DIGEST_SHA256,
    QUIC_DIGEST_SHA384,
    QUIC_DIGEST_SHA512,
    QUIC_DIGEST_SHA1,
    QUIC_DIGEST_MAX,
};

enum {
    QUIC_SIG_RSA,
    QUIC_SIG_ECC,
    QUIC_SIG_MAX,
};

struct QuicCipher {
    uint32_t alg;
//    uint32_t digest;
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


#ifdef QUIC_TEST
extern void (*QuicSecretTest)(uint8_t *secret);
#endif
int QuicCreateInitialDecoders(QUIC *, uint32_t);
int QuicCreateHandshakeServerDecoders(QUIC *);
int QuicCreateHandshakeClientEncoders(QUIC *);
int QuicCreateAppDataServerDecoders(QUIC *);
int QuicCreateAppDataClientEncoders(QUIC *);
void QuicCipherCtxFree(QUIC_CIPHERS *);
int QuicCipherNidFind(uint32_t);
size_t QuicCipherLenGet(uint32_t, size_t);
int QuicCipherGetTagLen(uint32_t);
int QuicDoCipher(QUIC_CIPHER *, uint8_t *, size_t *, size_t,
                    const uint8_t *, size_t);
const EVP_MD *QuicMd(uint32_t);
int QuicLoadCiphers(void);

#endif
