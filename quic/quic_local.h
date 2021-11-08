#ifndef TBQUIC_QUIC_QUIC_LOCAL_H_
#define TBQUIC_QUIC_QUIC_LOCAL_H_

#include <stdint.h>

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <tbquic/quic.h>

#include "statem.h"

#define QUIC_VERSION_1      0x01

#define TLS13_AEAD_NONCE_LENGTH     12

#define QUIC_BUFFER_HEAD(buffer) buffer.buf->data
#define QUIC_R_BUFFER_HEAD(quic) QUIC_BUFFER_HEAD(quic->rbuffer)
#define QUIC_P_BUFFER_HEAD(quic) QUIC_BUFFER_HEAD(quic->plain_buffer)
#define QUIC_W_BUFFER_HEAD(quic) QUIC_BUFFER_HEAD(quic->wbuffer)

struct QuicCipher {
    EVP_CIPHER_CTX *ctx;
};

typedef struct {
    QUIC_CIPHER   cipher;  /**< Header protection cipher. */
} QuicHPCipher;

typedef struct {
    QUIC_CIPHER   cipher;  /**< Packet protection cipher. */
    uint8_t       iv[TLS13_AEAD_NONCE_LENGTH];
} QuicPPCipher;

typedef struct {
    QuicHPCipher hp_cipher;
    QuicPPCipher pp_cipher;
} QUIC_CIPHERS;

struct QuicMethod {
    int (*handshake)(QUIC *);
};

struct QuicCtx {
    const QUIC_METHOD *method;
};

struct QuicBuffer {
    BUF_MEM *buf;
    size_t data_len;
};

typedef struct {
    uint8_t len;
    uint8_t *cid;
} QUIC_CID;

struct Quic {
    QUIC_STREAM_STATE state;
    uint8_t server:1;
    const QUIC_CTX *ctx;
    const QUIC_METHOD *method;
    BIO *rbio;
    BIO *wbio;
    int (*handshake)(QUIC *);
    QUIC_BUFFER rbuffer;
    QUIC_BUFFER plain_buffer;
    QUIC_BUFFER wbuffer;
    QUIC_CID peer_dcid;
    QUIC_CIPHERS client_init_ciphers;
    QUIC_CIPHERS server_init_ciphers;
    QUIC_CIPHERS zero_rtt_ciphers;
    QUIC_CIPHERS client_handshake_ciphers;
    QUIC_CIPHERS server_handshake_ciphers;
};


#endif
