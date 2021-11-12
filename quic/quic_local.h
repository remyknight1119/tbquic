#ifndef TBQUIC_QUIC_QUIC_LOCAL_H_
#define TBQUIC_QUIC_QUIC_LOCAL_H_

#include <stdint.h>

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <tbquic/quic.h>

#include "statem.h"
#include "cipher.h"

#define QUIC_VERSION_1      0x01

#define QUIC_BUFFER_HEAD(buffer) buffer.buf->data
#define QUIC_R_BUFFER_HEAD(quic) QUIC_BUFFER_HEAD(quic->rbuffer)
#define QUIC_P_BUFFER_HEAD(quic) QUIC_BUFFER_HEAD(quic->plain_buffer)
#define QUIC_W_BUFFER_HEAD(quic) QUIC_BUFFER_HEAD(quic->wbuffer)

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
    uint8_t *data;
    size_t len;
} QUIC_DATA;

typedef struct {
    QUIC_CIPHERS ciphers;
    uint64_t pkt_num;
} QuicCipherSpace;

struct Quic {
    QUIC_STREAM_STATE state;
    uint8_t server:1;
    const QUIC_CTX *ctx;
    const QUIC_METHOD *method;
    BIO *rbio;
    BIO *wbio;
    int (*do_handshake)(QUIC *);
    QUIC_BUFFER rbuffer;
    QUIC_BUFFER plain_buffer;
    QUIC_BUFFER wbuffer;
    QUIC_DATA peer_dcid;
    struct {
        QuicCipherSpace client;
        QuicCipherSpace server;
    } initial;
    struct {
        QUIC_CIPHERS ciphers;
    } zero_rtt;
    struct {
        QuicCipherSpace client;
        QuicCipherSpace server;
    } handshake;
};


#endif
