#ifndef TBQUIC_QUIC_QUIC_LOCAL_H_
#define TBQUIC_QUIC_QUIC_LOCAL_H_

#include <stdint.h>

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <tbquic/quic.h>

#include "statem.h"

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

struct Quic {
    enum StreamState state;
    const QUIC_CTX *ctx;
    const QUIC_METHOD *method;
    BIO *rbio;
    BIO *wbio;
    int (*handshake)(QUIC *);
    QUIC_BUFFER rbuffer;
    QUIC_BUFFER plain_buffer;
    QUIC_BUFFER wbuffer;
};

#endif