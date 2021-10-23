#ifndef TBQUIC_SRC_QUIC_LOCAL_H_
#define TBQUIC_SRC_QUIC_LOCAL_H_

#include <stdint.h>

#include <openssl/bio.h>
#include <tbquic/quic.h>

struct QuicMethod {
    int (*quic_handshake)(QUIC *);
};


struct QuicCtx {
    const QUIC_METHOD *method;
};

struct Quic {
    uint32_t state;
    const QUIC_CTX *ctx;
    BIO *rbio;
    BIO *wbio;
};

#endif
