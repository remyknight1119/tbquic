#ifndef TBQUIC_QUIC_QUIC_LOCAL_H_
#define TBQUIC_QUIC_QUIC_LOCAL_H_

#include <stdint.h>

#include <openssl/bio.h>
#include <tbquic/quic.h>

#include "statem.h"
#include "buffer.h"

struct QuicMethod {
    int (*quic_handshake)(QUIC *);
};


struct QuicCtx {
    const QUIC_METHOD *method;
};

struct Quic {
    enum StreamState state;
    const QUIC_CTX *ctx;
    BIO *rbio;
    BIO *wbio;
    QuicBufMem *buffer;
};

#endif
