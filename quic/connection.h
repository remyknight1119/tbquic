#ifndef TBQUIC_QUIC_CONNECTION_H_
#define TBQUIC_QUIC_CONNECTION_H_

#include "base.h"

#define QUIC_STATELESS_RESET_TOKEN_LEN  16

typedef struct {
    QUIC_DATA id;
    uint8_t stateless_reset_token[QUIC_STATELESS_RESET_TOKEN_LEN];
} QuicConn;

void QuicConnFree(QuicConn *c);

#endif
