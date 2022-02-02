#ifndef TBQUIC_QUIC_CONNECTION_H_
#define TBQUIC_QUIC_CONNECTION_H_

#include <tbquic/types.h>
#include "base.h"
#include "list.h"

#define QUIC_STATELESS_RESET_TOKEN_LEN  16

typedef struct {
    struct list_head node; 
    uint64_t seq;
    QUIC_DATA id;
    uint8_t stateless_reset_token[QUIC_STATELESS_RESET_TOKEN_LEN];
} QuicCid;

typedef struct {
    uint64_t max_seq;
    uint64_t retire_prior_to;
    int64_t num;
    struct list_head queue; 
} QuicCidPool;

typedef struct {
    QuicCidPool dcid;
    QuicCidPool scid;
} QuicConn;

int QuicCidGen(QUIC_DATA *, size_t);
QuicCid *QuicCidAlloc(uint64_t);
QuicCid *QuicCidIssue(QuicCidPool *, size_t);
void QuicCidAdd(QuicCidPool *, QuicCid *);
int QuicCidMatch(QuicCidPool *, void *, size_t);
int QuicCidRetire(QuicCidPool *, uint64_t);
void QuicCidRetirePriorTo(QuicCidPool *, uint64_t);
int QuicActiveCidLimitCheck(QuicCidPool *, uint64_t);
void QuicCheckStatelessResetToken(QUIC *, const uint8_t *);
int QuicConnInit(QuicConn *);
void QuicConnFree(QuicConn *);

#endif
