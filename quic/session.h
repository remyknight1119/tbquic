#ifndef TBQUIC_QUIC_SESSION_H_
#define TBQUIC_QUIC_SESSION_H_

#define TLS_MAX_RESUMPTION_PSK_LENGTH       256

#include <tbquic/types.h>

#include "base.h"
#include "list.h"
#include "tls.h"
#include "packet_local.h"

typedef struct {
    struct list_head node;
     /* Session lifetime hint in seconds */
    uint64_t lifetime_hint;
    uint32_t age_add;
    QUIC_DATA ticket;
    uint8_t master_key[TLS_MAX_RESUMPTION_PSK_LENGTH];
    size_t master_key_length;
} QuicSessionTicket;

struct QuicSession {
    struct list_head ticket_queue;
};

QUIC_SESSION *QuicSessionCreate(void);
void QuicSessionDestroy(QUIC_SESSION *);
int QuicGetSession(QUIC *);
QuicSessionTicket *QuicSessionTicketNew(uint32_t, uint32_t, const uint8_t *,
                                        size_t);
void QuicSessionTicketAdd(QUIC_SESSION *, QuicSessionTicket *);
int QuicSessionMasterKeyGen(TLS *, QuicSessionTicket *, RPacket *);

#endif
