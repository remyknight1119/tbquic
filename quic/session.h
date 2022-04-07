#ifndef TBQUIC_QUIC_SESSION_H_
#define TBQUIC_QUIC_SESSION_H_

#define TLS_MAX_RESUMPTION_PSK_LENGTH       256

#include <time.h>
#include <tbquic/types.h>

#include "base.h"
#include "list.h"
#include "tls.h"
#include "packet_local.h"

#define QUIC_SESSION_TICKET_LIFETIME_HINT_DEF   172800
#define QUIC_SESSION_TICKET_LEN                 180

typedef struct {
    struct list_head node;
     /* Session lifetime hint in seconds */
    uint64_t lifetime_hint;
    time_t time;
    uint32_t age_add;
    QUIC_DATA ticket;
    uint8_t master_key[TLS_MAX_RESUMPTION_PSK_LENGTH];
    size_t master_key_length;
} QuicSessionTicket;

struct QuicSession {
    const TlsCipher *cipher;
    uint32_t tick_identity;
    int references;
    struct list_head ticket_queue;
};

QUIC_SESSION *QuicSessionCreate(void);
void QuicSessionUpRef(QUIC_SESSION *);
void QuicSessionFree(QUIC_SESSION *);
int QuicGetSession(QUIC *);
QuicSessionTicket *QuicSessionTicketNew(uint32_t, uint32_t, const uint8_t *,
                                        size_t);
QuicSessionTicket *QuicSessionTicketGet(QUIC_SESSION *, uint32_t *);
void QuicSessionTicketAdd(QUIC_SESSION *, QuicSessionTicket *);
int QuicSessionMasterKeyGen(TLS *, QuicSessionTicket *, RPacket *);
void QuicSessionTicketFree(QuicSessionTicket *);

#endif
