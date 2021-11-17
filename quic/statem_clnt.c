/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "statem.h"

#include <assert.h>
#include <openssl/rand.h>

#include "quic_local.h"
#include "common.h"
#include "mem.h"
#include "packet_format.h"

static int QuicClientInitialSend(QUIC *);
static QuicStateMachine client_statem[QUIC_STATEM_MAX] = {
    [QUIC_STATEM_READY] = {
        .write = QuicClientInitialSend,
    },
};

#define QUIC_CLIENT_STATEM_NUM QUIC_ARRAY_SIZE(client_statem)

static int QuicCidGen(QUIC_DATA *cid, size_t len)
{
    assert(cid->data == NULL);

    cid->data = QuicMemMalloc(len);
    if (cid->data == NULL) {
        return -1;
    }

    RAND_bytes(cid->data, len);
    cid->len = len;

    return 0;
}

static int QuicClientInitialSend(QUIC *quic)
{
    QUIC_DATA *cid = NULL;

    cid = &quic->dcid;
    if (cid->data == NULL && QuicCidGen(cid, QUIC_MAX_CID_LENGTH) < 0) {
        return -1;
    }

    if (QuicCreateInitialDecoders(quic, quic->version) < 0) {
        return -1;
    }

    printf("client init\n");
    return 0;
}

int QuicConnect(QUIC *quic)
{
    return QuicStateMachineAct(quic, client_statem, QUIC_CLIENT_STATEM_NUM);
}

