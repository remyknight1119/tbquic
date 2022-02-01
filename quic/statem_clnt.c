/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "statem.h"

#include <assert.h>
#include <openssl/rand.h>

#include "quic_local.h"
#include "format.h"
#include "common.h"
#include "datagram.h"
#include "mem.h"
#include "rand.h"
#include "log.h"

static QuicFlowReturn QuicClientInitialRecv(QUIC *, RPacket *,
                                            QuicPacketFlags);
static int QuicClientInitialSend(QUIC *);

static QuicStatemFlow client_statem[QUIC_STATEM_MAX] = {
    [QUIC_STATEM_INITIAL] = {
        .pre_work = QuicClientInitialSend,
        .recv = QuicClientInitialRecv,
    },
    [QUIC_STATEM_HANDSHAKE] = {
        .recv = QuicPacketRead,
    },
    [QUIC_STATEM_HANDSHAKE_DONE] = {
        .recv = QuicPacketRead,
    },
};

static int QuicClientInitialSend(QUIC *quic)
{
    QUIC_DATA *cid = NULL;
    int ret = 0;

    cid = &quic->dcid;
    if (cid->data == NULL && QuicCidGen(cid, quic->cid_len) < 0) {
        return -1;
    }

    if (QuicCreateInitialDecoders(quic, quic->version, cid) < 0) {
        return -1;
    }

    ret = QuicInitialSend(quic);
    QuicBufReserve(QUIC_TLS_BUFFER(quic));
    return ret;
}

static QuicFlowReturn
QuicClientInitialRecv(QUIC *quic, RPacket *pkt, QuicPacketFlags flags)
{
    QuicFlowReturn ret;

    ret = QuicInitialRecv(quic, pkt, flags);
    if (ret == QUIC_FLOW_RET_ERROR) {
        return ret;
    }

    quic->statem.state = QUIC_STATEM_HANDSHAKE;

    return QUIC_FLOW_RET_WANT_READ;
}

int QuicConnect(QUIC *quic)
{
    return QuicStateMachineAct(quic, client_statem, QUIC_NELEM(client_statem));
}

