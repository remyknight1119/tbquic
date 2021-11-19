/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "statem.h"

#include "quic_local.h"
#include "common.h"
#include "datagram.h"
#include "packet_format.h"
#include "packet_local.h"

static int QuicServerReadyRead(QUIC *);
static int QuicServerReadyWrite(QUIC *);

static QuicStateMachine server_statem[QUIC_STATEM_MAX] = {
    [QUIC_STATEM_READY] = {
        .read = QuicServerReadyRead,
        .write = QuicServerReadyWrite,
    },
};

#define QUIC_SERVER_STATEM_NUM QUIC_ARRAY_SIZE(server_statem)

static int QuicServerReadyRead(QUIC *quic)
{
    if (QuicStreamRead(quic) < 0) {
        return -1;
    }

    return 0;
}

static int QuicServerReadyWrite(QUIC *quic)
{
    return 0;
}

int QuicAccept(QUIC *quic)
{
    return QuicStateMachineAct(quic, server_statem, QUIC_SERVER_STATEM_NUM);
}
