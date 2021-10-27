/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "statem.h"

#include "quic_local.h"
#include "common.h"
#include "datagram.h"
#include "packet_format.h"
#include "packet_local.h"

static int QuicServerReadyRead(QUIC *quic);
static int QuicServerReadyWrite(QUIC *quic);

static QuicStateMachine ServerStateMachine[] = {
    {
        .state = QUIC_STREAM_STATE_READY,
        .read = QuicServerReadyRead,
        .write = QuicServerReadyWrite,
    },
};

#define QUIC_SERVER_STATEM_NUM QUIC_ARRAY_SIZE(ServerStateMachine)

static int QuicServerReadyRead(QUIC *quic)
{
    RPacket pkt = {};

    QuicPacketHeader *header = NULL;
    int read_bytes = 0;

    read_bytes = QuicReadBytes(quic);
    if (read_bytes <= sizeof(*header)) {
        return -1;
    }

    header = (void *)QUIC_R_BUFFER_HEAD(quic);
    RPacketBufInit(&pkt, (const unsigned char *)(header + 1),
            read_bytes - sizeof(*header));

    return 0;
}

static int QuicServerReadyWrite(QUIC *quic)
{
    return 0;
}

int QuicAccept(QUIC *quic)
{
    return QuicStateMachineAct(quic, ServerStateMachine, QUIC_SERVER_STATEM_NUM);
}
