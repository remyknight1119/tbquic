/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "stream.h"

#include "quic_local.h"

int QuicStreamInit(QUIC *quic)
{
    QuicStreamState *s = &quic->stream_state;

    s->recv_state = QUIC_STREAM_STATE_START;
    s->send_state = QUIC_STREAM_STATE_START;

    return 0;
}

