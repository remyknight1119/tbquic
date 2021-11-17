/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "tls.h"

#include <tbquic/types.h>
#include <tbquic/quic.h>

#include "packet_local.h"


int QuicTlsConnect(QUIC_TLS *tls, const uint8_t *data, size_t len)
{
    RPacket pkt = {};

    RPacketBufInit(&pkt, data, len);

    return 0;
}

int QuicTlsClientInit(QUIC_TLS *tls)
{
    tls->handshake = QuicTlsConnect;
    tls->state = QUIC_TLS_ST_SERVER_HELLO;
    tls->server = 0;

    return 0;
}
