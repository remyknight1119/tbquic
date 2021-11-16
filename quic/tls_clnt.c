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
