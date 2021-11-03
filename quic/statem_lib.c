/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "statem.h"

#include "datagram.h"
#include "packet_format.h"
#include "packet_local.h"
#include "quic_local.h"

int QuicStreamRead(QUIC *quic, Packet *packet)
{
    uint32_t flags = 0;
    int read_bytes = 0;

    read_bytes = QuicReadBytes(quic);
    RPacketBufInit(&packet->frame, (const uint8_t *)QUIC_R_BUFFER_HEAD(quic),
            read_bytes);

    if (RPacketGet1(&packet->frame, &flags) < 0) {
        return -1;
    }

    packet->flags = flags;
    printf("read %d\n", read_bytes);
    return QuicPacketParse(packet);
}


