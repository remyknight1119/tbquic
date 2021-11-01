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
    QuicPacketHandler handler = NULL;
    int read_bytes = 0;

    read_bytes = QuicReadBytes(quic);
    RPacketBufInit(&packet->frame, (const uint8_t *)QUIC_R_BUFFER_HEAD(quic),
            read_bytes);

    if (RPacketGet1(&packet->frame, &packet->flags) < 0) {
        return -1;
    }

    printf("read %d, f = %x, type = %x\n", read_bytes, packet->flags, QUIC_PACKET_HEADER_GET_TYPE(packet->flags));
    handler = QuicPacketHandlerFind(packet->flags);
    if (handler == NULL) {
        return -1;
    }

    return handler(packet);
}


