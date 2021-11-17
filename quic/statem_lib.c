/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "statem.h"

#include "datagram.h"
#include "packet_format.h"
#include "packet_local.h"
#include "quic_local.h"

int QuicStreamRead(QUIC *quic, RPacket *pkt)
{
    uint32_t flags = 0;
    int read_bytes = 0;

    read_bytes = QuicReadBytes(quic);
    RPacketBufInit(pkt, (const uint8_t *)QUIC_R_BUFFER_HEAD(quic),
            read_bytes);

    //One packet maybe contain multiple QUIC messages
    while (RPacketGet1(pkt, &flags) >= 0) {
        if (QuicPacketParse(quic, pkt, flags) < 0) {
            return -1;
        }
    }

    return 0;
}


