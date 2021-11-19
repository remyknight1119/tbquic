/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "statem.h"

#include "datagram.h"
#include "packet_format.h"
#include "packet_local.h"
#include "quic_local.h"

int QuicStreamRead(QUIC *quic)
{
    RPacket pkt = {};
    uint32_t flags = 0;
    int ret = 0;

    ret = QuicDatagramRecv(quic);
    if (ret < 0) {
        return -1;
    }
    RPacketBufInit(&pkt, (const uint8_t *)QUIC_R_BUFFER_HEAD(quic),
            QUIC_R_BUFFER_DATA_LEN(quic));

    //One packet maybe contain multiple QUIC messages
    while (RPacketGet1(&pkt, &flags) >= 0) {
        if (QuicPacketParse(quic, &pkt, flags) < 0) {
            return -1;
        }
        RPacketHeadSync(&pkt);
    }

    return 0;
}


