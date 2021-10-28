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
    QuicPacketHeader *header = NULL;
    size_t len = 0;
    int read_bytes = 0;

    read_bytes = QuicReadBytes(quic);
    len = sizeof(*header);
    if (read_bytes <= len) {
        return -1;
    }

    header = (void *)QUIC_R_BUFFER_HEAD(quic);
    len += header->dest_conn_id_len;
    if (read_bytes <= len) {
        return -1;
    }
    pkt->flags = header->flags;
    RPacketBufInit(pkt, (const unsigned char *)header + len,
            read_bytes - len);

    return 0;
}


