/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "packet_local.h"

void RPacketBufInit(RPacket *pkt, const unsigned char *buf, size_t len)
{
    pkt->curr = buf;
    pkt->remaining = len;
}

void RPacketForward(RPacket *pkt, size_t len)
{
    pkt->curr += len;
    pkt->remaining -= len;
}

/*
 * Returns the number of bytes remaining to be read in the RPacket
 */
size_t RPacketRemaining(const RPacket *pkt)
{
    return pkt->remaining;
}

const unsigned char *RPacketData(const RPacket *pkt)
{
    return pkt->curr;
}
