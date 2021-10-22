#ifndef TBQUIC_SRC_PACKET_LOCAL_H_
#define TBQUIC_SRC_PACKET_LOCAL_H_

typedef struct {
    /* Pointer to where we are currently reading from */
    const unsigned char *curr;
    /* Number of bytes remaining */
    size_t remaining;
} Packet;

static inline void PacketForward(Packet *pkt, size_t len)
{
    pkt->curr += len;
    pkt->remaining -= len;
}

/*
 * Returns the number of bytes remaining to be read in the PACKET
 */
static inline size_t PacketRemaining(const Packet *pkt)
{
    return pkt->remaining;
}

#endif
