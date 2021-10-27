#ifndef TBQUIC_QUIC_PACKET_LOCAL_H_
#define TBQUIC_QUIC_PACKET_LOCAL_H_

#include <openssl/buffer.h>

typedef struct {
    /* Pointer to where we are currently reading from */
    const unsigned char *curr;
    /* Number of bytes remaining */
    size_t remaining;
} RPacket;

typedef struct {
    BUF_MEM *buf;
    size_t written;
} WPacket;

void RPacketBufInit(RPacket *pkt, const unsigned char *buf, size_t len);
void RPacketForward(RPacket *pkt, size_t len);
size_t RPacketRemaining(const RPacket *pkt);
const unsigned char *RPacketData(const RPacket *pkt);

#endif
