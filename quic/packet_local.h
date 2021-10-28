#ifndef TBQUIC_QUIC_PACKET_LOCAL_H_
#define TBQUIC_QUIC_PACKET_LOCAL_H_

#include <openssl/buffer.h>

typedef struct {
	uint8_t flags;
    /* Pointer to where we are currently reading from */
    const unsigned char *curr;
    /* Number of bytes remaining */
    size_t remaining;
} RPacket;

typedef struct {
    BUF_MEM *buf;
    size_t written;
} WPacket;

void RPacketBufInit(RPacket *, const unsigned char *, size_t);
void RPacketForward(RPacket *, size_t);
size_t RPacketRemaining(const RPacket *);
const unsigned char *RPacketData(const RPacket *);
int RPacketPeekBytes(const RPacket *, const unsigned char **, size_t);
int RPacketGetBytes(RPacket *, const unsigned char **, size_t);
int RPacketPeekCopyBytes(const RPacket *, unsigned char *, size_t);
int RPacketCopyBytes(RPacket *, unsigned char *, size_t);

#endif
