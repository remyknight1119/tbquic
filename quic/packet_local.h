#ifndef TBQUIC_QUIC_PACKET_LOCAL_H_
#define TBQUIC_QUIC_PACKET_LOCAL_H_

#include <openssl/buffer.h>

typedef struct {
    /* Pointer to where we are currently reading from */
    const uint8_t *curr;
    /* Number of bytes remaining */
    size_t remaining;
} RPacket;

typedef struct {
    BUF_MEM *buf;
    size_t written;
} WPacket;

typedef struct {
	uint8_t flags;
	uint8_t	dest_conn_id_len;
    const uint8_t *dest_conn_id;
	uint8_t	source_conn_id_len;
    const uint8_t *source_conn_id;
    uint32_t version;
    RPacket frame;
} Packet;

void RPacketBufInit(RPacket *, const uint8_t *, size_t);
void RPacketForward(RPacket *, size_t);
size_t RPacketRemaining(const RPacket *);
const uint8_t *RPacketData(const RPacket *);
int RPacketPeekBytes(const RPacket *, const uint8_t **, size_t);
int RPacketGetBytes(RPacket *, const uint8_t **, size_t);
int RPacketPeekCopyBytes(const RPacket *, uint8_t *, size_t);
int RPacketCopyBytes(RPacket *, uint8_t *, size_t);
int RPacketPeek1(const RPacket *, uint8_t *);
int RPacketGet1(RPacket *, uint8_t *);
int RPacketPeek4(const RPacket *, uint32_t *);
int RPacketGet4(RPacket *, uint32_t *);

#endif
