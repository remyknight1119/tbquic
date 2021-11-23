#ifndef TBQUIC_QUIC_PACKET_LOCAL_H_
#define TBQUIC_QUIC_PACKET_LOCAL_H_

#include <openssl/buffer.h>

typedef struct {
    const uint8_t *head;
    /* Pointer to where we are currently reading from */
    const uint8_t *curr;
    /* Number of bytes remaining */
    size_t total_len;
    size_t remaining;
} RPacket;

typedef struct {
    BUF_MEM *buf;
    uint8_t *static_buf;
    size_t curr;
    size_t written;
    size_t maxsize;
} WPacket;

void RPacketBufInit(RPacket *, const uint8_t *, size_t);
void RPacketHeadSync(RPacket *);
size_t RPacketTotalLen(const RPacket *pkt);
const uint8_t *RPacketHead(const RPacket *pkt);
void RPacketForward(RPacket *, size_t);
size_t RPacketRemaining(const RPacket *);
const uint8_t *RPacketData(const RPacket *);
int RPacketPeekBytes(const RPacket *, const uint8_t **, size_t);
int RPacketGetBytes(RPacket *, const uint8_t **, size_t);
int RPacketPeekCopyBytes(const RPacket *, uint8_t *, size_t);
int RPacketCopyBytes(RPacket *, uint8_t *, size_t);
int RPacketPeek1(const RPacket *, uint32_t *);
int RPacketGet1(RPacket *, uint32_t *);
int RPacketPeek2(const RPacket *, uint32_t *);
int RPacketGet2(RPacket *, uint32_t *);
int RPacketPeek3(const RPacket *, uint32_t *);
int RPacketGet3(RPacket *, uint32_t *);
int RPacketPeek4(const RPacket *, uint32_t *);
int RPacketGet4(RPacket *, uint32_t *);
int RPacketTransfer(RPacket *, RPacket *, size_t);
void WPacketBufInit(WPacket *, BUF_MEM *);
void WPacketStaticBufInit(WPacket *, uint8_t *, size_t);
uint8_t *WPacket_get_curr(WPacket *);
int WPacket_get_space(WPacket *);
size_t WPacket_get_written(WPacket *);
int WPacketAllocateBytes(WPacket *, size_t, uint8_t **);
int WPacketPutValue(uint8_t *, size_t, size_t);
int WPacketPutBytes(WPacket *, uint32_t, size_t);
int WPacketPut1(WPacket *, uint32_t);
int WPacketPut2(WPacket *, uint32_t);
int WPacketPut3(WPacket *, uint32_t);
int WPacketPut4(WPacket *, uint32_t);
int WPacketMemcpy(WPacket *, const void *, size_t);
int WPacketMemmove(WPacket *, const void *, size_t);

#endif
