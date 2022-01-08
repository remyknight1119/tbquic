#ifndef TBQUIC_QUIC_PACKET_LOCAL_H_
#define TBQUIC_QUIC_PACKET_LOCAL_H_

#include <openssl/buffer.h>

typedef struct WPacketSub WPACKET_SUB;

typedef struct {
    const uint8_t *head;
    /* Pointer to where we are currently reading from */
    const uint8_t *curr;
    /* Number of bytes remaining */
    size_t total_len;
    size_t remaining;
} RPacket;

struct WPacketSub {
    WPACKET_SUB *parent;
    uint8_t *value;
    size_t val_len;
};

typedef struct {
    BUF_MEM *buf;
    uint8_t *static_buf;
    size_t curr;
    size_t written;
    size_t maxsize;
    WPACKET_SUB *subs;
} WPacket;

void RPacketBufInit(RPacket *, const uint8_t *, size_t);
void RPacketHeadSync(RPacket *);
size_t RPacketTotalLen(const RPacket *);
const uint8_t *RPacketHead(const RPacket *);
void RPacketHeadPush(RPacket *, size_t);
void RPacketForward(RPacket *, size_t);
size_t RPacketRemaining(const RPacket *);
size_t RPacketReadLen(const RPacket *);
const uint8_t *RPacketData(const RPacket *);
void RPacketUpdate(RPacket *);
int RPacketPull(RPacket *, size_t);
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
int RPacketGetLengthPrefixed1(RPacket *, RPacket *);
int RPacketGetLengthPrefixed2(RPacket *, RPacket *);
int PRacketContainsZeroByte(const RPacket *);
int RPacketSaveU16(RPacket *, uint16_t **, size_t *);
int PRacketMemDup(const RPacket *, uint8_t **, size_t *);
char *RPacketStrndup(const RPacket *);
void WPacketBufInit(WPacket *, BUF_MEM *);
void WPacketStaticBufInit(WPacket *, uint8_t *, size_t);
uint8_t *WPacket_get_curr(WPacket *);
int WPacket_get_space(WPacket *);
size_t WPacket_get_maxsize(WPacket *);
size_t WPacket_get_written(WPacket *);
int WPacketAllocateBytes(WPacket *, size_t, uint8_t **);
int WPacketPutValue(uint8_t *, size_t, size_t);
int WPacketPutBytes(WPacket *, uint32_t, size_t);
int WPacketPut1(WPacket *, uint32_t);
int WPacketPut2(WPacket *, uint32_t);
int WPacketPut3(WPacket *, uint32_t);
int WPacketPut4(WPacket *, uint32_t);
int WPacketBufPull(WPacket *, size_t);
int WPacketMemcpy(WPacket *, const void *, size_t);
int WPacketMemmove(WPacket *, const void *, size_t);
int WPacketMemset(WPacket *, int, size_t);
int WPacketStartSubU8(WPacket *);
int WPacketStartSubU16(WPacket *);
int WPacketStartSubU24(WPacket *);
int WPacketStartSubU32(WPacket *);
int WPacketSubMemcpyBytes(WPacket *, const void *, size_t, size_t);
int WPacketSubMemcpyU8(WPacket *, const void *, size_t);
int WPacketSubMemcpyU16(WPacket *, const void *, size_t);
int WPacketSubMemcpyU24(WPacket *, const void *, size_t);
int WPacketSubMemcpyU32(WPacket *, const void *, size_t);
int WPacketSubAllocBytesU24(WPacket *, size_t, uint8_t **);

int WPacketClose(WPacket *);
void WPacketCleanup(WPacket *);

#endif
