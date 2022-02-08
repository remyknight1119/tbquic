/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "packet_local.h"

#include <assert.h>
#include <string.h>
#include <stdint.h>

#include "mem.h"
#include "common.h"
#include "log.h"

#define WPACKET_BUF_MAX_LEN    65535
#define DEFAULT_BUF_SIZE    256

void RPacketHeadSync(RPacket *pkt)
{
    pkt->head = pkt->curr;
}

void RPacketBufInit(RPacket *pkt, const uint8_t *buf, size_t len)
{
    pkt->curr = buf;
    pkt->total_len = len;
    pkt->remaining = len;

    RPacketHeadSync(pkt);
}

size_t RPacketReadLen(const RPacket *pkt)
{
    return (pkt->curr - pkt->head);
}

void RPacketForward(RPacket *pkt, size_t len)
{
    pkt->curr += len;
    pkt->remaining -= len;
}

size_t RPacketTotalLen(const RPacket *pkt)
{
    return pkt->total_len;
}

const uint8_t *RPacketHead(const RPacket *pkt)
{
    return pkt->head;
}

void RPacketHeadPush(RPacket *pkt, size_t len)
{
    pkt->head -= len;
    pkt->total_len += len;
}

/*
 * Returns the number of bytes remaining to be read in the RPacket
 */
size_t RPacketRemaining(const RPacket *pkt)
{
    return pkt->remaining;
}

const uint8_t *RPacketData(const RPacket *pkt)
{
    return pkt->curr;
}

void RPacketUpdate(RPacket *pkt)
{
    RPacketBufInit(pkt, RPacketData(pkt), RPacketRemaining(pkt));
}

int RPacketPull(RPacket *pkt, size_t len)
{
    if (QUIC_LT(RPacketRemaining(pkt), len)) {
        return -1;
    }

    RPacketForward(pkt, len);

    return 0;
}

static int RPacketPeekData(const RPacket *pkt, uint32_t *data, size_t len)
{
    size_t i = 0;

    if (QUIC_LT(RPacketRemaining(pkt), len)) {
        return -1;
    }

    *data = *pkt->curr;

    for (i = 1; i < len; i++) {
        *data = (*data << 8) | ((uint32_t)(*(pkt->curr + i)));
    }

    return 0;
}

static int RPacketGetData(RPacket *pkt, uint32_t *data, size_t len)
{
    if (RPacketPeekData(pkt, data, len) < 0) {
        return -1;
    }

    RPacketForward(pkt, len);

    return 0;
}

/* Peek ahead at 1 byte from |pkt| and store the value in |*data| */
int RPacketPeek1(const RPacket *pkt, uint32_t *data)
{
    return RPacketPeekData(pkt, data, 1);
}

/* Get 1 byte from |pkt| and store the value in |*data| */
int RPacketGet1(RPacket *pkt, uint32_t *data)
{
    return RPacketGetData(pkt, data, 1);
}

/*
 * Peek ahead at 2 bytes in from |pkt| and store the value in |*data|
 */
int RPacketPeek2(const RPacket *pkt, uint32_t *data)
{
    return RPacketPeekData(pkt, data, 2);
}

/* Equivalent of n2s */
/* Get 2 bytes from |pkt| and store the value in |*data| */
int RPacketGet2(RPacket *pkt, uint32_t *data)
{
    return RPacketGetData(pkt, data, 2);
}

/*
 * Peek ahead at 3 bytes from |pkt| and store the value in |*data|
 */
int RPacketPeek3(const RPacket *pkt, uint32_t *data)
{
    return RPacketPeekData(pkt, data, 3);
}

/* Equivalent of n2l3 */
/* Get 3 bytes from |pkt| and store the value in |*data|
 */
int RPacketGet3(RPacket *pkt, uint32_t *data)
{
    return RPacketGetData(pkt, data, 3);
}

/*
 * Peek ahead at 4 bytes from |pkt| and store the value |*data|
 */
int RPacketPeek4(const RPacket *pkt, uint32_t *data)
{
    return RPacketPeekData(pkt, data, 4);
}

/* Equivalent of c2l */
/*
 * Get 4 bytes order from |pkt| and store the value in |*data|
 */
int RPacketGet4(RPacket *pkt, uint32_t *data)
{
    return RPacketGetData(pkt, data, 4);
}

/*
 * Peek ahead at |len| bytes from the |pkt| and store a pointer to them in
 * |*data|. This just points at the underlying buffer that |pkt| is using. The
 * caller should not free this data directly (it will be freed when the
 * underlying buffer gets freed
 */
int RPacketPeekBytes(const RPacket *pkt, const uint8_t **data, 
        size_t len)
{
    if (QUIC_LT(RPacketRemaining(pkt), len)) {
        return -1;
    }

    *data = pkt->curr;

    return 0;
}

/*
 * Read |len| bytes from the |pkt| and store a pointer to them in |*data|. This
 * just points at the underlying buffer that |pkt| is using. The caller should
 * not free this data directly (it will be freed when the underlying buffer gets
 * freed
 */
int RPacketGetBytes(RPacket *pkt, const uint8_t **data, size_t len)
{
    if (RPacketPeekBytes(pkt, data, len) < 0) {
        return -1;
    }

    RPacketForward(pkt, len);

    return 0;
}

/* Peek ahead at |len| bytes from |pkt| and copy them to |data| */
int RPacketPeekCopyBytes(const RPacket *pkt, uint8_t *data, size_t len)
{
    if (QUIC_LT(RPacketRemaining(pkt), len)) {
        return -1;
    }

    QuicMemcpy(data, pkt->curr, len);

    return 0;
}

/*
 * Read |len| bytes from |pkt| and copy them to |data|.
 * The caller is responsible for ensuring that |data| can hold |len| bytes.
 */
int RPacketCopyBytes(RPacket *pkt, uint8_t *data, size_t len)
{
    if (RPacketPeekCopyBytes(pkt, data, len) < 0) {
        return -1;
    }

    RPacketForward(pkt, len);

    return 0;
}

int RPacketTransfer(RPacket *child, RPacket *parent, size_t len)
{
    if (QUIC_LT(RPacketRemaining(parent), len)) {
        return -1;
    }

    RPacketBufInit(child, RPacketData(parent), len);
    RPacketForward(parent, len);

    return 0;
}

static int RPacketGetLengthPrefixed(RPacket *pkt, RPacket *subpkt, size_t len)
{
    const uint8_t *data = NULL;

    if (RPacketGetBytes(pkt, &data, len) < 0) {
        return -1;
    }

    RPacketBufInit(subpkt, data, len);

    return 0;
}

int RPacketGetLengthPrefixed1(RPacket *pkt, RPacket *subpkt)
{
    uint32_t len = 0;

    if (RPacketGet1(pkt, &len) < 0) {
        return -1;
    }
    
    return RPacketGetLengthPrefixed(pkt, subpkt, len);
}

int RPacketGetLengthPrefixed2(RPacket *pkt, RPacket *subpkt)
{
    uint32_t len = 0;

    if (RPacketGet2(pkt, &len) < 0) {
        return -1;
    }
    
    return RPacketGetLengthPrefixed(pkt, subpkt, len);
}

int PRacketContainsZeroByte(const RPacket *pkt)
{
    return memchr(pkt->curr, 0, pkt->remaining) != NULL;
}

int RPacketSaveU16(RPacket *pkt, uint16_t **pdest, size_t *pdestlen)
{
    uint16_t *buf = NULL;
    size_t size = 0;
    size_t i = 0;
    uint32_t stmp = 0;

    size = RPacketRemaining(pkt);

    /* Invalid data length */
    if (size == 0 || (size & 0x01) != 0) {
        return -1;
    }

    size >>= 1;

    if ((buf = QuicMemMalloc(size * sizeof(*buf))) == NULL)  {
        return -1;
    }

    for (i = 0; i < size && RPacketGet2(pkt, &stmp) == 0; i++) {
        buf[i] = stmp;
    }

    if (i != size) {
        QuicMemFree(buf);
        return -1;
    }

    QuicMemFree(*pdest);
    *pdest = buf;
    *pdestlen = size;

    return 0;
}

char *RPacketStrndup(const RPacket *pkt)
{
    return strndup((const char *)pkt->curr, RPacketRemaining(pkt));
}

int PRacketMemDup(const RPacket *pkt, uint8_t **data, size_t *len)
{
    size_t length = 0;

    QuicMemFree(*data);
    *data = NULL;
    *len = 0;

    length = RPacketRemaining(pkt);
    if (length == 0) {
        return 0;
    }

    *data = QuicMemDup(pkt->curr, length);
    if (*data == NULL) {
        return -1;
    }

    *len = length;
    
    return 0;
}

void WPacketBufInit(WPacket *pkt, BUF_MEM *buf)
{
    memset(pkt, 0, sizeof(*pkt));
    pkt->buf = buf;
    pkt->maxsize = WPACKET_BUF_MAX_LEN;
}

void WPacketStaticBufInit(WPacket *pkt, uint8_t *buf, size_t len)
{
    memset(pkt, 0, sizeof(*pkt));
    pkt->static_buf = buf;
    pkt->maxsize = len;
}

uint8_t *WPacket_get_curr(WPacket *pkt)
{
    uint8_t *data = NULL;

    if (pkt->static_buf != NULL) {
        data = pkt->static_buf;
    } else {
        data = (void *)pkt->buf->data;
    }

    return data + pkt->curr;
}

int WPacket_get_space(WPacket *pkt)
{
    return (int)(pkt->maxsize - pkt->written);
}

size_t WPacket_get_maxsize(WPacket *pkt)
{
    return pkt->maxsize;
}

size_t WPacket_get_written(WPacket *pkt)
{
    return pkt->written;
}

int WPacketReserveBytes(WPacket *pkt, size_t len, uint8_t **allocbytes)
{
    if (QUIC_LT(pkt->maxsize - pkt->written, len)) {
        return -1;
    }

    if (pkt->static_buf == NULL && pkt->buf->length - pkt->written < len) {
        size_t newlen;
        size_t reflen;

        reflen = (len > pkt->buf->length) ? len : pkt->buf->length;

        if (reflen > SIZE_MAX / 2) {
            newlen = SIZE_MAX;
        } else {
            newlen = reflen * 2;
            if (newlen < DEFAULT_BUF_SIZE) {
                newlen = DEFAULT_BUF_SIZE;
            }
        }
        if (BUF_MEM_grow(pkt->buf, newlen) == 0) {
            return -1;
        }
    }

    if (allocbytes != NULL) {
        *allocbytes = WPacket_get_curr(pkt);
    }

    return 0;
}

int WPacketAllocateBytes(WPacket *pkt, size_t len, uint8_t **allocbytes)
{
    if (WPacketReserveBytes(pkt, len, allocbytes) < 0) {
        return -1;
    }

    pkt->written += len;
    pkt->curr += len;

    return 0;
}

int WPacketBufPull(WPacket *pkt, size_t len)
{
    if (QUIC_LT(pkt->maxsize, len)) {
        return -1;
    }

    pkt->curr += len;
    pkt->maxsize -= len;
    return 0;
}

int WPacketMemcpy(WPacket *pkt, const void *src, size_t len)
{
    uint8_t *dest;

    if (src == NULL) {
        return -1;
    }

    if (len == 0) {
        return 0;
    }

    if (WPacketAllocateBytes(pkt, len, &dest) < 0) {
        return -1;
    }

    QuicMemcpy(dest, src, len);

    return 0;
}

int WPacketMemmove(WPacket *pkt, const void *src, size_t len)
{
    uint8_t *dest;

    if (src == NULL) {
        return -1;
    }

    if (len == 0) {
        return 0;
    }

    if (WPacketAllocateBytes(pkt, len, &dest) < 0) {
        return -1;
    }

    if (dest != src) {
        QuicMemmove(dest, src, len);
    }

    return 0;
}

int WPacketMemset(WPacket *pkt, int c, size_t len)
{
    uint8_t *dest;

    if (len == 0) {
        return 0;
    }

    if (WPacketAllocateBytes(pkt, len, &dest) < 0) {
        return -1;
    }

    QuicMemset(dest, c, len);

    return 0;
}

/* Store the |value| of length |len| at location |data| */
int WPacketPutValue(uint8_t *data, size_t value, size_t len)
{
    for (data += len - 1; len > 0; len--) {
        *data = (uint8_t)(value & 0xFF);
        data--;
        value >>= 8;
    }

    /* Check whether we could fit the value in the assigned number of bytes */
    if (value > 0) {
        return -1;
    }

    return 0;
}

int WPacketPutBytes(WPacket *pkt, uint32_t val, size_t size)
{
    uint8_t *data = NULL;

    if (WPacketAllocateBytes(pkt, size, &data) < 0) {
        return -1;
    }
    
    return WPacketPutValue(data, val, size);
}

int WPacketPut1(WPacket *pkt, uint32_t val)
{
    return WPacketPutBytes(pkt, val, 1);
}

int WPacketPut2(WPacket *pkt, uint32_t val)
{
    return WPacketPutBytes(pkt, val, 2);
}

int WPacketPut3(WPacket *pkt, uint32_t val)
{
    return WPacketPutBytes(pkt, val, 3);
}

int WPacketPut4(WPacket *pkt, uint32_t val)
{
    return WPacketPutBytes(pkt, val, 4);
}

int WPacketStartSubBytes(WPacket *pkt, size_t len)
{
    WPACKET_SUB *sub = NULL;

    sub = QuicMemCalloc(sizeof(*sub));
    if (sub == NULL) {
        return -1;
    }

    sub->parent = pkt->subs;
    pkt->subs = sub;

    if (WPacketAllocateBytes(pkt, len, &sub->value) < 0) {
        return -1;
    }
    
    sub->val_len = len;
    return 0;
}

int WPacketStartSubU8(WPacket *pkt)
{
    return WPacketStartSubBytes(pkt, 1);
}

int WPacketStartSubU16(WPacket *pkt)
{
    return WPacketStartSubBytes(pkt, 2);
}

int WPacketStartSubU24(WPacket *pkt)
{
    return WPacketStartSubBytes(pkt, 3);
}

int WPacketStartSubU32(WPacket *pkt)
{
    return WPacketStartSubBytes(pkt, 4);
}

int WPacketClose(WPacket *pkt)
{
    WPACKET_SUB *sub = NULL;
    size_t data_len = 0;

    sub = pkt->subs;
    if (sub == NULL) {
        return -1;
    }

    data_len = WPacket_get_curr(pkt) - sub->value - sub->val_len;
    assert(QUIC_GE(data_len, 0));

    if (WPacketPutValue(sub->value, data_len, sub->val_len) < 0) {
        return -1;
    }
    
    pkt->subs = sub->parent;
    QuicMemFree(sub);

    return 0;
}

int WPacketSubMemcpyBytes(WPacket *pkt, const void *src, size_t len,
                         size_t lenbytes)
{
    if (WPacketStartSubBytes(pkt, lenbytes) < 0) {
        return -1;
    }
    
    if (WPacketMemcpy(pkt, src, len) < 0) {
        return -1;
    }

    return WPacketClose(pkt);
}

int WPacketSubMemcpyU8(WPacket *pkt, const void *src, size_t len)
{
    return WPacketSubMemcpyBytes(pkt, src, len, 1);
}

int WPacketSubMemcpyU16(WPacket *pkt, const void *src, size_t len)
{
    return WPacketSubMemcpyBytes(pkt, src, len, 2);
}

int WPacketSubMemcpyU24(WPacket *pkt, const void *src, size_t len)
{
    return WPacketSubMemcpyBytes(pkt, src, len, 3);
}

int WPacketSubMemcpyU32(WPacket *pkt, const void *src, size_t len)
{
    return WPacketSubMemcpyBytes(pkt, src, len, 4);
}

int WPacketSubAllocBytes(WPacket *pkt, size_t len, uint8_t **allocbytes,
                            size_t lenbytes)
{
    if (WPacketStartSubBytes(pkt, lenbytes) < 0) {
        return -1;
    }
    
    if (WPacketAllocateBytes(pkt, len, allocbytes) < 0) {
        return -1;
    }

    return WPacketClose(pkt);
}

int WPacketSubAllocBytesU24(WPacket *pkt, size_t len, uint8_t **allocbytes)
{
    return WPacketSubAllocBytes(pkt, len, allocbytes, 3);
}

int WPacketFillData(WPacket *pkt, uint8_t *data, size_t len)
{
    int space = 0;

    space = WPacket_get_space(pkt);
    if (QUIC_GT(len, space)) {
        len = space;
    }

    if (WPacketMemcpy(pkt, data, len) < 0) {
        return -1;
    }

    return len;
}

void WPacketCleanup(WPacket *pkt)
{
    WPACKET_SUB *sub = NULL;
    WPACKET_SUB *parent = NULL;

    for (sub = pkt->subs; sub != NULL; sub = parent) {
        parent = sub->parent;
        QuicMemFree(sub);
    }
    pkt->subs = NULL;
}
