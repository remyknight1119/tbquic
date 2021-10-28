/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "packet_local.h"

#include <string.h>

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

/* Peek ahead at 1 byte from |pkt| and store the value in |*data| */
int RPacketPeek1(const RPacket *pkt, unsigned char *data)
{
    if (!RPacketRemaining(pkt)) {
        return -1;
    }

    *data = *pkt->curr;

    return 0;
}

/* Get 1 byte from |pkt| and store the value in |*data| */
int RPacketGet1(RPacket *pkt, unsigned char *data)
{
    if (RPacketPeek1(pkt, data) < 0) {
        return -1;
    }

    RPacketForward(pkt, 1);

    return 0;
}

/*
 * Peek ahead at |len| bytes from the |pkt| and store a pointer to them in
 * |*data|. This just points at the underlying buffer that |pkt| is using. The
 * caller should not free this data directly (it will be freed when the
 * underlying buffer gets freed
 */
int RPacketPeekBytes(const RPacket *pkt, const unsigned char **data, 
        size_t len)
{
    if (RPacketRemaining(pkt) < len) {
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
int RPacketGetBytes(RPacket *pkt, const unsigned char **data, size_t len)
{
    if (RPacketPeekBytes(pkt, data, len) < 0) {
        return -1;
    }

    RPacketForward(pkt, len);

    return 0;
}

/* Peek ahead at |len| bytes from |pkt| and copy them to |data| */
int RPacketPeekCopyBytes(const RPacket *pkt, unsigned char *data, size_t len)
{
    if (RPacketRemaining(pkt) < len) {
        return -1;
    }

    memcpy(data, pkt->curr, len);

    return 0;
}

/*
 * Read |len| bytes from |pkt| and copy them to |data|.
 * The caller is responsible for ensuring that |data| can hold |len| bytes.
 */
int RPacketCopyBytes(RPacket *pkt, unsigned char *data, size_t len)
{
    if (RPacketPeekCopyBytes(pkt, data, len) < 0) {
        return -1;
    }

    RPacketForward(pkt, len);

    return 0;
}


