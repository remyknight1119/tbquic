/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include <tbquic/dispenser.h>

#include <tbquic/quic.h>
#include "dispenser.h"
#include "quic_local.h"
#include "mem.h"
#include "address.h"
#include "datagram.h"

QUIC_DISPENSER *QuicCreateDispenser(int fd)
{
    QUIC_DISPENSER *dis = NULL;

    dis = QuicMemCalloc(sizeof(*dis));
    if (dis == NULL) {
        return NULL;
    }

    if (getsockname(fd, &dis->dest.addr, &dis->dest.addrlen) != 0) {
        goto err;
    }

    dis->sock_fd = fd;
    INIT_LIST_HEAD(&dis->head);
    return dis;
err:
    QuicDestroyDispenser(dis);
    return NULL;
}

static QUIC *QuicDispenserFind(const QUIC_DISPENSER *dis, const Address *src)
{
    QUIC *quic = NULL;
    QUIC *pos = NULL;

    list_for_each_entry(quic, &dis->head, node) {
        if (AddressEqual(src, &quic->source) &&
                AddressEqual(&dis->dest, &quic->dest)) {
            quic = pos;
            break;
        }
    }

    return quic;
}

int QuicDispenserReadBytes(QUIC *quic, RPacket *pkt)
{
    QuicStaticBuffer *buf = quic->dispenser_buf;

    if (buf == NULL) {
        return -1;
    }

    RPacketBufInit(pkt, buf->data, buf->len);
    return 0;
}

QUIC *QuicDoDispense(QUIC_DISPENSER *dis, QUIC_CTX *ctx, bool *new)
{
    QUIC *quic = NULL;
    QuicStaticBuffer *buf = &dis->buf;
    Address source;
    int fd = dis->sock_fd;
    int rlen = 0;

    rlen = QuicDatagramRecvfrom(fd, buf->data, sizeof(buf->data), 0, &source);
    if (rlen <= 0) {
        buf->len = 0;
        return NULL;
    }

    buf->len = rlen;
    quic = QuicDispenserFind(dis, &source);
    if (quic != NULL) {
        *new = false;
        return quic;
    }

    quic = QuicNew(ctx);
    if (quic == NULL) {
        return NULL;
    }

    if (QUIC_set_fd(quic, fd) < 0) {
        goto err;
    }

    *new = true;
    quic->source = source;
    quic->dest = dis->dest;
    quic->dispenser_buf = &dis->buf;
    list_add_tail(&quic->node, &dis->head);

    return quic;
err:
    QuicFree(quic);
    return NULL;
}

void QuicDestroyDispenser(QUIC_DISPENSER *dis)
{
    if (dis == NULL) {
        return;
    }

    QuicMemFree(dis);
}

