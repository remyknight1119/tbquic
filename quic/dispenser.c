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
#include "log.h"

QUIC_DISPENSER *QuicCreateDispenser(int fd)
{
    QUIC_DISPENSER *dis = NULL;

    dis = QuicMemCalloc(sizeof(*dis));
    if (dis == NULL) {
        return NULL;
    }

    if (getsockname(fd, &dis->dest.addr.in, &dis->dest.addrlen) != 0) {
        goto err;
    }

    dis->sock_fd = fd;
    INIT_LIST_HEAD(&dis->head);
    return dis;
err:
    QuicDestroyDispenser(dis);
    return NULL;
}

static QUIC *
QuicDispenserFindByAddr(const QUIC_DISPENSER *dis, const Address *src)
{
    QUIC *quic = NULL;
    QUIC *pos = NULL;

    list_for_each_entry(pos, &dis->head, node) {
        if (AddressEqual(src, &pos->source) &&
                AddressEqual(&dis->dest, &pos->dest)) {
            quic = pos;
            QUIC_LOG("found\n");
            break;
        }
    }

    return quic;
}

static QUIC *
QuicDispenserFindByCid(const QUIC_DISPENSER *dis, const QUIC_DATA *cid)
{
    QUIC *quic = NULL;

    if (cid->len == 0) {
        return NULL;
    }

    return quic;
}

int QuicDispenserReadBytes(QUIC *quic, RPacket *pkt)
{
    QUIC_DATA *buf = quic->read_buf;

    if (buf->len == 0) {
        return -1;
    }

    RPacketBufInit(pkt, buf->data, buf->len);
    buf->len = 0;
    return 0;
}

int QuicDispenserWriteBytes(QUIC *quic, uint8_t *data, size_t len)
{
    int sock_fd = quic->send_fd;

    if (sock_fd < 0) {
        return -1;
    }

    return QuicDatagramSendto(sock_fd, data, len, 0, &quic->source);
}

QUIC *QuicDoDispense(QUIC_DISPENSER *dis, QUIC_CTX *ctx, bool *new)
{
    QUIC *quic = NULL;
    QUIC_DATA *buf = NULL;
    QUIC_DATA cid = {
        .len = ctx->cid_len,
    };
    Address source = {
        .addrlen = sizeof(source.addr),
    };
    int fd = dis->sock_fd;
    int rlen = 0;

    buf = QuicDataCreate(ctx->mss);
    if (buf == NULL) {
        return NULL;
    }

    rlen = QuicDatagramRecvfrom(fd, buf->data, buf->len, 0, &source);
    QUIC_LOG("rlen = %d\n", rlen);
    if (rlen <= 0) {
        buf->len = 0;
        goto err;
    }

    buf->len = rlen;
    quic = QuicDispenserFindByAddr(dis, &source);
    if (quic == NULL && QuicGetDcidFromPkt(&cid, buf->data, buf->len) == 0) {
        /* Maybe a Connection Migration */
        quic = QuicDispenserFindByCid(dis, &cid);
    }
    if (quic != NULL) {
        *new = false;
        dis->read = false;
        QuicDataDestroy(quic->read_buf);
        quic->read_buf = buf;
        return quic;
    }

    quic = QuicNew(ctx);
    if (quic == NULL) {
        return NULL;
    }

    QUIC_set_accept_state(quic);
    *new = true;
    quic->source = source;
    quic->dest = dis->dest;
    dis->read = false;
    quic->send_fd = dis->sock_fd;
    quic->fd_mode = 1;
    QuicDataDestroy(quic->read_buf);
    quic->read_buf = buf;
    buf = NULL;
    list_add_tail(&quic->node, &dis->head);

    return quic;
err:
    QuicFree(quic);
    QuicDataDestroy(buf);
    return NULL;
}

void QuicDestroyDispenser(QUIC_DISPENSER *dis)
{
    if (dis == NULL) {
        return;
    }

    QuicMemFree(dis);
}

