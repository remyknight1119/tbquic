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

static QUIC *QuicDispenserFind(const QUIC_DISPENSER *dis, const Address *src)
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

int QuicDispenserReadBytes(QUIC *quic, RPacket *pkt)
{
    QUIC_DISPENSER *dis = quic->dispense_arg;
    QuicStaticBuffer *buf = NULL; 

    if (dis == NULL || dis->read) {
        return -1;
    }

    buf = &dis->buf;
    RPacketBufInit(pkt, buf->data, buf->len);
    dis->read = true;
    return 0;
}

int QuicDispenserWriteBytes(QUIC *quic, uint8_t *data, size_t len)
{
    QUIC_DISPENSER *dis = quic->dispense_arg;

    if (dis == NULL) {
        return -1;
    }

    return QuicDatagramSendto(dis->sock_fd, data, len, 0, &quic->source);
}

QUIC *QuicDoDispense(QUIC_DISPENSER *dis, QUIC_CTX *ctx, bool *new)
{
    QUIC *quic = NULL;
    QuicStaticBuffer *buf = &dis->buf;
    Address source = {
        .addrlen = sizeof(source.addr),
    };
    int fd = dis->sock_fd;
    int rlen = 0;

    rlen = QuicDatagramRecvfrom(fd, buf->data, sizeof(buf->data), 0, &source);
    QUIC_LOG("rlen = %d\n", rlen);
    if (rlen <= 0) {
        buf->len = 0;
        return NULL;
    }

    buf->len = rlen;
    quic = QuicDispenserFind(dis, &source);
    if (quic != NULL) {
        *new = false;
        dis->read = false;
        return quic;
    }

    quic = QuicNew(ctx);
    if (quic == NULL) {
        return NULL;
    }

    if (QUIC_set_fd(quic, fd) < 0) {
        goto err;
    }

    QUIC_set_accept_state(quic);
    *new = true;
    quic->source = source;
    quic->dest = dis->dest;
    dis->read = false;
    quic->dispense_arg = dis;
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

