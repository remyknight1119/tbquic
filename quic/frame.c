/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "frame.h"

#include <assert.h>
#include <string.h>

#include "common.h"
#include "log.h"
#include "format.h"
#include "quic_local.h"
#include "q_buff.h"
#include "buffer.h"


static int QuicFramePaddingParser(QUIC *, RPacket *);
static int QuicFramePingParser(QUIC *, RPacket *);
static int QuicFrameCryptoParser(QUIC *, RPacket *);
static int QuicFrameAckParser(QUIC *, RPacket *);
static int QuicFrameStreamParser(QUIC *, RPacket *);
static int QuicFrameCryptoBuild(QUIC *, WPacket *, uint8_t *, uint64_t, size_t);
static int QuicFrameStreamBuild(QUIC *, WPacket *, uint8_t *, uint64_t, size_t);

static QuicFrameProcess frame_handler[QUIC_FRAME_TYPE_MAX] = {
    [QUIC_FRAME_TYPE_PADDING] = {
        .parser = QuicFramePaddingParser,
    },
    [QUIC_FRAME_TYPE_PING] = {
        .parser = QuicFramePingParser,
        .builder = QuicFramePingBuild,
    },
    [QUIC_FRAME_TYPE_CRYPTO] = {
        .parser = QuicFrameCryptoParser,
        .builder = QuicFrameCryptoBuild,
    },
    [QUIC_FRAME_TYPE_ACK] = {
        .parser = QuicFrameAckParser,
    },
    [QUIC_FRAME_TYPE_STREAM] = {
        .parser = QuicFrameStreamParser,
        .builder = QuicFrameStreamBuild,
    },
};

int QuicFrameDoParser(QUIC *quic, RPacket *pkt)
{
    QuicFrameParser parser = NULL;
    QuicFlowReturn ret;
    uint64_t type = 0;
    bool crypto_found = false;

    while (QuicVariableLengthDecode(pkt, &type) >= 0) {
        if (type >= QUIC_FRAME_TYPE_MAX) {
            QUIC_LOG("Unknown type(%lx)", type);
            return -1;
        }
        parser = frame_handler[type].parser;
        if (parser == NULL) {
            QUIC_LOG("No parser for type(%lx)", type);
            return -1;
        }

        if (parser(quic, pkt) < 0) {
            return -1;
        }

        if (type == QUIC_FRAME_TYPE_CRYPTO) {
            crypto_found = true;
        }
    }

    if (crypto_found == true) {
        ret = TlsDoHandshake(&quic->tls);
        if (ret == QUIC_FLOW_RET_ERROR) {
            QUIC_LOG("TLS Hadshake failed!\n");
            return -1;
        }

        if (ret == QUIC_FLOW_RET_END) {
            quic->statem.state = QUIC_STATEM_HANDSHAKE_DONE;
        }
    }

    return 0;
}

static int QuicFrameCryptoParser(QUIC *quic, RPacket *pkt)
{
    QUIC_BUFFER *buf = QUIC_TLS_BUFFER(quic);
    uint8_t *data = NULL;
    uint64_t offset = 0;
    uint64_t length = 0;
    uint64_t total_len = 0;

    if (QuicVariableLengthDecode(pkt, &offset) < 0) {
        QUIC_LOG("Offset decode failed!\n");
        return -1;
    }

    if (QuicVariableLengthDecode(pkt, &length) < 0) {
        QUIC_LOG("Length decode failed!\n");
        return -1;
    }

    total_len = offset + length;
    if (QUIC_GT(total_len, QuicBufLength(buf))) {
        if (QuicBufMemGrow(buf, total_len) == 0) {
            QUIC_LOG("Buffer grow failed!\n");
            return -1;
        }
    }

    data = QuicBufData(buf);
    if (data == NULL) {
        QUIC_LOG("Get buffer data failed!\n");
        return -1;
    }

    if (RPacketCopyBytes(pkt, &data[offset], length) < 0) {
        QUIC_LOG("Copy PKT data failed!\n");
        return -1;
    }

    if (QUIC_GT(total_len, QuicBufGetDataLength(buf))) {
        QuicBufSetDataLength(buf, total_len);
    }

    return 0;
}

static int QuicFramePaddingParser(QUIC *quic, RPacket *pkt)
{
    return 0;
}

static int QuicFramePingParser(QUIC *quic, RPacket *pkt)
{
    return 0;
}

static int QuicFrameAckParser(QUIC *quic, RPacket *pkt)
{
    uint64_t largest_acked = 0;
    uint64_t ack_delay = 0;
    uint64_t range_count = 0;
    uint64_t first_ack_range = 0;
    uint64_t gap = 0;
    uint64_t ack_range_len = 0;
    uint64_t i = 0;

    QuicPrint(RPacketData(pkt), RPacketRemaining(pkt));
    if (QuicVariableLengthDecode(pkt, &largest_acked) < 0) {
        QUIC_LOG("Largest acked decode failed!\n");
        return -1;
    }

    if (QuicVariableLengthDecode(pkt, &ack_delay) < 0) {
        QUIC_LOG("Ack delay decode failed!\n");
        return -1;
    }

    if (QuicVariableLengthDecode(pkt, &range_count) < 0) {
        QUIC_LOG("Range count decode failed!\n");
        return -1;
    }

    if (QuicVariableLengthDecode(pkt, &first_ack_range) < 0) {
        QUIC_LOG("First ack range decode failed!\n");
        return -1;
    }

    for (i = 0; i < range_count; i++) {
        if (QuicVariableLengthDecode(pkt, &gap) < 0) {
            QUIC_LOG("Gap decode failed!\n");
            return -1;
        }

        if (QuicVariableLengthDecode(pkt, &ack_range_len) < 0) {
            QUIC_LOG("ACK range len decode failed!\n");
            return -1;
        }
    }

    QUIC_LOG("in\n");
    return 0;
}

static int QuicFrameStreamParser(QUIC *quic, RPacket *pkt)
{
    const uint8_t *data = NULL;
    size_t data_len = 0;
    uint64_t id = 0;

    if (QuicVariableLengthDecode(pkt, &id) < 0) {
        QUIC_LOG("ID decode failed!\n");
        return -1;
    }

    data_len = RPacketRemaining(pkt);
    if (RPacketGetBytes(pkt, &data, data_len) < 0) {
        QUIC_LOG("Peek stream data failed!\n");
        return -1;
    }

    QuicPrint(data, data_len);
    return 0;
}

int QuicFramePaddingBuild(WPacket *pkt, size_t len)
{
    return WPacketMemset(pkt, 0, len);
}

int QuicFramePingBuild(QUIC *quic, WPacket *pkt, uint8_t *data, uint64_t offset,
                            size_t len)
{
    return WPacketPut1(pkt, QUIC_FRAME_TYPE_PING);
}

int QuicFrameCryptoComputeLen(uint64_t offset, size_t len)
{
    uint64_t vlen = 0;
    int owlen = 0;
    int lwlen = 0;

    owlen = QuicVariableLengthEncode((uint8_t *)&vlen, sizeof(vlen), offset);
    if (owlen < 0) {
        return -1;
    }

    lwlen = QuicVariableLengthEncode((uint8_t *)&vlen, sizeof(vlen), len);
    if (lwlen < 0) {
        return -1;
    }

    return 1 + owlen + lwlen + len;
}

static int QuicFrameCryptoBuild(QUIC *quic, WPacket *pkt, uint8_t *data,
                            uint64_t offset, size_t len)
{
    uint64_t var = 0;
    int data_len = len - offset;
    int space = 0;
    int wlen = 0;

    if (data_len <= 0) {
        return 0;
    }

    wlen = QuicVariableLengthEncode((uint8_t *)&var, sizeof(var), offset);
    if (wlen < 0) {
        return -1;
    }

    space = WPacket_get_space(pkt) - wlen - 1;
    wlen = QuicVariableLengthEncode((uint8_t *)&var, sizeof(var), data_len);
    if (wlen < 0) {
        return -1;
    }

    space -= wlen;
    if (space <= 0) {
        return 0;
    }

    if (data_len > space) {
        data_len = space;
    }

    if (WPacketPut1(pkt, QUIC_FRAME_TYPE_CRYPTO) < 0) {
        return -1;
    }

    if (QuicVariableLengthWrite(pkt, offset) < 0) {
        return -1;
    }

    if (QuicVariableLengthWrite(pkt, data_len) < 0) {
        return -1;
    }

    if (WPacketMemcpy(pkt, &data[offset], data_len) < 0) {
        return -1;
    }

    return data_len;
}

int QuicFrameStreamBuild(QUIC *quic, WPacket *pkt, uint8_t *data,
                            uint64_t offset, size_t len)
{
    size_t data_len = len - offset;
    uint64_t id = 3;

    if (QUIC_LE(data_len, 0)) {
        return 0;
    }

    if (WPacketPut1(pkt, QUIC_FRAME_TYPE_STREAM) < 0) {
        return -1;
    }

    if (QuicVariableLengthWrite(pkt, id) < 0) {
        return -1;
    }

    return WPacketFillData(pkt, &data[offset], data_len);
}

static int QuicFrameAddQueue(QUIC *quic, WPacket *pkt, QBUFF *qb)
{
    size_t written = 0;

    written = WPacket_get_written(pkt);
    if (written == 0) {
        return -1;
    }

    if (QBuffSetDataLen(qb, written) < 0) {
        return -1;
    }

    QuicAddQueue(quic, qb);
    WPacketCleanup(pkt);
    return 0;
}
 
int
QuicFrameBuild(QUIC *quic, uint32_t pkt_type, QuicFrameNode *node, size_t num)
{
    QuicFrameBuilder builder = NULL;
    QuicFrameNode *n = NULL;
    QBUFF *qb = NULL;
    uint8_t *data = NULL;
    WPacket pkt = {};
    size_t blen = 0;
    size_t i = 0;
    size_t written = 0;
    size_t space = 0;
    size_t buf_len = 0;
    size_t data_len = 0;
    size_t total_len = 0;
    size_t head_tail_len = 0;
    uint64_t type = 0;
    uint64_t offset = 0;
    uint32_t mss = 0;
    int wlen = 0;
    int ret = -1;

    mss = quic->mss;

    if (quic->send_head != NULL) {
        total_len = QBuffQueueComputePktTotalLen(quic, quic->send_head);
        if (QUIC_LT(mss, total_len)) {
            mss = total_len % mss;
        }
    }

    space = mss - total_len;
    head_tail_len = QBufPktComputeTotalLenByType(quic, pkt_type, mss) - mss;
    for (i = 0; i < num; i++) {
        n = &node[i];

        type = n->type;
        if (type >= QUIC_FRAME_TYPE_MAX) {
            QUIC_LOG("Unknown type(%lx)", type);
            continue;
        }
        
        builder = frame_handler[type].builder;
        if (builder == NULL) {
            continue;
        }

        data = node->data.data;
        data_len = node->data.len;
        offset = 0;
        do {
            if (QUIC_GT(head_tail_len, space)) {
                space = mss;
            }

            if (qb == NULL) {
                buf_len = space - head_tail_len;
                if (QUIC_LE(buf_len, 0)) {
                    if (space == mss) {
                        QUIC_LOG("No more space\n");
                        goto out;
                    }

                    space = mss;
                    continue;
                }
                qb = QBuffNew(mss, pkt_type);
                if (qb == NULL) {
                    goto out;
                }

                blen = QUIC_GT(QBuffLen(qb), buf_len) ? buf_len : QBuffLen(qb);
                WPacketStaticBufInit(&pkt, QBuffHead(qb), blen);
            }

            wlen = builder(quic, &pkt, data, offset, data_len);
            if (wlen < 0) {
                QUIC_LOG("Build failed\n");
                goto out;
            }

            offset += wlen;
            space -= QBufPktComputeTotalLen(quic, qb);
            written = WPacket_get_written(&pkt);
            if (written == 0) {
                QUIC_LOG("No written\n");
                goto out;
            }
            if (written == blen) {
                if (QBuffSetDataLen(qb, written) < 0) {
                    return -1;
                }

                QUIC_LOG("add pkt: %lu\n", written);
                QuicAddQueue(quic, qb);
                WPacketCleanup(&pkt);
                qb = NULL;
            }
        } while (QUIC_LT(offset, data_len));
    }

    if (qb != NULL) {
        if (QuicFrameAddQueue(quic, &pkt, qb) < 0) {
            QUIC_LOG("Add frame queue failed\n");
            goto out;
        }
        qb = NULL;
    }

    ret = 0;
out:
    WPacketCleanup(&pkt);
    QBuffFree(qb);
    return ret;
}

