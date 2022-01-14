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


static int QuicFramePingParser(QUIC *, RPacket *);
static int QuicFrameCryptoParser(QUIC *, RPacket *);
static int QuicFrameAckParser(QUIC *, RPacket *);
static int QuicFrameStreamParser(QUIC *, RPacket *);
static int QuicFrameCryptoBuild(QUIC *, WPacket *, uint8_t *, uint64_t, size_t);
static int QuicFrameStreamBuild(QUIC *, WPacket *, uint8_t *, uint64_t, size_t);

static QuicFrameProcess frame_handler[QUIC_FRAME_TYPE_MAX] = {
    [QUIC_FRAME_TYPE_PADDING] = {
        .flags = QUIC_FRAME_FLAGS_NO_BODY|QUIC_FRAME_FLAGS_SKIP,
    },
    [QUIC_FRAME_TYPE_PING] = {
        .flags = QUIC_FRAME_FLAGS_NO_BODY,
        .parser = QuicFramePingParser,
        .builder = QuicFramePingBuild,
    },
    [QUIC_FRAME_TYPE_CRYPTO] = {
        .flags = QUIC_FRAME_FLAGS_SPLIT_ENABLE,
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
    uint64_t flags = 0;
    bool crypto_found = false;

    while (QuicVariableLengthDecode(pkt, &type) >= 0) {
        if (type >= QUIC_FRAME_TYPE_MAX) {
            QUIC_LOG("Unknown type(%lx)", type);
            return -1;
        }
        flags = frame_handler[type].flags;
        if (flags & QUIC_FRAME_FLAGS_SKIP) {
            continue;
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
        //quic->statem.state = QUIC_STATEM_HANDSHAKE_DONE;
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
    int data_len = len - offset;

    assert(data_len > 0);

    if (QuicVariableLengthWrite(pkt, offset) < 0) {
        return -1;
    }

    return QuicWPacketSubMemcpyVar(pkt, &data[offset], data_len);
}

int QuicFrameStreamBuild(QUIC *quic, WPacket *pkt, uint8_t *data,
                            uint64_t offset, size_t len)
{
    uint64_t id = 3;

    if (QuicVariableLengthWrite(pkt, id) < 0) {
        return -1;
    }

    return WPacketMemcpy(pkt, data, len);
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
 
static QBUFF *
QuicFrameBufferNew(uint32_t pkt_type, size_t buf_len, WPacket *pkt)
{
    QBUFF *qb = NULL;

    qb = QBuffNew(pkt_type, buf_len);
    if (qb == NULL) {
        return NULL;
    }

    WPacketStaticBufInit(pkt, QBuffHead(qb), QBuffLen(qb));
    return qb;
}


static QBUFF *QuicBuffQueueAndNext(QUIC *quic, uint32_t pkt_type, WPacket *pkt,
                                    QBUFF *qb, size_t buf_len)
{
    if (QuicFrameAddQueue(quic, pkt, qb) < 0) {
        QUIC_LOG("Add frame queue failed\n");
        return NULL;
    }

    WPacketCleanup(pkt);
    return QuicFrameBufferNew(pkt_type, buf_len, pkt);
}

static QBUFF *
QuicFrameSplit(QUIC *quic, uint32_t pkt_type, uint64_t type, WPacket *pkt,
                            QBUFF *qb, size_t buf_len, uint8_t *data,
                            size_t len)
{
    QuicFrameBuilder builder = NULL;
    uint64_t offset = 0;
    int wlen = 0;

    if (QUIC_LE(WPacket_get_space(pkt), QUIC_FRAME_HEADER_MAX_LEN)) {
        qb = QuicBuffQueueAndNext(quic, pkt_type, pkt, qb, buf_len);
        if (qb == NULL) {
            return NULL;
        }
    }

    builder = frame_handler[type].builder;
    assert(builder != NULL);

    offset = 0;
    while (1) {
        if (QuicVariableLengthWrite(pkt, type) < 0) {
            goto err;
        }

        wlen = builder(quic, pkt, data, offset, len);
        if (wlen <= 0) {
            QUIC_LOG("Build failed\n");
            goto err;
        }

        offset += wlen;
        if (offset == len) {
            break;
        }

        assert(QUIC_LT(offset, len));
        qb = QuicBuffQueueAndNext(quic, pkt_type, pkt, qb, buf_len);
        if (qb == NULL) {
            return NULL;
        }
    }

    if (QuicFrameAddQueue(quic, pkt, qb) < 0) {
        QUIC_LOG("Add frame queue failed\n");
        goto err;
    }

    WPacketCleanup(pkt);

    return QuicFrameBufferNew(pkt_type, buf_len, pkt);
err:
    QBuffFree(qb);
    return NULL;
}

int
QuicFrameBuild(QUIC *quic, uint32_t pkt_type, QuicFrameNode *node, size_t num)
{
    QuicFrameBuilder builder = NULL;
    QuicFrameNode *n = NULL;
    QBUFF *qb = NULL;
    uint8_t *data = NULL;
    WPacket pkt = {};
    size_t i = 0;
    size_t buf_len = 0;
    size_t data_len = 0;
    size_t head_tail_len = 0;
    uint64_t type = 0;
    uint64_t flags = 0;
    uint32_t mss = 0;
    int ret = -1;

    mss = quic->mss;

    head_tail_len = QBufPktComputeTotalLenByType(quic, pkt_type, mss) - mss;
    buf_len = mss - head_tail_len;

    qb = QuicFrameBufferNew(pkt_type, buf_len, &pkt);
    if (qb == NULL) {
        goto out;
    }

    for (i = 0; i < num; i++) {
        n = &node[i];
        type = n->type;
        if (type >= QUIC_FRAME_TYPE_MAX) {
            QUIC_LOG("Unknown type(%lx)", type);
            continue;
        }
        
        data = node->data.data;
        data_len = node->data.len;
        flags = frame_handler[type].flags;
        if (flags & QUIC_FRAME_FLAGS_SPLIT_ENABLE) {
            qb = QuicFrameSplit(quic, pkt_type, type, &pkt, qb, buf_len, data,
                                    data_len);
            if (qb == NULL) {
                goto out;
            }
            continue;
        }

        if (QuicVariableLengthWrite(&pkt, type) < 0) {
            return -1;
        }

        if (flags & QUIC_FRAME_FLAGS_NO_BODY) {
            continue;
        }

        builder = frame_handler[type].builder;
        assert(builder != NULL);
        if (builder(quic, &pkt, data, 0, data_len) < 0) {
            QUIC_LOG("Build %lu failed\n", type);
            goto out;
        }
    }

    if (WPacket_get_written(&pkt)) {
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

