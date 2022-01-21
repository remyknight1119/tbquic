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
#include "time.h"

static int QuicFramePingParser(QUIC *, RPacket *, uint64_t, QUIC_CRYPTO *);
static int QuicFrameCryptoParser(QUIC *, RPacket *, uint64_t, QUIC_CRYPTO *);
static int QuicFrameNewTokenParser(QUIC *, RPacket *, uint64_t, QUIC_CRYPTO *);
static int QuicFrameAckParser(QUIC *, RPacket *, uint64_t, QUIC_CRYPTO *);
static int QuicFrameResetStreamParser(QUIC *, RPacket *, uint64_t,
                                        QUIC_CRYPTO *);
static int QuicFrameNewConnIdParser(QUIC *, RPacket *, uint64_t, QUIC_CRYPTO *);
static int QuicFrameHandshakeDoneParser(QUIC *, RPacket *, uint64_t,
                                        QUIC_CRYPTO *);
static int QuicFrameStreamParser(QUIC *, RPacket *, uint64_t, QUIC_CRYPTO *);
static int QuicFrameCryptoBuild(QUIC *, WPacket *, QUIC_CRYPTO *, uint64_t,
                                        void *, long);
static int QuicFrameAckBuild(QUIC *, WPacket *, QUIC_CRYPTO *, uint64_t,
                                        void *, long);
static int QuicFrameStreamBuild(QUIC *, WPacket *, QUIC_CRYPTO *, uint64_t,
                                        void *, long);

static QuicFrameProcess frame_handler[QUIC_FRAME_TYPE_MAX] = {
    [QUIC_FRAME_TYPE_PADDING] = {
        .flags = QUIC_FRAME_FLAGS_NO_BODY|QUIC_FRAME_FLAGS_SKIP,
    },
    [QUIC_FRAME_TYPE_PING] = {
        .flags = QUIC_FRAME_FLAGS_NO_BODY,
        .parser = QuicFramePingParser,
    },
    [QUIC_FRAME_TYPE_RESET_STREAM] = {
        .parser = QuicFrameResetStreamParser,
    },
    [QUIC_FRAME_TYPE_CRYPTO] = {
        .flags = QUIC_FRAME_FLAGS_SPLIT_ENABLE,
        .parser = QuicFrameCryptoParser,
        .builder = QuicFrameCryptoBuild,
    },
    [QUIC_FRAME_TYPE_NEW_TOKEN] = {
        .parser = QuicFrameNewTokenParser,
    },
    [QUIC_FRAME_TYPE_ACK] = {
        .parser = QuicFrameAckParser,
        .builder = QuicFrameAckBuild,
    },
    [QUIC_FRAME_TYPE_STREAM] = {
        .parser = QuicFrameStreamParser,
        .builder = QuicFrameStreamBuild,
    },
    [QUIC_FRAME_TYPE_STREAM_FIN] = {
        .parser = QuicFrameStreamParser,
        .builder = QuicFrameStreamBuild,
    },
    [QUIC_FRAME_TYPE_STREAM_LEN] = {
        .parser = QuicFrameStreamParser,
        .builder = QuicFrameStreamBuild,
    },
    [QUIC_FRAME_TYPE_STREAM_LEN_FIN] = {
        .parser = QuicFrameStreamParser,
        .builder = QuicFrameStreamBuild,
    },
    [QUIC_FRAME_TYPE_STREAM_OFF] = {
        .parser = QuicFrameStreamParser,
        .builder = QuicFrameStreamBuild,
    },
    [QUIC_FRAME_TYPE_STREAM_OFF_FIN] = {
        .parser = QuicFrameStreamParser,
        .builder = QuicFrameStreamBuild,
    },
    [QUIC_FRAME_TYPE_STREAM_OFF_LEN] = {
        .parser = QuicFrameStreamParser,
        .builder = QuicFrameStreamBuild,
    },
    [QUIC_FRAME_TYPE_STREAM_OFF_LEN_FIN] = {
        .parser = QuicFrameStreamParser,
        .builder = QuicFrameStreamBuild,
    },
    [QUIC_FRAME_TYPE_NEW_CONNECTION_ID] = {
        .parser = QuicFrameNewConnIdParser,
    },
    [QUIC_FRAME_TYPE_HANDSHAKE_DONE] = {
        .flags = QUIC_FRAME_FLAGS_NO_BODY,
        .parser = QuicFrameHandshakeDoneParser,
    },
};

int QuicFrameDoParser(QUIC *quic, RPacket *pkt, QUIC_CRYPTO *c)
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

        if (parser(quic, pkt, type, c) < 0) {
            return -1;
        }

        if (type == QUIC_FRAME_TYPE_CRYPTO) {
            crypto_found = true;
        }
    }

    if (crypto_found == true) {
        if (quic->tls.handshake_state != TLS_ST_HANDSHAKE_DONE) {
            ret = TlsDoHandshake(&quic->tls);
            if (ret == QUIC_FLOW_RET_ERROR) {
                QUIC_LOG("TLS Hadshake failed!\n");
                return -1;
            }
        }

        if (quic->tls.handshake_state == TLS_ST_HANDSHAKE_DONE) {
            QUIC_LOG("TLS handshake done\n");
            quic->statem.state = QUIC_STATEM_HANDSHAKE_DONE;
        }
    }

    return 0;
}

static int
QuicFrameCryptoParser(QUIC *quic, RPacket *pkt, uint64_t type, QUIC_CRYPTO *c)
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

static int
QuicFrameNewTokenParser(QUIC *quic, RPacket *pkt, uint64_t type, QUIC_CRYPTO *c)
{
    uint64_t length = 0;

    if (quic->quic_server) {
        //error PROTOCOL_VIOLATION
        return -1;
    }

    if (QuicVariableLengthDecode(pkt, &length) < 0) {
        QUIC_LOG("Length decode failed!\n");
        return -1;
    }

    return QuicDataParse(&quic->token, pkt, length);
}

static int
QuicFramePingParser(QUIC *quic, RPacket *pkt, uint64_t type, QUIC_CRYPTO *c)
{
    return 0;
}

static int QuicFrameResetStreamParser(QUIC *quic, RPacket *pkt, uint64_t type,
                                        QUIC_CRYPTO *c)
{
    uint64_t stream_id = 0;
    uint64_t error_code = 0;
    uint64_t final_size = 0;

    if (QuicVariableLengthDecode(pkt, &stream_id) < 0) {
        QUIC_LOG("Stream ID decode failed!\n");
        return -1;
    }

    if (QuicVariableLengthDecode(pkt, &error_code) < 0) {
        QUIC_LOG("Application error code decode failed!\n");
        return -1;
    }

    if (QuicVariableLengthDecode(pkt, &final_size) < 0) {
        QUIC_LOG("Final size decode failed!\n");
        return -1;
    }

    //QUIC_STREAM_SET_RECV_STATE(quic, QUIC_STREAM_STATE_RESET_RECVD);

    return 0;
}

static int
QuicFrameAckParser(QUIC *quic, RPacket *pkt, uint64_t type, QUIC_CRYPTO *c)
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

    if (QUIC_GE(largest_acked, c->largest_acked)) {
        c->largest_acked = largest_acked;
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

static int
QuicFrameStreamParser(QUIC *quic, RPacket *pkt, uint64_t type, QUIC_CRYPTO *c)
{
    const uint8_t *data = NULL;
    uint64_t id = 0;
    uint64_t offset = 0;
    uint64_t len = 0;

    if (QuicVariableLengthDecode(pkt, &id) < 0) {
        QUIC_LOG("ID decode failed!\n");
        return -1;
    }

    QUIC_LOG("Stream %lu\n", id);
    if (type & QUIC_FRAME_STREAM_BIT_OFF) {
        QUIC_LOG("Stream offset\n");
        if (QuicVariableLengthDecode(pkt, &offset) < 0) {
            QUIC_LOG("offset decode failed!\n");
            return -1;
        }
    }

    if (type & QUIC_FRAME_STREAM_BIT_LEN) {
        QUIC_LOG("Stream len\n");
        if (QuicVariableLengthDecode(pkt, &len) < 0) {
            QUIC_LOG("Length decode failed!\n");
            return -1;
        }
    } else {
        len = RPacketRemaining(pkt);
    }

    if (type & QUIC_FRAME_STREAM_BIT_FIN) {
        QUIC_LOG("Stream FIN\n");
#if 0
        if (QUIC_STREAM_GET_RECV_STATE(quic) == QUIC_STREAM_STATE_RECV) {
            QUIC_STREAM_SET_RECV_STATE(quic, QUIC_STREAM_STATE_SIZE_KNOWN);
        }
#endif
    }

    if (RPacketGetBytes(pkt, &data, len) < 0) {
        QUIC_LOG("Peek stream data failed!\n");
        return -1;
    }

#if 0
    if (QUIC_STREAM_GET_RECV_STATE(quic) == QUIC_STREAM_STATE_START) {
        QUIC_STREAM_SET_RECV_STATE(quic, QUIC_STREAM_STATE_RECV);
    }
#endif

    QuicPrint(data, len);
    return 0;
}

static int QuicFrameNewConnIdParser(QUIC *quic, RPacket *pkt, uint64_t type,
                                        QUIC_CRYPTO *c)
{
    QuicConn *conn = &quic->conn;
    uint64_t seq = 0;
    uint64_t retire_prior_to = 0;
    uint64_t len = 0;

    QUIC_LOG("in\n");

    if (QuicVariableLengthDecode(pkt, &seq) < 0) {
        QUIC_LOG("Seq decode failed!\n");
        return -1;
    }

    if (QuicVariableLengthDecode(pkt, &retire_prior_to) < 0) {
        QUIC_LOG("'Retire Prior To' decode failed!\n");
        return -1;
    }

    if (QuicVariableLengthDecode(pkt, &len) < 0) {
        QUIC_LOG("Length decode failed!\n");
        return -1;
    }

    if (QuicDataParse(&conn->id, pkt, len) < 0) {
        QUIC_LOG("Connection ID parse failed!\n");
        return -1;
    }

    return RPacketCopyBytes(pkt, conn->stateless_reset_token,
            sizeof(conn->stateless_reset_token));
}

static int QuicFrameHandshakeDoneParser(QUIC *quic, RPacket *pkt, uint64_t type,
                                        QUIC_CRYPTO *c)
{
    QUIC_LOG("handshake done\n");
    if (!quic->quic_server) {
        quic->statem.state = QUIC_STATEM_HANDSHAKE_DONE;
    }

    return 0;
}

int QuicFramePaddingBuild(WPacket *pkt, size_t len)
{
    return WPacketMemset(pkt, 0, len);
}

static int QuicFrameCryptoBuild(QUIC *quic, WPacket *pkt, QUIC_CRYPTO *c,
                                uint64_t offset, void *arg, long larg)
{
    QuicFrameCryptoArg *ca = arg;
    uint8_t *data = ca->data;
    size_t len = ca->len;
    int data_len = len - offset;

    assert(data_len > 0);

    if (QuicVariableLengthWrite(pkt, offset) < 0) {
        return -1;
    }

    return QuicWPacketSubMemcpyVar(pkt, &data[offset], data_len);
}

static int QuicFrameAckBuild(QUIC *quic, WPacket *pkt, QUIC_CRYPTO *c,
                                uint64_t offset, void *arg, long larg)
{
    uint64_t largest_ack = c->largest_pn;
    uint64_t curr_time = 0;
    uint64_t delay = 0;
    uint64_t range_count = 0;

    if (QuicVariableLengthWrite(pkt, largest_ack) < 0) {
        return -1;
    }

    curr_time = QuicGetTimeUs();
    delay = curr_time - c->arriv_time;
    assert(QUIC_GE(delay, 0));

    if (QuicVariableLengthWrite(pkt, delay) < 0) {
        return -1;
    }

    if (QuicVariableLengthWrite(pkt, range_count) < 0) {
        return -1;
    }

    if (QuicVariableLengthWrite(pkt, c->first_ack_range) < 0) {
        return -1;
    }

    c->largest_ack = largest_ack;
    return 0;
}

int QuicFrameAckSendCheck(QUIC_CRYPTO *c)
{
    if (!c->encrypt.cipher_inited) {
        return -1;
    }

    if (c->largest_ack == c->largest_pn) {
        return -1;
    }

    return 0;
}

int
QuicFrameStreamBuild(QUIC *quic, WPacket *pkt, QUIC_CRYPTO *c, uint64_t offset,
                            void *arg, long larg)
{
    QuicFrameStreamArg *sa = arg;
    uint8_t *data = sa->data;
    size_t len = sa->len;
    uint64_t id = sa->id;

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
                QBUFF *qb, size_t buf_len, void *arg, long larg)
{
    QUIC_CRYPTO *c = NULL;
    QuicFrameBuilder builder = NULL;
    uint64_t offset = 0;
    size_t len = larg;
    int wlen = 0;

    if (QUIC_LE(WPacket_get_space(pkt), QUIC_FRAME_HEADER_MAX_LEN)) {
        qb = QuicBuffQueueAndNext(quic, pkt_type, pkt, qb, buf_len);
        if (qb == NULL) {
            return NULL;
        }
    }

    builder = frame_handler[type].builder;
    assert(builder != NULL);

    c = QuicCryptoGet(quic, pkt_type);
    offset = 0;
    while (1) {
        if (QuicVariableLengthWrite(pkt, type) < 0) {
            goto err;
        }

        wlen = builder(quic, pkt, c, offset, arg, larg);
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
    QUIC_CRYPTO *c = NULL;
    QuicFrameNode *n = NULL;
    QBUFF *qb = NULL;
    WPacket pkt = {};
    size_t i = 0;
    size_t buf_len = 0;
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
        
        flags = frame_handler[type].flags;
        if (flags & QUIC_FRAME_FLAGS_SPLIT_ENABLE) {
            qb = QuicFrameSplit(quic, pkt_type, type, &pkt, qb, buf_len,
                                node->arg, node->larg);
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

        c = QuicCryptoGet(quic, pkt_type);
        builder = frame_handler[type].builder;
        assert(builder != NULL);
        if (builder(quic, &pkt, c, 0, node->arg, node->larg) < 0) {
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

