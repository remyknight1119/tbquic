/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "frame.h"

#include <assert.h>
#include <string.h>
#include <openssl/rand.h>
#include <tbquic/stream.h>

#include "common.h"
#include "log.h"
#include "format.h"
#include "quic_local.h"
#include "q_buff.h"
#include "buffer.h"
#include "quic_time.h"

#define QUIC_FRAM_IS_ACK_ELICITING(type) \
        (type != QUIC_FRAME_TYPE_PADDING && type != QUIC_FRAME_TYPE_ACK && \
                type != QUIC_FRAME_TYPE_CONNECTION_CLOSE)

static int QuicFramePingParser(QUIC *, RPacket *, uint64_t, QUIC_CRYPTO *,
                                    void *);
static int QuicFrameCryptoParser(QUIC *, RPacket *, uint64_t, QUIC_CRYPTO *,
                                    void *);
static int QuicFrameNewTokenParser(QUIC *, RPacket *, uint64_t, QUIC_CRYPTO *,
                                    void *);
static int QuicFrameAckParser(QUIC *, RPacket *, uint64_t, QUIC_CRYPTO *,
                                    void *);
static int QuicFrameResetStreamParser(QUIC *, RPacket *, uint64_t,
                                        QUIC_CRYPTO *, void *);
static int QuicFrameStopSendingParser(QUIC *, RPacket *, uint64_t,
                                        QUIC_CRYPTO *, void *);
static int QuicFrameNewConnIdParser(QUIC *, RPacket *, uint64_t, QUIC_CRYPTO *,
                                        void *);
static int QuicFrameRetireConnIdParser(QUIC *, RPacket *, uint64_t, QUIC_CRYPTO *,
                                        void *);
static int QuicFrameConnCloseParser(QUIC *, RPacket *, uint64_t,
                                        QUIC_CRYPTO *, void *);
static int QuicFrameHandshakeDoneParser(QUIC *, RPacket *, uint64_t,
                                        QUIC_CRYPTO *, void *);
static int QuicFrameStreamParser(QUIC *, RPacket *, uint64_t, QUIC_CRYPTO *,
                                        void *);
static int QuicFrameMaxStreamsBidiParser(QUIC *, RPacket *, uint64_t,
                                        QUIC_CRYPTO *, void *);
static int QuicFrameMaxStreamsUniParser(QUIC *, RPacket *, uint64_t,
                                        QUIC_CRYPTO *, void *);
static int QuicFrameMaxDataParser(QUIC *, RPacket *, uint64_t, QUIC_CRYPTO *,
                                        void *);
static int QuicFrameMaxStreamDataParser(QUIC *, RPacket *, uint64_t,
                                        QUIC_CRYPTO *, void *);
static int QuicFrameDataBlockedParser(QUIC *, RPacket *, uint64_t,
                                        QUIC_CRYPTO *, void *);
static int QuicFrameStreamDataBlockedParser(QUIC *, RPacket *, uint64_t,
                                        QUIC_CRYPTO *, void *);
static int QuicFrameAckBuild(QUIC *, WPacket *, QUIC_CRYPTO *, void *, long);
static int QuicFrameResetStreamBuild(QUIC *, WPacket *, QUIC_CRYPTO *,
                                        void *, long);
static int QuicFrameDataBlockedBuild(QUIC *, WPacket *, QUIC_CRYPTO *,
                                        void *, long);
static int QuicFrameStreamDataBlockedBuild(QUIC *, WPacket *, QUIC_CRYPTO *,
                                        void *, long);
static int QuicFrameNewTokenBuild(QUIC *, WPacket *, QUIC_CRYPTO *,
                                        void *, long);

static QuicFrameProcess frame_handler[QUIC_FRAME_TYPE_MAX] = {
    [QUIC_FRAME_TYPE_PADDING] = {
        .flags = QUIC_FRAME_FLAGS_NO_BODY|QUIC_FRAME_FLAGS_SKIP,
    },
    [QUIC_FRAME_TYPE_PING] = {
        .flags = QUIC_FRAME_FLAGS_NO_BODY,
        .parser = QuicFramePingParser,
    },
    [QUIC_FRAME_TYPE_ACK] = {
        .parser = QuicFrameAckParser,
        .builder = QuicFrameAckBuild,
    },
    [QUIC_FRAME_TYPE_RESET_STREAM] = {
        .parser = QuicFrameResetStreamParser,
        .builder = QuicFrameResetStreamBuild,
    },
    [QUIC_FRAME_TYPE_STOP_SENDING] = {
        .parser = QuicFrameStopSendingParser,
    },
    [QUIC_FRAME_TYPE_CRYPTO] = {
        .parser = QuicFrameCryptoParser,
    },
    [QUIC_FRAME_TYPE_NEW_TOKEN] = {
        .parser = QuicFrameNewTokenParser,
        .builder = QuicFrameNewTokenBuild,
    },
    [QUIC_FRAME_TYPE_STREAM] = {
        .parser = QuicFrameStreamParser,
    },
    [QUIC_FRAME_TYPE_STREAM_FIN] = {
        .parser = QuicFrameStreamParser,
    },
    [QUIC_FRAME_TYPE_STREAM_LEN] = {
        .parser = QuicFrameStreamParser,
    },
    [QUIC_FRAME_TYPE_STREAM_LEN_FIN] = {
        .parser = QuicFrameStreamParser,
    },
    [QUIC_FRAME_TYPE_STREAM_OFF] = {
        .parser = QuicFrameStreamParser,
    },
    [QUIC_FRAME_TYPE_STREAM_OFF_FIN] = {
        .parser = QuicFrameStreamParser,
    },
    [QUIC_FRAME_TYPE_STREAM_OFF_LEN] = {
        .parser = QuicFrameStreamParser,
    },
    [QUIC_FRAME_TYPE_STREAM_OFF_LEN_FIN] = {
        .parser = QuicFrameStreamParser,
    },
    [QUIC_FRAME_TYPE_MAX_DATA] = {
        .parser = QuicFrameMaxDataParser,
    },
    [QUIC_FRAME_TYPE_MAX_STREAM_DATA] = {
        .parser = QuicFrameMaxStreamDataParser,
    },
    [QUIC_FRAME_TYPE_MAX_STREAMS_BIDI] = {
        .parser = QuicFrameMaxStreamsBidiParser,
    },
    [QUIC_FRAME_TYPE_MAX_STREAMS_UNI] = {
        .parser = QuicFrameMaxStreamsUniParser,
    },
    [QUIC_FRAME_TYPE_DATA_BLOCKED] = {
        .parser = QuicFrameDataBlockedParser,
        .builder = QuicFrameDataBlockedBuild,
    },
    [QUIC_FRAME_TYPE_STREAM_DATA_BLOCKED] = {
        .parser = QuicFrameStreamDataBlockedParser,
        .builder = QuicFrameStreamDataBlockedBuild,
    },
    [QUIC_FRAME_TYPE_NEW_CONNECTION_ID] = {
        .parser = QuicFrameNewConnIdParser,
    },
    [QUIC_FRAME_TYPE_RETIRE_CONNECTION_ID] = {
        .parser = QuicFrameRetireConnIdParser,
    },
    [QUIC_FRAME_TYPE_CONNECTION_CLOSE] = {
        .parser = QuicFrameConnCloseParser,
    },
    [QUIC_FRAME_TYPE_CONNECTION_CLOSE_APP] = {
        .parser = QuicFrameConnCloseParser,
    },
    [QUIC_FRAME_TYPE_HANDSHAKE_DONE] = {
        .flags = QUIC_FRAME_FLAGS_NO_BODY,
        .parser = QuicFrameHandshakeDoneParser,
    },
};

int QuicFrameDoParser(QUIC *quic, RPacket *pkt, QUIC_CRYPTO *c,
                        uint32_t pkt_type, void *buf)
{
    QuicFrameParser parser = NULL;
    uint64_t type = 0;
    uint64_t flags = 0;
    bool ack_eliciting = false;

    while (QuicVariableLengthDecode(pkt, &type) >= 0) {
        if (type >= QUIC_FRAME_TYPE_MAX) {
            QUIC_LOG("Unknown type(%lx)\n", type);
            return -1;
        }
        flags = frame_handler[type].flags;
        if (flags & QUIC_FRAME_FLAGS_SKIP) {
            continue;
        }

        parser = frame_handler[type].parser;
        if (parser == NULL) {
            QUIC_LOG("No parser for type(%lx)\n", type);
            return -1;
        }

        if (parser(quic, pkt, type, c, buf) < 0) {
            QUIC_LOG("Parse failed: type = %lx\n", type);
            return -1;
        }

        if (QUIC_FRAM_IS_ACK_ELICITING(type)) {
            ack_eliciting = true;
        }
    }

    if (ack_eliciting) {
        QuicAckFrameBuild(quic, pkt_type);
    }

    return 0;
}

static int
QuicFrameCryptoParser(QUIC *quic, RPacket *pkt, uint64_t type, QUIC_CRYPTO *c,
                        void *buffer)
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
QuicFrameNewTokenParser(QUIC *quic, RPacket *pkt, uint64_t type, QUIC_CRYPTO *c,
                        void *buf)
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
QuicFramePingParser(QUIC *quic, RPacket *pkt, uint64_t type, QUIC_CRYPTO *c,
                        void *buf)
{
    return 0;
}

static int QuicFrameResetStreamParser(QUIC *quic, RPacket *pkt, uint64_t type,
                                        QUIC_CRYPTO *c, void *buf)
{
    QuicStreamInstance *si = NULL;
    uint64_t stream_id = 0;
    uint64_t error_code = 0;
    uint64_t final_size = 0;
    uint8_t recv_state = 0;

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

    si = QuicStreamGetInstance(quic, stream_id);
    if (si == NULL) {
        QUIC_LOG("Instance not found for ID %lu\n", stream_id);
        return -1;
    }

    recv_state = si->recv_state;
    if (recv_state == QUIC_STREAM_STATE_RECV ||
            recv_state == QUIC_STREAM_STATE_SIZE_KNOWN ||
            recv_state == QUIC_STREAM_STATE_DATA_RECVD) {
        si->recv_state = QUIC_STREAM_STATE_RESET_RECVD;
    }

    return 0;
}

static int QuicFrameStopSendingParser(QUIC *quic, RPacket *pkt,
                                    uint64_t type, QUIC_CRYPTO *c,
                                    void *buf)
{
    QuicStreamInstance *si = NULL;
    uint64_t id = 0;
    uint64_t err_code = 0;

    if (QuicVariableLengthDecode(pkt, &id) < 0) {
        QUIC_LOG("ID decode failed!\n");
        return -1;
    }

    QUIC_LOG("Stream %lu\n", id);
    si = QuicStreamGetInstance(quic, id);
    if (si == NULL) {
        QUIC_LOG("Instance not found for ID %lu\n", id);
        return -1;
    }

    if (si->send_state == QUIC_STREAM_STATE_START ||
            si->send_state == QUIC_STREAM_STATE_DISABLE) {
        //STREAM_STATE_ERROR
        QUIC_LOG("Send stream disabled\n");
        return -1;
    }

    si->send_state = QUIC_STREAM_STATE_DISABLE;

    if (QuicVariableLengthDecode(pkt, &err_code) < 0) {
        QUIC_LOG("Max Stream Data decode failed!\n");
        return -1;
    }

    if (si->recv_state == QUIC_STREAM_STATE_START) {
        si->recv_state = QUIC_STREAM_STATE_RECV;
    }

    return 0;
}

static int
QuicFrameAckParser(QUIC *quic, RPacket *pkt, uint64_t type, QUIC_CRYPTO *c,
                        void *buf)
{
    QBuffQueueHead *queue = &c->sent_queue;
    QBUFF *qb = NULL;
    uint64_t largest_acked = 0;
    uint64_t smallest_acked = 0;
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

    smallest_acked = largest_acked - first_ack_range;
    if (QUIC_LT(smallest_acked, 0)) {
        //FRAME_ENCODING_ERROR
        return -1;
    }

    qb = QBufAckSentPkt(quic, queue, smallest_acked, largest_acked, NULL);
    for (i = 0; i < range_count; i++) {
        if (QuicVariableLengthDecode(pkt, &gap) < 0) {
            QUIC_LOG("Gap decode failed!\n");
            return -1;
        }

        if (QuicVariableLengthDecode(pkt, &ack_range_len) < 0) {
            QUIC_LOG("ACK range len decode failed!\n");
            return -1;
        }
        largest_acked = smallest_acked - gap - 2;
        smallest_acked = largest_acked - ack_range_len;
        if (QUIC_LT(largest_acked, 0) || QUIC_LT(smallest_acked, 0)) {
            //FRAME_ENCODING_ERROR
            return -1;
        }
        qb = QBufAckSentPkt(quic, queue, smallest_acked, largest_acked, qb);
    }

    return 0;
}

static int
QuicFrameStreamParser(QUIC *quic, RPacket *pkt, uint64_t type, QUIC_CRYPTO *c,
                        void *buf)
{
    QuicStreamConf *scf = &quic->stream;
    QuicStreamInstance *si = NULL;
    QuicStreamData *sd = NULL;
    QuicStreamMsg *msg = NULL;
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

    si = QuicStreamGetInstance(quic, id);
    if (si == NULL) {
        QUIC_LOG("Instance not found for ID %lu\n", id);
        return -1;
    }

    if (si->recv_state == QUIC_STREAM_STATE_DISABLE) {
        QUIC_LOG("Receive stream disabled\n");
        return -1;
    }

    if (si->send_state == QUIC_STREAM_STATE_START) {
        si->send_state = QUIC_STREAM_STATE_READY;
    }

    if (type & QUIC_FRAME_STREAM_BIT_FIN) {
        QUIC_LOG("Stream FIN\n");
        if (si->recv_state == QUIC_STREAM_STATE_RECV) {
            si->recv_state = QUIC_STREAM_STATE_SIZE_KNOWN;
        }
    }

    if (RPacketGetBytes(pkt, &data, len) < 0) {
        QUIC_LOG("Peek stream data failed!\n");
        return -1;
    }

    if (si->recv_state == QUIC_STREAM_STATE_START) {
        si->recv_state = QUIC_STREAM_STATE_RECV;
    }

    if (si->recv_state != QUIC_STREAM_STATE_RECV &&
            si->recv_state != QUIC_STREAM_STATE_SIZE_KNOWN) {
        return 0;
    }

    sd = QuicStreamDataCreate(buf, offset, data, len);
    if (sd == NULL) {
        return -1;
    }

    QuicStreamDataAdd(quic, sd, si);

    if (!si->notified) {
        msg = QuicStreamMsgCreate(id, QUIC_STREAM_MSG_TYPE_DATA_RECVED);
        if (msg == NULL) {
            return 0;
        }
        QuicStreamMsgAdd(scf, msg);
        si->notified = 1;
    }

    return 0;
}

static int QuicFrameDataBlockedParser(QUIC *quic, RPacket *pkt,
                                    uint64_t type, QUIC_CRYPTO *c,
                                    void *buf)
{
    uint64_t max_data = 0;

    if (QuicVariableLengthDecode(pkt, &max_data) < 0) {
        QUIC_LOG("ID decode failed!\n");
        return -1;
    }

    return 0;
}

static int QuicFrameStreamDataBlockedParser(QUIC *quic, RPacket *pkt,
                                    uint64_t type, QUIC_CRYPTO *c,
                                    void *buf)
{
    QuicStreamInstance *si = NULL;
    uint64_t id = 0;
    uint64_t max_stream_data = 0;

    if (QuicVariableLengthDecode(pkt, &id) < 0) {
        QUIC_LOG("ID decode failed!\n");
        return -1;
    }

    QUIC_LOG("Stream %lu\n", id);
    si = QuicStreamGetInstance(quic, id);
    if (si == NULL) {
        QUIC_LOG("Instance not found for ID %lu\n", id);
        return -1;
    }

    if (si->recv_state == QUIC_STREAM_STATE_DISABLE) {
        QUIC_LOG("Receive stream disabled\n");
        return -1;
    }

    if (QuicVariableLengthDecode(pkt, &max_stream_data) < 0) {
        QUIC_LOG("Max Stream Data decode failed!\n");
        return -1;
    }

    if (si->recv_state == QUIC_STREAM_STATE_START) {
        si->recv_state = QUIC_STREAM_STATE_RECV;
    }

    return 0;
}

static int QuicFrameStreamParamUpdate(QuicTransParams *param, RPacket *pkt,
                                        uint64_t type)
{
    uint64_t max_streams = 0;
    uint64_t value = 0;

    if (QuicVariableLengthDecode(pkt, &max_streams) < 0) {
        QUIC_LOG("Max streams decode failed!\n");
        return -1;
    }

    if (QuicTransParamGet(param, type, &value, 0) < 0) {
        return -1;
    }

    if (QUIC_GT(max_streams, value)) {
        if (QuicTransParamSet(param, type, &max_streams, 0) < 0) {
            return -1;
        }
    }

    return 0;
}

static int QuicFrameMaxDataParser(QUIC *quic, RPacket *pkt, uint64_t type,
                                    QUIC_CRYPTO *c, void *buf)
{
    return QuicFrameStreamParamUpdate(&quic->peer_param, pkt,
                    QUIC_TRANS_PARAM_INITIAL_MAX_DATA);
}

static int QuicFrameMaxStreamDataParser(QUIC *quic, RPacket *pkt,
                                    uint64_t type, QUIC_CRYPTO *c,
                                    void *buf)
{
    QuicStreamInstance *si = NULL;
    uint64_t id = 0;
    uint64_t max_stream_data = 0;

    if (QuicVariableLengthDecode(pkt, &id) < 0) {
        QUIC_LOG("ID decode failed!\n");
        return -1;
    }

    QUIC_LOG("Stream %lu\n", id);
    si = QuicStreamGetInstance(quic, id);
    if (si == NULL) {
        QUIC_LOG("Instance not found for ID %lu\n", id);
        return -1;
    }

    if (si->recv_state == QUIC_STREAM_STATE_DISABLE ||
            si->recv_state == QUIC_STREAM_STATE_START) {
        //STREAM_STATE_ERROR
        QUIC_LOG("Receive stream disabled\n");
        return -1;
    }

    if (QuicVariableLengthDecode(pkt, &max_stream_data) < 0) {
        QUIC_LOG("Max Stream Data decode failed!\n");
        return -1;
    }

    if (QUIC_LT(si->max_stream_data, max_stream_data)) {
        si->max_stream_data = max_stream_data;
    }

    return 0;
}

static int QuicFrameMaxStreamsBidiParser(QUIC *quic, RPacket *pkt,
                                        uint64_t type, QUIC_CRYPTO *c,
                                        void *buf)
{
    return QuicFrameStreamParamUpdate(&quic->peer_param, pkt,
                QUIC_TRANS_PARAM_INITIAL_MAX_STREAMS_BIDI);
}

static int QuicFrameMaxStreamsUniParser(QUIC *quic, RPacket *pkt,
                                        uint64_t type, QUIC_CRYPTO *c,
                                        void *buf)
{
    return QuicFrameStreamParamUpdate(&quic->peer_param, pkt,
                QUIC_TRANS_PARAM_INITIAL_MAX_STREAMS_UNI);
}

static int QuicFrameNewConnIdParser(QUIC *quic, RPacket *pkt, uint64_t type,
                                        QUIC_CRYPTO *c, void *buf)
{
    QuicConn *conn = &quic->conn;
    QuicCidPool *p = NULL;
    QuicCid *cid = NULL;
    uint64_t seq = 0;
    uint64_t retire_prior_to = 0;
    uint64_t len = 0;
    uint64_t active_conn_limit = 0;

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

    if (quic->dcid.len == 0) {
        return -1;
    }

    p = &conn->dcid;
    QuicCidRetirePriorTo(p, retire_prior_to);
    if (QuicTransParamGet(&TLS_EXT_TRANS_PARAM(&quic->tls),
                QUIC_TRANS_PARAM_ACTIVE_CONNECTION_ID_LIMIT,
                &active_conn_limit, 0) < 0) {
        QUIC_LOG("Get transport parameter failed!\n");
        return -1;
    }

    if (QuicActiveCidLimitCheck(p, active_conn_limit) < 0) {
        QUIC_LOG("Active CID limit check failed!\n");
        return -1;
    }

    cid = QuicCidAlloc(seq);
    if (cid == NULL) {
        QUIC_LOG("Alloc CID failed!\n");
        return -1;
    }
    
    if (QuicDataParse(&cid->id, pkt, len) < 0) {
        QUIC_LOG("Connection ID parse failed!\n");
        return -1;
    }

    if (RPacketCopyBytes(pkt, cid->stateless_reset_token,
            sizeof(cid->stateless_reset_token)) < 0) {
        return -1;
    }

    QuicCidAdd(p, cid);
    return 0;
}

static int QuicFrameRetireConnIdParser(QUIC *quic, RPacket *pkt, uint64_t type,
                                        QUIC_CRYPTO *c, void *buf)
{
    QuicConn *conn = &quic->conn;
    uint64_t seq = 0;

    if (QuicVariableLengthDecode(pkt, &seq) < 0) {
        QUIC_LOG("Seq decode failed!\n");
        return -1;
    }

    if (QuicCidRetire(&conn->dcid, seq) < 0) {
        QUIC_LOG("Retire seq %lu failed!\n", seq);
    }

    return 0;
}

static int QuicFrameConnCloseParser(QUIC *quic, RPacket *pkt, uint64_t type,
                                        QUIC_CRYPTO *c, void *buf)
{
    const uint8_t *reason_phrase = NULL;
    uint64_t err_code = 0;
    uint64_t frame_type = 0;
    uint64_t reason_phrase_len = 0;
    
    QUIC_LOG("Connection Close\n");
    if (QuicVariableLengthDecode(pkt, &err_code) < 0) {
        QUIC_LOG("Error code decode failed!\n");
        return -1;
    }

    if (type == QUIC_FRAME_TYPE_CONNECTION_CLOSE) {
        if (QuicVariableLengthDecode(pkt, &frame_type) < 0) {
            QUIC_LOG("Frame type decode failed!\n");
            return -1;
        }
    }

    if (QuicVariableLengthDecode(pkt, &reason_phrase_len) < 0) {
        QUIC_LOG("Reason phrase length decode failed!\n");
        return -1;
    }

    if (RPacketGetBytes(pkt, &reason_phrase, reason_phrase_len) < 0) {
        QUIC_LOG("Get reason phrase failed!\n");
        return -1;
    }

    quic->statem.state = QUIC_STATEM_DRAINING;

    return 0;
}

static int QuicFrameHandshakeDoneParser(QUIC *quic, RPacket *pkt, uint64_t type,
                                        QUIC_CRYPTO *c, void *buf)
{
    QUIC_LOG("handshake done\n");
    if (!quic->quic_server) {
        quic->statem.state = QUIC_STATEM_HANDSHAKE_DONE;
        QuicCryptoFree(&quic->handshake);
    }

    return 0;
}

int QuicFramePaddingBuild(WPacket *pkt, size_t len)
{
    return WPacketMemset(pkt, 0, len);
}

static int QuicFrameCryptoBuild(QUIC *quic, WPacket *pkt, uint64_t offset,
                                uint8_t *data, size_t len)
{
    if (QuicVariableLengthWrite(pkt, QUIC_FRAME_TYPE_CRYPTO) < 0) {
        return -1;
    }

    if (QuicVariableLengthWrite(pkt, offset) < 0) {
        return -1;
    }

    return QuicWPacketSubMemcpyVar(pkt, data, len);
}

static int QuicFrameDataBlockedBuild(QUIC *quic, WPacket *pkt,
                                        QUIC_CRYPTO *c,
                                        void *arg, long larg)
{
    QuicStreamConf *scf = &quic->stream;

    return QuicVariableLengthWrite(pkt, scf->stat_all.sent);
}

static int QuicFrameStreamDataBlockedBuild(QUIC *quic, WPacket *pkt,
                                        QUIC_CRYPTO *c,
                                        void *arg, long larg)
{
    QuicStreamInstance *si = NULL;
    uint64_t id = larg;
    uint64_t max_stream_data = 0;

    si = QuicStreamGetInstance(quic, id);
    if (si == NULL) {
        return -1;
    }

    max_stream_data = si->stat_bytes.sent;

    if (si->send_state == QUIC_STREAM_STATE_READY) {
        si->send_state = QUIC_STREAM_STATE_SEND;
    }

    if (QuicVariableLengthWrite(pkt, id) < 0) {
        return -1;
    }

    if (QuicVariableLengthWrite(pkt, max_stream_data) < 0) {
        return -1;
    }

    return 0;
}

static int QuicFrameAckGen(QUIC *quic, WPacket *pkt, QUIC_CRYPTO *c)
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

static int QuicFrameAckBuild(QUIC *quic, WPacket *pkt, QUIC_CRYPTO *c,
                            void *arg, long larg)
{
    return QuicFrameAckGen(quic, pkt, c);
}

static int QuicFrameResetStreamBuild(QUIC *quic, WPacket *pkt, QUIC_CRYPTO *c,
                                        void *arg, long larg)
{
    QuicStreamInstance *si = NULL;
    uint64_t id = larg;
    uint64_t err_code = *((uint64_t *)arg);

    si = QuicStreamGetInstance(quic, id);
    if (si == NULL) {
        return -1;
    }

    if (si->send_state != QUIC_STREAM_STATE_READY &&
            si->send_state != QUIC_STREAM_STATE_SEND &&
            si->send_state != QUIC_STREAM_STATE_DATA_SENT) {
        return -1;
    }

    si->send_state = QUIC_STREAM_STATE_RESET_SENT;

    if (QuicVariableLengthWrite(pkt, id) < 0) {
        return -1;
    }

    if (QuicVariableLengthWrite(pkt, err_code) < 0) {
        return -1;
    }

    if (QuicVariableLengthWrite(pkt, si->stat_bytes.sent) < 0) {
        return -1;
    }

    return 0;
}

static int QuicFrameNewTokenBuild(QUIC *quic, WPacket *pkt, QUIC_CRYPTO *c,
                                        void *arg, long larg)
{
    uint8_t *token = NULL;
    uint64_t tlen = QUIC_NEW_TOKEN_LEN;

    if (QuicVariableLengthWrite(pkt, tlen) < 0) {
        return -1;
    }

    if (WPacketAllocateBytes(pkt, tlen, &token) < 0) {
        return -1;
    }

    if (RAND_bytes((unsigned char *)token, tlen) == 0) {
        return -1;
    }

    return QuicDataCopy(&quic->token, token, tlen);
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

static int QuicFrameStreamBuild(QUIC *quic, WPacket *pkt, uint64_t id,
                            uint8_t *data, size_t len, bool fin,
                            bool last)
{
    QuicStreamInstance *si = NULL;
    uint64_t type = QUIC_FRAME_TYPE_STREAM;
    uint64_t offset = 0;
    size_t space = 0;
    int data_len = 0;

    si = QuicStreamGetInstance(quic, id);
    if (si == NULL) {
        return -1;
    }

    if (si->send_state != QUIC_STREAM_STATE_READY &&
            si->send_state != QUIC_STREAM_STATE_SEND) {
        return -1;
    }

    if (si->send_state == QUIC_STREAM_STATE_READY) {
        si->send_state = QUIC_STREAM_STATE_SEND;
    }

    offset = si->stat_bytes.sent;
    if (offset) {
        type |= QUIC_FRAME_STREAM_BIT_OFF;
    }

    if (fin) {
        type |= QUIC_FRAME_STREAM_BIT_FIN;
        if (si->send_state == QUIC_STREAM_STATE_SEND) {
            si->send_state = QUIC_STREAM_STATE_DATA_SENT;
        }
    }

    if (!last) {
        type |= QUIC_FRAME_STREAM_BIT_LEN;
    }

    if (QuicVariableLengthWrite(pkt, type) < 0) {
        return -1;
    }

    if (QuicVariableLengthWrite(pkt, id) < 0) {
        return -1;
    }

    if (type & QUIC_FRAME_STREAM_BIT_OFF) {
        if (QuicVariableLengthWrite(pkt, offset) < 0) {
            return -1;
        }
    }

    if (type & QUIC_FRAME_STREAM_BIT_LEN) {
        return QuicWPacketSubMemcpyVar(pkt, data, len);
    }

    space = WPacket_get_space(pkt);
    data_len = QUIC_MIN(space, len);
    if (WPacketMemcpy(pkt, data, data_len) < 0) {
        return -1;
    }

    return data_len;
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
                                    QBUFF *qb, size_t buf_len, size_t max_hlen)
{
    if (QUIC_GT(WPacket_get_space(pkt), max_hlen)) {
        return qb;
    }

    if (QuicFrameAddQueue(quic, pkt, qb) < 0) {
        QUIC_LOG("Add frame queue failed\n");
        return NULL;
    }

    WPacketCleanup(pkt);
    return QuicFrameBufferNew(pkt_type, buf_len, pkt);
}

static QBUFF *QuicFrameCryptoSplit(QUIC *quic, uint32_t pkt_type, WPacket *pkt,
                QBUFF *qb, uint8_t *data, size_t len)
{
    uint64_t offset = 0;
    size_t buf_len = 0;
    int wlen = 0;

    buf_len = QBuffLen(qb);
    offset = 0;
    while (QUIC_LT(offset, len)) {
        qb = QuicBuffQueueAndNext(quic, pkt_type, pkt, qb, buf_len,
                                QUIC_FRAME_CRYPTO_HEADER_MAX_LEN);
        if (qb == NULL) {
            return NULL;
        }

        wlen = QuicFrameCryptoBuild(quic, pkt, offset, &data[offset],
                                        len - offset);
        if (wlen <= 0) {
            QUIC_LOG("Build failed\n");
            goto err;
        }

        offset += wlen;
    }

    WPacketCleanup(pkt);

    return qb;
err:
    QBuffFree(qb);
    return NULL;
}

static size_t QuicFrameGetBuffLen(QUIC *quic, uint32_t pkt_type)
{
    size_t buf_len = 0;
    size_t head_tail_len = 0;
    uint32_t mss = 0;

    mss = quic->mss;

    head_tail_len = QBufPktComputeTotalLenByType(quic, pkt_type, mss) - mss;
    buf_len = mss - head_tail_len;
    assert(QUIC_GT(buf_len, 0));

    return buf_len;
}

static int QuicFrameBuild(QUIC *quic, uint32_t pkt_type, QuicFrameNode *node,
                size_t num, QBUFF **out)
{
    QuicFrameBuilder builder = NULL;
    QUIC_CRYPTO *c = NULL;
    QuicFrameNode *n = NULL;
    QBUFF *qb = NULL;
    WPacket pkt = {};
    size_t i = 0;
    size_t buf_len = 0;
    uint64_t type = 0;
    uint64_t flags = 0;
    int ret = -1;

    buf_len = QuicFrameGetBuffLen(quic, pkt_type);
    qb = QuicFrameBufferNew(pkt_type, buf_len, &pkt);
    if (qb == NULL) {
        goto out;
    }

    c = QuicCryptoGet(quic, pkt_type);
    for (i = 0; i < num; i++) {
        n = &node[i];
        type = n->type;
        if (type >= QUIC_FRAME_TYPE_MAX) {
            QUIC_LOG("Unknown type(%lx)", type);
            continue;
        }
        
        flags = frame_handler[type].flags;
        builder = frame_handler[type].builder;
        if (builder == NULL && !(flags & QUIC_FRAME_FLAGS_NO_BODY)) {
            continue;
        }

        if (QuicVariableLengthWrite(&pkt, type) < 0) {
            goto out;
        }

        if (flags & QUIC_FRAME_FLAGS_NO_BODY) {
            continue;
        }

        if (builder(quic, &pkt, c, n->arg, n->larg) < 0) {
            QUIC_LOG("Build %lu failed\n", type);
            goto out;
        }
    }

    if (WPacket_get_written(&pkt)) {
        if (QuicFrameAddQueue(quic, &pkt, qb) < 0) {
            QUIC_LOG("Add frame queue failed\n");
            goto out;
        }

        if (out != NULL) {
            *out = qb;
        }

        qb = NULL;
    }

    ret = 0;
out:
    WPacketCleanup(&pkt);
    QBuffFree(qb);
    return ret;
}

static int QuicFrameStreamWrite(QUIC *quic, uint32_t pkt_type, WPacket *pkt,
                                int64_t id, uint8_t *data, size_t len,
                                QBUFF **qb, size_t buf_len, bool fin, bool last)
{
    QBUFF *nqb = *qb;
    uint64_t offset = 0;
    int wlen = 0;

    while (QUIC_LT(offset, len)) {
        nqb = QuicBuffQueueAndNext(quic, pkt_type, pkt, nqb, buf_len,
                QUIC_FRAME_STREAM_HEADER_MAX_LEN);
        if (nqb == NULL) {
            return -1;
        }

        nqb->stream_id = id;
        if (fin) {
            nqb->flags |= QBUFF_FLAGS_STREAM_FIN;
        }

        *qb = nqb;

        wlen = QuicFrameStreamBuild(quic, pkt, id, &data[offset], len - offset,
                                    fin, last);
        if (wlen < 0) {
            return -1;
        }

        nqb->stream_len += wlen;
        offset += wlen;
    }

    return 0;
}

int QuicStreamFrameBuild(QUIC *quic, QUIC_STREAM_IOVEC *iov, size_t num)
{
    QUIC_STREAM_IOVEC *v = NULL;
    QUIC_CRYPTO *c = NULL;
    QBUFF *qb = NULL;
    WPacket pkt = {};
    size_t i = 0;
    size_t buf_len = 0;
    uint64_t flags = 0;
    uint32_t pkt_type = QUIC_PKT_TYPE_1RTT;
    int ret = -1;

    buf_len = QuicFrameGetBuffLen(quic, pkt_type);
    qb = QuicFrameBufferNew(pkt_type, buf_len, &pkt);
    if (qb == NULL) {
        goto out;
    }

    c = QuicCryptoGet(quic, pkt_type);
    if (QuicFrameAckSendCheck(c) == 0) {
        if (QuicVariableLengthWrite(&pkt, QUIC_FRAME_TYPE_ACK) < 0) {
            return -1;
        }

        if (QuicFrameAckGen(quic, &pkt, c) < 0) {
            goto out;
        }
    }

    for (i = 0; i < num; i++) {
        v = &iov[i];
        if (QuicFrameStreamWrite(quic, pkt_type, &pkt, v->handle,
                    v->iov_base, v->data_len, &qb, buf_len,
                    flags & QUIC_STREAM_DATA_FLAGS_FIN,
                    i < num - 1) < 0) {
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

int QuicCryptoFrameBuild(QUIC *quic, uint32_t pkt_type)
{
    QUIC_BUFFER *buf = QUIC_TLS_BUFFER(quic);
    QBUFF *qb = NULL;
    uint8_t *data = NULL;
    WPacket pkt = {};
    size_t buf_len = 0;
    size_t len = 0;
    int ret = -1;

    data = QUIC_BUFFER_HEAD(buf);
    len = QuicBufGetDataLength(buf);

    buf_len = QuicFrameGetBuffLen(quic, pkt_type);
    qb = QuicFrameBufferNew(pkt_type, buf_len, &pkt);
    if (qb == NULL) {
        goto out;
    }

    qb = QuicFrameCryptoSplit(quic, pkt_type, &pkt, qb, data, len);
    if (qb == NULL) {
        goto out;
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

int QuicAckFrameBuild(QUIC *quic, uint32_t pkt_type)
{
    QUIC_CRYPTO *c = NULL;
    QuicFrameNode frame = {};

    c = QuicCryptoGet(quic, pkt_type);
    if (c == NULL) {
        return -1;
    }

    if (QuicFrameAckSendCheck(c) < 0) {
        return -1;
    }

    frame.type = QUIC_FRAME_TYPE_ACK;

    return QuicFrameBuild(quic, pkt_type, &frame, 1, NULL);
}

int QuicDataBlockedFrameBuild(QUIC *quic, int64_t id, uint32_t pkt_type)
{
    QuicFrameNode frame = {
        .type = QUIC_FRAME_TYPE_DATA_BLOCKED,
    };

    return QuicFrameBuild(quic, pkt_type, &frame, 1, NULL);
}

int QuicStreamDataBlockedFrameBuild(QUIC *quic, int64_t id, uint32_t pkt_type)
{
    QuicStreamInstance *si = NULL;
    QuicFrameNode frame = {
        .type = QUIC_FRAME_TYPE_STREAM_DATA_BLOCKED,
        .larg = id,
    };

    si = QuicStreamGetInstance(quic, id);
    if (si == NULL) {
        return -1;
    }

    return QuicFrameBuild(quic, pkt_type, &frame, 1, NULL);
}

int QuicResetStreamFrameBuild(QUIC *quic, int64_t id, uint32_t pkt_type,
                                uint64_t err_code)
{
    QuicStreamInstance *si = NULL;
    QBUFF *qb = NULL;
    QuicFrameNode frame = {
        .type = QUIC_FRAME_TYPE_RESET_STREAM,
        .arg = &err_code,
        .larg = id,
    };

    si = QuicStreamGetInstance(quic, id);
    if (si == NULL) {
        return -1;
    }

    if (QuicFrameBuild(quic, pkt_type, &frame, 1, &qb) < 0) {
        return -1;
    }

    if (qb != NULL) {
        qb->stream_id = id;
        qb->flags |= QBUFF_FLAGS_STREAM_RESET;
    }

    return 0;
}

int QuicDataHandshakeDoneFrameBuild(QUIC *quic, int64_t id, uint32_t pkt_type)
{
    QuicFrameNode frame[] = {
        {
            .type = QUIC_FRAME_TYPE_HANDSHAKE_DONE,
        },
        {
            .type = QUIC_FRAME_TYPE_NEW_TOKEN,
        },
    };

    return QuicFrameBuild(quic, pkt_type, frame, sizeof(frame)/sizeof(frame[0]),
                            NULL);
}


