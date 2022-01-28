/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "stream.h"

#include <assert.h>
#include <tbquic/quic.h>
#include <tbquic/stream.h>
#include "quic_local.h"
#include "tls.h"
#include "packet_local.h"
#include "frame.h"
#include "mem.h"
#include "common.h"
#include "log.h"

static uint64_t QuicStreamComputeMaxId(uint64_t num, bool uni, bool server)
{
    uint64_t base = num & QUIC_STREAM_ID_MASK;
    uint64_t top = num & ~QUIC_STREAM_ID_MASK;

    if (uni) {
        base |= QUIC_STREAM_UNIDIRECTIONAL;
    }

    if (server) {
        base |= QUIC_STREAM_INITIATED_BY_SERVER;
    }

    return ((top << 1) | base);
}

static bool QuicStreamPeerOpened(int64_t id, bool server)
{
    return (server && !(id & QUIC_STREAM_INITIATED_BY_SERVER)) ||
                (!server && (id & QUIC_STREAM_INITIATED_BY_SERVER));
}

static void
QuicStreamInstanceInit(QuicStreamInstance *si, int64_t id, bool server)
{
    si->recv_state = QUIC_STREAM_STATE_START;
    si->send_state = QUIC_STREAM_STATE_START;

    si->uni = 0;
    if (QuicStreamPeerOpened(id, server)) {
        if (id & QUIC_STREAM_UNIDIRECTIONAL) {
            si->send_state = QUIC_STREAM_STATE_DISABLE;
            si->uni = 1;
        }
        si->local_opened = 0;
    } else {
        if (id & QUIC_STREAM_UNIDIRECTIONAL) {
            si->recv_state = QUIC_STREAM_STATE_DISABLE;
            si->uni = 1;
        }
        si->local_opened = 1;
    }

    INIT_LIST_HEAD(&si->queue);
}

static void
QuicStreamInstanceDeInit(QuicStreamInstance *si)
{
    QuicStreamData *sd = NULL;
    QuicStreamData *n = NULL;

    list_for_each_entry_safe(sd, n, &si->queue, node) {
        list_del(&sd->node);
        QuicStreamDataFree(sd);
    }
}

static void QuicStreamInstanceRecvOpen(QuicStreamInstance *si)
{
    if (si->recv_state == QUIC_STREAM_STATE_START) {
        si->recv_state = QUIC_STREAM_STATE_RECV;
    }
}

static int QuicStreamConfInit(QuicStreamConf *scf, uint64_t max_stream_bidi,
                        uint64_t max_stream_uni, bool server)
{
    uint64_t max_bidi_stream_id = 0;
    uint64_t max_uni_stream_id = 0;
    int64_t id = 0;

    if (scf->stream != NULL) {
        QUIC_LOG("Stream initialized\n");
        return -1;
    }

    max_bidi_stream_id = QuicStreamComputeMaxId(max_stream_bidi, false, server);
    max_uni_stream_id = QuicStreamComputeMaxId(max_stream_uni, true, server);
    scf->max_id_value = QUIC_MAX(max_bidi_stream_id, max_uni_stream_id);
    scf->stream = QuicMemCalloc(sizeof(*scf->stream)*scf->max_id_value);
    if (scf->stream == NULL) {
        return -1;
    }

    for (id = 0; id < scf->max_id_value; id++) {
        QuicStreamInstanceInit(&scf->stream[id], id, server);
    }

    INIT_LIST_HEAD(&scf->msg_queue);
    return 0;
}

void QuicStreamConfDeInit(QuicStreamConf *scf)
{
    QuicStreamMsg *msg = NULL;
    QuicStreamMsg *n = NULL;
    int64_t id = 0;

    if (scf->stream == NULL) {
        return;
    }

    for (id = 0; id < scf->max_id_value; id++) {
        QuicStreamInstanceDeInit(&scf->stream[id]);
    }

    list_for_each_entry_safe(msg, n, &scf->msg_queue, node) {
        list_del(&msg->node);
        QuicStreamMsgFree(msg);
    }

    QuicMemFree(scf->stream);
}

QuicStreamMsg *QuicStreamMsgCreate(int64_t id, uint32_t type)
{
    QuicStreamMsg *msg = NULL;

    msg = QuicMemCalloc(sizeof(*msg));
    if (msg == NULL) {
        return NULL;
    }

    msg->id = id;
    msg->type = type;

    return msg;
}

void QuicStreamMsgAdd(QuicStreamConf *scf, QuicStreamMsg *msg)
{
    list_add_tail(&msg->node, &scf->msg_queue);
}

void QuicStreamMsgFree(QuicStreamMsg *msg)
{
    QuicMemFree(msg);
}

static int QuicStreamIdCheckPeer(QUIC *quic, int64_t id)
{
    QuicTransParams *param = &quic->tls.ext.trans_param;
    uint64_t max_stream_id = 0;

    if (QuicStreamPeerOpened(id, quic->quic_server)) {
        return 0;
    }

    if (id & QUIC_STREAM_UNIDIRECTIONAL) {
        max_stream_id = QuicStreamComputeMaxId(param->initial_max_stream_uni,
                                    true, quic->quic_server);
    } else {
        max_stream_id = QuicStreamComputeMaxId(param->initial_max_stream_bidi,
                                    false, quic->quic_server);
    }

    if (id >= max_stream_id) {
        //send a STREAMS_BLOCKED frame (type=0x16)
        return -1;
    }

    return 0;
}

static int QuicStreamIdCheck(QUIC *quic, QuicStreamConf *scf, int64_t id)
{
    if (id < 0) {
        return -1;
    }

    if (QuicStreamIdCheckPeer(quic, id) < 0) {
        return -1;
    }

    if (id >= scf->max_id_value) {
        QUIC_LOG("id = %ld, max id = %lu\n", id, scf->max_id_value);
        return -1;
    }

    return 0;
}

static int64_t QuicStreamIdGen(QuicStreamConf *scf, QuicTransParams *param,
                                bool server, bool uni)
{
    uint64_t *alloced = NULL;
    int64_t id = 0;

    if (uni) {
        id = scf->uni_id_alloced;
        if (id >= param->initial_max_stream_uni) {
            return -1;
        }
        id = (id << QUIC_STREAM_ID_MASK_BITS) | QUIC_STREAM_UNIDIRECTIONAL;
        alloced = &scf->uni_id_alloced;
    } else {
        id = scf->bidi_id_alloced;
        if (id >= param->initial_max_stream_bidi) {
            return -1;
        }
        id = (id << QUIC_STREAM_ID_MASK_BITS);
        alloced = &scf->bidi_id_alloced;
    }

    if (server) {
        id |= QUIC_STREAM_INITIATED_BY_SERVER;
    }

    if (id >= scf->max_id_value) {
        QUIC_LOG("id = %ld, max id = %lu\n", id, scf->max_id_value);
        return -1;
    }

    (*alloced)++;
    return id;
}

QUIC_STREAM_HANDLE QuicStreamOpen(QUIC *quic, bool uni)
{
    QuicStreamConf *scf = &quic->stream;
    QuicTransParams *peer = &quic->peer_param;
    QuicStreamInstance *si = NULL;
    int64_t id = -1;

    if (scf->stream == NULL) {
        QUIC_LOG("Stream not initialized\n");
        return -1;
    }

    id = QuicStreamIdGen(scf, &quic->peer_param, quic->quic_server, uni);
    if (id < 0) {
        return -1;
    }

    si = &scf->stream[id];

    assert(si->send_state == QUIC_STREAM_STATE_START);

    si->send_state = QUIC_STREAM_STATE_READY;
    if (uni) {
        si->max_stream_data = peer->initial_max_stream_data_uni;
    } else {
        si->max_stream_data = peer->initial_max_stream_data_bidi_remote;
        QuicStreamInstanceRecvOpen(si);
    }

    return id;
}

void QuicStreamClose(QUIC_STREAM_HANDLE h)
{
}

QuicStreamInstance *QuicStreamGetInstance(QUIC *quic, QUIC_STREAM_HANDLE h)
{
    QuicStreamConf *scf = &quic->stream;
    QuicStreamInstance *si = NULL;
    int64_t id = h;
    int64_t i = 0;

    if (scf->stream == NULL) {
        QUIC_LOG("Stream not initialized\n");
        return NULL;
    }

    if (QuicStreamIdCheck(quic, scf, id) < 0) {
        return NULL;
    }

    si = &scf->stream[id];

    if (!QuicStreamPeerOpened(id, quic->quic_server) &&
            si->send_state == QUIC_STREAM_STATE_START) {
        return NULL;
    }

    if (id > scf->max_id_opened) {
        for (i = scf->max_id_opened + 1; i <= id; i++) {
            QuicStreamInstanceRecvOpen(&scf->stream[i]);
        }

        scf->max_id_opened = id;
    }

    return si;
}

int QuicStreamSendEarlyData(QUIC *quic, QUIC_STREAM_HANDLE *h, bool uni,
                                void *data, size_t len)
{
    QUIC_STREAM_IOVEC iov = {
        .iov_base = data,
        .iov_len = len,
        .data_len = len,
    };
    TlsState handshake_state;
    int64_t id = 0;
    int ret = 0;

    ret = QuicDoHandshake(quic);
    handshake_state = quic->tls.handshake_state; 
    if (handshake_state == TLS_ST_SR_FINISHED ||
            handshake_state == TLS_ST_HANDSHAKE_DONE) {
            QUIC_LOG("Build Stream frame\n");
        id = QuicStreamOpen(quic, uni);
        if (id < 0) {
            QUIC_LOG("Open Stream failed\n");
            return -1;
        }

        *h = id;
        iov.handle = id;
        if (QuicStreamFrameBuild(quic, &iov, 1) < 0) {
            QUIC_LOG("Build Stream frame failed\n");
            return -1;
        }

        if (QuicSendPacket(quic) < 0) {
            return -1;
        }

        return len;
    }

    return ret;
}

int QuicStreamSend(QUIC *quic, QUIC_STREAM_HANDLE h, void *data, size_t len)
{
    QuicStreamInstance *si = NULL;
    QUIC_STREAM_IOVEC iov = {
        .handle = h,
        .iov_base = data,
        .iov_len = len,
        .data_len = len,
    };
 
    si = QuicStreamGetInstance(quic, h);
    if (si == NULL) {
        return -1;
    }

    if (si->send_state != QUIC_STREAM_STATE_READY &&
            si->send_state != QUIC_STREAM_STATE_SEND) {
        return -1;
    }

    if (QuicStreamFrameBuild(quic, &iov, 1) < 0) {
        QUIC_LOG("Build Stream frame failed\n");
        return -1;
    }

    if (QuicSendPacket(quic) < 0) {
        return -1;
    }

    return len;
}

static int QuicStreamReadData(QuicStreamInstance *si, uint32_t *flags,
                            uint8_t *data, size_t len)
{
    QuicStreamData *sd = NULL;
    QuicStreamData *n = NULL;
    size_t copy_bytes = 0;
    int rlen = 0;

    list_for_each_entry_safe(sd, n, &si->queue, node) {
        if (si->offset != sd->offset) {
            //Out of order data
            break;
        }

        if (sd->len + rlen > len) {
            copy_bytes = len - rlen;
            assert(QUIC_GT(copy_bytes, 0));
        } else {
            copy_bytes = sd->len;
        }

        QuicMemcpy(&data[rlen], sd->data, copy_bytes);
        if (copy_bytes == sd->len) {
            list_del(&sd->node);
            QuicStreamDataFree(sd);
        } else {
            sd->data += copy_bytes;
            sd->len -= copy_bytes;
        }

        si->offset += copy_bytes;
        rlen += copy_bytes;
        if (rlen == len) {
            break;
        }
    }

    if (list_empty(&si->queue)) {
        if (si->recv_state == QUIC_STREAM_STATE_DATA_RECVD) {
            si->recv_state = QUIC_STREAM_STATE_DATA_READ;
            if (flags != NULL) {
                *flags |= QUIC_STREAM_DATA_FLAGS_FIN;
            }
        }
    }

    if (si->recv_state == QUIC_STREAM_STATE_RESET_RECVD) {
        if (flags != NULL) {
            *flags |= QUIC_STREAM_DATA_FLAGS_RESET;
        }
    }

    si->notified = 0;
    return rlen;
}

static int QuicStreamRecvNew(QUIC *quic)
{
    RPacket pkt = {};
    QuicPacketFlags pkt_flags;
    QuicFlowReturn ret = QUIC_FLOW_RET_ERROR;
    uint32_t flag = 0;
    int err = 0;

    err = quic->method->read_bytes(quic, &pkt);
    if (err < 0) {
        return -1;
    }

    while (RPacketRemaining(&pkt)) {
        if (RPacketGet1(&pkt, &flag) < 0) {
            return -1;
        }

        pkt_flags.value = flag;
        ret = QuicPacketRead(quic, &pkt, pkt_flags);
        if (ret == QUIC_FLOW_RET_ERROR) {
            return -1;
        }

        RPacketUpdate(&pkt);
    }

    return 0;
}

int QuicStreamRecv(QUIC *quic, QUIC_STREAM_HANDLE h, uint32_t *flags,
                        void *data, size_t len)
{
    QuicStreamInstance *si = NULL;
    int rlen = 0;

    si = QuicStreamGetInstance(quic, h);
    if (si == NULL) {
        return -1;
    }

    rlen = QuicStreamReadData(si, flags, data, len);
    if (rlen > 0) {
        return rlen;
    }

    if (QuicStreamRecvNew(quic) < 0) {
        return -1;
    }

    return QuicStreamReadData(si, flags, data, len);
}

int QuicStreamReadV(QUIC *quic, QUIC_STREAM_IOVEC *iov, size_t iovcnt)
{
    QuicStreamConf *scf = &quic->stream;
    QUIC_STREAM_IOVEC *iov_cur = NULL;
    QuicStreamMsg *msg = NULL;
    QuicStreamMsg *n = NULL;
    QuicStreamInstance *si = NULL;
    uint32_t flags = 0;
    int64_t id = 0;
    int cnt = 0;
    int rlen = 0;

    if (scf->stream == NULL) {
        return -1;
    }

    if (iovcnt == 0) {
        return 0;
    }

    if (list_empty(&scf->msg_queue)) {
        if (QuicStreamRecvNew(quic) < 0) {
            return -1;
        }
    }

    list_for_each_entry_safe(msg, n, &scf->msg_queue, node) {
        if (msg->type != QUIC_STREAM_MSG_TYPE_DATA_RECVED) {
            continue;
        }
        while (1) {
            if (cnt >= iovcnt) {
                return cnt;
            }
            iov_cur = &iov[cnt];
            id = msg->id;
            si = QuicStreamGetInstance(quic, id);
            if (si == NULL) {
                break;
            }

            rlen = QuicStreamReadData(si, &flags, iov_cur->iov_base,
                    iov_cur->iov_len);
            if (rlen > 0) {
                iov_cur->handle = id;
                iov_cur->data_len = rlen;
                iov_cur->flags = flags;
                cnt++;
            }

            if (rlen < iov_cur->iov_len) {
                break;
            }
        }
        list_del(&msg->node);
        QuicStreamMsgFree(msg);
    }

    return cnt;
}

int QuicStreamInit(QUIC *quic)
{
    QuicTransParams *local = &quic->tls.ext.trans_param;
    QuicTransParams *peer = &quic->peer_param;
    uint32_t max_stream_bidi = 0;
    uint32_t max_stream_uni = 0;

    max_stream_bidi = QUIC_MAX(local->initial_max_stream_bidi,
                                peer->initial_max_stream_bidi);
    max_stream_uni = QUIC_MAX(local->initial_max_stream_uni,
                                peer->initial_max_stream_uni);
    return QuicStreamConfInit(&quic->stream, max_stream_bidi, max_stream_uni,
                                quic->quic_server);
}

QuicStreamData *QuicStreamDataCreate(void *origin_buf, int64_t offset,
                                        const void *data, size_t len)
{
    QuicStreamData *sd = NULL;

    if (origin_buf == NULL) {
        return NULL;
    }

    sd = QuicMemCalloc(sizeof(*sd));
    if (sd == NULL) {
        return NULL;
    }

    sd->offset = offset;
    sd->data = data;
    sd->len = len;

    QuicDataBufGet(origin_buf);
    sd->origin_buf = origin_buf;
    return sd;
}

static int QuicStreamRecvFlowCtrl(QUIC *quic, QuicStreamInstance *si,
                                        size_t data_len)
{
    QuicStreamConf *scf = &quic->stream;
    QuicTransParams *local = &quic->tls.ext.trans_param;
    QuicTransParams *peer = &quic->peer_param;
    uint64_t recvd = si->stat_bytes.recvd + data_len;
    uint64_t total_recvd = scf->stat_all.recvd + data_len;
    uint64_t local_limit = 0;
    uint64_t conn_limit = 0;

    if (si->local_opened) {
        if (si->uni) {
            return -1;
        }
        local_limit = local->initial_max_stream_data_bidi_remote;
    } else {
        if (si->uni) {
            local_limit = local->initial_max_stream_data_uni;
        } else {
            local_limit = peer->initial_max_stream_data_bidi_remote;
        }
    }

    if (QUIC_GT(recvd, local_limit)) {
        QUIC_LOG("Data exceed stream limit\n");
        return -1;
    }

    conn_limit = peer->initial_max_data;
    if (QUIC_GT(total_recvd, conn_limit)) {
        QUIC_LOG("Data exceed connection limit\n");
        return -1;
    }

    si->stat_bytes.recvd = recvd;
    scf->stat_all.recvd = total_recvd;

    return 0;
}

int QuicStreamSendFlowCtrl(QUIC *quic, int64_t id, size_t len,
                            uint32_t pkt_type)
{
    QuicStreamConf *scf = &quic->stream;
    QuicTransParams *peer = &quic->peer_param;
    QuicStreamInstance *si = NULL;
    uint64_t stream_send = 0;
    uint64_t total_send = 0;

    if (len == 0) {
        return 0;
    }

    si = QuicStreamGetInstance(quic, id);
    if (si == NULL) {
        return 0;
    }

    stream_send = si->stat_bytes.sent + len;
    if (QUIC_GT(stream_send, si->max_stream_data)) {
        QuicStreamDataBlockedFrameBuild(quic, id, pkt_type);
        return -1;
    }

    total_send = scf->stat_all.sent + len;
    if (QUIC_GT(total_send, peer->initial_max_data)) {
        QuicDataBlockedFrameBuild(quic, id, pkt_type);
        return -1;
    }

    si->stat_bytes.sent = stream_send;
    scf->stat_all.sent = total_send;
    return 0;
}

static void QuicStreamDataAddOfo(QUIC *quic, QuicStreamData *sd,
                            QuicStreamInstance *si)
{
    if (QuicStreamRecvFlowCtrl(quic, si, sd->len) < 0) {
        QUIC_LOG("Drop because of flow control\n");
        QuicStreamDataFree(sd);
        return;
    }

    list_add_tail(&sd->node, &si->queue);
}

static bool QuicStreamOrdered(QuicStreamInstance *si)
{
    QuicStreamData *sd = NULL;
    bool ordered = true;
    int64_t start = si->offset;

    list_for_each_entry(sd, &si->queue, node) {
        if (start != sd->offset) {
            ordered = false;
            break;
        }

        start = sd->offset + sd->len;
    }

    return ordered;
}

void QuicStreamDataAdd(QUIC *quic, QuicStreamData *sd,
                    QuicStreamInstance *si)
{
    int64_t start = sd->offset;
    int64_t end = sd->offset + sd->len;
    int64_t offset = 0;

    if (si->offset >= end){
        //Retransmitted
        QUIC_LOG("Retransmitted\n");
        QuicStreamDataFree(sd);
        return;
    }

    if (si->offset < start) {
        //Out of Order
        QuicStreamDataAddOfo(quic, sd, si);
        return;
    }

    if (si->offset > start) {
        //Overlap
        offset = si->offset - start;
        sd->data += offset;
        sd->len -= offset;
        sd->offset = si->offset;
    }

    if (QuicStreamRecvFlowCtrl(quic, si, sd->len) < 0) {
        QUIC_LOG("Drop because of flow control\n");
        QuicStreamDataFree(sd);
        return;
    }

    list_add_tail(&sd->node, &si->queue);

    if (si->recv_state == QUIC_STREAM_STATE_SIZE_KNOWN ||
            si->recv_state == QUIC_STREAM_STATE_RESET_RECVD) {
        if (QuicStreamOrdered(si)) {
            si->recv_state = QUIC_STREAM_STATE_DATA_RECVD;
        }
    }
}

void QuicStreamDataFree(QuicStreamData *sd)
{
    QuicDataBufFree(sd->origin_buf);
    QuicMemFree(sd);
}


