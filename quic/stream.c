/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "stream.h"

#include <tbquic/quic.h>
#include "quic_local.h"
#include "tls.h"
#include "packet_local.h"
#include "frame.h"
#include "mem.h"
#include "common.h"
#include "log.h"

static uint64_t QuicStreamComputeMaxId(uint64_t num)
{
    uint64_t base = num & QUIC_STREAM_ID_MASK;
    uint64_t top = num & ~QUIC_STREAM_ID_MASK;

    return ((top << 1) | base);
}

static void QuicStreamInstanceInit(QuicStreamInstance *si)
{
    si->recv_state = QUIC_STREAM_STATE_START;
    si->send_state = QUIC_STREAM_STATE_START;
}

int QuicStreamConfInit(QuicStreamConf *scf, uint64_t max_stream_bidi,
                        uint64_t max_stream_uni)
{
    size_t i = 0;
    uint64_t max_bidi_stream_id = 0;
    uint64_t max_uni_stream_id = 0;

    if (scf->stream != NULL) {
        QUIC_LOG("Stream initialized\n");
        return -1;
    }

    max_bidi_stream_id = QuicStreamComputeMaxId(max_stream_bidi);
    max_uni_stream_id = QuicStreamComputeMaxId(max_stream_uni);
    scf->max_id_value = QUIC_MAX(max_bidi_stream_id, max_uni_stream_id);
    scf->stream = QuicMemCalloc(sizeof(*scf->stream)*scf->max_id_value);
    if (scf->stream == NULL) {
        return -1;
    }

    for (i = 0; i < scf->max_id_value; i++) {
        QuicStreamInstanceInit(&scf->stream[i]);
    }

    return 0;
}

void QuicStreamConfDeInit(QuicStreamConf *scf)
{
    QuicMemFree(scf->stream);
}

static int64_t QuicStreamIdGen(QuicTransParams *param, QuicStreamConf *scf,
                                bool server, bool uni)
{
    int64_t id = 0;

    if (uni) {
        if (scf->uni_id_alloced > param->initial_max_stream_uni) {
            return -1;
        }
        id = scf->uni_id_alloced++;
        id = (id << QUIC_STREAM_ID_MASK_BITS) | QUIC_STREAM_UNIDIRECTIONAL;
    } else {
        if (scf->bidi_id_alloced > param->initial_max_stream_bidi) {
            return -1;
        }
        id = scf->bidi_id_alloced++;
        id = (id << QUIC_STREAM_ID_MASK_BITS);
    }

    if (server) {
        id |= QUIC_STREAM_INITIATED_BY_SERVER;
    }

    if (id >= scf->max_id_value) {
        QUIC_LOG("id = %ld, max id = %lu\n", id, scf->max_id_value);
        return -1;
    }

    return id;
}

QUIC_STREAM_HANDLE QuicStreamOpen(QUIC *quic, bool uni)
{
    QuicStreamConf *scf = &quic->stream;
    QuicStreamInstance *si = NULL;
    int64_t id = -1;

    if (scf->stream == NULL) {
        QUIC_LOG("Stream not initialized\n");
        return -1;
    }

    id = QuicStreamIdGen(&quic->negoed_param, scf, quic->quic_server, uni);
    if (id < 0) {
        return -1;
    }

    si = &scf->stream[id];
    si->send_state = QUIC_STREAM_STATE_READY;
    if (!uni) {
        si->recv_state = QUIC_STREAM_STATE_RECV;
    }

    return id;
}

void QuicStreamClose(QUIC_STREAM_HANDLE h)
{
}

int QuicStreamSendEarlyData(QUIC *quic, QUIC_STREAM_HANDLE *h, bool uni,
                                void *data, size_t len)
{
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
        if (QuicStreamFrameBuild(quic, id, data, len) < 0) {
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
    if (QuicStreamFrameBuild(quic, h, data, len) < 0) {
        QUIC_LOG("Build Stream frame failed\n");
        return -1;
    }

    if (QuicSendPacket(quic) < 0) {
        return -1;
    }

    return len;
}

int QuicStreamRecv(QUIC *quic, void *data, size_t len)
{
    RPacket pkt = {};
    QuicPacketFlags flags;
    QuicFlowReturn ret = QUIC_FLOW_RET_ERROR;
    uint32_t flag = 0;
    int rlen = 0;

    rlen = quic->method->read_bytes(quic, &pkt);
    if (rlen < 0) {
        return -1;
    }

    while (RPacketRemaining(&pkt)) {
        if (RPacketGet1(&pkt, &flag) < 0) {
            return -1;
        }

        flags.value = flag;
        ret = QuicPacketRead(quic, &pkt, flags);
        if (ret == QUIC_FLOW_RET_ERROR) {
            return -1;
        }

        RPacketUpdate(&pkt);
    }

    return 0;
}

int QuicStreamInit(QUIC *quic)
{
    QuicTransParams *param = &quic->negoed_param;

    return QuicStreamConfInit(&quic->stream, param->initial_max_stream_bidi,
                                param->initial_max_stream_uni);
}
