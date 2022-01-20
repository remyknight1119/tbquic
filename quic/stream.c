/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "stream.h"

#include <tbquic/quic.h>
#include "quic_local.h"
#include "tls.h"
#include "packet_local.h"
#include "mem.h"
#include "log.h"

void QuicStreamConfInit(QUIC *quic)
{
    QuicStreamConf *scf = &quic->stream;

    INIT_LIST_HEAD(&scf->queue);
}

static uint64_t QuicStreamIdGen(QuicStreamConf *scf, bool server)
{
    uint64_t id = 0;

    id = scf->id_alloced++;
    id = (id << QUIC_STREAM_ID_MASK_BITS) | QUIC_STREAM_UNIDIRECTIONAL;
    if (server) {
        id |= QUIC_STREAM_INITIATED_BY_SERVER;
    }

    return id;
}

QUIC_STREAM_HANDLE QuicStreamCreate(QUIC *quic)
{
    QuicStreamConf *scf = &quic->stream;
    QuicStreamInstance *si = NULL;

    si = QuicMemCalloc(sizeof(*si));
    if (si == NULL) {
        return NULL;
    }

    si->id = QuicStreamIdGen(scf, quic->quic_server);
    si->recv_state = QUIC_STREAM_STATE_START;
    si->send_state = QUIC_STREAM_STATE_START;
    si->quic = quic;
    list_add_tail(&si->node, &scf->queue);

    return (QUIC_STREAM_HANDLE)si;
}

static void QuicStreamInstanceFree(QUIC_STREAM_HANDLE h)
{
    QuicMemFree(h);
}

int QuicStreamSendEarlyData(QUIC_STREAM_HANDLE h, void *data, size_t len)
{
    QUIC *quic = NULL; 
    TlsState handshake_state;
    int ret = 0;

    quic = h->quic;
    ret = QuicDoHandshake(quic);
    QUIC_LOG("ret = %d\n", ret);
    handshake_state = quic->tls.handshake_state; 
    if (handshake_state == TLS_ST_SR_FINISHED ||
            handshake_state == TLS_ST_HANDSHAKE_DONE) {
            QUIC_LOG("Build Stream frame\n");
        if (QuicStreamFrameBuild(h, data, len) < 0) {
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

int QuicStreamSend(QUIC_STREAM_HANDLE h, void *data, size_t len)
{
    QUIC *quic = NULL; 

    quic = h->quic;
    if (QuicStreamFrameBuild(h, data, len) < 0) {
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

void QuicStreamQueueDestroy(QuicStreamConf *scf)
{
    QuicStreamInstance *si = NULL;
    QuicStreamInstance *n = NULL;

    list_for_each_entry_safe(si, n, &scf->queue, node) {
        list_del(&si->node);
        QuicStreamInstanceFree(si);
    }
}

