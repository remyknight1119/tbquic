/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "tls.h"

#include <assert.h>
#include <tbquic/types.h>
#include <tbquic/quic.h>

#include "packet_local.h"
#include "quic_local.h"
#include "tls_cipher.h"
#include "mem.h"
#include "log.h"

QuicFlowReturn
QuicTlsDoHandshake(QUIC_TLS *tls, const uint8_t *data, size_t len)
{
    return tls->handshake(tls, data, len);
}

static void QuicTlsFlowFinish(QUIC_TLS *tls, QuicTlsState prev_state,
                                QuicTlsState next_state)
{
    /* If proc not assign next_state, use default */
    if (prev_state == tls->handshake_state) {
        tls->handshake_state = next_state;
    }
}

static QuicFlowReturn
QuicTlsHandshakeRead(QUIC_TLS *tls, const QuicTlsProcess *p, RPacket *pkt)
{
    QuicTlsState state = 0;
    QuicFlowReturn ret = QUIC_FLOW_RET_FINISH;
    uint32_t type = 0;

    if (p->handler == NULL) {
        QUIC_LOG("No handler func found\n");
        return QUIC_FLOW_RET_ERROR;
    }

    if (RPacketGet1(pkt, &type) < 0) {
        return QUIC_FLOW_RET_WANT_READ;
    }

    if (type != p->handshake_type) {
        QUIC_LOG("type not match\n");
        return QUIC_FLOW_RET_ERROR;
    }

    state = tls->handshake_state;
    ret = p->handler(tls, pkt);
    if (ret != QUIC_FLOW_RET_FINISH) {
        return ret;
    }

    QuicTlsFlowFinish(tls, state, p->next_state);
    return ret;
}

static QuicFlowReturn
QuicTlsHandshakeWrite(QUIC_TLS *tls, const QuicTlsProcess *p, WPacket *pkt)
{
    QuicTlsState state = 0;
    QuicFlowReturn ret = QUIC_FLOW_RET_FINISH;

    if (p->handler == NULL) {
        QUIC_LOG("No handler func found\n");
        return QUIC_FLOW_RET_ERROR;
    }

    if (WPacketPut1(pkt, p->handshake_type) < 0) {
        QUIC_LOG("Put handshake type failed\n");
        return QUIC_FLOW_RET_ERROR;
    }

    /* TLS handshake message length 3 byte */
    if (WPacketStartSubU24(pkt) < 0) { 
        return QUIC_FLOW_RET_ERROR;
    }
 
    state = tls->handshake_state;
    ret = p->handler(tls, pkt);
    if (ret != QUIC_FLOW_RET_FINISH) {
        return ret;
    }

    if (WPacketClose(pkt) < 0) {
        QUIC_LOG("Close packet failed\n");
        return QUIC_FLOW_RET_ERROR;
    }

    QuicTlsFlowFinish(tls, state, p->next_state);
    return ret;
}

static QuicFlowReturn
QuicTlsHandshakeStatem(QUIC_TLS *tls, RPacket *rpkt, WPacket *wpkt,
                        const QuicTlsProcess *proc, size_t num)
{
    const QuicTlsProcess *p = NULL;
    QuicTlsState state = 0;
    QuicFlowReturn ret = QUIC_FLOW_RET_FINISH;

    state = tls->handshake_state;
    assert(state >= 0 && state < num);
    p = &proc[state];

    while (!QUIC_FLOW_STATEM_FINISHED(p->flow_state)) {
        switch (p->flow_state) {
            case QUIC_FLOW_NOTHING:
                tls->handshake_state = p->next_state;
                break;
            case QUIC_FLOW_READING:
                ret = QuicTlsHandshakeRead(tls, p, rpkt);
                break;
            case QUIC_FLOW_WRITING:
                ret = QuicTlsHandshakeWrite(tls, p, wpkt);
                break;
            default:
                QUIC_LOG("Unknown flow state(%d)\n", p->flow_state);
                return QUIC_FLOW_RET_ERROR;
        }
        if (ret != QUIC_FLOW_RET_FINISH) {
            return ret;
        }
        state = tls->handshake_state;
        assert(state >= 0 && state < num);
        p = &proc[state];
    }

    return QUIC_FLOW_RET_FINISH;
}

QuicFlowReturn QuicTlsHandshake(QUIC_TLS *tls, const uint8_t *data, size_t len,
                        const QuicTlsProcess *proc, size_t num)
{
    QUIC_BUFFER *buffer = &tls->buffer;
    RPacket rpkt = {};
    WPacket wpkt = {};
    QuicFlowReturn ret;

    RPacketBufInit(&rpkt, data, len);
    WPacketBufInit(&wpkt, buffer->buf);

    ret = QuicTlsHandshakeStatem(tls, &rpkt, &wpkt, proc, num);
    buffer->data_len = WPacket_get_written(&wpkt);
    WPacketCleanup(&wpkt);

    return ret;
}

int QuicTlsInit(QUIC_TLS *tls, QUIC_CTX *ctx)
{
    tls->handshake_state = QUIC_TLS_ST_OK;
    if (QuicBufInit(&tls->buffer, TLS_MESSAGE_MAX_LEN) < 0) {
        return -1;
    }

    tls->cert = QuicCertDup(ctx->cert);
    if (tls->cert == NULL) {
        return -1;
    }

    if (QuicDataDup(&tls->ext.alpn, &ctx->ext.alpn) < 0) {
        return -1;
    }

    if (!QuicDataIsEmpty(&ctx->ext.supported_groups)) {
        if (QuicDataDupU16(&tls->ext.supported_groups,
                    &ctx->ext.supported_groups) < 0) {
            return -1;
        }
    }

    INIT_HLIST_HEAD(&tls->cipher_list);
    return 0;
}

void QuicTlsFree(QUIC_TLS *tls)
{
    if (tls->ext.hostname != NULL) {
        QuicMemFree(tls->ext.hostname);
    }

    EVP_PKEY_free(tls->tmp_key);
    QuicDataFree(&tls->ext.supported_groups);
    QuicDataFree(&tls->ext.alpn);

    QuicTlsDestroyCipherList(&tls->cipher_list);
    QuicCertFree(tls->cert);
    QuicBufFree(&tls->buffer);
}

