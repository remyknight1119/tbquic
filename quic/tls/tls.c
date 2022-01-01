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
#include "tls_lib.h"
#include "mem.h"
#include "common.h"
#include "log.h"

QuicFlowReturn
TlsDoHandshake(TLS *tls)
{
    return tls->method->handshake(tls);
}

static void TlsFlowFinish(TLS *tls, TlsState prev_state,
                                TlsState next_state)
{
    /* If proc not assign next_state, use default */
    if (prev_state == tls->handshake_state) {
        tls->handshake_state = next_state;
    }
}

static QuicFlowReturn
TlsHandshakeRead(TLS *tls, const TlsProcess *p, RPacket *pkt)
{
    RPacket packet = {};
    RPacket msg = {};
    TlsState state = 0;
    size_t remain = 0;
    uint32_t type = 0;
    uint32_t len = 0;
    int offset = 0;

    if (p->handler == NULL) {
        QUIC_LOG("No handler func found\n");
        return QUIC_FLOW_RET_ERROR;
    }

    remain = RPacketRemaining(pkt);
    if (remain == 0) {
        return QUIC_FLOW_RET_WANT_READ;
    }

    packet = *pkt;
    if (RPacketGet1(pkt, &type) < 0) {
        return QUIC_FLOW_RET_WANT_READ;
    }

    if (type != p->msg_type) {
        QUIC_LOG("type not match\n");
        return QUIC_FLOW_RET_ERROR;
    }

    if (RPacketGet3(pkt, &len) < 0) {
        *pkt = packet;
        return QUIC_FLOW_RET_WANT_READ;
    }

    offset = remain - RPacketRemaining(pkt);
    assert(offset > 0);

    if (RPacketTransfer(&msg, pkt, len) < 0) {
        *pkt = packet;
        return QUIC_FLOW_RET_WANT_READ;
    }
 
    if (type == TLS_MT_FINISHED) {
        if (TlsTakeMac(tls) < 0) {
            return QUIC_FLOW_RET_ERROR;
        }
    }

    RPacketHeadPush(&msg, offset);
    if (TlsFinishMac(tls, RPacketHead(&msg), RPacketTotalLen(&msg)) < 0) {
        return QUIC_FLOW_RET_ERROR;
    }

    state = tls->handshake_state;
    if (p->handler(tls, &msg) < 0) {
        return QUIC_FLOW_RET_ERROR;
    }

    TlsFlowFinish(tls, state, p->next_state);
    return QUIC_FLOW_RET_FINISH;
}

static QuicFlowReturn
TlsHandshakeWrite(TLS *tls, const TlsProcess *p, WPacket *pkt)
{
    uint8_t *msg = NULL;
    TlsState state = 0;
    size_t msg_len = 0;
    size_t wlen = 0;

    if (p->handler == NULL) {
        QUIC_LOG("No handler func found\n");
        return QUIC_FLOW_RET_ERROR;
    }

    msg = WPacket_get_curr(pkt);
    wlen = WPacket_get_written(pkt);
    if (WPacketPut1(pkt, p->msg_type) < 0) {
        QUIC_LOG("Put Message type failed\n");
        return QUIC_FLOW_RET_ERROR;
    }

    /* TLS handshake message length 3 byte */
    if (WPacketStartSubU24(pkt) < 0) { 
        return QUIC_FLOW_RET_ERROR;
    }
 
    state = tls->handshake_state;
    if (p->handler(tls, pkt) < 0) {
        return QUIC_FLOW_RET_ERROR;
    }

    if (WPacketClose(pkt) < 0) {
        QUIC_LOG("Close packet failed\n");
        return QUIC_FLOW_RET_ERROR;
    }

    msg_len = WPacket_get_written(pkt) - wlen;
    assert(QUIC_GT(msg_len, 0));
    if (TlsFinishMac(tls, msg, msg_len) < 0) {
        return QUIC_FLOW_RET_ERROR;
    }

    TlsFlowFinish(tls, state, p->next_state);

    return QUIC_FLOW_RET_FINISH;
}

static QuicFlowReturn
TlsHandshakeStatem(TLS *tls, RPacket *rpkt, WPacket *wpkt,
                        const TlsProcess *proc, size_t num)
{
    const TlsProcess *p = NULL;
    TlsState state = 0;
    QuicFlowReturn ret = QUIC_FLOW_RET_ERROR;

    state = tls->handshake_state;
    assert(state >= 0 && state < num);
    p = &proc[state];

    while (!QUIC_FLOW_STATEM_FINISHED(p->flow_state)) {
        switch (p->flow_state) {
            case QUIC_FLOW_NOTHING:
                tls->handshake_state = p->next_state;
                ret = QUIC_FLOW_RET_CONTINUE;
                break;
            case QUIC_FLOW_READING:
                ret = TlsHandshakeRead(tls, p, rpkt);
                break;
            case QUIC_FLOW_WRITING:
                ret = TlsHandshakeWrite(tls, p, wpkt);
                break;
            default:
                QUIC_LOG("Unknown flow state(%d)\n", p->flow_state);
                return QUIC_FLOW_RET_ERROR;
        }

        if (ret == QUIC_FLOW_RET_ERROR) {
            return ret;
        }

        if (ret == QUIC_FLOW_RET_WANT_READ) {
            return ret;
        }

        if (p->post_work != NULL && p->post_work(tls) < 0) {
            return QUIC_FLOW_RET_ERROR;
        }

        state = tls->handshake_state;
        assert(state >= 0 && state < num);
        p = &proc[state];
    }

    return QUIC_FLOW_RET_FINISH;
}

QuicFlowReturn
TlsHandshake(TLS *tls, const TlsProcess *proc, size_t num)
{
    QUIC_BUFFER *buffer = &tls->buffer;
    RPacket rpkt = {};
    WPacket wpkt = {};
    QuicFlowReturn ret = QUIC_FLOW_RET_ERROR;
    size_t data_len = 0;

    data_len = QuicBufGetDataLength(buffer) - QuicBufGetOffset(buffer);
    assert(QUIC_GE(data_len, 0));
    RPacketBufInit(&rpkt, QuicBufMsg(buffer), data_len);
    WPacketBufInit(&wpkt, buffer->buf);

    ret = TlsHandshakeStatem(tls, &rpkt, &wpkt, proc, num);
    if (ret == QUIC_FLOW_RET_WANT_READ && RPacketRemaining(&rpkt)) {
        if (QuicBufAddOffset(buffer, RPacketReadLen(&rpkt)) < 0) {
            return QUIC_FLOW_RET_ERROR;
        }
    } else {
        QuicBufResetOffset(buffer);
    }

    QuicBufSetDataLength(buffer, WPacket_get_written(&wpkt));
    WPacketCleanup(&wpkt);

    return ret;
}

int TlsHelloHeadParse(TLS *tls, RPacket *pkt, uint8_t *random,
                            size_t random_size)
{
    uint32_t session_id_len = 0;
    uint32_t legacy_version = 0;

    if (RPacketGet2(pkt, &legacy_version) < 0) {
        return -1;
    }

    if (RPacketCopyBytes(pkt, random, random_size) < 0) {
        return -1;
    }

    if (RPacketGet1(pkt, &session_id_len) < 0) {
        return -1;
    }

    if (RPacketPull(pkt, session_id_len) < 0) {
        return -1;
    }

    return 0;
}

int TlsExtLenParse(RPacket *pkt)
{
    uint32_t ext_len = 0;

    if (RPacketGet2(pkt, &ext_len) < 0) {
        return -1;
    }

    if (RPacketRemaining(pkt) != ext_len) {
        QUIC_LOG("Check extension len failed\n");
        return -1;
    }

    return 0;
}

int TlsFinishedBuild(TLS *s, void *packet)
{
    WPacket *pkt = packet;
    const char *sender = NULL;
    size_t finish_md_len = 0;
    size_t slen = 0;

    if (s->server) {
        sender = tls_md_server_finish_label;
        slen = TLS_MD_SERVER_FINISH_LABEL_LEN;
    } else {
        sender = tls_md_client_finish_label;
        slen = TLS_MD_CLIENT_FINISH_LABEL_LEN;
    }

    finish_md_len = TlsFinalFinishMac(s, sender, slen, s->finish_md);
    if (finish_md_len == 0) {
        return -1;
    }

    s->finish_md_len = finish_md_len;

    if (WPacketMemcpy(pkt, s->finish_md, finish_md_len) < 0) {
        return -1;
    }

    return 0;
}

int TlsInit(TLS *tls, QUIC_CTX *ctx)
{
    tls->handshake_state = TLS_ST_OK;
    tls->method = ctx->method->tls_method;
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

    if (TlsCreateCipherList(&tls->cipher_list, TLS_CIPHERS_DEF,
                                sizeof(TLS_CIPHERS_DEF) - 1) < 0) {
        QUIC_LOG("Create cipher list failed\n");
        return -1;
    }

    return 0;
}

void TlsFree(TLS *tls)
{
    if (tls->ext.hostname != NULL) {
        QuicMemFree(tls->ext.hostname);
    }

    X509_free(tls->peer_cert);
    EVP_MD_CTX_free(tls->handshake_dgst);
    EVP_PKEY_free(tls->peer_kexch_key);
    EVP_PKEY_free(tls->kexch_key);
    QuicDataFree(&tls->ext.supported_groups);
    QuicDataFree(&tls->ext.alpn);

    TlsDestroyCipherList(&tls->cipher_list);
    QuicCertFree(tls->cert);
    QuicBufFree(&tls->buffer);
}

