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
#include "extension.h"
#include "frame.h"
#include "common.h"
#include "log.h"

static bool
TlsHandshakeRetransMsg(TlsMessageType type, QuicStatem state,
                const QuicStatemMachine *statem, size_t num)
{
    const QuicStatemMachine *sm = NULL;
    size_t i = 0;

    for (i = 0; i < state; i++) {
        sm = &statem[i];
        if (sm->rw_state != QUIC_READING) {
            continue;
        }
        
        if (sm->msg_type == type) {
            return true;
        }
    }

    return false;
}

QuicFlowReturn
TlsHandshakeMsgRead(TLS *s, QuicStatem *state, const QuicStatemMachine *statem,
                    size_t num, RPacket *pkt, bool *skip)
{
    const QuicStatemMachine *sm = NULL;
    RPacket packet = {};
    RPacket msg = {};
    size_t remain = 0;
    uint32_t type = 0;
    uint32_t len = 0;
    int offset = 0;

    sm = &statem[*state];
    if (sm->handshake == NULL) {
        QUIC_LOG("No handler func found\n");
        return QUIC_FLOW_RET_ERROR;
    }

    remain = RPacketRemaining(pkt);
    packet = *pkt;
    if (RPacketGet1(pkt, &type) < 0) {
        return QUIC_FLOW_RET_WANT_READ;
    }

    while (type != sm->msg_type) {
        if (sm->skip_check != NULL && sm->skip_check(s) == 0) {
            QUIC_LOG("Skip optional state \"%s\"\n", QuicStatStrGet(*state));
            *state = sm->next_state;
            sm = &statem[*state];
            *skip = true;
            QUIC_LOG("Enter state \"%s\"\n", QuicStatStrGet(*state));
            continue;
        }
        QUIC_LOG("type not match(target : %u, msg: %u)\n", sm->msg_type, type);
        if (TlsHandshakeRetransMsg(type, *state, statem, num)) {
            QUIC_LOG("retrans\n");
            if (RPacketGet3(pkt, &len) < 0) {
                return QUIC_FLOW_RET_ERROR;
            }

            if (RPacketPull(pkt, len) < 0) {
                return QUIC_FLOW_RET_ERROR;
            }

            return QUIC_FLOW_RET_WANT_READ;
        }

        QuicPrint(RPacketData(pkt), RPacketRemaining(pkt));
        return QUIC_FLOW_RET_ERROR;
    }

    if (RPacketGet3(pkt, &len) < 0) {
        *pkt = packet;
        QUIC_LOG("Read len failed\n");
        return QUIC_FLOW_RET_WANT_READ;
    }

    offset = remain - RPacketRemaining(pkt);
    assert(offset > 0);

    if (RPacketTransfer(&msg, pkt, len) < 0) {
        *pkt = packet;
        return QUIC_FLOW_RET_WANT_READ;
    }
 
    if (type == TLS_MT_FINISHED) {
        if (TlsTakeMac(s) < 0) {
            return QUIC_FLOW_RET_ERROR;
        }
    }

    RPacketHeadPush(&msg, offset);
    if (TlsFinishMac(s, RPacketHead(&msg), RPacketTotalLen(&msg)) < 0) {
        return QUIC_FLOW_RET_ERROR;
    }

    return sm->handshake(s, &msg);
}

QuicFlowReturn
TlsHandshakeMsgWrite(TLS *s, const QuicStatemMachine *sm, WPacket *pkt)
{
    uint8_t *msg = NULL;
    QuicFlowReturn ret = QUIC_FLOW_RET_FINISH;
    size_t msg_len = 0;
    size_t wlen = 0;

    if (sm->handshake == NULL) {
        QUIC_LOG("No handler func found\n");
        return QUIC_FLOW_RET_ERROR;
    }

    msg = WPacket_get_curr(pkt);
    wlen = WPacket_get_written(pkt);
    if (WPacketPut1(pkt, sm->msg_type) < 0) {
        QUIC_LOG("Put Message type failed\n");
        return QUIC_FLOW_RET_ERROR;
    }

    /* TLS handshake message length 3 byte */
    if (WPacketStartSubU24(pkt) < 0) { 
        return QUIC_FLOW_RET_ERROR;
    }
 
    ret = sm->handshake(s, pkt);
    if (ret == QUIC_FLOW_RET_ERROR) {
        return QUIC_FLOW_RET_ERROR;
    }

    if (WPacketClose(pkt) < 0) {
        QUIC_LOG("Close packet failed\n");
        return QUIC_FLOW_RET_ERROR;
    }

    msg_len = WPacket_get_written(pkt) - wlen;
    assert(QUIC_GT(msg_len, 0));
    if (TlsFinishMac(s, msg, msg_len) < 0) {
        return QUIC_FLOW_RET_ERROR;
    }

    return ret;
}

int TlsHelloHeadParse(TLS *s, RPacket *pkt, uint8_t *random,
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

static int TlsAddCertToWpacket(TLS *s, WPacket *pkt, X509 *x, int chain,
                                TlsExtConstructor ext)
{
    unsigned char *outbytes = NULL;
    int len = 0;

    len = i2d_X509(x, NULL);
    if (len < 0) {
        return -1;
    }

    if (WPacketSubAllocBytesU24(pkt, len, &outbytes) < 0) {
        return -1;
    }

    if (i2d_X509(x, &outbytes) != len) {
        return -1;
    }

    return ext(s, pkt, TLSEXT_CERTIFICATE, x, chain);
}

int TlsAddCertChain(TLS *s, WPacket *pkt, QuicCertPkey *cpk,
                    TlsExtConstructor ext)
{
    STACK_OF(X509) *extra_certs = NULL;
    X509 *x = NULL;
    int i = 0;

    if (cpk == NULL || cpk->x509 == NULL) {
        return -1;
    }

    x = cpk->x509;

    if (cpk->chain != NULL) {
        extra_certs = cpk->chain;
    }

    if (TlsAddCertToWpacket(s, pkt, x, 0, ext) < 0) {
        return -1;
    }

    for (i = 0; i < sk_X509_num(extra_certs); i++) {
        x = sk_X509_value(extra_certs, i);
        if (TlsAddCertToWpacket(s, pkt, x, i + 1, ext) < 0) {
            return -1;
        }
    }

    return 0;
}

QuicFlowReturn TlsCertChainBuild(TLS *s, WPacket *pkt, QuicCertPkey *cpk,
                                    TlsExtConstructor ext)
{
    if (WPacketStartSubU24(pkt) < 0) {
        return QUIC_FLOW_RET_ERROR;
    }

    if (TlsAddCertChain(s, pkt, cpk, ext) < 0) {
        return QUIC_FLOW_RET_ERROR;
    }

    if (WPacketClose(pkt) < 0) {
        return QUIC_FLOW_RET_ERROR;
    }

    return QUIC_FLOW_RET_FINISH;
}

QuicFlowReturn TlsCertVerifyBuild(TLS *s, WPacket *pkt)
{
    if (TlsConstructCertVerify(s, pkt) < 0) {
        return QUIC_FLOW_RET_ERROR;
    }

    return QUIC_FLOW_RET_FINISH;
}

QuicFlowReturn TlsFinishedBuild(TLS *s, void *packet)
{
    WPacket *pkt = packet;
    const char *sender = NULL;
    size_t finish_md_len = 0;
    size_t slen = 0;

    if (s->server) {
        sender = kTlsMdServerFinishLabel;
        slen = TLS_MD_SERVER_FINISH_LABEL_LEN;
    } else {
        sender = kTlsMdClientFinishLabel;
        slen = TLS_MD_CLIENT_FINISH_LABEL_LEN;
    }

    finish_md_len = TlsFinalFinishMac(s, sender, slen, s->finish_md);
    if (finish_md_len == 0) {
        return QUIC_FLOW_RET_ERROR;
    }

    s->finish_md_len = finish_md_len;

    if (WPacketMemcpy(pkt, s->finish_md, finish_md_len) < 0) {
        return QUIC_FLOW_RET_ERROR;
    }

    return QUIC_FLOW_RET_FINISH;
}

int TlsFinishedCheck(TLS *s, RPacket *pkt)
{
    size_t len = 0;

    len = s->peer_finish_md_len;
    if (RPacketRemaining(pkt) != len) {
        return -1;
    }

    if (QuicMemCmp(RPacketData(pkt), s->peer_finish_md, len) != 0) {
        return -1;
    }

    return 0;
}

int TlsInit(TLS *s, QUIC_CTX *ctx)
{
    s->lifetime_hint = QUIC_SESSION_TICKET_LIFETIME_HINT_DEF;
    s->max_early_data = ctx->max_early_data;
    s->early_data_state = TLS_EARLY_DATA_NONE;
    s->verify_callback = ctx->verify_callback;
    s->verify_result = X509_V_OK;

    if (QuicBufInit(&s->buffer, TLS_MESSAGE_MAX_LEN) < 0) {
        return -1;
    }

    s->cert = QuicCertDup(ctx->cert);
    if (s->cert == NULL) {
        return -1;
    }

    if (QuicDataDup(&s->ext.alpn, &ctx->ext.alpn) < 0) {
        return -1;
    }

    if (!QuicDataIsEmpty(&ctx->ext.supported_groups)) {
        if (QuicDataDupU16(&s->ext.supported_groups,
                    &ctx->ext.supported_groups) < 0) {
            return -1;
        }
    }

    s->ext.ticket_key = ctx->ext.ticket_key;

    INIT_HLIST_HEAD(&s->cipher_list);

    if (TlsCreateCipherList(&s->cipher_list, TLS_CIPHERS_DEF,
                                sizeof(TLS_CIPHERS_DEF) - 1) < 0) {
        QUIC_LOG("Create cipher list failed\n");
        return -1;
    }

    return 0;
}

void TlsFree(TLS *s)
{
    QuicDataFree(&s->alpn_selected);
    QuicDataFree(&s->alpn_proposed);

    if (s->ext.hostname != NULL) {
        QuicMemFree(s->ext.hostname);
    }

    X509_free(s->peer_cert);
    EVP_MD_CTX_free(s->handshake_dgst);
    EVP_PKEY_free(s->peer_kexch_key);
    EVP_PKEY_free(s->kexch_key);
    QuicMemFree((void *)s->shared_sigalgs);
    QuicDataFree(&s->tmp.peer_cert_sigalgs);
    QuicDataFree(&s->ext.supported_groups);
    QuicDataFree(&s->ext.peer_supported_groups);
    QuicDataFree(&s->ext.peer_sigalgs);
    QuicDataFree(&s->ext.alpn);

    TlsDestroyCipherList(&s->cipher_list);
    QuicCertFree(s->cert);
    QuicBufFree(&s->buffer);
}

int QuicTlsInit(void)
{
    if (!QuicX509StoreCtxInit()) {
        return -1;
    }

    return 0;
}

