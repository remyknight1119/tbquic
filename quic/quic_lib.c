/*
 * Remy Lewis(remyknight1119@gmail.com)
 */
#include "quic_local.h"

#include <string.h>
#include <assert.h>
#include <tbquic/quic.h>
#include <tbquic/cipher.h>
#include <tbquic/tls.h>

#include "statem.h"
#include "mem.h"
#include "log.h"
#include "cipher.h"
#include "tls_lib.h"
#include "sig_alg.h"
#include "datagram.h"
#include "common.h"
#include "format.h"

QUIC_CTX *QuicCtxNew(const QUIC_METHOD *meth)
{
    QUIC_CTX *ctx = NULL;

    ctx = QuicMemCalloc(sizeof(*ctx));
    if (ctx == NULL) {
        return NULL;
    }

    ctx->method = meth;
    ctx->mss = QUIC_DATAGRAM_SIZE_MAX_DEF;
    ctx->verify_mode = QUIC_TLS_VERIFY_NONE;
    ctx->cid_len = QUIC_MIN_CID_LENGTH;

    ctx->cert = QuicCertNew();
    if (ctx->cert == NULL) {
        goto out;
    }

    return ctx;
out:
    QuicCtxFree(ctx);
    return NULL;
}

void QuicCtxFree(QUIC_CTX *ctx)
{
    QuicDataFree(&ctx->ext.alpn);
    QuicDataFree(&ctx->ext.supported_groups);
    QuicCertFree(ctx->cert);
    QuicMemFree(ctx);
}

int QuicCtxCtrl(QUIC_CTX *ctx, uint32_t cmd, void *parg, long larg)
{
    switch (cmd) {
        case QUIC_CTRL_SET_GROUPS:
            return TlsSetSupportedGroups(&ctx->ext.supported_groups.ptr_u16,
                    &ctx->ext.supported_groups.len,
                    parg, larg);
        case QUIC_CTRL_SET_SIGALGS:
            return TlsSetSigalgs(ctx->cert, parg, larg);
        case QUIC_CTRL_SET_MSS:
            uint32_t mss = *((uint32_t *)(parg));
            if (QUIC_GT(mss, QUIC_DATAGRAM_SIZE_MAX)) {
                return -1;
            }

            ctx->mss = mss;
            return 0;
        default:
            return -1;
    }

    return 0;
}

int QUIC_CTX_set_transport_parameter(QUIC_CTX *ctx, uint64_t type, void *value,
                                        size_t len)
{
    return QuicTransParamSet(&ctx->ext.trans_param, type, value, len);
}

int QUIC_set_transport_parameter(QUIC *quic, uint64_t type,
                                    void *value, size_t len)
{
    return QuicTransParamSet(&quic->tls.ext.trans_param, type, value, len);
}

/*
 * QUIC_CTX_set_alpn_protos sets the ALPN protocol list on |ctx| to |protos|.
 * |protos| must be in wire-format (i.e. a series of non-empty, 8-bit
 * length-prefixed strings). Returns 0 on success.
 */
int QUIC_CTX_set_alpn_protos(QUIC_CTX *ctx, const uint8_t *protos,
                                size_t protos_len)
{
    return QuicDataCopy(&ctx->ext.alpn, protos, protos_len);
}

/*
 * QUIC_set_alpn_protos sets the ALPN protocol list on |quic| to |protos|.
 * |protos| must be in wire-format (i.e. a series of non-empty, 8-bit
 * length-prefixed strings). Returns 0 on success.
 */
int QUIC_set_alpn_protos(QUIC *quic, const uint8_t *protos, size_t protos_len)
{
    return QuicDataCopy(&quic->tls.ext.alpn, protos, protos_len);
}

static int QUIC_set_cipher_alg(QUIC_CIPHER *cipher, uint32_t alg)
{
    if (alg >= QUIC_ALG_MAX) {
        return -1;
    }

    cipher->alg = alg;
    return 0;
}

static int QUIC_set_hp_ciphers_alg(QUIC_CIPHERS *ciphers, uint32_t alg)
{
    return QUIC_set_cipher_alg(&ciphers->hp_cipher.cipher, alg);
}

int QUIC_set_hp_cipher_space_alg(QuicCipherSpace *space, uint32_t alg)
{
    return QUIC_set_hp_ciphers_alg(&space->ciphers, alg);
}

int QUIC_set_hp_cipher(QUIC_CRYPTO *c, uint32_t alg)
{
    if (QUIC_set_hp_cipher_space_alg(&c->decrypt, alg) < 0) {
        return -1;
    }

    return QUIC_set_hp_cipher_space_alg(&c->encrypt, alg);
}

int QUIC_set_initial_hp_cipher(QUIC *quic, uint32_t alg)
{
    return QUIC_set_hp_cipher(&quic->initial, alg);
}

int QUIC_set_handshake_hp_cipher(QUIC *quic, uint32_t alg)
{
    return QUIC_set_hp_cipher(&quic->handshake, alg);
}

static int QUIC_set_pp_ciphers_alg(QUIC_CIPHERS *ciphers, uint32_t alg)
{
    return QUIC_set_cipher_alg(&ciphers->pp_cipher.cipher, alg);
}

int QUIC_set_pp_cipher_space_alg(QuicCipherSpace *space, uint32_t alg)
{
    return QUIC_set_pp_ciphers_alg(&space->ciphers, alg);
}

int QUIC_set_initial_pp_cipher(QUIC *quic, uint32_t alg)
{
    if (QUIC_set_pp_cipher_space_alg(&quic->initial.decrypt, alg) < 0) {
        return -1;
    }

    return QUIC_set_pp_cipher_space_alg(&quic->initial.encrypt, alg);
}

static void QuicCipherSpaceInit(QuicCipherSpace *c)
{
    c->cipher_inited = false;
}

static void QuicCryptoCipherInit(QUIC_CRYPTO *c)
{
    QuicCipherSpaceInit(&c->decrypt);
    QuicCipherSpaceInit(&c->encrypt);

    QBuffQueueHeadInit(&c->sent_queue);
}

QUIC *QuicNew(QUIC_CTX *ctx)
{
    QUIC *quic = NULL;

    quic = QuicMemCalloc(sizeof(*quic));
    if (quic == NULL) {
        return NULL;
    }

    quic->statem.state = QUIC_STATEM_INITIAL;
    quic->statem.rwstate = QUIC_NOTHING; 
    quic->statem.read_state = QUIC_WANT_DATA; 
    quic->method = ctx->method;
    quic->mss = ctx->mss;
    quic->verify_mode = ctx->verify_mode;
    quic->cid_len = ctx->cid_len;
    quic->options = ctx->options;
    quic->version = ctx->method->version;
    quic->send_fd = -1;
    quic->tls.ext.trans_param = ctx->ext.trans_param;
    quic->ctx = ctx;

    if (QuicConnInit(&quic->conn) < 0) {
        goto out;
    }

    if (TlsInit(&quic->tls, ctx) < 0) {
        goto out;
    }

    if (quic->method->alloc_rbuf) {
        quic->read_buf = QuicDataCreate(quic->mss);
        if (quic->read_buf == NULL) {
            goto out;
        }
    }

    if (QUIC_set_initial_hp_cipher(quic, QUIC_ALG_AES_128_ECB) < 0) {
        goto out;
    }

    if (QUIC_set_initial_pp_cipher(quic, QUIC_ALG_AES_128_GCM) < 0) {
        goto out;
    }

    QuicTransParamInit(&quic->peer_param);
    QuicCryptoCipherInit(&quic->initial);
    QuicCryptoCipherInit(&quic->handshake);
    QuicCryptoCipherInit(&quic->application);

    QBuffQueueHeadInit(&quic->rx_queue);
    QBuffQueueHeadInit(&quic->tx_queue);
    INIT_LIST_HEAD(&quic->node);

    return quic;
out:

    QuicFree(quic);
    return NULL;
}

void QUIC_set_accept_state(QUIC *quic)
{
    quic->quic_server = 1;
    quic->do_handshake = quic->method->quic_accept;
}

void QUIC_set_connect_state(QUIC *quic)
{
    quic->quic_server = 0;
    quic->do_handshake = quic->method->quic_connect;
}

int QuicCtrl(QUIC *quic, uint32_t cmd, void *parg, long larg)
{
    TLS *tls = &quic->tls;
    size_t len = 0;

    switch (cmd) {
        case QUIC_CTRL_SET_PKT_NUM_MAX_LEN:
            len = *((size_t *)parg);
            if (len == 0 || QUIC_GT(len, 4)) {
                return -1;
            }
            quic->pkt_num_len = len - 1;
            break;
        case QUIC_CTRL_SET_GROUPS:
            return TlsSetSupportedGroups(&tls->ext.supported_groups.ptr_u16,
                    &tls->ext.supported_groups.len,
                    parg, larg);
        case QUIC_CTRL_SET_SIGALGS:
            return TlsSetSigalgs(tls->cert, parg, larg);
        case QUIC_CTRL_SET_TLSEXT_HOSTNAME:
            QuicMemFree(tls->ext.hostname);
            tls->ext.hostname = NULL;
            if (parg == NULL) {
                break;
            }

            len = strlen(parg);
            if (len == 0 || len > TLSEXT_MAXLEN_HOST_NAME) {
                return -1;
            }

            tls->ext.hostname = QuicMemStrDup(parg);
            if (tls->ext.hostname == NULL) {
                return -1;
            }

            break;
        default:
            return -1;
    }

    return 0;
}

int QuicDoHandshake(QUIC *quic)
{
    if (quic->do_handshake == NULL) {
        QUIC_LOG("Handshake not set\n");
        return -1;
    }

    return quic->do_handshake(quic);
}

void QuicFree(QUIC *quic)
{
    QuicStreamConfDeInit(&quic->stream);
    list_del(&quic->node);

    QuicDataFree(&quic->token);
    QuicDataFree(&quic->dcid);
    QuicDataFree(&quic->scid);

    BIO_free_all(quic->rbio);
    BIO_free_all(quic->wbio);

    QBuffQueueDestroy(&quic->tx_queue);
    QBuffQueueDestroy(&quic->rx_queue);

    QuicCryptoFree(&quic->application);
    QuicCryptoFree(&quic->handshake);
    QuicCryptoFree(&quic->initial);

    QuicDataDestroy(quic->read_buf);
    TlsFree(&quic->tls);

    QuicConnFree(&quic->conn);
    QuicMemFree(quic);
}

BIO *QUIC_get_rbio(const QUIC *quic)
{
    return quic->rbio;
}

BIO *QUIC_get_wbio(const QUIC *quic)
{
    return quic->wbio;
}

static void quic_set_bio(BIO **target, BIO *bio)
{
    BIO_free_all(*target);
    *target = bio;
}

void QUIC_set_rbio(QUIC *quic, BIO *rbio)
{
    quic_set_bio(&quic->rbio, rbio);
}

void QUIC_set_wbio(QUIC *quic, BIO *wbio)
{
    quic_set_bio(&quic->wbio, wbio);
}

void QUIC_set_bio(QUIC *quic, BIO *rbio, BIO *wbio)
{
    if (rbio == QUIC_get_rbio(quic) && wbio == QUIC_get_wbio(quic)) {
        return;
    }

    if (rbio != NULL && rbio == wbio) {
        BIO_up_ref(rbio);
    }

    if (rbio == QUIC_get_rbio(quic)) {
        QUIC_set_wbio(quic, wbio);
        return;
    }

    if (wbio == QUIC_get_wbio(quic)) {
        QUIC_set_rbio(quic, rbio);
        return;
    }

    QUIC_set_rbio(quic, rbio);
    QUIC_set_wbio(quic, wbio);
}

int QUIC_set_fd(QUIC *quic, int fd)
{
    BIO *bio = NULL;
    int ret = -1;

    bio = BIO_new(BIO_s_socket());
    if (bio == NULL) {
        goto err;
    }

    BIO_set_fd(bio, fd, BIO_NOCLOSE);
    QUIC_set_bio(quic, bio, bio);
    quic->fd_mode = 1;
    ret = 0;

err:
    return ret;
}

bool QuicWantRead(QUIC *quic)
{
    return quic->statem.rwstate == QUIC_READING;
}

bool QuicWantWrite(QUIC *quic)
{
    return quic->statem.rwstate == QUIC_WRITING;
}

int QUIC_get_error(QUIC *quic, int ret)
{
    if (ret == 0) {
        return QUIC_ERROR_NONE;
    }

    if (QuicWantRead(quic)) {
        return QUIC_ERROR_WANT_READ;
    }

    if (QuicWantWrite(quic)) {
        return QUIC_ERROR_WANT_WRITE;
    }

    return QUIC_ERROR_QUIC;
}

int QuicSendPacket(QUIC *quic)
{
    QuicStaticBuffer *buffer = NULL;
    QBuffQueueHead *send_queue = &quic->tx_queue;
    int wlen = 0;

    buffer = QuicGetSendBuffer();

    while (!QBuffQueueEmpty(send_queue)) {
        quic->statem.rwstate = QUIC_WRITING;
        if (QuicWritePkt(quic, buffer) < 0) {
            return -1;
        }

        wlen = quic->method->write_bytes(quic, buffer->data, buffer->len);
        if (wlen < 0) {
            QUIC_LOG("errno = %s\n", strerror(errno));
            return -1;
        }

        if (!quic->fd_mode) {
            break;
        }
    }
 
    if (quic->statem.rwstate == QUIC_WRITING && QBuffQueueEmpty(send_queue)) {
        quic->statem.rwstate = QUIC_FINISHED;
    }

    return 0;
}

int QuicInit(void)
{
    if (QuicLoadCiphers() < 0) {
        return -1;
    }

	return 0;
}

void QuicExit(void)
{
}

