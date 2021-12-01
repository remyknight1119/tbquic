/*
 * Remy Lewis(remyknight1119@gmail.com)
 */
#include "quic_local.h"

#include <tbquic/quic.h>
#include <tbquic/cipher.h>

#include "statem.h"
#include "mem.h"
#include "log.h"
#include "cipher.h"
#include "tls_lib.h"

QUIC_CTX *QuicCtxNew(const QUIC_METHOD *meth)
{
    QUIC_CTX *ctx = NULL;

    ctx = QuicMemCalloc(sizeof(*ctx));
    if (ctx == NULL) {
        return NULL;
    }

    ctx->method = meth;
    ctx->mtu = QUIC_DATAGRAM_SIZE_MAX_DEF;

    return ctx;
#if 0
out:
    QuicCtxFree(ctx);
    return NULL;
#endif
}

void QuicCtxFree(QUIC_CTX *ctx)
{
    QuicDataFree(&ctx->ext.alpn);
    QuicMemFree(ctx);
}

int QuicCtxCtrl(QUIC_CTX *ctx, uint32_t cmd, void *parg, long larg)
{
    switch (cmd) {
        case QUIC_CTRL_SET_GROUPS:
            return TlsSetSupportedGroups(&ctx->ext.supported_groups,
                    &ctx->ext.supported_groups_len,
                    parg, larg);
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

static int QUIC_set_hp_cipher_space_alg(QuicCipherSpace *space, uint32_t alg)
{
    return QUIC_set_hp_ciphers_alg(&space->ciphers, alg);
}

int QUIC_set_initial_hp_cipher(QUIC *quic, uint32_t alg)
{
    if (QUIC_set_hp_cipher_space_alg(&quic->initial.decrypt, alg) < 0) {
        return -1;
    }

    return QUIC_set_hp_cipher_space_alg(&quic->initial.encrypt, alg);
}

static int QUIC_set_pp_ciphers_alg(QUIC_CIPHERS *ciphers, uint32_t alg)
{
    return QUIC_set_cipher_alg(&ciphers->pp_cipher.cipher, alg);
}

static int QUIC_set_pp_cipher_space_alg(QuicCipherSpace *space, uint32_t alg)
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

QUIC *QuicNew(QUIC_CTX *ctx)
{
    QUIC *quic = NULL;

    quic = QuicMemCalloc(sizeof(*quic));
    if (quic == NULL) {
        return NULL;
    }

    quic->statem = QUIC_STATEM_READY;
    quic->stream_state = QUIC_STREAM_STATE_READY;
    quic->rwstate = QUIC_NOTHING; 
    //4 bytes packet number length
    quic->pkt_num_len = 3;
    quic->do_handshake = ctx->method->quic_handshake; 
    quic->method = ctx->method;
    quic->mtu = ctx->mtu;
    quic->version = ctx->method->version;
    quic->tls.ext.trans_param = ctx->ext.trans_param;
    if (QuicDataDup(&quic->tls.ext.alpn, &ctx->ext.alpn) < 0) {
        goto out;
    }

    quic->ctx = ctx;

    if (quic->method->tls_init(&quic->tls) < 0) {
        goto out;
    }

    if (QuicBufInit(&quic->rbuffer, QUIC_DATAGRAM_SIZE_MAX_DEF) < 0) {
        goto out;
    }

    if (QuicBufInit(&quic->plain_buffer, QUIC_DATAGRAM_SIZE_MAX_DEF) < 0) {
        goto out;
    }

    if (QuicBufInit(&quic->wbuffer, QUIC_DATAGRAM_SIZE_MAX_DEF) < 0) {
        goto out;
    }

    if (QUIC_set_initial_hp_cipher(quic, QUIC_ALG_AES_128_ECB) < 0) {
        goto out;
    }

    if (QUIC_set_initial_pp_cipher(quic, QUIC_ALG_AES_128_GCM) < 0) {
        goto out;
    }

    quic->initial.cipher_initialed = false;

    return quic;
out:

    QuicFree(quic);
    return NULL;
}

int QuicDoHandshake(QUIC *quic)
{
    if (quic->do_handshake == NULL) {
        QUIC_LOG("Handshake not set\n");
        return -1;
    }

    return quic->do_handshake(quic);
}

void QuicCryptoCipherFree(QuicCipherSpace *cs)
{
    QuicCipherCtxFree(&cs->ciphers);
}

void QuicCryptoFree(QuicCrypto *c)
{
    QuicCryptoCipherFree(&c->decrypt);
    QuicCryptoCipherFree(&c->encrypt);
}

void QuicFree(QUIC *quic)
{
    QuicDataFree(&quic->dcid);
    QuicDataFree(&quic->scid);

    BIO_free_all(quic->rbio);
    BIO_free_all(quic->wbio);

    QuicCipherCtxFree(&quic->zero_rtt.ciphers);
    QuicCipherCtxFree(&quic->handshake.client.ciphers);
    QuicCipherCtxFree(&quic->handshake.server.ciphers);

    QuicCryptoFree(&quic->initial);

    QuicBufFree(&quic->wbuffer);
    QuicBufFree(&quic->plain_buffer);
    QuicBufFree(&quic->rbuffer);

    QuicTlsFree(&quic->tls);

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
    ret = 0;

err:
    return ret;
}

