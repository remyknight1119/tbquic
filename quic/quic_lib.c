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


QUIC_CTX *QuicCtxNew(const QUIC_METHOD *meth)
{
    QUIC_CTX *ctx = NULL;

    ctx = QuicMemCalloc(sizeof(*ctx));
    if (ctx == NULL) {
        return NULL;
    }

    ctx->method = meth;
	ctx->tls_ctx = SSL_CTX_new(TLS_server_method());
	if (ctx->tls_ctx == NULL) {
        goto out;
    }

    SSL_CTX_set_min_proto_version(ctx->tls_ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx->tls_ctx, TLS1_3_VERSION);

    return ctx;
out:
    QuicCtxFree(ctx);
    return NULL;
}

void QuicCtxFree(QUIC_CTX *ctx)
{
    SSL_CTX_free(ctx->tls_ctx);
    QuicMemFree(ctx);
}

static int QUIC_set_cipher_alg(QUIC_CIPHER *cipher, uint32_t alg)
{
    if (alg >= QUIC_ALG_MAX) {
        return -1;
    }

    cipher->cipher_alg = alg;
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
    if (QUIC_set_hp_cipher_space_alg(&quic->initial.client, alg) < 0) {
        return -1;
    }

    return QUIC_set_hp_cipher_space_alg(&quic->initial.server, alg);
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
    if (QUIC_set_pp_cipher_space_alg(&quic->initial.client, alg) < 0) {
        return -1;
    }

    return QUIC_set_pp_cipher_space_alg(&quic->initial.server, alg);
}


QUIC *QuicNew(QUIC_CTX *ctx)
{
    QUIC *quic = NULL;

    quic = QuicMemCalloc(sizeof(*quic));
    if (quic == NULL) {
        return NULL;
    }

    quic->tls = SSL_new(ctx->tls_ctx);
    if (quic->tls == NULL) {
        goto out;
    }

    quic->tls_rbio = BIO_new(BIO_s_mem());
    if (quic->tls_rbio == NULL) {
        goto out;
    }

    quic->tls_wbio = BIO_new(BIO_s_mem());
    if (quic->tls_wbio == NULL) {
        goto out;
    }

    SSL_set_bio(quic->tls, quic->tls_rbio, quic->tls_wbio);
    BIO_up_ref(quic->tls_rbio);
    BIO_up_ref(quic->tls_wbio);

    if (QuicBufInit(&quic->rbuffer, QUIC_DATAGRAM_SIZE_MAX_DEF) < 0) {
        goto out;
    }

    if (QuicBufInit(&quic->plain_buffer, QUIC_DATAGRAM_SIZE_MAX_DEF) < 0) {
        goto out;
    }

    if (QuicBufInit(&quic->wbuffer, QUIC_DATAGRAM_SIZE_MAX_DEF) < 0) {
        goto out;
    }

    if (QuicBufInit(&quic->crypto_fbuffer, QUIC_DATAGRAM_SIZE_MAX_DEF) < 0) {
        goto out;
    }

    quic->state = QUIC_STREAM_STATE_READY;
    quic->do_handshake = ctx->method->handshake; 
    quic->method = ctx->method;
    quic->ctx = ctx;
    if (QUIC_set_initial_hp_cipher(quic, QUIC_ALG_AES_128_ECB) < 0) {
        goto out;
    }

    if (QUIC_set_initial_pp_cipher(quic, QUIC_ALG_AES_128_GCM) < 0) {
        goto out;
    }

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

void QuicFree(QUIC *quic)
{
    SSL_free(quic->tls);

    BIO_free_all(quic->tls_rbio);
    BIO_free_all(quic->tls_wbio);
    BIO_free_all(quic->rbio);
    BIO_free_all(quic->wbio);

    QuicBufFree(&quic->crypto_fbuffer);
    QuicBufFree(&quic->wbuffer);
    QuicBufFree(&quic->plain_buffer);
    QuicBufFree(&quic->rbuffer);

    QuicMemFree(quic->peer_dcid.data);

    QuicCipherCtxFree(&quic->initial.client.ciphers);
    QuicCipherCtxFree(&quic->initial.server.ciphers);
    QuicCipherCtxFree(&quic->zero_rtt.ciphers);
    QuicCipherCtxFree(&quic->handshake.client.ciphers);
    QuicCipherCtxFree(&quic->handshake.server.ciphers);

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

