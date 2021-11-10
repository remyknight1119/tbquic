/*
 * Remy Lewis(remyknight1119@gmail.com)
 */
#include "quic_local.h"

#include <tbquic/quic.h>

#include "statem.h"
#include "mem.h"
#include "log.h"

QUIC_CTX *QuicCtxNew(const QUIC_METHOD *meth)
{
    QUIC_CTX *ctx = NULL;

    ctx = QuicMemCalloc(sizeof(*ctx));
    if (ctx == NULL) {
        return NULL;
    }

    ctx->method = meth;

    return ctx;
}

void QuicCtxFree(QUIC_CTX *ctx)
{
    QuicMemFree(ctx);
}

static int QuicBufInit(QUIC_BUFFER *qbuf, size_t len)
{
    BUF_MEM *buf = NULL;

    buf = BUF_MEM_new();
    if (buf == NULL) {
        return -1;
    }

    if (!BUF_MEM_grow(buf, len)) {
        goto out;
    }

    qbuf->buf = buf;

    return 0;
out:

    BUF_MEM_free(buf);
    return -1;
}

static void QuicBufFree(QUIC_BUFFER *qbuf)
{
    BUF_MEM_free(qbuf->buf);
}

QUIC *QuicNew(QUIC_CTX *ctx)
{
    QUIC *quic = NULL;

    quic = QuicMemCalloc(sizeof(*quic));
    if (quic == NULL) {
        return NULL;
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

    quic->state = QUIC_STREAM_STATE_READY;
    quic->handshake = ctx->method->handshake; 
    quic->method = ctx->method;
    quic->ctx = ctx;

    return quic;
out:

    QuicFree(quic);
    return NULL;
}

int QuicDoHandshake(QUIC *quic)
{
    if (quic->handshake == NULL) {
        QUIC_LOG("Handshake not set\n");
        return -1;
    }

    return quic->handshake(quic);
}

void QuicFree(QUIC *quic)
{
    BIO_free_all(quic->rbio);
    BIO_free_all(quic->wbio);

    QuicBufFree(&quic->wbuffer);
    QuicBufFree(&quic->plain_buffer);
    QuicBufFree(&quic->rbuffer);

    QuicMemFree(quic->peer_dcid.data);
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

