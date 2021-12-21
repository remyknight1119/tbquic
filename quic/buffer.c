/*
 * Remy Lewis(remyknight1119@gmail.com)
 */
#include "buffer.h"

#include <assert.h>
#include <openssl/buffer.h>

#include "common.h"
#include "mem.h"
#include "log.h"

int QuicBufInit(QUIC_BUFFER *qbuf, size_t len)
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
    qbuf->offset = 0;
    qbuf->data_len = 0;

    return 0;
out:

    BUF_MEM_free(buf);
    return -1;
}

void QuicBufFree(QUIC_BUFFER *qbuf)
{
    BUF_MEM_free(qbuf->buf);
}

size_t QuicBufMemGrow(QUIC_BUFFER *qbuf, size_t len)
{
    return BUF_MEM_grow(qbuf->buf, len);
}

uint8_t *QuicBufData(QUIC_BUFFER *qbuf)
{
    assert(qbuf->buf != NULL);

    return (uint8_t *)(&qbuf->buf->data[qbuf->offset]);
}

uint8_t *QuicBufHead(QUIC_BUFFER *qbuf)
{
    assert(qbuf->buf != NULL);

    return (uint8_t *)qbuf->buf->data;
}

uint8_t *QuicBufTail(QUIC_BUFFER *qbuf)
{
    assert(qbuf->buf != NULL);

    return QuicBufData(qbuf) + qbuf->data_len;
}

size_t QuicBufLength(QUIC_BUFFER *qbuf)
{
    assert(qbuf->buf != NULL);

    return qbuf->buf->length;
}

size_t QuicBufRemaining(QUIC_BUFFER *qbuf)
{
    size_t total_len = qbuf->offset + qbuf->data_len;

    assert(qbuf->buf != NULL && QUIC_GE(qbuf->buf->length, total_len));

    return qbuf->buf->length - total_len;
}

size_t QuicBufOffset(QUIC_BUFFER *qbuf)
{
    assert(qbuf->buf != NULL);

    return qbuf->offset;
}

size_t QuicBufGetDataLength(QUIC_BUFFER *qbuf)
{
    assert(qbuf->buf != NULL);

    return qbuf->data_len;
}

void QuicBufSetDataLength(QUIC_BUFFER *qbuf, size_t len)
{
    assert(qbuf->buf != NULL);

    qbuf->data_len = len;
}

void QuicBufAddDataLength(QUIC_BUFFER *qbuf, size_t len)
{
    assert(qbuf->buf != NULL);

    qbuf->data_len += len;
}

void QuicBufReserve(QUIC_BUFFER *qbuf)
{
    qbuf->offset = qbuf->data_len;
    qbuf->data_len = 0;
}

int QuicBufCopyData(QUIC_BUFFER *qbuf, const uint8_t *data, size_t len)
{
    assert(qbuf->buf != NULL);

    if (QUIC_LT(QuicBufRemaining(qbuf), len)) {
        return -1;
    }

    QuicMemcpy(QuicBufData(qbuf), data, len);
    QuicBufSetDataLength(qbuf, len);
    return 0;
}

void QuicBufClear(QUIC_BUFFER *qbuf)
{
    qbuf->offset = 0;
    qbuf->data_len = 0;
}
