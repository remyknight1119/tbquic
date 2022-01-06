/*
 * Remy Lewis(remyknight1119@gmail.com)
 */
#include "buffer.h"

#include <assert.h>
#include <openssl/buffer.h>

#include "common.h"
#include "mem.h"
#include "log.h"

static __thread QUIC_BUFFER QuicPlainTextBuffer;

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

    QuicMemset(qbuf, 0, sizeof(*qbuf));
    qbuf->buf = buf;

    return 0;
out:

    BUF_MEM_free(buf);
    return -1;
}

void QuicBufFree(QUIC_BUFFER *qbuf)
{
    BUF_MEM_free(qbuf->buf);
}

QUIC_BUFFER *QuicGetPlainTextBuffer(void)
{
    return &QuicPlainTextBuffer;
}

int QuicInitPlainTextBuffer(void)
{
    return QuicBufInit(&QuicPlainTextBuffer, QUIC_BUF_MAX_LEN);
}

void QuicFreePlainTextBuffer(void)
{
    QuicBufFree(&QuicPlainTextBuffer);
}

size_t QuicBufMemGrow(QUIC_BUFFER *qbuf, size_t len)
{
    return BUF_MEM_grow(qbuf->buf, len);
}

uint8_t *QuicBufData(QUIC_BUFFER *qbuf)
{
    assert(qbuf->buf != NULL);

    return (uint8_t *)(&qbuf->buf->data[qbuf->reserved]);
}

uint8_t *QuicBufMsg(QUIC_BUFFER *qbuf)
{
    return QuicBufData(qbuf) + qbuf->offset;
}

uint8_t *QuicBufHead(QUIC_BUFFER *qbuf)
{
    assert(qbuf->buf != NULL);

    return (uint8_t *)qbuf->buf->data;
}

uint8_t *QuicBufTail(QUIC_BUFFER *qbuf)
{
    return QuicBufData(qbuf) + qbuf->data_len;
}

size_t QuicBufLength(QUIC_BUFFER *qbuf)
{
    assert(qbuf->buf != NULL);

    return qbuf->buf->length;
}

size_t QuicBufGetOffset(QUIC_BUFFER *qbuf)
{
    return qbuf->offset;
}

int QuicBufAddOffset(QUIC_BUFFER *qbuf, size_t offset)
{
    size_t total = qbuf->offset + offset;

    if (QUIC_LT(QuicBufLength(qbuf), total)) {
        return -1;
    }

    qbuf->offset = total;
    return 0;
}

void QuicBufResetOffset(QUIC_BUFFER *qbuf)
{
    qbuf->offset = 0;
}

size_t QuicBufRemaining(QUIC_BUFFER *qbuf)
{
    size_t total_len = qbuf->reserved + qbuf->data_len;

    assert(qbuf->buf != NULL && QUIC_GE(qbuf->buf->length, total_len));

    return qbuf->buf->length - total_len;
}

size_t QuicBufGetDataLength(QUIC_BUFFER *qbuf)
{
    return qbuf->data_len;
}

void QuicBufSetDataLength(QUIC_BUFFER *qbuf, size_t len)
{
    qbuf->data_len = len;
}

void QuicBufAddDataLength(QUIC_BUFFER *qbuf, size_t len)
{
    qbuf->data_len += len;
}

void QuicBufResetDataLength(QUIC_BUFFER *qbuf)
{
    qbuf->data_len = 0;
}

void QuicBufReserve(QUIC_BUFFER *qbuf)
{
    qbuf->reserved = qbuf->data_len;
    qbuf->data_len = 0;
}

size_t QuicBufGetReserved(QUIC_BUFFER *qbuf)
{
    return qbuf->reserved;
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
    qbuf->reserved = 0;
    qbuf->data_len = 0;
}
