/*
 * Remy Lewis(remyknight1119@gmail.com)
 */
#include "buffer.h"

#include <assert.h>
#include <openssl/buffer.h>

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

    return (uint8_t *)qbuf->buf->data;
}

size_t QuicBufLength(QUIC_BUFFER *qbuf)
{
    assert(qbuf->buf != NULL);

    return qbuf->buf->length;
}

size_t QuicBufDataLength(QUIC_BUFFER *qbuf)
{
    assert(qbuf->buf != NULL);

    return qbuf->data_len;
}

void QuicBufClear(QUIC_BUFFER *qbuf)
{
    qbuf->data_len = 0;
}
