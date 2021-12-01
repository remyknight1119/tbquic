/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "base.h"

#include "mem.h"

int QuicDataIsEmpty(QUIC_DATA *data)
{
    return data->data == NULL;
}

int QuicDataDup(QUIC_DATA *dst, const QUIC_DATA *src)
{
    QuicMemFree(dst->data);

    if (src->data == NULL) {
        dst->data = NULL;
        goto out;
    }

    dst->data = QuicMemDup(src->data, src->len);
    if (dst->data == NULL) {
        return -1;
    }

out:
    dst->len = src->len;
    return 0;
}

void QuicDataSet(QUIC_DATA *dst, const uint8_t *data, size_t len)
{
    dst->data = (uint8_t *)data;
    dst->len = len;
}

void QuicDataGet(QUIC_DATA *src, const uint8_t **data, size_t *len)
{
    *data = src->data;
    *len = src->len;
}

int QuicDataCopy(QUIC_DATA *dst, const uint8_t *data, size_t len)
{
    QUIC_DATA src = {
        .data = (uint8_t *)data,
        .len = len,
    };

    return QuicDataDup(dst, &src);
}

void QuicDataFree(QUIC_DATA *data)
{
    QuicMemFree(data->data);
    data->data = NULL;
}

