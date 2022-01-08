/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "base.h"

#include "mem.h"

int QuicDataIsEmpty(const QUIC_DATA *data)
{
    return data->data == NULL || data->len == 0;
}

static int QuicDataDupBytes(QUIC_DATA *dst, const QUIC_DATA *src, size_t byte_len)
{
    QuicMemFree(dst->data);

    if (src->data == NULL) {
        dst->data = NULL;
        goto out;
    }

    dst->data = QuicMemDup(src->data, src->len * byte_len);
    if (dst->data == NULL) {
        return -1;
    }

out:
    dst->len = src->len;
    return 0;
}

int QuicDataDup(QUIC_DATA *dst, const QUIC_DATA *src)
{
    return QuicDataDupBytes(dst, src, 1);
}

int QuicDataDupU16(QUIC_DATA *dst, const QUIC_DATA *src)
{
    return QuicDataDupBytes(dst, src, 2);
}

void QuicDataSet(QUIC_DATA *dst, const void *data, size_t len)
{
    dst->data = (void *)data;
    dst->len = len;
}

void QuicDataGet(const QUIC_DATA *src, const void **data, size_t *len)
{
    *data = src->data;
    *len = src->len;
}

void QuicDataGetU16(const QUIC_DATA *src, const uint16_t **data, size_t *len)
{
    *data = src->ptr_u16;
    *len = src->len;
}

static int QuicDataCopyBytes(QUIC_DATA *dst, const uint8_t *data, size_t len,
                        size_t byte_len)
{
    QUIC_DATA src = {
        .data = (void *)data,
        .len = len,
    };

    return QuicDataDupBytes(dst, &src, byte_len);
}

int QuicDataCopy(QUIC_DATA *dst, const uint8_t *data, size_t len)
{
    return QuicDataCopyBytes(dst, data, len, 1);
}

int QuicDataCopyU16(QUIC_DATA *dst, const uint8_t *data, size_t len)
{
    return QuicDataCopyBytes(dst, data, len, 2);
}

void QuicDataFree(QUIC_DATA *data)
{
    QuicMemFree(data->data);
    data->data = NULL;
    data->len = 0;
}

