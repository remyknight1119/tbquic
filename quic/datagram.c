/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "datagram.h"

#include "quic_local.h"

int QuicReadBytes(QUIC *quic)
{
    QUIC_BUFFER *qbuf = NULL;
    int read_bytes = 0;

    if (quic->rbio == NULL) {
        return -1;
    }

    qbuf = &quic->rbuffer;
    read_bytes = BIO_read(quic->rbio, qbuf->buf->data, qbuf->buf->length);
    if (read_bytes >= 0) {
        qbuf->data_len = read_bytes;
    }

    return read_bytes;
}
