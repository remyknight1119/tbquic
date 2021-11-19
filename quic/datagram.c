/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "datagram.h"

#include "quic_local.h"

int QuicDatagramRecv(QUIC *quic)
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

    return 0;
}

int QuicDatagramSend(QUIC *quic)
{
    QUIC_BUFFER *qbuf = NULL;
    int write_bytes = 0;

    if (quic->wbio == NULL) {
        return -1;
    }

    qbuf = &quic->wbuffer;
    write_bytes = BIO_write(quic->wbio, qbuf->buf->data, qbuf->data_len);
    if (write_bytes < 0 || write_bytes < qbuf->data_len) {
        return -1;
    }

    qbuf->data_len = 0;
    return 0;
}
