/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "datagram.h"

#include "quic_local.h"
#include "buffer.h"
#include "format.h"
#include "log.h"
#include "common.h"

int QuicDatagramRecvBuffer(QUIC *quic, QUIC_BUFFER *qbuf)
{
    int read_bytes = 0;

    quic->statem.rwstate = QUIC_NOTHING;
    if (quic->rbio == NULL) {
        return -1;
    }

    quic->statem.rwstate = QUIC_READING;
    read_bytes = BIO_read(quic->rbio, QuicBufData(qbuf), QuicBufLength(qbuf));
    if (read_bytes < 0) {
        return -1;
    }

    QuicBufSetDataLength(qbuf, read_bytes);
    quic->statem.rwstate = QUIC_FINISHED;

    return 0;
}

int QuicDatagramRecv(QUIC *quic)
{
    return QuicDatagramRecvBuffer(quic, QUIC_READ_BUFFER(quic));
}

int QuicDatagramSendBytes(QUIC *quic, uint8_t *data, size_t len)
{
    int write_bytes = 0;

    if (len == 0) {
        return 0;
    }

    if (quic->wbio == NULL) {
        return -1;
    }

    write_bytes = BIO_write(quic->wbio, data, len);
    if (write_bytes < 0 || write_bytes < len) {
        return -1;
    }

    return 0;
}

