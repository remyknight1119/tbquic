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

    if (read_bytes < QUIC_INITIAL_PKT_DATAGRAM_SIZE_MIN) {
        QUIC_LOG("Read length(%d) smaller than (%d)\n", read_bytes,
                QUIC_INITIAL_PKT_DATAGRAM_SIZE_MIN);
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

int QuicDatagramSendBuffer(QUIC *quic, QUIC_BUFFER *qbuf)
{
    int write_bytes = 0;

    if (QuicBufGetDataLength(qbuf) == 0) {
        return 0;
    }

    quic->statem.rwstate = QUIC_NOTHING;
    if (quic->wbio == NULL) {
        return -1;
    }

    quic->statem.rwstate = QUIC_WRITING;
    write_bytes = BIO_write(quic->wbio, QuicBufData(qbuf),
            QuicBufGetDataLength(qbuf));
    if (write_bytes < 0 || write_bytes < QuicBufGetDataLength(qbuf)) {
        return -1;
    }

    quic->statem.rwstate = QUIC_FINISHED;
    QuicBufSetDataLength(qbuf, 0);
    return 0;
}

int QuicDatagramSend(QUIC *quic)
{
    return QuicDatagramSendBuffer(quic, QUIC_WRITE_BUFFER(quic));
}
