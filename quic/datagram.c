/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "datagram.h"

#include <tbquic/quic.h>

#include "quic_local.h"
#include "buffer.h"
#include "format.h"
#include "address.h"
#include "common.h"
#include "log.h"

int QuicDatagramRecv(QUIC *quic, uint8_t *buf, size_t len)
{
    int read_bytes = 0;

    quic->statem.rwstate = QUIC_NOTHING;
    if (quic->rbio == NULL) {
        return -1;
    }

    quic->statem.rwstate = QUIC_READING;
    read_bytes = BIO_read(quic->rbio, buf, len);
    if (read_bytes < 0) {
        return -1;
    }

    quic->statem.rwstate = QUIC_FINISHED;

    return read_bytes;
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

int
QuicDatagramRecvfrom(int fd, void *buf, size_t len, int flags, Address *addr)
{
    return recvfrom(fd, buf, len, flags, &addr->addr.in, &addr->addrlen);
}

int QuicDatagramSendto(int fd, void *buf, size_t len, int flags, Address *addr)
{
    return sendto(fd, buf, len, flags, &addr->addr.in, addr->addrlen);
}


