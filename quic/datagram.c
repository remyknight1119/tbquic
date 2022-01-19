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

int QuicDatagramSendEarlyData(QUIC *quic, void *data, size_t len)
{
    TlsState handshake_state;
    int ret = 0;

    ret = QuicDoHandshake(quic);
    QUIC_LOG("ret = %d\n", ret);
    handshake_state = quic->tls.handshake_state; 
    if (handshake_state == TLS_ST_SR_FINISHED ||
            handshake_state == TLS_ST_HANDSHAKE_DONE) {
            QUIC_LOG("Build Stream frame\n");
        if (QuicStreamFrameBuild(quic, data, len) < 0) {
            QUIC_LOG("Build Stream frame failed\n");
            return -1;
        }

        if (QuicSendPacket(quic) < 0) {
            return -1;
        }

        return len;
    }

    return ret;
}

int QuicDatagramRecv(QUIC *quic, void *data, size_t len)
{
    RPacket pkt = {};
    QuicPacketFlags flags;
    QuicFlowReturn ret = QUIC_FLOW_RET_ERROR;
    uint32_t flag = 0;
    int rlen = 0;

    rlen = quic->method->read_bytes(quic, &pkt);
    if (rlen < 0) {
        return -1;
    }

    while (RPacketRemaining(&pkt)) {
        if (RPacketGet1(&pkt, &flag) < 0) {
            return -1;
        }

        flags.value = flag;
        ret = QuicPacketRead(quic, &pkt, flags);
        if (ret == QUIC_FLOW_RET_ERROR) {
            return -1;
        }

        RPacketUpdate(&pkt);
    }

    return 0;
}

