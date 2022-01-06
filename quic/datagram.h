#ifndef TBQUIC_QUIC_DATAGRAM_H_
#define TBQUIC_QUIC_DATAGRAM_H_

#include <stdint.h>
#include <stddef.h>
#include <tbquic/types.h>

int QuicDatagramSendBytes(QUIC *, uint8_t *, size_t);
int QuicDatagramRecvBuffer(QUIC *, QUIC_BUFFER *);
int QuicDatagramRecv(QUIC *);

#endif
