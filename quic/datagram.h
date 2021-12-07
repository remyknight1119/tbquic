#ifndef TBQUIC_QUIC_DATAGRAM_H_
#define TBQUIC_QUIC_DATAGRAM_H_

#include <tbquic/types.h>

int QuicDatagramRecvBuffer(QUIC *, QUIC_BUFFER *);
int QuicDatagramSendBuffer(QUIC *, QUIC_BUFFER *);
int QuicDatagramRecv(QUIC *);
int QuicDatagramSend(QUIC *);

#endif
