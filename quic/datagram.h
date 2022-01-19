#ifndef TBQUIC_QUIC_DATAGRAM_H_
#define TBQUIC_QUIC_DATAGRAM_H_

#include <stdint.h>
#include <stddef.h>
#include <tbquic/types.h>

#include "address.h"

int QuicDatagramSendBytes(QUIC *, uint8_t *, size_t);
int QuicDatagramRecvBuffer(QUIC *, QUIC_BUFFER *);
int QuicDatagramRecvfrom(int, void *, size_t, int, Address *);
int QuicDatagramSendto(int, void *, size_t, int, Address *);


#endif
