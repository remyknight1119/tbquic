#ifndef TBQUIC_QUIC_DISPENSER_H_
#define TBQUIC_QUIC_DISPENSER_H_

#include <tbquic/dispenser.h>
#include "list.h"
#include "address.h"
#include "buffer.h"
#include "packet_local.h"

struct QuicDispenser {
    int sock_fd;
    bool read;
    QuicStaticBuffer buf;
    struct list_head head; 
    Address dest;
};

int QuicDispenserReadBytes(QUIC *, RPacket *);
int QuicDispenserWriteBytes(QUIC *, uint8_t *, size_t);

#endif
