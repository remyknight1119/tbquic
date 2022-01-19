#ifndef TBQUIC_INCLUDE_TBQUIC_DISPENSER_H_
#define TBQUIC_INCLUDE_TBQUIC_DISPENSER_H_

#include <stdbool.h>
#include <stddef.h>
#include <tbquic/types.h>

extern QUIC_DISPENSER *QuicCreateDispenser(int fd);
extern QUIC *QuicDoDispense(QUIC_DISPENSER *dis,
                                QUIC_CTX *ctx, bool *new);
extern void QuicDestroyDispenser(QUIC_DISPENSER *dis);

#endif
