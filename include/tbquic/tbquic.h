#ifndef TBQUIC_INCLUDE_TBQUIC_TBQUIC_H_
#define TBQUIC_INCLUDE_TBQUIC_TBQUIC_H_

#include <tbquic/types.h>

extern int QuicInit(void);
extern QUIC *QuicNew(void);
extern void QuicFree(QUIC *quic);

#endif
