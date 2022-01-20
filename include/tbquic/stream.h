#ifndef TBQUIC_INCLUDE_TBQUIC_STREAM_H_
#define TBQUIC_INCLUDE_TBQUIC_STREAM_H_

#include <tbquic/types.h>

extern QUIC_STREAM_HANDLE QuicStreamCreate(QUIC *quic);
extern int QuicStreamSendEarlyData(QUIC_STREAM_HANDLE h, void *data,
                                    size_t len);
extern int QuicStreamRecv(QUIC *quic, void *data, size_t len);

#endif
