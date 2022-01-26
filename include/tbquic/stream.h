#ifndef TBQUIC_INCLUDE_TBQUIC_STREAM_H_
#define TBQUIC_INCLUDE_TBQUIC_STREAM_H_

#include <tbquic/types.h>

#define QUIC_STREAM_DATA_FLAGS_FIN      0x01
#define QUIC_STREAM_DATA_FLAGS_RESET    0x02

extern QUIC_STREAM_HANDLE QuicStreamOpen(QUIC *quic, bool uni);
extern int QuicStreamSendEarlyData(QUIC *quic, QUIC_STREAM_HANDLE *h, bool uni,
                                    void *data, size_t len);
extern int QuicStreamSend(QUIC *quic, QUIC_STREAM_HANDLE h,
                                void *data, size_t len);
extern int QuicStreamRecv(QUIC *quic, void *data, size_t len);

#endif
