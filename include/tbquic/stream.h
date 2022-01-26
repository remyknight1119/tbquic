#ifndef TBQUIC_INCLUDE_TBQUIC_STREAM_H_
#define TBQUIC_INCLUDE_TBQUIC_STREAM_H_

#include <stdbool.h>
#include <tbquic/types.h>

#define QUIC_STREAM_DATA_FLAGS_FIN      0x01
#define QUIC_STREAM_DATA_FLAGS_RESET    0x02

struct QuicStreamIovec {            /* Scatter/gather array items */
    QUIC_STREAM_HANDLE handle;      /* Stream handle */
    uint32_t flags;                 /* Stream flags */
    void  *iov_base;                /* Starting address */
    size_t iov_len;                 /* Length of iov_base buffer */
    size_t data_len;                 /* Length of data in iov_base */
};

extern QUIC_STREAM_HANDLE QuicStreamOpen(QUIC *quic, bool uni);
extern int QuicStreamSendEarlyData(QUIC *quic, QUIC_STREAM_HANDLE *h, bool uni,
                                    void *data, size_t len);
extern int QuicStreamSend(QUIC *quic, QUIC_STREAM_HANDLE h,
                                void *data, size_t len);
extern int QuicStreamRecv(QUIC *quic, QUIC_STREAM_HANDLE h, uint32_t *flags,
                            void *data, size_t len);
extern int QuicStreamReadV(QUIC *quic, QUIC_STREAM_IOVEC *iov, size_t iovcnt);

#endif
