#ifndef TBQUIC_QUIC_BUFFER_H_
#define TBQUIC_QUIC_BUFFER_H_

#include <openssl/buffer.h>
#include <tbquic/types.h>

struct QuicBuffer {
    BUF_MEM *buf;
    size_t data_len;
};

int QuicBufInit(QUIC_BUFFER *, size_t);
void QuicBufFree(QUIC_BUFFER *);
void QuicBufClear(QUIC_BUFFER *);
size_t QuicBufMemGrow(QUIC_BUFFER *, size_t);
uint8_t *QuicBufData(QUIC_BUFFER *);
uint8_t *QuicBufTail(QUIC_BUFFER *);
size_t QuicBufLength(QUIC_BUFFER *);
size_t QuicBufGetDataLength(QUIC_BUFFER *);
size_t QuicBufRemaining(QUIC_BUFFER *);
void QuicBufSetDataLength(QUIC_BUFFER *, size_t);
void QuicBufAddDataLength(QUIC_BUFFER *, size_t);

#endif
