#ifndef TBQUIC_SRC_BUFFER_H_
#define TBQUIC_SRC_BUFFER_H_

#include <stddef.h>

typedef struct BufMem {
    unsigned char *data;
    size_t length;
    size_t max;
} QuicBufMem;

#define GET_BUF_DATA(buf)   buf->data

QuicBufMem *QuicBufNew(void);
void QuicBufFree(QuicBufMem *buf);

#endif
