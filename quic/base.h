#ifndef TBQUIC_QUIC_BASE_H_
#define TBQUIC_QUIC_BASE_H_

#include <stdint.h>
#include <sys/types.h>

typedef struct {
    uint8_t *data;
    size_t len;
} QUIC_DATA;

int QuicDataIsEmpty(QUIC_DATA *);
void QuicDataSet(QUIC_DATA *, const uint8_t *, size_t);
void QuicDataGet(QUIC_DATA *, const uint8_t **, size_t *);
int QuicDataDup(QUIC_DATA *, const QUIC_DATA *);
int QuicDataCopy(QUIC_DATA *, const uint8_t *, size_t);
void QuicDataFree(QUIC_DATA *);

#endif
