#ifndef TBQUIC_QUIC_BASE_H_
#define TBQUIC_QUIC_BASE_H_

#include <stdint.h>
#include <sys/types.h>

#include "packet_local.h"

typedef struct {
    union {
        void *data;
        uint8_t *ptr_u8;
        uint16_t *ptr_u16;
    };
    size_t len;
} QUIC_DATA;

typedef struct {
    uint32_t ref;
    size_t data_len;
    QUIC_DATA buf;
} QUIC_DATA_BUF;

typedef struct {
    uint64_t sent;
    uint64_t recvd;
} QuicDataStat;

int QuicDataIsEmpty(const QUIC_DATA *);
void QuicDataSet(QUIC_DATA *, const void *, size_t);
void QuicDataGet(const QUIC_DATA *, const void **, size_t *);
void QuicDataGetU16(const QUIC_DATA *, const uint16_t **, size_t *);
int QuicDataDup(QUIC_DATA *, const QUIC_DATA *);
int QuicDataDupU16(QUIC_DATA *, const QUIC_DATA *);
int QuicDataCopy(QUIC_DATA *, const uint8_t *, size_t);
QUIC_DATA *QuicDataCreate(size_t);
void QuicDataFree(QUIC_DATA *);
void QuicDataDestroy(QUIC_DATA *);
int QuicDataParse(QUIC_DATA *, RPacket *, size_t);
QUIC_DATA_BUF *QuicDataBufCreate(size_t);
void QuicDataBufGet(QUIC_DATA_BUF *);
void QuicDataBufFree(QUIC_DATA_BUF *);

#endif
