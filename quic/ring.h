#ifndef TBQUIC_QUIC_RING_H_
#define TBQUIC_QUIC_RING_H_

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint8_t *head;
    uint8_t *tail;
    uint8_t *buf;
    size_t buf_len;
} Ring;

#endif
