#ifndef TBQUIC_QUIC_TIMER_H_
#define TBQUIC_QUIC_TIMER_H_

#include "list.h"

typedef struct {
    struct list_head node;
    uint64_t expire;
    void *arg;
    void (*action)(void *);
} Timer;


#endif
