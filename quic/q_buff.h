#ifndef TBQUIC_Q_BUFF_H_
#define TBQUIC_Q_BUFF_H_

#include <stdint.h>
#include "list.h"

typedef struct {
    struct list_head queue; 
} QBuffHead;

typedef struct {
    struct list_head node; 
    uint64_t pkt_num;
    void *buff;
    size_t len;
} QBuff;

void QBuffHeadInit(QBuffHead *);
QBuff *QBufNew(size_t len);
void QBufFree(QBuff *);
void QBuffQueueDestroy(QBuffHead *);

#endif
