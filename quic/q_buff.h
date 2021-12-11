#ifndef TBQUIC_Q_BUFF_H_
#define TBQUIC_Q_BUFF_H_

#include <stdint.h>
#include <tbquic/quic.h>
#include "list.h"

#define QBUF_LIST_FOR_EACH(qb, head) list_for_each_entry(qb, &(head)->queue, node)

typedef struct QBuff QBUFF;
typedef int (*QBuffPktBuilder)(QUIC *, QBUFF *);

typedef struct {
    struct list_head queue; 
} QBuffQueueHead;

struct QBuff {
    struct list_head node; 
    uint64_t pkt_num;
    QBuffPktBuilder build_pkt;
    void *buff;
    size_t buff_len;
    size_t data_len;
};

void QBuffQueueHeadInit(QBuffQueueHead *);
QBUFF *QBuffNew(size_t, QBuffPktBuilder);
void QBuffFree(QBUFF *);
void *QBuffHead(QBUFF *);
void *QBuffTail(QBUFF *);
size_t QBuffLen(QBUFF *);
size_t QBuffSpace(QBUFF *);
size_t QBuffGetDataLen(QBUFF *);
int QBuffSetDataLen(QBUFF *, size_t);
int QBuffAddDataLen(QBUFF *, size_t);
int QBuffBuildPkt(QUIC *, QBUFF *);
void QBuffQueueAdd(QBuffQueueHead *, QBUFF *);
void QBuffQueueDestroy(QBuffQueueHead *);

#endif
