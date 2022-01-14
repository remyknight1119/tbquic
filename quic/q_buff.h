#ifndef TBQUIC_Q_BUFF_H_
#define TBQUIC_Q_BUFF_H_

#include <stdint.h>
#include <stdbool.h>
#include <tbquic/quic.h>
#include "list.h"
#include "packet_local.h"

#define QBUF_LIST_FOR_EACH(qb, next, head) \
    list_for_each_entry_send(qb, next, &(head)->queue, node)

#define QBUF_LAST_NODE(head) \
    ({ \
        QBUFF *pos = NULL; \
        pos = list_last_entry(&(head)->queue, typeof(*pos), node); \
        pos; \
     })

typedef struct QBuff QBUFF;
typedef int (*QBuffPktBuilder)(QUIC *, WPacket *, QBUFF *, bool);
typedef size_t (*QBuffPktGetTotalLen)(QUIC *, size_t);

typedef struct {
    QBuffPktBuilder build_pkt;
    QBuffPktGetTotalLen compute_totallen;
    QUIC_CRYPTO *(*get_crypto)(QUIC *);
} QBuffPktMethod;

typedef struct {
    struct list_head queue; 
} QBuffQueueHead;

struct QBuff {
    struct list_head node; 
    uint64_t pkt_num;
    const QBuffPktMethod *method;
    void *buff;
    size_t buff_len;
    size_t data_len;
};

void QBuffQueueHeadInit(QBuffQueueHead *);
QBUFF *QBuffNew(uint32_t, size_t);
void QBuffFree(QBUFF *);
void *QBuffHead(QBUFF *);
void *QBuffTail(QBUFF *);
size_t QBuffLen(QBUFF *);
size_t QBuffSpace(QBUFF *);
size_t QBuffGetDataLen(QBUFF *);
QUIC_CRYPTO *QBuffCrypto(QUIC *, QBUFF *);
int QBuffSetDataLen(QBUFF *, size_t);
int QBuffAddDataLen(QBUFF *, size_t);
int QBuffBuildPkt(QUIC *, WPacket *, QBUFF *, bool);
size_t QBufPktComputeTotalLenByType(QUIC *, uint32_t, size_t);
size_t QBufPktComputeTotalLen(QUIC *, QBUFF *);
void QBuffQueueAdd(QBuffQueueHead *, QBUFF *);
void QBuffQueueDestroy(QBuffQueueHead *);

#endif
