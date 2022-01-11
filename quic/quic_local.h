#ifndef TBQUIC_QUIC_QUIC_LOCAL_H_
#define TBQUIC_QUIC_QUIC_LOCAL_H_

#include <stdint.h>
#include <stdbool.h>

#include <openssl/bio.h>
#include <tbquic/quic.h>

#include "base.h"
#include "statem.h"
#include "stream.h"
#include "cipher.h"
#include "buffer.h"
#include "tls.h"
#include "cert.h"
#include "q_buff.h"

#define QUIC_VERSION_1      0x01

#define QUIC_BUFFER_HEAD(buffer) (uint8_t *)((buffer)->buf->data)
#define QUIC_R_BUFFER_HEAD(quic) QUIC_BUFFER_HEAD(&quic->rbuffer)

#define QUIC_READ_BUFFER(quic) (&quic->rbuffer)
#define QUIC_TLS_BUFFER(quic) (&quic->tls.buffer)

#define QUIC_IS_SERVER(q) (q->quic_server)
#define QUIC_IS_READING(q) QUIC_STATEM_READING(q->rwstate)
#define QUIC_IS_WRITNG(q) QUIC_STATEM_WRITNG(q->rwstate)

#define QUIC_GET_FLOW_STATE(q) ((q)->statem.flow_state)
#define QUIC_SET_FLOW_STATE(q, v) \
    do { \
        (q)->statem.flow_state = v; \
    } while (0)

struct QuicMethod {
    uint32_t version;
    int (*quic_connect)(QUIC *);
    int (*quic_accept)(QUIC *);
    const TlsMethod *tls_method;
};

struct QuicCtx {
    const QUIC_METHOD *method;
    /* Max Segment Size */
    uint32_t mss;
    uint32_t verify_mode;
    QuicCert *cert;
    struct {
        QUIC_DATA alpn;
        QuicTransParams trans_param;
        QUIC_DATA supported_groups;
    } ext;
};

typedef struct {
    QUIC_CIPHERS ciphers;
    uint64_t pkt_num;
    uint64_t pkt_acked;
    bool cipher_inited;
} QuicCipherSpace;

typedef struct {
    QuicCipherSpace decrypt;
    QuicCipherSpace encrypt;
} QuicCrypto;

typedef struct {
    QuicStatem state;
    QuicReadState read_state;
    QuicReadWriteState rwstate;
    QuicFlowState flow_state; 
} QUIC_STATEM;

struct Quic {
    /* This member must be first */
    TLS tls;
#define quic_server tls.server
    QuicStreamState stream_state;
    QUIC_STATEM statem;
    uint32_t version;
    uint32_t mss;
    uint32_t verify_mode;
    uint64_t pkt_num_len:2;
    uint64_t cid_len:8;
    uint64_t fd_mode:1;
    const QUIC_CTX *ctx;
    const QUIC_METHOD *method;
    BIO *rbio;
    BIO *wbio;
    int (*do_handshake)(QUIC *);
    /* Read Buffer */
    QUIC_BUFFER rbuffer;
    QUIC_DATA dcid;
    QUIC_DATA scid;
    QUIC_DATA token;
    QuicCrypto initial;
    QuicCrypto handshake;
    QuicCrypto zero_rtt;
    QuicCrypto one_rtt;
    QBUFF *send_head;
    QBuffQueueHead tx_queue;
};

static inline QUIC *QuicTlsTrans(TLS *s)
{
    return (QUIC *)s;
}

int QUIC_set_handshake_hp_cipher(QUIC *, uint32_t);
int QUIC_set_pp_cipher_space_alg(QuicCipherSpace *, uint32_t);
int QUIC_set_hp_cipher(QuicCrypto *, uint32_t);
int QUIC_set_hp_cipher_space_alg(QuicCipherSpace *, uint32_t);

#endif
