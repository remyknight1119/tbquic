#ifndef TBQUIC_QUIC_QUIC_LOCAL_H_
#define TBQUIC_QUIC_QUIC_LOCAL_H_

#include <stdint.h>
#include <stdbool.h>

#include <openssl/bio.h>
#include <openssl/lhash.h>
#include <tbquic/quic.h>

#include "base.h"
#include "statem.h"
#include "stream.h"
#include "cipher.h"
#include "buffer.h"
#include "tls.h"
#include "cert.h"
#include "list.h"
#include "q_buff.h"
#include "address.h"
#include "packet_local.h"
#include "connection.h"
#include "timer.h"

#define QUIC_VERSION_1      0x01

#define QUIC_BUFFER_HEAD(buffer) (uint8_t *)((buffer)->buf->data)

#define QUIC_TLS_BUFFER(quic) (&quic->tls.buffer)

#define QUIC_IS_SERVER(q) (q->quic_server)
#define QUIC_IS_READING(q) QUIC_STATEM_READING(q->rwstate)
#define QUIC_IS_WRITNG(q) QUIC_STATEM_WRITNG(q->rwstate)
#define QUIC_STATE_GET(q) q->statem.state
#define QUIC_TLS_STATE_SET(s, st) \
    do { \
        QUIC *q = QuicTlsTrans(s); \
        q->statem.state = st; \
    } while (0)

#define QUIC_NEW_TOKEN_LEN  60

struct QuicMethod {
    uint32_t version;
    bool alloc_rbuf;
    int (*quic_connect)(QUIC *);
    int (*quic_accept)(QUIC *);
    int (*parse_dcid)(QUIC *, RPacket *, size_t);
    int (*parse_scid)(QUIC *, RPacket *, size_t);
    int (*read_bytes)(QUIC *, RPacket *);
    int (*write_bytes)(QUIC *, uint8_t *, size_t);
};

struct QuicCtx {
    const QUIC_METHOD *method;
    uint64_t options;
    /* Max Segment Size */
    uint32_t mss;
    uint32_t verify_mode;
    uint32_t max_early_data;
    uint8_t cid_len;
    QuicCert *cert;
    X509_VERIFY_PARAM *param;
    X509_STORE *cert_store;
    X509_STORE *chain_store;
    X509_STORE *verify_store;
    STACK_OF(X509_NAME) *ca_names;
    STACK_OF(X509_NAME) *client_ca_names;
    QUIC_CTX_verify_callback_func verify_callback;
    QUIC_CTX_keylog_cb_func keylog_callback;
    struct {
        QUIC_DATA alpn;
        QuicTransParams trans_param;
        QUIC_DATA supported_groups;
        TlsTicketKey ticket_key;
    } ext;
};

typedef struct {
    QUIC_CIPHERS ciphers;
    bool cipher_inited;
} QuicCipherSpace;

struct QuicCrypto {
    uint64_t pkt_num;
    uint64_t min_pkt_num;
    uint64_t largest_pn;
    uint64_t largest_acked;
    uint64_t largest_ack;
    uint64_t arriv_time;
    uint64_t first_ack_range;
    QBuffQueueHead sent_queue; 
    QuicCipherSpace decrypt;
    QuicCipherSpace encrypt;
};

typedef struct {
    QuicStatem state;
    QuicReadWriteState rwstate;
} QUIC_STATEM;

struct Quic {
    /* This member must be first */
    TLS tls;
#define quic_server tls.server
    QuicStreamConf stream;
    QUIC_STATEM statem;
    struct list_head node; 
    int send_fd;
    uint32_t version;
    uint32_t mss;
    uint32_t verify_mode;
    uint64_t options;
    uint64_t pkt_num_len:2;
    uint64_t cid_len:8;
    uint64_t fd_mode:1;
    uint64_t dcid_inited:1;
    uint64_t scid_inited:1;
    const QUIC_CTX *ctx;
    const QUIC_METHOD *method;
    X509_VERIFY_PARAM *param;
    BIO *rbio;
    BIO *wbio;
    QUIC_DATA *read_buf;
    int (*do_handshake)(QUIC *);
    QUIC_SESSION *session;
    Address source;
    Address dest;
    QuicConn conn;
    QUIC_DATA dcid;
    QUIC_DATA scid;
    QUIC_DATA token;
    QUIC_CRYPTO initial;
    QUIC_CRYPTO handshake;
    QUIC_CRYPTO application;
    QuicTransParams peer_param;
    QBUFF *send_head;
    Timer delay_ack;
    Timer retrans;
    Timer keep_alive;
    QBuffQueueHead rx_queue;
    QBuffQueueHead tx_queue;
};

DEFINE_LHASH_OF(X509_NAME);

static inline QUIC *QuicTlsTrans(TLS *s)
{
    return (QUIC *)s;
}

int QUIC_set_handshake_hp_cipher(QUIC *, uint32_t);
int QUIC_set_pp_cipher_space_alg(QuicCipherSpace *, uint32_t);
int QUIC_set_hp_cipher(QUIC_CRYPTO *, uint32_t);
int QUIC_set_hp_cipher_space_alg(QuicCipherSpace *, uint32_t);
QUIC_CRYPTO *QuicCryptoGet(QUIC *, uint32_t);
QUIC_CRYPTO *QuicGetInitialCrypto(QUIC *);
QUIC_CRYPTO *QuicGetHandshakeCrypto(QUIC *);
QUIC_CRYPTO *QuicGetOneRttCrypto(QUIC *);
int QuicWritePkt(QUIC *, QuicStaticBuffer *);
void QuicCryptoFree(QUIC_CRYPTO *);



#endif
