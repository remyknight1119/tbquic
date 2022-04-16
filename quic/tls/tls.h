#ifndef TBQUIC_QUIC_TLS_TLS_H_
#define TBQUIC_QUIC_TLS_TLS_H_

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <openssl/evp.h>
#include <tbquic/types.h>
#include "packet_local.h"
#include "buffer.h"
#include "statem.h"
#include "list.h"
#include "transport.h"
#include "base.h"
#include "cert.h"
#include "tls_cipher.h"
#include "types.h"
#include "sig_alg.h"
#include "q_buff.h"

#define TLS_RANDOM_BYTE_LEN     32
#define TLS_HANDSHAKE_LEN_SIZE  3
#define TLS_CIPHESUITE_LEN_SIZE sizeof(uint16_t)

#define TLS_MESSAGE_MAX_LEN     16384
#define TLS_VERSION_1_2         0x0303
#define TLS_VERSION_1_3         0x0304

#define TLSEXT_KEYNAME_LENGTH  16
#define TLSEXT_TICK_KEY_LENGTH 32

#define TICKET_NONCE_SIZE       8

#define TLS_IS_READING(t) QUIC_STATEM_READING(t->rwstate)
#define TLS_IS_WRITING(t) QUIC_STATEM_WRITING(t->rwstate)
#define TLS_HANDSHAKE_STATE(t, state) ((t)->handshake_state == state)
#define TLS_HANDSHAKE_DONE(t) TLS_HANDSHAKE_STATE(t, TLS_ST_HANDSHAKE_DONE)
#define TLS_USE_PSS(s) \
    (s->peer_sigalg != NULL && s->peer_sigalg->sig == EVP_PKEY_RSA_PSS)
#define TLS_EXT_TRANS_PARAM(tls) (tls)->ext.trans_param 

typedef int (*TlsExtConstructor)(TLS *, WPacket *, uint32_t, X509 *, size_t);

typedef enum {
    TLS_MT_HELLO_REQUEST = 0,
    TLS_MT_CLIENT_HELLO = 1,
    TLS_MT_SERVER_HELLO = 2,
    TLS_MT_HELLO_VERIFY_REQUEST = 3,
    TLS_MT_NEW_SESSION_TICKET = 4,
    TLS_MT_END_OF_EARLY_DATA = 5,
    TLS_MT_HELLO_RETRY_REQUEST = 6,
    TLS_MT_ENCRYPTED_EXTENSIONS = 8,
    TLS_MT_CERTIFICATE = 11,
    TLS_MT_SERVER_KEY_EXCHANGE = 12,
    TLS_MT_CERTIFICATE_REQUEST = 13,
    TLS_MT_SERVER_HELLO_DONE = 14,
    TLS_MT_CERTIFICATE_VERIFY = 15,
    TLS_MT_CLIENT_KEY_EXCHANGE = 16,
    TLS_MT_FINISHED = 20,
    TLS_MT_CERTIFICATE_URL = 21,
    TLS_MT_CERTIFICATE_STATUS = 22,
    TLS_MT_SUPPLEMENTAL_DATA = 23,
    TLS_MT_KEY_UPDATE = 24,
    TLS_MT_MESSAGE_HASH = 254,
    TLS_MT_MESSAGE_TYPE_MAX,
} TlsMessageType;

typedef enum {
    TLS_ST_OK,
    TLS_ST_CW_CLIENT_HELLO,
    TLS_ST_CW_CLIENT_CERTIFICATE,
    TLS_ST_CW_CERT_VERIFY,
    TLS_ST_CW_FINISHED,
    /*Read state must in order */
    TLS_ST_CR_SERVER_HELLO,
    TLS_ST_CR_ENCRYPTED_EXTENSIONS,
    TLS_ST_CR_CERT_REQUEST,
    TLS_ST_CR_SERVER_CERTIFICATE,
    TLS_ST_CR_CERT_VERIFY,
    TLS_ST_CR_FINISHED,
    TLS_ST_CR_NEW_SESSION_TICKET,
    TLS_ST_SR_CLIENT_HELLO,
    TLS_ST_SR_CLIENT_CERTIFICATE,
    TLS_ST_SR_CERT_VERIFY,
    TLS_ST_SR_FINISHED,
    TLS_ST_SW_SERVER_HELLO,
    TLS_ST_SW_ENCRYPTED_EXTENSIONS,
    TLS_ST_SW_CERT_REQUEST,
    TLS_ST_SW_SERVER_CERTIFICATE,
    TLS_ST_SW_CERT_VERIFY,
    TLS_ST_SW_FINISHED,
    TLS_ST_SW_NEW_SESSION_TICKET,
    TLS_ST_SW_HANDSHAKE_DONE,
    TLS_ST_HANDSHAKE_DONE,
    TLS_ST_MAX,
} TlsState;

typedef struct {
    uint8_t tick_hmac_key[TLSEXT_TICK_KEY_LENGTH];
    uint8_t tick_aes_key[TLSEXT_TICK_KEY_LENGTH];
    uint8_t tick_key_name[TLSEXT_KEYNAME_LENGTH];
} TlsTicketKey;

typedef struct {
    QuicFlowReturn (*handshake)(TLS *);
} TlsMethod;

struct Tls {
    TlsState handshake_state;
    const TlsMethod *method;
    uint64_t server:1;
    uint64_t alpn_sent:1;
    uint64_t hit:1; //reusing a session
    uint8_t client_random[TLS_RANDOM_BYTE_LEN];
    uint8_t server_random[TLS_RANDOM_BYTE_LEN];
    struct hlist_head cipher_list;
    size_t handshake_msg_len;
    QUIC_BUFFER buffer;
    QuicCert *cert;
    const TlsCipher *handshake_cipher;
    EVP_PKEY *kexch_key;
    EVP_PKEY *peer_kexch_key;
    EVP_MD_CTX *handshake_dgst;
    X509 *peer_cert;
    const SigAlgLookup *peer_sigalg;
    uint16_t group_id;
    uint16_t psk_kex_mode;
    uint32_t lifetime_hint;
    uint32_t max_early_data;
    uint64_t next_ticket_nonce;
    uint8_t early_secret[EVP_MAX_MD_SIZE];
    uint8_t handshake_secret[EVP_MAX_MD_SIZE];
    uint8_t master_secret[EVP_MAX_MD_SIZE];
    uint8_t resumption_master_secret[EVP_MAX_MD_SIZE];
    uint8_t client_finished_secret[EVP_MAX_MD_SIZE];
    uint8_t server_finished_secret[EVP_MAX_MD_SIZE];
    uint8_t client_app_traffic_secret[EVP_MAX_MD_SIZE];
    uint8_t server_app_traffic_secret[EVP_MAX_MD_SIZE];
    uint8_t handshake_traffic_hash[EVP_MAX_MD_SIZE];
    uint8_t server_finished_hash[EVP_MAX_MD_SIZE];
    uint8_t cert_verify_hash[EVP_MAX_MD_SIZE];
    size_t cert_verify_hash_len;
    uint8_t finish_md[EVP_MAX_MD_SIZE];
    size_t finish_md_len;
    uint8_t peer_finish_md[EVP_MAX_MD_SIZE];
    size_t peer_finish_md_len;
    QUIC_DATA alpn_selected;
    QUIC_DATA alpn_proposed;
    const SigAlgLookup **shared_sigalgs;
    size_t shared_sigalgs_len;
    struct {
        QuicCertPkey *cert;
        const SigAlgLookup *sigalg;
        QUIC_DATA peer_cert_sigalgs;
    } tmp;
    /* TLS extensions. */
    struct {
        char *hostname;
        QuicTransParams trans_param;
        QUIC_DATA alpn;
        QUIC_DATA supported_groups;
        QUIC_DATA peer_supported_groups;
        QUIC_DATA peer_sigalgs;
        size_t key_share_max_group_idx;
        TlsTicketKey ticket_key;
        uint16_t tick_identity;
    } ext;
};

typedef struct {
    QuicFlowState flow_state;
    TlsState next_state;
    TlsMessageType msg_type;
    QuicFlowReturn (*handler)(TLS *, void *);
    int (*post_work)(TLS *);
    uint32_t pkt_type;
    uint32_t optional;
} TlsProcess;

#ifdef QUIC_TEST
extern uint8_t *quic_random_test;
#endif

int TlsInit(TLS *, QUIC_CTX *);
void TlsFree(TLS *);
QuicFlowReturn TlsConnect(TLS *tls);
QuicFlowReturn TlsAccept(TLS *tls);
QuicFlowReturn TlsDoHandshake(TLS *);
int TlsDoProcess(TLS *, RPacket *, WPacket *, const TlsProcess *,
                        size_t);
QuicFlowReturn TlsHandshake(TLS *, const TlsProcess *, size_t);
int TlsGenRandom(uint8_t *, size_t, WPacket *);

int TlsHelloHeadParse(TLS *, RPacket *, uint8_t *, size_t);
int TlsExtLenParse(RPacket *);
int TlsPutCipherList(TLS *, WPacket *);
int TlsPutCompressionMethod(WPacket *);
int TlsConstructCertVerify(TLS *, WPacket *);
int TlsFinishedCheck(TLS *, RPacket *);
QuicFlowReturn TlsCertChainBuild(TLS *s, WPacket *, QuicCertPkey *,
                                TlsExtConstructor);
QuicFlowReturn TlsCertVerifyBuild(TLS *s, WPacket *pkt);
QuicFlowReturn TlsFinishedBuild(TLS *, void *);

#endif
