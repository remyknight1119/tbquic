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
#define TLS_HANDSHAKE_DONE(t) TLS_HANDSHAKE_STATE(t, TLS_ST_HANDSHAKE_DONE)
#define TLS_USE_PSS(s) \
    (s->peer_sigalg != NULL && s->peer_sigalg->sig == EVP_PKEY_RSA_PSS)
#define TLS_EXT_TRANS_PARAM(tls) (tls)->ext.trans_param 

typedef int (*TlsExtConstructor)(TLS *, WPacket *, uint32_t, X509 *, size_t);

typedef enum {
    TLS_EARLY_DATA_NONE = 0,
    TLS_EARLY_DATA_CONNECT_RETRY,
    TLS_EARLY_DATA_CONNECTING,
    TLS_EARLY_DATA_WRITE_RETRY,
    TLS_EARLY_DATA_WRITING,
    TLS_EARLY_DATA_WRITE_FLUSH,
    TLS_EARLY_DATA_UNAUTH_WRITING,
    TLS_EARLY_DATA_FINISHED_WRITING,
    TLS_EARLY_DATA_ACCEPT_RETRY,
    TLS_EARLY_DATA_ACCEPTING,
    TLS_EARLY_DATA_READ_RETRY,
    TLS_EARLY_DATA_READING,
    TLS_EARLY_DATA_FINISHED_READING
} TlsEarlyDataState;

typedef struct {
    uint8_t tick_hmac_key[TLSEXT_TICK_KEY_LENGTH];
    uint8_t tick_aes_key[TLSEXT_TICK_KEY_LENGTH];
    uint8_t tick_key_name[TLSEXT_KEYNAME_LENGTH];
} TlsTicketKey;

struct Tls {
    TlsEarlyDataState early_data_state;
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
//        uint16_t early_data;
    } ext;
};

#ifdef QUIC_TEST
extern uint8_t *quic_random_test;
#endif

int TlsInit(TLS *, QUIC_CTX *);
void TlsFree(TLS *);
QuicFlowReturn TlsHandshakeMsgRead(TLS *, QuicStatem *,
                    const QuicStatemMachine *, size_t,
                    RPacket *, bool *);
QuicFlowReturn TlsHandshakeMsgWrite(TLS *, const QuicStatemMachine *,
                    WPacket *);
int TlsGenRandom(uint8_t *, size_t, WPacket *);

int TlsHelloHeadParse(TLS *, RPacket *, uint8_t *, size_t);
int TlsExtLenParse(RPacket *);
int TlsPutCipherList(TLS *, WPacket *);
int TlsPutCompressionMethod(WPacket *);
int TlsConstructCertVerify(TLS *, WPacket *);
int TlsFinishedCheck(TLS *, RPacket *);
QuicFlowReturn TlsServerHelloProc(TLS *, void *);
QuicFlowReturn TlsClntEncExtProc(TLS *, void *);
QuicFlowReturn TlsCertRequestProc(TLS *, void *);
QuicFlowReturn TlsServerCertProc(TLS *, void *);
QuicFlowReturn TlsCertVerifyProc(TLS *, void *);
QuicFlowReturn TlsClntFinishedProc(TLS *, void *);
QuicFlowReturn TlsClientHelloProc(TLS *, void *);
QuicFlowReturn TlsSrvrCertProc(TLS *, void *);
QuicFlowReturn TlsSrvrCertVerifyProc(TLS *, void *);
QuicFlowReturn TlsSrvrFinishedProc(TLS *, void *);
QuicFlowReturn TlsClntNewSessionTicketProc(TLS *, void *);
QuicFlowReturn TlsCertChainBuild(TLS *s, WPacket *, QuicCertPkey *,
                                TlsExtConstructor);
QuicFlowReturn TlsCertVerifyBuild(TLS *s, WPacket *pkt);
QuicFlowReturn TlsClntHelloBuild(TLS *, void *);
QuicFlowReturn TlsFinishedBuild(TLS *, void *);
QuicFlowReturn TlsClntFinishedBuild(TLS *, void *);
QuicFlowReturn TlsClntCertBuild(TLS *, void *);
QuicFlowReturn TlsClntCertVerifyBuild(TLS *, void *);
QuicFlowReturn TlsServerHelloBuild(TLS *, void *);
QuicFlowReturn TlsSrvrEncryptedExtBuild(TLS *, void *);
QuicFlowReturn TlsSrvrCertRequestBuild(TLS *, void *);
QuicFlowReturn TlsSrvrServerCertBuild(TLS *, void *);
QuicFlowReturn TlsSrvrCertVerifyBuild(TLS *, void *);
QuicFlowReturn TlsSrvrFinishedBuild(TLS *, void *);
QuicFlowReturn TlsSrvrNewSessionTicketBuild(TLS *, void *);
int TlsSrvrClientHelloPostWork(QUIC *);
int TlsClntSkipCheckCertRequest(TLS *);
int TlsClntSkipCheckServerCert(TLS *);
int TlsClntSkipCheckCertVerify(TLS *);

#endif
