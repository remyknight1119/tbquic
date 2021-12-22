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

#define TLS_RANDOM_BYTE_LEN     32
#define TLS_HANDSHAKE_LEN_SIZE  3
#define TLS_CIPHESUITE_LEN_SIZE sizeof(uint16_t)

#define TLS_MESSAGE_MAX_LEN     16384
#define TLS_VERSION_1_2         0x0303
#define TLS_VERSION_1_3         0x0304

#define TLS_IS_READING(t) QUIC_STATEM_READING(t->rwstate)
#define TLS_IS_WRITING(t) QUIC_STATEM_WRITING(t->rwstate)
#define TLS_HANDSHAKE_STATE(t, state) ((t)->handshake_state == state)
#define TLS_HANDSHAKE_DONE(t) TLS_HANDSHAKE_STATE(t, QUIC_TLS_ST_HANDSHAKE_DONE)

typedef struct QuicTls QUIC_TLS;

typedef enum {
    HELLO_REQUEST = 0,
    CLIENT_HELLO = 1,
    SERVER_HELLO = 2,
    HELLO_VERIFY_REQUEST = 3,
    NEW_SESSION_TICKET = 4,
    END_OF_EARLY_DATA = 5,
    HELLO_RETRY_REQUEST = 6,
    ENCRYPTED_EXTENSIONS = 8,
    CERTIFICATE = 11,
    SERVER_KEY_EXCHANGE = 12,
    CERTIFICATE_REQUEST = 13,
    SERVER_HELLO_DONE = 14,
    CERTIFICATE_VERIFY = 15,
    CLIENT_KEY_EXCHANGE = 16,
    FINISHED = 20,
    CERTIFICATE_URL = 21,
    CERTIFICATE_STATUS = 22,
    SUPPLEMENTAL_DATA = 23,
    KEY_UPDATE = 24,
    MESSAGE_HASH = 254,
    HANDSHAKE_MAX,
} HandshakeType;

typedef enum {
    QUIC_TLS_ST_OK,
    QUIC_TLS_ST_CW_CLIENT_HELLO,
    QUIC_TLS_ST_CW_CLIENT_CERTIFICATE,
    QUIC_TLS_ST_CW_CERTIFICATE_VERIFY,
    QUIC_TLS_ST_CW_FINISHED,
    QUIC_TLS_ST_CR_SERVER_HELLO,
    QUIC_TLS_ST_CR_ENCRYPTED_EXTENSIONS,
    QUIC_TLS_ST_CR_SERVER_CERTIFICATE,
    QUIC_TLS_ST_CR_CERTIFICATE_VERIFY,
    QUIC_TLS_ST_CR_FINISHED,
    QUIC_TLS_ST_SR_CLIENT_HELLO,
    QUIC_TLS_ST_SW_SERVER_HELLO,
    QUIC_TLS_ST_SW_SERVER_CERTIFICATE,
    QUIC_TLS_ST_HANDSHAKE_DONE,
    QUIC_TLS_ST_MAX,
} QuicTlsState;

struct QuicTls {
    QuicTlsState handshake_state;
    uint8_t server:1;
    QuicFlowReturn (*handshake)(QUIC_TLS *);
    uint8_t client_random[TLS_RANDOM_BYTE_LEN];
    uint8_t server_random[TLS_RANDOM_BYTE_LEN];
    struct hlist_head cipher_list;
    QUIC_BUFFER buffer;
    QuicCert *cert;
    const TlsCipher *handshake_cipher;
    EVP_PKEY *kexch_key;
    EVP_PKEY *peer_kexch_key;
    EVP_MD_CTX *handshake_dgst;
    uint16_t group_id;
    uint8_t early_secret[EVP_MAX_MD_SIZE];
    uint8_t handshake_secret[EVP_MAX_MD_SIZE];
    uint8_t master_secret[EVP_MAX_MD_SIZE];
    /* TLS extensions. */
    struct {
        char *hostname;
        QuicTransParams trans_param;
        QUIC_DATA alpn;
        QUIC_DATA supported_groups;
        size_t key_share_max_group_idx;
    } ext;
};

typedef struct {
    QuicFlowState flow_state;
    QuicTlsState next_state;
    HandshakeType handshake_type;
    int (*handler)(QUIC_TLS *, void *);
} QuicTlsProcess;

#ifdef QUIC_TEST
extern uint8_t *quic_random_test;
#endif

int QuicTlsInit(QUIC_TLS *, QUIC_CTX *);
void QuicTlsFree(QUIC_TLS *);
void QuicTlsClientInit(QUIC_TLS *);
void QuicTlsServerInit(QUIC_TLS *);
QuicFlowReturn QuicTlsDoHandshake(QUIC_TLS *);
int QuicTlsDoProcess(QUIC_TLS *, RPacket *, WPacket *, const QuicTlsProcess *,
                        size_t);
QuicFlowReturn QuicTlsHandshake(QUIC_TLS *, const QuicTlsProcess *, size_t);
int QuicTlsGenRandom(uint8_t *, size_t, WPacket *);

int QuicTlsHelloHeadParse(QUIC_TLS *, RPacket *, uint8_t *, size_t);
int QuicTlsExtLenParse(RPacket *);
int QuicTlsPutCipherList(QUIC_TLS *, WPacket *);
int QuicTlsPutCompressionMethod(WPacket *);
int QuicTlsFinishedBuild(QUIC_TLS *, void *);

#endif
