#ifndef TBQUIC_INCLUDE_TBQUIC_QUIC_H_
#define TBQUIC_INCLUDE_TBQUIC_QUIC_H_

#include <stdbool.h>
#include <openssl/bio.h>
#include <tbquic/types.h>
#include <tbquic/ec.h>

//MTU - IP Header - UDP Header
#define QUIC_DATAGRAM_GET_MSS(mtu)  (mtu - 20 - 8)
#define QUIC_DATAGRAM_SIZE_MAX_DEF  QUIC_DATAGRAM_GET_MSS(1500)
#define QUIC_DATAGRAM_SIZE_MAX      QUIC_DATAGRAM_GET_MSS(65535)

#define QUIC_ERROR_NONE         0
#define QUIC_ERROR_QUIC         1
#define QUIC_ERROR_WANT_READ    2
#define QUIC_ERROR_WANT_WRITE   3
#define QUIC_ERROR_WANT_ASYNC   4

#define QUIC_TLS_VERIFY_NONE    0
#define QUIC_TLS_VERIFY_PEER    1

#define QUIC_TRANS_PARAM_ORIGINAL_DESTINATION_CONNECTION_ID     0x00
#define QUIC_TRANS_PARAM_MAX_IDLE_TIMEOUT                       0x01
#define QUIC_TRANS_PARAM_STATELESS_RESET_TOKEN                  0x02
#define QUIC_TRANS_PARAM_MAX_UDP_PAYLOAD_SIZE                   0x03
#define QUIC_TRANS_PARAM_INITIAL_MAX_DATA                       0x04
#define QUIC_TRANS_PARAM_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL     0x05
#define QUIC_TRANS_PARAM_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE    0x06
#define QUIC_TRANS_PARAM_INITIAL_MAX_STREAM_DATA_UNI            0x07
#define QUIC_TRANS_PARAM_INITIAL_MAX_STREAMS_BIDI               0x08
#define QUIC_TRANS_PARAM_INITIAL_MAX_STREAMS_UNI                0x09
#define QUIC_TRANS_PARAM_ACK_DELAY_EXPONENT                     0x0A
#define QUIC_TRANS_PARAM_MAX_ACK_DELAY                          0x0B
#define QUIC_TRANS_PARAM_DISABLE_ACTIVE_MIGRATION               0x0C
#define QUIC_TRANS_PARAM_PREFERRED_ADDRESS                      0x0D
#define QUIC_TRANS_PARAM_ACTIVE_CONNECTION_ID_LIMIT             0x0E
#define QUIC_TRANS_PARAM_INITIAL_SOURCE_CONNECTION_ID           0x0F
#define QUIC_TRANS_PARAM_RETRY_SOURCE_CONNECTION_ID             0x10
#define QUIC_TRANS_PARAM_MAX_DATAGRAME_FRAME_SIZE               0x20

typedef void (*QUIC_CTX_keylog_cb_func)(const QUIC *, const char *);
typedef int (*QUIC_CTX_verify_callback_func)(bool, X509_STORE_CTX *);

enum {
    QUIC_FILE_TYPE_ASN1,
    QUIC_FILE_TYPE_PEM,
    QUIC_FILE_TYPE_MAX,
};

enum {
    QUIC_CTRL_SET_PKT_NUM_MAX_LEN,
    QUIC_CTRL_SET_GROUPS,
    QUIC_CTRL_SET_SIGALGS,
    QUIC_CTRL_SET_TLSEXT_HOSTNAME,
    QUIC_CTRL_SET_MSS,
};

extern int QuicInit(void);
extern void QuicExit(void);
extern QUIC_CTX *QuicCtxNew(const QUIC_METHOD *meth);
extern void QuicCtxFree(QUIC_CTX *ctx);
extern int QuicCtxCtrl(QUIC_CTX *ctx, uint32_t cmd, void *parg, long larg);
extern int QuicCtxUsePrivateKeyFile(QUIC_CTX *ctx, const char *file,
                                    uint32_t type);
extern int QuicCtxUseCertificateFile(QUIC_CTX *ctx, const char *file,
                                        uint32_t type);
extern int QUIC_CTX_set_transport_parameter(QUIC_CTX *ctx, uint64_t type,
                                        void *value, size_t len);
extern int QUIC_set_transport_parameter(QUIC *quic, uint64_t type,
                                    void *value, size_t len);
extern int QUIC_CTX_set_alpn_protos(QUIC_CTX *ctx, const uint8_t *protos,
                                    size_t protos_len);
extern int QUIC_set_alpn_protos(QUIC *quic, const uint8_t *protos,
                                    size_t protos_len);
extern int QUIC_CTX_set_max_early_data(QUIC_CTX *ctx, uint32_t max_early_data);
extern void QUIC_CTX_set_keylog_callback(QUIC_CTX *ctx,
                        QUIC_CTX_keylog_cb_func cb);
extern void QUIC_CTX_set_verify(QUIC_CTX *ctx, uint32_t mode,
                        QUIC_CTX_verify_callback_func cb);
extern void QUIC_CTX_set_verify_depth(QUIC_CTX *ctx, int depth);
extern int QuicCtxLoadVerifyLocations(QUIC_CTX *ctx, const char *CAfile,
                        const char *CApath);
extern STACK_OF(X509_NAME) *QuicLoadClientCaFile(const char *file);
extern void QUIC_CTX_set_client_CA_list(QUIC_CTX *ctx,
                        STACK_OF(X509_NAME) *name_list);

extern int QuicSendPacket(QUIC *quic);
extern bool QuicWantRead(QUIC *quic);
extern bool QuicWantWrite(QUIC *quic);

extern QUIC_METHOD *QuicClientMethod(void);
extern QUIC_METHOD *QuicServerMethod(void);
extern QUIC_METHOD *QuicDispenserMethod(void);
extern QUIC *QuicNew(QUIC_CTX *ctx);
extern void QuicFree(QUIC *quic);
extern void QUIC_set_accept_state(QUIC *quic);
extern void QUIC_set_connect_state(QUIC *quic);
extern int QuicCtrl(QUIC *quic, uint32_t cmd, void *parg, long larg);
extern int QuicDoHandshake(QUIC *quic);
extern BIO *QUIC_get_rbio(const QUIC *quic);
extern BIO *QUIC_get_wbio(const QUIC *quic);
extern void QUIC_set_rbio(QUIC *quic, BIO *rbio);
extern void QUIC_set_wbio(QUIC *quic, BIO *wbio);
extern void QUIC_set_bio(QUIC *quic, BIO *rbio, BIO *wbio);
extern int QUIC_set_fd(QUIC *quic, int fd);
extern QUIC_SESSION *QUIC_get_session(QUIC *quic);
extern QUIC_SESSION *QUIC_get1_session(QUIC *quic);
extern int QUIC_set_session(QUIC *quic, QUIC_SESSION *sess);
extern int QUIC_get_error(QUIC *quic, int ret);

#endif
