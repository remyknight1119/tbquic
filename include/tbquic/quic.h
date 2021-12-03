#ifndef TBQUIC_INCLUDE_TBQUIC_QUIC_H_
#define TBQUIC_INCLUDE_TBQUIC_QUIC_H_

#include <openssl/bio.h>
#include <tbquic/types.h>
#include <tbquic/ec.h>

//MTU - IP Header - UDP Header
#define QUIC_DATAGRAM_SIZE_MAX_DEF  (1500 - 20 - 8)

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

enum {
    QUIC_FILE_TYPE_ASN1,
    QUIC_FILE_TYPE_PEM,
    QUIC_FILE_TYPE_MAX,
};

enum {
    QUIC_ERROR_NONE,
    QUIC_ERROR_WANT_READ,
    QUIC_ERROR_WANT_WRITE,
    QUIC_ERROR_WANT_ASYNC,
};

enum {
    QUIC_CTRL_SET_GROUPS,
    QUIC_CTRL_SET_SIGALGS,
    QUIC_CTRL_SET_TLSEXT_HOSTNAME,
};

extern int QuicInit(void);
extern QUIC_CTX *QuicCtxNew(const QUIC_METHOD *meth);
extern void QuicCtxFree(QUIC_CTX *ctx);
extern int QuicCtxCtrl(QUIC_CTX *ctx, uint32_t cmd, void *parg, long larg);
extern int QuicCtxUsePrivateKeyFile(QUIC_CTX *ctx, const char *file,
                                    uint32_t type);
extern int QuicCtxUseCertificate_File(QUIC_CTX *ctx, const char *file,
                                        uint32_t type);
extern int QUIC_CTX_set_transport_parameter(QUIC_CTX *ctx, uint64_t type,
                                        void *value, size_t len);
extern int QUIC_set_transport_parameter(QUIC *quic, uint64_t type,
                                    void *value, size_t len);
extern int QUIC_CTX_set_alpn_protos(QUIC_CTX *ctx, const uint8_t *protos,
                                    size_t protos_len);
extern int QUIC_set_alpn_protos(QUIC *quic, const uint8_t *protos,
                                    size_t protos_len);

extern QUIC_METHOD *QuicClientMethod(void);
extern QUIC_METHOD *QuicServerMethod(void);
extern QUIC *QuicNew(QUIC_CTX *ctx);
extern void QuicFree(QUIC *quic);
extern int QuicCtrl(QUIC *quic, uint32_t cmd, void *parg, long larg);
extern int QuicDoHandshake(QUIC *quic);

extern BIO *QUIC_get_rbio(const QUIC *quic);
extern BIO *QUIC_get_wbio(const QUIC *quic);
extern void QUIC_set_rbio(QUIC *quic, BIO *rbio);
extern void QUIC_set_wbio(QUIC *quic, BIO *wbio);
extern void QUIC_set_bio(QUIC *quic, BIO *rbio, BIO *wbio);
extern int QUIC_set_fd(QUIC *quic, int fd);

#endif
