#ifndef TBQUIC_INCLUDE_TBQUIC_QUIC_H_
#define TBQUIC_INCLUDE_TBQUIC_QUIC_H_

#include <openssl/bio.h>
#include <tbquic/types.h>

//MTU - IP Header - UDP Header
#define QUIC_DATAGRAM_SIZE_MAX_DEF  (1500 - 20 - 8)

enum {
    QUIC_FILE_TYPE_ASN1,
    QUIC_FILE_TYPE_PEM,
    QUIC_FILE_TYPE_MAX,
};

extern int QuicInit(void);
extern QUIC_CTX *QuicCtxNew(const QUIC_METHOD *meth);
extern void QuicCtxFree(QUIC_CTX *ctx);
extern int QuicCtxUsePrivateKeyFile(QUIC_CTX *ctx, const char *file,
                                    uint32_t type);
extern int QuicCtxUseCertificate_File(QUIC_CTX *ctx, const char *file,
                                        uint32_t type);
extern QUIC_METHOD *QuicClientMethod(void);
extern QUIC_METHOD *QuicServerMethod(void);
extern QUIC *QuicNew(QUIC_CTX *ctx);
extern void QuicFree(QUIC *quic);
extern int QuicDoHandshake(QUIC *quic);

extern BIO *QUIC_get_rbio(const QUIC *quic);
extern BIO *QUIC_get_wbio(const QUIC *quic);
extern void QUIC_set_rbio(QUIC *quic, BIO *rbio);
extern void QUIC_set_wbio(QUIC *quic, BIO *wbio);
extern void QUIC_set_bio(QUIC *quic, BIO *rbio, BIO *wbio);
extern int QUIC_set_fd(QUIC *quic, int fd);


#endif
