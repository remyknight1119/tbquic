#ifndef TBQUIC_INCLUDE_TBQUIC_QUIC_H_
#define TBQUIC_INCLUDE_TBQUIC_QUIC_H_

#include <openssl/bio.h>
#include <tbquic/types.h>

extern int QuicInit(void);
extern QUIC_CTX *QuicCtxNew(const QUIC_METHOD *meth);
extern void QuicCtxFree(QUIC_CTX *ctx);
extern QUIC *QuicNew(void);
extern void QuicFree(QUIC *quic);

extern BIO *QUIC_get_rbio(const QUIC *quic);
extern BIO *QUIC_get_wbio(const QUIC *quic);
extern void QUIC_set_rbio(QUIC *quic, BIO *rbio);
extern void QUIC_set_wbio(QUIC *quic, BIO *wbio);
extern void QUIC_set_bio(QUIC *quic, BIO *rbio, BIO *wbio);
extern int QUIC_set_fd(QUIC *quic, int fd);


#endif
