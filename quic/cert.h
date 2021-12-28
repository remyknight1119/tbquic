#ifndef TBQUIC_QUIC_CERT_H_
#define TBQUIC_QUIC_CERT_H_

#include <openssl/x509_vfy.h>
#include <tbquic/types.h>
#include "base.h"

typedef struct {
    QUIC_DATA conf_sigalgs;
} QuicCert;

QuicCert *QuicCertNew(void);
QuicCert *QuicCertDup(QuicCert *);
void QuicCertFree(QuicCert *);
int QuicVerifyCertChain(QUIC *, STACK_OF(X509) *);

#endif
