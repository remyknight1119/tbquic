#ifndef TBQUIC_QUIC_CERT_H_
#define TBQUIC_QUIC_CERT_H_

#include "base.h"

typedef struct {
    QUIC_DATA conf_sigalgs;
} QuicCert;

QuicCert *QuicCertNew(void);
QuicCert *QuicCertDup(QuicCert *);
void QuicCertFree(QuicCert *);

#endif
