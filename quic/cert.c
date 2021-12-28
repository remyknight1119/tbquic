/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "cert.h"

#include "mem.h"

QuicCert *QuicCertNew(void)
{
    QuicCert *cert = NULL;

    cert = QuicMemCalloc(sizeof(*cert));
    if (cert == NULL) {
        return NULL;
    }

    return cert;
}

QuicCert *QuicCertDup(QuicCert *cert)
{
    QuicCert *dst = NULL;

    dst = QuicCertNew();
    if (dst == NULL) {
        return NULL;
    }

    if (QuicDataDupU16(&dst->conf_sigalgs, &cert->conf_sigalgs) < 0) {
        goto out;
    }

    return dst;
out:
    QuicCertFree(dst);
    return NULL;
}

void QuicCertFree(QuicCert *cert)
{
    if (cert == NULL) {
        return;
    }

    QuicDataFree(&cert->conf_sigalgs);
    QuicMemFree(cert);
}

int QuicVerifyCertChain(QUIC *quic, STACK_OF(X509) *sk)
{
    return 0;
}
