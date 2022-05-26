#ifndef TBQUIC_QUIC_CERT_H_
#define TBQUIC_QUIC_CERT_H_

#include <openssl/x509_vfy.h>
#include <openssl/x509.h>
#include <tbquic/types.h>
#include "base.h"
#include "cipher.h"

typedef struct {
    X509 *x509;
    EVP_PKEY *privatekey;
    STACK_OF(X509) *chain;
} QuicCertPkey;

typedef struct {
    QuicCertPkey *key;
    QuicCertPkey pkeys[QUIC_PKEY_NUM];
    QUIC_DATA conf_sigalgs;
    X509_STORE *verify_store;
} QuicCert;

typedef struct {
    int nid; /* NID of public key algorithm */
    uint32_t mask; /* authmask corresponding to key type */
} QuicCertLookup;

QuicCert *QuicCertNew(void);
QuicCert *QuicCertDup(QuicCert *);
void QuicCertFree(QuicCert *);
int QuicVerifyCertChain(QUIC *, STACK_OF(X509) *);
int QuicSetPkey(QuicCert *, EVP_PKEY *);
int QuicSetCert(QuicCert *, X509 *);
const QuicCertLookup *QuicCertLookupByPkey(const EVP_PKEY *, size_t *);
bool QuicX509StoreCtxInit(void);

#endif
