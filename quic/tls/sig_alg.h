#ifndef TBQUIC_QUIC_TLS_SIG_ALG_H_
#define TBQUIC_QUIC_TLS_SIG_ALG_H_

#include "packet_local.h"
#include "tls.h"

/*
 * Structure containing table entry of values associated with the signature
 * algorithms (signature scheme) extension
*/
typedef struct {
    /* Raw value used in extension */
    uint16_t sigalg;
    /* NID of hash algorithm or NID_undef if no hash */
    int hash;
    /* Index of hash algorithm or -1 if no hash algorithm */
    int hash_idx;
    /* NID of signature algorithm */
    int sig;
    /* Index of signature algorithm */
    int sig_idx;
    /* Combined hash and signature NID, if any */
    int sigandhash;
    /* Required public key curve (ECDSA only) */
    int curve;
} SigAlgLookup;

int TlsCopySigAlgs(WPacket *, const uint16_t *, size_t);
size_t TlsGetPSigAlgs(QUIC_TLS *, const uint16_t **);
int TlsSetSigalgs(QuicCert *c, const uint16_t *, size_t);

#endif
