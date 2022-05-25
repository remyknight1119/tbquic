/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "sig_alg.h"

#include <openssl/evp.h>
#include <tbquic/tls.h>

#include "extension.h"
#include "cipher.h"
#include "common.h"
#include "log.h"

static const uint16_t kTlsSigalgs[] = {
    TLSEXT_SIGALG_ECDSA_SECP256R1_SHA256,
    TLSEXT_SIGALG_ECDSA_SECP384R1_SHA384,
    TLSEXT_SIGALG_ECDSA_SECP521R1_SHA512,
    TLSEXT_SIGALG_RSA_PSS_RSAE_SHA256,
    TLSEXT_SIGALG_RSA_PSS_RSAE_SHA384,
    TLSEXT_SIGALG_RSA_PSS_RSAE_SHA512,
    TLSEXT_SIGALG_RSA_PKCS1_SHA256,
    TLSEXT_SIGALG_RSA_PKCS1_SHA384,
    TLSEXT_SIGALG_RSA_PKCS1_SHA512,
};

#define SIG_ALG_DEF_NUM QUIC_NELEM(kTlsSigalgs)

static const SigAlgLookup kSigAlgLookup[] = {
    {
        .sigalg = TLSEXT_SIGALG_ECDSA_SECP256R1_SHA256,
        .hash = NID_sha256,
        .hash_idx = QUIC_DIGEST_SHA256,
        .sig = EVP_PKEY_EC,
        .sig_idx = QUIC_PKEY_ECC,
        .sigandhash = NID_ecdsa_with_SHA256,
        .curve = NID_X9_62_prime256v1,
    },
    {
        .sigalg = TLSEXT_SIGALG_ECDSA_SECP384R1_SHA384,
        .hash = NID_sha384,
        .hash_idx = QUIC_DIGEST_SHA384,
        .sig = EVP_PKEY_EC,
        .sig_idx = QUIC_PKEY_ECC,
        .sigandhash = NID_ecdsa_with_SHA384,
        .curve = NID_secp384r1,
    },
    {
        .sigalg = TLSEXT_SIGALG_ECDSA_SECP521R1_SHA512,
        .hash = NID_sha512,
        .hash_idx = QUIC_DIGEST_SHA512,
        .sig = EVP_PKEY_EC,
        .sig_idx = QUIC_PKEY_ECC,
        .sigandhash = NID_ecdsa_with_SHA512,
        .curve = NID_secp521r1,
    },
    {
        .sigalg = TLSEXT_SIGALG_RSA_PSS_RSAE_SHA256,
        .hash = NID_sha256,
        .hash_idx = QUIC_DIGEST_SHA256,
        .sig = EVP_PKEY_RSA_PSS,
        .sig_idx = QUIC_PKEY_RSA,
    },
    {
        .sigalg = TLSEXT_SIGALG_RSA_PSS_RSAE_SHA384,
        .hash = NID_sha384,
        .hash_idx = QUIC_DIGEST_SHA384,
        .sig = EVP_PKEY_RSA_PSS,
        .sig_idx = QUIC_PKEY_RSA,
    },
    {
        .sigalg = TLSEXT_SIGALG_RSA_PSS_RSAE_SHA512,
        .hash = NID_sha512,
        .hash_idx = QUIC_DIGEST_SHA512,
        .sig = EVP_PKEY_RSA_PSS,
        .sig_idx = QUIC_PKEY_RSA,
    },
    {
        .sigalg = TLSEXT_SIGALG_RSA_PKCS1_SHA256,
        .hash = NID_sha256,
        .hash_idx = QUIC_DIGEST_SHA256,
        .sig = EVP_PKEY_RSA,
        .sig_idx = QUIC_PKEY_RSA,
    },
    {
        .sigalg = TLSEXT_SIGALG_RSA_PKCS1_SHA384,
        .hash = NID_sha384,
        .hash_idx = QUIC_DIGEST_SHA384,
        .sig = EVP_PKEY_RSA,
        .sig_idx = QUIC_PKEY_RSA,
    },
    {
        .sigalg = TLSEXT_SIGALG_RSA_PKCS1_SHA512,
        .hash = NID_sha512,
        .hash_idx = QUIC_DIGEST_SHA512,
        .sig = EVP_PKEY_RSA,
        .sig_idx = QUIC_PKEY_RSA,
    },
    {
        .sigalg = TLSEXT_SIGALG_RSA_PKCS1_SHA1,
        .hash = NID_sha1,
        .hash_idx = QUIC_DIGEST_SHA512,
        .sig = EVP_PKEY_RSA,
        .sig_idx = QUIC_PKEY_RSA,
        .sigandhash = NID_sha1WithRSAEncryption,
    },
};

#define SIG_ALG_LOOKUP_NUM QUIC_NELEM(kSigAlgLookup)

const SigAlgLookup *TlsLookupSigAlg(uint16_t sigalg)
{
    const SigAlgLookup *lu = NULL;
    size_t i = 0;

    for (i = 0; i < SIG_ALG_LOOKUP_NUM; i++) {
        lu = &kSigAlgLookup[i];
        if (lu->sigalg == sigalg) {
            return lu;
        }
    }

    return NULL;
}

const SigAlgLookup *TlsLookupSigAlgBySig(int sig)
{
    const SigAlgLookup *lu = NULL;
    size_t i = 0;

    for (i = 0; i < SIG_ALG_LOOKUP_NUM; i++) {
        lu = &kSigAlgLookup[i];
        if (lu->sig == sig) {
            return lu;
        }
    }

    return NULL;
}

const SigAlgLookup *TlsLookupSigAlgByPkey(const EVP_PKEY *pk)
{
    int nid = EVP_PKEY_id(pk);

    if (nid == NID_undef) {
        return NULL;
    }

    return TlsLookupSigAlgBySig(nid);
}

int TlsCopySigAlgs(WPacket *pkt, const uint16_t *psig, size_t psiglen)
{
    const SigAlgLookup *lu = NULL;
    size_t i = 0;

    for (i = 0; i < psiglen; i++, psig++) {
        lu = TlsLookupSigAlg(*psig);
        if (lu == NULL) {
            QUIC_LOG("Sig id %x not found\n", *psig);
            return -1;
        }

        if (WPacketPut2(pkt, *psig) < 0) {
            QUIC_LOG("Put session ID len failed\n");
            return -1;
        }
    }

    return 0;
}

size_t TlsGetPSigAlgs(TLS *s, const uint16_t **psigs)
{
    if (!QuicDataIsEmpty(&s->cert->conf_sigalgs)) {
        *psigs = s->cert->conf_sigalgs.ptr_u16;
        return s->cert->conf_sigalgs.len;
    }

    *psigs = kTlsSigalgs;

    return SIG_ALG_DEF_NUM;
}

int TlsSetSigalgs(QuicCert *c, const uint16_t *psig_nids, size_t salglen)
{
    const SigAlgLookup *lu = NULL;
    QUIC_DATA sig_alg = {};
    size_t i = 0;

    for (i = 0; i < salglen; i++) {
        lu = TlsLookupSigAlg(psig_nids[i]);
        if (lu == NULL) {
            return -1;
        }
    }

    QuicDataSet(&sig_alg, psig_nids, salglen);

    return QuicDataDupU16(&c->conf_sigalgs, &sig_alg);
}

