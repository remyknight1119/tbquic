/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "sig_alg.h"

#include <openssl/evp.h>
#include "extension.h"
#include "cipher.h"
#include "common.h"
#include "log.h"

static const uint16_t tls_sigalgs[] = {
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

#define SIG_ALG_DEF_NUM QUIC_NELEM(tls_sigalgs)

static const SigAlgLookup sig_alg_lookup[] = {
    {
        .sigalg = TLSEXT_SIGALG_ECDSA_SECP256R1_SHA256,
        .hash = NID_sha256,
        .hash_idx = QUIC_DIGEST_SHA256,
        .sig = EVP_PKEY_EC,
        .sig_idx = QUIC_SIG_ECC,
        .sigandhash = NID_ecdsa_with_SHA256,
        .curve = NID_X9_62_prime256v1,
    },
    {
        .sigalg = TLSEXT_SIGALG_ECDSA_SECP384R1_SHA384,
        .hash = NID_sha384,
        .hash_idx = QUIC_DIGEST_SHA384,
        .sig = EVP_PKEY_EC,
        .sig_idx = QUIC_SIG_ECC,
        .sigandhash = NID_ecdsa_with_SHA384,
        .curve = NID_secp384r1,
    },
    {
        .sigalg = TLSEXT_SIGALG_ECDSA_SECP521R1_SHA512,
        .hash = NID_sha512,
        .hash_idx = QUIC_DIGEST_SHA512,
        .sig = EVP_PKEY_EC,
        .sig_idx = QUIC_SIG_ECC,
        .sigandhash = NID_ecdsa_with_SHA512,
        .curve = NID_secp521r1,
    },
    {
        .sigalg = TLSEXT_SIGALG_RSA_PSS_RSAE_SHA256,
        .hash = NID_sha256,
        .hash_idx = QUIC_DIGEST_SHA256,
        .sig = EVP_PKEY_RSA_PSS,
        .sig_idx = QUIC_SIG_RSA,
    },
    {
        .sigalg = TLSEXT_SIGALG_RSA_PSS_RSAE_SHA384,
        .hash = NID_sha384,
        .hash_idx = QUIC_DIGEST_SHA384,
        .sig = EVP_PKEY_RSA_PSS,
        .sig_idx = QUIC_SIG_RSA,
    },
    {
        .sigalg = TLSEXT_SIGALG_RSA_PSS_RSAE_SHA512,
        .hash = NID_sha512,
        .hash_idx = QUIC_DIGEST_SHA512,
        .sig = EVP_PKEY_RSA_PSS,
        .sig_idx = QUIC_SIG_RSA,
    },
    {
        .sigalg = TLSEXT_SIGALG_RSA_PKCS1_SHA256,
        .hash = NID_sha256,
        .hash_idx = QUIC_DIGEST_SHA256,
        .sig = EVP_PKEY_RSA,
        .sig_idx = QUIC_SIG_RSA,
    },
    {
        .sigalg = TLSEXT_SIGALG_RSA_PKCS1_SHA384,
        .hash = NID_sha384,
        .hash_idx = QUIC_DIGEST_SHA384,
        .sig = EVP_PKEY_RSA,
        .sig_idx = QUIC_SIG_RSA,
    },
    {
        .sigalg = TLSEXT_SIGALG_RSA_PKCS1_SHA512,
        .hash = NID_sha512,
        .hash_idx = QUIC_DIGEST_SHA512,
        .sig = EVP_PKEY_RSA,
        .sig_idx = QUIC_SIG_RSA,
    },
    {
        .sigalg = TLSEXT_SIGALG_RSA_PKCS1_SHA1,
        .hash = NID_sha1,
        .hash_idx = QUIC_DIGEST_SHA512,
        .sig = EVP_PKEY_RSA,
        .sig_idx = QUIC_SIG_RSA,
        .sigandhash = NID_sha1WithRSAEncryption,
    },
};

#define SIG_ALG_LOOKUP_NUM QUIC_NELEM(sig_alg_lookup)

static const SigAlgLookup *TlsLookupSigAlg(uint16_t sigalg)
{
    const SigAlgLookup *lu = NULL;
    size_t i = 0;

    for (i = 0; i < SIG_ALG_LOOKUP_NUM; i++) {
        lu = &sig_alg_lookup[i];
        if (lu->sigalg == sigalg) {
            return lu;
        }
    }

    return NULL;
}

int TlsCopySigAlgs(WPacket *pkt, const uint16_t *psig, size_t psiglen)
{
    const SigAlgLookup *lu = NULL;
    size_t i = 0;

    for (i = 0; i < psiglen; i++, psig++) {
        lu = TlsLookupSigAlg(*psig);
        if (lu == NULL) {
            return -1;
        }

        if (WPacketPut2(pkt, *psig) < 0) {
            QUIC_LOG("Put session ID len failed\n");
            return -1;
        }
    }

    return 0;
}

#ifdef QUIC_TEST
size_t (*TlsTestGetPSigAlgs)(const uint16_t **psigs);
#endif

size_t TlsGetPSigAlgs(QUIC_TLS *tls, const uint16_t **psigs)
{
#ifdef QUIC_TEST
    if (TlsTestGetPSigAlgs) {
        return TlsTestGetPSigAlgs(psigs);
    }
#endif
    *psigs = tls_sigalgs;

    return SIG_ALG_DEF_NUM;
}

