/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "cert.h"

#include "quic_local.h"
#include "mem.h"
#include "cipher.h"
#include "common.h"

static const QuicCertLookup QuicCertInfo[QUIC_PKEY_MAX] = {
    [QUIC_PKEY_RSA] = {
        .nid = EVP_PKEY_RSA,
        .mask = QUIC_A_ALG_MASK_RSA,
    },
    [QUIC_PKEY_RSA_PSS] = {
        .nid = EVP_PKEY_RSA_PSS,
        .mask = QUIC_A_ALG_MASK_RSA,
    },
    [QUIC_PKEY_ECC] = {
        .nid = EVP_PKEY_EC,
        .mask = QUIC_A_ALG_MASK_ECDRSA,
    },
    [QUIC_PKEY_ED25519] = {
        .nid = EVP_PKEY_ED25519,
        .mask = QUIC_A_ALG_MASK_ECDRSA,
    },
    [QUIC_PKEY_ED448] = {
        .nid = EVP_PKEY_ED448,
        .mask = QUIC_A_ALG_MASK_ECDRSA,
    },
};

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
    QuicCertPkey *cpk = NULL;
    QuicCertPkey *dpk = NULL;
    int i = 0;

    dst = QuicCertNew();
    if (dst == NULL) {
        return NULL;
    }

    if (QuicDataDupU16(&dst->conf_sigalgs, &cert->conf_sigalgs) < 0) {
        goto out;
    }

    dst->key = &dst->pkeys[cert->key - cert->pkeys];
    for (i = 0; i < QUIC_PKEY_MAX; i++) {
        cpk = &cert->pkeys[i];
        dpk = &dst->pkeys[i];
        if (cpk->x509 != NULL) {
            dpk->x509 = cpk->x509;
            X509_up_ref(dpk->x509);
        }
        if (cpk->privatekey != NULL) {
            dpk->privatekey = cpk->privatekey;
            EVP_PKEY_up_ref(dpk->privatekey);
        }
        if (cpk->chain) {
            dpk->chain = X509_chain_up_ref(cpk->chain);
            if (dpk->chain == NULL) {
                goto out;
            }
        }
    }

    return dst;
out:
    QuicCertFree(dst);
    return NULL;
}

static void QuicCertClearCerts(QuicCert *c)
{
    QuicCertPkey *cp = NULL;
    int i = 0;

    if (c == NULL) {
        return;
    }

    for (i = 0; i < QUIC_PKEY_MAX; i++) {
        cp = &c->pkeys[i];
        X509_free(cp->x509);
        cp->x509 = NULL;
        EVP_PKEY_free(cp->privatekey);
        cp->privatekey = NULL;
        sk_X509_pop_free(cp->chain, X509_free);
        cp->chain = NULL;
    }
}

void QuicCertFree(QuicCert *cert)
{
    if (cert == NULL) {
        return;
    }

    QuicDataFree(&cert->conf_sigalgs);
    QuicCertClearCerts(cert);
    QuicMemFree(cert);
}

int QuicVerifyCertChain(QUIC *quic, STACK_OF(X509) *sk)
{
    return 0;
}

const QuicCertLookup *QuicCertLookupByNid(int nid, size_t *index)
{
    const QuicCertLookup *lu = NULL;
    size_t i = 0;

    for (i = 0; i < QUIC_NELEM(QuicCertInfo); i++) {
        lu = &QuicCertInfo[i];
        if (lu->nid == nid) {
            if (index != NULL) {
                *index = i;
            }
            return lu;
        }
    }

    return NULL;
}

const QuicCertLookup *QuicCertLookupByPkey(const EVP_PKEY *pk, size_t *index)
{
    int nid = EVP_PKEY_id(pk);

    if (nid == NID_undef) {
        return NULL;
    }

    return QuicCertLookupByNid(nid, index);
}

int QuicSetPkey(QuicCert *c, EVP_PKEY *pkey)
{
    const QuicCertLookup *lu = NULL;
    EVP_PKEY *pktmp = NULL;
    RSA *rsa = NULL;
    size_t i = 0;

    lu = QuicCertLookupByPkey(pkey, &i);
    if (lu == NULL) {
        return -1;
    }

    if (c->pkeys[i].x509 != NULL) {
        pktmp = X509_get0_pubkey(c->pkeys[i].x509);
        if (pktmp == NULL) {
            return -1;
        }
        EVP_PKEY_copy_parameters(pktmp, pkey);
        /*
         * Don't check the public/private key, this is mostly for smart card
         */
        rsa = EVP_PKEY_get0_RSA(pkey);
        if (EVP_PKEY_id(pkey) != EVP_PKEY_RSA ||
                !(RSA_flags(rsa) & RSA_METHOD_FLAG_NO_CHECK)) {
            if (!X509_check_private_key(c->pkeys[i].x509, pkey)) {
                X509_free(c->pkeys[i].x509);
                c->pkeys[i].x509 = NULL;
                return -1;
            }
        }
    }

    EVP_PKEY_free(c->pkeys[i].privatekey);
    EVP_PKEY_up_ref(pkey);
    c->pkeys[i].privatekey = pkey;
    c->key = &c->pkeys[i];
    return 0;
}

int QuicSetCert(QuicCert *c, X509 *x)
{
    const QuicCertLookup *lu = NULL;
    EVP_PKEY *pkey = NULL;
    RSA *rsa = NULL;
    size_t i = 0;

    pkey = X509_get0_pubkey(x);
    if (pkey == NULL) {
        return -1;
    }

    lu = QuicCertLookupByPkey(pkey, &i);
    if (lu == NULL) {
        return -1;
    }

    if (i == QUIC_PKEY_ECC && !EC_KEY_can_sign(EVP_PKEY_get0_EC_KEY(pkey))) {
        return -1;
    }

    if (c->pkeys[i].privatekey != NULL) {
        /*
         * The return code from EVP_PKEY_copy_parameters is deliberately
         * ignored. Some EVP_PKEY types cannot do this.
         */
        EVP_PKEY_copy_parameters(pkey, c->pkeys[i].privatekey);

        /*
         * Don't check the public/private key, this is mostly for smart
         * cards.
         */
        rsa = EVP_PKEY_get0_RSA(c->pkeys[i].privatekey);
        if (EVP_PKEY_id(c->pkeys[i].privatekey) != EVP_PKEY_RSA
                || !(RSA_flags(rsa) & RSA_METHOD_FLAG_NO_CHECK)) {
            if (!X509_check_private_key(x, c->pkeys[i].privatekey)) {
                /*
                 * don't fail for a cert/key mismatch, just free current private
                 * key (when switching to a different cert & key, first this
                 * function should be used, then ssl_set_pkey
                 */
                EVP_PKEY_free(c->pkeys[i].privatekey);
                c->pkeys[i].privatekey = NULL;
            }
        }
    }

    X509_free(c->pkeys[i].x509);
    X509_up_ref(x);
    c->pkeys[i].x509 = x;
    c->key = &(c->pkeys[i]);

    return 0;
}

