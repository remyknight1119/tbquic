/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "cert.h"

#include <openssl/pem.h>

#include "quic_local.h"
#include "mem.h"
#include "cipher.h"
#include "common.h"
#include "log.h"

static volatile int quic_x509_store_ctx_idx = -1;

static const QuicCertLookup kQuicCertInfo[QUIC_PKEY_NUM] = {
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

bool QuicX509StoreCtxInit(void)
{
    quic_x509_store_ctx_idx = X509_STORE_CTX_get_ex_new_index(0,
                                    "QUIC TLS for verify callback",
                                    NULL, NULL, NULL);
    return quic_x509_store_ctx_idx >= 0;
}

int QuicGetExDataX509StoreCtxIdx(void)
{
    return quic_x509_store_ctx_idx;
}

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
    for (i = 0; i < QUIC_PKEY_NUM; i++) {
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

    if (cert->verify_store) {
        X509_STORE_up_ref(cert->verify_store);
        dst->verify_store = cert->verify_store;
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

    for (i = 0; i < QUIC_PKEY_NUM; i++) {
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
    X509_STORE_free(cert->verify_store);
    QuicCertClearCerts(cert);
    QuicMemFree(cert);
}

int QuicVerifyCertChain(QUIC *quic, STACK_OF(X509) *sk)
{
    X509_STORE_CTX *ctx = NULL;
    X509_STORE *verify_store = NULL;
    X509_VERIFY_PARAM *param = NULL;
    TLS *s = &quic->tls;
    X509 *x = NULL;
    int ret = 0;

    if ((sk == NULL) || (sk_X509_num(sk) == 0)) {
        return -1;
    }

    if (s->cert->verify_store) {
        verify_store = s->cert->verify_store;
    } else {
        verify_store = quic->ctx->cert_store;
    }

    ctx = X509_STORE_CTX_new();
    if (ctx == NULL) {
        return -1;
    }

    x = sk_X509_value(sk, 0);
    if (!X509_STORE_CTX_init(ctx, verify_store, x, sk)) {
        goto end;
    }

    if (!X509_STORE_CTX_set_ex_data(ctx, QuicGetExDataX509StoreCtxIdx(), s)) {
        goto end;
    }

    X509_STORE_CTX_set_default(ctx, s->server ? "quic_client" : "quic_server");

    param = X509_STORE_CTX_get0_param(ctx);
    X509_VERIFY_PARAM_set1(param, quic->param);
    if (s->verify_callback) {
        X509_STORE_CTX_set_verify_cb(ctx, s->verify_callback);
    }

    ret = X509_verify_cert(ctx);
    s->verify_result = X509_STORE_CTX_get_error(ctx);
    X509_VERIFY_PARAM_move_peername(quic->param, param);

end:
    X509_STORE_CTX_free(ctx);
    if (ret == 0) {
        return -1;
    }

    return 0;
}

const QuicCertLookup *QuicCertLookupByNid(int nid, size_t *index)
{
    const QuicCertLookup *lu = NULL;
    size_t i = 0;

    for (i = 0; i < QUIC_NELEM(kQuicCertInfo); i++) {
        lu = &kQuicCertInfo[i];
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

static int XnameCmp(const X509_NAME *a, const X509_NAME *b)
{
    unsigned char *abuf = NULL, *bbuf = NULL;
    int alen, blen, ret;

    /* X509_NAME_cmp() itself casts away constness in this way, so
     * assume it's safe:
     */
    alen = i2d_X509_NAME((X509_NAME *)a, &abuf);
    blen = i2d_X509_NAME((X509_NAME *)b, &bbuf);

    if (alen < 0 || blen < 0) {
        ret = -2;
    } else if (alen != blen) {
        ret = alen - blen;
    } else {/* alen == blen */
        ret = QuicMemCmp(abuf, bbuf, alen);
    }

    OPENSSL_free(abuf);
    OPENSSL_free(bbuf);

    return ret;
}

static unsigned long XnameHash(const X509_NAME *a)
{
    return X509_NAME_hash((X509_NAME *)a);
}

STACK_OF(X509_NAME) *QuicLoadClientCaFile(const char *file)
{
    BIO *in = NULL;
    X509 *x = NULL;
    X509_NAME *xn = NULL;
    LHASH_OF(X509_NAME) *name_hash = NULL;
    STACK_OF(X509_NAME) *ret = NULL;

    in = BIO_new(BIO_s_file());
    if (in == NULL) {
        goto err;
    }

    name_hash = lh_X509_NAME_new(XnameHash, XnameCmp);
    if (name_hash == NULL) {
        goto err;
    }

    if (!BIO_read_filename(in, file)) {
        goto err;
    }

    for (;;) {
        if (PEM_read_bio_X509(in, &x, NULL, NULL) == NULL) {
            break;
        }
        if (ret == NULL) {
            ret = sk_X509_NAME_new_null();
            if (ret == NULL) {
                goto err;
            }
        }
        if ((xn = X509_get_subject_name(x)) == NULL) {
            goto err;
        }
        /* check for duplicates */
        xn = X509_NAME_dup(xn);
        if (xn == NULL) {
            goto err;
        }
        if (lh_X509_NAME_retrieve(name_hash, xn) != NULL) {
            /* Duplicate. */
            X509_NAME_free(xn);
            xn = NULL;
        } else {
            lh_X509_NAME_insert(name_hash, xn);
            if (!sk_X509_NAME_push(ret, xn)) {
                goto err;
            }
        }
    }
    goto done;

err:
    X509_NAME_free(xn);
    sk_X509_NAME_pop_free(ret, X509_NAME_free);
    ret = NULL;
done:
    BIO_free(in);
    X509_free(x);
    lh_X509_NAME_free(name_hash);
    return ret;
}
