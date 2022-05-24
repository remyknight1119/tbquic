/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "tls_lib.h"

#include <string.h>
#include <openssl/obj_mac.h>
#include <openssl/ec.h>
#include <openssl/kdf.h>
#include <openssl/hmac.h>
#include <tbquic/ec.h>
#include <tbquic/tls.h>

#include "tls.h"
#include "base.h"
#include "asn1.h"
#include "cert.h"
#include "crypto.h"
#include "quic_local.h"
#include "common.h"
#include "cipher.h"
#include "mem.h"
#include "log.h"

static const uint8_t default_zeros[EVP_MAX_MD_SIZE];
static const char servercontext[] = "TLS 1.3, server CertificateVerify";
static const char clientcontext[] = "TLS 1.3, client CertificateVerify";
const char tls_md_client_finish_label[] = "client finished";
const char tls_md_server_finish_label[] = "server finished";

/* The default curves */
static const uint16_t eccurves_default[] = {
    EC_NAMED_CURVE_X25519,
    EC_NAMED_CURVE_SECP256R1,
    EC_NAMED_CURVE_X448,
    EC_NAMED_CURVE_SECP521R1,
    EC_NAMED_CURVE_SECP384R1,
};

static const uint16_t ffdh_group[] = {
    TLS_SUPPORTED_GROUPS_FFDHE2048,
    TLS_SUPPORTED_GROUPS_FFDHE3072,
    TLS_SUPPORTED_GROUPS_FFDHE4096,
    TLS_SUPPORTED_GROUPS_FFDHE6144,
    TLS_SUPPORTED_GROUPS_FFDHE8192,
};

static const TlsGroupInfo group_nid_list[] = {
    [EC_NAMED_CURVE_SECT163K1] = {
        .nid = NID_sect163k1,
        .secbits = 80,
        .flags = TLS_CURVE_CHAR2,
    },
    [EC_NAMED_CURVE_SECT163R1] = {
        .nid = NID_sect163r1,
        .secbits = 80,
        .flags = TLS_CURVE_CHAR2,
    },
    [EC_NAMED_CURVE_SECT163R2] = {
        .nid = NID_sect163r2,
        .secbits = 80,
        .flags = TLS_CURVE_CHAR2,
    },
    [EC_NAMED_CURVE_SECT193R1] = {
        .nid = NID_sect193r1,
        .secbits = 80,
        .flags = TLS_CURVE_CHAR2,
    },
    [EC_NAMED_CURVE_SECT193R2] = {
        .nid = NID_sect193r2,
        .secbits = 80,
        .flags = TLS_CURVE_CHAR2,
    },
    [EC_NAMED_CURVE_SECT233K1] = {
        .nid = NID_sect233k1,
        .secbits = 112,
        .flags = TLS_CURVE_CHAR2,
    },
    [EC_NAMED_CURVE_SECT233R1] = {
        .nid = NID_sect233r1,
        .secbits = 112,
        .flags = TLS_CURVE_CHAR2,
    },
    [EC_NAMED_CURVE_SECT239K1] = {
        .nid = NID_sect239k1,
        .secbits = 112,
        .flags = TLS_CURVE_CHAR2,
    },
    [EC_NAMED_CURVE_SECT283K1] = {
        .nid = NID_sect283k1,
        .secbits = 128,
        .flags = TLS_CURVE_CHAR2,
    },
    [EC_NAMED_CURVE_SECT283R1] = {
        .nid = NID_sect283r1,
        .secbits = 128,
        .flags = TLS_CURVE_CHAR2,
    },
    [EC_NAMED_CURVE_SECT409K1] = {
        .nid = NID_sect409k1,
        .secbits = 192,
        .flags = TLS_CURVE_CHAR2,
    },
    [EC_NAMED_CURVE_SECT409R1] = {
        .nid = NID_sect409r1,
        .secbits = 192,
        .flags = TLS_CURVE_CHAR2,
    },
    [EC_NAMED_CURVE_SECT571K1] = {
        .nid = NID_sect571k1,
        .secbits = 256,
        .flags = TLS_CURVE_CHAR2,
    },
    [EC_NAMED_CURVE_SECT571R1] = {
        .nid = NID_sect571r1,
        .secbits = 256,
        .flags = TLS_CURVE_CHAR2,
    },
    [EC_NAMED_CURVE_SECP160K1] = {
        .nid = NID_secp160k1,
        .secbits = 80,
        .flags = TLS_CURVE_PRIME,
    },
    [EC_NAMED_CURVE_SECP160R1] = {
        .nid = NID_secp160r1,
        .secbits = 80,
        .flags = TLS_CURVE_PRIME,
    },
    [EC_NAMED_CURVE_SECP160R2] = {
        .nid = NID_secp160r2,
        .secbits = 80,
        .flags = TLS_CURVE_PRIME,
    },
    [EC_NAMED_CURVE_SECP192K1] = {
        .nid = NID_secp192k1,
        .secbits = 80,
        .flags = TLS_CURVE_PRIME,
    },
    [EC_NAMED_CURVE_SECP192R1] = {
        .nid = NID_X9_62_prime192v1,
        .secbits = 80,
        .flags = TLS_CURVE_PRIME,
    },
    [EC_NAMED_CURVE_SECP224K1] = {
        .nid = NID_secp224k1,
        .secbits = 112,
        .flags = TLS_CURVE_PRIME,
    },
    [EC_NAMED_CURVE_SECP224R1] = {
        .nid = NID_secp224r1,
        .secbits = 112,
        .flags = TLS_CURVE_PRIME,
    },
    [EC_NAMED_CURVE_SECP256K1] = {
        .nid = NID_secp256k1,
        .secbits = 128,
        .flags = TLS_CURVE_PRIME,
    },
    [EC_NAMED_CURVE_SECP256R1] = {
        .nid = NID_X9_62_prime256v1,
        .secbits = 128,
        .flags = TLS_CURVE_PRIME,
    },
    [EC_NAMED_CURVE_SECP384R1] = {
        .nid = NID_secp384r1,
        .secbits = 192,
        .flags = TLS_CURVE_PRIME,
    },
    [EC_NAMED_CURVE_SECP521R1] = {
        .nid = NID_secp521r1,
        .secbits = 256,
        .flags = TLS_CURVE_PRIME,
    },
    [EC_NAMED_CURVE_BRAINPOOLP256R1] = {
        .nid = NID_brainpoolP256r1,
        .secbits = 128,
        .flags = TLS_CURVE_PRIME,
    },
    [EC_NAMED_CURVE_BRAINPOOLP384R1] = {
        .nid = NID_brainpoolP384r1,
        .secbits = 192,
        .flags = TLS_CURVE_PRIME,
    },
    [EC_NAMED_CURVE_BRAINPOOL512R1] = {
        .nid = NID_brainpoolP512r1,
        .secbits = 256,
        .flags = TLS_CURVE_PRIME,
    },
    [EC_NAMED_CURVE_X25519] = {
        .nid = NID_X25519,
        .secbits = 128,
        .flags = TLS_CURVE_CUSTOM,
    },
    [EC_NAMED_CURVE_X448] = {
        .nid = NID_X448,
        .secbits = 224,
        .flags = TLS_CURVE_CUSTOM,
    },
};

int TlsCheckFfdhGroup(uint16_t id)
{
    size_t i = 0;

    for (i = 0; i < QUIC_NELEM(ffdh_group); i++) {
        if (id == ffdh_group[i]) {
            return 0;
        }
    }

    return -1;
}

const TlsGroupInfo *TlsGroupIdLookup(uint16_t id)
{
    if (id >= QUIC_NELEM(group_nid_list)) {
        return NULL;
    }

    return &group_nid_list[id];
}

void TlsGetPeerGroups(TLS *s, const uint16_t **pgroups, size_t *pgroupslen)
{
    QuicDataGetU16(&s->ext.peer_supported_groups, pgroups, pgroupslen);
}

int TlsCheckInList(TLS *s, uint16_t group_id, const uint16_t *groups,
                    size_t num_groups)
{
    size_t i = 0;
    uint16_t group = 0;

    if (groups == NULL || num_groups == 0) {
        return -1;
    }

    for (i = 0; i < num_groups; i++) {
        group = groups[i];
        if (group_id == group) {
            return 0;
        }
    }

    return -1;
}

/*
 * Set *pgroups to the supported groups list and *pgroupslen to
 * the number of groups supported.
 */
void TlsGetSupportedGroups(TLS *s, const uint16_t **pgroups, size_t *pgroupslen)
{
    if (QuicDataIsEmpty(&s->ext.supported_groups)) {
        *pgroups = eccurves_default;
        *pgroupslen = QUIC_NELEM(eccurves_default);
    } else {
        QuicDataGetU16(&s->ext.supported_groups, pgroups, pgroupslen);
    }
}

int TlsSetSupportedGroups(uint16_t **pext, size_t *pextlen, uint16_t *groups,
                            size_t ngroups)
{
    const TlsGroupInfo *g_info = NULL;
    uint16_t *glist = NULL;
    uint16_t id = 0;
    size_t i = 0;

    if (ngroups == 0) {
        return -1;
    }

    for (i = 0; i < ngroups; i++) {
        id = groups[i];
        g_info = TlsGroupIdLookup(id);
        if (g_info != NULL) {
            if (g_info->secbits == 0) {
                return -1;
            }
        } else if (TlsCheckFfdhGroup(id) < 0) {
            return -1;
        }
    }

    glist = QuicMemDup(groups, ngroups * sizeof(*groups));
    if (glist == NULL) {
        return -1;
    }

    QuicMemFree(*pext);
    *pext = glist;
    *pextlen = ngroups;
    return 0;
}

/* Generate a private key from parameters */
EVP_PKEY *TlsGeneratePkey(EVP_PKEY *pm)
{
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pkey = NULL;

    if (pm == NULL) {
        return NULL;
    }

    pctx = EVP_PKEY_CTX_new(pm, NULL);
    if (pctx == NULL) {
        goto err;
    }

    if (EVP_PKEY_keygen_init(pctx) <= 0) {
        goto err;
    }

    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }

err:
    EVP_PKEY_CTX_free(pctx);
    return pkey;
}

EVP_PKEY *TlsGeneratePkeyGroup(TLS *tls, uint16_t id)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    const TlsGroupInfo *g_info = NULL;
    uint16_t gtype = 0;

    g_info = TlsGroupIdLookup(id);
    if (g_info == NULL) {
        return NULL;
    }
 
    gtype = g_info->flags & TLS_CURVE_TYPE;
    if (gtype == TLS_CURVE_CUSTOM) {
        pctx = EVP_PKEY_CTX_new_id(g_info->nid, NULL);
    } else {
        pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    }

    if (pctx == NULL) {
        return NULL;
    }

    if (EVP_PKEY_keygen_init(pctx) <= 0) {
        goto out;
    }

    if (gtype != TLS_CURVE_CUSTOM &&
            EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, g_info->nid) <= 0) {
        goto out;
    }

    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }

out:
    EVP_PKEY_CTX_free(pctx);
    return pkey;
}

/*
 * Generate parameters from a group ID
 */
EVP_PKEY *TlsGenerateParamGroup(uint16_t id)
{
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pkey = NULL;
    const TlsGroupInfo *g_info = NULL;
    uint16_t gtype = 0;

    g_info = TlsGroupIdLookup(id);
    if (g_info == NULL) {
        return NULL;
    }
 
    gtype = g_info->flags & TLS_CURVE_TYPE;
    if (gtype == TLS_CURVE_CUSTOM) {
        pkey = EVP_PKEY_new();
        if (pkey != NULL && EVP_PKEY_set_type(pkey, g_info->nid)) {
            return pkey;
        }
        EVP_PKEY_free(pkey);
        return NULL;
    }

    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (pctx == NULL) {
        goto err;
    }

    if (EVP_PKEY_paramgen_init(pctx) <= 0) {
        goto err;
    }

    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, g_info->nid) <= 0) {
        goto err;
    }

    if (EVP_PKEY_paramgen(pctx, &pkey) <= 0) {
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }

 err:
    EVP_PKEY_CTX_free(pctx);
    return pkey;
}

const EVP_MD *TlsHandshakeMd(TLS *tls)
{
    if (tls->handshake_cipher == NULL) {
        return NULL;
    }

    return QuicMd(tls->handshake_cipher->digest);
}

int TlsDigestCachedRecords(TLS *tls)
{
    const EVP_MD *md = NULL;
    QUIC_BUFFER *buffer = NULL;
    size_t hdatalen = 0;
    void *hdata = NULL;

    if (tls->handshake_dgst != NULL) {
        return 0;
    }

    buffer = &tls->buffer;
    hdatalen = tls->handshake_msg_len + QuicBufGetReserved(buffer);
    if (hdatalen == 0) {
        return -1;
    }

    hdata = QuicBufHead(buffer);
    //QuicPrint(hdata, hdatalen);
    tls->handshake_dgst = EVP_MD_CTX_new();
    if (tls->handshake_dgst == NULL) {
        return -1;
    }

    md = TlsHandshakeMd(tls);
    if (md == NULL) {
        return -1;
    }
    
    if (!EVP_DigestInit_ex(tls->handshake_dgst, md, NULL)) {
        return -1;
    }
    
    if (!EVP_DigestUpdate(tls->handshake_dgst, hdata, hdatalen)) {
        return -1;
    }

    return 0;
}

int TlsFinishMac(TLS *tls, const uint8_t *buf, size_t len)
{
    if (tls->handshake_dgst == NULL) {
        return 0;
    }

    if (EVP_DigestUpdate(tls->handshake_dgst, buf, len) == 0) {
        return -1;
    }

    return 0;
}

int TlsHandshakeHash(TLS *tls, uint8_t *hash, size_t outlen, size_t *hash_size)
{
    EVP_MD_CTX *ctx = NULL;
    EVP_MD_CTX *hdgst = tls->handshake_dgst;
    int hashlen = 0;
    int ret = -1;

    if (hdgst == NULL) {
        QUIC_LOG("Hdgst is NULL\n");
        return -1;
    }

    hashlen = EVP_MD_CTX_size(hdgst);
    if (hashlen < 0 || (size_t)hashlen > outlen) {
        QUIC_LOG("Hash len invalid(%d, %lu)\n", hashlen, outlen);
        return -1;
    }

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        return -1;
    }

    if (!EVP_MD_CTX_copy_ex(ctx, hdgst)) {
        goto err;
    }
    
    if (EVP_DigestFinal_ex(ctx, hash, NULL) <= 0) {
        goto err;
    }

    if (hash_size != NULL) {
        *hash_size = hashlen;
    }
    ret = 0;

 err:
    EVP_MD_CTX_free(ctx);
    return ret;
}

int TlsDeriveSecrets(TLS *tls, const EVP_MD *md, const uint8_t *in_secret,
                        const uint8_t *label, size_t label_len,
                        const uint8_t *hash, uint8_t *out)
{
    int len = 0;

    len = EVP_MD_size(md);
    if (len <= 0) {
        return -1;
    }

    return TLS13HkdfExpandLabel(md, in_secret, len, label, label_len, hash,
                                len, out, len);
}

int TlsGenerateSecret(const EVP_MD *md, const uint8_t *prevsecret,
        const uint8_t *insecret, size_t insecretlen,
        uint8_t *outsecret)
{
    EVP_PKEY_CTX *pctx = NULL;
    EVP_MD_CTX *mctx = NULL;
    uint8_t hash[EVP_MAX_MD_SIZE] = {};
    uint8_t preextractsec[EVP_MAX_MD_SIZE] = {};
    static const char derived_secret_label[] = "derived";
    size_t mdlen = 0;
    size_t prevsecretlen = 0;
    int mdleni = 0;
    int retval = 0;
    int ret = -1;

    if (md == NULL) {
        return -1;
    }

    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (pctx == NULL) {
        return -1;
    }

    mdleni = EVP_MD_size(md);
    if (mdleni < 0) {
        return -1;
    }

    mdlen = (size_t)mdleni;
    if (insecret == NULL) {
        insecret = default_zeros;
        insecretlen = mdlen;
    }

    if (prevsecret == NULL) {
        prevsecret = default_zeros;
        prevsecretlen = 0;
    } else {
        mctx = EVP_MD_CTX_new();
        /* The pre-extract derive step uses a hash of no messages */
        if (mctx == NULL) {
            goto out;
        }
        
        if (EVP_DigestInit_ex(mctx, md, NULL) <= 0) {
            EVP_MD_CTX_free(mctx);
            goto out;
        }
        
        retval = EVP_DigestFinal_ex(mctx, hash, NULL);
        EVP_MD_CTX_free(mctx);
        if (retval <= 0) {
            goto out;
        }

        /* Generate the pre-extract secret */
        if (TLS13HkdfExpandLabel(md, prevsecret, mdlen, 
                    (const uint8_t *)derived_secret_label,
                    sizeof(derived_secret_label) - 1, hash,
                    mdlen, preextractsec, mdlen)) {
            goto out;
        }

        prevsecret = preextractsec;
        prevsecretlen = mdlen;
    }

    if (EVP_PKEY_derive_init(pctx) <= 0) {
        goto out;
    }
    
    if (EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY) <= 0) {
        goto out;
    }
    
    if (EVP_PKEY_CTX_set_hkdf_md(pctx, md) <= 0) {
        goto out;
    }

    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, insecret, insecretlen) <= 0) {
        goto out;
    }

    if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, prevsecret, prevsecretlen) <= 0) {
        goto out;
    }

    if (EVP_PKEY_derive(pctx, outsecret, &mdlen) <= 0) {
        goto out;
    }

    ret = 0;

out:
    EVP_PKEY_CTX_free(pctx);
    return ret;
}

#ifdef QUIC_TEST
void (*QuicHandshakeSecretHook)(uint8_t *secret);
#endif
int TlsKeyDerive(TLS *s, EVP_PKEY *privkey, EVP_PKEY *pubkey)
{
    EVP_PKEY_CTX *pctx = NULL;
    const EVP_MD *md = NULL;
    unsigned char *pms = NULL;
    size_t pmslen = 0;
    int ret = -1;

    if (privkey == NULL || pubkey == NULL) {
        return -1;
    }

    pctx = EVP_PKEY_CTX_new(privkey, NULL);
    if (EVP_PKEY_derive_init(pctx) <= 0) {
        goto out;
    }

    if (EVP_PKEY_derive_set_peer(pctx, pubkey) <= 0) {
        goto out;
    }

    if (EVP_PKEY_derive(pctx, NULL, &pmslen) <= 0) {
        goto out;
    }

    pms = QuicMemMalloc(pmslen);
    if (pms == NULL) {
        goto out;
    }

    if (EVP_PKEY_derive(pctx, pms, &pmslen) <= 0) {
        goto out;
    }

    md = TlsHandshakeMd(s);
    if (!s->hit) {
        ret = TlsGenerateSecret(md, NULL, NULL, 0, s->early_secret);
        if (ret < 0) {
            goto out;
        }
    }

    ret = TlsGenerateSecret(md, s->early_secret, pms, pmslen,
                            s->handshake_secret);
#ifdef QUIC_TEST
    if (QuicHandshakeSecretHook) {
        QuicHandshakeSecretHook(s->handshake_secret);
    }
#endif
out:
    QuicMemFree(pms);
    EVP_PKEY_CTX_free(pctx);
    return ret;
}

int TlsDeriveFinishedKey(TLS *s, const EVP_MD *md, const uint8_t *secret,
                        uint8_t *finsecret, size_t finsecret_len)
{
    static const uint8_t finishedlabel[] = "finished";

    return TLS13HkdfExpandLabel(md, secret, EVP_MD_size(md), finishedlabel,
                        sizeof(finishedlabel) - 1, NULL, 0, finsecret,
                        finsecret_len);
}

int TlsGenerateMasterSecret(TLS *s, uint8_t *out, uint8_t *prev,
                                 size_t *secret_size)
{
    const EVP_MD *md = TlsHandshakeMd(s);

    *secret_size = EVP_MD_size(md);
    return TlsGenerateSecret(md, prev, NULL, 0, out);
}

int TlsCheckPeerSigAlg(TLS *tls, uint16_t sig, EVP_PKEY *pkey)
{
    const SigAlgLookup *lu = NULL;

    lu = TlsLookupSigAlg(sig);
    if (lu == NULL) {
        return -1;
    }

    tls->peer_sigalg = lu;

    return 0;
}

static size_t
TlsGetSharedSigAlgsInfo(const SigAlgLookup **shared, const QUIC_DATA *sigalg1,
                                    const QUIC_DATA *sigalg2)
{
    const SigAlgLookup *lu = NULL;
    size_t i = 0;
    size_t j = 0;
    size_t matched = 0;
    uint16_t sigalg = 0;

    for (i = 0; i < sigalg1->len; i++) {
        sigalg = sigalg1->ptr_u16[i];
        lu = TlsLookupSigAlg(sigalg);
        if (lu == NULL) {
            continue;
        }
        for (j = 0; j < sigalg2->len; j++) {
            if (sigalg == sigalg2->ptr_u16[j]) {
                if (shared != NULL) {
                    *(shared + matched) = lu;
                }
                matched++;
            }
        }
    }

    return matched;
}

int TlsGetSharedSigAlgs(TLS *s, const QUIC_DATA *sigalg1,
                            const QUIC_DATA *sigalg2)
{
    const SigAlgLookup **salgs = NULL;
    size_t matched = 0;

    if (QuicDataIsEmpty(sigalg1) || QuicDataIsEmpty(sigalg2)) {
        return -1;
    }

    matched = TlsGetSharedSigAlgsInfo(NULL, sigalg1, sigalg2);
    if (matched == 0) {
        return -1;
    }

    salgs = QuicMemMalloc(matched * sizeof(*salgs));
    if (salgs == NULL) {
        return -1;
    }

    s->shared_sigalgs_len = TlsGetSharedSigAlgsInfo(salgs, sigalg1, sigalg2);
    s->shared_sigalgs = salgs;
    return 0;
}

int TlsSetServerSigAlgs(TLS *s)
{
    const uint16_t *salgs = NULL;
    QUIC_DATA sigalgs = {};

    QuicMemFree(s->shared_sigalgs);
    s->shared_sigalgs_len = 0;

    if (QuicDataIsEmpty(&s->ext.peer_sigalgs)) {
    }

    sigalgs.len = TlsGetPSigAlgs(s, &salgs);
    sigalgs.ptr_u16 = (void *)salgs;

    return TlsGetSharedSigAlgs(s, &s->ext.peer_sigalgs, &sigalgs);
}

QUIC_SESSION *TlsGetSession(TLS *s)
{
    QUIC *quic = QuicTlsTrans(s);

    return quic->session;
}

static bool TlsHasCert(const TLS *s, int idx)
{
    if (idx < 0 || idx >= QUIC_PKEY_NUM) {
        return false;
    }

    return (s->cert->pkeys[idx].x509 != NULL &&
            s->cert->pkeys[idx].privatekey != NULL);
}

static bool TlsCheckCertUsable(TLS *s, const SigAlgLookup *sig, X509 *x,
                                EVP_PKEY *pkey)
{
    size_t i = 0;
    int default_mdnid = 0;

    if (EVP_PKEY_get_default_digest_nid(pkey, &default_mdnid) == 2 &&
            sig->hash != default_mdnid) {
        QUIC_LOG("Default digest not match\n");
        return false;
    }

    if (!QuicDataIsEmpty(&s->tmp.peer_cert_sigalgs)) {
        for (i = 0; i < s->tmp.peer_cert_sigalgs.len; i++) {
        }
    }

    return true;
}

static bool TlsHasUsableCert(TLS *s, const SigAlgLookup *sig)
{
    int idx = sig->sig_idx;

    if (TlsHasCert(s, idx) == false) {
        return false;
    }

    return TlsCheckCertUsable(s, sig, s->cert->pkeys[idx].x509,
            s->cert->pkeys[idx].privatekey);
}

static bool
TlsIsUsableCert(TLS *s, const SigAlgLookup *sig, X509 *x, EVP_PKEY *pkey)
{
    size_t idx = 0;

    if (QuicCertLookupByPkey(pkey, &idx) == NULL) {
        return false;
    }

    if (idx != sig->sig_idx) {
        return false;
    }

    return TlsCheckCertUsable(s, sig, x, pkey);
}

const EVP_MD *TlsLookupMd(const SigAlgLookup *lu)
{
    if (lu == NULL) {
        return NULL;
    }

    if (lu->hash == NID_undef) {
        return NULL;
    }

    return QuicMd(lu->hash_idx);
}

/*
* Check if key is large enough to generate RSA-PSS signature.
*
* The key must greater than or equal to 2 * hash length + 2.
* SHA512 has a hash length of 64 bytes, which is incompatible
* with a 128 byte (1024 bit) key.
*/
#define RSA_PSS_MINIMUM_KEY_SIZE(md) (2 * EVP_MD_size(md) + 2)
static int TlsRsaPssCheckMinKeySize(const RSA *rsa, const SigAlgLookup *lu)
{
    const EVP_MD *md = NULL;

    if (rsa == NULL) {
        return -1;
    }

    md = TlsLookupMd(lu);
    if (md == NULL) {
        return -1;
    }

    if (RSA_size(rsa) < RSA_PSS_MINIMUM_KEY_SIZE(md)) {
        return -1;
    }

    return 0;
}

const SigAlgLookup *TlsFindSigAlg(TLS *s, X509 *x, EVP_PKEY *pkey)
{
    const SigAlgLookup *lu = NULL;
    EVP_PKEY *tmppkey = NULL;
    EC_KEY *ec = NULL;
    size_t i = 0;
    int curve = -1;

    for (i = 0; i < s->shared_sigalgs_len; i++) {
        lu = s->shared_sigalgs[i];
        if (TlsLookupMd(lu) == NULL) {
            continue;
        }

        if (pkey == NULL && TlsHasUsableCert(s, lu) == false) {
            continue;
        }

        if (pkey != NULL && TlsIsUsableCert(s, lu, x, pkey) == false) {
            continue;
        }

        tmppkey = (pkey != NULL) ? pkey
                                 : s->cert->pkeys[lu->sig_idx].privatekey;
        if (lu->sig == EVP_PKEY_EC) {
            if (curve == -1) {
                ec = EVP_PKEY_get0_EC_KEY(tmppkey);
                curve = EC_GROUP_get_curve_name(EC_KEY_get0_group(ec));
            }

            if (lu->curve != NID_undef && curve != lu->curve) {
                continue;
            }
        } else if (lu->sig == EVP_PKEY_RSA_PSS) {
            /* validate that key is large enough for the signature algorithm */
            if (TlsRsaPssCheckMinKeySize(EVP_PKEY_get0(tmppkey), lu) < 0) {
                continue;
            }
        }

        break;
    }

    if (i == s->shared_sigalgs_len) {
        return NULL;
    }

    return lu;
}

int TlsChooseSigalg(TLS *s)
{
    const SigAlgLookup *lu = NULL;

    lu = TlsFindSigAlg(s, NULL, NULL);
    if (lu == NULL) {
        return -1;
    }

    s->tmp.cert = &s->cert->pkeys[lu->sig_idx];
    s->cert->key = s->tmp.cert;
    s->tmp.sigalg = lu;

    return 0;
}

/*
 * Size of the to-be-signed TLS13 data, without the hash size itself:
 * 64 bytes of value 32, 33 context bytes, 1 byte separator
 */
#define TLS_TBS_START_SIZE          64
#define TLS_TBS_PREAMBLE_SIZE       (TLS_TBS_START_SIZE + sizeof(servercontext))

int TlsGetCertVerifyData(TLS *s, uint8_t *tbs, void **hdata, size_t *hdatalen)
{
    QUIC *quic = QuicTlsTrans(s);
    QUIC_STATEM *st = &quic->statem;
    int state = 0;
    size_t hashlen;

    /* Set the first 64 bytes of to-be-signed data to octet 32 */
    memset(tbs, 32, TLS_TBS_START_SIZE);

    state = st->state;

    /* This copies the 33 bytes of context plus the 0 separator byte */
    if (state == QUIC_STATEM_TLS_ST_CR_CERT_VERIFY ||
            state == QUIC_STATEM_TLS_ST_SW_CERT_VERIFY) {
        strcpy((char *)tbs + TLS_TBS_START_SIZE, servercontext);
    } else {
        strcpy((char *)tbs + TLS_TBS_START_SIZE, clientcontext);
    }
    /*
     * If we're currently reading then we need to use the saved handshake
     * hash value. We can't use the current handshake hash state because
     * that includes the CertVerify itself.
     */
    if (state == QUIC_STATEM_TLS_ST_CR_CERT_VERIFY
            || state  == QUIC_STATEM_TLS_ST_SR_CERT_VERIFY) {
        memcpy(tbs + TLS_TBS_PREAMBLE_SIZE, s->cert_verify_hash,
                s->cert_verify_hash_len);
        hashlen = s->cert_verify_hash_len;
    } else if (TlsHandshakeHash(s, tbs + TLS_TBS_PREAMBLE_SIZE, EVP_MAX_MD_SIZE,
                &hashlen) < 0) {
        return -1;
    }

    *hdata = tbs;
    *hdatalen = TLS_TBS_PREAMBLE_SIZE + hashlen;

    return 0;
}

int TlsDoCertVerify(TLS *s, const uint8_t *data, size_t len, EVP_PKEY *pkey,
                        const EVP_MD *md)
{
    EVP_MD_CTX *mctx = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    void *hdata = NULL;
    uint8_t tbs[TLS_TBS_PREAMBLE_SIZE + EVP_MAX_MD_SIZE] = {};
    size_t hdatalen = 0;
    int ret = -1;

    mctx = EVP_MD_CTX_new();
    if (mctx == NULL) {
        return -1;
    }

    if (TlsGetCertVerifyData(s, tbs, &hdata, &hdatalen) < 0) {
        goto err;
    }

    if (EVP_DigestVerifyInit(mctx, &pctx, md, NULL, pkey) <= 0) {
        goto err;
    }

    if (TLS_USE_PSS(s)) {
        if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) <= 0
            || EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx,
                                                RSA_PSS_SALTLEN_DIGEST) <= 0) {
            goto err;
        }
    }

    if (EVP_DigestVerify(mctx, data, len, hdata, hdatalen) <= 0) {
        QUIC_LOG("Verify Failed\n");
        goto err;
    }

    ret = 0;
err:
    EVP_MD_CTX_free(mctx);
    return ret;
}

int TlsConstructCertVerify(TLS *s, WPacket *pkt)
{
    const SigAlgLookup *lu = s->tmp.sigalg;
    EVP_PKEY *pkey = NULL;
    const EVP_MD *md = NULL;
    EVP_MD_CTX *mctx = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    void *hdata = NULL;
    uint8_t *sig = NULL;
    uint8_t tbs[TLS_TBS_PREAMBLE_SIZE + EVP_MAX_MD_SIZE] = {};
    size_t hdatalen = 0;
    size_t siglen = 0;
    QuicFlowReturn ret = QUIC_FLOW_RET_ERROR;

    if (lu == NULL || s->tmp.cert == NULL) {
        return -1;
    }

    pkey = s->tmp.cert->privatekey;
    if (pkey == NULL) {
        return -1;
    }

    md = TlsLookupMd(lu);
    if (md == NULL) {
        return -1;
    }

    mctx = EVP_MD_CTX_new();
    if (mctx == NULL) {
        return -1;
    }

    if (TlsGetCertVerifyData(s, tbs, &hdata, &hdatalen) < 0) {
        goto err;
    }

    if (WPacketPut2(pkt, lu->sigalg) < 0) {
        goto err;
    }

    siglen = EVP_PKEY_size(pkey);
    sig = QuicMemMalloc(siglen);
    if (sig == NULL) {
        goto err;
    }

    if (EVP_DigestSignInit(mctx, &pctx, md, NULL, pkey) <= 0) {
        goto err;
    }

    if (lu->sig == EVP_PKEY_RSA_PSS) {
        if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) <= 0) {
            goto err;
        }

        if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx,
                    RSA_PSS_SALTLEN_DIGEST) <= 0) {
            goto err;
        }
    }

    if (EVP_DigestSign(mctx, sig, &siglen, hdata, hdatalen) <= 0) {
        goto err;
    }

    if (WPacketSubMemcpyU16(pkt, sig, siglen) < 0) {
        goto err;
    }

    ret = 0;
err:
    QuicMemFree(sig);
    EVP_MD_CTX_free(mctx);
    return ret;
}


#ifdef QUIC_TEST
void (*QuicTlsFinalFinishMacHashHook)(uint8_t *hash, size_t len);
#endif
size_t TlsFinalFinishMac(TLS *s, const char *str, size_t slen, uint8_t *out)
{
    const EVP_MD *md = TlsHandshakeMd(s);
    EVP_PKEY *key = NULL;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    uint8_t hash[EVP_MAX_MD_SIZE];
    size_t hashlen = 0;
    size_t ret = 0;

    if (TlsHandshakeHash(s, hash, sizeof(hash), &hashlen) < 0) {
        QUIC_LOG("Handshake Hash failed\n");
        goto err;
    }

#ifdef QUIC_TEST
    if (QuicTlsFinalFinishMacHashHook) {
        QuicTlsFinalFinishMacHashHook(hash, hashlen);
    }
#endif
    if (str == tls_md_server_finish_label) {
        key = EVP_PKEY_new_raw_private_key(EVP_PKEY_HMAC, NULL,
                                           s->server_finished_secret, hashlen);
    } else if (str == tls_md_client_finish_label) {
        key = EVP_PKEY_new_raw_private_key(EVP_PKEY_HMAC, NULL,
                                           s->client_finished_secret, hashlen);
    } else {
        QUIC_LOG("Unknown label!\n");
        goto err;
    }

    if (key == NULL
            || ctx == NULL
            || EVP_DigestSignInit(ctx, NULL, md, NULL, key) <= 0
            || EVP_DigestSignUpdate(ctx, hash, hashlen) <= 0
            || EVP_DigestSignFinal(ctx, out, &hashlen) <= 0) {
        QUIC_LOG("Get Digest failed!\n");
        goto err;
    }

    ret = hashlen;
 err:
    EVP_PKEY_free(key);
    EVP_MD_CTX_free(ctx);
    return ret;
}

int TlsTakeMac(TLS *s)
{
    const char *sender;
    size_t slen;

    if (!s->server) {
        sender = tls_md_server_finish_label;
        slen = TLS_MD_SERVER_FINISH_LABEL_LEN;
    } else {
        sender = tls_md_client_finish_label;
        slen = TLS_MD_CLIENT_FINISH_LABEL_LEN;
    }

    s->peer_finish_md_len = TlsFinalFinishMac(s, sender, slen,
                                s->peer_finish_md);
    if (s->peer_finish_md_len == 0) {
        return -1;
    }

    return 0;
}

int TlsPskDoBinder(TLS *s, const EVP_MD *md, uint8_t *msgstart,
                    size_t binder_offset, uint8_t *binder_in,
                    uint8_t *binder_out, QuicSessionTicket *t)
{
    EVP_MD_CTX *mctx = NULL;
    EVP_PKEY *mackey = NULL;
    static const uint8_t resumption_label[] = "res binder";
    uint8_t hash[EVP_MAX_MD_SIZE] = {};
    uint8_t tmpbinder[EVP_MAX_MD_SIZE] = {};
    uint8_t binderkey[EVP_MAX_MD_SIZE] = {};
    uint8_t finishedkey[EVP_MAX_MD_SIZE] = {};
    size_t hashsize = EVP_MD_size(md);
    size_t bindersize = 0;
    int ret = -1;
    
    if (TlsGenerateSecret(md, NULL, t->master_key, t->master_key_length,
                            s->early_secret) < 0) {
        QUIC_LOG("Generate Secret failed\n");
        return -1;
    }

    mctx = EVP_MD_CTX_new();
    if (mctx == NULL) {
        return -1;
    }

    if (EVP_DigestInit_ex(mctx, md, NULL) <= 0) {
        QUIC_LOG("Init Digest failed\n");
        goto err;
    }

    if (EVP_DigestFinal_ex(mctx, hash, NULL) <= 0) {
        QUIC_LOG("Digest final failed\n");
        goto err;
    }

    if (TLS13HkdfExpandLabel(md, s->early_secret, hashsize, resumption_label,
                        sizeof(resumption_label) - 1, hash, hashsize, binderkey,
                        hashsize) < 0) {
        QUIC_LOG("TLS HKDF Expand Label failed\n");
        goto err;
    }

    if (TlsDeriveFinishedKey(s, md, binderkey, finishedkey, hashsize) < 0) {
        QUIC_LOG("TLS derive finished key failed\n");
        goto err;
    }

    if (EVP_DigestInit_ex(mctx, md, NULL) <= 0) {
        QUIC_LOG("Init Digest failed\n");
        goto err;
    }

    if (EVP_DigestUpdate(mctx, msgstart, binder_offset) <= 0) {
        QUIC_LOG("Digest update failed\n");
        goto err;
    }

    if (EVP_DigestFinal_ex(mctx, hash, NULL) <= 0) {
        QUIC_LOG("Digest final failed\n");
        goto err;
    }

    mackey = EVP_PKEY_new_raw_private_key(EVP_PKEY_HMAC, NULL, finishedkey,
                                            hashsize);
    if (mackey == NULL) {
        QUIC_LOG("New PKEY failed\n");
        goto err;
    }

    if (EVP_DigestSignInit(mctx, NULL, md, NULL, mackey) <= 0) {
        QUIC_LOG("Digest sign init failed\n");
        goto err;
    }

    if (EVP_DigestSignUpdate(mctx, hash, hashsize) <= 0) {
        QUIC_LOG("Digest sign update failed\n");
        goto err;
    }

    if (binder_out == NULL) {
        binder_out = tmpbinder;
    }

    bindersize = hashsize;
    if (EVP_DigestSignFinal(mctx, binder_out, &bindersize) <= 0 ||
            bindersize != hashsize) {
        QUIC_LOG("Digest sign final failed\n");
        goto err;
    }

    if (binder_in != NULL) {
        if (QuicMemCmp(binder_in, binder_out, hashsize) != 0) {
            QUIC_LOG("Compare binder failed\n");
            goto err;
        }
    }

    ret = 0;

err:
    EVP_PKEY_free(mackey);
    EVP_MD_CTX_free(mctx);
    return ret;
}

int TlsDecryptTicket(TLS *s, const uint8_t *etick, size_t eticklen,
                        QUIC_SESSION **sess)
{
    TlsTicketKey *tk = &s->ext.ticket_key;
    HMAC_CTX *hctx = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    const uint8_t *p = NULL;
    uint8_t *sdec = NULL;
    unsigned char tick_hmac[EVP_MAX_MD_SIZE];
    size_t mlen = 0;
    int iv_len = 0;
    int declen = 0;
    int slen = 0;
    int ret = -1;

    if (eticklen < TLSEXT_KEYNAME_LENGTH + EVP_MAX_IV_LENGTH) {
        return -1;
    }

    hctx = HMAC_CTX_new();
    if (hctx == NULL) {
        goto end;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        goto end;
    }

    if (QuicMemCmp(etick, tk->tick_key_name, TLSEXT_KEYNAME_LENGTH) != 0) {
        QUIC_LOG("Tick Key Name invalid\n");
        goto end;
    }

    if (!HMAC_Init_ex(hctx, tk->tick_hmac_key, sizeof(tk->tick_hmac_key),
                EVP_sha256(), NULL)) {
        goto end;
    }

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, tk->tick_aes_key,
                etick + TLSEXT_KEYNAME_LENGTH)) {
        goto end;
    }

    mlen = HMAC_size(hctx);
    if (mlen == 0) {
        goto end;
    }

    iv_len = EVP_CIPHER_CTX_iv_length(ctx);
    if (eticklen <= TLSEXT_KEYNAME_LENGTH + iv_len + mlen) {
        goto end;
    }

    eticklen -= mlen;
    if (HMAC_Update(hctx, etick, eticklen) <= 0) {
        QUIC_LOG("HMAC update failed\n");
        goto end;
    }

    if (HMAC_Final(hctx, tick_hmac, NULL) <= 0) {
        QUIC_LOG("HMAC final failed\n");
        goto end;
    }

    if (QuicMemCmp(tick_hmac, etick + eticklen, mlen) != 0) {
        QUIC_LOG("Compare HMAC failed\n");
        goto end;
    }

    p = etick + TLSEXT_KEYNAME_LENGTH + iv_len;
    eticklen -= TLSEXT_KEYNAME_LENGTH + iv_len;
    sdec = QuicMemMalloc(eticklen);
    if (sdec == NULL) {
        goto end;
    }

    if (EVP_DecryptUpdate(ctx, sdec, &slen, p, (int)eticklen) <= 0) {
        QUIC_LOG("Decrypt update failed\n");
        QuicMemFree(sdec);
        goto end;
    }

    if (EVP_DecryptFinal(ctx, sdec + slen, &declen) <= 0) {
        QUIC_LOG("Decrypt final failed\n");
        QuicMemFree(sdec);
        goto end;
    }

    slen += declen;
    p = sdec;

    *sess = d2iQuicSession(&p, slen);
    if (*sess == NULL) {
        QUIC_LOG("d2i Session failed\n");
        goto end;
    }

    QuicMemFree(sdec);

    ret = 0;
end:
    EVP_CIPHER_CTX_free(ctx);
    HMAC_CTX_free(hctx);

    return ret;
}

