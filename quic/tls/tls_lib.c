/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "tls_lib.h"

#include <openssl/obj_mac.h>
#include <openssl/ec.h>
#include <openssl/kdf.h>
#include <tbquic/ec.h>
#include <tbquic/tls.h>

#include "tls.h"
#include "base.h"
#include "crypto.h"
#include "common.h"
#include "cipher.h"
#include "mem.h"
#include "log.h"

static const uint8_t default_zeros[EVP_MAX_MD_SIZE];

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

/*
 * Set *pgroups to the supported groups list and *pgroupslen to
 * the number of groups supported.
 */
void TlsGetSupportedGroups(TLS *tls, const uint16_t **pgroups,
                               size_t *pgroupslen)
{
    if (QuicDataIsEmpty(&tls->ext.supported_groups)) {
        *pgroups = eccurves_default;
        *pgroupslen = QUIC_NELEM(eccurves_default);
    } else {
        QuicDataGetU16(&tls->ext.supported_groups, pgroups, pgroupslen);
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
    hdatalen = QuicBufGetDataLength(buffer) + QuicBufGetReserved(buffer);
    if (hdatalen == 0) {
        return -1;
    }

    hdata = QuicBufHead(buffer);
//    QuicPrint(hdata, hdatalen);
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

int TlsHandshakeHash(TLS *tls, uint8_t *hash)
{
    EVP_MD_CTX *ctx = NULL;
    EVP_MD_CTX *hdgst = tls->handshake_dgst;
    int ret = -1;

    if (hdgst == NULL) {
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

int TlsKeyDerive(TLS *tls, EVP_PKEY *privkey, EVP_PKEY *pubkey)
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

    md = TlsHandshakeMd(tls);
    ret = TlsGenerateSecret(md, NULL, NULL, 0, tls->early_secret);
    if (ret < 0) {
        goto out;
    }

    ret = TlsGenerateSecret(md, tls->early_secret, pms, pmslen,
                            tls->handshake_secret);
out:
    QuicMemFree(pms);
    EVP_PKEY_CTX_free(pctx);
    return ret;
}

