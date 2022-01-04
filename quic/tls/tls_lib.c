/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "tls_lib.h"

#include <string.h>
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
#ifdef QUIC_TEST
    if (QuicHandshakeSecretHook) {
        QuicHandshakeSecretHook(tls->handshake_secret);
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

int TlsCheckPeerSigalg(TLS *tls, uint16_t sig, EVP_PKEY *pkey)
{
    const SigAlgLookup *lu = NULL;

    lu = TlsLookupSigAlg(sig);
    if (lu == NULL) {
        return -1;
    }

    tls->peer_sigalg = lu;

    return 0;
}

const EVP_MD *TlsLookupMd(const SigAlgLookup *lu)
{
    if (lu == NULL) {
        return NULL;
    }

    return QuicMd(lu->hash_idx);
}

/*
 * Size of the to-be-signed TLS13 data, without the hash size itself:
 * 64 bytes of value 32, 33 context bytes, 1 byte separator
 */
#define TLS_TBS_START_SIZE          64
#define TLS_TBS_PREAMBLE_SIZE       (TLS_TBS_START_SIZE + sizeof(servercontext))

int TlsGetCertVerifyData(TLS *s, uint8_t *tbs, void **hdata, size_t *hdatalen)
{
    size_t hashlen;

    /* Set the first 64 bytes of to-be-signed data to octet 32 */
    memset(tbs, 32, TLS_TBS_START_SIZE);
    /* This copies the 33 bytes of context plus the 0 separator byte */
    if (s->handshake_state == TLS_ST_CR_CERT_VERIFY
            || s->handshake_state == TLS_ST_SW_CERT_VERIFY) {
        strcpy((char *)tbs + TLS_TBS_START_SIZE, servercontext);
    } else {
        strcpy((char *)tbs + TLS_TBS_START_SIZE, clientcontext);
    }

    /*
     * If we're currently reading then we need to use the saved handshake
     * hash value. We can't use the current handshake hash state because
     * that includes the CertVerify itself.
     */
    if (s->handshake_state == TLS_ST_CR_CERT_VERIFY
            || s->handshake_state  == TLS_ST_SR_CERT_VERIFY) {
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


