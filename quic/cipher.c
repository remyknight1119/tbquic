/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "cipher.h"

#include <string.h>
#include <assert.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <tbquic/cipher.h>

#include "quic_local.h"
#include "crypto.h"
#include "common.h"
#include "mem.h"
#include "tls_lib.h"
#include "evp.h"
#include "log.h"

typedef struct {
    const uint8_t *salt;
    size_t salt_len;
    uint32_t version;
} QuicSalt;

static size_t QuicAesEcbGetCipherLen(size_t, size_t);
static size_t QuicAesGcmGetCipherLen(size_t, size_t);
static size_t QuicAesCcmGetCipherLen(size_t, size_t);

static const QuicCipherSuite cipher_suite[QUIC_ALG_MAX] = {
    [QUIC_ALG_AES_128_ECB] = {
        .nid = NID_aes_128_ecb,
        .get_cipher_len = QuicAesEcbGetCipherLen,
    },
    [QUIC_ALG_AES_192_ECB] = {
        .nid = NID_aes_192_ecb,
        .get_cipher_len = QuicAesEcbGetCipherLen,
    },
    [QUIC_ALG_AES_256_ECB] = {
        .nid = NID_aes_256_ecb,
        .get_cipher_len = QuicAesEcbGetCipherLen,
    },
    [QUIC_ALG_AES_128_GCM] = {
        .nid = NID_aes_128_gcm,
        .tag_len = EVP_GCM_TLS_TAG_LEN,
        .get_cipher_len = QuicAesGcmGetCipherLen,
    },
    [QUIC_ALG_AES_192_GCM] = {
        .nid = NID_aes_192_gcm,
        .tag_len = EVP_GCM_TLS_TAG_LEN,
        .get_cipher_len = QuicAesGcmGetCipherLen,
    },
    [QUIC_ALG_AES_256_GCM] = {
        .nid = NID_aes_256_gcm,
        .tag_len = EVP_GCM_TLS_TAG_LEN,
        .get_cipher_len = QuicAesGcmGetCipherLen,
    },
    [QUIC_ALG_AES_128_CCM] = {
        .nid = NID_aes_128_ccm,
        .get_cipher_len = QuicAesCcmGetCipherLen,
    },
    [QUIC_ALG_AES_192_CCM] = {
        .nid = NID_aes_192_ccm,
        .get_cipher_len = QuicAesCcmGetCipherLen,
    },
    [QUIC_ALG_AES_256_CCM] = {
        .nid = NID_aes_256_ccm,
        .get_cipher_len = QuicAesCcmGetCipherLen,
    },
    [QUIC_ALG_CHACHA20] = {
        .nid = NID_aes_256_ccm,
        .get_cipher_len = QuicAesCcmGetCipherLen,
    },
};

static int quic_digest_method_map[QUIC_DIGEST_MAX] = {
    [QUIC_DIGEST_SHA256] = NID_sha256,
    [QUIC_DIGEST_SHA384] = NID_sha384,
    [QUIC_DIGEST_SHA512] = NID_sha512,
    [QUIC_DIGEST_SHA1] = NID_sha1,
};

static const EVP_MD *quic_digest_methods[QUIC_DIGEST_MAX];

static const uint8_t handshake_salt_v1[] =
    "\x38\x76\x2C\xF7\xF5\x59\x34\xB3\x4D\x17"
    "\x9A\xE6\xA4\xC8\x0C\xAD\xCC\xBB\x7F\x0A";

static const QuicSalt handshake_salt[] = {
    {
        .salt = handshake_salt_v1,
        .salt_len = sizeof(handshake_salt_v1) - 1,
        .version = QUIC_VERSION_1,
    },
};

static const QuicSalt *QuicSaltFind(const QuicSalt *salt, size_t num,
                                    uint32_t version)
{
    int i = 0;

    for (i = 0; i < num; i++) {
        if (salt[i].version == version) {
            return &salt[i];
        }
    }

    return NULL;
}

static size_t QuicAesEcbGetCipherLen(size_t plaintext_len, size_t tag_len)
{
    return plaintext_len;
}

static size_t QuicAesGcmGetCipherLen(size_t plaintext_len, size_t tag_len)
{
    return plaintext_len + tag_len;
}

static size_t QuicAesCcmGetCipherLen(size_t plaintext_len, size_t tag_len)
{
    return plaintext_len;
}

static const QuicCipherSuite *QuicCipherSuiteFind(uint32_t alg)
{
    if (alg >= QUIC_ALG_MAX) {
        return NULL;
    }

    return &cipher_suite[alg];
}

size_t QuicCipherLenGet(uint32_t alg, size_t plaintext_len)
{
    const QuicCipherSuite *suite = NULL;

    suite = QuicCipherSuiteFind(alg);
    if (suite == NULL) {
        return 0;
    }

    return suite->get_cipher_len(plaintext_len, suite->tag_len);
}

int QuicCipherNidFind(uint32_t alg)
{
    const QuicCipherSuite *suite = NULL;

    suite = QuicCipherSuiteFind(alg);
    if (suite == NULL) {
        return -1;
    }

    return suite->nid;
}

int QuicCipherGetTagLen(uint32_t alg)
{
    const QuicCipherSuite *suite = NULL;

    suite = QuicCipherSuiteFind(alg);
    if (suite == NULL) {
        return -1;
    }

    return suite->tag_len;
}

/*
 * Compute the initial secrets given Connection ID "cid".
 */
static int QuicDeriveInitialSecrets(const QUIC_DATA *cid, const EVP_MD *md,
        uint8_t *client_secret, uint8_t *server_secret, uint32_t version)
{
    const QuicSalt *salt = NULL;
    uint8_t secret[HASH_SHA2_256_LENGTH];
    static const uint8_t client_label[] = "client in";
    static const uint8_t server_label[] = "server in";
    size_t secret_len = 0;

    salt = QuicSaltFind(handshake_salt, QUIC_NELEM(handshake_salt), version);
    if (salt == NULL) {
        return -1;
    }

    if (HkdfExtract(md, salt->salt, salt->salt_len, cid->data,
                    cid->len, secret, &secret_len) == NULL) {
        return -1;
    }

    if (QuicTLS13HkdfExpandLabel(md, secret, sizeof(secret),
                        client_label, sizeof(client_label) - 1,
                        client_secret, HASH_SHA2_256_LENGTH) < 0) {
        return -1;
    }

    if (QuicTLS13HkdfExpandLabel(md, secret, sizeof(secret),
                        server_label, sizeof(server_label) - 1,
                        server_secret, HASH_SHA2_256_LENGTH) < 0) {
        return -1;
    }

    return 0;
}

static int QuicCipherDoPrepare(QUIC_CIPHER *cipher, const EVP_CIPHER *c,
                                uint8_t *secret, const uint8_t *key,
                                int enc)
{
    cipher->ctx = EVP_CIPHER_CTX_new();
    if (cipher->ctx == NULL) {
        return -1;
    }

    if (secret == NULL) {
        return 0;
    }

    cipher->enc = enc;
    return QuicEvpCipherInit(cipher->ctx, c, key, NULL, enc);
}

static const EVP_CIPHER *QuicFindCipherByAlg(uint32_t alg)
{
    int nid = 0;

    nid = QuicCipherNidFind(alg);
    if (nid < 0) {
        return NULL;
    }

    return EVP_get_cipherbynid(nid);
}

static int QuicHPCipherPrepare(QuicHPCipher *cipher, const EVP_MD *md,
                                uint8_t *secret)
{
    const EVP_CIPHER *c = NULL;
    uint8_t key[AES_KEY_MAX_SIZE] = {};
    static const uint8_t quic_hp_label[] = "quic hp";
    int key_len = 0;

    c = QuicFindCipherByAlg(cipher->cipher.alg);
    if (c == NULL) {
        return -1;
    }

    key_len = EVP_CIPHER_key_length(c);
    if (key_len > sizeof(key)) {
        return -1;
    }

    if (secret != NULL) {
        if (QuicTLS13HkdfExpandLabel(md, secret, EVP_MD_size(md), quic_hp_label,
                    sizeof(quic_hp_label) - 1, key, key_len) < 0) {
            return -1;
        }
    }

    return QuicCipherDoPrepare(&cipher->cipher, c, secret, key,
                                QUIC_EVP_ENCRYPT);
}

static int QuicPPCipherPrepare(QuicPPCipher *cipher, const EVP_MD *md,
                                uint8_t *secret, int enc)
{
    const EVP_CIPHER *c = NULL;
    uint8_t key[AES_KEY_MAX_SIZE] = {};
    static const uint8_t quic_key_label[] = "quic key";
    static const uint8_t quic_iv_label[] = "quic iv";
    int key_len = 0;

    c = QuicFindCipherByAlg(cipher->cipher.alg);
    if (c == NULL) {
        QUIC_LOG("Find cipher by %d failed\n", cipher->cipher.alg);
        return -1;
    }

    key_len = EVP_CIPHER_key_length(c);
    if (key_len > sizeof(key)) {
        QUIC_LOG("key len(%d) is too big(%lu)\n", key_len, sizeof(key));
        return -1;
    }

    if (secret != NULL) {
        if (QuicTLS13HkdfExpandLabel(md, secret, EVP_MD_size(md),
                    quic_key_label, sizeof(quic_key_label) - 1,
                    key, key_len) < 0) {
            QUIC_LOG("Gen Key failed\n");
            return -1;
        }

        if (QuicTLS13HkdfExpandLabel(md, secret, EVP_MD_size(md), quic_iv_label,
                    sizeof(quic_iv_label) - 1, cipher->iv, sizeof(cipher->iv))
                < 0) {
            QUIC_LOG("Gen IV failed\n");
            return -1;
        }
    }

    return QuicCipherDoPrepare(&cipher->cipher, c, secret, key, enc);
}

int QuicCiphersPrepare(QUIC_CIPHERS *ciphers, const EVP_MD *md,
                        uint8_t *secret, int enc)
{
    if (QuicHPCipherPrepare(&ciphers->hp_cipher, md, secret) < 0) {
        return 1;
    }

    return QuicPPCipherPrepare(&ciphers->pp_cipher, md, secret, enc);
}

static int QuicPrepareEncoderDecoders(QuicCrypto *c, const EVP_MD *md,
                                uint8_t *dec_secret, 
                                uint8_t *enc_secret)
{
    if (QuicCiphersPrepare(&c->decrypt.ciphers, md, dec_secret,
                QUIC_EVP_DECRYPT) < 0) {
        return -1;
    }

    if (QuicCiphersPrepare(&c->encrypt.ciphers, md, enc_secret,
                QUIC_EVP_ENCRYPT) < 0) {
        return -1;
    }

    c->decrypt.cipher_inited = true;
    c->encrypt.cipher_inited = true;

    return 0;
}

int QuicCreateInitialDecoders(QUIC *quic, uint32_t version)
{
    QuicCrypto *init = NULL;
    QUIC_DATA *cid = NULL;
    uint8_t *decrypt_secret = NULL;
    uint8_t *encrypt_secret = NULL;
    uint8_t client_secret[HASH_SHA2_256_LENGTH];
    uint8_t server_secret[HASH_SHA2_256_LENGTH];
    
    init = &quic->initial;
    if (init->decrypt.cipher_inited == true ||
            init->encrypt.cipher_inited == true) {
        return 0;
    }

    /* 
     * Packet numbers are protected with AES128-CTR,
     * initial packets are protected with AEAD_AES_128_GCM.
     */
    if (QUIC_IS_SERVER(quic)) {
        cid = &quic->scid;
        decrypt_secret = client_secret;
        encrypt_secret = server_secret;
    } else {
        cid = &quic->dcid;
        decrypt_secret = server_secret;
        encrypt_secret = client_secret;
    }

    if (QuicDeriveInitialSecrets(cid, EVP_sha256(), client_secret,
                server_secret, version) < 0) {
        return -1;
    }

    return QuicPrepareEncoderDecoders(init, EVP_sha256(), decrypt_secret,
                            encrypt_secret);
}

#ifdef QUIC_TEST
void (*QuicSecretTest)(uint8_t *secret);
#endif
static int QuicInstallEncryptorDecryptor(TLS *s, const EVP_MD *md,
                    const uint8_t *in_secret,
                    const uint8_t *label, size_t labellen,
                    const uint8_t *hash, QuicCipherSpace *cs,
                    uint8_t *finsecret, size_t finsecretlen,
                    const char *log_label, int enc)
{
    uint8_t secret[EVP_MAX_MD_SIZE];
    
    if (TlsDeriveSecrets(s, md, in_secret, label, labellen, hash, secret) < 0) {
        QUIC_LOG("Derive secret failed\n");
        return -1;
    }

#if 0
    fprintf(stdout, "%s ", log_label);
    int i = 0;

    for (i = 0; i < sizeof(tls->client_random); i++) {
        fprintf(stdout, "%02X", tls->client_random[i]);
    }

    fprintf(stdout, " ");
    for (i = 0; i < EVP_MD_size(md); i++) {
        fprintf(stdout, "%02X", secret[i]);
    }
    fprintf(stdout, "\n");

#endif
#ifdef QUIC_TEST
    if (QuicSecretTest != NULL) {
        QuicSecretTest(secret);
    }
#endif

    if (finsecret != NULL) {
        if (TlsDeriveFinishedKey(s, md, secret, finsecret, finsecretlen) < 0) {
            return -1;
        }
    }

    return QuicCiphersPrepare(&cs->ciphers, md, secret, enc);
}

static int
QuicCreateEncryptorDecryptor(TLS *s, QuicCrypto *c, QuicCipherSpace *cs,
                            uint8_t *in_secret, uint8_t *hash, size_t hsize,
                            const uint8_t *label, size_t label_len,
                            uint8_t *finsecret, const char *log_label,
                            bool server_traffic, int enc)
{
    const TlsCipher *cipher = NULL;
    const EVP_MD *md = NULL;
    int md_size = 0;
    
    if (cs->cipher_inited == true) {
        return 0;
    }

    cipher = s->handshake_cipher;
    if (cipher == NULL) {
        QUIC_LOG("No cipher\n");
        return -1;
    }

    if (TlsDigestCachedRecords(s) < 0) {
        QUIC_LOG("Gigest Cached Record failed\n");
        return -1;
    }

    if (server_traffic == true) {
        size_t hlen = 0;
        if (TlsHandshakeHash(s, hash, hsize, &hlen) < 0) {
            QUIC_LOG("Handshake Hash failed\n");
            return -1;
        }
    }

    if (QUIC_set_hp_cipher(c, QUIC_ALG_AES_128_ECB) < 0) {
        QUIC_LOG("Set handshake HP cipher failed\n");
        return QUIC_FLOW_RET_ERROR;
    }

    if (QUIC_set_pp_cipher_space_alg(cs, cipher->algorithm_enc) < 0) {
        QUIC_LOG("Set handshake PP cipher failed\n");
        return QUIC_FLOW_RET_ERROR;
    }

    md = TlsHandshakeMd(s);
    if (md == NULL) {
        QUIC_LOG("Handshake MD failed\n");
        return -1;
    }

    md_size = EVP_MD_size(md);
    if (md_size <= 0) {
        return -1;
    }

    return QuicInstallEncryptorDecryptor(s, md, in_secret, label, label_len,
                                            hash, cs, finsecret, md_size,
                                            log_label, enc);
}

static int
QuicCreateEncryptor(TLS *s, QuicCrypto *c, uint8_t *in_secret, uint8_t *hash,
                            size_t hsize, const uint8_t *label, size_t labellen,
                            uint8_t *finsecret, const char *log_label,
                            bool server_traffic)
{
    return QuicCreateEncryptorDecryptor(s, c, &c->encrypt, in_secret, hash,
                            hsize, label, labellen, finsecret, log_label,
                            server_traffic, QUIC_EVP_ENCRYPT);
}

static int
QuicCreateDecryptor(TLS *s, QuicCrypto *c, uint8_t *in_secret, uint8_t *hash,
                            size_t hsize, const uint8_t *label, size_t labellen,
                            uint8_t *finsecret, const char *log_label,
                            bool server_traffic)
{
    return QuicCreateEncryptorDecryptor(s, c, &c->decrypt, in_secret, hash,
                            hsize, label, labellen, finsecret, log_label,
                            server_traffic, QUIC_EVP_DECRYPT);
}


int QuicCreateAppDataServerDecoders(QUIC *quic)
{
    TLS *s = &quic->tls;
    static const uint8_t server_application_traffic[] = "s ap traffic";
    
    return QuicCreateDecryptor(s, &quic->one_rtt, s->master_secret,
                            s->server_finished_hash,
                            sizeof(s->server_finished_hash),
                            server_application_traffic,
                            sizeof(server_application_traffic) - 1,
                            NULL, SERVER_APPLICATION_LABEL, true);

}

int QuicCreateHandshakeServerDecoders(QUIC *quic)
{
    TLS *s = &quic->tls;
    static const uint8_t server_handshake_traffic[] = "s hs traffic";
    
    return QuicCreateDecryptor(s, &quic->handshake, s->handshake_secret,
                            s->handshake_traffic_hash,
                            sizeof(s->handshake_traffic_hash),
                            server_handshake_traffic,
                            sizeof(server_handshake_traffic) - 1,
                            s->server_finished_secret,
                            SERVER_HANDSHAKE_LABEL, true);
}

int QuicCreateHandshakeClientEncoders(QUIC *quic)
{
    TLS *s = &quic->tls;
    static const uint8_t client_handshake_traffic[] = "c hs traffic";
    
    return QuicCreateEncryptor(s, &quic->handshake, s->handshake_secret,
                            s->handshake_traffic_hash,
                            sizeof(s->handshake_traffic_hash),
                            client_handshake_traffic,
                            sizeof(client_handshake_traffic) - 1,
                            s->client_finished_secret,
                            CLIENT_HANDSHAKE_LABEL, false);
}

int QuicDoCipher(QUIC_CIPHER *cipher, uint8_t *out, size_t *outl,
                    size_t out_buf_len, const uint8_t *in,
                    size_t inl)
{
    size_t len = 0;

    if (QuicEvpCipherUpdate(cipher->ctx, out, outl, in, inl) < 0) {
        QUIC_LOG("Cipher Update failed\n");
        return -1;
    }

    assert(QUIC_LE(*outl, out_buf_len));

    if (QuicEvpCipherFinal(cipher->ctx, &out[*outl], &len) < 0) {
        QUIC_LOG("Cipher Final failed\n");
        return -1;
    }

    *outl += len;
    assert(QUIC_LE(*outl, out_buf_len));

    return 0;
}

const EVP_MD *QuicMd(uint32_t idx)
{
    if (QUIC_GE(idx, QUIC_DIGEST_MAX)) {
        return NULL;
    }
    
    return quic_digest_methods[idx];
}

static void QuicCipherFree(QUIC_CIPHER *cipher)
{
    EVP_CIPHER_CTX_free(cipher->ctx);
    cipher->ctx = NULL;
}

void QuicCipherCtxFree(QUIC_CIPHERS *ciphers)
{
    QuicCipherFree(&ciphers->hp_cipher.cipher);
    QuicCipherFree(&ciphers->pp_cipher.cipher);
}

int QuicLoadCiphers(void)
{
    const EVP_MD *md = NULL;
    uint32_t md_id = 0;

    for (md_id = 0; md_id < QUIC_DIGEST_MAX; md_id++) {
        md = EVP_get_digestbynid(quic_digest_method_map[md_id]);
        if (md == NULL) {
            return -1;
        }
        quic_digest_methods[md_id] = md;
    }

    return 0;
}

