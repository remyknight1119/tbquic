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

#define QUIC_HANDSHAKE_SALT_NUM QUIC_ARRAY_SIZE(handshake_salt)


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
static int QuicDeriveInitialSecrets(const QUIC_DATA *cid, uint8_t *client_secret,
        uint8_t *server_secret, uint32_t version)
{
    const QuicSalt *salt = NULL;
    uint8_t secret[HASH_SHA2_256_LENGTH];
    static const uint8_t client_label[] = "client in";
    static const uint8_t server_label[] = "server in";
    size_t secret_len = 0;

    salt = QuicSaltFind(handshake_salt, QUIC_HANDSHAKE_SALT_NUM, version);
    if (salt == NULL) {
        return -1;
    }

    if (HkdfExtract(EVP_sha256(), salt->salt, salt->salt_len, cid->data,
                    cid->len, secret, &secret_len) == NULL) {
        return -1;
    }

    if (QuicTLS13HkdfExpandLabel(EVP_sha256(), secret, sizeof(secret),
                        client_label, sizeof(client_label) - 1,
                        client_secret, HASH_SHA2_256_LENGTH) < 0) {
        return -1;
    }

    if (QuicTLS13HkdfExpandLabel(EVP_sha256(), secret, sizeof(secret),
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
        return -1;
    }

    key_len = EVP_CIPHER_key_length(c);
    if (key_len > sizeof(key)) {
        return -1;
    }

    if (secret != NULL) {
        if (QuicTLS13HkdfExpandLabel(md, secret, EVP_MD_size(md),
                    quic_key_label, sizeof(quic_key_label) - 1,
                    key, key_len) < 0) {
            return -1;
        }

        if (QuicTLS13HkdfExpandLabel(md, secret, EVP_MD_size(md), quic_iv_label,
                    sizeof(quic_iv_label) - 1, cipher->iv, sizeof(cipher->iv))
                < 0) {
            return -1;
        }
    }

    return QuicCipherDoPrepare(&cipher->cipher, c, secret, key, enc);
}

int QuicCiphersPrepare(QUIC_CIPHERS *ciphers, const EVP_MD *md,
                        uint8_t *secret, int enc)
{
    if (QuicHPCipherPrepare(&ciphers->hp_cipher, md, secret)
            < 0) {
        return 1;
    }

    return QuicPPCipherPrepare(&ciphers->pp_cipher, md, secret, enc);
}

int QuicCreateInitialDecoders(QUIC *quic, uint32_t version)
{
    QUIC_DATA *cid = NULL;
    uint8_t *decrypt_secret = NULL;
    uint8_t *encrypt_secret = NULL;
    uint8_t client_secret[HASH_SHA2_256_LENGTH];
    uint8_t server_secret[HASH_SHA2_256_LENGTH];
    
    if (quic->initial.cipher_initialed == true) {
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

    if (QuicDeriveInitialSecrets(cid, client_secret, server_secret,
                version) < 0) {
        return -1;
    }

    if (QuicCiphersPrepare(&quic->initial.decrypt.ciphers, EVP_sha256(),
                decrypt_secret, QUIC_EVP_DECRYPT) < 0) {
        return -1;
    }

    if (QuicCiphersPrepare(&quic->initial.encrypt.ciphers, EVP_sha256(),
                encrypt_secret, QUIC_EVP_ENCRYPT) < 0) {
        return -1;
    }

    quic->initial.cipher_initialed = true;
    return 0;
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

