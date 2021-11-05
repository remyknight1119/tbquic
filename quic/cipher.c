/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "cipher.h"

#include <openssl/evp.h>

#include "quic_local.h"
#include "crypto.h"
#include "common.h"

typedef struct {
    const uint8_t *salt;
    size_t salt_len;
    uint32_t version;
} QuicSalt;

static const uint8_t handshake_salt_v1[] = {
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
    0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a
};

static const QuicSalt handshake_salt[] = {
    {
        .salt = handshake_salt_v1,
        .salt_len = sizeof(handshake_salt_v1),
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

/*
 * Compute the initial secrets given Connection ID "cid".
 */
static int QuicDeriveInitialSecret(const QUIC_CID *cid, uint8_t *client_secret,
        uint8_t *server_secret, uint32_t version)
{
    const QuicSalt *salt = NULL;
    uint8_t secret[HASH_SHA2_256_LENGTH];
    static const uint8_t client_label[] = "client in ";
    static const uint8_t server_label[] = "server in ";
    size_t secret_len = 0;

    salt = QuicSaltFind(handshake_salt, QUIC_HANDSHAKE_SALT_NUM, version);
    if (salt == NULL) {
        return -1;
    }

    if (HkdfExtract(EVP_sha256(), salt->salt, salt->salt_len, cid->cid,
                    cid->len, secret, &secret_len) == NULL) {
        return -1;
    }

    if (QuicTLS13HkdfExpand(EVP_sha256(), secret, sizeof(secret),
                        client_label, sizeof(client_label),
                        client_secret, HASH_SHA2_256_LENGTH) < 0) {
        return -1;
    }

    if (QuicTLS13HkdfExpand(EVP_sha256(), secret, sizeof(secret),
                        server_label, sizeof(server_label),
                        server_secret, HASH_SHA2_256_LENGTH) < 0) {
        return -1;
    }

    return 0;
}

int QuicCreateInitialDecoders(QUIC *quic, uint32_t version)
{
    uint8_t client_secret[HASH_SHA2_256_LENGTH];
    uint8_t server_secret[HASH_SHA2_256_LENGTH];
    
    if (QuicDeriveInitialSecret(&quic->peer_dcid, client_secret, server_secret,
                version) < 0) {
        return -1;
    }

    return 0;
}


