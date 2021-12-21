/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "quic_test.h"

#include <string.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <tbquic/quic.h>

#include "crypto.h"
#include "common.h"
#include "quic_local.h"

typedef struct {
    QUIC_DATA in_secret;
    const char *label;
    QUIC_DATA out_secret;
} QuicHkdfExpandLabelTest;

static uint8_t initial_salt[] = "\x38\x76\x2C\xF7\xF5\x59\x34\xB3\x4D\x17"
                                "\x9A\xE6\xA4\xC8\x0C\xAD\xCC\xBB\x7F\x0A";

static uint8_t dest_cid[] = "\x83\x94\xC8\xF0\x3E\x51\x57\x08";
static uint8_t initial_secret[] =
    "\x7D\xB5\xDF\x06\xE7\xA6\x9E\x43\x24\x96\xAD\xED\xB0\x08\x51\x92"
    "\x35\x95\x22\x15\x96\xAE\x2A\xE9\xFB\x81\x15\xC1\xE9\xED\x0A\x44";
static uint8_t client_initial_secret[] =
    "\xC0\x0C\xF1\x51\xCA\x5B\xE0\x75\xED\x0E\xBF\xB5\xC8\x03\x23\xC4"
    "\x2D\x6B\x7D\xB6\x78\x81\x28\x9A\xF4\x00\x8F\x1F\x6C\x35\x7A\xEA";
static uint8_t client_key[] =
    "\x1F\x36\x96\x13\xDD\x76\xD5\x46\x77\x30\xEF\xCB\xE3\xB1\xA2\x2D";
static uint8_t client_iv[] = "\xFA\x04\x4B\x2F\x42\xA3\xFD\x3B\x46\xFB\x25\x5C";
static uint8_t client_hp[] =
    "\x9F\x50\x44\x9E\x04\xA0\xE8\x10\x28\x3A\x1E\x99\x33\xAD\xED\xD2";
static uint8_t server_initial_secret[] =
    "\x3C\x19\x98\x28\xFD\x13\x9E\xFD\x21\x6C\x15\x5A\xD8\x44\xCC\x81"
    "\xFB\x82\xFA\x8D\x74\x46\xFA\x7D\x78\xBE\x80\x3A\xCD\xDA\x95\x1B";
static uint8_t server_key[] =
    "\xCF\x3A\x53\x31\x65\x3C\x36\x4C\x88\xF0\xF3\x79\xB6\x06\x7E\x37";
static uint8_t server_iv[] = "\x0A\xC1\x49\x3C\xA1\x90\x58\x53\xB0\xBB\xA0\x3E";
static uint8_t server_hp[] =
    "\xC2\x06\xB8\xD9\xB9\xF0\xF3\x76\x44\x43\x0B\x49\x0E\xEA\xA3\x14";

static QuicHkdfExpandLabelTest QuicHkdfExpandLabelTestCases[] = {
    {
        .in_secret = {
            .data = initial_secret,
            .len = sizeof(initial_secret) - 1,
        },
        .label = "client in",
        .out_secret = {
            .data = client_initial_secret,
            .len = sizeof(client_initial_secret) - 1,
        },
    },
    {
        .in_secret = {
            .data = client_initial_secret,
            .len = sizeof(client_initial_secret) - 1,
        },
        .label = "quic key",
        .out_secret = {
            .data = client_key,
            .len = sizeof(client_key) - 1,
        },
    },
    {
        .in_secret = {
            .data = client_initial_secret,
            .len = sizeof(client_initial_secret) - 1,
        },
        .label = "quic iv",
        .out_secret = {
            .data = client_iv,
            .len = sizeof(client_iv) - 1,
        },
    },
    {
        .in_secret = {
            .data = client_initial_secret,
            .len = sizeof(client_initial_secret) - 1,
        },
        .label = "quic hp",
        .out_secret = {
            .data = client_hp,
            .len = sizeof(client_hp) - 1,
        },
    },
    {
        .in_secret = {
            .data = initial_secret,
            .len = sizeof(initial_secret) - 1,
        },
        .label = "server in",
        .out_secret = {
            .data = server_initial_secret,
            .len = sizeof(server_initial_secret) - 1,
        },
    },
    {
        .in_secret = {
            .data = server_initial_secret,
            .len = sizeof(server_initial_secret) - 1,
        },
        .label = "quic key",
        .out_secret = {
            .data = server_key,
            .len = sizeof(server_key) - 1,
        },
    },
    {
        .in_secret = {
            .data = server_initial_secret,
            .len = sizeof(server_initial_secret) - 1,
        },
        .label = "quic iv",
        .out_secret = {
            .data = server_iv,
            .len = sizeof(server_iv) - 1,
        },
    },
    {
        .in_secret = {
            .data = server_initial_secret,
            .len = sizeof(server_initial_secret) - 1,
        },
        .label = "quic hp",
        .out_secret = {
            .data = server_hp,
            .len = sizeof(server_hp) - 1,
        },
    },
};

#define QUIC_HKDF_EXPAND_LABEL_TEST_NUM \
    QUIC_NELEM(QuicHkdfExpandLabelTestCases)

int QuicHkdfExpandLabel(void)
{
    QuicHkdfExpandLabelTest *tcase = NULL;
    uint8_t secret[HASH_SHA2_256_LENGTH];
    size_t secret_len = 0;
    size_t out_len = 0;
    int i = 0;

    if (HkdfExtract(EVP_sha256(), initial_salt, sizeof(initial_salt) - 1,
                dest_cid, sizeof(dest_cid) - 1, secret, &secret_len)
            == NULL) {
        return -1;
    }

    if (secret_len != sizeof(initial_secret) - 1 ||
            memcmp(secret, initial_secret, secret_len) != 0) {
        printf("Extract Initial Secret failed\n");
        return -1;
    }

    for (i = 0; i < QUIC_HKDF_EXPAND_LABEL_TEST_NUM; i++) {
        tcase = &QuicHkdfExpandLabelTestCases[i];
        out_len = tcase->out_secret.len;
        if (QuicTLS13HkdfExpandLabel(EVP_sha256(), tcase->in_secret.data,
                    tcase->in_secret.len, (uint8_t *)tcase->label,
                    strlen(tcase->label), secret, out_len) < 0) {
            printf("Expand Label %s failed\n", tcase->label);
            return -1;
        }
        
        if (memcmp(secret, tcase->out_secret.data, out_len) != 0) {
            printf("Derive secret for label %s failed\n", tcase->label);
            QuicPrint(secret, out_len);
            return -1;
        }
    }

    return QUIC_HKDF_EXPAND_LABEL_TEST_NUM;
}

