/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "quic_test.h"

#include <string.h>
#include <openssl/evp.h>
#include "tls.h"
#include "tls_lib.h"
#include "common.h"

static uint8_t secret[] =
    "\x7E\xE8\x20\x6F\x55\x70\x02\x3E\x6D\xC7\x51\x9E\xB1\x07\x3B\xC4"
    "\xE7\x91\xAD\x37\xB5\xC3\x82\xAA\x10\xBA\x18\xE2\x35\x7E\x71\x69"
    "\x71\xF9\x36\x2F\x2C\x2F\xE2\xA7\x6B\xFD\x78\xDF\xEC\x4E\xA9\xB5"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
static uint8_t insecret[] =
    "\x70\x48\x2A\xE0\x7A\x00\x84\x76\x25\x54\xCA\xBB\xC2\xF6\x89\x05"
    "\x29\xBE\xCB\x86\x3A\x5D\x74\x87\xCB\x6F\x4A\x32\x20\xE5\x67\x6D";
static uint8_t outsecret[] =
    "\x54\x97\xBB\x37\x82\x23\xB4\x08\xFF\x3D\x0E\x1A\xE4\x6F\xE4\xCF"
    "\x3E\x7E\xE2\xAC\x6A\x80\x1E\x08\x14\x3A\x90\xE4\x9A\x5F\x1D\xF1"
    "\xD8\xD2\xF4\xA6\x54\x58\x71\xCF\x47\x2B\x56\xA3\xF2\xBF\xFF\x58"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

int QuicTlsGenerateSecretTest(void)
{
    uint8_t pre_secret[EVP_MAX_MD_SIZE] = {};
    uint8_t out[EVP_MAX_MD_SIZE] = {};

    if (TlsGenerateSecret(EVP_sha384(), NULL, NULL, 0, pre_secret) < 0) {
        return -1;
    }

    if (memcmp(pre_secret, secret, sizeof(secret) - 1) != 0) {
        QuicPrint(pre_secret, sizeof(pre_secret));
        return -1;
    }

    if (TlsGenerateSecret(EVP_sha384(), pre_secret, insecret,
                    sizeof(insecret) - 1, out) < 0) {
        return -1;
    }

    if (memcmp(out, outsecret, sizeof(outsecret) - 1) != 0) {
        QuicPrint(out, sizeof(out));
        return -1;
    }

    return 2;
}
