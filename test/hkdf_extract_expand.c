/*
 * Remy Lewis(remyknight1119@gmail.com)
 * RFC 5869 P 10-13, Appendix A
 */

#include "quic_test.h"

#include <string.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include <tbquic/quic.h>

#include "crypto.h"
#include "common.h"
#include "quic_local.h"

#define QUIC_CRYPTO_TEST_PRK_MAX_LEN    64
#define QUIC_CRYPTO_TEST_OKM_MAX_LEN    256

typedef struct {
    int digest_id;
    QUIC_DATA salt;
    QUIC_DATA ikm;
    QUIC_DATA info;
    QUIC_DATA prk;
    QUIC_DATA okm;
} QuicHkdfTest;

static uint8_t salt1[] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C";
static uint8_t salt2[] =
    "\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6A\x6B\x6C\x6D\x6E\x6F"
    "\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7A\x7B\x7C\x7D\x7E\x7f"
    "\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8A\x8B\x8C\x8D\x8E\x8F"
    "\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9A\x9B\x9C\x9D\x9E\x9F"
    "\xA0\xA1\xA2\xA3\xA4\xA5\xA6\xA7\xA8\xA9\xAA\xAB\xAC\xAD\xAE\xAF";
static uint8_t salt3[SHA_DIGEST_LENGTH];
static uint8_t ikm1[] = "\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B"
                        "\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B";
static uint8_t ikm2[] =
    "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"
    "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F"
    "\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2A\x2B\x2C\x2D\x2E\x2F"
    "\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3A\x3B\x3C\x3D\x3E\x3F"
    "\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4A\x4B\x4C\x4D\x4E\x4F";
static uint8_t ikm3[] = "\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C"
                        "\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C";
static uint8_t info1[] = "\xF0\xF1\xF2\xF3\xF4\xF5\xF6\xF7\xF8\xF9";
static uint8_t info2[] = 
    "\xB0\xB1\xB2\xB3\xB4\xB5\xB6\xB7\xB8\xB9\xBA\xBB\xBC\xBD\xBE\xBF"
    "\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF"
    "\xD0\xD1\xD2\xD3\xD4\xD5\xD6\xD7\xD8\xD9\xDA\xDB\xDC\xDD\xDE\xDF"
    "\xE0\xE1\xE2\xE3\xE4\xE5\xE6\xE7\xE8\xE9\xEA\xEB\xEC\xED\xEE\xEF"
    "\xF0\xF1\xF2\xF3\xF4\xF5\xF6\xF7\xF8\xF9\xFA\xFB\xFC\xFD\xFE\xFF";
static uint8_t prk1[] = "\x07\x77\x09\x36\x2C\x2E\x32\xDF"
                        "\x0D\xDC\x3F\x0D\xC4\x7B\xBA\x63"
                        "\x90\xB6\xC7\x3B\xB5\x0F\x9C\x31"
                        "\x22\xEC\x84\x4A\xD7\xC2\xB3\xE5";
static uint8_t prk2[] = "\x06\xA6\xB8\x8C\x58\x53\x36\x1A"
                        "\x06\x10\x4C\x9C\xEB\x35\xB4\x5C"
                        "\xEF\x76\x00\x14\x90\x46\x71\x01"
                        "\x4A\x19\x3F\x40\xC1\x5F\xC2\x44";
static uint8_t prk3[] = "\x19\xEF\x24\xA3\x2C\x71\x7B\x16"
                        "\x7F\x33\xA9\x1D\x6F\x64\x8B\xDF"
                        "\x96\x59\x67\x76\xAF\xDB\x63\x77"
                        "\xAC\x43\x4C\x1C\x29\x3C\xCB\x04";
static uint8_t prk4[] = "\x9B\x6C\x18\xC4\x32\xA7\xBF\x8F\x0E\x71"
                        "\xC8\xEB\x88\xF4\xB3\x0B\xAA\x2B\xA2\x43";
static uint8_t prk5[] = "\x8A\xDA\xE0\x9A\x2A\x30\x70\x59\x47\x8D"
                        "\x30\x9B\x26\xC4\x11\x5A\x22\x4C\xFA\xF6";
static uint8_t prk6[] = "\xDA\x8C\x8A\x73\xC7\xFA\x77\x28\x8E\xC6"
                        "\xF5\xE7\xC2\x97\x78\x6A\xA0\xD3\x2D\x01";
static uint8_t prk7[] = "\x2A\xDC\xCA\xDA\x18\x77\x9E\x7C\x20\x77"
                        "\xAD\x2E\xB1\x9D\x3F\x3E\x73\x13\x85\xDD";
static uint8_t okm1[] =
    "\x3C\xB2\x5F\x25\xFA\xAC\xD5\x7A\x90\x43\x4F\x64\xD0\x36"
    "\x2F\x2A\x2D\x2D\x0A\x90\xCF\x1A\x5A\x4C\x5D\xB0\x2D\x56"
    "\xEC\xC4\xC5\xBF\x34\x00\x72\x08\xD5\xB8\x87\x18\x58\x65";
static uint8_t okm2[] =
    "\xB1\x1E\x39\x8D\xC8\x03\x27\xA1\xC8\xE7\xF7\x8C\x59\x6A\x49\x34"
    "\x4F\x01\x2E\xDA\x2D\x4E\xFA\xD8\xA0\x50\xCC\x4C\x19\xAF\xA9\x7C"
    "\x59\x04\x5A\x99\xCA\xC7\x82\x72\x71\xCB\x41\xC6\x5E\x59\x0E\x09"
    "\xDA\x32\x75\x60\x0C\x2F\x09\xB8\x36\x77\x93\xA9\xAC\xA3\xDB\x71"
    "\xCC\x30\xC5\x81\x79\xEC\x3E\x87\xC1\x4C\x01\xD5\xC1\xF3\x43\x4F"
    "\x1D\x87";
static uint8_t okm3[] =
    "\x8D\xA4\xE7\x75\xA5\x63\xC1\x8F\x71\x5F\x80\x2A\x06\x3C"
    "\x5A\x31\xB8\xA1\x1F\x5C\x5E\xE1\x87\x9E\xC3\x45\x4E\x5F"
    "\x3C\x73\x8D\x2D\x9D\x20\x13\x95\xFA\xA4\xB6\x1A\x96\xC8";
static uint8_t okm4[] =
    "\x08\x5A\x01\xEA\x1B\x10\xF3\x69\x33\x06\x8B\x56\xEF\xA5"
    "\xAD\x81\xA4\xF1\x4B\x82\x2F\x5B\x09\x15\x68\xA9\xCD\xD4"
    "\xF1\x55\xFD\xA2\xC2\x2E\x42\x24\x78\xD3\x05\xF3\xF8\x96";
static uint8_t okm5[] =
    "\x0B\xD7\x70\xA7\x4D\x11\x60\xF7\xC9\xF1\x2C\xD5\x91\x2A\x06\xEB"
    "\xFF\x6A\xDC\xAE\x89\x9D\x92\x19\x1F\xE4\x30\x56\x73\xBA\x2F\xFE"
    "\x8F\xA3\xF1\xA4\xE5\xAD\x79\xF3\xF3\x34\xB3\xB2\x02\xB2\x17\x3C"
    "\x48\x6E\xA3\x7C\xE3\xD3\x97\xED\x03\x4C\x7F\x9D\xFE\xB1\x5C\x5E"
    "\x92\x73\x36\xD0\x44\x1F\x4C\x43\x00\xE2\xCF\xF0\xD0\x90\x0B\x52"
    "\xD3\xB4";
static uint8_t okm6[] =
    "\x0A\xC1\xAF\x70\x02\xB3\xD7\x61\xD1\xE5\x52\x98\xDA\x9D"
    "\x05\x06\xB9\xAE\x52\x05\x72\x20\xA3\x06\xE0\x7B\x6B\x87"
    "\xE8\xDF\x21\xD0\xEA\x00\x03\x3D\xE0\x39\x84\xD3\x49\x18";
static uint8_t okm7[] =
    "\x2C\x91\x11\x72\x04\xD7\x45\xF3\x50\x0D\x63\x6A\x62\xF6"
    "\x4F\x0A\xB3\xBA\xE5\x48\xAA\x53\xD4\x23\xB0\xD1\xF2\x7E"
    "\xBB\xA6\xF5\xE5\x67\x3A\x08\x1D\x70\xCC\xE7\xAC\xFC\x48";

static QuicHkdfTest QuicHkdfTestCases[] = {
    {
        .digest_id = NID_sha256,
        .salt = {
            .data = salt1,
            .len = sizeof(salt1) - 1,
        },
        .ikm = {
            .data = ikm1,
            .len = sizeof(ikm1) - 1,
        },
        .info = {
            .data = info1,
            .len = sizeof(info1) - 1,
        },
        .prk = {
            .data = prk1,
            .len = sizeof(prk1) - 1,
        },
        .okm = {
            .data = okm1,
            .len = sizeof(okm1) - 1,
        },
    },
    {
        .digest_id = NID_sha256,
        .salt = {
            .data = salt2,
            .len = sizeof(salt2) - 1,
        },
        .ikm = {
            .data = ikm2,
            .len = sizeof(ikm2) - 1,
        },
        .info = {
            .data = info2,
            .len = sizeof(info2) - 1,
        },
        .prk = {
            .data = prk2,
            .len = sizeof(prk2) - 1,
        },
        .okm = {
            .data = okm2,
            .len = sizeof(okm2) - 1,
        },
    },
    {
        .digest_id = NID_sha256,
        .ikm = {
            .data = ikm1,
            .len = sizeof(ikm1) - 1,
        },
        .prk = {
            .data = prk3,
            .len = sizeof(prk3) - 1,
        },
        .okm = {
            .data = okm3,
            .len = sizeof(okm3) - 1,
        },
    },
    {
        .digest_id = NID_sha1,
        .salt = {
            .data = salt1,
            .len = sizeof(salt1) - 1,
        },
        .ikm = {
            .data = ikm1,
            .len = 11,
        },
        .info = {
            .data = info1,
            .len = sizeof(info1) - 1,
        },
        .prk = {
            .data = prk4,
            .len = sizeof(prk4) - 1,
        },
        .okm = {
            .data = okm4,
            .len = sizeof(okm4) - 1,
        },
    },
    {
        .digest_id = NID_sha1,
        .salt = {
            .data = salt2,
            .len = sizeof(salt2) - 1,
        },
        .ikm = {
            .data = ikm2,
            .len = sizeof(ikm2) - 1,
        },
        .info = {
            .data = info2,
            .len = sizeof(info2) - 1,
        },
        .prk = {
            .data = prk5,
            .len = sizeof(prk5) - 1,
        },
        .okm = {
            .data = okm5,
            .len = sizeof(okm5) - 1,
        },
    },
    {
        .digest_id = NID_sha1,
        .ikm = {
            .data = ikm1,
            .len = sizeof(ikm1) - 1,
        },
        .prk = {
            .data = prk6,
            .len = sizeof(prk6) - 1,
        },
        .okm = {
            .data = okm6,
            .len = sizeof(okm6) - 1,
        },
    },
    {
        .digest_id = NID_sha1,
        .salt = {
            .data = salt3,
            .len = sizeof(salt3) - 1,
        },
        .ikm = {
            .data = ikm3,
            .len = sizeof(ikm3) - 1,
        },
        .prk = {
            .data = prk7,
            .len = sizeof(prk7) - 1,
        },
        .okm = {
            .data = okm7,
            .len = sizeof(okm7) - 1,
        },
    },
};

#define QUIC_HKDF_TEST_NUM QUIC_NELEM(QuicHkdfTestCases)

int QuicHkdfExtractExpandTest(void)
{
    QuicHkdfTest *tcase = NULL;
    const EVP_MD *md = NULL;
    uint8_t prk[QUIC_CRYPTO_TEST_PRK_MAX_LEN] = {};
    uint8_t okm[QUIC_CRYPTO_TEST_OKM_MAX_LEN] = {};
    size_t prk_len = 0;
    size_t okm_len = 0;
    int i = 0;

    for (i = 0; i < QUIC_HKDF_TEST_NUM; i++) {
        tcase = &QuicHkdfTestCases[i];
        md = EVP_get_digestbynid(tcase->digest_id);
        if (md == NULL) {
            return -1;
        }

        if (HkdfExtract(md, tcase->salt.data, tcase->salt.len, tcase->ikm.data,
                        tcase->ikm.len, prk, &prk_len) == NULL) {
            printf("case %d failed\n", i);
            return -1;
        }

        if (prk_len > sizeof(prk)) {
            printf("case %d failed, prk_len too big\n", i);
            return -1;
        }

        if (prk_len != tcase->prk.len || 
                memcmp(tcase->prk.data, prk, prk_len) != 0) {
            printf("case %d failed, prk not same\n", i);
            return -1;
        }

        okm_len = tcase->okm.len;
        if (okm_len > sizeof(okm)) {
            return -1;
        }

        if (HkdfExpand(md, prk, prk_len, tcase->info.data, tcase->info.len,
                                  okm, okm_len) == NULL) {
            return -1;
        }

       if (memcmp(tcase->okm.data, okm, okm_len) != 0) {
            printf("case %d failed, okm not same\n", i);
            return -1;
        }

//        QuicPrint(okm, okm_len);
    }

    printf("All %lu testcases of HKDF passed\n", QUIC_HKDF_TEST_NUM);
    return QUIC_HKDF_TEST_NUM;
}

