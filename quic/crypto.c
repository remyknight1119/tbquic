/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "crypto.h"

#include <string.h>
#include <openssl/hmac.h>

#include "packet_local.h"

uint8_t *HkdfExtract(const EVP_MD *evp_md, const uint8_t *salt, size_t salt_len,
                        const uint8_t *key, size_t key_len, uint8_t *prk,
                        size_t *prk_len)
{
    unsigned int tmp_len;

    if (!HMAC(evp_md, (const unsigned char *)salt, salt_len,
                (const unsigned char *)key, key_len,
                (unsigned char *)prk, &tmp_len)) {
        return NULL;
    }

    *prk_len = tmp_len;
    return prk;
}


uint8_t *HkdfExpand(const EVP_MD *evp_md, const uint8_t *prk, size_t prk_len,
                                  const uint8_t *info, size_t info_len,
                                  uint8_t *okm, size_t okm_len)
{
    HMAC_CTX *hmac;
    uint8_t *ret = NULL;
    uint8_t i;
    unsigned char prev[EVP_MAX_MD_SIZE];

    size_t done_len = 0, dig_len = EVP_MD_size(evp_md);

    size_t n = okm_len / dig_len;

    if (okm_len % dig_len) {
        n++;
    }

    if (n > 255 || okm == NULL) {
        return NULL;
    }

    if ((hmac = HMAC_CTX_new()) == NULL) {
        return NULL;
    }

    if (!HMAC_Init_ex(hmac, prk, prk_len, evp_md, NULL)) {
        goto err;
    }

    for (i = 1; i <= n; i++) {
        size_t copy_len;
        const unsigned char ctr = i;

        if (i > 1) {
            if (!HMAC_Init_ex(hmac, NULL, 0, NULL, NULL)) {
                goto err;
            }

            if (!HMAC_Update(hmac, prev, dig_len)) {
                goto err;
            }
        }

        if (!HMAC_Update(hmac, info, info_len)) {
            goto err;
        }

        if (!HMAC_Update(hmac, &ctr, 1)) {
            goto err;
        }

        if (!HMAC_Final(hmac, prev, NULL)) {
            goto err;
        }

        copy_len = (done_len + dig_len > okm_len) ?
                       okm_len - done_len :
                       dig_len;

        memcpy(okm + done_len, prev, copy_len);

        done_len += copy_len;
    }
    ret = okm;

 err:
    OPENSSL_cleanse(prev, sizeof(prev));
    HMAC_CTX_free(hmac);
    return ret;
}

int TLS13HkdfExpand(const EVP_MD *md, const uint8_t *secret,
                        size_t secret_len, const uint8_t *label,
                        size_t labellen, const uint8_t *data,
                        size_t datalen, uint8_t *out,
                        size_t outlen)
{
    BUF_MEM *buf = NULL;
    WPacket pkt = {};
    static const unsigned char label_prefix[] = "tls13 ";
    size_t buf_len = 0;

    if ((buf = BUF_MEM_new()) == NULL) {
        goto out;
    }

    buf_len = sizeof(uint16_t) + sizeof(uint8_t) + (sizeof(label_prefix) - 1) +
                labellen + sizeof(uint8_t) + datalen;
    if (BUF_MEM_grow(buf, buf_len) == 0) {
        goto out;
    }

    WPacketBufInit(&pkt, buf);

    return 0;
out:
    BUF_MEM_free(buf);
    return -1;
}

int QuicTLS13HkdfExpand(const EVP_MD *md, const uint8_t *secret,
                        size_t secret_len, const uint8_t *label,
                        size_t labellen, uint8_t *out, size_t outlen)
{
    return TLS13HkdfExpand(md, secret, secret_len, label, labellen, NULL, 0,
                            out, outlen);
}

