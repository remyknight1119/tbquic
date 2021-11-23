/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "tls_cipher.h"

#include <assert.h>
#include <string.h>
#include <tbquic/types.h>
#include <tbquic/cipher.h>
#include <tbquic/quic.h>

#include "common.h"
#include "log.h"
#include "tls.h"
#include "cipher.h"
#include "mem.h"

#define TLS_CIPHERS_SEP ":"
#define TLS_CIPHERS_DEF \
    TLS_RFC_AES_128_GCM_SHA256 TLS_CIPHERS_SEP TLS_RFC_AES_256_GCM_SHA384 \
    TLS_CIPHERS_SEP TLS_RFC_CHACHA20_POLY1305_SHA256

#define TLS_CIPHER_DEF_IDS_NUM  QUIC_ARRAY_SIZE(tls_cipher_def_ids)

static TlsCipher tls_ciphers[] = {
    {
        .name = TLS_RFC_AES_128_GCM_SHA256,
        .id = TLS_CK_AES_128_GCM_SHA256,
        .algorithm_enc = QUIC_ALG_AES_128_GCM,
        .digest = QUIC_DIGEST_SHA256, 
        .alg_bits = 128,
        .strength_bits = 128,
    },
    {
        .name = TLS_RFC_AES_256_GCM_SHA384,
        .id = TLS_CK_AES_256_GCM_SHA384,
        .algorithm_enc = QUIC_ALG_AES_256_GCM,
        .digest = QUIC_DIGEST_SHA384, 
        .alg_bits = 256,
        .strength_bits = 256,
    },
    {
        .name = TLS_RFC_CHACHA20_POLY1305_SHA256,
        .id = TLS_CK_CHACHA20_POLY1305_SHA256,
        .algorithm_enc = QUIC_ALG_CHACHA20POLY1305,
        .digest = QUIC_DIGEST_SHA256, 
        .alg_bits = 256,
        .strength_bits = 256,
    },
    {
        .name = TLS_RFC_AES_128_CCM_SHA256,
        .id = TLS_CK_AES_128_CCM_SHA256,
        .algorithm_enc = QUIC_ALG_AES_128_CCM,
        .digest = QUIC_DIGEST_SHA256, 
        .alg_bits = 128,
        .strength_bits = 128,
    },
    {
        .name = TLS_RFC_AES_128_CCM_8_SHA256,
        .id = TLS_CK_AES_128_CCM_8_SHA256,
        .algorithm_enc = QUIC_ALG_AES_128_CCM_8,
        .digest = QUIC_DIGEST_SHA256, 
        .alg_bits = 128,
        .strength_bits = 128,
    },
};

#define TLS_CIPHERS_NUM  QUIC_ARRAY_SIZE(tls_ciphers)

TlsCipher *QuicGetTlsCipherByName(const char *name, size_t name_len)
{
    TlsCipher *cipher = NULL;
    size_t len = 0;
    int i = 0;

    for (i = 0; i < TLS_CIPHERS_NUM; i++) {
        cipher = &tls_ciphers[i];
        len = strlen(cipher->name);
        if (len == name_len && strncmp(cipher->name, name, len) == 0) {
            return cipher;
        }
    }

    return NULL;
}
 
TlsCipher *QuicGetTlsCipherById(uint16_t id)
{
    TlsCipher *cipher = NULL;
    int i = 0;

    for (i = 0; i < TLS_CIPHERS_NUM; i++) {
        cipher = &tls_ciphers[i];
        if (cipher->id == id) {
            return cipher;
        }
    }

    return NULL;
}

int QuicTlsCreateCipherList(struct hlist_head *h, const char *cipher_str,
                            size_t len)
{
    if (!hlist_empty(h)) {
        return 0;
    }

    return 0;
}

void QuicTlsDestroyCipherList(struct hlist_head *h)
{
    TlsCipherList *pos = NULL;
    struct hlist_node *n = NULL;

    if (hlist_empty(h)) {
        return;
    }

    hlist_for_each_entry_safe(pos, n, h, node) {
        hlist_del(&pos->node);
        QuicMemFree(pos);
    }

    QuicMemFree(h->first);
    h->first = NULL;
}

