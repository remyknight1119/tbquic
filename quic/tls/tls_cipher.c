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


#define TLS_CIPHER_DEF_IDS_NUM  QUIC_NELEM(tls_cipher_def_ids)

static const TlsCipher tls_ciphers[] = {
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

#define TLS_CIPHERS_NUM  QUIC_NELEM(tls_ciphers)

const TlsCipher *QuicGetTlsCipherByName(const char *name, size_t name_len)
{
    const TlsCipher *cipher = NULL;
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
 
const TlsCipher *QuicGetTlsCipherById(uint16_t id)
{
    const TlsCipher *cipher = NULL;
    int i = 0;

    for (i = 0; i < TLS_CIPHERS_NUM; i++) {
        cipher = &tls_ciphers[i];
        if (cipher->id == id) {
            return cipher;
        }
    }

    return NULL;
}

int QuicTlsParseCipherList(struct hlist_head *h, RPacket *pkt, size_t len)
{
    const TlsCipher *cipher = NULL;
    TlsCipherListNode *node = NULL;
    struct hlist_node *tail = NULL;
    uint32_t id = 0;
    size_t rlen = 0;

    for (rlen = 0; rlen < len; rlen += 2) {
        if (RPacketGet2(pkt, &id) < 0) {
            goto err;
        }

        cipher = QuicGetTlsCipherById(id);
        if (cipher == NULL) {
            QUIC_LOG("Cipher ID(%X) not valid\n", id);
            goto err;
        }
        node = QuicMemCalloc(sizeof(*node));
        if (node == NULL) {
            goto err;
        }
        node->cipher = cipher;
        if (tail == NULL) {
            hlist_add_head(&node->node, h);
        } else {
            hlist_add_behind(&node->node, tail);
        }
        tail = &node->node;
    }

    return 0;
err:
    QuicTlsDestroyCipherList(h);
    return -1;
}

int QuicTlsCreateCipherList(struct hlist_head *h, const char *cipher_str,
                            size_t cipher_str_len)
{
    const TlsCipher *cipher = NULL;
    TlsCipherListNode *node = NULL;
    struct hlist_node *tail = NULL;
    const char *name = NULL;
    const char *sep = NULL;
    size_t len = 0;

    if (!hlist_empty(h)) {
        return 0;
    }

    name = cipher_str;
    do {
        sep = strstr(name, TLS_CIPHERS_SEP);
        if (sep != NULL) {
            len = sep - name;
            if (QUIC_GT(len, cipher_str_len)) {
                len = cipher_str_len;
                sep = NULL;
            }
        } else {
            len = strlen(name);
        }
        
        cipher = QuicGetTlsCipherByName(name, len);
        name = sep + 1;
        if (cipher == NULL) {
            continue;
        }

        node = QuicMemCalloc(sizeof(*node));
        if (node == NULL) {
            QuicTlsDestroyCipherList(h);
            return -1;
        }
        node->cipher = cipher;
        if (tail == NULL) {
            hlist_add_head(&node->node, h);
        } else {
            hlist_add_behind(&node->node, tail);
        }
        tail = &node->node;
    } while (sep != NULL);

    return 0;
}

void QuicTlsDestroyCipherList(struct hlist_head *h)
{
    TlsCipherListNode *pos = NULL;
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

