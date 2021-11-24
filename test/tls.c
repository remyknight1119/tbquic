/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "quic_test.h"

#include <stdio.h>
#include <string.h>

#include <tbquic/quic.h>

#include "tls_cipher.h"
#include "list.h"

int QuicVTlsCipherListTest(void)
{
    TlsCipherListNode *pos = NULL;
    HLIST_HEAD(h);
    char ciphers[sizeof(TLS_CIPHERS_DEF)] = {};
    int offset = 0;

    if (QuicTlsCreateCipherList(&h, TLS_CIPHERS_DEF,
                    sizeof(TLS_CIPHERS_DEF) - 1) < 0) {
        return -1;
    }

    hlist_for_each_entry(pos, &h, node)	{
        if (offset != 0) {
            offset += snprintf(&ciphers[offset], sizeof(ciphers) - offset,
                        TLS_CIPHERS_SEP);
        }
        offset += snprintf(&ciphers[offset], sizeof(ciphers) - offset,
                    "%s", pos->cipher->name);
        if (offset >= sizeof(ciphers)) {
            QuicTlsDestroyCipherList(&h);
            return -1;
        }
    }

    if (strcmp(ciphers, TLS_CIPHERS_DEF) != 0) {
        QuicTlsDestroyCipherList(&h);
        return -1;
    }

    QuicTlsDestroyCipherList(&h);
    return 1;
}

