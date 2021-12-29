/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "tls.h"

#include <assert.h>
#include <string.h>
#include <tbquic/types.h>
#include <tbquic/quic.h>

#include "rand.h"
#include "packet_local.h"
#include "common.h"
#include "tls_cipher.h"
#include "log.h"

#ifdef QUIC_TEST
uint8_t *quic_random_test;
#endif

int TlsGenRandom(uint8_t *random, size_t len, WPacket *pkt)
{
    if (QuicRandBytes(random, len) < 0) {
        QUIC_LOG("Generate Random failed\n");
        return -1;
    }

#ifdef QUIC_TEST
    if (quic_random_test != NULL) {
        memcpy(random, quic_random_test, len);
    }
#endif

    return WPacketMemcpy(pkt, random, len);
}

int TlsPutCipherList(TLS *tls, WPacket *pkt)
{
    TlsCipherListNode *node = NULL;
    int ret = 0;

    if (WPacketStartSubU16(pkt) < 0) { 
        return -1;
    }

    hlist_for_each_entry(node, &tls->cipher_list, node)	{
        assert(node->cipher != NULL);
        if (WPacketPut2(pkt, node->cipher->id) < 0) {
            ret = -1;
            break;
        }
    }

    if (WPacketClose(pkt) < 0) {
        QUIC_LOG("Close packet failed\n");
        return -1;
    }

    return ret;
}

int TlsPutCompressionMethod(WPacket *pkt)
{
    return WPacketPut1(pkt, 0);
}

