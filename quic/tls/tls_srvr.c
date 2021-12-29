/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "tls.h"

#include <assert.h>
#include <tbquic/types.h>
#include <tbquic/quic.h>

#include "packet_local.h"
#include "tls_cipher.h"
#include "common.h"
#include "log.h"

static int TlsClientHelloProc(TLS *, void *);
static int TlsServerHelloBuild(TLS *, void *);

static const TlsProcess server_proc[HANDSHAKE_MAX] = {
    [TLS_ST_OK] = {
        .flow_state = QUIC_FLOW_NOTHING,
        .next_state = TLS_ST_SR_CLIENT_HELLO,
    },
    [TLS_ST_SR_CLIENT_HELLO] = {
        .flow_state = QUIC_FLOW_READING,
        //.next_state = TLS_ST_SW_SERVER_HELLO,
        .next_state = TLS_ST_HANDSHAKE_DONE,
        .handshake_type = CLIENT_HELLO,
        .handler = TlsClientHelloProc,
    },
    [TLS_ST_SW_SERVER_HELLO] = {
        .flow_state = QUIC_FLOW_WRITING,
        .next_state = TLS_ST_SW_SERVER_CERTIFICATE,
        .handshake_type = SERVER_HELLO,
        .handler = TlsServerHelloBuild,
    },
};

static QuicFlowReturn TlsAccept(TLS *tls)
{
    return TlsHandshake(tls, server_proc, QUIC_NELEM(server_proc));
}

static int TlsClientHelloProc(TLS *tls, void *packet)
{
    RPacket *pkt = packet;
    const TlsCipher *cipher = NULL;
    TlsCipherListNode *server_cipher = NULL;
    HLIST_HEAD(cipher_list);
    uint32_t cipher_len = 0;
    uint32_t compress_len = 0;

    if (TlsHelloHeadParse(tls, pkt, tls->client_random,
                sizeof(tls->client_random)) < 0) {
        return -1;
    }

    if (RPacketGet2(pkt, &cipher_len) < 0) {
        return -1;
    }

    if (cipher_len & 0x01) {
        return -1;
    }

    if (RPacketRemaining(pkt) < cipher_len) {
        return -1;
    }

    if (TlsParseCipherList(&cipher_list, pkt, cipher_len) < 0) {
        return -1;
    }

    hlist_for_each_entry(server_cipher, &tls->cipher_list, node) {
        assert(server_cipher->cipher != NULL);
        cipher = TlsCipherMatchListById(&cipher_list,
                server_cipher->cipher->id);
        if (cipher != NULL) {
            break;
        }
    }

    TlsDestroyCipherList(&cipher_list);
    if (cipher == NULL) {
        QUIC_LOG("No shared cipher found\n");
        return -1;
    }

    /* Skip legacy Compression Method */
    if (RPacketGet1(pkt, &compress_len) < 0) {
        return -1;
    }

    if (RPacketPull(pkt, compress_len) < 0) {
        return -1;
    }

    if (TlsExtLenParse(pkt) < 0) {
        return -1;
    }

    return 0;
}

static int TlsServerHelloBuild(TLS *tls, void *packet)
{
    printf("SSSSSSSSSSSSSSSSSSSSSServerhello Build\n");
    return 0;
}

void TlsServerInit(TLS *tls)
{
    tls->handshake = TlsAccept;
}
