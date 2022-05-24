/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "statem.h"

#include <assert.h>
#include <openssl/rand.h>

#include "quic_local.h"
#include "format.h"
#include "common.h"
#include "datagram.h"
#include "mem.h"
#include "rand.h"
#include "tls.h"
#include "log.h"

static int QuicTlsClientHelloPreWork(QUIC *);
static int QuicTlsClientHelloPostWork(QUIC *);
static int QuicClntTlsEncExtPostWork(QUIC *);
static int QuicClntTlsFinishedPostWork(QUIC *);

static const QuicStatemMachine client_statem[QUIC_STATEM_MAX] = {
    [QUIC_STATEM_TLS_ST_OK] = {
        .next_state = QUIC_STATEM_TLS_ST_CW_CLIENT_HELLO,
        .rw_state = QUIC_NOTHING,
    },
    [QUIC_STATEM_TLS_ST_CW_CLIENT_HELLO] = {
        .next_state = QUIC_STATEM_TLS_ST_CR_SERVER_HELLO,
        .rw_state = QUIC_WRITING,
        .msg_type = TLS_MT_CLIENT_HELLO,
        .pre_work = QuicTlsClientHelloPreWork,
        .post_work = QuicTlsClientHelloPostWork,
        .handshake = TlsClntHelloBuild,
        .pkt_type = QUIC_PKT_TYPE_INITIAL,
    },
    [QUIC_STATEM_TLS_ST_CR_SERVER_HELLO] = {
        .next_state = QUIC_STATEM_TLS_ST_CR_ENCRYPTED_EXTENSIONS,
        .rw_state = QUIC_READING,
        .msg_type = TLS_MT_SERVER_HELLO,
        .handshake = TlsServerHelloProc,
        .pkt_type = QUIC_PKT_TYPE_INITIAL,
    },
    [QUIC_STATEM_TLS_ST_CR_ENCRYPTED_EXTENSIONS] = {
        .next_state = QUIC_STATEM_TLS_ST_CR_CERT_REQUEST,
        .rw_state = QUIC_READING,
        .msg_type = TLS_MT_ENCRYPTED_EXTENSIONS,
        .handshake = TlsClntEncExtProc,
        .post_work = QuicClntTlsEncExtPostWork,
        .pkt_type = QUIC_PKT_TYPE_HANDSHAKE,
    },
    [QUIC_STATEM_TLS_ST_CR_CERT_REQUEST] = {
        .next_state = QUIC_STATEM_TLS_ST_CR_SERVER_CERTIFICATE,
        .rw_state = QUIC_READING,
        .msg_type = TLS_MT_CERTIFICATE_REQUEST,
        .handshake = TlsCertRequestProc,
        .skip_check = TlsClntSkipCheckCertRequest,
        .pkt_type = QUIC_PKT_TYPE_HANDSHAKE,
    },
    [QUIC_STATEM_TLS_ST_CR_SERVER_CERTIFICATE] = {
        .next_state = QUIC_STATEM_TLS_ST_CR_CERT_VERIFY,
        .rw_state = QUIC_READING,
        .msg_type = TLS_MT_CERTIFICATE,
        .handshake = TlsServerCertProc,
        .skip_check = TlsClntSkipCheckServerCert,
        .pkt_type = QUIC_PKT_TYPE_HANDSHAKE,
    },
    [QUIC_STATEM_TLS_ST_CR_CERT_VERIFY] = {
        .next_state = QUIC_STATEM_TLS_ST_CR_FINISHED,
        .rw_state = QUIC_READING,
        .msg_type = TLS_MT_CERTIFICATE_VERIFY,
        .handshake = TlsCertVerifyProc,
        .skip_check = TlsClntSkipCheckCertVerify,
        .pkt_type = QUIC_PKT_TYPE_HANDSHAKE,
    },
    [QUIC_STATEM_TLS_ST_CR_FINISHED] = {
        .next_state = QUIC_STATEM_TLS_ST_CW_FINISHED,
        .rw_state = QUIC_READING,
        .msg_type = TLS_MT_FINISHED,
        .handshake = TlsClntFinishedProc,
        .pkt_type = QUIC_PKT_TYPE_HANDSHAKE,
    },
    [QUIC_STATEM_TLS_ST_CW_CLIENT_CERTIFICATE] = {
        .next_state = QUIC_STATEM_TLS_ST_CW_CERT_VERIFY,
        .rw_state = QUIC_WRITING,
        .msg_type = TLS_MT_CERTIFICATE,
        .handshake = TlsClntCertBuild,
        .pkt_type = QUIC_PKT_TYPE_INITIAL,
    },
    [QUIC_STATEM_TLS_ST_CW_CERT_VERIFY] = {
        .next_state = QUIC_STATEM_TLS_ST_CW_FINISHED,
        .rw_state = QUIC_WRITING,
        .msg_type = TLS_MT_CERTIFICATE_VERIFY,
        .handshake = TlsClntCertVerifyBuild,
        .pkt_type = QUIC_PKT_TYPE_INITIAL,
    },
    [QUIC_STATEM_TLS_ST_CW_FINISHED] = {
        .next_state = QUIC_STATEM_TLS_ST_CR_NEW_SESSION_TICKET,
        .rw_state = QUIC_WRITING,
        .msg_type = TLS_MT_FINISHED,
        .handshake = TlsClntFinishedBuild,
        .post_work = QuicClntTlsFinishedPostWork,
        .pkt_type = QUIC_PKT_TYPE_HANDSHAKE,
    },
    [QUIC_STATEM_TLS_ST_CR_NEW_SESSION_TICKET] = {
        .next_state = QUIC_STATEM_TLS_ST_CR_NEW_SESSION_TICKET,
        .rw_state = QUIC_READING,
        .msg_type = TLS_MT_NEW_SESSION_TICKET,
        .handshake = TlsClntNewSessionTicketProc,
        .pkt_type = QUIC_PKT_TYPE_1RTT,
    },
    [QUIC_STATEM_HANDSHAKE_DONE] = {
        .next_state = QUIC_STATEM_HANDSHAKE_DONE,
        .rw_state = QUIC_FINISHED,
        .pkt_type = QUIC_PKT_TYPE_1RTT,
    },
};

static int QuicTlsClientHelloPreWork(QUIC *quic)
{
    QUIC_DATA *cid = NULL;

    cid = &quic->dcid;
    if (cid->data == NULL && QuicCidGen(cid, quic->cid_len) < 0) {
        return -1;
    }

    if (QuicCreateInitialDecoders(quic, quic->version, cid) < 0) {
        return -1;
    }

    return 0;
}

static int QuicTlsClientHelloPostWork(QUIC *quic)
{
    QuicBufReserve(QUIC_TLS_BUFFER(quic));
    return 0;
}

static int QuicClntTlsEncExtPostWork(QUIC *quic)
{
    if (QuicStreamInit(quic) < 0) {
        return -1;
    }

    return 0;
}

static int QuicClntTlsFinishedPostWork(QUIC *quic)
{
    return QuicCreateAppDataClientEncoders(quic);
}

int QuicConnect(QUIC *quic)
{
    return QuicHandshakeStatem(quic, client_statem, QUIC_NELEM(client_statem));
}

