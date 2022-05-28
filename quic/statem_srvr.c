/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "statem.h"

#include "quic_local.h"
#include "common.h"
#include "datagram.h"
#include "format.h"
#include "packet_local.h"
#include "tls.h"
#include "tls_lib.h"
#include "log.h"

static int QuicTlsSrvrServerHelloPostWork(QUIC *);
static int QuicTlsServerReadFinishedPostWork(QUIC *);
static int QuicTlsServerWriteFinishedPostWork(QUIC *);

static const QuicStatemMachine kServerStatem[QUIC_STATEM_MAX] = {
    [QUIC_STATEM_TLS_ST_OK] = {
        .next_state = QUIC_STATEM_TLS_ST_SR_CLIENT_HELLO,
        .rw_state = QUIC_NOTHING,
    },
    [QUIC_STATEM_TLS_ST_SR_CLIENT_HELLO] = {
        .next_state = QUIC_STATEM_TLS_ST_SW_SERVER_HELLO,
        .rw_state = QUIC_READING,
        .msg_type = TLS_MT_CLIENT_HELLO,
        .handshake = TlsClientHelloProc,
        .post_work = TlsSrvrClientHelloPostWork,
        .pkt_type = QUIC_PKT_TYPE_INITIAL,
    },
    [QUIC_STATEM_TLS_ST_SW_SERVER_HELLO] = {
        .next_state = QUIC_STATEM_TLS_ST_SW_ENCRYPTED_EXTENSIONS,
        .rw_state = QUIC_WRITING,
        .msg_type = TLS_MT_SERVER_HELLO,
        .handshake = TlsServerHelloBuild,
        .post_work = QuicTlsSrvrServerHelloPostWork,
        .pkt_type = QUIC_PKT_TYPE_INITIAL,
    },
    [QUIC_STATEM_TLS_ST_SW_ENCRYPTED_EXTENSIONS] = {
        .next_state = QUIC_STATEM_TLS_ST_SW_CERT_REQUEST,
        .rw_state = QUIC_WRITING,
        .msg_type = TLS_MT_ENCRYPTED_EXTENSIONS,
        .handshake = TlsSrvrEncryptedExtBuild,
        .pkt_type = QUIC_PKT_TYPE_HANDSHAKE,
    },
    [QUIC_STATEM_TLS_ST_SW_CERT_REQUEST] = {
        .next_state = QUIC_STATEM_TLS_ST_SW_SERVER_CERTIFICATE,
        .rw_state = QUIC_WRITING,
        .msg_type = TLS_MT_CERTIFICATE_REQUEST,
        .handshake = TlsSrvrCertRequestBuild,
        .skip_check = TlsSrvrSkipCheckCertRequest,
        .pkt_type = QUIC_PKT_TYPE_HANDSHAKE,
    },
    [QUIC_STATEM_TLS_ST_SW_SERVER_CERTIFICATE] = {
        .next_state = QUIC_STATEM_TLS_ST_SW_CERT_VERIFY,
        .rw_state = QUIC_WRITING,
        .msg_type = TLS_MT_CERTIFICATE,
        .handshake = TlsSrvrServerCertBuild,
        .pkt_type = QUIC_PKT_TYPE_HANDSHAKE,
    },
    [QUIC_STATEM_TLS_ST_SW_CERT_VERIFY] = {
        .next_state = QUIC_STATEM_TLS_ST_SW_FINISHED,
        .rw_state = QUIC_WRITING,
        .msg_type = TLS_MT_CERTIFICATE_VERIFY,
        .handshake = TlsSrvrCertVerifyBuild,
        .pkt_type = QUIC_PKT_TYPE_HANDSHAKE,
    },
    [QUIC_STATEM_TLS_ST_SW_FINISHED] = {
        .next_state = QUIC_STATEM_TLS_ST_SR_FINISHED,
        .rw_state = QUIC_WRITING,
        .msg_type = TLS_MT_FINISHED,
        .handshake = TlsSrvrFinishedBuild,
        .post_work = QuicTlsServerWriteFinishedPostWork,
        .pkt_type = QUIC_PKT_TYPE_HANDSHAKE,
    },
    [QUIC_STATEM_TLS_ST_SR_CLIENT_CERTIFICATE] = {
        .next_state = QUIC_STATEM_TLS_ST_SR_CERT_VERIFY,
        .rw_state = QUIC_READING,
        .msg_type = TLS_MT_CERTIFICATE,
        .handshake = TlsSrvrCertProc,
        .pkt_type = QUIC_PKT_TYPE_HANDSHAKE,
    },
    [QUIC_STATEM_TLS_ST_SR_CERT_VERIFY] = {
        .next_state = QUIC_STATEM_TLS_ST_SR_FINISHED,
        .rw_state = QUIC_READING,
        .msg_type = TLS_MT_CERTIFICATE_VERIFY,
        .handshake = TlsSrvrCertVerifyProc,
        .pkt_type = QUIC_PKT_TYPE_HANDSHAKE,
    },
    [QUIC_STATEM_TLS_ST_SR_FINISHED] = {
        .next_state = QUIC_STATEM_TLS_ST_SW_NEW_SESSION_TICKET,
        .rw_state = QUIC_READING,
        .msg_type = TLS_MT_FINISHED,
        .handshake = TlsSrvrFinishedProc,
        .post_work = QuicTlsServerReadFinishedPostWork,
        .pkt_type = QUIC_PKT_TYPE_HANDSHAKE,
    },
    [QUIC_STATEM_TLS_ST_SW_NEW_SESSION_TICKET] = {
        .next_state = QUIC_STATEM_TLS_ST_SW_NEW_SESSION_TICKET,
        .rw_state = QUIC_WRITING,
        .msg_type = TLS_MT_NEW_SESSION_TICKET,
        .handshake = TlsSrvrNewSessionTicketBuild,
        .pkt_type = QUIC_PKT_TYPE_1RTT,
    },
    [QUIC_STATEM_TLS_ST_SW_HANDSHAKE_DONE] = {
        .rw_state = QUIC_FINISHED,
        .next_state = QUIC_STATEM_HANDSHAKE_DONE,
    },
    [QUIC_STATEM_HANDSHAKE_DONE] = {
        .rw_state = QUIC_FINISHED,
        .next_state = QUIC_STATEM_HANDSHAKE_DONE,
    },
};
 
static int QuicTlsSrvrServerHelloPostWork(QUIC *quic)
{
    if (QuicCreateHandshakeServerEncoders(quic) < 0) {
        return -1;
    }

    return 0;
}

static int QuicTlsServerReadFinishedPostWork(QUIC *quic)
{
    return 0;
}

static int QuicTlsServerWriteFinishedPostWork(QUIC *quic)
{
    TLS *s = &quic->tls;
    size_t secret_size = 0;

    if (TlsGenerateMasterSecret(s, s->master_secret, s->handshake_secret,
                                    &secret_size) < 0) {
        return -1;
    }

    if (QuicCreateHandshakeClientDecoders(quic) < 0) {
        return -1;
    }

    return QuicCreateAppDataServerEncoders(quic);
}

int QuicAccept(QUIC *quic)
{
    return QuicHandshakeStatem(quic, kServerStatem, QUIC_NELEM(kServerStatem));
}
