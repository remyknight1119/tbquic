/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "statem.h"

#include <assert.h>
#include <openssl/err.h>

#include "quic_local.h"
#include "format.h"
#include "rand.h"
#include "datagram.h"
#include "q_buff.h"
#include "mem.h"
#include "common.h"
#include "frame.h"
#include "log.h"

static const char *kQuicStateStr[QUIC_STATEM_MAX] = {
    [QUIC_STATEM_TLS_ST_OK] = "TLS State OK",
    [QUIC_STATEM_TLS_ST_CW_CLIENT_HELLO] = "Client Write ClientHello",
    [QUIC_STATEM_TLS_ST_CW_CLIENT_CERTIFICATE] = "Client Write Client Cert",
    [QUIC_STATEM_TLS_ST_CW_CERT_VERIFY] = "Client Write Cert Verify",
    [QUIC_STATEM_TLS_ST_CW_FINISHED] = "Client Write Finished",
    [QUIC_STATEM_TLS_ST_CR_SERVER_HELLO] = "Client Read ServerHello",
    [QUIC_STATEM_TLS_ST_CR_ENCRYPTED_EXTENSIONS] = "Client Read Enc Ext",
    [QUIC_STATEM_TLS_ST_CR_CERT_REQUEST] = "Client Read Cert Request",
    [QUIC_STATEM_TLS_ST_CR_SERVER_CERTIFICATE] = "Client Read Server Cert",
    [QUIC_STATEM_TLS_ST_CR_CERT_VERIFY] = "Client Read Cert Verify",
    [QUIC_STATEM_TLS_ST_CR_FINISHED] = "Client Read Finished",
    [QUIC_STATEM_TLS_ST_CR_NEW_SESSION_TICKET] = "Client Read New Sess Ticket",
    [QUIC_STATEM_TLS_ST_SR_CLIENT_HELLO] = "Server Read ClientHello",
    [QUIC_STATEM_TLS_ST_SR_CLIENT_CERTIFICATE] = "Server Read Client Cert",
    [QUIC_STATEM_TLS_ST_SR_CERT_VERIFY] = "Server Cert Verify",
    [QUIC_STATEM_TLS_ST_SR_FINISHED] = "Server Read Finished",
    [QUIC_STATEM_TLS_ST_SW_SERVER_HELLO] = "Server Write ServerHello",
    [QUIC_STATEM_TLS_ST_SW_ENCRYPTED_EXTENSIONS] = "Server Write Enc Ext",
    [QUIC_STATEM_TLS_ST_SW_CERT_REQUEST] = "Server Write Cert Request",
    [QUIC_STATEM_TLS_ST_SW_SERVER_CERTIFICATE] = "Server Write Server Cert",
    [QUIC_STATEM_TLS_ST_SW_CERT_VERIFY] = "Server Write Cert Verify",
    [QUIC_STATEM_TLS_ST_SW_FINISHED] = "Server Write Finished",
    [QUIC_STATEM_TLS_ST_SW_NEW_SESSION_TICKET] = "Server Write New Sess Ticket",
    [QUIC_STATEM_TLS_ST_SW_HANDSHAKE_DONE] = "Server ",
	[QUIC_STATEM_HANDSHAKE_DONE] = "Server ",
#if 0
	QUIC_STATEM_CLOSING,
	QUIC_STATEM_DRAINING,
	QUIC_STATEM_CLOSED,
#endif
};

const char *QuicStatStrGet(QuicStatem state)
{
    const char *str = NULL;

    if (state < 0 || state >= QUIC_STATEM_MAX) {
        return "";
    }

    str = kQuicStateStr[state];
    if (str == NULL) {
        str = "";
    }

    return str;
}

int QuicStatemReadBytes(QUIC *quic, RPacket *pkt)
{
    QUIC_DATA *buf = quic->read_buf;
    int rlen = 0;

    assert(buf != NULL);
    rlen = QuicDatagramRecv(quic, buf->data, buf->len);
    if (rlen < 0) {
        return -1;
    }

    RPacketBufInit(pkt, buf->data, rlen);
    return 0;
}

static int QuicPktParse(QUIC *quic, RPacket *pkt)
{
    const uint8_t *stateless_reset_token = NULL;
    QUIC_DATA new_dcid = {};
    QuicPacketFlags flags;
    bool update_dcid = false;
    uint64_t offset = 0;
    uint32_t type = 0;

    if (QuicGetPktFlags(&flags, pkt) < 0) {
        return -1;
    }

    offset = RPacketRemaining(pkt) - QUIC_STATELESS_RESET_TOKEN_LEN;
    if (QUIC_GT(offset, 0)) {
        stateless_reset_token = RPacketData(pkt) + offset;
    }

    if (QuicPktHeaderParse(quic, pkt, flags, &type, &new_dcid,
                            &update_dcid) < 0) {
        QUIC_LOG("Header parse failed\n");
        goto err;
    }

    if (QuicPktBodyParse(quic, pkt, type) < 0) {
        QUIC_LOG("Body parse failed\n");
        goto err;
    }

    if (update_dcid && QuicUpdateDcid(quic, &new_dcid, type) < 0) {
        QUIC_LOG("Update DCID failed\n");
        return -1;
    }

    return 0;
err:

    QuicCheckStatelessResetToken(quic, stateless_reset_token);
    return -1;
}

static void
QuicInitTlsReadBuffer(QUIC *quic, RPacket *pkt)
{
    QUIC_BUFFER *buffer = QUIC_TLS_BUFFER(quic);
    size_t data_len = 0;

    /*
     * Read buffer:
     *                                       second
     * |------------ first read -----------| read  |
     * ---------------------------------------------
     * | prev message | new message seg 1  | seg 2 |
     * ---------------------------------------------
     * |--- offset ---|
     * |------------- total data len --------------|
     *                |--- new message data len ---|
     */
    data_len = QuicBufGetDataLength(buffer) - QuicBufGetOffset(buffer);
    assert(QUIC_GE(data_len, 0));
    RPacketBufInit(pkt, QuicBufMsg(buffer), data_len);
}

static void
QuicInitTlsWriteBuffer(QUIC *quic, WPacket *pkt)
{
    QUIC_BUFFER *buffer = QUIC_TLS_BUFFER(quic);

    WPacketBufInit(pkt, buffer->buf);
}

static QuicFlowReturn
QuicRecvPacket(QUIC *quic, RPacket *pkt)
{
    int rlen = 0;

    if (RPacketRemaining(pkt) == 0) {
        rlen = quic->method->read_bytes(quic, pkt);
        if (rlen < 0) {
            return QUIC_FLOW_RET_STOP;
        }
    } else {
        RPacketUpdate(pkt);
    }

    if (QuicPktParse(quic, pkt) < 0) {
        return QUIC_FLOW_RET_ERROR;
    }

    return QUIC_FLOW_RET_FINISH;
}

static QuicFlowReturn
QuicHandshakeRead(QUIC *quic, QuicStatem *state, const QuicStatemMachine *stm,
                    size_t num, RPacket *pkt, RPacket *qpkt, bool *skip)
{
    QUIC_BUFFER *buffer = QUIC_TLS_BUFFER(quic);
    bool missing_data = false;
    QuicFlowReturn ret = QUIC_FLOW_RET_FINISH;

    while (*state < QUIC_STATEM_HANDSHAKE_DONE) {
        if (RPacketRemaining(pkt) == 0 || missing_data) {
            if (RPacketRemaining(pkt) == 0) {
                QuicBufResetDataLength(buffer);
            }
            ret = QuicRecvPacket(quic, qpkt);
            if (ret != QUIC_FLOW_RET_FINISH) {
                return ret;
            }

            QuicInitTlsReadBuffer(quic, pkt);
            if (RPacketRemaining(pkt) == 0) {
                continue;
            }
            missing_data = false;
        } else {
            RPacketUpdate(pkt);
        }

        ret = TlsHandshakeMsgRead(&quic->tls, state, stm, num, pkt, skip);
        if ((ret == QUIC_FLOW_RET_WANT_READ || ret == QUIC_FLOW_RET_NEXT) &&
                RPacketRemaining(pkt)) {
            if (QuicBufAddOffset(buffer, RPacketReadLen(pkt)) < 0) {
                return QUIC_FLOW_RET_ERROR;
            }
            missing_data = true;
        } else {
            QuicBufResetOffset(buffer);
        }

        if (ret != QUIC_FLOW_RET_WANT_READ) {
            return ret;
        }
    }

    return ret;
}

static QuicFlowReturn
QuicHandshakeWrite(QUIC *quic, QuicStatem *state, const QuicStatemMachine *stm,
                    size_t num, WPacket *pkt, bool *skip)
{
    const QuicStatemMachine *sm = NULL;
    QUIC_BUFFER *buffer = QUIC_TLS_BUFFER(quic);
    QuicFlowReturn ret = QUIC_FLOW_RET_ERROR;

    ret = TlsHandshakeMsgWrite(&quic->tls, state, stm, num, pkt, skip);
    if (ret != QUIC_FLOW_RET_NEXT) {
        return ret;
    }

    QuicBufSetDataLength(buffer, WPacket_get_written(pkt));
    WPacketCleanup(pkt);
    sm = &stm[*state];
    if (QuicCryptoFrameBuild(quic, sm->pkt_type) < 0) {
        return QUIC_FLOW_RET_ERROR;
    }

    QuicInitTlsWriteBuffer(quic, pkt);
    if (QuicSendPacket(quic) < 0) {
        return QUIC_FLOW_RET_ERROR;
    }
    return ret;
}

int
QuicHandshakeStatem(QUIC *quic, const QuicStatemMachine *statem, size_t num)
{
    QUIC_STATEM *st = &quic->statem;
    const QuicStatemMachine *sm = NULL;
    RPacket rpkt = {};
    RPacket qpkt = {};
    WPacket wpkt = {};
    bool skip_state = false;
    QuicStatem state = QUIC_STATEM_TLS_ST_OK;
    QuicFlowReturn ret = QUIC_FLOW_RET_ERROR;
    int res = -1;

    QuicInitTlsReadBuffer(quic, &rpkt);
    QuicInitTlsWriteBuffer(quic, &wpkt);

    while (st->state < QUIC_STATEM_HANDSHAKE_DONE) {
        state = st->state;
        assert(state >= 0 && state < num);

        sm = &statem[state];
        skip_state = false;

        if (sm->pre_work != NULL && sm->pre_work(quic) < 0) {
            goto err;
        }

        switch (sm->rw_state) {
            case QUIC_NOTHING:
                ret = QUIC_FLOW_RET_FINISH;
                break;
            case QUIC_READING:
                ret = QuicHandshakeRead(quic, &st->state, statem, num,
                                            &rpkt, &qpkt, &skip_state);
                break;
            case QUIC_WRITING:
                ret = QuicHandshakeWrite(quic, &st->state, statem, num,
                                            &wpkt, &skip_state);
                break;
            case QUIC_FINISHED:
                res = 0;
                goto out;
            default:
                QUIC_LOG("Unknown state(%d)\n", sm->rw_state);
                return -1;
        }

        if (ret == QUIC_FLOW_RET_CONT) {
            continue;
        }

        sm = &statem[st->state];
        if (ret == QUIC_FLOW_RET_STOP) {
            st->rwstate = sm->rw_state;
            goto out;
        }

        if (ret == QUIC_FLOW_RET_ERROR) {
            goto err;
        }

        if (sm->post_work != NULL && sm->post_work(quic) < 0) {
            goto err;
        }

        if (state == st->state || skip_state) {
            st->state = sm->next_state;
        }
    }

    res = 0;
out:

    if (st->state == QUIC_STATEM_TLS_ST_SW_HANDSHAKE_DONE) {
        QuicDataHandshakeDoneFrameBuild(quic, 0, QUIC_PKT_TYPE_1RTT);
        st->state = QUIC_STATEM_HANDSHAKE_DONE;
        if (QuicSendPacket(quic) < 0) {
            goto err;
        }
    }

    return res;
err:
    QUIC_LOG("Error: state = \"%s\"\n", QuicStatStrGet(state));
    st->rwstate = QUIC_NOTHING;
    return -1;
}

static int
QuicLongPktParse(QUIC *quic, RPacket *pkt, QuicPacketFlags flags, uint8_t type,
                    QUIC_DATA *new_dcid, bool *update_dcid)
{
    if (!QUIC_PACKET_IS_LONG_PACKET(flags)) {
        QUIC_LOG("Not Long packet\n");
        return -1;
    }

    if (flags.lh.lpacket_type != type) {
        QUIC_LOG("Type not match\n");
        return -1;
    }

    if (QuicLPacketHeaderParse(quic, pkt, new_dcid, update_dcid) < 0) {
        QUIC_LOG("Header Parse failed\n");
        return -1;
    }

    return 0;
}

QuicFlowReturn
QuicInitialRecv(QUIC *quic, RPacket *pkt, QuicPacketFlags flags)
{
    QUIC_DATA new_dcid = {};
    bool update_dcid = false;

    if (QuicLongPktParse(quic, pkt, flags, QUIC_LPACKET_TYPE_INITIAL,
                &new_dcid, &update_dcid) < 0) {
        return QUIC_FLOW_RET_ERROR;
    }

    if (QuicInitPacketParse(quic, pkt, &quic->initial) < 0) {
        return QUIC_FLOW_RET_ERROR;
    }

    if (update_dcid && QuicUpdateDcid(quic, &new_dcid,
                QUIC_LPACKET_TYPE_INITIAL) < 0) {
        QUIC_LOG("Update DCID failed\n");
        return QUIC_FLOW_RET_ERROR;
    }

    return QUIC_FLOW_RET_FINISH;
}

int QuicInitialPktBuild(QUIC *quic)
{
    return QuicCryptoFrameBuild(quic, QUIC_PKT_TYPE_INITIAL);
}

int QuicHandshakePktBuild(QUIC *quic)
{
    return QuicCryptoFrameBuild(quic, QUIC_PKT_TYPE_HANDSHAKE);
}

int QuicOneRttPktBuild(QUIC *quic)
{
    return QuicCryptoFrameBuild(quic, QUIC_PKT_TYPE_1RTT);
}

QuicFlowReturn QuicPacketRead(QUIC *quic, RPacket *pkt, QuicPacketFlags flags)
{
    const uint8_t *stateless_reset_token = NULL;
    QUIC_DATA new_dcid = {};
    bool update_dcid = false;
    uint64_t offset = 0;
    uint32_t type = 0;

    offset = RPacketRemaining(pkt) - QUIC_STATELESS_RESET_TOKEN_LEN;
    if (QUIC_GT(offset, 0)) {
        stateless_reset_token = RPacketData(pkt) + offset;
    }

    if (QuicPktHeaderParse(quic, pkt, flags, &type, &new_dcid,
                            &update_dcid) < 0) {
        QUIC_LOG("Header parse failed\n");
        goto err;
    }

    if (QuicPktBodyParse(quic, pkt, type) < 0) {
        QUIC_LOG("Body parse failed\n");
        goto err;
    }

    if (update_dcid && QuicUpdateDcid(quic, &new_dcid, type) < 0) {
        QUIC_LOG("Update DCID failed\n");
        return QUIC_FLOW_RET_ERROR;
    }

    return QUIC_FLOW_RET_FINISH;
err:

    QuicCheckStatelessResetToken(quic, stateless_reset_token);
    return QUIC_FLOW_RET_ERROR;
}

QuicFlowReturn
QuicPacketClosingRecv(QUIC *quic, RPacket *pkt, QuicPacketFlags flags)
{
    return QUIC_FLOW_RET_FINISH;
}

QuicFlowReturn
QuicPacketDrainingRecv(QUIC *quic, RPacket *pkt, QuicPacketFlags flags)
{
    return QUIC_FLOW_RET_FINISH;
}

