/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "extension.h"

#include <openssl/x509.h>
#include "tls.h"
#include "tls_lib.h"
#include "quic_local.h"
#include "packet_local.h"
#include "transport.h"
#include "common.h"
#include "mem.h"
#include "log.h"

static int TlsExtSrvrCheckAlpn(TLS *);
static int TlsExtSrvrCheckKeyShare(TLS *);
static int TlsExtSrvrCheckPreSharedKey(TLS *);
static ExtReturn TlsExtSrvrConstructSupportedVersion(TLS *, WPacket *, uint32_t,
                                        X509 *, size_t);
static ExtReturn TlsExtSrvrConstructKeyShare(TLS *, WPacket *, uint32_t,
                                        X509 *, size_t);
static ExtReturn TlsExtSrvrConstructServerName(TLS *, WPacket *, uint32_t,
                                        X509 *, size_t);
static ExtReturn TlsExtSrvrConstructAlpn(TLS *, WPacket *, uint32_t, X509 *,
                                        size_t);
static ExtReturn TlsExtSrvrConstructQtp(TLS *, WPacket *, uint32_t, X509 *,
                                        size_t);
static ExtReturn TlsExtSrvrConstructEarlyData(TLS *, WPacket *, uint32_t,
                                        X509 *, size_t);
static ExtReturn TlsExtSrvrConstructPreSharedKey(TLS *, WPacket *, uint32_t,
                                        X509 *, size_t);

static int TlsExtSrvrParseServerName(TLS *, RPacket *, uint32_t,
                                            X509 *, size_t);
static int TlsExtSrvrParseSigAlgs(TLS *, RPacket *, uint32_t, X509 *,
                                        size_t);
static int TlsExtSrvrParseQtp(TLS *, RPacket *, uint32_t, X509 *, size_t);
static int TlsExtSrvrParseEarlyData(TLS *, RPacket *, uint32_t, X509 *, size_t);
static int TlsExtSrvrParseSupportedGroups(TLS *, RPacket *, uint32_t,
                                        X509 *, size_t);
static int TlsExtSrvrParseSupportedVersion(TLS *, RPacket *, uint32_t,
                                        X509 *, size_t);
static int TlsExtSrvrParseKeyExchModes(TLS *, RPacket *, uint32_t,
                                        X509 *, size_t);
static int TlsExtSrvrParseKeyShare(TLS *, RPacket *, uint32_t,
                                        X509 *, size_t);
static int TlsExtSrvrParseAlpn(TLS *, RPacket *, uint32_t, X509 *,
                                        size_t);
static int TlsExtsrvrParsePsk(TLS *, RPacket *, uint32_t, X509 *,
                                        size_t);

static const TlsExtConstruct server_ext_construct[] = {
    {
        .type = EXT_TYPE_SERVER_NAME,
        .context = TLSEXT_ENCRYPTED_EXT,
        .construct = TlsExtSrvrConstructServerName,
    },
    {
        .type = EXT_TYPE_SUPPORTED_VERSIONS,
        .context = TLSEXT_SERVER_HELLO,
        .construct = TlsExtSrvrConstructSupportedVersion,
    },
    {
        .type = EXT_TYPE_KEY_SHARE,
        .context = TLSEXT_SERVER_HELLO,
        .check = TlsExtSrvrCheckKeyShare,
        .construct = TlsExtSrvrConstructKeyShare,
    },
    {
        .type = EXT_TYPE_APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
        .context = TLSEXT_ENCRYPTED_EXT,
        .check = TlsExtSrvrCheckAlpn,
        .construct = TlsExtSrvrConstructAlpn,
    },
    {
        .type = EXT_TYPE_QUIC_TRANS_PARAMS,
        .context = TLSEXT_ENCRYPTED_EXT,
        .construct = TlsExtSrvrConstructQtp,
    },
    {
        .type = EXT_TYPE_EARLY_DATA, 
        .context = TLSEXT_NEW_SESSION_TICKET,
        .construct = TlsExtSrvrConstructEarlyData,
    },
    {
        .type = EXT_TYPE_PRE_SHARED_KEY,
        .context = TLSEXT_SERVER_HELLO,
        .check = TlsExtSrvrCheckPreSharedKey,
        .construct = TlsExtSrvrConstructPreSharedKey,
    },
};

static const TlsExtParse server_ext_parse[] = {
    {
        .type = EXT_TYPE_SERVER_NAME,
        .context = TLSEXT_CLIENT_HELLO,
        .parse = TlsExtSrvrParseServerName,
    },
    {
        .type = EXT_TYPE_SUPPORTED_GROUPS,
        .context = TLSEXT_CLIENT_HELLO,
        .parse = TlsExtSrvrParseSupportedGroups,
    },
    {
        .type = EXT_TYPE_SIGNATURE_ALGORITHMS,
        .context = TLSEXT_CLIENT_HELLO,
        .parse = TlsExtSrvrParseSigAlgs,
    },
    {
        .type = EXT_TYPE_APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
        .context = TLSEXT_CLIENT_HELLO,
        .parse = TlsExtSrvrParseAlpn,
    },
    {
        .type = EXT_TYPE_SUPPORTED_VERSIONS,
        .context = TLSEXT_CLIENT_HELLO,
        .parse = TlsExtSrvrParseSupportedVersion,
    },
    {
        .type = EXT_TYPE_PSK_KEY_EXCHANGE_MODES,
        .context = TLSEXT_CLIENT_HELLO,
        .parse = TlsExtSrvrParseKeyExchModes,
    },
    {
        .type = EXT_TYPE_KEY_SHARE,
        .context = TLSEXT_CLIENT_HELLO,
        .parse = TlsExtSrvrParseKeyShare,
    },
    {
        .type = EXT_TYPE_QUIC_TRANS_PARAMS,
        .context = TLSEXT_CLIENT_HELLO,
        .parse = TlsExtSrvrParseQtp,
    },
    {
        .type = EXT_TYPE_EARLY_DATA,
        .context = TLSEXT_CLIENT_HELLO,
        .parse = TlsExtSrvrParseEarlyData,
    },
    {
        .type = EXT_TYPE_PRE_SHARED_KEY,
        .context = TLSEXT_CLIENT_HELLO,
        .parse = TlsExtsrvrParsePsk,
    },
};

static int TlsExtQtpParseSourceConnId(TLS *tls, QuicTransParams *param, size_t offset,
                        RPacket *pkt, uint64_t len);

static TlsExtQtpDefinition server_transport_param[] = {
    {
        .type = QUIC_TRANS_PARAM_ORIGINAL_DESTINATION_CONNECTION_ID,
        .construct = TlsExtQtpConstructSourceConnId,
    },
    {
        .type = QUIC_TRANS_PARAM_MAX_IDLE_TIMEOUT,
        .parse = TlsExtQtpParseInteger,
        .check = TlsExtQtpCheckInteger,
        .construct = TlsExtQtpConstructInteger,
    },
    {
        .type = QUIC_TRANS_PARAM_MAX_UDP_PAYLOAD_SIZE,
        .parse = TlsExtQtpParseInteger,
        .check = TlsExtQtpCheckInteger,
        .construct = TlsExtQtpConstructInteger,
    },
    {
        .type = QUIC_TRANS_PARAM_INITIAL_MAX_DATA,
        .parse = TlsExtQtpParseInteger,
        .check = TlsExtQtpCheckInteger,
        .construct = TlsExtQtpConstructInteger,
    },
    {
        .type = QUIC_TRANS_PARAM_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
        .parse = TlsExtQtpParseInteger,
        .check = TlsExtQtpCheckInteger,
        .construct = TlsExtQtpConstructInteger,
    },
    {
        .type = QUIC_TRANS_PARAM_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
        .parse = TlsExtQtpParseInteger,
        .check = TlsExtQtpCheckInteger,
        .construct = TlsExtQtpConstructInteger,
    },
    {
        .type = QUIC_TRANS_PARAM_INITIAL_MAX_STREAM_DATA_UNI,
        .parse = TlsExtQtpParseInteger,
        .check = TlsExtQtpCheckInteger,
        .construct = TlsExtQtpConstructInteger,
    },
    {
        .type = QUIC_TRANS_PARAM_INITIAL_MAX_STREAMS_BIDI,
        .parse = TlsExtQtpParseInteger,
        .check = TlsExtQtpCheckInteger,
        .construct = TlsExtQtpConstructInteger,
    },
    {
        .type = QUIC_TRANS_PARAM_INITIAL_MAX_STREAMS_UNI,
        .parse = TlsExtQtpParseInteger,
        .check = TlsExtQtpCheckInteger,
        .construct = TlsExtQtpConstructInteger,
    },
    {
        .type = QUIC_TRANS_PARAM_INITIAL_SOURCE_CONNECTION_ID,
        .parse = TlsExtQtpParseSourceConnId,
        .construct = TlsExtQtpConstructSourceConnId,
    },
    {
        .type = QUIC_TRANS_PARAM_MAX_DATAGRAME_FRAME_SIZE,
        .parse = TlsExtQtpParseInteger,
        .check = TlsExtQtpCheckInteger,
        .construct = TlsExtQtpConstructInteger,
    },
};

#define QUIC_SERVER_TRANS_PARAM_NUM QUIC_NELEM(server_transport_param)

static ExtReturn TlsExtSrvrConstructServerName(TLS *s, WPacket *pkt,
                                        uint32_t context, X509 *x,
                                        size_t chainidx)
{
    return EXT_RETURN_SENT;
}

static ExtReturn TlsExtSrvrConstructSupportedVersion(TLS *s, WPacket *pkt,
                                        uint32_t context, X509 *x,
                                        size_t chainidx)
{
    if (WPacketPut2(pkt, TLS_VERSION_1_3) < 0) {
        return EXT_RETURN_FAIL;
    }

    return EXT_RETURN_SENT;
}

static int TlsExtSrvrCheckKeyShare(TLS *s)
{
    EVP_PKEY *ckey = NULL;

    ckey = s->peer_kexch_key;
    if (ckey == NULL) {
        return -1;
    }

    return 0;
}

static int TlsExtSrvrCheckPreSharedKey(TLS *s)
{
    if (!s->hit) {
        return -1;
    }

    return 0;
}

static ExtReturn
TlsExtSrvrConstructKeyShare(TLS *s, WPacket *pkt, uint32_t context,
                                        X509 *x, size_t chainidx)
{
    EVP_PKEY *ckey = NULL;
    EVP_PKEY *skey = NULL;
    unsigned char *encoded_point = NULL;
    size_t encoded_pt_len = 0;
    int ret = -1;
    int err = EXT_RETURN_FAIL;

    ckey = s->peer_kexch_key;
    if (ckey == NULL) {
        return EXT_RETURN_FAIL;
    }

    if (WPacketPut2(pkt, s->group_id) < 0) {
        return EXT_RETURN_FAIL;
    }

    skey = TlsGeneratePkey(ckey);
    if (skey == NULL) {
        return EXT_RETURN_FAIL;
    }

    encoded_pt_len = EVP_PKEY_get1_tls_encodedpoint(skey, &encoded_point);
    if (encoded_pt_len == 0) {
        goto out;
    }

    ret = WPacketSubMemcpyU16(pkt, encoded_point, encoded_pt_len);
    OPENSSL_free(encoded_point);
    if (ret < 0) {
        goto out;
    }

    s->kexch_key = skey;
    skey = NULL;

    if (TlsKeyDerive(s, s->kexch_key, ckey) < 0) {
        QUIC_LOG("Derive key failed\n");
        goto out;
    }
    err = EXT_RETURN_SENT;

out:
    EVP_PKEY_free(skey);
    return err;
}

static ExtReturn TlsExtSrvrConstructPreSharedKey(TLS *s, WPacket *pkt,
                                    uint32_t context, X509 *x,
                                    size_t chainidx)
{
    if (WPacketPut2(pkt, s->ext.tick_identity) < 0) {
        return EXT_RETURN_FAIL;
    }

    return EXT_RETURN_SENT;
}

static int TlsExtSrvrCheckAlpn(TLS *s)
{
    if (QuicDataIsEmpty(&s->alpn_selected)) {
        return -1;
    }

    return 0;
}

static ExtReturn TlsExtSrvrConstructAlpn(TLS *s, WPacket *pkt,
                                        uint32_t context, X509 *x,
                                        size_t chainidx)
{
    QUIC_DATA *alpn = &s->alpn_selected;

    if (TlsExtConstructAlpn(alpn, pkt) < 0) {
        return EXT_RETURN_FAIL;
    }

    return EXT_RETURN_SENT;
}

static ExtReturn TlsExtSrvrConstructQtp(TLS *s, WPacket *pkt, uint32_t context,
                                    X509 *x, size_t chainidx)
{
    return TlsConstructQtpExtension(s, pkt, server_transport_param,
                                    QUIC_SERVER_TRANS_PARAM_NUM);
}

static ExtReturn TlsExtSrvrConstructEarlyData(TLS *s, WPacket *pkt, uint32_t context,
                                    X509 *x, size_t chainidx)
{
    if (context == TLSEXT_NEW_SESSION_TICKET) {
        if (s->max_early_data == 0) {
            return EXT_RETURN_NOT_SENT;
        }
        
        if (WPacketPut4(pkt, s->max_early_data) < 0) {
            return EXT_RETURN_FAIL;
        }

        return EXT_RETURN_SENT;
    }

    return EXT_RETURN_SENT;
}

static int TlsExtSrvrParseServerName(TLS *s, RPacket *pkt, uint32_t context,
                                X509 *x, size_t chainidx)
{
    RPacket sni = {};
    RPacket hostname = {};
    uint32_t servname_type = 0;

    if (RPacketGetLengthPrefixed2(pkt, &sni) < 0) {
        QUIC_LOG("Get SNI len failed\n");
        return -1;
    }

    if (RPacketGet1(&sni, &servname_type) < 0) {
        QUIC_LOG("Get SNI type failed\n");
        return -1;
    }

    /*
    * Although the intent was for server_name to be extensible, RFC 4366
    * was not clear about it; and so OpenSSL among other implementations,
    * always and only allows a 'host_name' name types.
    * RFC 6066 corrected the mistake but adding new name types
    * is nevertheless no longer feasible, so act as if no other
    * SNI types can exist, to simplify parsing.
    *
    * Also note that the RFC permits only one SNI value per type,
    * i.e., we can only have a single hostname.
    */
    if (servname_type != TLSEXT_NAMETYPE_HOST_NAME) {
        QUIC_LOG("SNI type invalid\n");
        return -1;
    }

    if (RPacketGetLengthPrefixed2(&sni, &hostname) < 0) {
        QUIC_LOG("Get SNI len failed\n");
        return -1;
    }

    if (RPacketRemaining(&hostname) > TLSEXT_MAXLEN_HOST_NAME) {
        QUIC_LOG("Bad ServerName format\n");
        return -1;
    }

    if (PRacketContainsZeroByte(&hostname)) {
        QUIC_LOG("Hostname contains zero byte\n");
        return -1;
    }

    QuicMemFree(s->ext.hostname);
    s->ext.hostname = RPacketStrndup(&hostname);
    if (s->ext.hostname == NULL) {
        QUIC_LOG("Dup hostanme failed\n");
        return -1;
    }

    return 0;
}

static int TlsExtSrvrParseSigAlgs(TLS *s, RPacket *pkt, uint32_t context,
                                X509 *x, size_t chainidx)
{
    QUIC_DATA *peer = &s->ext.peer_sigalgs;
    RPacket sig_algs = {};

    if (RPacketGetLengthPrefixed2(pkt, &sig_algs) < 0) {
        QUIC_LOG("Get SigAlg len failed\n");
        return -1;
    }

    return RPacketSaveU16(&sig_algs, &peer->ptr_u16, &peer->len);
}

static int TlsExtSrvrParseQtp(TLS *s, RPacket *pkt, uint32_t context,
                                    X509 *x, size_t chainidx)
{
    return TlsParseQtpExtension(s, pkt, server_transport_param,
                                QUIC_SERVER_TRANS_PARAM_NUM);
}

static int TlsExtSrvrParseEarlyData(TLS *s, RPacket *pkt, uint32_t context,
                                    X509 *x, size_t chainidx)
{
    if (RPacketRemaining(pkt) != 0) {
        return -1;
    }

    return 0;
}

static int
TlsExtSrvrParseSupportedGroups(TLS *s, RPacket *pkt, uint32_t context,
                                X509 *x, size_t chainidx)
{
    QUIC_DATA *peer = &s->ext.peer_supported_groups;
    RPacket supported_groups = {};

    if (RPacketGetLengthPrefixed2(pkt, &supported_groups) < 0) {
        QUIC_LOG("Get Supported Groups len failed\n");
        return -1;
    }

    return RPacketSaveU16(&supported_groups, &peer->ptr_u16, &peer->len);
}

static int
TlsExtSrvrParseSupportedVersion(TLS *s, RPacket *pkt, uint32_t context,
                                X509 *x, size_t chainidx)
{
    RPacket supported_version = {};
    uint32_t version = 0;

    if (RPacketGetLengthPrefixed1(pkt, &supported_version) < 0) {
        return -1;
    }

    if (RPacketGet2(&supported_version, &version) < 0) {
        return -1;
    }

    if (version != TLS_VERSION_1_3) {
        return -1;
    }

    return 0;
}

static int TlsExtSrvrParseKeyExchModes(TLS *s, RPacket *pkt, uint32_t context,
                                X509 *x, size_t chainidx)
{
    RPacket psk_kex_modes = {};
    uint32_t mode = 0;

    if (RPacketGetLengthPrefixed1(pkt, &psk_kex_modes) < 0) {
        return -1;
    }

    while (RPacketGet1(&psk_kex_modes, &mode) == 0) {
        if (mode == TLSEXT_KEX_MODE_KE_DHE) {
            s->psk_kex_mode |= TLSEXT_KEX_MODE_KE_DHE;
            return 0;
        }
    }

    return -1;
}

static int TlsExtSrvrParseKeyShare(TLS *s, RPacket *pkt, uint32_t context,
                                X509 *x, size_t chainidx)
{
    const uint16_t *clntgroups = NULL;
    const uint16_t *srvrgroups = NULL;
    RPacket key_share_list = {};
    RPacket encoded_pt = {};
    size_t clnt_num_groups = 0;
    size_t srvr_num_groups = 0;
    uint32_t group_id = 0;
    bool found = false;

    if (RPacketGetLengthPrefixed2(pkt, &key_share_list) < 0) {
        return -1;
    }

    TlsGetSupportedGroups(s, &srvrgroups, &srvr_num_groups);
    TlsGetPeerGroups(s, &clntgroups, &clnt_num_groups);
    if (clnt_num_groups == 0) {
        QUIC_LOG("Client group num invalid\n");
        return -1;
    }

    while (RPacketRemaining(&key_share_list) > 0) {
        if (RPacketGet2(&key_share_list, &group_id) < 0) {
            QUIC_LOG("Get group id failed\n");
            return -1;
        }

        if (RPacketGetLengthPrefixed2(&key_share_list, &encoded_pt) < 0) {
            QUIC_LOG("Get Length prefixed failed\n");
            return -1;
        }

        if (RPacketRemaining(&encoded_pt) == 0) {
            QUIC_LOG("Remaining len invalid\n");
            return -1;
        }

        if (found == true) {
            continue;
        }

        if (TlsCheckInList(s, group_id, clntgroups, clnt_num_groups) < 0) {
            QUIC_LOG("Check client group failed\n");
            return -1;
        }

        if (TlsCheckInList(s, group_id, srvrgroups, srvr_num_groups) < 0) {
            continue;
        }

        s->peer_kexch_key = TlsGenerateParamGroup(group_id);
        if (s->peer_kexch_key == NULL) {
            QUIC_LOG("Generate param group failed\n");
            return -1;
        }

        s->group_id = group_id;
        if (!EVP_PKEY_set1_tls_encodedpoint(s->peer_kexch_key,
                        RPacketData(&encoded_pt),
                        RPacketRemaining(&encoded_pt))) {
            QUIC_LOG("Set encoded point failed\n");
            return -1;
        }

        found = true;
    }

    return 0;
}

static int TlsExtSrvrParseAlpn(TLS *s, RPacket *pkt, uint32_t context, X509 *x,
                                        size_t chainidx)
{
    RPacket protocol_list = {};
    RPacket saved_protocol_list = {};
    RPacket protocol = {};
    QUIC_DATA selected = {};

    if (RPacketGetLengthPrefixed2(pkt, &protocol_list) < 0) {
        return -1;
    }

    if (RPacketRemaining(&protocol_list) < 2) {
        QUIC_LOG("Remaining data is too short\n");
        return -1;
    }

    saved_protocol_list = protocol_list;
    do {
        if (RPacketGetLengthPrefixed1(&protocol_list, &protocol) < 0) {
            return -1;
        }

        if (RPacketRemaining(&protocol) == 0) {
            return -1;
        }
    } while (RPacketRemaining(&protocol_list) != 0);

    if (PRacketMemDup(&saved_protocol_list, &s->alpn_proposed.ptr_u8,
                &s->alpn_proposed.len) < 0) {
        return -1;
    }

    /*
     * if (s->ctx->ext.alpn_select_cb != NULL && s->s3->alpn_proposed != NULL) {
     * int r = s->ctx->ext.alpn_select_cb(s, &selected, &selected_len,
     *                      s->s3->alpn_proposed,
     *                      (unsigned int)s->s3->alpn_proposed_len,
     *                      s->ctx->ext.alpn_select_cb_arg);
     */
    selected.data = s->alpn_proposed.ptr_u8 + 1;
    selected.len = s->alpn_proposed.len - 1;
    if (QuicDataDup(&s->alpn_selected, &selected) < 0) {
        return -1;
    }

    return 0;
}

static int TlsExtsrvrParsePsk(TLS *s, RPacket *pkt, uint32_t context,
                                    X509 *x, size_t chainidx)
{
    QUIC *quic = QuicTlsTrans(s);
    QUIC_SESSION *sess = NULL;
    QuicSessionTicket *t = NULL;
    const EVP_MD *md = NULL;
    RPacket identities = {};
    RPacket identity = {};
    RPacket binders = {};
    RPacket binder = {};
    size_t binder_offset = 0;
    size_t i = 0;
    uint32_t ticket_agel = 0;
    uint32_t id = 0;

    if (RPacketGetLengthPrefixed2(pkt, &identities) < 0) {
        return -1;
    }

    QUIC_LOG("innnnnnnnnnnnnnnnnnnnPSK\n");
    for (id = 0; RPacketRemaining(&identities) != 0; id++) {
        if (RPacketGetLengthPrefixed2(&identities, &identity) < 0) {
            return -1;
        }

        if (RPacketGet4(&identities, &ticket_agel) < 0) {
            return -1;
        }

        if (TlsDecryptTicket(s, RPacketData(&identity),
                    RPacketRemaining(&identity), &sess) < 0) {
            QUIC_LOG("Decrypt Ticket failed\n");
            continue;
        }

        if (sess->cipher->digest != s->handshake_cipher->digest) {
            QUIC_LOG("The ciphersuite is not compatible with this session\n");
            continue;
        }

        break;
    }

    if (sess == NULL) {
        return 0;
    }

    binder_offset = RPacketReadLen(pkt);
    md = QuicMd(sess->cipher->digest);
    if (RPacketGetLengthPrefixed2(pkt, &binders) < 0) {
        QUIC_LOG("Get binders failed\n");
        goto err;
    }

    for (i = 0; i <= id; i++) {
        if (RPacketGetLengthPrefixed1(&binders, &binder) < 0) {
            QUIC_LOG("Get binder failed\n");
            goto err;
        }
    }

    if (RPacketRemaining(&binder) != EVP_MD_size(md)) {
        QUIC_LOG("Remaining binder size incorrect\n");
        goto err;
    }

    t = QuicSessionTicketPickTail(sess);
    if (t == NULL) {
        QUIC_LOG("Get Session ticket failed\n");
        goto err;
    }

    if (TlsPskDoBinder(s, md, (uint8_t *)RPacketHead(pkt), binder_offset,
                (uint8_t *)RPacketData(&binder), NULL, t) < 0) {
        QUIC_LOG("Do PSK Binder failed\n");
        goto err;
    }

    QUIC_LOG("Parse PSK\n");
    QuicSessionFree(quic->session);
    quic->session = sess;
    s->hit = 1;
    s->ext.tick_identity = id;

    return 0;
err:
    QuicSessionFree(sess);
    return -1;
}

int TlsSrvrParseExtensions(TLS *s, RPacket *pkt, uint32_t context, X509 *x,
                                        size_t chainidx)
{
    return TlsParseExtensions(s, pkt, context, x, chainidx, server_ext_parse,
                                    QUIC_NELEM(server_ext_parse));
}

static int TlsExtQtpParseSourceConnId(TLS *s, QuicTransParams *param,
                        size_t offset, RPacket *pkt, uint64_t len)
{
    QUIC *quic = QuicTlsTrans(s);
    QUIC_DATA *dcid = NULL;
    const uint8_t *data = NULL;
    QUIC_DATA scid = {
        .len = len,
    };

    if (RPacketGetBytes(pkt, &data, len) < 0) {
        return -1;
    }

    scid.data = (void *)data;
    dcid = &quic->dcid;
    if (dcid->len == 0) {
        return 0;
    }

    if (!QuicDataEq(dcid, &scid)) {
        QUIC_LOG("CID not match, SCID, len = %lu, DCID len = %lu\n",
                        len, dcid->len);
        return -1;
    }

    return 0;
}

int TlsSrvrConstructExtensions(TLS *s, WPacket *pkt, uint32_t context, X509 *x,
                        size_t chainidx)
{
    return TlsConstructExtensions(s, pkt, context, x, chainidx,
                                    server_ext_construct,
                                    QUIC_NELEM(server_ext_construct));
}


