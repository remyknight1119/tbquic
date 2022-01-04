/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "extension.h"

#include <openssl/x509.h>
#include "tls.h"
#include "tls_lib.h"
#include "packet_local.h"
#include "common.h"
#include "mem.h"
#include "log.h"

static int TlsExtSrvrParseServerName(TLS *, RPacket *, uint32_t,
                                            X509 *, size_t);
static int TlsExtSrvrParseSigAlgs(TLS *, RPacket *, uint32_t, X509 *,
                                        size_t);
static int TlsExtSrvrParseTlsExtQtp(TLS *, RPacket *, uint32_t,
                                        X509 *, size_t);
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
        .parse = TlsExtSrvrParseTlsExtQtp,
    },
};

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

static int TlsExtSrvrParseTlsExtQtp(TLS *s, RPacket *pkt, uint32_t context,
                                X509 *x, size_t chainidx)
{
    QUIC_LOG("in\n");
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
    }
    QUIC_LOG("in\n");

    return 0;
}

static int TlsExtSrvrParseAlpn(TLS *s, RPacket *pkt, uint32_t context, X509 *x,
                                        size_t chainidx)
{
    QUIC_LOG("in\n");
    return 0;
}

int TlsSrvrParseExtensions(TLS *tls, RPacket *pkt, uint32_t context, X509 *x,
                                        size_t chainidx)
{
    return TlsParseExtensions(tls, pkt, context, x, chainidx, server_ext_parse,
                                    QUIC_NELEM(server_ext_parse));
}


