/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "extension.h"

#include "format.h"
#include "common.h"
#include "log.h"

#define QUIC_GET_U64_VALUE_BY_OFFSET(p, offset) \
    *((uint64_t *)((uint8_t *)p + offset))
#define QUIC_SET_U64_VALUE_BY_OFFSET(p, offset, v) \
    *((uint64_t *)((uint8_t *)p + offset)) = v

static int TlsShouldAddExtension(TLS *tls, uint32_t extctx,
                                    uint32_t thisctx)
{
    /* Skip if not relevant for our context */
    if ((extctx & thisctx) == 0) {
        return 0;
    }

    return 1;
}

static int TlsShouldParseExtension(TLS *tls, uint32_t extctx,
                                    uint32_t thisctx)
{
    /* Skip if not relevant for our context */
    if ((extctx & thisctx) == 0) {
        return 0;
    }

    return 1;
}

#ifdef QUIC_TEST
const TlsExtConstruct *(*QuicTestExtensionHook)(const
        TlsExtConstruct *, size_t);
#endif
int TlsConstructExtensions(TLS *tls, WPacket *pkt, uint32_t context,
                             X509 *x, size_t chainidx,
                             const TlsExtConstruct *ext,
                             size_t num)
{
    const TlsExtConstruct *thisexd = NULL;
    size_t i = 0;
    int ret = 0;

    if (WPacketStartSubU16(pkt) < 0) { 
        return -1;
    }

    for (i = 0; i < num; i++) {
        thisexd = &ext[i];
#ifdef QUIC_TEST
        if (QuicTestExtensionHook) {
            thisexd = QuicTestExtensionHook(ext, num);
            if (thisexd == NULL) {
                break;
            }
        }
#endif
        /* Skip if not relevant for our context */
        if (!TlsShouldAddExtension(tls, thisexd->context, context)) {
            continue;
        }

        if (thisexd->check != NULL && thisexd->check(tls) < 0) {
            continue;
        }

        if (thisexd->construct == NULL) {
            continue;
        }

        if (WPacketPut2(pkt, thisexd->type) < 0) {
            QUIC_LOG("Put session ID len failed\n");
            return -1;
        }

        if (WPacketStartSubU16(pkt) < 0) { 
            return -1;
        }

        ret = thisexd->construct(tls, pkt, context, x, chainidx);
        if (ret < 0) {
            return -1;
        }
        if (WPacketClose(pkt) < 0) {
            QUIC_LOG("Close packet failed\n");
            return -1;
        }
    }

    if (WPacketClose(pkt) < 0) {
        QUIC_LOG("Close packet failed\n");
        return -1;
    }

    return 0;
}

static const TlsExtParse *
TlsFindExtParser(uint32_t type, const TlsExtParse *ext, size_t num)
{
    size_t i = 0;

    for (i = 0; i < num; i++) {
        if (ext[i].type  == type) {
            return &ext[i];
        }
    }

    return NULL;
}
 
int TlsParseExtensions(TLS *tls, RPacket *pkt, uint32_t context,
                             X509 *x, size_t chainidx,
                             const TlsExtParse *ext,
                             size_t num)
{
    const TlsExtParse *thisexd = NULL;
    RPacket ext_data = {};
    uint32_t type = 0;
    uint32_t len = 0;
    int ret = 0;

    if (TlsExtLenParse(pkt) < 0) {
        return -1;
    }

    while (RPacketRemaining(pkt)) {
        if (RPacketGet2(pkt, &type) < 0) {
            return -1;
        }

        if (RPacketGet2(pkt, &len) < 0) {
            return -1;
        }

        if (len == 0) {
            continue;
        }

        thisexd = TlsFindExtParser(type, ext, num);
        if (thisexd == NULL) {
            RPacketPull(pkt, len);
            continue;
        }

        /* Skip if not relevant for our context */
        if (!TlsShouldParseExtension(tls, thisexd->context, context)) {
            RPacketPull(pkt, len);
            continue;
        }

        RPacketBufInit(&ext_data, RPacketData(pkt), len);
        RPacketPull(pkt, len);
        ret = thisexd->parse(tls, &ext_data, context, x, chainidx);
        if (ret < 0) {
            return -1;
        }
    }

    return 0;
}

#ifdef QUIC_TEST
const TlsExtQtpDefinition *(*QuicTestTransParamHook)(const TlsExtQtpDefinition
                                *param, size_t num);
#endif
int TlsConstructQtpExtension(TLS *tls, WPacket *pkt,
                                const TlsExtQtpDefinition *param,
                                size_t num)
{
    const TlsExtQtpDefinition *p = NULL;
    size_t offset = 0;
    size_t i = 0;

    for (i = 0; i < num; i++) {
        p = param + i;
#ifdef QUIC_TEST
        if (QuicTestTransParamHook) {
            p = QuicTestTransParamHook(param, num);
            if (p == NULL) {
                break;
            }
        }
#endif
        QuicTransParamGetOffset(p->type, &offset);
        if (p->check && p->check(tls, &tls->ext.trans_param, offset) < 0) {
            continue;
        }

        if (QuicVariableLengthWrite(pkt, p->type) < 0) {
            return -1;
        }

        if (p->construct == NULL) {
            continue;
        }

        if (p->construct(tls, &tls->ext.trans_param, offset, pkt) < 0) {
            return -1;
        }
    }

    return 0;
}

int TlsParseQtpExtension(TLS *tls, QuicTransParams *param, RPacket *pkt,
                                const TlsExtQtpDefinition *tp, size_t num)
{
    const TlsExtQtpDefinition *p = NULL;
    uint64_t type = 0;
    uint64_t len = 0;
    size_t offset = 0;
    size_t i = 0;

    while (RPacketRemaining(pkt)) {
        if (QuicVariableLengthDecode(pkt, &type) < 0) {
            return -1;
        }
        if (QuicVariableLengthDecode(pkt, &len) < 0) {
            return -1;
        }

        for (i = 0; i < num; i++) {
            p = tp + i;
            if (p->type == type) {
                break;
            }
        }

        if (i == num || QuicTransParamGetOffset(type, &offset) < 0) {
            if (RPacketPull(pkt, len) < 0) {
                return -1;
            }
            continue;
        }

        if (p->parse == NULL) {
            if (RPacketPull(pkt, len) < 0) {
                return -1;
            }
            continue;
        }

        if (p->parse(tls, param, offset, pkt, len) < 0) {
            return -1;
        }
    }

    return 0;
}

int TlsExtQtpCheckInteger(TLS *tls, QuicTransParams *param,
                                size_t offset)
{
    uint64_t value;

    value = QUIC_GET_U64_VALUE_BY_OFFSET(param, offset);
    if (value == 0) {
        return -1;
    }

    return 0;
}

int TlsExtQtpConstructInteger(TLS *tls, QuicTransParams *param, size_t offset,
                                            WPacket *pkt)
{
    uint64_t value;

    value = QUIC_GET_U64_VALUE_BY_OFFSET(param, offset);

    return QuicVariableLengthValueWrite(pkt, value);
}

int TlsExtQtpParseInteger(TLS *tls, QuicTransParams *param, size_t offset,
                                RPacket *pkt, uint64_t len)
{
    uint64_t length = 0;

    if (QuicVariableLengthDecode(pkt, &length) < 0) {
        return -1;
    }

    QUIC_SET_U64_VALUE_BY_OFFSET(param, offset, length);

    return 0;
}

