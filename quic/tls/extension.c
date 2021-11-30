/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "extension.h"

#include "packet_format.h"
#include "common.h"
#include "log.h"

#define QUIC_GET_U64_VALUE_BY_OFFSET(p, offset) \
    *((uint64_t *)((uint8_t *)p + offset))

int TlsExtInitServerName(QUIC_TLS *tls, uint32_t context)
{
    return 0;
}

int TlsExtFinalServerName(QUIC_TLS *tls, uint32_t context, int sent)
{
    return 0;
}

int TlsExtInitSigAlgs(QUIC_TLS *tls, uint32_t context)
{
    return 0;
}

int TlsExtFinalSigAlgs(QUIC_TLS *tls, uint32_t context, int sent)
{
    return 0;
}

static int TlsShouldAddExtension(QUIC_TLS *tls, uint32_t extctx,
                                    uint32_t thisctx)
{
    /* Skip if not relevant for our context */
    if ((extctx & thisctx) == 0) {
        return 0;
    }

    return 1;
}

#ifdef QUIC_TEST
const QuicTlsExtensionDefinition *(*QuicTestExtensionHook)(const
        QuicTlsExtensionDefinition *, size_t *i);
#endif
int TlsConstructExtensions(QUIC_TLS *tls, WPacket *pkt, uint32_t context,
                             X509 *x, size_t chainidx,
                             const QuicTlsExtensionDefinition *ext,
                             size_t num)
{
    const QuicTlsExtensionDefinition *thisexd = NULL;
    size_t i = 0;
    int ret = 0;

    if (WPacketStartSubU16(pkt) < 0) { 
        return -1;
    }

    for (i = 0; i < num; i++) {
        thisexd = &ext[i];
#ifdef QUIC_TEST
        if (QuicTestExtensionHook) {
            thisexd = QuicTestExtensionHook(ext, &i);
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

        if (WPacketPut2(pkt, i) < 0) {
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

#ifdef QUIC_TEST
QuicTransParamDefinition *(*QuicTestTransParamHook)(QuicTransParamDefinition
                                *param, size_t num);
#endif
int TlsConstructQuicTransParamExtension(QUIC_TLS *tls, WPacket *pkt,
                                QuicTransParamDefinition *param,
                                size_t num)
{
    QuicTransParamDefinition *p = NULL;
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
        if (p->check && p->check(&tls->trans_param, offset) < 0) {
            printf("check failed\n");
            continue;
        }

        if (QuicVariableLengthWrite(pkt, p->type) < 0) {
            return -1;
        }

        if (p->construct == NULL) {
            continue;
        }

        if (p->construct(&tls->trans_param, offset, pkt) < 0) {
            return -1;
        }
    }

    return 0;
}

int QuicTransParamCheckInteger(QuicTransParams *param, size_t offset)
{
    uint64_t value;

    value = QUIC_GET_U64_VALUE_BY_OFFSET(param, offset);
    if (value == 0) {
        return -1;
    }

    return 0;
}

int QuicTransParamConstructInteger(QuicTransParams *param, size_t offset,
                                            WPacket *pkt)
{
    uint64_t value;

    value = QUIC_GET_U64_VALUE_BY_OFFSET(param, offset);

    return QuicVariableLengthValueWrite(pkt, value);
}

