/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "quic_test.h"

#include <assert.h>
#include <string.h>
#include <openssl/bio.h>
#include <tbquic/quic.h>
#include <tbquic/tls.h>
#include <tbquic/ec.h>

#include "quic_local.h"
#include "packet_local.h"
#include "format.h"
#include "extension.h"
#include "sig_alg.h"
#include "common.h"

static const uint16_t tls_sigalgs[] = {
    TLSEXT_SIGALG_ECDSA_SECP256R1_SHA256,
    TLSEXT_SIGALG_RSA_PSS_RSAE_SHA256,
    TLSEXT_SIGALG_RSA_PKCS1_SHA256,
    TLSEXT_SIGALG_ECDSA_SECP384R1_SHA384,
    TLSEXT_SIGALG_RSA_PSS_RSAE_SHA384,
    TLSEXT_SIGALG_RSA_PKCS1_SHA384,
    TLSEXT_SIGALG_RSA_PSS_RSAE_SHA512,
    TLSEXT_SIGALG_RSA_PKCS1_SHA512,
    TLSEXT_SIGALG_RSA_PKCS1_SHA1,
};


static uint8_t client_random[] =
    "\x3C\xB9\xB6\xA9\x89\x49\xAB\xDE\x36\xC3\x4F\xBE\xB7\x68\x75\x59"
    "\x9F\x86\x8D\x75\x98\xEF\x0A\x6D\x8D\x95\x8A\x1A\xDE\xCB\xCE\x5E";

static uint8_t client_hello[] =
    "\x01\x00\x01\x08\x03\x03\x3C\xB9\xB6\xA9\x89\x49\xAB\xDE\x36\xC3"
    "\x4F\xBE\xB7\x68\x75\x59\x9F\x86\x8D\x75\x98\xEF\x0A\x6D\x8D\x95"
    "\x8A\x1A\xDE\xCB\xCE\x5E\x00\x00\x06\x13\x01\x13\x02\x13\x03\x01"
    "\x00\x00\xD9\x00\x0D\x00\x14\x00\x12\x04\x03\x08\x04\x04\x01\x05"
    "\x03\x08\x05\x05\x01\x08\x06\x06\x01\x02\x01\x00\x39\x00\x50\x07"
    "\x04\x80\x60\x00\x00\x06\x04\x80\x60\x00\x00\xDC\xD4\xC8\xD5\x64"
    "\x14\x22\xF0\x0C\xB9\xF8\xCB\xDE\x38\x55\x6D\x9D\x34\x30\x0F\x89"
    "\x09\x02\x40\x67\x04\x04\x80\xF0\x00\x00\x01\x04\x80\x09\x27\xC0"
    "\x03\x02\x45\xC0\x20\x04\x80\x01\x00\x00\x08\x02\x40\x64\x05\x04"
    "\x80\x60\x00\x00\x80\x00\x47\x52\x04\x00\x00\x00\x01\x0F\x00\x00"
    "\x10\x00\x05\x00\x03\x02\x68\x33\x00\x0A\x00\x08\x00\x06\x00\x1D"
    "\x00\x17\x00\x18\x00\x2B\x00\x03\x02\x03\x04\x00\x33\x00\x26\x00"
    "\x24\x00\x1D\x00\x20\xED\xC3\x0A\x02\x80\x93\x20\xAA\xF1\x1F\x0F"
    "\x7D\x9E\x6F\xC4\x78\xF8\x62\x04\x15\x1B\x39\xAA\x67\x7D\xEA\x82"
    "\xEC\x77\xCE\x52\x3B\x44\x69\x00\x05\x00\x03\x02\x68\x33\x00\x2D"
    "\x00\x02\x01\x01\x00\x00\x00\x14\x00\x12\x00\x00\x0F\x77\x77\x77"
    "\x2E\x65\x78\x61\x6D\x70\x6C\x65\x2E\x6F\x72\x67";

static uint8_t client_extension[] =
    "\x00\xD9\x00\x0D\x00\x14\x00\x12\x04\x03\x08\x04\x04\x01\x05"
    "\x03\x08\x05\x05\x01\x08\x06\x06\x01\x02\x01\x00\x39\x00\x50\x07"
    "\x04\x80\x60\x00\x00\x06\x04\x80\x60\x00\x00\xDC\xD4\xC8\xD5\x64"
    "\x14\x22\xF0\x0C\xB9\xF8\xCB\xDE\x38\x55\x6D\x9D\x34\x30\x0F\x89"
    "\x09\x02\x40\x67\x04\x04\x80\xF0\x00\x00\x01\x04\x80\x09\x27\xC0"
    "\x03\x02\x45\xC0\x20\x04\x80\x01\x00\x00\x08\x02\x40\x64\x05\x04"
    "\x80\x60\x00\x00\x80\x00\x47\x52\x04\x00\x00\x00\x01\x0F\x00\x00"
    "\x10\x00\x05\x00\x03\x02\x68\x33\x00\x0A\x00\x08\x00\x06\x00\x1D"
    "\x00\x17\x00\x18\x00\x2B\x00\x03\x02\x03\x04\x00\x33\x00\x26\x00"
    "\x24\x00\x1D\x00\x20\xED\xC3\x0A\x02\x80\x93\x20\xAA\xF1\x1F\x0F"
    "\x7D\x9E\x6F\xC4\x78\xF8\x62\x04\x15\x1B\x39\xAA\x67\x7D\xEA\x82"
    "\xEC\x77\xCE\x52\x3B\x44\x69\x00\x05\x00\x03\x02\x68\x33\x00\x2D"
    "\x00\x02\x01\x01\x00\x00\x00\x14\x00\x12\x00\x00\x0F\x77\x77\x77"
    "\x2E\x65\x78\x61\x6D\x70\x6C\x65\x2E\x6F\x72\x67";

static uint16_t extension_defs[] = {
    EXT_TYPE_SIGNATURE_ALGORITHMS,
    EXT_TYPE_QUIC_TRANS_PARAMS,
    EXT_TYPE_APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
    EXT_TYPE_SUPPORTED_GROUPS,
    EXT_TYPE_SUPPORTED_VERSIONS,
    EXT_TYPE_KEY_SHARE,
    0x4469,
    EXT_TYPE_PSK_KEY_EXCHANGE_MODES,
    EXT_TYPE_SERVER_NAME,
};

static QuicTlsTestParam test_param[] = {
    {
        .type = QUIC_TRANS_PARAM_INITIAL_MAX_STREAM_DATA_UNI,
        .value = 0x600000,
    },
    {
        .type = QUIC_TRANS_PARAM_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
        .value = 0x600000,
    },
    {
        .type = 0x1CD4C8D5641422F0,
    },
    {
        .type = QUIC_TRANS_PARAM_INITIAL_MAX_STREAMS_UNI,
        .value = 103,
    },
    {
        .type = QUIC_TRANS_PARAM_INITIAL_MAX_DATA,
        .value = 15728640,
    },
    {
        .type = QUIC_TRANS_PARAM_MAX_IDLE_TIMEOUT,
        .value = 600000,
    },
    {
        .type = QUIC_TRANS_PARAM_MAX_UDP_PAYLOAD_SIZE,
        .value = 1472,
    },
    {
        .type = QUIC_TRANS_PARAM_MAX_DATAGRAME_FRAME_SIZE,
        .value = 65536,
    },
    {
        .type = QUIC_TRANS_PARAM_INITIAL_MAX_STREAMS_BIDI,
        .value = 100,
    },
    {
        .type = QUIC_TRANS_PARAM_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
        .value = 6291456,
    },
    {
        .type = 0x4752,
    },
    {
        .type = QUIC_TRANS_PARAM_INITIAL_SOURCE_CONNECTION_ID,
    },
};

static size_t TlsExtIndex;
static const QuicTlsExtConstruct *QuicTlsTestGetExtension(const
        QuicTlsExtConstruct *ext, size_t num)
{
    size_t j = 0;
    uint16_t type = 0;

    if (TlsExtIndex >= QUIC_NELEM(extension_defs)) {
        return NULL;
    }
    type = extension_defs[TlsExtIndex];
    TlsExtIndex++;
    for (j = 0; j < num; j++) {
        if (type == ext[j].type) {
            return ext + j;
        }
    }

    return NULL;
}

static size_t TlsTransParamIndex;
static const TlsExtQtpDefinition *
QuicTlsTestGetTransParams(const TlsExtQtpDefinition *param, size_t num)
{
    QuicTlsTestParam *p = NULL;
    size_t j = 0;

    if (TlsTransParamIndex < QUIC_NELEM(test_param)) {
        p = &test_param[TlsTransParamIndex];
        TlsTransParamIndex++;
        for (j = 0; j < num; j++) {
            if (p->type == param[j].type) {
                return param + j;
            }
        }
    } 

    return NULL;
}

static size_t QuicTlsTestSetEncodedpoint(unsigned char **point)
{
    unsigned char encoded_point[] =
        "\xED\xC3\x0A\x02\x80\x93\x20\xAA\xF1\x1F\x0F\x7D\x9E\x6F\xC4\x78"
        "\xF8\x62\x04\x15\x1B\x39\xAA\x67\x7D\xEA\x82\xEC\x77\xCE\x52\x3B";
    size_t len = sizeof(encoded_point) - 1;

    *point = malloc(len);
    if (*point == NULL) {
        return 0;
    }

    memcpy(*point, encoded_point, len);
    return len;
}

static int QuicTlsCtxClientExtensionSet(QUIC_CTX *ctx)
{
    const uint8_t alpn[] = "\x02\x68\x33";
    uint16_t groups[] = {
        TLS_SUPPORTED_GROUPS_X25519,
        TLS_SUPPORTED_GROUPS_SECP256R1,
        TLS_SUPPORTED_GROUPS_SECP384R1,
    };
    int ret = -1;

    if (QuicCtxCtrl(ctx, QUIC_CTRL_SET_GROUPS, groups,
                QUIC_NELEM(groups)) < 0) {
        goto out;
    }

    if (QuicCtxCtrl(ctx, QUIC_CTRL_SET_SIGALGS, (void *)tls_sigalgs,
                QUIC_NELEM(tls_sigalgs)) < 0) {
        goto out;
    }

    if (QUIC_CTX_set_alpn_protos(ctx, alpn, sizeof(alpn) - 1) < 0) {
        goto out;
    }

    ret = 0;
out:
    return ret;
}
 
static int QuicTlsClientExtensionSet(QUIC *quic)
{
    QuicTlsTestParam *p = NULL;
    size_t i = 0;
    int ret = -1;

    if (QuicCtrl(quic, QUIC_CTRL_SET_TLSEXT_HOSTNAME,
                "www.example.org", 0) < 0) {
        goto out;
    }

    for (i = 0; i < QUIC_NELEM(test_param); i++) {
        p = &test_param[i];
        if (p->value == 0) {
            continue;
        }
        QUIC_set_transport_parameter(quic, p->type, &p->value, 0);
    }

    QuicTestExtensionHook = QuicTlsTestGetExtension;
    QuicTestTransParamHook = QuicTlsTestGetTransParams;
    QuicTestEncodedpointHook = QuicTlsTestSetEncodedpoint;

    ret = 0;
out:
    return ret;
}
 
int QuicTlsClientHelloTest(void)
{
    QUIC_CTX *ctx = NULL;
    QUIC *quic = NULL;
    QUIC_BUFFER *buffer = NULL;
    BIO *rbio = NULL;
    BIO *wbio = NULL;
    size_t data_len = 0;
    int case_num = -1;
    int err = 0;
    int ret = 0;

    ctx = QuicCtxNew(QuicClientMethod());
    if (ctx == NULL) {
        goto out;
    }

    if (QuicTlsCtxClientExtensionSet(ctx) < 0) {
        return -1;
    }

    quic = QuicNew(ctx);
    if (quic == NULL) {
        goto out;
    }

    QUIC_set_connect_state(quic);
    if (QuicTlsClientExtensionSet(quic) < 0) {
        return -1;
    }

    rbio = BIO_new(BIO_s_mem());
    if (rbio == NULL) {
        goto out;
    }

    wbio = BIO_new(BIO_s_mem());
    if (wbio == NULL) {
        goto out;
    }
    QUIC_set_bio(quic, rbio, wbio);

    rbio = NULL;
    wbio = NULL;

    quic_random_test = client_random;
    ret = QuicDoHandshake(quic);
    if (ret < 0) {
        err = QUIC_get_error(quic, ret);
        if (err != QUIC_ERROR_WANT_READ) {
            printf("Do Client Handshake failed\n");
            goto out;
        }
    }

    buffer = QUIC_TLS_BUFFER(quic);
    data_len = QuicBufGetReserved(buffer);
    if (data_len != sizeof(client_hello) - 1 ||
            memcmp(QuicBufHead(buffer), client_hello,
                data_len) != 0) {
        printf("ClientHello content Inconsistent!\n");
        QuicPrint(QuicBufData(buffer), data_len);
        QuicPrint(client_hello, data_len);
        goto out;
    }

    case_num = 1;
out:
    BIO_free(rbio);
    BIO_free(wbio);
    QuicFree(quic);
    QuicCtxFree(ctx);

    return case_num;
}

int QuicTlsClientExtensionTest(void)
{
    QUIC_CTX *ctx = NULL;
    QUIC *quic = NULL;
    WPacket pkt = {};
    uint8_t buf[sizeof(client_extension)] = {};
    size_t wlen = 0;
    size_t ext_len = 0;
    int ret = -1;

    ctx = QuicCtxNew(QuicClientMethod());
    if (ctx == NULL) {
        goto out;
    }

    if (QuicTlsCtxClientExtensionSet(ctx) < 0) {
        goto out;
    }

    quic = QuicNew(ctx);
    if (quic == NULL) {
        goto out;
    }

    QUIC_set_connect_state(quic);
    if (QuicTlsClientExtensionSet(quic) < 0) {
        goto out;
    }

    WPacketStaticBufInit(&pkt, buf, sizeof(buf));

    TlsExtIndex = 0;
    TlsTransParamIndex = 0;
    if (TlsClientConstructExtensions(&quic->tls, &pkt, TLSEXT_CLIENT_HELLO,
                NULL, 0) < 0) {
        printf("Client Construct Extensions failed!\n");
        goto out;
    }

    wlen = WPacket_get_written(&pkt);
    ext_len = sizeof(client_extension) - 1;
    if (wlen != ext_len || memcmp(buf, client_extension, wlen) != 0) {
        printf("Client Extension content Inconsistent!\n");
        QuicPrint(buf, wlen);
        QuicPrint(client_extension, ext_len);
        goto out;
    }

    ret = 1;
out:
    WPacketCleanup(&pkt);
    QuicFree(quic);
    QuicCtxFree(ctx);
    return ret;
}

