/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "quic_test.h"

#include <assert.h>
#include <string.h>
#include <tbquic/quic.h>
#include <openssl/bio.h>

#include "quic_local.h"
#include "packet_local.h"
#include "packet_format.h"
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
    EXT_TYPE_SERVER_NAME,
};

int QuicTlsClientHelloTest(void)
{
    QUIC_CTX *ctx = NULL;
    QUIC *quic = NULL;
    QUIC_BUFFER *buffer = NULL;
    BIO *rbio = NULL;
    BIO *wbio = NULL;
    int offset = 0;
    int case_num = -1;
    int ret = 0;

    ctx = QuicCtxNew(QuicClientMethod());
    if (ctx == NULL) {
        goto out;
    }

    quic = QuicNew(ctx);
    if (quic == NULL) {
        goto out;
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
        printf("Do Client Handshake failed\n");
        goto out;
    }

    buffer = &quic->tls.buffer;

    offset = 4;
    if (memcmp(QuicBufData(buffer) + offset, &client_hello[offset],
                buffer->data_len - offset) != 0) {
        printf("ClientHello content Inconsistent!\n");
        QuicPrint(QuicBufData(buffer) + offset, buffer->data_len - offset);
        QuicPrint(&client_hello[offset], buffer->data_len - offset);
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

static size_t QuicTlsTestGetPSigAlgs(const uint16_t **psigs)
{
    *psigs = tls_sigalgs;

    return QUIC_ARRAY_SIZE(tls_sigalgs);
}

static const QuicTlsExtensionDefinition *QuicTlsTestGetExtension(const
        QuicTlsExtensionDefinition *ext, size_t *i)
{
    static size_t j = 0;

    if (j >= sizeof(extension_defs)/sizeof(extension_defs)) {
        *i = EXT_TYPE_MAX - 1; 
    } else {
        *i = extension_defs[j];
    }
    j++;
    return &ext[*i];
}

int QuicTlsClientExtensionTest(void)
{
    QUIC_CTX *ctx = NULL;
    QUIC *quic = NULL;
    WPacket pkt = {};
    uint8_t buf[sizeof(client_extension)] = {};
    size_t wlen = 0;
    int offset = 0;
    int ret = -1;

    ctx = QuicCtxNew(QuicClientMethod());
    if (ctx == NULL) {
        goto out;
    }

    quic = QuicNew(ctx);
    if (quic == NULL) {
        goto out;
    }

    WPacketStaticBufInit(&pkt, buf, sizeof(buf));

    TlsTestGetPSigAlgs = QuicTlsTestGetPSigAlgs;
    QuicTestExtensionHook = QuicTlsTestGetExtension;
    if (TlsClientConstructExtensions(&quic->tls, &pkt, TLSEXT_CLIENT_HELLO,
                NULL, 0) < 0) {
        goto out;
    }

    offset = 2;
    wlen = WPacket_get_written(&pkt);
    if (memcmp(&buf[offset], &client_extension[offset],
                wlen - offset) != 0) {
        printf("Client Extension content Inconsistent!\n");
        QuicPrint(buf, wlen);
        QuicPrint(client_extension, sizeof(client_extension) - 1);
        goto out;
    }

    ret = 1;
out:
    WPacketCleanup(&pkt);
    QuicFree(quic);
    QuicCtxFree(ctx);
    return ret;
}

