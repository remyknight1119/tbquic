/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "quic_test.h"

#include <string.h>
#include <openssl/evp.h>
#include <tbquic/quic.h>
#include <tbquic/tls.h>

#include "quic_local.h"
#include "tls.h"
#include "tls_lib.h"
#include "tls_test.h"
#include "common.h"
#include "log.h"

static uint8_t secret[] =
    "\x7E\xE8\x20\x6F\x55\x70\x02\x3E\x6D\xC7\x51\x9E\xB1\x07\x3B\xC4"
    "\xE7\x91\xAD\x37\xB5\xC3\x82\xAA\x10\xBA\x18\xE2\x35\x7E\x71\x69"
    "\x71\xF9\x36\x2F\x2C\x2F\xE2\xA7\x6B\xFD\x78\xDF\xEC\x4E\xA9\xB5"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
static uint8_t insecret[] =
    "\x70\x48\x2A\xE0\x7A\x00\x84\x76\x25\x54\xCA\xBB\xC2\xF6\x89\x05"
    "\x29\xBE\xCB\x86\x3A\x5D\x74\x87\xCB\x6F\x4A\x32\x20\xE5\x67\x6D";
static uint8_t outsecret[] =
    "\x54\x97\xBB\x37\x82\x23\xB4\x08\xFF\x3D\x0E\x1A\xE4\x6F\xE4\xCF"
    "\x3E\x7E\xE2\xAC\x6A\x80\x1E\x08\x14\x3A\x90\xE4\x9A\x5F\x1D\xF1"
    "\xD8\xD2\xF4\xA6\x54\x58\x71\xCF\x47\x2B\x56\xA3\xF2\xBF\xFF\x58"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
static char clienthello_serverhello[] =
    "010000CA0303EA95A69606179E03B6D50D242A51242F3D46DE2ED744F5979207"
    "D10138400ECB203FF19B542AEE9D8A73AF1BBE679EC70C87B84FFF71E13AC6DE"
    "9D4D7266473A51000813021301130300FF01000079000B000403000102000A00"
    "0C000A001D0017001E001900180016000000170000000D001E001C0403050306"
    "03080708080809080A080B080408050806040105010601002B0003020304002D"
    "00020101003300260024001D00202B2701432E8F35238923CDB416D38568F29A"
    "B5A59E008B922E81A8BCF4D38A4A020000760303CCC778B69A32D73F5A9B7A98"
    "6920B49EE30447CFB54B8AFF8422A616627F7209203FF19B542AEE9D8A73AF1B"
    "BE679EC70C87B84FFF71E13AC6DE9D4D7266473A51130200002E002B00020304"
    "00330024001D0020D7492B04563F43E8E3EA0D80A228EB4CE1AC929B1D706924"
    "1BAB94BCE4A36523";
static char handshake_insecret[] =
    "C43920B7E18336477919AA88D6E4EE8DFD83B0F22ADB2CE7268E39A73E7394D3"
    "FCEFFAE1469ECDE801D63A44D5E3FC1F00000000000000000000000000000000";
static char handshake_secret[] =
    "E1A482F4E51A18DB76CA4967CD8047CBA210447428EFE9437A4707C25F9C7CFB"
    "C028CAE5327A2A72199F3B06FBC3614A";
static char server_finished_pre_msg_hash[] =
    "C84EF2A06765BEE28713472E8BF08CEEA900679ED730CF90EB654A83668B08E15C11F843480948D6E9D9A36D14246827";
static char server_finished_secret[] =
    "492DB343C836412E06F489DA5B0B7A3CECD64BABAB0E0F4F8A5A98699C318D39F13FCAEEF2DD7C835D6670D6AA3AFA36";
static char server_finished_hash[] =
    "AF8A07AA6A152DAD3057F3D275EE3FC92A427280DAB09C5E410A4386E3770865B4E8C9EEE7A4A7967E71A3D9BD35587A";

int TlsGenerateSecretTest(void)
{
    uint8_t pre_secret[EVP_MAX_MD_SIZE] = {};
    uint8_t out[EVP_MAX_MD_SIZE] = {};

    if (TlsGenerateSecret(EVP_sha384(), NULL, NULL, 0, pre_secret) < 0) {
        return -1;
    }

    if (memcmp(pre_secret, secret, sizeof(secret) - 1) != 0) {
        QuicPrint(pre_secret, sizeof(pre_secret));
        return -1;
    }

    if (TlsGenerateSecret(EVP_sha384(), pre_secret, insecret,
                    sizeof(insecret) - 1, out) < 0) {
        return -1;
    }

    if (memcmp(out, outsecret, sizeof(outsecret) - 1) != 0) {
        QuicPrint(out, sizeof(out));
        return -1;
    }

    return 2;
}

static int handshake_secret_cmp_ok;

static void QuicHandshakeSecretComp(uint8_t *secret)
{
    uint8_t hsecret[EVP_MAX_MD_SIZE] = {};
    size_t len = 0;

    len = (sizeof(handshake_secret) - 1)/2;
    str2hex(hsecret, handshake_secret, len);
    if (memcmp(secret, hsecret, len) == 0) {
        handshake_secret_cmp_ok = 1;
    } else {
//        QuicPrint(secret, len);
        handshake_secret_cmp_ok = 0;
    }
}

int TlsGenerateServerSecretTest(void)
{
    uint8_t *msg = NULL;
    QUIC_CTX *ctx = NULL;
    QUIC *quic = NULL;
    TLS *tls = NULL;
    QUIC_BUFFER *buf = NULL;
    const char *server_hello = NULL;
    size_t msg_len = 0;
    int ret = -1;

    ctx = QuicCtxNew(QuicClientMethod());
    if (ctx == NULL) {
        goto out;
    }

    quic = QuicNew(ctx);
    if (quic == NULL) {
        goto out;
    }

    buf = QUIC_TLS_BUFFER(quic);
    msg = QuicBufData(buf);
    msg_len = (sizeof(clienthello_serverhello) - 1)/2;
    str2hex(msg, clienthello_serverhello, msg_len);
    QuicBufSetDataLength(buf, msg_len);
    tls = &quic->tls;
    str2hex(tls->handshake_secret, handshake_insecret,
            sizeof(tls->handshake_secret));
    tls->handshake_cipher = QuicGetTlsCipherById(TLS_CK_AES_256_GCM_SHA384);
    if (tls->handshake_cipher == NULL) {
        printf("Find handshake cipher failed\n");
        goto out;
    }

    QuicSecretTest = QuicHandshakeSecretComp;
    server_hello = TlsFindServerHello(clienthello_serverhello,
            sizeof(clienthello_serverhello) - 1);
    if (server_hello == NULL) {
        goto out;
    }

    tls->handshake_msg_len = msg_len;
    if (QuicCreateHandshakeServerDecoders(quic) < 0) {
        printf("Create handshake decoders failed\n");
        goto out;
    }

    if (handshake_secret_cmp_ok == 0) {
        printf("Handshake secret compare failed\n");
        goto out;
    }

    ret = 1;
out:
    QuicFree(quic);
    QuicCtxFree(ctx);
    return ret;
}

void TlsFinalFinishMacHashHook(uint8_t *hash, size_t len)
{
    str2hex(hash, server_finished_pre_msg_hash, len);
}

int TlsTlsFinalFinishMacTest(void)
{
    QUIC_CTX *ctx = NULL;
    QUIC *quic = NULL;
    TLS *s = NULL;
    uint8_t hash[EVP_MAX_MD_SIZE] = {};
    size_t hash_len = 0;
    int ret = -1;

    ctx = QuicCtxNew(QuicClientMethod());
    if (ctx == NULL) {
        goto out;
    }

    quic = QuicNew(ctx);
    if (quic == NULL) {
        goto out;
    }

    s = &quic->tls;
    s->handshake_cipher = QuicGetTlsCipherById(TLS_CK_AES_256_GCM_SHA384);
    if (s->handshake_cipher == NULL) {
        printf("Find handshake cipher failed\n");
        goto out;
    }
    hash_len = (sizeof(server_finished_secret) - 1)/2;
    str2hex(s->server_finished_secret, server_finished_secret, hash_len);
    str2hex(hash, server_finished_hash, hash_len);
    s->handshake_msg_len = 16;
    if (TlsDigestCachedRecords(s) < 0) {
        printf("Digest Cached Records failed\n");
        goto out;
    }
 
    QuicTlsFinalFinishMacHashHook = TlsFinalFinishMacHashHook;
    if (TlsFinalFinishMac(s, kTlsMdServerFinishLabel,
                TLS_MD_SERVER_FINISH_LABEL_LEN, s->peer_finish_md) < 0) {
        printf("Final Finish Mac failed\n");
        goto out;
    }

    if (memcmp(hash, s->peer_finish_md, hash_len)) {
        QuicPrint(s->peer_finish_md, hash_len);
        QuicPrint(hash, hash_len);
    }

    ret = 1;
out:
    QuicFree(quic);
    QuicCtxFree(ctx);
    return ret;
}

