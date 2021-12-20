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
    "010000CA03038CD8E41B97A7C1A5F3392799497AAEFD31DE6FB9D9926C86CCC0"
    "856062E9457B207A1E6DF85B912E20465191012CDC8641AA73E21DA3F175528B"
    "F36890EC108857000813021301130300FF01000079000B000403000102000A00"
    "0C000A001D0017001E001900180016000000170000000D001E001C0403050306"
    "03080708080809080A080B080408050806040105010601002B0003020304002D"
    "00020101003300260024001D0020CB50694A5D86545F16DBC56C7695B5FE5CE3"
    "38A44EA0C90DE01E4B3459DCDE3F020000760303F2682E53CDE0C2FEE52BC3AB"
    "9328F3FED0EE0958134B5DA1701E07E4B9687592207A1E6DF85B912E20465191"
    "012CDC8641AA73E21DA3F175528BF36890EC108857130200002E002B00020304"
    "00330024001D00204C3A9E972860E0B36340F3FB412E1B28F044E8E856F74937"
    "66A041B92151382F";
static char handshake_insecret[] =
    "6114AEC8B38268314754A3288867F9F9893D22F199AE377591E57C6AA1EB58DA"
    "697ACA8EFD4DF27793522FA5EA7CF59200000000000000000000000000000000";
static char handshake_secret[] =
    "2A7703211520816EAE739D0F9493274BF0B1C7DD7E21DF60F094AA98032D3698"
    "CFA5B5651E7E18648633418E915F668F";

int QuicTlsGenerateSecretTest(void)
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
        handshake_secret_cmp_ok = 0;
    }
}

int QuicTlsGenerateServerSecretTest(void)
{
    uint8_t *msg = NULL;
    QUIC_CTX *ctx = NULL;
    QUIC *quic = NULL;
    QUIC_TLS *tls = NULL;
    QUIC_BUFFER *buf = NULL;
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

