/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "quic_test.h"

#include <stdio.h>
#include <string.h>

#include <tbquic/quic.h>
#include <tbquic/tls.h>

#include "tls_cipher.h"
#include "quic_local.h"
#include "tls.h"
#include "tls_lib.h"
#include "list.h"
#include "tls_test.h"
#include "common.h"

static char psk_msg[] =
    "010001EF03039788212B11D6068990BC6D438B7F76040B374EBA6A6B3D5AAF01"
    "7B3530DE87AA20F966B9EB43DC046E3A785A569EEF32CB68445C325AFACA82C4"
    "E2A422E165622C000A130213031301130400FF0100019C000B00040300010200"
    "0A000C000A001D0017001E00190018002300000016000000170000000D001E00"
    "1C040305030603080708080809080A080B080408050806040105010601002B00"
    "03020304002D00020101003300260024001D00203C8EBEDF399B493826AEB2BD"
    "9C65A348671D92BB4ACAB3E8F0BAF8187916AA5B0029011B00E600E0C68F6624"
    "C5C463CDC2E1963D220350CCF890459D2EF9BC19A08E387E912BDF4C2DB4D38C"
    "696A00FD642E7E7D31497D00B572986D7CE0EDC84261C4059B83377122D1E8CB"
    "97B4271D89CE70B7305D0BA379A1D37EBEA1DDC2C5C4E48B4C287EC194DF0DC8"
    "6A48ED1CCC567B00F559658E729A6269091C9EFE1B3DFFC8A33328415FE05E20"
    "E1355221EE5AD754B49E0BB50CD50071C69F21A168EF05405DAA31DCCCD6D989"
    "76816ACD0FB1A9EEA09AB5CD2F74EAED9E0260AD3D47AF88C3FFE267EB084B78"
    "D50768648D2F6D9B0CB3AEA1D01888D48AEE1F7E69AE75C2F3448D86DF7CAE0F";
static char psk_master_key[] =
    "ABB0251CC72C477B9486C1DE1D289399D41E4C3658138DB0D68AF48B9EDAE6D6"
    "B17A4C1AF7870A692CA9420110553210";
static char psk_early_secret[] =
    "D9CB03C28368430727B14ADF4D9C8DC928E521181780DD3B8F9700D6E07F19AA"
    "0EFFC265D67E9F9AB0756CCAADF1941C";
static char psk_binder[] =
    "D8C199CC1DF69D5668863A66462C846DB5EECB5D60C18A25D45333CB4A720E45"
    "2F250A110F33CD3D99D5B80ABECAAA9A";

int TlsCipherListTest(void)
{
    TlsCipherListNode *pos = NULL;
    HLIST_HEAD(h);
    char ciphers[sizeof(TLS_CIPHERS_DEF)] = {};
    int offset = 0;

    if (TlsCreateCipherList(&h, TLS_CIPHERS_DEF,
                    sizeof(TLS_CIPHERS_DEF) - 1) < 0) {
        return -1;
    }

    hlist_for_each_entry(pos, &h, node)	{
        if (offset != 0) {
            offset += snprintf(&ciphers[offset], sizeof(ciphers) - offset,
                        TLS_CIPHERS_SEP);
        }
        offset += snprintf(&ciphers[offset], sizeof(ciphers) - offset,
                    "%s", pos->cipher->name);
        if (offset >= sizeof(ciphers)) {
            TlsDestroyCipherList(&h);
            return -1;
        }
    }

    if (strcmp(ciphers, TLS_CIPHERS_DEF) != 0) {
        TlsDestroyCipherList(&h);
        return -1;
    }

    TlsDestroyCipherList(&h);
    return 1;
}

int TlsGenerateMasterSecretTest(void)
{
    QUIC_CTX *ctx = NULL;
    QUIC *quic = NULL;
    TLS *s = NULL;
    static char insecret[] =
        "5A8B2ADBD93465AF3F053309A35EA97BE632E2669F7F0091C888C32EC70"
        "FABFAFBFE580AE3CE9F747E8341443C85BD0A";
    static char outsecret[] =
        "ACAA9B84279FD9294988AF0A78C3C8F3B2EAC6AD0BA209147DFFFEF87EF"
        "21C665EB47963F8664715F054E81E197F3713";
    static uint8_t secret[MSG_SIZE(outsecret)];
    size_t secret_size = 0;
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
    str2hex(s->handshake_secret, insecret, sizeof(s->handshake_secret));
    s->handshake_cipher = QuicGetTlsCipherById(TLS_CK_AES_256_GCM_SHA384);
    if (s->handshake_cipher == NULL) {
        printf("Find handshake cipher failed\n");
        goto out;
    }

    if (TlsGenerateMasterSecret(s, s->master_secret, s->handshake_secret,
                                 &secret_size) < 0) {
        goto out;
    }

    str2hex(secret, outsecret, sizeof(secret));
    if (memcmp(secret, s->master_secret, secret_size) != 0) {
        goto out;
    }

    ret = 1;
out:
    QuicFree(quic);
    QuicCtxFree(ctx);
    return ret;
}

int TlsPskDoBinderTest(void)
{
    QUIC_CTX *ctx = NULL;
    QUIC *quic = NULL;
    TLS *s = NULL;
    const EVP_MD *md = EVP_sha384();
    QuicSessionTicket t = {};
    uint8_t msg[MSG_SIZE(psk_msg)] = {};
    uint8_t binder[TLS_MAX_RESUMPTION_PSK_LENGTH];
    uint8_t p_binder[MSG_SIZE(psk_binder)] = {};
    uint8_t early_secret[MSG_SIZE(psk_early_secret)] = {};
    size_t binder_offset = sizeof(msg);
    size_t hashsize = EVP_MD_size(md);
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
    t.master_key_length = MSG_SIZE(psk_master_key);
    str2hex(t.master_key, psk_master_key, t.master_key_length);
    str2hex(msg, psk_msg, sizeof(msg));
    str2hex(p_binder, psk_binder, sizeof(p_binder));
    str2hex(early_secret, psk_early_secret, sizeof(early_secret));

    if (TlsPskDoBinder(s, md, msg, binder_offset, p_binder, binder, &t) < 0) {
        printf("PSK do binder failed\n");
        goto out;
    }
 
    if (memcmp(s->early_secret, early_secret, hashsize) != 0) {
        printf("Early secert not match\n");
        goto out;
    }

    if (memcmp(binder, p_binder, hashsize) != 0) {
        printf("Binder not match\n");
        goto out;
    }

    ret = 1;
out:
    QuicFree(quic);
    QuicCtxFree(ctx);
    return ret;
}
