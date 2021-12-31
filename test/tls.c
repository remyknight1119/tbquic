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

static const char clienthello_serverhello[] =
    "010000CA030361AC7A2CF257F07DAAB55B63C7D67DD25F1F1F585B1D48FF9CB4"
    "569610D98787200DFC3CC391384E45138F22BDA24F3755BE0AC891068A734551"
    "969BA80A871A00000813021301130300FF01000079000B000403000102000A00"
    "0C000A001D0017001E001900180016000000170000000D001E001C0403050306"
    "03080708080809080A080B080408050806040105010601002B0003020304002D"
    "00020101003300260024001D0020D34042A00C0DC88E8C20BDAE45F791417B6D"
    "3A38277EC2236920D62A48A91F530200007603031538AFA713434DBDA7555E8A"
    "CF5EDA4BFF35D185FD41D4F286D07F4ADFAD0DBC200DFC3CC391384E45138F22"
    "BDA24F3755BE0AC891068A734551969BA80A871A00130200002E002B00020304"
    "00330024001D0020884FD732A818C09777D644864D71B5D310BCA41CD5011D52"
    "324AD03D7D0C0609";
static const char update_msg[] =
    "0800000200000B0004E8000004E40004DF308204DB308203C3A0030201020203"
    "044E05300D06092A864886F70D01010B05003081AB310B300906035504061302"
    "5553311330110603550408130A43616C69666F726E6961311230100603550407"
    "130953756E6E7976616C653111300F060355040A1308466F7274696E6574311E"
    "301C060355040B1315436572746966696361746520417574686F72697479311B"
    "301906035504031312666F7274696E65742D7375626361323030313123302106"
    "092A864886F70D0109011614737570706F727440666F7274696E65742E636F6D"
    "3020170D3139303232373233353030395A180F32303536303131393033313430"
    "375A308196310B3009060355040613025553311330110603550408130A43616C"
    "69666F726E6961311230100603550407130953756E6E7976616C653111300F06"
    "0355040A1308466F7274696E65743111300F060355040B1308466F7274694144"
    "43311330110603550403130A466F727469414443564D3123302106092A864886"
    "F70D0109011614737570706F727440666F7274696E65742E636F6D3082012230"
    "0D06092A864886F70D01010105000382010F003082010A0282010100CBD25313"
    "835D84E4A386ECEC070BA5264222C74F511A6BEDBDE9426E410674B85CAA5874"
    "90F6E0A3B622157963142973C6E89CD5BC4A0554D7C7D5C8FC95E74B67297278"
    "CA2334BD5A2F5E60B7A9AC6CB7CA037BA901BFE5B61821D9F14D19F9617A6E4F"
    "456D92EE8C5AAF8D7AFD769EC15343B4DB0AD455C54A5F5733DB925C24B0A206"
    "98A123864B8C5821C92F26143E9A1508D5B4A8D90D0E600E4259671D223D7588"
    "D4BB4F4D7F7B31B042EA5C7A3FE88416F66A94E4385108DDF4546516321C10DE"
    "F5ED4D1CA82667059F559B9027265A9B216694F6FD10AA7FEA37BAD30C508CFD"
    "4BCC74B868A027B4FE514FD4BA35C3084AA20BA9E28FD395A69BD58102030100"
    "01A382011730820113301D0603551D0E041604142EC1622503BC3883A19314A2"
    "31141FA5A67284F93081D30603551D230481CB3081C88014982B253C30CA2C2B"
    "56E7DBFC5933B3DC3D5B6AD7A181ABA481A83081A5310B300906035504061302"
    "5553311330110603550408130A43616C69666F726E6961311230100603550407"
    "130953756E6E7976616C653111300F060355040A1308466F7274696E6574311E"
    "301C060355040B1315436572746966696361746520417574686F726974793115"
    "30130603550403130C666F7274696E65742D6361323123302106092A864886F7"
    "0D0109011614737570706F727440666F7274696E65742E636F6D82022001300C"
    "0603551D130101FF04023000300E0603551D0F0101FF040403020780300D0609"
    "2A864886F70D01010B050003820101007F8D9F95C9B9019F3D248F920BC23ACD"
    "4259FE5C9098546333B9652A6236EEB9053EB9653838ECFF250B82AC7FB35A3F"
    "422A7A5F377F90BD253BAC1729EBB1E03BF37ABEFC207F05C26D91594E4B6154"
    "8B22F6D3D7447C508D8D805C6D0AC71D0EB2985D6C8F686D719DA34150BF26E2"
    "68EB88F7AE9E26A42ACDD5EEC6DEECF89B0789320D8C7833AB421ABB0C5244E2"
    "EC14C98ADF1F3D6A5C9D0727B435EE76E268D889CF0001E06573AFCC8EC9B4AF"
    "C823AA97015E9E384084AA30C7409CEAFC4479D55755FF0E3CF363D74643C3AD"
    "755FBE29BFEC1724F9ACFAD221FB7EF51456D07B2892C3B5C4D956FF5E8E062E"
    "DCAF06C45660843A15AB76EB5EB30AD300000F000104080401002BA39BFBD810"
    "51CEB09DF6B010CEC4DFC0B0396C92A41460C095BDE5E6C250F52B7FBEA32414"
    "724712821631DFBEA843BDEECAA2908B88551F4EC7C1AB24A08D0A1776ED8FDF"
    "98E9615DBE6DB94B251C713999D588EBED01361B8880E026A6A7B83E5E029743"
    "CAE6C562D3F9C42A3AC9BC94E8F352DF30413B9D3C322571A74665813533E917"
    "CAD939FFC9B156085C5A50E5D536A579861875FD437B70B9D5D4F1E6C34B6E3F"
    "85D277D15FBF64C937CC5A62B5D7B64D40DCAD1B28DB93A66A849148CB0825A0"
    "8581E4B5537B95DF663067247D9130A86A2D3086FEBBC787AA1EFE005C3DD01A"
    "5503FAAF0DA902CA5AD498B6EE2D045C72AB343F7075B4CD73F614000030E360"
    "766ACC2BDFBEFBA94561A898C82C6A22DE88FAE4B24C4B3B38B270473CA4892A"
    "289CA1EDDD82C19821BD484D48F3";
static char handshake_insecret[] =
    "5A8B2ADBD93465AF3F053309A35EA97BE632E2669F7F0091C888C32EC70FABFA"
    "FBFE580AE3CE9F747E8341443C85BD0A00000000000000000000000000000000";
static char server_handshake_secret[] =
    "C1F2861D3E1A023397775D6125959B5F541882C832A98DFB34E144BD5FD61B9E"
    "37ECFCE52DF310598EDC85D997121DE4";
static char server_traffic_secret[] =
    "DBAB85E74FC53EEDC25995AF4C3A20A79BE43BB7138862599B987E2E0A79AA15"
    "D6C065A8B69AF7FCBD75CBC3D68A62AB";
static char client_handshake_secret[] =
    "6847E634D0CEA4BFE50480CA433D5853F3A6D6DE1804778A6101DE5F56795529"
    "DB905EF6BCD1C2D234C98C7ACBE986AA";

static int server_handshake_secret_cmp_ok;
static int server_traffic_secret_cmp_ok;
static int client_handshake_secret_cmp_ok;

static int QuicSecretCmp(uint8_t *dest, char *src, size_t len)
{
    uint8_t hsecret[EVP_MAX_MD_SIZE] = {};

    str2hex(hsecret, src, len);
    
    return (memcmp(dest, hsecret, len) == 0);
}

#define SecretCmp(r, s, ret) \
    do { \
        size_t len = 0; \
        len = (sizeof(r) - 1)/2; \
        ret = QuicSecretCmp(s, r, len); \
    } while (0)

static void QuicHandshakeSecretComp(uint8_t *secret)
{
    static int seq = 0;

    if (seq == 0) {
        SecretCmp(server_handshake_secret, secret, \
                server_handshake_secret_cmp_ok);
    } else if (seq == 1) {
        SecretCmp(server_traffic_secret, secret, \
                server_traffic_secret_cmp_ok);
    } else if (seq == 2) {
        SecretCmp(client_handshake_secret, secret, \
                client_handshake_secret_cmp_ok);
    }

    seq++;
}

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

static int TlsCtxClientExtensionSet(QUIC_CTX *ctx)
{
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

    ret = 0;
out:
    return ret;
}
 
static void TlsSetHandshakeSecret(uint8_t *secret)
{
    str2hex(secret, handshake_insecret, (sizeof(handshake_insecret) - 1)/2);

}

int TlsClientHandshakeReadTest(void)
{
    QUIC_CTX *ctx = NULL;
    QUIC *quic = NULL;
    TLS *tls = NULL;
    QUIC_BUFFER *buf = NULL;
    BIO *rbio = NULL;
    BIO *wbio = NULL;
    const char *server_hello = NULL;
    size_t msg_len = 0;
    int offset = 0;
    int err = 0;
    int ret = -1;

    ctx = QuicCtxNew(QuicClientMethod());
    if (ctx == NULL) {
        goto out;
    }

    if (TlsCtxClientExtensionSet(ctx) < 0) {
        goto out;
    }

    quic = QuicNew(ctx);
    if (quic == NULL) {
        goto out;
    }

    QUIC_set_connect_state(quic);
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

    ret = QuicDoHandshake(quic);
    if (ret < 0) {
        err = QUIC_get_error(quic, ret);
        if (err != QUIC_ERROR_WANT_READ) {
            printf("Do Client Handshake failed\n");
            goto out;
        }
    }

    server_hello = TlsFindServerHello(clienthello_serverhello,
            sizeof(clienthello_serverhello) - 1);
    if (server_hello == NULL) {
        goto out;
    }

    offset = (server_hello - clienthello_serverhello)/2;
    buf = QUIC_TLS_BUFFER(quic);
    str2hex((void *)QuicBufHead(buf), (void *)clienthello_serverhello,
            offset);
    QuicBufSetDataLength(buf, offset);
    QuicBufReserve(buf);
    msg_len = strlen(server_hello)/2;
    str2hex((void *)QuicBufData(buf), (void *)server_hello, msg_len);
    QuicBufSetDataLength(buf, msg_len);
    msg_len = strlen(update_msg)/2;
    str2hex((void *)(QuicBufData(buf) + QuicBufGetDataLength(buf)),
            (void *)update_msg, msg_len);
    QuicBufAddDataLength(buf, msg_len);

    tls = &quic->tls;
    tls->kexch_key = TlsGeneratePkeyGroup(tls, EC_NAMED_CURVE_X25519);
    if (tls->kexch_key == NULL) {
        printf("TLS Gen Pkey Group failed!\n");
        goto out;
    }

    QuicSecretTest = QuicHandshakeSecretComp;
    QuicHandshakeSecretHook = TlsSetHandshakeSecret;
    if (TlsDoHandshake(tls) == QUIC_FLOW_RET_ERROR) {
        printf("TLS Hadshake failed!\n");
        goto out;
    }

    if (server_handshake_secret_cmp_ok == 0) {
        printf("Server Handshake secret compare failed\n");
        goto out;
    }

    if (server_traffic_secret_cmp_ok == 0) {
        printf("Server Traffic secret compare failed\n");
        goto out;
    }

    if (client_handshake_secret_cmp_ok == 0) {
        printf("Client Handshake secret compare failed\n");
        goto out;
    }

    ret = 1;
out:
    BIO_free(wbio);
    BIO_free(rbio);
    QuicFree(quic);
    QuicCtxFree(ctx);
    return ret;
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
    static uint8_t secret[(sizeof(outsecret) - 1)/2];
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

