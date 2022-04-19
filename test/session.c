
#include "quic_test.h"

#include <string.h>
#include <openssl/rand.h>
#include <tbquic/types.h>

#include "session.h"
#include "asn1.h"
#include "mem.h"
#include "tls.h"
#include "common.h"
#include "tls_lib.h"

static char ticket_iv[] = "7999f26550626926eaf65877bf4568f9";
static char ticket_aes_key[] =
    "035a6071066318fba4337482146af9748825ed755cc13a30a5e4a5be45adf1cb";
static char ticket_hmac_key[] =
    "b85a88eec8c772ea3c825a104ab5c13f988eb0c05c65792876536bdfd67110d3";
static char ticket_key_name[] = "32e1efbfe36c3c212048f62264677751";
static char ticket_session_asn1[] =
    "30790201010202030404021302042033132cb93a597e818dbb29ed6b08619e9"
    "976c0bd085f9c627e460571f91fd98c0430240b26f59f663bbaa8c51611995d"
    "a2b7545dbe614a5aacd397f4b77c259f978a7250c57e2dc7548c57f6998f449"
    "a96eea10602046257614ea20402021c20a4020400ae06020410913ad6";
static char ticket_result[] =
    "00001C2010913AD608000000000000000000C032E1EFBFE36C3C212048F62264"
    "6777517999F26550626926EAF65877BF4568F9BF1C1AFADC47B07B33FA6E8766"
    "D97995E452DAA0BB62789E739E050436837B20A3F594910D1441D28255D8D4D8"
    "D521C03870D34F18A7C4720BA147228C827DF1ECDDF8C2A4D4FD66EE012421A6"
    "7CEEABD7EC7366A98700BA4084DD78B7EBEF71B6E0371E8459A989DBF78602E0"
    "A0B1AF5A1FEE284627F4FDB27FB71A9A90235011B4E6A8DADE6F95FF5D0BFDDB"
    "7B62809509375DD3D025B6F07E1AED953800A1";

int QuicSessionAsn1Test(void)
{
    QUIC_SESSION *sess = NULL;
    QUIC_SESSION *res = NULL;
    QuicSessionTicket *t = NULL;
    QuicSessionTicket *rt = NULL;
    uint8_t *p = NULL;
    const uint8_t *const_p = NULL;
    struct {
        uint32_t lifetime_hint;
        uint32_t age_add;
        uint8_t ticket[128];
    } arg;
    uint8_t *code = NULL;
    int len = 0;
    int ret = -1;

    sess = QuicSessionCreate();
    if (sess == NULL) {
        return -1;
    }

    sess->cipher = QuicGetTlsCipherById(TLS_CK_AES_256_GCM_SHA384); 
    sess->max_early_data = 0x8D7F;
    RAND_bytes((void *)&arg, sizeof(arg));
    t = QuicSessionTicketNew(arg.lifetime_hint, arg.age_add, arg.ticket,
                            sizeof(arg.ticket));
    if (t == NULL) {
        QuicSessionTicketFree(t);
        goto err;
    }

    QuicSessionTicketAdd(sess, t);

    len = i2dQuicSession(sess, NULL);
    if (len <= 0) {
        goto err;
    }

    code = QuicMemMalloc(len);
    if (code == NULL) {
        goto err;
    }

    p = code;
    if (i2dQuicSession(sess, &p) <= 0) {
        printf("i2dQuicSession failed!\n");
        goto err;
    }

    const_p = code;
    res = d2iQuicSession(&const_p, len);
    if (res == NULL) {
        goto err;
    }

    rt = QuicSessionTicketPickTail(res);
    if (rt == NULL) {
        goto err;
    }

    if (t->lifetime_hint != rt->lifetime_hint) {
        goto err;
    }

    if (t->age_add != rt->age_add) {
        goto err;
    }

    if (QuicDataEq(&t->ticket, &rt->ticket) == false) {
        goto err;
    }

    if (sess->max_early_data != res->max_early_data) {
        goto err;
    }

    ret = 0;
err:
    QuicSessionFree(res);
    QuicMemFree(code);
    QuicSessionFree(sess);
    return ret;
}

static uint8_t *QuicSessionAsn1(uint8_t *senc, int *slen)
{
    uint8_t *s = NULL;
    int len = strlen(ticket_session_asn1)/2;

    free(senc);
    s = malloc(len);
    if (s == NULL) {
        return NULL;
    }

    str2hex(s, ticket_session_asn1, len);
    *slen = len;
    return s;
}

static int QuicSessionTicketIv(uint8_t *iv)
{
    int len = strlen(ticket_iv)/2;

    str2hex(iv, ticket_iv, len);

    return len;
}

static int QuicStatelessTicketTest(int enc)
{
    QUIC_SESSION *sess = NULL;
    QUIC_SESSION *rsess = NULL;
    QuicSessionTicket *t = NULL;
    TlsTicketKey *tk = NULL;
    WPacket pkt;
    TLS tls = {};
    RPacket tick_nonce = {};
    size_t len = 0;
    uint8_t buf[1024];
    uint8_t ticket_n[TICKET_NONCE_SIZE] = {};
    uint8_t ticket[QUIC_SESSION_TICKET_LEN] = {};
    uint8_t res[sizeof(ticket_result)/2] = {};
    uint32_t lifetime_hint = 7200;
    uint32_t age_add = 277953238;
    int offset = 0;
    int ret = -1;

    WPacketStaticBufInit(&pkt, buf, sizeof(buf));
    sess = QuicSessionCreate();
    if (sess == NULL) {
        goto err;
    }

    sess->cipher = QuicGetTlsCipherById(TLS_CK_AES_256_GCM_SHA384); 
    tk = &tls.ext.ticket_key;
    str2hex(tk->tick_aes_key, ticket_aes_key, strlen(ticket_aes_key)/2);
    str2hex(tk->tick_hmac_key, ticket_hmac_key, strlen(ticket_hmac_key)/2);
    str2hex(tk->tick_key_name, ticket_key_name, strlen(ticket_key_name)/2);

    t = QuicSessionTicketNew(lifetime_hint, age_add, ticket, sizeof(ticket));
    if (t == NULL) {
        goto err;
    }

    QuicSessionTicketAdd(sess, t);

    if (enc) {
        QuicSessionTicketTest = QuicSessionAsn1;
        QuicSessionTicketIvTest = QuicSessionTicketIv;
    } else {
        QuicSessionTicketTest = NULL;
        QuicSessionTicketIvTest = NULL;
    }

    RPacketBufInit(&tick_nonce, ticket_n, TICKET_NONCE_SIZE);
    if (TlsConstructStatelessTicket(&tls, sess, &pkt, &tick_nonce) < 0) {
        printf("Construct Ticket Failed\n");
        goto err;
    }

    len = WPacket_get_written(&pkt);
    if (enc) {
        if (len != sizeof(res)) {
            goto err;
        }

        str2hex(res, ticket_result, len);
        if (memcmp(buf, res, len) != 0) {
            goto err;
        }
    } else {
        offset = 4 + 4 + 1 + 8 + 2;
        if (TlsDecryptTicket(&tls, &buf[offset], len - offset, &rsess) < 0) {
            printf("Decrypt TLS ticket failed\n");
            goto err;
        }
    }

    ret = 0;
err:
    QuicSessionFree(rsess);
    QuicSessionFree(sess);
    return ret;
}

int QuicConstructStatelessTicket(void)
{
    return QuicStatelessTicketTest(1);
}

int QuicDecryptStatelessTicket(void)
{
    return QuicStatelessTicketTest(0);
}

