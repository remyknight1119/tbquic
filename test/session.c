
#include "quic_test.h"

#include <openssl/rand.h>
#include <tbquic/types.h>

#include "session.h"
#include "asn1.h"
#include "mem.h"


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

    ret = 0;
err:
    QuicSessionFree(res);
    QuicMemFree(code);
    QuicSessionFree(sess);
    return ret;
}
