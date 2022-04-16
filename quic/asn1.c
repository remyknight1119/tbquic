/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "asn1.h"

#include <tbquic/types.h>
#include "mem.h"
#include "log.h"

ASN1_SEQUENCE(QUIC_SESSION_ASN1) = {
    ASN1_SIMPLE(QUIC_SESSION_ASN1, master_key, ASN1_OCTET_STRING),
    ASN1_EXP_OPT_EMBED(QUIC_SESSION_ASN1, cipher_id, UINT32, 0),
    ASN1_EXP_OPT_EMBED(QUIC_SESSION_ASN1, tick_age_add, ZUINT32, 1),
    ASN1_EXP_OPT_EMBED(QUIC_SESSION_ASN1, tick_lifetime_hint, ZUINT64, 2),
    ASN1_EXP_OPT(QUIC_SESSION_ASN1, tlsext_tick, ASN1_OCTET_STRING, 3),
} static_ASN1_SEQUENCE_END(QUIC_SESSION_ASN1)

IMPLEMENT_STATIC_ASN1_ENCODE_FUNCTIONS(QUIC_SESSION_ASN1)

static void QuicSessionOinit(ASN1_OCTET_STRING **dest, ASN1_OCTET_STRING *os,
        uint8_t *data, size_t len)
{
    os->data = data;
    os->length = (int)len;
    os->flags = 0;
    *dest = os;
}

static int QuicSessionMemcpy(uint8_t *dst, size_t *pdstlen,
                ASN1_OCTET_STRING *src, size_t maxlen)
{
    if (src == NULL || src->length == 0) {
        *pdstlen = 0;
        return 0;
    }

    if (src->length < 0 || src->length > (int)maxlen) {
        return -1;
    }

    QuicMemcpy(dst, src->data, src->length);
    *pdstlen = src->length;
    return 0;
}

int i2dQuicSession(QUIC_SESSION *in, uint8_t **pp)
{
    QuicSessionTicket *t = NULL;
    QUIC_DATA *tk = NULL;
    ASN1_OCTET_STRING tlsext_tick;
    ASN1_OCTET_STRING master_key;
    QUIC_SESSION_ASN1 as = {};

    if (in->cipher == NULL) {
        return -1;
    }

    t = QuicSessionTicketPickTail(in);
    if (t == NULL) {
        return -1;
    }

    as.cipher_id = in->cipher->id;
    as.tick_lifetime_hint = t->lifetime_hint;
    as.tick_age_add = t->age_add;

    tk = &t->ticket;
    if (!QuicDataIsEmpty(tk)) {
        QuicSessionOinit(&as.tlsext_tick, &tlsext_tick, tk->data, tk->len);
    }

    QuicSessionOinit(&as.master_key, &master_key, t->master_key,
            t->master_key_length);

    return i2d_QUIC_SESSION_ASN1(&as, (unsigned char **)pp);
}

QUIC_SESSION *d2iQuicSession(const uint8_t **pp, long length)
{
    QUIC_SESSION_ASN1 *as = NULL;
    QUIC_SESSION *sess = NULL;
    QuicSessionTicket *t = NULL;
    const uint8_t *p = *pp;
    size_t master_key_len = 0;

    as = d2i_QUIC_SESSION_ASN1(NULL, &p, length);
    if (as == NULL) {
        QUIC_LOG("d2i_QUIC_SESSION_ASN1 failed\n");
        goto err;
    }

    sess = QuicSessionCreate();
    if (sess == NULL) {
        goto err;
    }

    sess->cipher = QuicGetTlsCipherById(as->cipher_id);
    if (sess->cipher == NULL) {
        goto err;
    }

    t = QuicSessionTicketNew(as->tick_lifetime_hint, as->tick_age_add, NULL, 0);
    if (t == NULL) {
        goto err;
    }

    if (as->tlsext_tick != NULL) {
        t->ticket.data = as->tlsext_tick->data;
        t->ticket.len = as->tlsext_tick->length;
        as->tlsext_tick->data = NULL;
    }

    if (QuicSessionMemcpy(t->master_key, &master_key_len, as->master_key,
                TLS_MAX_RESUMPTION_PSK_LENGTH) < 0) {
        goto err;
    }

    t->master_key_length = master_key_len;

    QuicSessionTicketAdd(sess, t);

    M_ASN1_free_of(as, QUIC_SESSION_ASN1);
    *pp = p;

    return sess;

err:
    M_ASN1_free_of(as, QUIC_SESSION_ASN1);
    QuicSessionFree(sess);
    return NULL;
}

