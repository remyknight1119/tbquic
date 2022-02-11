/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "session.h"

#include "mem.h"
#include "quic_local.h"
#include "tls_lib.h"
#include "common.h"
#include "crypto.h"

QuicSessionTicket *
QuicSessionTicketNew(uint32_t lifetime_hint, uint32_t age_add,
                        const uint8_t *ticket, size_t len)
{
    QuicSessionTicket *t = NULL;

    t = QuicMemCalloc(sizeof(*t));
    if (t == NULL) {
        return NULL;
    }

    if (QuicDataCopy(&t->ticket, ticket, len) < 0) {
        QuicMemFree(t);
        return NULL;
    }

    t->lifetime_hint = lifetime_hint;
    t->age_add = age_add;
    t->time = time(NULL);

    return t;
}

void QuicSessionTicketAdd(QUIC_SESSION *sess, QuicSessionTicket *t)
{
    list_add_tail(&t->node, &sess->ticket_queue);
    sess->tick_identity++;
}

QuicSessionTicket *QuicSessionTicketGet(QUIC_SESSION *sess, uint32_t *age_ms)
{
    QuicSessionTicket *t = NULL;
    QuicSessionTicket *n = NULL;
    time_t now = time(NULL);
    int age_sec = 0;

    struct list_head *head = &sess->ticket_queue;

    if (list_empty(head)) {
        return NULL;
    }

    list_for_each_entry_safe(t, n, head, node) {
        age_sec = now - t->time - 1;
        if (age_sec >= 0 && QUIC_GE(t->lifetime_hint, age_sec)) {
            if (age_ms != NULL) {
                *age_ms = age_sec * 1000 + t->age_add;
            }
            return t;
        }
        list_del(&t->node);
        QuicSessionTicketFree(t);
    }

    return NULL;
}

void QuicSessionTicketFree(QuicSessionTicket *t)
{
    QuicDataFree(&t->ticket);
    QuicMemFree(t);
}

int QuicSessionMasterKeyGen(TLS *s, QuicSessionTicket *t, RPacket *nonce)
{
    static const uint8_t nonce_label[] = "resumption";
    const EVP_MD *md = TlsHandshakeMd(s);
    size_t hash_len = EVP_MD_size(md);

    if (QUIC_LE(hash_len, 0)) {
        return -1;
    }

    if (TLS13HkdfExpandLabel(md, s->resumption_master_secret, hash_len,
                        nonce_label, sizeof(nonce_label) - 1,
                        RPacketData(nonce), RPacketRemaining(nonce),
                        t->master_key, hash_len) < 0) {
        return -1;
    }

    t->master_key_length = hash_len;
    return 0;
}

QUIC_SESSION *QuicSessionCreate(void)
{
    QUIC_SESSION *sess = NULL;

    sess = QuicMemCalloc(sizeof(*sess));
    if (sess == NULL) {
        return NULL;
    }

    sess->references = 1;
    INIT_LIST_HEAD(&sess->ticket_queue);
    return sess;
}

void QuicSessionUpRef(QUIC_SESSION *sess)
{
    sess->references++;
}

void QuicSessionDestroy(QUIC_SESSION *sess)
{
    QuicSessionTicket *t = NULL;
    QuicSessionTicket *n = NULL;

    list_for_each_entry_safe(t, n, &sess->ticket_queue, node) {
        list_del(&t->node);
        QuicSessionTicketFree(t);
    }

    QuicMemFree(sess);
}

void QuicSessionFree(QUIC_SESSION *sess)
{
    if (sess == NULL) {
        return;
    }

    if (--sess->references > 0) {
        return;
    }

    QuicSessionDestroy(sess);
}

int QuicGetSession(QUIC *quic)
{
    quic->session = QuicSessionCreate();
    if (quic->session == NULL) {
        return -1;
    }

    quic->session->cipher = quic->tls.handshake_cipher;
    return 0;
}
