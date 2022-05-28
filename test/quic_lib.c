
#include "quic_test.h"

#include <sys/epoll.h>
#include <tbquic/types.h>
#include <tbquic/stream.h>
#include <tbquic/tls.h>

#include "quic_local.h"
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

static TlsTestParam client_test_param[] = {
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

static TlsTestParam server_test_param[] = {
    {
        .type = QUIC_TRANS_PARAM_INITIAL_MAX_STREAM_DATA_UNI,
        .value = 0x600000,
    },
    {
        .type = QUIC_TRANS_PARAM_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
        .value = 0x600000,
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
        .type = QUIC_TRANS_PARAM_INITIAL_SOURCE_CONNECTION_ID,
    },
};


void QuicTestStreamIovecInit(QUIC_STREAM_IOVEC *iov, QuicTestBuff *buf,
                                size_t num)
{
    size_t i = 0;

    for (i = 0; i < num; i++) {
        iov[i].iov_base = buf[i].buf;
        iov[i].iov_len = sizeof(buf[i].buf);
    }
}

void QuicKeyLog(const QUIC *quic, const char *log)
{
    fprintf(stdout, "%s\n", log);
}

int QuicTlsCtxClientExtensionSet(QUIC_CTX *ctx)
{
    const uint8_t alpn[] = "h3";
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
 
int QuicTlsClientExtensionSet(QUIC *quic)
{
    TlsTestParam *p = NULL;
    size_t i = 0;
    int ret = -1;

    if (QuicCtrl(quic, QUIC_CTRL_SET_TLSEXT_HOSTNAME,
                "www.example.org", 0) < 0) {
        goto out;
    }

    for (i = 0; i < QUIC_NELEM(client_test_param); i++) {
        p = &client_test_param[i];
        if (p->value == 0) {
            continue;
        }
        QUIC_set_transport_parameter(quic, p->type, &p->value, 0);
    }

    ret = 0;
out:
    return ret;
}

int QuicCtxServerExtensionSet(QUIC_CTX *ctx)
{
    TlsTestParam *p = NULL;
    const uint8_t alpn[] = "h3";
    size_t i = 0;
    int ret = -1;

    for (i = 0; i < ARRAY_SIZE(server_test_param); i++) {
        p = &server_test_param[i];
        if (p->value == 0) {
            continue;
        }
        QUIC_CTX_set_transport_parameter(ctx, p->type, &p->value, 0);
    }

    if (QUIC_CTX_set_alpn_protos(ctx, alpn, sizeof(alpn) - 1) < 0) {
        goto out;
    }

    ret = 0;
out:
    return ret;
}
 
static int QuicVerifyCallback(int ok, X509_STORE_CTX *ctx)
{
    return 1;
}

void QuicSetVerify(void *ctx, int mode, char *peer_cf)
{
    STACK_OF(X509_NAME)  *list = NULL;

    QUIC_CTX_set_verify(ctx, mode, QuicVerifyCallback);
    QUIC_CTX_set_verify_depth(ctx, 6);

    if (QuicCtxLoadVerifyLocations(ctx, peer_cf, NULL) == 0) {
        fprintf(stderr, "Load verify locations %s failed\n", peer_cf);
        exit(1);
    }
    
    list = QuicLoadClientCaFile(peer_cf);
    if (list == NULL) {
        fprintf(stderr, "Load client ca file %s failed\n", peer_cf);
        exit(1);
    }

    QUIC_CTX_set0_CA_list(ctx, list);
}

void AddEpollEvent(int epfd, struct epoll_event *ev, int fd)
{
    ev->data.fd = fd;
    ev->events = EPOLLIN;
    epoll_ctl(epfd, EPOLL_CTL_ADD, fd, ev);
}


