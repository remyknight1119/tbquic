/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "quic_test.h"

#include <stdio.h>
#include <getopt.h>
#include <sys/epoll.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <tbquic/quic.h>
#include <tbquic/ec.h>
#include <tbquic/tls.h>
#include <tbquic/stream.h>

#include "quic_local.h"
#include "common.h"

#define TEST_EVENT_MAX_NUM   10
#define QUIC_RECORD_MAX_LEN  1500
#define CLIENT_TEST_IOV_NUM 5

static QuicTestBuff QuicClientIovBuf[CLIENT_TEST_IOV_NUM];
static const char *program_version = "1.0.0";//PACKAGE_STRING;

static const struct option long_opts[] = {
    {"help", 0, 0, 'H'},
    {"address", 0, 0, 'a'},
    {"port", 0, 0, 'p'},
    {"certificate", 0, 0, 'c'},
    {"key", 0, 0, 'k'},
    {0, 0, 0, 0}
};

static const char *options[] = {
    "--address      		-a	IP address for QUIC communication\n",	
    "--port         		-p	Port for QUIC communication\n",	
    "--certificate  		-c	certificate file\n",	
    "--key      		    -k	key file\n",	
    "--help         		-H	Print help information\n",	
};

static uint8_t appdata1[] =
    "\x00\x04\x19\x01\x80\x01\x00\x00\x06\x80\x02\x00\x00\x07\x40\x64"
    "\xc0\x00\x00\x09\x03\x15\xe8\x23\xa8\x51\x09\x24\xc0\x00\x00\x04"
    "\x2f\x0c\x7e\x1f\x02\xf6\x12";
static uint8_t appdata2[] =
    "\x02\x3f\xe1\xff\x03\xc0\x8c\xf1\xe3\xc2\xe5\xf2\x3a\x6b\xa0\xab"
    "\x9e\xc9\xbf";
static uint8_t appdata3[] =
    "\x01\x06\x02\x00\xd1\xd7\x80\xc1";

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

static TlsTestParam test_param[] = {
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

static void help(void)
{
    int     index;

    fprintf(stdout, "Version: %s\n", program_version);

    fprintf(stdout, "\nOptions:\n");
    for (index = 0; index < ARRAY_SIZE(options); index++) {
        fprintf(stdout, "  %s", options[index]);
    }
}

static const char *optstring = "Ha:p:c:k:";

static int QuicTlsCtxClientExtensionSet(QUIC_CTX *ctx)
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
 
static int QuicTlsClientExtensionSet(QUIC *quic)
{
    TlsTestParam *p = NULL;
    size_t i = 0;
    int ret = -1;

    if (QuicCtrl(quic, QUIC_CTRL_SET_TLSEXT_HOSTNAME,
                "www.example.org", 0) < 0) {
        goto out;
    }

    for (i = 0; i < QUIC_NELEM(test_param); i++) {
        p = &test_param[i];
        if (p->value == 0) {
            continue;
        }
        QUIC_set_transport_parameter(quic, p->type, &p->value, 0);
    }

    ret = 0;
out:
    return ret;
}

static int QuicClient(struct sockaddr_in *addr, char *cert, char *key)
{
    QUIC_CTX *ctx = NULL;
    QUIC *quic = NULL;
    QUIC_STREAM_HANDLE h = -1;
    QUIC_STREAM_HANDLE h2 = -1;
    QUIC_STREAM_IOVEC iov[CLIENT_TEST_IOV_NUM] = {};
    int sockfd = 0;
    int i = 0;
    int ret = 0;
    int cnt = 0;
    int err = 0;

    QuicTestStreamIovecInit(iov, QuicClientIovBuf, CLIENT_TEST_IOV_NUM);
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        perror("socket");
        return -1;
    }

    if (connect(sockfd, (struct sockaddr *)addr, sizeof(*addr)) != 0) {
        perror("connect");
        return -1;
    }

    ctx = QuicCtxNew(QuicClientMethod());
    if (ctx == NULL) {
        goto out;
    }

    if (QuicTlsCtxClientExtensionSet(ctx) < 0) {
        goto out;
    }

    quic = QuicNew(ctx);
    if (quic == NULL) {
        goto out;
    }

    QUIC_set_connect_state(quic);
    if (QUIC_set_fd(quic, sockfd) < 0) {
        goto out;
    }

    if (QuicTlsClientExtensionSet(quic) < 0) {
        goto out;
    }

    while (1) {
        ret = QuicDoHandshake(quic);
        if (ret == 0) {
            break;
        }
        err = QUIC_get_error(quic, ret);
        if (err != QUIC_ERROR_WANT_READ) {
            goto out;
        }
    }

    printf("Handshake done\n");
    cnt = QuicStreamReadV(quic, iov, CLIENT_TEST_IOV_NUM);
    printf("cnt = %d\n", cnt);
    if (cnt < 0) {
        err = QUIC_get_error(quic, ret);
        if (err != QUIC_ERROR_WANT_READ) {
            goto out;
        }
    }

    for (i = 0; i < cnt; i++) {
        printf("Stream ID: %lu\t", iov[i].handle);
        QuicPrint(iov[i].iov_base, iov[i].data_len);
    }

    h = QuicStreamOpen(quic, false);
    if (h < 0) {
        goto out;
    }

    if (QuicStreamSend(quic, h, appdata1, sizeof(appdata1) - 1) < 0) {
        goto out;
    }

    h2 = QuicStreamOpen(quic, false);
    if (h2 < 0) {
        goto out;
    }

    if (QuicStreamSend(quic, h2, appdata2, sizeof(appdata2) - 1) < 0) {
        goto out;
    }

    if (QuicStreamSend(quic, h, appdata3, sizeof(appdata3) - 1) < 0) {
        goto out;
    }

    cnt = QuicStreamReadV(quic, iov, CLIENT_TEST_IOV_NUM);
    printf("cnt = %d\n", cnt);
    if (cnt < 0) {
    }

out:
    QuicFree(quic);
    QuicCtxFree(ctx);
    close(sockfd);

    return 0;
}

int main(int argc, char **argv)  
{
    char *ip = NULL;
    char *port = NULL;
    char *cert = NULL;
    char *key = NULL;
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
    };
    int c = 0;

    while ((c = getopt_long(argc, argv, optstring, long_opts, NULL)) != -1) {
        switch (c) {
            case 'H':
                help();
                return 0;
            case 'a':
                ip = optarg;
                break;
            case 'p':
                port = optarg;
                break;
            case 'c':
                cert = optarg;
                break;
            case 'k':
                key = optarg;
                break;

            default:
                help();
                return -1;
        }
    }

    if (ip == NULL) {
        fprintf(stderr, "Please input IP by -a!\n");
        return -1;
    }

    if (port == NULL) {
        fprintf(stderr, "Please input port by -p!\n");
        return -1;
    }

    QuicInit();

    addr.sin_port = htons(atoi(port));
    addr.sin_addr.s_addr = inet_addr(ip);

    return QuicClient(&addr, cert, key);
}
