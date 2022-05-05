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
    {"verify-ca", 0, 0, 'v'},
    {"key", 0, 0, 'k'},
    {0, 0, 0, 0}
};

static const char *options[] = {
    "--address      		-a	IP address for QUIC communication\n",	
    "--port         		-p	Port for QUIC communication\n",	
    "--certificate  		-c	certificate file\n",	
    "--verify-ca  		    -v	CA cert which used for verify\n",	
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

static void help(void)
{
    int     index;

    fprintf(stdout, "Version: %s\n", program_version);

    fprintf(stdout, "\nOptions:\n");
    for (index = 0; index < ARRAY_SIZE(options); index++) {
        fprintf(stdout, "  %s", options[index]);
    }
}


QUIC_SESSION *session;

static int QuicClientDo(struct sockaddr_in *addr, char *cert,
                            char *key, char *ca)
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

    QUIC_CTX_set_keylog_callback(ctx, QuicKeyLog);

    if (ca != NULL) {
        QuicSetVerify(ctx, QUIC_TLS_VERIFY_PEER, ca);
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

    if (session == NULL) {
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

        session = QUIC_get1_session(quic);
    } else {
        if (QUIC_set_session(quic, session) < 0) {
            printf("Set session failed\n");
            goto out;
        }

        while (1) {
            printf("Send Early data\n");
            ret = QuicStreamSendEarlyData(quic, &h, true, appdata1,
                    sizeof(appdata1) - 1);
            if (ret < 0) {
                err = QUIC_get_error(quic, ret);
                if (err != QUIC_ERROR_WANT_READ) {
                    printf("Error\n");
                    goto out;
                }

                continue;
            }

            break;
        }
    }
    printf("Handshake done, session = %p\n", session);
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

static int QuicClient(struct sockaddr_in *addr, char *cert, char *key, char *ca)
{
    QuicClientDo(addr, cert, key, ca);

    return QuicClientDo(addr, cert, key, ca);
}

static const char *optstring = "Ha:p:c:k:v:";

int main(int argc, char **argv)  
{
    char *ip = NULL;
    char *port = NULL;
    char *cert = NULL;
    char *key = NULL;
    char *ca = NULL;
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
            case 'v':
                ca = optarg;
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

    return QuicClient(&addr, cert, key, ca);
}
