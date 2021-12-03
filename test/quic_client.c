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

#include "quic_local.h"
#include "common.h"

#define TEST_EVENT_MAX_NUM   10
#define QUIC_RECORD_MAX_LEN  1500

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

static int QuicClient(struct sockaddr_in *addr, char *cert, char *key)
{
    QUIC_CTX *ctx = NULL;
    QUIC *quic = NULL;
    static uint8_t cid[] = "\x83\x94\xC8\xF0\x3E\x51\x57\x08";
    int sockfd = 0;
    int ret = 0;

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

    if (QUIC_set_fd(quic, sockfd) < 0) {
        goto out;
    }

    if (QuicTlsClientExtensionSet(quic) < 0) {
        goto out;
    }

    quic->dcid.data = cid;
    quic->dcid.len = sizeof(cid) - 1;
    ret = QuicDoHandshake(quic);
    quic->dcid.data = NULL;
    quic->dcid.len = 0;
    if (ret < 0) {
        printf("Do Client Handshake failed\n");
        goto out;
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
