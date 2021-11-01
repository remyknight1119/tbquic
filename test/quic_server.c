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

#define TEST_EVENT_MAX_NUM   10
#define QUIC_RECORD_MAX_LEN  1500

#define ARRAY_SIZE(array)    (sizeof(array)/sizeof(array[0]))

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

static void AddEpollEvent(int epfd, struct epoll_event *ev, int fd)
{
    ev->data.fd = fd;
    ev->events = EPOLLIN;
    epoll_ctl(epfd, EPOLL_CTL_ADD, fd, ev);
}

static int QuicServer(struct sockaddr_in *addr, char *cert, char *key)
{
    QUIC_CTX *ctx = NULL;
    QUIC *quic = NULL;
    BIO *rbio = NULL;
    BIO *wbio = NULL;
    QuicUdpConnKey udp_key = {};
    struct epoll_event ev = {};
    struct epoll_event events[TEST_EVENT_MAX_NUM] = {};
    char quic_data[QUIC_RECORD_MAX_LEN] = {};
    socklen_t addrlen = sizeof(udp_key);
	ssize_t rlen = 0;
    int sockfd = 0;
    int reuse = 1;
    int epfd = 0;
    int nfds = 0;
    int efd = 0;
    int handshake_done = 0;
    int i = 0;
    int ret = 0;

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        perror("socket");
        return -1;
    }

    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    if (bind(sockfd, (struct sockaddr *)addr, sizeof(*addr)) == -1) {
        perror("bind");
        return -1;
    }

    epfd = epoll_create(1);
    if (epfd < 0) {
        close(sockfd);
        return -1;
    }
    AddEpollEvent(epfd, &ev, sockfd);

    ctx = QuicCtxNew(QuicServerMethod());
    if (ctx == NULL) {
        goto out;
    }

    while (1) {
        nfds = epoll_wait(epfd, events, TEST_EVENT_MAX_NUM, -1);
        for (i = 0; i < nfds; i++) {
            if (events[i].events & EPOLLIN) {
                if ((efd = events[i].data.fd) < 0) {
                    continue;
                }

                memset(&udp_key, 0, sizeof(udp_key));
                if (efd == sockfd) {
                    fprintf(stdout, "UDP msg!\n");
                    rlen = recvfrom(efd, quic_data, sizeof(quic_data), 0, 
                            (struct sockaddr *)&udp_key, &addrlen);
                    fprintf(stdout, "rlen = %d, addr len = %d!\n", (int)rlen, (int)addrlen);
                    if (rlen <= 0) {
                        goto next;
                    }

                    if (quic == NULL) {
                        quic = QuicNew(ctx);
                        if (quic == NULL) {
                            goto out;
                        }

                        rbio = BIO_new(BIO_s_mem());
                        if (rbio == NULL) {
                            goto out;
                        }

                        wbio = BIO_new(BIO_s_mem());
                        if (wbio == NULL) {
                            goto out;
                        }
                        QUIC_set_bio(quic, rbio, wbio);
                    } else {
                        rbio = QUIC_get_rbio(quic);
                    }

                    BIO_write(rbio, quic_data, rlen);
                    rbio = NULL;
                    wbio = NULL;
                    if (handshake_done == 0) {
                        ret = QuicDoHandshake(quic);
                        if (ret < 0) {
                            goto next;
                        }
                        handshake_done = 1;
                    }

                    printf("conn found, sport = %d\n", ntohs(udp_key.addr4.sin_port));
                    //bzero(buf, sizeof(buf));
                    /* 接收客户端的消息 */

next:
                    AddEpollEvent(epfd, &ev, sockfd);
                    continue;
                }
            }
        }
    }

out:
    BIO_free(rbio);
    BIO_free(wbio);
    QuicFree(quic);
    QuicCtxFree(ctx);
    close(epfd);
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

    return QuicServer(&addr, cert, key);
}
