/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "quic_test.h"

#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <tbquic/quic.h>
#include <tbquic/dispenser.h>
#include <tbquic/stream.h>

#include "quic_local.h"

#define QUIC_TEST_IP                "127.0.0.1"
#define QUIC_TEST_PORT              6231
#define QUIC_TEST_BUF_MAX_LEN       256
#define QUIC_TEST_CMD_START         "start"
#define QUIC_TEST_CMD_OK            "ok"
#define QUIC_TEST_CMD_END           "end"

static void QuicSetAddr(struct sockaddr_in *addr)
{
    addr->sin_family = AF_INET,
    addr->sin_port = htons(QUIC_TEST_PORT);
    addr->sin_addr.s_addr = inet_addr(QUIC_TEST_IP);
}

static int QuicTlsClientMain(void)
{
    QUIC_CTX *ctx = NULL;
    QUIC *quic = NULL;
    struct sockaddr_in addr = {};
    int sockfd = -1;
    int err = -1;
    int ret = -1;

    QuicSetAddr(&addr);

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        perror("socket");
        return -1;
    }

    if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        perror("connect");
        goto out;
    }

    ctx = QuicCtxNew(QuicClientMethod());
    if (ctx == NULL) {
        goto out;
    }

    QuicSetVerify(ctx, QUIC_TLS_VERIFY_PEER, quic_ca);

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
        printf("client ret = %d\n", ret);
        if (ret == 0) {
            break;
        }
        err = QUIC_get_error(quic, ret);
        if (err != QUIC_ERROR_WANT_READ) {
            goto out;
        }
    }

    ret = 0;
out:
    QuicFree(quic);
    QuicCtxFree(ctx);
    close(sockfd);
    return ret;
}

static int
QuicTlsClient(int pipefd)
{
    char buf[QUIC_TEST_BUF_MAX_LEN] = {};
    ssize_t rlen = 0;
    ssize_t wlen = 0;
    int ret = 0;

    wlen = write(pipefd, QUIC_TEST_CMD_START, strlen(QUIC_TEST_CMD_START));
    if (wlen < strlen(QUIC_TEST_CMD_START)) {
        fprintf(stderr, "Write to pipefd failed(errno=%s)\n", strerror(errno));
        goto err;
    }
    rlen = read(pipefd, buf, sizeof(buf));
    if (rlen < 0 || strcmp(QUIC_TEST_CMD_OK, buf) != 0) {
        fprintf(stderr, "Read from pipefd failed(errno=%s)\n", strerror(errno));
        goto err;
    }

    ret = QuicTlsClientMain();
    if (ret < 0) {
        goto err;
    }

    fprintf(stdout, "Send message to server!\n");
    wlen = write(pipefd, QUIC_TEST_CMD_END, strlen(QUIC_TEST_CMD_END));
    if (wlen < strlen(QUIC_TEST_CMD_END)) {
        fprintf(stderr, "Write to pipefd failed(errno=%s), wlen = %d\n",
                strerror(errno), (int)wlen);
        goto err;
    }

    rlen = read(pipefd, buf, sizeof(buf));
    if (rlen < 0 || strcmp(QUIC_TEST_CMD_OK, buf) != 0) {
        fprintf(stderr, "Read from pipefd failed(errno=%s)\n", strerror(errno));
        goto err;
    }

    close(pipefd);
    return 1;
err:
    close(pipefd);
    return -1;
}

static int
QuicTlsServer(int pipefd)
{
    QUIC_CTX *ctx = NULL;
    QUIC *quic = NULL;
    QUIC_DISPENSER *dis = NULL;
    QUIC_STREAM_HANDLE h = -1;
    struct sockaddr_in addr = {};
    struct epoll_event ev = {};
    struct epoll_event events[QUIC_TEST_EVENT_MAX_NUM] = {};
    char buf[QUIC_BUF_MAX_LEN] = {};
    bool new = false;
    ssize_t rlen = 0;
    ssize_t wlen = 0;
    uint32_t mss = QUIC_RECORD_MSS_LEN;
    int sockfd = 0;
    int epfd = 0;
    int nfds = 0;
    int i = 0;
    int efd = -1;
    int reuse = 1;
    int err = 1;
    int ret = -1;

    QuicSetAddr(&addr);

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        perror("socket");
        return -1;
    }

    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        perror("bind");
        goto err;
    }

    epfd = epoll_create(1);
    if (epfd < 0) {
        goto err;
    }
    AddEpollEvent(epfd, &ev, pipefd);
    AddEpollEvent(epfd, &ev, sockfd);

    ctx = QuicCtxNew(QuicDispenserMethod());
    if (ctx == NULL) {
        goto err;
    }

    if (QuicCtxUsePrivateKeyFile(ctx, quic_key, QUIC_FILE_TYPE_PEM) < 0) {
        printf("Use Private Key file %s failed\n", quic_key);
        goto err;
    }

    if (QuicCtxUseCertificateFile(ctx, quic_cert, QUIC_FILE_TYPE_PEM) < 0) {
        printf("Use Private Cert file %s failed\n", quic_cert);
        goto err;
    }

    if (QuicCtxCtrl(ctx, QUIC_CTRL_SET_MSS, &mss, 0) < 0) {
        goto err;
    }

    if (QuicCtxServerExtensionSet(ctx) < 0) {
        printf("Set Extension failed\n");
        goto out;
    }

    dis = QuicCreateDispenser(sockfd);
    if (dis == NULL) {
        printf("Create dispenser failed\n");
        goto err;
    }

    while (1) {
        nfds = epoll_wait(epfd, events, QUIC_TEST_EVENT_MAX_NUM, -1);
        for (i = 0; i < nfds; i++) {
            if (events[i].events & EPOLLIN) {
                if ((efd = events[i].data.fd) < 0) {
                    continue;
                }

                if (efd == sockfd) {
                    quic = QuicDoDispense(dis, ctx, &new);
                    if (quic == NULL) {
                        goto next;
                    }

                    if (new) {
                        printf("new QUIC\n");
                    }
 
                    ret = QuicDoHandshake(quic);
                    if (ret == 0) {
                        printf("HHHHHHHHHHHHHHHHHHHHHHHHH ok\n");
                        h = QuicStreamOpen(quic, false);
                        if (h < 0) {
                            goto out;
                        }

#if 0
                        if (QuicStreamSend(quic, h, appdata1, sizeof(appdata1) - 1) < 0) {
                            goto out;
                        }
#endif

                        continue;
                    }
                    err = QUIC_get_error(quic, ret);
                    if (err != QUIC_ERROR_WANT_READ) {
                        printf("err = %d, state = %d\n", err, quic->statem.state);
                        goto err;
                    }
next:
                    AddEpollEvent(epfd, &ev, sockfd);
                    continue;
                }

                if (efd == pipefd) {
                    fprintf(stdout, "Message from client!\n");
                    rlen = read(pipefd, buf, sizeof(buf));
                    if (rlen < 0) {
                        fprintf(stderr, "Server read form pipe failed!\n");
                        goto err;
                    }
                    wlen = write(pipefd, QUIC_TEST_CMD_OK, sizeof(QUIC_TEST_CMD_OK));
                    if (wlen < sizeof(QUIC_TEST_CMD_OK)) {
                        fprintf(stderr, "Server write to pipe failed!\n");
                        goto err;
                    }
                    if (strcmp(buf, QUIC_TEST_CMD_START) == 0) {
                        fprintf(stdout, "Server test start!\n");
                        AddEpollEvent(epfd, &ev, pipefd);
                        continue;
                    } else if (strcmp(buf, QUIC_TEST_CMD_END) == 0) {
                        fprintf(stdout, "Server test end!\n");
                        goto out;
                    }
                }
            }
        }
    }
 
out:
    ret = 1;
err:
    QuicFree(quic);
    QuicCtxFree(ctx);
    close(sockfd);
    if (efd >= 0) {
        close(efd);
    }
    close(pipefd);
    return ret;
}

int QuicHandshakeTest(void)
{
    pid_t pid = 0;
    int fd[2] = {};

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fd) < 0) {
        return -1;
    }

    if ((pid = fork()) < 0) {
        close(fd[0]);
        close(fd[1]);
        return -1;
    }

    if (pid > 0) {  /* Parent */
        close(fd[0]);
        return QuicTlsClient(fd[1]);
    }

    /* Child */
    close(fd[1]);
    return QuicTlsServer(fd[0]);
}
