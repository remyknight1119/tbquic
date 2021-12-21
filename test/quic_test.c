/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "quic_test.h"

#include <tbquic/quic.h>

#include <stdio.h>
#include <getopt.h>
#include <arpa/inet.h>

#include "format.h"
#include "packet_local.h"
#include "common.h"

typedef struct FuncTest {
    int (*test)(void);
    char *err_msg;
} QuicFuncTest;

char *quic_cert;
char *quic_key;

static QuicFuncTest test_funcs[] = {
    {
        .test = QuicVariableLengthDecodeTest,
        .err_msg = "Varibale Length Decode",
    },
    {
        .test = QuicHkdfExtractExpandTest,
        .err_msg = "HKDF Extract and Expand",
    },
    {
        .test = QuicHkdfExpandLabel,
        .err_msg = "HKDF Expand Label",
    },
    {
        .test = QuicPktFormatTestClient,
        .err_msg = "Packet Format Client",
    },
    {
        .test = QuicPktFormatTestServer,
        .err_msg = "Packet Format Server",
    },
    {
        .test = QuicPktNumberDecodeTest,
        .err_msg = "PKT Number Decode",
    },
    {
        .test = QuicPktNumberEncodeTest,
        .err_msg = "PKT Number Encode",
    },
    {
        .test = QuicVTlsCipherListTest,
        .err_msg = "TLS Cipher List",
    },
    {
        .test = QuicTlsClientHelloTest,
        .err_msg = "TLS ClientHello",
    },
    {
        .test = QuicTlsClientExtensionTest,
        .err_msg = "TLS Client Extension",
    },
    {
        .test = QuicTlsGenerateSecretTest,
        .err_msg = "TLS GenerateSecret",
    },
    {
        .test = QuicTlsGenerateServerSecretTest,
        .err_msg = "TLS Generate Server Secret",
    },
};

#define QUIC_FUNC_TEST_NUM QUIC_NELEM(test_funcs)

static uint8_t QuicBitsOrderTrans(uint8_t value)
{
    uint8_t v = 0;
    int i = 0;

    for (i = 0; i < 8; i++) {
        v |= (((value >> i) & 0x1) << (7 - i));
    }

    return v;
}

uint16_t QuicShortOrderTrans(uint16_t value)
{
    uint16_t v = 0;
    uint8_t b = 0;

    b = value | 0xFF;
    v = QuicBitsOrderTrans(b) << 8;
    b = value >> 8;
    v |= QuicBitsOrderTrans(b);

    return v;
}

uint32_t QuicUintOrderTrans(uint32_t value)
{
    uint32_t v = 0;
    uint8_t b = 0;
    int i = 0;

    for (i = 0; i < 4; i++) {
        b = (value >> (i * 8)) | 0xFF;
        v |= QuicBitsOrderTrans(b) << ((3 - i) * 8);
    }

    return v;
}

static const char *program_version = "1.0.0";//PACKAGE_STRING;

static const struct option long_opts[] = {
    {"help", 0, 0, 'H'},
    {"certificate", 0, 0, 'c'},
    {"key", 0, 0, 'k'},
    {0, 0, 0, 0}
};

static const char *options[] = {
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


int main(int argc, char **argv)
{
    int passed = 0;
    int ok_num = 0;
    int i = 0;
    int c = 0;
    int ret = 0;

    while ((c = getopt_long(argc, argv, optstring, long_opts, NULL)) != -1) {
        switch (c) {
            case 'H':
                help();
                return 0;
            case 'c':
                quic_cert = optarg;
                break;
            case 'k':
                quic_key = optarg;
                break;

            default:
                help();
                return -1;
        }
    }

    if (quic_cert == NULL) {
        fprintf(stderr, "please input certificate file by -c\n");
        return -1;
    }

    if (quic_key == NULL) {
        fprintf(stderr, "please input key file by -k\n");
        return -1;
    }

    QuicInit();

    for (i = 0; i < QUIC_FUNC_TEST_NUM; i++) {
        fprintf(stdout, "Testing %s...", test_funcs[i].err_msg);
        ret = test_funcs[i].test();
        if (ret < 0) {
            fprintf(stdout, "failed\n");
        } else {
            passed++;
            ok_num += ret;
            fprintf(stdout, "OK\n");
        }
    }

    fprintf(stdout, "%d/%lu Function test passed! Total passed case number"
            " is %d\n", passed, QUIC_FUNC_TEST_NUM, ok_num);
    if (passed == QUIC_FUNC_TEST_NUM) {
        fprintf(stdout, "Success!\n");
    } else {
        fprintf(stdout, "Failed!\n");
    }

    return 0;
}

