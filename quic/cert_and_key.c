/*
 * Remy Lewis(remyknight1119@gmail.com)
 */
#include <tbquic/quic.h>

#include <openssl/x509.h>
#include <openssl/pem.h>
#include <tbquic/cipher.h>

#include "quic_local.h"
#include "cert.h"
#include "log.h"

static const int kFileType[QUIC_FILE_TYPE_MAX] = {
    [QUIC_FILE_TYPE_ASN1] = X509_FILETYPE_ASN1,
    [QUIC_FILE_TYPE_PEM] = X509_FILETYPE_PEM,
};

static int QuicFindFileType(uint32_t type)
{
    if (type >= QUIC_FILE_TYPE_MAX) {
        return -1;
    }

    return kFileType[type];
}

int QuicCtxUsePrivateKey(QUIC_CTX *ctx, EVP_PKEY *pkey)
{
    if (pkey == NULL) {
        return -1;
    }

    return QuicSetPkey(ctx->cert, pkey);
}

int QuicCtxUsePrivateKeyFile(QUIC_CTX *ctx, const char *file, uint32_t type)
{
    EVP_PKEY *pkey = NULL;
    BIO *in = NULL;
    int ret = -1;
    int file_type = 0;

    file_type = QuicFindFileType(type);
    if (file_type < 0) {
        return -1;
    }

    in = BIO_new(BIO_s_file());
    if (in == NULL) {
        goto end;
    }

    if (BIO_read_filename(in, file) <= 0) {
        goto end;
    }

    if (file_type == X509_FILETYPE_PEM) {
        pkey = PEM_read_bio_PrivateKey(in, NULL, NULL, NULL);
    } else if (file_type == X509_FILETYPE_ASN1) {
        pkey = d2i_PrivateKey_bio(in, NULL);
    } else {
        goto end;
    }

    if (pkey == NULL) {
        goto end;
    }

    ret = QuicCtxUsePrivateKey(ctx, pkey);
    EVP_PKEY_free(pkey);
 end:
    BIO_free(in);
    return ret;
}

int QuicCtxUseCertificate(QUIC_CTX *ctx, X509 *x)
{
    if (x == NULL) {
        return -1;
    }

    return QuicSetCert(ctx->cert, x);
}

int QuicCtxUseCertificateFile(QUIC_CTX *ctx, const char *file, uint32_t type)
{
    X509 *x = NULL;
    BIO *in = NULL;
    int ret = -1;
    int file_type = 0;

    file_type = QuicFindFileType(type);
    if (file_type < 0) {
        return -1;
    }

    in = BIO_new(BIO_s_file());
    if (in == NULL) {
        goto end;
    }

    if (BIO_read_filename(in, file) <= 0) {
        goto end;
    }

    if (file_type == X509_FILETYPE_PEM) {
        x = PEM_read_bio_X509(in, NULL, NULL, NULL);
    } else if (file_type == X509_FILETYPE_ASN1) {
        x = d2i_X509_bio(in, NULL);
    } else {
        goto end;
    }

    if (x == NULL) {
        goto end;
    }

    ret = QuicCtxUseCertificate(ctx, x);

 end:
    X509_free(x);
    BIO_free(in);
    return ret;
}

