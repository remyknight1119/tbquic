/*
 * Remy Lewis(remyknight1119@gmail.com)
 */
#include "quic_local.h"

#include <openssl/x509.h>
#include <openssl/ssl.h>
#include <tbquic/quic.h>
#include <tbquic/cipher.h>

#include "log.h"

static const int FileType[QUIC_FILE_TYPE_MAX] = {
    [QUIC_FILE_TYPE_ASN1] = X509_FILETYPE_ASN1,
    [QUIC_FILE_TYPE_PEM] = X509_FILETYPE_PEM,
};

static int QuicFindFileType(uint32_t type)
{
    if (type >= QUIC_FILE_TYPE_MAX) {
        return -1;
    }

    return FileType[type];
}

int QuicCtxUsePrivateKeyFile(QUIC_CTX *ctx, const char *file, uint32_t type)
{
    int file_type = 0;

    file_type = QuicFindFileType(type);
    if (file_type < 0) {
        return -1;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx->tls_ctx, file, file_type) == 0) {
        return -1;
    }

    return 0;
}

int QuicCtxUseCertificate_File(QUIC_CTX *ctx, const char *file, uint32_t type)
{
    int file_type = 0;

    file_type = QuicFindFileType(type);
    if (file_type < 0) {
        return -1;
    }

    if (SSL_CTX_use_certificate_file(ctx->tls_ctx, file, file_type) < 0) {
        return -1;
    }

    return 0;
}


