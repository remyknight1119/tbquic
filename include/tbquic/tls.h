#ifndef TBQUIC_INCLUDE_TBQUIC_TLS_H_
#define TBQUIC_INCLUDE_TBQUIC_TLS_H_

#include <tbquic/types.h>
#include <tbquic/ec.h>

#define TLSEXT_MAXLEN_HOST_NAME     255

/* NameType value from RFC 6066 */
#define TLSEXT_NAMETYPE_HOST_NAME   0

#define TLS_SUPPORTED_GROUPS_SECP256R1     EC_NAMED_CURVE_SECP256R1
#define TLS_SUPPORTED_GROUPS_SECP384R1     EC_NAMED_CURVE_SECP384R1
#define TLS_SUPPORTED_GROUPS_SECP521R1     EC_NAMED_CURVE_SECP521R1
#define TLS_SUPPORTED_GROUPS_X25519        EC_NAMED_CURVE_X25519
#define TLS_SUPPORTED_GROUPS_X448          EC_NAMED_CURVE_X448
#define TLS_SUPPORTED_GROUPS_FFDHE2048     0x0100
#define TLS_SUPPORTED_GROUPS_FFDHE3072     0x0101
#define TLS_SUPPORTED_GROUPS_FFDHE4096     0x0102
#define TLS_SUPPORTED_GROUPS_FFDHE6144     0x0103
#define TLS_SUPPORTED_GROUPS_FFDHE8192     0x0104

/* Sigalgs values */
#define TLSEXT_SIGALG_ECDSA_SECP256R1_SHA256                    0x0403
#define TLSEXT_SIGALG_ECDSA_SECP384R1_SHA384                    0x0503
#define TLSEXT_SIGALG_ECDSA_SECP521R1_SHA512                    0x0603
#define TLSEXT_SIGALG_ECDSA_SHA224                              0x0303
#define TLSEXT_SIGALG_ECDSA_SHA1                                0x0203
#define TLSEXT_SIGALG_RSA_PSS_RSAE_SHA256                       0x0804
#define TLSEXT_SIGALG_RSA_PSS_RSAE_SHA384                       0x0805
#define TLSEXT_SIGALG_RSA_PSS_RSAE_SHA512                       0x0806
#define TLSEXT_SIGALG_RSA_PSS_PSS_SHA256                        0x0809
#define TLSEXT_SIGALG_RSA_PSS_PSS_SHA384                        0x080a
#define TLSEXT_SIGALG_RSA_PSS_PSS_SHA512                        0x080b
#define TLSEXT_SIGALG_RSA_PKCS1_SHA256                          0x0401
#define TLSEXT_SIGALG_RSA_PKCS1_SHA384                          0x0501
#define TLSEXT_SIGALG_RSA_PKCS1_SHA512                          0x0601
#define TLSEXT_SIGALG_RSA_PKCS1_SHA224                          0x0301
#define TLSEXT_SIGALG_RSA_PKCS1_SHA1                            0x0201

#endif