#ifndef TBQUIC_QUIC_TLS_TLS_LIB_H_
#define TBQUIC_QUIC_TLS_TLS_LIB_H_

#include "tls.h"
#include "session.h"

#include <openssl/evp.h>

#define TLS_FINISH_MAC_LENGTH               12
#define TLS_MD_MAX_CONST_SIZE               22
#define TLS_MD_CLIENT_FINISH_LABEL_LEN      15
#define TLS_MD_SERVER_FINISH_LABEL_LEN      15

typedef struct {
    int nid;                /* Curve NID */
    uint32_t secbits;       /* Bits of security (from SP800-57) */
    /* flags type */
# define TLS_CURVE_PRIME         0x0
# define TLS_CURVE_CHAR2         0x1
# define TLS_CURVE_CUSTOM        0x2
# define TLS_CURVE_TYPE          0x3 /* Mask for group type */
    uint32_t flags;
} TlsGroupInfo;

extern const char tls_md_client_finish_label[];
extern const char tls_md_server_finish_label[];
#ifdef QUIC_TEST
extern void (*QuicHandshakeSecretHook)(uint8_t *);
extern void (*QuicTlsFinalFinishMacHashHook)(uint8_t *, size_t);
#endif
void TlsGetPeerGroups(TLS *s, const uint16_t **, size_t *);
void TlsGetSupportedGroups(TLS *, const uint16_t **, size_t *);
int TlsSetSupportedGroups(uint16_t **, size_t *, uint16_t *, size_t);
int TlsCheckFfdhGroup(uint16_t);
int TlsCheckInList(TLS *, uint16_t, const uint16_t *, size_t);
const EVP_MD *TlsHandshakeMd(TLS *);
EVP_PKEY *TlsGeneratePkey(EVP_PKEY *);
EVP_PKEY *TlsGeneratePkeyGroup(TLS *, uint16_t);
EVP_PKEY *TlsGenerateParamGroup(uint16_t);
int TlsDigestCachedRecords(TLS *);
int TlsFinishMac(TLS *, const uint8_t *, size_t);
int TlsHandshakeHash(TLS *, uint8_t *, size_t, size_t *);
int TlsDeriveSecrets(TLS *, const EVP_MD *, const uint8_t *, const uint8_t *,
                        size_t, const uint8_t *, uint8_t *);
int TlsDeriveFinishedKey(TLS *, const EVP_MD *, const uint8_t *, uint8_t *,
                        size_t);
int TlsGenerateSecret(const EVP_MD *, const uint8_t *, const uint8_t *, size_t,
                        uint8_t *);
int TlsKeyDerive(TLS *, EVP_PKEY *, EVP_PKEY *);
int TlsGenerateMasterSecret(TLS *, uint8_t *, uint8_t *, size_t *);
int TlsCheckPeerSigAlg(TLS *, uint16_t, EVP_PKEY *);
int TlsSetServerSigAlgs(TLS *);
int TlsChooseSigalg(TLS *);
const EVP_MD *TlsLookupMd(const SigAlgLookup *);
int TlsDoCertVerify(TLS *, const uint8_t *, size_t, EVP_PKEY *, const EVP_MD *);
size_t TlsFinalFinishMac(TLS *, const char *, size_t, uint8_t *);
int TlsTakeMac(TLS *);
QUIC_SESSION *TlsGetSession(TLS *s);
int TlsPskDoBinder(TLS *, const EVP_MD *, uint8_t *, size_t, uint8_t *,
                        QuicSessionTicket *);

#endif
