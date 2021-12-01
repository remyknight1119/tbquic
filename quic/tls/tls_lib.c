/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "tls_lib.h"

#include <openssl/obj_mac.h>

#include "tls.h"
#include "ec.h"
#include "base.h"
#include "common.h"
#include "mem.h"

/* The default curves */
static const uint16_t eccurves_default[] = {
    EC_NAMED_CURVE_X25519,
    EC_NAMED_CURVE_SECP256R1,
    EC_NAMED_CURVE_X448,
    EC_NAMED_CURVE_SECP521R1,
    EC_NAMED_CURVE_SECP384R1,
};

static const TlsGroupInfo group_nid_list[] = {
    [EC_NAMED_CURVE_SECT163K1] = {
        .nid = NID_sect163k1,
        .secbits = 80,
    },
    [EC_NAMED_CURVE_SECT163R1] = {
        .nid = NID_sect163r1,
        .secbits = 80,
    },
    [EC_NAMED_CURVE_SECT163R2] = {
        .nid = NID_sect163r2,
        .secbits = 80,
    },
    [EC_NAMED_CURVE_SECT193R1] = {
        .nid = NID_sect193r1,
        .secbits = 80,
    },
    [EC_NAMED_CURVE_SECT193R2] = {
        .nid = NID_sect193r2,
        .secbits = 80,
    },
    [EC_NAMED_CURVE_SECT233K1] = {
        .nid = NID_sect233k1,
        .secbits = 112,
    },
    [EC_NAMED_CURVE_SECT233R1] = {
        .nid = NID_sect233r1,
        .secbits = 112,
    },
    [EC_NAMED_CURVE_SECT239K1] = {
        .nid = NID_sect239k1,
        .secbits = 112,
    },
    [EC_NAMED_CURVE_SECT283K1] = {
        .nid = NID_sect283k1,
        .secbits = 128,
    },
    [EC_NAMED_CURVE_SECT283R1] = {
        .nid = NID_sect283r1,
        .secbits = 128,
    },
    [EC_NAMED_CURVE_SECT409K1] = {
        .nid = NID_sect409k1,
        .secbits = 192,
    },
    [EC_NAMED_CURVE_SECT409R1] = {
        .nid = NID_sect409r1,
        .secbits = 192,
    },
    [EC_NAMED_CURVE_SECT571K1] = {
        .nid = NID_sect571k1,
        .secbits = 256,
    },
    [EC_NAMED_CURVE_SECT571R1] = {
        .nid = NID_sect571r1,
        .secbits = 256,
    },
    [EC_NAMED_CURVE_SECP160K1] = {
        .nid = NID_secp160k1,
        .secbits = 80,
    },
    [EC_NAMED_CURVE_SECP160R1] = {
        .nid = NID_secp160r1,
        .secbits = 80,
    },
    [EC_NAMED_CURVE_SECP160R2] = {
        .nid = NID_secp160r2,
        .secbits = 80,
    },
    [EC_NAMED_CURVE_SECP192K1] = {
        .nid = NID_secp192k1,
        .secbits = 80,
    },
    [EC_NAMED_CURVE_SECP192R1] = {
        .nid = NID_X9_62_prime192v1,
        .secbits = 80,
    },
    [EC_NAMED_CURVE_SECP224K1] = {
        .nid = NID_secp224k1,
        .secbits = 112,
    },
    [EC_NAMED_CURVE_SECP224R1] = {
        .nid = NID_secp224r1,
        .secbits = 112,
    },
    [EC_NAMED_CURVE_SECP256K1] = {
        .nid = NID_secp256k1,
        .secbits = 128,
    },
    [EC_NAMED_CURVE_SECP256R1] = {
        .nid = NID_X9_62_prime256v1,
        .secbits = 128,
    },
    [EC_NAMED_CURVE_SECP384R1] = {
        .nid = NID_secp384r1,
        .secbits = 192,
    },
    [EC_NAMED_CURVE_SECP521R1] = {
        .nid = NID_secp521r1,
        .secbits = 256,
    },
    [EC_NAMED_CURVE_BRAINPOOLP256R1] = {
        .nid = NID_brainpoolP256r1,
        .secbits = 128,
    },
    [EC_NAMED_CURVE_BRAINPOOLP384R1] = {
        .nid = NID_brainpoolP384r1,
        .secbits = 192,
    },
    [EC_NAMED_CURVE_BRAINPOOL512R1] = {
        .nid = NID_brainpoolP512r1,
        .secbits = 256,
    },
    [EC_NAMED_CURVE_X25519] = {
        .nid = NID_X25519,
        .secbits = 128,
    },
    [EC_NAMED_CURVE_X448] = {
        .nid = NID_X448,
        .secbits = 224,
    },
};

/*
 * Set *pgroups to the supported groups list and *pgroupslen to
 * the number of groups supported.
 */
void TlsGetSupportedGroups(QUIC_TLS *tls, const uint16_t **pgroups,
                               size_t *pgroupslen)
{
    if (tls->ext.supported_groups == NULL) {
        *pgroups = eccurves_default;
        *pgroupslen = QUIC_NELEM(eccurves_default);
    } else {
        *pgroups = tls->ext.supported_groups;
        *pgroupslen = tls->ext.supported_groups_len;
    }
}

int TlsSetSupportedGroups(uint16_t **pext, size_t *pextlen, int *groups,
                            size_t ngroups)
{
    uint16_t *glist = NULL;
    size_t i = 0;

    if (ngroups == 0) {
        return -1;
    }

    if ((glist = QuicMemMalloc(ngroups * sizeof(*glist))) == NULL) {
        return -1;
    }

    for (i = 0; i < QUIC_NELEM(group_nid_list); i++) {
    }

    QuicMemFree(*pext);
    *pext = glist;
    *pextlen = ngroups;
    return 0;
}

