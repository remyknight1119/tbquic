/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "tls_lib.h"

#include <openssl/obj_mac.h>
#include <tbquic/ec.h>
#include <tbquic/quic.h>

#include "tls.h"
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

static const uint16_t ffdh_group[] = {
    QUIC_SUPPORTED_GROUPS_FFDHE2048,
    QUIC_SUPPORTED_GROUPS_FFDHE3072,
    QUIC_SUPPORTED_GROUPS_FFDHE4096,
    QUIC_SUPPORTED_GROUPS_FFDHE6144,
    QUIC_SUPPORTED_GROUPS_FFDHE8192,
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

int TlsCheckFfdhGroup(uint16_t id)
{
    size_t i = 0;

    for (i = 0; i < QUIC_NELEM(ffdh_group); i++) {
        if (id == ffdh_group[i]) {
            return 0;
        }
    }

    return -1;
}

/*
 * Set *pgroups to the supported groups list and *pgroupslen to
 * the number of groups supported.
 */
void TlsGetSupportedGroups(QUIC_TLS *tls, const uint16_t **pgroups,
                               size_t *pgroupslen)
{
    if (QuicDataIsEmpty(&tls->ext.supported_groups)) {
        *pgroups = eccurves_default;
        *pgroupslen = QUIC_NELEM(eccurves_default);
    } else {
        QuicDataGetU16(&tls->ext.supported_groups, pgroups, pgroupslen);
    }
}

int TlsSetSupportedGroups(uint16_t **pext, size_t *pextlen, uint16_t *groups,
                            size_t ngroups)
{
    const TlsGroupInfo *g_info = NULL;
    uint16_t *glist = NULL;
    uint16_t id = 0;
    size_t i = 0;

    if (ngroups == 0) {
        return -1;
    }

    for (i = 0; i < ngroups; i++) {
        id = groups[i];
        if (id >= QUIC_NELEM(group_nid_list)) {
            if (TlsCheckFfdhGroup(id) < 0) {
                return -1;
            }
        }

        g_info = &group_nid_list[id];
        if (g_info->secbits == 0) {
            return -1;
        }
    }

    glist = QuicMemDup(groups, ngroups * sizeof(*groups));
    if (glist == NULL) {
        return -1;
    }

    QuicMemFree(*pext);
    *pext = glist;
    *pextlen = ngroups;
    return 0;
}

