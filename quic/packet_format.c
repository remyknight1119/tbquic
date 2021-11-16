/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "packet_format.h"

#include <string.h>
#include <assert.h>
#include <arpa/inet.h>

#include "common.h"
#include "mem.h"
#include "quic_local.h"
#include "evp.h"
#include "cipher.h"
#include "log.h"
#include "frame.h"
#include "tls.h"

static int QuicInitPacketPaser(QUIC *, RPacket *, QuicLPacketHeader *);
static int Quic0RttPacketPaser(QUIC *, RPacket *, QuicLPacketHeader *);
static int QuicHandshakePacketPaser(QUIC *, RPacket *, QuicLPacketHeader *);
static int QuicRetryPacketPaser(QUIC *, RPacket *, QuicLPacketHeader *);

static QuicLongPacketParse LPacketPaser[] = {
    {
        .min_version = QUIC_VERSION_1,
        .max_version = QUIC_VERSION_1,
        .type = QUIC_LPACKET_TYPE_INITIAL,
        .parser = QuicInitPacketPaser,
    },
    {
        .min_version = QUIC_VERSION_1,
        .max_version = QUIC_VERSION_1,
        .type = QUIC_LPACKET_TYPE_0RTT,
        .parser = Quic0RttPacketPaser,
    },
    {
        .min_version = QUIC_VERSION_1,
        .max_version = QUIC_VERSION_1,
        .type = QUIC_LPACKET_TYPE_HANDSHAKE,
        .parser = QuicHandshakePacketPaser,
    },
    {
        .min_version = QUIC_VERSION_1,
        .max_version = QUIC_VERSION_1,
        .type = QUIC_LPACKET_TYPE_RETRY,
        .parser = QuicRetryPacketPaser,
    },
};

#define LPACKET_PARSER_NUM     QUIC_ARRAY_SIZE(LPacketPaser) 

static int QuicLPacketHeaderParse(QUIC *quic, QuicLPacketHeader *h, RPacket *pkt)
{
    uint32_t version = 0;
    uint32_t len = 0;

    if (RPacketGet4(pkt, &version) < 0) {
        QUIC_LOG("Get version failed\n");
        return -1;
    }

    h->version = ntohl(version);

    if (RPacketGet1(pkt, &len) < 0) {
        QUIC_LOG("Get dest CID len failed\n");
        return -1;
    }

    if ((h->version == QUIC_VERSION_1 && len > QUIC_MAX_CID_LENGTH) ||
            len == 0) {
        QUIC_LOG("CID len is too long(%u)\n", len);
        return -1;
    }

    if (len < QUIC_MIN_CID_LENGTH) {
        QUIC_LOG("CID len is too short(%u)\n", len);
        return -1;
    }

    h->dest_conn_id_len = len;
    h->dest_conn_id = RPacketData(pkt);
    RPacketForward(pkt, h->dest_conn_id_len);

    if (RPacketGet1(pkt,  &len) < 0) {
        QUIC_LOG("Get source CID len failed\n");
        return -1;
    }

    h->source_conn_id_len = len;
    if (h->source_conn_id_len != 0) {
        h->source_conn_id = RPacketData(pkt);
        RPacketForward(pkt, h->source_conn_id_len);
    }

    return 0;
}

static int QuicLongPacketDoParse(QUIC *quic, RPacket *pkt, uint8_t flags)
{
    QuicLongPacketParse *p = NULL;
    QuicLPacketHeader h = {};
    uint32_t version = 0;
    uint8_t type = 0;
    int i = 0;

    if (QuicLPacketHeaderParse(quic, &h, pkt) < 0) {
        QUIC_LOG("Long Packet Header Parse failed\n");
        return -1;
    }

    version = h.version;
    h.flags.value = flags;
    type = h.flags.lpacket_type;
    for (i = 0; i < LPACKET_PARSER_NUM; i++) {
        p = &LPacketPaser[i];
        if (p->type == type && p->min_version <= version &&
                version <= p->max_version) {
            return p->parser(quic, pkt, &h);
        }
    }

    QUIC_LOG("No parser found\n");
    return -1;
}

static int QuicShortPacketDoParse(QUIC *quic, RPacket *pkt, uint8_t flags)
{
    return -1;
}

int QuicPacketParse(QUIC *quic, RPacket *pkt, uint8_t flags)
{
    QuicPacketFlags pflags;

    pflags.value = flags;
    if (QUIC_PACKET_IS_LONG_PACKET(pflags)) {
        return QuicLongPacketDoParse(quic, pkt, flags);
    }

    return QuicShortPacketDoParse(quic, pkt, flags);
}

static int QuicVariableLengthValueEncode(uint8_t *buf, size_t blen,
        uint64_t length, uint8_t prefix)
{
    QuicVarLenFirstByte *var = NULL;
    uint8_t len = 0;
    uint8_t shift = 0;
    int i = 0;

    len = (1 << prefix);
    if (len > blen) {
        return -1;
    }
    var = (void *)buf;
    var->prefix = prefix;
    shift = (len - 1) * 8;
    var->value = (length >> shift) & 0x3F;
    for (i = 1; i < len; i++) {
        shift = (len - i - 1)*8;
        buf[i] = (length >> shift) & 0xFF;
    }

    return 0;
}

int QuicVariableLengthEncode(uint8_t *buf, size_t blen, uint64_t length)
{
    uint8_t prefix = 0;

    if ((length >> 62) > 0) {
        return -1;
    }

    for (prefix = 3; prefix > 0; prefix--) {
        if ((length >> ((1 << (prefix - 1))*8 - 2)) > 0) {
            break;
        }
    }

    return QuicVariableLengthValueEncode(buf, blen, length, prefix);
}

int QuicVariableLengthDecode(RPacket *pkt, uint64_t *length)
{
    QuicVarLenFirstByte var = {};
    uint8_t prefix = 0;
    uint8_t len = 0;
    uint32_t v = 0;
    int i = 0;

    if (RPacketGet1(pkt,  &v) < 0) {
        return -1;
    }

    var.var = v;
    prefix = var.prefix;
    len = 1 << prefix;

    *length = var.value;

    for (i = 1; i < len; i++) {
        if (RPacketGet1(pkt,  &v) < 0) {
            return -1;
        }
        *length = (*length << 8) + v;
    }

    return 0;
}

/*
 * RFC 9000
 * A.3.  Sample Packet Number Decoding Algorithm
 * @largest_pn is the largest packet number that has been successfully
 *     processed in the current packet number space.
 * @truncated_pn is the value of the Packet Number field.
 * @pn_nbits is the number of bits in the Packet Number field (8, 16,
      24, or 32).
 */

//(1 << 62)
#define LEFT_SHIFT_62 0x4000000000000000

uint64_t QuicPktNumberDecode(uint64_t largest_pn, uint32_t truncated_pn,
                                uint8_t pn_nbits)
{
    uint64_t expected_pn = largest_pn + 1;
    uint64_t pn_win = 1 << pn_nbits;
    uint64_t pn_hwin = pn_win / 2;
    uint64_t pn_mask = pn_win - 1;
    // The incoming packet number should be greater than
    // expected_pn - pn_hwin and less than or equal to
    // expected_pn + pn_hwin
    //
    // This means we cannot just strip the trailing bits from
    // expected_pn and add the truncated_pn because that might
    // yield a value outside the window.
    //
    // The following code calculates a candidate value and
    // makes sure it's within the packet number window.
    // Note the extra checks to prevent overflow and underflow.
    uint64_t candidate_pn = (expected_pn & ~pn_mask) | truncated_pn;

    if (candidate_pn <= expected_pn - pn_hwin &&
            candidate_pn < (LEFT_SHIFT_62 - pn_win)) {
         return candidate_pn + pn_win;
    }

    if (candidate_pn > expected_pn + pn_hwin && candidate_pn >= pn_win) {
        return candidate_pn - pn_win;
    }

    return candidate_pn;
}

static int QuicHPDoCipher(QuicHPCipher *cipher, uint8_t *out, size_t *outl,
                        const uint8_t *in, size_t inl)
{
    return QuicDoCipher(&cipher->cipher, out, outl, in, inl);
}

int QuicDecryptHeader(QuicHPCipher *hp_cipher, uint8_t flags, uint32_t *pkt_num,
                            uint8_t *p_num_len, uint8_t *first_byte,
                            RPacket *pkt, uint8_t bits_mask)
{
    const uint8_t *pkt_num_start = NULL;
    uint8_t sample[QUIC_SAMPLE_LEN] = {};
    uint8_t mask[QUIC_SAMPLE_LEN*2] = {};
    uint8_t pkn_bytes[QUIC_MACKET_NUM_MAX_LEN] = {};
    uint8_t packet0 = 0;
    uint8_t pkt_num_len = 0;
    size_t sample_len = sizeof(sample);
    size_t mask_len = 0;
    int i = 0;

    if (hp_cipher->cipher.ctx == NULL) {
        return -1;
    }

    if (RPacketRemaining(pkt) < QUIC_MACKET_NUM_MAX_LEN + sample_len) {
        return -1;
    }

    pkt_num_start = RPacketData(pkt);
    memcpy(sample, pkt_num_start + QUIC_MACKET_NUM_MAX_LEN, sample_len);

    if (QuicHPDoCipher(hp_cipher, mask, &mask_len, sample, sample_len) < 0) {
        return -1;
    }

    packet0 = flags ^ (mask[0] & bits_mask);
    pkt_num_len = (packet0 & 0x3) + 1;
    if (first_byte != NULL) {
        *first_byte = packet0;
    }

    if (RPacketCopyBytes(pkt, pkn_bytes, pkt_num_len) < 0) {
        return -1;
    }

    for (i = 0; i < pkt_num_len; i++) {
        *pkt_num |= (pkn_bytes[i] ^ mask[i + 1]) << (8 * (pkt_num_len - i - 1));
    }

    *p_num_len = pkt_num_len;
    return 0;
}

int QuicDecryptInitPacketHeader(QuicHPCipher *hp_cipher, uint8_t flags,
                                uint32_t *pkt_num, uint8_t *pkt_num_len,
                                uint8_t *first_byte, RPacket *pkt)
{
    return QuicDecryptHeader(hp_cipher, flags, pkt_num, pkt_num_len,
                                first_byte, pkt, 0x0F);
}

static int QuicPktNumberWrite(uint32_t pkt_num, uint8_t *buf, uint8_t len)
{
    int i = 0;

    if (len > sizeof(pkt_num)) {
        return -1;
    }

    for (i = 0; i < len; i++) {
        buf[len - 1 - i] = (pkt_num >> (8 * i)) & 0xFF;
    }

    return 0;
}

static int QuicDecryptMessage(QuicPPCipher *cipher, uint8_t *out, size_t *outl,
                                uint8_t first_byte, uint64_t pkt_num,
                                uint8_t pkt_num_len, const RPacket *pkt)
{
    QUIC_CIPHER *c = NULL;
    uint8_t *head = NULL;
    const uint8_t *data = NULL;
    uint8_t nonce[TLS13_AEAD_NONCE_LENGTH] = {};
    size_t data_len = 0;
    int tag_len = 0;
    int offset = 0;
    int i = 0;

    data_len = RPacketRemaining(pkt);
    offset = RPacketTotalLen(pkt) - data_len;
    assert(offset > 0);

    head = QuicMemDup(RPacketHead(pkt), offset);
    if (head == NULL) {
        QUIC_LOG("Memory Duplicate failed\n");
        return -1;
    }

    head[0] = first_byte;
    QuicPktNumberWrite(pkt_num, head + offset - pkt_num_len, pkt_num_len);
    c = &cipher->cipher;
    memcpy(nonce, cipher->iv, sizeof(nonce));
    for (i = 0; i < 8; i++) {
        nonce[sizeof(nonce) - 1 - i] ^= (pkt_num >> 8 * i) & 0xFF;
    }

    if (QuicEvpCipherInit(c->ctx, NULL, NULL, nonce, c->enc) < 0) {
        QUIC_LOG("Cipher Init failed\n");
        return -1;
    }

    tag_len = QuicCipherGetTagLen(c->cipher_alg);
    if (tag_len < 0) {
        QUIC_LOG("Get tag len failed\n");
        return -1;
    }

    if (data_len < tag_len) {
        QUIC_LOG("Data len too small\n");
        return -1;
    }

    data = RPacketData(pkt);
    if (tag_len > 0) {
        if (QUIC_EVP_CIPHER_gcm_set_tag(c->ctx, tag_len,
                        (void *)&data[data_len - tag_len]) < 0) {
            QUIC_LOG("Set GCM tag failed\n");
            return -1;
        }
    }

    if (QUIC_EVP_CIPHER_set_iv_len(c->ctx, sizeof(nonce)) < 0) {
        QUIC_LOG("Set IV len failed\n");
        return -1;
    }

    if (QuicEvpCipherUpdate(c->ctx, NULL, outl, head, offset) < 0) {
        QUIC_LOG("Cipher Update failed\n");
        return -1;
    }

    return QuicDoCipher(&cipher->cipher, out, outl, data, data_len - tag_len);
}

static int QuicInitPacketPaser(QUIC *quic, RPacket *pkt, QuicLPacketHeader *h)
{
    QuicCipherSpace *initial = NULL;
    QUIC_CIPHERS *cipher = NULL;
    QUIC_BUFFER *buffer = NULL;
    QUIC_BUFFER *crypto_buf = &quic->wbuffer;
    RPacket frame = {};
    uint64_t token_len = 0;
    uint64_t length = 0;
    uint64_t pkt_num = 0;
    uint8_t first_byte = 0;
    int ret = 0;

    if (quic->cid.data == NULL) {
        quic->cid.data = QuicMemMalloc(h->dest_conn_id_len);
        if (quic->cid.data == NULL) {
            QUIC_LOG("Peer CID malloc failed!\n");
            return -1;
        }
        quic->cid.len = h->dest_conn_id_len;
        memcpy(quic->cid.data, h->dest_conn_id, quic->cid.len);
    } else if (quic->cid.len != h->dest_conn_id_len ||
            memcmp(quic->cid.data, h->dest_conn_id, quic->cid.len) != 0) {
        QUIC_LOG("DCID not match!\n");
        return -1;
    }
 
    if (QuicVariableLengthDecode(pkt, &token_len) < 0) {
        QUIC_LOG("Token len decode failed!\n");
        return -1;
    }

    if (token_len != 0) {
        //token = RPacketData(pkt);
        RPacketForward(pkt, token_len);
    }

    if (QuicVariableLengthDecode(pkt, &length) < 0) {
        QUIC_LOG("Length decode failed!\n");
        return -1;
    }

    if (length != RPacketRemaining(pkt)) {
        QUIC_LOG("length(%lu) not match remaining(%lu)!\n",
                length, RPacketRemaining(pkt));
        return -1;
    }

    if (QuicCreateInitialDecoders(quic, h->version) < 0) {
        QUIC_LOG("Create Initial Decoders failed!\n");
        return -1;
    }

    initial = QUIC_IS_SERVER(quic) ?
        &quic->initial.client : &quic->initial.server;
    cipher = &initial->ciphers;
    if (QuicDecryptInitPacketHeader(&cipher->hp_cipher, h->flags.value,
                &h->pkt_num, &h->pkt_num_len, &first_byte, pkt) < 0) {
        QUIC_LOG("Decrypt Initial packet header failed!\n");
        return -1;
    }

    pkt_num = QuicPktNumberDecode(initial->pkt_num, h->pkt_num,
                                h->pkt_num_len*8);
    if ((int)(initial->pkt_num - pkt_num) > 0) {
        QUIC_LOG("PKT number invalid!\n");
        return -1;
    }

    if (initial->pkt_num == pkt_num && pkt_num != 0) {
        QUIC_LOG("PKT number invalid!\n");
        return -1;
    }

    initial->pkt_num = pkt_num;

    buffer = &quic->plain_buffer;
    if (QuicDecryptMessage(&cipher->pp_cipher, (uint8_t *)buffer->buf->data,
                &buffer->data_len, first_byte, h->pkt_num, h->pkt_num_len,
                pkt) < 0) {
        return -1;
    }

    RPacketBufInit(&frame, (uint8_t *)buffer->buf->data, buffer->data_len);
    if (QuicFrameDoParser(quic, &frame) < 0) {
        return -1;
    }

    if (crypto_buf->data_len == 0) {
        return -1;
    }

    QuicPrint(QuicBufData(crypto_buf), crypto_buf->data_len);

    ret = QuicTlsDoHandshake(&quic->tls, QuicBufData(crypto_buf),
            crypto_buf->data_len);
    if (ret < 0) {
        QUIC_LOG("SSL handshake failed!\n");
        return -1;
    }

    printf("IIIint, f = %x, pkt_num = %u, ipkt = %lu\n", h->flags.value, h->pkt_num, initial->pkt_num);
    return 0;
}

static int Quic0RttPacketPaser(QUIC *quic, RPacket *pkt, QuicLPacketHeader *h)
{
    return 0;
}

static int QuicHandshakePacketPaser(QUIC *quic, RPacket *pkt, QuicLPacketHeader *h)
{
    return 0;
}

static int QuicRetryPacketPaser(QUIC *quic, RPacket *pkt, QuicLPacketHeader *h)
{
    return 0;
}

