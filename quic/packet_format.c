/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "packet_format.h"

#include <string.h>
#include <math.h>
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

static int QuicVersionSelect(QUIC *quic, uint32_t version)
{
    return -1;
}

static int QuicCidParse(QUIC_DATA *cid, const uint8_t *data, size_t len)
{
    if (len == 0) {
        return 0;
    }

    if (cid->data == NULL) {
        cid->data = QuicMemMalloc(len);
        if (cid->data == NULL) {
            QUIC_LOG("CID malloc failed!\n");
            return -1;
        }
        memcpy(cid->data, data, len);
        cid->len = len;
    } else if (cid->len != len || memcmp(cid->data, data, len) != 0) {
        QUIC_LOG("CID not match!\n");
        return -1;
    }
 
    return 0;
}

static int QuicLPacketHeaderParse(QUIC *quic, QuicLPacketHeader *h, RPacket *pkt)
{
    uint32_t version = 0;
    uint32_t len = 0;

    if (RPacketGet4(pkt, &version) < 0) {
        QUIC_LOG("Get version failed\n");
        return -1;
    }

    if (RPacketGet1(pkt, &len) < 0) {
        QUIC_LOG("Get dest CID len failed\n");
        return -1;
    }

    if (version != quic->version && QuicVersionSelect(quic, version) < 0) {
        QUIC_LOG("Version invalid\n");
        return -1;
    }

    if ((version == QUIC_VERSION_1 && len > QUIC_MAX_CID_LENGTH) || len == 0) {
        QUIC_LOG("CID len is too long(%u)\n", len);
        return -1;
    }

    if (len < QUIC_MIN_CID_LENGTH) {
        QUIC_LOG("CID len is too short(%u)\n", len);
        return -1;
    }

    if (QuicCidParse(&quic->scid, RPacketData(pkt), len) < 0) {
        QUIC_LOG("DCID parse failed!\n");
        return -1;
    }
 
    RPacketForward(pkt, len);

    if (RPacketGet1(pkt,  &len) < 0) {
        QUIC_LOG("Get source CID len failed\n");
        return -1;
    }

    if (QuicCidParse(&quic->dcid, RPacketData(pkt), len) < 0) {
        QUIC_LOG("SCID parse failed!\n");
        return -1;
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

    version = quic->version;
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

    return len;
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

static void QuicPktNumberGetParam(uint64_t *win, uint64_t *half_win,
                                    uint64_t *mask, uint8_t pn_nbits)
{
    assert(pn_nbits <= 32);

    *win = 1L << pn_nbits;
    *half_win = *win >> 1;
    *mask = *win - 1;
}

/*
 * RFC 9000
 * A.2.  Sample Packet Number Encoding Algorithm
 * @full_pn is the full packet number of the packet being sent.
 * @largest_acked is the largest packet number that has been
 *    acknowledged by the peer in the current packet number space, if
 *    any.
 * @pn_nbits is the number of bits in the Packet Number field (8, 16,
 *    24, or 32).
 */
uint32_t QuicPktNumberEncode(uint64_t full_pn, uint64_t largest_acked,
                            uint8_t pn_nbits)
{
    uint64_t pn_win = 0;
    uint64_t pn_hwin = 0;
    uint64_t pn_mask = 0;
    uint64_t num_unacked = 0;
    uint32_t code = 0;
    uint8_t min_bits = 0;
    uint8_t num_bytes = 0;
    int i = 0;

    QuicPktNumberGetParam(&pn_win, &pn_hwin, &pn_mask, pn_nbits);
 
    // The number of bits must be at least one more
    // than the base-2 logarithm of the number of contiguous
    // unacknowledged packet numbers, including the new packet.
    if (largest_acked == 0) {
        num_unacked = full_pn + 1;
    } else {
        assert(QUIC_GE(full_pn, largest_acked));
        num_unacked = full_pn - largest_acked;
    }

    for (i = sizeof(num_unacked)*8 - 1; i >= 0; i--){
        if (num_unacked >> i) {
            break;
        }
    }
    min_bits = i + 2; 
    num_bytes = (min_bits >> 3) + !!(min_bits & 0x7);

    if (num_bytes > pn_nbits) {
        return -1;
    }
    // Encode the integer value and truncate to
    // the num_bytes least significant bytes.
    code = full_pn & pn_mask;
    return code;
}

/*
 * RFC 9000
 * A.3.  Sample Packet Number Decoding Algorithm
 * @largest_pn is the largest packet number that has been successfully
 *     processed in the current packet number space.
 * @truncated_pn is the value of the Packet Number field.
 * @pn_nbits is the number of bits in the Packet Number field (8, 16,
 *    24, or 32).
 */


uint64_t QuicPktNumberDecode(uint64_t largest_pn, uint32_t truncated_pn,
                                uint8_t pn_nbits)
{
    uint64_t expected_pn = largest_pn + 1;
    uint64_t pn_win = 0;
    uint64_t pn_hwin = 0;
    uint64_t pn_mask = 0;
    uint64_t candidate_pn = 0;

    QuicPktNumberGetParam(&pn_win, &pn_hwin, &pn_mask, pn_nbits);
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
    candidate_pn = (expected_pn & ~pn_mask) | truncated_pn;

    if (QUIC_LE(candidate_pn, (expected_pn - pn_hwin)) &&
            QUIC_LT(candidate_pn, ((1L << 62) - pn_win))) {
         return candidate_pn + pn_win;
    }

    if (QUIC_GT(candidate_pn, (expected_pn + pn_hwin)) &&
            QUIC_GE(candidate_pn, pn_win)) {
        return candidate_pn - pn_win;
    }

    return candidate_pn;
}

static int QuicHPDoCipher(QuicHPCipher *cipher, uint8_t *out, size_t *outl,
                            size_t out_buf_len, const uint8_t *in, size_t inl)
{
    return QuicDoCipher(&cipher->cipher, out, outl, out_buf_len, in, inl);
}

static int QuicHPMaskGen(QuicHPCipher *hp_cipher, uint8_t *mask_out,
                        size_t mask_out_len, const uint8_t *pkt_num_start,
                        size_t total_len)
{
    const uint8_t *sample = NULL;
    uint8_t mask[QUIC_SAMPLE_LEN*2] = {};
    size_t mask_len = 0;

    if (hp_cipher->cipher.ctx == NULL) {
        return -1;
    }

    if (total_len < QUIC_PACKET_NUM_MAX_LEN + QUIC_SAMPLE_LEN) {
        return -1;
    }

    sample = pkt_num_start + QUIC_PACKET_NUM_MAX_LEN;
    if (QuicHPDoCipher(hp_cipher, mask, &mask_len, sizeof(mask), sample,
                QUIC_SAMPLE_LEN) < 0) {
        return -1;
    }

    assert(QUIC_LE(mask_len, sizeof(mask)) && QUIC_GE(mask_len, mask_out_len));

    memcpy(mask_out, mask, mask_out_len);

    return 0;
}

int QuicDecryptLHeader(QuicHPCipher *hp_cipher, uint32_t *pkt_num,
                        uint8_t *p_num_len, RPacket *pkt,
                        uint8_t bits_mask)
{
    uint8_t *pkt_num_start = NULL;
    uint8_t *head = NULL;
    uint8_t mask[QUIC_SAMPLE_LEN] = {};
    uint8_t pkt_num_len = 0;
    int i = 0;

    pkt_num_start = (void *)RPacketData(pkt);
    if (QuicHPMaskGen(hp_cipher, mask, sizeof(mask), pkt_num_start,
                RPacketRemaining(pkt)) < 0) {
        return -1;
    }

    head = (void *)RPacketHead(pkt);
    head[0] ^= (mask[0] & bits_mask);
    pkt_num_len = (head[0] & 0x3) + 1;

    if (RPacketRemaining(pkt) < pkt_num_len) {
        return -1;
    }

    RPacketForward(pkt, pkt_num_len);

    assert(pkt_num_len < sizeof(mask));

    for (i = 0; i < pkt_num_len; i++) {
        pkt_num_start[i] ^= mask[i + 1];
        *pkt_num |= pkt_num_start[i] << (8 * (pkt_num_len - i - 1));
    }

    *p_num_len = pkt_num_len;
    return 0;
}

static int QuicEncryptLHeader(QuicHPCipher *hp_cipher, uint8_t *first_byte,
                            uint8_t *pkt_num_start, size_t data_len,
                            uint8_t bits_mask)
{
    uint8_t mask[QUIC_SAMPLE_LEN] = {};
    uint8_t pkt_num_len = 0;
    int i = 0;

    if (QuicHPMaskGen(hp_cipher, mask, sizeof(mask), pkt_num_start,
                        data_len) < 0) {
        return -1;
    }

    pkt_num_len = (*first_byte & 0x3) + 1;
    *first_byte ^= mask[0] & bits_mask;

    assert(pkt_num_len < sizeof(mask));

    for (i = 0; i < pkt_num_len; i++) {
        pkt_num_start[i] ^= mask[i + 1];
    }

    return 0;
}

int QuicDecryptInitPacketHeader(QuicHPCipher *hp_cipher, uint32_t *pkt_num,
                                uint8_t *pkt_num_len, RPacket *pkt)
{
    return QuicDecryptLHeader(hp_cipher, pkt_num, pkt_num_len, pkt,
                                QUIC_LPACKET_TYPE_RESV_MASK);
}

int QuicPktNumberWrite(uint32_t pkt_num, uint8_t *buf, uint8_t len)
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
                                size_t out_buf_len, uint64_t pkt_num,
                                uint8_t pkt_num_len, const RPacket *pkt)
{
    QUIC_CIPHER *c = NULL;
    uint8_t *head = NULL;
    const uint8_t *data = NULL;
    uint8_t nonce[TLS13_AEAD_NONCE_LENGTH] = {};
    size_t data_len = 0;
    int tag_len = 0;
    int header_len = 0;
    int i = 0;

    data_len = RPacketRemaining(pkt);
    header_len = RPacketTotalLen(pkt) - data_len;
    assert(header_len > 0);

    head = (void *)RPacketHead(pkt);

    c = &cipher->cipher;
    memcpy(nonce, cipher->iv, sizeof(nonce));
    for (i = 0; i < 8; i++) {
        nonce[sizeof(nonce) - 1 - i] ^= (pkt_num >> 8 * i) & 0xFF;
    }

    if (QuicEvpCipherInit(c->ctx, NULL, NULL, nonce, c->enc) < 0) {
        QUIC_LOG("Cipher Init failed\n");
        goto out;
    }

    tag_len = QuicCipherGetTagLen(c->cipher_alg);
    if (tag_len < 0) {
        QUIC_LOG("Get tag len failed\n");
        goto out;
    }

    if (data_len < tag_len) {
        QUIC_LOG("Data len too small\n");
        goto out;
    }

    data = RPacketData(pkt);
    if (tag_len > 0) {
        if (QUIC_EVP_CIPHER_gcm_set_tag(c->ctx, tag_len,
                        (void *)&data[data_len - tag_len]) < 0) {
            QUIC_LOG("Set GCM tag failed\n");
            goto out;
        }
    }

    if (QUIC_EVP_CIPHER_set_iv_len(c->ctx, sizeof(nonce)) < 0) {
        QUIC_LOG("Set IV len failed\n");
        goto out;
    }

    if (QuicEvpCipherUpdate(c->ctx, NULL, outl, head, header_len) < 0) {
        QUIC_LOG("Cipher Update failed\n");
        goto out;
    }

    assert(QUIC_LT(*outl, out_buf_len));

    printf("data_len = %lu======tag_len = %u\n", data_len, tag_len);
    return QuicDoCipher(&cipher->cipher, out, outl, out_buf_len, data,
                        data_len - tag_len);
out:
    return -1;
}

static int QuicEncryptMessage(QuicPPCipher *cipher, uint8_t *out, size_t *outl,
                                size_t out_buf_len, uint8_t *head,
                                uint64_t pkt_num, uint8_t pkt_num_len,
                                uint8_t *in, size_t inlen)
{
#if 0
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
        goto out;
    }

    tag_len = QuicCipherGetTagLen(c->cipher_alg);
    if (tag_len < 0) {
        QUIC_LOG("Get tag len failed\n");
        goto out;
    }

    data = in;
    if (tag_len > 0) {
        if (QUIC_EVP_CIPHER_gcm_set_tag(c->ctx, tag_len,
                        (void *)&data[data_len - tag_len]) < 0) {
            QUIC_LOG("Set GCM tag failed\n");
            goto out;
        }
    }

    if (QUIC_EVP_CIPHER_set_iv_len(c->ctx, sizeof(nonce)) < 0) {
        QUIC_LOG("Set IV len failed\n");
        goto out;
    }

    if (QuicEvpCipherUpdate(c->ctx, NULL, outl, head, offset) < 0) {
        QUIC_LOG("Cipher Update failed\n");
        goto out;
    }

    assert(QUIC_LT(*outl, out_buf_len));
    QuicMemFree(head);

    return QuicDoCipher(&cipher->cipher, out, outl, out_buf_len, data,
                        data_len - tag_len);
out:
    QuicMemFree(head);
    return -1;
#endif
    return 0;
}

static int QuicTokenVerify(QUIC_DATA *token, const uint8_t *data, size_t len)
{
    if (len == 0) {
        return 0;
    }

    if (token->data == NULL) {
        QUIC_LOG("No token received!\n");
        return -1;
    }

    if (token->len != len || memcmp(token->data, data, len) != 0) {
        QUIC_LOG("Token not match!\n");
        return -1;
    }

    return 0;
}

static int QuicInitPacketPaser(QUIC *quic, RPacket *pkt, QuicLPacketHeader *h)
{
    QuicCipherSpace *initial = NULL;
    QUIC_CIPHERS *cipher = NULL;
    QUIC_BUFFER *buffer = NULL;
    QUIC_BUFFER *crypto_buf = &quic->tls.buffer;
    RPacket message = {};
    RPacket frame = {};
    size_t remaining = 0;
    uint64_t token_len = 0;
    uint64_t length = 0;
    uint64_t pkt_num = 0;
    uint32_t h_pkt_num = 0;
    uint8_t pkt_num_len;
    int offset = 0;
    int ret = 0;

    if (QuicVariableLengthDecode(pkt, &token_len) < 0) {
        QUIC_LOG("Token len decode failed!\n");
        return -1;
    }

    if (QuicTokenVerify(&quic->token, RPacketData(pkt), token_len) < 0) {
        QUIC_LOG("Token verify failed!\n");
        return -1;
    }

    RPacketForward(pkt, token_len);

    if (QuicVariableLengthDecode(pkt, &length) < 0) {
        QUIC_LOG("Length decode failed!\n");
        return -1;
    }

    remaining = RPacketRemaining(pkt);
    if (length > remaining) {
        QUIC_LOG("Length(%lu) bigger than remaining(%lu)\n", length, remaining);
        return -1;
    }

    offset = RPacketTotalLen(pkt) - remaining;
    
    assert(offset >= 0);

    /*
     * Init message packet buffer for a single packet
     * For a buffer maybe contain multiple packets
     */
    RPacketBufInit(&message, RPacketHead(pkt), length + offset);
    RPacketForward(&message, offset);
    RPacketForward(pkt, length);

    if (QuicCreateInitialDecoders(quic, quic->version) < 0) {
        QUIC_LOG("Create Initial Decoders failed!\n");
        return -1;
    }

    initial = &quic->initial.decrypt;
    cipher = &initial->ciphers;
    if (QuicDecryptInitPacketHeader(&cipher->hp_cipher, &h_pkt_num,
                &pkt_num_len, &message) < 0) {
        QUIC_LOG("Decrypt Initial packet header failed!\n");
        return -1;
    }

    pkt_num = QuicPktNumberDecode(initial->pkt_num, h_pkt_num, pkt_num_len*8);
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
    if (QuicDecryptMessage(&cipher->pp_cipher, QuicBufData(buffer),
                &buffer->data_len, QuicBufLength(buffer),
                h_pkt_num, pkt_num_len, &message) < 0) {
        return -1;
    }

    printf("ttttttttttttttttlen = %lu\n", buffer->data_len);
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

    quic->statem = QUIC_STATEM_INITIAL_RECV;
    printf("IIIint, f = %x, pkt_num = %u, ipkt = %lu\n", h->flags.value, h_pkt_num, initial->pkt_num);
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

static int QuicCidPut(QUIC_DATA *cid, WPacket *pkt)
{
    if (WPacketPut1(pkt, cid->len) < 0) {
        return -1;
    }

    if (cid->len == 0) {
        return 0;
    }

    return WPacketMemcpy(pkt, cid->data, cid->len);
}

static int QuicTokenPut(QUIC_DATA *token, WPacket *pkt)
{
    int len = 0;
    int blen = 0;

    if (token->len == 0) {
        return WPacketPut1(pkt, 0);
    }

    blen = WPacket_get_space(pkt);
    if (blen <= 0) {
        return -1;
    }

    len = QuicVariableLengthEncode(WPacket_get_curr(pkt), blen, token->len);
    if (len <= 0) {
        return -1;
    }

    if (WPacketAllocateBytes(pkt, len, NULL) < 0) {
        return -1;
    }

    return WPacketMemcpy(pkt, token->data, token->len);
}

static int QuicLHeaderGen(QUIC *quic, uint8_t **first_byte, WPacket *pkt,
                            uint8_t type, uint8_t pkt_num_len)
{
    QuicLPacketFlags flags;

    flags.fixed_bit = 1;
    flags.header_form = 1;
    flags.reserved_bits = 0;
    flags.lpacket_type = type;
    flags.packet_num_len = (pkt_num_len & 0x3) - 1;

    *first_byte = WPacket_get_curr(pkt);

    if (WPacketPut1(pkt, flags.value) < 0) {
        QUIC_LOG("Put flags failed\n");
        return -1;
    }

    if (WPacketPut4(pkt, quic->version) < 0) {
        QUIC_LOG("Put version failed\n");
        return -1;
    }

    if (QuicCidPut(&quic->dcid, pkt) < 0) {
        return -1;
    }

    if (QuicCidPut(&quic->scid, pkt) < 0) {
        return -1;
    }

    return 0;
}

static uint8_t encrypt_frame[] =
    "\xD1\xB1\xC9\x8D\xD7\x68\x9F\xB8\xEC\x11"
    "\xD2\x42\xB1\x23\xDC\x9B\xD8\xBA\xB9\x36\xB4\x7D\x92\xEC\x35\x6C"
    "\x0B\xAB\x7D\xF5\x97\x6D\x27\xCD\x44\x9F\x63\x30\x00\x99\xF3\x99"
    "\x1C\x26\x0E\xC4\xC6\x0D\x17\xB3\x1F\x84\x29\x15\x7B\xB3\x5A\x12"
    "\x82\xA6\x43\xA8\xD2\x26\x2C\xAD\x67\x50\x0C\xAD\xB8\xE7\x37\x8C"
    "\x8E\xB7\x53\x9E\xC4\xD4\x90\x5F\xED\x1B\xEE\x1F\xC8\xAA\xFB\xA1"
    "\x7C\x75\x0E\x2C\x7A\xCE\x01\xE6\x00\x5F\x80\xFC\xB7\xDF\x62\x12"
    "\x30\xC8\x37\x11\xB3\x93\x43\xFA\x02\x8C\xEA\x7F\x7F\xB5\xFF\x89"
    "\xEA\xC2\x30\x82\x49\xA0\x22\x52\x15\x5E\x23\x47\xB6\x3D\x58\xC5"
    "\x45\x7A\xFD\x84\xD0\x5D\xFF\xFD\xB2\x03\x92\x84\x4A\xE8\x12\x15"
    "\x46\x82\xE9\xCF\x01\x2F\x90\x21\xA6\xF0\xBE\x17\xDD\xD0\xC2\x08"
    "\x4D\xCE\x25\xFF\x9B\x06\xCD\xE5\x35\xD0\xF9\x20\xA2\xDB\x1B\xF3"
    "\x62\xC2\x3E\x59\x6D\x11\xA4\xF5\xA6\xCF\x39\x48\x83\x8A\x3A\xEC"
    "\x4E\x15\xDA\xF8\x50\x0A\x6E\xF6\x9E\xC4\xE3\xFE\xB6\xB1\xD9\x8E"
    "\x61\x0A\xC8\xB7\xEC\x3F\xAF\x6A\xD7\x60\xB7\xBA\xD1\xDB\x4B\xA3"
    "\x48\x5E\x8A\x94\xDC\x25\x0A\xE3\xFD\xB4\x1E\xD1\x5F\xB6\xA8\xE5"
    "\xEB\xA0\xFC\x3D\xD6\x0B\xC8\xE3\x0C\x5C\x42\x87\xE5\x38\x05\xDB"
    "\x05\x9A\xE0\x64\x8D\xB2\xF6\x42\x64\xED\x5E\x39\xBE\x2E\x20\xD8"
    "\x2D\xF5\x66\xDA\x8D\xD5\x99\x8C\xCA\xBD\xAE\x05\x30\x60\xAE\x6C"
    "\x7B\x43\x78\xE8\x46\xD2\x9F\x37\xED\x7B\x4E\xA9\xEC\x5D\x82\xE7"
    "\x96\x1B\x7F\x25\xA9\x32\x38\x51\xF6\x81\xD5\x82\x36\x3A\xA5\xF8"
    "\x99\x37\xF5\xA6\x72\x58\xBF\x63\xAD\x6F\x1A\x0B\x1D\x96\xDB\xD4"
    "\xFA\xDD\xFC\xEF\xC5\x26\x6B\xA6\x61\x17\x22\x39\x5C\x90\x65\x56"
    "\xBE\x52\xAF\xE3\xF5\x65\x63\x6A\xD1\xB1\x7D\x50\x8B\x73\xD8\x74"
    "\x3E\xEB\x52\x4B\xE2\x2B\x3D\xCB\xC2\xC7\x46\x8D\x54\x11\x9C\x74"
    "\x68\x44\x9A\x13\xD8\xE3\xB9\x58\x11\xA1\x98\xF3\x49\x1D\xE3\xE7"
    "\xFE\x94\x2B\x33\x04\x07\xAB\xF8\x2A\x4E\xD7\xC1\xB3\x11\x66\x3A"
    "\xC6\x98\x90\xF4\x15\x70\x15\x85\x3D\x91\xE9\x23\x03\x7C\x22\x7A"
    "\x33\xCD\xD5\xEC\x28\x1C\xA3\xF7\x9C\x44\x54\x6B\x9D\x90\xCA\x00"
    "\xF0\x64\xC9\x9E\x3D\xD9\x79\x11\xD3\x9F\xE9\xC5\xD0\xB2\x3A\x22"
    "\x9A\x23\x4C\xB3\x61\x86\xC4\x81\x9E\x8B\x9C\x59\x27\x72\x66\x32"
    "\x29\x1D\x6A\x41\x82\x11\xCC\x29\x62\xE2\x0F\xE4\x7F\xEB\x3E\xDF"
    "\x33\x0F\x2C\x60\x3A\x9D\x48\xC0\xFC\xB5\x69\x9D\xBF\xE5\x89\x64"
    "\x25\xC5\xBA\xC4\xAE\xE8\x2E\x57\xA8\x5A\xAF\x4E\x25\x13\xE4\xF0"
    "\x57\x96\xB0\x7B\xA2\xEE\x47\xD8\x05\x06\xF8\xD2\xC2\x5E\x50\xFD"
    "\x14\xDE\x71\xE6\xC4\x18\x55\x93\x02\xF9\x39\xB0\xE1\xAB\xD5\x76"
    "\xF2\x79\xC4\xB2\xE0\xFE\xB8\x5C\x1F\x28\xFF\x18\xF5\x88\x91\xFF"
    "\xEF\x13\x2E\xEF\x2F\xA0\x93\x46\xAE\xE3\x3C\x28\xEB\x13\x0F\xF2"
    "\x8F\x5B\x76\x69\x53\x33\x41\x13\x21\x19\x96\xD2\x00\x11\xA1\x98"
    "\xE3\xFC\x43\x3F\x9F\x25\x41\x01\x0A\xE1\x7C\x1B\xF2\x02\x58\x0F"
    "\x60\x47\x47\x2F\xB3\x68\x57\xFE\x84\x3B\x19\xF5\x98\x40\x09\xDD"
    "\xC3\x24\x04\x4E\x84\x7A\x4F\x4A\x0A\xB3\x4F\x71\x95\x95\xDE\x37"
    "\x25\x2D\x62\x35\x36\x5E\x9B\x84\x39\x2B\x06\x10\x85\x34\x9D\x73"
    "\x20\x3A\x4A\x13\xE9\x6F\x54\x32\xEC\x0F\xD4\xA1\xEE\x65\xAC\xCD"
    "\xD5\xE3\x90\x4D\xF5\x4C\x1D\xA5\x10\xB0\xFF\x20\xDC\xC0\xC7\x7F"
    "\xCB\x2C\x0E\x0E\xB6\x05\xCB\x05\x04\xDB\x87\x63\x2C\xF3\xD8\xB4"
    "\xDA\xE6\xE7\x05\x76\x9D\x1D\xE3\x54\x27\x01\x23\xCB\x11\x45\x0E"
    "\xFC\x60\xAC\x47\x68\x3D\x7B\x8D\x0F\x81\x13\x65\x56\x5F\xD9\x8C"
    "\x4C\x8E\xB9\x36\xBC\xAB\x8D\x06\x9F\xC3\x3B\xD8\x01\xB0\x3A\xDE"
    "\xA2\xE1\xFB\xC5\xAA\x46\x3D\x08\xCA\x19\x89\x6D\x2B\xF5\x9A\x07"
    "\x1B\x85\x1E\x6C\x23\x90\x52\x17\x2F\x29\x6B\xFB\x5E\x72\x40\x47"
    "\x90\xA2\x18\x10\x14\xF3\xB9\x4A\x4E\x97\xD1\x17\xB4\x38\x13\x03"
    "\x68\xCC\x39\xDB\xB2\xD1\x98\x06\x5A\xE3\x98\x65\x47\x92\x6C\xD2"
    "\x16\x2F\x40\xA2\x9F\x0C\x3C\x87\x45\xC0\xF5\x0F\xBA\x38\x52\xE5"
    "\x66\xD4\x45\x75\xC2\x9D\x39\xA0\x3F\x0C\xDA\x72\x19\x84\xB6\xF4"
    "\x40\x59\x1F\x35\x5E\x12\xD4\x39\xFF\x15\x0A\xAB\x76\x13\x49\x9D"
    "\xBD\x49\xAD\xAB\xC8\x67\x6E\xEF\x02\x3B\x15\xB6\x5B\xFC\x5C\xA0"
    "\x69\x48\x10\x9F\x23\xF3\x50\xDB\x82\x12\x35\x35\xEB\x8A\x74\x33"
    "\xBD\xAB\xCB\x90\x92\x71\xA6\xEC\xBC\xB5\x8B\x93\x6A\x88\xCD\x4E"
    "\x8F\x2E\x6F\xF5\x80\x01\x75\xF1\x13\x25\x3D\x8F\xA9\xCA\x88\x85"
    "\xC2\xF5\x52\xE6\x57\xDC\x60\x3F\x25\x2E\x1A\x8E\x30\x8F\x76\xF0"
    "\xBE\x79\xE2\xFB\x8F\x5D\x5F\xBB\xE2\xE3\x0E\xCA\xDD\x22\x07\x23"
    "\xC8\xC0\xAE\xA8\x07\x8C\xDF\xCB\x38\x68\x26\x3F\xF8\xF0\x94\x00"
    "\x54\xDA\x48\x78\x18\x93\xA7\xE4\x9A\xD5\xAF\xF4\xAF\x30\x0C\xD8"
    "\x04\xA6\xB6\x27\x9A\xB3\xFF\x3A\xFB\x64\x49\x1C\x85\x19\x4A\xAB"
    "\x76\x0D\x58\xA6\x06\x65\x4F\x9F\x44\x00\xE8\xB3\x85\x91\x35\x6F"
    "\xBF\x64\x25\xAC\xA2\x6D\xC8\x52\x44\x25\x9F\xF2\xB1\x9C\x41\xB9"
    "\xF9\x6F\x3C\xA9\xEC\x1D\xDE\x43\x4D\xA7\xD2\xD3\x92\xB9\x05\xDD"
    "\xF3\xD1\xF9\xAF\x93\xD1\xAF\x59\x50\xBD\x49\x3F\x5A\xA7\x31\xB4"
    "\x05\x6D\xF3\x1B\xD2\x67\xB6\xB9\x0A\x07\x98\x31\xAA\xF5\x79\xBE"
    "\x0A\x39\x01\x31\x37\xAA\xC6\xD4\x04\xF5\x18\xCF\xD4\x68\x40\x64"
    "\x7E\x78\xBF\xE7\x06\xCA\x4C\xF5\xE9\xC5\x45\x3E\x9F\x7C\xFD\x2B"
    "\x8B\x4C\x8D\x16\x9A\x44\xE5\x5C\x88\xD4\xA9\xA7\xF9\x47\x42\x41"
    "\xE2\x21\xAF\x44\x86\x00\x18\xAB\x08\x56\x97\x2E\x19\x4C\xD9\x34";

int QuicEncryptFrame(QUIC *quic, QuicPPCipher *pp_cipher, uint8_t *head,
                        uint8_t *out, size_t out_len, uint32_t pkt_num,
                        uint8_t pkt_num_len)
{
    QUIC_BUFFER *frame_buffer = &quic->tls.buffer;
    size_t outl = 0;

    if (QuicEncryptMessage(pp_cipher, out, &outl, out_len, head, pkt_num,
                            pkt_num_len, QuicBufData(frame_buffer),
                            QuicBufDataLength(frame_buffer)) < 0) {
        return -1;
    }

    if (out_len != outl) {
        printf("00000000000000000000\n");
    }

    QuicPrint(out, outl);
    outl = sizeof(encrypt_frame) - 1;
    memcpy(out, encrypt_frame, outl);
    return 0;
}

#ifdef QUIC_TEST
void (*QuicEncryptFrameHook)(QUIC_BUFFER *buffer);
#endif

static size_t QuicGetEncryptedFrameLen(QUIC *quic, QuicPPCipher *pp_cipher)
{
    QUIC_BUFFER *frame_buffer = &quic->tls.buffer;

#ifdef QUIC_TEST
    if (QuicEncryptFrameHook != NULL) {
        QuicEncryptFrameHook(frame_buffer);
    }
#endif
    return QuicCipherLenGet(pp_cipher->cipher.cipher_alg,
                        QuicBufDataLength(frame_buffer));
}

int QuicInitialPacketGen(QUIC *quic, WPacket *pkt)
{
    QuicCipherSpace *cs = NULL;
    QuicPPCipher *pp_cipher = NULL;
    uint8_t *first_byte = 0;
    uint8_t *pkt_num_start = NULL;
    uint8_t *dest = NULL;
    size_t cipher_len = 0;
    uint64_t var_len = 0;
    uint32_t pkt_num = 0;
    uint32_t len = 0;
    uint8_t pkt_num_len = quic->pkt_num_len + 1;
    int wlen = 0;

    if (QuicLHeaderGen(quic, &first_byte, pkt, QUIC_LPACKET_TYPE_INITIAL,
                pkt_num_len) < 0) {
        QUIC_LOG("Long header generate failed\n");
        return -1;
    }

    if (QuicTokenPut(&quic->token, pkt) < 0) {
        QUIC_LOG("Token put failed\n");
        return -1;
    }

    cs = &quic->initial.encrypt;
    cs->pkt_num++;

    pkt_num = QuicPktNumberEncode(cs->pkt_num, cs->pkt_acked, pkt_num_len*8);

    pp_cipher = &cs->ciphers.pp_cipher;
    cipher_len = QuicGetEncryptedFrameLen(quic, pp_cipher);
    if (cipher_len == 0) {
        return -1;
    }

    len = cipher_len + pkt_num_len;
    wlen = QuicVariableLengthEncode((uint8_t *)&var_len, sizeof(var_len), len);
    if (wlen < 0) {
        return -1;
    }

    assert(wlen <= QUIC_VARIABLE_LEN_MAX_SIZE);

    if (WPacketMemcpy(pkt, &var_len, wlen) < 0) {
        return -1;
    }

    pkt_num_start = WPacket_get_curr(pkt);
    if (WPacketPutBytes(pkt, pkt_num, pkt_num_len) < 0) {
        return -1;
    }

    if (WPacketAllocateBytes(pkt, cipher_len, &dest) < 0) {
        return -1;
    }

    printf("clen = %lu\n", cipher_len);
    if (QuicEncryptFrame(quic, pp_cipher, first_byte, dest, cipher_len, pkt_num,
                            pkt_num_len) < 0) {
        return -1;
    }

    return QuicEncryptLHeader(&cs->ciphers.hp_cipher, first_byte,
                            pkt_num_start, pkt_num_len + cipher_len,
                            QUIC_LPACKET_TYPE_RESV_MASK);
}


