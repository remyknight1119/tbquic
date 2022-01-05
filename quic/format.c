/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "format.h"

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

int QuicLPacketHeaderParse(QUIC *quic, RPacket *pkt)
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

    if ((version == QUIC_VERSION_1 && len > QUIC_MAX_CID_LENGTH)) {
        QUIC_LOG("CID len is too long(%u)\n", len);
        return -1;
    }

    if (quic->quic_server && len == 0) {
        QUIC_LOG("DCID len is zero\n");
        return -1;
    } 

    if (len > 0 && len < QUIC_MIN_CID_LENGTH) {
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
 
    RPacketForward(pkt, len);

    return 0;
}

int QuicSPacketHeaderParse(QUIC *quic, RPacket *pkt)
{
    uint32_t len = 0;

    len = quic->scid.len;
    if (QuicCidParse(&quic->scid, RPacketData(pkt), len) < 0) {
        QUIC_LOG("DCID parse failed!\n");
        return -1;
    }
 
    RPacketForward(pkt, len);

    return 0;
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
        QUIC_LOG("HP cipher not set\n");
        return -1;
    }

    if (total_len < QUIC_PACKET_NUM_MAX_LEN + QUIC_SAMPLE_LEN) {
        QUIC_LOG("Total len is too small(%lu)\n", total_len);
        return -1;
    }

    sample = pkt_num_start + QUIC_PACKET_NUM_MAX_LEN;
    if (QuicHPDoCipher(hp_cipher, mask, &mask_len, sizeof(mask), sample,
                QUIC_SAMPLE_LEN) < 0) {
        QUIC_LOG("Do HP cipher failed\n");
        return -1;
    }

    assert(QUIC_LE(mask_len, sizeof(mask)) && QUIC_GE(mask_len, mask_out_len));

    memcpy(mask_out, mask, mask_out_len);

    return 0;
}

int QuicDecryptHeader(QuicHPCipher *hp_cipher, uint32_t *pkt_num,
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
        QUIC_LOG("HP mask gen failed\n");
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

static int QuicEncryptHeader(QuicHPCipher *hp_cipher, uint8_t *first_byte,
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

static int QuicCryptoSetIV(QuicPPCipher *cipher, uint64_t pkt_num)
{
    QUIC_CIPHER *c = NULL;
    uint8_t nonce[TLS13_AEAD_NONCE_LENGTH] = {};
    int i = 0;

    c = &cipher->cipher;
    memcpy(nonce, cipher->iv, sizeof(nonce));
    for (i = 0; i < 8; i++) {
        nonce[sizeof(nonce) - 1 - i] ^= (pkt_num >> 8 * i) & 0xFF;
    }

    if (QuicEvpCipherInit(c->ctx, NULL, NULL, nonce, c->enc) < 0) {
        QUIC_LOG("Cipher Init failed\n");
        return -1;
    }

    if (QUIC_EVP_CIPHER_set_iv_len(c->ctx, sizeof(nonce)) < 0) {
        QUIC_LOG("Set IV len failed\n");
        return -1;
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
    size_t data_len = 0;
    int tag_len = 0;
    int header_len = 0;

    data_len = RPacketRemaining(pkt);
    header_len = RPacketTotalLen(pkt) - data_len;
    assert(header_len > 0);

    head = (void *)RPacketHead(pkt);

    c = &cipher->cipher;
    if (QuicCryptoSetIV(cipher, pkt_num) < 0) {
        QUIC_LOG("Cipher set IV failed\n");
        return -1;
    }

    tag_len = QuicCipherGetTagLen(c->alg);
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

    if (QuicEvpCipherUpdate(c->ctx, NULL, outl, head, header_len) < 0) {
        QUIC_LOG("Cipher Update failed\n");
        return -1;
    }

    assert(QUIC_LT(*outl, out_buf_len));

    return QuicDoCipher(&cipher->cipher, out, outl, out_buf_len, data,
                        data_len - tag_len);
}

static int QuicEncryptMessage(QuicPPCipher *cipher, uint8_t *out, size_t *outl,
                                size_t out_buf_len, uint8_t *head, size_t hlen,
                                uint64_t pkt_num, uint8_t pkt_num_len,
                                uint8_t *in, size_t inlen)
{
    QUIC_CIPHER *c = NULL;
    int tag_len = 0;

    c = &cipher->cipher;
    if (QuicCryptoSetIV(cipher, pkt_num) < 0) {
        QUIC_LOG("Cipher set IV failed\n");
        return -1;
    }

    if (QuicEvpCipherUpdate(c->ctx, NULL, outl, head, hlen) < 0) {
        QUIC_LOG("Cipher Update failed\n");
        return -1;
    }

    assert(QUIC_LT(*outl, out_buf_len));

    if (QuicDoCipher(&cipher->cipher, out, outl, out_buf_len, in, inlen) < 0) {
        QUIC_LOG("Do cipher failed\n");
        return -1;
    }

    tag_len = QuicCipherGetTagLen(c->alg);
    if (tag_len < 0) {
        QUIC_LOG("Get tag len failed\n");
        return -1;
    }

    if (tag_len > 0) {
        if (*outl + tag_len > out_buf_len) {
            return -1;
        }
        if (QUIC_EVP_CIPHER_gcm_get_tag(c->ctx, tag_len,
                        (void *)&out[*outl]) < 0) {
            QUIC_LOG("Set GCM tag failed\n");
        }
        *outl += tag_len;
    }

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

static int QuicLengthParse(RPacket *msg, RPacket *pkt)
{
    uint64_t length = 0;
    size_t remaining = 0;
    int offset = 0;

    if (QuicVariableLengthDecode(pkt, &length) < 0) {
        QUIC_LOG("Length decode failed!\n");
        return -1;
    }

    remaining = RPacketRemaining(pkt);
    if (QUIC_GT(length, remaining)) {
        QUIC_LOG("Length(%lu) bigger than remaining(%lu)\n", length, remaining);
        return -1;
    }

    offset = RPacketTotalLen(pkt) - remaining;
    assert(offset >= 0);

    /*
     * Init message packet buffer for a single packet
     * For a buffer maybe contain multiple packets
     */
    RPacketBufInit(msg, RPacketData(pkt), length);
    RPacketHeadPush(msg, offset);
    RPacketForward(pkt, length);

    return 0;
}
 
static int
QuicDecryptPacket(QuicCipherSpace *cs, RPacket *pkt, QUIC_BUFFER *buffer,
                    uint8_t bit_mask)
{
    QUIC_CIPHERS *cipher = NULL;
    uint64_t pkt_num = 0;
    uint32_t h_pkt_num = 0;
    uint8_t pkt_num_len;

    cipher = &cs->ciphers;
    if (QuicDecryptHeader(&cipher->hp_cipher, &h_pkt_num,
                &pkt_num_len, pkt, bit_mask) < 0) {
        QUIC_LOG("Decrypt Initial packet header failed!\n");
        return -1;
    }

    pkt_num = QuicPktNumberDecode(cs->pkt_num, h_pkt_num, pkt_num_len*8);
    if (QUIC_GT(cs->pkt_num, pkt_num)) {
        QUIC_LOG("PKT number invalid!\n");
        return -1;
    }

    if (cs->pkt_num == pkt_num && pkt_num != 0) {
        QUIC_LOG("PKT number invalid!\n");
        return -1;
    }

    cs->pkt_num = pkt_num;

    return QuicDecryptMessage(&cipher->pp_cipher, QuicBufData(buffer),
                &buffer->data_len, QuicBufLength(buffer),
                h_pkt_num, pkt_num_len, pkt);
}

static int QuicFrameParse(QUIC *quic, QUIC_BUFFER *f_buf)
{
    RPacket frame = {};

    RPacketBufInit(&frame, QuicBufData(f_buf), QuicBufGetDataLength(f_buf));
    if (QuicFrameDoParser(quic, &frame) < 0) {
        QUIC_LOG("Do parser failed!\n");
        return -1;
    }

    if (TlsDoHandshake(&quic->tls) == QUIC_FLOW_RET_ERROR) {
        QUIC_LOG("TLS Hadshake failed!\n");
        return -1;
    }

    return 0;
}

int Quic0RttPacketParse(QUIC *quic, RPacket *pkt)
{
    return 0;
}

int QuicInitPacketParse(QUIC *quic, RPacket *pkt)
{
    QuicCipherSpace *initial = NULL;
    QUIC_BUFFER *buffer = QuicGetPlainTextBuffer();
    RPacket message = {};
    uint64_t token_len = 0;

    if (QuicVariableLengthDecode(pkt, &token_len) < 0) {
        QUIC_LOG("Token len decode failed!\n");
        return -1;
    }

    if (QuicTokenVerify(&quic->token, RPacketData(pkt), token_len) < 0) {
        QUIC_LOG("Token verify failed!\n");
        return -1;
    }

    RPacketForward(pkt, token_len);

    if (QuicLengthParse(&message, pkt) < 0) {
        return -1;
    }

    if (QuicCreateInitialDecoders(quic, quic->version) < 0) {
        QUIC_LOG("Create Initial Decoders failed!\n");
        return -1;
    }

    initial = &quic->initial.decrypt;
    if (QuicDecryptPacket(initial, &message, buffer,
                QUIC_LPACKET_TYPE_RESV_MASK) < 0) {
        QUIC_LOG("Decrypt message failed!\n");
        return -1;
    }

    return QuicFrameParse(quic, buffer);
}

int QuicHandshakePacketParse(QUIC *quic, RPacket *pkt)
{
    QUIC_BUFFER *buffer = QuicGetPlainTextBuffer();
    RPacket message = {};

    if (QuicLengthParse(&message, pkt) < 0) {
        return -1;
    }

    if (QuicDecryptPacket(&quic->handshake.decrypt, &message, buffer,
                QUIC_LPACKET_TYPE_RESV_MASK) < 0) {
        QUIC_LOG("Decrypt message failed!\n");
        return -1;
    }

    return QuicFrameParse(quic, buffer);
}

int QuicOneRttParse(QUIC *quic, RPacket *pkt)
{
    QUIC_BUFFER *buffer = QuicGetPlainTextBuffer();

    if (QuicDecryptPacket(&quic->one_rtt.decrypt, pkt, buffer,
                QUIC_SPACKET_TYPE_RESV_MASK) < 0) {
        QUIC_LOG("Decrypt message failed!\n");
        return -1;
    }

    return QuicFrameParse(quic, buffer);
}

int QuicRetryPacketParse(QUIC *quic, RPacket *pkt)
{
    return 0;
}

int QuicVariableLengthWrite(WPacket *pkt, uint64_t len)
{
    uint64_t var_len = 0;
    int wlen = 0;

    wlen = QuicVariableLengthEncode((uint8_t *)&var_len, sizeof(var_len), len);
    if (wlen < 0) {
        return -1;
    }

    assert(wlen <= QUIC_VARIABLE_LEN_MAX_SIZE);

    return WPacketMemcpy(pkt, &var_len, wlen);
}

int QuicVariableLengthValueWrite(WPacket *pkt, uint64_t value)
{
    uint64_t var = 0;
    int wlen = 0;

    wlen = QuicVariableLengthEncode((uint8_t *)&var, sizeof(var), value);
    if (wlen < 0) {
        return -1;
    }

    assert(wlen <= QUIC_VARIABLE_LEN_MAX_SIZE);

    if (QuicVariableLengthWrite(pkt, wlen) < 0) {
        return -1;
    }

    return WPacketMemcpy(pkt, &var, wlen);
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
    if (token->len == 0) {
        return WPacketPut1(pkt, 0);
    }

    if (QuicVariableLengthWrite(pkt, token->len) < 0) {
        return -1;
    }

    return WPacketMemcpy(pkt, token->data, token->len);
}

static int QuicLHeaderGen(QUIC *quic, uint8_t **first_byte, WPacket *pkt,
                            uint8_t type, uint8_t pkt_num_len)
{
    QuicPacketFlags flags;

    flags.lh.fixed = 1;
    flags.lh.header_form = 1;
    flags.lh.reserved = 0;
    flags.lh.lpacket_type = type;
    flags.lh.packet_num_len = (pkt_num_len & 0x3) - 1;

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

static int QuicFrameBufferAddPadding(QUIC *quic, size_t padding_len, QBUFF *qb)
{
    WPacket pkt = {};

    WPacketStaticBufInit(&pkt, QBuffTail(qb), QBuffSpace(qb));

    if (QuicFramePaddingBuild(&pkt, padding_len) < 0) {
        WPacketCleanup(&pkt);
        return -1;
    }
    WPacketCleanup(&pkt);

    return QBuffAddDataLen(qb, padding_len);
}

int QuicEncryptPayload(QUIC *quic, QuicPPCipher *pp_cipher, uint8_t *head,
                        size_t hlen, uint8_t *out, size_t out_len,
                        uint32_t pkt_num, uint8_t pkt_num_len, QBUFF *qb)
{
    size_t outl = 0;

    if (QuicEncryptMessage(pp_cipher, out, &outl, out_len, head, hlen, pkt_num,
                            pkt_num_len, QBuffHead(qb),
                            QBuffGetDataLen(qb)) < 0) {
        return -1;
    }

    if (out_len != outl) {
        QUIC_LOG("Out data len not match(%lu:%lu)\n", out_len, outl);
        return -1;
    }

    return 0;
}

#ifdef QUIC_TEST
void (*QuicEncryptPayloadHook)(QBUFF *qb);
#endif

static size_t
QuicGetEncryptedPayloadLen(QUIC *quic, QuicPPCipher *pp_cipher, QBUFF *qb)
{
#ifdef QUIC_TEST
    if (QuicEncryptPayloadHook != NULL) {
        QuicEncryptPayloadHook(qb);
    }
#endif
    return QuicCipherLenGet(pp_cipher->cipher.alg, QBuffGetDataLen(qb));
}

int QuicInitialPacketGen(QUIC *quic, WPacket *pkt, QBUFF *qb)
{
    QuicCipherSpace *cs = NULL;
    QuicPPCipher *pp_cipher = NULL;
    uint8_t *first_byte = 0;
    uint8_t *pkt_num_start = NULL;
    uint8_t *dest = NULL;
    size_t cipher_len = 0;
    size_t total_len = 0;
    size_t padding_len = 0;
    uint64_t var_len = 0;
    uint64_t len = 0;
    uint32_t pkt_num = 0;
    uint8_t pkt_num_len = quic->pkt_num_len + 1;
    int wlen = 0;
    int wlen_curr = 0;
    int len_offset = 0;
    int offset = 0;

    if (QuicLHeaderGen(quic, &first_byte, pkt, QUIC_LPACKET_TYPE_INITIAL,
                pkt_num_len) < 0) {
        QUIC_LOG("Long header generate failed\n");
        return -1;
    }

    if (QuicTokenPut(&quic->token, pkt) < 0) {
        QUIC_LOG("Token put failed\n");
        return -1;
    }

    total_len = WPacket_get_written(pkt);
    cs = &quic->initial.encrypt;
    cs->pkt_num++;

    qb->pkt_num = cs->pkt_num;
    pkt_num = QuicPktNumberEncode(cs->pkt_num, cs->pkt_acked, pkt_num_len*8);

    pp_cipher = &cs->ciphers.pp_cipher;
    cipher_len = QuicGetEncryptedPayloadLen(quic, pp_cipher, qb);
    if (cipher_len == 0) {
        return -1;
    }

    len = cipher_len + pkt_num_len;

    wlen = QuicVariableLengthEncode((uint8_t *)&var_len, sizeof(var_len), len);
    if (wlen < 0) {
        return -1;
    }

    total_len += len + wlen;
    if (QUIC_LT(total_len, QUIC_INITIAL_PKT_DATAGRAM_SIZE_MIN)) {
        padding_len = QUIC_INITIAL_PKT_DATAGRAM_SIZE_MIN - total_len;
        len += padding_len;
        wlen_curr = QuicVariableLengthEncode((uint8_t *)&var_len, sizeof(var_len), len);
        len_offset = wlen_curr - wlen;
        assert(len_offset >= 0);
        padding_len -= len_offset;
        len -= len_offset;
        cipher_len += padding_len;
    }

    if (QuicVariableLengthWrite(pkt, len) < 0) {
        return -1;
    }

    pkt_num_start = WPacket_get_curr(pkt);
    if (WPacketPutBytes(pkt, pkt_num, pkt_num_len) < 0) {
        return -1;
    }

    if (WPacketAllocateBytes(pkt, cipher_len, &dest) < 0) {
        return -1;
    }

    offset = dest - first_byte;
    assert(offset > 0);

    if (QuicFrameBufferAddPadding(quic, padding_len, qb) < 0) {
        return -1;
    }

    if (QuicEncryptPayload(quic, pp_cipher, first_byte, offset, dest, cipher_len,
                            pkt_num, pkt_num_len, qb) < 0) {
        return -1;
    }

    return QuicEncryptHeader(&cs->ciphers.hp_cipher, first_byte,
                            pkt_num_start, pkt_num_len + cipher_len,
                            QUIC_LPACKET_TYPE_RESV_MASK);
}

int QuicInitialPacketBuild(QUIC *quic, QBUFF *qb)
{
    QUIC_BUFFER *qbuf = QUIC_WRITE_BUFFER(quic);
    WPacket pkt = {};
    int ret = 0;

    WPacketBufInit(&pkt, qbuf->buf);
    ret = QuicInitialPacketGen(quic, &pkt, qb);
    QuicBufSetDataLength(qbuf, WPacket_get_written(&pkt));
    WPacketCleanup(&pkt);

    return ret;
}

int QuicFrameBuild(QUIC *quic, QBuffPktBuilder build_pkt)
{
    QBUFF *qb = NULL;
    WPacket pkt = {};
    int ret = -1;

    qb = QBuffNew(quic->mtu, build_pkt);
    if (qb == NULL) {
        return -1;
    }

    WPacketStaticBufInit(&pkt, QBuffHead(qb), QBuffLen(qb));
    if (QuicFramePingBuild(&pkt) < 0) {
        goto out;
    }

    if (QuicFrameCryptoBuild(quic, &pkt) < 0) {
        goto out;
    }

    if (QBuffSetDataLen(qb, WPacket_get_written(&pkt)) < 0) {
        goto out;
    }

    QBuffQueueAdd(&quic->tx_queue, qb);

    ret = 0;
out:
    WPacketCleanup(&pkt);
    return ret;
}

