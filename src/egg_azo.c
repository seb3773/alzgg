/* egg_azo.c — AZO codec (EGG method 3), appendix A of FORMAT-EGG.md.
 *
 * An EGG block's stream starts with a 2-byte stream header ('1' version, x86
 * filter flag), followed by big-endian 12-byte slices (decompressed size,
 * compressed size, XOR check) and a null 12-byte terminal slice. Each slice is
 * either copied verbatim (compressSize == blockSize) or coded by the adaptive
 * range coder described in the appendix. Slices are at most 2^19 bytes
 * (AZO_BLOCKSIZE) and each one starts from fresh models, history and finder.
 *
 * Decoding AND encoding. The encoder reproduces byte for byte the five AZO
 * references of the corpus (make test, steps 9 and 10):
 *   - packed_egg/probe_sys_optimized.egg       (probe.sys, one slice);
 *   - packed_egg/probe_com_optimized.egg       (probe.com: ALZip also routes
 *     .com to AZO, same payload);
 *   - packed_egg_8.0/sysmulti_sys_optimized.egg (633,780 bytes, two slices:
 *     this is the reference that pins the internal slicing);
 *   - packed_egg_8.0/mz_sys_optimized.egg      (mz.sys, 73,560-byte PE:
 *     `31 01` flag, x86 filter in the encoder direction);
 *   - packed_egg_8.0/mzmulti_sys_optimized.egg   (594,264 bytes, two slices
 *     whose second does not start with MZ: the flag is sticky).
 * It was tuned by reading the AZO.dll 10.3.28.0 disassembly and checked against
 * extra outputs of an ALZipCon oracle under Wine (outside make test).
 *
 * Measured parameters, never guessed: 2^19 slices, 0x4000000C window, maximum
 * length 0x8019, threshold 2 (above it a match is accepted; below it, a cost
 * test runs), 3 progressive hash levels (2/4/8-byte prefixes, 18-bit index),
 * one candidate per level with a stop at the first accepted one, lazy one-byte
 * parse, and reuse of a remembered pair only at EXACTLY equal length (lowest
 * index), with the shortReuse bit marking the first two slots.
 */
#include "egg_azo.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "zlib.h"   /* crc32 (zlib vendored in src/zlib_deflate) */

/* ============================================================ bit reader ==== */

typedef struct {
    const uint8_t *p;
    size_t         size;
    size_t         pos;      /* bytes consumed */
    unsigned       cur;      /* current byte, MSB first */
    unsigned       bits;     /* bits left in `cur` */
    unsigned       over;     /* reads past the end (padding) */
} AzoBits;

static unsigned azo_read_bit(AzoBits *b)
{
    if (!b->bits) {
        if (b->pos < b->size)
            b->cur = b->p[b->pos++];
        else {
            b->cur = 0;          /* end-of-stream padding */
            b->over++;
        }
        b->bits = 8;
    }
    b->bits--;
    return (b->cur >> b->bits) & 1u;
}

/* ===================================================== arithmetic decoder == */

#define AZO_MASK 0xFFFFFFFFu
#define AZO_MSB  0x80000000u
#define AZO_SMSB 0x40000000u

typedef struct {
    AzoBits  in;
    uint64_t low, up, tag;
} AzoDec;

static void azo_init(AzoDec *d, const uint8_t *src, size_t size)
{
    int i;

    d->in.p = src;
    d->in.size = size;
    d->in.pos = 0;
    d->in.cur = 0;
    d->in.bits = 0;
    d->in.over = 0;
    d->low = 0;
    d->up = AZO_MASK;
    d->tag = 0;
    for (i = 0; i < 32; i++)                  /* amorce : 32 bits, MSB d'abord */
        d->tag = ((d->tag << 1) | azo_read_bit(&d->in)) & AZO_MASK;
}

static void azo_rescale(AzoDec *d)
{
    while ((d->low & AZO_MSB) == (d->up & AZO_MSB)) {
        unsigned bit = azo_read_bit(&d->in);

        d->tag = ((d->tag << 1) & AZO_MASK) | bit;
        d->low = (d->low << 1) & AZO_MASK;
        d->up  = ((d->up << 1) & AZO_MASK) | 1u;
    }
    while ((d->low & AZO_SMSB) && !(d->up & AZO_SMSB)) {
        unsigned bit = azo_read_bit(&d->in);

        d->tag = (((d->tag << 1) | bit) ^ AZO_MSB) & AZO_MASK;
        d->low = (d->low << 1) & (AZO_MASK >> 1);
        d->up  = ((d->up << 1) | 1u | AZO_MSB) & AZO_MASK;
    }
}

/* `cum` = probability of 0 over `total_bit` bits (4096 for BoolState, 1024 for
 * EntropyBitProb). Returns the symbol. */
static unsigned azo_decode_bool(AzoDec *d, uint32_t cum, int total_bit)
{
    uint64_t t = ((d->up - d->low) + 1) >> total_bit;
    uint64_t v = (d->tag - d->low) / t;

    if (v >= cum) {
        d->low += t * cum;
        azo_rescale(d);
        return 1;
    }
    d->up = d->low + t * cum - 1;
    azo_rescale(d);
    return 0;
}

static uint32_t azo_decode_uniform(AzoDec *d, int total_bit)
{
    uint64_t t = ((d->up - d->low) + 1) >> total_bit;
    uint64_t v = (d->tag - d->low) / t;

    d->up  = d->low + t * (v + 1) - 1;
    d->low = d->low + t * v;
    azo_rescale(d);
    return (uint32_t)v;
}

/* =================================================== probability models === */

#define AZO_NODES 256                     /* 2^8: largest alphabet used */

typedef struct {                          /* EntropyBitProb<N> */
    int      bit_n;
    uint32_t prob[AZO_NODES];
} AzoEbp;

static void ebp_init(AzoEbp *m, int bit_n)
{
    int i;

    m->bit_n = bit_n;
    for (i = 0; i < (1 << bit_n); i++)
        m->prob[i] = 512;                 /* TOTAL_COUNT / 2, TOTAL_COUNT=1024 */
}

static unsigned ebp_decode(AzoDec *d, AzoEbp *m)
{
    unsigned value = 0, pre = 1;
    int      i;

    for (i = m->bit_n - 1; i >= 0; i--) {
        unsigned bit = azo_decode_bool(d, m->prob[pre], 10);

        if (bit) m->prob[pre] -= m->prob[pre] >> 4;
        else     m->prob[pre] += (1024u - m->prob[pre]) >> 4;
        if (bit) value |= 1u << i;
        pre = (pre << 1) | bit;
    }
    return value;
}

/* Same update, without reading the stream: keeps the other PredictProb model. */
static void ebp_update(AzoEbp *m, unsigned value)
{
    unsigned pre = 1;
    int      i;

    for (i = m->bit_n - 1; i >= 0; i--) {
        unsigned bit = (value >> i) & 1u;

        if (bit) m->prob[pre] -= m->prob[pre] >> 4;
        else     m->prob[pre] += (1024u - m->prob[pre]) >> 4;
        pre = (pre << 1) | bit;
    }
}

typedef struct {                          /* BoolState<8> */
    uint32_t prob[256];
    unsigned state;
} AzoBool;

static void ab_init(AzoBool *b)
{
    int i;

    for (i = 0; i < 256; i++)
        b->prob[i] = 2048;                /* TOTAL_COUNT / 2, TOTAL_COUNT=4096 */
    b->state = 0;
}

static unsigned ab_decode(AzoDec *d, AzoBool *b)
{
    unsigned bit = azo_decode_bool(d, b->prob[b->state], 12);

    if (bit) b->prob[b->state] -= b->prob[b->state] >> 6;
    else     b->prob[b->state] += (4096u - b->prob[b->state]) >> 6;
    b->state = ((b->state << 1) | bit) & 0xFF;
    return bit;
}

/* ============================================== PredictProb: two models ===== */

typedef struct {
    AzoEbp *fine;                          /* one model per context */
    AzoEbp *coarse;                        /* one per group of contexts */
    int    *lucky;
} AzoPp;

static unsigned pp_decode(AzoDec *d, AzoPp *pp, int pre, int bit_n, int shift)
{
    AzoEbp   *m1 = &pp->fine[pre];
    AzoEbp   *m2 = &pp->coarse[pre >> shift];
    unsigned  value;
    uint32_t  prod1 = 1, prod2 = 1;
    unsigned  node = 1;
    int       i, r;

    if (pp->lucky[pre] >= 0) {
        value = ebp_decode(d, m1);
        ebp_update(m2, value);
    } else {
        value = ebp_decode(d, m2);
        ebp_update(m1, value);
    }

    /* Compare (A.7): product of the probabilities along the decoded path. */
    for (i = bit_n - 1; i >= 0; i--) {
        uint32_t p1 = m1->prob[node];
        uint32_t p2 = m2->prob[node];
        unsigned v = (value >> i) & 1u;

        if ((prod1 | prod2) & ((1024u - 1u) << (32 - 10))) {
            prod1 >>= 10;
            prod2 >>= 10;
        }
        prod1 *= v ? (1024u - p1) : p1;
        prod2 *= v ? (1024u - p2) : p2;
        node = (node << 1) | v;
    }
    r = (prod1 > prod2) - (prod1 < prod2);
    if (r > 0) pp->lucky[pre]++;
    else if (r < 0) pp->lucky[pre]--;
    return value;
}

/* ================================================== listes MRU (A.8) ======== */

typedef struct {
    int      n;
    uint32_t *rep;
} AzoHist;

/* The length, distance and index lists are seeded with
 * `init, init+1, ...`; the position list starts at zero (A.8). */
static void hist_init(AzoHist *h, uint32_t *mem, int n, uint32_t init, int step)
{
    int i;

    h->n = n;
    h->rep = mem;
    for (i = 0; i < n; i++)
        h->rep[i] = step ? init + (uint32_t)i : init;
}

static uint32_t hist_take(AzoHist *h, int idx)
{
    uint32_t v = h->rep[idx];
    int      i;

    for (i = idx; i > 0; i--)
        h->rep[i] = h->rep[i - 1];
    h->rep[0] = v;
    return v;
}

static void hist_add(AzoHist *h, uint32_t v)
{
    int i;

    for (i = h->n - 1; i > 0; i--)
        h->rep[i] = h->rep[i - 1];
    h->rep[0] = v;
}

/* ===================================================== tables de codes ====== */

static uint32_t azo_len_base[128];
static int      azo_len_extra[128];
static uint32_t azo_dist_base[128];
static int      azo_dist_extra[128];
static int      azo_tables_ready;

static int azo_ilog2(uint32_t v)
{
    int n = 0;

    while (v >>= 1)
        n++;
    return n;
}

static void azo_build_tables(void)
{
    int i;

    if (azo_tables_ready)
        return;
    for (i = 0; i < 128; i++) {
        azo_len_extra[i] = i < 32 ? 0 : (i - 32) / 8;
        azo_dist_extra[i] = i < 16 ? 0 : (i - 16) / 4;
    }
    azo_len_base[0] = 2;
    azo_dist_base[0] = 1;
    for (i = 1; i < 128; i++) {
        azo_len_base[i] = azo_len_base[i - 1] + (1u << azo_len_extra[i - 1]);
        azo_dist_base[i] = azo_dist_base[i - 1] + (1u << azo_dist_extra[i - 1]);
    }
    azo_tables_ready = 1;
}

/* A.11.2: value -> code index (context of the length code). */
static unsigned azo_dist_code(uint32_t value)
{
    uint32_t v = value - 1;
    uint32_t extra;

    if (v < 16)
        return v;
    v -= 16;
    extra = (uint32_t)azo_ilog2(v / 4 + 1);
    return 16 + extra * 4 + (v - ((1u << extra) - 1) * 4) / (1u << extra);
}

/* ============================================================ filtre x86 ==== */

/* AZO.dll's x86 filter (0x619094b0). `forward` non-zero = encoder direction
 * (relative -> absolute: addr += i), zero = decoder direction (absolute ->
 * relative: addr -= i). The test of both ends (0xE8/0xE9 and a high byte of
 * 0x00 or 0xFF) and the step of 5 on a match are the same in both directions. */
static void azo_x86_filter(uint8_t *buf, size_t size, int forward)
{
    size_t i = 0;

    if (size < 5)
        return;
    while (i < size - 4) {
        if (buf[i] == 0xE8 || buf[i] == 0xE9) {
            if (buf[i + 4] == 0x00 || buf[i + 4] == 0xFF) {
                uint32_t addr = (uint32_t)buf[i + 1] | ((uint32_t)buf[i + 2] << 8) |
                                ((uint32_t)buf[i + 3] << 16) | ((uint32_t)buf[i + 4] << 24);

                addr = forward ? addr + (uint32_t)i : addr - (uint32_t)i;
                if ((addr >> 24) & 1)
                    addr |= 0xFF000000u;
                else
                    addr &= 0x00FFFFFFu;
                buf[i + 1] = (uint8_t)addr;
                buf[i + 2] = (uint8_t)(addr >> 8);
                buf[i + 3] = (uint8_t)(addr >> 16);
                buf[i + 4] = (uint8_t)(addr >> 24);
            }
            i += 5;
        } else {
            i += 1;
        }
    }
}

/* ================================================================ encoder ==== */

/* The parser and encoder reproduce those of AZO.dll 10.3.28.0: configuration
 * table 0x6190c840 row 1 (2^19 bytes per block, 3 hash levels of 2/4/8 bytes,
 * 18 bits, threshold 2), search 0x61905a90, decision 0x61905bf0, arithmetic
 * coder 0x619047f0-0x61904a60. Checked byte for byte on probe_sys_optimized.egg
 * and on the oracle's multi-block outputs. */

#define AZO_SHIFT     18
#define AZO_LEVELS    3
#define AZO_HASH_MASK ((1u << AZO_SHIFT) - 1u)
#define AZO_THRESHOLD 2
/* Maximum match length: 0x8019, the bound read by the length function at
 * 0x6190b320 (0x61905905). It is also the maximum length the A.11.2 table can
 * code. Proved decisively by patching those 4 bytes in the Wine copy of AZO.dll:
 * the DLL patched to 0x100 emits matches of at most 256 (identical ranges split
 * into 256-byte slices), the original DLL emits 0x8019 — and the original
 * oracle does reproduce probe_sys_optimized.egg byte for byte. */
#define AZO_MAXLEN    0x8019u
#define AZO_DISTLIM   0x4000000Cu
#define AZO_BLOCKSHIFT 19                  /* 2^19 = 512 KiB per block */
#define AZO_BLOCKSIZE (1u << AZO_BLOCKSHIFT)

typedef struct {
    uint8_t *p;
    size_t   len, cap;
    unsigned cur, nbits;
    int      oom;
} AzoBuf;

static void buf_bit(AzoBuf *b, unsigned bit)
{
    if (b->oom)
        return;
    if (bit)
        b->cur |= 1u << (7 - b->nbits);
    if (++b->nbits == 8) {
        if (b->len == b->cap) {
            size_t ncap = b->cap ? b->cap * 2 : 4096;
            uint8_t *np = realloc(b->p, ncap);

            if (!np) {
                b->oom = 1;
                return;
            }
            b->p = np;
            b->cap = ncap;
        }
        b->p[b->len++] = (uint8_t)b->cur;
        b->cur = 0;
        b->nbits = 0;
    }
}

static void buf_align(AzoBuf *b)
{
    while (b->nbits)
        buf_bit(b, 0);
}

typedef struct {
    AzoBuf   out;
    uint32_t low, up;
    unsigned pending;
} AzoEnc;

static void enc_init(AzoEnc *e)
{
    memset(e, 0, sizeof *e);
    e->low = 0;
    e->up = AZO_MASK;
}

static void enc_renorm(AzoEnc *e)
{
    while ((e->low & AZO_MSB) == (e->up & AZO_MSB)) {
        unsigned bit = (e->low & AZO_MSB) ? 1u : 0u;

        buf_bit(&e->out, bit);
        e->low = (e->low << 1) & AZO_MASK;
        e->up  = ((e->up << 1) & AZO_MASK) | 1u;
        while (e->pending) {
            e->pending--;
            buf_bit(&e->out, bit ^ 1u);
        }
    }
    while ((e->low & AZO_SMSB) && !(e->up & AZO_SMSB)) {
        e->low = (e->low << 1) & (AZO_MASK >> 1);
        e->up  = ((e->up << 1) | 1u | AZO_MSB) & AZO_MASK;
        e->pending++;
    }
}

/* `cum` = probability of 0 (as in azo_decode_bool). */
static void enc_bool(AzoEnc *e, uint32_t cum, int total_bit, unsigned bit)
{
    uint64_t t = (e->low == 0 && e->up == AZO_MASK)
                     ? (uint64_t)1 << (32 - total_bit)
                     : (((uint64_t)e->up - e->low) + 1) >> total_bit;

    if (bit)
        e->low += (uint32_t)(t * cum);
    else
        e->up = e->low + (uint32_t)(t * cum) - 1;
    enc_renorm(e);
}

static void enc_uniform(AzoEnc *e, int total_bit, uint32_t value)
{
    uint64_t t = (e->low == 0 && e->up == AZO_MASK)
                     ? (uint64_t)1 << (32 - total_bit)
                     : (((uint64_t)e->up - e->low) + 1) >> total_bit;

    e->up  = e->low + (uint32_t)(t * (value + 1)) - 1;
    e->low = e->low + (uint32_t)(t * value);
    enc_renorm(e);
}

static void enc_flush(AzoEnc *e)
{
    if (!(e->low & AZO_SMSB)) {
        buf_bit(&e->out, 0);
        while (e->pending) {
            e->pending--;
            buf_bit(&e->out, 1);
        }
    }
    buf_bit(&e->out, 1);
    buf_align(&e->out);
}

/* --- models: same updates as the decoder, on the writing side -------------- */

static void ab_encode(AzoEnc *e, AzoBool *b, unsigned bit)
{
    uint32_t p = b->prob[b->state];

    enc_bool(e, p, 12, bit);
    if (bit) b->prob[b->state] -= p >> 6;
    else     b->prob[b->state] += (4096u - p) >> 6;
    b->state = ((b->state << 1) | bit) & 0xFF;
}

static void ebp_encode(AzoEnc *e, AzoEbp *m, unsigned value)
{
    unsigned pre = 1;
    int      i;

    for (i = m->bit_n - 1; i >= 0; i--) {
        unsigned bit = (value >> i) & 1u;

        enc_bool(e, m->prob[pre], 10, bit);
        if (bit) m->prob[pre] -= m->prob[pre] >> 4;
        else     m->prob[pre] += (1024u - m->prob[pre]) >> 4;
        pre = (pre << 1) | bit;
    }
}

static double ebp_prob(const AzoEbp *m, unsigned value)
{
    double   p = 1.0;
    unsigned pre = 1;
    int      i;

    for (i = m->bit_n - 1; i >= 0; i--) {
        unsigned bit = (value >> i) & 1u;
        uint32_t q = m->prob[pre];

        p *= bit ? (double)(1024u - q) / 1024.0 : (double)q / 1024.0;
        pre = (pre << 1) | bit;
    }
    return p;
}

static const AzoEbp *pp_model(const AzoPp *pp, int pre, int shift)
{
    return pp->lucky[pre] >= 0 ? &pp->fine[pre] : &pp->coarse[pre >> shift];
}

static double pp_prob(const AzoPp *pp, int pre, int shift, unsigned value)
{
    return ebp_prob(pp_model(pp, pre, shift), value);
}

static void pp_encode(AzoEnc *e, AzoPp *pp, int pre, int bit_n, int shift,
                      unsigned value)
{
    AzoEbp   *m1 = &pp->fine[pre];
    AzoEbp   *m2 = &pp->coarse[pre >> shift];
    uint32_t  prod1 = 1, prod2 = 1;
    unsigned  node = 1;
    int       i, r;

    if (pp->lucky[pre] >= 0) {
        ebp_encode(e, m1, value);
        ebp_update(m2, value);
    } else {
        ebp_encode(e, m2, value);
        ebp_update(m1, value);
    }
    for (i = bit_n - 1; i >= 0; i--) {
        uint32_t p1 = m1->prob[node];
        uint32_t p2 = m2->prob[node];
        unsigned v = (value >> i) & 1u;

        if ((prod1 | prod2) & ((1024u - 1u) << (32 - 10))) {
            prod1 >>= 10;
            prod2 >>= 10;
        }
        prod1 *= v ? (1024u - p1) : p1;
        prod2 *= v ? (1024u - p2) : p2;
        node = (node << 1) | v;
    }
    r = (prod1 > prod2) - (prod1 < prod2);
    if (r > 0) pp->lucky[pre]++;
    else if (r < 0) pp->lucky[pre]--;
}

/* A.11.2, writing side: length -> code index. */
static unsigned azo_len_code(uint32_t len)
{
    uint32_t v = len - 2;

    if (v < 32)
        return v;
    v -= 32;
    {
        uint32_t k = (uint32_t)azo_ilog2(v / 8 + 1);

        return 32 + k * 8 + (v - ((1u << k) - 1) * 8) / (1u << k);
    }
}

/* --- finder: 3 progressive hash levels, one candidate per slot ------------- */

typedef struct {
    int32_t *tbl[AZO_LEVELS];             /* (1 << AZO_SHIFT) slots/level */
    uint32_t bucket[AZO_LEVELS];          /* hashes of the current position */
    long     last;                        /* last inserted position */
    unsigned h[AZO_LEVELS];
} AzoFind;

static unsigned azo_sm16(const uint8_t *d, size_t o)
{
    unsigned v = (unsigned)d[o] | ((unsigned)d[o + 1] << 8);

    return (v & 0x8000u) ? (v | 0xFFFF0000u) : v;
}

static uint32_t azo_u32(const uint8_t *d, size_t o)
{
    return (uint32_t)d[o] | ((uint32_t)d[o + 1] << 8) |
           ((uint32_t)d[o + 2] << 16) | ((uint32_t)d[o + 3] << 24);
}

/* Hashes of position `pos` (widths 2, 4 then 8 bytes). Levels whose prefix runs
 * past the end of the block are not computed (0x61905430 breaks out of its
 * loop), exactly like the reference encoder. */
static void finder_hashes(AzoFind *f, const uint8_t *d, size_t n, size_t pos)
{
    uint32_t h;
    size_t   p;
    int      i;

    for (i = 0; i < AZO_LEVELS; i++)
        f->h[i] = 0xFFFFFFFFu;
    if (pos + 2 > n)
        return;
    h = ((uint32_t)d[pos] << 8) | d[pos + 1];
    f->h[0] = ((h >> AZO_SHIFT) ^ h) & AZO_HASH_MASK;
    p = pos + 2;
    if (p + 2 > n)
        return;
    h = (h * 33u + azo_sm16(d, p)) & AZO_MASK;
    f->h[1] = ((h >> AZO_SHIFT) ^ h) & AZO_HASH_MASK;
    p += 2;
    for (i = 2; i < AZO_LEVELS; i++) {
        size_t ext = (size_t)1 << i;
        size_t k;

        if (p + ext > n)
            break;
        for (k = 0; k < (ext >> 2); k++) {
            h = (h * 33u + azo_u32(d, p)) & AZO_MASK;
            p += 4;
        }
        f->h[i] = ((h >> AZO_SHIFT) ^ h) & AZO_HASH_MASK;
    }
}

static void finder_insert_upto(AzoFind *f, const uint8_t *d, size_t n,
                               size_t pos)
{
    while (f->last < (long)pos) {
        int i;

        f->last++;
        finder_hashes(f, d, n, (size_t)f->last);
        for (i = 0; i < AZO_LEVELS; i++)
            if (f->h[i] != 0xFFFFFFFFu)
                f->tbl[i][f->h[i]] = (int32_t)f->last;
    }
}

/* ================================================================ bloc ====== */

static int azo_err(char *err, size_t errsz, const char *msg)
{
    if (err && errsz)
        snprintf(err, errsz, "AZO : %s", msg);
    return -1;
}

static int azo_decode_block(const uint8_t *comp, size_t csize, uint8_t *out,
                            size_t usize, char *err, size_t errsz)
{
    AzoDec  d;
    AzoBool matchFlag, reuseFlag, shortReuse, shortDist;
    AzoEbp  idxShort, idxLong, distShort, distLong;
    AzoPp   alpha, lengths;
    AzoEbp *alpha_fine = NULL, *alpha_coarse = NULL;
    AzoEbp *len_fine = NULL, *len_coarse = NULL;
    int    *alpha_lucky = NULL, *len_lucky = NULL;
    uint32_t len_rep[128], pos_rep[128], dist_rep[2], match_rep[2];
    AzoHist  lenHist, posHist, recentDist, recentMatch;
    size_t   i = 0;
    int      rc = -1;

    azo_build_tables();
    azo_init(&d, comp, csize);
    /* Four distinct boolean models — decoding the reference sample confirms it:
     * sharing them (any other topology) diverges at the first misplaced byte. */
    ab_init(&matchFlag);
    ab_init(&reuseFlag);
    ab_init(&shortReuse);
    ab_init(&shortDist);
    ebp_init(&idxShort, 1);
    ebp_init(&idxLong, 7);
    ebp_init(&distShort, 1);
    ebp_init(&distLong, 7);

    alpha_fine = calloc(256, sizeof *alpha_fine);
    alpha_coarse = calloc(8, sizeof *alpha_coarse);
    alpha_lucky = calloc(256, sizeof *alpha_lucky);
    len_fine = calloc(128, sizeof *len_fine);
    len_coarse = calloc(8, sizeof *len_coarse);
    len_lucky = calloc(128, sizeof *len_lucky);
    if (!alpha_fine || !alpha_coarse || !alpha_lucky ||
        !len_fine || !len_coarse || !len_lucky) {
        azo_err(err, errsz, "out of memory");
        goto done;
    }
    for (int k = 0; k < 256; k++) ebp_init(&alpha_fine[k], 8);
    for (int k = 0; k < 8; k++)   ebp_init(&alpha_coarse[k], 8);
    for (int k = 0; k < 128; k++) ebp_init(&len_fine[k], 7);
    for (int k = 0; k < 8; k++)   ebp_init(&len_coarse[k], 7);
    alpha.fine = alpha_fine; alpha.coarse = alpha_coarse; alpha.lucky = alpha_lucky;
    lengths.fine = len_fine; lengths.coarse = len_coarse; lengths.lucky = len_lucky;

    hist_init(&lenHist, len_rep, 128, 2, 1);
    hist_init(&posHist, pos_rep, 128, 0, 0);
    hist_init(&recentDist, dist_rep, 2, 1, 1);
    hist_init(&recentMatch, match_rep, 2, 0, 1);

    if (usize == 0) {
        rc = 0;
        goto done;
    }

    out[0] = (uint8_t)pp_decode(&d, &alpha, 0, 8, 5);
    i = 1;
    while (i < usize) {
        if (!ab_decode(&d, &matchFlag)) {
            out[i] = (uint8_t)pp_decode(&d, &alpha, out[i - 1], 8, 5);
            i++;
            continue;
        }

        size_t   distance, length;

        if (ab_decode(&d, &reuseFlag)) {
            unsigned hidx;

            if (ab_decode(&d, &shortReuse))
                hidx = hist_take(&recentMatch, (int)ebp_decode(&d, &idxShort));
            else {
                hidx = ebp_decode(&d, &idxLong);
                hist_add(&recentMatch, hidx);
            }
            length = hist_take(&lenHist, (int)hidx);
            distance = i - hist_take(&posHist, (int)hidx);
        } else {
            if (ab_decode(&d, &shortDist)) {
                distance = hist_take(&recentDist, (int)ebp_decode(&d, &distShort));
            } else {
                unsigned code = ebp_decode(&d, &distLong);

                distance = azo_dist_base[code];
                if (azo_dist_extra[code])
                    distance += azo_decode_uniform(&d, azo_dist_extra[code]);
                hist_add(&recentDist, (uint32_t)distance);
            }
            if (distance == 0 || distance > i) {
                azo_err(err, errsz, "distance invalide");
                goto done;
            }
            unsigned code = azo_dist_code((uint32_t)distance);
            unsigned lcode = pp_decode(&d, &lengths, (int)code, 7, 4);

            length = azo_len_base[lcode];
            if (azo_len_extra[lcode])
                length += azo_decode_uniform(&d, azo_len_extra[lcode]);
            hist_add(&lenHist, (uint32_t)length);
            hist_add(&posHist, (uint32_t)i);
        }

        if (distance == 0 || distance > i) {
            azo_err(err, errsz, "distance invalide");
            goto done;
        }
        if (length > usize - i)
            length = usize - i;           /* truncated: reported by the caller */
        while (length--) {
            out[i] = out[i - distance];
            i++;
        }
    }

    rc = 0;

done:
    free(alpha_fine);
    free(alpha_coarse);
    free(alpha_lucky);
    free(len_fine);
    free(len_coarse);
    free(len_lucky);
    return rc;
}

/* -------------------------------------------------- parseur + codage bloc -- */

typedef struct {
    AzoEnc         enc;
    const uint8_t *d;
    size_t         n;
    AzoBool        matchFlag, reuseFlag, shortReuse, shortDist;
    AzoEbp         idxShort, idxLong, distShort, distLong;
    AzoPp          alpha, lengths;
    AzoEbp        *alpha_fine, *alpha_coarse, *len_fine, *len_coarse;
    int           *alpha_lucky, *len_lucky;
    uint32_t       len_rep[128], pos_rep[128], dist_rep[2], match_rep[2];
    AzoHist        lenHist, posHist, recentDist, recentMatch;
    AzoFind        find;
    int32_t       *tbl[AZO_LEVELS];
    int            pending;
    uint32_t       pend_dist, pend_len;
} AzoEncCtx;

static size_t finder_match_len(const uint8_t *d, size_t n, size_t cand,
                               size_t pos, size_t minlen)
{
    size_t L = minlen, max;

    if (cand + minlen > n || pos + minlen > n)
        return 0;
    if (memcmp(d + cand, d + pos, minlen) != 0)
        return 0;
    max = n - pos;
    if (max > AZO_MAXLEN)
        max = AZO_MAXLEN;
    while (L < max && d[cand + L] == d[pos + L])
        L++;
    return L;
}

/* Cost of a literal of `len` bytes at `pos`: product of the alpha model
 * probabilities, times P(matchFlag = 0). */
static double ctx_lit_prob(AzoEncCtx *c, size_t pos, size_t len)
{
    double p = 1.0;
    size_t i;

    for (i = pos; i < pos + len; i++)
        p *= pp_prob(&c->alpha, c->d[i - 1], 5, c->d[i]);
    return p * (double)c->matchFlag.prob[c->matchFlag.state] / 4096.0;
}

/* exact 2^-n, without libm. */
static double azo_half_pow(int n)
{
    double v = 1.0;

    while (n-- > 0)
        v *= 0.5;
    return v;
}

/* Cost of a match: P(matchFlag = 1) x distance code x length code, each code
 * multiplied by the uniform probability of its extra bits. The two 1/2 factors
 * (ALZip's {1,0,1} price for the literal side and the match side, cf.
 * 0x61904460) cancel out: the expression stays the one of the validated
 * prototype. */
static double ctx_match_prob(AzoEncCtx *c, uint32_t dist, size_t len)
{
    unsigned code = azo_dist_code(dist);
    unsigned lc = azo_len_code((uint32_t)len);
    double   pd = ebp_prob(&c->distLong, code) * azo_half_pow(azo_dist_extra[code] + 1);
    double   pl = pp_prob(&c->lengths, (int)code, 4, lc) * azo_half_pow(azo_len_extra[lc]);
    double   q = (double)c->matchFlag.prob[c->matchFlag.state] / 4096.0;

    return (1.0 - q) * pd * 0.5 * pl;
}

/* Search 0x61905a90: from the widest level to the narrowest, one candidate per
 * level; stops at the first accepted one (threshold 2, otherwise a cost
 * test). */
static void ctx_search(AzoEncCtx *c, size_t pos, uint32_t *dist, size_t *len)
{
    int i;

    *dist = 0;
    *len = 0;
    if (pos + 2 > c->n)
        return;
    finder_insert_upto(&c->find, c->d, c->n, pos - 1);
    finder_hashes(&c->find, c->d, c->n, pos);
    for (i = AZO_LEVELS - 1; i >= 0; i--) {
        uint32_t hv = c->find.h[i];
        int32_t  cand;
        size_t   L;

        if (hv == 0xFFFFFFFFu)
            continue;
        cand = c->find.tbl[i][hv];
        if (cand < 0)
            continue;
        if (pos - (size_t)cand > AZO_DISTLIM)
            continue;
        L = finder_match_len(c->d, c->n, (size_t)cand, pos, (size_t)1 << (i + 1));
        if (!L)
            continue;
        if (L > AZO_THRESHOLD ||
            ctx_lit_prob(c, pos, L) * 0.5 < ctx_match_prob(c, pos - (uint32_t)cand, L)) {
            *dist = (uint32_t)(pos - (size_t)cand);
            *len = L;
            return;
        }
    }
}

static void ctx_literal(AzoEncCtx *c, size_t i)
{
    ab_encode(&c->enc, &c->matchFlag, 0);
    pp_encode(&c->enc, &c->alpha, c->d[i - 1], 8, 5, c->d[i]);
}

/* `reuse` >= 0: reuse of the remembered pair at index `reuse`.
 * Otherwise a fresh match of distance `dist` and length `len`. */
static void ctx_match(AzoEncCtx *c, uint32_t dist, size_t len, int reuse)
{
    ab_encode(&c->enc, &c->matchFlag, 1);
    if (reuse >= 0) {
        ab_encode(&c->enc, &c->reuseFlag, 1);
        if (reuse == (int)c->match_rep[0] || reuse == (int)c->match_rep[1]) {
            unsigned slot = reuse == (int)c->match_rep[0] ? 0u : 1u;

            ab_encode(&c->enc, &c->shortReuse, 1);
            ebp_encode(&c->enc, &c->idxShort, slot);
            hist_take(&c->recentMatch, (int)slot);
        } else {
            ab_encode(&c->enc, &c->shortReuse, 0);
            ebp_encode(&c->enc, &c->idxLong, (unsigned)reuse);
            hist_add(&c->recentMatch, (uint32_t)reuse);
        }
        return;
    }

    ab_encode(&c->enc, &c->reuseFlag, 0);
    if (dist == c->dist_rep[0] || dist == c->dist_rep[1]) {
        unsigned slot = dist == c->dist_rep[0] ? 0u : 1u;

        ab_encode(&c->enc, &c->shortDist, 1);
        ebp_encode(&c->enc, &c->distShort, slot);
        hist_take(&c->recentDist, (int)slot);
    } else {
        unsigned code = azo_dist_code(dist);

        ab_encode(&c->enc, &c->shortDist, 0);
        ebp_encode(&c->enc, &c->distLong, code);
        if (azo_dist_extra[code])
            enc_uniform(&c->enc, azo_dist_extra[code], dist - azo_dist_base[code]);
        hist_add(&c->recentDist, dist);
    }
    {
        unsigned code = azo_dist_code(dist);
        unsigned lc = azo_len_code((uint32_t)len);

        pp_encode(&c->enc, &c->lengths, (int)code, 7, 4, lc);
        if (azo_len_extra[lc])
            enc_uniform(&c->enc, azo_len_extra[lc], (uint32_t)len - azo_len_base[lc]);
    }
}

/* First remembered pair whose length is EXACTLY equal to the fresh match and
 * whose source agrees (ALZip's pair finder); -1 when none. */
static int ctx_best_pair(AzoEncCtx *c, size_t pos, size_t len)
{
    int i;

    for (i = 0; i < 128; i++) {
        uint32_t p;

        if (c->lenHist.rep[i] != len)
            continue;
        p = c->posHist.rep[i];
        if (p >= pos)
            continue;
        if (pos + len > c->n || p + len > c->n)
            continue;
        if (memcmp(c->d + p, c->d + pos, len) != 0)
            continue;
        return i;
    }
    return -1;
}

/* One parser step (0x61905bf0): returns the number of bytes consumed. */
static size_t ctx_step(AzoEncCtx *c, size_t pos)
{
    uint32_t dist = 0, nd = 0;
    size_t   len = 0, nl = 0;
    int      idx;

    if (c->pending) {
        dist = c->pend_dist;
        len = c->pend_len;
        c->pending = 0;
    } else {
        ctx_search(c, pos, &dist, &len);
    }
    if (len && pos < c->n - 1) {
        ctx_search(c, pos + 1, &nd, &nl);
        if (nl > len) {
            c->pending = 1;
            c->pend_dist = nd;
            c->pend_len = nl;
            len = 1;
        }
    }
    if (len < 2) {
        ctx_literal(c, pos);
        return 1;
    }
    idx = ctx_best_pair(c, pos, len);
    if (idx >= 0) {
        uint32_t l2, p2;

        l2 = hist_take(&c->lenHist, idx);
        p2 = hist_take(&c->posHist, idx);
        ctx_match(c, (uint32_t)(pos - p2), l2, idx);
        return l2;
    }
    hist_add(&c->lenHist, (uint32_t)len);
    hist_add(&c->posHist, (uint32_t)pos);
    ctx_match(c, dist, len, -1);
    return len;
}

/* ================================================================ flux ====== */

static uint32_t be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

int egg_azo_decode(const uint8_t *src, size_t csize, uint8_t *dst, size_t usize,
                   char *err, size_t errsz)
{
    size_t   pos = 0, out = 0;
    unsigned flags;

    if (csize < 2)
        return azo_err(err, errsz, "stream shorter than 2 bytes");
    if (src[0] != '1')
        return azo_err(err, errsz, "unknown stream version");
    flags = src[1];
    pos = 2;

    for (;;) {
        uint32_t bus, bcs, chk;

        if (pos + 12 > csize)
            return azo_err(err, errsz, "truncated block header");
        bus = be32(src + pos);
        bcs = be32(src + pos + 4);
        chk = be32(src + pos + 8);
        pos += 12;

        if (!bus && !bcs)
            break;                        /* bloc terminal */
        if ((bus ^ bcs) != chk)
            return azo_err(err, errsz, "invalid size check");
        if (bus > usize - out)
            return azo_err(err, errsz, "block larger than the member");
        if (bcs > csize - pos)
            return azo_err(err, errsz, "truncated block");

        if (bcs == bus)
            memcpy(dst + out, src + pos, bus);
        else if (azo_decode_block(src + pos, bcs, dst + out, bus, err, errsz))
            return -1;
        pos += bcs;
        out += bus;
        if (flags & 1)
            azo_x86_filter(dst + out - bus, bus, 0);
    }

    if (out != usize)
        return azo_err(err, errsz, "unexpected decompressed size");
    return 0;
}

/* ======================================================== codage des blocs == */

static void put_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static int ctx_init(AzoEncCtx *c, const uint8_t *d, size_t n,
                    int32_t *tbl[AZO_LEVELS])
{
    int i;

    memset(c, 0, sizeof *c);
    c->d = d;
    c->n = n;
    enc_init(&c->enc);
    ab_init(&c->matchFlag);
    ab_init(&c->reuseFlag);
    ab_init(&c->shortReuse);
    ab_init(&c->shortDist);
    ebp_init(&c->idxShort, 1);
    ebp_init(&c->idxLong, 7);
    ebp_init(&c->distShort, 1);
    ebp_init(&c->distLong, 7);

    c->alpha_fine = calloc(256, sizeof *c->alpha_fine);
    c->alpha_coarse = calloc(8, sizeof *c->alpha_coarse);
    c->alpha_lucky = calloc(256, sizeof *c->alpha_lucky);
    c->len_fine = calloc(128, sizeof *c->len_fine);
    c->len_coarse = calloc(8, sizeof *c->len_coarse);
    c->len_lucky = calloc(128, sizeof *c->len_lucky);
    if (!c->alpha_fine || !c->alpha_coarse || !c->alpha_lucky ||
        !c->len_fine || !c->len_coarse || !c->len_lucky)
        return -1;
    for (i = 0; i < 256; i++) ebp_init(&c->alpha_fine[i], 8);
    for (i = 0; i < 8; i++)   ebp_init(&c->alpha_coarse[i], 8);
    for (i = 0; i < 128; i++) ebp_init(&c->len_fine[i], 7);
    for (i = 0; i < 8; i++)   ebp_init(&c->len_coarse[i], 7);
    c->alpha.fine = c->alpha_fine;
    c->alpha.coarse = c->alpha_coarse;
    c->alpha.lucky = c->alpha_lucky;
    c->lengths.fine = c->len_fine;
    c->lengths.coarse = c->len_coarse;
    c->lengths.lucky = c->len_lucky;

    hist_init(&c->lenHist, c->len_rep, 128, 2, 1);
    hist_init(&c->posHist, c->pos_rep, 128, 0, 0);
    hist_init(&c->recentDist, c->dist_rep, 2, 1, 1);
    hist_init(&c->recentMatch, c->match_rep, 2, 0, 1);

    for (i = 0; i < AZO_LEVELS; i++) {
        c->find.tbl[i] = tbl[i];
        memset(tbl[i], 0xFF, ((size_t)1 << AZO_SHIFT) * sizeof *tbl[i]);
    }
    c->find.last = -1;
    return 0;
}

static void ctx_free(AzoEncCtx *c)
{
    free(c->alpha_fine);
    free(c->alpha_coarse);
    free(c->alpha_lucky);
    free(c->len_fine);
    free(c->len_coarse);
    free(c->len_lucky);
}

/* Encodes ONE block (at most 2^19 bytes) into `out` (zeroed). */
static int azo_encode_block(const uint8_t *d, size_t n, AzoBuf *out,
                            int32_t *tbl[AZO_LEVELS], char *err, size_t errsz)
{
    AzoEncCtx *c = malloc(sizeof *c);
    size_t     i;

    if (!c)
        return azo_err(err, errsz, "out of memory");
    if (ctx_init(c, d, n, tbl)) {
        ctx_free(c);
        free(c);
        return azo_err(err, errsz, "out of memory");
    }

    if (n) {
        pp_encode(&c->enc, &c->alpha, 0, 8, 5, d[0]);
        i = 1;
        while (i < n)
            i += ctx_step(c, i);
    }
    enc_flush(&c->enc);

    *out = c->enc.out;                    /* the buffer goes to the caller */
    ctx_free(c);
    free(c);
    if (out->oom) {
        free(out->p);
        memset(out, 0, sizeof *out);
        return azo_err(err, errsz, "out of memory");
    }
    return 0;
}

/* ============================================================== flux ======= */

int egg_azo_encode_range(const char *path, uint64_t off, uint64_t len,
                         FILE **blob, uint64_t *csize, uint32_t *crc,
                         char *err, size_t errsz)
{
    FILE    *f = NULL, *tmp = NULL;
    uint8_t *buf = NULL;
    int32_t *tbl[AZO_LEVELS] = {NULL, NULL, NULL};
    AzoBuf   enc;
    uint64_t left = len, total = 0;
    uint32_t c = (uint32_t)crc32(0L, Z_NULL, 0);
    uint8_t  mz[2];
    int      flags = 0, i, rc = -1;
    static const uint8_t zeros[12] = {0};

    azo_build_tables();
    memset(&enc, 0, sizeof enc);
    f = fopen(path, "rb");
    tmp = tmpfile();
    if (!f || !tmp) {
        if (err && errsz) snprintf(err, errsz, "%s : %s", path, strerror(errno));
        goto done;
    }
    if (off && fseeko(f, (off_t)off, SEEK_SET) != 0) {
        if (err && errsz)
            snprintf(err, errsz, "%s : position %llu illisible", path,
                     (unsigned long long)off);
        goto done;
    }
    buf = malloc(AZO_BLOCKSIZE);
    for (i = 0; i < AZO_LEVELS; i++)
        tbl[i] = malloc(((size_t)1 << AZO_SHIFT) * sizeof *tbl[i]);
    if (!buf || !tbl[0] || !tbl[1] || !tbl[2]) {
        azo_err(err, errsz, "out of memory");
        goto done;
    }

    /* x86 filter flag: AZO.dll sets it from the CONTENT, not from the extension
     * — 0x61907410 returns 1 if (and only if) the first buffer presented starts
     * with "MZ", the DOS/PE signature; `0x31` is written at 0x61907869 and the
     * flag at 0x61907892 (`31 01` / `31 00`). The corpus .sys/.com references
     * are text, hence their flag 0: the route really is .sys/.com, the filter
     * depends on the file. The flag holds for the whole stream: following slices
     * are filtered even when they do not start with MZ (state [this+0x2a] is
     * sticky). */
    if (len >= 2 && fread(mz, 1, 2, f) == 2 && mz[0] == 'M' && mz[1] == 'Z')
        flags = 1;
    if (fseeko(f, (off_t)off, SEEK_SET) != 0) {
        if (err && errsz)
            snprintf(err, errsz, "%s : position %llu illisible", path,
                     (unsigned long long)off);
        goto done;
    }
    if (fwrite(flags ? "1\1" : "1\0", 1, 2, tmp) != 2) {
        if (err && errsz)
            snprintf(err, errsz, "temporary file: %s", strerror(errno));
        goto done;
    }
    total = 2;

    while (left) {
        size_t  want = left < AZO_BLOCKSIZE ? (size_t)left : AZO_BLOCKSIZE;
        uint8_t hdr[12];
        size_t  n;

        if (fread(buf, 1, want, f) != want) {
            if (err && errsz)
                snprintf(err, errsz, "%s: short read (%llu bytes "
                                     "left)", path, (unsigned long long)left);
            goto done;
        }
        c = (uint32_t)crc32(c, buf, (unsigned)want);   /* ORIGINAL data */
        if (flags)
            azo_x86_filter(buf, want, 1);
        if (azo_encode_block(buf, want, &enc, tbl, err, errsz))
            goto done;
        if (enc.len >= want) {             /* no gain: block copied */
            const uint8_t *src = buf;

            put_be32(hdr, (uint32_t)want);
            put_be32(hdr + 4, (uint32_t)want);
            put_be32(hdr + 8, 0);
            n = want;
            if (fwrite(hdr, 1, 12, tmp) != 12 ||
                fwrite(src, 1, n, tmp) != n) {
                if (err && errsz)
                    snprintf(err, errsz, "temporary file: %s", strerror(errno));
                goto done;
            }
        } else {
            put_be32(hdr, (uint32_t)want);
            put_be32(hdr + 4, (uint32_t)enc.len);
            put_be32(hdr + 8, (uint32_t)(want ^ enc.len));
            n = enc.len;
            if (fwrite(hdr, 1, 12, tmp) != 12 ||
                fwrite(enc.p, 1, n, tmp) != n) {
                if (err && errsz)
                    snprintf(err, errsz, "temporary file: %s", strerror(errno));
                goto done;
            }
        }
        total += 12 + n;
        free(enc.p);
        memset(&enc, 0, sizeof enc);
        left -= want;
    }

    if (fwrite(zeros, 1, sizeof zeros, tmp) != sizeof zeros) {
        if (err && errsz)
            snprintf(err, errsz, "temporary file: %s", strerror(errno));
        goto done;
    }
    total += sizeof zeros;

    if (fflush(tmp) || fseeko(tmp, 0, SEEK_SET) != 0) {
        if (err && errsz)
            snprintf(err, errsz, "temporary file: %s", strerror(errno));
        goto done;
    }
    *blob  = tmp;
    *csize = total;
    *crc   = c;
    tmp = NULL;
    rc = 0;

done:
    for (i = 0; i < AZO_LEVELS; i++)
        free(tbl[i]);
    free(buf);
    free(enc.p);
    if (f) fclose(f);
    if (tmp) fclose(tmp);
    return rc;
}
