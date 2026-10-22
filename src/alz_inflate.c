/* alz_inflate.c — home-grown inflate for the RAW deflate (RFC1951) of ALZ members.
 *
 * Covers container method 2, the only one the GUI's ALZ profiles produce (see
 * FORMAT-ALZ.md). No scrambled code order here: the corpus members are standard
 * deflate, checked byte for byte.
 *
 * Two outputs: `alz_inflate()` fills a buffer of the member's exact size,
 * `alz_inflate_to()` pushes bytes to a `stream_sink_fn` in 64 KiB slices, which
 * allows a member or a solid stream of several GiB to be decoded without ever
 * holding it in memory. The 32 KiB window is the same in both cases: it is what
 * makes the deflate decodable, not the output buffer.
 */
#include "alz_inflate.h"

#include <stdlib.h>
#include <string.h>

/* ---------- lecteur de bits ---------- */
typedef struct BitR {
    const uint8_t *buf;
    size_t size;          /* bytes available */
    size_t pos;           /* current byte */
    uint64_t acc;         /* bit accumulator (least significant bit = next) */
    int nbits;            /* valid bits in acc */
    int err;
} BitR;

static void bfill(BitR *b)
{
    while (b->nbits <= 56 && b->pos < b->size) {
        b->acc |= (uint64_t)b->buf[b->pos++] << b->nbits;
        b->nbits += 8;
    }
}

static int bneed(BitR *b, int n)
{
    if (b->nbits < n) { bfill(b); if (b->nbits < n) { b->err = 1; return 0; } }
    return 1;
}

static uint32_t bget(BitR *b, int n)
{
    uint32_t v;
    if (!bneed(b, n)) return 0;
    v = (uint32_t)(b->acc & (((uint64_t)1 << n) - 1));
    b->acc >>= n; b->nbits -= n;
    return v;
}

static void binit(BitR *b, const uint8_t *buf, size_t size)
{
    memset(b, 0, sizeof(*b));
    b->buf = buf; b->size = size;
}

/* no point byte-aligning a complete stream; trailing bytes are ignored */

/* --------- canonical Huffman decoder (RFC1951 style) ---------- */
#define MAX_BITS 15
typedef struct Huff {
    int16_t count[MAX_BITS + 1];   /* nb de codes par longueur */
    int16_t symbol[288 + 30 + 2];  /* symbols sorted by (canonical code) */
    int fast[MAX_BITS + 1];        /* first code value per length */
} Huff;

static int huff_build(Huff *h, const uint8_t *lengths, int n)
{
    int i, len, offs[MAX_BITS + 2];
    memset(h, 0, sizeof(*h));
    for (i = 0; i < n; ++i) h->count[lengths[i]]++;
    h->count[0] = 0;
    /* over-subscription: left starting at 1 = a possible zero-length code (puff) */
    {
        int left = 1;
        for (i = 1; i <= MAX_BITS; ++i) {
            left <<= 1;
            left -= h->count[i];
            if (left < 0) return -1;              /* codes over-subscribed */
        }
        /* left > 0: incomplete set — tolerated here, the decoder will reject if real */
    }
    /* offset per length */
    offs[1] = 0;
    for (i = 1; i < MAX_BITS; ++i) offs[i + 1] = offs[i] + h->count[i];
    for (i = 0; i < n; ++i) if (lengths[i]) h->symbol[offs[lengths[i]]++] = (int16_t)i;
    /* first code values per length (for incremental decoding) */
    {
        int code = 0;
        for (len = 1; len <= MAX_BITS; ++len) {
            code = (code + h->count[len - 1]) << 1;
            h->fast[len] = code;
        }
    }
    return 0;
}

/* decodes one symbol; returns -1 on error */
static int huff_decode(BitR *b, const Huff *h)
{
    int len, code = 0, first = 0, index = 0, count;
    for (len = 1; len <= MAX_BITS; ++len) {
        code |= (int)bget(b, 1);
        count = h->count[len];
        if (code - first < count) return h->symbol[index + (code - first)];
        index += count;
        first += count; first <<= 1;
        code <<= 1;
        if (b->err) return -1;
    }
    return -1;
}

/* ---------- tables RFC1951 ---------- */
static const uint16_t len_base[29]  = {3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,67,83,99,115,131,163,195,227,258};
static const uint8_t  len_extra[29] = {0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0};
static const uint16_t dist_base[30] = {1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,769,1025,1537,2049,3073,4097,6145,8193,12289,16385,24577};
static const uint8_t  dist_extra[30]= {0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13};

static const uint8_t STD_ORDER[19] = {
    16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15
};

#define MAX_SYM_LIT 288
#define MAX_SYM_DIST 32

/* Slice pushed to the sink: large enough for the call to be free, small enough
 * to stay negligible next to a reader's window. */
#define SINK_CHUNK (64u * 1024u)

typedef struct AlzInflate {
    BitR b;
    Huff lit, dist, clen;
    uint8_t order[19];
    /* circular output window (32K) */
    unsigned char win[32768];
    size_t wpos;          /* circular position */
    uint64_t total;
    unsigned char *out;   /* buffer mode: exact size known */
    size_t out_size, out_off;
    stream_sink_fn sink;  /* stream mode: one or the other, never both */
    void *sink_ctx;
    unsigned char stage[SINK_CHUNK];
    size_t stage_len;
} AlzInflate;

static int flush_stage(AlzInflate *s)
{
    if (!s->stage_len) return 0;
    if (s->sink(s->sink_ctx, s->stage, s->stage_len)) {
        s->stage_len = 0;
        s->b.err = 1;
        return -1;
    }
    s->stage_len = 0;
    return 0;
}

static void put_byte(AlzInflate *s, unsigned char c)
{
    s->win[s->wpos] = c;
    s->wpos = (s->wpos + 1) & 32767;
    if (s->sink) {
        s->stage[s->stage_len++] = c;
        if (s->stage_len == sizeof s->stage) flush_stage(s);
    } else if (s->out && s->out_off < s->out_size) {
        s->out[s->out_off++] = c;
    }
    s->total++;
}

static void copy_match(AlzInflate *s, int length, int distance)
{
    int i;
    if (distance == 0 || (size_t)distance > 32768) { s->b.err = 1; return; }
    if ((uint64_t)distance > s->total) { s->b.err = 1; return; }
    for (i = 0; i < length; ++i) {
        unsigned char c = s->win[(s->wpos - distance) & 32767];
        put_byte(s, c);
        if (s->b.err) return;
    }
}

/* reads a dynamic block; order = length order of the "code length code" */
static int read_dynamic_block(AlzInflate *s, const uint8_t *order)
{
    int hlit  = (int)bget(&s->b, 5) + 257;
    int hdist = (int)bget(&s->b, 5) + 1;
    int hclen = (int)bget(&s->b, 4) + 4;
    uint8_t clen_l[MAX_SYM_LIT + MAX_SYM_DIST];
    uint8_t clen_lengths[19];
    int i, sym, len;
    if (s->b.err || hlit > MAX_SYM_LIT || hdist > MAX_SYM_DIST) return -1;
    for (i = 0; i < hclen; ++i)
        clen_lengths[order[i]] = (uint8_t)bget(&s->b, 3);
    for (; i < 19; ++i) clen_lengths[order[i]] = 0;
    if (huff_build(&s->clen, clen_lengths, 19) < 0) return -1;

    i = 0;
    while (i < hlit + hdist) {
        sym = huff_decode(&s->b, &s->clen);
        if (sym < 0) return -1;
        if (sym < 16) { clen_l[i++] = (uint8_t)sym; }
        else if (sym == 16) {
            if (i == 0) return -1;
            len = 3 + (int)bget(&s->b, 2);
            { uint8_t prev = clen_l[i - 1]; while (len-- && i < hlit + hdist) clen_l[i++] = prev; }
        } else if (sym == 17) {
            len = 3 + (int)bget(&s->b, 3);
            while (len-- && i < hlit + hdist) clen_l[i++] = 0;
        } else { /* 18 */
            len = 11 + (int)bget(&s->b, 7);
            while (len-- && i < hlit + hdist) clen_l[i++] = 0;
        }
        if (s->b.err) return -1;
    }
    if (clen_l[256] == 0) return -1;             /* no end-of-block code */
    if (huff_build(&s->lit, clen_l, hlit) < 0) return -1;
    if (huff_build(&s->dist, clen_l + hlit, hdist) < 0) return -1;

    for (;;) {
        sym = huff_decode(&s->b, &s->lit);
        if (sym < 0) return -1;
        if (sym < 256) put_byte(s, (unsigned char)sym);
        else if (sym == 256) return 0;
        else {
            int li = sym - 257, dsym, length, dist;
            if (li >= 29) return -1;
            length = len_base[li] + (int)bget(&s->b, len_extra[li]);
            dsym = huff_decode(&s->b, &s->dist);
            if (dsym < 0 || dsym >= 30) return -1;
            dist = dist_base[dsym] + (int)bget(&s->b, dist_extra[dsym]);
            copy_match(s, length, dist);
            if (s->b.err) return -1;
        }
    }
}

static int read_static_block(AlzInflate *s)
{
    uint8_t lit_l[MAX_SYM_LIT], dist_l[MAX_SYM_DIST];
    int i;
    for (i = 0;   i < 144; ++i) lit_l[i] = 8;
    for (;       i < 256; ++i) lit_l[i] = 9;
    for (;       i < 280; ++i) lit_l[i] = 7;
    for (;       i < 288; ++i) lit_l[i] = 8;
    for (i = 0;  i < 30;  ++i) dist_l[i] = 5;
    (void)huff_build(&s->lit, lit_l, 288);
    (void)huff_build(&s->dist, dist_l, 30);
    /* symbols 30/31 are invalid distances in a static stream — checked on decode */
    for (;;) {
        int sym = huff_decode(&s->b, &s->lit);
        if (sym < 0) return -1;
        if (sym < 256) put_byte(s, (unsigned char)sym);
        else if (sym == 256) return 0;
        else {
            int li = sym - 257, dsym, length, dist;
            if (li >= 29) return -1;
            length = len_base[li] + (int)bget(&s->b, len_extra[li]);
            dsym = huff_decode(&s->b, &s->dist);
            if (dsym < 0 || dsym >= 30) return -1;
            dist = dist_base[dsym] + (int)bget(&s->b, dist_extra[dsym]);
            copy_match(s, length, dist);
            if (s->b.err) return -1;
        }
    }
}

static int read_stored_block(AlzInflate *s)
{
    int len, nl;
    bget(&s->b, s->b.nbits & 7);   /* byte-align: drop the remaining bits */
    len = (int)bget(&s->b, 16);
    nl  = (int)bget(&s->b, 16);
    if (s->b.err || (len ^ 0xFFFF) != nl) return -1;
    /* accumulate byte by byte (the accumulator is already byte-aligned) */
    while (len--) {
        if (!bneed(&s->b, 8)) return -1;
        put_byte(s, (unsigned char)bget(&s->b, 8));
    }
    return 0;
}

/* Decodes the whole stream, pushing the output to s->out or s->sink. */
static int inflate_run(AlzInflate *s)
{
    int final = 0;

    memcpy(s->order, STD_ORDER, 19);
    do {
        if (!bneed(&s->b, 3)) return -1;
        final = (int)bget(&s->b, 1);
        switch (bget(&s->b, 2)) {
            case 0: if (read_stored_block(s) < 0) return -1; break;
            case 1: if (read_static_block(s) < 0) return -1; break;
            case 2: if (read_dynamic_block(s, s->order) < 0) return -1; break;
            default: return -1;
        }
        if (s->b.err) return -1;
    } while (!final);
    return 0;
}

/* full inflate of a raw deflate stream (container method 2).
 * out/out_size: output buffer (must have the exact usize size).
 * Returns: 0 = OK, -1 = error.
 */
int alz_inflate(const uint8_t *in, size_t in_size,
                unsigned char *out, size_t out_size)
{
    AlzInflate s;

    memset(&s, 0, sizeof(s));
    binit(&s.b, in, in_size);
    s.out = out; s.out_size = out_size;
    if (inflate_run(&s) < 0) return -1;
    return (s.out_off == out_size) ? 0 : (out_size ? -1 : 0);
}

/* Streaming variant: every produced slice goes to the sink, nothing is kept
 * beyond the 32 KiB window and the 64 KiB buffer. `expect` is the expected
 * decompressed size (usize); `produced` (optional) receives it. */
int alz_inflate_to(const uint8_t *in, size_t in_size,
                   stream_sink_fn sink, void *ctx,
                   uint64_t expect, uint64_t *produced)
{
    AlzInflate s;
    int rc;

    memset(&s, 0, sizeof(s));
    binit(&s.b, in, in_size);
    s.sink = sink; s.sink_ctx = ctx;
    rc = inflate_run(&s);
    if (rc == 0) rc = flush_stage(&s);
    if (produced) *produced = s.total;
    if (rc < 0) return -1;
    return s.total == expect ? 0 : -1;
}
