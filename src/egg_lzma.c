/* egg_lzma.c — LZMA codec for EGG blocks (method 4, spec §11.1).
 *
 * Block header: 4 constant bytes measured (`04 41 05 00` on the 25 LZMA blocks
 * of the corpus), then the 5 property bytes of the SDK. The stream that follows
 * is raw LZMA, without an end marker (ALZip's decoder knows the decompressed
 * size from the block header).
 *
 * Encoder: LZMA SDK 4.65 set to its default level 5 (lc=3, lp=0, pb=2,
 * 16 MiB dictionary, nice_len 32, mc 32, BT4). That version/setting pair is what
 * reproduces the 25 reference blocks byte for byte; SDK 19.00, with the same
 * properties, diverges from the first few hundred bytes.
 */
#include "egg_lzma.h"
#include "lzma_sdk/LzmaEnc.h"
#include "lzma_sdk/LzmaDec.h"
#include "zlib.h"

#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

static void err_set(char *err, size_t errsz, const char *fmt, ...)
{
    va_list ap;
    if (!err || !errsz) return;
    va_start(ap, fmt);
    vsnprintf(err, errsz, fmt, ap);
    va_end(ap);
}

/* ================================================================ allocation */

static void *lz_alloc(void *p, size_t size)
{
    (void)p;
    return malloc(size);
}

static void lz_free(void *p, void *address)
{
    (void)p;
    free(address);
}

static ISzAlloc lz_allocator = { lz_alloc, lz_free };

/* ================================================================== decoding */

int egg_lzma_decode(const uint8_t *src, size_t csize, uint8_t *dst, size_t usize,
                    char *err, size_t errsz)
{
    ELzmaStatus status = LZMA_STATUS_NOT_SPECIFIED;
    SizeT dlen = (SizeT)usize, slen;
    SRes r;

    if (csize < 9) {
        err_set(err, errsz, "LZMA block of %zu bytes: incomplete 9-byte header", csize);
        return -1;
    }
    slen = (SizeT)(csize - 9);
    r = LzmaDecode(dst, &dlen, src + 9, &slen, src + 4, 5,
                   LZMA_FINISH_ANY, &status, &lz_allocator);
    if (r != SZ_OK) {
        err_set(err, errsz, "LZMA : %s (code %d)",
                r == SZ_ERROR_DATA ? "corrupt stream" :
                r == SZ_ERROR_MEM  ? "out of memory" : "failed", r);
        return -1;
    }
    if ((size_t)dlen != usize) {
        err_set(err, errsz, "LZMA: %zu bytes decompressed for %zu expected",
                (size_t)dlen, usize);
        return -1;
    }
    if (status == LZMA_STATUS_NEEDS_MORE_INPUT) {
        err_set(err, errsz, "LZMA: truncated stream");
        return -1;
    }
    return 0;
}

int egg_lzma_decode_to(const uint8_t *src, size_t csize, stream_sink_fn sink,
                       void *ctx, uint64_t usize, char *err, size_t errsz)
{
    CLzmaDec st;
    const Byte *in;
    SizeT in_left;
    uint64_t produced = 0;
    uint8_t out[1 << 16];
    int ret = -1;

    if (csize < 9) {
        err_set(err, errsz, "LZMA block of %zu bytes: incomplete 9-byte header", csize);
        return -1;
    }
    LzmaDec_Construct(&st);
    if (LzmaDec_Allocate(&st, src + 4, 5, &lz_allocator) != SZ_OK) {
        err_set(err, errsz, "LZMA: out of memory (properties)");
        return -1;
    }
    LzmaDec_Init(&st);
    in = src + 9;
    in_left = (SizeT)(csize - 9);

    while (produced < usize) {
        SizeT dlen = (SizeT)(usize - produced);
        SizeT slen = in_left;
        ELzmaStatus status = LZMA_STATUS_NOT_SPECIFIED;
        SRes r;

        if (dlen > sizeof out) dlen = sizeof out;
        r = LzmaDec_DecodeToBuf(&st, out, &dlen, in, &slen,
                                LZMA_FINISH_ANY, &status);
        in += slen;
        in_left -= slen;
        if (r != SZ_OK) {
            err_set(err, errsz, "LZMA : %s (code %d)",
                    r == SZ_ERROR_DATA ? "corrupt stream" :
                    r == SZ_ERROR_MEM  ? "out of memory" : "failed", r);
            goto done;
        }
        if (dlen) {
            produced += dlen;
            if (sink(ctx, out, dlen)) {
                err_set(err, errsz, "LZMA: write interrupted");
                goto done;
            }
        } else if (!slen) {
            err_set(err, errsz, "LZMA: truncated stream (%llu bytes produced, "
                                "%llu expected)",
                    (unsigned long long)produced, (unsigned long long)usize);
            goto done;
        }
    }
    if (produced != usize) {
        err_set(err, errsz, "LZMA: %llu bytes decompressed for %llu expected",
                (unsigned long long)produced, (unsigned long long)usize);
        goto done;
    }
    ret = 0;

 done:
    LzmaDec_Free(&st, &lz_allocator);
    return ret;
}

/* ================================================================== encoding */

/* The 4 bytes ALZip's writer puts before the LZMA properties. Constant on the
 * 25 reference blocks (all sizes together): it is neither a size nor a CRC, only
 * a marker copied as is. */
static const uint8_t lzma_prefix[4] = { 0x04, 0x41, 0x05, 0x00 };

typedef struct {
    ISeqInStream vt;
    FILE        *f;
    uint64_t     left;
    uint32_t     crc;
    int          failed;
} LzIn;

typedef struct {
    ISeqOutStream vt;
    FILE         *f;
    uint64_t      total;
    int           failed;
} LzOut;

static SRes lz_read(void *p, void *buf, size_t *size)
{
    LzIn *in = (LzIn *)p;
    size_t want = *size;
    size_t got;

    if (want > in->left) want = (size_t)in->left;
    got = fread(buf, 1, want, in->f);
    if (got != want && ferror(in->f)) {
        *size = got;
        in->failed = 1;
        return SZ_ERROR_READ;
    }
    in->crc = (uint32_t)crc32(in->crc, (const Bytef *)buf, (uInt)got);
    in->left -= got;
    *size = got;
    return SZ_OK;
}

static size_t lz_write(void *p, const void *buf, size_t size)
{
    LzOut *out = (LzOut *)p;
    size_t put = fwrite(buf, 1, size, out->f);

    if (put != size) out->failed = 1;
    out->total += put;
    return put;
}

int egg_lzma_encode_stream(FILE *in_file, uint64_t len, FILE **blob,
                           uint64_t *csize, uint32_t *crc,
                           char *err, size_t errsz)
{
    CLzmaEncProps props;
    CLzmaEncHandle enc = NULL;
    Byte props_enc[LZMA_PROPS_SIZE];
    SizeT props_size = LZMA_PROPS_SIZE;
    LzIn in;
    LzOut out;
    FILE *tmp = NULL;
    SRes r;
    int rc = -1;

    tmp = tmpfile();
    if (!tmp) {
        err_set(err, errsz, "temporary file: %s", strerror(errno));
        return -1;
    }

    LzmaEncProps_Init(&props);
    props.level = 5;            /* setting measured on the 25 reference blocks */
    enc = LzmaEnc_Create(&lz_allocator);
    if (!enc) {
        err_set(err, errsz, "LZMA: out of memory");
        goto done;
    }
    if (LzmaEnc_SetProps(enc, &props) != SZ_OK ||
        LzmaEnc_WriteProperties(enc, props_enc, &props_size) != SZ_OK) {
        err_set(err, errsz, "LZMA: encoder rejected the properties");
        goto done;
    }

    if (fwrite(lzma_prefix, 1, sizeof lzma_prefix, tmp) != sizeof lzma_prefix ||
        fwrite(props_enc, 1, props_size, tmp) != props_size) {
        err_set(err, errsz, "temporary file: %s", strerror(errno));
        goto done;
    }

    in.vt.Read = lz_read;
    in.f = in_file;
    in.left = len;
    in.crc = (uint32_t)crc32(0L, Z_NULL, 0);
    in.failed = 0;

    out.vt.Write = lz_write;
    out.f = tmp;
    out.total = 0;
    out.failed = 0;

    r = LzmaEnc_Encode(enc, &out.vt, &in.vt, NULL, &lz_allocator, &lz_allocator);
    if (r != SZ_OK || in.failed || out.failed) {
        err_set(err, errsz, "LZMA: encoding interrupted (%s)",
                r == SZ_ERROR_READ ? "read" :
                r == SZ_ERROR_WRITE ? "write" :
                r == SZ_ERROR_MEM ? "memory" : "code");
        goto done;
    }
    if (in.left != 0) {
        err_set(err, errsz, "LZMA: %llu bytes unread",
                (unsigned long long)in.left);
        goto done;
    }
    if (fflush(tmp) || fseeko(tmp, 0, SEEK_SET) != 0) {
        err_set(err, errsz, "temporary file: %s", strerror(errno));
        goto done;
    }
    *blob  = tmp;
    *csize = (uint64_t)sizeof lzma_prefix + props_size + out.total;
    *crc   = in.crc;
    tmp = NULL;
    rc = 0;

done:
    if (enc) LzmaEnc_Destroy(enc, &lz_allocator, &lz_allocator);
    if (tmp) fclose(tmp);
    return rc;
}

int egg_lzma_encode_range(const char *path, uint64_t off, uint64_t len,
                          FILE **blob, uint64_t *csize, uint32_t *crc,
                          char *err, size_t errsz)
{
    FILE *f = fopen(path, "rb");
    int rc;

    if (!f) {
        err_set(err, errsz, "%s : %s", path, strerror(errno));
        return -1;
    }
    if (fseeko(f, (off_t)off, SEEK_SET) != 0) {
        err_set(err, errsz, "%s: position %llu unreadable", path,
                (unsigned long long)off);
        fclose(f);
        return -1;
    }
    rc = egg_lzma_encode_stream(f, len, blob, csize, crc, err, errsz);
    fclose(f);
    return rc;
}
