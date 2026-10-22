/* egg_bzip2.c — adapter between the EGG reader and the bzip2 library.
 *
 * The library is the **official 1.0.5** — the one FIXTURES.md names as this
 * codec's reference — copied as is into src/bzip2_dec/ (bzip2 licence included,
 * src/bzip2_dec/LICENSE) and built separately, without -Wextra: its warnings are
 * not this project's, and masking them locally beats making them disappear from
 * the rest of the build.
 *
 * Why not the copy in research/unalz/: it is NOT standard bzip2. `UnAlzbzlib.c`
 * and `UnAlzBz2decompress.c` are modified for a stream without a "BZh" header,
 * with "DLZ" blocks and no CRC (checks commented out as `// [ALZ]`): they suit
 * ALZ's own bzip2, not EGG's, whose blocks do start with "BZh4" and end with the
 * combined CRC.
 *
 * Why this decoding is necessary: EGG method 2 is bzip2, and ALZip's "Normal"
 * profile routes source files through it (code_normal.egg: code.c in m2,
 * hint 4), just as "Optimized" routes .c/.txt. Refusing m2 therefore left 10 of
 * the corpus's 97 archives unusable, including the only three encrypted archives
 * (their blocks are bzip2, so the decryption already implemented could never be
 * checked end to end).
 */
#include "egg_bzip2.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "bzlib.h"
#include "zlib.h"   /* crc32 (zlib vendored in src/zlib_deflate) */

static const char *bzerr(int rc)
{
    switch (rc) {
        case BZ_OK:               return "ok";
        case BZ_PARAM_ERROR:      return "invalid parameter";
        case BZ_MEM_ERROR:        return "out of memory";
        case BZ_DATA_ERROR:       return "corrupt stream (block CRC)";
        case BZ_DATA_ERROR_MAGIC: return "missing or invalid bzip2 header";
        case BZ_IO_ERROR:         return "I/O error";
        case BZ_UNEXPECTED_EOF:   return "truncated stream";
        case BZ_OUTBUFF_FULL:     return "output larger than usize";
        case BZ_CONFIG_ERROR:     return "library misconfigured";
        default:                  return "bzip2 error";
    }
}

int egg_bzip2_decode(const uint8_t *in, size_t in_size,
                     uint8_t *out, size_t out_size, char *err, size_t errsz)
{
    unsigned int dest_len, src_len;
    int rc;

    if (in_size > 0xFFFFFFFFu || out_size > 0xFFFFFFFFu) {
        if (err && errsz)
            snprintf(err, errsz, "bzip2: size outside the 32-bit field");
        return -1;
    }
    dest_len = (unsigned int)out_size;
    src_len  = (unsigned int)in_size;

    /* small = 0: the fast variant, the one with no impact on the produced
     * bytes. verbosity = 0: no message on stderr, the error comes back through
     * the `err` buffer as everywhere else in the reader. */
    rc = BZ2_bzBuffToBuffDecompress((char *)out, &dest_len, (char *)in, src_len,
                                    0, 0);
    if (rc != BZ_OK) {
        if (err && errsz)
            snprintf(err, errsz, "bzip2: %s (code %d, %u input bytes)",
                     bzerr(rc), rc, (unsigned)in_size);
        return -1;
    }
    if (dest_len != out_size) {
        if (err && errsz)
            snprintf(err, errsz,
                     "bzip2: %u bytes decompressed, %llu expected",
                     dest_len, (unsigned long long)out_size);
        return -1;
    }
    return 0;
}

int egg_bzip2_decode_to(const uint8_t *in, size_t in_size,
                        stream_sink_fn sink, void *ctx, uint64_t expect,
                        char *err, size_t errsz)
{
    bz_stream zs;
    uint8_t out[1 << 16];
    uint64_t produced = 0;
    int rc, ret = -1;

    if (in_size > 0xFFFFFFFFu) {
        if (err && errsz)
            snprintf(err, errsz, "bzip2: size outside the 32-bit field");
        return -1;
    }
    memset(&zs, 0, sizeof zs);
    zs.next_in = (char *)in;
    zs.avail_in = (unsigned)in_size;
    rc = BZ2_bzDecompressInit(&zs, 0, 0);
    if (rc != BZ_OK) {
        if (err && errsz)
            snprintf(err, errsz, "bzip2 : %s (code %d)", bzerr(rc), rc);
        return -1;
    }
    for (;;) {
        size_t have;

        zs.next_out = (char *)out;
        zs.avail_out = (unsigned)sizeof out;
        rc = BZ2_bzDecompress(&zs);
        have = sizeof out - zs.avail_out;
        if (have) {
            produced += have;
            if (produced > expect) {
                if (err && errsz)
                    snprintf(err, errsz, "bzip2: output larger than %llu "
                                         "bytes", (unsigned long long)expect);
                goto done;
            }
            if (sink(ctx, out, have)) {
                if (err && errsz)
                    snprintf(err, errsz, "bzip2: write interrupted");
                goto done;
            }
        }
        if (rc == BZ_STREAM_END) break;
        if (rc != BZ_OK) {
            if (err && errsz)
                snprintf(err, errsz, "bzip2 : %s (code %d)", bzerr(rc), rc);
            goto done;
        }
        if (!have && !zs.avail_in) {
            if (err && errsz) snprintf(err, errsz, "bzip2: truncated stream");
            goto done;
        }
    }
    if (produced != expect) {
        if (err && errsz)
            snprintf(err, errsz, "bzip2: %llu bytes decompressed, %llu "
                                 "expected", (unsigned long long)produced,
                     (unsigned long long)expect);
        goto done;
    }
    ret = 0;

 done:
    BZ2_bzDecompressEnd(&zs);
    return ret;
}

/* --------------------------------------------------------------- encodage */

/* Flushes into `ob`: writes what the encoder left there, then resets the
 * output. Called whenever the output buffer is full AND after BZ_STREAM_END
 * (the last bytes do not necessarily fill the buffer). */
static int bz_flush(FILE *tmp, uint8_t *ob, size_t obsz, bz_stream *zs,
                    uint64_t *total, char *err, size_t errsz)
{
    size_t have = obsz - zs->avail_out;

    if (have && fwrite(ob, 1, have, tmp) != have) {
        if (err && errsz)
            snprintf(err, errsz, "temporary file: %s", strerror(errno));
        return -1;
    }
    *total += have;
    zs->next_out = (char *)ob;
    zs->avail_out = (unsigned)obsz;
    return 0;
}

/* Same bzip2 error message as the decoder, with the raw code. */
static void bz_err(char *err, size_t errsz, const char *phase, int rc)
{
    if (err && errsz)
        snprintf(err, errsz, "bzip2 (%s) : %s (code %d)", phase, bzerr(rc), rc);
}

int egg_bzip2_encode_range(const char *path, uint64_t off, uint64_t len,
                           int block_size_100k, FILE **blob, uint64_t *csize,
                           uint32_t *crc, char *err, size_t errsz)
{
    uint8_t in[1 << 16], ob[1 << 16];
    bz_stream zs;
    FILE *f = NULL, *tmp = NULL;
    uint64_t left = len, total = 0;
    uint32_t c = (uint32_t)crc32(0L, Z_NULL, 0);
    int rc = -1, r, inited = 0;

    /* blockSize100k: 1..9 for bzip2 1.0.5; ALZip writes 4 (every reference
     * block), which the caller passes and nothing else reads here. */
    if (block_size_100k < 1 || block_size_100k > 9) {
        if (err && errsz)
            snprintf(err, errsz, "bzip2 : blockSize100k %d hors de 1..9",
                     block_size_100k);
        return -1;
    }

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

    memset(&zs, 0, sizeof zs);
    /* verbosity 0: no message on stderr, the error comes back through `err`.
     * workFactor 30: bzip2's documented default (and the value workFactor 0 is
     * read as); not observable on the corpus, see the .h. */
    r = BZ2_bzCompressInit(&zs, block_size_100k, 0, 30);
    if (r != BZ_OK) {
        bz_err(err, errsz, "initialisation", r);
        goto done;
    }
    inited = 1;
    zs.next_out = (char *)ob;
    zs.avail_out = (unsigned)sizeof ob;

    while (left) {
        size_t want = left < sizeof in ? (size_t)left : sizeof in;
        size_t got = fread(in, 1, want, f);

        if (got != want) {
            if (err && errsz)
                snprintf(err, errsz, "%s: short read (%llu bytes "
                                     "left)", path, (unsigned long long)left);
            goto done;
        }
        c = (uint32_t)crc32(c, in, (unsigned)got);
        zs.next_in = (char *)in;
        zs.avail_in = (unsigned)got;
        while (zs.avail_in) {
            r = BZ2_bzCompress(&zs, BZ_RUN);
            if (r != BZ_RUN_OK) {
                bz_err(err, errsz, "compression", r);
                goto done;
            }
            if (zs.avail_out == 0 &&
                bz_flush(tmp, ob, sizeof ob, &zs, &total, err, errsz))
                goto done;
        }
        left -= want;
    }

    for (;;) {                       /* fin de flux */
        r = BZ2_bzCompress(&zs, BZ_FINISH);
        if ((zs.avail_out == 0 || r == BZ_STREAM_END) &&
            bz_flush(tmp, ob, sizeof ob, &zs, &total, err, errsz))
            goto done;
        if (r == BZ_STREAM_END) break;
        if (r != BZ_FINISH_OK) {
            bz_err(err, errsz, "end of stream", r);
            goto done;
        }
    }

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
    if (inited) BZ2_bzCompressEnd(&zs);
    if (f) fclose(f);
    if (tmp) fclose(tmp);
    return rc;
}
