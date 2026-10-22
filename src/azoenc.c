/* azoenc.c — checker for the AZO encoder (src/egg_azo.c).
 *
 *   azoenc input1 stream1 [input2 stream2 ...]
 *
 * Each (input, reference AZO payload) pair is re-encoded then compared byte for
 * byte. One line per pair, a summary, and exit status 0 only when ALL pairs are
 * identical.
 *
 * This is the tool that pins the encoder parameters (AZO.dll configuration
 * table, match search, cost decision) on the three AZO payloads of the corpus
 * (tests/run_tests.sh, step 10): probe.sys, the same behind a .com extension,
 * and sysmulti.sys — 633,780 bytes, hence TWO internal 2^19 slices, which is
 * what pins the slicing and the reset of the models (a single-slice archive
 * would not). `alz create` alone is not enough: it compares the whole archive,
 * and the Optimized .sys/.com route is the only one that writes AZO.
 */
#include "egg_azo.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static uint8_t *slurp(const char *path, size_t *size, char *err, size_t errsz)
{
    FILE *f = fopen(path, "rb");
    uint8_t *buf;
    long n;

    if (!f) {
        snprintf(err, errsz, "%s: cannot open", path);
        return NULL;
    }
    if (fseek(f, 0, SEEK_END) || (n = ftell(f)) < 0 || fseek(f, 0, SEEK_SET)) {
        snprintf(err, errsz, "%s: unreadable size", path);
        fclose(f);
        return NULL;
    }
    buf = malloc(n ? (size_t)n : 1);
    if (!buf) {
        snprintf(err, errsz, "out of memory");
        fclose(f);
        return NULL;
    }
    if (n && fread(buf, 1, (size_t)n, f) != (size_t)n) {
        snprintf(err, errsz, "%s: short read", path);
        free(buf);
        fclose(f);
        return NULL;
    }
    fclose(f);
    *size = (size_t)n;
    return buf;
}

/* Compares the temporary stream with the reference. Fills in the produced length
 * and the first difference (a position past the reference included), returns 1
 * when they differ. */
static int diff_stream(FILE *blob, const uint8_t *ref, size_t reflen,
                       size_t *gotlen, size_t *firstdiff)
{
    uint8_t buf[1 << 16];
    size_t off = 0, first = 0;
    int different = 0;

    for (;;) {
        size_t got = fread(buf, 1, sizeof buf, blob);
        size_t i;

        for (i = 0; i < got; ++i) {
            if (off + i >= reflen || buf[i] != ref[off + i]) {
                if (!different) first = off + i;
                different = 1;
                break;                       /* only the first difference counts */
            }
        }
        off += got;
        if (got < sizeof buf) break;
    }
    *gotlen = off;
    *firstdiff = first;
    return different || off != reflen;
}

int main(int argc, char **argv)
{
    int i, nfail = 0, npair = 0;
    char err[512];

    if (argc < 3 || (argc - 1) % 2) {
        fprintf(stderr, "usage: azoenc input reference [input reference ...]\n");
        return 2;
    }

    for (i = 1; i + 1 < argc; i += 2) {
        const char *in = argv[i], *refpath = argv[i + 1];
        struct stat st;
        uint8_t *ref;
        size_t reflen = 0, gotlen = 0, firstdiff = 0;
        uint64_t csize = 0;
        uint32_t crc = 0;
        FILE *blob = NULL;

        err[0] = 0;
        ref = slurp(refpath, &reflen, err, sizeof err);
        if (!ref) {
            fprintf(stderr, "azoenc: %s\n", err);
            return 2;
        }
        if (stat(in, &st) || !S_ISREG(st.st_mode)) {
            fprintf(stderr, "azoenc: %s: no such regular file\n", in);
            free(ref);
            return 2;
        }
        npair++;
        if (egg_azo_encode_range(in, 0, (uint64_t)st.st_size,
                                 &blob, &csize, &crc, err, sizeof err)) {
            printf("FAIL %s: %s\n", in, err);
            free(ref);
            nfail++;
            continue;
        }
        if (diff_stream(blob, ref, reflen, &gotlen, &firstdiff)) {
            uint8_t head[32];
            size_t  have = 0;

            printf("FAIL %s: re-encoded stream differs (first difference at %zu; "
                   "%zu bytes produced, %zu expected)\n",
                   in, firstdiff, gotlen, reflen);
            if (fseeko(blob, 0, SEEK_SET) == 0)
                have = fread(head, 1, sizeof head, blob);
            printf("     produced :");
            for (size_t k = 0; k < have; k++) printf(" %02x", head[k]);
            printf("\n     reference:");
            for (size_t k = 0; k < reflen && k < sizeof head; k++) printf(" %02x", ref[k]);
            printf("\n");
            nfail++;
        } else {
            printf("OK   %s: %zu identical bytes (usize %llu, CRC-32 %08x)\n",
                   in, gotlen, (unsigned long long)st.st_size, crc);
        }
        fclose(blob);
        free(ref);
    }

    printf("AZO: %d/%d streams reproduced byte for byte\n", npair - nfail, npair);
    return nfail ? 1 : 0;
}
