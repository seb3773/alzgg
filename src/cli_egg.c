/* cli_egg.c — EGG implementation of the alzgg binary: list / extract / create
 * (src/alz.c routes both containers to this file or to cli_alz.c)
 *
 *   alzgg list    archive.egg
 *   alzgg extract archive.egg [-d dest] [-p password] [--raw]
 *   alzgg create  archive.egg [-p profile] [-s] [-v SIZE] [-i id[,id...]]
 *                 [--password PASS [--crypt zip|aes128|aes256|lea128|lea256]
 *                  [--crypt-info HEX[,HEX...]]] INPUTS...
 *
 * Scope: the EGG format only (ALZip container). Structure details:
 * FORMAT-EGG.md. Block decoding covers methods 0 (store), 1 (raw deflate),
 * 2 (bzip2, the 1.0.5 library from src/bzip2_dec/), 3 (AZO, src/egg_azo.c) and
 * 4 (LZMA, SDK 4.65 from src/lzma_sdk/), including solid archives (one
 * continuous stream spread over the members, spec §14.3), and decryption
 * covers ZipCrypto, AES-128/256 and LEA-128/256 (spec §12). `--raw` writes the
 * decrypted payload without decompressing it (a decryption-only check).
 *
 * `create` writes the five ALZipCon 12.30 profiles: "No Compression"
 * (`-m0`, store), "Priority on Compressing Speed" (`-m1`, deflate hint 2),
 * "Normal" (`-m2`, deflate hint 4, default), "Priority on Compress Ratio"
 * (`-m3`, LZMA hint 8 everywhere) and "Optimized" (`-m4`, ALZip's full table:
 * store, bzip2, LZMA .doc/.ico, AZO .sys/.com then deflate hint 5 as the
 * fallback, no extension refused — appendix A.15, routing). The levels are
 * those of 12.30, measured byte for byte (lot K); they differ from ALZip 8.0
 * (deflate 6 / 5 / LZMA 6), whose archives stay readable.
 * Single volume or split into volumes (`-v`, one Header ID per volume),
 * encrypted or not (`--password`, `--crypt zip|aes128|aes256|lea128|lea256`,
 * with `--crypt-info` to re-inject ALZip's random material). Solid mode (`-s`)
 * accepts only Compressing Speed (`-m1`, deflate hint 2) and Compress Ratio
 * (`-m3`, LZMA hint 8), one stream over the concatenation of the members
 * (§14.3). Encryption is refused with `-s` (ALZip: "Solid-Compressed file
 * cannot be encrypted") and for a member above 3 GiB (several blocks), for
 * want of a reference; it combines with `-v` (ALZip encrypts before splitting,
 * the lot-H case with sixteen volumes). An empty member or a directory is
 * written without Encrypt Info, as ALZip does. The password is converted to
 * the ANSI code page before derivation (spec §12.9).
 */
#include "egg.h"
#include "egg_crypt.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

static const char *method_name(uint8_t m)
{
    switch (m) {
        case EGG_M_STORE:   return "store";
        case EGG_M_DEFLATE: return "deflate";
        case EGG_M_BZIP2:   return "bzip2";
        case EGG_M_AZO:     return "azo";
        case EGG_M_LZMA:    return "lzma";
        default:            return "?";
    }
}

static const char *crypt_name(int c)
{
    switch (c) {
        case EGG_CRYPT_ZIP:    return "zip";
        case EGG_CRYPT_AES128: return "aes128";
        case EGG_CRYPT_AES256: return "aes256";
        case EGG_CRYPT_LEA128: return "lea128";
        case EGG_CRYPT_LEA256: return "lea256";
        default:               return "none";
    }
}

static void usage(void)
{
    fprintf(stderr,
        "usage:\n"
        "  alzgg list    archive.egg [-u|--unix] [-1|--bare]\n"
        "  alzgg extract archive.egg [-d dest] [-p password] [-u|--unix] [--raw]\n"
        "     -p PASS   password (ZipCrypto, AES-128/256, LEA-128/256)\n"
        "     -u, --unix format paths as Unix relative paths (/ slashes, lowercase)\n"
        "     -1, --bare bare output format (one path per line, script friendly)\n"
        "     --raw     write the decrypted payload without decompressing it\n"
        "  alzgg create  archive.egg [-p profile] [-s] [-i header_id] INPUTS...\n"
        "     --password PASS  encrypt (ZipCrypto by default, see --crypt)\n"
        "     --crypt M        zip (ZipCrypto) | aes128 | aes256 | lea128 |\n"
        "                      lea256: Encrypt Info methods (spec §12);\n"
        "                      refused with -s (ALZip:\n"
        "                      \"Solid-Compressed file cannot be encrypted\");\n"
        "                      combines with -v (encryption before splitting)\n"
        "     --crypt-info HEX,...  random material per member (ZipCrypto:\n"
        "                      10 bytes; AES and LEA: the 8/16-byte salt),\n"
        "                      hexadecimal.\n"
        "                      ALZip draws it randomly: fix it to compare byte\n"
        "                      for byte, /dev/urandom otherwise\n"
        "     -p PROF   none (store) | normal | compspeed | compratio | optimized;\n"
        "               ALZip 12.30: normal = -m2 (deflate 4), compspeed =\n"
        "               -m1 (deflate 2), compratio = -m3 (LZMA 8), optimized =\n"
        "               -m4 (ALZip's full table: store, bzip2, LZMA\n"
        "               .doc/.ico, AZO .sys/.com, deflate 5 fallback)\n"
        "     -mN       ALZipCon 12.30 profile number: 0 none, 1 compspeed,\n"
        "               2 normal, 3 compratio, 4 optimized (default 2)\n"
        "     -s        Solid-Compression: one stream over the concatenation\n"
        "               of the members, deflate (m1) or LZMA (m3), without\n"
        "               volumes or password\n"
        "     -v SIZE   split into volumes of SIZE bytes (decimal, or K/KB,\n"
        "               M/MB, G/GB in base 1024: -v100KB = 102400, measured); the\n"
        "               files are then archive.vol1.egg, archive.vol2.egg, ...\n"
        "               (the last one shorter), volume header included; -s\n"
        "               is refused with -v, as in ALZip\n"
        "     -i ID     archive Header ID (decimal or 0x...): not reproducible\n"
        "               in ALZip, so fix it to compare byte for byte;\n"
        "               with -v, one ID per volume: -i id1,id2,...\n");
    exit(2);
}

static void format_unix_path(const char *in, size_t in_len, char *out, size_t outsz)
{
    if (!out || outsz == 0) return;
    if (!in || in_len == 0) {
        out[0] = '\0';
        return;
    }
    size_t k = 0;
    size_t lim = in_len < outsz - 1 ? in_len : outsz - 1;
    for (size_t i = 0; i < lim; ++i) {
        char c = in[i];
        if (c == '\\') c = '/';
        out[k++] = (char)tolower((unsigned char)c);
    }
    out[k] = '\0';

    char *p = out;
    while (*p == '/') p++;
    while (p[0] == '.' && p[1] == '/') {
        p += 2;
        while (*p == '/') p++;
    }
    if (p != out) {
        memmove(out, p, strlen(p) + 1);
    }
}

static int cmd_list(const char *path, int unix_paths, int bare_list)
{
    EggArchive arc;
    char err[512];
    size_t i, j;

    if (egg_open(path, &arc, err, sizeof err)) {
        fprintf(stderr, "alzgg: %s\n", err);
        return 2;
    }
    if (!bare_list) {
        printf("version=0x%04x header_id=%08x solid=%s members=%zu\n",
               arc.version, arc.header_id, arc.solid ? "yes" : "no", arc.nentries);
    }
    for (i = 0; i < arc.nentries; ++i) {
        const EggEntry *e = &arc.entries[i];
        char name_buf[4096];
        if (unix_paths) {
            format_unix_path(e->name, strlen(e->name), name_buf, sizeof(name_buf));
        } else {
            snprintf(name_buf, sizeof(name_buf), "%s", e->name);
        }

        if (bare_list) {
            printf("%s\n", name_buf);
        } else {
            printf("[%zu] '%s' usize=%llu attr=%02x crypt=%s",
                   i, name_buf, (unsigned long long)e->usize,
                   e->has_wininfo ? e->attrs : 0, crypt_name(e->crypt));
            if (e->has_wininfo) printf(" time=%llu", (unsigned long long)e->filetime);
            printf(" blocks=%zu\n", e->nblocks);
            for (j = 0; j < e->nblocks; ++j) {
                const EggBlock *b = &e->blocks[j];
                printf("      block %zu meth=%u(%s) hint=%u usize=%u csize=%u crc=%08x\n",
                       j, b->method, method_name(b->method), b->hint,
                       b->usize, b->csize, b->crc32);
            }
        }
    }
    egg_close(&arc);
    return 0;
}

static int cmd_extract(const char *path, const EggExtractOpts *opt)
{
    EggArchive arc;
    char err[512];
    size_t i;
    int n;

    if (egg_open(path, &arc, err, sizeof err)) {
        fprintf(stderr, "alzgg: %s\n", err);
        return 2;
    }
    printf("%zu member(s)\n", arc.nentries);
    n = egg_extract_all(&arc, opt, err, sizeof err);
    if (n < 0) {
        fprintf(stderr, "alzgg: %s\n", err);
        egg_close(&arc);
        return 2;
    }
    for (i = 0; i < arc.nentries; ++i) {
        const EggEntry *e = &arc.entries[i];
        char name_buf[4096];
        if (opt->unix_paths) {
            format_unix_path(e->name, strlen(e->name), name_buf, sizeof(name_buf));
        } else {
            snprintf(name_buf, sizeof(name_buf), "%s", e->name);
        }
        if (e->has_wininfo && (e->attrs & 0x80))
            printf("%s ... directory\n", name_buf);
        else
            printf("%s ... ok (%llu bytes)\n", name_buf,
                   (unsigned long long)e->usize);
    }
    printf("%d member(s) extracted\n", n);
    egg_close(&arc);
    return 0;
}

static EggProfile profile_of(const char *name)
{
    if (!strcmp(name, "none"))      return EGG_PROF_NONE;
    if (!strcmp(name, "normal"))    return EGG_PROF_NORMAL;
    if (!strcmp(name, "compspeed")) return EGG_PROF_COMPSPEED;
    if (!strcmp(name, "compratio")) return EGG_PROF_COMPRATIO;
    if (!strcmp(name, "optimized")) return EGG_PROF_OPTIMIZED;
    fprintf(stderr, "alzgg: unknown profile '%s' "
                    "(none|normal|compspeed|compratio|optimized)\n", name);
    exit(2);
}

/* ALZipCon 12.30 `-mN` number: 0 store, 1 Compressing Speed (deflate 2),
 * 2 Normal (deflate 4), 3 Ratio (LZMA 8), 4 Optimized. That is the order
 * measured on code.c, biased.bin and eng.txt (FIXTURES.md lot K); ALZip 8.0
 * put Normal at -m1 and Compressing Speed at -m2, which 12.30 reversed. */
static EggProfile profile_from_m(int n)
{
    switch (n) {
        case 0: return EGG_PROF_NONE;
        case 1: return EGG_PROF_COMPSPEED;
        case 2: return EGG_PROF_NORMAL;
        case 3: return EGG_PROF_COMPRATIO;
        case 4: return EGG_PROF_OPTIMIZED;
    }
    fprintf(stderr, "alzgg: -m%d does not exist for EGG (0..4)\n", n);
    exit(2);
}

/* Comma-separated identifier list, each in decimal or 0x... . */
static int parse_ids(const char *arg, uint32_t **out, size_t *n)
{
    uint32_t *v = NULL;
    size_t k = 0;
    const char *p = arg;

    for (;;) {
        char *end = NULL;
        unsigned long val;
        uint32_t *grown;

        errno = 0;
        val = strtoul(p, &end, 0);
        if (end == p || errno || val > 0xFFFFFFFFul) {
            free(v);
            return -1;
        }
        grown = realloc(v, (k + 1) * sizeof *grown);
        if (!grown) {
            free(v);
            return -1;
        }
        v = grown;
        v[k++] = (uint32_t)val;
        if (!*end) break;
        if (*end != ',') {
            free(v);
            return -1;
        }
        p = end + 1;
    }
    *out = v;
    *n = k;
    return 0;
}

/* Volume size: bytes, or a K/KB, M/MB, G/GB suffix (base 1024, like ALZip's
 * `-v100KB`, measured at 102,400 bytes). */
static int parse_size(const char *arg, uint64_t *out)
{
    char *end = NULL;
    unsigned long long v;
    unsigned shift = 0;

    errno = 0;
    v = strtoull(arg, &end, 0);
    if (end == arg || errno) return -1;
    if (*end) {
        if (!strcasecmp(end, "k") || !strcasecmp(end, "kb"))       shift = 10;
        else if (!strcasecmp(end, "m") || !strcasecmp(end, "mb"))  shift = 20;
        else if (!strcasecmp(end, "g") || !strcasecmp(end, "gb"))  shift = 30;
        else return -1;
        if (v > (UINT64_MAX >> shift)) return -1;
        v <<= shift;
    }
    *out = v;
    return 0;
}

/* Random-material size per method: 10 bytes for ZipCrypto (ALZip appends the
 * two high bytes of the member CRC), 8/16 for the AES and LEA salt (§12.2). */
static size_t material_len(int method)
{
    return method == EGG_CRYPT_ZIP ? 10 :
           method == EGG_CRYPT_AES128 || method == EGG_CRYPT_LEA128 ? 8 :
           method == EGG_CRYPT_AES256 || method == EGG_CRYPT_LEA256 ? 16 : 0;
}

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* List of hexadecimal materials, one per member (same shape as -i id1,id2,...).
 * Returns how many were read, or -1 if a token lacks the method's length. */
static int parse_materials(const char *arg, int method, EggCryptMaterial *out,
                           size_t max)
{
    size_t want = material_len(method), n = 0;
    const char *p = arg;

    if (!want) return -1;
    while (*p) {
        size_t k;

        if (n >= max) return -1;
        for (k = 0; k < want; ++k) {
            int hi, lo;
            if (!p[0] || !p[1]) return -1;
            hi = hex_nibble(p[0]);
            lo = hex_nibble(p[1]);
            if (hi < 0 || lo < 0) return -1;
            out[n].bytes[k] = (uint8_t)((hi << 4) | lo);
            p += 2;
        }
        out[n].len = want;
        n++;
        if (!*p) break;
        if (*p != ',') return -1;
        p++;
    }
    return (int)n;
}

static int random_material(EggCryptMaterial *m, size_t len)
{
    FILE *f = fopen("/dev/urandom", "rb");
    int ok;

    if (!f) return -1;
    ok = fread(m->bytes, 1, len, f) == len;
    fclose(f);
    m->len = len;
    return ok ? 0 : -1;
}

static int cmd_create(const char *out, EggProfile prof, int solid,
                      uint64_t volume_size, const char *id_arg,
                      const char *password, int crypt,
                      EggCryptMaterial *mats, size_t nmats,
                      char **paths, int npaths)
{
    EggCreateOpts opt;
    EggSrc *items = NULL;
    uint32_t *ids = NULL;
    EggCryptMaterial *generated = NULL;
    size_t n = 0, i, nids = 0, nvol = 0;
    char err[512];

    memset(&opt, 0, sizeof opt);
    opt.profile     = prof;
    opt.solid       = solid;
    opt.volume_size = volume_size;
    if (id_arg && parse_ids(id_arg, &ids, &nids)) {
        fprintf(stderr, "alzgg: invalid Header ID '%s' "
                        "(decimal, 0x..., or a list id1,id2,...)\n", id_arg);
        return 2;
    }
    if (volume_size && !nids) {
        fprintf(stderr, "alzgg: splitting: -i id1[,id2,...] is required "
                        "(one Header ID per volume; ALZip draws them from a "
                        "counter that cannot be reproduced)\n");
        free(ids);
        return 2;
    }
    if (nids) {
        opt.header_id    = ids[0];
        opt.volume_ids   = ids;
        opt.n_volume_ids = nids;
    } else {
        /* ALZip draws this field from an activity counter, never
         * reproducible; without a reference value we pick a neighbouring
         * one, non-zero and inside the observed range (the corpus stays
         * below 0x10000). */
        uint32_t v = (uint32_t)time(NULL) & 0xFFFFu;
        opt.header_id = v ? v : 1;
    }

    if (egg_scan_paths(paths, (size_t)npaths, &items, &n, err, sizeof err)) {
        fprintf(stderr, "alzgg: %s\n", err);
        return 2;
    }

    if (password) {
        opt.password = password;
        opt.crypt    = crypt;
        if (mats) {
            opt.crypt_material   = mats;
            opt.n_crypt_material = nmats;
        } else {
            size_t k, len = material_len(crypt);

            generated = calloc(n ? n : 1, sizeof *generated);
            if (!generated) {
                fprintf(stderr, "alzgg: out of memory\n");
                egg_inputs_free(items, n);
                free(ids);
                return 2;
            }
            for (k = 0; k < n; ++k) {
                if (random_material(&generated[k], len)) {
                    fprintf(stderr, "alzgg: /dev/urandom unreadable: encryption "
                                    "material unavailable\n");
                    free(generated);
                    egg_inputs_free(items, n);
                    free(ids);
                    return 2;
                }
            }
            opt.crypt_material   = generated;
            opt.n_crypt_material = n;
        }
    }
    printf("%zu entry(ies), profile %s%s, header_id=%08x",
           n, egg_profile_name(opt.profile), opt.solid ? ", solid" : "",
           opt.header_id);
    if (volume_size)
        printf(", volumes of %llu bytes", (unsigned long long)volume_size);
    printf("\n");
    for (i = 0; i < n; ++i)
        printf("  [%zu] %s%s (%llu bytes)\n", i, items[i].name,
               items[i].is_dir ? "/" : "",
               (unsigned long long)items[i].usize);

    if (egg_create(out, items, n, &opt, &nvol, err, sizeof err)) {
        fprintf(stderr, "alzgg: %s\n", err);
        egg_inputs_free(items, n);
        free(generated);
        free(ids);
        return 2;
    }
    egg_inputs_free(items, n);
    free(generated);
    free(ids);
    if (volume_size) {
        size_t len = strlen(out), k;
        if (len > 4 && !strcasecmp(out + len - 4, ".egg")) len -= 4;
        for (k = 1; k <= nvol; ++k)
            printf("%s%.*s.vol%zu.egg\n", k == 1 ? "-> " : "   ", (int)len,
                   out, k);
        printf("   (%zu volume(s))\n", nvol);
    } else {
        printf("-> %s\n", out);
    }
    return 0;
}

int egg_cli_main(int argc, char **argv)
{
    if (argc < 3) usage();
    if (!strcmp(argv[1], "list")) {
        const char *arc = NULL;
        int unix_paths = 0;
        int bare_list = 0;
        for (int i = 2; i < argc; ++i) {
            const char *arg = argv[i];
            if (!strcmp(arg, "-u") || !strcmp(arg, "--unix")) {
                unix_paths = 1;
            } else if (!strcmp(arg, "-1") || !strcmp(arg, "--bare") || !strcmp(arg, "-b")) {
                bare_list = 1;
            } else if (arg[0] == '-' && arg[1] != '-' && arg[1] != '\0') {
                for (const char *p = arg + 1; *p; ++p) {
                    if (*p == 'u' || *p == 'U') unix_paths = 1;
                    else if (*p == '1' || *p == 'b' || *p == 'B') bare_list = 1;
                    else {
                        fprintf(stderr, "alzgg: unknown option '%s'\n", arg);
                        return 2;
                    }
                }
            } else if (arg[0] == '-') {
                fprintf(stderr, "alzgg: unknown option '%s'\n", arg);
                return 2;
            } else if (!arc) {
                arc = arg;
            } else {
                fprintf(stderr, "alzgg: unexpected argument '%s'\n", arg);
                return 2;
            }
        }
        if (!arc) {
            fprintf(stderr, "alzgg: list: missing archive\n");
            return 2;
        }
        return cmd_list(arc, unix_paths, bare_list);
    }
    if (!strcmp(argv[1], "create")) {
        EggProfile prof = EGG_PROF_NORMAL;
        const char *id_arg = NULL;
        const char *password = NULL, *info_arg = NULL;
        EggCryptMaterial *mats = NULL;
        size_t nmats = 0;
        int crypt = EGG_CRYPT_ZIP, crypt_given = 0;
        uint64_t volume_size = 0;
        int solid = 0, i, first = 3;

        for (i = 3; i < argc; ++i) {
            if (!strcmp(argv[i], "-p") && i + 1 < argc) {
                prof = profile_of(argv[++i]);
                first = i + 1;
            } else if (!strcmp(argv[i], "-m") && i + 1 < argc) {
                char *end = NULL;
                long v = strtol(argv[++i], &end, 10);
                if (!end || *end || v < 0 || v > 4) {
                    fprintf(stderr, "alzgg: -m expects 0..4\n");
                    return 2;
                }
                prof = profile_from_m((int)v);
                first = i + 1;
            } else if (!strncmp(argv[i], "-m", 2) && argv[i][2] >= '0' &&
                       argv[i][2] <= '9' && !argv[i][3]) {
                prof = profile_from_m(argv[i][2] - '0');
                first = i + 1;
            } else if (!strcmp(argv[i], "-s")) {
                solid = 1;
                first = i + 1;
            } else if (!strcmp(argv[i], "-i") && i + 1 < argc) {
                id_arg = argv[++i];
                first = i + 1;
            } else if (!strcmp(argv[i], "-v") && i + 1 < argc) {
                if (parse_size(argv[++i], &volume_size) || !volume_size) {
                    fprintf(stderr, "alzgg: invalid volume size '%s'\n",
                            argv[i]);
                    return 2;
                }
                first = i + 1;
            } else if (!strcmp(argv[i], "--password") && i + 1 < argc) {
                password = argv[++i];
                first = i + 1;
            } else if (!strcmp(argv[i], "--crypt") && i + 1 < argc) {
                const char *m = argv[++i];
                crypt_given = 1;
                if (!strcmp(m, "zip"))         crypt = EGG_CRYPT_ZIP;
                else if (!strcmp(m, "aes128")) crypt = EGG_CRYPT_AES128;
                else if (!strcmp(m, "aes256")) crypt = EGG_CRYPT_AES256;
                else if (!strcmp(m, "lea128")) crypt = EGG_CRYPT_LEA128;
                else if (!strcmp(m, "lea256")) crypt = EGG_CRYPT_LEA256;
                else {
                    fprintf(stderr, "alzgg: unknown cipher '%s' "
                                    "(zip|aes128|aes256|lea128|lea256)\n", m);
                    return 2;
                }
                first = i + 1;
            } else if (!strcmp(argv[i], "--crypt-info") && i + 1 < argc) {
                info_arg = argv[++i];
                first = i + 1;
            } else {
                break;
            }
        }
        if (first >= argc) usage();
        /* `--crypt` without `--password` makes no sense: without this refusal
         * it was silently ignored and the archive came out in the clear while
         * the command line asked for encryption. */
        if (crypt_given && !password) {
            fprintf(stderr, "alzgg: --crypt only makes sense with --password\n");
            return 2;
        }
        if (info_arg) {
            int nread;

            if (!password) {
                fprintf(stderr, "alzgg: --crypt-info only makes sense with "
                                "--password\n");
                return 2;
            }
            mats = calloc(256, sizeof *mats);      /* CLI ceiling */
            if (!mats) {
                fprintf(stderr, "alzgg: out of memory\n");
                return 2;
            }
            nread = parse_materials(info_arg, crypt, mats, 256);
            if (nread <= 0) {
                fprintf(stderr, "alzgg: invalid --crypt-info: %zu hexadecimal "
                                "bytes per member expected (%s material)\n",
                        material_len(crypt),
                        crypt == EGG_CRYPT_ZIP ? "ZipCrypto" :
                        crypt == EGG_CRYPT_LEA128 || crypt == EGG_CRYPT_LEA256 ?
                        "LEA" : "AES");
                free(mats);
                return 2;
            }
            nmats = (size_t)nread;
        }
        {
            int rc = cmd_create(argv[2], prof, solid, volume_size, id_arg,
                                password, crypt, mats, nmats,
                                argv + first, argc - first);
            free(mats);
            return rc;
        }
    }
    if (!strcmp(argv[1], "extract")) {
        EggExtractOpts opt;
        const char *arc = NULL;
        int i;
        memset(&opt, 0, sizeof opt);
        opt.dest = ".";
        for (i = 2; i < argc; ++i) {
            if (!strcmp(argv[i], "-d") && i + 1 < argc) opt.dest = argv[++i];
            else if (!strcmp(argv[i], "-p") && i + 1 < argc) opt.password = argv[++i];
            else if (!strcmp(argv[i], "--raw")) opt.raw = 1;
            else if (!strcmp(argv[i], "-u") || !strcmp(argv[i], "--unix")) opt.unix_paths = 1;
            else if (argv[i][0] != '-' && !arc) arc = argv[i];
            else usage();
        }
        if (!arc) usage();
        return cmd_extract(arc, &opt);
    }
    usage();
    return 2;
}
