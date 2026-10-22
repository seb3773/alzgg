/* egg_w.c — writing of ALZip's EGG container (.egg).
 *
 * Profiles written: "No Compression" (store), "Normal Compression",
 * "Priority on Compressing Speed", "Priority on Compress Ratio" and
 * "Optimized Compression" — single volume or split into volumes (`-v`), with or
 * without ZipCrypto / AES-128 / AES-256 encryption (spec §12), non-solid,
 * without comment. The scale written is ALZip 12.30's, the reference:
 * "Compressing Speed" (`-m1`) is deflate hint 2, "Normal" (`-m2`) deflate hint 4,
 * "Priority on Compress Ratio" (`-m3`) LZMA hint 8. The ALZip plugin's m1
 * profile registers as "Deflate + Store" and
 * packed_egg_8.0/gui_normal_matrix.egg confirms it on fifteen members (65 B to
 * 1 MiB, .c, .txt, .java, .xml, .pas, .cc, .htm, .1st and .bin): no routing by
 * extension, hence no refusal — 12.30 only changes the level (8.0 wrote hint 6
 * in Normal and hint 5 in Compressing Speed). "Optimized" applies ALZip's four
 * extension lists (store, bzip2, LZMA through src/egg_lzma.c, AZO through
 * src/egg_azo.c) and the deflate hint 5 fallback for everything else — the table
 * is complete, no extension is refused (see OPT_*_EXT below); its routes are
 * unchanged in 12.30. "Priority on Compress Ratio" is LZMA hint 8 everywhere
 * (hint 6 in 8.0, same stream). The layout of the records is measured on the
 * ALZip 8 reference archives
 * (packed_egg/, packed_alz/, packed_egg_8.0/, packed_alz_8.0/) and described in
 * FORMAT-EGG.md:
 *
 *   archive header      EGGA + version(2) + header_id(4) + reserved(4)   = 14 B
 *   prefix              sub-headers then END_MARKER (empty prefix here)
 *   member              FILE + file_id(4) + usize(8)
 *                       sub-headers (FILENAME, WININFO), END_MARKER
 *                       then zero or more blocks:
 *                         BLOCK + meth(1) + hint(1) + usize(4) + csize(4)
 *                               + crc32(4) + END_MARKER + data
 *   end of archive      END_MARKER
 *
 * Points checked on the references, and which explain non-obvious choices:
 *   - file_id = index of the member in the archive (0, 1, 2, ...): nested_none.egg;
 *   - an empty file has NO block at all (empty_none.egg);
 *   - an empty directory is a member with attr=0x80, usize=0, no block; a
 *     non-empty directory yields no member (names already carry the path);
 *   - the FILETIME field holds the file's LOCAL time, not UTC (measured: +2 h
 *     apart from the epoch on corpus/hello.txt archived by ALZip);
 *   - the DOS attribute observed for a read-only file is 0x01.
 *
 * Deflate parameters: the `hint` byte IS the zlib level — measured on the 39
 * hint=5 and 36 hint=6 samples of the 8.0 corpus (all reproduced, level 5 and
 * level 6), and confirmed on the 12.30 scale (hint 2 = level 2 for `-m1`,
 * hint 4 = level 4 for `-m2`, lot K) — with windowBits -15, memLevel 8,
 * strategy 0, the settings already exact for ALZ.
 *
 * bzip2 parameters: the `hint` of a method-2 block IS the stream's blockSize100k
 * ("BZh4" everywhere: the vendored bzip2 1.0.5 re-encodes byte for byte the 426
 * unencrypted bzip2 blocks of the corpus — the five Optimized archives, including
 * gui_optimized_matrix.egg and its fifteen members up to 1 MiB, and the 420
 * members of splitmany_optimized). bzip2 only appears in the Optimized profile:
 * the Normal profile routes nothing. workFactor is not observable on these
 * inputs (every value tried, 1 as 250, yields the same bytes), so it is bzip2's
 * documented default, 30, that is written — see egg_bzip2.h.
 *
 * Block splitting: measured on the normal profile, a 5 GiB member gives TWO
 * blocks of 3221225472 then 2147483648 bytes (exactly 3 GiB for the first), each
 * compressed into an independent stream; 1 GiB fits in a single block. That 3 GiB
 * threshold is applied to the deflate profiles. For store, only a member of
 * 3 GiB or less is proven: beyond that, no reference producer was measured, so
 * writing is refused instead of guessing.
 *
 * Writes: "No Compression" (store), "Compressing Speed" (deflate hint 2),
 * "Normal" (hint 4), "Priority on Compress Ratio" (LZMA hint 8) and "Optimized"
 * for its measured extensions, single volume or split, encrypted or not; and
 * solid mode on the Compressing Speed and Compress Ratio profiles (12.30: `-m1`
 * and `-m3`).
 *
 * Encryption: the Encrypt Info sub-header carries the method then the member's
 * material (12 encrypted verifier bytes + CRC-32 for ZipCrypto, salt + verifier +
 * HMAC for AES), and the compressed stream is encrypted in one piece. The
 * material is supplied by the caller (ALZip draws it at random); it is what makes
 * the nine encrypted references reproducible byte for byte (FORMAT-EGG.md
 * §12.8).
 *
 * Solid: a single deflate stream over the concatenated members, in their archive
 * order, a single BLOCK placed after the headers, SOLID_INFO (7 bytes: flags and
 * size zeroed) in the prefix. Checked byte for byte on
 * packed_egg/nested_normal_solid.egg (8 members, 822,784 bytes) and
 * packed_egg_8.0/unicode_normal_solid.egg (3 members).
 *
 * Splitting (`-v SIZE`): the volumes are exactly SIZE bytes, each with a 33-byte
 * header (EGGA + SPLIT_INFO + end); only a block's data is cut at the boundary,
 * every record (sub-header, block header, end) being preceded by a DUMMY that
 * fills the volume when it no longer fits. Reproduced byte for byte on
 * corpus_probe/splitmany_normal.vol1-3.egg; rules and unobserved cases in
 * FORMAT-EGG.md §13.3.
 *
 * Refused explicitly, never guessed: solid with a profile other than Compressing
 * Speed (m1) or Compress Ratio (m3), solid + `-v` (ALZip refuses to split a solid
 * archive), solid + encryption (ALZip: "Solid-Compressed file cannot be
 * encrypted"), encryption of a multi-block member (no reference), comment,
 * symbolic links, a store member above 3 GiB and a solid stream above 3 GiB
 * (splitting never observed). Encrypted volumes and non-ASCII passwords are
 * written, on the other hand: ALZip encrypts before splitting (lot H, sixteen
 * volumes) and converts the password to the ANSI code page before deriving the
 * key (§12.9).
 */
#include "egg.h"
#include "egg_bzip2.h"   /* bzip2 encoder (bzip2 routes of the Optimized profile) */
#include "egg_crypt.h"   /* ZipCrypto / AES-128 / AES-256 encryption */
#include "egg_lzma.h"    /* LZMA encoder (Ratio profile, .doc/.ico routes) */
#include "egg_azo.h"     /* AZO encoder (Optimized profile, .sys/.com route) */
#include "zlib.h"

#include <dirent.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>      /* strcasecmp (suffixe .egg) */
#include <sys/stat.h>
#include <time.h>

#define EGG_NAME_MAX     4096
#define EGG_VOL_PATH_MAX 4096
/* Volume header as represented by the project: EGGA(14) + SPLIT_INFO(11) +
 * end marker(4). Measured on every split reference. */
#define EGG_VOL_HEADER   33

/* Block limit measured on the deflate profile (5 GiB -> 3 GiB + 2 GiB). */
#define EGG_BLOCK_MAX 3221225472ULL

const char *egg_profile_name(EggProfile p)
{
    switch (p) {
        case EGG_PROF_NONE:      return "none";
        case EGG_PROF_NORMAL:    return "normal";
        case EGG_PROF_COMPSPEED: return "compspeed";
        case EGG_PROF_COMPRATIO: return "compratio";
        case EGG_PROF_OPTIMIZED: return "optimized";
        default:                 return "?";
    }
}

/* ------------------------------------------------------------- diagnostics */
static void err_set(char *err, size_t errsz, const char *fmt, ...)
{
    va_list ap;
    if (!err || !errsz) return;
    va_start(ap, fmt);
    vsnprintf(err, errsz, fmt, ap);
    va_end(ap);
}

/* ------------------------------------------------------------------- bytes */
static int put_u8(FILE *f, uint8_t v)
{
    return fputc(v, f) == v ? 0 : -1;
}

static int put_u16(FILE *f, uint16_t v)
{
    return put_u8(f, (uint8_t)(v & 0xFF)) || put_u8(f, (uint8_t)(v >> 8)) ? -1 : 0;
}

static int put_u32(FILE *f, uint32_t v)
{
    int i;
    for (i = 0; i < 4; ++i)
        if (put_u8(f, (uint8_t)(v >> (8 * i)))) return -1;
    return 0;
}

static int put_u64(FILE *f, uint64_t v)
{
    int i;
    for (i = 0; i < 8; ++i)
        if (put_u8(f, (uint8_t)(v >> (8 * i)))) return -1;
    return 0;
}

static int put_mem(FILE *f, const void *p, size_t n)
{
    return n && fwrite(p, 1, n, f) != n ? -1 : 0;
}

/* Sub-header: signature + size marker. Bit 0x01 of the flags says the size takes
 * 4 bytes instead of 2 (spec §4). */
static int put_subheader(FILE *f, uint32_t sig, uint32_t size)
{
    if (size > 0xFFFFu) {
        return put_u32(f, sig) || put_u8(f, 0x01) || put_u32(f, size) ? -1 : 0;
    }
    return put_u32(f, sig) || put_u8(f, 0x00) || put_u16(f, (uint16_t)size) ? -1 : 0;
}

/* FILETIME (100 ns since 1601) built from the file's LOCAL time: that is what
 * ALZip writes (measured on the references), not UTC. The conversion therefore
 * goes through localtime() then the same calendar read back as UTC. */
static uint64_t filetime_of(time_t secs)
{
    struct tm tmv;
    time_t shifted;

    if (!localtime_r(&secs, &tmv)) return 0;
    tmv.tm_isdst = -1;
    shifted = timegm(&tmv);
    if (shifted == (time_t)-1) return 0;
    return ((uint64_t)(int64_t)shifted + 11644473600ULL) * 10000000ULL;
}

/* ------------------------------------------------------- logical stream */
/* The writer first produces the logical stream (as for a single-volume
 * archive); in split mode it writes it to a temporary file and records each
 * segment in order. An `atomic` segment — file header, sub-header, block header,
 * end marker — cannot cross a volume boundary: ALZip then inserts a DUMMY that
 * fills the volume exactly (measured in splitmany_normal.vol2.egg, where the
 * DUMMY falls between the FILENAME and the WININFO of member 403). A block's
 * data, on the other hand, is cut at the boundary. */
typedef struct Seg {
    uint64_t off;
    uint64_t len;
    int      atomic;
} Seg;

typedef struct Layout {
    Seg   *v;
    size_t n, cap;
} Layout;

static int64_t tell_at(FILE *f)
{
    off_t o = ftello(f);
    return o < 0 ? -1 : (int64_t)o;
}

static int layout_add(Layout *l, uint64_t off, uint64_t len, int atomic)
{
    if (l->n == l->cap) {
        size_t cap = l->cap ? l->cap * 2 : 512;
        Seg *grown = realloc(l->v, cap * sizeof *grown);
        if (!grown) return -1;
        l->v = grown;
        l->cap = cap;
    }
    l->v[l->n].off    = off;
    l->v[l->n].len    = len;
    l->v[l->n].atomic = atomic;
    l->n++;
    return 0;
}

/* Closes an atomic record started at `start`. */
static int rec_close(Layout *lay, int64_t start, FILE *f)
{
    int64_t end;

    if (!lay) return 0;
    end = tell_at(f);
    if (start < 0 || end < start) return -1;
    return layout_add(lay, (uint64_t)start, (uint64_t)(end - start), 1);
}

/* --------------------------------------------------------------- membres */
typedef struct Node {
    EggSrc  item;
    char   *name;   /* stored name (owned) */
    char   *path;   /* source path (owned) */
} Node;

/* Values of a file or directory, carried by the node so that sorting a directory
 * (which goes through a temporary list) need not re-read each child's inode. */
static void node_from_stat(Node *n, const struct stat *st, int is_dir)
{
    const char *base = strrchr(n->name, '/');
    uint8_t attr;

    base = base ? base + 1 : n->name;
    n->item.name      = n->name;
    n->item.path      = n->path;
    n->item.usize     = is_dir ? 0 : (uint64_t)st->st_size;
    n->item.filetime  = filetime_of(st->st_mtim.tv_sec);
    /* ALZip reuses the Windows attributes: directory 0x80, read-only 0x01,
     * hidden 0x02. On POSIX the hidden bit does not exist, but a name starting
     * with a dot is the equivalent convention — and that is what ALZip wrote for
     * `.dotfile` in lot H (attr=0x02). */
    attr = (uint8_t)(is_dir ? 0x80 : (st->st_mode & S_IWUSR ? 0x00 : 0x01));
    if (base[0] == '.' && base[1]) attr |= 0x02;
    n->item.attrs     = attr;
    n->item.is_dir    = is_dir;
}

typedef struct NodeList {
    Node  *v;
    size_t n, cap;
} NodeList;

static void nodes_free(NodeList *l)
{
    size_t i;
    for (i = 0; i < l->n; ++i) {
        free(l->v[i].name);
        free(l->v[i].path);
    }
    free(l->v);
    l->v = NULL;
    l->n = l->cap = 0;
}

static int nodes_push(NodeList *l, const char *name, const char *path,
                      const struct stat *st, int is_dir)
{
    Node *n;

    if (l->n == l->cap) {
        size_t cap = l->cap ? l->cap * 2 : 64;
        Node *grown = realloc(l->v, cap * sizeof *grown);
        if (!grown) return -1;
        l->v = grown;
        l->cap = cap;
    }
    n = &l->v[l->n];
    n->name = strdup(name);
    n->path = strdup(path);
    if (!n->name || !n->path) {
        free(n->name);
        free(n->path);
        return -1;
    }
    node_from_stat(n, st, is_dir);
    l->n++;
    return 0;
}

/* Copies an already built node to the end of `l` (same values, duplicated
 * strings: the source list keeps ownership of its own). */
static int nodes_push_copy(NodeList *l, const Node *src)
{
    Node *n;

    if (l->n == l->cap) {
        size_t cap = l->cap ? l->cap * 2 : 64;
        Node *grown = realloc(l->v, cap * sizeof *grown);
        if (!grown) return -1;
        l->v = grown;
        l->cap = cap;
    }
    n = &l->v[l->n];
    n->name = strdup(src->name);
    n->path = strdup(src->path);
    if (!n->name || !n->path) {
        free(n->name);
        free(n->path);
        return -1;
    }
    n->item = src->item;
    n->item.name = n->name;
    n->item.path = n->path;
    l->n++;
    return 0;
}

/* Stored name: the path as given, separators converted to '/'. ALZip would
 * archive the same name, except that its exact prefixing rule with -af is not
 * established: it is not invented here. */
static void stored_name(const char *given, char *out, size_t outsz)
{
    size_t i = 0, o = 0;

    while (given[i] == '.' && given[i + 1] == '/') i += 2;   /* ./x -> x */
    for (; given[i] && o + 1 < outsz; ++i)
        out[o++] = given[i] == '\\' ? '/' : given[i];
    out[o] = 0;
}

/* ALZip collation (Windows): case-insensitive lexicographic comparison, with no
 * numeric sort. The order measured in lot H is `-dash`, `.dotfile`,
 * `_underscore`, `a`, `A0`, `B`, `c1`, `c10`, `c2`, `z z`: `c10` really comes
 * before `c2` (string order), not a "natural sort". */
static int natural_cmp(const char *a, const char *b)
{
    while (*a && *b) {
        unsigned char ca = (unsigned char)*a, cb = (unsigned char)*b;

        if (ca >= 'A' && ca <= 'Z') ca = (unsigned char)(ca + 32);
        if (cb >= 'A' && cb <= 'Z') cb = (unsigned char)(cb + 32);
        if (ca != cb) return (int)ca - (int)cb;
        ++a; ++b;
    }
    return (int)(unsigned char)*a - (int)(unsigned char)*b;
}

static int cmp_names(const void *a, const void *b)
{
    const Node *x = a, *y = b;
    int c = natural_cmp(x->name, y->name);
    return c ? c : strcmp(x->name, y->name);
}

/* Walking a directory: files in alphabetical order, recursion in place, and a
 * dedicated member (attr 0x80) for a truly empty directory — that is what the
 * references show. */
static int walk(NodeList *l, const char *given, const char *syspath,
                char *err, size_t errsz)
{
    struct stat st;
    DIR *dir;

    if (lstat(syspath, &st)) {
        err_set(err, errsz, "%s : %s", syspath, strerror(errno));
        return -1;
    }
    if (S_ISLNK(st.st_mode)) {
        err_set(err, errsz, "%s : lien symbolique non pris en charge "
                            "(ALZip behaviour not established)", syspath);
        return -1;
    }
    if (!S_ISDIR(st.st_mode)) {
        if (!S_ISREG(st.st_mode)) {
            err_set(err, errsz, "%s: unsupported input type", syspath);
            return -1;
        }
        return nodes_push(l, given, syspath, &st, 0) ? -1 : 0;
    }

    dir = opendir(syspath);
    if (!dir) {
        err_set(err, errsz, "%s : %s", syspath, strerror(errno));
        return -1;
    }
    {
        NodeList sub = {0};
        struct dirent *de;
        size_t i;
        int rc = 0;

        while ((de = readdir(dir))) {
            char child_given[EGG_NAME_MAX], child_path[EGG_NAME_MAX];
            int nn;

            if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;
            nn = snprintf(child_given, sizeof child_given, "%s/%s", given, de->d_name);
            if (nn < 0 || (size_t)nn >= sizeof child_given) {
                err_set(err, errsz, "%s: name too long", syspath);
                rc = -1;
                break;
            }
            nn = snprintf(child_path, sizeof child_path, "%s/%s", syspath, de->d_name);
            if (nn < 0 || (size_t)nn >= sizeof child_path) {
                err_set(err, errsz, "%s: name too long", syspath);
                rc = -1;
                break;
            }
            if (walk(&sub, child_given, child_path, err, errsz)) {
                rc = -1;
                break;
            }
        }
        closedir(dir);
        if (rc == 0) {
            if (sub.n == 0) {                       /* empty directory: one member */
                rc = nodes_push(l, given, syspath, &st, 1) ? -1 : 0;
                if (rc) err_set(err, errsz, "out of memory");
            } else {
                qsort(sub.v, sub.n, sizeof *sub.v, cmp_names);
                for (i = 0; i < sub.n && rc == 0; ++i) {
                    rc = nodes_push_copy(l, &sub.v[i]) ? -1 : 0;
                    if (rc) err_set(err, errsz, "out of memory");
                }
            }
            nodes_free(&sub);
        } else {
            nodes_free(&sub);
        }
        return rc;
    }
}

int egg_scan_paths(char **paths, size_t npaths, EggSrc **out, size_t *count,
                   char *err, size_t errsz)
{
    NodeList l = {0};
    size_t i, j;

    for (i = 0; i < npaths; ++i) {
        char name[EGG_NAME_MAX];
        stored_name(paths[i], name, sizeof name);
        if (!name[0]) {
            err_set(err, errsz, "chemin vide");
            goto fail;
        }
        if (walk(&l, name, paths[i], err, errsz)) goto fail;
    }
    if (l.n == 0) {
        err_set(err, errsz, "no entry to archive");
        goto fail;
    }
    /* No global sort: ALZip only sorts what it enumerates itself, that is, the
     * content of a directory (`walk` above, measured on names_order_m1.egg).
     * Entries named one by one keep the order they were given:
     * `gui_nocomp_matrix.egg` and `gui_normal_matrix.egg` record
     * c3...c8, eng, hello, normal_r525, r120k, zeros then big1m, c1, c1.txt, c2.txt
     * — two sorted runs, in the order the GUI received them, not the global
     * alphabetical order (big1m.c would come first). */

    *out = calloc(l.n, sizeof **out);
    if (!*out) {
        err_set(err, errsz, "out of memory");
        goto fail;
    }
    for (j = 0; j < l.n; ++j) {
        (*out)[j].name      = l.v[j].name;
        (*out)[j].path      = l.v[j].path;
        (*out)[j].usize     = l.v[j].item.usize;
        (*out)[j].filetime  = l.v[j].item.filetime;
        (*out)[j].attrs     = l.v[j].item.attrs;
        (*out)[j].is_dir    = l.v[j].item.is_dir;
        l.v[j].name = l.v[j].path = NULL;      /* handed to the caller */
    }
    *count = l.n;
    free(l.v);
    return 0;

fail:
    nodes_free(&l);
    return -1;
}

void egg_inputs_free(EggSrc *items, size_t n)
{
    size_t i;
    for (i = 0; i < n; ++i) {
        free((char *)items[i].name);
        free((char *)items[i].path);
    }
    free(items);
}

/* ------------------------------------------------------------------- codecs */
/* Codec of a member according to the profile. Measured on the reference
 * archives, on the 12.30 scale (the hints in parentheses are the 8.0 corpus's,
 * which stays readable but is no longer written):
 *   - Normal (`-m2`): deflate hint 4 (6 in 8.0) for EVERY member, with no routing
 *     by extension and no refusal. `gui_normal_matrix.egg` shows it on fifteen
 *     entries (65 B to 1 MiB, .c/.txt/.java/.xml/.pas/.cc/.htm/.1st/.bin) and
 *     `lot K/egg_m2_two.egg` pins it in 12.30. The `.c` -> bzip2 once attributed
 *     to Normal came from `packed_egg/code_normal.egg`, which is an Optimized
 *     archive (blocks identical to code_optimized.egg): the plugin table
 *     (Normal -> Deflate + Store) and the measurement agree, there is nothing
 *     to route;
 *   - Compressing Speed (`-m1`): deflate hint 2 (5 in 8.0) for everything,
 *     measured on `biased.bin`, `eng.txt` and `code.c` of lot K;
 *   - No Compression: store.
 * The `hint` byte IS the zlib level for deflate (windowBits -15, memLevel 8,
 * strategy 0: no other set reproduces the corpus blocks) and the blockSize100k
 * for bzip2. */
typedef struct Codec {
    uint8_t method;   /* EGG_M_STORE / _DEFLATE / _BZIP2 */
    uint8_t hint;
    int     level;    /* deflate only */
} Codec;

/* Extension of the stored name: only the last suffix counts (`dbl.tar.gz` ->
 * `gz`, `dbl2.c.bak` -> `bak`) and a leading dot does not make an extension
 * (`noext` behaves like `.dotfile`, measured). Case is preserved here; the
 * caller chooses the comparison (Optimized ignores case, Normal stays exact
 * because no uppercase Normal reference exists). */
static const char *extension_of(const char *name)
{
    const char *dot = strrchr(name, '.');
    const char *base = strrchr(name, '/');

    base = base ? base + 1 : name;
    if (!dot || dot <= base || !dot[1]) return NULL;
    return dot + 1;
}

/* Optimized profile: the four extension lists of the original ALZip 8
 * (`Formats/Egg.dll`, registered at start-up under the names AZO, Store, BZ2 and
 * LZMA) and the deflate hint 5 fallback, measured extension by extension on a
 * 148-member archive produced by ALZipCon `-m4` (FIXTURES.md lot G) and replayed
 * byte for byte by `packed_egg/routes_optimized.egg`.
 *
 * The table is therefore COMPLETE: an extension missing from the lists is no
 * longer refused, it takes the fallback, and that is what ALZip does for the 54
 * extensions outside the tested lists (.exe, .dll, .json, .md, .log, .pdf, no
 * extension at all, ...). The order of the lists does not matter, no extension
 * appears in two of them.
 *
 * Two details only the matrix revealed:
 *   - the comparison is CASE-INSENSITIVE (.C, .TXT, .SYS, .DOC, .JPG, .ZIP follow
 *     their lowercase route);
 *   - nine extensions the DLL's BZ2 list announces are NEVER routed to bzip2:
 *     htm, as, b, bb, cp, d, j, jav and x fall into the deflate hint 5 fallback
 *     (a.htm -> 1004 B, a.html -> 725 B for the same content, at the same size
 *     and in the same archive). They are therefore absent from OPT_BZIP2_EXT
 *     below: the table carries the measured behaviour, not the theoretical list.
 *     The rest of the lists is measured, entry by entry.
 *
 * AZO (sys, com) is written by egg_azo.c; LZMA (ppt...emf) by egg_lzma.c. .com
 * has no reference of its own, but the only one measured (probe.com, same content
 * as probe.sys) yields an AZO block identical byte for byte, hint 1 included: it
 * was produced by ALZipCon, and the test compares it against the whole archive.
 * Routing therefore does follow the extension, for those two. */

/* Effective lists, without the nine ineffective BZ2 entries (see above). */
static const char *const OPT_AZO_EXT[] = {
    "sys", "com", NULL
};

/* 12.30 removed `ace` from this list (8.0 had it first): the reference
 * `packed_egg/routes_optimized.egg` stores `r001.ace` as deflate hint 5, and the
 * list read from Formats/Egg.dll starts at `alz`. */
static const char *const OPT_STORE_EXT[] = {
    "alz", "arc", "arj", "bz", "bz2", "cab", "egg", "ice", "ear",
    "war", "gz", "ha", "jar", "lha", "lzh", "pak", "rar", "tbz", "tbz2",
    "tgz", "7z", "z", "zip", "zoo", "docx", "xlsx", "pptx", "jpg",
    "jpeg", "png", "gif", "ape", "mp4", "mov", "flac", "flv", "mp3",
    "ogg", "wma", "wmv", NULL
};

static const char *const OPT_LZMA_EXT[] = {
    "ppt", "xls", "doc", "ani", "ico", "cur", "pcx", "emf", NULL
};

static const char *const OPT_BZIP2_EXT[] = {
    "h", "c", "java", "cpp", "txt", "pas", "xml", "html", "bat", "1st",
    "ans", "asc", "ascii", "bbs", "charset", "dbt", "err", "faq", "hs",
    "klg", "man", "ada", "au3", "bas", "bet", "cs", "def", "dev",
    "dpr", "dsp", "fpp", "hpp", "hh", "inc", "xaml", NULL
};

/* Optimized profile fallback: deflate level 5 (hint 5). The 54 extensions
 * outside the measured lists (r096-r139 and the uppercase variants), the
 * extension-less name and the nine ineffective BZ2 entries all come out as
 * deflate hint 5, never hint 6 or store. */
#define OPT_FALLBACK_HINT 5

static int ext_in_ci(const char *ext, const char *const *list)
{
    size_t i;

    if (!ext) return 0;
    for (i = 0; list[i]; ++i)
        if (!strcasecmp(ext, list[i])) return 1;
    return 0;
}

static int member_codec(EggProfile p, const char *name, Codec *c,
                        char *err, size_t errsz)
{
    const char *ext;

    switch (p) {
        case EGG_PROF_NONE:
            c->method = EGG_M_STORE;   c->hint = 0; c->level = 0; return 0;
        case EGG_PROF_COMPSPEED:
            /* ALZip 12.30, -m1: deflate hint 2, level 2 (measured on
             * biased.bin, eng.txt and code.c; ALZip 8.0 used level 5 for the
             * same profile). */
            c->method = EGG_M_DEFLATE; c->hint = 2; c->level = 2; return 0;
        case EGG_PROF_NORMAL:
            /* ALZip 12.30, -m2: deflate hint 4, level 4 (8.0 wrote 6), for every
             * member and with no routing by extension. The fifteen members of
             * packed_egg_8.0/gui_normal_matrix.egg (65 B to 1 MiB, nine
             * extensions) already carried the same route in 8.0, and
             * gui_normal_code.egg gives hint 4 to a 45,270-byte code.c in 12.30
             * (lot K). The ALZip plugin's m1 profile only declares
             * "Deflate + Store", moreover. The bzip2 of the old table came from
             * packed_egg/code_normal.egg, in reality a mislabelled Optimized
             * archive (code_optimized.egg, identical blocks). */
            (void)name;
            c->method = EGG_M_DEFLATE; c->hint = 4; c->level = 4; return 0;
        case EGG_PROF_OPTIMIZED:
            /* Four measured lists then the deflate hint 5 fallback; the table is
             * complete, so no extension is refused any more. */
            ext = extension_of(name);
            if (ext_in_ci(ext, OPT_AZO_EXT)) {
                c->method = EGG_M_AZO;     c->hint = 1; c->level = 0; return 0;
            }
            if (ext_in_ci(ext, OPT_STORE_EXT)) {
                c->method = EGG_M_STORE;   c->hint = 0; c->level = 0; return 0;
            }
            if (ext_in_ci(ext, OPT_LZMA_EXT)) {
                c->method = EGG_M_LZMA;    c->hint = 6; c->level = 0; return 0;
            }
            if (ext_in_ci(ext, OPT_BZIP2_EXT)) {
                c->method = EGG_M_BZIP2;   c->hint = 4; c->level = 0; return 0;
            }
            c->method = EGG_M_DEFLATE;
            c->hint   = OPT_FALLBACK_HINT;
            c->level  = OPT_FALLBACK_HINT;
            return 0;
        case EGG_PROF_COMPRATIO:
            /* ALZip 12.30, -m3: LZMA hint 8, whatever the extension. The stream
             * is identical to ALZip 8.0's (hint 6): only the hint byte
             * changes. */
            c->method = EGG_M_LZMA; c->hint = 8; c->level = 0; return 0;
        default:
            err_set(err, errsz, "profile '%s': ALZip routes it to LZMA "
                                "(m4.hint6 over the whole corpus); the LZMA "
                                "encoder is not implemented",
                    egg_profile_name(p));
            return -1;
    }
}

typedef struct Payload {
    FILE    *blob;    /* NULL: copy the source (store); otherwise compressed stream */
    uint64_t usize;   /* uncompressed bytes of the block */
    uint64_t csize;   /* bytes written for this block */
    uint32_t crc;
} Payload;

/* Compresses the [off, off+len) slice of `path` into a temporary file and
 * returns the CRC-32 of the uncompressed slice (that is the block's). */
static int deflate_chunk(const char *path, uint64_t off, uint64_t len, int level,
                         Payload *out, char *err, size_t errsz)
{
    uint8_t in[1 << 16], obuf[1 << 16];
    z_stream zs;
    FILE *f = NULL, *tmp = NULL;
    uint32_t crc = (uint32_t)crc32(0L, Z_NULL, 0);
    uint64_t left = len, csize = 0;
    int rc = -1;

    f = fopen(path, "rb");
    tmp = tmpfile();
    if (!f || !tmp) {
        err_set(err, errsz, "%s : %s", path, strerror(errno));
        goto done;
    }
    if (fseeko(f, (off_t)off, SEEK_SET) != 0) {
        err_set(err, errsz, "%s : position %llu illisible", path,
                (unsigned long long)off);
        goto done;
    }

    memset(&zs, 0, sizeof zs);
    if (deflateInit2(&zs, level, Z_DEFLATED, -15, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
        err_set(err, errsz, "deflateInit2: %s", zs.msg ? zs.msg : "failed");
        goto done;
    }

    while (left) {
        size_t want = left < sizeof in ? (size_t)left : sizeof in;
        size_t got = fread(in, 1, want, f);

        if (got != want) {
            err_set(err, errsz, "%s: short read (%llu bytes left)",
                    path, (unsigned long long)left);
            deflateEnd(&zs);
            goto done;
        }
        crc = (uint32_t)crc32(crc, in, (unsigned)got);
        zs.next_in = in;
        zs.avail_in = (unsigned)got;
        do {
            size_t have;
            zs.next_out = obuf;
            zs.avail_out = (unsigned)sizeof obuf;
            if (deflate(&zs, Z_NO_FLUSH) != Z_OK) {
                err_set(err, errsz, "deflate: %s", zs.msg ? zs.msg : "failed");
                deflateEnd(&zs);
                goto done;
            }
            have = sizeof obuf - zs.avail_out;
            if (have && fwrite(obuf, 1, have, tmp) != have) {
                err_set(err, errsz, "temporary file: %s", strerror(errno));
                deflateEnd(&zs);
                goto done;
            }
            csize += have;
        } while (zs.avail_out == 0);
        left -= got;
    }

    for (;;) {                       /* fin de flux */
        size_t have;
        int r;
        zs.next_out = obuf;
        zs.avail_out = (unsigned)sizeof obuf;
        r = deflate(&zs, Z_FINISH);
        have = sizeof obuf - zs.avail_out;
        if (have && fwrite(obuf, 1, have, tmp) != have) {
            err_set(err, errsz, "temporary file: %s", strerror(errno));
            deflateEnd(&zs);
            goto done;
        }
        csize += have;
        if (r == Z_STREAM_END) break;
        if (r != Z_OK) {
            err_set(err, errsz, "deflate (end): %s", zs.msg ? zs.msg : "failed");
            deflateEnd(&zs);
            goto done;
        }
    }
    deflateEnd(&zs);

    if (fflush(tmp) || fseeko(tmp, 0, SEEK_SET) != 0) {
        err_set(err, errsz, "temporary file: %s", strerror(errno));
        goto done;
    }
    out->blob  = tmp;
    out->usize = len;
    out->csize = csize;
    out->crc   = crc;
    tmp = NULL;
    rc = 0;

done:
    if (f) fclose(f);
    if (tmp) fclose(tmp);
    return rc;
}

/* Concatenates the members' contents (directories and empty files ignored) into
 * a temporary file, in archive order. Used by solid mode, whose stream is split
 * into 3 GiB blocks exactly like an ordinary member
 * (measured: huge_solid.egg has the same blocks as huge_deflate.egg). */
static int concat_items(const EggSrc *items, size_t n, FILE **out,
                        uint64_t *total, char *err, size_t errsz)
{
    uint8_t buf[1 << 16];
    FILE *cat = tmpfile();
    uint64_t usum = 0;
    size_t i;

    if (!cat) {
        err_set(err, errsz, "temporary file: %s", strerror(errno));
        return -1;
    }
    for (i = 0; i < n; ++i) {
        const EggSrc *m = &items[i];
        FILE *f;

        if (m->is_dir || m->usize == 0) continue;
        f = fopen(m->path, "rb");
        if (!f) {
            err_set(err, errsz, "%s : %s", m->path, strerror(errno));
            fclose(cat);
            return -1;
        }
        for (;;) {
            size_t got = fread(buf, 1, sizeof buf, f);

            if (got == 0) {
                if (ferror(f)) {
                    err_set(err, errsz, "%s : lecture impossible", m->path);
                    fclose(f);
                    fclose(cat);
                    return -1;
                }
                break;
            }
            if (fwrite(buf, 1, got, cat) != got) {
                err_set(err, errsz, "temporary file: %s", strerror(errno));
                fclose(f);
                fclose(cat);
                return -1;
            }
            usum += got;
        }
        fclose(f);
    }
    if (fflush(cat) || fseeko(cat, 0, SEEK_SET) != 0) {
        err_set(err, errsz, "temporary file: %s", strerror(errno));
        fclose(cat);
        return -1;
    }
    *out = cat;
    *total = usum;
    return 0;
}

/* Raw deflate of a `len`-byte slice read from `in` (current position), with its
 * uncompressed CRC-32. Same setting as the ordinary blocks (level 6,
 * windowBits -15, memLevel 8, strategy 0). */
static int deflate_stream(FILE *in, uint64_t len, int level, Payload *out,
                          char *err, size_t errsz)
{
    uint8_t buf[1 << 16], obuf[1 << 16];
    z_stream zs;
    FILE *tmp = tmpfile();
    uint32_t crc = (uint32_t)crc32(0L, Z_NULL, 0);
    uint64_t left = len, csize = 0;
    int rc = -1;

    if (!tmp) {
        err_set(err, errsz, "temporary file: %s", strerror(errno));
        return -1;
    }
    memset(&zs, 0, sizeof zs);
    if (deflateInit2(&zs, level, Z_DEFLATED, -15, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
        err_set(err, errsz, "deflateInit2: %s", zs.msg ? zs.msg : "failed");
        goto done;
    }
    while (left) {
        size_t want = left < sizeof buf ? (size_t)left : sizeof buf;
        size_t got = fread(buf, 1, want, in);

        if (got == 0) {
            err_set(err, errsz, "solid stream: short read");
            deflateEnd(&zs);
            goto done;
        }
        crc = (uint32_t)crc32(crc, buf, (unsigned)got);
        left -= got;
        zs.next_in = buf;
        zs.avail_in = (unsigned)got;
        do {
            size_t have;
            zs.next_out = obuf;
            zs.avail_out = (unsigned)sizeof obuf;
            if (deflate(&zs, Z_NO_FLUSH) != Z_OK) {
                err_set(err, errsz, "deflate: %s", zs.msg ? zs.msg : "failed");
                deflateEnd(&zs);
                goto done;
            }
            have = sizeof obuf - zs.avail_out;
            if (have && fwrite(obuf, 1, have, tmp) != have) {
                err_set(err, errsz, "temporary file: %s", strerror(errno));
                deflateEnd(&zs);
                goto done;
            }
            csize += have;
        } while (zs.avail_out == 0);
    }
    for (;;) {
        size_t have;
        int r;
        zs.next_out = obuf;
        zs.avail_out = (unsigned)sizeof obuf;
        r = deflate(&zs, Z_FINISH);
        have = sizeof obuf - zs.avail_out;
        if (have && fwrite(obuf, 1, have, tmp) != have) {
            err_set(err, errsz, "temporary file: %s", strerror(errno));
            deflateEnd(&zs);
            goto done;
        }
        csize += have;
        if (r == Z_STREAM_END) break;
        if (r != Z_OK) {
            err_set(err, errsz, "deflate (end): %s", zs.msg ? zs.msg : "failed");
            deflateEnd(&zs);
            goto done;
        }
    }
    deflateEnd(&zs);
    if (fflush(tmp) || fseeko(tmp, 0, SEEK_SET) != 0) {
        err_set(err, errsz, "temporary file: %s", strerror(errno));
        goto done;
    }
    out->blob  = tmp;
    out->usize = len;
    out->csize = csize;
    out->crc   = crc;
    tmp = NULL;
    rc = 0;

done:
    if (tmp) fclose(tmp);
    return rc;
}

static int copy_stream(FILE *dst, FILE *src, char *err, size_t errsz)
{
    uint8_t buf[1 << 16];
    for (;;) {
        size_t got = fread(buf, 1, sizeof buf, src);
        if (got && put_mem(dst, buf, got)) {
            err_set(err, errsz, "cannot write: %s", strerror(errno));
            return -1;
        }
        if (got < sizeof buf) {
            if (ferror(src)) {
                err_set(err, errsz, "temporary file: %s", strerror(errno));
                return -1;
            }
            return 0;
        }
    }
}

/* Recopie [off, off+len) de `path` vers l'archive (cas store). */
static int copy_range(FILE *dst, const char *path, uint64_t off, uint64_t len,
                      char *err, size_t errsz)
{
    uint8_t buf[1 << 16];
    uint64_t left = len;
    FILE *f = fopen(path, "rb");

    if (!f) {
        err_set(err, errsz, "%s : %s", path, strerror(errno));
        return -1;
    }
    if (fseeko(f, (off_t)off, SEEK_SET) != 0) {
        err_set(err, errsz, "%s : position %llu illisible", path,
                (unsigned long long)off);
        fclose(f);
        return -1;
    }
    while (left) {
        size_t want = left < sizeof buf ? (size_t)left : sizeof buf;
        size_t got = fread(buf, 1, want, f);
        if (got != want) {
            err_set(err, errsz, "%s: short read", path);
            fclose(f);
            return -1;
        }
        if (put_mem(dst, buf, got)) {
            err_set(err, errsz, "cannot write: %s", strerror(errno));
            fclose(f);
            return -1;
        }
        left -= got;
    }
    fclose(f);
    return 0;
}

/* CRC-32 of the [off, off+len) slice of `path` (store case: the block header
 * carries the CRC, so it must be computed before writing the data). */
static int range_crc(const char *path, uint64_t off, uint64_t len, uint32_t *crc,
                     char *err, size_t errsz)
{
    uint8_t buf[1 << 16];
    uint64_t left = len;
    uint32_t c = (uint32_t)crc32(0L, Z_NULL, 0);
    FILE *f = fopen(path, "rb");

    if (!f) {
        err_set(err, errsz, "%s : %s", path, strerror(errno));
        return -1;
    }
    if (fseeko(f, (off_t)off, SEEK_SET) != 0) {
        err_set(err, errsz, "%s : position %llu illisible", path,
                (unsigned long long)off);
        fclose(f);
        return -1;
    }
    while (left) {
        size_t want = left < sizeof buf ? (size_t)left : sizeof buf;
        size_t got = fread(buf, 1, want, f);
        if (got != want) {
            err_set(err, errsz, "%s: short read", path);
            fclose(f);
            return -1;
        }
        c = (uint32_t)crc32(c, buf, (unsigned)got);
        left -= got;
    }
    fclose(f);
    *crc = c;
    return 0;
}

/* --------------------------------------------------------------------- writing */

/* Produces a block payload (deflate, bzip2, AZO, LZMA) into a temporary file;
 * store needs no temporary (the CRC is then enough to write the header). */
static int build_payload(const EggSrc *m, const Codec *c, uint64_t off,
                         uint64_t len, Payload *pl, char *err, size_t errsz)
{
    memset(pl, 0, sizeof *pl);
    if (c->method == EGG_M_DEFLATE)
        return deflate_chunk(m->path, off, len, c->level, pl, err, errsz);
    if (c->method == EGG_M_BZIP2) {
        if (egg_bzip2_encode_range(m->path, off, len, c->hint, &pl->blob,
                                   &pl->csize, &pl->crc, err, errsz))
            return -1;
        pl->usize = len;
        return 0;
    }
    if (c->method == EGG_M_LZMA) {
        if (egg_lzma_encode_range(m->path, off, len, &pl->blob, &pl->csize,
                                  &pl->crc, err, errsz))
            return -1;
        pl->usize = len;
        return 0;
    }
    if (c->method == EGG_M_AZO) {
        /* A single EGG block per member (up to 3 GiB): the 2^19 slicing of the
         * references is INTERNAL to the AZO stream, as the three slices of the
         * oracle's 1.5 MiB .sys and the single 1,572,864-byte block ALZip writes
         * from it show. */
        if (egg_azo_encode_range(m->path, off, len, &pl->blob, &pl->csize,
                                 &pl->crc, err, errsz))
            return -1;
        pl->usize = len;
        return 0;
    }
    if (range_crc(m->path, off, len, &pl->crc, err, errsz)) return -1;
    pl->blob  = NULL;
    pl->usize = len;
    pl->csize = len;
    return 0;
}

/* Encrypts the payload of ONE member (a single block: multi-block encryption has
 * no reference, cf. egg_create). `pl->blob` is replaced by the encrypted stream;
 * its length does not change (ZipCrypto and CTR are stream ciphers of equal
 * length). */
static int encrypt_payload(const EggSrc *m, uint64_t off, uint64_t len,
                           Payload *pl, EggCryptCtx *ctx,
                           char *err, size_t errsz)
{
    uint8_t buf[1 << 16];
    FILE *src = pl->blob, *own = NULL, *tmp = NULL;
    uint64_t left = len;
    int rc = -1;

    if (src) {
        if (fseeko(src, 0, SEEK_SET) != 0) {
            err_set(err, errsz, "temporary file: %s", strerror(errno));
            return -1;
        }
    } else {
        own = fopen(m->path, "rb");
        if (!own || fseeko(own, (off_t)off, SEEK_SET) != 0) {
            err_set(err, errsz, "%s : %s", m->path, strerror(errno));
            goto done;
        }
        src = own;
    }
    tmp = tmpfile();
    if (!tmp) {
        err_set(err, errsz, "temporary file: %s", strerror(errno));
        goto done;
    }
    while (left) {
        size_t want = left < sizeof buf ? (size_t)left : sizeof buf;

        if (fread(buf, 1, want, src) != want) {
            err_set(err, errsz, "%s: short read", m->path);
            goto done;
        }
        if (egg_crypt_enc_update(ctx, buf, want)) {
            err_set(err, errsz, "encryption: invalid state");
            goto done;
        }
        if (fwrite(buf, 1, want, tmp) != want) {
            err_set(err, errsz, "temporary file: %s", strerror(errno));
            goto done;
        }
        left -= want;
    }
    if (fflush(tmp) || fseeko(tmp, 0, SEEK_SET) != 0) {
        err_set(err, errsz, "temporary file: %s", strerror(errno));
        goto done;
    }
    if (pl->blob) fclose(pl->blob);
    pl->blob = tmp;
    tmp = NULL;
    rc = 0;

done:
    if (own) fclose(own);
    if (tmp) fclose(tmp);
    return rc;
}

/* Member header: FILE + file_id(4) + usize(8), FILENAME and WININFO sub-headers
 * (filetime + attributes), Encrypt Info when the member is encrypted (spec
 * §8.5: method(1) + data), then the end of the sub-headers. Each sub-header is a
 * separate record for volume splitting: ALZip places one at a time and stops at
 * the boundary (see splitmany). `lay` may be NULL (single-volume archive, no
 * splitting to prepare). `crypt_method` < 0: no Encrypt Info sub-header. */
static int write_member_header(FILE *f, const EggSrc *m, size_t id, Layout *lay,
                               int crypt_method, const uint8_t *crypt_info,
                               size_t crypt_len)
{
    size_t namelen = strlen(m->name);
    int64_t start;

    start = tell_at(f);
    if (start < 0 || put_u32(f, EGG_SIG_FILE) || put_u32(f, (uint32_t)id) ||
        put_u64(f, m->usize) || rec_close(lay, start, f)) return -1;
    start = tell_at(f);
    if (start < 0 || put_subheader(f, EGG_SIG_FILENAME, (uint32_t)namelen) ||
        put_mem(f, m->name, namelen) || rec_close(lay, start, f)) return -1;
    start = tell_at(f);
    if (start < 0 || put_subheader(f, EGG_SIG_WININFO, 9) ||
        put_u64(f, m->filetime) || put_u8(f, m->attrs) ||
        rec_close(lay, start, f)) return -1;
    if (crypt_method >= 0) {
        start = tell_at(f);
        if (start < 0 ||
            put_subheader(f, EGG_SIG_ENCRYPT, (uint32_t)(1 + crypt_len)) ||
            put_u8(f, (uint8_t)crypt_method) ||
            put_mem(f, crypt_info, crypt_len) ||
            rec_close(lay, start, f)) return -1;
    }
    start = tell_at(f);
    if (start < 0 || put_u32(f, EGG_SIG_END) || rec_close(lay, start, f))
        return -1;
    return 0;
}

/* ------------------------------------------------------------ volume split */
/* Rules measured on the three volumes of packed_egg_8.0/splitmany_normal and the
 * two of packed_egg/records_optimized (FORMAT-EGG.md §13.3):
 *   - each volume is exactly the requested size (the last one less), header
 *     included;
 *   - a volume header is EGGA(14) + SPLIT_INFO(11) + end(4) = 33 bytes, including
 *     for continuation volumes;
 *   - SPLIT_INFO carries prev = previous volume, next = following volume (0 at
 *     the start and at the end); the IDs come from the caller (ALZip counter);
 *   - an atomic record that no longer fits is preceded by a DUMMY that fills the
 *     volume exactly: signature + flags 0 + UInt16 size + `size` null bytes, that
 *     is 7 + size = remaining space; a remainder of 1 to 6 bytes is observed
 *     nowhere: the volume is then left shorter (no invented padding);
 *   - a block's data is cut at the boundary, without alignment. */
typedef struct Splitter {
    const char     *out;    /* requested name (without .volN) */
    const uint32_t *ids;
    size_t          nids;
    uint64_t        limit;  /* size of one volume, header included */
    size_t          index;  /* volume courant, 1-based */
    FILE           *f;
    uint64_t        pos;
} Splitter;

static int volume_path(const char *out, size_t idx, char *buf, size_t bufsz)
{
    size_t n = strlen(out);

    if (n > 4 && !strcasecmp(out + n - 4, ".egg")) n -= 4;
    if (snprintf(buf, bufsz, "%.*s.vol%zu.egg", (int)n, out, idx) >=
        (int)bufsz)
        return -1;
    return 0;
}

static int vol_open(Splitter *s, char *err, size_t errsz)
{
    char path[EGG_VOL_PATH_MAX];
    uint32_t prev = s->index > 1 ? s->ids[s->index - 2] : 0;

    if (!s->ids || s->index > s->nids) {
        err_set(err, errsz, "volume %zu: missing Header ID — one identifier per "
                            "volume is required (-i id1,id2,...)", s->index);
        return -1;
    }
    if (volume_path(s->out, s->index, path, sizeof path)) {
        err_set(err, errsz, "volume name too long for '%s'", s->out);
        return -1;
    }
    s->f = fopen(path, "wb");
    if (!s->f) {
        err_set(err, errsz, "%s : %s", path, strerror(errno));
        return -1;
    }
    s->pos = EGG_VOL_HEADER;
    if (put_mem(s->f, "EGGA", 4) || put_u16(s->f, 0x0100) ||
        put_u32(s->f, s->ids[s->index - 1]) || put_u32(s->f, 0) ||
        put_subheader(s->f, EGG_SIG_SPLIT, 8) || put_u32(s->f, prev) ||
        put_u32(s->f, 0) ||               /* next: patched when closing */
        put_u32(s->f, EGG_SIG_END)) {
        err_set(err, errsz, "%s: cannot write (%s)", path,
                strerror(errno));
        return -1;
    }
    return 0;
}

/* Closes the current volume and fixes its `next` (offset 25: 14 header +
 * 4 Split signature + 3 size field + 4 `prev`). */
static int vol_close(Splitter *s, uint32_t next, char *err, size_t errsz)
{
    int rc = 0;
    char path[EGG_VOL_PATH_MAX];

    if (!s->f) return 0;
    if (fseeko(s->f, 25, SEEK_SET) || put_u32(s->f, next) || fflush(s->f)) {
        if (!volume_path(s->out, s->index, path, sizeof path))
            err_set(err, errsz, "%s: cannot write (%s)", path,
                    strerror(errno));
        rc = -1;
    }
    if (fclose(s->f)) {
        if (!rc && !volume_path(s->out, s->index, path, sizeof path))
            err_set(err, errsz, "%s : %s", path, strerror(errno));
        rc = -1;
    }
    s->f = NULL;
    return rc;
}

static void vol_cleanup(Splitter *s)
{
    char path[EGG_VOL_PATH_MAX];
    size_t k;

    if (s->f) {
        fclose(s->f);
        s->f = NULL;
    }
    for (k = 1; k <= s->index; ++k)
        if (!volume_path(s->out, k, path, sizeof path)) remove(path);
}

/* DUMMY of `total` bytes: signature, flags 0, UInt16 size = total - 7, null
 * payload. `total` stays below the record that did not fit (a few KiB at most),
 * so the size fits in 16 bits. */
static int vol_pad_dummy(Splitter *s, uint64_t total, char *err, size_t errsz)
{
    uint8_t zero[64] = {0};
    uint64_t left = total - 7;

    if (left > 0xFFFFu) {
        err_set(err, errsz, "splitting: %llu-byte DUMMY — the size of an observed "
                            "DUMMY fits in 16 bits",
                (unsigned long long)left);
        return -1;
    }
    if (put_u32(s->f, EGG_SIG_DUMMY) || put_u8(s->f, 0) ||
        put_u16(s->f, (uint16_t)left)) {
        err_set(err, errsz, "cannot write the DUMMY (%s)", strerror(errno));
        return -1;
    }
    while (left) {
        size_t n = left < sizeof zero ? (size_t)left : sizeof zero;
        if (put_mem(s->f, zero, n)) {
            err_set(err, errsz, "cannot write the DUMMY (%s)",
                    strerror(errno));
            return -1;
        }
        left -= n;
    }
    s->pos += total;
    return 0;
}

/* Copies `len` bytes of the logical stream, cutting at volume boundaries. */
static int vol_copy(Splitter *s, FILE *logical, uint64_t len,
                    char *err, size_t errsz)
{
    uint8_t buf[1 << 16];
    uint64_t left = len;

    while (left) {
        uint64_t room = s->limit - s->pos;
        size_t want;

        if (room == 0) {
            if (s->index >= s->nids) {
                err_set(err, errsz, "volume %zu: missing Header ID — one "
                                    "identifier per volume is required "
                                    "(-i id1,id2,...)", s->index + 1);
                return -1;
            }
            if (vol_close(s, s->ids[s->index], err, errsz)) return -1;
            s->index++;
            if (vol_open(s, err, errsz)) return -1;
            room = s->limit - s->pos;
        }
        want = left < room ? (size_t)left : (size_t)room;
        if (want > sizeof buf) want = sizeof buf;
        if (fread(buf, 1, want, logical) != want) {
            err_set(err, errsz, "logical stream: short read");
            return -1;
        }
        if (put_mem(s->f, buf, want)) {
            err_set(err, errsz, "cannot write (%s)", strerror(errno));
            return -1;
        }
        s->pos += want;
        left -= want;
    }
    return 0;
}

static int layout_split(const char *out, FILE *logical, const Layout *lay,
                        const EggCreateOpts *opt, size_t *n_volumes,
                        char *err, size_t errsz)
{
    Splitter s;
    uint8_t buf[EGG_NAME_MAX + 64];
    uint64_t expect;
    size_t i;

    memset(&s, 0, sizeof s);
    s.out    = out;
    s.ids    = opt->volume_ids;
    s.nids   = opt->n_volume_ids;
    s.limit  = opt->volume_size;
    s.index  = 1;

    if (s.limit <= EGG_VOL_HEADER + 4) {
        err_set(err, errsz, "volume size %llu: a volume header already takes "
                            "%d bytes",
                (unsigned long long)s.limit, EGG_VOL_HEADER);
        return -1;
    }

    /* The logical stream starts with the archive header and the prefix end
     * (14 + 4): each volume carries ITS OWN header, so those 18 bytes are not
     * copied. No other kind of prefix exists here (solid + -v is refused, and an
     * archive comment is not written). */
    expect = lay->n ? lay->v[0].off : 0;
    if (expect != 18) {
        err_set(err, errsz, "splitting: %llu-byte logical prefix, "
                            "18 expected", (unsigned long long)expect);
        return -1;
    }
    if (fseeko(logical, (off_t)expect, SEEK_SET) != 0) {
        err_set(err, errsz, "flux logique : position illisible");
        return -1;
    }

    for (i = 0; i < lay->n; ++i) {
        const Seg *g = &lay->v[i];

        if (g->off != expect) {
            err_set(err, errsz, "splitting: segment %zu at %llu, %llu expected",
                    i, (unsigned long long)g->off, (unsigned long long)expect);
            goto fail;
        }
        if (!s.f && vol_open(&s, err, errsz)) goto fail;

        if (g->atomic) {
            uint64_t rem;

            if (g->len > s.limit - EGG_VOL_HEADER) {
                err_set(err, errsz, "splitting: a %llu-byte record does not "
                                    "fit in a %llu-byte volume",
                        (unsigned long long)g->len,
                        (unsigned long long)s.limit);
                goto fail;
            }
            if (s.pos + g->len > s.limit) {
                rem = s.limit - s.pos;
                if (rem >= 7 && vol_pad_dummy(&s, rem, err, errsz)) goto fail;
                if (s.index >= s.nids) {
                    err_set(err, errsz, "volume %zu: missing Header ID — one "
                                        "identifier per volume is required "
                                        "(-i id1,id2,...)", s.index + 1);
                    goto fail;
                }
                if (vol_close(&s, s.ids[s.index], err, errsz)) goto fail;
                s.index++;
                if (vol_open(&s, err, errsz)) goto fail;
            }
            if (g->len > sizeof buf) {
                err_set(err, errsz, "splitting: %llu-byte record "
                                    "larger than the buffer",
                        (unsigned long long)g->len);
                goto fail;
            }
            if (fread(buf, 1, (size_t)g->len, logical) != (size_t)g->len) {
                err_set(err, errsz, "logical stream: short read");
                goto fail;
            }
            if (put_mem(s.f, buf, (size_t)g->len)) {
                err_set(err, errsz, "cannot write (%s)",
                        strerror(errno));
                goto fail;
            }
            s.pos += g->len;
        } else {
            if (vol_copy(&s, logical, g->len, err, errsz)) goto fail;
        }
        expect += g->len;
    }

    if (vol_close(&s, 0, err, errsz)) goto fail;
    if (n_volumes) *n_volumes = s.index;
    return 0;

fail:
    vol_cleanup(&s);
    return -1;
}

int egg_create(const char *out, const EggSrc *items, size_t n,
               const EggCreateOpts *opt, size_t *n_volumes,
               char *err, size_t errsz)
{
    FILE *f;
    size_t i;
    int splitting = opt->volume_size != 0;
    Layout lay = {0};

    if (n_volumes) *n_volumes = 1;

    /* Split + solid: ALZip refuses it (FORMAT-EGG.md §14.1, "Solid-Compression
     * doesn't support spanning archives"). No solid volume exists: it is refused
     * instead of writing an invented chaining. */
    if (splitting && opt->solid) {
        err_set(err, errsz, "solid: ALZip refuses to split a solid archive "
                            "(\"Solid-Compression doesn't support "
                            "spanning archives\") — the archive is not written");
        return -1;
    }

    /* "Priority on Compress Ratio": LZMA hint 8 in 12.30 (6 in the 8.0 corpus,
     * identical stream) for EVERY member, with no routing by type. */
    if (opt->profile != EGG_PROF_NONE && opt->profile != EGG_PROF_NORMAL &&
        opt->profile != EGG_PROF_COMPSPEED &&
        opt->profile != EGG_PROF_OPTIMIZED &&
        opt->profile != EGG_PROF_COMPRATIO) {
        err_set(err, errsz, "unknown profile '%s': the archive is not written",
                egg_profile_name(opt->profile));
        return -1;
    }

    /* Solid: ALZip only allows Normal (m1) and Priority on Compress Ratio (m3)
     * (FORMAT-EGG.md §14.1). The stream is deflate (hint 6 in 8.0, 4 in 12.30)
     * or LZMA (hint 6 in 8.0, 8 in 12.30); the references of both series are
     * reproduced to the byte. */
    if (opt->solid) {
        /* ALZip 12.30 only allows -m1 (Compressing Speed) and -m3 (Priority on
         * Compress Ratio) in solid mode; -m2 (Normal) is refused there, whereas
         * ALZip 8.0 accepted Normal + Ratio. */
        if (opt->profile != EGG_PROF_COMPSPEED &&
            opt->profile != EGG_PROF_COMPRATIO) {
            err_set(err, errsz,
                    "solid: ALZip 12.30 only allows Priority on Compressing "
                    "Speed (m1) and Priority on Compress Ratio (m3) "
                    "(requested profile: %s)", egg_profile_name(opt->profile));
            return -1;
        }
        /* A solid stream above 3 GiB is split into 3 GiB blocks, each compressed
         * independently (huge_solid.egg, 5 GiB: two blocks identical to those of
         * huge_deflate.egg). Nothing to refuse here. */
    }

    /* Encryption (spec §12). ALZip forbids encrypting a solid archive
     * ("ERROR : Solid-Compressed file cannot be encrypted.", §14.1): this
     * combination is refused without writing. Encrypted volumes, on the other
     * hand, are produced by ALZip: packed_egg_8.0/span_15vol_crypt (.vol1 to
     * .vol16, ZipCrypto, a single 1.5 MiB member); encryption comes before the
     * split, which only spreads the already encrypted stream. Encrypting a
     * multi-block member has no reference: refused instead of invented, while an
     * empty member or a directory is simply not encrypted (lot H crypt). */
    if (opt->password) {
        if (opt->solid) {
            err_set(err, errsz, "ERROR : Solid-Compressed file cannot be "
                                "encrypted. — the archive is not written");
            return -1;
        }
        if (opt->crypt != EGG_CRYPT_ZIP && opt->crypt != EGG_CRYPT_AES128 &&
            opt->crypt != EGG_CRYPT_AES256 &&
            opt->crypt != EGG_CRYPT_LEA128 &&
            opt->crypt != EGG_CRYPT_LEA256) {
            err_set(err, errsz, "encryption: method %d not implemented "
                                "(ZipCrypto, AES-128/256, LEA-128/256)",
                    opt->crypt);
            return -1;
        }
        if (!opt->crypt_material || opt->n_crypt_material != n) {
            err_set(err, errsz, "encryption: one random material per member "
                                "is required (%zu member(s), %zu supplied)",
                    n, opt->n_crypt_material);
            return -1;
        }
        for (i = 0; i < n; ++i) {
            /* An empty member or a directory has neither data nor verifier:
             * ALZip writes no Encrypt Info for it (lot H crypt:
             * enc_egg_empty_tp0.egg, enc_egg_dir_tp0.egg, both crypt=none even
             * though -tp0 -ppassword was requested). Encryption therefore only
             * applies to non-empty members, which the writing loop already
             * does. */
            if (items[i].is_dir || items[i].usize == 0) continue;
            /* A member above 3 GiB is encrypted by a single continuous context,
             * with the whole member CRC in the verifier: measured on
             * huge_enc_zip.egg (5 GiB, two blocks), which now extracts back
             * correctly. */
        }
    }

    for (i = 0; i < n; ++i) {
        Codec c;
        if (items[i].is_dir || items[i].usize == 0) continue;
        /* Routing and codec decided before opening anything: an unmeasured
         * extension or a missing codec leaves no file behind. */
        if (member_codec(opt->profile, items[i].name, &c, err, errsz))
            return -1;
        if (c.method == EGG_M_BZIP2 && items[i].usize > EGG_BLOCK_MAX) {
            /* Store, deflate and LZMA are measured beyond 3 GiB: a 5 GiB member
             * gives two blocks, 3 GiB then the rest (lot H huge and huge_lzma).
             * bzip2 splitting at that size has no reference yet: refused instead
             * of guessed. */
            err_set(err, errsz, "'%s': %llu bytes — splitting a bzip2 member "
                                "beyond 3 GiB has no reference producer",
                    items[i].name,
                    (unsigned long long)items[i].usize);
            return -1;
        }
    }

    /* Split: the logical stream is built in a temporary file then spread out
     * (only the boundaries change, the bytes stay the same). */
    f = splitting ? tmpfile() : fopen(out, "wb");
    if (!f) {
        err_set(err, errsz, "%s : %s", splitting ? "temporary file" : out,
                strerror(errno));
        return -1;
    }

    if (put_mem(f, "EGGA", 4) || put_u16(f, 0x0100) ||
        put_u32(f, opt->header_id) || put_u32(f, 0) ||
        /* Solid: SOLID_INFO = signature + flags(1) + size(2) = 7 bytes (flags
         * and size zeroed), measured on the three solid references, then the
         * prefix end marker. */
        (opt->solid ? put_subheader(f, EGG_SIG_SOLID, 0) : 0) ||
        put_u32(f, EGG_SIG_END)) {
        goto io;
    }

    for (i = 0; i < n; ++i) {
        const EggSrc *m = &items[i];
        int crypt_method = -1;
        uint8_t cinfo[32];
        size_t cinfo_len = 0;
        Codec pre_codec;
        Payload pre;
        Payload *chunks = NULL;
        size_t nchunks = 0;
        int have_pre = 0;

        memset(&pre, 0, sizeof pre);
        memset(&pre_codec, 0, sizeof pre_codec);

        /* Encrypted: the member's material depends on the CRC of the
         * uncompressed content, so the Encrypt Info sub-header can only be
         * written after compression. A member above 3 GiB is split into blocks,
         * each compressed separately but ENCRYPTED by a single continuous context
         * (measured: huge_enc_zip.egg, 5 GiB in two blocks, verifier = whole
         * member CRC, continuous encrypted stream). The blocks are prepared
         * before the header because AES computes its HMAC at the end. */
        if (opt->password && !m->is_dir && m->usize > 0) {
            EggCryptCtx *ctx;

            if (member_codec(opt->profile, m->name, &pre_codec, err, errsz))
                goto fail;
            if (m->usize > EGG_BLOCK_MAX) {
                uint32_t full_crc;
                uint64_t off = 0;
                size_t k = 0;

                if (range_crc(m->path, 0, m->usize, &full_crc, err, errsz))
                    goto fail;
                nchunks = (size_t)((m->usize + EGG_BLOCK_MAX - 1) /
                                   EGG_BLOCK_MAX);
                chunks = calloc(nchunks, sizeof *chunks);
                if (!chunks) {
                    err_set(err, errsz, "out of memory");
                    goto fail;
                }
                ctx = egg_crypt_enc_begin(opt->crypt, &opt->crypt_material[i],
                                          full_crc, opt->password, cinfo,
                                          sizeof cinfo, &cinfo_len, err, errsz);
                if (!ctx) goto fail;
                while (off < m->usize) {
                    uint64_t len = m->usize - off;

                    if (len > EGG_BLOCK_MAX) len = EGG_BLOCK_MAX;
                    if (build_payload(m, &pre_codec, off, len, &chunks[k],
                                      err, errsz))
                        goto enc_fail;
                    if (chunks[k].csize > 0xFFFFFFFFULL) {
                        err_set(err, errsz, "'%s': %llu-byte compressed block "
                                            "— a block size field is 32 bits",
                                m->name,
                                (unsigned long long)chunks[k].csize);
                        goto enc_fail;
                    }
                    if (encrypt_payload(m, off, chunks[k].csize, &chunks[k],
                                        ctx, err, errsz))
                        goto enc_fail;
                    off += len;
                    ++k;
                }
                if (egg_crypt_enc_finish(ctx, cinfo, cinfo_len)) goto enc_fail;
                egg_crypt_enc_free(ctx);
                if (opt->crypt == EGG_CRYPT_ZIP) {
                    cinfo[12] = (uint8_t)full_crc;
                    cinfo[13] = (uint8_t)(full_crc >> 8);
                    cinfo[14] = (uint8_t)(full_crc >> 16);
                    cinfo[15] = (uint8_t)(full_crc >> 24);
                    cinfo_len = 16;
                }
                crypt_method = opt->crypt;
                goto header;
enc_fail:
                egg_crypt_enc_free(ctx);
                for (k = 0; k < nchunks; ++k)
                    if (chunks[k].blob) fclose(chunks[k].blob);
                free(chunks);
                chunks = NULL;
                goto fail;
            }
            if (build_payload(m, &pre_codec, 0, m->usize, &pre, err, errsz))
                goto fail;
            if (pre.csize > 0xFFFFFFFFULL) {
                err_set(err, errsz, "'%s': %llu-byte compressed block — a "
                                    "block size field is 32 bits",
                        m->name, (unsigned long long)pre.csize);
                if (pre.blob) fclose(pre.blob);
                goto fail;
            }
            ctx = egg_crypt_enc_begin(opt->crypt, &opt->crypt_material[i],
                                      pre.crc, opt->password, cinfo,
                                      sizeof cinfo, &cinfo_len, err, errsz);
            if (!ctx) {
                if (pre.blob) fclose(pre.blob);
                goto fail;
            }
            /* The stream to encrypt is csize bytes (store: csize = usize). */
            if (encrypt_payload(m, 0, pre.csize, &pre, ctx, err, errsz) ||
                egg_crypt_enc_finish(ctx, cinfo, cinfo_len)) {
                egg_crypt_enc_free(ctx);
                if (pre.blob) fclose(pre.blob);
                goto fail;
            }
            egg_crypt_enc_free(ctx);
            if (opt->crypt == EGG_CRYPT_ZIP) {
                /* Complete Encrypt Info ZipCrypto: 12 verifier bytes then the
                 * CRC-32 of the UNCOMPRESSED content, low byte first (spec
                 * §12.2), which brings the field to 16 bytes. */
                cinfo[12] = (uint8_t)pre.crc;
                cinfo[13] = (uint8_t)(pre.crc >> 8);
                cinfo[14] = (uint8_t)(pre.crc >> 16);
                cinfo[15] = (uint8_t)(pre.crc >> 24);
                cinfo_len = 16;
            }
            crypt_method = opt->crypt;
            have_pre = 1;
        }

header:

        /* file header: file_id = index of the member in the archive */
        if (write_member_header(f, m, i, splitting ? &lay : NULL,
                                crypt_method, cinfo, cinfo_len)) {
            if (have_pre && pre.blob) fclose(pre.blob);
            goto io;
        }

        if (opt->solid) continue;                 /* one block, after the headers */

        if (nchunks) {
            size_t k;

            for (k = 0; k < nchunks; ++k) {
                int64_t mark = splitting ? tell_at(f) : 0;

                if (put_u32(f, EGG_SIG_BLOCK) ||
                    put_u8(f, pre_codec.method) || put_u8(f, pre_codec.hint) ||
                    put_u32(f, (uint32_t)chunks[k].usize) ||
                    put_u32(f, (uint32_t)chunks[k].csize) ||
                    put_u32(f, chunks[k].crc) ||
                    put_u32(f, EGG_SIG_END) || (splitting && mark < 0)) {
                    fclose(chunks[k].blob);
                    goto io;
                }
                if (splitting && rec_close(&lay, mark, f)) {
                    fclose(chunks[k].blob);
                    goto fail;
                }
                if (splitting) {
                    int64_t dmark = tell_at(f);
                    if (dmark < 0 || layout_add(&lay, (uint64_t)dmark,
                                                chunks[k].csize, 0)) {
                        fclose(chunks[k].blob);
                        goto io;
                    }
                }
                if (copy_stream(f, chunks[k].blob, err, errsz)) {
                    fclose(chunks[k].blob);
                    goto fail;
                }
                fclose(chunks[k].blob);
                chunks[k].blob = NULL;
            }
            free(chunks);
            chunks = NULL;
            continue;
        }

        if (have_pre) {
            int64_t mark = splitting ? tell_at(f) : 0;

            if (put_u32(f, EGG_SIG_BLOCK) || put_u8(f, pre_codec.method) ||
                put_u8(f, pre_codec.hint) || put_u32(f, (uint32_t)pre.usize) ||
                put_u32(f, (uint32_t)pre.csize) || put_u32(f, pre.crc) ||
                put_u32(f, EGG_SIG_END) || (splitting && mark < 0)) {
                fclose(pre.blob);
                goto io;
            }
            if (splitting && rec_close(&lay, mark, f)) {
                fclose(pre.blob);
                goto fail;
            }
            /* The encrypted stream is exactly csize bytes: the ZipCrypto
             * verifier is in Encrypt Info, not in the block data (measured on the
             * encrypted volumes of lot H). */
            if (splitting) {
                int64_t dmark = tell_at(f);
                if (dmark < 0 || layout_add(&lay, (uint64_t)dmark,
                                            pre.csize, 0)) {
                    fclose(pre.blob);
                    goto io;
                }
            }
            if (copy_stream(f, pre.blob, err, errsz)) {
                fclose(pre.blob);
                goto fail;
            }
            fclose(pre.blob);
            continue;
        }

        if (!m->is_dir && m->usize > 0) {
            uint64_t off = 0;
            Codec c;

            if (member_codec(opt->profile, m->name, &c, err, errsz)) goto fail;
            while (off < m->usize) {
                uint64_t len = m->usize - off;
                Payload pl;

                if (len > EGG_BLOCK_MAX) len = EGG_BLOCK_MAX;   /* 3 GiB, measured */
                if (build_payload(m, &c, off, len, &pl, err, errsz)) goto fail;
                if (pl.csize > 0xFFFFFFFFULL) {
                    err_set(err, errsz, "'%s': %llu-byte compressed block — a "
                                        "block size field is 32 bits",
                            m->name, (unsigned long long)pl.csize);
                    if (pl.blob) fclose(pl.blob);
                    goto fail;
                }
                {
                    int64_t mark = splitting ? tell_at(f) : 0;

                    if (put_u32(f, EGG_SIG_BLOCK) || put_u8(f, c.method) ||
                        put_u8(f, c.hint) || put_u32(f, (uint32_t)pl.usize) ||
                        put_u32(f, (uint32_t)pl.csize) || put_u32(f, pl.crc) ||
                        put_u32(f, EGG_SIG_END) ||
                        (splitting && mark < 0)) {
                        if (pl.blob) fclose(pl.blob);
                        goto io;
                    }
                    if (splitting && rec_close(&lay, mark, f)) {
                        if (pl.blob) fclose(pl.blob);
                        goto fail;
                    }
                }
                {
                    int64_t mark = splitting ? tell_at(f) : 0;

                    if (splitting && mark < 0) {
                        if (pl.blob) fclose(pl.blob);
                        goto io;
                    }
                    if (pl.blob) {
                        int rc = copy_stream(f, pl.blob, err, errsz);
                        fclose(pl.blob);
                        if (rc) goto fail;
                    } else if (copy_range(f, m->path, off, len, err, errsz)) {
                        goto fail;
                    }
                    if (splitting && layout_add(&lay, (uint64_t)mark, pl.csize, 0))
                        goto fail;
                }
                off += len;
            }
        }
    }

    if (opt->solid) {
        /* The blocks follow the last header: that is their place in
         * nested_normal_solid.egg (BLOCK just before the end marker). The stream
         * is the concatenation of the members, cut into 3 GiB slices compressed
         * INDEPENDENTLY — measured on huge_solid.egg, whose two blocks are
         * identical to those of huge_deflate.egg (same csize and CRC for 3 GiB
         * then 2 GiB). Each block therefore carries its own CRC; a directory or
         * an empty file contributes nothing. */
        FILE *cat = NULL;
        uint64_t total = 0, off = 0;
        /* The solid stream follows the same table as the members: it is what
         * gives the hint (deflate 6/5/LZMA 6 in 8.0; deflate 2/4/LZMA 8 in
         * 12.30) and the zlib level of the stream. */
        Codec sc;

        if (member_codec(opt->profile, "", &sc, err, errsz)) {
            fclose(cat);
            goto fail;
        }
        uint8_t method = sc.method;
        const int solid_hint = sc.hint;

        if (concat_items(items, n, &cat, &total, err, errsz)) goto fail;
        do {
            uint64_t len = total - off;
            Payload pl;

            if (len > EGG_BLOCK_MAX) len = EGG_BLOCK_MAX;
            memset(&pl, 0, sizeof pl);
            if (fseeko(cat, (off_t)off, SEEK_SET) != 0) {
                err_set(err, errsz, "solid stream: unreadable position");
                fclose(cat);
                goto fail;
            }
            if (method == EGG_M_LZMA) {
                if (egg_lzma_encode_stream(cat, len, &pl.blob, &pl.csize,
                                           &pl.crc, err, errsz)) {
                    fclose(cat);
                    goto fail;
                }
                pl.usize = len;
            } else if (deflate_stream(cat, len, sc.level, &pl, err, errsz)) {
                fclose(cat);
                goto fail;
            }
            if (pl.csize > 0xFFFFFFFFULL) {
                err_set(err, errsz, "solid stream of %llu compressed bytes — "
                                    "a block size field is 32 bits",
                        (unsigned long long)pl.csize);
                fclose(pl.blob);
                fclose(cat);
                goto fail;
            }
            if (put_u32(f, EGG_SIG_BLOCK) || put_u8(f, method) ||
                put_u8(f, (uint8_t)solid_hint) || put_u32(f, (uint32_t)pl.usize) ||
                put_u32(f, (uint32_t)pl.csize) || put_u32(f, pl.crc) ||
                put_u32(f, EGG_SIG_END)) {
                fclose(pl.blob);
                fclose(cat);
                goto io;
            }
            if (copy_stream(f, pl.blob, err, errsz)) {
                fclose(pl.blob);
                fclose(cat);
                goto fail;
            }
            fclose(pl.blob);
            off += len;
        } while (off < total);
        fclose(cat);
    }

    {                                              /* fin d'archive */
        int64_t mark = splitting ? tell_at(f) : 0;

        if (put_u32(f, EGG_SIG_END) || (splitting && mark < 0) ||
            (splitting && rec_close(&lay, mark, f)))
            goto io;
    }

    if (splitting) {
        if (fflush(f) || fseeko(f, 0, SEEK_SET) != 0) goto io;
        if (layout_split(out, f, &lay, opt, n_volumes, err, errsz)) {
            fclose(f);
            free(lay.v);
            return -1;
        }
        free(lay.v);
        if (fclose(f)) {
            err_set(err, errsz, "temporary file: %s", strerror(errno));
            return -1;
        }
        return 0;
    }

    if (fclose(f)) {
        err_set(err, errsz, "%s : %s", out, strerror(errno));
        remove(out);
        return -1;
    }
    return 0;

io:
    err_set(err, errsz, "%s: cannot write (%s)",
            splitting ? "temporary file" : out, strerror(errno));
fail:
    fclose(f);
    free(lay.v);
    if (!splitting) remove(out);
    return -1;
}
