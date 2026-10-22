/* egg.c — reader for ALZip's EGG container (.egg).
 *
 * Structure implemented from FORMAT-EGG.md (measured on the ALZip 8 samples):
 * EGGA header, prefix section (Split/Solid/Dummy), file headers and sub-headers,
 * blocks, end markers.
 *
 * Volumes: Split Info gives the identifiers of the neighbouring volumes; as
 * spec §13.1 describes, each volume is found by scanning the `.egg` files of the
 * same directory by Header ID, then the data areas are concatenated in chain
 * order (the first volume keeps its header and its prefix).
 *
 * Block decoding: 0 (store), 1 (raw deflate, src/alz_inflate.c), 2 (bzip2,
 * src/egg_bzip2.c), 3 (AZO, src/egg_azo.c) and 4 (LZMA, src/egg_lzma.c).
 * Encryption covers ZipCrypto, AES-128/256 and LEA-128/256 (methods 5 and 6,
 * src/egg_crypt.c and src/egg_lea.c).
 *
 * Memory: a single volume is mmap()ed, and each member is decoded then written
 * block by block (1 MiB slices for store), never holding the whole member. Only
 * solid archives are decoded as a whole, their stream being shared between the
 * members (spec §14.3).
 *
 * Solid archives (Solid Info prefix): the blocks of all members form a single
 * continuous stream (spec §14.3), decoded then spread over the members in
 * archive order (solid_decode below); the same methods are accepted, LZMA
 * included (both solid m3 references are reproduced).
 */
#include "egg.h"
#include "alz_inflate.h"
#include "egg_azo.h"
#include "egg_bzip2.h"
#include "egg_crypt.h"
#include "egg_lzma.h"
#include "zlib.h"          /* crc32 (zlib vendored) */

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define EGG_MAX_VOLUMES 4096
#define EGG_PATH_MAX    4096

/* ------------------------------------------------------------------- bytes */
static uint16_t le16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static uint32_t le32(const uint8_t *p)
{
    return (uint32_t)le16(p) | ((uint32_t)le16(p + 2) << 16);
}
static uint64_t le64(const uint8_t *p)
{
    return (uint64_t)le32(p) | ((uint64_t)le32(p + 4) << 32);
}

static void err_set(char *err, size_t errsz, const char *fmt, ...)
{
    va_list ap;
    if (!err || !errsz) return;
    va_start(ap, fmt);
    vsnprintf(err, errsz, fmt, ap);
    va_end(ap);
}

/* ------------------------------------------------------------------ volumes */
typedef struct EggVol {
    char     *path;
    uint16_t  version;
    uint32_t  header_id;
    uint32_t  prev;
    uint32_t  next;
    size_t    payload;   /* data offset after the header and the prefix */
    int       solid;
} EggVol;

typedef struct VolList {
    EggVol *vol;
    size_t  n;
    size_t  cap;
} VolList;

static int vol_push(VolList *l, const EggVol *v)
{
    if (l->n == l->cap) {
        size_t cap = l->cap ? l->cap * 2 : 8;
        EggVol *grown = realloc(l->vol, cap * sizeof *grown);
        if (!grown) return -1;
        l->vol = grown;
        l->cap = cap;
    }
    l->vol[l->n++] = *v;
    return 0;
}

static void vol_free(VolList *l)
{
    size_t i;
    for (i = 0; i < l->n; ++i) free(l->vol[i].path);
    free(l->vol);
    l->vol = NULL;
    l->n = l->cap = 0;
}

static int read_at(FILE *f, void *buf, size_t n)
{
    return fread(buf, 1, n, f) == n ? 0 : -1;
}

/* "extra field" (spec §4): flags(1) + size (UInt16 or UInt32).
 * Returns 0 and the size of the data block that follows. */
static int read_extra_field(FILE *f, uint8_t *flags, uint32_t *size)
{
    uint8_t b[4];
    if (read_at(f, b, 1)) return -1;
    *flags = b[0];
    if (b[0] & 0x01) {
        if (read_at(f, b, 4)) return -1;
        *size = le32(b);
    } else {
        if (read_at(f, b, 2)) return -1;
        *size = le16(b);
    }
    return 0;
}

static int skip_bytes(FILE *f, uint32_t n)
{
    return fseek(f, (long)n, SEEK_CUR) == 0 ? 0 : -1;
}

/* Reads the volume header and the prefix section up to the end marker.
 * `v->payload` receives the offset of the volume data. */
static int read_volume(const char *path, EggVol *v, char *err, size_t errsz)
{
    uint8_t b[16];
    FILE *f = fopen(path, "rb");
    long pos;

    if (!f) {
        err_set(err, errsz, "%s: %s", path, strerror(errno));
        return -1;
    }
    memset(v, 0, sizeof *v);
    v->path = strdup(path);
    if (!v->path) {
        err_set(err, errsz, "out of memory");
        fclose(f);
        return -1;
    }

    if (read_at(f, b, 14) || le32(b) != EGG_SIG_ARCHIVE) {
        err_set(err, errsz, "%s: EGGA header missing", path);
        goto fail;
    }
    v->version   = le16(b + 4);
    v->header_id = le32(b + 6);
    /* b[10..13]: reserved, observed as zero in the corpus */

    for (;;) {
        uint8_t flags;
        uint32_t size;
        if (read_at(f, b, 4)) {
            err_set(err, errsz, "%s: truncated prefix", path);
            goto fail;
        }
        if (le32(b) == EGG_SIG_END) break;
        if (le32(b) == EGG_SIG_FILE) {          /* empty prefix (continuation volume) */
            if (fseek(f, -4, SEEK_CUR) != 0) {
                err_set(err, errsz, "%s: recul impossible", path);
                goto fail;
            }
            break;
        }
        if (le32(b) == EGG_SIG_SPLIT) {
            if (read_extra_field(f, &flags, &size) || size != 8 || read_at(f, b, 8)) {
                err_set(err, errsz, "%s: Split Info invalide", path);
                goto fail;
            }
            v->prev = le32(b);
            v->next = le32(b + 4);
            continue;
        }
        if (le32(b) == EGG_SIG_SOLID) {
            if (read_extra_field(f, &flags, &size) || skip_bytes(f, size)) {
                err_set(err, errsz, "%s: Solid Info invalide", path);
                goto fail;
            }
            v->solid = 1;
            continue;
        }
        if (le32(b) == EGG_SIG_DUMMY || le32(b) == EGG_SIG_SKIP ||
            le32(b) == EGG_SIG_GENCRYPT) {
            if (read_extra_field(f, &flags, &size) || skip_bytes(f, size)) {
                err_set(err, errsz, "%s: invalid prefix sub-header", path);
                goto fail;
            }
            continue;
        }
        err_set(err, errsz, "%s: unexpected prefix sub-header %08x", path, le32(b));
        goto fail;
    }

    pos = ftell(f);
    if (pos < 0) {
        err_set(err, errsz, "%s: ftell", path);
        goto fail;
    }
    v->payload = (size_t)pos;
    fclose(f);
    return 0;

fail:
    free(v->path);
    v->path = NULL;
    fclose(f);
    return -1;
}

static uint8_t *slurp(const char *path, size_t *out_n, char *err, size_t errsz)
{
    FILE *f = fopen(path, "rb");
    uint8_t *buf;
    long n;

    if (!f) {
        err_set(err, errsz, "%s: %s", path, strerror(errno));
        return NULL;
    }
    if (fseek(f, 0, SEEK_END) != 0 || (n = ftell(f)) < 0 ||
        fseek(f, 0, SEEK_SET) != 0) {
        err_set(err, errsz, "%s: taille illisible", path);
        fclose(f);
        return NULL;
    }
    buf = malloc((size_t)n + 1);
    if (!buf) {
        err_set(err, errsz, "out of memory for %s", path);
        fclose(f);
        return NULL;
    }
    if (n && fread(buf, 1, (size_t)n, f) != (size_t)n) {
        err_set(err, errsz, "%s: short read", path);
        free(buf);
        fclose(f);
        return NULL;
    }
    fclose(f);
    *out_n = (size_t)n;
    return buf;
}

static int ends_with_egg(const char *name)
{
    size_t n = strlen(name);
    return n > 4 && strcmp(name + n - 4, ".egg") == 0;
}

/* Gathers the volumes of the chain containing `first`: the `.egg` files of the
 * same directory are indexed by Header ID, then the chain is walked from the head
 * (prev == 0) through `next`. */
static int collect_volumes(const char *first, VolList *list,
                           char *err, size_t errsz)
{
    EggVol start;
    char dirbuf[EGG_PATH_MAX];
    const char *slash;
    DIR *d;
    struct dirent *de;
    size_t i, j;

    if (read_volume(first, &start, err, errsz)) return -1;
    if (vol_push(list, &start)) {
        free(start.path);
        err_set(err, errsz, "out of memory");
        return -1;
    }
    if (!start.prev && !start.next) return 0;       /* archive mono-volume */

    snprintf(dirbuf, sizeof dirbuf, "%s", first);
    slash = strrchr(dirbuf, '/');
    if (slash) dirbuf[slash - dirbuf] = 0;
    else snprintf(dirbuf, sizeof dirbuf, ".");
    d = opendir(dirbuf);
    if (!d) {
        err_set(err, errsz, "%s: dossier illisible", dirbuf);
        return -1;
    }
    while ((de = readdir(d)) != NULL && list->n < EGG_MAX_VOLUMES) {
        char candidate[EGG_PATH_MAX + 264];
        EggVol v;
        int dup = 0;

        if (!ends_with_egg(de->d_name)) continue;
        if (strlen(dirbuf) + 1 + strlen(de->d_name) >= sizeof candidate) continue;
        snprintf(candidate, sizeof candidate, "%s/%s", dirbuf, de->d_name);
        if (!strcmp(candidate, first)) continue;
        if (read_volume(candidate, &v, err, errsz)) continue;   /* not an EGG */
        for (i = 0; i < list->n; ++i)
            if (list->vol[i].header_id == v.header_id) dup = 1;
        if (dup || vol_push(list, &v)) free(v.path);
    }
    closedir(d);

    /* order: walk up through `prev` to the head, then down through `next` */
    {
        size_t *chain = malloc(EGG_MAX_VOLUMES * sizeof *chain);
        EggVol *kept;
        size_t n = 0, head = 0, requested = 0;
        int guard = 0;

        if (!chain) {
            err_set(err, errsz, "out of memory");
            return -1;
        }
        for (i = 0; i < list->n; ++i)
            if (!strcmp(list->vol[i].path, first)) requested = i;

        while (list->vol[head].prev && guard++ < EGG_MAX_VOLUMES) {
            for (j = 0; j < list->n; ++j)
                if (list->vol[j].header_id == list->vol[head].prev) break;
            if (j == list->n) {
                err_set(err, errsz, "(%s) previous volume %08x missing",
                        first, list->vol[head].prev);
                free(chain);
                return -1;
            }
            head = j;
        }
        if (list->vol[head].prev) {
            err_set(err, errsz, "(%s) cyclic volume chain (prev)", first);
            free(chain);
            return -1;
        }
        i = head;
        for (;;) {
            chain[n++] = i;
            if (!list->vol[i].next || n >= EGG_MAX_VOLUMES) break;
            for (j = 0; j < list->n; ++j)
                if (list->vol[j].header_id == list->vol[i].next) break;
            if (j == list->n) {
                err_set(err, errsz, "(%s) volume suivant %08x introuvable",
                        first, list->vol[i].next);
                free(chain);
                return -1;
            }
            i = j;
        }
        for (j = 0; j < n; ++j)
            if (chain[j] == requested) break;
        if (j == n) {
            err_set(err, errsz, "(%s) volume missing from the Split Info chain", first);
            free(chain);
            return -1;
        }

        kept = malloc(n * sizeof *kept);
        if (!kept) {
            err_set(err, errsz, "out of memory");
            free(chain);
            return -1;
        }
        for (i = 0; i < n; ++i) kept[i] = list->vol[chain[i]];
        for (i = 0; i < list->n; ++i) {          /* free the volumes outside the chain */
            int in_chain = 0;
            for (j = 0; j < n; ++j) if (chain[j] == i) in_chain = 1;
            if (!in_chain) free(list->vol[i].path);
        }
        memcpy(list->vol, kept, n * sizeof *kept);
        list->n = n;
        free(kept);
        free(chain);
    }
    return 0;
}

/* ------------------------------------------------------ flux logique + parse */
static int build_logical(const VolList *list, EggArchive *arc,
                         char *err, size_t errsz)
{
    size_t total, i, off;

    /* Single volume: mmap() the file instead of copying it twice (slurp then
     * concatenation). The parser reads only this stream, and egg_close()
     * unmaps it: a 5 GiB .egg then no longer occupies the heap, only the page
     * cache. Falls back to a full read when mmap fails. */
    if (list->n == 1) {
        int fd = open(list->vol[0].path, O_RDONLY);
        struct stat st;

        if (fd >= 0 && !fstat(fd, &st) && st.st_size > 0) {
            void *m = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_PRIVATE,
                           fd, 0);
            if (m != MAP_FAILED) {
                close(fd);
                arc->logical = m;
                arc->logical_size = (size_t)st.st_size;
                arc->map = m;
                arc->map_size = (size_t)st.st_size;
                return 0;
            }
        }
        if (fd >= 0) close(fd);
    }
    uint8_t *buf;
    uint8_t **parts = calloc(list->n, sizeof *parts);
    size_t *sizes = calloc(list->n, sizeof *sizes);

    if (!parts || !sizes) {
        free(parts); free(sizes);
        err_set(err, errsz, "out of memory");
        return -1;
    }
    for (i = 0; i < list->n; ++i) {
        parts[i] = slurp(list->vol[i].path, &sizes[i], err, errsz);
        if (!parts[i]) goto fail;
        if (sizes[i] < list->vol[i].payload) {
            err_set(err, errsz, "%s: volume shorter than its prefix",
                    list->vol[i].path);
            goto fail;
        }
    }

    /* the first volume keeps its header and its prefix; the following ones only
     * bring their data (spec §13.2). */
    total = sizes[0];
    for (i = 1; i < list->n; ++i) total += sizes[i] - list->vol[i].payload;

    buf = malloc(total + 1);
    if (!buf) {
        err_set(err, errsz, "out of memory (%zu bytes)", total);
        goto fail;
    }
    memcpy(buf, parts[0], sizes[0]);
    off = sizes[0];
    for (i = 1; i < list->n; ++i) {
        memcpy(buf + off, parts[i] + list->vol[i].payload,
               sizes[i] - list->vol[i].payload);
        off += sizes[i] - list->vol[i].payload;
    }
    for (i = 0; i < list->n; ++i) free(parts[i]);
    free(parts); free(sizes);

    arc->logical = buf;
    arc->logical_size = total;
    return 0;

fail:
    for (i = 0; i < list->n; ++i) free(parts[i]);
    free(parts); free(sizes);
    return -1;
}

typedef struct Parser {
    const uint8_t *buf;
    size_t         size;
    size_t         pos;
} Parser;

static int need_at(const Parser *p, size_t off, size_t n)
{
    return off <= p->size && n <= p->size - off;
}

static uint32_t sig_at(const Parser *p, size_t off)
{
    return need_at(p, off, 4) ? le32(p->buf + off) : 0xFFFFFFFFu;
}

/* Sub-header with an "extra field" at `pos`: returns the data offset and their
 * size, or -1 when truncated. */
static int subheader(const Parser *p, size_t pos, size_t *data, uint32_t *size)
{
    uint8_t flags;
    size_t hdr;

    if (!need_at(p, pos, 5)) return -1;             /* sig(4) + flags(1) */
    flags = p->buf[pos + 4];
    hdr = (flags & 0x01) ? 5 : 3;                   /* flags + taille(2|4) */
    if (!need_at(p, pos, 4 + hdr)) return -1;
    *size = (flags & 0x01) ? le32(p->buf + pos + 5) : le16(p->buf + pos + 5);
    if (!need_at(p, pos, 4 + hdr + *size)) return -1;
    *data = pos + 4 + hdr;
    return 0;
}

static int parse_prefix(Parser *p, EggArchive *arc, char *err, size_t errsz)
{
    for (;;) {
        uint32_t sig;
        size_t data;
        uint32_t size;

        if (!need_at(p, p->pos, 4)) {
            err_set(err, errsz, "truncated prefix @%#zx", p->pos);
            return -1;
        }
        sig = sig_at(p, p->pos);
        if (sig == EGG_SIG_END) { p->pos += 4; return 0; }
        if (sig == EGG_SIG_FILE) return 0;          /* empty prefix */
        if (subheader(p, p->pos, &data, &size)) {
            err_set(err, errsz, "truncated prefix @%#zx", p->pos);
            return -1;
        }
        if (sig == EGG_SIG_SOLID) {
            arc->solid = 1;
        } else if (sig != EGG_SIG_SPLIT && sig != EGG_SIG_DUMMY &&
                   sig != EGG_SIG_SKIP && sig != EGG_SIG_GENCRYPT) {
            err_set(err, errsz, "unexpected prefix sub-header %08x @%#zx",
                    sig, p->pos);
            return -1;
        }
        p->pos = data + size;
    }
}

static int parse_subheaders(Parser *p, EggEntry *e, char *err, size_t errsz)
{
    for (;;) {
        uint32_t sig;
        size_t data;
        uint32_t size;
        uint8_t flags;

        if (!need_at(p, p->pos, 4)) {
            err_set(err, errsz, "truncated sub-headers @%#zx", p->pos);
            return -1;
        }
        sig = sig_at(p, p->pos);
        if (sig == EGG_SIG_END) { p->pos += 4; return 0; }
        if (sig == EGG_SIG_BLOCK) {
            err_set(err, errsz,
                    "unterminated sub-headers before a block @%#zx", p->pos);
            return -1;
        }
        if (subheader(p, p->pos, &data, &size)) {
            err_set(err, errsz, "truncated sub-header @%#zx", p->pos);
            return -1;
        }
        flags = p->buf[p->pos + 4];

        if (sig == EGG_SIG_FILENAME) {
            size_t q = data;
            if (flags & 0x08) q += 2;               /* locale */
            if (flags & 0x10) q += 4;               /* parent path id */
            if (q > data + size) {
                err_set(err, errsz, "Filename: inconsistent flags @%#zx", p->pos);
                return -1;
            }
            free(e->name);
            e->name = malloc(data + size - q + 1);
            if (!e->name) {
                err_set(err, errsz, "out of memory");
                return -1;
            }
            memcpy(e->name, p->buf + q, data + size - q);
            e->name[data + size - q] = 0;
            e->name_flags = flags;
        } else if (sig == EGG_SIG_WININFO) {
            if (size != 9) {
                err_set(err, errsz, "Windows File Info de taille %u", size);
                return -1;
            }
            e->filetime = le64(p->buf + data);
            e->attrs = p->buf[data + 8];
            e->has_wininfo = 1;
        } else if (sig == EGG_SIG_ENCRYPT) {
            if (size < 1) {
                err_set(err, errsz, "Encrypt Info vide");
                return -1;
            }
            e->crypt = p->buf[data];
            e->crypt_size = (int)size;
            if (e->crypt != EGG_CRYPT_ZIP && e->crypt != EGG_CRYPT_AES128 &&
                e->crypt != EGG_CRYPT_AES256 && e->crypt != EGG_CRYPT_LEA128 &&
                e->crypt != EGG_CRYPT_LEA256) {
                err_set(err, errsz, "unknown encryption method %u", e->crypt);
                return -1;
            }
            /* The Encrypt Info field is [method(1)][salt, verifier, HMAC]: the
             * first byte is the method (already read above), the following ones
             * are the key data (spec §12.2) kept to derive the key. The ZipCrypto
             * check CRC is NOT here: it is the high byte of the block CRC
             * (§12.3). */
            {
                uint32_t n = size > 0 ? size - 1 : 0;
                e->crypt_info_len = (uint8_t)(n < sizeof e->crypt_info
                                              ? n : sizeof e->crypt_info);
                memcpy(e->crypt_info, p->buf + data + 1, e->crypt_info_len);
            }
        } else if (sig != EGG_SIG_COMMENT && sig != EGG_SIG_POSIXINFO &&
                   sig != EGG_SIG_DUMMY) {
            err_set(err, errsz, "unexpected sub-header %08x @%#zx", sig, p->pos);
            return -1;
        }
        p->pos = data + size;
    }
}

static int parse_blocks(Parser *p, EggEntry *e, char *err, size_t errsz)
{
    for (;;) {
        uint32_t sig;
        size_t data, start;
        uint32_t size;

        if (!need_at(p, p->pos, 4)) {
            err_set(err, errsz, "truncated blocks @%#zx", p->pos);
            return -1;
        }
        sig = sig_at(p, p->pos);
        if (sig == EGG_SIG_COMMENT || sig == EGG_SIG_FILE || sig == EGG_SIG_END)
            return 0;
        if (sig == EGG_SIG_ENCRYPT || sig == EGG_SIG_DUMMY) {
            if (subheader(p, p->pos, &data, &size)) {
                err_set(err, errsz, "truncated sub-header between blocks @%#zx", p->pos);
                return -1;
            }
            p->pos = data + size;
            continue;
        }
        if (sig != EGG_SIG_BLOCK) {
            err_set(err, errsz, "bloc inattendu %08x @%#zx", sig, p->pos);
            return -1;
        }
        if (!need_at(p, p->pos, 18)) {
            err_set(err, errsz, "truncated block header @%#zx", p->pos);
            return -1;
        }
        {
            EggBlock blk;
            EggBlock *grown;

            blk.method = p->buf[p->pos + 4];
            blk.hint   = p->buf[p->pos + 5];
            blk.usize  = le32(p->buf + p->pos + 6);
            blk.csize  = le32(p->buf + p->pos + 10);
            blk.crc32  = le32(p->buf + p->pos + 14);
            start = p->pos + 18;
            if (sig_at(p, start) != EGG_SIG_END) {
                err_set(err, errsz,
                        "missing end marker after the block header @%#zx", start);
                return -1;
            }
            start += 4;
            if (start > p->size || blk.csize > p->size - start) {
                err_set(err, errsz, "truncated block data (%u expected) @%#zx",
                        blk.csize, start);
                return -1;
            }
            blk.data = p->buf + start;
            grown = realloc(e->blocks, (e->nblocks + 1) * sizeof *grown);
            if (!grown) {
                err_set(err, errsz, "out of memory");
                return -1;
            }
            e->blocks = grown;
            e->blocks[e->nblocks++] = blk;
            p->pos = start + blk.csize;
        }
    }
}

static int add_entry(EggArchive *arc, const EggEntry *e, char *err, size_t errsz)
{
    EggEntry *grown = realloc(arc->entries, (arc->nentries + 1) * sizeof *grown);
    if (!grown) {
        err_set(err, errsz, "out of memory");
        return -1;
    }
    arc->entries = grown;
    arc->entries[arc->nentries++] = *e;
    return 0;
}

static int egg_parse(EggArchive *arc, char *err, size_t errsz)
{
    Parser p;

    p.buf = arc->logical;
    p.size = arc->logical_size;
    p.pos = 0;
    if (!need_at(&p, 0, 14) || le32(p.buf) != EGG_SIG_ARCHIVE) {
        err_set(err, errsz, "EGGA header missing from the logical stream");
        return -1;
    }
    arc->version   = le16(p.buf + 4);
    arc->header_id = le32(p.buf + 6);
    p.pos = 14;

    if (parse_prefix(&p, arc, err, errsz)) return -1;

    for (;;) {
        uint32_t sig;
        size_t data;
        uint32_t size;

        if (!need_at(&p, p.pos, 4)) {
            err_set(err, errsz, "marqueur de fin final absent @%#zx", p.pos);
            return -1;
        }
        sig = sig_at(&p, p.pos);
        if (sig == EGG_SIG_END) {
            p.pos += 4;
            if (p.pos != p.size) {
                err_set(err, errsz, "data after the final end marker @%#zx",
                        p.pos);
                return -1;
            }
            return 0;
        }
        if (sig == EGG_SIG_COMMENT) {                  /* commentaire d'archive */
            if (subheader(&p, p.pos, &data, &size)) {
                err_set(err, errsz, "truncated archive comment @%#zx", p.pos);
                return -1;
            }
            p.pos = data + size;
            continue;
        }
        if (sig != EGG_SIG_FILE) {
            err_set(err, errsz, "expected a file header, found %08x @%#zx",
                    sig, p.pos);
            return -1;
        }
        {
            EggEntry e;
            memset(&e, 0, sizeof e);
            e.crypt = EGG_CRYPT_NONE;
            if (!need_at(&p, p.pos, 16)) {
                err_set(err, errsz, "truncated file header @%#zx", p.pos);
                return -1;
            }
            e.file_id = le32(p.buf + p.pos + 4);
            e.usize   = le64(p.buf + p.pos + 8);
            p.pos += 16;
            if (parse_subheaders(&p, &e, err, errsz) ||
                parse_blocks(&p, &e, err, errsz)) {
                free(e.name); free(e.blocks);
                return -1;
            }
            if (!e.name) {
                err_set(err, errsz, "member #%u without a file name", e.file_id);
                free(e.blocks);
                return -1;
            }
            if (add_entry(arc, &e, err, errsz)) {
                free(e.name); free(e.blocks);
                return -1;
            }
        }
    }
}

/* ------------------------------------------------------------------ ouverture */
int egg_open(const char *path, EggArchive *arc, char *err, size_t errsz)
{
    VolList list;

    memset(&list, 0, sizeof list);
    memset(arc, 0, sizeof *arc);
    if (collect_volumes(path, &list, err, errsz)) {
        vol_free(&list);
        return -1;
    }
    arc->solid = list.vol[0].solid;
    if (build_logical(&list, arc, err, errsz)) {
        vol_free(&list);
        return -1;
    }
    vol_free(&list);
    if (egg_parse(arc, err, errsz)) {
        egg_close(arc);
        return -1;
    }
    return 0;
}

void egg_close(EggArchive *arc)
{
    size_t i;
    if (!arc) return;
    for (i = 0; i < arc->nentries; ++i) {
        free(arc->entries[i].name);
        free(arc->entries[i].blocks);
    }
    free(arc->entries);
    if (arc->map) munmap(arc->map, arc->map_size);
    else free(arc->logical);
    memset(arc, 0, sizeof *arc);
}

/* ------------------------------------------------------------------ extraction */
static int mkdir_p(const char *path)
{
    char tmp[EGG_PATH_MAX];
    size_t i, len;

    len = strlen(path);
    if (!len || len >= sizeof tmp) return -1;
    memcpy(tmp, path, len + 1);
    for (i = 1; i < len; ++i) {
        if (tmp[i] == '/') {
            tmp[i] = 0;
            if (mkdir(tmp, 0777) && errno != EEXIST) return -1;
            tmp[i] = '/';
        }
    }
    return (mkdir(tmp, 0777) && errno != EEXIST) ? -1 : 0;
}

/* Readable name of an encryption method, for error messages (the bare number
 * would be confused with the block methods'). */
static const char *crypt_label(int c)
{
    switch (c) {
        case EGG_CRYPT_ZIP:    return "ZipCrypto";
        case EGG_CRYPT_AES128: return "AES-128";
        case EGG_CRYPT_AES256: return "AES-256";
        case EGG_CRYPT_LEA128: return "LEA-128";
        case EGG_CRYPT_LEA256: return "LEA-256";
        default:               return "?";
    }
}

/* Refuses anything whose decoding is not implemented, BEFORE writing anything.
 * Solid archives pass this check: their blocks are decoded by solid_decode(),
 * with the same allowed methods. */
static int preflight(const EggArchive *arc, const EggExtractOpts *opt,
                     char *err, size_t errsz)
{
    size_t i, j;
    int chiffre = 0;

    for (i = 0; i < arc->nentries; ++i) {
        const EggEntry *e = &arc->entries[i];

        if (e->crypt != EGG_CRYPT_NONE) {
            chiffre = 1;
            if (!opt->password || !opt->password[0]) {
                err_set(err, errsz, "'%s' is encrypted with %s: password required (-p)",
                        e->name, crypt_label(e->crypt));
                return -1;
            }
        }
        if (opt->raw) continue;     /* no decompression: method irrelevant */
        for (j = 0; j < e->nblocks; ++j) {
            uint8_t m = e->blocks[j].method;
            if (m != EGG_M_STORE && m != EGG_M_DEFLATE && m != EGG_M_BZIP2 &&
                m != EGG_M_AZO && m != EGG_M_LZMA) {
                err_set(err, errsz,
                        "'%s' uses block method %u: not implemented",
                        e->name, m);
                return -1;
            }
        }
    }
    /* ALZip never writes an encrypted solid archive (spec §14.1) and no
     * third-party sample exercises it: the solid stream shared between several
     * members would make the sharing of the decryptor state need checking, so it
     * is refused. */
    if (chiffre && arc->solid) {
        err_set(err, errsz,
                "solid AND encrypted archive: ALZip does not produce this "
                "combination (spec §14.1) and no sample exercises it: refused");
        return -1;
    }
    return 0;
}

/* Check for path traversal: reject absolute paths, Windows drive letters, and components navigating above root */
static int is_safe_relpath(const char *path)
{
    if (!path || !path[0]) return 0;
    if (path[0] == '/' || path[0] == '\\') return 0;
    if (isalpha((unsigned char)path[0]) && path[1] == ':') return 0;

    int depth = 0;
    const char *p = path;
    while (*p) {
        while (*p == '/' || *p == '\\') p++;
        if (!*p) break;
        const char *start = p;
        while (*p && *p != '/' && *p != '\\') p++;
        size_t len = (size_t)(p - start);
        if (len == 1 && start[0] == '.') {
            continue;
        }
        if (len == 2 && start[0] == '.' && start[1] == '.') {
            depth--;
            if (depth < 0) return 0;
        } else {
            depth++;
        }
    }
    return 1;
}

/* Opens a member's destination. `full` receives the final path (so a partial
 * file can be removed if decoding then fails); `*fp` is NULL for a directory,
 * which is only created (spec §8.3). */
static int open_blob(const EggEntry *e, const char *dest, char *full,
                     size_t fullsz, FILE **fp, char *err, size_t errsz,
                     int unix_paths)
{
    size_t i;

    if (!is_safe_relpath(e->name)) {
        fprintf(stderr, "Security warning: skipping unsafe path traversal '%s'\n", e->name);
        err_set(err, errsz, "Security warning: skipping unsafe path traversal '%s' (suspicious path in the archive)", e->name);
        return -1;
    }
    char safe_name[EGG_PATH_MAX];
    if (unix_paths) {
        size_t k = 0;
        for (i = 0; e->name[i] && k < sizeof(safe_name) - 1; ++i) {
            char c = e->name[i];
            if (c == '\\') c = '/';
            safe_name[k++] = (char)tolower((unsigned char)c);
        }
        safe_name[k] = '\0';
    } else {
        snprintf(safe_name, sizeof safe_name, "%s", e->name);
    }
    if (snprintf(full, fullsz, "%s/%s", dest, safe_name) >= (int)fullsz) {
        err_set(err, errsz, "path too long in the archive: %s", safe_name);
        return -1;
    }
    for (i = 0; full[i]; ++i) if (full[i] == '\\') full[i] = '/';

    if (e->has_wininfo && (e->attrs & 0x80)) {       /* directory (spec §8.3) */
        if (mkdir_p(full)) {
            err_set(err, errsz, "%s: %s", full, strerror(errno));
            return -1;
        }
        *fp = NULL;
        return 0;
    }
    {
        char parent[EGG_PATH_MAX];
        char *slash;
        snprintf(parent, sizeof parent, "%s", full);
        slash = strrchr(parent, '/');
        if (slash && slash != parent) {
            *slash = 0;
            if (mkdir_p(parent)) {
                err_set(err, errsz, "%s: %s", parent, strerror(errno));
                return -1;
            }
        }
    }

    *fp = fopen(full, "wb");
    if (!*fp) {
        err_set(err, errsz, "%s: %s", full, strerror(errno));
        return -1;
    }
    return 0;
}

/* Writes an already decoded member (`data`, `len`). Directories are only
 * created, with no content. */
static int write_blob(const EggEntry *e, const char *dest,
                      const uint8_t *data, size_t len, char *err, size_t errsz,
                      int unix_paths)
{
    char full[EGG_PATH_MAX];
    FILE *fp;

    if (open_blob(e, dest, full, sizeof full, &fp, err, errsz, unix_paths)) return -1;
    if (!fp) return 0;
    if (len && fwrite(data, 1, len, fp) != len) {
        err_set(err, errsz, "%s: short write", full);
        fclose(fp);
        remove(full);
        return -1;
    }
    if (fclose(fp)) {
        err_set(err, errsz, "%s: %s", full, strerror(errno));
        remove(full);
        return -1;
    }
    return 0;
}

/* Reader's write slice: memory no longer depends on the member size, only on
 * this buffer. */
#define EXTRACT_CHUNK (1u << 20)

static int put_stream(FILE *fp, const uint8_t *src, size_t len,
                      EggCryptDec *dec, uint32_t *block_crc,
                      uint32_t *member_crc, uint8_t *chunk,
                      char *err, size_t errsz)
{
    while (len) {
        size_t n = len < EXTRACT_CHUNK ? len : EXTRACT_CHUNK;

        memcpy(chunk, src, n);
        if (dec && egg_crypt_dec_update(dec, chunk, n)) {
            err_set(err, errsz, "decryption failed");
            return -1;
        }
        if (block_crc)  *block_crc  = (uint32_t)crc32(*block_crc, chunk, (uInt)n);
        if (member_crc) *member_crc = (uint32_t)crc32(*member_crc, chunk, (uInt)n);
        if (fp && fwrite(chunk, 1, n, fp) != n) {
            err_set(err, errsz, "short write");
            return -1;
        }
        src += n;
        len -= n;
    }
    return 0;
}

static int decode_block(const EggEntry *e, size_t i, const uint8_t *src,
                        uint32_t csize, uint8_t *dst, uint32_t usize,
                        char *err, size_t errsz)
{
    const EggBlock *b = &e->blocks[i];

    if (b->method == EGG_M_DEFLATE) {
        if (alz_inflate(src, csize, dst, usize) != 0) {
            err_set(err, errsz, "'%s': inflate failed (block %zu)",
                    e->name, i);
            return -1;
        }
    } else if (b->method == EGG_M_LZMA) {
        char lerr[160];
        if (egg_lzma_decode(src, csize, dst, usize, lerr, sizeof lerr) != 0) {
            err_set(err, errsz, "'%s' : %s (bloc %zu)", e->name, lerr, i);
            return -1;
        }
    } else if (b->method == EGG_M_AZO) {
        char aerr[160];
        if (egg_azo_decode(src, csize, dst, usize, aerr, sizeof aerr) != 0) {
            err_set(err, errsz, "'%s' : %s (bloc %zu)", e->name, aerr, i);
            return -1;
        }
    } else {
        char berr[160];
        if (egg_bzip2_decode(src, csize, dst, usize, berr, sizeof berr) != 0) {
            err_set(err, errsz, "'%s' : %s (bloc %zu)", e->name, berr, i);
            return -1;
        }
    }
    return 0;
}

/* Decodes ONE member block by block. Each decoded slice is written at once
 * (`fp`), or only checked when `fp` is NULL (first pass that establishes the
 * member CRC before writing anything). Memory: a 1 MiB slice for store, one block
 * for the codecs — never the whole member. */
static int member_decode(const EggEntry *e, const EggExtractOpts *opt, FILE *fp,
                         int raw, uint32_t *crc_out, char *err, size_t errsz)
{
    EggCryptDec *dec = NULL;
    uint8_t ver[12] = {0};
    uint8_t *chunk = NULL;
    uint32_t member_crc = (uint32_t)crc32(0, Z_NULL, 0);
    size_t i;
    int defer_zip = 0, rc = -1;

    if (e->crypt != EGG_CRYPT_NONE) {
        /* The ZipCrypto verifier carries the high byte of the WHOLE member CRC
         * (measured on huge_enc_zip.egg, 5 GiB in two blocks): for a single-block
         * member that is the block CRC and the check can be immediate; beyond
         * that it is deferred and compared at the end of the member. */
        int eager = e->nblocks <= 1;

        dec = egg_crypt_dec_begin(e->crypt, e->crypt_info, e->crypt_info_len,
                                  e->nblocks ? e->blocks[0].crc32 : 0,
                                  opt->password, eager, ver, err, errsz);
        if (!dec) return -1;
        defer_zip = !eager && e->crypt == EGG_CRYPT_ZIP;
        if (e->crypt == EGG_CRYPT_AES128 || e->crypt == EGG_CRYPT_AES256 ||
            e->crypt == EGG_CRYPT_LEA128 || e->crypt == EGG_CRYPT_LEA256) {
            /* Authentication (AES and LEA share the same HMAC) covers the whole
             * ciphertext: nothing in the clear is written before it has
             * succeeded. */
            for (i = 0; i < e->nblocks; ++i)
                if (egg_crypt_dec_auth(dec, e->blocks[i].data,
                                       e->blocks[i].csize))
                    goto done;
            if (egg_crypt_dec_ready(dec, err, errsz)) goto done;
        }
    }
    chunk = malloc(EXTRACT_CHUNK);
    if (!chunk) {
        err_set(err, errsz, "out of memory for '%s'", e->name);
        goto done;
    }

    for (i = 0; i < e->nblocks; ++i) {
        const EggBlock *b = &e->blocks[i];
        uint32_t block_crc = (uint32_t)crc32(0, Z_NULL, 0);

        if (raw) {
            if (put_stream(fp, b->data, b->csize, dec, NULL, NULL, chunk,
                           err, errsz))
                goto done;
            continue;
        }
        if (b->method == EGG_M_STORE) {
            if (b->csize != b->usize) {
                err_set(err, errsz, "'%s' : bloc store %u/%u",
                        e->name, b->csize, b->usize);
                goto done;
            }
            if (put_stream(fp, b->data, b->csize, dec, &block_crc, &member_crc,
                           chunk, err, errsz))
                goto done;
        } else {
            size_t csize = b->csize ? b->csize : 1;
            size_t usize = b->usize ? b->usize : 1;
            uint8_t *cbuf = malloc(csize);
            uint8_t *obuf = malloc(usize);

            if (!cbuf || !obuf) {
                free(cbuf);
                free(obuf);
                err_set(err, errsz, "out of memory for '%s'", e->name);
                goto done;
            }
            memcpy(cbuf, b->data, b->csize);
            if (dec && egg_crypt_dec_update(dec, cbuf, b->csize)) {
                free(cbuf);
                free(obuf);
                err_set(err, errsz, "decryption failed");
                goto done;
            }
            if (decode_block(e, i, cbuf, b->csize, obuf, b->usize,
                             err, errsz)) {
                free(cbuf);
                free(obuf);
                goto done;
            }
            free(cbuf);
            block_crc = (uint32_t)crc32(0, obuf, (uInt)b->usize);
            member_crc = (uint32_t)crc32(member_crc, obuf, (uInt)b->usize);
            if (fp && b->usize && fwrite(obuf, 1, b->usize, fp) != b->usize) {
                free(obuf);
                err_set(err, errsz, "short write for '%s'", e->name);
                goto done;
            }
            free(obuf);
        }
        if (block_crc != b->crc32) {
            err_set(err, errsz,
                    "'%s': CRC mismatch (block %zu: expected %08x, computed %08x)",
                    e->name, i, b->crc32, block_crc);
            goto done;
        }
    }
    if (defer_zip && (uint8_t)(member_crc >> 24) != ver[11]) {
        err_set(err, errsz, "'%s': ZipCrypto verifier differs from the whole "
                            "member CRC (expected %02x, computed %02x)",
                e->name, ver[11], (unsigned char)(member_crc >> 24));
        goto done;
    }
    *crc_out = member_crc;
    rc = 0;

 done:
    free(chunk);
    egg_crypt_dec_close(dec);
    return rc;
}

/* Extracts a non-solid member. For a multi-block ZipCrypto member, a first pass
 * decodes without writing to learn the member CRC and validate the verifier
 * BEFORE creating the file; the second pass writes. A failure while writing
 * removes the partial file. */
static int extract_entry(const EggEntry *e, const EggExtractOpts *opt,
                         const char *dest, int raw, char *err, size_t errsz)
{
    char full[EGG_PATH_MAX];
    FILE *fp = NULL;
    uint32_t crc = 0;
    size_t i, total = 0;

    if (!raw) {
        for (i = 0; i < e->nblocks; ++i) total += e->blocks[i].usize;
        if (total != (size_t)e->usize) {
            err_set(err, errsz, "'%s': blocks %zu bytes, header %llu",
                    e->name, total, (unsigned long long)e->usize);
            return -1;
        }
        if (e->crypt == EGG_CRYPT_ZIP && e->nblocks > 1 &&
            member_decode(e, opt, NULL, 0, &crc, err, errsz))
            return -1;
    } else if (e->crypt == EGG_CRYPT_ZIP && e->nblocks > 1) {
        err_set(err, errsz, "'%s': encrypted multi-block member — the verifier "
                            "carries the whole member CRC, unavailable without "
                            "decompression (--raw)", e->name);
        return -1;
    }

    if (open_blob(e, dest, full, sizeof full, &fp, err, errsz, opt ? opt->unix_paths : 0)) return -1;
    if (!fp) return 0;
    if (member_decode(e, opt, fp, raw, &crc, err, errsz)) {
        fclose(fp);
        remove(full);
        return -1;
    }
    if (fclose(fp)) {
        err_set(err, errsz, "%s: %s", full, strerror(errno));
        remove(full);
        return -1;
    }
    return 0;
}

/* ===== Solid archive: streaming decode towards the members =====
 *
 * The block payloads of all members, in archive order, form ONE compressed
 * stream whose output is the concatenation of the contents (spec §14.3). The
 * ALZip samples carry a single block, attached to the LAST member, whose usize
 * is the size of the whole stream (`nested_normal_solid.egg`: 822,784 bytes;
 * `unicode_normal_solid.egg`: 78).
 *
 * The decoder pushes the output into a sink that opens the members as it goes,
 * writes each slice into the current file and computes the CRC of the block
 * covering it: memory no longer depends on the archive size, only on a 64 KiB
 * slice and on the COMPRESSED stream (csize). A failure along the way closes the
 * current file and removes every file already written, as the non-solid reader
 * does for its partial member. */

typedef struct SolidBlock {
    uint64_t len;
    uint32_t crc;
} SolidBlock;

typedef struct SolidOut {
    const EggArchive *arc;
    const char       *dest;
    size_t            ent;          /* next entry to open */
    FILE             *fp;
    int               have_fp;
    char              full[EGG_PATH_MAX];
    uint64_t          entry_left;
    SolidBlock       *blocks;
    size_t            nblocks, blk;
    uint64_t          blk_left;
    uint32_t          blk_crc;
    char            **paths;        /* written files, removed on failure */
    size_t            npaths, path_cap;
    uint64_t          total;        /* bytes written */
    uint64_t          expect;
    char             *err;
    size_t            errsz;
    int               unix_paths;
} SolidOut;

static int solid_remember(SolidOut *s, const char *path)
{
    if (s->npaths == s->path_cap) {
        size_t cap = s->path_cap ? s->path_cap * 2 : 16;
        char **p = realloc(s->paths, cap * sizeof *p);

        if (!p) {
            err_set(s->err, s->errsz, "out of memory (file tracking)");
            return -1;
        }
        s->paths = p;
        s->path_cap = cap;
    }
    s->paths[s->npaths] = strdup(path);
    if (!s->paths[s->npaths]) {
        err_set(s->err, s->errsz, "out of memory (path)");
        return -1;
    }
    s->npaths++;
    return 0;
}

/* Frees the file list without removing the files (success). */
static void solid_forget(SolidOut *s)
{
    size_t i;

    for (i = 0; i < s->npaths; ++i) free(s->paths[i]);
    free(s->paths);
    s->paths = NULL;
    s->npaths = s->path_cap = 0;
}

/* Failure: closes the current file and removes everything written. */
static void solid_cleanup(SolidOut *s)
{
    size_t i;

    if (s->have_fp && s->fp) fclose(s->fp);
    s->fp = NULL;
    s->have_fp = 0;
    for (i = 0; i < s->npaths; ++i) {
        remove(s->paths[i]);
        free(s->paths[i]);
    }
    free(s->paths);
    s->paths = NULL;
    s->npaths = s->path_cap = 0;
}

/* Opens the next entry (directories and empty files are handled in place).
 * *done = 1 when there are none left. */
static int solid_open_next(SolidOut *s, int *done)
{
    *done = 0;
    while (s->ent < s->arc->nentries) {
        const EggEntry *e = &s->arc->entries[s->ent];

        if (e->has_wininfo && (e->attrs & 0x80)) {
            if (write_blob(e, s->dest, NULL, 0, s->err, s->errsz, s->unix_paths)) return -1;
            s->ent++;
            continue;
        }
        if (open_blob(e, s->dest, s->full, sizeof s->full, &s->fp,
                      s->err, s->errsz, s->unix_paths)) return -1;
        s->ent++;
        if (!s->fp) continue;                 /* directory already created */
        s->have_fp = 1;
        if (solid_remember(s, s->full)) return -1;
        s->entry_left = e->usize;
        if (s->entry_left == 0) {             /* empty file */
            if (fclose(s->fp)) {
                err_set(s->err, s->errsz, "%s : %s", s->full, strerror(errno));
                s->fp = NULL;
                s->have_fp = 0;
                return -1;
            }
            s->fp = NULL;
            s->have_fp = 0;
        }
        return 0;
    }
    *done = 1;
    return 0;
}

/* Checks the current block CRC and moves to the next one (skipping zero-length
 * blocks, whose CRC is the one of an empty buffer). */
static int solid_finish_block(SolidOut *s)
{
    if (s->blk >= s->nblocks) {
        err_set(s->err, s->errsz, "solid stream: more bytes than blocks");
        return -1;
    }
    if (s->blk_crc != s->blocks[s->blk].crc) {
        const char *name = s->ent ? s->arc->entries[s->ent - 1].name : "?";
        err_set(s->err, s->errsz,
                "solid stream: diverging CRC (block on '%s': expected %08x, "
                "computed %08x)", name, s->blocks[s->blk].crc, s->blk_crc);
        return -1;
    }
    s->blk++;
    while (s->blk < s->nblocks && s->blocks[s->blk].len == 0) {
        if (s->blocks[s->blk].crc != (uint32_t)crc32(0, Z_NULL, 0)) {
            err_set(s->err, s->errsz, "flux solide : CRC divergent (bloc vide)");
            return -1;
        }
        s->blk++;
    }
    if (s->blk < s->nblocks) {
        s->blk_left = s->blocks[s->blk].len;
        s->blk_crc = (uint32_t)crc32(0, Z_NULL, 0);
    } else {
        s->blk_left = 0;
        s->blk_crc = 0;
    }
    return 0;
}

/* First non-empty block (the caller already checked there is one). */
static void solid_start_blocks(SolidOut *s)
{
    s->blk = 0;
    while (s->blk < s->nblocks && s->blocks[s->blk].len == 0) {
        /* an empty block with a zero CRC is valid; the CRC is checked on the way */
        s->blk++;
    }
    s->blk_crc = (uint32_t)crc32(0, Z_NULL, 0);
    s->blk_left = s->blk < s->nblocks ? s->blocks[s->blk].len : 0;
}

static int solid_sink(void *ctx, const unsigned char *data, size_t len)
{
    SolidOut *s = ctx;

    while (len) {
        size_t n;

        if (!s->have_fp) {
            int done = 0;

            if (!s->blk_left && s->blk < s->nblocks &&
                solid_finish_block(s)) return -1;
            if (solid_open_next(s, &done)) return -1;
            if (done) {
                err_set(s->err, s->errsz,
                        "solid stream: more bytes than the members");
                return -1;
            }
            if (!s->have_fp) continue;
        }
        if (s->blk >= s->nblocks) {
            err_set(s->err, s->errsz,
                    "solid stream: more bytes than blocks");
            return -1;
        }
        n = len;
        if (n > s->entry_left) n = (size_t)s->entry_left;
        if (n > s->blk_left) n = (size_t)s->blk_left;
        if (n == 0) {
            if (solid_finish_block(s)) return -1;
            continue;
        }
        if (fwrite(data, 1, n, s->fp) != n) {
            err_set(s->err, s->errsz, "%s: short write", s->full);
            return -1;
        }
        s->blk_crc = (uint32_t)crc32(s->blk_crc, data, (uInt)n);
        s->blk_left -= n;
        s->entry_left -= n;
        s->total += n;
        data += n;
        len -= n;
        if (s->blk_left == 0 && solid_finish_block(s)) return -1;
        if (s->entry_left == 0) {
            if (fclose(s->fp)) {
                err_set(s->err, s->errsz, "%s : %s", s->full, strerror(errno));
                s->fp = NULL;
                s->have_fp = 0;
                return -1;
            }
            s->fp = NULL;
            s->have_fp = 0;
        }
    }
    return 0;
}

#define SOLID_CHUNK (64u * 1024u)

static int solid_extract(const EggArchive *arc, const EggExtractOpts *opt,
                         char *err, size_t errsz)
{
    SolidOut s;
    SolidBlock *blocks = NULL;
    size_t nblocks = 0, i, j;
    uint64_t expect = 0, csize = 0, off = 0;
    uint8_t method = 0;
    uint8_t *cbuf = NULL;
    int rc = -1;

    memset(&s, 0, sizeof s);
    s.arc = arc;
    s.dest = opt->dest ? opt->dest : ".";
    s.unix_paths = opt ? opt->unix_paths : 0;
    s.err = err;
    s.errsz = errsz;
    if (err && errsz) err[0] = 0;      /* the sink may hold the real cause */

    for (i = 0; i < arc->nentries; ++i) {
        const EggEntry *e = &arc->entries[i];

        if (e->has_wininfo && (e->attrs & 0x80)) continue;      /* directory */
        expect += e->usize;
        for (j = 0; j < e->nblocks; ++j) {
            const EggBlock *b = &e->blocks[j];
            SolidBlock *nb;

            if (nblocks == 0) method = b->method;
            else if (b->method != method) {
                err_set(err, errsz,
                        "solid stream: mixed block methods (%u and %u)",
                        method, b->method);
                goto done;
            }
            nb = realloc(blocks, (nblocks + 1) * sizeof *blocks);
            if (!nb) {
                err_set(err, errsz, "out of memory (solid blocks)");
                goto done;
            }
            blocks = nb;
            blocks[nblocks].len = b->usize;
            blocks[nblocks].crc = b->crc32;
            nblocks++;
            csize += b->csize;
        }
    }
    if (nblocks == 0 || expect == 0) {
        err_set(err, errsz, "empty solid stream (%zu block(s), %llu byte(s))",
                nblocks, (unsigned long long)expect);
        goto done;
    }
    if (csize > (uint64_t)SIZE_MAX) {
        err_set(err, errsz, "solid stream: %llu compressed bytes, out of range",
                (unsigned long long)csize);
        goto done;
    }

    cbuf = malloc(csize ? (size_t)csize : 1);
    if (!cbuf) {
        err_set(err, errsz, "out of memory (%llu compressed bytes)",
                (unsigned long long)csize);
        goto done;
    }
    for (i = 0; i < arc->nentries; ++i) {
        const EggEntry *e = &arc->entries[i];

        for (j = 0; j < e->nblocks; ++j) {
            memcpy(cbuf + off, e->blocks[j].data, e->blocks[j].csize);
            off += e->blocks[j].csize;
        }
    }

    s.blocks = blocks;
    s.nblocks = nblocks;
    s.expect = expect;
    solid_start_blocks(&s);

    if (method == EGG_M_STORE) {
        if (csize != expect) {
            err_set(err, errsz, "solid store stream: %llu bytes for %llu "
                                "expected", (unsigned long long)csize,
                    (unsigned long long)expect);
            goto done;
        }
        for (off = 0; off < csize; off += SOLID_CHUNK) {
            size_t n = csize - off < SOLID_CHUNK ? (size_t)(csize - off)
                                                 : SOLID_CHUNK;
            if (solid_sink(&s, cbuf + off, n)) goto fail;
        }
    } else if (method == EGG_M_BZIP2) {
        char berr[160];

        if (egg_bzip2_decode_to(cbuf, (size_t)csize, solid_sink, &s, expect,
                                berr, sizeof berr) != 0) {
            if (!(err && errsz && err[0]))
                err_set(err, errsz, "flux solide : %s", berr);
            goto fail;
        }
    } else if (method == EGG_M_LZMA) {
        char lerr[160];

        if (egg_lzma_decode_to(cbuf, (size_t)csize, solid_sink, &s, expect,
                               lerr, sizeof lerr) != 0) {
            if (!(err && errsz && err[0]))
                err_set(err, errsz, "flux solide : %s", lerr);
            goto fail;
        }
    } else if (method == EGG_M_AZO) {
        /* AZO is only emitted by the Optimized profile, which solid mode
         * forbids (spec §14.1): no sample can exist. The decoding is kept
         * anyway, into one buffer, so as not to refuse a stream a third party
         * might have written; it is the only solid path that is not streamed. */
        char aerr[160];
        uint8_t *obuf = malloc((size_t)expect);

        if (!obuf) {
            err_set(err, errsz, "out of memory (AZO solid stream)");
            goto fail;
        }
        if (egg_azo_decode(cbuf, (size_t)csize, obuf, (size_t)expect,
                           aerr, sizeof aerr) != 0) {
            free(obuf);
            err_set(err, errsz, "flux solide : %s", aerr);
            goto fail;
        }
        for (off = 0; off < expect; off += SOLID_CHUNK) {
            size_t n = expect - off < SOLID_CHUNK ? (size_t)(expect - off)
                                                  : SOLID_CHUNK;
            if (solid_sink(&s, obuf + off, n)) { free(obuf); goto fail; }
        }
        free(obuf);
    } else if (alz_inflate_to(cbuf, (size_t)csize, solid_sink, &s, expect,
                              NULL) != 0) {
        if (!(err && errsz && err[0]))
            err_set(err, errsz, "solid stream: inflate failed (%llu -> %llu)",
                    (unsigned long long)csize, (unsigned long long)expect);
        goto fail;
    }

    /* The stream must have stopped exactly at the end of the last block. */
    if (s.have_fp || s.blk_left || s.blk < nblocks || s.total != expect) {
        err_set(err, errsz, "solid stream: %llu bytes written, %llu expected "
                            "(%zu block(s) of %zu consumed)",
                (unsigned long long)s.total, (unsigned long long)expect,
                s.blk, nblocks);
        goto fail;
    }
    /* Remaining entries: directories and empty files to create. A non-empty
     * member here would mean the stream is shorter than the archive. */
    for (;;) {
        int done = 0;

        if (solid_open_next(&s, &done)) goto fail;
        if (done) break;
        if (s.have_fp) {
            err_set(err, errsz, "solid stream: members longer than the stream "
                                "(%llu bytes written for '%s')",
                    (unsigned long long)s.total, s.full);
            goto fail;
        }
    }
    solid_forget(&s);
    rc = 0;
    goto done;

 fail:
    solid_cleanup(&s);
 done:
    free(cbuf);
    free(blocks);
    return rc;
}

int egg_extract_all(const EggArchive *arc, const EggExtractOpts *opt,
                    char *err, size_t errsz)
{
    const char *dest = opt->dest ? opt->dest : ".";
    size_t i;
    int written = 0;
    int skipped_unsafe = 0;

    if (preflight(arc, opt, err, errsz)) return -1;
    if (mkdir_p(dest)) {
        err_set(err, errsz, "%s: %s", dest, strerror(errno));
        return -1;
    }
    if (opt->raw) {
        /* No decompression: the payload is written (decrypted when the member is
         * encrypted). Useful to check decryption independently of the codec, and
         * to recover data from an archive whose codec is not implemented yet. */
        for (i = 0; i < arc->nentries; ++i) {
            const EggEntry *e = &arc->entries[i];

            if (!is_safe_relpath(e->name)) {
                fprintf(stderr, "Security warning: skipping unsafe path traversal '%s'\n", e->name);
                skipped_unsafe++;
                continue;
            }

            if (e->has_wininfo && (e->attrs & 0x80)) {
                if (write_blob(e, dest, NULL, 0, err, errsz, opt ? opt->unix_paths : 0)) return -1;
            } else if (extract_entry(e, opt, dest, 1, err, errsz)) {
                return -1;
            }
            written++;
        }
        if (skipped_unsafe > 0) {
            err_set(err, errsz, "Security warning: skipping unsafe path traversal (%d member(s), suspicious path in the archive)",
                    skipped_unsafe);
            return -1;
        }
        return written;
    }
    if (arc->solid) {
        /* Streaming decode: the members are written as it goes, never holding
         * the decompressed stream in memory. */
        if (solid_extract(arc, opt, err, errsz)) return -1;
        return (int)arc->nentries;
    }
    for (i = 0; i < arc->nentries; ++i) {
        const EggEntry *e = &arc->entries[i];

        if (!is_safe_relpath(e->name)) {
            fprintf(stderr, "Security warning: skipping unsafe path traversal '%s'\n", e->name);
            skipped_unsafe++;
            continue;
        }

        if (e->has_wininfo && (e->attrs & 0x80)) {              /* directory */
            if (write_blob(e, dest, NULL, 0, err, errsz, opt ? opt->unix_paths : 0)) return -1;
        } else if (extract_entry(e, opt, dest, 0, err, errsz)) {
            return -1;
        }
        written++;
    }
    if (skipped_unsafe > 0) {
        err_set(err, errsz, "Security warning: skipping unsafe path traversal (%d member(s), suspicious path in the archive)",
                skipped_unsafe);
        return -1;
    }
    return written;
}
