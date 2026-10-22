/* cli_alz.c — ALZ implementation of the alzgg binary: create / extract / list
 * (src/alz.c routes both containers to this file or to cli_egg.c)
 *
 *   alzgg list    archive.alz
 *   alzgg extract archive.alz [-d dest]
 *   alzgg create  [-p none|faster|normal | -m0|-m1|-m2]
 *                 [-v bytes_per_volume] [-T "YYYY-MM-DD hh:mm:ss"]
 *                 -o archive.alz [path=>name ...]
 *
 * Vocabulary: the -p options above are the three ALZ profiles the GUI exposes
 * in 12.30 (No Compression, Faster, Normal); "method" is the container
 * identifier in the `meth` byte (0 store, 1 BZip2, 2 deflate, 3 deflate with
 * an obfuscated initialisation), unrelated to a profile number.
 *
 * The -m numbers of ALZipCon 12.30 were measured under Wine (code.c,
 * records.bin, biased.bin): `-m0` = No Compression (store), `-m1` = Faster
 * (zlib level 1), `-m2` = Normal (level 4, the default when -m is omitted).
 * `-m3` exits 0 without writing anything; ALZip 8.0's level 2 no longer has a
 * number, so the CLI refuses `-m3` and `-p fast` instead of inventing an
 * archive. 12.30 also sets attr=0x20 on every file (8.0 wrote 0).
 *
 * Solid: ALZ has no solid mode (Solid-Compression is EGG only, see
 * FORMAT-ALZ.md and FORMAT-EGG.md §14); -s is therefore refused with
 * ALZipCon's exact message:
 *   ERROR : The format doesn't support Solid-Compression
 *
 * Scope: only container methods 0 and 2 are implemented, because they are the
 * only ones ALZip writes (the 8.0 corpus covers every ALZ profile and carries
 * no other method; Formats/Alz.dll embeds no BZip2 codec). Methods 1 and 3 are
 * refused explicitly by extract. Format details: FORMAT-ALZ.md. The deflate
 * decoder is src/alz_inflate.c; the encoder uses the vendored
 * zlib 1.3.1 sources (src/zlib_deflate/, zlib licence) to produce a deflate
 * stream that is bit-exact with 12.30's settings:
 *   faster = level 1, normal = level 4,
 *   always memLevel=8, wbits=-15 (RAW deflate, no zlib header).
 * With -p none: method 0 (store). Empty file: fd=0, no optional block.
 *
 * Multi-volume (corpus): every non-final volume is EXACTLY volsz bytes
 * (100 KiB = 102400): 8 archive-header bytes, data, 16 END bytes. A member
 * crossing a boundary writes its header once (in its starting volume); its
 * data continues directly (offset 8) in the next volume.
 */
#include "alz.h"
#include "egg.h"        /* EGG_CRYPT_* (ZipCrypto encryption shared with EGG) */
#include "egg_crypt.h"  /* egg_crypt_decrypt */
#include "alz_inflate.h"
#include "zlib.h"   /* deflate + crc32 (vendored zlib 1.3.1) */
#include <limits.h>

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#define MAX_FILES 4096
#define MAX_VOLS  128
#define HDR_FIXED 12   /* magic(4) + name_len(2) + attr(1) + time(4) + fd(1) + unk2(1) */

/* memory buffer reused when writing the volumes */
/* ------------------------------------------------------------------- bytes */

/* CRC-32 of a buffer larger than 4 GiB: the zlib API takes a uInt (32 bits),
 * so a 4.5 GiB member used to be truncated (the CRC of huge_store_45g.alz did
 * not match). Large members are hashed in 1 GiB slices, which yields the same
 * CRC as a single zlib call. */
static uint32_t crc32_buf(const uint8_t *p, uint64_t len)
{
    uint32_t crc = (uint32_t)crc32(0, Z_NULL, 0);
    while (len) {
        uInt n = len > (1u << 30) ? (1u << 30) : (uInt)len;
        crc = (uint32_t)crc32(crc, p, n);
        p += n;
        len -= n;
    }
    return crc;
}
static uint16_t le16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static uint32_t le32(const uint8_t *p) { return (uint32_t)le16(p) | ((uint32_t)le16(p + 2) << 16); }
static uint64_t leN(const uint8_t *p, int n)
{
    uint64_t v = 0; int i;
    for (i = 0; i < n; ++i) v |= (uint64_t)p[i] << (8 * i);
    return v;
}
static void put16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static void put32(uint8_t *p, uint32_t v)
{
    put16(p, (uint16_t)(v & 0xFFFF));
    put16(p + 2, (uint16_t)(v >> 16));
}
static void putN(uint8_t *p, uint64_t v, int n)
{
    int i; for (i = 0; i < n; ++i) p[i] = (uint8_t)(v >> (8 * i));
}

static void die(const char *msg, const char *arg)
{
    if (msg && arg) fprintf(stderr, "alzgg: %s: %s\n", msg, arg);
    else if (msg)   fprintf(stderr, "alzgg: %s\n", msg);
    exit(2);
}

static uint8_t *slurp(const char *path, size_t *out_n)
{
    FILE *f = fopen(path, "rb");
    uint8_t *buf;
    long n;
    if (!f) die(strerror(errno), path);
    fseek(f, 0, SEEK_END);
    n = ftell(f);
    if (n < 0) die("ftell", path);
    fseek(f, 0, SEEK_SET);
    buf = malloc((size_t)n + 1);
    if (!buf) die("out of memory", NULL);
    if (n && fread(buf, 1, (size_t)n, f) != (size_t)n) die("read", path);
    fclose(f);
    *out_n = (size_t)n;
    return buf;
}

static void dump_file(const char *path, const uint8_t *buf, size_t n)
{
    FILE *fp = fopen(path, "wb");
    if (!fp) die(strerror(errno), path);
    if (n) fwrite(buf, 1, n, fp);
    fclose(fp);
}

/* ------------------------------------------------------------ read/write */
/* Volume mapped in memory (mmap, read-only): its content is read once, but
 * its pages only count in RSS as they are touched — a 512 MiB volume no longer
 * forces a 512 MiB heap. `mapped` tells an mmap from a malloc buffer (empty
 * file). */
typedef struct Rd {
    uint8_t *buf;
    size_t   size;
    int      mapped;
    size_t   released;   /* leading bytes already dropped from RSS (mmap) */
} Rd;
typedef struct Wr { uint8_t *buf; size_t len, cap; } Wr;
static void rd_load(Rd *r, const char *path);
static void rd_release(Rd *r, size_t upto);

/* Pages kept behind the cursor before being dropped from RSS: at least one
 * read slice, so a range still in use is never dropped. */
#define RD_LAG (16u << 20)

/* global cursor (volume index + position inside the volume) */
typedef struct Cur { Rd *vols; size_t nvols; size_t v; size_t pos; } Cur;

static int cur_avail(const Cur *c, size_t n) { return c->pos + n <= c->vols[c->v].size; }
static const uint8_t *cur_ptr(const Cur *c)  { return c->vols[c->v].buf + c->pos; }
static const uint8_t *cur_ptr_at(const Cur *c, size_t n) { return c->vols[c->v].buf + c->pos + n; }
static void cur_skip(Cur *c, size_t n)       { c->pos += n; }

/* advance to the next "element start": if we are too close to the end of the
   volume to have a magic + 16 END bytes, move to the next volume.
   Returns 0 when there is nothing left. */
static int cur_seek_item(Cur *c)
{
    for (;;) {
        if (c->pos + 4 <= c->vols[c->v].size) return 1;
        if (c->v + 1 >= c->nvols) return 0;
        c->v++; c->pos = 8;
    }
}

/* read a BLZ header: c must point at the first byte AFTER the magic */
static int read_blz(Cur *c, AlzFileHeader *h, AlzFileOptional *o)
{
    memset(h, 0, sizeof *h);
    memset(o, 0, sizeof *o);
    if (!cur_avail(c, 9)) return -1;
    h->name_len = le16(cur_ptr(c));
    h->attr     = cur_ptr(c)[2];
    h->dos_time = le32(cur_ptr(c) + 3);
    h->fd       = cur_ptr(c)[7];
    h->unknown2 = cur_ptr(c)[8];
    cur_skip(c, 9);
    if (h->fd & 0xF0) {
        if (!cur_avail(c, 6)) return -1;
        o->method   = cur_ptr(c)[0];
        o->unknown3 = cur_ptr(c)[1];
        o->crc      = le32(cur_ptr(c) + 2);
        cur_skip(c, 6);
        o->nb = h->fd >> 4;
        if (!cur_avail(c, (size_t)o->nb * 2)) return -1;
        o->csize = leN(cur_ptr(c), o->nb);
        o->usize = leN(cur_ptr(c) + o->nb, o->nb);
        cur_skip(c, (size_t)o->nb * 2);
    }
    /* the name MUST follow in the same volume (corpus hypothesis: yes) */
    if (!cur_avail(c, h->name_len)) return -1;
    return 0;
}

/* raw data crossing volumes: advance the cursor, return a buffer */
static uint8_t *span_read(Cur *c, uint64_t n)
{
    uint8_t *out = malloc((size_t)n + 1);
    uint64_t got = 0;
    if (!out) die("out of memory", NULL);
    while (got < n) {
        /* a volume's data area stops 16 bytes before the end of file: that is
           the volume's END. To read further, move to the next volume (data at
           offset 8). */
        if (c->pos + 16 >= c->vols[c->v].size) {
            if (c->v + 1 >= c->nvols) { free(out); return NULL; }
            c->v++; c->pos = 8;
            continue;
        }
        size_t avail = (c->vols[c->v].size - 16) - c->pos;
        size_t take  = avail < (size_t)(n - got) ? avail : (size_t)(n - got);
        memcpy(out + got, c->vols[c->v].buf + c->pos, take);
        c->pos += take; got += take;
    }
    return out;
}

/* Streaming read of a member data area: returns a pointer to the longest
 * contiguous range available (the member may cross several volumes) without
 * ever copying the bytes. 0 = end of the area.
 *
 * Used by the store method: the member is then copied to the output in slices
 * instead of being materialised in memory, which is exactly the case where
 * csize equals usize. */
typedef struct Span {
    Cur     *c;
    uint64_t left;
} Span;

static void span_init(Span *s, Cur *c, uint64_t n)
{
    s->c = c;
    s->left = n;
}

/* Direct pointer to `n` contiguous bytes of the current volume, or NULL if the
 * area crosses a volume boundary (rare: only split members).
 * Avoids copying a deflate member's COMPRESSED stream: it is read from the
 * mmap instead of into a csize-byte buffer. */
static const uint8_t *span_map(Cur *c, uint64_t n)
{
    if (c->pos + 16 + n > c->vols[c->v].size) return NULL;
    {
        const uint8_t *p = c->vols[c->v].buf + c->pos;
        c->pos += (size_t)n;
        return p;
    }
}

/* `cap` bounds the returned slice (SIZE_MAX to take it whole). */
static size_t span_chunk(Span *s, const uint8_t **p, size_t cap)
{
    while (s->left) {
        if (s->c->pos + 16 >= s->c->vols[s->c->v].size) {
            if (s->c->v + 1 >= s->c->nvols) return 0;
            s->c->v++; s->c->pos = 8;
            continue;
        }
        {
            size_t avail = (s->c->vols[s->c->v].size - 16) - s->c->pos;
            size_t take  = avail < (size_t)s->left ? avail : (size_t)s->left;

            if (take > cap) take = cap;
            *p = s->c->vols[s->c->v].buf + s->c->pos;
            s->c->pos += take;
            s->left -= take;
            if (s->c->pos > RD_LAG)
                rd_release(&s->c->vols[s->c->v], s->c->pos - RD_LAG);
            return take;
        }
    }
    return 0;
}

static void span_skip(Cur *c, uint64_t n)
{
    Span sp;
    const uint8_t *p;
    span_init(&sp, c, n);
    while (sp.left) {
        if (!span_chunk(&sp, &p, SIZE_MAX)) break;
    }
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

static void load_volumes(const char *arc, Rd *vols, size_t *nvols)
{
    /* volpath must hold base + the volume suffix (".a128" at most for
       MAX_VOLS): otherwise the compiler flags a possible truncation. */
    char base[4096], volpath[sizeof base + 8];
    size_t bl;
    if (snprintf(base, sizeof base, "%s", arc) >= (int)sizeof base)
        die("path too long", arc);
    bl = strlen(base);
    if (bl > 4 && !strcmp(base + bl - 4, ".alz")) base[bl - 4] = 0;
    *nvols = 1;
    rd_load(&vols[0], arc);
    if (vols[0].size < 8 || le32(vols[0].buf) != ALZ_MAGIC)
        die("not an ALZ file", arc);
    for (;;) {
        snprintf(volpath, sizeof volpath, "%s.a%02zu", base, *nvols - 1);
        FILE *fp = fopen(volpath, "rb");
        if (!fp) break;
        fclose(fp);
        if (*nvols >= MAX_VOLS) die("too many volumes", NULL);
        rd_load(&vols[*nvols], volpath);
        (*nvols)++;
    }
}

static void rd_load(Rd *r, const char *path)
{
    struct stat st;
    int fd = open(path, O_RDONLY);

    if (fd < 0) die(strerror(errno), path);
    if (fstat(fd, &st) < 0) { close(fd); die(strerror(errno), path); }
    r->size = (size_t)st.st_size;
    r->mapped = 0;
    if (r->size) {
        void *p = mmap(NULL, r->size, PROT_READ, MAP_PRIVATE, fd, 0);
        if (p == MAP_FAILED) { close(fd); die(strerror(errno), path); }
        r->buf = p;
        r->mapped = 1;
    } else {
        r->buf = malloc(1);
        if (!r->buf) { close(fd); die("out of memory", NULL); }
    }
    close(fd);
}

/* Drop the already-consumed pages of an mmap'ed volume from the resident set.
 * Without this, an end-to-end extraction leaves the whole volume in RSS (a
 * sequential read touches every page), even though those pages are reclaimable
 * page cache. RD_LAG bytes are kept behind the cursor so the slice just handed
 * to the caller is never dropped under its feet; a dropped page is re-read from
 * the file if touched again, so the content stays correct whatever happens
 * next. */
static void rd_release(Rd *r, size_t upto)
{
    static size_t page = 0;

    if (!page) {
        long ps = sysconf(_SC_PAGESIZE);
        page = ps > 0 ? (size_t)ps : 4096;
    }
    if (!r->mapped || upto <= r->released) return;
    if (upto > r->size) upto = r->size;
    upto &= ~(page - 1);
    if (upto <= r->released) return;
    madvise(r->buf + r->released, upto - r->released, MADV_DONTNEED);
    r->released = upto;
}

static void rd_unload(Rd *r)
{
    if (r->mapped) munmap(r->buf, r->size);
    else free(r->buf);
    r->buf = NULL;
    r->size = 0;
    r->mapped = 0;
}

/* --------------------------------------------------------- write (buffer) */
static void wr_bytes(Wr *w, const void *p, size_t n)
{
    if (w->len + n > w->cap) {
        w->cap = (w->len + n) * 2 + 256;
        w->buf = realloc(w->buf, w->cap);
        if (!w->buf) die("out of memory", NULL);
    }
    memcpy(w->buf + w->len, p, n);
    w->len += n;
}
static void wr_u8(Wr *w, uint8_t v)   { wr_bytes(w, &v, 1); }
static void wr_u16(Wr *w, uint16_t v) { uint8_t t[2]; put16(t, v); wr_bytes(w, t, 2); }
static void wr_u32(Wr *w, uint32_t v) { uint8_t t[4]; put32(t, v); wr_bytes(w, t, 4); }
static void wrN(Wr *w, uint64_t v, int n)
{
    uint8_t t[8]; putN(t, v, n); wr_bytes(w, t, (size_t)n);
}

/* END record closing a volume */
static void wr_end_record(Wr *w, int final)
{
    wr_u32(w, ALZ_END_MAGIC);
    wr_u32(w, 0);
    wr_u32(w, 0);
    wr_u32(w, final ? ALZ_FINAL_MAGIC : ALZ_NONFINAL_MAGIC);
}

/* ================================================================== LIST === */
/* Size of a member's data, verifier included: an encrypted member
 * (fd bit 0) starts with the 12-byte ZipCrypto verifier, then csize bytes of
 * encrypted stream (measured on the lot-B references: the 12 decrypted bytes
 * end with the high byte of the member CRC, and the following stream inflates
 * to the right bytes once decrypted). */
static uint64_t data_span(const AlzFileHeader *h, const AlzFileOptional *o)
{
    return (uint64_t)o->csize + ((h->fd & 0x01) ? 12u : 0u);
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

static int cmd_list(const char *arc, int unix_paths, int bare_list)
{
    Rd vols[MAX_VOLS];
    size_t nvols, i;
    Cur c;
    load_volumes(arc, vols, &nvols);
    c.vols = vols; c.nvols = nvols; c.v = 0; c.pos = 8;

    for (;;) {
        if (!cur_seek_item(&c)) die("archive without END", arc);
        uint32_t m = le32(cur_ptr(&c));
        if (m == ALZ_END_MAGIC) {
            uint32_t m2 = le32(cur_ptr_at(&c, 12));
            if (!bare_list) {
                printf("END vol=%zu %s\n", c.v,
                       m2 == ALZ_FINAL_MAGIC ? "final" :
                       m2 == ALZ_NONFINAL_MAGIC ? "non-final" : "unknown magic");
            }
            break;
        }
        if (m != ALZ_FILE_MAGIC) die("unexpected magic in the archive", arc);
        cur_skip(&c, 4);
        AlzFileHeader h; AlzFileOptional o;
        if (read_blz(&c, &h, &o) < 0) die("truncated BLZ header", arc);

        char name_buf[4096];
        if (unix_paths) {
            format_unix_path((const char *)cur_ptr(&c), (size_t)h.name_len, name_buf, sizeof(name_buf));
        } else {
            size_t copy_len = (size_t)h.name_len < sizeof(name_buf) - 1 ? (size_t)h.name_len : sizeof(name_buf) - 1;
            memcpy(name_buf, cur_ptr(&c), copy_len);
            name_buf[copy_len] = '\0';
        }

        if (bare_list) {
            printf("%s\n", name_buf);
        } else {
            /* attr is printed: it is the only way to check DOS attribute parity
             * (RO/hidden/system, bit 4 = directory) without extracting, and no
             * corpus archive lets us guess it. */
            printf("%s meth=%d csize=%llu usize=%llu crc=%08x fd=%02x attr=%02x ts=%08x%s\n",
                   name_buf,
                   o.method, (unsigned long long)o.csize, (unsigned long long)o.usize,
                   o.crc, h.fd, h.attr, h.dos_time,
                   (h.fd & 0x01) ? " crypt=zip2" : "");
        }
        cur_skip(&c, h.name_len);
        if (h.fd & 0xF0 && data_span(&h, &o)) {
            uint8_t *data = span_read(&c, data_span(&h, &o));
            if (!data) die("inconsistent data", NULL);
            free(data);
        }
    }
    for (i = 0; i < nvols; ++i) rd_unload(&vols[i]);
    return 0;
}

/* =============================================================== EXTRACT === */
static void mkdir_p(char *path)
{
    char *p = path + (path[0] == '/' ? 1 : 0);
    for (;; ++p) {
        if (*p == '/' || !*p) {
            char keep = *p;
            *p = 0;
            mkdir(path, 0777);
            *p = keep;
            if (!keep) break;
        }
    }
}

static FILE *dest_open(const char *dest, const uint8_t *name, int name_len,
                       char fullname[4096], int unix_paths)
{
    char safe_name[4096];
    if (name_len <= 0 || name_len >= (int)sizeof(safe_name)) {
        fprintf(stderr, "Security warning: skipping unsafe path traversal '%.*s'\n",
                name_len, (const char *)name);
        die("Security warning: skipping unsafe path traversal (suspicious path in the archive)", NULL);
    }
    memcpy(safe_name, name, name_len);
    safe_name[name_len] = '\0';
    if (!is_safe_relpath(safe_name)) {
        fprintf(stderr, "Security warning: skipping unsafe path traversal '%s'\n", safe_name);
        die("Security warning: skipping unsafe path traversal (suspicious path in the archive)", safe_name);
    }

    snprintf(fullname, 4096, "%s/%.*s", dest, name_len, (const char *)name);
    size_t dlen = strlen(dest);
    for (char *q = fullname; *q; ++q) {
        if (*q == '\\') *q = '/';
        if (unix_paths && (size_t)(q - fullname) > dlen) *q = (char)tolower((unsigned char)*q);
    }
    {
        char parent[4096];
        char *slash;
        snprintf(parent, sizeof parent, "%s", fullname);
        slash = strrchr(parent, '/');
        if (slash && slash != parent) { *slash = 0; mkdir_p(parent); }
    }
    FILE *fp = fopen(fullname, "wb");
    if (!fp) die(strerror(errno), fullname);
    return fp;
}

/* Read slice for members decrypted as a stream. */
#define ALZ_CHUNK (1u << 20)

/* Output of an ALZ member: write + incremental CRC-32, without a buffer the
 * size of the member. */
typedef struct AlzOut {
    FILE    *fp;
    uint32_t crc;
} AlzOut;

static int alz_out_sink(void *ctx, const unsigned char *data, size_t len)
{
    AlzOut *o = ctx;

    if (len) o->crc = (uint32_t)crc32(o->crc, data, (uInt)len);
    if (len && fwrite(data, 1, len, o->fp) != len) return -1;
    return 0;
}

static void why_set(char *why, size_t whysz, const char *msg)
{
    if (why && whysz) snprintf(why, whysz, "%s", msg);
}

/* Write the decompressed content of ONE member to `fp`, as a stream: store is
 * copied straight from the volumes, deflate is inflated into the sink,
 * encrypted data is decrypted in 1 MiB slices and handled the same way. No
 * buffer the size of the member is allocated (only the COMPRESSED stream of a
 * deflate member is materialised, csize being much smaller than usize).
 *
 * Returns: 0 success; 1 password required; 2 decryption refused; -1
 * decoding/writing, `why` describing the cause. */
static int member_stream(Cur *c, const AlzFileOptional *o, int encrypted,
                         const char *password, FILE *fp, uint32_t *crc_out,
                         char *why, size_t whysz)
{
    AlzOut out;
    uint64_t csize = o->csize, usize = o->usize;
    int store = (o->method == ALZ_M_STORE);

    out.fp = fp;
    out.crc = (uint32_t)crc32(0, Z_NULL, 0);
    if (why && whysz) why[0] = 0;

    if (encrypted) {
        uint8_t ver[12], info[16];
        char cerr[256];
        EggCryptDec *dec;
        uint8_t *raw = span_read(c, 12);

        if (!raw) { why_set(why, whysz, "inconsistent data (missing volume?)"); return -1; }
        if (!password) { free(raw); why_set(why, whysz, "password required"); return 1; }
        memcpy(ver, raw, 12);
        free(raw);
        memcpy(info, ver, 12);
        memset(info + 12, 0, 4);
        dec = egg_crypt_dec_begin(EGG_CRYPT_ZIP, info, sizeof info, o->crc,
                                  password, 1, NULL, cerr, sizeof cerr);
        memset(ver, 0, sizeof ver);
        memset(info, 0, sizeof info);
        if (!dec) { why_set(why, whysz, cerr); return 2; }

        if (store) {
            uint8_t *chunk = malloc(ALZ_CHUNK);
            Span sp;
            int rc = 0;

            if (!chunk) { egg_crypt_dec_close(dec); why_set(why, whysz, "out of memory"); return -1; }
            span_init(&sp, c, csize);
            while (sp.left) {
                const uint8_t *p;
                size_t n = span_chunk(&sp, &p, ALZ_CHUNK);

                if (!n) { rc = -1; break; }
                memcpy(chunk, p, n);
                if (egg_crypt_dec_update(dec, chunk, n) ||
                    alz_out_sink(&out, chunk, n)) { rc = -1; break; }
            }
            free(chunk);
            egg_crypt_dec_close(dec);
            if (rc) { why_set(why, whysz, "decryption or write interrupted"); return -1; }
        } else {
            uint8_t *buf = span_read(c, csize);
            int rc;

            if (!buf) { egg_crypt_dec_close(dec); why_set(why, whysz, "inconsistent data (missing volume?)"); return -1; }
            rc = egg_crypt_dec_update(dec, buf, (size_t)csize) ? -1 :
                 alz_inflate_to(buf, (size_t)csize, alz_out_sink, &out, usize, NULL);
            free(buf);
            egg_crypt_dec_close(dec);
            if (rc) { why_set(why, whysz, "inflate failed"); return -1; }
        }
        *crc_out = out.crc;
        return 0;
    }

    if (store) {
        Span sp;

        span_init(&sp, c, csize);
        while (sp.left) {
            const uint8_t *p;
            /* Bounded slices: this is what lets rd_release() hand back already
             * written pages as it goes (a single 512 MiB slice would keep them
             * all resident until the end). */
            size_t n = span_chunk(&sp, &p, ALZ_CHUNK);

            if (!n) { why_set(why, whysz, "inconsistent data (missing volume?)"); return -1; }
            if (alz_out_sink(&out, p, n)) { why_set(why, whysz, "incomplete write"); return -1; }
        }
        *crc_out = out.crc;
        return 0;
    }

    {
        const uint8_t *mapped = span_map(c, csize);
        const uint8_t *cdata = mapped;
        uint8_t *owned = NULL;
        int rc;

        if (!cdata) {
            owned = span_read(c, csize);
            cdata = owned;
            if (!cdata) { why_set(why, whysz, "inconsistent data (missing volume?)"); return -1; }
        }
        rc = alz_inflate_to(cdata, (size_t)csize, alz_out_sink, &out, usize, NULL);
        free(owned);
        if (rc) { why_set(why, whysz, "inflate failed"); return -1; }
        *crc_out = out.crc;
        return 0;
    }
}

static int cmd_extract(const char *arc, const char *dest, const char *password, int unix_paths)
{
    static Rd vols[MAX_VOLS];
    size_t nvols, i;
    Cur c;
    static char volpath_name[4096];

    mkdir_p((char *)dest);
    load_volumes(arc, vols, &nvols);
    c.vols = vols; c.nvols = nvols; c.v = 0; c.pos = 8;

    int n_extracted = 0, bad = 0;
    for (;;) {
        if (!cur_seek_item(&c)) break;
        uint32_t m = le32(cur_ptr(&c));
        if (m == ALZ_END_MAGIC) break;
        if (m != ALZ_FILE_MAGIC) die("unexpected magic in the archive", arc);
        cur_skip(&c, 4);
        AlzFileHeader h; AlzFileOptional o;
        if (read_blz(&c, &h, &o) < 0) die("truncated BLZ header", arc);
        const uint8_t *name = cur_ptr(&c);
        cur_skip(&c, h.name_len);

        char relname[4096];
        int safe = 1;
        if (h.name_len <= 0 || h.name_len >= (int)sizeof(relname)) {
            safe = 0;
        } else {
            memcpy(relname, name, h.name_len);
            relname[h.name_len] = '\0';
            safe = is_safe_relpath(relname);
        }

        if (!safe) {
            fprintf(stderr, "Security warning: skipping unsafe path traversal '%.*s'\n",
                    h.name_len, (const char *)name);
            bad++;
            if (h.fd & 0xF0) {
                uint64_t to_skip = o.csize;
                if (h.fd & 0x01) to_skip += 12;
                span_skip(&c, to_skip);
            }
            continue;
        }

        if (unix_paths) {
            char pbuf[4096];
            format_unix_path((const char *)name, (size_t)h.name_len, pbuf, sizeof(pbuf));
            printf("%s ... ", pbuf);
        } else {
            printf("%.*s ... ", h.name_len, (const char *)name);
        }
        fflush(stdout);

        if (!(h.fd & 0xF0)) {
            snprintf(volpath_name, sizeof volpath_name, "%s", dest);
            char fullname[4096];
            if (h.attr & 0x10) {
                snprintf(fullname, sizeof fullname, "%s/%.*s", dest,
                         h.name_len, (const char *)name);
                size_t dlen = strlen(dest);
                for (char *q = fullname; *q; ++q) {
                    if (*q == '\\') *q = '/';
                    if (unix_paths && (size_t)(q - fullname) > dlen) *q = (char)tolower((unsigned char)*q);
                }
                mkdir_p(fullname);
                printf("dossier\n");
            } else {
                FILE *fp = dest_open(volpath_name, name, h.name_len, fullname, unix_paths);
                fclose(fp);
                printf("vide\n");
            }
            n_extracted++;
            continue;
        }
        if (o.method == ALZ_M_BZIP2 || o.method == ALZ_M_DEFLATE3) {
            /* Out of scope: no ALZ profile of ALZip writes these methods,
             * so no reference exists to validate them. */
            fprintf(stderr, "alzgg: container method %u not supported "
                            "(no ALZ profile produces it): %.*s\n",
                    o.method, h.name_len, (const char *)name);
            return 2;
        }
        if (o.method != ALZ_M_STORE && o.method != ALZ_M_DEFLATE)
            die("unknown compression method", NULL);
        if (o.method == ALZ_M_STORE && o.csize != o.usize)
            die("store: inconsistent sizes", NULL);

        uint64_t usize = o.usize;
        char fullname[4096];
        FILE *fp = dest_open(dest, name, h.name_len, fullname, unix_paths);
        uint32_t crc = 0;
        char why[256] = "";
        int s = member_stream(&c, &o, h.fd & 0x01, password, fp, &crc,
                              why, sizeof why);

        if (s) {
            fclose(fp);
            remove(fullname);
            if (s == 1)
                fprintf(stderr, "alzgg: %.*s: encrypted member (ZipCrypto), "
                                "password required (-p)\n",
                        h.name_len, (const char *)name);
            else
                fprintf(stderr, "alzgg: %.*s : %s\n", h.name_len,
                        (const char *)name, why[0] ? why : "failed");
            return 2;
        }
        if (fclose(fp)) die(strerror(errno), fullname);
        int crc_ok = (crc == o.crc);
        printf("%s (%llu bytes)\n", crc_ok ? "ok" : "INVALID CRC",
               (unsigned long long)usize);
        if (!crc_ok) {
            /* A reordered or corrupt volume must neither pass for a success
             * nor leave a misleading file: the CRC proves the stream is not
             * the archive's. */
            fprintf(stderr, "alzgg: CRC mismatch for %.*s (expected %08x, "
                    "computed %08x) - file removed\n",
                    h.name_len, (const char *)name, o.crc, crc);
            remove(fullname);
            bad++;
        }
        n_extracted++;
    }
    printf("%d member(s) extracted\n", n_extracted);
    for (i = 0; i < nvols; ++i) rd_unload(&vols[i]);
    if (bad) {
        fprintf(stderr, "alzgg: %d member(s) failed or skipped (invalid CRC or unsafe path traversal, suspicious path in the archive): extraction failed\n", bad);
        return 2;
    }
    return 0;
}

/* ================================================================ CREATE === */
typedef struct Member {
    const char *src;
    char *arcname;
    uint8_t *udata; size_t usize;
    uint8_t *cdata; size_t csize;
    uint32_t crc;
    uint8_t *wdata; size_t wsize;   /* bytes actually written: ZipCrypto
                                       verifier (12) then csize encrypted, or
                                       cdata as is when not encrypted */
    uint8_t attr;                   /* 0x01 read-only, 0x02 hidden,
                                       0x10 directory (lot-h) */
} Member;

static void usage_create(void)
{
    fprintf(stderr,
        "usage: alz create [-p PROFILE | -mN] [-v bytes_per_volume]\n"
        "       [-T \"YYYY-MM-DD hh:mm:ss\"] [--password PASS]\n"
        "       [--crypt-info HEX[,HEX...]] -o archive.alz [path=>name ...]\n"
        "       -p PROFILE             none | faster | normal\n"
        "       -mN                    ALZipCon 12.30 profile number, synonym\n"
        "                              of -p: -m0 none (store), -m1 faster\n"
        "                              (zlib level 1), -m2 normal (level 4,\n"
        "                              the default). 12.30 writes nothing\n"
        "                              for -m3: ALZip 8.0's level 2 has no\n"
        "                              equivalent any more and is refused\n"
        "       --password PASS        encrypts with ZipCrypto (\"Zip 2.0 "
        "Compatible\", the only\n"
        "                              cipher the ALZ plugin announces)\n"
        "       --attr HEX[,HEX...]    Windows attributes (0x20 archive, 0x04\n"
        "                              system, 0x02 hidden, 0x01 read-only);\n"
        "                              by default read-only and hidden are\n"
        "                              derived from the POSIX mode and the name\n"
        "       --crypt-info HEX,...   10 bytes of material per member (hex):\n"
        "                              ALZip draws it randomly, so fix it to\n"
        "                              compare byte for byte; /dev/urandom by default\n"
        "       (-s is refused: Solid-Compression is EGG-only, cf. FORMAT-ALZ.md)\n");
    exit(2);
}

/* 10 bytes of material per member: what ALZip draws randomly. The two high
 * bytes of the CRC complete the 12-byte verifier, so they are not requested. */
static int parse_crypt_info(const char *arg, EggCryptMaterial *out, int max)
{
    int n = 0;
    const char *p = arg;

    while (*p) {
        size_t k;

        if (n >= max) return -1;
        for (k = 0; k < 10; ++k) {
            int hi, lo;
            if (!p[0] || !p[1]) return -1;
            hi = p[0] >= '0' && p[0] <= '9' ? p[0] - '0' :
                 p[0] >= 'a' && p[0] <= 'f' ? p[0] - 'a' + 10 :
                 p[0] >= 'A' && p[0] <= 'F' ? p[0] - 'A' + 10 : -1;
            lo = p[1] >= '0' && p[1] <= '9' ? p[1] - '0' :
                 p[1] >= 'a' && p[1] <= 'f' ? p[1] - 'a' + 10 :
                 p[1] >= 'A' && p[1] <= 'F' ? p[1] - 'A' + 10 : -1;
            if (hi < 0 || lo < 0) return -1;
            out[n].bytes[k] = (uint8_t)((hi << 4) | lo);
            p += 2;
        }
        out[n].len = 10;
        n++;
        if (!*p) break;
        if (*p != ',') return -1;
        p++;
    }
    return n;
}

static void random_material(EggCryptMaterial *m)
{
    FILE *f = fopen("/dev/urandom", "rb");

    if (!f || fread(m->bytes, 1, 10, f) != 10) {
        if (f) fclose(f);
        die("/dev/urandom unreadable: encryption material unavailable", NULL);
    }
    fclose(f);
    m->len = 10;
}

static uint32_t dos_time_from_spec(const char *spec)
{
    int y, mo, d, h, mi, s;
    if (sscanf(spec, "%d-%d-%d %d:%d:%d", &y, &mo, &d, &h, &mi, &s) != 6)
        die("-T expects the format \"YYYY-MM-DD hh:mm:ss\"", spec);
    uint32_t t  = (uint32_t)((h << 11) | (mi << 5) | (s / 2));
    uint32_t dt = (uint32_t)(((y - 1980) << 9) | (mo << 5) | d);
    return t | (dt << 16);
}

static int cmd_create(const char *out, const char *profile,
                      long volsz, const uint32_t *times, int ntimes, int nfiles,
                      char **files, const char *password,
                      EggCryptMaterial *mats, const uint8_t *attrs, int nattrs)
{
    int level, method, i;
    static Member m[MAX_FILES];
    static char srcs[MAX_FILES][4096];
    static char names[MAX_FILES][4096];

    if (!profile) profile = "normal";
    if (!strcmp(profile, "none") || !strcmp(profile, "m0") ||
        !strcmp(profile, "0"))
        { level = 0; method = ALZ_M_STORE; }
    else if (!strcmp(profile, "faster") || !strcmp(profile, "m1") ||
             !strcmp(profile, "1"))
        { level = 1; method = ALZ_M_DEFLATE; }
    else if (!strcmp(profile, "normal") || !strcmp(profile, "m2") ||
             !strcmp(profile, "2"))
        { level = 4; method = ALZ_M_DEFLATE; }
    else if (!strcmp(profile, "fast") || !strcmp(profile, "m3") ||
             !strcmp(profile, "3"))
        die("ALZip 12.30 writes nothing for ALZ -m3 (profiles 0..2: "
            "none|faster|normal); ALZip 8.0's level 2 has no "
            "equivalent any more", profile);
    else die("expected profile: none|faster|normal, or -m0|-m1|-m2",
             profile);

    for (i = 0; i < nfiles; ++i) {
        char *sep = strstr(files[i], "=>");
        if (sep) {
            size_t plen = (size_t)(sep - files[i]);
            if (plen >= sizeof srcs[0]) die("path too long", files[i]);
            memcpy(srcs[i], files[i], plen);
            srcs[i][plen] = 0;
            if (strlen(sep + 2) >= sizeof names[0]) die("name too long", files[i]);
            strcpy(names[i], sep + 2);
        } else {
            strcpy(srcs[i], files[i]);
            strcpy(names[i], files[i]);
            for (char *q = names[i]; *q; ++q) if (*q == '\\') *q = '/';
        }
        m[i].src = srcs[i];
        m[i].arcname = names[i];
        m[i].usize = 0;
        m[i].wdata = NULL;
        m[i].wsize = 0;
        {
            struct stat st;
            const char *base;

            if (stat(m[i].src, &st)) die(strerror(errno), m[i].src);
            base = strrchr(m[i].arcname, '/');
            base = base ? base + 1 : m[i].arcname;
            /* ALZip reuses the Windows attributes: directory 0x10, read-only
             * 0x01, hidden 0x02. POSIX has no hidden bit; a name starting with
             * a dot is the equivalent convention (and the attribute ALZip wrote
             * for `.dotfile` in lot H). */
            m[i].attr = (uint8_t)(S_ISDIR(st.st_mode) ? 0x10 :
                                  (st.st_mode & S_IWUSR ? 0x00 : 0x01));
            if (base[0] == '.' && base[1]) m[i].attr |= 0x02;
            /* ALZip 12.30 sets FILE_ATTRIBUTE_ARCHIVE (0x20) on every file of
             * an ALZ archive — measured on the ten lot-K archives, whereas
             * ALZip 8.0 wrote 0x00 (the packed_alz_8.0/ archives). */
            if (!S_ISDIR(st.st_mode)) m[i].attr |= 0x20;
            /* The other Windows attributes (system 0x04, read-only 0x01,
             * hidden 0x02) are set explicitly: --attr, one value or one per
             * member. --attr still wins over the default. */
            if (nattrs) m[i].attr = nattrs == 1 ? attrs[0] : attrs[i];
            if (S_ISDIR(st.st_mode)) {
                /* A directory is a member without data (fd=0), named without
                 * a trailing slash like edge_dir_only.alz. */
                size_t nl = strlen(m[i].arcname);
                while (nl && m[i].arcname[nl - 1] == '/') m[i].arcname[--nl] = 0;
                m[i].udata = NULL;
                m[i].csize = 0;
                m[i].cdata = NULL;
                m[i].crc = 0;
                continue;
            }
        }
        m[i].udata = slurp(m[i].src, &m[i].usize);
        m[i].crc = crc32_buf(m[i].udata, m[i].usize);
        if (m[i].usize == 0) {
            /* ALZip empty members have no optional compression fields or data. */
            m[i].cdata = m[i].udata;
            m[i].csize = 0;
        } else if (method == ALZ_M_STORE) {
            m[i].cdata = m[i].udata;
            m[i].csize = m[i].usize;
        } else {
            uLong bound = compressBound((uLong)m[i].usize) + 16;
            m[i].cdata = malloc(bound);
            if (!m[i].cdata) die("out of memory", NULL);
            z_stream zs;
            memset(&zs, 0, sizeof zs);
            if (deflateInit2(&zs, level, Z_DEFLATED, -15, 8, Z_DEFAULT_STRATEGY) != Z_OK)
                die("deflateInit2", NULL);
            /* avail_in is 32 bits: a member above 4 GiB is pushed in 1 GiB
             * slices, which produces the same stream as a single call (zlib is
             * incremental). */
            uint64_t off = 0;
            int ret;
            zs.next_out = m[i].cdata;
            zs.avail_out = bound;
            do {
                uInt chunk = (uInt)(m[i].usize - off > (1u << 30)
                                        ? (1u << 30) : m[i].usize - off);
                zs.next_in = m[i].udata + off;
                zs.avail_in = chunk;
                off += chunk;
                ret = deflate(&zs, off == m[i].usize ? Z_FINISH : Z_NO_FLUSH);
                if (ret != Z_OK && ret != Z_STREAM_END) die("deflate", NULL);
            } while (ret != Z_STREAM_END);
            m[i].csize = zs.total_out;
            deflateEnd(&zs);
        }
    }

    /* ZipCrypto encryption of the compressed stream (the member CRC, over the
     * uncompressed data, provides the last two verifier bytes). An empty member
     * has neither optional field nor data: ALZip writes no verifier for it and
     * leaves it in the clear (packed_alz_8.0/enc_alz_empty.alz, produced with
     * -tp0 -psecret, fd=00 and no encrypted byte). */
    for (i = 0; i < nfiles; ++i) {
        char crypt_err[256];
        uint8_t info[12];
        size_t ilen = 0;
        EggCryptCtx *ctx;

        if (!password || m[i].usize == 0) {
            m[i].wdata = m[i].cdata;
            m[i].wsize = m[i].csize;
            continue;
        }
        ctx = egg_crypt_enc_begin(EGG_CRYPT_ZIP, &mats[i], m[i].crc, password,
                                  info, sizeof info, &ilen, crypt_err,
                                  sizeof crypt_err);
        if (!ctx) die(crypt_err, m[i].arcname);
        m[i].wdata = malloc(12 + m[i].csize);
        if (!m[i].wdata) die("out of memory", NULL);
        memcpy(m[i].wdata, info, 12);
        memcpy(m[i].wdata + 12, m[i].cdata, m[i].csize);
        if (egg_crypt_enc_update(ctx, m[i].wdata + 12, m[i].csize) ||
            egg_crypt_enc_finish(ctx, info, ilen))
            die("chiffrement ZipCrypto", m[i].arcname);
        egg_crypt_enc_free(ctx);
        m[i].wsize = 12 + m[i].csize;
    }

    size_t vnum = 0;
    int member = 0;
    size_t carry_member = 0, carry_off = 0;
    int have_carry = 0;
    size_t cap = volsz > 0 ? (size_t)volsz : 0;

    while (member < nfiles || have_carry) {
        Wr w = {0};
        char path[4096];
        wr_u32(&w, ALZ_MAGIC);
        wr_u8(&w, 0x0A); wr_u8(&w, 0x00);
        /* ALZip numbers volumes in archive-header byte 6:
           .alz = 0, .a00 = 1, .a01 = 2, ...; byte 7 is reserved zero. */
        if (vnum > 255) die("ALZ volume number out of range", NULL);
        wr_u8(&w, (uint8_t)vnum);
        wr_u8(&w, 0);

        /* room for (headers + data): 8 (archive hdr) + 16 (END) already
           reserved; the corpus note 24 is not used: END=16. */
        size_t avail = cap ? cap - 8 - 16 : (size_t)-1;
        int is_last = 1;

        /* 1) data of the member being traversed (no header) */
        if (have_carry) {
            Member *mm = &m[carry_member];
            size_t remaining = mm->wsize - carry_off;
            size_t take = remaining < avail ? remaining : avail;
            wr_bytes(&w, mm->wdata + carry_off, take);
            avail -= take;
            carry_off += take;
            if (take < remaining) {
                is_last = 0;                 /* one more volume follows */
            } else {
                have_carry = 0; carry_off = 0;
                member = (int)carry_member + 1;
            }
        }

        /* 2) following members that start in this volume */
        while (member < nfiles) {
            Member *mm = &m[member];
            size_t namelen = strlen(mm->arcname);
            size_t hdr_len = 4 + 2 + 1 + 4 + 1 + 1 + namelen;   /* BLZ+fixed+name */
            if (mm->usize > 0) {
                uint64_t big = mm->csize > mm->usize ? mm->csize : mm->usize;
                int nb = big <= 0xFFFF ? 2 :
                         big <= 0xFFFFFFFFull ? 4 : 8;
                hdr_len += 1 + 1 + 4 + 2 * (size_t)nb;
                (void)nb;
            }
            if (avail < hdr_len) {          /* header does not fit: cut here */
                is_last = 0;
                break;
            }
            uint32_t dos_time = ntimes > 1 ? times[member] : times[0];

            wr_u32(&w, ALZ_FILE_MAGIC);
            if (mm->usize == 0) {
                wr_u16(&w, (uint16_t)namelen);
                wr_u8(&w, mm->attr);        /* attributs (dossier 0x10) */
                wr_u32(&w, dos_time);
                wr_u8(&w, 0);               /* fd = 0: empty file */
                wr_u8(&w, 0);               /* unknown2 */
            } else {
                uint64_t big = mm->csize > mm->usize ? mm->csize : mm->usize;
                int nb = big <= 0xFFFF ? 2 :
                         big <= 0xFFFFFFFFull ? 4 : 8;
                wr_u16(&w, (uint16_t)namelen);
                wr_u8(&w, mm->attr);
                wr_u32(&w, dos_time);
                wr_u8(&w, (uint8_t)((nb << 4) |
                                    (password ? 0x01 : 0x00)));  /* fd */
                wr_u8(&w, 0);                   /* unknown2 */
                wr_u8(&w, (uint8_t)method);
                wr_u8(&w, 0);                   /* unknown3 */
                wr_u32(&w, mm->crc);
                wrN(&w, mm->csize, nb);
                wrN(&w, mm->usize, nb);
            }
            wr_bytes(&w, mm->arcname, namelen);
            avail -= hdr_len;

            size_t take = mm->wsize < avail ? mm->wsize : avail;
            wr_bytes(&w, mm->wdata, take);
            avail -= take;
            if (take < mm->wsize) {         /* crosses: keep the rest for next */
                is_last = 0;
                have_carry = 1;
                carry_member = (size_t)member;
                carry_off = take;
                member++;                    /* the next member follows it */
                break;
            }
            member++;
            /* worst case: does the next header still fit? */
        }

        wr_end_record(&w, is_last);
        if (vnum == 0) snprintf(path, sizeof path, "%s", out);
        else {
            /* ALZip convention: archive.alz -> archive.a00 (suffix replaced) */
            char base[4000];
            if (snprintf(base, sizeof base, "%s", out) >= (int)sizeof base)
                die("output path too long", out);
            size_t bl2 = strlen(base);
            if (bl2 > 4 && !strcmp(base + bl2 - 4, ".alz")) base[bl2 - 4] = 0;
            snprintf(path, sizeof path, "%s.a%02zu", base, vnum - 1);
        }
        dump_file(path, w.buf, w.len);
        printf("%s: %zu bytes\n", path, w.len);
        free(w.buf);

        vnum++;
        if (vnum > 10000) die("splitting loop", NULL);
    }

    for (i = 0; i < nfiles; ++i) {
        if (m[i].wdata && m[i].wdata != m[i].cdata) free(m[i].wdata);
        if (m[i].cdata != m[i].udata) free(m[i].cdata);
        free(m[i].udata);
    }
    return 0;
}

/* ================================================================== MAIN === */
int alz_cli_main(int argc, char **argv)
{
    const char *dest = ".";
    if (argc < 3) {
        fprintf(stderr,
            "usage:\n"
            "  alzgg list    archive.alz [-u|--unix] [-1|--bare]\n"
            "  alzgg extract archive.alz [-d dest] [-p password] [-u|--unix]\n"
            "  alzgg create  [-p none|faster|normal] [-v bytes_per_volume]\n"
            "                [-m0|-m1|-m2] [-T \"date[,date...]\"] [--password PASS]\n"
            "                [--crypt-info HEX,...] -o archive.alz path[=>name] [file...]\n"
            "                (-m0 none, -m1 faster, -m2 normal [default]: ALZipCon\n"
            "                 12.30 numbers, synonyms of -p)\n"
            "  (-s is refused: Solid-Compression is EGG-only, cf. FORMAT-ALZ.md)\n");
        exit(2);
    }
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
    if (!strcmp(argv[1], "extract")) {
        const char *arc = NULL, *password = NULL;
        int unix_paths = 0;
        for (int i = 2; i < argc; ++i) {
            if (!strcmp(argv[i], "-d") && i + 1 < argc) dest = argv[++i];
            else if (!strcmp(argv[i], "-p") && i + 1 < argc) password = argv[++i];
            else if (!strcmp(argv[i], "-u") || !strcmp(argv[i], "--unix")) unix_paths = 1;
            else if (argv[i][0] != '-' && !arc) arc = argv[i];
            else if (argv[i][0] == '-') {
                fprintf(stderr, "alzgg: unknown option '%s'\n", argv[i]);
                return 2;
            }
        }
        if (!arc) {
            fprintf(stderr, "alzgg: extract: missing archive\n");
            return 2;
        }
        return cmd_extract(arc, dest, password, unix_paths);
    }
    if (!strcmp(argv[1], "create")) {
        const char *out = NULL, *profile = NULL;
        const char *password = NULL, *info_arg = NULL;
        static EggCryptMaterial mats_store[MAX_FILES];
        EggCryptMaterial *mats = NULL;
        long volsz = 0;
        uint32_t times[MAX_FILES];
        static uint8_t attrs[MAX_FILES];
        int nattrs = 0;
        int ntimes = 0, dos_set = 0, nfiles = 0, nmats = 0;
        char *files[MAX_FILES];
        int i = 2;
        for (; i < argc; ++i) {
            if (!strcmp(argv[i], "-o") && i + 1 < argc) out = argv[++i];
            else if ((!strcmp(argv[i], "-p") || !strcmp(argv[i], "-m")) &&
                     i + 1 < argc)
                profile = argv[++i];
            else if (!strncmp(argv[i], "-m", 2) && argv[i][2] >= '0' &&
                     argv[i][2] <= '9' && argv[i][3] == 0)
                profile = argv[i] + 1;

            else if (!strcmp(argv[i], "-v") && i + 1 < argc) volsz = atol(argv[++i]);
            else if (!strcmp(argv[i], "-T") && i + 1 < argc) {
                /* One date, or a list (one per member): ALZip timestamps each
                 * member with its mtime, so reproducing a multi-member archive
                 * needs those dates. */
                const char *p = argv[++i];
                for (;;) {
                    const char *comma = strchr(p, ',');
                    size_t n = comma ? (size_t)(comma - p) : strlen(p);
                    char one[64];
                    if (n >= sizeof one) die("-T date too long", p);
                    memcpy(one, p, n);
                    one[n] = 0;
                    if (ntimes >= MAX_FILES) die("too many -T dates", NULL);
                    times[ntimes++] = dos_time_from_spec(one);
                    if (!comma) break;
                    p = comma + 1;
                }
                dos_set = 1;
            } else if (!strcmp(argv[i], "--attr") && i + 1 < argc) {
                const char *p = argv[++i];
                for (;;) {
                    char *end;
                    unsigned long v = strtoul(p, &end, 0);
                    const char *comma = strchr(p, ',');

                    if (end == p || v > 0xFF || (comma && end != comma))
                        die("--attr: hexadecimal or decimal value (0..0xFF) "
                            "per member", p);
                    if (nattrs >= MAX_FILES) die("too many --attr values", NULL);
                    attrs[nattrs++] = (uint8_t)v;
                    if (!comma) break;
                    p = comma + 1;
                }
            } else if (!strcmp(argv[i], "--password") && i + 1 < argc) {
                password = argv[++i];
            } else if (!strcmp(argv[i], "--crypt-info") && i + 1 < argc) {
                info_arg = argv[++i];
                mats = mats_store;
                nmats = parse_crypt_info(info_arg, mats, MAX_FILES);
                if (nmats <= 0)
                    die("--crypt-info: 10 hexadecimal bytes per member, "
                        "comma-separated", info_arg);
            } else if (!strcmp(argv[i], "-s")) {
                /* ALZipCon accepts -s for any format and refuses it for ALZ
                 * with this message: Solid-Compression exists only for EGG
                 * (FORMAT-ALZ.md, FORMAT-EGG.md §14). */
                fprintf(stderr,
                        "ERROR : The format doesn't support Solid-Compression\n");
                exit(2);
            } else if (argv[i][0] != '-') files[nfiles++] = argv[i];
            else usage_create();
        }
        if (!out || nfiles == 0) usage_create();
        (void)dos_set;
        if (ntimes == 0) { times[0] = 0; ntimes = 1; }
        if (ntimes != 1 && ntimes != nfiles)
            die("-T: one date, or one per member", NULL);
        if (nattrs && nattrs != 1 && nattrs != nfiles)
            die("--attr: one value, or one per member", NULL);
        if (info_arg && !password)
            die("--crypt-info only makes sense with --password", NULL);
        if (password) {
            if (info_arg && nmats != nfiles)
                die("--crypt-info: 10 bytes of material per member expected "
                    "(archive refused, nothing written)", NULL);
            if (!info_arg) {
                mats = mats_store;
                for (i = 0; i < nfiles; ++i) random_material(&mats[i]);
            }
        }
        return cmd_create(out, profile, volsz, times, ntimes, nfiles,
                          files, password, mats, attrs, nattrs);
    }
    fprintf(stderr, "alzgg: unknown subcommand: %s\n", argv[1]);
    exit(2);
}
