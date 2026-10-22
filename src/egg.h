/* egg.h — ALZip's EGG container: reading and writing.
 *
 * Scope: only ALZip's EGG format, described in FORMAT-EGG.md (structure measured
 * on the ALZip 8 samples). Signatures and fields come from that spec, not from a
 * guess.
 */
#ifndef EGG_H
#define EGG_H

#include <stddef.h>
#include <stdint.h>

/* Signatures (4 little-endian bytes on disk) */
#define EGG_SIG_ARCHIVE   0x41474745u  /* 'EGGA' */
#define EGG_SIG_SPLIT     0x24F5A262u
#define EGG_SIG_SOLID     0x24E5A060u
#define EGG_SIG_GENCRYPT  0x08D144A8u
#define EGG_SIG_FILE      0x0A8590E3u
#define EGG_SIG_FILENAME  0x0A8591ACu
#define EGG_SIG_COMMENT   0x04C63672u
#define EGG_SIG_WININFO   0x2C86950Bu
#define EGG_SIG_POSIXINFO 0x1EE922E5u
#define EGG_SIG_ENCRYPT   0x08D1470Fu
#define EGG_SIG_BLOCK     0x02B50C13u
#define EGG_SIG_DUMMY     0x07463307u
#define EGG_SIG_SKIP      0xFFFF0000u
#define EGG_SIG_END       0x08E28222u

/* Block compression methods (spec §11) */
enum EGG_METHOD {
    EGG_M_STORE   = 0,
    EGG_M_DEFLATE = 1,   /* deflate BRUT RFC1951 */
    EGG_M_BZIP2   = 2,
    EGG_M_AZO     = 3,
    EGG_M_LZMA    = 4
};

/* Encryption methods (spec §12) */
enum EGG_CRYPT {
    EGG_CRYPT_NONE   = -1,
    EGG_CRYPT_ZIP    = 0,
    EGG_CRYPT_AES128 = 1,
    EGG_CRYPT_AES256 = 2,
    EGG_CRYPT_LEA128 = 5,
    EGG_CRYPT_LEA256 = 6
};

typedef struct EggBlock {
    uint8_t         method;
    uint8_t         hint;
    uint32_t        usize;
    uint32_t        csize;
    uint32_t        crc32;
    const uint8_t  *data;   /* inside the logical stream held by the archive */
} EggBlock;

typedef struct EggEntry {
    uint32_t    file_id;
    uint64_t    usize;
    char       *name;        /* UTF-8, '/' or '\\' separators */
    uint32_t    name_flags;
    int         crypt;       /* EGG_CRYPT_* or EGG_CRYPT_NONE */
    int         crypt_size;  /* declared size of the Encrypt Info field */
    uint8_t     crypt_info[32];  /* start of the Encrypt Info field (salt,
                                    verifier, HMAC); 32 bytes cover AES-256 (28) */
    uint8_t     crypt_info_len;  /* bytes actually copied */
    int         has_wininfo;
    uint64_t    filetime;    /* FILETIME Windows */
    uint8_t     attrs;       /* EGG bits: 0x01 RO, 0x02 hidden, 0x04 system,
                                0x08 link, 0x80 directory */
    EggBlock   *blocks;
    size_t      nblocks;
} EggEntry;

typedef struct EggArchive {
    uint16_t    version;
    uint32_t    header_id;
    int         solid;
    EggEntry   *entries;
    size_t      nentries;
    uint8_t    *logical;     /* logical stream: 1st header + concatenated data */
    size_t      logical_size;
    void       *map;         /* single volume: mmap() of the whole file, else NULL */
    size_t      map_size;
} EggArchive;

/* Loads the archive (volumes chained through Split Info when needed).
 * Returns 0 on success, -1 otherwise after filling `err`. */
int  egg_open(const char *path, EggArchive *arc, char *err, size_t errsz);
void egg_close(EggArchive *arc);

/* --------------------------------------------------------------------- writing */
/* EGG compression profiles exposed by ALZip (GUI/CLI naming measured in
 * FORMAT-EGG.md §14.1: ALZ 1~3, EGG 1~4, 0 = no compression).
 * All five profiles are written: _NONE is store, _NORMAL is deflate hint 6 for
 * every member (no routing by extension), _COMPSPEED is deflate hint 5,
 * _COMPRATIO is LZMA hint 6 everywhere, and _OPTIMIZED follows its full table
 * (AZO / store / LZMA / bzip2 routes then a deflate hint 5 fallback): no
 * extension is refused. */
typedef enum EggProfile {
    EGG_PROF_NONE      = 0,
    EGG_PROF_NORMAL    = 1,
    EGG_PROF_COMPSPEED = 2,
    EGG_PROF_COMPRATIO = 3,
    EGG_PROF_OPTIMIZED = 4
} EggProfile;


/* Member to write. `name` is the stored name ('/' separators), `path` the source
 * file; the two may differ (an empty directory is a member with no data source,
 * a name may come from another path). */
typedef struct EggSrc {
    const char *name;
    const char *path;
    uint64_t    usize;      /* real size, 0 for a directory */
    uint64_t    filetime;   /* FILETIME = local file time (see egg_w.c) */
    uint8_t     attrs;      /* 0x01 read-only, 0x80 directory */
    int         is_dir;
} EggSrc;

/* Random encryption material, defined by egg_crypt.h (one per member: 10 bytes
 * for ZipCrypto, 8 or 16 salt bytes for AES-128/256). */
struct EggCryptMaterial;

typedef struct EggCreateOpts {
    uint32_t   header_id;   /* volume identifier: not reproducible from one ALZip
                               run to the next (activity counter), so fixed by
                               the caller for any byte-for-byte check */
    EggProfile profile;
    int        solid;       /* 1: Solid-Compression, a single stream over the
                               concatenated members: deflate (m1) or LZMA (m3) */
    /* Volume splitting (CLI `-v`): 0 = single volume. Otherwise each volume is
     * exactly `volume_size` bytes (the last one less), 33-byte header included,
     * and the files are named <output>.vol1.egg, <output>.vol2.egg, ... —
     * measured on corpus_probe/splitmany_normal.vol1-3 and
     * packed_egg/records_optimized.vol1-2 (FORMAT-EGG.md §13.3). */
    uint64_t   volume_size;
    /* Volume identifiers, volume 1 first: ALZip draws them from a global counter
     * (+3, +4, +6 between the corpus volumes), so they are not computable and the
     * caller supplies them. The first one must equal `header_id`. */
    const uint32_t *volume_ids;
    size_t         n_volume_ids;
    /* Encryption (spec §12). `password` NULL = plain archive. `crypt` is
     * EGG_CRYPT_ZIP, _AES128, _AES256, _LEA128 or _LEA256. ALZip 8 exposes
     * -tp0/-tp1/-tp2 (ZipCrypto/AES-128/AES-256); ALZip 10.5+ adds LEA,
     * and its ALZipCon 12.30 also accepts -tp3/-tp4 (undocumented) for
     * LEA-128/LEA-256 — that is how packed_egg/ was produced.
     * `crypt_material` holds one material per member (n_crypt_material = n):
     * ALZip draws it at random, so an archive is reproducible byte for byte only
     * if the caller returns the same material. Refused with -s (ALZip:
     * "Solid-Compressed file cannot be encrypted") and with -v (ALZip refuses
     * encrypted volumes, FORMAT-EGG.md §13.3). */
    const char *password;
    int         crypt;
    const struct EggCryptMaterial *crypt_material;
    size_t      n_crypt_material;
} EggCreateOpts;

const char *egg_profile_name(EggProfile p);

/* Walks the given paths (files or directories) and builds the member list in
 * write order. Stored names are the supplied ones, with '/' separators. An empty
 * directory becomes a member with attr=0x80; a non-empty directory is walked
 * (alphabetical order) without yielding a member. Symbolic links are refused
 * (ALZip behaviour not established).
 * Returns 0, or -1 after filling `err`. The list must be freed with
 * egg_inputs_free(). */
int  egg_scan_paths(char **paths, size_t npaths, EggSrc **out, size_t *count,
                    char *err, size_t errsz);
void egg_inputs_free(EggSrc *items, size_t n);

/* Writes the archive. Returns 0, or -1 after filling `err` (partial files are
 * removed). All five EGG_PROF_* profiles are written; only combinations with no
 * ALZip reference are refused explicitly (solid outside m1/m3, solid with
 * volumes or encryption, encryption of a multi-block member), never
 * approximated. With volume_size != 0, writes <out>.vol1.egg... and returns the
 * volume count in `n_volumes` (may be NULL); `out` is then not created. With
 * `password`, the archive is encrypted (ZipCrypto, AES-128 or AES-256) and
 * `crypt_material` must hold one material per member; encryption is refused
 * with -s, and combines with -v (encryption runs before the split —
 * FORMAT-EGG.md §12.8). */
int  egg_create(const char *out, const EggSrc *items, size_t n,
                const EggCreateOpts *opt, size_t *n_volumes,
                char *err, size_t errsz);

typedef struct EggExtractOpts {
    const char *dest;      /* destination directory */
    const char *password;  /* password, NULL when none (spec §12) */
    int         raw;       /* 1: write the decrypted payload as is, without
                              decompressing (diagnostic/fallback: separates the
                              encryption from the compression codec) */
    int         unix_paths;/* 1: format paths as Unix relative paths (/ slashes, lowercase) */
} EggExtractOpts;

/* Extracts every member into opt->dest. Fails without writing anything if the
 * archive uses an unimplemented decoding feature (encryption without a password,
 * encrypted solid, block method other than store/deflate in normal mode) or if a
 * CRC diverges.
 * Solid archives are decoded: the continuous stream (spec §14.3) is decompressed
 * then spread over the members in archive order.
 * ZipCrypto, AES-128/256 and LEA-128/256 encryption is decoded (spec §12): the
 * password must be supplied, and it is checked before any write.
 * Returns the number of members written, or -1 after filling `err`. */
int  egg_extract_all(const EggArchive *arc, const EggExtractOpts *opt,
                     char *err, size_t errsz);

#endif
