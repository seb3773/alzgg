/* alz.h — shared structures of the ALZip container (.alz)
 *
 * Descriptions verified in FORMAT-ALZ.md (measurements on packed_corpus +
 * reading the unalz 0.65 code). Everything is little-endian.
 */
#ifndef ALZ_H
#define ALZ_H

#include <stdint.h>
#include <stddef.h>

/* archive header magic:
   'A'=0x41 'L'=0x4C 'Z'=0x5A, lowest byte first => 0x015A4C41 etc. */
#define ALZ_MAGIC         0x015A4C41u  /* 'ALZ\x01' */
#define ALZ_FILE_MAGIC    0x015A4C42u  /* 'BLZ\x01' */
#define ALZ_END_MAGIC     0x015A4C43u  /* 'CLZ\001' */
#define ALZ_FINAL_MAGIC   0x025A4C43u  /* 'CLZ\002' (final volume) */
#define ALZ_NONFINAL_MAGIC 0x035A4C43u /* 'CLZ\003' (non-final volume) */

/* Compression methods = the member's `meth` byte (CONTAINER ids).
   Not to be confused with the GUI/CLI profile numbers (-m: ALZ 1~3,
   EGG 1~4, 0 = no compression): the three compressed ALZ profiles
   all write ALZ_M_DEFLATE.

   Only 0 and 2 are produced by ALZip 8 (checked on the 62 archives of the
   corpus: no ALZ profile emits 1 or 3, and Formats/Alz.dll embeds no BZip2
   codec). Values 1 and 3 are kept to name what alz refuses explicitly,
   not to be decoded. Cf. FORMAT-ALZ.md. */
enum ALZ_METHOD { ALZ_M_STORE = 0, ALZ_M_BZIP2 = 1, ALZ_M_DEFLATE = 2, ALZ_M_DEFLATE3 = 3 };

/* zlib levels of the three ALZ deflate profiles (faster=1, fast=2, normal=4).
   These are zlib levels, not profile numbers. */
enum ALZ_DEFLATE_LEVEL { ALZ_L_FASTER = 1, ALZ_L_FAST = 2, ALZ_L_NORMAL = 4 };

/* default volume size observed in the corpus (unit: bytes) */
#define ALZ_VOLUME_SIZE_DEFAULT ((size_t)102400)

/* file header (12-byte fixed part after the magic) */
typedef struct AlzFileHeader {
    uint16_t  name_len;
    uint8_t   attr;          /* bit0 RO, bit1 hidden, bit4 dir, bit5 file */
    uint32_t  dos_time;      /* low16 = time (hh:mm:ss/2), high16 = date */
    uint8_t   fd;            /* bit0 encrypted; bits4..7 = field sizes (in bytes) */
    uint8_t   unknown2;
} AlzFileHeader;

/* optional part (present when fd & 0xF0) */
typedef struct AlzFileOptional {
    uint8_t   method;
    uint8_t   unknown3;
    uint32_t  crc;
    uint64_t  csize;         /* over the `nb` bytes actually stored */
    uint64_t  usize;
    int       nb;            /* 1,2,4,8 bytes stored */
} AlzFileOptional;

/* used for encoding: description of a member */
typedef struct AlzMember {
    const char *path;        /* on-disk path */
    const char *arc_name;    /* name inside the archive ('/' only) */
    uint32_t   dos_time;
} AlzMember;

#endif /* ALZ_H */
