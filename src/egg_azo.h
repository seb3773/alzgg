/* egg_azo.h — AZO codec for EGG blocks (method 3, appendix A of
 * FORMAT-EGG.md).
 *
 * AZO is an LZ77 with an adaptive arithmetic coder (32-bit range coder). A
 * block's stream opens with a 2-byte stream header ('1' version, x86 filter
 * flag) followed by big-endian 12-byte slices, ending with a null 12-byte slice.
 * Both the decoder and the encoder are provided: the Optimized route for .sys
 * and .com extensions is reproduced byte for byte on the three corpus references
 * (one slice, the same behind .com, and a 633,780-byte member in two slices;
 * see A.15).
 */
#ifndef EGG_AZO_H
#define EGG_AZO_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/* Decodes a complete AZO stream (stream header, blocks, terminal block):
 * `src`/`csize` hold the EGG block payload, `dst`/`usize` the expected output.
 * Returns 0, or -1 after filling `err`. */
int egg_azo_decode(const uint8_t *src, size_t csize, uint8_t *dst, size_t usize,
                   char *err, size_t errsz);

/* Encodes the [off, off+len) slice of `path` into a COMPLETE AZO stream ('1'
 * stream header, 512 KiB blocks, terminal block) written to a fresh temporary
 * file, rewound and handed back to the caller (`*blob`). Also fills in the
 * CRC-32 of the UNCOMPRESSED slice — the one the EGG block header carries — and
 * the stream size.
 *
 * Settings measured on packed_egg/probe_sys_optimized.egg, mz_sys_optimized.egg,
 * mzmulti_sys_optimized.egg and on the streams the local oracle produces
 * (tools/egg_oracle.sh):
 *   - AZO.dll configuration table (0x6190c840, row 1): 2^19 bytes per block,
 *     3 progressive hash levels (2/4/8-byte prefixes), 18 hash bits, cost
 *     threshold 2;
 *   - a block whose stream does not shrink it is copied verbatim
 *     (compressSize == blockSize) — and it is the FILTERED bytes that are
 *     stored, the filter running before the copy decision: measured on
 *     packed_egg_8.0/mzraw_sys_optimized.egg and mzraw2_sys_optimized.egg (MZ +
 *     random data, one then two slices, `csize == usize + 26`, slice field 3
 *     zeroed);
 *   - the x86 filter flag depends on the content, not on the extension: it is 1
 *     when the data starts with "MZ" (AZO.dll 0x61907410), and the filter is
 *     then applied to EVERY 2^19 block, in the relative -> absolute direction
 *     (A.12); the block CRC stays the one of the original data.
 *
 * Returns 0 on success (the caller closes `*blob`), or -1 after filling `err`
 * and leaving nothing open. */
int egg_azo_encode_range(const char *path, uint64_t off, uint64_t len,
                         FILE **blob, uint64_t *csize, uint32_t *crc,
                         char *err, size_t errsz);

#endif
