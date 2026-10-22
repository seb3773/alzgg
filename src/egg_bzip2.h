/* egg_bzip2.h — bzip2 codec for EGG blocks (method 2). */
#ifndef EGG_BZIP2_H
#define EGG_BZIP2_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "stream_sink.h"

/* Decodes a COMPLETE bzip2 stream ("BZh" header, blocks, stream CRC) into `out`,
 * whose expected size is exactly `out_size` (the block's usize).
 *
 * The EGG stream is standard bzip2: measured on code_normal.egg, whose block
 * (2,402 bytes) decompresses to corpus/code.c (45,270 bytes), with a matching
 * block CRC. The block's `hint` field is 4, which is the stream's blockSize100k
 * (400 KiB) and not a setting to apply: it is already in the BZh4 header.
 *
 * Returns 0 on success, -1 otherwise after filling `err`. */
int egg_bzip2_decode(const uint8_t *in, size_t in_size,
                     uint8_t *out, size_t out_size, char *err, size_t errsz);

/* Same decoding, but the output streams out to `sink` (64 KiB slices) instead of
 * filling a buffer of `expect` bytes: this is what allows a solid stream of
 * several GiB to be decoded without holding it in memory. The input stream
 * stays contiguous (it is the compressed stream, far smaller).
 * Returns 0 when the stream produces exactly `expect` bytes, -1 otherwise. */
int egg_bzip2_decode_to(const uint8_t *in, size_t in_size,
                        stream_sink_fn sink, void *ctx, uint64_t expect,
                        char *err, size_t errsz);

/* Encodes the [off, off+len) slice of `path` into a COMPLETE bzip2 stream
 * ("BZh<block_size_100k>" header, blocks, stream CRC) written to a fresh
 * temporary file, rewound and handed back to the caller (`*blob`). Also fills in
 * the CRC-32 of the UNCOMPRESSED slice — the one the EGG block header carries —
 * and the stream size.
 *
 * Parameters, measured on the 429 bzip2 blocks of the corpus (426 of them
 * unencrypted, re-encoded byte for byte by make test):
 *   - block_size_100k = 4, the value of every reference block and of their
 *     "BZh4" header (the EGG block's `hint` field); it is bzip2's blockSize100k,
 *     not a setting to pick per file size;
 *   - workFactor: 30, bzip2's documented default. It is NOT observable on the
 *     corpus (1 and 250 yield the same bytes for these inputs), so no measured
 *     value exists: 30 is the explicit choice.
 *
 * Returns 0 on success (the caller closes `*blob`), or -1 after filling `err`
 * and leaving nothing open. */
int egg_bzip2_encode_range(const char *path, uint64_t off, uint64_t len,
                           int block_size_100k, FILE **blob, uint64_t *csize,
                           uint32_t *crc, char *err, size_t errsz);

#endif
