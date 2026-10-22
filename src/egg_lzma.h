/* egg_lzma.h — LZMA codec for EGG blocks (method 4, spec §11.1).
 *
 * A block's stream starts with 9 bytes: 4 constant bytes (measured
 * `04 41 05 00` on the 25 LZMA blocks of the corpus, ignored when reading) then
 * the 5 property bytes of the LZMA SDK (lc/lp/pb + dictionary size). The rest is
 * the raw LZMA stream, without an end marker.
 *
 * The encoder is LZMA SDK 4.65 (public domain, src/lzma_sdk/), set to its
 * default level 5 — lc=3, lp=0, pb=2, 16 MiB dictionary, nice_len 32,
 * mc 32, BT4. That is the only setting that reproduces the 25 reference blocks
 * byte for byte (SDK 19.00 diverges after a few hundred bytes).
 */
#ifndef EGG_LZMA_H
#define EGG_LZMA_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "stream_sink.h"

/* Decodes a whole block: `src` holds the 9 header bytes + the stream, `usize`
 * is the expected output size. Returns 0, or -1 after filling `err`. */
int egg_lzma_decode(const uint8_t *src, size_t csize, uint8_t *dst, size_t usize,
                    char *err, size_t errsz);

/* Same decoding, streaming out to `sink` (64 KiB slices): used for solid
 * archives, whose decompressed stream does not fit in memory. Returns 0 when
 * exactly `usize` bytes are produced. */
int egg_lzma_decode_to(const uint8_t *src, size_t csize, stream_sink_fn sink,
                       void *ctx, uint64_t usize, char *err, size_t errsz);

/* Encodes the [off, off+len) slice of `path` into a temporary file (returned in
 * `*blob`, rewound), with its uncompressed CRC-32. */
int egg_lzma_encode_range(const char *path, uint64_t off, uint64_t len,
                          FILE **blob, uint64_t *csize, uint32_t *crc,
                          char *err, size_t errsz);

/* Encodes an already concatenated stream (solid archive) read from `in` over
 * `len` bytes, starting at its current position. */
int egg_lzma_encode_stream(FILE *in, uint64_t len, FILE **blob, uint64_t *csize,
                           uint32_t *crc, char *err, size_t errsz);

#endif
