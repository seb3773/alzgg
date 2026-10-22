#ifndef ALZ_INFLATE_H
#define ALZ_INFLATE_H

#include <stddef.h>
#include <stdint.h>

#include "stream_sink.h"

/* inflate of a raw deflate stream (RFC1951) from an ALZ member, container
 * method 2. out: output buffer, exact size out_size (the member's usize).
 * Returns 0 = success, -1 = error. */
int alz_inflate(const uint8_t *in, size_t in_size,
                unsigned char *out, size_t out_size);

/* Same decoder, but the output streams out: `sink` receives slices of at most
 * 64 KiB, in order. `expect` is the expected decompressed size (usize): decoding
 * fails if the stream does not produce exactly that much. `produced`
 * (optional) receives the total produced, even when the sink fails. */
int alz_inflate_to(const uint8_t *in, size_t in_size,
                   stream_sink_fn sink, void *ctx,
                   uint64_t expect, uint64_t *produced);

#endif
