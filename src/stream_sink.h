/* stream_sink.h — streaming output for the decompression codecs.
 *
 * A decoder that produces more bytes than the memory we want to hold calls this
 * callback for each slice instead of filling a buffer the size of the member.
 * It is used by the ALZ reader and by solid EGG archives, whose decompressed
 * stream is never held in memory.
 *
 * The callback returns 0 to continue, -1 to stop: the decoder then propagates
 * its own error code (-1) and the caller produces the message.
 */
#ifndef STREAM_SINK_H
#define STREAM_SINK_H

#include <stddef.h>

typedef int (*stream_sink_fn)(void *ctx, const unsigned char *data, size_t len);

#endif
