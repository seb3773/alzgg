/* LzMatchLen.h -- alzgg addition (not part of LZMA SDK 4.65).

   MatchLenFrom(a, b, i, limit): the smallest j >= i such that j == limit or
   a[j] != b[j]; i itself when i >= limit. It is EXACTLY the value of the
   SDK's byte loops `for (; i < limit && a[i] == b[i]; i++);`, computed eight
   bytes at a time where the target allows unaligned little-endian 64-bit
   loads (only bytes below `limit` are ever read, as in the byte loop). */
#ifndef __LZ_MATCH_LEN_H
#define __LZ_MATCH_LEN_H

#include <string.h>
#include "Types.h"

#if defined(__GNUC__) && (defined(__x86_64__) || defined(__i386__) || defined(__aarch64__)) && \
    defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define LZ_MATCHLEN_WORDS 1
#endif

static __inline UInt32 MatchLenFrom(const Byte *a, const Byte *b, UInt32 i, UInt32 limit)
{
#ifdef LZ_MATCHLEN_WORDS
  while (i + 8 <= limit)
  {
    unsigned long long x, y;
    memcpy(&x, a + i, 8);
    memcpy(&y, b + i, 8);
    x ^= y;
    if (x)
      return i + ((UInt32)__builtin_ctzll(x) >> 3);
    i += 8;
  }
#endif
  while (i < limit && a[i] == b[i])
    i++;
  return i;
}

#endif
