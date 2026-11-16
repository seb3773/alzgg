/* egg_lea.h — LEA-128 / LEA-256 block cipher (KS X 3246).
 *
 * Used by EGG encryption methods 5 (LEA-128) and 6 (LEA-256), which appeared
 * with ALZip 10.5. The format frames the block exactly like AES (FORMAT-EGG.md
 * §12.5): PBKDF2-HMAC-SHA1 over the salt, 2-byte verifier, HMAC-SHA1 truncated
 * to 10 bytes, then CTR over the member stream.
 *
 * Only the encryption direction is needed: CTR encrypts the counter with the
 * forward function. The standard vectors (appendix A) are checked by
 * `make test` (tests/run_tests.sh, step 8).
 */
#ifndef EGG_LEA_H
#define EGG_LEA_H

#include <stddef.h>
#include <stdint.h>

typedef struct EggLea {
    uint32_t rk[32][6];          /* one set of 6 words per round */
    int      rounds;
} EggLea;

/* `keylen` is 16 (LEA-128, 24 rounds) or 32 (LEA-256, 32 rounds). */
void egg_lea_init(EggLea *l, const uint8_t *key, size_t keylen);

/* Encrypts one 16-byte block (input and output may be the same buffer). */
void egg_lea_encrypt(const EggLea *l, const uint8_t in[16], uint8_t out[16]);

/* alzgg: XORs `len` bytes of `buf` with the CTR keystream E(ctr), E(ctr+1),
 * ... (128-bit big-endian counter, +1 per 16-byte block; a final partial
 * block still consumes its counter), leaving `ctr` advanced. Same bytes as
 * egg_lea_encrypt on each counter in turn. */
void egg_lea_ctr_xor(const EggLea *l, uint8_t ctr[16], uint8_t *buf, size_t len);

#endif
