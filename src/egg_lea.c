/* egg_lea.c — LEA-128 / LEA-256 (KS X 3246, TTAK.KO-12.0223).
 *
 * 32-bit ARX, 4 state words, 6 words per round key set. The constants come from
 * the hexadecimal expansion of sqrt(766995) — 76/69/95 are the ASCII codes of
 * "L", "E", "A". The appendix A vectors are reproduced by `make test`.
 */
#include "egg_lea.h"

#include <string.h>

static const uint32_t lea_delta[8] = {
    0xc3efe9dbu, 0x44626b02u, 0x79e27c8au, 0x78df30ecu,
    0x715ea49eu, 0xc785da0au, 0xe04ef22au, 0xe5c40957u
};

/* Rotations by position in the round key set, whatever the key size:
 * 1, 3, 6, 11, 13, 17 (KS X 3246, §2.2). */
static const unsigned lea_rot[6] = { 1, 3, 6, 11, 13, 17 };

static uint32_t rol32(uint32_t x, unsigned n)
{
    n &= 31;
    return n ? (x << n) | (x >> (32 - n)) : x;
}

static uint32_t ror32(uint32_t x, unsigned n)
{
    n &= 31;
    return n ? (x >> n) | (x << (32 - n)) : x;
}

static uint32_t get_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void put_le32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

void egg_lea_init(EggLea *l, const uint8_t *key, size_t keylen)
{
    uint32_t t[8];
    size_t n, i, j;

    memset(l, 0, sizeof *l);
    if (keylen != 16 && keylen != 32) return;
    n = keylen / 4;                       /* 4 ou 8 mots */
    l->rounds = keylen == 16 ? 24 : 32;
    for (i = 0; i < n; ++i) t[i] = get_le32(key + 4 * i);

    for (i = 0; i < (size_t)l->rounds; ++i) {
        if (n == 4) {
            for (j = 0; j < 4; ++j)
                t[j] = rol32(t[j] + rol32(lea_delta[i % 4], (unsigned)(i + j)),
                             lea_rot[j]);
            /* LEA-128 reuses T1 three times (document, §12.5.4). */
            l->rk[i][0] = t[0];
            l->rk[i][1] = t[1];
            l->rk[i][2] = t[2];
            l->rk[i][3] = t[1];
            l->rk[i][4] = t[3];
            l->rk[i][5] = t[1];
        } else {
            for (j = 0; j < 6; ++j) {
                size_t k = (6 * i + j) % 8;
                t[k] = rol32(t[k] + rol32(lea_delta[i % 8], (unsigned)(i + j)),
                             lea_rot[j]);
            }
            for (j = 0; j < 6; ++j)
                l->rk[i][j] = t[(6 * i + j) % 8];
        }
    }
    memset(t, 0, sizeof t);
}

void egg_lea_encrypt(const EggLea *l, const uint8_t in[16], uint8_t out[16])
{
    uint32_t x[4];
    int i;

    for (i = 0; i < 4; ++i) x[i] = get_le32(in + 4 * i);
    for (i = 0; i < l->rounds; ++i) {
        const uint32_t *k = l->rk[i];
        uint32_t t0 = rol32((x[0] ^ k[0]) + (x[1] ^ k[1]), 9);
        uint32_t t1 = ror32((x[1] ^ k[2]) + (x[2] ^ k[3]), 5);
        uint32_t t2 = ror32((x[2] ^ k[4]) + (x[3] ^ k[5]), 3);

        x[3] = x[0];                      /* l'ancien X0 devient X3 */
        x[0] = t0;
        x[1] = t1;
        x[2] = t2;
    }
    for (i = 0; i < 4; ++i) put_le32(out + 4 * i, x[i]);
    memset(x, 0, sizeof x);
}
