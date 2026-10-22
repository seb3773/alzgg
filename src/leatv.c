/* leatv.c — LEA standard vectors (KS X 3246, annex A).
 *
 * Internal checker, outside the user binary (like bz2enc and azoenc): it pins
 * the key schedule and the round functions of src/egg_lea.c on both sizes the
 * EGG format uses (methods 5 and 6). The packed_egg/ archives check the rest of
 * the chain (PBKDF2, verifier, HMAC, CTR) byte for byte against ALZip 12.30.
 *
 * Output: one line per vector, exit status 0 when everything matches.
 */
#include "egg_lea.h"

#include <stdio.h>
#include <string.h>

static int hexval(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Decode a hex string (no separator) into `out`. */
static size_t unhex(const char *s, unsigned char *out, size_t cap)
{
    size_t n = 0;

    while (s[0] && s[1] && n < cap) {
        int hi = hexval((unsigned char)s[0]), lo = hexval((unsigned char)s[1]);
        if (hi < 0 || lo < 0) break;
        out[n++] = (unsigned char)(hi << 4 | lo);
        s += 2;
    }
    return n;
}

static int vector(const char *name, const char *key_hex, const char *pt_hex,
                  const char *ct_hex)
{
    unsigned char key[32], pt[16], want[16], got[16];
    size_t keylen = unhex(key_hex, key, sizeof key);
    EggLea lea;
    size_t i;

    if (unhex(pt_hex, pt, sizeof pt) != 16 || unhex(ct_hex, want, sizeof want) != 16) {
        printf("%s: malformed vector\n", name);
        return 1;
    }
    egg_lea_init(&lea, key, keylen);
    egg_lea_encrypt(&lea, pt, got);
    if (memcmp(got, want, 16) != 0) {
        printf("%s: encrypted ", name);
        for (i = 0; i < 16; ++i) printf("%02x", got[i]);
        printf(" != expected ");
        for (i = 0; i < 16; ++i) printf("%02x", want[i]);
        printf("\n");
        return 1;
    }
    printf("%s: standard vector reproduced\n", name);
    return 0;
}

int main(void)
{
    int bad = 0;

    bad |= vector("LEA-128",
                  "0f1e2d3c4b5a69788796a5b4c3d2e1f0",
                  "101112131415161718191a1b1c1d1e1f",
                  "9fc84e3528c6c6185532c7a704648bfd");
    bad |= vector("LEA-256",
                  "0f1e2d3c4b5a69788796a5b4c3d2e1f0"
                  "f0e1d2c3b4a5968778695a4b3c2d1e0f",
                  "303132333435363738393a3b3c3d3e3f",
                  "d651aff647b189c13a8900ca27f9e197");
    return bad;
}
