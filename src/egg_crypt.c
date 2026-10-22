/* egg_crypt.c — encryption and decryption of EGG/ALZ members
 * (FORMAT-EGG.md §12).
 *
 * Both directions use the same primitives, checkable against the ALZip 8
 * measurements (ten encrypted archives: EGG and ALZ, single- and multi-member,
 * split):
 *   - ZipCrypto (method 0): the classic PKZIP 2.0 stream cipher;
 *   - AES-128/256 (methods 1, 2): WinZip AE-2 CTR mode, keys derived with
 *     PBKDF2-HMAC-SHA1 (1000 iterations, 8- or 16-byte salt);
 *   - LEA-128/256 (methods 5, 6): same derivation and same HMAC as AES, CTR with
 *     a big-endian 128-bit counter starting at zero (KS X 3246);
 *   - HMAC-SHA1 (first 10 bytes) for authentication of the ciphertext.
 *
 * ALZip 8 does not offer LEA (its `-tp` stops at 2, and no resource names it);
 * the LEA references come from ALZip 12.30, whose undocumented `-tp3`/`-tp4`
 * writes LEA-128/LEA-256 (packed_egg/).
 *
 * None of these routines releases a plaintext byte before validating the
 * password (ZipCrypto verifier / PBKDF2 verifier + AES/LEA HMAC).
 */
#include "egg_crypt.h"
#include "egg.h"          /* EGG_CRYPT_* */
#include "egg_lea.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Key length of the PBKDF2-derived methods (AES and LEA): 0 for ZipCrypto and
 * everything else. */
static int crypt_keylen(int method)
{
    switch (method) {
        case EGG_CRYPT_AES128:
        case EGG_CRYPT_LEA128: return 16;
        case EGG_CRYPT_AES256:
        case EGG_CRYPT_LEA256: return 32;
        default:               return 0;
    }
}

static int crypt_is_lea(int method)
{
    return method == EGG_CRYPT_LEA128 || method == EGG_CRYPT_LEA256;
}

/* LEA counter increment: big-endian 128-bit integer, +1 from byte 15
 * (spec §12.5.6). The carry stops at the first non-null byte.
 * (AES does the opposite: little-endian, from byte 0 — AE-2.) */
static void ctr_inc_be(uint8_t ctr[16])
{
    int i;

    for (i = 15; i >= 0; --i)
        if (++ctr[i]) break;
}

static const char *crypt_name(int method)
{
    switch (method) {
        case EGG_CRYPT_AES128: return "AES-128";
        case EGG_CRYPT_AES256: return "AES-256";
        case EGG_CRYPT_LEA128: return "LEA-128";
        case EGG_CRYPT_LEA256: return "LEA-256";
        default:               return "?";
    }
}

static void err_set(char *err, size_t errsz, const char *fmt, ...)
{
    va_list ap;
    if (!err || !errsz) return;
    va_start(ap, fmt);
    vsnprintf(err, errsz, fmt, ap);
    va_end(ap);
}

/* ======================================================= mot de passe === */
/* ALZip converts the password (UTF-16) to the system ANSI code page before key
 * derivation; a character missing from that page becomes '?'. Measured on the
 * oracle (ALZipCon 8.0.0.18 under Wine, code page 1252):
 *   "é" -> E9, "ß" -> DF, "€" -> 80, "한" -> 3F.
 * The 27 positions CP1252 fills outside Latin-1 are therefore needed to
 * reproduce 0x80-0x9F; the five undefined positions (81 8D 8F 90 9D) and any
 * code point beyond U+00FF become '?'. */
static const uint16_t cp1252_hi[32] = {
    0x20AC, 0x0000, 0x201A, 0x0192, 0x201E, 0x2026, 0x2020, 0x2021,
    0x02C6, 0x2030, 0x0160, 0x2039, 0x0152, 0x0000, 0x017D, 0x0000,
    0x0000, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014,
    0x02DC, 0x2122, 0x0161, 0x203A, 0x0153, 0x0000, 0x017E, 0x0178
};

static uint8_t cp1252_byte(uint32_t cp)
{
    int i;
    if (cp < 0x80 || (cp >= 0xA0 && cp <= 0xFF)) return (uint8_t)cp;
    for (i = 0; i < 32; ++i)
        if (cp1252_hi[i] && cp1252_hi[i] == cp) return (uint8_t)(0x80 + i);
    return '?';
}

int egg_pw_encode(const char *password, uint8_t *out, size_t cap,
                  size_t *out_len, char *err, size_t errsz)
{
    const unsigned char *s = (const unsigned char *)password;
    size_t n = 0;

    if (out_len) *out_len = 0;
    if (!password) {
        err_set(err, errsz, "missing password");
        return -1;
    }
    while (*s) {
        uint32_t cp;

        if (*s < 0x80) {
            cp = *s++;
        } else if ((*s & 0xE0) == 0xC0) {
            if ((s[1] & 0xC0) != 0x80 || (*s & 0x1E) == 0) goto bad_utf8;
            cp = ((uint32_t)(s[0] & 0x1F) << 6) | (s[1] & 0x3F);
            if (cp < 0x80) goto bad_utf8;
            s += 2;
        } else if ((*s & 0xF0) == 0xE0) {
            if ((s[1] & 0xC0) != 0x80 || (s[2] & 0xC0) != 0x80) goto bad_utf8;
            cp = ((uint32_t)(s[0] & 0x0F) << 12) |
                 ((uint32_t)(s[1] & 0x3F) << 6) | (s[2] & 0x3F);
            if (cp < 0x800 || (cp >= 0xD800 && cp <= 0xDFFF)) goto bad_utf8;
            s += 3;
        } else if ((*s & 0xF8) == 0xF0) {
            if ((s[1] & 0xC0) != 0x80 || (s[2] & 0xC0) != 0x80 ||
                (s[3] & 0xC0) != 0x80) goto bad_utf8;
            cp = ((uint32_t)(s[0] & 0x07) << 18) |
                 ((uint32_t)(s[1] & 0x3F) << 12) |
                 ((uint32_t)(s[2] & 0x3F) << 6) | (s[3] & 0x3F);
            if (cp < 0x10000 || cp > 0x10FFFF) goto bad_utf8;
            s += 4;
        } else {
            goto bad_utf8;
        }
        if (n + 1 >= cap) {
            err_set(err, errsz, "password too long");
            return -1;
        }
        out[n++] = cp1252_byte(cp);
    }
    out[n] = 0;                       /* the derivation reads a C string */
    if (out_len) *out_len = n;
    return 0;

bad_utf8:
    err_set(err, errsz, "mot de passe : UTF-8 invalide");
    return -1;
}

/* ================================================================== AES === */
/* Only the forward direction (encrypting one block) is needed: CTR uses AES
 * only as a stream generator. */

static const uint8_t aes_sbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static const uint8_t aes_rcon[11] =
    { 0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };

typedef struct Aes {
    uint32_t rk[60];      /* round key words (4 * (Nr + 1)) */
    int      nr;
} Aes;

static uint32_t be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static uint32_t sub_word(uint32_t w)
{
    return ((uint32_t)aes_sbox[(w >> 24) & 0xFF] << 24) |
           ((uint32_t)aes_sbox[(w >> 16) & 0xFF] << 16) |
           ((uint32_t)aes_sbox[(w >> 8) & 0xFF] << 8) |
           (uint32_t)aes_sbox[w & 0xFF];
}

/* nk : 4 (AES-128) ou 8 (AES-256) */
static void aes_expand(Aes *a, const uint8_t *key, int nk)
{
    int nwords, i;
    a->nr = nk + 6;
    nwords = 4 * (a->nr + 1);
    for (i = 0; i < nk; ++i) a->rk[i] = be32(key + 4 * i);
    for (i = nk; i < nwords; ++i) {
        uint32_t t = a->rk[i - 1];
        if (i % nk == 0) {
            t = sub_word((t << 8) | (t >> 24)) ^ ((uint32_t)aes_rcon[i / nk] << 24);
        } else if (nk > 6 && i % nk == 4) {
            t = sub_word(t);
        }
        a->rk[i] = a->rk[i - nk] ^ t;
    }
}

/* State = 16 bytes in column order (s[4c + r] = byte r of column c), that is,
 * the order of the AES input block. */
static void add_round_key(uint8_t s[16], const uint32_t *rk)
{
    int c;
    for (c = 0; c < 4; ++c) {
        uint32_t k = rk[c];
        s[4 * c + 0] ^= (uint8_t)(k >> 24);
        s[4 * c + 1] ^= (uint8_t)(k >> 16);
        s[4 * c + 2] ^= (uint8_t)(k >> 8);
        s[4 * c + 3] ^= (uint8_t)k;
    }
}

static void sub_bytes(uint8_t s[16])
{
    int i;
    for (i = 0; i < 16; ++i) s[i] = aes_sbox[s[i]];
}

static uint8_t xtime(uint8_t x)
{
    return (uint8_t)((x << 1) ^ ((x & 0x80) ? 0x1b : 0x00));
}

static void shift_rows(uint8_t s[16])
{
    uint8_t t;
    t = s[1];  s[1]  = s[5];  s[5]  = s[9];  s[9]  = s[13]; s[13] = t;
    t = s[2];  s[2]  = s[10]; s[10] = t;
    t = s[6];  s[6]  = s[14]; s[14] = t;
    t = s[15]; s[15] = s[11]; s[11] = s[7];  s[7]  = s[3];  s[3]  = t;
}

static void mix_columns(uint8_t s[16])
{
    int c;
    for (c = 0; c < 4; ++c) {
        uint8_t *p = s + 4 * c;
        uint8_t a0 = p[0], a1 = p[1], a2 = p[2], a3 = p[3];
        uint8_t t = (uint8_t)(a0 ^ a1 ^ a2 ^ a3);
        p[0] ^= (uint8_t)(t ^ xtime((uint8_t)(a0 ^ a1)));
        p[1] ^= (uint8_t)(t ^ xtime((uint8_t)(a1 ^ a2)));
        p[2] ^= (uint8_t)(t ^ xtime((uint8_t)(a2 ^ a3)));
        p[3] ^= (uint8_t)(t ^ xtime((uint8_t)(a3 ^ a0)));
    }
}

static void aes_encrypt_block(const Aes *a, const uint8_t in[16], uint8_t out[16])
{
    uint8_t s[16];
    int r;
    memcpy(s, in, 16);
    add_round_key(s, a->rk);
    for (r = 1; r < a->nr; ++r) {
        sub_bytes(s);
        shift_rows(s);
        mix_columns(s);
        add_round_key(s, a->rk + 4 * r);
    }
    sub_bytes(s);
    shift_rows(s);
    add_round_key(s, a->rk + 4 * a->nr);
    memcpy(out, s, 16);
}

/* ================================================================== SHA-1 === */
typedef struct Sha1 {
    uint32_t h[5];
    uint64_t len;         /* bytes absorbed */
    uint8_t  buf[64];
    size_t   n;
} Sha1;

static uint32_t rol32(uint32_t x, int n)
{
    return (x << n) | (x >> (32 - n));
}

static void sha1_block(Sha1 *s, const uint8_t *p)
{
    uint32_t w[80], a, b, c, d, e;
    int i;

    for (i = 0; i < 16; ++i) w[i] = be32(p + 4 * i);
    for (i = 16; i < 80; ++i)
        w[i] = rol32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);

    a = s->h[0]; b = s->h[1]; c = s->h[2]; d = s->h[3]; e = s->h[4];
    for (i = 0; i < 80; ++i) {
        uint32_t f, k, t;
        if (i < 20)      { f = (b & c) | (~b & d);          k = 0x5A827999u; }
        else if (i < 40) { f = b ^ c ^ d;                   k = 0x6ED9EBA1u; }
        else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDCu; }
        else             { f = b ^ c ^ d;                   k = 0xCA62C1D6u; }
        t = rol32(a, 5) + f + e + k + w[i];
        e = d; d = c; c = rol32(b, 30); b = a; a = t;
    }
    s->h[0] += a; s->h[1] += b; s->h[2] += c; s->h[3] += d; s->h[4] += e;
}

static void sha1_init(Sha1 *s)
{
    s->h[0] = 0x67452301u; s->h[1] = 0xEFCDAB89u; s->h[2] = 0x98BADCFEu;
    s->h[3] = 0x10325476u; s->h[4] = 0xC3D2E1F0u;
    s->len = 0; s->n = 0;
}

static void sha1_update(Sha1 *s, const uint8_t *p, size_t n)
{
    s->len += n;
    if (s->n) {
        size_t take = 64 - s->n;
        if (take > n) take = n;
        memcpy(s->buf + s->n, p, take);
        s->n += take;
        p += take;
        n -= take;
        if (s->n == 64) { sha1_block(s, s->buf); s->n = 0; }
    }
    while (n >= 64) { sha1_block(s, p); p += 64; n -= 64; }
    if (n) { memcpy(s->buf, p, n); s->n = n; }
}

static void sha1_final(Sha1 *s, uint8_t out[20])
{
    uint64_t bits = s->len * 8;
    uint8_t pad[8];
    int i;
    uint8_t one = 0x80, zero = 0x00;

    sha1_update(s, &one, 1);
    while (s->n != 56) sha1_update(s, &zero, 1);
    for (i = 0; i < 8; ++i) pad[i] = (uint8_t)(bits >> (8 * (7 - i)));
    sha1_update(s, pad, 8);
    for (i = 0; i < 5; ++i) {
        out[4 * i + 0] = (uint8_t)(s->h[i] >> 24);
        out[4 * i + 1] = (uint8_t)(s->h[i] >> 16);
        out[4 * i + 2] = (uint8_t)(s->h[i] >> 8);
        out[4 * i + 3] = (uint8_t)s->h[i];
    }
}

/* ============================================================== HMAC-SHA1 === */
/* ipad/opad precomputed: allows the same buffers to be reused in the PBKDF2
 * loop without redoing the derivation on every iteration. */
static void hmac_sha1_pads(const uint8_t ipad[64], const uint8_t opad[64],
                           const uint8_t *msg, size_t msglen, uint8_t out[20])
{
    uint8_t inner[20];
    Sha1 s;

    sha1_init(&s);
    sha1_update(&s, ipad, 64);
    sha1_update(&s, msg, msglen);
    sha1_final(&s, inner);

    sha1_init(&s);
    sha1_update(&s, opad, 64);
    sha1_update(&s, inner, 20);
    sha1_final(&s, out);
}

static void hmac_pads_from_key(const uint8_t *key, size_t keylen,
                              uint8_t ipad[64], uint8_t opad[64])
{
    uint8_t k[64];
    Sha1 s;
    size_t i;

    memset(k, 0, sizeof k);
    if (keylen > 64) {
        sha1_init(&s);
        sha1_update(&s, key, keylen);
        sha1_final(&s, k);
    } else {
        memcpy(k, key, keylen);
    }
    for (i = 0; i < 64; ++i) {
        ipad[i] = (uint8_t)(k[i] ^ 0x36);
        opad[i] = (uint8_t)(k[i] ^ 0x5c);
    }
    memset(k, 0, sizeof k);
}

static void hmac_sha1(const uint8_t *key, size_t keylen,
                      const uint8_t *msg, size_t msglen, uint8_t out[20])
{
    uint8_t ipad[64], opad[64];

    hmac_pads_from_key(key, keylen, ipad, opad);
    hmac_sha1_pads(ipad, opad, msg, msglen, out);
    memset(ipad, 0, sizeof ipad);
    memset(opad, 0, sizeof opad);
}

/* ================================================================= PBKDF2 === */
/* PBKDF2-HMAC-SHA1, 1000 iterations, requested length <= 20 * 2^32 but here
 * always <= 66 bytes (2 * key + 2), hence at most 4 blocks. */
static void pbkdf2_hmac_sha1(const uint8_t *pw, size_t pwlen,
                             const uint8_t *salt, size_t saltlen,
                             uint32_t iters, uint8_t *out, size_t outlen)
{
    uint8_t ipad[64], opad[64], u[20], t[20], saltblk[256];
    uint32_t block = 1;
    size_t done = 0;

    if (saltlen + 4 > sizeof saltblk) {
        /* Impossible for EGG (salt <= 16), but truncation is never silent:
         * without the full derivation the key would be wrong. */
        memset(out, 0, outlen);
        return;
    }
    memcpy(saltblk, salt, saltlen);
    hmac_pads_from_key(pw, pwlen, ipad, opad);

    while (done < outlen) {
        uint32_t i;
        size_t j, take;

        saltblk[saltlen + 0] = (uint8_t)(block >> 24);
        saltblk[saltlen + 1] = (uint8_t)(block >> 16);
        saltblk[saltlen + 2] = (uint8_t)(block >> 8);
        saltblk[saltlen + 3] = (uint8_t)block;

        /* U1 = HMAC(pw, salt || block), puis Ui = HMAC(pw, U(i-1)) */
        hmac_sha1_pads(ipad, opad, saltblk, saltlen + 4, u);
        memcpy(t, u, 20);
        for (i = 1; i < iters; ++i) {
            hmac_sha1_pads(ipad, opad, u, 20, u);
            for (j = 0; j < 20; ++j) t[j] ^= u[j];
        }

        take = outlen - done < 20 ? outlen - done : 20;
        memcpy(out + done, t, take);
        done += take;
        block++;
    }

    memset(ipad, 0, sizeof ipad);
    memset(opad, 0, sizeof opad);
    memset(u, 0, sizeof u);
    memset(t, 0, sizeof t);
    memset(saltblk, 0, sizeof saltblk);
}

/* ============================================================== ZipCrypto === */
static uint32_t zip_tab[256];
static int zip_tab_ready;

static void zip_init_tab(void)
{
    int i, k;
    for (i = 0; i < 256; ++i) {
        uint32_t c = (uint32_t)i;
        for (k = 0; k < 8; ++k)
            c = (c >> 1) ^ ((c & 1) ? 0xEDB88320u : 0u);
        zip_tab[i] = c;
    }
    zip_tab_ready = 1;
}

static void zip_update(uint32_t k[3], uint8_t c)
{
    k[0] = zip_tab[(k[0] ^ c) & 0xFF] ^ (k[0] >> 8);
    k[1] = (k[1] + (k[0] & 0xFF)) * 134775813u + 1u;
    k[2] = zip_tab[(k[2] ^ (k[1] >> 24)) & 0xFF] ^ (k[2] >> 8);
}

static uint8_t zip_stream_byte(const uint32_t k[3])
{
    uint32_t t = k[2] | 2u;
    return (uint8_t)((t * (t ^ 1u)) >> 8);
}

/* ================================================================== input === */
int egg_crypt_decrypt_ex(int method, const uint8_t *info, uint32_t info_len,
                         uint32_t crc32_declare, const char *password,
                         int check_zip, uint8_t *ver_out,
                         uint8_t *buf, size_t len, char *err, size_t errsz)
{
    size_t i, pwlen = 0;
    uint8_t pwbuf[256];
    const uint8_t *pw = pwbuf;

    if (egg_pw_encode(password, pwbuf, sizeof pwbuf, &pwlen, err, errsz))
        return -1;

    if (method == EGG_CRYPT_ZIP) {
        uint32_t k[3] = { 0x12345678u, 0x23456789u, 0x34567890u };
        uint8_t ver[12], c;

        /* Only the 12 verifier bytes are read: the caller may come from EGG
(the Encrypt Info sub-header, longer) or from ALZ (the 12 bytes at the head of
the member data). */
        if (info_len < 12) {
            err_set(err, errsz, "ZipCrypto verifier too short (%u bytes)", info_len);
            return -1;
        }
        if (!zip_tab_ready) zip_init_tab();
        for (i = 0; i < pwlen; ++i) zip_update(k, pw[i]);
        /* The 12 verifier bytes also seed the state (spec §12.3) */
        for (i = 0; i < 12; ++i) {
            c = (uint8_t)(info[i] ^ zip_stream_byte(k));
            ver[i] = c;
            zip_update(k, c);
        }
        if (check_zip && ver[11] != (uint8_t)(crc32_declare >> 24)) {
            err_set(err, errsz, "incorrect password (ZipCrypto verifier)");
            return -1;
        }
        if (ver_out) memcpy(ver_out, ver, 12);
        for (i = 0; i < len; ++i) {
            c = (uint8_t)(buf[i] ^ zip_stream_byte(k));
            buf[i] = c;
            zip_update(k, c);
        }
        return 0;
    }

    if (crypt_keylen(method)) {
        int klen = crypt_keylen(method);
        size_t saltlen = (size_t)klen / 2;
        const uint8_t *salt, *ver, *mac;
        uint8_t dk[66], tag[20], ks[16], ctr[16];
        Aes aes;
        EggLea lea;
        size_t off, n;

        if (info_len < saltlen + 12) {
            err_set(err, errsz, "Encrypt Info %s too short (%u bytes, %zu required)",
                    crypt_name(method), info_len, saltlen + 12);
            return -1;
        }
        salt = info;
        ver  = info + saltlen;
        mac  = info + saltlen + 2;

        pbkdf2_hmac_sha1(pw, pwlen, salt, saltlen, 1000,
                         dk, (size_t)klen * 2 + 2);
        if (memcmp(dk + klen * 2, ver, 2) != 0) {
            err_set(err, errsz, "incorrect password (PBKDF2 verifier %s)",
                    crypt_name(method));
            memset(dk, 0, sizeof dk);
            return -1;
        }
        /* HMAC computed over the CIPHERTEXT, before any decryption (spec §12.4) */
        hmac_sha1(dk + klen, (size_t)klen, buf, len, tag);
        if (memcmp(tag, mac, 10) != 0) {
            err_set(err, errsz,
                    "%s authentication mismatch (HMAC-SHA1 of the ciphertext)",
                    crypt_name(method));
            memset(dk, 0, sizeof dk);
            return -1;
        }

        if (crypt_is_lea(method)) {
            egg_lea_init(&lea, dk, (size_t)klen);
            memset(ctr, 0, sizeof ctr);   /* LEA : compteur 128 bits gros-boutiste */
        } else {
            aes_expand(&aes, dk, klen / 4);
            memset(ctr, 0, sizeof ctr);
            ctr[0] = 1;                   /* AE-2 : valeur 1, petit-boutiste */
        }
        for (off = 0; off < len; off += 16) {
            n = len - off < 16 ? len - off : 16;
            if (crypt_is_lea(method)) {
                egg_lea_encrypt(&lea, ctr, ks);
                for (i = 0; i < n; ++i) buf[off + i] ^= ks[i];
                ctr_inc_be(ctr);
            } else {
                aes_encrypt_block(&aes, ctr, ks);
                for (i = 0; i < n; ++i) buf[off + i] ^= ks[i];
                for (i = 0; i < 16; ++i) if (++ctr[i]) break;
            }
        }
        memset(dk, 0, sizeof dk);
        memset(&aes, 0, sizeof aes);
        memset(&lea, 0, sizeof lea);
        return 0;
    }

    err_set(err, errsz, "encryption method %d not implemented", method);
    return -1;
}

int egg_crypt_decrypt(int method, const uint8_t *info, uint32_t info_len,
                      uint32_t crc32_declare, const char *password,
                      uint8_t *buf, size_t len, char *err, size_t errsz)
{
    return egg_crypt_decrypt_ex(method, info, info_len, crc32_declare,
                                password, 1, NULL, buf, len, err, errsz);
}

/* ============================================================= encryption === */
/* Same primitives, opposite direction. A member's stream is continuous: the
 * state (ZipCrypto keys, AES counter, ciphertext HMAC) therefore lives in a
 * context covering all its blocks, like ALZip's decryptor (spec §12.6). */

struct EggCryptCtx {
    int      method;
    uint32_t k[3];               /* ZipCrypto */
    Aes      aes;                /* AES    */
    EggLea   lea;                /* LEA    */
    uint8_t  ctr[16];
    size_t   saltlen;
    uint8_t  mac_ipad[64], mac_opad[64];
    Sha1     mac;
};

void egg_crypt_enc_free(EggCryptCtx *ctx)
{
    if (!ctx) return;
    memset(ctx, 0, sizeof *ctx);
    free(ctx);
}

EggCryptCtx *egg_crypt_enc_begin(int method, const EggCryptMaterial *material,
                                 uint32_t crc32_member, const char *password,
                                 uint8_t *info, size_t info_cap,
                                 size_t *info_len, char *err, size_t errsz)
{
    EggCryptCtx *ctx;
    uint8_t pwbuf[256];
    size_t i, pwlen = 0;
    const uint8_t *pw = pwbuf;

    if (egg_pw_encode(password, pwbuf, sizeof pwbuf, &pwlen, err, errsz))
        return NULL;
    if (!material) {
        err_set(err, errsz, "missing random encryption material");
        return NULL;
    }
    ctx = calloc(1, sizeof *ctx);
    if (!ctx) {
        err_set(err, errsz, "out of memory");
        return NULL;
    }
    ctx->method = method;

    if (method == EGG_CRYPT_ZIP) {
        uint8_t plain[12], stored[12];

        if (material->len != 10) {
            err_set(err, errsz, "ZipCrypto: 10 bytes of material expected "
                                "(got %zu)", material->len);
            goto fail;
        }
        if (info_cap < sizeof stored) {
            err_set(err, errsz, "Encrypt Info ZipCrypto: %zu bytes", info_cap);
            goto fail;
        }
        /* The last two verifier bytes are the member CRC-32, low byte first
         * (measured on the seven verifiers of the corpus). */
        memcpy(plain, material->bytes, 10);
        plain[10] = (uint8_t)(crc32_member >> 16);
        plain[11] = (uint8_t)(crc32_member >> 24);

        if (!zip_tab_ready) zip_init_tab();
        ctx->k[0] = 0x12345678u;
        ctx->k[1] = 0x23456789u;
        ctx->k[2] = 0x34567890u;
        for (i = 0; i < pwlen; ++i) zip_update(ctx->k, pw[i]);
        for (i = 0; i < 12; ++i) {
            stored[i] = (uint8_t)(plain[i] ^ zip_stream_byte(ctx->k));
            zip_update(ctx->k, plain[i]);
        }
        memcpy(info, stored, 12);
        *info_len = 12;
        memset(plain, 0, sizeof plain);
        memset(stored, 0, sizeof stored);
        return ctx;
    }

    if (crypt_keylen(method)) {
        int klen = crypt_keylen(method);
        size_t saltlen = (size_t)klen / 2;
        uint8_t dk[66];

        if (material->len != saltlen) {
            err_set(err, errsz, "%s: %zu salt bytes expected (got %zu)",
                    crypt_name(method), saltlen, material->len);
            goto fail;
        }
        if (info_cap < saltlen + 12) {
            err_set(err, errsz, "Encrypt Info %s: %zu bytes",
                    crypt_name(method), info_cap);
            goto fail;
        }
        memcpy(info, material->bytes, saltlen);
        pbkdf2_hmac_sha1(pw, pwlen, info, saltlen, 1000,
                         dk, (size_t)klen * 2 + 2);
        memcpy(info + saltlen, dk + klen * 2, 2);       /* verifier */
        ctx->saltlen = saltlen;
        memset(ctx->ctr, 0, sizeof ctx->ctr);
        if (crypt_is_lea(method)) {
            egg_lea_init(&ctx->lea, dk, (size_t)klen);
            /* LEA: big-endian 128-bit counter, zeroed (spec §12.5.6). */
        } else {
            aes_expand(&ctx->aes, dk, klen / 4);
            ctx->ctr[0] = 1;                            /* AE-2, petit-boutiste */
        }
        /* HMAC of the CIPHERTEXT, key = dk[klen..2*klen): incremental state so
         * the whole stream need not be kept in memory. */
        hmac_pads_from_key(dk + klen, (size_t)klen,
                           ctx->mac_ipad, ctx->mac_opad);
        sha1_init(&ctx->mac);
        sha1_update(&ctx->mac, ctx->mac_ipad, 64);
        memset(dk, 0, sizeof dk);
        *info_len = saltlen + 12;
        return ctx;
    }

    err_set(err, errsz, "encryption method %d not implemented", method);

fail:
    egg_crypt_enc_free(ctx);
    return NULL;
}

int egg_crypt_enc_update(EggCryptCtx *ctx, uint8_t *buf, size_t len)
{
    size_t i, off;

    if (!ctx) return -1;
    if (ctx->method == EGG_CRYPT_ZIP) {
        for (i = 0; i < len; ++i) {
            uint8_t c = (uint8_t)(buf[i] ^ zip_stream_byte(ctx->k));
            zip_update(ctx->k, buf[i]);
            buf[i] = c;
        }
        return 0;
    }
    if (crypt_keylen(ctx->method)) {
        uint8_t ks[16];
        int lea = crypt_is_lea(ctx->method);

        for (off = 0; off < len; off += 16) {
            size_t n = len - off < 16 ? len - off : 16;

            if (lea) {
                egg_lea_encrypt(&ctx->lea, ctx->ctr, ks);
                for (i = 0; i < n; ++i) buf[off + i] ^= ks[i];
                sha1_update(&ctx->mac, buf + off, n);   /* the CIPHERTEXT */
                ctr_inc_be(ctx->ctr);
            } else {
                aes_encrypt_block(&ctx->aes, ctx->ctr, ks);
                for (i = 0; i < n; ++i) buf[off + i] ^= ks[i];
                sha1_update(&ctx->mac, buf + off, n);   /* the CIPHERTEXT */
                for (i = 0; i < 16; ++i) if (++ctx->ctr[i]) break;
            }
        }
        memset(ks, 0, sizeof ks);
        return 0;
    }
    return -1;
}

/* ===================================================== streaming decrypt === */
/* Same primitives as egg_crypt_decrypt_ex(), but the state lives in a context and
 * the plaintext output is produced in slices: a 5 GiB member is decrypted with
 * two bounded buffers instead of a copy of the whole member. */

struct EggCryptDec {
    int      method;
    uint32_t k[3];               /* ZipCrypto */
    int      klen;               /* AES: 16 or 32 key bytes */
    size_t   saltlen;
    uint8_t  dk[32];             /* AES: PBKDF2 key (wiped on close) */
    uint8_t  mac_ipad[64], mac_opad[64];
    uint8_t  mac_expect[10];
    Sha1     mac;
    int      authed;
    Aes      aes;
    EggLea   lea;
    uint8_t  ctr[16];
};

void egg_crypt_dec_close(EggCryptDec *d)
{
    if (!d) return;
    memset(d, 0, sizeof *d);
    free(d);
}

EggCryptDec *egg_crypt_dec_begin(int method, const uint8_t *info,
                                 uint32_t info_len, uint32_t crc32_declare,
                                 const char *password, int check_zip,
                                 uint8_t ver_out[12], char *err, size_t errsz)
{
    uint8_t pwbuf[256];
    size_t pwlen = 0, i;
    const uint8_t *pw = pwbuf;
    EggCryptDec *d;

    if (egg_pw_encode(password, pwbuf, sizeof pwbuf, &pwlen, err, errsz))
        return NULL;
    d = calloc(1, sizeof *d);
    if (!d) {
        err_set(err, errsz, "out of memory");
        return NULL;
    }
    d->method = method;

    if (method == EGG_CRYPT_ZIP) {
        uint8_t ver[12], c;

        if (info_len < 12) {
            err_set(err, errsz, "ZipCrypto verifier too short (%u bytes)",
                    info_len);
            goto fail;
        }
        if (!zip_tab_ready) zip_init_tab();
        d->k[0] = 0x12345678u;
        d->k[1] = 0x23456789u;
        d->k[2] = 0x34567890u;
        for (i = 0; i < pwlen; ++i) zip_update(d->k, pw[i]);
        for (i = 0; i < 12; ++i) {
            c = (uint8_t)(info[i] ^ zip_stream_byte(d->k));
            ver[i] = c;
            zip_update(d->k, c);
        }
        if (check_zip && ver[11] != (uint8_t)(crc32_declare >> 24)) {
            err_set(err, errsz, "incorrect password (ZipCrypto verifier)");
            memset(ver, 0, sizeof ver);
            goto fail;
        }
        if (ver_out) memcpy(ver_out, ver, 12);
        memset(ver, 0, sizeof ver);
        return d;
    }

    if (crypt_keylen(method)) {
        uint8_t dk[66];
        const uint8_t *salt, *ver, *mac;

        d->klen = crypt_keylen(method);
        d->saltlen = (size_t)d->klen / 2;
        if (info_len < d->saltlen + 12) {
            err_set(err, errsz, "Encrypt Info %s too short (%u bytes)",
                    crypt_name(method), info_len);
            goto fail;
        }
        salt = info;
        ver  = info + d->saltlen;
        mac  = info + d->saltlen + 2;
        pbkdf2_hmac_sha1(pw, pwlen, salt, d->saltlen, 1000,
                         dk, (size_t)d->klen * 2 + 2);
        if (memcmp(dk + d->klen * 2, ver, 2) != 0) {
            err_set(err, errsz, "incorrect password (PBKDF2 verifier %s)",
                    crypt_name(method));
            memset(dk, 0, sizeof dk);
            goto fail;
        }
        memcpy(d->dk, dk, (size_t)d->klen);
        memcpy(d->mac_expect, mac, 10);
        hmac_pads_from_key(dk + d->klen, (size_t)d->klen,
                           d->mac_ipad, d->mac_opad);
        sha1_init(&d->mac);
        sha1_update(&d->mac, d->mac_ipad, 64);
        memset(dk, 0, sizeof dk);
        return d;
    }

    err_set(err, errsz, "encryption method %d not implemented", method);

fail:
    egg_crypt_dec_close(d);
    return NULL;
}

int egg_crypt_dec_auth(EggCryptDec *d, const uint8_t *buf, size_t len)
{
    if (!d) return -1;
    if (crypt_keylen(d->method)) {
        sha1_update(&d->mac, buf, len);
        return 0;
    }
    return 0;                       /* ZipCrypto does not authenticate the stream */
}

int egg_crypt_dec_ready(EggCryptDec *d, char *err, size_t errsz)
{
    uint8_t inner[20], tag[20];
    Sha1 s;

    if (!d) return -1;
    if (!crypt_keylen(d->method)) return 0;

    sha1_final(&d->mac, inner);
    sha1_init(&s);
    sha1_update(&s, d->mac_opad, 64);
    sha1_update(&s, inner, 20);
    sha1_final(&s, tag);
    memset(inner, 0, sizeof inner);
    memset(&s, 0, sizeof s);
    if (memcmp(tag, d->mac_expect, 10) != 0) {
        memset(tag, 0, sizeof tag);
        err_set(err, errsz,
                "%s authentication mismatch (HMAC-SHA1 of the ciphertext)",
                crypt_name(d->method));
        return -1;
    }
    memset(tag, 0, sizeof tag);
    memset(d->ctr, 0, sizeof d->ctr);
    if (crypt_is_lea(d->method)) {
        egg_lea_init(&d->lea, d->dk, (size_t)d->klen);
        /* LEA: big-endian 128-bit counter, zeroed (spec §12.5.6). */
    } else {
        aes_expand(&d->aes, d->dk, d->klen / 4);
        d->ctr[0] = 1;              /* compteur AE-2, petit-boutiste */
    }
    d->authed = 1;
    return 0;
}

int egg_crypt_dec_update(EggCryptDec *d, uint8_t *buf, size_t len)
{
    size_t i, off;

    if (!d) return -1;
    if (d->method == EGG_CRYPT_ZIP) {
        for (i = 0; i < len; ++i) {
            uint8_t c = (uint8_t)(buf[i] ^ zip_stream_byte(d->k));
            buf[i] = c;
            zip_update(d->k, c);
        }
        return 0;
    }
    if (crypt_keylen(d->method)) {
        uint8_t ks[16];
        int lea = crypt_is_lea(d->method);

        if (!d->authed) return -1;  /* ready() not called yet */
        for (off = 0; off < len; off += 16) {
            size_t n = len - off < 16 ? len - off : 16;

            if (lea) {
                egg_lea_encrypt(&d->lea, d->ctr, ks);
                for (i = 0; i < n; ++i) buf[off + i] ^= ks[i];
                ctr_inc_be(d->ctr);
            } else {
                aes_encrypt_block(&d->aes, d->ctr, ks);
                for (i = 0; i < n; ++i) buf[off + i] ^= ks[i];
                for (i = 0; i < 16; ++i) if (++d->ctr[i]) break;
            }
        }
        memset(ks, 0, sizeof ks);
        return 0;
    }
    return -1;
}

int egg_crypt_enc_finish(EggCryptCtx *ctx, uint8_t *info, size_t info_len)
{
    uint8_t inner[20], tag[20];
    Sha1 s;

    if (!ctx) return -1;
    if (ctx->method == EGG_CRYPT_ZIP) return 0;
    if (!crypt_keylen(ctx->method)) return -1;
    if (info_len < ctx->saltlen + 12) return -1;

    sha1_final(&ctx->mac, inner);
    sha1_init(&s);
    sha1_update(&s, ctx->mac_opad, 64);
    sha1_update(&s, inner, 20);
    sha1_final(&s, tag);
    memcpy(info + ctx->saltlen + 2, tag, 10);
    memset(inner, 0, sizeof inner);
    memset(tag, 0, sizeof tag);
    memset(&s, 0, sizeof s);
    return 0;
}
