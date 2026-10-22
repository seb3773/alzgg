/* egg_crypt.h — encryption and decryption of EGG and ALZ members (spec §12). */
#ifndef EGG_CRYPT_H
#define EGG_CRYPT_H

#include <stddef.h>
#include <stdint.h>

/* Decrypts IN PLACE the compressed stream of ONE member: its block payloads
 * concatenated in block order, which is exactly the stream ALZip's decryptor
 * works on (spec §12.6: one decryptor per file, continuing from block to block).
 *
 *   method        : EGG_CRYPT_ZIP / _AES128 / _AES256 / _LEA128 / _LEA256
 *   info/info_len : data of the Encrypt Info sub-header (salt, verifier, HMAC)
 *   crc32_declare : CRC-32 of the block's decompressed content, used as the
 *                   ZipCrypto password check (verifier byte 11, §12.3)
 *   password      : UTF-8 password, converted by egg_pw_encode()
 *
 * Checks performed BEFORE any plaintext byte is released:
 *   - ZipCrypto: the 12 verifier bytes must yield the expected byte;
 *   - AES, LEA : the PBKDF2 verifier (2 bytes) then the HMAC-SHA1 of the
 *                ciphertext (first 10 bytes, §12.4) must match.
 *
 * Returns 0 on success, -1 otherwise after filling `err`. */
int egg_crypt_decrypt(int method, const uint8_t *info, uint32_t info_len,
                      uint32_t crc32_declare, const char *password,
                      uint8_t *buf, size_t len, char *err, size_t errsz);

/* Variant for a multi-block EGG member: the ZipCrypto verifier carries the two
 * high bytes of the WHOLE member CRC (measured on lot H: 5 GiB in two blocks),
 * which the caller only knows after decompression. With `check_zip` set to 0,
 * decryption happens without a check and `ver_out` (12 bytes, optional) receives
 * the plain verifier; the caller then compares ver_out[11] with
 * (whole_crc >> 24). */
int egg_crypt_decrypt_ex(int method, const uint8_t *info, uint32_t info_len,
                         uint32_t crc32_declare, const char *password,
                         int check_zip, uint8_t *ver_out,
                         uint8_t *buf, size_t len, char *err, size_t errsz);

/* Streaming decryption, for reading: one context covers ALL blocks of a member
 * (the stream is continuous from block to block, spec §12.6) and the plaintext
 * bytes come out in slices, never holding the member in memory.
 *
 *   - ZipCrypto: the key state is enough; `ver_out` (12 bytes, optional) receives
 *     the plain verifier. `check_zip` set to 1 requires it to match the CRC
 *     passed in (single-block member); at 0, the caller compares `ver_out[11]`
 *     with the whole member CRC itself (multi-block, cf.
 *     egg_crypt_decrypt_ex).
 *   - AES: `egg_crypt_dec_auth()` must receive the whole CIPHERTEXT (in order)
 *     before `egg_crypt_dec_ready()`, which checks the HMAC then arms the
 *     counter: no plaintext byte is produced until authentication has succeeded.
 *
 * `egg_crypt_dec_update()` decrypts IN PLACE and returns 0, or -1 when the method
 * is not supported. Free with egg_crypt_dec_close(). */
typedef struct EggCryptDec EggCryptDec;

EggCryptDec *egg_crypt_dec_begin(int method, const uint8_t *info,
                                 uint32_t info_len, uint32_t crc32_declare,
                                 const char *password, int check_zip,
                                 uint8_t ver_out[12], char *err, size_t errsz);
int  egg_crypt_dec_auth(EggCryptDec *d, const uint8_t *buf, size_t len);
int  egg_crypt_dec_ready(EggCryptDec *d, char *err, size_t errsz);
int  egg_crypt_dec_update(EggCryptDec *d, uint8_t *buf, size_t len);
void egg_crypt_dec_close(EggCryptDec *d);

/* Password encoding as ALZip derives it (spec §12.7): the UTF-8 string is
 * converted to the ANSI code page (CP1252 under the reference build), an
 * unrepresentable character becoming '?'. `out` receives the bytes followed by a
 * zero and must hold `cap` bytes (256 is enough); `out_len` (optional) receives
 * the length. Returns 0, or -1 on a missing password, an over-long one or
 * invalid UTF-8, after filling `err`. */
int egg_pw_encode(const char *password, uint8_t *out, size_t cap,
                  size_t *out_len, char *err, size_t errsz);

/* --------------------------------------------------------------- chiffrement */

/* Random material supplied by the caller for one member. ALZip draws it at
 * random: an archive is therefore reproducible byte for byte only if it is given
 * the same material back. The size depends on the method:
 *   ZipCrypto: 10 bytes. ALZip fills the 12-byte verifier with those ten bytes
 *              then the TWO high bytes of the member CRC-32 (low byte first:
 *              measured on the 7 verifiers of the corpus, EGG and ALZ).
 *   AES, LEA : 8 salt bytes (128 bits) or 16 (256 bits). The PBKDF2 verifier and
 *              the HMAC are derived from them, so nothing else to supply.
 * The `len` field is the useful length of `bytes` (16 at most). */
typedef struct EggCryptMaterial {
    uint8_t bytes[16];
    size_t  len;
} EggCryptMaterial;

/* Encryption context of ONE member, opaque. A member's stream is continuous from
 * block to block (spec §12.6): a single context therefore covers all its
 * blocks. */
typedef struct EggCryptCtx EggCryptCtx;

/* Prepares the encryption of a member and fills the Encrypt Info field:
 *   ZipCrypto: 12 ENCRYPTED verifier bytes (what is stored in the sub-header,
 *              and at the head of the data on the ALZ side);
 *   AES      : salt || verifier(2) || HMAC(10) — the last 10 bytes are written by
 *              egg_crypt_enc_finish(), once the ciphertext is known.
 * `crc32_member` is the CRC-32 of the UNCOMPRESSED content: it provides the last
 * two bytes of the ZipCrypto verifier. `info_cap` must be at least 12
 * (ZipCrypto), 20 (AES-128) or 28 (AES-256).
 * Returns a context to free with egg_crypt_enc_free(), or NULL after filling
 * `err`. The password is converted by egg_pw_encode() (spec §12.7: ANSI code
 * page, missing character -> '?'). */
EggCryptCtx *egg_crypt_enc_begin(int method, const EggCryptMaterial *material,
                                 uint32_t crc32_member, const char *password,
                                 uint8_t *info, size_t info_cap,
                                 size_t *info_len, char *err, size_t errsz);

/* Encrypts IN PLACE `len` bytes of the member stream (the same call sequence as
 * on reading: blocks in order). */
int egg_crypt_enc_update(EggCryptCtx *ctx, uint8_t *buf, size_t len);

/* Finishes the member: fills the AES HMAC into `info` (10 bytes starting at
 * offset salt + 2). No effect for ZipCrypto. */
int egg_crypt_enc_finish(EggCryptCtx *ctx, uint8_t *info, size_t info_len);

void egg_crypt_enc_free(EggCryptCtx *ctx);

#endif
