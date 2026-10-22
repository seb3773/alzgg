================================================================================
alzgg - Pure C encoder and decoder for ALZ and EGG archives
================================================================================
(based on ALZip (c) ESTsoft Corp)
pure C reimplementation by seb3773
https://github.com/seb3773/alzgg


LEGAL NOTICE & DISCLAIMER (INTEROPERABILITY & DIGITAL PRESERVATION)
--------------------------------------------------------------------------------
* Independent Implementation: alzgg is an independent pure C reimplementation
  developed through reverse engineering, disassembly, and protocol analysis by
  seb3773 for digital format preservation and technical interoperability.
* No Affiliation: This project is completely independent and is not affiliated
  with, sponsored by, or endorsed by ESTsoft Corp.
* No Proprietary Binaries: Absolutely no proprietary software, binaries, or
  dynamic link libraries (.exe, .dll) from ESTsoft Corp. are distributed, bundled,
  or included in this package.
* Trademarks: "ALZip", ".alz", ".egg", and associated marks are trademarks or
  registered trademarks of ESTsoft Corp. All original proprietary assets remain
  the exclusive property of ESTsoft Corp.
* Legal Basis: Developed in accordance with EU Directive 2009/24/EC on the legal
  protection of computer programs (transposed into French law under Code de la
  propriete intellectuelle, Article L122-6-1 IV), explicitly permitting reverse
  engineering and decompilation solely to achieve technical interoperability.


OVERVIEW & CAPABILITIES
--------------------------------------------------------------------------------
alzgg is a standalone, single-binary C tool providing bidirectional bit-exact
parity with ESTsoft ALZip (ALZipCon 12.30 and 8.0) for both historical ALZ and
modern EGG archive formats.

Containers:
  * ALZ (.alz) and EGG (.egg) archive creation, listing and extraction.
  * Automatic format detection via magic signature or output extension.
  * Split multi-volume archives (.alz, .a01, .a02... / .vol1.egg, .vol2.egg...).
  * Solid EGG archives with on-the-fly streaming CRC verification.
  * Preserves POSIX/Windows attributes, timestamps and UTF-8 member names.

Compression Codecs:
  * Method 0: Store (uncompressed)
  * Method 1: Raw DEFLATE
  * Method 2: BZip2 (via vendored bzip2 1.0.5)
  * Method 3: AZO (reverse-engineered range coder with x86 filter)
  * Method 4: LZMA (via vendored LZMA SDK 4.65)
  * Full reproduction of the ALZip 12.30 Optimized routing matrix (148 extensions).

Encryption:
  * ZipCrypto (traditional PKZIP encryption for ALZ and EGG).
  * AES-128 and AES-256 (standard EGG encryption).
  * LEA-128 and LEA-256 (Korean national cipher KS X 3246, ALZip 12.30 -tp3/-tp4).

Security:
  * Path Traversal & Zip-Slip Protection: continuously tracks directory nesting
    depth; intercepts any attempt to ascend above destination root (../ or ..\).
  * Rejects leading absolute slashes (/ or \) and DOS drive identifiers (C:).


COMMAND LINE USAGE
--------------------------------------------------------------------------------
  alzgg list    ARCHIVE [-u|--unix] [-1|--bare]
  alzgg extract ARCHIVE [-d DEST] [-p PASSWORD] [-u|--unix] [--raw]
  alzgg create  OUTPUT [-p PROFILE] [-s] [-v SIZE] [-T DATE[,DATE...]]
                [-m0|-m1|-m2] [-i ID[,ID...]] [--attr HEX[,HEX...]]
                [--password PASS] [--crypt zip|aes128|aes256|lea128|lea256]
                [--crypt-info HEX[,HEX...]] ENTRY...

Common Options:
  -d DEST       Destination directory for extraction (default: current directory).
  -p PASSWORD   Password for decryption during extraction.
  -p PROFILE    Compression profile for EGG creation:
                  none      (m0: uncompressed)
                  compspeed (m1: fast deflate)
                  normal    (m2: normal deflate)
                  compratio (m3: LZMA)
                  optimized (m4: automatic codec routing by file extension)
  -s            Create a solid EGG archive (shared compression stream).
  -v SIZE       Split into volumes of SIZE bytes (e.g. 100KB, 1MB, 10MB, 1GB).
  -u, --unix    Format paths as Unix relative paths (/ slashes, lowercase).
  -1, --bare    Bare output format (one path per line, ideal for scripts/xargs).
  --password P  Set password to encrypt created archive.
  --crypt C     Encryption cipher: zip, aes128, aes256, lea128, lea256.
  --format FMT  Force container format: alz or egg.


EXAMPLES
--------------------------------------------------------------------------------
1. List archive contents:
   alzgg list archive.egg
   alzgg list -1 archive.alz               # bare output for scripting

2. Extract an archive:
   alzgg extract archive.egg -d /tmp/output
   alzgg extract secret.egg -p mysecret -d out/

3. Create an archive:
   alzgg create backup.egg docs/ photos/
   alzgg create -p optimized release.egg src/ Makefile
   alzgg create -s -p compratio solid_backup.egg project/
   alzgg create --password secret --crypt aes256 safe.egg secret.txt
   alzgg create -v 10MB split_data.egg bigfile.iso


LICENCE & CREDITS
--------------------------------------------------------------------------------
Project code is provided as-is for digital format preservation and interoperability.
Pure C reimplementation by seb3773.

Vendored third-party components:
  * zlib (src/zlib_deflate/): zlib licence
  * bzip2 1.0.5 (src/bzip2_dec/): bzip2 licence
  * LZMA SDK 4.65 (src/lzma_sdk/): Public Domain
