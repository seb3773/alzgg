# EGG Archive Format Specification

Legal Notice: This reverse-engineering work was conducted strictly for the purposes of software interoperability and digital data preservation (under European Directive 2009/24/EC) to reconstruct the container structures, prediction filters, and entropy decoding/encoding algorithms of an obsolete historical archive format.

All multi-byte integers are little-endian unless stated otherwise.


---

## Table of Contents

1. [Overview](#1-overview)
2. [Archive Layout](#2-archive-layout)
3. [Signatures](#3-signatures)
4. [Extra Field](#4-extra-field)
5. [EGG Header](#5-egg-header)
6. [Prefix Section](#6-prefix-section)
7. [File Header](#7-file-header)
8. [File Sub-Headers](#8-file-sub-headers)
9. [Block Header](#9-block-header)
10. [End Marker](#10-end-marker)
11. [Compression Methods](#11-compression-methods)
12. [Encryption](#12-encryption)
13. [Split Archives](#13-split-archives)
14. [Solid Archives](#14-solid-archives)
15. [CRC-32](#15-crc-32)
16. [Parsing Notes](#16-parsing-notes)

Appendix:

- [A. AZO Compression Algorithm](#a-azo-compression-algorithm)

---

## 1. Overview

The EGG format is an archive format that supports multiple compression algorithms, multiple encryption
methods, split (multi-volume) archives, solid compression, and per-file
comments.

File extension: `.egg`

Byte order: Little-endian throughout, except AZO block headers (Appendix A.2).

---

## 2. Archive Layout

An EGG archive is a sequence of tagged records identified by 4-byte signatures.
The overall structure is:

```
[EGG Header]
[Prefix Section]
  [Split Info]        0 or more
  [Solid Info]        0 or 1
[End Marker]

[File Header 0]
  [Filename]          1 or more
  [Comment]           0 or more
  [Windows File Info] 0 or more
  [Encrypt Info]      0 or 1
[End Marker]
  [Block 0]
    [Block Header]
    [End Marker]
    [Compressed Data]
  [Block 1 ...]

[File Header 1 ...]

[Comment]             0 or more  (archive-level)

[End Marker]          final
```

Every section of sub-headers is terminated by an End Marker (`0x08E28222`).
Blocks follow immediately after the file sub-header End Marker. The archive
itself ends with a final End Marker.

---

## 3. Signatures

Every structural element begins with a 4-byte little-endian signature:

| Name               | Hex          | Description                    |
|--------------------|--------------|--------------------------------|
| EGG Header         | `0x41474745` | Archive magic (`EGGA` in ASCII)|
| Split Info         | `0x24F5A262` | Split archive info             |
| Solid Info         | `0x24E5A060` | Solid archive flag             |
| Global Encrypt     | `0x08D144A8` | Global encryption header       |
| File Header        | `0x0A8590E3` | File entry                     |
| Filename           | `0x0A8591AC` | Filename sub-header            |
| Comment            | `0x04C63672` | Comment sub-header             |
| Windows File Info  | `0x2C86950B` | Windows file information       |
| Posix File Info    | `0x1EE922E5` | POSIX file information         |
| Encrypt Info       | `0x08D1470F` | Encryption sub-header          |
| Block Header       | `0x02B50C13` | Compressed data block          |
| Dummy              | `0x07463307` | Padding/dummy block            |
| Skip               | `0xFFFF0000` | Ignored split info             |
| End Marker         | `0x08E28222` | Section terminator             |

Notes:
- Global Encrypt (`0x08D144A8`) and Posix File Info (`0x1EE922E5`) are defined
  in the format but not used in practice. Implementations should skip
  unrecognized extra-field-based sub-headers by reading their extra field
  prefix and advancing past `size` bytes.

---

## 4. Extra Field

Several sub-headers are wrapped in an "extra field" prefix. This prefix encodes
flags and the byte size of the data that follows.

```
Offset  Size  Description
+0      1     Flags byte
+1      2|4   Data size (UInt16 if flags bit 0 is 0; UInt32 if bit 0 is 1)
```

If `flags & 0x01 == 0`: the size field is 2 bytes (UInt16). Total prefix = 3 bytes.
If `flags & 0x01 == 1`: the size field is 4 bytes (UInt32). Total prefix = 5 bytes.

Remaining bits of the flags byte have sub-header-specific meanings (see
sections 8.1 and 8.2). For most sub-headers, flags is `0x00`.

Sub-headers that use this prefix: Split Info, Solid Info, Filename, Comment,
Windows File Info, Posix File Info, Encrypt Info, Dummy.

Sub-headers that do NOT use this prefix: File Header, Block Header.

---

## 5. EGG Header

The archive begins with the 4-byte magic signature `0x41474745`, followed by:

```
Offset  Size  Type    Description
+0      2     UInt16  Version (e.g. 0x0100 for v1.0)
+2      4     UInt32  Header ID (random non-zero value; used as volume ID)
+6      4     UInt32  Reserved (0x00000000)
```

Total: 4 (signature) + 10 (header) = 14 bytes.

The Header ID field serves as the volume identifier in split archives. Each
volume has a unique Header ID, and volumes reference each other by ID.

Observed encoder artefact: the reference build ships `NewEgg.dat`, the template
used for a new empty archive. Its 22 bytes are the entire content of an empty
EGG file and pin the fields ALZip writes before anything is added:

```
offset  bytes        meaning
0       45 47 47 41  'EGGA'
4       00 01        version 0x0100 (matches every supplied sample)
6       01 00 00 00  header ID = 1
10      00 00 00 00  reserved = 0
14      22 82 e2 08  End Marker (closes the empty prefix section)
18      22 82 e2 08  final End Marker
```

---

## 6. Prefix Section

After the EGG Header, a sequence of optional sub-headers may appear, terminated
by an End Marker. Valid sub-headers in this section:

- Split Info (`0x24F5A262`)
- Solid Info (`0x24E5A060`)
- Skip (`0xFFFF0000`) -- parsed like Split Info but ignored
- Global Encrypt (`0x08D144A8`) -- reserved, not implemented

### 6.1 Split Info

```
[Extra Field]             3 bytes (flags=0x00, UInt16 size=8)
Offset  Size  Type    Description
+0      4     UInt32  Previous volume ID (0 = this is the first volume)
+4      4     UInt32  Next volume ID (0 = this is the last volume)
```

See section 13 for full split archive details.

### 6.2 Solid Info

```
[Extra Field]             3 bytes (flags=0x00, UInt16 size=0)
```

The presence of this sub-header marks the archive as using solid compression.
No additional data beyond the extra field prefix. Solid-Compression is an
EGG-only feature, available only with two of the compression profiles and never
combined with spanning or a password; see §14.1 for the reference wording.

---

## 7. File Header

Signature: `0x0A8590E3`

Immediately after the signature (no extra field prefix):

```
Offset  Size  Type    Description
+0      4     UInt32  File ID (unique index, starting from 0)
+4      8     UInt64  Uncompressed file size
```

Total: 4 (signature) + 12 (data) = 16 bytes.

After the File Header, a sequence of sub-headers follows (section 8), terminated
by an End Marker. After the End Marker, one or more Block entries follow
(section 9).

Files larger than 4 GB are split across multiple blocks.

Directory entries have file size 0, the directory attribute set (section 8.3),
and zero blocks.

---

## 8. File Sub-Headers

These appear between the File Header and its End Marker.

### 8.1 Filename (`0x0A8591AC`)

```
[Extra Field]             3 bytes
  Flags byte:
    Bit 2: 0=not encrypted, 1=encrypted
    Bit 3: 0=UTF-8, 1=area code (locale-specific encoding)
    Bit 4: 0=absolute path, 1=relative path
  Size: UInt16
[Locale]                  0 or 2 bytes (present when bit 3 is set)
                          UInt16 locale code:
                            0 = system default
                            932 = Japanese (Shift-JIS)
                            949 = Korean (EUC-KR)
[Parent Path ID]          0 or 4 bytes (present when bit 4 is set)
                          UInt32 File ID of the entry containing the parent path
[Filename]                remaining bytes (no null terminator)
```

In practice, the flags byte is always `0x00` and the filename is UTF-8. Path separators may be `/` or `\`;
implementations should normalize to the platform convention.

### 8.2 Comment (`0x04C63672`)

```
[Extra Field]             3 bytes
  Flags byte:
    Bit 2: 0=not encrypted, 1=encrypted
    Bit 3: 0=UTF-8, 1=area code
  Size: UInt16
[Comment text]            UTF-8, no null terminator
```

Can appear as a file sub-header or at the archive level (between file entries).

### 8.3 Windows File Info (`0x2C86950B`)

```
[Extra Field]             3 bytes (flags=0x00, UInt16 size=9)
Offset  Size  Type    Description
+0      8     UInt64  Last modified time (Windows FILETIME: 100-nanosecond
                      intervals since 1601-01-01 00:00:00 UTC)
+8      1     BYTE    File attributes
```

Attribute bits:

| Bit | Mask | Meaning       |
|-----|------|---------------|
| 0   | 0x01 | Read-only     |
| 1   | 0x02 | Hidden        |
| 2   | 0x04 | System        |
| 3   | 0x08 | Symbolic link |
| 7   | 0x80 | Directory     |

These are EGG-specific attribute bits, not raw Windows `FILE_ATTRIBUTE_*`
values. Implementations must map them to platform equivalents.

### 8.4 POSIX File Info (`0x1EE922E5`)

Defined in the format but not used in practice. Included here for
completeness.

```
[Extra Field]             3 bytes (flags=0x00, UInt16 size=20)
Offset  Size  Type    Description
+0      4     UInt32  POSIX mode (file type + permissions, see stat(2))
+4      4     UInt32  User ID (UID)
+8      4     UInt32  Group ID (GID)
+12     8     UInt64  Last modified time (seconds since 1970-01-01 00:00:00 UTC)
```

The mode field uses standard POSIX bit layout:
- `0170000`: file type mask (socket, symlink, regular, block, directory, char, FIFO)
- `04000`: setuid, `02000`: setgid, `01000`: sticky
- `00700`/`00070`/`00007`: owner/group/other rwx permissions

### 8.5 Encrypt Info (`0x08D1470F`)

```
[Extra Field]             3 bytes (flags=0x00, UInt16 size)
Offset  Size  Type    Description
+0      1     BYTE    Encryption method
+1      var   BYTE[]  Method-specific data
```

The extra field's UInt16 size declares the total method-specific payload size
(including the method byte itself). However, for validation purposes, the
expected size is determined by the method. The data to read is always
`size - 1` bytes after the method byte. Expected total sizes by method:

| Method | Total size field | Data after method byte |
|--------|-----------------|------------------------|
| 0      | 17              | 16 bytes               |
| 1      | 21              | 20 bytes               |
| 2      | 29              | 28 bytes               |
| 5      | 21              | 20 bytes               |
| 6      | 29              | 28 bytes               |

Unknown encryption methods are a fatal error.

See section 12 for encryption details.

### 8.6 Dummy (`0x07463307`)

```
[Extra Field]             3 bytes (flags=0x00, UInt16 size)
[Padding data]            `size` bytes (skipped)
```

Used for alignment and padding in split archives. In a split archive, the
compressor may insert a Dummy sub-header to fill remaining space in a volume
before starting a new file in the next volume. Readers should skip the padding
data (read `size` bytes and discard) if they encounter this signature.
Dummy may appear between file entries in split archives but does not appear
within a file's sub-header group (between Filename/Comment/Encrypt Info).

---

## 9. Block Header

Signature: `0x02B50C13`

One file may consist of multiple blocks. After a file's sub-header End Marker,
block signatures are read in a loop. When a Comment (`0x04C63672`), File Header
(`0x0A8590E3`), or End Marker (`0x08E28222`) signature is encountered instead
of a Block signature, the reader seeks back 4 bytes to unread the signature and
stops reading blocks. Any other unexpected signature is a format error.

Immediately after the signature (no extra field prefix):

```
Offset  Size  Type    Description
+0      1     BYTE    Compression method (see section 11)
+1      1     BYTE    Compression hint (method-specific, currently unused)
+2      4     UInt32  Uncompressed size of this block
+6      4     UInt32  Compressed (packed) size of this block
+10     4     UInt32  CRC-32 of uncompressed data
```

Total header: 14 bytes.

Immediately after the header, an End Marker (`0x08E28222`, 4 bytes) MUST
appear, followed by `packSize` bytes of compressed data.

Complete block layout:

```
[Block signature]     4 bytes   0x02B50C13
[Block header]       14 bytes
[End marker]          4 bytes   0x08E28222
[Compressed data]     packSize bytes
```

The CRC-32 is computed over the decompressed (and decrypted) output of this
block, not the compressed data.

---

## 10. End Marker

The End Marker `0x08E28222` (4 bytes) terminates:

1. The prefix section (after EGG Header sub-headers)
2. Each file's sub-header sequence
3. Each block (between block header and compressed data)
4. The archive (final End Marker after all entries)

---

## 11. Compression Methods

| EGG method ID | Format coder | ALZip GUI choice(s) observed in samples | Sample suffix alias (not a GUI name) | Algorithm / framing |
|---:|---|---|---|---|
| 0 | Store | No Compression; Optimized Compression for its 41 already-compressed/media extensions (§11.0) | `_none`, `_optimized` | Raw copy |
| 1 | Deflate | Normal Compression; Priority on Compression Speed; Optimized Compression fallback (hint 5) | `_normal`, `_compspeed`, `_optimized` | Raw DEFLATE (RFC 1951; no zlib/gzip wrapper) |
| 2 | BZip2 | Optimized Compression for the 35 effective text/source extensions (§11.0); the `_normal`-suffixed `code_normal.egg` is one of those Optimized archives, not a Normal one | `_optimized` | Standard BZip2 stream |
| 3 | AZO | Optimized Compression for `.sys`/`.com` (whatever their content) | `_optimized` | LZ77 + range coder (Appendix A) |
| 4 | LZMA | Priority on Compression Ratio; Optimized Compression for its 8 office/drawing extensions | `_compratio`, `_optimized` | LZMA with 9-byte header (§11.1) |

### 11.0 Extension lists embedded in the ALZip 8 plugin, and the routing rule

`Formats/Egg.dll` contains four comma-separated UTF-16 extension lists and
registers each one with a codec object through `0x62318430` — AZO at
`0x6231503d`, LZMA at `0x6231505a`, Store at `0x62315075`, BZip2 at
`0x62315092`. `AZCTM.dll` carries the same four strings:

**ALZip 12.30 dropped `ace`**: the 8.0 list starts with `.ace, .alz, …` while
the 12.30 DLL starts at `.alz, .arc, …`, and the two routing references disagree
on exactly that one member (`r001.ace`: Store in 8.0, Deflate hint 5 in
`packed_egg/routes_optimized.egg`). The writer implements the 12.30 list — 40
entries — and `make test` replays the 12.30 rule against the list read from
`Formats/Egg.dll`.

| List | Count | Extensions |
|---|---:|---|
| AZO | 2 | `.sys .com` |
| Already-compressed / media (Store) | 40 | `.alz .arc .arj .bz .bz2 .cab .egg .ice .ear .war .gz .ha .jar .lha .lzh .pak .rar .tbz .tbz2 .tgz .7z .z .zip .zoo .docx .xlsx .pptx .jpg .jpeg .png .gif .ape .mp4 .mov .flac .flv .mp3 .ogg .wma .wmv` |
| Text / source (BZip2) | 45 (`.hs` twice → 44 distinct) | `.h .c .java .cpp .txt .pas .xml .html .htm .bat .1st .ans .asc .ascii .bbs .charset .dbt .err .faq .hs .klg .man .ada .as .au3 .b .bas .bb .bet .cp .cs .d .def .dev .dpr .dsp .fpp .hpp .hh .hs .inc .j .jav .xaml .x` |
| Office / drawing (LZMA) | 8 | `.ppt .xls .doc .ani .ico .cur .pcx .emf` |

For **Optimized Compression** these lists *are* the rule, and it is now measured
in full rather than sampled. A single `-m4` archive of 148 members — every list
entry plus 54 extensions outside the lists, a name without extension and names
with two suffixes, all holding the same 4,096 bytes of text
(`packed_egg/routes_optimized.egg`) — shows:

- the lookup is an **exact match on the last suffix**, case-insensitive: `.C`,
  `.TXT` and `.SYS` follow their lowercase entry, while `.hb`, `.htmz`,
  `.javax` and `.cppx` are not in the lists and fall through;
- the suffix is the part after the **last** dot (`dbl.tar.gz` → `.gz`,
  `dbl2.c.bak` → `.bak`), and a leading dot is not an extension (`.dotfile`
  behaves like `noext`);
- anything outside the four lists falls back to **Deflate hint 5** — never
  hint 6, never Store — which is what the 54 unlisted extensions (`.exe`,
  `.dll`, `.json`, `.md`, `.log`, `.pdf`, `.bin`, `.raw`, `.wav`, …) and the
  nameless-extension case all show;
- nine of the 44 distinct BZip2 entries never fire in this build: `.htm`, `.as`, `.b`,
  `.bb`, `.cp`, `.d`, `.j`, `.jav` and `.x` land in the Deflate hint 5
  fallback (`a.htm` → 1,004 bytes vs `a.html` → 725 bytes for the same
  content, same size, same archive). This is not a quirk of those extensions:
  it is the **matcher's own rule**, read in the binaries (see below), and the
  table implemented by the writer is the *effective* one — those nine entries
  are absent from it.

#### The matcher: `find` plus one comma, no retry

The lists above are not consulted by `Formats/Egg.dll` but by the **application**
(`ALZipCon.exe` / `ALZip.exe`), which receives them from the plugin at startup
and picks the codec per member; `AZCTM.dll` and `AZCTM64.dll` carry the same
four strings for the GUI side. The lookup, at `ALZipCon.exe 0x456954-0x456b65`,
walks the codec descriptors of the active profile in registration order
(`Formats/Egg.dll` registers AZO `0x6231503d`, LZMA `0x6231505a`, Store
`0x62315075`, BZip2 `0x62315092`) and, for each one, does exactly this:

```
pos = list.find(ext)                      ; one call, always from position 0
if (pos == npos) continue                 ; 0x456a87 / 0x456a95
if (pos + len(ext) == list.end() ||       ; 0x456ae6
    list[pos + len(ext)] == L',')         ; 0x456aef
        return this codec                 ; 0x456bf3
continue                                  ; 0x456af9 -> next descriptor (0x456b61)
```

So a match counts only when the extension appears in the list **immediately
followed by a comma** — and the search is never retried from a later position.
The first occurrence of the extension anywhere in the string decides, even when
it sits *inside* a longer entry. That is exactly the nine dead entries: `.htm`
first occurs inside `.html` (`list[pos+4]` is `l`, not a comma), `.as` inside
`.asc`, `.b` inside `.bat`, `.bb` inside `.bbs`, `.cp` inside `.cpp`, `.d`
inside `.dbt`, `.j` and `.jav` inside `.java`, `.x` inside `.xml` — and because
no retry happens, the real entry later in the same string is never reached.

Two consequences worth stating, both checked by `make test` (step 9 replays the
rule on the lists read out of `Formats/Egg.dll` and requires it to reproduce the
148 members of `routes_optimized.egg`, then requires the shadowed set of the
Store, LZMA and AZO lists to be empty and the BZip2 one to be exactly those
nine):

- the effective list is derivable from the DLL's own strings — no probe archive
  is needed to know it any more, and the derivation is asserted on every run;
- an entry is only shadowed by a **longer entry placed earlier in the same
  list** (`.asc` is alive because it precedes `.ascii`, `.hs` is alive at its
  first occurrence, `.z` is alive because `.zip`/`.zoo` come later).

**Normal Compression** does not follow these lists at all: the plugin gives it a
profile of its own whose only codecs are **Deflate (level 6) and Store** (below).
`ALZipCon -m1` confirms it — Deflate hint 6 for every member of a 149-extension
tree, `.c` included, and for every size from 65 bytes to 1 MiB — and so does the
GUI: `packed_egg_8.0/gui_normal_matrix.egg` (fifteen members, 65 B to 1 MiB,
`.c`, `.txt`, `.java`, `.xml`, `.pas`, `.cc`, `.htm`, `.1st`, `.bin`) is Deflate
hint 6 from end to end, and `packed_egg_8.0/gui_normal_code.egg` gives the 45,270-byte
`code.c` the same route. **There is therefore no extension routing in the Normal
profile at all**, and no extension to refuse.

The reference that had suggested otherwise, `packed_egg/code_normal.egg`, is an
**Optimized** archive: its `code.c` block is BZip2 hint 4 and is byte-identical to
`code_optimized.egg` (only the randomised `header_id` differs). It is kept and
compared as an Optimized reference (test step 9).

What the writer does, therefore: **Optimized** applies the four effective lists
and the Deflate hint 5 fallback, so no extension is refused and every entry of
`routes_optimized.egg` is reproduced byte for byte (test step 9). **Normal** is
Deflate hint 6 for every member — no table, no refusal — and `hello_normal`,
`nested_normal`, the GUI batch (`gui_normal_matrix.egg`, `gui_normal_code.egg`),
the solid pair and `solid_normal_code.egg` are reproduced byte for byte. The
Optimized route follows the name and not the bytes: `text_contenu.bin` (text
content, `.bin` name) stays Deflate 5 there, while Normal gives it Deflate 6.

The plugin also declares which codecs each GUI compression level may use, in
`Formats/Egg.dll` (`0x62314ff0`-`0x62315170`): `Nocomp` → Store, `Normal` →
Deflate (level 6) and Store, `CS_PRIORITY` → Deflate (level 5) and Store,
`Maximum` → LZMA, `OPTIMUM` → the four lists above. That is the mapping behind
the CLI numbers — `-m0` Nocomp, `-m1` Normal, `-m2` CS_PRIORITY, `-m3` Maximum,
`-m4` OPTIMUM — and it is what makes the per-extension routing an **OPTIMUM
feature only**: for the other levels the chosen method does not depend on the
name at all.

### 11.1 LZMA Framing

LZMA compressed data in EGG blocks starts with a 9-byte header:

```
Offset  Size  Description
+0      4     Reserved (read and discarded)
+4      5     LZMA properties (standard LZMA SDK format):
              Byte 0: lc/lp/pb packed as (pb * 45 + lp * 9 + lc)
              Bytes 1-4: dictionary size (UInt32, little-endian)
```

The remaining `packSize - 9` bytes are the LZMA compressed bitstream.

When encryption is active, the entire block data (including this 9-byte header)
is encrypted. The header must be decrypted before parsing the LZMA properties.

**Observed constants.** The 25 LZMA blocks of the corpus (eighteen archives:
thirteen single-member `_compratio` samples, `nested_compratio` with its eight
blocks, `empty_compratio` with none, `probe_doc_optimized`,
`probe_ico_optimized`, and the two solid `_compratio_solid` streams) agree on
both fields: the four reserved bytes are `04 41 05 00` in every block, regardless
of the input, and the property byte is `0x5D` (`lc=3, lp=0, pb=2`) with a
16 MiB dictionary (`0x01000000`). The reserved word is therefore a constant
marker, not a size or a CRC; a reader ignores it, as the 9-byte data layout
above already states.

Those are exactly the properties of the LZMA SDK's **default level 5**
(`nice_len` 32, `mc` 32, BT4) — and the SDK generation matters: LZMA SDK 4.65
reproduces all 25 reference bitstreams byte for byte with that single setting,
while LZMA SDK 19.00 configured with the same properties diverges within the
first hundreds of bytes. The writer (`src/egg_lzma.c`) therefore links the
vendored 4.65 sources in `src/lzma_sdk/` and calls `LzmaEncProps_Init` with
`level = 5`, no other override. Blocks are encoded as raw LZMA (no end marker,
no size field: the block header's `unpackSize` terminates decoding).

This is the one codec where the *SDK version* is part of the parity contract; a
newer encoder that is "better" is not equivalent. `make test` pins it by
rebuilding every `_compratio` archive and both solid LZMA trees from their
reference inputs through `alzgg create` and demanding byte equality, so a vendor
or default change fails the suite instead of silently producing different
archives.

### 11.2 Deflate Details

Uses raw DEFLATE without zlib or gzip wrapper. Equivalent to
`inflateInit2(stream, -MAX_WBITS)` in zlib.

### 11.3 Bzip2 Details

Standard bzip2 stream with standard stream header (`BZh[1-9]`), block magic,
and CRC. No modifications from standard bzip2.

ALZip 8 writes `BZh4` in every bzip2 block of the corpus: the digit is the
`blockSize100k` of the stream, and it equals the block header's own `hint` byte
(4 in all 477 reference blocks). Recompressing each block's uncompressed content
with bzip2 1.0.5 at `blockSize100k` 4 reproduces the 474 cleartext reference
streams byte for byte (`src/egg_bzip2.c` both ways; `make test` step 10), so no
other coder setting is involved. The `workFactor` is not observable on this
corpus — 1 and 250 emit identical bytes for these inputs — and this project
writes bzip2's documented default, 30.

### 11.4 Compression Hint Byte

The 1-byte compression hint is part of the block header. A decoder may not need
it to decode the stream, but it is **not** safe to discard it from a writer's
parity requirements: observed reference samples use it to distinguish coder
settings (for example, Deflate hints 5 and 6, BZip2 hint 4, and AZO/LZMA hint
values). For exact archive reproduction, preserve and test the byte against
reference output. The mapping is empirical and may be coder-specific.

### 11.5 Unknown Compression Methods

Values outside {0, 1, 2, 3, 4} are not defined. Implementations should treat
unknown compression methods as a fatal error and abort extraction of the
affected file.

---

## 12. Encryption

### 12.1 Encryption Methods

| Value | Name      | Key size | Salt size | Verify size | Footer size |
|-------|-----------|----------|-----------|-------------|-------------|
| 0     | ZipCrypto | n/a      | n/a       | 12          | n/a         |
| 1     | AES-128   | 16       | 8         | 2           | 10          |
| 2     | AES-256   | 32       | 16        | 2           | 10          |
| 3     | (reserved)|          |           |             |             |
| 4     | (reserved)|          |           |             |             |
| 5     | LEA-128   | 16       | 8         | 2           | 10          |
| 6     | LEA-256   | 32       | 16        | 2           | 10          |

Methods 3 and 4 are deprecated/reserved and must not be used.

### 12.2 Encrypt Info Data Layout

All encryption data is stored in the Encrypt Info sub-header, not in the
compressed data stream. The footer (HMAC tag) for AES/LEA is also stored in
the sub-header, not appended to the block data.

**ZipCrypto (method 0) -- 16 bytes:**

```
Offset  Size  Description
+0      12    Encryption verify data (12-byte random header)
+12     4     UInt32 CRC-32 (for password verification)
```

**AES-128 / LEA-128 (methods 1, 5) -- 20 bytes:**

```
Offset  Size  Description
+0      8     Salt
+8      2     Password verifier
+10     10    Authentication footer (HMAC-SHA1 tag)
```

**AES-256 / LEA-256 (methods 2, 6) -- 28 bytes:**

```
Offset  Size  Description
+0      16    Salt
+16     2     Password verifier
+18     10    Authentication footer (HMAC-SHA1 tag)
```

### 12.3 ZipCrypto (method 0)

Traditional PKZIP stream cipher, identical to ZIP 2.0 encryption.

**Key state**: Three 32-bit unsigned integers, initialized to:

```
key[0] = 0x12345678
key[1] = 0x23456789
key[2] = 0x34567890
```

**UpdateKeys(c):**

```
key[0] = CRC32_TABLE[(key[0] ^ c) & 0xFF] ^ (key[0] >> 8)
key[1] = (key[1] + (key[0] & 0xFF)) * 134775813 + 1
key[2] = CRC32_TABLE[(key[2] ^ (key[1] >> 24)) & 0xFF] ^ (key[2] >> 8)
```

The constant 134775813 is `0x08088405` in hexadecimal. `CRC32_TABLE` is the
standard CRC-32 lookup table with polynomial `0xEDB88320`.

**Initialization**: Process each byte of the password through UpdateKeys.

**DecryptByte():**

```
temp = key[2] | 2           (32-bit, no truncation)
return ((temp * (temp ^ 1)) >> 8) as BYTE
```

Note: `temp` is a full 32-bit value. The multiplication `temp * (temp ^ 1)` is
performed at 32-bit width (overflow wraps). The result is shifted right by 8
and truncated to a byte. This differs from the standard PKZIP specification
which truncates to 16-bit before the multiply.

**Decryption**: For each ciphertext byte:

```
plain = cipher ^ DecryptByte()
UpdateKeys(plain)
```

**Password verification**: Initialize keys with the password. Decrypt the
12-byte verify data. If `decrypted[11] != (storedCRC >> 24)`, the password is
wrong. If the password is correct, the keys are already in the correct state
for data decryption (the 12-byte header decryption both validates the password
and advances the key state). No re-initialization or re-decryption is needed.

For subsequent files using the same password, the keys are restored to their
post-password initialization state (before any verify data was processed), then
the new file's 12-byte verify data is decrypted to set up keys for that file.

### 12.4 AES-128 / AES-256 (methods 1, 2)

AES in CTR mode with HMAC-SHA1 authentication, compatible with the WinZip AE-2
encryption scheme.

**Mode mapping**: AES-128 uses fcrypt mode 1; AES-256 uses fcrypt mode 3.

**Key derivation (PBKDF2-HMAC-SHA1):**

- Password: UTF-8 encoded
- Salt: from Encrypt Info header (8 bytes for AES-128, 16 bytes for AES-256)
- Iterations: 1000
- Output length: `keySize * 2 + 2` bytes
  - Bytes `[0, keySize)`: AES encryption key
  - Bytes `[keySize, keySize*2)`: HMAC-SHA1 authentication key
  - Bytes `[keySize*2, keySize*2+2)`: Password verifier (2 bytes)

**Password verification**: Compare derived verifier bytes with the stored
password verifier. If they do not match, the password is wrong.

**Decryption**: AES in CTR mode (counter mode), using the WinZip AE-2 counter
convention:

- **Initial counter**: 1 (little-endian: `[0x01, 0x00, ..., 0x00]`)
- **Counter increment**: little-endian (increment byte 0, carry to byte 1, etc.)
- The nonce/counter state is maintained across the entire file's data (all
  blocks)

Note: This differs from the LEA CTR mode (section 12.5.6) which uses a counter
starting at 0 with big-endian increment.

**Authentication footer**: The 10-byte footer is the first 10 bytes of the
HMAC-SHA1 tag (truncated from the full 20-byte HMAC output) computed over the
ciphertext. Verification of this tag is optional but recommended.

### 12.5 LEA-128 / LEA-256 (methods 5, 6)

LEA (Lightweight Encryption Algorithm) is a 128-bit block cipher standardized
as KS X 3246 and TTAK.KO-12.0223 (South Korea). It uses only ARX operations
(Addition mod 2^32, Rotation, XOR) on 32-bit words -- no S-boxes.

The EGG format uses LEA-128 (method 5) and LEA-256 (method 6) in CTR mode.

#### 12.5.1 EGG Integration

**Mode mapping**: LEA-128 uses mode 1; LEA-256 uses mode 3.

**Evidence**: ALZip 8.0's `-tp` stops at 2, but ALZip 12.30's `ALZipCon.exe`
accepts `-tp3` and `-tp4` without documenting them, and writes method 5 and 6
members with exactly this framing. The six archives of
`packed_egg/` are that output (password `password`); `src/egg_crypt.c`
decrypts them and `alzgg create --crypt lea128|lea256` rebuilds all six byte for
byte once the per-member salt is re-injected (see §12.8 of this document for
the random-material rule, which is the same as AES).

**Key derivation (PBKDF2-HMAC-SHA1):**

Same as AES (section 12.4):
- Salt: from Encrypt Info header (8 bytes for LEA-128, 16 bytes for LEA-256)
- Iterations: 1000
- Output length: `keySize * 2 + 2` bytes
- Same key/auth-key/verifier split as AES

**Password verification**: Same as AES.

**Decryption**: LEA in CTR mode with a zero IV (16 bytes of `0x00`). See
12.5.6 for CTR mode details.

**Authentication footer**: Same 10-byte layout as AES. Verification is
optional.

#### 12.5.2 Notation and Byte Order

All operations are on 32-bit unsigned integers (words). Overflow wraps
(mod 2^32).

| Symbol      | Meaning                                            |
|-------------|----------------------------------------------------|
| `x + y`     | Addition mod 2^32                                  |
| `x - y`     | Subtraction mod 2^32                               |
| `x ^ y`     | Bitwise XOR                                        |
| `ROL_n(x)`  | Left-rotate x by n bits: `(x << n) | (x >> (32-n))` |
| `ROR_n(x)`  | Right-rotate x by n bits: `(x >> n) | (x << (32-n))`|

**Byte-to-word conversion** (little-endian):

A 16-byte plaintext/ciphertext block `B[0..15]` maps to 4 words:

```
X[0] = B[0] | (B[1] << 8) | (B[2] << 16) | (B[3] << 24)
X[1] = B[4] | (B[5] << 8) | (B[6] << 16) | (B[7] << 24)
X[2] = B[8] | (B[9] << 8) | (B[10] << 16) | (B[11] << 24)
X[3] = B[12] | (B[13] << 8) | (B[14] << 16) | (B[15] << 24)
```

Keys are converted the same way: a 16-byte key becomes 4 words, a 24-byte
key becomes 6 words, a 32-byte key becomes 8 words.

#### 12.5.3 Delta Constants

The key schedule uses 8 constant words derived from the hexadecimal expansion
of sqrt(766995), where 76/69/95 are ASCII codes for 'L','E','A':

```
delta[0] = 0xc3efe9db
delta[1] = 0x44626b02
delta[2] = 0x79e27c8a
delta[3] = 0x78df30ec
delta[4] = 0x715ea49e
delta[5] = 0xc785da0a
delta[6] = 0xe04ef22a
delta[7] = 0xe5c40957
```

#### 12.5.4 Key Schedule

The key schedule produces `Nr` round keys, each consisting of 6 words
(192 bits). `Nr` depends on key size:

| Key size | Nr (rounds) | Key words | Delta mod |
|----------|-------------|-----------|-----------|
| 128-bit  | 24          | 4 (T[0..3]) | `i mod 4` |
| 192-bit  | 28          | 6 (T[0..5]) | `i mod 6` |
| 256-bit  | 32          | 8 (T[0..7]) | `i mod 8` |

**LEA-128 key schedule** (K = 4 words from key bytes):

```
T = K  (copy 4 words)
for i = 0 to 23:
    T[0] = ROL_1(T[0] + ROL_i(delta[i mod 4]))
    T[1] = ROL_3(T[1] + ROL_(i+1)(delta[i mod 4]))
    T[2] = ROL_6(T[2] + ROL_(i+2)(delta[i mod 4]))
    T[3] = ROL_11(T[3] + ROL_(i+3)(delta[i mod 4]))
    RK[i] = (T[0], T[1], T[2], T[1], T[3], T[1])
```

Note: `ROL_i(delta[j])` means left-rotate `delta[j]` by `i` bits (mod 32).

**LEA-192 key schedule** (K = 6 words from key bytes):

```
T = K  (copy 6 words)
for i = 0 to 27:
    T[0] = ROL_1(T[0] + ROL_i(delta[i mod 6]))
    T[1] = ROL_3(T[1] + ROL_(i+1)(delta[i mod 6]))
    T[2] = ROL_6(T[2] + ROL_(i+2)(delta[i mod 6]))
    T[3] = ROL_11(T[3] + ROL_(i+3)(delta[i mod 6]))
    T[4] = ROL_13(T[4] + ROL_(i+4)(delta[i mod 6]))
    T[5] = ROL_17(T[5] + ROL_(i+5)(delta[i mod 6]))
    RK[i] = (T[0], T[1], T[2], T[3], T[4], T[5])
```

**LEA-256 key schedule** (K = 8 words from key bytes):

```
T = K  (copy 8 words)
for i = 0 to 31:
    T[6i mod 8]     = ROL_1(T[6i mod 8]     + ROL_i(delta[i mod 8]))
    T[(6i+1) mod 8] = ROL_3(T[(6i+1) mod 8] + ROL_(i+1)(delta[i mod 8]))
    T[(6i+2) mod 8] = ROL_6(T[(6i+2) mod 8] + ROL_(i+2)(delta[i mod 8]))
    T[(6i+3) mod 8] = ROL_11(T[(6i+3) mod 8] + ROL_(i+3)(delta[i mod 8]))
    T[(6i+4) mod 8] = ROL_13(T[(6i+4) mod 8] + ROL_(i+4)(delta[i mod 8]))
    T[(6i+5) mod 8] = ROL_17(T[(6i+5) mod 8] + ROL_(i+5)(delta[i mod 8]))
    RK[i] = (T[6i mod 8], T[(6i+1) mod 8], T[(6i+2) mod 8],
             T[(6i+3) mod 8], T[(6i+4) mod 8], T[(6i+5) mod 8])
```

#### 12.5.5 Encryption and Decryption Round Functions

**Encryption** (Nr rounds):

```
X = plaintext as 4 words
for i = 0 to Nr-1:
    tmp[0] = ROL_9((X[0] ^ RK[i][0]) + (X[1] ^ RK[i][1]))
    tmp[1] = ROR_5((X[1] ^ RK[i][2]) + (X[2] ^ RK[i][3]))
    tmp[2] = ROR_3((X[2] ^ RK[i][4]) + (X[3] ^ RK[i][5]))
    tmp[3] = X[0]
    X = tmp
ciphertext = X as 16 bytes
```

**Decryption** (Nr rounds, round keys applied in reverse):

```
X = ciphertext as 4 words
for i = Nr-1 downto 0:
    tmp[0] = X[3]
    tmp[1] = (ROR_9(X[0]) - (tmp[0] ^ RK[i][0])) ^ RK[i][1]
    tmp[2] = (ROL_5(X[1]) - (tmp[1] ^ RK[i][2])) ^ RK[i][3]
    tmp[3] = (ROL_3(X[2]) - (tmp[2] ^ RK[i][4])) ^ RK[i][5]
    X = tmp
plaintext = X as 16 bytes
```

Note: In CTR mode, only the encrypt function is used (CTR encrypts the
counter block, then XORs the result with the data). Decryption of data =
encryption of counter block, then XOR.

#### 12.5.6 CTR Mode

The EGG format uses LEA-CTR with a 16-byte (128-bit) counter block:

- **Initial counter**: 16 bytes of `0x00`
- **Counter increment**: The counter is treated as a 128-bit big-endian
  integer. After each block encryption, it is incremented by 1 starting from
  the least significant byte (byte index 15):

```
def ctr128_inc(counter):
    for i = 15 downto 0:
        counter[i] += 1
        if counter[i] != 0:   // no overflow
            break
```

- **Encryption/Decryption**: For each 16-byte chunk of data, encrypt the
  current counter block with LEA-ECB to produce a keystream block, then XOR
  it with the data. Increment the counter. For the final partial block
  (< 16 bytes), only XOR with the first N bytes of the keystream.

```
counter = [0x00] * 16
for each 16-byte chunk of plaintext/ciphertext:
    keystream = LEA_ECB_Encrypt(key, counter)
    output = chunk ^ keystream
    ctr128_inc(counter)
```

#### 12.5.7 Test Vectors (from KS X 3246 Appendix A)

**LEA-128 encryption**:

```
Key (16 bytes):  0f 1e 2d 3c 4b 5a 69 78 87 96 a5 b4 c3 d2 e1 f0
Plaintext:       10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f
Ciphertext:      9f c8 4e 35 28 c6 c6 18 55 32 c7 a7 04 64 8b fd
```

Intermediate state (X_i as 4 words, round-by-round):

| Round | X[0]     | X[1]     | X[2]     | X[3]     |
|-------|----------|----------|----------|----------|
| X_0   | 13121110 | 17161514 | 1b1a1918 | 1f1e1d1c |
| X_1   | 0f079051 | 693d668d | e5edcfd4 | 13121110 |
| X_2   | 3fc44a2d | f767ea2a | a0b67cf0 | 0f079051 |
| X_3   | 99e912cd | 906fd05d | 4d293e55 | 3fc44a2d |
| ...   | ...      | ...      | ...      | ...      |
| X_24  | 354ec89f | 18c6c628 | a7c73255 | fd8b6404 |
| C     | 9f c8 4e 35 28 c6 c6 18 55 32 c7 a7 04 64 8b fd |

Round keys (encryption, first 4 shown):

```
RK0enc:  003a0fd4 02497010 194f7db1 02497010 090d0883 02497010
RK1enc:  11fdcbb1 9e98e0c8 18b570cf 9e98e0c8 9dc53a79 9e98e0c8
RK2enc:  f30f7bb5 6d6628db b74e5dad 6d6628db a65e46d0 6d6628db
RK3enc:  74120631 dac9bd17 cd1ecf34 dac9bd17 540f76f1 dac9bd17
```

**LEA-192 encryption**:

```
Key (24 bytes):  0f 1e 2d 3c 4b 5a 69 78 87 96 a5 b4 c3 d2 e1 f0
                 f0 e1 d2 c3 b4 a5 96 87
Plaintext:       20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f
Ciphertext:      6f b9 5e 32 5a ad 1b 87 8c dc f5 35 76 74 c6 f2
```

**LEA-256 encryption**:

```
Key (32 bytes):  0f 1e 2d 3c 4b 5a 69 78 87 96 a5 b4 c3 d2 e1 f0
                 f0 e1 d2 c3 b4 a5 96 87 78 69 5a 4b 3c 2d 1e 0f
Plaintext:       30 31 32 33 34 35 36 37 38 39 3a 3b 3c 3d 3e 3f
Ciphertext:      d6 51 af f6 47 b1 89 c1 3a 89 00 ca 27 f9 e1 97
```

### 12.6 Decryption Pipeline

Encryption is applied at the stream level. The decoder reads compressed data
from the input stream, decrypts it in-place, then feeds the result to the
decompressor. CRC-32 is computed on the decompressed output.

**Buffer-at-a-time flow**: Each decoder allocates two 1 MB buffers (one for
input, one for output). The decode loop for each block is:

```
1. Read a chunk from the input stream into the input buffer
2. If a decryptor is active, decrypt the input buffer in-place:
     decryptor->Decrypt(inBuffer, bytesRead)
3. Feed the decrypted data to the decompressor (inflate, LZMA decode, etc.)
4. CRC32Update on the decompressed output bytes
5. Write decompressed output to the output stream
6. Repeat until the block's packSize bytes are consumed
7. CRC32Finish and compare against the block's stored CRC
```

**Per-block decoder, shared decryptor**: Each block creates a fresh decoder
instance (new inflate state, new LZMA state, etc.), but the decryptor is
shared across all blocks of a single file. The decryptor maintains its
internal counter/key state continuously across block boundaries.

**LZMA special case**: The LZMA decoder reads and decrypts the 9-byte header
(section 11.1) separately before entering the main decode loop. The header
bytes are read via `inStream->Read(header, 9, &read)`, then decrypted in-place
if a decryptor is active. After parsing the LZMA properties from the decrypted
header, the remaining `packSize - 9` bytes are processed through the standard
buffer loop.

**Store special case**: For Store (method 0), the "decompression" is a direct
copy. The CRC-32 is computed on the data after decryption (which IS the output
data). There is no separate decompression step.

**Decryptor lifecycle**:
- ZipCrypto: keys are restored to post-password state before each file, then
  the 12-byte verify data is decrypted (which sets up keys for that file's data)
- AES/LEA: a new decryptor is created for each encrypted file (each file has
  its own salt and password verifier in its Encrypt Info sub-header)

### 12.7 Verification status in this project

The three password samples of the corpus carry the **same** passphrase
(`password`), so the samples differ only in the cipher layer:
`hello_optimized_password_zip2.egg`, `..._aes128.egg`, `..._aes256.egg`. All of
§12.1-§12.4 is now confirmed against them, not just transcribed:

| Layer | What the samples confirm |
|---|---|
| ZipCrypto | The 12-byte verify data decrypts so that byte 11 equals the high byte of the block's CRC-32, and the keys left by that step decrypt the 95 ciphertext bytes into a valid bzip2 stream that inflates to `corpus/hello.txt` (65 bytes, CRC-32 `50575a24` = the block header's CRC) |
| AES-128 | PBKDF2-HMAC-SHA1(`password`, 8-byte salt, 1000 iterations, 34 bytes) reproduces the stored 2-byte verifier **and** HMAC-SHA1 of the ciphertext keyed with bytes 16..31 reproduces the stored 10-byte footer |
| AES-256 | Same, with the 16-byte salt, 32-byte key and 66 derived bytes |
| CTR mode | The initial counter is the little-endian value 1 with little-endian increment (§12.4): that is the convention which turns the ciphertext into `BZh4...`; a big-endian increment does not |

Two findings worth recording rather than guessing at:

- The §12.3 remark about the 32-bit multiply is **unobservable**. The returned
  byte is bits 8..15 of `temp * (temp ^ 1)`, and those bits depend only on
  `temp mod 2^16`; masking `temp` to 16 bits before the multiply (the classic
  PKZIP formulation) therefore yields exactly the same byte for every state. The
  two formulations cannot be told apart by any fixture, so no sample is needed to
  settle it - but an implementation must still mask the *output*, not the input,
  when it takes `>> 8`.
- The ZipCrypto check byte is fed by the CRC of the member's **uncompressed**
  content, and for a multi-block member by the CRC of the member as a whole, not
  of its first block. That is what `packed_egg_8.0/huge_enc_zip.egg` shows: 5 GiB of Store
  data under ZipCrypto, two blocks of 3 GiB and 2 GiB, whose verifier's two CRC
  bytes match the full member CRC. That CRC is only known after decompression,
  so this port defers the ZipCrypto check byte for such a member until then
  (§12.6, `--raw` excepted). The 5 GiB reference is checked in and verified by
  `make heavy` (see §12.8).

### 12.8 Writer

Encryption is written in both directions of the port. The Encrypt Info
sub-header (`0x08D1470F`) is laid out exactly as a reader expects it, with the
method byte first:

| Method | Sub-header size | Payload |
|---|---:|---|
| ZipCrypto | 17 | method(1) + encrypted verifier(12) + CRC-32 UInt32 LE (member, uncompressed) |
| AES-128 | 21 | method(1) + salt(8) + verifier(2) + HMAC-SHA1 ciphertext tag(10) |
| AES-256 | 29 | method(1) + salt(16) + verifier(2) + HMAC-SHA1 ciphertext tag(10) |

The only non-derivable input is the random material ALZip draws per member:
ten plaintext bytes for ZipCrypto (the writer appends `crc >> 16` and `crc >>
24`, so the 12-byte plaintext verifier ends with the CRC high half, low byte
first), or the AES salt. `alzgg create --crypt-info HEX,…` injects it, one value
per member; without the option the writer reads `/dev/urandom`.

**Twenty-four** ALZip references are rebuilt byte for byte, and `make test`
compares every one of them:

- the first nine: the three `packed_egg` samples (Optimized with ZipCrypto,
  AES-128 and AES-256), `packed_egg_8.0/enc_store_basic.egg` (Store),
  `enc_deflate_aes128/256.egg` (Deflate) and
  `enc_twofiles_basic/aes128/aes256.egg` (two members, so one salt and one
  verifier per member);
- the twelve of the lot-H matrix, `enc_egg_m0..m3_tp0..2.egg`: the four EGG
  profiles (None, Normal, Compressing Speed, Compress Ratio) crossed with the
  three methods. On 65 bytes the three deflate levels emit the same bytes, but
  Store, Deflate and LZMA are all in the matrix, so every profile's codec is
  exercised under every cipher;
- `enc_egg_two_m0_tp0.egg`, two Store members with one verifier each;
- `enc_egg_empty_tp0.egg` and `enc_egg_dir_tp0.egg`, where ALZip writes **no**
  Encrypt Info at all: a member without data has no verifier, and no place to
  put one, exactly as if `-p` had not been passed. The writer follows that
  measured behaviour instead of refusing the input.

A fifth group is a span: `packed_egg_8.0/span_15vol_crypt.vol1..16.egg`,
1.5 MiB of Store data under ZipCrypto, cut into 16 volumes of 102,400 bytes
(the last one 37,497 bytes). It shows that ALZip encrypts the member first and
then splits the ciphertext (the verifier lives in Encrypt Info, never at the
head of the data), and it pins the writer's behaviour for chains longer than
three volumes; `make test` rebuilds the sixteen volume files byte for byte,
then extracts the chain from vol16.

`make test` also builds one archive per cipher with random material and
re-extracts it (right password succeeds, missing and wrong passwords are refused
with nothing written).

The writer refuses only what no reference can validate: `-s` with a password
(ALZip's own "Solid-Compressed file cannot be encrypted.", §14.1). Encryption
combined with `-v` is **not** refused: the 16-volume reference above shows the
composition. Neither are empty members or directories, which are written
without Encrypt Info, nor LEA-128/256, whose six ALZip 12.30 references
(§12.5.1) are rebuilt byte for byte.

**Multi-block members** are written with one continuous cipher context and a
verifier carrying the CRC-32 of the whole member, exactly as
`packed_egg_8.0/huge_enc_zip.egg` (5 GiB of Store data under ZipCrypto,
3 GiB + 2 GiB, the same two block CRCs as the clear `huge_store_5g.egg`) does.
That archive is too large for `make test`, so it has its own check,
`make heavy` → `tests/heavy_multiblock.sh`, which asserts all three directions:

- the reader re-extracts the 5 GiB (the deferred ZipCrypto check of §12.7
  accepting the member, so the whole-member CRC rule is exercised, not assumed);
- `alzgg create` rebuilds the archive **byte for byte** (5 368 709 263 bytes) from
  the same member, the per-member material re-read from the reference and the
  same FILETIME;
- a wrong password is refused.

The script skips with a message when `corpus/huge` or the reference is missing
(`fixtures/build-fixtures.py --only h` regenerates both; `--skip-huge` omits the
5 GiB members), and it needs roughly 15 GiB of temporary space.

### 12.9 Password encoding

ALZip converts the password to the **system ANSI code page** before deriving any
key; a character the code page cannot represent becomes `?` (0x3F). Measured on
the local oracle (ALZipCon 8.0.0.18 under Wine, page 1252):

| Input (UTF-8) | Code point | Byte fed to the cipher |
|---|---|---:|
| `é` | U+00E9 | `E9` |
| `ß` | U+00DF | `DF` |
| `€` | U+20AC | `80` |
| `한` | U+D55C | `3F` |

So the encoding is neither UTF-8 (`E2 82 AC` for `€`) nor Latin-1 (which has no
`€` at all), and it must cover the 27 positions CP1252 fills above U+00FF, not
just Latin-1. Three lot-H references pin the rule: `enc_egg_napw_euro.egg`
(`€` → `80`), `enc_egg_napw_han.egg` (`한` → `?`) and
`enc_egg_napw_acute_aes256.egg` (`é` → `E9`, through PBKDF2 instead of
ZipCrypto). All three are rebuilt byte for byte. A password that is not valid
UTF-8 has no measured answer (which byte would `F6` alone be?), so the writer
refuses it rather than guessing.

The same conversion applies to ALZ (FORMAT-ALZ.md), where `enc_alz_napw_euro.alz`
and `enc_alz_napw_euro_records.alz` are the references.

---

## 13. Split Archives

Split (multi-volume) archives use the Split Info sub-header in the prefix
section. Each volume is a standalone EGG file with its own EGG Header. The
reference GUI/CLI permits spanning EGG archives, except when Solid Compression
is enabled. The supplied reference volumes are 102,400 bytes; this is an
observed setting, not a format-mandated volume size.

The volume links, continuation behavior, and record-boundary rules below define
the logical archive stream. In the observed ALZip archives, compressed block
data can continue across a volume boundary. If the next file header cannot fit
in the remaining bytes, ALZip uses a DUMMY extra-field; one observed DUMMY
record has signature `07 33 46 07`, flags=0, a UInt16 size of 2 and two payload
bytes, occupying 9 bytes total. This is an observed padding case; the DUMMY
record's declared size determines how much data a decoder skips.

The supplied split corpus includes a two-volume `records_optimized` archive
and three-volume `splitmany_normal` and `splitmany_optimized` archives, kept in
`corpus_probe/`. Each `splitmany` archive contains 420 file records. These
examples exercise both continued compressed data and DUMMY padding; they do not
constrain all legal volume sizes or all possible boundary placements. Across the
whole corpus exactly **one** DUMMY record is present, in
`splitmany_normal.vol2.egg` (signature `07 33 46 07`, flags 0, UInt16 size 2), so
the three-volume chain is what `make test` uses to keep that skip path alive.

### 13.1 Volume Linking

- First volume: `previous = 0`, `next = <Header ID of next volume>`
- Middle volumes: `previous = <ID>`, `next = <ID>`
- Last volume: `next = 0`

The Header ID field in the EGG Header serves as the volume ID. To locate the
next volume, scan files in the same directory for EGG files whose Header ID
matches the expected next ID.

### 13.2 Continuation Volumes

When opening a continuation volume (not the first), the reader expects an End
Marker (`0x08E28222`) as the first signature after the Split Info. This End
Marker is mandatory. After it, the data stream continues from where the
previous volume left off.

To read continuation volumes, skip past the EGG Header + Split Info + End
Marker, then treat the remaining data as a continuation of the previous
volume's stream. This makes the multi-volume archive appear as a single
contiguous stream.

### 13.3 Split Rules

- File headers and sub-headers must not be split across volumes. Only compressed
  block data may span volume boundaries.
- If a file header would not fit in the remaining space, a Dummy sub-header is
  inserted as padding, and the file header begins in the next volume.
- Split archives support up to 2^32 - 1 volumes.
- The Skip signature (`0xFFFF0000`) may be used in place of Split Info to
  indicate a volume that should be ignored.

The reference volumes pin the writer's layout down to the byte. Measured on
`corpus_probe/splitmany_normal.vol1-3.egg` (420 members, `-v100KB`) and
`packed_egg/records_optimized.vol1-2.egg`:

- Each volume file is exactly the requested size (102,400 bytes for `-v100KB`),
  the last one shorter, header included. A volume header is 33 bytes — EGG
  header (14) + Split Info (7 + 8 payload) + End Marker (4) — and a continuation
  volume carries the same 33 bytes before the continued stream.
- The unit that may not cross a boundary is **each record**, not the whole
  member header: `splitmany_normal.vol2.egg` ends between the FILENAME and the
  WININFO sub-header of member 403. Compressed block data, by contrast, is cut
  wherever the volume fills, with no alignment — vol1 of the same archive ends
  inside a deflate stream.
- The padding DUMMY fills the remaining space exactly: signature, flags 0, UInt16
  size = remaining - 7, then that many zero bytes (the corpus's only DUMMY is
  9 bytes, leaving 2 payload bytes at the end of vol2). A remainder of 1-6 bytes
  — too small for the smallest DUMMY — is not observed anywhere; nothing is
  invented for it.
- Naming: ALZip renames the output to `<base>.vol1.egg`, `<base>.vol2.egg`, …, a
  single-volume result included (`egg_span1m_50m.vol1.egg`, lot C), and the
  Header IDs come from a global activity counter — +3 then +4 between the
  `splitmany_normal` volumes, +3 between the `records_optimized` ones — so they
  are not derivable and must be supplied per volume.

Encrypted spans are measured too: `packed_egg_8.0/span_15vol_crypt`
is a ZipCrypto member of 1.5 MiB cut into **16** volumes (15 of 102,400 bytes,
the last 37,497) by
`Alz -a -m0 -tp0 -psecret -v100KB` (§12.8). The ciphertext is split like any
other block data and the verifier stays in Encrypt Info, so decryption starts
again from the member's header and not from the volume boundary; volume 16 alone
re-extracts the member. That also settles the earlier note that ALZip refused
encrypted volumes: this build produces them, and it is solid spans that it
refuses (§14.1).

Still unobserved: chain lengths other than 2, 3 and 16 volumes, volume sizes
other than 100 KB, solid spans (ALZip refuses them with a message), a boundary
between the last member and the archive End Marker, and the 1-6-byte remainder
above.

---

## 14. Solid Archives

When the Solid Info sub-header is present in the prefix section, the archive
uses solid compression: the member contents form one continuous compressed
stream (the stream model is described in §14.3). Solid-Compression is an
application feature and an option constraint, not a restriction in the EGG
record grammar - a third-party writer can emit a solid, spanned or encrypted
EGG archive, and a reader must still parse it.

### 14.1 Availability and option constraints (reference)

Solid-Compression is **EGG-only**: ALZ has no solid mode at all
([FORMAT-ALZ.md](FORMAT-ALZ.md)). ALZip 8.0.0.18 states the remaining
restrictions in its own resource strings (`research/Program Files (x86)/ALZip/`):

| Constraint | Reference text | Source |
|---|---|---|
| EGG only (GUI) | "Solid-Compression is available only in EGG archive." / "Only EGG format can use Solid Compression." | `en-US.dll` |
| EGG only (CLI) | `-s` is "Compress with Solid-Compression method" ... "In addition, it can only be used in EGG file archive."; a non-EGG format is refused with "ERROR : The format doesn't support Solid-Compression" | `con_en-US.dll` |
| Only two profiles | "ERROR : Solid-Compression supports only basic-compression(m1) and compression-ratio-prioritized (m3) methods." | `con_en-US.dll` |
| Same rule, GUI wording | 'Only "Normal" and "Priority on Compress Ratio" can be set when Solid-Compressing. Disable Solid-Compression?' | `en-US.dll` |
| No spanning | "ERROR : Solid-Compression doesn't support spanning archives" / "Solid-Compressed archive cannot be spanned." | `con_en-US.dll`, `en-US.dll` |
| No password | "ERROR : Solid-Compressed file cannot be encrypted." / "Cannot set password in Solid-Compressed archive ." | `con_en-US.dll`, `en-US.dll` |
| Reminder shown when enabling it | "ATTN: Solid-Compression doesn't support spanning archive or encryption."; GUI prompt: 'Only "Normal" or "Priority on Compress Ratio" type can be used, and setting password or spanning is unavailable. Do you want to use Solid-Compression?' | both libraries |

The profile numbers used by those messages are the CLI `-m` numbering
(`con_en-US.dll`: `EGG 1~4 (4 : Optimized Compression)`, `0` = no compression):
`m1` = basic / **Normal Compression**, `m2` = Priority on Compressing Speed,
`m3` = **Priority on Compress Ratio**, `m4` = Optimized Compression. The m1/m3
identification follows from the error string above plus the CLI help; with `-s`,
only `m1` and `m3` are accepted, so no solid archive can use No Compression,
Speed-prioritized or Optimized Compression.

The GUI's **Method** list, in the order it shows and with its exact wording, is:

| GUI label | `-m` | `alzgg create -p` |
|---|---:|---|
| No compression | 0 | `none` |
| Normal compression | 1 | `normal` |
| Priority on compressing speed | 2 | `compspeed` |
| Priority on compress ratio | 3 | `compratio` |
| Optimized compression | 4 | `optimized` |

**ALZip 12.30 update (the writer reference).** The table above is the 8.0
numbering. 12.30 keeps five profiles but **swaps `m1` and `m2` and raises the
levels**: `m1` = Priority on compressing speed (deflate **2**), `m2` = Normal
(deflate **4**), `m3` = Priority on compress ratio (LZMA **8**), `m4` =
Optimized. The hints are the zlib level (deflate) or the LZMA level byte; the
payload of `m3` is byte-identical to 8.0's LZMA 6, only the hint differs. A
solid archive therefore carries deflate 2 under `m1` and LZMA 8 under `m3` in
12.30, where 8.0 carried deflate 6 and LZMA 6; the archives of both scales are
readable. See FIXTURES lot K for the byte-exact references.

Capitals differ from the CLI help on purpose: the samples of FIXTURES lot I were
produced from this dialog, and the GUI writes `compression` / `speed` / `ratio`
in lower case. The ALZ dialog uses its own list and order (`Normal`, `Fast`,
`Faster`, `No compression`, FORMAT-ALZ §“Compression methods and sampled
profiles”).

**Writer constraints (normative).** The record grammar permits a solid, spanned,
encrypted archive (§14 intro) - that is a statement about what a reader must
accept, not about what ALZip will produce. The reference application forbids the
combinations, and this port follows the reference, so a solid archive written by
this project MUST satisfy all four constraints below, each of them enforced in
code rather than assumed:

| # | Constraint | Consequence for a writer |
|---|---|---|
| 1 | **EGG only** | `.alz` has no solid mode; the tool refuses `-s` with `ERROR : The format doesn't support Solid-Compression` |
| 2 | **Normal Compression or Priority on Compression Ratio only** | never No Compression, Speed-prioritized or Optimized Compression |
| 3 | **No spanning** | never combine `-s` with `-v`; a solid archive is single-volume |
| 4 | **No encryption** | never combine `-s` with `-tp`/`-p`; a solid archive carries no Encrypt Info |

No reference asset can be requested for the forbidden combinations - there is no
solid spanned archive, no solid encrypted archive, and no solid `-m2`/`-m4`
archive for a writer to be validated against, because ALZip cannot create one.

**Codecs that solid mode can carry.** Constraint 2 leaves exactly two. In
ALZip 8.0, `m1` is Deflate hint 6 for every member (Normal routes nothing,
§11.0) and `m3` is LZMA hint 6; in **12.30** the same two routes are Deflate
hint 2 (Speed) and LZMA hint 8 (Ratio). A solid stream therefore never carries BZip2 — the codec only exists in
Optimized Compression, which constraint 2 forbids — and `solid_normal_code.egg`
shows the expected shape for the one member that used to look ambiguous: a
`.c` inside a solid `m1` archive is part of the single Deflate hint 6 stream,
with no per-member block. **AZO (method 3) likewise cannot appear**: it is
emitted only by Optimized Compression (`-m4`,
`packed_egg/probe_sys_optimized.egg`). A reader must still meet any method in
a third-party archive and refuse the unimplemented ones explicitly rather than
guess.

The four older solid samples carry a single block whose stream is Deflate or
LZMA; `solid_normal_code.egg` adds the `.c` case and is also a single block
(45,335-byte stream, CRC-32 `aa9ef832`), reproduced byte for byte.

The 8.0 corpus matches: the four solid samples
(`packed_egg/nested_normal_solid.egg`, `packed_egg/nested_compratio_solid.egg`,
`packed_egg_8.0/unicode_normal_solid.egg`,
`packed_egg_8.0/unicode_compratio_solid.egg`) cover exactly the Normal (deflate,
hint 6) and Priority-on-Ratio (LZMA, hint 6) routes, none is spanned and none is
encrypted. The 12.30 references `packed_egg/egg_s_m1_two.egg` and
`egg_s_m3_two.egg` cover deflate 2 and LZMA 8 on a two-member tree. They also show the single-stream layout: each `nested_*_solid.egg`
carries **one** 822,784-byte block covering its 8 members (stream CRC-32
`03ecd79a`), and each `unicode_*_solid.egg` one 78-byte block covering its 3
members (stream CRC-32 `70ce4dc7`) - one block for the whole archive instead of
one block per member, because the blocks describe the concatenated stream.

### 14.2 Extraction Requirements

- Files MUST be decompressed sequentially in archive order.
- You cannot extract a single file from a solid archive without decompressing
  all preceding files first (because the decompressor may reference data from
  earlier files in the combined stream).
- Each block still has its own Block Header with packSize, unpackSize, and CRC.
  The CRC is per-block, not per-file or per-archive.

### 14.3 Decompression Semantics

In a solid archive, the compressed data for all files is laid out as a single
contiguous stream. The decompressor state (LZ77 dictionary, LZMA dictionary,
Deflate sliding window, AZO probability models) is maintained continuously
across block and file boundaries -- it is NOT reset between files.

Each block still has its own Block Header specifying packSize and unpackSize.
The extraction loop processes files in index order, reading blocks
sequentially. A new decoder instance is NOT created per block in solid mode;
instead, the same decoder continues across all blocks.

Bzip2 is the exception: bzip2 blocks are self-contained (the dictionary is
reset at each bzip2 block boundary), so solid mode has no effect on bzip2
decompression.

**Observed block placement.** In the four supplied solid samples the whole
stream is carried by a single block, and that block belongs to the *last* member
record - the other members have no blocks at all. Its `unpackSize` is the total
size of the concatenated members (`822784` for the eight nested members, `78` for
the three Unicode members) and its CRC-32 is the CRC of that whole stream, not of
one member. `src/egg.c` therefore concatenates the block payloads of all members
in archive order, decodes them as one stream(deflate, LZMA, or a plain copy for store), then splits the result on the members' `unpackSize` values in archive
order and checks each block's CRC-32 against its own slice of the decoded stream.
The decoder is the one for the stream's method (Deflate hint 6 under `m1`, LZMA
hint 6 under `m3`; a plain copy for store).
Multi-block solid streams are not covered by any sample yet: the same code path
handles them (payloads concatenate in archive order), but that order is inferred,
not observed. This is the **only** solid fixture still worth requesting: because
of the §14.1 constraints it has to be a single-volume, unencrypted, `-m1` (or
`-m3`) archive whose stream is large enough to be split into several blocks - see
[FIXTURES.md](FIXTURES.md) Lot C, item 5.

---

## 15. CRC-32

Standard CRC-32 with polynomial `0xEDB88320` (reflected representation of
`0x04C11DB7`).

**Algorithm:**

```
Initialize: crc = 0xFFFFFFFF
For each byte b:
    crc = CRC32_TABLE[(crc ^ b) & 0xFF] ^ (crc >> 8)
Finalize: crc = crc ^ 0xFFFFFFFF  (bitwise NOT)
```

The CRC-32 lookup table is generated from the polynomial:

```
for i in 0..256:
    c = i
    for j in 0..8:
        if c & 1:
            c = 0xEDB88320 ^ (c >> 1)
        else:
            c = c >> 1
    CRC32_TABLE[i] = c
```

CRC-32 is computed over decompressed (and decrypted) data and verified against
the `crc` field in each Block Header.

---

## 16. Parsing Notes

### 16.1 Error Handling

When an unknown signature is encountered during parsing, it should be treated
as a format error. The archive open operation should return a "not recognized"
status rather than a hard failure, allowing the caller to try other format
handlers.

### 16.2 Empty Files and Directories

Files with size 0 are skipped during extraction (no decompression occurs).
Directories have zero blocks; the block reading loop simply reads zero
iterations.

### 16.3 Block Reading Termination

After a file's sub-header End Marker, signatures are read in a loop. The loop
terminates when:
- A Block signature (`0x02B50C13`) is read: parse the block and continue.
- A Comment, File Header, or End Marker signature is read: seek back 4 bytes
  (unread the signature) and stop. The parent parser will re-read it.
- Any other signature: format error.

### 16.4 Sub-Header Ordering

Within a file's sub-header section, the following signatures are recognized:
Filename, Comment, Windows File Info, Encrypt Info, End Marker. Any other
signature is a format error. The End Marker terminates the section.

### 16.5 Forward Compatibility

Implementations should handle unrecognized extra-field-based sub-headers by
reading the extra field prefix (to get the size) and skipping `size` bytes.
Sub-headers without extra field prefixes (File Header, Block Header) cannot
be skipped this way.

---

## A. AZO Compression Algorithm

AZO is the compression algorithm used in the EGG format. It is an
LZ77-based scheme using a binary arithmetic (range) coder with adaptive
probability models. This appendix provides sufficient detail to implement a
complete AZO decompressor.

### A.1 Stream Structure

AZO compressed data has a 2-byte stream header followed by one or more blocks:

```
[Stream Header]     2 bytes
[Block 0]           variable
[Block 1 ...]
[Terminal Block]    12 bytes (all zeros)
```

**Stream Header:**

```
Offset  Size  Description
+0      1     Version: ASCII '0' + version number (version 1 = '1' = 0x31)
+1      1     Flags: bit 0 = x86 filter enabled
```

The only defined version is 1 (byte value `0x31`). Any other value is a fatal
error (`AZO_DATA_ERROR_VERSION`).

### A.2 Block Structure

Each block has a 12-byte header. **All three fields are big-endian**, unlike the
rest of the EGG format which is little-endian:

```
Offset  Size  Type    Description
+0      4     UInt32  Uncompressed size (blockSize) [big-endian]
+4      4     UInt32  Compressed size (compressSize) [big-endian]
+8      4     UInt32  Check value (blockSize XOR compressSize) [big-endian]
```

Validation: `(blockSize ^ compressSize) == checkValue`, otherwise
`AZO_DATA_ERROR_BLOCKSIZE`. This check is optional; skipping it is safe.

When `blockSize == 0 && compressSize == 0`, the stream is complete
(`AZO_STREAM_END`).

If `compressSize == blockSize`, the block is stored uncompressed (raw copy).
Otherwise, the block is compressed with the range coder.

After decompressing a block, if the x86 filter flag is set, apply the x86
filter (section A.12) to the decompressed output.

### A.3 Decompression Algorithm

Each compressed block is decoded as follows:

```
1. Create an EntropyCode (range decoder) over the compressed data.
2. Call entropy.Initialize() -- reads 4 bytes to seed the tag.
3. Decode the first byte as a literal with context byte = 0.
4. For position i = 1 to blockSize - 1:
   a. Decode a match/literal flag via BoolState (section A.5).
   b. If literal (flag == 0):
      - Decode an 8-bit value using buf[i-1] as context (section A.9).
      - Store it at buf[i]. Advance i by 1.
   c. If match (flag == 1):
      - Decode distance and length via match decoding (section A.10).
      - Copy `length` bytes from buf[i - distance] to buf[i].
        The copy is byte-by-byte (overlapping copies are valid).
      - Advance i by length.
5. Call entropy.Finalize().
6. Verify that the entropy decoder consumed exactly compressSize bytes.
```

### A.4 Range Decoder

32-bit arithmetic range coder reading bits MSB-first from a byte buffer.

**Types:** The range values (`low`, `up`, `tag`) should be stored in 64-bit
unsigned integers (`uint64_t`) to avoid overflow when computing
`(up - low + 1)` at full range. Constants are 32-bit:
- `MSB = 0x80000000`
- `sMSB = 0x40000000` (second most significant bit)

Alternatively, 32-bit variables may be used with a special case: when
`low == 0 && up == 0xFFFFFFFF`, compute `t = 1 << (32 - totalBit)` directly
instead of `(up - low + 1) >> totalBit` (which would overflow to 0).
Both approaches produce identical output.

**State:**
- `low`: lower bound (uint64_t, initialized to `0x00000000`)
- `up`: upper bound (uint64_t, initialized to `0xFFFFFFFF`)
- `tag`: current value from bitstream (uint64_t)

**Initialize:** Read 32 bits MSB-first from the bitstream into `tag`:

```
tag = 0
for i in 0..31:
    tag = (tag << 1) | ReadBit()
```

(Equivalently: read 4 bytes in big-endian order.)

**Decode uniform symbol** (given `totalBit` -- log2 of the alphabet size):

```
t = (up - low + 1) >> totalBit
value = (tag - low) / t
up = low + t * (value + 1) - 1
low = low + t * value
Rescale()
return value
```

This is used to decode `N`-bit raw values (e.g., extra bits for distance/length
codes).

**Decode boolean** (given `cumCount` = probability of 0, and `totalBit`):

```
t = (up - low + 1) >> totalBit
v = (tag - low) / t
if v >= cumCount:
    low += t * cumCount
    Rescale()
    return 1
else:
    up = low + t * cumCount - 1
    Rescale()
    return 0
```

**Rescale:**

All shifts are masked to 32 bits (MASK = 0xFFFFFFFF):

```
// Phase 1: MSB convergence
while (low & MSB) == (up & MSB):
    bit = ReadBit()
    tag = ((tag << 1) & MASK) | bit
    low = (low << 1) & MASK
    up = ((up << 1) & MASK) | 1

// Phase 2: Underflow resolution
while (low & sMSB) != 0 and (up & sMSB) == 0:
    bit = ReadBit()
    tag = (((tag << 1) | bit) ^ MSB) & MASK
    low = (low << 1) & (MASK >> 1)
    up = ((up << 1) | 1 | MSB) & MASK
```

**Bit reader:** Reads bits MSB-first from the byte buffer. Maintains a pointer
into the compressed data and a remaining-bits counter for the current byte.
Reading beyond the buffer is an error.

### A.5 BoolState -- Adaptive Binary Model

Used for match/literal decisions and other boolean flags. Parameterized by
`N` (number of context bits, default 8).

**State:**
- `state`: unsigned integer in range `[0, 2^N)`, initialized to 0
- `prob[2^N]`: array of 32-bit probabilities, each initialized to 2048
  (= TOTAL_COUNT / 2 = 4096 / 2, representing 50% initial probability)

**Constants:**
- `TOTAL_BIT = 12`
- `TOTAL_COUNT = 4096` (= 2^12)
- `SHIFT_BIT = 6` (= TOTAL_BIT - 6)

**Decode:**

```
bit = entropy.DecodeBoolean(prob[state], TOTAL_BIT)
// Update probability:
if bit == 0:
    prob[state] += (TOTAL_COUNT - prob[state]) >> SHIFT_BIT
else:
    prob[state] -= prob[state] >> SHIFT_BIT
// Update state:
state = ((state << 1) | bit) & (2^N - 1)
return bit
```

The match/literal flag in the block decoder uses `BoolState<8>` (256 states).

### A.6 EntropyBitProb -- Adaptive Multi-Bit Tree Model

Used for decoding multi-bit symbols (distance codes, length codes, history
indices) as a binary tree with per-node adaptive probabilities.

Parameterized by `N` (alphabet size).

**Constants:**
- `BIT_N = ceil(log2(N))` (number of bits to encode a symbol)
- `ARRAY_N = 2^BIT_N` (number of tree nodes)
- `TOTAL_BIT = 10`
- `TOTAL_COUNT = 1024`
- `SHIFT_BIT = 4` (= TOTAL_BIT - 6)

**State:**
- `prob[ARRAY_N]`: per-node probabilities, each initialized to 512
  (= TOTAL_COUNT / 2 = 1024 / 2, representing 50% initial probability)

**Decode:**

```
value = 0
pre = 1                         // tree node index, starts at root
for i in (BIT_N - 1) downto 0:
    bit = entropy.DecodeBoolean(prob[pre], TOTAL_BIT)

    // Update probability inline (each node is independent):
    if bit == 0:
        prob[pre] += (TOTAL_COUNT - prob[pre]) >> SHIFT_BIT
    else:
        prob[pre] -= prob[pre] >> SHIFT_BIT

    if bit: value |= (1 << i)
    pre = (pre << 1) | bit      // descend left (0) or right (1)

return value
```

Note: probability updates can be done inline (single pass) or in a separate
pass after decoding -- both produce identical results since each tree node's
probability is independent.

**Update (passive, no decoding):** Updates probabilities for a known value
without reading from the range coder. Used by PredictProb (A.7) to keep the
inactive model in sync.

```
Update(value):
    pre = 1
    for i in (BIT_N - 1) downto 0:
        v = (value >> i) & 1
        if v == 0:
            prob[pre] += (TOTAL_COUNT - prob[pre]) >> SHIFT_BIT
        else:
            prob[pre] -= prob[pre] >> SHIFT_BIT
        pre = (pre << 1) | v
```

### A.7 PredictProb -- Dual-Model Adaptive Predictor

Used for literals (AlphaCode) and lengths (LengthCode). Selects between two
EntropyBitProb models based on a "luckiness" counter that tracks which model
is more accurate.

Parameterized by `KEY` (number of contexts), `N` (alphabet size), `SHIFT`.

**State:**
- `prob1[KEY]`: array of `EntropyBitProb<N>` (fine-grained, indexed by full context)
- `prob2[KEY >> SHIFT]`: array of `EntropyBitProb<N>` (coarse, indexed by context >> SHIFT)
- `lucky[KEY]`: array of `int`, each initialized to 0

**Decode (given context `pre`):**

```
if lucky[pre] >= 0:
    value = prob1[pre].Decode(entropy)     // use fine model
    prob2[pre >> SHIFT].Update(value)      // update coarse model passively
else:
    value = prob2[pre >> SHIFT].Decode(entropy)  // use coarse model
    prob1[pre].Update(value)               // update fine model passively

// Compare which model would have been better:
r = Compare(prob1[pre], prob2[pre >> SHIFT], value)
if r > 0: lucky[pre] += 1    // fine model was better
if r < 0: lucky[pre] -= 1    // coarse model was better

return value
```

**Compare function:** Compares which model better predicted the decoded value by
computing the product of per-bit probabilities along the decoding path.

```
Compare(model1, model2, value):
    prod1 = 1
    prod2 = 1
    pre = 1
    for i in (BIT_N - 1) downto 0:
        p1 = model1.prob[pre]
        p2 = model2.prob[pre]
        v = (value >> i) & 1

        // Overflow guard: if either product has bits in the upper
        // TOTAL_BIT positions of a 32-bit word, right-shift both.
        // For TOTAL_BIT=10: mask is (1023 << 22) = 0xFFC00000.
        if (prod1 | prod2) & ((TOTAL_COUNT - 1) << (32 - TOTAL_BIT)):
            prod1 >>= TOTAL_BIT
            prod2 >>= TOTAL_BIT

        prod1 *= (v ? (TOTAL_COUNT - p1) : p1)
        prod2 *= (v ? (TOTAL_COUNT - p2) : p2)

        pre = (pre << 1) | v

    if prod1 > prod2: return +1    // model1 was better
    if prod1 < prod2: return -1    // model2 was better
    return 0
```

All arithmetic is 32-bit unsigned (overflow wraps). The TOTAL_BIT and
TOTAL_COUNT values are those of the EntropyBitProb model (TOTAL_BIT=10,
TOTAL_COUNT=1024).

### A.8 HistoryList -- MRU List

A fixed-size most-recently-used list, parameterized by type `T` and size `N`.
Four instances are used: two of size 2 (recent distances; recent match-history
indices) and two of size 128 (remembered match lengths; match start positions).

**State:**
- `rep[N]`: array of values, initialized to `[init, init+1, ..., init+N-1]`:
  - recent distances: `init = MATCH_MIN_DIST = 1` -> `[1, 2]`
  - recent match indices: `init = 0` -> `[0, 1]`
  - match lengths: `init = MATCH_MIN_LENGTH = 2` -> `[2, 3, ..., 129]`
  - match positions: `init = 0` -> all zero

**Operations (no bitstream interaction):**

- `AddRecent(value)`: shift every entry right by one (dropping the last) and
  insert `value` at index 0.
- `GetDataAndUpdate(index)`: return `rep[index]` and move it to the front,
  shifting entries `[0..index-1]` right to `[1..index]`.

### A.9 AlphaCode -- Literal Byte Decoding

Decodes a single literal byte using the previous byte as context.

Uses `PredictProb<256, 256, 5>`:
- 256 contexts (one per possible previous byte value)
- 256-symbol alphabet (one per possible byte value)
- SHIFT = 5 (coarse context uses previous byte >> 5, giving 8 groups)

```
byte = PredictProb.Decode(entropy, previousByte)
```

At position 0 (first byte of block), `previousByte = 0`.

### A.10 Match Decoding

When the match/literal flag indicates a match, a second BoolState "reuse" flag
selects between reusing a remembered match and decoding a fresh one:

```
1. Decode a "reuse" flag via BoolState.
   - reuse == 1: reuse a remembered (length, position) pair (A.10.1).
   - reuse == 0: decode a fresh distance and length (A.10.2), then remember it.
```

Either way the result is a `(distance, length)` pair: copy `length` bytes from
`output[writePos - distance]` forward, byte-by-byte (overlapping copies valid).

Four MRU HistoryLists (A.8) back this: two size-128 lists `lengthHistory` and
`posHistory` (parallel: the i-th entry is one remembered match's length and
start position), plus two size-2 lists `recentDist` and `recentMatchIndex`.

#### A.10.1 Reuse a remembered match

Decode an index into the size-128 histories:

```
1. Decode a "short" flag via BoolState.
   - short == 1: decode a 1-bit index via EntropyBitProb<2>; look it up in the
     size-2 recentMatchIndex list -> historyIndex = recentMatchIndex.GetDataAndUpdate(bit)
   - short == 0: decode a 7-bit index via EntropyBitProb<128> -> historyIndex,
     then recentMatchIndex.AddRecent(historyIndex)
2. length   = lengthHistory.GetDataAndUpdate(historyIndex)
3. position = posHistory.GetDataAndUpdate(historyIndex)
4. distance = writePos - position
```

#### A.10.2 Decode a fresh distance and length

Distance:

```
1. Decode a "short" flag via BoolState.
   - short == 1: decode a 1-bit index via EntropyBitProb<2>;
     distance = recentDist.GetDataAndUpdate(bit)
   - short == 0: decode a 7-bit distance code via EntropyBitProb<128>;
     distance = DIST_CODE_TABLE[code];
     if DIST_EXTRABIT_TABLE[code] > 0:
         distance += DecodeUniform(DIST_EXTRABIT_TABLE[code])
     then recentDist.AddRecent(distance)
```

Length (context = the distance's code index):

```
1. distCode = GetDistCode(distance)
2. code = PredictProb<128,128,4>.Decode(entropy, distCode)   // A.7
3. length = LENGTH_CODE_TABLE[code]
4. if LENGTH_EXTRABIT_TABLE[code] > 0:
       length += DecodeUniform(LENGTH_EXTRABIT_TABLE[code])
```

Finally, remember this match:
`lengthHistory.AddRecent(length)` and `posHistory.AddRecent(writePos)`.

`PredictProb<128, 128, 4>` means 128 contexts (one per distance code), a
128-symbol alphabet (length codes), and SHIFT = 4 (coarse context =
distCode >> 4, giving 8 groups).

### A.11 Code Tables

The distance and length code tables map code indices to base values with
optional extra bits.

#### A.11.1 Length Code Table (128 entries)

**Extra bits formula:**
```
ExtraBit(N) = 0                          if N < 32
ExtraBit(N) = (N - 32) / 8              otherwise
```

**Code table formula (recursive):**
```
LengthCode(0) = 2                       (= MATCH_MIN_LENGTH)
LengthCode(N) = LengthCode(N-1) + (1 << ExtraBit(N-1))
```

**First entries:**

| Index | Base Length | Extra Bits |
|-------|-----------|------------|
| 0     | 2         | 0          |
| 1     | 3         | 0          |
| ...   | ...       | 0          |
| 31    | 33        | 0          |
| 32    | 34        | 0          |
| 33    | 35        | 0          |
| ...   | ...       | 0          |
| 39    | 41        | 0          |
| 40    | 42        | 1          |
| 41    | 44        | 1          |
| ...   | ...       | ...        |
| 48    | 58        | 2          |
| ...   | ...       | ...        |

The maximum representable length is `LengthCode(128) - 1`.

**Reverse lookup** (value to code index, needed for A.10.3):

```
GetLengthCode(value):
    value -= MATCH_MIN_LENGTH          // subtract 2
    if value < MATCH_LENGTH_SGAP:      // < 32
        return value
    value -= MATCH_LENGTH_SGAP
    extraBit = floor(log2(value / MATCH_LENGTH_GAP + 1))
    return MATCH_LENGTH_SGAP + extraBit * MATCH_LENGTH_GAP
           + (value - ((1 << extraBit) - 1) * MATCH_LENGTH_GAP) / (1 << extraBit)
```

#### A.11.2 Distance Code Table (128 entries)

**Extra bits formula:**
```
ExtraBit(N) = 0                          if N < 16
ExtraBit(N) = (N - 16) / 4              otherwise
```

**Code table formula (recursive):**
```
DistCode(0) = 1                          (= MATCH_MIN_DIST)
DistCode(N) = DistCode(N-1) + (1 << ExtraBit(N-1))
```

**First entries:**

| Index | Base Distance | Extra Bits |
|-------|--------------|------------|
| 0     | 1            | 0          |
| 1     | 2            | 0          |
| ...   | ...          | 0          |
| 15    | 16           | 0          |
| 16    | 17           | 0          |
| 17    | 18           | 0          |
| 18    | 19           | 0          |
| 19    | 20           | 0          |
| 20    | 21           | 1          |
| 21    | 23           | 1          |
| ...   | ...          | ...        |

The maximum representable distance is `DistCode(128) - 1`.

**Reverse lookup** (value to code index, needed for A.10.3):

```
GetDistCode(value):
    value -= MATCH_MIN_DIST            // subtract 1
    if value < MATCH_DIST_SGAP:        // < 16
        return value
    value -= MATCH_DIST_SGAP
    extraBit = floor(log2(value / MATCH_DIST_GAP + 1))
    return MATCH_DIST_SGAP + extraBit * MATCH_DIST_GAP
           + (value - ((1 << extraBit) - 1) * MATCH_DIST_GAP) / (1 << extraBit)
```

### A.12 x86 Filter

When the stream header filter flag is set, apply this filter to each
decompressed block. The filter reverses x86 CALL/JMP address transformations
that the compressor applied to improve compression of executable code.

The flag is set from the **content, not the extension**: AZO.dll's prepare
function calls `0x61907410` on the first input chunk, which returns 1 exactly
when it starts with `4d 5a` (`MZ`, the DOS/PE signature); the header's `0x31`
is stored at `0x61907869` and the flag byte at `0x61907892` (`31 01` / `31 00`). The decision is made once
per stream, so every later chunk is filtered as well even when it does not
start with `MZ`. The compressor applies the same function in the opposite
direction (`+i` instead of `-i`, `0x6190798a`), to each chunk separately, before
compressing it; the block CRC-32 stays the CRC of the *original* bytes.

Reference measurements (`corpus_probe/`): `probe.sys` and `probe.com` are text
and carry flag 0, `mz.sys` (a 73,560-byte PE) carries `31 01`, and
`mzmulti.sys` (ALZipCon.exe, 594,264 bytes, two 2^19 chunks whose second one
does not start with `MZ`) carries `31 01` too and is filtered on both chunks.
All three are reproduced byte for byte by the encoder.

The filter also runs on the **copied-chunk path**, which is the last shape worth
spelling out: a chunk that does not shrink is stored raw (`compressSize ==
blockSize`), and what is stored is the *filtered* buffer, not the input. Two
references pin it — `mzraw.sys` (MZ + 524,286 bytes of a fixed PRNG, exactly one
2^19 chunk) and `mzraw2.sys` (1 MiB, two chunks, the second one not starting
with `MZ`) — both reproduced byte for byte. In both, the block's `csize` is
`usize + 26` (2 stream-header bytes + 12 per slice + a 12-byte terminator), the
slice header's third `UInt32` is `0`, the flag stays `31 01`, and the stored
bytes differ from the input at the filtered `E8`/`E9` words. The order matters
and is now measured: **filter first, decide the copy second** — a chunk that is
incompressible *after* filtering is stored filtered.

x86 CALL (`0xE8`) and JMP (`0xE9`) instructions use relative 32-bit addresses.
The compressor converts these to absolute addresses (better for compression).
This filter converts them back to relative.

The check `buf[i+4] == 0x00 or buf[i+4] == 0xFF` tests the high byte of the
address to filter only addresses that are "near" (within ~16 MB), avoiding
false positives on non-address data that happens to follow a `0xE8`/`0xE9`.

```
if size < 5: return

i = 0
while i < size - 4:
    if buf[i] == 0xE8 or buf[i] == 0xE9:   // CALL or JMP
        if buf[i+4] == 0x00 or buf[i+4] == 0xFF:
            addr = read_le32(buf[i+1])      // 4 bytes, little-endian
            addr -= i                        // absolute -> relative
            if (addr >> 24) & 1:             // test bit 24
                addr |= 0xFF000000          // sign-extend: negative 24-bit
            else:
                addr &= 0x00FFFFFF          // positive 24-bit
            write_le32(buf[i+1], addr)
        i += 5
    else:
        i += 1
```

### A.13 Constants Summary

| Name                       | Value |
|----------------------------|-------|
| AZO_PRIVATE_VERSION        | 1     |
| COMPRESSION_REDUCE_MIN_SIZE| 8     |
| ALPHA_SIZE                 | 256   |
| ALPHACODE_PREDICT_SHIFT    | 5     |
| LENGTHCODE_PREDICT_SHIFT   | 4     |
| MATCH_MIN_LENGTH           | 2     |
| MATCH_MIN_DIST             | 1     |
| MATCH_LENGTH_CODE_SIZE     | 128   |
| MATCH_DIST_CODE_SIZE       | 128   |
| MATCH_LENGTH_SGAP          | 32    |
| MATCH_LENGTH_GAP           | 8     |
| MATCH_DIST_SGAP            | 16    |
| MATCH_DIST_GAP             | 4     |
| LENPOS_HISTORY_SIZE        | 128   |
| RECENT_MATCH_INDEX_SIZE    | 2     |
| RECENT_DISTANCE_SIZE       | 2     |

### A.14 Error Codes

| Value | Name                     |
|-------|--------------------------|
| 0     | AZO_OK                  |
| 1     | AZO_STREAM_END          |
| -1    | AZO_PARAM_ERROR         |
| -2    | AZO_MEM_ERROR           |
| -3    | AZO_OUTBUFF_FULL        |
| -4    | AZO_DATA_ERROR          |
| -5    | AZO_DATA_ERROR_VERSION  |
| -6    | AZO_DATA_ERROR_BLOCKSIZE|

### A.15 AZO in this project: decoder and encoder, both byte-exact

`src/egg_azo.c` implements A.1-A.14 in both directions and is validated on the
five AZO references of the corpus:

| Reference | Member | Shape |
|---|---|---|
| `packed_egg/probe_sys_optimized.egg` | `probe.sys`, 74,627 bytes, CRC-32 `5d2395c9` | one coded chunk |
| `packed_egg/probe_com_optimized.egg` | `probe.com`, same bytes as `probe.sys` | one coded chunk, payload identical to the `.sys` reference |
| `packed_egg_8.0/sysmulti_sys_optimized.egg` | `sysmulti.sys`, 633,780 bytes, CRC-32 `4c9b06cc` | two chunks, 524,288 + 109,492 bytes |
| `packed_egg_8.0/mz_sys_optimized.egg` | `mz.sys`, 73,560 bytes (a PE), CRC-32 `57005dbb` | x86 filter flag set (`31 01`), one coded chunk |
| `packed_egg_8.0/mzmulti_sys_optimized.egg` | `mzmulti.sys`, 594,264 bytes (ALZipCon.exe), CRC-32 `13bcab37` | x86 filter flag set, two chunks, second one not `MZ` |

All five extract byte for byte (`alzgg extract`, `make test` step 7), and all
five are re-produced byte for byte: the whole archive by `alzgg create -p
optimized` (step 9) and the AZO payload alone by `azoenc` (step 10). Three
details the specification text left implicit and that the reference bitstream
forced:

- the four `BoolState` instances (match/literal flag, reuse flag, and the two
  "short" flags) must stay separate — sharing any of them desynchronises the
  range decoder within the first tens of bytes;
- the position history list starts at zero for every entry, while the length,
  distance and match-index lists start at `init, init+1, …` (A.8);
- the initial pair with a zero position (length `init+i`, position 0) is not a
  degenerate entry — ALZip reuses it as an ordinary match (its second symbol is
  a reuse of index 5, i.e. length 6 at position 0).

The stream header's x86-filter flag (A.12) is now exercised in both directions:
`mz_sys_optimized.egg` (`mz.sys`, a 73,560-byte PE) and
`mzmulti_sys_optimized.egg` (`mzmulti.sys`, ALZipCon.exe, 594,264 bytes, two
chunks) set it because their first bytes are `MZ`, and the encoder reproduces
both byte for byte — including the second chunk of the pair, which is filtered
even though it does not start with `MZ` (the flag is sticky, A.12). The three
text `.sys`/`.com` references carry flag 0. Multi-chunk streams were also what
pinned the 2^19-byte chunking: the decoder restarts its models and its position
history at every chunk.

Encoding is **implemented** (see "The encoder" below): `alzgg create -p
optimized` writes the measured `.sys`/`.com` route instead of refusing it. The
decoder was instrumented to recover the symbol stream ALZip actually wrote,
which is the only measurement of the AZO *parse* (1,124 symbols for the
`probe.sys` block); that recovered parse is what the encoder now reproduces:

| Observation | Measurement |
|---|---|
| Symbol mix | 234 literals, 475 fresh matches, 415 reuses |
| Fresh distances | 5 … 73,682 (the search window covers the whole 74 KB block; nothing suggests a smaller limit) |
| Reuse choice | always the **longest** matching remembered pair, lowest index on a tie: 415/415 |
| Pair vs fresh | the pair is used only when a remembered pair has **exactly** the fresh match's length (first such index): the two apparent counter-examples of the first reading (p=952 and p=72,516, where a *longer* pair exists and a fresh match is written anyway) are exactly what this rule predicts |
| Search key | 2 bytes: at p=7 the encoder emits a 2-byte match (`lo`), which a 3-byte hash cannot find; every chosen distance shares the 2-byte prefix |
| Fresh search result | the globally longest match only in 446/475 cases; the 29 misses have a **longer match at a smaller distance** (p=952: chose `d=101, l=5` while 6 bytes are available at `d=515` and `d=897`), so the finder's candidate ordering/early exit is not "longest, tie → nearest" |
| Recent-distance list | not a factor: only 4 of the 475 fresh distances are in the sampled `recentDist` pair |

#### The match finder, recovered by disassembly

The encoder side of `Coder_CompressBuffer` has now been read out of
`research/Program Files (x86)/ALZip/Coders/AZO.dll` (version 10.3.28.0). The
module is a small C++ PE32; the parse lives in a per-position decision function
(`0x61905bf0`), the search in `0x61905a90`, the hash insertion in `0x61905430`
+ `0x619055e0`, and the arithmetic encoder in `0x619047f0` (renormalise),
`0x619049c0` (binary symbol), `0x61904930` (uniform bits) and `0x61904a60`
(flush).

The coder is the exact mirror of A.4-A.6 and is fully disclosed:

- renormalise: while the two MSBs are equal, emit the MSB and then, for every
  pending underflow bit, emit its **complement** (the pending counter is not a
  counter of identical bits but of E3 events); then, while bit 30 is set in
  `low` and clear in `up`, shift and increment the pending counter;
- binary symbol with cumulative value `cum` on `total_bit` bits: `t = (up − low
  + 1) >> total_bit` (with the degenerate `low = 0, up = 0xFFFFFFFF` case
  replaced by `t = 1 << (32 − total_bit)`); bit 0 sets `up = low + t*cum − 1`,
  bit 1 sets `low += t*cum`;
- uniform value with `total_bit` bits: `low += t*value`, `up = low + t − 1`;
- flush: if bit 30 of `low` is clear, emit a 0 followed by one 1 per pending
  bit; then emit a final 1 and pad the current byte (bits are emitted MSB
  first).

The match finder is a **progressive hash** — not a chain: one table per level,
one stored position per bucket. The loop is generic over the level count, which
comes from the configuration object (line 1 of the table at `0x6190c840`); the
measured value is **3 levels** with 2/4/8-byte prefixes and an 18-bit bucket
index:

| Level | Prefix hashed | Table slot |
|---:|---:|---|
| 0 | 2 bytes | one position |
| 1 | 4 bytes | one position |
| 2 | 8 bytes | one position |

The running hash starts at `(b0 << 8) | b1` (big-endian pair) and each
extension step (2 more bytes, then 4-byte words) folds it with `h = h * 33 +
word`, the 16-bit step using a **sign-extended** little-endian pair and the
4-byte steps a little-endian dword; the bucket index is `(h >> shift) ^ h`
masked to `shift` bits. Insertion happens for **every** position, in order, one
position behind the search cursor (so a position never matches itself).

Search, per position: for the highest level down to 0, take that level's single
candidate, reject it if the distance exceeds `0x4000000C` or its claimed
2^(i+1)-byte prefix does not verify (the higher levels also compare the last two
bytes and `memcmp` the first `n−2`), compute the true match length (capped by
the chunk end and by a global limit read at `0x6190b320`, `0x8019` = 32 793),
and **accept the first candidate that passes** — length above the threshold 2,
or, for a short match, a coded cost lower than a literal's. That early exit is
exactly what makes the parse differ from "longest match, ties to the nearest":
a longer match at a lower level is never examined. Lazy matching sits one level
above: if a match of length `L` exists at `pos` and `pos < len − 1`, the finder
runs again at `pos + 1`, and if that length is strictly greater the encoder
writes a literal and caches the new `(distance, length)` for the next call
(`+0x54e40`/`+0x54e44` in the object).

Reuse is decided against the same MRU lists the decoder keeps (A.8): among the
128 remembered pairs, the usable ones are those whose position is strictly
before the cursor, whose bytes still match, and whose stored length is **exactly
the fresh match's length**; the chosen one is the **lowest index**. A fresh match
is written when no pair has that exact length, which is why a *longer* remembered
pair does not win: the pair list is not a "best match" search, it is an equality
test against the length the finder just returned. The `shortReuse` flag is set
exactly when the chosen index currently sits in the first two slots of the
match-index list (415/415 on the reference block), which is why the decoder can
encode it with a single bit. Measured on the reference block, this reproduces
the observed parse: reuse index 415/415, reused length 415/415, `shortReuse`
flag 415/415, and the pair used exactly when a remembered pair has the fresh
length — including the two positions (`p=952` and `p=72,516`) that a "pair at
least as long" rule gets wrong.

With that rule the parse is complete, and the two remaining parameters — the
chunk size and the stream header's two bytes — are measured rather than
guessed: 2^19 bytes per chunk (`sysmulti_sys_optimized.egg`: 524,288 + 109,492)
and the header `31 00`, replaced by `31 01` when the member starts with `MZ`
(A.12). That is enough to write the encoder.

#### The encoder

`egg_azo_encode_range` (`src/egg_azo.c`) writes the whole AZO payload of one EGG
member: the 2-byte stream header (`31 00`, or `31 01` with the x86 filter), one
chunk per 2^19 input bytes — each
with its 12-byte big-endian header (uncompressed size, compressed size, XOR of
the two) — then a 12-byte all-zero terminator, and it returns the CRC-32 of the
uncompressed member for the EGG block header. Models, position history and hash
tables are re-initialised at every chunk, so chunks are independent. A chunk
whose coded form is not smaller than the input is stored raw (`compressSize ==
blockSize`) — after filtering, since the decoder filters what it reads back.

| Parameter | Value | Where it comes from |
|---|---|---|
| Chunk size | 2^19 bytes | the 633,780-byte reference splits 524,288 + 109,492; a 1.36 MiB `.sys` splits into three chunks |
| Match window | `0x4000000C` | rejection test in the search routine `0x61905a90` |
| Maximum length | `0x8019` (32,793) | limit read at `0x6190b320` |
| Hash levels | 3 (2/4/8-byte prefixes), 18-bit bucket index | configuration object, line 1 of the table at `0x6190c840` |
| Threshold | 2: above it a match is always taken, at or below it a coded-cost test decides | decision routine `0x61905bf0` |
| Pair memory | 128 entries, reused only at exactly the fresh match's length, lowest index | pair search of the decision routine + the 415/415 measurement above |
| `hint` | 1 | every method-3 block of the corpus |

Validation. `make test` step 9 compares the whole archive produced by `alz
create -p optimized` against the three references, and step 10 re-encodes their
payloads with `azoenc` (3/3 identical). The final encoder was also re-checked on
eight further samples generated locally by the Wine oracle — incompressible
input (raw chunk), RLE (`zeros`), text, two binary corpora, a `.doc` renamed
`.sys`, and a 1.36 MiB `.sys` in three chunks — all 8 identical; those samples
are not checked in, so `make test` never depends on Wine.

#### A local reference producer (Wine)

`ALZipCon.exe` runs under Wine on Linux against the same 8.0.0.18 coder DLLs,
and it reproduces the checked-in reference byte for byte: compressing
`corpus/probe.sys` at `-m4` yields an AZO block whose payload has the
same SHA-256 as `packed_egg/probe_sys_optimized.egg`. That turns the reference
build into a local oracle for the encoder work (`tools/azo_trace.py` dumps the
symbol stream of any AZO block; `packed_egg_8.0/` and the Wine runs agree).
One routing fact it settles immediately: at `-m4` only `.sys` and `.com` route
to AZO — `.dll`, `.exe`, `.ocx`, `.vxd`, `.drv`, `.cpl`, `.ax`, `.tlb`, `.acm`,
`.scr`, `.mui`-style system extensions and `.bat` (BZip2), `.bin`/`.raw`/`.wav`
(deflate hint 5) do not, which is why the lot-G `.dll`/`.exe` archives carry
deflate blocks rather than the AZO samples they were requested for.
It also produced the two AZO references that go beyond the original Windows
sample — `probe_com_optimized.egg` (same content as `probe.sys`, `.com` name) and
`sysmulti_sys_optimized.egg` (two chunks) — which are checked in so that `make
test` pins the `.com` route and the multi-chunk path without Wine. The script
keeps the input's basename (only the extension matters for routing), so the
stored member name is the one `alzgg create` will write.

This oracle is a development aid only: `make test` must not depend on Wine or
on the reference binaries.

---

## References

- **LEA block cipher**: KS X 3246, TTAK.KO-12.0223 (South Korean standard)
- **PBKDF2**: RFC 8018 (PKCS #5 v2.1)
- **HMAC-SHA1**: RFC 2104
- **CRC-32**: ISO 3309, ITU-T V.42 (polynomial 0xEDB88320)
- **DEFLATE**: RFC 1951
- **bzip2**: Julian Seward, https://sourceware.org/bzip2/
- **LZMA**: Igor Pavlov, LZMA SDK
- **WinZip AE-2**: WinZip AES encryption specification

---

## 17. C implementation status in this project

`src/egg.c` implements an EGG **reader** for `.egg` archives only. Scope is
deliberately narrow: the format's reference for every field is this document,
and codecs are only implemented when an ALZip-written sample exists to compare
against.

**Memory.** Reading does not scale with the member: a single-volume archive is
`mmap()`ed instead of being copied into the heap, and a member is decoded and
written block by block (1 MiB tranches for store, one block for the codecs, then
freed), so the working set is bounded by the format's own block unit rather than
by the file. `make test` asserts it by extracting a 128 MiB member — clear and
ZipCrypto — under a 320 MiB address-space limit. Two consequences are worth
noting: a failed member is removed instead of being left truncated, and a
multi-block ZipCrypto member is decoded once *without writing* to learn the
whole-member CRC its password verifier covers, then decoded again to write, so
a wrong password still creates no file. Solid archives are no exception any
more: their shared stream is decoded through a 64 KiB sink that opens each
member in archive order and checks the block CRC on the slice it covers, so a
128 MiB solid archive extracts under 96 MiB of address space (`make test`
step 6) and a failed CRC removes the files already written. Only the
*compressed* stream is held in memory; the AZO codec, unreachable in solid mode
(§14.1), is the single fallback that still decodes into one buffer.

| Capability | State in `src/egg.c` / `src/cli_egg.c` | Evidence |
|---|---|---|
| Container: EGG header, prefix (Split/Solid/Dummy), file headers, sub-headers, blocks | Implemented | `alzgg list` on all 70 supplied samples plus the `corpus_probe/` probes |
| Split volumes | Implemented; volumes are matched by Split Info Header ID as in §13.1 and their data regions are concatenated in chain order | `records_optimized.vol1/vol2.egg` extract byte-for-byte from either volume; `splitmany_normal.vol1/2/3.egg` yield all 420 members from each volume, which is the path that crosses the corpus's only DUMMY record |
| Windows File Info (time, attributes, directory bit) | Parsed and displayed; directory entries are created on extract | `nested_*.egg` samples; non-ASCII member names in `unicode_normal.egg` are reproduced byte for byte |
| Store (method 0) and Deflate (method 1) | Decoded, with CRC-32 verified per block (solid streams included) | 69 of the 70 supplied samples extract (the three encrypted ones included, with their password) and every member matches its reference file byte for byte; the supported `corpus_probe/` samples reproduce theirs too |
| BZip2 (2) | **Decoded and encoded**, block CRC-32 verified on decode: `src/egg_bzip2.c` links the bzip2 1.0.5 library vendored in `src/bzip2_dec/` (licence included), the same version FIXTURES.md names as this codec's reference. The encoder reproduces ALZip's parameters: `blockSize100k` is the block's own `hint` byte (4 in every reference block, and the `BZh4` of the stream), `workFactor` 30 — a value the corpus cannot discriminate (1 and 250 emit the same bytes on these inputs), chosen as bzip2's documented default | Decode: 477 bzip2 blocks over the 11 archives that carry one (`code_normal/code_optimized/eng_optimized/hello_optimized/nested_optimized.egg`, the three encrypted `hello_optimized_password_*` samples, `probe_java_optimized.egg`, the 420 members of `splitmany_optimized` and the 11 blocks of `gui_optimized_matrix.egg`), decryption and codec exercised together end to end. Encode: `make test` step 10 re-encodes the **474 cleartext blocks** byte for byte through `bz2enc`, whose inputs are decompressed by Python's libbzip2 — never by this project's decoder, so the encoder is compared to the corpus rather than to itself |
| LZMA (4) | **Decoded and encoded** (`src/egg_lzma.c`, vendored LZMA SDK 4.65): 9-byte block header parsed, raw bitstream decoded against the block's `unpackSize`, and the encoder reproduces ALZip's setting — default level 5 (`lc=3, lp=0, pb=2`, 16 MiB dictionary, `nice_len` 32, `mc` 32, BT4) behind the constant `04 41 05 00` marker | Decode: all 25 LZMA blocks of the corpus reproduced byte for byte, across the 16 `_compratio` archives (one solid) and the `.doc`/`.ico` Optimized probes. Encode: the 14 non-solid `_compratio` archives, the two `.doc`/`.ico` Optimized archives and the two solid LZMA trees are rebuilt byte for byte by `alzgg create` (`make test` steps 9-10) |
| AZO (3) | **Decoded and encoded** (`src/egg_azo.c`, appendix A): two-byte stream header, big-endian 12-byte chunk headers, terminal chunk, raw chunks when `compressSize == blockSize`, the range coder and all five adaptive models, the pair-MRU mechanism, the x86 filter in both directions, and the 2^19-byte internal chunking with its per-chunk model reset. The encoder's parse was read out of `AZO.dll` 10.3.28.0 (A.15); the filter flag is set from the `MZ` signature of the first chunk (A.12) | Decode: all five AZO samples extract byte for byte — `probe_sys_optimized.egg` (`probe.sys`, CRC `5d2395c9`), `probe_com_optimized.egg` (same payload behind a `.com` name), `sysmulti_sys_optimized.egg` (`sysmulti.sys`, 633,780 bytes, CRC `4c9b06cc`, two chunks), `mz_sys_optimized.egg` (PE, flag `31 01`) and `mzmulti_sys_optimized.egg` (594,264-byte PE, flag `31 01`, two chunks) — through both `alzgg extract` and `make test` step 7. Encode: those five archives, the two copied-chunk `MZ` references (`mzraw_sys_optimized.egg`, 524,410 bytes; `mzraw2_sys_optimized.egg`, 1,048,711 bytes) and `routes_optimized.egg`, whose `.sys`/`.com`/`.SYS` members exercise the case-insensitive route, are rebuilt byte for byte by `alzgg create -p optimized` (step 9), and all ten payloads are re-encoded by `azoenc` (step 10); eight further shapes from the local Wine oracle (raw chunk, RLE, text, random binaries, three chunks) also match |
| Encryption (ZipCrypto, AES-128/256) | **Decoded**: password verifier checked first (ZipCrypto check byte / PBKDF2 verifier), AES footer authenticated, then the member's concatenated payload is decrypted in place; `-p PASS` on `alzgg extract`, `--raw` to write the decrypted payload without decompressing (§12.7) | The 3 password samples now extract to `corpus/hello.txt` byte for byte through the normal path (decryption + bzip2) and not only through `--raw`, with the block CRC-32 matching; wrong password, missing password and a tampered AES ciphertext are each refused with nothing written |
| Encryption (LEA-128/256, methods 5 and 6) | **Decoded and encoded** (`src/egg_lea.c`, KS X 3246): same PBKDF2 verifier and same HMAC-SHA1 footer as AES, CTR with a 128-bit big-endian counter starting at zero (§12.5.6); `--crypt lea128|lea256` on `alzgg create` | `make test` step 8 decrypts the six ALZip 12.30 archives of `packed_egg/` — store and Optimized (bzip2), one and two members (one salt each) — to `corpus/hello.txt` and `corpus/code.c`, and refuses a missing/wrong password and a tampered ciphertext; step 9 rebuilds all six byte for byte; the block cipher itself is pinned on the KS X 3246 appendix A vectors by `tests/bin/leatv` |
| Solid archives, Deflate route | **Decoded**: the single block carrying the whole stream is inflated once and split across the members in archive order, each block CRC-32 checked on its own slice (§14.3) | `packed_egg/nested_normal_solid.egg` (8 members, 822,784 bytes) and `packed_egg_8.0/unicode_normal_solid.egg` (3 members, 78 bytes) reproduce `corpus/nested/` and `corpus/unicode/` byte for byte |
| Solid archives, LZMA route | **Decoded and encoded**: one LZMA stream spans the whole archive, split on `unpackSize` like the deflate route (§14.3) | `packed_egg/nested_compratio_solid.egg` (8 members, 334 971 bytes) and `packed_egg_8.0/unicode_compratio_solid.egg` (3 members) reproduce `corpus/nested/` and `corpus/unicode/` byte for byte, and are rebuilt byte for byte by `alzgg create -s -p compratio` |
| Solid archives, AZO | Structurally impossible: AZO is emitted only by Optimized Compression, which solid mode forbids (§14.1) | — |
| Writer, store / Deflate, single volume | **Implemented** (`alzgg create -p none|compspeed|normal`), on the **12.30** scale: Normal (`-m2`) is Deflate hint 4 for every member, with no extension routing and no refusal (§11.0); Compressing Speed (`-m1`) is Deflate hint 2 | `egg_m0/m1/m2_two.egg` reproduced byte for byte (lot K, step 9), as are the unchanged 8.0 Store references; the 8.0 deflate 6/5 archives remain decode-only |
| Writer, Optimized (complete routing table) | **Implemented** (§11.0): the four effective extension lists of ALZip — Store, BZip2, LZMA hint 6, AZO hint 1 for `.sys`/`.com` — matched on the last suffix, case-insensitively, with **Deflate hint 5** as the fallback. No extension is refused any more, and the nine shadowed BZip2 entries are not a table entry but a **consequence of the matcher's rule** (`find` + following comma, no retry), which `make test` replays on the lists read out of `Formats/Egg.dll` | The `Optimized` references reproduced byte for byte (all of §11.0's shapes): the corpus archives, `routes_optimized.egg` (148 extensions, one per route and fallback, 285,730 bytes), and the four `MZ` AZO archives (`mz_sys_optimized`, `mzmulti_sys_optimized`, plus the two copied-chunk ones, `mzraw_sys_optimized` and `mzraw2_sys_optimized`) |
| Writer, Priority on Compress Ratio | **Implemented** (`alzgg create -p compratio`, `-m3`): every member LZMA hint **8**, one block per member, single volume | `egg_m3_two.egg` byte for byte (lot K); the 13 single-member and 8-member nested 8.0 `_compratio` archives have the same payload and are compared block by block (step 9) |
| Writer, solid Deflate and solid LZMA | **Implemented** (`alzgg create -s -p compspeed|compratio`, `-m1`/`-m3`): one deflate (hint 2) or LZMA (hint 8) stream over the concatenation of the members, one block after the headers, 7-byte SOLID_INFO prefix | `egg_s_m1_two.egg` and `egg_s_m3_two.egg` reproduced byte for byte, then extracted back (lot K, step 9) |
| Writer, split volumes | **Implemented** (`alzgg create -v SIZE -i id1,id2,…`): writes `<base>.vol1.egg`, `<base>.vol2.egg`, …, each volume exactly SIZE bytes with a 33-byte header, cuts only inside block data, pads the leftover with a DUMMY when the next sub-header does not fit, and links the volumes through Split Info (§13.3) | Three reference chains reproduced byte for byte: `splitmany_normal` (3 volumes, 420 members, the corpus's only DUMMY, a mid-block cut), `records_optimized` (2 volumes) and `splitmany_optimized` (3 volumes, 420 BZip2 members); each chain is then extracted back from its **last** volume. A one-volume run yields `<base>.vol1.egg`; solid + `-v`, `-v` without IDs, a volume smaller than its own header, and exhausted IDs are refused and leave no volume behind |
| Writer, encryption combined with everything else | **Implemented**: encrypted members in store, deflate, bzip2 and LZMA profiles, empty members and directories (written with **no** Encrypt Info, as ALZip does), multi-block members under one continuous cipher context, and encrypted volumes | 24 references rebuilt byte for byte — the nine of the first batch, the `m0..m3 × tp0..2` matrix, two Store members, an empty member and a directory — plus the 16 volumes of `span_15vol_crypt` (§12.8); the empty member and the directory are compared to ALZip rather than refused, and `enc_egg_napw_*` pin the CP1252 password encoding (§12.9) |
| Writer, everything else | **Refused** with an explicit message, never approximated: solid with any profile other than `m1`/`m3`, solid + `-v`, solid + password, comments, symlinks, bzip2 members above 3 GiB, solid streams above 3 GiB | `make test` asserts each refusal writes no archive and no volume |

The reader runs clean under AddressSanitizer + UndefinedBehaviorSanitizer with
leak detection over all 70 supplied samples and the `corpus_probe/` probes, both
for `list` and for `extract` (both solid routes and the three encrypted samples
included), and over **26 deliberately malformed archives**: six truncations (in
the header, the prefix, a sub-header, a block header, the block data and the end
marker), a forged prefix end, a member `usize` of 2^64-1, a FILENAME size larger
than the rest of the file, an unknown block method, each codec fed a stream that
is not its own (deflate labelled BZip2, AZO and LZMA — the `hint` byte and the
archive version are deliberately *not* validated, since neither changes how the
data is decoded), a block `usize`/`csize` of 0xFFFFFFFF, a zero `csize` with a
non-zero `usize`, a flipped block CRC, corrupted block data, a broken block end
marker, trailing bytes after the final end marker, an unknown cipher method, a
flipped ZipCrypto verifier and a truncated encrypted archive. Each one must exit
non-zero, without a signal and without writing a file. Two of them are
security properties rather than format ones: a member named `../../pwn` or
`/tmp/absx` is refused with "suspicious path in the archive" and nothing is
written outside the destination directory, so the check cannot be removed
silently. `make test` asserts the split-chain output, 69 byte-exact extractions
from `packed_egg/`, byte-exact extraction of everything in `corpus_probe/` — the
five block methods included, with seven AZO samples (one chunk, one `.com`
route, one two-chunk member, the two `MZ` members with the x86 filter — one of
them two-chunk — and the two incompressible `MZ` members whose chunk is copied
raw *after* filtering) and no refusal left in that corpus. On the writer side it
rebuilds every reference archive from its inputs and demands byte equality —
`hello_none`/`empty_none`/`nested_none`, the four Normal/Compressing-Speed ones,
the five `corpus2` GUI matrices (15 members each, all five levels, up to 1 MiB),
the fourteen Priority-on-Ratio ones, the Optimized ones (including the
148-extension routing table, the two `MZ` archives and `code_normal.egg`, which
is itself Optimized), the twenty-four encrypted ones, the sixteen encrypted
volumes and the five solid trees (three m1, two m3) plus three clear split
chains (six volume files) — then reads each split chain back from its last
volume. It also asserts that the
fixtures keep supplying AZO samples that must be extracted and re-encoded, LZMA samples
that must be extracted (per-member, solid, and in the `.doc`/`.ico` Optimized
routes), BZip2 samples that must be extracted (the step fails if the corpus stops
carrying any, so the codec cannot silently lose its coverage), solid samples of
both routes that must be extracted, at least three non-ASCII members, and the
three encrypted samples - which must keep refusing a missing or wrong password
while decrypting correctly with the known one - so no coverage can silently
disappear.

The three encrypted samples no longer stop at a codec: their blocks are BZip2,
and with the codec in place `alzgg extract -p password` now decrypts *and*
decompresses them to `corpus/hello.txt` byte for byte through the normal path,
with the block CRC-32 matching. `--raw` remains as the decryption-only check
(§12.7): it writes the decrypted payload without decompressing, which is what
separates the two layers when one of them is suspected.

The bzip2, LZMA and AZO encoders are also verified on their own terms, not only
through whole archives. For bzip2 the reference sources are 474 cleartext block
payloads spread over eleven archives, and **all** of them are Optimized-route
output (`gui_optimized_matrix.egg`, `code_normal.egg`/`code_optimized.egg`, the
other `_optimized` samples, the split chains, or the encrypted samples) — the
Normal profile never emits BZip2. `src/bz2enc.c` therefore
recompresses each pair (input, ALZip stream) and demands byte equality, with the
inputs coming from Python's libbzip2 rather than from this project's decoder. For
LZMA no separate probe is needed: all 25 reference blocks are reachable through
`alzgg create` (twelve archives, the `.doc`/`.ico` routes, and both solid trees),
so the archive-level byte comparison is itself the encoder test — and it is the
comparison that pinned SDK 4.65 against 19.00. AZO has both: the whole-archive
comparison in step 9, and `src/azoenc.c` in step 10, which re-encodes the three
reference payloads (`probe.sys`, the identical `.com` one, and the two-chunk
`sysmulti.sys`) and demands byte equality — the shape that pins the 2^19 chunk
boundary and the per-chunk model reset, which a single-chunk fixture cannot.

Two read-only probes keep the derivation visible instead of stating it:
`tools/bzip2_probe.py` recompresses every cleartext reference block at each
`blockSize100k` and shows that exactly one value — the block's `hint`, 4 —
reproduces each stream, and `tools/egg_routing_probe.py` prints the per-archive
member/method/hint table that the routing statements above are read from; it
prints the GUI batch too, which is where the Normal profile's "no routing at
all" statement comes from.
