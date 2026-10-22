# alzgg (alzip alz & egg port)

> [!IMPORTANT]
> **Legal Notice & Disclaimer (Interoperability & Digital Preservation)**
>
> - **Independent Implementation**: `alzgg` is an independent pure C reimplementation developed through reverse engineering, disassembly, and protocol analysis by seb3773 for digital format preservation and interoperability.
> - **No Affiliation**: This project is completely independent and is not affiliated with, sponsored by, or endorsed by **ESTsoft Corp.**
> - **No Proprietary Binaries**: Absolutely no proprietary software, binaries, or dynamic link libraries (`.exe`, `.dll`) from ESTsoft Corp. are distributed, bundled, or included in this repository.
> - **Trademarks & Copyrights**: "ALZip", ".alz", ".egg", and related marks are trademarks or registered trademarks of ESTsoft Corp. All original proprietary assets and intellectual property remain the exclusive property of ESTsoft Corp.
> - **Legal Basis (EU & French Interoperability Laws)**: This project is developed in accordance with European Directive 2009/24/EC on the legal protection of computer programs (transposed in France into the *Code de la propriété intellectuelle*, Article L122-6-1 IV), which explicitly permits reverse engineering, decompilation, observation, and testing of software solely to achieve technical interoperability with independently created computer programs.

A from-scratch C implementation of the two ALZip container formats, **ALZ**
(`.alz`) and **EGG** (`.egg`), with both a reader and a writer. The objective is
**byte-for-byte parity** with the current reference, **ALZip 12.30**
(`ALZipCon -m0`…`-m4`): an archive this tool writes is identical to the one
12.30 writes for the same input and options, and every reference archive —
12.30's as well as ALZip 8.0's — is extracted back to the exact original bytes.
The format did not change between 8.0 and 12.30, so 8.0 archives stay readable
and 12.30 archives are readable by 8.0; only the writer's profile scale moved.

The build produces a single executable, `alzgg`, which handles both formats —
the same shape as ALZip's own console front end.

- [Format specification: ALZ](FORMAT-ALZ.md)
- [Format specification: EGG](FORMAT-EGG.md)
- [Parity scoreboard](_work/STATUS.md) — per-capability status (dev notes)
- [Fixtures and how they were produced](FIXTURES.md)
- [Roadmap and open questions](_work/PLANS.md)

## Features

**Containers**

- `list`, `extract` and `create` for both ALZ and EGG.
- Automatic format detection: by file magic (`ALZ\x01`, `EGGA`) when reading,
  by output extension (`.alz`, `.egg`) when writing; `--format alz|egg` overrides.
- Split archives (volumes chained by Split Info IDs), including the DUMMY
  padding record and reads from any volume of a chain.
- Solid EGG archives (one stream shared by all members), read and written.
- WININFO/POSIXINFO attributes, UTF-8 names, empty members and directory
  entries.

**Codecs**

| Format | Method | Read | Write |
|---|---|---|---|
| ALZ | 0 store | yes | yes |
| ALZ | 2 raw DEFLATE | yes | yes (bit-exact zlib settings) |
| EGG | 0 store | yes | yes |
| EGG | 1 raw DEFLATE | yes | yes |
| EGG | 2 bzip2 | yes | yes (bzip2 1.0.5, vendored) |
| EGG | 3 AZO | yes | yes (reverse-engineered range coder) |
| EGG | 4 LZMA | yes | yes (LZMA SDK 4.65, vendored) |

**Encryption** (EGG, and ZipCrypto for ALZ)

- ZipCrypto, AES-128/256 and LEA-128/256, read and written (LEA comes from the
  undocumented `-tp3`/`-tp4` of ALZip 12.30; see [FIXTURES.md](FIXTURES.md) lot J).
- Per-member random material can be injected with `--crypt-info` so encrypted
  archives can be compared byte for byte against their ALZip reference.

**Large members and large archives**

- Volumes are `mmap()`ed rather than copied, and every decoder writes through a
  64 KiB sink instead of filling a buffer the size of the data: store is copied
  in 1 MiB chunks, deflate/LZMA/bzip2 push their output as it is produced, and
  an ALZ volume's consumed pages are handed back to the kernel as extraction
  advances. Extracting a 128 MiB ALZ member peaks at ~17 MiB of RSS (measured),
  and a 128 MiB **solid** EGG archive extracts under 96 MiB of address space.
- `make heavy` re-extracts and rebuilds the encrypted 5 GiB EGG reference the
  same way.

## Usage

```
alzgg list    ARCHIVE
alzgg extract ARCHIVE [-d DEST] [-p PASSWORD] [--raw]
alzgg create  OUTPUT [-p PROFILE] [-s] [-v SIZE] [-T DATE[,DATE…]]
              [-m0|-m1|-m2] [-i ID[,ID…]] [--attr HEX[,HEX…]]
              [--password PASS] [--crypt zip|aes128|aes256|lea128|lea256]
              [--crypt-info HEX[,HEX…]] ENTRY...
```

On launch, `alzgg` displays its identification header:
```
alzgg (.alz/.egg)
(based on ALZip (c) ESTsoft Corp)
pure C reimplementation by seb3773
https://github.com/seb3773/alzgg
```

`alzgg` with no arguments, `-h` or `--help` prints the same summary. Exit status is
`0` on success and `2` on any refusal or error. Preflight refusals write nothing
at all, and a member that fails to decode is removed instead of being left
truncated.

### Common options

| Option | Meaning |
|---|---|
| `-d DEST` | extraction directory (default: current directory) |
| `-p`, `--password` | profile for `create`; **password** for `extract` (`-p`) and `create` (`--password`) |
| `-u`, `--unix` | format paths as Unix relative paths (`/` slashes, lowercase) |
| `-1`, `--bare` | bare output format (one path per line, ideal for scripts, `xargs`, `grep`) |
| `--raw` | write the decrypted payload without decompressing (EGG) |
| `-v SIZE` | split into volumes of `SIZE` bytes (`100KB`, `1MB`, `10MB`, … in base 1024) |
| `--format` | `alz` or `egg`, to override detection |

### Profiles

They follow **ALZipCon 12.30** exactly; the numbers are its `-m` values.

- **ALZ**: `none` (`-m0`, store), `faster` (`-m1`, zlib 1), `normal`
  (`-m2`, zlib 4, default). 12.30 no longer writes a level-2 ALZ profile: `-m3`
  exits without producing anything, so `alzgg` refuses it explicitly (and `-p
  fast`, the 8.0 level 2, with it).
- **EGG**: `none` (`-m0`), `compspeed` (`-m1`, deflate hint 2), `normal`
  (`-m2`, deflate hint 4, default), `compratio` (`-m3`, LZMA hint 8),
  `optimized` (`-m4`). 12.30 swapped `-m1`/`-m2` relative to 8.0 (which wrote
  deflate 6 / 5 / LZMA 6); the archives of both scales remain readable.

Solid-Compression accepts only `-m1` (compspeed) and `-m3` (compratio) in 12.30,
like the reference; ALZ refuses `-s` with the reference message.

EGG-only options: `-s` (Solid-Compression), `-i` (Header ID, or one ID per
volume), `--crypt` and `--crypt-info`.

### Examples

```sh
# List and extract; the format is detected from the file itself
alzgg list  backup.alz
alzgg extract backup.alz -d restored/

# List archive contents with Unix relative paths ('/' separators, lowercase)
alzgg list -u backup.alz
alzgg list -u backup.egg

# Bare listing for scripting and shell pipelines (one file per line)
alzgg list -1 -u backup.alz | grep '\.c$'
alzgg list -1u backup.egg | xargs -n1 echo "Processing"

# Write either container; the extension picks the format
alzgg create backup.alz src/ docs/
alzgg create backup.egg -p optimized src/

# A spanned EGG archive: one fixed Header ID per volume (ALZip draws them from
# a counter that cannot be reproduced), and no password (refused with -v)
alzgg create backup.egg -p normal -v 100MB -i 0x1234,0x1235 src/

# An encrypted EGG archive
alzgg create secret.egg -p normal --password s3cret --crypt aes256 src/

# Rebuild a reference archive byte for byte (fixed Header ID and crypto material)
alzgg create out.egg -p none -i 0x1234 --password s3cret \
    --crypt zip --crypt-info 00112233445566778899 files/

# LEA-256 instead of AES or ZipCrypto
alzgg create secret.egg -p optimized --password s3cret --crypt lea256 src/

# Extract an encrypted archive whose password is not ASCII
alzgg extract enc_egg_napw_euro.egg -p '€' -d out/
```

When the output is given positionally (rather than with `-o`), an existing file
is never overwritten and the output may not also be one of the inputs; `-o`
makes the intent explicit.

## Build

Requirements: a C11 compiler (gcc or clang) and a POSIX environment (the reader
uses `mmap`). There are **no external dependencies**: zlib (deflate), bzip2
1.0.5 and the LZMA SDK 4.65 are vendored under `src/`, with their licences.

```sh
./build.sh          # or 'make': builds ./alzgg (Release mode)
./build.sh debug    # builds with debug symbols
./build.sh deb      # or 'make deb': creates Debian package (.deb) in dist/
./build.sh dist     # or 'make dist': builds .deb and .tar.gz packages with SHA256 in dist/
sudo make install   # installs binary into /usr/local/bin
make clean          # removes the binary, the test tools and intermediate objects
```

## Tests

```sh
make test       # full suite (~80 s): all reference archives, both ways
make sanitize   # same suite under AddressSanitizer/UBSan/LeakSanitizer
make heavy      # opt-in: 5 GiB encrypted EGG member (~15 GiB of temp space)
```

`make test` decodes the whole 8.0 corpus and the 12.30 lot K, rebuilds the 12.30
references byte for byte (ALZ store/levels 1 and 4 + a volume chain; EGG
`-m0`…`-m4`, solid, AZO and encrypted archives), checks the codec encoders
against reference blocks, exercises the encrypted paths in both directions,
injects 26 malformed archives (no crash, no signal, no file written, path
traversal included) and extracts a 128 MiB member under a 320 MiB address-space
limit to keep the streaming reader honest. The helpers it needs
(`tests/bin/bz2enc`, `tests/bin/azoenc`, `tests/bin/leatv`) are built into
`tests/bin/`, not next to `alzgg`.

`make heavy` needs the `corpus/huge/` inputs; it rebuilds the 5 GiB encrypted
archive byte for byte, re-extracts it, and rejects a wrong password.

Regenerating the references themselves is a separate, Wine-only path.
`fixtures/build-12.30.sh` rewrites the 55 archives of the writer contract through
`tools/alz_oracle.sh` (using ALZip 12.30 if placed under `_work/binaries/alzip-12.30`), and
`fixtures/lot-k.sh` replays the set K commands and compares each result with the
checked-in reference — byte for byte outside the DOS timestamps, the random
Header ID and the crypto material, and member by member for the encrypted
archives. On the 8.0 side, `fixtures/build-fixtures.py` produces the whole
reader corpus (sets A–D, G and H) with the console build if placed under `_work/binaries/alzip-8.0`.
All three are developer aids, outside `make test` because they need Wine and optional external binaries.
`tools/egg_oracle.sh` still drives the 8.0 install for one-off commands.

## Fixtures under Wine

The 8.0 references are produced by `ALZipCon.exe` 8.0.0.18. It is Windows-only,
but runs unmodified under Wine, so the whole fixture pipeline is reproducible on
Linux. `fixtures/build-fixtures.py` is the single entry point (it replaced the
three PowerShell scripts that had to run on a Windows machine); it needs Python
3 and only the standard library:

```sh
fixtures/build-fixtures.py --help
fixtures/build-fixtures.py                          # every set (needs ~25 GiB)
fixtures/build-fixtures.py --only a,b,d,g           # the fast sets (~4 min)
fixtures/build-fixtures.py --only h --only-h span,crypt
fixtures/build-fixtures.py --skip-huge              # without the 5 GiB members
```

Sets: `a` encryption, `b` ALZ encryption + non-ASCII names, `c` large members and
volumes, `d` metadata, `g` AZO samples, `h` writer edge cases (`huge`, `span`,
`solid`, `crypt`, `names`, `edges`). There is no set `e`: its method-routing
matrix was deleted from the corpus (the table is replayed from
`packed_egg/routes_optimized.egg` and `packed_egg_8.0/gui_normal_matrix.egg`),
so regenerating it would only create archives no test can consume. At the end of
a run the script checks that every archive file it wrote has a twin in
`packed_egg_8.0/` or `packed_alz_8.0/` (volumes included, a chain is only a
fixture if the corpus has all of it), and fails otherwise (`--no-verify` skips
the check); commands whose outcome is the reference (a refusal, a no-op, an
archive written by an option the writer does not implement) are probes, and the
last kind is printed and discarded. Inputs are staged
under `fixtures/out/<set>/`, the archives land next to them, and every ALZipCon
call is printed with its own output.

That check is about existence; content parity is
`tools/fixture_parity.py`'s job. It compares a regenerated tree with the corpus
member by member (base name, uncompressed size, CRC-32, container method and
block hint, DOS attributes with the Wine-only `0x20` bit cleared), using
`tools/egg_dump.py` for EGG and `./alzgg list` for ALZ, so the random Header ID,
the FILETIMEs of the staging copy and the crypto material do not matter:

```sh
fixtures/build-fixtures.py --only a,b,d,g
make alzgg && tools/fixture_parity.py
```

The script owns its Wine environment, so nothing has to be installed system-wide
beyond Wine itself:

```
out/oracle-8/prefix/    WINEPREFIX, created by Wine on the first run
out/oracle-8/install/   copy of the ALZip 8.0 tree (once)
fixtures/out/<set>/     staged inputs and the archives they produced
```

On the first run Wine boots the prefix (~15 s, a few hundred MB), then a `y:`
drive is created inside it that points at the repository root, and the install
tree is copied once. The Windows side therefore sees the checkout as `Y:\`,
which is why the staged paths in the script are written `Y:\fixtures\out\...`.
`--work DIR` moves the prefix and the install copy, `--install DIR` selects
another ALZip 8.0 tree, and `--out DIR` another staging root. Only `--out` must
stay inside the repository (its paths become archive member names); the other two
accept any location.

### Installing Wine

Wine 8 or newer is enough; the script is tested with wine-11.0 on Linux. Install
it with the distribution's package manager:

```sh
sudo apt install wine          # Debian/Ubuntu
sudo dnf install wine          # Fedora
sudo pacman -S wine            # Arch
```

`ALZipCon.exe` is a 32-bit binary. Recent Wine runs those inside a 64-bit prefix
through WoW64; on a distribution that still splits the packages, also install the
32-bit runtime (`wine32`/`wine-stable-i386`), otherwise the console build exits
without doing anything. `wine --version` must print a version, and
`wine wineboot -i` must be able to create a prefix — the script does that for
you. On a Wine older than 9, which has no WoW64, create the prefix as 32-bit
instead: export `WINEARCH=win32` before the first run (the script keeps the
prefix it finds and passes the environment through).

### Setting the prefix up by hand

The script is a thin wrapper; the same environment can be driven directly.
`tools/alz_oracle.sh -r 8` does exactly that for one-off commands (it shares the
work area, `out/oracle-8/`); `tools/egg_oracle.sh` is the older helper and uses
`/tmp/azowine`:

```sh
export WINEPREFIX="$PWD/out/oracle-8/prefix"   # must be an absolute path
wine wineboot -i                              # creates the prefix (first time)
ln -sfn "$PWD" "$WINEPREFIX/dosdevices/y:"    # the checkout as Y:\
cp -a "_work/binaries/alzip-8.0" out/oracle-8/install

cd out/oracle-8/install
WINEDEBUG=-all WINEDLLOVERRIDES='mscoree,mshtml=' \
    wine ALZipCon.exe -a -m1 'Y:\corpus\hello.txt' 'Y:\fixtures\out\hello.egg'
```

`WINEDEBUG=-all` silences the fixme trace, and `WINEDLLOVERRIDES=mscoree,mshtml=`
keeps Wine from offering to install Mono/Gecko in a console build that needs
neither. Both are disposable: stop any Wine process using the prefix, delete
`out/oracle-8/` (the prefix and the install copy) or `fixtures/out/` (the staged
inputs and the archives) and rerun the script; no ALZip state is stored anywhere
else.

Two things are environment-dependent and are expected to differ from the
checked-in references: Wine reports `FILE_ATTRIBUTE_ARCHIVE` on every regular
file, which the 8.0 ALZ writer stores (`attr=0x20`, where the Windows-produced
references have `0x00`; the EGG writer filters it), and a Korean member name is
only stored as such if the prefix runs under the Korean ANSI code page — the
script skips `names_korean_m1.egg` unless `FIXTURE_ACP=949` is set. Wine also
returns 0 for the `-v10MB` probe that Windows refused with 1: the first volume it
writes is the same 175 bytes as the reference, so the script records the file and
not the status.

## Layout

```
src/alz.c          single-binary router (ALZ vs EGG, format detection)
src/cli_alz.c      ALZ front end: list / extract / create
src/cli_egg.c      EGG front end: list / extract / create
src/egg.c          EGG reader (container, blocks, volumes, extraction)
src/egg_w.c        EGG writer
src/egg_crypt.c    ZipCrypto, AES-128/256, LEA-128/256, PBKDF2, password encoding
src/egg_lea.c      LEA block cipher (KS X 3246)
src/egg_azo.c      AZO codec (decoder + encoder)
src/egg_bzip2.c    bzip2 adapter  (src/bzip2_dec/, bzip2 1.0.5)
src/egg_lzma.c     LZMA adapter   (src/lzma_sdk/, LZMA SDK 4.65)
src/alz.h          ALZ container constants and record structs
src/alz_inflate.c  raw DEFLATE decoder
src/zlib_deflate/  zlib, vendored for the ALZ encoder
tests/             test suite and opt-in heavy check
tools/             independent parsers and oracle helpers
_work/binaries/    (optional, git-ignored) local reference installs for Wine oracles
FORMAT-ALZ.md      ALZ container specification
FORMAT-EGG.md      EGG container specification
FIXTURES.md        every reference archive, and how it was produced
_work/             development notes: parity scoreboard, roadmap
corpus/            every input: sources, nested trees, 5 GiB samples
```

## Corpus layout

The checkout has one input tree and four reference directories, nothing else:

```
corpus/            inputs (and the 8.0 password prototypes kept for the reader)
packed_egg/        12.30 EGG references — the writer contract, 63 archives
packed_alz/        12.30 ALZ references — the writer contract, 20 archives
packed_egg_8.0/    8.0 EGG references — decoding coverage, 247 archives
packed_alz_8.0/    8.0 ALZ references — decoding coverage, 86 archives (135 files with volumes)
fixtures/          the scripts that produced them, plus corpus-12.30.manifest
_work/             development notes: parity scoreboard, roadmap, open points
```

Nothing else is needed to build or to run the suite: `fixtures/inputs/` (a copy
of the old 8.0 staging tree) was removed once `corpus/` became the single input
tree, and `fixtures/` now holds only the 12.30 manifest — which `make test`
reads — and the regeneration scripts (`build-12.30.sh`, `lot-k.sh`,
`build-fixtures.py`), which need Wine and an ALZip install and are therefore
outside the suite.

`fixtures/corpus-12.30.manifest` lists the 55 lines (13 ALZ, 42 EGG) that make
up the writer contract; `tools/manifest_parity.py`, run as step 13 of
`make test`, replays every one of them and fails if a reference is missing or
no longer reproduced byte for byte. Archives produced by ALZip 8.0 are never a
writer target: they stay as decoding references, and the differences the two
builds have (deflate levels, the `ace` entry of the store list, ALZ attributes)
are documented in FORMAT-EGG.md and FORMAT-ALZ.md.

## Scope

The target is **exact parity with ALZip**, not a compatible approximation.
ALZip 12.30 is the writer reference: for the same input and options, the
archive this project writes is byte-for-byte the 12.30 archive, except the
salt/IV material ALZip itself draws at random on every run. ALZip 8.0 and 12.30
are both reader references — the format did not change between them, each build
extracts the other's archives — so every archive either build has produced is
read and extracted with identical metadata.

Refusing what ALZip cannot produce is part of that parity, not a gap. The CLI
rejects, with ALZip's own message where the build has one, and writes nothing:

- ALZ container methods 1 and 3 — no ALZ profile writes them;
- ALZ `-m3` / `-p fast` — 12.30 writes nothing for it, and the 8.0 level-2
  profile it used to select has no 12.30 equivalent;
- solid mode outside EGG `-m1`/`-m3`, solid combined with spanning or a
  password, and `-s` on ALZ.

The 8.0-only streams (ALZ level 2, EGG deflate hints 6/5) are equally a
consequence of that choice: they are decoded, and they are reproducible from
their own build with `tools/alz_oracle.sh -r 8`, but the writer emits the 12.30
scale only. Features **neither** build can emit (archive and per-file comments,
encrypted member names, POSIX_INFO) stay out of scope until a reference exists.

See the [parity scoreboard](_work/STATUS.md) for the per-feature state, and
[FORMAT-ALZ.md](FORMAT-ALZ.md) / [FORMAT-EGG.md](FORMAT-EGG.md)
for the formats themselves.

## Implementation notes (no effect on archive bytes)

- Solid EGG archives are written **as the stream is decoded**: members are
  created in archive order and the per-block CRC is checked on each slice as it
  goes, so a failed CRC removes the files already written and leaves nothing
  behind. Only the **compressed** stream is held in memory (usually tiny), not
  the decompressed one — the bytes written are those ALZip writes.
- AZO inside a solid archive is the one buffered codec; ALZip cannot produce
  that combination (AZO is Optimized-only, solid is not), so it exists only to
  read a third-party stream rather than refuse it.
- A compressed member's input is read from the mapping when it lies in one
  volume (the common case); members split across volumes are reassembled in
  memory first, as ALZ requires.

## Path Traversal & Zip-Slip Protection

- All extraction paths (both ALZ and EGG) are strictly validated with `is_safe_relpath()`.
- Prevents directory traversal attacks by continuously tracking directory nesting depth: any attempt to ascend above the destination root via `../` (or `..\`) is intercepted and safely rejected with a security warning (`Security warning: skipping unsafe path traversal`).
- Rejects leading absolute slashes (`/`, `\`) and DOS drive identifiers (`C:`).
- Automatically sanitizes and normalizes historical DOS backslashes to forward slashes `/` on POSIX systems.

## Licence

Project code is provided as-is for digital format preservation and interoperability purposes under European Directive 2009/24/EC and French CPI Article L122-6-1 IV. Pure C implementation by seb3773. All original ALZip trademarks and copyrights remain the exclusive property of ESTsoft Corp.

The open-source vendored components keep their own licences: zlib (`src/zlib_deflate/`), bzip2 1.0.5 (`src/bzip2_dec/`) and the LZMA SDK 4.65 (`src/lzma_sdk/README.txt`).
