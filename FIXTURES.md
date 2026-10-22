# Fixtures to generate with ALZip 8.0.0.18

This is a work order for the reference material that **cannot be derived from the
bytes already in this checkout**. The **writer** reference is **ALZip 12.30**
(lot K, below): its `-m` scale is the one the encoder reproduces byte for byte.
The 8.0.0.18 material stays the **reader** corpus, and lot J/Lot K extend it
where 8.0 could not write.

## Layout of the checkout (after the consolidation)

The lots below name the staging directories the fixtures were produced in
(`fixtures/out/lot-*`, `corpus2/`, `corpus_probe/`, `packed_corpus/`,
`packed_corpus2/`). Those directories no longer exist; everything lives in six
places, and the prose keeps the lot names only as provenance:

| Produced in | Now stored in |
|---|---|
| `fixtures/out/lot-b`, `-c`, `-d`, `-g`, `-h` (archives) | `packed_egg_8.0/` or `packed_alz_8.0/`, 8.0 references |
| `fixtures/out/lot-j`, `-k` (archives) | `packed_egg/` or `packed_alz/`, 12.30 references |
| `fixtures/out/lot-*` (inputs, `nested/…`, `two/…`, `meta/…`) | `corpus/` (see the mapping table below) |
| `corpus2/`, `corpus_probe/` (sources) | `corpus/` |
| `packed_corpus/` | `packed_alz_8.0/` |
| `packed_corpus2/` | `packed_egg_8.0/` |

`fixtures/out/lot-e` (224 routing probes) was deleted: its whole table is
covered by `packed_egg/routes_optimized.egg` (148 members, 12.30) and
`packed_egg_8.0/routes_optimized.egg`, replayed member by member in `make test`.
The 55 lines of `fixtures/corpus-12.30.manifest` are replayed one by one by
`tools/manifest_parity.py` (step 13), which stages each input tree from the
reference itself, so a lost or renamed reference fails instead of skipping.

Rule applied throughout: nothing is implemented from speculation while its
reference is outstanding, and nothing is requested that this project can obtain
or already holds.

---

## 0. Already held — do not produce these again

| Capability | Reference material in this checkout |
|---|---|
| ALZ profiles (No Compression, Faster, Fast, Normal) × 13 inputs | `packed_alz_8.0/` (86 archives; 135 files with the volume chains) |
| EGG profiles (all five) × 15 inputs | `packed_egg_8.0/` (247 archives) plus the 12.30 contract in `packed_egg/` (63 archives); the GUI batch is `packed_egg_8.0/gui_*_matrix.egg` with its inputs in `corpus/` (six archives, 65 B to 1 MiB each, all five levels) |
| EGG AZO (method 3) | `packed_egg/probe_sys_optimized.egg` + input `corpus/probe.sys` (method 3, hint 1, CRC `5d2395c9`); `packed_egg/probe_com_optimized.egg` (the same payload behind a `.com` name, so the `.com` route is pinned; its input is `probe.sys` copied to `probe.com`) and `packed_egg_8.0/sysmulti_sys_optimized.egg` (input `sysmulti.sys` = `corpus/code.c` repeated 14 times, 633,780 bytes, CRC `4c9b06cc`, two internal chunks of 2^19); `packed_egg_8.0/mz_sys_optimized.egg` (input `mz.sys` = the build's own `Coders/Deflate.dll`, 73,560 bytes, x86 filter flag `31 01`) and `packed_egg_8.0/mzmulti_sys_optimized.egg` (`mzmulti.sys` = `ALZipCon.exe`, 594,264 bytes, flag `31 01`, two chunks, the second not starting with `MZ`), and the **copied-chunk** pair `packed_egg_8.0/mzraw_sys_optimized.egg` (`mzraw.sys` = `MZ` + 524,286 PRNG bytes, one raw chunk) and `packed_egg_8.0/mzraw2_sys_optimized.egg` (`mzraw2.sys`, 1 MiB, two raw chunks) — these two show the filter runs *before* the copy decision. The six extra archives were produced by the local Wine oracle (A.15) and their inputs are *derived* rather than stored — `make test` rebuilds them from the recipes |
| EGG BZip2 (method 2) | 8 blocks in `packed_egg/`, 1 in `packed_egg_8.0/probe_java_optimized.egg`, 420 in each `splitmany_optimized` volume |
| EGG LZMA (method 4) | 22 blocks in `packed_egg/` + `probe_doc/ico_optimized.egg`, `unicode_compratio_solid.egg` |
| EGG split: 2 and 3 volumes, DUMMY padding | `packed_egg_8.0/records_optimized.vol1/2.egg`; `packed_egg_8.0/splitmany_normal.vol1/2/3.egg` and `..._optimized...` (420 members each; the corpus's only DUMMY record is in `splitmany_normal.vol2.egg`), plus the 12.30 split contract `packed_egg/egg_m1_records_v100k.vol1/2.egg` and `packed_egg/records_compspeed_v100k{,_zip}.vol1/2.egg` |
| EGG solid | `nested_normal_solid.egg`, `nested_compratio_solid.egg`, `unicode_normal_solid.egg`, `unicode_compratio_solid.egg` (the Normal and Priority-on-Ratio profiles only, as the reference restricts `-s` to `-m1`/`-m3`; no solid fixture exists or can exist for ALZ, and none for EGG's other profiles), plus `solid_normal_code.egg` (`ALZipCon -m1 -s` over `hello.txt` + `code.c`: one Deflate hint 6 block, a `.c` inside a solid stream) |
| EGG encryption, all three methods | `packed_egg/hello_optimized_password_{zip2,aes128,aes256}.egg`, all three under the passphrase **`password`**; decryption is verified byte for byte (FORMAT-EGG.md §12.7) and `make test` uses the passphrase (step 8) |
| EGG non-ASCII names (Korean + accented, nested) | `packed_egg/unicode_normal.egg` (+ solid variants) with reference files under `corpus/unicode/` |
| EGG extension routing probe (10 extensions × 2 profiles) | `packed_egg_8.0/probe_{1st,cc,doc,ico,java,jpg,pas,sys,xml,zip}*_*.egg` + `text_contenu_*` + `normal_r525…r592` |
| Empty-archive template | `Formats/NewEgg.dat` of the installed build (22 bytes) |

Two codec sources are public and are obtained by this project, so they are **not**
a fixture request: BZip2 1.0.5 (for EGG method 2) and the LZMA SDK (method 4).

ALZip is Windows-only, but its console build runs unmodified under Wine, so
anything below is produced locally: `fixtures/build-fixtures.py` drives the 8.0
install (README, "Fixtures under Wine" records the prefix setup). The option
grammar is quoted from `con_en-US.dll` of the reference build, including the
three rules that decide whether a command runs at all:

```
Command: ALZipCon.exe <argument> <option N> <files...> <files...>

Instructions:
1. Add to archive: ALZip -a <option> <file list> <archive name>
2. To extract archive: ALZip -x <option> <file list> <location>
3. To restore archive: ALZip -r <option> <archive name>
4. To create exe file: ALZip -sfx <archive name> <filename to create>
5. Check for Error: ALZip -t <option> <archive name>
6. View Files in Archive: ALZip -l <archive name>
Possible archive formats are EGG, ALZ, ZIP, LZH, TAR and JAR.

<options>
1. Compression options
 -an     Add to archive excluding the file. You can use wildcards such as '*', '?'.
         ex) -an*.alz;"..\ALZipTest.*"
 -v      Set size to span into. Input is in bytes, and you can use units such as KB, MB
         and so on. Cannot use in formats that doesn't support spanning archive.
         ex) -v100KB
 -m      Select compression method. 0 : No compression. Higher number leads to
         higher compression ratio.  ALZ 1~3   EGG 1~4 (4 : Optimized Compression)
         ZIP 1~4   LZH 1
 -sfx    Create self-extractor (EXE file)
 -af     Compress including entire path
 -xr     Compress excluding sub folders
 -t      Check for errors after compression
 -d      Delete original files after compression
 -tp     Select encryption method. Can enter from 0 to 2. Default is 0.
         0: Basic encryption, 1: 128bit AES encryption, 2: 256bit AES encryption
         ZIP,EGG  0~2      ALZ  0
 -s      Compress with Solid-Compression method.
         ATTN: Solid-Compression doesn't support spanning archive or encryption.
         In addition, it can only be used in EGG file archive.
2. Extraction options
 -xn     Extract only selected files (same instruction as '-an').
 -xf     Extract without using folder name.
 -oa     Overwrite all duplicate files.
 -os     Skip all duplicate files.
 -on     Overwrite all duplicate files if extracting file is newer.
 -oo     Overwrite all duplicate files if extracting file is older.
3. Common Compression/Extraction options
 -p      Set password          ex) -pPassword
 -b      Execute other tasks first.
4. Restoration options
 -f      Set file format of restored file. 0: EGG, 1: ALZ, 2: ZIP
5. SFX options
 -p      Set password          ex) -pPassword
 -tp     Set encryption method. Can set from 0 to 2, and default is 0.
6. Common options
 -nq     Overwrite duplicate files without asking.

<ATTN>
 If setting multiple files, distinguish files using comma (,).
 If file includes spaces, double quotation the file.
 Option and option's value should have no space between them.
 Options must have space between each.
```

The help text says `ALZip` because `ALZip.exe` shares that console front-end;
`ALZipCon.exe` is the same command with the same options.

| Option | Meaning |
|---|---|
| `-m<N>` | compression method: `0` = No compression for every format; ALZ `1~3`; EGG `1~4` (`4` = Optimized Compression, and FORMAT-EGG.md §14.1 derives `1` = Normal, `2` = Priority on Compressing Speed, `3` = Priority on Compress Ratio from the `-s` error text - the fixtures below are also what confirms that mapping, so state the number you used); ZIP `1~4` |
| `-tp<N>` | encryption: `0` = Basic (ZipCrypto), `1` = 128-bit AES, `2` = 256-bit AES; ZIP and EGG accept `0~2`, **ALZ accepts only `0`** |
| `-pPASSWORD` | password, value attached |
| `-v<SIZE>` | size to span into, e.g. `-v100KB` (only in formats that support spanning) |
| `-s` | Solid-Compression: EGG only, `-m1`/`-m3` only, incompatible with spanning and with a password (FORMAT-EGG.md §14.1) |
| `-af` | compress including the entire path |
| `-xr` | compress excluding sub folders |
| `-an<pattern>` | add excluding files; patterns separated by `;`, wildcards `*` and `?` (e.g. `-an*.alz;"..\ALZipTest.*"`) |
| `-xr` / `-sfx` | exclude sub folders / create a self-extractor |
| `-d` | delete the original files after compression |
| `-t` | check the archive for errors after compression (also an argument: `ALZip -t <option> <archive>`) |
| `-xn<pattern>` / `-xf` | extract only the selected files / extract without the folder name |
| `-oa` / `-os` / `-on` / `-oo` | overwrite all / skip all / overwrite if newer / overwrite if older |
| `-nq` | overwrite duplicates without asking |
| `-b` | run other tasks first |
| `-f<N>` | format of a restored file: `0` EGG, `1` ALZ, `2` ZIP (restoration) |

The value is glued to its option (`-m2`, `-tp1`, `-ppassword`, `-v100KB`),
options are separated by spaces, and **several inputs are a single
comma-separated argument** - not several arguments:

```
ALZipCon.exe -a -m2 -tp1 -ppassword hello.txt,records.bin  enc_twofiles_aes128.egg
```

Deliver each archive **together with the exact input file** (same folder). The
input bytes and its timestamp are what let a re-encoding be verified byte for
byte. Keep source timestamps intact (a plain copy preserves them) and record the
machine time zone (`tzutil /g`) — EGG and ALZ both store the file's *local* wall
clock, in fields documented as UTC.

---

## Producing these fixtures from the GUI

The GUI exposes the same options, and it is the practical path when several
members have to land in one archive (a comma-separated input list is easy to get
wrong in a shell). Its labels, from `en-US.dll` of the reference build:

1. Select the inputs, right-click, **Compress in ALZip** — or **Add to Current
   Archive** when an archive is already open — then set the archive name in the
   dialog's path field.
2. **Method** (the profile list of the compression dialog, in the order the
   GUI shows it, exact spelling): EGG `No compression`, `Normal compression`,
   `Priority on compressing speed`, `Priority on compress ratio`,
   `Optimized compression`; ALZ `Normal`, `Fast`, `Faster`, `No compression`.
   Note the two lists are ordered differently and do not share their wording.
   The dialog also has the `Compressed Size` / `Compression Ratio` read-outs, so
   the profile a fixture used can be recorded from there. Mapping to the
   project's own options: EGG `-p none|normal|compspeed|compratio|optimized`
   (= `-m0`…`-m4`, FORMAT-EGG §14.1); ALZ `-p normal|fast|faster|none`. For ALZ
   only `-m0` (No compression) is pinned: which CLI number selects `Faster`,
   `Fast` and `Normal` is still open — the lot H script wrote the `alz_normal_*`
   references with `-m3`, but no label was recorded alongside them, so the
   ALZ number → label mapping is lot E's remaining question.
3. **Solid Compression**: the `-s` switch. Ticking it leaves only `Normal` and
   `Priority on Compress Ratio` selectable and disables **Span Archive** and the
   password fields, exactly as FORMAT-EGG.md §14.1 records.
4. **Span Archive** plus **Spanned Size**: the `-v` pair.
5. **Set Password** ("Set Password to:"): the `-p` option.
6. Leave **Delete Source File after Spanned** unticked and do not use `-d`: each
   archive has to be delivered together with its inputs.

One GUI-side restriction that is easy to miss when composing Lot B: ALZip
refuses a **Korean password** outright ("Cannot set password in Korean."), so an
encrypted archive with a Korean *member name* has to use an ASCII password.

---

## Lot A — EGG encryption (**closed**: six archives, all byte-exact)

The passphrase of the three password samples is **`password`** (supplied by the
maintainer). Decryption is implemented and the three samples are verified byte for byte
(FORMAT-EGG.md §12.7). The gap this lot was created for — **two members under
one passphrase** — is closed: §12.3 says the ZipCrypto keys are restored to
their post-password state before each file and the new file's 12-byte verify
data is decrypted again, so re-seeding per member and continuing the stream
produce different ciphertext for the second member. The three two-member
archives below (and their store/deflate single-member siblings) are reproduced
byte for byte by `alz create` in step 9.

```
ALZipCon.exe -a -m1 -tp0 -ppassword hello.txt,records.bin            enc_twofiles_basic.egg
ALZipCon.exe -a -m1 -tp2 -ppassword hello.txt,records.bin            enc_twofiles_aes256.egg
```

From the GUI, each of those is one dialog: profile `Normal`, **Set Password**,
and select both inputs before compressing.

An encrypted member whose codec is *not* BZip2 — store (`-m0`) or deflate
(`-m1`) — was also requested here. It now exists: `enc_store_basic.egg`
(ZipCrypto over Store) and `enc_deflate_aes128/256.egg` (the two AES methods over
Deflate) are reproduced byte for byte, so the decryptor is exercised behind
three different codecs and not only behind BZip2.

---

## Lot B — ALZ encryption (no reference at all)

The ALZ plugin advertises only `Zip 2.0 Compatible` (`-tp0`), so only that
method is in scope, and ALZ accepts no other value (its row in the CLI help is
`ALZ 0`). **Delivered**: the commands below produced `enc_basic.alz`,
`enc_basic_split.alz` + `.a00`, `enc_basic_paths.alz` and
`unicode_basic_encrypted.alz`, now checked in under `packed_alz_8.0/` and
used by `make test` for byte-exact writer parity and decode coverage. What is
still missing from this lot is only the reference *output* for a wrong password
(see the end of the section) and the role of the `ELZ` signature.

```
ALZipCon.exe -a -tp0 -psecret hello.txt             enc_basic.alz
ALZipCon.exe -a -tp0 -psecret -v100KB records.bin   enc_basic_split.alz
ALZipCon.exe -a -tp0 -psecret -af nested\           enc_basic_paths.alz
ALZipCon.exe -a -m1 -af 갈대숲,café_clair           unicode_basic.alz
ALZipCon.exe -a -tp0 -psecret -af 갈대숲,café_clair unicode_basic_encrypted.alz
```

**No non-ASCII file has to be created**: the inputs already exist in this
checkout, and they are the very tree the EGG references were built from, so
archiving the same tree as ALZ gives a directly comparable pair. Run the last two
commands **from inside `corpus/unicode/`** (`cd corpus\unicode`) so the
member names come out exactly as the EGG side stores them:

| Input in this checkout | Names it carries |
|---|---|
| `corpus/unicode/갈대숲/텍스트.txt` | 3 Hangul syllables in a folder name, 3 in the file name |
| `corpus/unicode/café_clair/menu_é.txt` | `é` in the folder name and in the file name |
| `corpus/unicode/café_clair/ nested/deep_ñ.txt` | a folder name that starts with a **space**, plus `ñ` |

`unicode_normal.egg` and `unicode_compratio_solid.egg` store exactly
`갈대숲/텍스트.txt`, `café_clair/menu_é.txt` and
`café_clair/ nested/deep_ñ.txt`, which is what the ALZ archive has to reproduce.
If a transfer mangles the names (a zip written with the wrong code page will),
restore the three files under `corpus/unicode/` in place before running the
fixtures: `fixtures/build-fixtures.py` checks them and stops with the list of
missing names rather than archiving `?`. Their bytes matter, not just the names
- byte-identical contents are what let the ALZ archive and
`packed_egg/unicode_normal.egg` be compared member by member.

The passwords stay **ASCII**: ALZip answers "Cannot set password in Korean." to a
Korean one, so the non-ASCII case has to be a *member name* under an ASCII
password — which is exactly what the encrypted variant above pins down, along
with the order of name-encoding versus encryption and the role of the `ELZ`
signature. Still to collect: the exact **failure output** when extracting
`enc_basic.alz` with a wrong password (what the GUI/CLI prints); the port has its
own message (`incorrect password`), and the reference text is not needed for
parity of the archive bytes.

---

## Lot C — large members and the block-splitting threshold

Every non-solid EGG sample in this checkout has **exactly one block per member**
(the solid samples instead carry a single block, attached to the last member,
holding the whole stream) and at most 240 000 bytes, so ALZip's block-splitting
threshold is unknown, and
no ALZ member exercises the 8-byte (`fd = 0x80`) size fields (largest ALZ input
here: 240 000 bytes).

1. EGG, Normal (`-m1`) and Optimized (`-m4`), for payloads of **~4 MiB, ~50 MiB
   and ~1 GiB** (zero-filled files are fine and cheap): this shows whether and
   where ALZip starts emitting multiple blocks per member, and what each block's
   `usize` is.
2. EGG, one **~5 GiB** zero-filled member (Normal), to check 64-bit sizes and the
   "larger inputs get several blocks" rule.
3. ALZ, one member **> 4 GiB** (zeros) and one between 4 MiB and 200 MiB, to
   exercise the 8-byte size fields and the volume/number edge cases.
4. Volume edge cases: `-v100KB` and `-v1MB` for both formats, plus one EGG split
   with **≥ 4 volumes**, and ideally a member whose header lands exactly on a
   volume boundary. (Not `-v10KB`: on the reference build that exits 0 and
   writes nothing - see Lot H, "What the first Windows run already showed" - so
   the two `-v10KB` calls in `fixtures/build-fixtures.py` (lot C) cannot have produced
   a file on this build, so `egg_span10k_64k`/`alz_span10k_64k` are worth
   checking for before relying on them.)
5. **Solid streams that are not a single block** (the only solid fixtures that
   can still be requested, because solid mode admits only `-m1`/`-m3` and
   forbids spanning and passwords - see `FORMAT-EGG.md` §14.1): the five solid
   samples held here each carry **one** block for the whole stream, so
   multi-block solid placement is inferred, not observed. Cases: `-s -m1` over a
   ~50 MiB and a ~1 GiB payload (does ALZip split the stream into several
   blocks, and does each block's CRC stay per-slice?), and a store/Deflate
   member above 3 GiB. There is no BZip2 question left: solid `-m1` is Deflate
   hint 6 for every member (`solid_normal_code.egg`), and BZip2 only exists
   under Optimized, which solid mode cannot select.

---

## Lot D — ALZ metadata and paths (EGG equivalents already exist)

All **92 members of the 62 ALZ archives** in this checkout have `attr = 0` and an
ASCII name, while the EGG side already has Korean and accented names
(`packed_egg/unicode_*.egg`). So CP949 versus UTF-8 for ALZ names cannot be
answered from the corpus at all. Missing on the ALZ side:

- a **Korean (CP949) filename** and an **accented filename**;
- an explicit **empty directory**, and nested `dir\sub\file.txt` paths (`-af`);
- files marked **read-only, hidden and system**;
- timestamps with an odd second (`:05`), an even second (`:06`), a pre-1980 date
  and a 2038+ date:

```sh
python3 -c "import os,time; p='probe/meta/a.txt'; \
  t=time.mktime(time.strptime('2001-02-03 04:05:06','%Y-%m-%d %H:%M:%S')); \
  os.utime(p,(t,t))"
```

Produce the same folder once as ALZ (`-m1`, `-m2` and `-m3` — that also pins the
CLI number → `Faster`/`Fast`/`Normal` label mapping, which is still unestablished
here) and once as EGG (`-m0` for the no-compression case, `-m1` Normal, `-m4`
Optimized).

---

## Lot E — the method-routing matrix (**closed**)

The whole lot is closed: its 224 probes were deleted from the corpus (see the
layout table above) and `fixtures/build-fixtures.py` no longer regenerates them.
The EGG routing table is replayed from `packed_egg/routes_optimized.egg` and
`packed_egg_8.0/gui_normal_matrix.egg`; the ALZ profiles are held by the 13
inputs × 4 profiles of `packed_alz_8.0/`, and the 12.30 `-m` scale (`-m1` = zlib
level 1, `-m2` = level 4, `-m3` writes nothing) is the writer contract that
`make test` checks (FORMAT-ALZ). Producing this matrix again would create
archives with no reference and no consumer.

The EGG side is closed and this lot is no longer needed for it. Optimized was
settled by the Wine oracle's 148-member `-m4` archive
(`packed_egg/routes_optimized.egg`, reproduced byte for byte, FORMAT-EGG
§11.0), and Normal by the lot I GUI run: **Deflate hint 6 for every member, no
extension routing at all** (`packed_egg_8.0/gui_normal_matrix.egg`, fifteen
members). The plugin's own profile table said the same (`Normal` → Deflate 6 +
Store). The `code_normal.egg` archive that had suggested a `.c` → BZip2 route is
an Optimized archive with a different `header_id`.

The **ALZ** side that was still asked here was answered without a matrix: the
13 inputs × 4 profiles of `packed_alz_8.0/` already pin what an ALZ profile
writes, and the number→profile scale belongs to the **12.30** writer contract
(FORMAT-ALZ: `-m1` = zlib level 1, `-m2` = level 4, `-m3` exits 0 without
writing), not to the 8.0 reader corpus. The 16-extension × 7-profile loop that
the first version of the script ran (224 archives under `packed_egg_8.0/` and
`packed_alz_8.0/`) was therefore removed: those archives had no consumer, and
they duplicated routes_optimized.egg / gui_normal_matrix.egg. `--only e` now
exits with that explanation.

---

## Lot F — verification loop (Windows side, no archive to send)

Byte exactness is **not** a Windows question. Every archive in the corpus was
produced from a known input with recorded options, so the writer is checked
here by re-encoding those inputs and comparing the result with the reference
byte for byte (`tests/run_tests.sh`, step 9, for EGG, and the store/deflate
section for ALZ). A closed flow of `out\` / `inputs\` from lot H extends that
same check to the new cases as soon as the files arrive.

What Windows adds is only what the corpus does not contain:

1. **Acceptance** — ALZip opens, lists, extracts and `-t`-checks archives this
   project writes for inputs no reference used, which rules out a stream that is
   self-consistent but not ALZip-compatible.
2. **Behaviour** — the refusal messages and edge cases of lot H, which exist
   only in the reference build.

So this lot complements a check that already runs here; it is not the only way
to turn the writer from "self-consistent" into "ALZip-compatible".

---

## Lot G — AZO samples for the encoder (**closed**: the encoder is done)

**Outcome of the first run:** the four requested archives arrived, and they
settled the routing question the wrong way for the request's premise — at `-m4`
this build routes `.dll`, `.exe` and `.bin` payloads to **deflate hint 5**, not
to AZO. Only `.sys` and `.com` produce method-3 blocks (verified locally: the
reference `ALZipCon.exe` runs under Wine and reproduces
`probe_sys_optimized.egg` byte for byte, so `.sys`/`.com` references can be
generated on the Linux side — see FORMAT-EGG.md A.15, "A local reference
producer (Wine)"). No further Windows request was needed: the oracle plus
`tools/azo_trace.py` supplied the references and symbol streams the encoder
work required.

The lot is **closed** (FORMAT-EGG A.15, "The encoder"). `packed_egg/probe_sys_optimized.egg`
holds one method-3, hint-1 block over 74,627 bytes, which pins the parse but
neither the internal chunk size nor the `.com` route. The oracle produced the
two missing shapes, both checked in (their inputs are derived, not stored):
`probe_com_optimized.egg` (the same payload behind a `.com` name, which is
byte-identical to the `.sys` one) and `sysmulti_sys_optimized.egg` (633,780
bytes = two chunks of 2^19, which pins the chunk boundary and the per-chunk
model reset). `make test` compares all three archives byte for byte (step 9) and
re-encodes their payloads with `src/azoenc.c` (step 10); the writer's `.sys` and
`.com` routes are therefore no longer a gap, and no new Windows sample is
needed for them.

Two later oracle runs closed the last AZO path, the x86 filter, without any
Windows work either: AZO.dll sets the stream flag from the **content** (`MZ`
signature of the first chunk, FORMAT-EGG A.12), so the same oracle, fed a real
PE renamed `.sys`, produced `mz_sys_optimized.egg` (73,560 bytes, flag `31 01`)
and `mzmulti_sys_optimized.egg` (594,264 bytes, flag `31 01`, two chunks whose
second one is not `MZ`, which pins the sticky flag). Both are checked in; their
inputs are the reference build's own `Coders/Deflate.dll` and `ALZipCon.exe`,
derived at test time rather than stored.

The same oracle also produced the **routing matrix**: one `-m4` archive of 148
members, all holding the same 4,096 bytes of `corpus/eng.txt` and differing only
by extension — every extension of the four `Formats/Egg.dll` lists, ~90 outside
them, a name without extension and names with two suffixes. It is checked in as
`packed_egg/routes_optimized.egg` (285,730 bytes) and reproduced byte for byte
by `alz create -p optimized` (step 9), which is what turned the routing rule
from a sample into a complete table (FORMAT-EGG §11.0). Two of its members, the
"locked" ones (`dbl.tar.gz` → `.gz`, `dbl2.c.bak`), also pin the
last-suffix rule. `.dotfile` was left out of the archive: Wine marks it hidden
(attr `02`) and the writer does not guess attributes; `noext` carries the same
"no extension" case.

---

## Lot H — write-path gaps (reading is proven, writing is not)

Reading is now verified on the whole corpus: 171 ALZ archives (244 members, 23 of
them ZipCrypto-encrypted) and 258 EGG archives (store, deflate, 1 288 BZip2
blocks, 61 LZMA, the five AZO samples, 7 solid prefixes, 11 split archives,
ZipCrypto/AES-128/
AES-256) - every one of them, the five block methods included. Writing has a
reference for EGG store/deflate/BZip2/LZMA/AZO in all five profiles (including
the Optimized routes and both solid profiles), ZipCrypto, AES-128/256, split
volumes — including a **16-volume encrypted chain** — and for ALZ
store/deflate in its four profiles plus ZipCrypto and volumes. The `crypt`
group below is produced and compared byte for byte (see its row), so what is
left of lot H is the `huge`, `span`-size, `solid` and `names` rows. The Optimized extension routing is no longer open (lot G closed it with
`routes_optimized.egg`); what remains for lot E is the Normal profile, where
`ALZipCon -m1` and the GUI disagree. Lot H produces the rows below.
`fixtures/build-fixtures.py` generates all of it (set H); the Wine prefix it
needs is described in README, "Fixtures under Wine":

```sh
fixtures/build-fixtures.py --only h                          # everything (~20 GiB free for the 5 GiB cases)
fixtures/build-fixtures.py --only h --skip-huge              # without the 5 GiB members
fixtures/build-fixtures.py --only h --only-h span,crypt      # selected groups
```

Groups, and the gap each one closes:

| Group | Samples | Question it answers |
|---|---|---|
| `huge` (**produced**, verified by `make heavy`) | `-m0` on a 5 GiB zero file, EGG and ALZ; `-m0` 4.5 GiB ALZ; and `-m0 -tp0 -ppassword` on the same 5 GiB (EGG) | answered: a store member above 3 GiB is **two blocks of 3 GiB then 2 GiB**, identically whether or not the member is encrypted (`huge_store_5g.egg` and `huge_enc_zip.egg` carry the same two block CRCs). The encrypted one pins the multi-block rule of FORMAT-EGG.md §12.8 — one continuous cipher context, verifier on the whole-member CRC — and `tests/heavy_multiblock.sh` (`make heavy`) re-extracts its 5 GiB and rebuilds it byte for byte. Both are out of `make test` because of their size (~15 GiB in `corpus/huge`), and `--skip-huge` exists precisely so set H can be run without them |
| `span` (**EGG encrypted chain produced**) | `-v100KB` on `random1m.bin`, 1.5 MiB of deterministic incompressible bytes → **16 volumes**, for EGG `-m0`/`-m1`, ALZ `-m0`/`-m2` and `-tp0 -psecret` in both; a volume boundary between two members (240 KB + 120 KB); `-v1MB` on a 65-byte member; then `-v10KB`, `-v4KB` and `-v10MB` as probes | chains longer than three volumes are no longer unobserved: `span_15vol_crypt.vol1..16.egg` is byte-reproduced by `alz create -v 102400 --password …` and re-extracted from vol16, which also proves that ALZip encrypts first and splits the ciphertext. `.vol10`-style naming, the volume layout at 16 volumes and the `-p`+`-v` composition are therefore pinned. The ALZ chains are now complete too: `span_15vol_{m0,m2}.alz` keep their Windows volumes and gained the `.a03`–`.a14` produced by the Wine run (the first four were byte-identical), and `span_15vol_crypt` was regenerated whole under Wine (ALZip draws a new ZipCrypto keystream per run, so volumes from two runs cannot be mixed); `make test` reads all three chains from `.alz` and compares the 1.5 MiB payload. What stays open is volume sizes other than 100 KB, a boundary at the final End Marker, a 1-6-byte remainder, and the ALZ volume **writer** (reading is pinned; `.alz` + `.a00`… writing does not exist yet). A compressible payload proves nothing here: `-v` is a *volume* size, which is why the existing `egg_span1m_50m.vol1.egg` is a single volume (50 MB of zeros compress to 51 KB). The first Windows run showed `-v10KB` and `-v4KB` exiting 0 while writing **nothing** and `-v10MB` exiting 1, so the floor of `-v` on this build lies between 4 KB and 100 KB: the probes pin that floor, which is a refusal our CLI must reproduce (under Wine `-v10MB` writes a one-volume `probe_v10mb.vol1.egg` instead, which is checked in) |
| `solid` | a solid stream larger than one block (a ~1 GiB payload under `-m1` and `-m3`), and the **exact refusals** of `-s` with `-m0`, `-m2`, `-m4`, `-v10KB`, `-tp0 -p…`, and `-s` on ALZ | neither solid profile needs a sample any more: `-s -m1` (deflate) and `-s -m3` (LZMA) are implemented and compared byte for byte to `nested_normal_solid.egg`, `nested_compratio_solid.egg` and the two `unicode_*_solid.egg` probes. What remains unobserved is whether ALZip splits a solid stream into several blocks (every solid sample holds one block for the whole stream, so the writer refuses above 3 GiB instead of guessing) and the refusal *text* of the forbidden combinations, which our CLI has to reproduce word for word |
| `crypt` (**produced**) | EGG: `-m0..-m3` × `-tp0/1/2` (`enc_egg_m*_tp*`), an encrypted empty member (`enc_egg_empty_tp0`), an encrypted directory (`enc_egg_dir_tp0`), two members at `-m0 -tp0`, and three non-ASCII passwords (`enc_egg_napw_euro/han/acute_aes256`). ALZ: `-m0..-m3 -tp0 -psecret` (`enc_alz_m0..m3`), an encrypted empty member (`enc_alz_empty`), encrypted + read-only (`enc_alz_attrs`), and `enc_alz_napw_euro` / `enc_alz_napw_euro_records` | answered: the 65-byte matrix is reproduced byte for byte by `alz create`, so encryption is not restricted to m0/m1/m4 (the three deflate levels simply coincide on 65 bytes). A member without blocks carries **no Encrypt Info at all** — the empty member and the directory look exactly as if `-p` had been omitted, a row the writer used to refuse. A non-ASCII password is converted through the system ANSI code page (`€` → `0x80`, `한` → `0x3F`), which FORMAT-EGG.md §12.9 records; no case is left open in this group |
| `names` | member ordering (`a.txt`, `B.txt`, `c1/c10/c2.txt`, `-dash`, `_underscore`, `.dotfile`, `z z.txt`); case duplicates appended in two calls; routing for `payload` (no extension), `.tar.gz`, `.docx`, `.xlsx`, `.pptx`, `.mp4`, `.cab`, `.iso`, `.ttf`, `.wav`, `PAYLOAD.TXT` and `Payload.Txt` at `-m3`/`-m4`; 200-character and special-character names | the writer has to reproduce ALZip's member **order** (byte order and Windows collation differ), and lot E left these extensions out of the routing matrix. The Korean-name case is not about the name (`packed_egg/unicode_normal.egg` already has them) but about the FILENAME `locale` bit 0x08: all 324 corpus entries are `fn_flags=0x00`, so it has never been exercised |
| `edges` | empty archive (both formats), the same member added twice, a second member appended to an existing archive, `-xr`, `-an*.bin` in two spellings (probes: under Wine they write an archive holding only the non-matching members, which is printed and not checked in), a directory-only archive, `-t` on a produced archive | these are the cases where the writer must choose between writing and refusing, and no corpus archive exercises them. Note that `packed_alz_8.0/empty_*.alz` are **not** empty archives — each holds one zero-length member `empty.dat` — while the empty *EGG* archive does exist as the installer's `NewEgg.dat` (22 bytes, `header_id` 0x00000001), which our reader lists as 0 members |

### What the first Windows run already showed

- `-v10KB` and `-v4KB` make `ALZipCon.exe` exit **0 without writing anything**
  and without printing a message, in EGG as in ALZ. A zero exit is therefore not
  a success: the script now classifies that outcome as *no effect*, distinct
  from a refusal, whose message is itself a reference.
- `-v10MB` on a 65-byte member exits **1** on Windows; the message was not
  captured by the first log. Under Wine the same command exits 0 and writes a
  one-volume `probe_v10mb.vol1.egg`, which is checked in: the behaviour of `-v`
  above the member size is part of what the reference set records.
- `-an<pattern>` produced nothing in either spelling on the first Windows run
  (with and without `-af`) and printed no message. The regenerated Wine run
  disagrees: both spellings write an archive holding only the members the
  pattern does not match (`hello.txt`; `records.bin` excluded). Neither archive
  is checked in: the writer has no `-an`, so no test can replay it, and the
  probes print the outcome and discard the file.
- The cases that must produce an archive are therefore built on `-v100KB`, the
  only volume size the corpus attests, over a 1.5 MiB payload instead of the
  120 KB one.

### What the CLI cannot produce (GUI or out of scope)

1. **Archive and per-file comments.** No option in `con_en-US.dll`; the COMMENT
   record has zero occurrences in the corpus, so neither the writer nor the reader
   can implement it yet. One EGG with an archive comment and a per-file comment
   settles the record, the encoding and the ordering.
2. **Encrypted member names (GLOBAL_CRYPT).** No CLI option; look for an
   "encrypt file names" control in the password dialog. Zero occurrences today.
3. **LEA-128 / LEA-256** (crypt methods 5 and 6). This 8.0 build's `-tp` only
   accepts `0..2`, but the format does define the two methods — and ALZip 12.30
   produces them, see **Lot J** below.
4. **POSIX_INFO.** No Windows file carries POSIX attributes, so no fixture can
   exist; if a Linux build ever writes it, that is the sample to ask for.
5. **ALZ extraction with a wrong password**: the exact message, to reproduce it.

## Lot I — the GUI compression levels (**closed**: six archives, all byte-exact)

The archives are in `packed_egg_8.0/`, their inputs in `corpus/` (65 B to
1 MiB), and step 9 of `make test` rebuilds each of them byte for byte with the
profile its name announces. What they settled:

| archive | level shown in the GUI | result |
|---|---|---|
| `gui_normal_matrix.egg` | Normal compression | **all 15 members are Deflate hint 6**, `c1.c` and the 1 MiB `big1m.c` included: the GUI's Normal has no per-extension routing at all |
| `gui_normal_code.egg` | Normal compression | `code.c` (45 270 B) → Deflate hint 6 — exactly the member `packed_egg/code_normal.egg` reported as BZip2 |
| `gui_optimized_matrix.egg` | Optimized compression | `.c`/`.txt`/`.java`/`.xml`/`.pas`/`.1st` → BZip2 hint 4 (1 MiB `.c` included), `.cc`/`.htm`/`.bin`/`.zeros` → Deflate hint 5: the runtime table and its nine shadowed entries confirmed on a second, independent sample |
| `gui_nocomp_matrix.egg` | No compression | Store, 15 members |
| `gui_cs_matrix.egg` | Priority on compressing speed | Deflate hint 5, 15 members |
| `gui_ratio_matrix.egg` | Priority on compress ratio | LZMA hint 6, 15 members |

Consequence: `packed_egg/code_normal.egg` is an **Optimized** archive — its
blocks are identical to `code_optimized.egg` and only the randomised `header_id`
differs — so the `.c` → BZip2 route it suggested for *Normal* never existed.
The writer's Normal profile is now Deflate hint 6 for every member, with no
refusal; `code_normal.egg` is kept and compared as an Optimized reference
(step 9).

One extra archive came out of the same session: `packed_egg_8.0/solid_normal_code.egg`,
produced by `ALZipCon -m1 -s` over `hello.txt` + `code.c` (one Deflate hint 6
block over the 45 335-byte concatenation, members `tree/code.c` then
`tree/hello.txt`). It is reproduced byte for byte too, so a `.c` member inside a
solid Normal archive is no longer an untested combination.

---

## Lot J — LEA-128 / LEA-256 (**closed**: six archives, all byte-exact)

ALZip 8.0 cannot express these methods (`-tp` stops at 2, and no string in its
binaries names LEA), but the format reserves methods 5 and 6 for them. ALZip
12.30, whose `ALZipCon.exe` accepts the undocumented `-tp3` (`LEA-128`) and
`-tp4` (`LEA-256`), produces them; that is the reference this project uses,
under Wine, exactly like the 8.0 oracle of `tools/egg_oracle.sh`.

| archive | command | members |
|---|---|---|
| `lea128_store_hello.egg` | `-a -m0 -tp3 -ppassword hello.txt` | 1, Store |
| `lea256_store_hello.egg` | `-a -m0 -tp4 -ppassword hello.txt` | 1, Store |
| `lea128_optimized_hello.egg` | `-a -m4 -tp3 -ppassword hello.txt` | 1, BZip2 hint 4 (Optimized routing) |
| `lea256_optimized_hello.egg` | `-a -m4 -tp4 -ppassword hello.txt` | 1, BZip2 hint 4 |
| `lea128_store_two.egg` | `-a -m0 -tp3 -ppassword two/` | 2, Store, **one salt each** |
| `lea256_store_two.egg` | `-a -m0 -tp4 -ppassword two/` | 2, Store, **one salt each** |

Inputs: `corpus/hello.txt` and `corpus/code.c`; the two-member archives are
built from a staged directory `two/`, which ALZip stores as the `two/` name
prefix (the same ALZipCon behaviour `tools/egg_oracle.sh` documents: a comma-separated
list of inputs produces nothing under Wine). Password: `password`.

What they settled: the framing of §12.5 is exactly AES's — PBKDF2-HMAC-SHA1
over the salt (8 bytes for LEA-128, 16 for LEA-256, 1000 iterations), the same
2-byte verifier and the same 10-byte HMAC-SHA1 footer over the ciphertext — and
the CTR counter is 128-bit **big-endian** starting at zero, unlike AE-2's
little-endian counter (the two differ from the second block on, which is why
the 65-byte Store fixtures alone would not have discriminated them: the two-
member archives and `corpus/code.c`'s 45 270 bytes do).

`make test` decrypts all six (step 8) and rebuilds all six **byte for byte**
(step 9) by re-injecting the salt read from each reference; `tests/bin/leatv`
replays the KS X 3246 appendix A vectors on the block cipher.

### 12.30 is the writer reference

The format itself did not change between 8.0 and 12.30: ALZip 8.0 extracts every
12.30 archive below (all profiles, solid, AZO) and 12.30 extracts the 8.0
corpus, both verified under Wine. What changed is the **profile scale**: on the
same input 12.30 writes Deflate hint **2** for `-m1`, hint **4** for `-m2`,
LZMA hint **8** for `-m3`, BZip2 hint 4 for `-m4`, where 8.0 wrote hints 6, 5,
6 and the same Optimized routing. `-m1` and `-m2` are therefore **swapped**
between the two versions. ALZ lost its level-2 profile in 12.30: `-m0..-m2` =
store/1/4, default `-m2`, and `-m3` exits without writing anything; 12.30 also
sets `attr=0x20` on ALZ files where 8.0 wrote 0.

Since a single encoder cannot be bit-exact with both scales, the project
follows **12.30** for every written byte (see lot K). That is the parity rule,
not a missing capability: the 8.0 scale is still producible by the 8.0 build
itself (`tools/alz_oracle.sh -r 8`), and the reader decodes it, but the writer
intentionally emits only the 12.30 numbers. The 8.0 corpus therefore remains a
**reader** corpus; the only 8.0 references still compared byte for byte are the
ones whose output did not change (Store, Optimized/bzip2/AZO, LZMA payloads —
only their `hint` byte moved from 6 to 8).

---

## Lot K — ALZip 12.30 encoder references (**closed**: every written profile)

### Reproducing it from the repository

The 12.30 console build can be placed in `_work/binaries/alzip-12.30/` (5 MB: `ALZipCon.exe`,
its VC90 runtime DLLs and manifests, `Formats/`, `Coders/`, the empty-archive
templates and the licence) so regeneration does not depend on an external Windows machine.
`tools/alz_oracle.sh` runs it under Wine from that copy, with a project-local prefix (`out/oracle-12/`):

```
tools/alz_oracle.sh OUTPUT -m1 corpus/hello.txt        # 12.30 by default
tools/alz_oracle.sh -r 8 SORTIE.alz -m0 corpus/hello.txt  # install 8.0, corpus historique
```

`fixtures/lot-k.sh` replays every command of the table below into
`out/lot-k-regen/` (~35 s, exit status 0 on success) and compares each result
with the checked-in reference: ALZ byte for byte outside the DOS timestamps,
EGG outside the random Header ID and the staging FILETIMEs, and the encrypted
archives — whose salt/IV ALZip draws at random — member by member after
decryption. Wine runs the console build (it is Windows-only); everything else
comes from the repository, so no external install or temporary directory is
involved. `make test` remains the check that our own writer matches it.

### Contents

Produced by `ALZipCon.exe` 12.30 under Wine, from `corpus/hello.txt` and
`corpus/code.c` (staged as `two/` for the multi-member cases), password
`password`. Each archive is rebuilt byte for byte with its Header ID and
FILETIME (and its random crypto material) re-injected.

| archive | command | contents |
|---|---|---|
| `egg_m0_two.egg` | `-a -m0 two/` | 2 members, Store |
| `egg_m1_two.egg` | `-a -m1 two/` | deflate hint 2, level 2 |
| `egg_m2_two.egg` | `-a -m2 two/` | deflate hint 4, level 4 |
| `egg_m3_two.egg` | `-a -m3 two/` | LZMA hint 8 |
| `egg_m4_two.egg` | `-a -m4 two/` | Optimized: BZip2 hint 4 |
| `egg_s_m1_two.egg` | `-a -s -m1 two/` | solid, one deflate 2 stream |
| `egg_s_m3_two.egg` | `-a -s -m3 two/` | solid, one LZMA 8 stream |
| `egg_m4_sys.egg` | `-a -m4 probe.sys` | AZO, hint 1 |
| `egg_zip_m0_hello.egg` | `-a -m0 -tp0 -ppassword hello.txt` | ZipCrypto |
| `egg_zip_m1_two.egg` | `-a -m1 -tp0 -ppassword two/` | ZipCrypto, one salt per member |
| `egg_aes256_m2_hello.egg` | `-a -m2 -tp2 -ppassword hello.txt` | AES-256 |
| `egg_m1_records_v100k.vol1-2.egg` | `-a -m1 -v100KB records.bin` | 2 volumes, deflate 2 |
| `alz_m0_hello.alz` | `-a -m0 hello.txt` | Store, `attr=0x20` |
| `alz_m1_biased_v100k.alz` | `-a -m1 biased.bin` | level 1 (discriminates 1 vs 2) |
| `alz_m2_code.alz` | `-a -m2 code.c` | level 4 |
| `alz_m0_random_v100k.alz(.a00)` | `-a -m0 -v100KB random.bin` | 2 volumes |
| `alz_zip_m1_hello.alz` | `-a -m1 -tp0 -ppassword hello.txt` | ZipCrypto |
| `alz_zip_m1_two.alz` | `-a -m1 -tp0 -ppassword two/` | ZipCrypto, one material per member |

`make test` rebuilds every one of them (steps 3, 9 and 12) and extracts them
back. The `.sys` payload is `probe.sys` (derived from the 8.0
`Coders/Deflate.dll`, like the other AZO probes).

### Two 12.30 chains share their Header IDs

`packed_egg/records_compspeed_v100k*` is a different story: those two chains
(`…_v100k` and `…_v100k_zip`, four files) come from the same `build-12.30.sh`
run, and ALZip gave both the same Header IDs (`0xedf3fdbe` for volume 1,
`0x56ab3820` for volume 2), because the only difference between the two
commands is `-tp0 -ppassword`. A reader that indexes sibling volumes by Header
ID therefore sees four files for two chains and may pair the encrypted data of
one with the plain sibling of the other; reading `records_compspeed_v100k_zip`
from volume 1 fails with `truncated block data` when the plain chain sits in the
same directory, and succeeds once the chain is alone in its directory. This is
an ambiguity of the fixture layout, not of the format: `make test` never reads
those two chains from a volume (step 9 reads the split chains from their last
volume, and `splitmany` — the plain 3-volume case — from every volume), and
`fixtures/lot-k.sh` compares them with each chain isolated.

---

---

## Priority

1. **Lot B** — the only completely absent format capability on the ALZ side.
2. **Lot C** — the encoder cannot reproduce a block split it has never seen (and
   item 5 is the only solid case still observable at all).
3. **Lot A** — two small additions: an encrypted store/deflate member (so the
   decryption can be checked through the normal `extract` path) and two members
   under one passphrase (to pin the per-member key re-seeding of §12.3).
4. **Lot D, Lot F** — completeness and the round-trip check. (Lots G and I are
   closed: the AZO encoder's references and all five GUI profiles are in the
   checkout and compared in `make test`.)
5. **Lot H** — everything the writer still lacks: the store threshold above
   3 GiB, volume sizes other than 100 KB, multi-block solid streams, member
   ordering, the residual routing extensions, and the empty/duplicate edge
   cases. The `crypt` group and a 16-volume encrypted chain are produced and
   compared, so they are no longer part of what lot H has to supply.
