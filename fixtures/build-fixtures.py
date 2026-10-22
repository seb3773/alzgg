#!/usr/bin/env python3
"""Regenerates the ALZip 8.0 fixture sets under Wine.

Wine/POSIX replacement for the three PowerShell scripts that used to sit here
(`generate-fixtures.ps1`, `missing-fixtures.ps1`, `lot-h.ps1`). ALZipCon.exe
8.0.0.18 is Windows-only, but it runs unmodified under Wine, so the fixture
pipeline is reproducible on Linux (the tested host; it needs a Wine that can
run a 32-bit binary):

    fixtures/build-fixtures.py                     # sets a b c d g h
    fixtures/build-fixtures.py --only d
    fixtures/build-fixtures.py --only h --skip-huge
    fixtures/build-fixtures.py --only a,g --out fixtures/out

Sets (FIXTURES.md explains what each one answers):

    a  EGG and ALZ encryption on the write side (store, deflate, two members)
    b  ALZ encryption with paths, and the non-ASCII tree
    c  large members: 64 KiB to 5 GiB, 64-bit size fields, volumes, solid
    d  metadata: odd/even seconds, pre-1980 and post-2038 dates, DOS
       attributes, an empty directory, a nested tree
    g  AZO samples (probe.sys copies under other extensions)
    h  write-path gaps: huge store members, volume sizes, solid, encryption per
       profile, member order and names, and the writer's edge cases

There is no set `e`: the method-routing matrix it used to produce (224 archives,
16 extensions x 7 profile/format pairs) was deleted from the corpus during the
consolidation. Its table lives in `packed_egg/routes_optimized.egg` (148 members)
and `packed_egg_8.0/gui_normal_matrix.egg`, both replayed by `make test`; the ALZ
profiles are pinned by the 13 inputs x 4 profiles of `packed_alz_8.0/`. A set
without a reference would only produce archives nothing can compare against, so
this port does not regenerate it (FIXTURES.md, lot E).

Every archive a run writes must therefore have a twin in `packed_egg_8.0/` or
`packed_alz_8.0/`, which is what `make test` reads; the run checks that at the
end (`--no-verify` skips it). Commands whose *outcome* is the reference (a
refusal, a no-op, an archive written by an option the writer does not implement)
are probes, not fixtures: `probe(..., discard=True)` prints the outcome and
removes the archive it wrote when nothing in the corpus can replay it.

Everything is staged under `fixtures/out/<set>/...` and archived from that path,
so the member names carry a `fixtures/out/...` prefix. Some checked-in
references were produced from inside their lot instead, and therefore store the
bare name (`hello.txt`): `tools/egg_mask_compare.py` and
`tools/archive_compare.py` compare containers, so use them on the references
whose names match, and compare the others after extraction. Everything else is
guaranteed to match (Header ID, FILETIMEs and crypto material are masked: ALZip
draws them at random).

One Wine deviation is expected on the ALZ side: ALZip 8.0 asks Windows for the
file attributes, and Wine reports FILE_ATTRIBUTE_ARCHIVE on every regular file,
so a regenerated `.alz` stores `attr=0x20` where the Windows-produced reference
stores `0x00`. The EGG writer filters that bit and is unaffected.

Wine setup: the first run copies `research/Program Files (x86)/ALZip` into
`out/oracle-8/install` and lets Wine create its prefix at `out/oracle-8/prefix`
(~15 s and a few hundred MB). The prefix gets a `Y:` drive pointing at the
repository root, so the paths handed to ALZip read `Y:\\fixtures\\out\\...` and
the archived names come out as `fixtures/out/...`, exactly as on a Windows
checkout on `Y:\\`. `--work` moves both and `--install` picks another copy of
ALZip.

Two Windows behaviours are reproduced differently; FIXTURES.md records both.
The read-only DOS attribute comes from the file mode: Wine maps a non-writable
Unix file to `FILE_ATTRIBUTE_READONLY`, so `set_readonly()` is a `chmod`.
Hidden and system are stored as `0x00`, which is what ALZip 8.0 wrote on Windows
too. The ANSI code page is the Wine prefix': a Korean member name is stored as
UTF-8 unless the prefix was built under `LANG=ko_KR.UTF-8`, so
`names_korean_m1.egg` is skipped unless `FIXTURE_ACP=949` is set.
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
_cand8 = REPO / '_work' / 'binaries' / 'alzip-8.0'
DEFAULT_INSTALL = _cand8 if _cand8.is_dir() else (REPO / 'research' / 'Program Files (x86)' / 'ALZip')

# A desktop session can export LD_PRELOAD for its own libraries; passing it to
# Wine makes every run print an ld.so warning.
BASE_ENV = {k: v for k, v in os.environ.items() if k != 'LD_PRELOAD'}


class Fail(Exception):
    pass


class Oracle:
    """A copy of the 8.0 install, its Wine prefix, and the staging helpers."""

    def __init__(self, install, work, quiet=False):
        self.install = Path(install)
        self.work = Path(work)
        self.prefix = self.work / 'prefix'
        self.copy = self.work / 'install'
        self.quiet = quiet
        self.produced = []
        self.failed = []

    # -------------------------------------------------------------- setup
    def prepare(self):
        if not self.install.is_dir():
            raise Fail(f'ALZip 8.0 install not found: {self.install}')
        if shutil.which('wine') is None:
            raise Fail('wine is required: the fixtures are produced by ALZipCon.exe')
        self.work.mkdir(parents=True, exist_ok=True)
        if not (self.copy / '.copied').exists():
            if self.copy.exists():
                shutil.rmtree(self.copy)
            shutil.copytree(self.install, self.copy)
            (self.copy / '.copied').write_text('')
        dosdevices = self.prefix / 'dosdevices'
        dosdevices.mkdir(parents=True, exist_ok=True)
        link = dosdevices / 'y:'
        if link.is_symlink() and link.resolve() == REPO:
            return
        if link.is_symlink() or link.exists():
            link.unlink()
        link.symlink_to(REPO)

    # ----------------------------------------------------------- plumbing
    @staticmethod
    def wine_path(path):
        path = Path(path)
        if not path.is_absolute():
            path = REPO / path
        return 'Y:\\' + str(path.relative_to(REPO)).replace('/', '\\')

    def run(self, argv, cwd=None):
        env = dict(BASE_ENV)
        env['WINEPREFIX'] = str(self.prefix)
        env['WINEDEBUG'] = '-all'
        env['WINEDLLOVERRIDES'] = 'mscoree,mshtml='
        cmd = ['wine', str(self.copy / 'ALZipCon.exe')] + [str(a) for a in argv]
        try:
            proc = subprocess.run(cmd, cwd=str(cwd or self.copy), env=env,
                                  capture_output=True, text=True, timeout=1800)
        except subprocess.TimeoutExpired:
            raise Fail(f'ALZipCon timed out: {" ".join(str(a) for a in argv)}')
        output = '\n'.join(
            line for line in (proc.stdout + proc.stderr).splitlines()
            if line.strip() and 'ld.so' not in line
            and 'Could not parse file' not in line)
        if not self.quiet:
            print(f'> ALZipCon.exe {" ".join(str(a) for a in argv)}')
            for line in output.splitlines():
                print(f'  {line}')
        return proc.returncode == 0, output

    def arg_list(self, options, sources, target):
        """Options, then sources, then the archive.

        A source that starts with `-` is passed through as an option, which is
        how `-af <directory>` is spelled: `['-af', directory]`.
        """
        argv = list(options)
        for source in sources:
            if isinstance(source, str) and source.startswith('-'):
                argv.append(source)
            else:
                argv.append(self.wine_path(source))
        argv.append(self.wine_path(target))
        return argv

    @staticmethod
    def same_family(target, candidate):
        """Whether `candidate` is `target` or one of its volumes.

        An `.egg` and an `.alz` with the same stem are two different archives
        (the corpus holds both), so the family is the container: `x.a00` belongs
        to `x.alz`, and `x.vol2.egg` to `x.egg`.
        """
        if candidate.suffix == target.suffix:
            return True
        return target.suffix == '.alz' and re.fullmatch(r'\.a\d+', candidate.suffix) is not None

    @classmethod
    def outputs(cls, target):
        """Archive files ALZip wrote for `target` (a `-v` stem yields volumes)."""
        target = REPO / target
        stem = target.with_suffix('')
        files = [p for p in sorted(stem.parent.glob(stem.name + '*'))
                 if p.is_file() and p.stat().st_size > 0
                 and cls.same_family(target, p)]
        for preferred in (f'{stem.name}.alz', f'{stem.name}.vol1.egg'):
            for path in files:
                if path.name == preferred:
                    return [path] + [p for p in files if p is not path]
        return files

    def clear(self, target):
        """Removes every archive a previous run may have left for this stem.

        The ALZ volumes are `.a00`, `.a01`, … (not just `.a00`), and the EGG ones
        `.vol1.egg`, so the test is on the name, not on the suffix. Only this
        archive's own family goes: the same stem as the other format is another
        fixture (`huge_store_5g.egg` and `huge_store_5g.alz`).
        """
        target = REPO / target
        stem = target.with_suffix('')
        for stale in stem.parent.glob(stem.name + '*'):
            if stale.is_file() and self.same_family(target, stale):
                stale.unlink()

    # ------------------------------------------------------------ writers
    def archive(self, target, sources=(), options=(), append=False):
        """Creates `target` from `sources`; returns the first file written."""
        target = REPO / target
        target.parent.mkdir(parents=True, exist_ok=True)
        if not append:
            self.clear(target)
        argv = self.arg_list(options, sources, target)
        ok, output = self.run(argv)
        written = self.outputs(target)
        if not ok or not written:
            reason = 'ALZipCon refused the command' if not ok else 'no file written'
            print(f'  FAILED ({target.name}): {reason}')
            self.failed.append((argv, output or reason))
            return None
        # Every file of a split archive, not only the first volume: a chain is
        # only a fixture if the corpus has all of it (the ALZ span chains used
        # to stop at .a02, and a truncated chain cannot be read back).
        self.produced.extend(written)
        if written[0] != target:
            print(f'  named {written[0].relative_to(REPO)} (first volume)')
        print(f'  ok: {written[0].relative_to(REPO)} ({written[0].stat().st_size} bytes)')
        return written[0]

    def probe(self, target, sources=(), options=(), discard=False):
        """A command whose outcome IS the reference: archive, refusal, or nothing.

        An archive a probe writes is kept when the corpus has a reference for it
        (`-v10MB` in lot H). `discard` is for a behaviour the corpus cannot
        consume (the writer has no option for it, so no test can replay the
        archive): the outcome is printed and the file deleted, instead of leaving
        a fixture without a reference behind.
        """
        target = REPO / target
        target.parent.mkdir(parents=True, exist_ok=True)
        self.clear(target)
        argv = self.arg_list(options, sources, target)
        ok, output = self.run(argv)
        written = self.outputs(target)
        if written and discard:
            print(f'  archive (discarded, probe): {written[0].name} '
                  f'({written[0].stat().st_size} bytes)')
            self.clear(target)
            return 'archive'
        if written:
            self.produced.append(written[0])
            note = '' if ok else ' (partial: non-zero exit)'
            print(f'  archive: {written[0].relative_to(REPO)}{note}')
            return 'archive'
        if ok and not output.strip():
            print(f'  no effect: {target.name} (code 0, no message, no file)')
            return 'no effect'
        print(f'  refused: {target.name} (code 0 but a message)')
        return 'refused'

    def expect_refusal(self, target, sources=(), options=()):
        target = REPO / target
        target.parent.mkdir(parents=True, exist_ok=True)
        self.clear(target)
        argv = self.arg_list(options, sources, target)
        ok, output = self.run(argv)
        written = self.outputs(target)
        if written:
            print(f'  UNEXPECTED: {target.name} was written (a refusal was expected)')
            self.failed.append((argv, 'refusal expected, archive written'))
            return False
        print(f'  refused: {target.name}')
        return True


# --------------------------------------------------------------------- staging
def stage(source, destination):
    source, destination = REPO / source, REPO / destination
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.is_symlink() or destination.exists():
        if destination.is_dir() and not destination.is_symlink():
            shutil.rmtree(destination)
        else:
            destination.unlink()
    if source.is_dir():
        shutil.copytree(source, destination, symlinks=True, copy_function=shutil.copy2)
    else:
        shutil.copy2(source, destination)
    return destination


def write_text(path, text, encoding='utf-8'):
    path = REPO / path
    path.parent.mkdir(parents=True, exist_ok=True)
    # A previous run may have left the file read-only (the DOS attribute is the
    # Unix mode), and truncating it in place would then fail.
    if path.exists():
        os.chmod(path, 0o644)
        path.unlink()
    path.write_text(text, encoding=encoding)
    return path


def touch(path, when):
    ts = time.mktime(time.strptime(when, '%Y-%m-%d %H:%M:%S'))
    os.utime(REPO / path, (ts, ts))


def set_readonly(path, readonly=True):
    """The DOS read-only bit: Wine takes it from the file mode."""
    path = REPO / path
    mode = path.stat().st_mode
    os.chmod(path, (mode & ~0o222) if readonly else (mode | 0o200))


def sparse(path, size):
    path = REPO / path
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.stat().st_size == size:
        return path
    with open(path, 'wb') as handle:
        handle.truncate(size)          # no space used until ALZip reads it
    return path


KOREAN_DIR = '\uac08\ub300\uc232'
KOREAN_FILE = '\ud14d\uc2a4\ud2b8'
ACCENT_DIR = 'caf\u00e9_clair'


# ------------------------------------------------------------------- the sets
def set_a(oracle, out):
    """Encryption on the write side, one member and two members (lot A)."""
    lot = out / 'lot-a'
    for name in ('hello.txt', 'records.bin'):
        stage(f'corpus/{name}', lot / name)
    two = lot / 'twofiles'
    for name in ('hello.txt', 'records.bin'):
        stage(f'corpus/{name}', two / name)

    oracle.archive(lot / 'enc_store_basic.egg', [lot / 'hello.txt'],
                   ['-a', '-m0', '-tp0', '-ppassword'])
    oracle.archive(lot / 'enc_deflate_aes128.egg', [lot / 'hello.txt'],
                   ['-a', '-m1', '-tp1', '-ppassword'])
    oracle.archive(lot / 'enc_deflate_aes256.egg', [lot / 'hello.txt'],
                   ['-a', '-m1', '-tp2', '-ppassword'])
    for method, label in enumerate(('basic', 'aes128', 'aes256')):
        oracle.archive(lot / f'enc_twofiles_{label}.egg', ['-af', two],
                       ['-a', '-m1', f'-tp{method}', '-ppassword'])


def set_b(oracle, out):
    """ALZ encryption with paths, and the non-ASCII tree (lot B)."""
    lot = out / 'lot-b'
    stage('corpus/nested', lot / 'nested')
    for name in ('hello.txt', 'records.bin'):
        stage(f'corpus/{name}', lot / name)

    oracle.archive(lot / 'enc_basic.alz', [lot / 'hello.txt'], ['-a', '-tp0', '-psecret'])
    oracle.archive(lot / 'enc_basic_split.alz', [lot / 'records.bin'],
                   ['-a', '-tp0', '-psecret', '-v100KB'])
    oracle.archive(lot / 'enc_basic_paths.alz', ['-af', lot / 'nested'],
                   ['-a', '-tp0', '-psecret'])

    # Non-ASCII names are rebuilt from code points: a checkout that travelled
    # through a zip written with the wrong code page has '?' instead of Hangul.
    uni = lot / 'unicode'
    references = (f'{KOREAN_DIR}/{KOREAN_FILE}.txt',
                  f'{ACCENT_DIR}/menu_\u00e9.txt',
                  f'{ACCENT_DIR}/ nested/deep_\u00f1.txt')
    missing = [rel for rel in references if not (REPO / 'corpus/unicode' / rel).exists()]
    if missing:
        raise Fail('corpus/unicode lost its non-ASCII names: ' + ', '.join(missing) +
                   ' (a zip written with the wrong code page mangles them; restore '
                   'them in place rather than copying the tree again)')
    for rel in references:
        stage(f'corpus/unicode/{rel}', uni / rel)
    oracle.archive(lot / 'unicode_basic.alz', ['-af', uni], ['-a', '-m1'])
    oracle.archive(lot / 'unicode_basic_encrypted.alz', ['-af', uni],
                   ['-a', '-tp0', '-psecret'])


def set_c(oracle, out, skip_huge=False):
    """Large members, 64-bit sizes, volumes and solid (lot C)."""
    lot = out / 'lot-c'
    zero64k = sparse(lot / 'zero64k.bin', 64 << 10)
    zero4m = sparse(lot / 'zero4m.bin', 4 << 20)
    zero50m = sparse(lot / 'zero50m.bin', 50 << 20)
    zero1g = sparse(lot / 'zero1g.bin', 1 << 30)
    zero5g = None if skip_huge else sparse(lot / 'zero5g.bin', 5 << 30)
    zero4g5 = None if skip_huge else sparse(lot / 'zero4g5.bin', 4500 << 20)

    for path in (zero4m, zero50m, zero1g):
        oracle.archive(lot / f'egg_normal_{path.name}.egg', [path], ['-a', '-m1'])
        oracle.archive(lot / f'egg_optimized_{path.name}.egg', [path], ['-a', '-m4'])
    if zero5g:
        oracle.archive(lot / 'egg_normal_zero5g.egg', [zero5g], ['-a', '-m1'])
    if zero4g5:
        oracle.archive(lot / 'alz_normal_zero4g5.alz', [zero4g5], ['-a', '-m3'])
    oracle.archive(lot / 'alz_normal_zero50m.alz', [zero50m], ['-a', '-m3'])

    # `-v10KB` is below this build's floor (FIXTURES.md, lot C): it exits 0
    # without writing anything, which is the reference in itself, so these two
    # are probes rather than expected archives.
    oracle.probe(lot / 'egg_span10k_64k.egg', [zero64k], ['-a', '-m1', '-v10KB'])
    oracle.archive(lot / 'egg_span1m_50m.egg', [zero50m], ['-a', '-m1', '-v1MB'])
    oracle.probe(lot / 'alz_span10k_64k.alz', [zero64k], ['-a', '-m1', '-v10KB'])
    splitmany = stage('corpus/splitmany', lot / 'splitmany')
    oracle.archive(lot / 'egg_splitmany_v100k.egg', ['-af', splitmany],
                   ['-a', '-m1', '-v100KB'])

    oracle.archive(lot / 'egg_solid_zero50m.egg', [zero50m], ['-a', '-s', '-m1'])
    oracle.archive(lot / 'egg_solid_zero1g.egg', [zero1g], ['-a', '-s', '-m1'])
    sources = lot / 'sources'
    stage('corpus/code.c', sources / 'code.c')
    stage('corpus/hello.txt', sources / 'hello.txt')
    oracle.archive(lot / 'egg_solid_sources.egg', [sources], ['-a', '-s', '-m1'])


def set_d(oracle, out):
    """Dates, DOS attributes, empty directory, nested tree (lot D)."""
    lot = out / 'lot-d'
    meta = lot / 'meta'
    # The lot D sources were written from PowerShell, whose `-Encoding UTF8`
    # emits a BOM, and the checked-in CRCs cover it: reproduce the files byte
    # for byte, BOM included.
    for name, text in {
        'odd_second.txt': 'seconde impaire\n',
        'even_second.txt': 'seconde paire\n',
        'old.txt': 'date pre-1980\n',
        'future.txt': 'date post-2038\n',
        'attr_ro.txt': 'lecture seule\n',
        'attr_hidden.txt': 'cache\n',
        'attr_system.txt': 'systeme\n',
        'attr_all.txt': 'lecture seule + cache + systeme\n',
        'sub/deep/nested.txt': 'imbrique\n',
    }.items():
        write_text(meta / name, text, encoding='utf-8-sig')
    (meta / 'empty').mkdir(parents=True, exist_ok=True)

    touch(meta / 'odd_second.txt', '2001-02-03 04:05:07')
    touch(meta / 'even_second.txt', '2001-02-03 04:05:06')
    touch(meta / 'old.txt', '1979-06-05 12:00:00')
    touch(meta / 'future.txt', '2040-01-01 00:00:00')

    # Only the read-only bit reaches the archive (see the module docstring):
    # Wine reads it from the file mode, and ALZip 8.0 stored hidden and system
    # as 0x00 on Windows as well.
    set_readonly(meta / 'attr_ro.txt')
    set_readonly(meta / 'attr_all.txt')

    for profile in '123':
        oracle.archive(lot / f'meta_alz_m{profile}.alz', ['-af', meta],
                       ['-a', f'-m{profile}'])
    oracle.archive(lot / 'meta_egg_m1.egg', ['-af', meta], ['-a', '-m1'])
    oracle.archive(lot / 'meta_egg_m4.egg', ['-af', meta], ['-a', '-m4'])


def set_g(oracle, out):
    """AZO samples: probe.sys under other extensions (lot G)."""
    lot = out / 'lot-g'
    stage('corpus/probe.sys', lot / 'probe.sys')
    stage('corpus/random.bin', lot / 'random.bin')
    for ext in ('dll', 'exe'):
        stage('corpus/probe.sys', lot / f'probe.{ext}')

    oracle.archive(lot / 'probe_dll_optimized.egg', [lot / 'probe.dll'], ['-a', '-m4'])
    oracle.archive(lot / 'probe_exe_optimized.egg', [lot / 'probe.exe'], ['-a', '-m4'])
    oracle.archive(lot / 'probe_random_optimized.egg', [lot / 'random.bin'], ['-a', '-m4'])

    multi = lot / 'multi'
    for name in ('probe.sys', 'probe.dll', 'probe.exe'):
        stage(lot / name, multi / name)
    oracle.archive(lot / 'probe_multi_optimized.egg', ['-af', multi], ['-a', '-m4'])


# --------------------------------------------------------------- set H groups
def h_huge(oracle, out):
    """A store member beyond 3 GiB, EGG and ALZ, plain and encrypted."""
    lot = out / 'lot-h' / 'huge'
    five = sparse(lot / 'zero5g.bin', 5 << 30)
    four5 = sparse(lot / 'zero4g5.bin', 4500 << 20)
    oracle.archive(lot / 'huge_store_5g.egg', [five], ['-a', '-m0'])
    oracle.archive(lot / 'huge_store_5g.alz', [five], ['-a', '-m0'])
    oracle.archive(lot / 'huge_store_45g.alz', [four5], ['-a', '-m0'])
    # Multi-block encrypted member: 3 GiB + 2 GiB under one cipher context.
    oracle.archive(lot / 'huge_enc_zip.egg', [five], ['-a', '-m0', '-tp0', '-ppassword'])


def h_span(oracle, out):
    """Volume sizes, the 10+ naming, and the `-v` floor (lot H)."""
    lot = out / 'lot-h' / 'span'
    # The 1.5 MiB payload is an input, not something to draw: the checked-in
    # 16-volume chains embed this exact file, and `make test` rebuilds them from
    # `corpus/span/random1m.bin` (tests/run_tests.sh, lot H).
    stage('corpus/span/random.bin', lot / 'random.bin')
    stage('corpus/span/hello.txt', lot / 'hello.txt')
    big = stage('corpus/span/random1m.bin', lot / 'random1m.bin')

    oracle.archive(lot / 'span_15vol_m0.egg', [big], ['-a', '-m0', '-v100KB'])
    oracle.archive(lot / 'span_15vol_m1.egg', [big], ['-a', '-m1', '-v100KB'])
    oracle.archive(lot / 'span_15vol_m0.alz', [big], ['-a', '-m0', '-v100KB'])
    oracle.archive(lot / 'span_15vol_m2.alz', [big], ['-a', '-m2', '-v100KB'])
    oracle.archive(lot / 'span_15vol_crypt.egg', [big],
                   ['-a', '-m0', '-tp0', '-psecret', '-v100KB'])
    oracle.archive(lot / 'span_15vol_crypt.alz', [big],
                   ['-a', '-m0', '-tp0', '-psecret', '-v100KB'])

    multi = stage('corpus/span/multi', lot / 'multi')
    oracle.archive(lot / 'span_multi_100k.egg', ['-af', multi], ['-a', '-m0', '-v100KB'])
    oracle.archive(lot / 'span_nosplit_1mb.egg', [lot / 'hello.txt'],
                   ['-a', '-m1', '-v1MB'])

    # The `-v` floor: the low sizes exit 0 without writing anything, which is
    # the reference itself ("no effect", not a refusal). `-v10MB` was reported
    # to exit 1 on Windows; under Wine it writes a one-volume archive, so it is
    # a probe too (probe() discards the archive and prints what happened).
    for name, options in (('probe_v10k_m0.egg', ['-a', '-m0', '-v10KB']),
                          ('probe_v10k_m2.alz', ['-a', '-m2', '-v10KB']),
                          ('probe_v4k_m0.egg', ['-a', '-m0', '-v4KB']),
                          ('probe_v10mb.egg', ['-a', '-m1', '-v10MB'])):
        entry = lot / 'hello.txt' if 'v10mb' in name else lot / 'random.bin'
        oracle.probe(lot / name, [entry], options)


def h_solid(oracle, out):
    """Solid over a tree and a binary, plus the exact refusals (lot H)."""
    lot = out / 'lot-h' / 'solid'
    tree = lot / 'tree'
    stage('corpus/hello.txt', tree / 'a' / 'hello.txt')
    stage('corpus/code.c', tree / 'a' / 'code.c')
    stage('corpus/records.bin', tree / 'a' / 'sub' / 'records.bin')
    stage('corpus/random.bin', lot / 'random.bin')

    oracle.archive(lot / 'solid_tree_m1.egg', [tree], ['-a', '-s', '-m1'])
    oracle.archive(lot / 'solid_bin_m3.egg', [lot / 'random.bin'], ['-a', '-s', '-m3'])

    oracle.expect_refusal(lot / 'solid_refused_m0.egg', [tree / 'a' / 'hello.txt'],
                          ['-a', '-s', '-m0'])
    oracle.expect_refusal(lot / 'solid_refused_m2.egg', [tree / 'a' / 'hello.txt'],
                          ['-a', '-s', '-m2'])
    oracle.expect_refusal(lot / 'solid_refused_m4.egg', [tree / 'a' / 'hello.txt'],
                          ['-a', '-s', '-m4'])
    oracle.expect_refusal(lot / 'solid_refused_v.egg', [lot / 'random.bin'],
                          ['-a', '-s', '-m1', '-v10KB'])
    oracle.expect_refusal(lot / 'solid_refused_p.egg', [tree / 'a' / 'hello.txt'],
                          ['-a', '-s', '-m1', '-tp0', '-psecret'])
    oracle.expect_refusal(lot / 'solid_refused.alz', [tree / 'a' / 'hello.txt'],
                          ['-a', '-s', '-m1'])


def h_crypt(oracle, out):
    """Encryption per profile, per method, and the block-less cases (lot H)."""
    lot = out / 'lot-h' / 'crypt'
    for name in ('hello.txt', 'empty.dat', 'records.bin'):
        stage(f'corpus/{name}', lot / name)
    (lot / 'emptydir').mkdir(parents=True, exist_ok=True)

    for profile in '0123':
        for method in '012':
            oracle.archive(lot / f'enc_egg_m{profile}_tp{method}.egg',
                           [lot / 'hello.txt'],
                           ['-a', f'-m{profile}', f'-tp{method}', '-ppassword'])
    oracle.archive(lot / 'enc_egg_empty_tp0.egg', [lot / 'empty.dat'],
                   ['-a', '-m0', '-tp0', '-ppassword'])
    oracle.archive(lot / 'enc_egg_dir_tp0.egg', ['-af', lot / 'emptydir'],
                   ['-a', '-m1', '-tp0', '-ppassword'])

    two = lot / 'two'
    for name in ('hello.txt', 'records.bin'):
        stage(f'corpus/{name}', two / name)
    oracle.archive(lot / 'enc_egg_two_m0_tp0.egg', ['-af', two],
                   ['-a', '-m0', '-tp0', '-ppassword'])

    for profile in '0123':
        oracle.archive(lot / f'enc_alz_m{profile}.alz', [lot / 'hello.txt'],
                       ['-a', f'-m{profile}', '-tp0', '-psecret'])
    oracle.archive(lot / 'enc_alz_empty.alz', [lot / 'empty.dat'],
                   ['-a', '-m0', '-tp0', '-psecret'])

    attrs = lot / 'attrs'
    for name in ('hello.txt', 'records.bin'):
        stage(f'corpus/{name}', attrs / name)
    set_readonly(attrs / 'hello.txt')
    oracle.archive(lot / 'enc_alz_attrs.alz', ['-af', attrs],
                   ['-a', '-m1', '-tp0', '-psecret'])
    set_readonly(attrs / 'hello.txt', False)


def h_names(oracle, out):
    """Member order, case duplicates, routing, long and special names (lot H)."""
    lot = out / 'lot-h' / 'names'
    order = lot / 'order'
    for name in ('a.txt', 'B.txt', 'c1.txt', 'c10.txt', 'c2.txt', '-dash.txt',
                 '_underscore.txt', '.dotfile', 'z z.txt', 'A0.txt'):
        stage('corpus/hello.txt', order / name)
    oracle.archive(lot / 'names_order_m1.egg', ['-af', order], ['-a', '-m1'])

    # A case duplicate cannot exist in one NTFS directory, so both members are
    # added in two calls to the SAME archive (an append, not a creation).
    case1, case2 = lot / 'case1', lot / 'case2'
    stage('corpus/hello.txt', case1 / 'Alpha.txt')
    stage('corpus/records.bin', case2 / 'alpha.txt')
    target = lot / 'names_case_m1.egg'
    oracle.archive(target, [case1 / 'Alpha.txt'], ['-a', '-m1', '-nq'])
    oracle.archive(target, [case2 / 'alpha.txt'], ['-a', '-m1', '-nq'], append=True)

    route = lot / 'route'
    extensions = ('', '.tar.gz', '.docx', '.xlsx', '.pptx', '.mp4', '.cab',
                  '.iso', '.ttf', '.wav')
    suffixes = ('_noext', '_tar_gz', '_docx', '_xlsx', '_pptx', '_mp4', '_cab',
                '_iso', '_ttf', '_wav')
    for ext, suffix in zip(extensions, suffixes):
        entry = stage('corpus/mixed.bin', route / f'payload{ext}')
        oracle.archive(lot / f'route{suffix}_m3.egg', [entry], ['-a', '-m3'])
        oracle.archive(lot / f'route{suffix}_m4.egg', [entry], ['-a', '-m4'])
    stage('corpus/mixed.bin', route / 'PAYLOAD.TXT')
    oracle.archive(lot / 'route_upper_m3.egg', [route / 'PAYLOAD.TXT'], ['-a', '-m3'])
    oracle.archive(lot / 'route_upper_m4.egg', [route / 'PAYLOAD.TXT'], ['-a', '-m4'])
    # The reference was written on Windows, where `Payload.Txt` and `PAYLOAD.TXT`
    # are the same file: the staged copy kept the name it found, so the member
    # is stored upper case. Reproduce that name here rather than a second file
    # (which this filesystem allows but Windows does not); the extension still
    # selects the codec case-insensitively.
    oracle.archive(lot / 'route_mixedcase_m3.egg', [route / 'PAYLOAD.TXT'], ['-a', '-m3'])

    specials = lot / 'specials'
    for name in ('with space.txt', '100%.txt', 'a&b.txt', "quote's.txt",
                 'hash#.txt', 'brackets[1].txt', 'plus+.txt', 'l' * 190 + '.txt'):
        stage('corpus/hello.txt', specials / name)
    oracle.archive(lot / 'names_specials_m1.egg', ['-af', specials], ['-a', '-m1'])

    # Korean names: the ENCODING is what no reference settles, so the archive is
    # only produced by a prefix running under the Korean code page.
    kdir = lot / 'korean'
    stage('corpus/hello.txt', kdir / f'{KOREAN_DIR}_{KOREAN_FILE}.txt')
    if os.environ.get('FIXTURE_ACP') == '949':
        oracle.archive(lot / 'names_korean_m1.egg', ['-af', kdir], ['-a', '-m1'])
    else:
        print('  skipped: names_korean_m1.egg (needs a Korean Wine prefix; set '
              'FIXTURE_ACP=949 once it is created under LANG=ko_KR.UTF-8)')


def h_edges(oracle, out):
    """Empty archive, duplicate member, -xr, -an, lone directory (lot H)."""
    lot = out / 'lot-h' / 'edges'
    (lot / 'nothing').mkdir(parents=True, exist_ok=True)
    stage('corpus/hello.txt', lot / 'hello.txt')
    stage('corpus/records.bin', lot / 'records.bin')

    # No entry at all: what ALZip writes here is the reference, so neither an
    # archive nor a message counts as a failure.
    for name in ('empty_archive.egg', 'empty_archive.alz'):
        print(f'  {name}:')
        oracle.probe(lot / name, [], ['-a', '-m1'])

    # `-nq` keeps ALZipCon from asking anything before it overwrites a member;
    # the append is the case being observed, so the archive is kept.
    target = lot / 'edge_duplicate.egg'
    oracle.archive(target, [lot / 'hello.txt'], ['-a', '-m0', '-nq'])
    oracle.archive(target, [lot / 'hello.txt'], ['-a', '-m0', '-nq'], append=True)

    target = lot / 'edge_append.egg'
    oracle.archive(target, [lot / 'records.bin'], ['-a', '-m1', '-nq'])
    oracle.archive(target, [lot / 'hello.txt'], ['-a', '-m1', '-nq'], append=True)

    tree = lot / 'tree'
    stage('corpus/hello.txt', tree / 'top' / 'hello.txt')
    stage('corpus/records.bin', tree / 'top' / 'sub' / 'records.bin')
    oracle.archive(lot / 'edge_xr.egg', [tree / 'top'], ['-a', '-m1', '-xr'])

    # `-an*.bin` under Wine writes an archive holding only the members the
    # pattern does not match (`hello.txt` here, `records.bin` excluded), with and
    # without `-af`; the first Windows report saw no file at all. The writer has
    # no `-an`, so no test can replay these archives: probe() prints the outcome
    # and discards them rather than leaving fixtures nothing consumes.
    for name, sources in (('edge_an.egg', ['-af', tree / 'top']),
                          ('edge_an_plain.egg', [tree / 'top'])):
        print(f'  {name}:')
        oracle.probe(lot / name, sources, ['-a', '-m1', '-an*.bin'],
                     discard=True)

    only = lot / 'onlydir'
    only.mkdir(parents=True, exist_ok=True)
    oracle.archive(lot / 'edge_dir_only.egg', ['-af', only], ['-a', '-m1'])
    oracle.archive(lot / 'edge_dir_only.alz', ['-af', only], ['-a', '-m1'])

    ok, output = oracle.run(['-t', oracle.wine_path(lot / 'edge_dir_only.egg')])
    print('  -t: archive valid for ALZip' if ok else f'  -t: refused ({output})')


H_GROUPS = ('huge', 'span', 'solid', 'crypt', 'names', 'edges')


def check_references(produced):
    """Every archive a run writes must have a checked-in reference.

    `make test` reads `packed_egg_8.0/` and `packed_alz_8.0/`, so an archive with
    no twin there is a dead output: it cannot be replayed, compared or consumed.
    This is the check that would have caught the deleted lot E matrix still being
    regenerated (and it is why probes that write archives outside the corpus
    discard them). Content equality is `tools/fixture_parity.py`'s job; this
    guard is about the produced set and the corpus agreeing on *which* archives
    exist, volumes included.
    """
    orphans = []
    for path in produced:
        # `.a00`, `.a01`, … belong to the `.alz` family, like the writer's
        # `same_family()`.
        suffix = '.alz' if re.fullmatch(r'\.a\d+', path.suffix) else path.suffix
        references = REPO / f'packed_{suffix[1:]}_8.0' / path.name
        if not references.exists():
            orphans.append(path)
    if orphans:
        print(f'{len(orphans)} produced archive(s) have no reference in '
              f'packed_*_8.0:')
        for path in orphans:
            try:
                print(f'  {path.relative_to(REPO)}')
            except ValueError:
                print(f'  {path}')
        return False
    print(f'all {len(produced)} produced archive file(s) have a checked-in '
          f'reference')
    return True


# ------------------------------------------------------------------------ main
def main(argv=None):
    parser = argparse.ArgumentParser(
        description='Regenerate the ALZip 8.0 fixture sets under Wine.')
    parser.add_argument('--only', default='a,b,c,d,g,h',
                        help='comma-separated sets (default: all of them)')
    parser.add_argument('--no-verify', action='store_true',
                        help='do not check that every produced archive has a '
                             'reference in packed_*_8.0')
    parser.add_argument('--only-h', default=','.join(H_GROUPS),
                        help='comma-separated set H groups (default: all)')
    parser.add_argument('--skip-huge', action='store_true',
                        help='skip the 5 GiB members (set c and the "huge" group)')
    parser.add_argument('--out', default='fixtures/out',
                        help='output directory, repository-relative')
    parser.add_argument('--work', default='out/oracle-8',
                        help='Wine prefix and install copy (default: out/oracle-8)')
    parser.add_argument('--install', default=str(DEFAULT_INSTALL),
                        help='ALZip 8.0 install to copy into the prefix')
    parser.add_argument('--quiet', action='store_true', help='only report results')
    args = parser.parse_args(argv)

    out = (REPO / args.out).resolve()
    if REPO not in out.parents and out != REPO:
        raise SystemExit('--out must stay inside the repository')

    oracle = Oracle(args.install, (REPO / args.work).resolve(), quiet=args.quiet)
    try:
        oracle.prepare()
    except Fail as exc:
        print(f'error: {exc}', file=sys.stderr)
        return 1

    wanted = {part.strip() for part in args.only.split(',') if part.strip()}
    groups = {part.strip() for part in args.only_h.split(',') if part.strip()}
    if 'e' in wanted:
        raise SystemExit('set e is retired: its routing matrix was deleted from '
                         'the corpus (FIXTURES.md, lot E) and the table is '
                         'replayed from packed_egg/routes_optimized.egg and '
                         'packed_egg_8.0/gui_normal_matrix.egg')
    unknown = wanted - set('abcdfgh')
    if unknown:
        raise SystemExit(f'unknown set(s): {", ".join(sorted(unknown))}')
    unknown = groups - set(H_GROUPS)
    if unknown:
        raise SystemExit(f'unknown set H group(s): {", ".join(sorted(unknown))}')

    print(f'ALZipCon : {oracle.copy}')
    print(f'prefix   : {oracle.prefix}')
    print(f'output   : {out}')

    started = time.time()
    plan = [('a', 'encryption on the write side', lambda: set_a(oracle, out)),
            ('b', 'ALZ encryption with paths, non-ASCII tree', lambda: set_b(oracle, out)),
            ('c', 'large members, volumes, solid',
             lambda: set_c(oracle, out, skip_huge=args.skip_huge)),
            ('d', 'metadata', lambda: set_d(oracle, out)),
            ('g', 'AZO samples', lambda: set_g(oracle, out))]
    for name, title, run in plan:
        if name in wanted:
            print(f'\n[{name}] {title}', flush=True)
            # A broken set stops that set, not the remaining ones: ALZipCon
            # refusals are recorded per call and the summary lists them.
            try:
                run()
            except Fail as exc:
                print(f'  set {name} interrupted: {exc}', file=sys.stderr)
                oracle.failed.append(([f'set {name}'], str(exc)))

    if 'h' in wanted:
        handlers = {'huge': h_huge, 'span': h_span, 'solid': h_solid,
                    'crypt': h_crypt, 'names': h_names, 'edges': h_edges}
        for name in H_GROUPS:
            if name not in groups:
                continue
            if name == 'huge' and args.skip_huge:
                print('\n[h/huge] skipped (--skip-huge)')
                continue
            print(f'\n[h/{name}]', flush=True)
            try:
                handlers[name](oracle, out)
            except Fail as exc:
                print(f'  group {name} interrupted: {exc}', file=sys.stderr)
                oracle.failed.append(([f'h/{name}'], str(exc)))

    elapsed = int(time.time() - started)
    print(f'\n{len(oracle.produced)} archive file(s) produced in {out} ({elapsed} s)')
    references_ok = True
    if not args.no_verify:
        references_ok = check_references(oracle.produced)
    if oracle.failed:
        print(f'{len(oracle.failed)} call(s) failed:')
        for argv, output in oracle.failed:
            print(f'  ALZipCon {" ".join(str(a) for a in argv)}')
            if output:
                for line in output.splitlines():
                    print(f'    {line}')
        return 1
    return 0 if references_ok else 1


if __name__ == '__main__':
    sys.exit(main())
