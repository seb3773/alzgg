#!/usr/bin/env python3
"""Replay `fixtures/corpus-12.30.manifest`: every 12.30 reference must be
reproduced **byte for byte** by `alz create` with the same options.

    python3 tools/manifest_parity.py SCRATCH_DIR [--verbose]

This is the reference wiring of `make test`: the manifest is the only list of
12.30 archives, and every line in it is a required proof. The script copies
neither the options nor the member names by hand:

  * options are translated from the manifest (`-mN`, `-s`, `-v…`, `-tpN`,
    `-ppassword`) into an `alz create` command line, which is not the same for
    ALZ (`-o`) and for EGG;
  * the input tree is rebuilt **from the reference**: each member is rewritten
    at its archived path with the bytes of its source in `corpus/`, then
    `alz create` receives the top-level entries. Member names, sizes and dates
    are therefore the reference's by construction, and a missing entry is
    reported, never guessed;
  * the comparison masks what ALZip draws at random — Header ID, volume string
    identifiers, encryption material — and the FILETIMEs, through
    `tools/egg_mask_compare.py` (EGG) and `tools/archive_compare.py` (ALZ).

No masking covers payloads, block headers, codec hints, volume sizes or names:
a difference there is a failure.
"""
import glob
import os
import random
import re
import shutil
import subprocess
import sys

TOOLS = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(TOOLS)
sys.path.insert(0, TOOLS)

import egg_dump as ed          # independent structural parser (EGG)
import header_dump as hd       # ALZ parser
import archive_compare as ac   # ALZ comparison (volumes included)
import egg_mask_compare as emc  # EGG comparison (random masks)

MANIFEST = os.path.join(ROOT, 'fixtures', 'corpus-12.30.manifest')
ALZ = os.path.join(ROOT, 'alzgg')

EGG_PROFILE = {'0': 'none', '1': 'compspeed', '2': 'normal',
               '3': 'compratio', '4': 'optimized'}
CIPHER = {'0': 'zip', '1': 'aes128', '2': 'aes256',
          '3': 'lea128', '4': 'lea256'}

MZ_SRC = os.environ.get('ALZIP_80_DIR', os.path.join(ROOT, '_work', 'binaries', 'alzip-8.0'))
if not os.path.isdir(MZ_SRC):
    MZ_SRC = os.path.join(ROOT, 'research', 'Program Files (x86)', 'ALZip')
PASSWORD = b'password'


# --------------------------------------------------------------------------
# Sources: the bytes of each archived member, recovered from `corpus/`.
# --------------------------------------------------------------------------
def _read(path):
    with open(path, 'rb') as f:
        return f.read()


def _candidate_paths(name):
    """Paths under `corpus/` where the source of an archived member may live."""
    # Archived names sometimes keep a staging prefix
    # (`fixtures/out/lot-b/nested/…`) and ALZip strips leading spaces from a
    # path component (`café_clair/ nested/` -> `café_clair/nested/`).
    normalised = '/'.join(part.strip() for part in name.split('/'))
    for candidate in (name, normalised, os.path.join('nested', name),
                      os.path.join('unicode', name),
                      os.path.join('unicode', normalised),
                      os.path.basename(name)):
        yield os.path.join(ROOT, 'corpus', candidate)


def resolve(name):
    """('dir', path) | ('file', bytes, mode) | None.

    The mode is the source's: it carries the Windows attributes the writer
    derives (read-only, hidden), which the comparison does not mask.
    """
    if name.startswith('routes/') or '/routes/' in name:
        return ('file', _read(os.path.join(ROOT, 'corpus', 'eng.txt'))[:4096], 0o644)
    base = os.path.basename(name)
    if base == 'probe.com':                 # same payload as .sys
        return ('file', _read(os.path.join(ROOT, 'corpus', 'probe.sys')), 0o644)
    if base == 'sysmulti.sys':
        return ('file', _read(os.path.join(ROOT, 'corpus', 'code.c')) * 14, 0o644)
    if base == 'mz.sys':
        return ('file', _read(os.path.join(MZ_SRC, 'Coders', 'Deflate.dll')), 0o644)
    if base == 'mzmulti.sys':
        return ('file', _read(os.path.join(MZ_SRC, 'ALZipCon.exe')), 0o644)
    if base in ('mzraw.sys', 'mzraw2.sys'):
        r = random.Random(0x415a4f)
        n = 524288 if base == 'mzraw.sys' else 2 * 524288
        return ('file', b'MZ' + bytes(r.randrange(256) for _ in range(n - 2)),
                0o644)

    for path in _candidate_paths(name):
        if os.path.isdir(path):
            return ('dir', path)
        if os.path.isfile(path):
            return ('file', _read(path), os.stat(path).st_mode & 0o777)
    for dirpath, _dirs, files in os.walk(os.path.join(ROOT, 'corpus', 'unicode')):
        if base in files:
            path = os.path.join(dirpath, base)
            return ('file', _read(path), os.stat(path).st_mode & 0o777)
    return None


# --------------------------------------------------------------------------
# Manifest
# --------------------------------------------------------------------------
def parse_manifest():
    cases = []
    with open(MANIFEST) as fp:
        for line in fp:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            dest, opts, inputs = line.split('|')
            cases.append({'dest': dest, 'opts': opts.split(),
                          'inputs': inputs.split()})
    return cases


def volume_bytes(spec):
    """`100KB` -> 102400: the ALZ CLI does not read suffixes, EGG does."""
    match = re.fullmatch(r'(\d+)([KMG]?)B?', spec, re.IGNORECASE)
    if not match:
        raise SystemExit(f'unreadable volume size: {spec}')
    size = int(match.group(1))
    factor = {'': 1, 'K': 1024, 'M': 1024 ** 2, 'G': 1024 ** 3}[match.group(2).upper()]
    return size * factor


def egg_options(case):
    args = []
    for opt in case['opts']:
        if opt == '-s':
            args.append('-s')
        elif opt.startswith('-m'):
            level = opt[2:]
            if level not in EGG_PROFILE:
                raise SystemExit(f'{case["dest"]}: unknown EGG profile {opt}')
            args += ['-p', EGG_PROFILE[level]]
        elif opt.startswith('-v'):
            args += ['-v', opt[2:]]
        elif opt.startswith('-tp'):
            args += ['--crypt', CIPHER[opt[3:]]]
        elif opt.startswith('-p'):
            args += ['--password', opt[2:].decode() if isinstance(opt, bytes)
                     else opt[2:]]
        else:
            raise SystemExit(f'{case["dest"]}: unknown EGG option {opt}')
    return args


def alz_options(case):
    args = []
    for opt in case['opts']:
        if opt.startswith('-m'):
            args.append(opt)              # the ALZ CLI takes -mN as-is
        elif opt.startswith('-v'):
            args += ['-v', str(volume_bytes(opt[2:]))]
        elif opt.startswith('-tp'):
            if opt != '-tp0':
                raise SystemExit(f'{case["dest"]}: ALZ only encrypts with ZipCrypto')
        elif opt.startswith('-p'):
            args += ['--password', opt[2:]]
        else:
            raise SystemExit(f'{case["dest"]}: unknown ALZ option {opt}')
    return args


# --------------------------------------------------------------------------
# ZipCrypto material (ALZ): ALZip draws it at random, so we read it back from
# the reference, the way step 12 of `make test` does.
# --------------------------------------------------------------------------
_ZT = []
for _i in range(256):
    _c = _i
    for _ in range(8):
        _c = (_c >> 1) ^ (0xEDB88320 if _c & 1 else 0)
    _ZT.append(_c)


def _zupd(k, c):
    k[0] = (k[0] >> 8) ^ _ZT[(k[0] ^ c) & 0xFF]
    k[1] = ((k[1] + (k[0] & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF
    k[2] = (k[2] >> 8) ^ _ZT[(k[2] ^ (k[1] >> 24)) & 0xFF]


def zip_material(stored, crc):
    k = [0x12345678, 0x23456789, 0x34567890]
    for b in PASSWORD:
        _zupd(k, b)
    plain = bytearray()
    for b in stored:
        t = (k[2] | 2) & 0xFFFFFFFF
        plain.append(b ^ ((((t * (t ^ 1)) & 0xFFFFFFFF) >> 8) & 0xFF))
        _zupd(k, plain[-1])
    if plain[10] != ((crc >> 16) & 0xFF) or plain[11] != ((crc >> 24) & 0xFF):
        raise SystemExit(f'inconsistent ZipCrypto verifier: {plain.hex()}')
    return bytes(plain[:10]).hex()


def alz_crypt_info(ref):
    blob = _read(ref)
    mats = []
    for name, info in hd.parse(ref)[0][2]:
        if name == 'END' or info is None or not info['fd'] & 1:
            continue
        at = info['data_off']
        mats.append(zip_material(blob[at:at + 12], info['crc']))
    return ','.join(mats) if mats else None


def egg_crypt_info(ref):
    """Encryption material read back from the EGG reference.

    ZipCrypto decrypts into 10 bytes of material (the verifier also carries the
    two high bytes of the CRC); AES and LEA have only a salt, 8 bytes for
    128-bit keys and 16 for 256-bit ones.
    """
    mats = []
    try:
        entries = ed.parse(ref)['files']
    except ed.Fail:
        entries = _logical_parse(ref)['files']
    for entry in entries:
        crypt = entry.get('crypt')
        if not crypt:
            continue
        data = bytes.fromhex(crypt['data'])
        if crypt['method'] == 0:
            crc = entry['blocks'][0]['crc']
            mats.append(zip_material(data[:12],
                                     int(crc, 16) if isinstance(crc, str) else crc))
        else:
            mats.append(data[:16 if crypt['method'] % 2 == 0 else 8].hex())
    return ','.join(mats) if mats else None


def _logical_parse(path):
    """`egg_dump.parse` on the reassembled stream of a split archive."""
    import tempfile
    _ordered, logical = ed.vol_chain(path)
    handle, tmp = tempfile.mkstemp(suffix='.egg')
    try:
        with os.fdopen(handle, 'wb') as fp:
            fp.write(logical)
        return ed.parse(tmp)
    finally:
        os.remove(tmp)


def dos_stamps(ref):
    """DOS timestamps of the members, in the reference's order."""
    stamps = []
    for name, info in hd.parse(ref)[0][2]:
        if name == 'END' or info is None or info.get('attr', 0) & 0x10:
            continue
        ts = info['time']
        stamps.append('%d-%02d-%02d %02d:%02d:%02d' % (
            1980 + (ts >> 25), (ts >> 21) & 15, (ts >> 16) & 31,
            (ts >> 11) & 31, (ts >> 5) & 63, (ts & 31) * 2))
    return stamps


def header_ids(ref):
    """One Header ID per volume: ALZip draws them from a non-reproducible counter.

    The writer therefore needs them supplied to reproduce a split chain
    (`-i id1,id2,…`)."""
    ids = []
    for path in egg_volumes(ref):
        blob = _read(path)
        ids.append(int.from_bytes(blob[6:10], 'little'))
    return ','.join('0x%x' % value for value in ids)


def alz_volumes(path):
    base = path[:-4]
    found = [path]
    index = 0
    while os.path.isfile(f'{base}.a{index:02d}'):
        found.append(f'{base}.a{index:02d}')
        index += 1
    return found


def alz_bytes_equal(ref, produced):
    """Strict ALZ volume comparison, encrypted archives included.

    `archive_compare` skips `csize` bytes after the header and therefore
    ignores the 12-byte verifier of an encrypted member; when the material is
    reinjected (--crypt-info), the archive must be identical byte for byte.
    """
    ref_vols, gen_vols = alz_volumes(ref), alz_volumes(produced)
    if len(ref_vols) != len(gen_vols):
        return f'{len(gen_vols)} volumes generated, {len(ref_vols)} expected'
    for index, (r, g) in enumerate(zip(ref_vols, gen_vols)):
        want, got = _read(r), _read(g)
        if want != got:
            at = next((i for i in range(min(len(want), len(got)))
                       if want[i] != got[i]), min(len(want), len(got)))
            return (f'volume {index}: {len(got)} bytes for {len(want)}, '
                    f'first difference at 0x{at:x}')
    return None


# --------------------------------------------------------------------------
# Staging from the reference
# --------------------------------------------------------------------------
def reference_members(ref):
    """(name, kind, wininfo, usize) of every member, volumes included."""
    first = ref
    if '.vol' in ref:
        first = re.sub(r'\.vol\d+\.egg$', '.vol1.egg', ref)
    if first.endswith('.egg'):
        try:
            entries = ed.parse(first)['files']
        except ed.Fail:
            # Split reference: the first volume only carries a fragment of each
            # member, so go through the reassembled logical stream.
            entries = _logical_parse(first)['files']
        return [(e['name'], e.get('kind'), e.get('wininfo'),
                 sum(b['usize'] for b in e.get('blocks', [])))
                for e in entries]
    # ALZ: header_dump returns [(path, volume, [(name, infos)])], with a final
    # "END" entry; bit 4 of the attributes marks a directory.
    entries = hd.parse(first)[0][2]
    if isinstance(entries, str):
        raise SystemExit(f'{ref}: unreadable ({entries})')
    members = []
    for name, info in entries:
        if name == 'END' or info is None:
            continue
        if info.get('attr', 0) & 0x10 or name.endswith('/'):
            members.append((name.rstrip('/'), 'dir', None, 0))
        else:
            members.append((name, 'file', None, info.get('usize', 0)))
    return members


def stage_from_reference(case, stage):
    """Rewrite every reference member into `stage` from `corpus/`.

    Returns (entries in the reference's order, members without a source).
    Order matters: both formats archive members in the order they receive, and
    the comparison does not mask that order.
    """
    ref = os.path.join(ROOT, case['dest'])
    ordered, missing = [], []
    for name, _kind, wininfo, usize in reference_members(ref):
        path = os.path.join(stage, *name.split('/'))
        resolved = resolve(name)
        if resolved is None and usize == 0:
            resolved = ('file', b'', 0o644)
        if resolved is None:
            missing.append(name)
            continue
        if resolved[0] == 'dir':
            # Empty directory: the writer makes it a member with attr=0x80,
            # usize=0.
            os.makedirs(path, exist_ok=True)
            ordered.append(name)
            continue
        _kind2, data, mode = resolved
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'wb') as fp:
            fp.write(data)
        os.chmod(path, mode)
        if wininfo and wininfo.get('filetime'):
            # FILETIME is UTC while the writer goes through local time, so we
            # set the UTC wall clock as local time; otherwise the field drifts
            # by the time zone (2 h here) and so does the archive.
            import datetime
            wall = wininfo['filetime'] // 10000000 - 11644473600
            epoch = int(datetime.datetime.utcfromtimestamp(wall)
                        .astimezone().timestamp())
            os.utime(path, (epoch, epoch))
        ordered.append(name)
    return ordered, missing


# --------------------------------------------------------------------------
# Comparison
# --------------------------------------------------------------------------
def egg_volumes(path):
    base = re.sub(r'\.vol\d+\.egg$', '', path)
    found = glob.glob(base + '.vol*.egg')
    if not found:
        return []
    return sorted(found,
                  key=lambda p: int(re.search(r'\.vol(\d+)\.egg$', p).group(1)))


def compare(case, produced):
    ref = os.path.join(ROOT, case['dest'])
    if case['dest'].endswith('.egg'):
        ref_vols = egg_volumes(ref)
        if ref_vols:
            stem = produced[:-len('.egg')] if produced.endswith('.egg') else produced
            gen_vols = egg_volumes(re.sub(r'\.vol\d+$', '', stem) + '.vol1.egg')
            if len(gen_vols) != len(ref_vols):
                return (f'{len(gen_vols)} volumes generated, '
                        f'{len(ref_vols)} expected')
            for index, (r, g) in enumerate(zip(ref_vols, gen_vols), 1):
                if emc.main(['egg_mask_compare.py', '--volume', r, g]):
                    return f'volume {index} differs'
            return None
        if not os.path.isfile(produced):
            return 'no archive generated'
        return (None if emc.main(['egg_mask_compare.py', ref, produced]) == 0
                else 'archive differs')

    if alz_crypt_info(ref):
        return alz_bytes_equal(ref, produced)
    # Plain ALZ: archive_compare handles the volume chain and masks the DOS
    # timestamps, the only non-reproducible bytes.
    try:
        ac.compare(ref, produced)
    except (ac.ArchiveError, OSError, ValueError) as exc:
        return str(exc)
    return None


# --------------------------------------------------------------------------
def main(argv):
    if len(argv) < 2:
        print('usage: manifest_parity.py SCRATCH_DIR [--verbose]', file=sys.stderr)
        return 2
    work = os.path.abspath(argv[1])
    verbose = '--verbose' in argv
    # The directory is reused across runs: start from an empty state, otherwise
    # `alz create` refuses to overwrite its own outputs.
    if os.path.isdir(work):
        shutil.rmtree(work)
    os.makedirs(work)

    cases = parse_manifest()
    failures = []
    for index, case in enumerate(cases):
        dest = case['dest']
        is_egg = dest.endswith('.egg')
        stage = os.path.join(work, f'case{index:02d}')
        os.makedirs(stage)

        ref = os.path.join(ROOT, dest)
        if not os.path.exists(ref):
            failures.append((dest, 'reference missing'))
            continue
        entries, missing = stage_from_reference(case, stage)
        if missing:
            failures.append((dest, 'no source for ' + ', '.join(missing)))
            continue

        target = os.path.join(work, f'gen{index:02d}' + ('.egg' if is_egg else '.alz'))
        if is_egg:
            args = [ALZ, 'create', target] + egg_options(case)
            mats = egg_crypt_info(ref)
            if mats:
                args += ['--crypt-info', mats]
            if egg_volumes(ref):
                args += ['-i', header_ids(ref)]
            args += entries
        else:
            args = [ALZ, 'create', '-o', target] + alz_options(case)
            mats = alz_crypt_info(ref)
            if mats:
                args += ['--crypt-info', mats]
            stamps = dos_stamps(ref)
            if stamps:
                args += ['-T', ','.join(stamps)]
            args += entries
        result = subprocess.run(args, cwd=stage, capture_output=True, text=True)
        if result.returncode:
            failures.append((dest, 'create failed: '
                             + (result.stderr or result.stdout).strip()))
            continue

        problem = compare(case, target)
        if problem:
            failures.append((dest, problem))
            continue
        if verbose:
            print(f'  OK   {dest}')

    for dest, problem in failures:
        print(f'  FAIL {dest}: {problem}', file=sys.stderr)
    print(f'{len(cases) - len(failures)}/{len(cases)} 12.30 references '
          f'reproduced byte for byte')
    return 1 if failures else 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv))
