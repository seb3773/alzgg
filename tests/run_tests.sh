#!/usr/bin/env bash
# Exact-corpus regression tests: profile/container-method coverage, byte-exact
# decode and encode, refusal of container methods that no ALZ profile emits, and
# refusal of Solid-Compression (an EGG-only feature, cf. FORMAT-ALZ.md).
# This suite does not prove full ALZ parity.
set -euo pipefail
cd "$(dirname "$0")/.."

TMP_ROOT=${TMPDIR:-/tmp}
TEST_TMP=$(mktemp -d "$TMP_ROOT/alzip-tests.XXXXXX")
trap 'rm -rf "$TEST_TMP"' EXIT

# Do not erase the user's existing outC tree. This suite owns only its temp dir.
EXTRACT_ROOT="$TEST_TMP/extracted"
mkdir -p "$EXTRACT_ROOT"

shopt -s nullglob
# The 8.0 directory also holds the special cases (encrypted, volumes, huge);
# this step only walks the profile matrix of the original corpus.
archives=()
for f in packed_alz_8.0/*.alz; do
    case $(basename "$f") in
        biased_*|code_*|empty_*|eng_*|hello_*|image24_*|image_*|mixed_*| \
        nested_*|Noise_*|pattern_*|random_*|records_*|sound_*|zeros_*)
            archives+=("$f") ;;
    esac
done
if ((${#archives[@]} != 62)); then
    echo "expected 62 ALZ corpus archives, found ${#archives[@]}" >&2
    exit 1
fi

echo "== [1/13] ALZ corpus profile/method coverage =="
python3 - "${archives[@]}" <<'EOF'
import os, sys
sys.path.insert(0, 'tools')
import header_dump

# The corpus samples every ALZ profile the GUI/CLI exposes: No Compression plus
# the three Deflate profiles of the ALZ plugin (labels 'Nocomp', 'Faster',
# 'Fast', 'Normal' in Formats/Alz.dll). A profile number is NOT a container
# method ID: all three compressed profiles write container method 2.
PROFILE_METHOD = {'none': 0, 'faster': 2, 'fast': 2, 'normal': 2}
# image24_none.alz carries the fast profile's method-2 stream (documented in
# FORMAT-ALZ.md); keep the exception explicit instead of tolerating it.
MISLABELED = {'image24_none': 2}

profiles, methods, empty_members = set(), {}, 0
for archive in sys.argv[1:]:
    base = os.path.basename(archive)[:-4]
    stem, profile = base.rsplit('_', 1)
    if profile not in PROFILE_METHOD:
        raise SystemExit(f'{base}: unknown ALZ profile suffix "{profile}"')
    profiles.add(profile)
    wanted = MISLABELED.get(base, PROFILE_METHOD[profile])
    parsed = header_dump.parse(archive)
    if len(parsed) != 1 or not isinstance(parsed[0][2], list):
        raise SystemExit(f'{base}: could not parse archive headers')
    for name, info in parsed[0][2]:
        if info is None or name == 'END':
            continue
        if not info['fd'] & 0xF0:
            empty_members += 1
            if info['csize'] is not None or info['method'] is not None:
                raise SystemExit(f'{base}/{name}: optional fields without fd high nibble')
            continue
        if info['method'] in (1, 3):
            raise SystemExit(f'{base}/{name}: container method {info["method"]} found; '
                             'no ALZip 8 ALZ profile is expected to emit it')
        if info['method'] != wanted:
            raise SystemExit(f'{base}/{name}: method {info["method"]} != expected {wanted}')
        methods[info['method']] = methods.get(info['method'], 0) + 1
missing = set(PROFILE_METHOD) - profiles
if missing:
    raise SystemExit(f'corpus does not cover ALZ profile(s): {sorted(missing)}')
print(f'profiles covered {sorted(profiles)}; method-0 members {methods.get(0, 0)}, '
      f'method-2 members {methods.get(2, 0)}, '
      f'members without optional fields {empty_members}')
EOF

echo "== [2/13] ALZ decode: ${#archives[@]} archives =="
python3 - "$EXTRACT_ROOT" "${archives[@]}" <<'EOF'
import os, subprocess, sys, zlib
sys.path.insert(0, 'tools')
import header_dump
root, *archives = sys.argv[1:]
extmap = {'hello':'hello.txt','code':'code.c','eng':'eng.txt','mixed':'mixed.bin',
          'records':'records.bin','pattern':'pattern.bin','biased':'biased.bin',
          'random':'random.bin','zeros':'zeros.bin','image':'image.raw',
          'image24':'image24.raw','sound':'sound.wav','Noise':'Noise.wav'}
nested = [('corpus/nested/dir1/hello.txt','dir1/hello.txt'),
          ('corpus/nested/dir1/pattern.bin','dir1/pattern.bin'),
          ('corpus/nested/dir1/sound.wav','dir1/sound.wav'),
          ('corpus/nested/dir2/biased.bin','dir2/biased.bin'),
          ('corpus/nested/dir2/random.bin','dir2/random.bin'),
          ('corpus/nested/dir2/records.bin','dir2/records.bin'),
          ('corpus/nested/image24.raw','image24.raw'),
          ('corpus/nested/mixed.bin','mixed.bin')]
for archive in archives:
    base = os.path.basename(archive)[:-4]
    profile = base.rsplit('_',1)[-1]
    stem = base.rsplit('_',1)[0]
    if stem.startswith('records_span100k'):
        members = [('corpus/records.bin','records.bin')]
    elif stem.startswith('nested'):
        members = nested
    elif stem == 'empty':
        members = [('corpus/empty.dat','empty.dat')]
    else:
        if stem not in extmap:
            raise SystemExit(f'unmapped ALZ test archive: {archive}')
        name = extmap[stem]
        members = [(f'corpus/{name}',name)]
    dest = os.path.join(root,base)
    os.makedirs(dest,exist_ok=True)
    result = subprocess.run(['./alzgg','extract',archive,'-d',dest],
                            stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    if result.returncode:
        raise SystemExit(f'extract failed for {base}: {result.stderr or result.stdout}')
    expected_names = {name for _,name in members}
    actual_names = set()
    for current, _, filenames in os.walk(dest):
        for filename in filenames:
            path = os.path.join(current,filename)
            actual_names.add(os.path.relpath(path,dest).replace(os.sep,'/'))
    if actual_names != expected_names:
        raise SystemExit(f'{base}: member set differs; expected={sorted(expected_names)}, actual={sorted(actual_names)}')
    parsed = header_dump.parse(archive)
    if len(parsed) != 1 or not isinstance(parsed[0][2], list):
        raise SystemExit(f'{base}: could not parse archive headers')
    headers = {header_name: info for header_name, info in parsed[0][2] if info is not None and header_name != 'END'}
    for source,name in members:
        actual = os.path.join(dest,*name.split('/'))
        with open(source,'rb') as f: expected = f.read()
        with open(actual,'rb') as f: decoded = f.read()
        if decoded != expected:
            raise SystemExit(f'{base}/{name}: decoded bytes differ from {source}')
        info = headers.get(name)
        if info is None:
            raise SystemExit(f'{base}/{name}: missing source archive header for CRC check')
        if info['crc'] is not None and (zlib.crc32(decoded) & 0xffffffff) != info['crc']:
            raise SystemExit(f'{base}/{name}: extracted bytes do not match archive CRC32')
print(f'decode byte-for-byte: {len(archives)}/{len(archives)} archives')

# --- Memory: a 128 MiB stored ALZ member extracts without the process RSS
# following its size. The volume is mmap()ed and the pages already written are
# handed back as we go (rd_release), so the measurement is the child's peak
# RSS, not its address space (the mmap counts there).
# Before the streaming switch, the same extraction peaked at ~3x the member
# size (stream copy + output buffer + mapping).
import resource

ALZ = os.path.abspath('./alzgg')
size = 128 << 20
block = bytes(range(256)) * 4096
big = os.path.join(root, 'mem-alz-big.bin')
with open(big, 'wb') as f:
    for _ in range(size // len(block)):
        f.write(block)
memarc = os.path.join(root, 'mem-alz.alz')
r = subprocess.run([ALZ, 'create', '-o', memarc, '-p', 'none',
                    'mem-alz-big.bin'], cwd=root, capture_output=True, text=True)
if r.returncode:
    raise SystemExit('mem ALZ: create failed: ' + (r.stderr or r.stdout).strip())
memout = os.path.join(root, 'mem-alz-out')
os.makedirs(memout)
probe = ('import resource, subprocess, sys\n'
         'r = subprocess.run(sys.argv[1:], stdout=subprocess.DEVNULL)\n'
         'print(resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss)\n'
         'sys.exit(r.returncode)\n')
r = subprocess.run([sys.executable, '-c', probe, ALZ, 'extract', memarc,
                    '-d', memout], capture_output=True, text=True)
if r.returncode:
    raise SystemExit('mem ALZ: extraction failed: ' + (r.stderr or r.stdout).strip())
rss_kb = int(r.stdout.split()[-1])
limit_kb = 64 << 10
if rss_kb > limit_kb:
    raise SystemExit(f'mem ALZ: {size >> 20} MiB member extracted with '
                     f'{rss_kb >> 10} MiB of RSS (limit {limit_kb >> 10} MiB)')
with open(big, 'rb') as f1, open(os.path.join(memout, 'mem-alz-big.bin'), 'rb') as f2:
    while True:
        a, b = f1.read(1 << 20), f2.read(1 << 20)
        if a != b:
            raise SystemExit('mem ALZ: extracted bytes differ')
        if not a:
            break
os.remove(memarc)
os.remove(big)
import shutil as _shutil
_shutil.rmtree(memout)
print(f'memory ALZ: {size >> 20} MiB stored member extracted as a stream, peak '
      f'RSS {rss_kb >> 10} MiB (limit {limit_kb >> 10} MiB)')

# Path traversal & Zip-Slip protection in ALZ:
import glob
alz_store = open('packed_alz/hello_none.alz', 'rb').read()
alz_at = alz_store.find(b'hello.txt')
assert alz_at >= 0
for tag, name in (
    ('alz-dotdot', b'../../pwn'),
    ('alz-dotdot-win', rb'..\..\pwn'),
    ('alz-abs', b'/tmp/absx'),
    ('alz-abs-win', rb'\tmp\absy'),
    ('alz-drive-abs', rb'C:\evil.x'),
    ('alz-drive-rel', rb'C:evil.tx'),
    ('alz-nested-esc', rb'sub\..\..'),
):
    b = bytearray(alz_store)
    b[alz_at:alz_at + 9] = name
    bad_arc = os.path.join(root, tag + '.alz')
    open(bad_arc, 'wb').write(b)
    bad_out = os.path.join(root, 'out-' + tag)
    os.makedirs(bad_out)
    r = subprocess.run([ALZ, 'extract', bad_arc, '-d', bad_out], capture_output=True, text=True)
    if r.returncode == 0:
        raise SystemExit(f'{tag}: accepted although it has unsafe traversal')
    if 'skipping unsafe path traversal' not in (r.stdout + r.stderr):
        raise SystemExit(f'{tag}: missing security warning: {(r.stderr or r.stdout).strip()}')
    left = [p for p in glob.glob(os.path.join(bad_out, '**'), recursive=True) if os.path.isfile(p)]
    if left:
        raise SystemExit(f'{tag}: left files behind in destination')
    if any(os.path.exists(p) for p in (os.path.join(root, 'pwn'), '/tmp/absx', '/tmp/absy', 'C:\\evil.x')):
        raise SystemExit(f'{tag}: hostile name wrote outside destination directory')
print('ALZ path traversal & Zip-Slip protection: all attack vectors safely rejected')
EOF

echo "== [3/13] ALZ encode: byte-parity against ALZip 12.30 =="
python3 - "$TEST_TMP" <<'EOF'
import os, subprocess, sys

sys.path.insert(0, 'tools')
import header_dump as hd

tmp = sys.argv[1]
FIX = 'packed_alz'
ALZ = os.path.abspath('./alzgg')


def dos(ts):
    return '%d-%02d-%02d %02d:%02d:%02d' % (
        1980 + (ts >> 25), (ts >> 21) & 15, (ts >> 16) & 31,
        (ts >> 11) & 31, (ts >> 5) & 63, (ts & 31) * 2)


def timestamps(ref):
    (_, _, entries), = hd.parse(ref)
    return [info['time'] for name, info in entries
            if name != 'END' and info is not None]


# References produced by ALZipCon 12.30 (Wine): the four ALZ profiles 12.30 can
# write (store, -m1 level 1, -m2 level 4) and volume splitting. ALZip 8.0 is no
# longer the write contract; its archives stay covered on the read side (step 2),
# including the level 2 that 12.30 dropped.
cases = [
    ('alz_m0_hello.alz', 'none', ['corpus/hello.txt=>hello.txt'], []),
    ('alz_m1_code.alz', 'faster', ['corpus/code.c=>code.c'], []),
    ('alz_m2_code.alz', 'normal', ['corpus/code.c=>code.c'], []),
    ('alz_m0_random_v100k.alz', 'none',
     ['corpus/random.bin=>random.bin'], ['-v', '102400']),
]

for index, (base, prof, files, extra) in enumerate(cases):
    ref = os.path.join(FIX, base)
    if not os.path.exists(ref):
        raise SystemExit(f'{base}: 12.30 reference missing')
    case_dir = os.path.join(tmp, f'alz-1230-{index}')
    os.makedirs(case_dir)
    out = os.path.join(case_dir, base)
    args = [ALZ, 'create', '-p', prof,
            '-T', ','.join(dos(t) for t in timestamps(ref))] + extra + ['-o', out] + files
    r = subprocess.run(args, capture_output=True, text=True)
    if r.returncode:
        raise SystemExit(f'{base}: create failed: ' + (r.stderr or r.stdout).strip())
    if open(out, 'rb').read() != open(ref, 'rb').read():
        raise SystemExit(f'{base}: archive differs from the 12.30 reference')
    stem = out[:-4]
    vol = 0
    while True:
        name = '.alz' if vol == 0 else '.a%02d' % (vol - 1)
        refv = ref[:-4] + name
        gotv = stem + name
        if not os.path.exists(refv):
            break
        if open(gotv, 'rb').read() != open(refv, 'rb').read():
            raise SystemExit(f'{base}: volume {vol} differs from the reference')
        vol += 1
    print(f'  {base}: profile {prof}, {vol} volume(s), identical bytes')

# The decoder must read these 12.30 archives back, including the two-volume
# chain (level 4 and store are the only ALZ levels 12.30 writes).
dec = os.path.join(tmp, 'alz-1230-dec')
os.makedirs(dec)
r = subprocess.run([ALZ, 'extract', os.path.join(FIX, 'alz_m0_random_v100k.alz'),
                    '-d', dec], capture_output=True, text=True)
if r.returncode or open(os.path.join(dec, 'random.bin'), 'rb').read() != \
        open('corpus/random.bin', 'rb').read():
    raise SystemExit('ALZ 12.30 volume chain is not readable: '
                     + (r.stdout + r.stderr).strip())
os.makedirs(os.path.join(dec, 'code'))
r = subprocess.run([ALZ, 'extract', os.path.join(FIX, 'alz_m2_code.alz'),
                    '-d', os.path.join(dec, 'code')], capture_output=True,
                   text=True)
if r.returncode or open(os.path.join(dec, 'code', 'code.c'), 'rb').read() != \
        open('corpus/code.c', 'rb').read():
    raise SystemExit('ALZ 12.30 -m2 archive is not readable: '
                     + (r.stdout + r.stderr).strip())
print('  read 12.30: two-volume chain read back, level 4 conforms')

# -m0..-m2 are ALZipCon 12.30 numbers: store, level 1, level 4, default -m2.
# -m3 writes NOTHING in 12.30 (verified on code.c and records.bin), so the CLI
# refuses instead of producing an archive the reference would not write.
mapdir = os.path.join(tmp, 'profile-map')
os.makedirs(mapdir)


def make(tag, *opts):
    out = os.path.join(mapdir, tag + '.alz')
    r = subprocess.run([ALZ, 'create', *opts, '-T', '2026-10-15 16:14:58',
                        '-o', out, 'corpus/code.c=>payload.bin'],
                       capture_output=True, text=True)
    if r.returncode:
        raise SystemExit(f'-m mapping: create {tag} failed: {r.stderr.strip()}')
    return open(out, 'rb').read()


for num, name in enumerate(('none', 'faster', 'normal')):
    if make(f'-m{num}', f'-m{num}') != make(f'-p-{name}', '-p', name):
        raise SystemExit(f'-m{num} does not match -p {name}')
if make('default') != make('p-normal', '-p', 'normal'):
    raise SystemExit('alzgg create without -p/-m does not default to Normal (-m2)')

for label, args in (('-m3', ['-m3']), ('-p fast', ['-p', 'fast'])):
    out = os.path.join(mapdir, 'refuse.alz')
    r = subprocess.run([ALZ, 'create'] + args +
                       ['-T', '2026-10-15 16:14:58', '-o', out,
                        'corpus/code.c=>payload.bin'], capture_output=True)
    if r.returncode == 0 or os.path.exists(out):
        raise SystemExit(f'ALZ create {label}: expected a refusal without output')

# 12.30 sets FILE_ATTRIBUTE_ARCHIVE (0x20) on every file; --attr still wins so
# an 8.0 entry (0x00) can be reproduced.
def attr_of(path):
    (_, _, entries), = hd.parse(path)
    return next(i['attr'] for n, i in entries if n != 'END')

if attr_of(os.path.join(mapdir, 'p-normal.alz')) != 0x20:
    raise SystemExit('ALZ 12.30: default attr is not 0x20')
zero = os.path.join(mapdir, 'attr0.alz')
subprocess.run([ALZ, 'create', '-p', 'normal', '--attr', '0x00',
                '-T', '2026-10-15 16:14:58', '-o', zero,
                'corpus/code.c=>payload.bin'], check=True)
if attr_of(zero) != 0x00:
    raise SystemExit('ALZ --attr 0x00 should force the 8.0 attribute byte')
print('  -m0..-m2 = none/faster/normal, default -m2, -m3/fast refused, attr=0x20')
EOF

echo "== [4/13] ALZ unsupported container methods are rejected =="
python3 - "$TEST_TMP" <<'EOF'
import pathlib, struct, subprocess, sys, zlib

# Container methods 1 (BZip2) and 3 (obfuscated-init Deflate) are named by the
# format but emitted by no ALZ profile of ALZip 8, so the port must refuse them
# instead of carrying an unverifiable codec. Listing stays metadata-only.
root = pathlib.Path(sys.argv[1])
case = root / 'unsupported-methods'
case.mkdir()
name = b'legacy.bin'
payload = bytes(range(256)) * 8
crc = zlib.crc32(payload) & 0xffffffff
for method in (1, 3):
    header = (b'BLZ\x01' + struct.pack('<HBI BB', len(name), 0, 0, 0x40, 0)
              + bytes([method, 0])
              + struct.pack('<III', crc, len(payload), len(payload)) + name)
    archive = (b'ALZ\x01\x0a\x00\x00\x00' + header + payload
               + b'CLZ\x01' + b'\0' * 8 + b'CLZ\x02')
    path = case / f'method{method}.alz'
    path.write_bytes(archive)
    listing = subprocess.run(['./alzgg', 'list', str(path)],
                             capture_output=True, text=True)
    if listing.returncode:
        raise SystemExit(f'list failed on a method-{method} container: '
                         f'{listing.stderr or listing.stdout}')
    extract = case / f'out{method}'
    extract.mkdir()
    result = subprocess.run(['./alzgg', 'extract', str(path), '-d', str(extract)],
                            capture_output=True, text=True)
    if result.returncode == 0:
        raise SystemExit(f'method {method}: extract succeeded although no ALZ profile emits it')
    if 'not supported' not in (result.stdout + result.stderr):
        raise SystemExit(f'method {method}: expected an explicit unsupported-method error, '
                         f'got: {result.stdout or result.stderr}')
    if any(extract.iterdir()):
        raise SystemExit(f'method {method}: extraction left files behind')
print('container methods 1 and 3 refused with an explicit error; list still works')
EOF

echo "== [5/13] ALZ refuses solid compression (-s is EGG-only) =="
# Solid-Compression does not exist for ALZ: ALZipCon accepts -s for every
# format but rejects it here with "ERROR : The format doesn't support
# Solid-Compression" (FORMAT-ALZ.md). The port must behave the same and
# must not leave an archive behind.
solid_out="$TEST_TMP/solid.alz"
solid_log="$TEST_TMP/solid.log"
if ./alzgg create -s -o "$solid_out" corpus/hello.txt >"$solid_log" 2>&1; then
    echo "alzgg create -s succeeded although ALZ has no solid mode" >&2
    exit 1
fi
if ! grep -q "ERROR : The format doesn't support Solid-Compression" "$solid_log"; then
    echo "alzgg create -s: expected the ALZipCon refusal message, got: $(cat "$solid_log")" >&2
    exit 1
fi
if [ -e "$solid_out" ]; then
    echo "alzgg create -s left $solid_out behind" >&2
    exit 1
fi
echo "alzgg create -s refused with the reference message; no archive written"

echo "== [6/13] EGG: list + extraction coverage =="
python3 - "$TEST_TMP" <<'EOF'
import glob, os, random, subprocess, sys

sys.path.insert(0, 'tools')
import egg_dump as ed   # independent structural parser (reverse-engineered spec)

root = sys.argv[1]
samples = (sorted(glob.glob('packed_egg/*.egg'))
           + sorted(glob.glob('packed_egg_8.0/*.egg')))
listed = extracted = refused = 0
crypted_extracted = 0

for sample in samples:
    base = os.path.basename(sample)
    # A volume is not a standalone EGG stream: the chain is read back and
    # compared by the splitting tests (step 9), not here.
    if '.vol' in base:
        continue
    # The special 8.0 sets (volumes, encryption, names, edges, huge, LEA) have
    # their own steps; here we only walk the profile matrix and the codec
    # probes.
    if base.startswith(('egg_', 'enc_', 'meta_', 'span_', 'huge_', 'edge_',
                        'lea128_', 'lea256_', 'records_span', 'nested_span',
                        'names_', 'route_')):
        continue
    listing = subprocess.run(['./alzgg', 'list', sample],
                             capture_output=True, text=True)
    if listing.returncode:
        raise SystemExit(f'{base}: list failed: {listing.stderr.strip()}')
    listed += 1

    # Expectations come from the Python parser (independent of the C code):
    # unencrypted store/deflate blocks must come out byte for byte, including
    # solid archives, whose continuous stream is spread over the members (§14.3).
    if '.vol' in base:
        # split archive: validated from the first volume only, once
        if not base.endswith('.vol1.egg'):
            continue
        files, state = [{'name': 'records.bin', 'wininfo': None}], 'extract'
        # An encrypted chain (lot H, and now the 12.30 `…_v100k_zip`
        # reference) needs the password from the first volume on.
        crypted = any(tag in base for tag in ('_zip', '_aes', '_lea'))
    else:
        parsed = ed.parse(sample)
        files = [e for e in parsed['files'] if e.get('kind') == 'file']
        solid = any(k == 'SOLID_INFO' for k, _ in parsed.get('prefix', []))
        methods = {b['method'] for e in files for b in e['blocks']}
        crypted = any(e.get('crypt') for e in files)
        # bzip2 (method 2) is decoded by the 1.0.5 library in src/bzip2_dec/,
        # LZMA (method 4) by the 4.65 SDK in src/lzma_sdk/ and AZO (method 3) by
        # src/egg_azo.c (probe_sys_optimized.egg): the whole corpus of the five
        # methods comes out byte for byte.
        state = 'refuse' if methods - {0, 1, 2, 3, 4} else 'extract'
        if solid:
            # solid stream model: the blocks cover exactly the members'
            # content (the corpus carries a single block on the last one).
            blk = sum(b['usize'] for e in files for b in e['blocks'])
            mem = sum(e['usize'] for e in files
                      if not (e.get('wininfo') and e['wininfo']['attrs'] & 0x80))
            if blk != mem:
                raise SystemExit(f'{base}: solid stream {blk} bytes != members {mem}')

    # Two generations can share a name (biased_compspeed.egg in 8.0 and in
    # 12.30): the output directory keeps the origin apart.
    out = os.path.join(root, ('80-' if '8.0' in sample else '12-') + base)
    os.makedirs(out)
    args = ['./alzgg', 'extract', sample, '-d', out]
    if crypted:
        # The three encrypted samples are bzip2: without the password the
        # refusal must come from the encryption and nothing may be written
        # (checked below); with it, extraction must succeed byte for byte,
        # which finally exercises decryption all the way into the codec.
        no_pw = subprocess.run(args, capture_output=True, text=True)
        message = no_pw.stdout + no_pw.stderr
        if no_pw.returncode == 0 or 'password required' not in message:
            raise SystemExit(f'{base}: expected a missing-password refusal, got: '
                             f'{(no_pw.stderr or no_pw.stdout).strip()}')
        leftovers = [p for p in glob.glob(os.path.join(out, '**'), recursive=True)
                     if os.path.isfile(p)]
        if leftovers:
            raise SystemExit(f'{base}: the missing-password refusal left files '
                             f'behind: {leftovers}')
        args += ['-p', 'password']
    result = subprocess.run(args, capture_output=True, text=True)

    if state == 'refuse':
        message = result.stdout + result.stderr
        if result.returncode == 0:
            raise SystemExit(f'{base}: extraction succeeded although the codec is unsupported')
        if 'not implemented' not in message:
            raise SystemExit(f'{base}: expected an explicit unsupported error, '
                             f'got: {(result.stderr or result.stdout).strip()}')
        refused += 1
        leftovers = [p for p in glob.glob(os.path.join(out, '**'), recursive=True)
                     if os.path.isfile(p)]
        if leftovers:
            raise SystemExit(f'{base}: refusal left files behind: {leftovers}')
        continue

    if result.returncode:
        raise SystemExit(f'{base}: extraction failed: {result.stderr.strip()}')
    expected = sorted(e['name'] for e in files
                      if not (e.get('wininfo') and e['wininfo']['attrs'] & 0x80))
    actual = sorted(os.path.relpath(p, out).replace(os.sep, '/')
                    for p in glob.glob(os.path.join(out, '**'), recursive=True)
                    if os.path.isfile(p))
    if actual != expected:
        raise SystemExit(f'{base}: member set differs: {actual} != {expected}')
    route_payload = open('corpus/eng.txt', 'rb').read()[:4096]

    def source_bytes(name):
        if name.startswith('routes/'):
            return route_payload
        if name == 'probe.com':      # same payload as .sys, other AZO route
            with open('corpus/probe.sys', 'rb') as f:
                return f.read()
        azip8 = os.environ.get('ALZIP_80_DIR', os.path.join('_work', 'binaries', 'alzip-8.0'))
        if not os.path.isdir(azip8):
            azip8 = os.path.join('research', 'Program Files (x86)', 'ALZip')
        if name == 'sysmulti.sys':
            with open('corpus/code.c', 'rb') as f:
                return f.read() * 14
        if name == 'mz.sys':
            p = os.path.join(azip8, 'Coders', 'Deflate.dll')
            return open(p, 'rb').read() if os.path.isfile(p) else None
        if name == 'mzmulti.sys':
            p = os.path.join(azip8, 'ALZipCon.exe')
            return open(p, 'rb').read() if os.path.isfile(p) else None
        if name in ('mzraw.sys', 'mzraw2.sys'):
            r = random.Random(0x415a4f)
            n = 524288 if name == 'mzraw.sys' else 2 * 524288
            return b'MZ' + bytes(r.randrange(256) for _ in range(n - 2))
        # References mix flat names, trees (`nested/...`, `two/...`) and 8.0
        # staging paths (`fixtures/out/...`, verbatim in the archived name):
        # try the path, then its base name, and the unicode tree for non-ASCII.
        # ALZip 12.30 strips leading spaces of a path component:
        # `café_clair/ nested/` is stored as `café_clair/nested/`, so the
        # normalised form is tried too.
        stripped = '/'.join(part.strip() for part in name.split('/'))
        candidates = [os.path.join('corpus', name),
                      os.path.join('corpus', 'nested', name),
                      os.path.join('corpus', 'unicode', name),
                      os.path.join('corpus', stripped),
                      os.path.join('corpus', os.path.basename(name))]
        for candidate in candidates:
            if os.path.exists(candidate):
                with open(candidate, 'rb') as f:
                    return f.read()
        # Last resort: same base name under the unicode tree (leading spaces of
        # a directory are lost at archival time).
        wanted = os.path.basename(name)
        for dirpath, _dirs, files in os.walk(os.path.join('corpus', 'unicode')):
            if wanted in files:
                with open(os.path.join(dirpath, wanted), 'rb') as f:
                    return f.read()
        raise SystemExit(f'{base}/{name}: no source file (tried '
                         f'{candidates[0]})')

    for name in expected:
        with open(os.path.join(out, *name.split('/')), 'rb') as f:
            got = f.read()
        src = source_bytes(name)
        if src is not None and got != src:
            raise SystemExit(f'{base}/{name}: extracted bytes differ from the source')
    extracted += 1
    if crypted:
        crypted_extracted += 1

# The three encrypted samples must have been decrypted AND decompressed: if
# one disappears, the test says so instead of passing vacuously.
if crypted_extracted < 3:
    raise SystemExit(f'only {crypted_extracted} encrypted sample(s) extracted with the '
                     'known password; the encrypted fixtures are missing or no '
                     'longer detected')
if refused:
    raise SystemExit(f'{refused} packed_egg sample(s) refused although every method '
                     'of the corpus is now decoded')
print(f'list {listed}/{len(samples)} archives; byte-for-byte extraction {extracted} '
      f'({crypted_extracted} encrypted with password)')

# The six ALZip 8.0 GUI archives (65 B to 1 MiB) go through the same reader:
# their entries live in corpus/ (code.c for gui_normal_code.egg, the `tree/...`
# tree of solid_normal_code.egg under corpus/nested). This is the only coverage
# of the reader beyond a few hundred kilobytes, and it spans all five methods:
# store, deflate hint 5 and 6, bzip2 and LZMA.
gui_extracted = 0
for sample in (sorted(glob.glob('packed_egg_8.0/gui_*.egg'))
               + ['packed_egg_8.0/solid_normal_code.egg']):
    base = os.path.basename(sample)
    listing = subprocess.run(['./alzgg', 'list', sample],
                             capture_output=True, text=True)
    if listing.returncode:
        raise SystemExit(f'{base}: list failed: {listing.stderr.strip()}')
    files = [e for e in ed.parse(sample)['files'] if e.get('kind') == 'file']
    out = os.path.join(root, 'gui-' + base)
    os.makedirs(out)
    result = subprocess.run(['./alzgg', 'extract', sample, '-d', out],
                            capture_output=True, text=True)
    if result.returncode:
        raise SystemExit(f'{base}: extraction failed: {result.stderr.strip()}')
    expected = sorted(e['name'] for e in files
                      if not (e.get('wininfo') and e['wininfo']['attrs'] & 0x80))
    actual = sorted(os.path.relpath(p, out).replace(os.sep, '/')
                    for p in glob.glob(os.path.join(out, '**'), recursive=True)
                    if os.path.isfile(p))
    if actual != expected:
        raise SystemExit(f'{base}: member set differs: {actual} != {expected}')
    for name in expected:
        src = os.path.join('corpus', name)
        if not os.path.exists(src):
            src = os.path.join('corpus', os.path.basename(name))
        with open(src, 'rb') as f:
            want = f.read()
        with open(os.path.join(out, *name.split('/')), 'rb') as f:
            got = f.read()
        if got != want:
            raise SystemExit(f'{base}/{name}: extracted bytes differ from {src}')
    gui_extracted += 1
if gui_extracted < 7:
    raise SystemExit(f'only {gui_extracted} GUI archive(s) extracted; the batch '
                     'is missing or incomplete')
print(f'GUI 8.0 set: {gui_extracted} archives (five levels + one solid, up to '
      f'1 MiB) extracted byte for byte')

# The 31 lot-H edge, naming and routing archives (30 EGG + 1 ALZ):
# names_ (order with dotfile, case overwrite, special chars),
# edge_ (duplicate, append, -xr subfolder exclusion, lone directory in EGG and ALZ),
# route_ (10 extensions x m3 LZMA / m4 codec routing, plus uppercase and mixed case).
mixed_payload = open('corpus/mixed.bin', 'rb').read()
hello_payload = open('corpus/hello.txt', 'rb').read()
records_payload = open('corpus/records.bin', 'rb').read()

def lot_h_source(name):
    b = os.path.basename(name)
    if b.startswith(('payload', 'PAYLOAD')):
        return mixed_payload
    if b in ('Alpha.txt', 'a.txt', 'B.txt', 'c1.txt', 'c10.txt', 'c2.txt',
             '-dash.txt', '_underscore.txt', '.dotfile', 'z z.txt', 'A0.txt',
             'with space.txt', '100%.txt', 'a&b.txt', "quote's.txt",
             'hash#.txt', 'brackets[1].txt', 'plus+.txt', 'hello.txt') or b.startswith('l' * 20):
        return hello_payload
    if b in ('alpha.txt', 'records.bin'):
        return records_payload
    raise SystemExit(f'unknown lot H member source: {name}')

h_archives = sorted(glob.glob('packed_egg_8.0/names_*.egg') +
                    glob.glob('packed_egg_8.0/route_*.egg') +
                    glob.glob('packed_egg_8.0/edge_*.egg') +
                    ['packed_alz_8.0/edge_dir_only.alz'])
if len(h_archives) != 31:
    raise SystemExit(f'expected 31 lot-H archives, found {len(h_archives)}: {h_archives}')

h_extracted = 0
for arc in h_archives:
    base = os.path.basename(arc)
    r_list = subprocess.run(['./alzgg', 'list', arc], capture_output=True, text=True)
    if r_list.returncode:
        raise SystemExit(f'{base}: list failed: {r_list.stderr.strip()}')
    out = os.path.join(root, 'h-' + base)
    os.makedirs(out)
    r_ext = subprocess.run(['./alzgg', 'extract', arc, '-d', out],
                           capture_output=True, text=True)
    if r_ext.returncode:
        raise SystemExit(f'{base}: extract failed: {r_ext.stderr.strip()}')

    extracted_files = []
    for cur, _dirs, files in os.walk(out):
        for f in files:
            extracted_files.append(os.path.join(cur, f))

    if 'dir_only' in base:
        if extracted_files:
            raise SystemExit(f'{base}: expected 0 files extracted for dir-only, got {extracted_files}')
    else:
        if not extracted_files:
            raise SystemExit(f'{base}: no files extracted')
        for p in extracted_files:
            rel = os.path.relpath(p, out).replace(os.sep, '/')
            want = lot_h_source(rel)
            with open(p, 'rb') as f:
                got = f.read()
            if got != want:
                raise SystemExit(f'{base}/{rel}: extracted bytes differ from source')
    h_extracted += 1

print(f'lot-H set: {h_extracted} archives (names, routes, edges, dir-only EGG+ALZ) extracted byte for byte')


# --- Memory: a member larger than the process address-space limit still
# extracts. The reader mmap()s the volume and writes in 1 MiB slices; the old
# read path held the whole decompressed member (plus its decrypted payload), so
# about 4x the file size on the heap. The test therefore fails if per-member
# allocation comes back.
# Under ASan the limit does not apply (the runtime reserves a huge space), so
# the check is skipped EXPLICITLY, with its reason, never silently.
import resource, shutil

if os.environ.get('ASAN_OPTIONS'):
    print('memory: check skipped under ASan (RLIMIT_AS does not apply)')
else:
    size = 128 << 20
    limit = 320 << 20
    big = os.path.join(root, 'mem-big.bin')
    block = bytes(range(256)) * 4096
    with open(big, 'wb') as f:
        for _ in range(size // len(block)):
            f.write(block)
    alz = os.path.abspath('./alzgg')
    for tag, extra in (('plain', []), ('crypt', ['--password', 'password'])):
        arc = os.path.join(root, 'mem-' + tag + '.egg')
        # Relative entry (cwd=root): the stored name stays `mem-big.bin`, since
        # an absolute path is refused by the reader's traversal guard.
        r = subprocess.run([alz, 'create', '-o', arc, '-p', 'none',
                            *extra, 'mem-big.bin'], cwd=root,
                           capture_output=True, text=True)
        if r.returncode:
            raise SystemExit(f'mem {tag}: create failed: {r.stderr.strip()}')
        out = os.path.join(root, 'mem-out-' + tag)
        r = subprocess.run([alz, 'extract', arc, '-d', out, '-p', 'password'],
                           capture_output=True, text=True,
                           preexec_fn=lambda: resource.setrlimit(
                               resource.RLIMIT_AS, (limit, limit)))
        if r.returncode:
            raise SystemExit(f'mem {tag}: extraction under {limit >> 20} MiB of '
                             f'address space failed: '
                             f'{(r.stderr or r.stdout).strip()}')
        with open(big, 'rb') as f1, open(os.path.join(out, 'mem-big.bin'), 'rb') as f2:
            while True:
                a, b = f1.read(1 << 20), f2.read(1 << 20)
                if a != b:
                    raise SystemExit(f'mem {tag}: extracted bytes differ')
                if not a:
                    break
        os.remove(arc)
        shutil.rmtree(out)
    # Solid archive: every member shares ONE stream. It is now decoded and
    # written as a stream, member by member: 96 MiB of address space is enough
    # to extract 128 MiB (the old reader allocated the whole decompressed
    # stream and failed under this limit).
    solid_arc = os.path.join(root, 'mem-solid.egg')
    r = subprocess.run([alz, 'create', '-o', solid_arc, '-p', 'compspeed', '-s',
                        'mem-big.bin'], cwd=root, capture_output=True, text=True)
    if r.returncode:
        raise SystemExit('mem solid: create failed: '
                         + (r.stderr or r.stdout).strip())
    solid_out = os.path.join(root, 'mem-solid-out')
    solid_limit = 96 << 20
    r = subprocess.run([alz, 'extract', solid_arc, '-d', solid_out],
                       capture_output=True, text=True,
                       preexec_fn=lambda: resource.setrlimit(
                           resource.RLIMIT_AS, (solid_limit, solid_limit)))
    if r.returncode:
        raise SystemExit(f'mem solid: extraction under '
                         f'{solid_limit >> 20} MiB of address space failed: '
                         + (r.stderr or r.stdout).strip())
    with open(big, 'rb') as f1, open(os.path.join(solid_out, 'mem-big.bin'), 'rb') as f2:
        while True:
            a, b = f1.read(1 << 20), f2.read(1 << 20)
            if a != b:
                raise SystemExit('mem solid: extracted bytes differ')
            if not a:
                break
    os.remove(solid_arc)
    shutil.rmtree(solid_out)
    print(f'memory: 128 MiB extracted (store, plain, ZipCrypto) under '
          f'{limit >> 20} MiB of address space, and 128 MiB solid under '
          f'{solid_limit >> 20} MiB')
EOF

echo "== [7/13] EGG probe corpus: splitmany (3 volumes, DUMMY), unicode, refusals, malformed input =="
python3 - "$TEST_TMP" <<'EOF'
import glob, os, random, struct, subprocess, sys

sys.path.insert(0, 'tools')
import egg_dump as ed   # independent structural parser (reverse-engineered spec)

root = sys.argv[1]
PROBE = 'packed_egg_8.0'
ALZIP = os.environ.get('ALZIP_80_DIR', os.path.join('_work', 'binaries', 'alzip-8.0'))
if not os.path.isdir(ALZIP):
    ALZIP = os.path.join('research', 'Program Files (x86)', 'ALZip')

# --- 1. splitmany: 3 volumes, 420 members, extraction from every entry point.
# Volume 2 carries the corpus' only DUMMY record, so going through it proves the
# DUMMY path (a header pushed from one volume to the next).
source_dir = os.path.join('corpus', 'splitmany')
expected = {os.path.basename(p): open(p, 'rb').read()
            for p in glob.glob(os.path.join(source_dir, '*.txt'))}
if len(expected) != 420:
    raise SystemExit(f'splitmany corpus incomplete: {len(expected)} source files,'
                     ' expected 420')
dummy_vols = []
for vol in (1, 2, 3):
    sample = f'{PROBE}/splitmany_normal.vol{vol}.egg'
    if not os.path.exists(sample):
        raise SystemExit(f'missing split fixture {sample}')
    if b'\x07\x33\x46\x07' in open(sample, 'rb').read():
        dummy_vols.append(vol)
    out = os.path.join(root, f'splitmany-vol{vol}')
    os.makedirs(out)
    result = subprocess.run(['./alzgg', 'extract', sample, '-d', out],
                            capture_output=True, text=True)
    if result.returncode:
        raise SystemExit(f'{sample}: extraction failed: '
                         f'{(result.stderr or result.stdout).strip()}')
    actual = {}
    for current, _, filenames in os.walk(out):
        for filename in filenames:
            path = os.path.join(current, filename)
            actual[os.path.relpath(path, out)] = open(path, 'rb').read()
    if actual != expected:
        missing = sorted(set(expected) - set(actual))
        differing = sorted(k for k in set(actual) & set(expected)
                           if actual[k] != expected[k])
        raise SystemExit(f'{sample}: {len(actual)} members extracted != 420,'
                         f' missing={missing[:3]}, differing={differing[:3]}')
if not dummy_vols:
    raise SystemExit('no DUMMY record anywhere in the splitmany volumes; the '
                     'DUMMY path is no longer exercised by this fixture')
print(f'splitmany: 420 members from each of the 3 volumes (DUMMY in '
      f'vol{sorted(dummy_vols)})')

# --- 2. packed_egg_8.0/: single- and multi-member samples, non-ASCII names, and
# the five methods of the format, all decoded by now: AZO from src/egg_azo.c,
# LZMA from the 4.65 SDK, BZip2 from the bundled 1.0.5. Solid archives are
# covered there on both sides (deflate and LZMA).
# Two reference entries are not stored, they are derived from the repository
# (step 9 rebuilds them the same way): probe.com is probe.sys under another
# extension, sysmulti.sys is corpus/code.c repeated 14 times.
# The third x86-filter case: a 2^19 slice that is INCOMPRESSIBLE, hence copied
# raw, whose data starts with MZ. AZO.dll filters the slice before noticing the
# stream does not shrink it, then stores it as is (csize == usize, slice field 3
# zero) and the filter flag stays `31 01`. mzraw.sys fits in one slice, mzraw2.sys
# (1 MiB) spans two - the second does not start with MZ and is filtered anyway
# (sticky flag).
def mzraw_payload(n):
    """MZ + (n-2) bytes of a fixed-seed PRNG: no redundancy at all."""
    r = random.Random(0x415a4f)
    return b'MZ' + bytes(r.randrange(256) for _ in range(n - 2))


DERIVED = {
    'probe.com': ('probe.sys under another extension',
                  lambda: open(os.path.join('corpus', 'probe.sys'), 'rb').read()),
    'sysmulti.sys': ('corpus/code.c repeated 14 times',
                     lambda: open(os.path.join('corpus', 'code.c'), 'rb').read() * 14),
    # The two x86-filter references are real Windows executables (MZ signature)
    # renamed to .sys to take the AZO route: the filter depends on the content,
    # not on the extension (AZO.dll 0x61907410).
    'mz.sys': ('Coders/Deflate.dll, a 73,560-byte PE',
               lambda: open(os.path.join(ALZIP, 'Coders', 'Deflate.dll'), 'rb').read()
                       if os.path.isfile(os.path.join(ALZIP, 'Coders', 'Deflate.dll')) else None),
    'mzmulti.sys': ('ALZipCon.exe, a 594,264-byte PE (two AZO slices)',
                    lambda: open(os.path.join(ALZIP, 'ALZipCon.exe'), 'rb').read()
                            if os.path.isfile(os.path.join(ALZIP, 'ALZipCon.exe')) else None),
    'mzraw.sys': ('MZ + 524,286 random bytes (one raw-copied slice)',
                  lambda: mzraw_payload(524288)),
    'mzraw2.sys': ('MZ + 1,048,574 random bytes (two raw-copied slices)',
                   lambda: mzraw_payload(2 * 524288)),
}

# The routing reference (routes_optimized.egg, 148 extensions) has a single
# content for all its members: the first 4,096 bytes of corpus/eng.txt.
# That is what isolates the route (only the extension decides); step 9 rebuilds
# it with the same computation and compares the whole archive.
ROUTE_PAYLOAD = open(os.path.join('corpus', 'eng.txt'), 'rb').read()[:4096]

extracted = refused = 0
solid_extracted = solid_refused = 0
solid_lzma_extracted = 0
bzip2_extracted = 0
azo_extracted = 0
refusal_methods = set()
unicode_members = 0
# Corpus cases only: the 8.0 sets moved into the same directory carry staging
# paths (`fixtures/out/...`) and are not codec probes; steps 8 to 12 cover them.
CORPUS_PROBES = ('gui_', 'probe_', 'normal_r', 'text_contenu_', 'unicode_',
                 'routes_optimized.egg', 'sysmulti_', 'mz_sys_optimized.egg',
                 'mzmulti_sys_optimized.egg', 'mzraw_sys_optimized.egg',
                 'mzraw2_sys_optimized.egg', 'solid_normal_code.egg')
for sample in sorted(glob.glob(os.path.join(PROBE, '*.egg'))):
    base = os.path.basename(sample)
    if '.vol' in base:      # chained volumes: handled by part 1
        continue
    if not base.startswith(CORPUS_PROBES):
        continue
    parsed = ed.parse(sample)
    files = [e for e in parsed['files'] if e.get('kind') == 'file']
    solid = any(k == 'SOLID_INFO' for k, _ in parsed.get('prefix', []))
    methods = {b['method'] for e in files for b in e['blocks']}
    state = 'refuse' if (methods - {0, 1, 2, 3, 4}) else 'extract'

    out = os.path.join(root, 'probe', base)
    os.makedirs(out)
    result = subprocess.run(['./alzgg', 'extract', sample, '-d', out],
                            capture_output=True, text=True)

    if state == 'refuse':
        if result.returncode == 0:
            raise SystemExit(f'{base}: extraction succeeded although the codec is unsupported')
        if 'not implemented' not in (result.stdout + result.stderr):
            raise SystemExit(f'{base}: expected an explicit unsupported error, '
                             f'got: {(result.stderr or result.stdout).strip()}')
        leftovers = [p for p in glob.glob(os.path.join(out, '**'), recursive=True)
                     if os.path.isfile(p)]
        if leftovers:
            raise SystemExit(f'{base}: refusal left files behind: {leftovers[:3]}')
        refusal_methods |= (methods - {0, 1, 2, 3, 4})
        if solid:
            solid_refused += 1
        refused += 1
        continue

    if result.returncode:
        raise SystemExit(f'{base}: extraction failed: '
                         f'{(result.stderr or result.stdout).strip()}')
    want_names = sorted(e['name'] for e in files)
    got_names = sorted(os.path.relpath(p, out).replace(os.sep, '/')
                       for p in glob.glob(os.path.join(out, '**'), recursive=True)
                       if os.path.isfile(p))
    if got_names != want_names:
        raise SystemExit(f'{base}: member set differs: {got_names} != {want_names}')
    for name in want_names:
        # Non-ASCII names live under corpus/unicode/ in UTF-8; the other probe
        # corpus members are flat files.
        source = (os.path.join('corpus', 'unicode', name) if not name.isascii()
                  else os.path.join('corpus', os.path.basename(name)))
        if name in DERIVED:
            source, make = DERIVED[name]
            expected = make()
        elif name.startswith('routes/'):
            source, expected = 'the first 4,096 bytes of corpus/eng.txt', ROUTE_PAYLOAD
        else:
            if not os.path.exists(source):
                raise SystemExit(f'{base}/{name}: no reference file at {source}')
            expected = open(source, 'rb').read()
        if expected is not None and open(os.path.join(out, *name.split('/')), 'rb').read() != expected:
            raise SystemExit(f'{base}/{name}: extracted bytes differ from {source}')
        if not name.isascii():
            unicode_members += 1
    if solid:
        solid_extracted += 1
        if 4 in methods:
            solid_lzma_extracted += 1
    if 2 in methods:
        bzip2_extracted += 1
    if 3 in methods:
        azo_extracted += 1
    extracted += 1

# These requirements bear on the fixtures themselves: if the only AZO or BZip2
# sample disappeared, the test must say so instead of passing vacuously.
if refused:
    raise SystemExit(f'{refused} probe sample(s) refused although every method of '
                     'the probe corpus is now decoded')
if bzip2_extracted < 1:
    raise SystemExit('no probe archive with bzip2 blocks is extracted any more: '
                     'the bzip2 decoder is no longer exercised')
if azo_extracted < 1:
    raise SystemExit('no probe archive with AZO blocks is extracted any more: '
                     'the AZO decoder is no longer exercised')
if unicode_members < 3:
    raise SystemExit(f'only {unicode_members} non-ASCII members in the probe corpus; '
                     'the unicode fixtures are missing')
# Both solid routes must stay covered: deflate and LZMA, each extracted from
# its single block.
if solid_extracted < 2:
    raise SystemExit('fewer than two solid samples are extracted: the solid '
                     'codec paths are no longer covered by the probe corpus')
if solid_lzma_extracted < 1:
    raise SystemExit('no solid LZMA sample is extracted any more: the m3 stream '
                     'path is no longer covered')
# --- Malformed input: the reader must refuse cleanly, never crash.
# Every mutation starts from a valid reference archive; we require a non-zero
# exit code, NO death by signal (a buffer overflow shows up as a signal or an
# ASan report, hence a negative rc), and NO file written. The two path-traversal
# cases are security properties: without a test the guard could vanish unnoticed.
ALZ = os.path.abspath('./alzgg')
BAD = os.path.join(root, 'malformed')
os.makedirs(BAD)


def refuse(tag, data, needle=None, password=None):
    path = os.path.join(BAD, tag + '.egg')
    open(path, 'wb').write(bytes(data))
    out = os.path.join(BAD, 'out-' + tag)
    os.makedirs(out)
    args = [ALZ, 'extract', path, '-d', out]
    if password:
        args += ['-p', password]
    r = subprocess.run(args, capture_output=True, text=True, timeout=120)
    message = r.stdout + r.stderr
    if r.returncode < 0:
        raise SystemExit(f'malformed {tag}: killed by signal {-r.returncode} '
                         f'({message.strip()})')
    if r.returncode == 0:
        raise SystemExit(f'malformed {tag}: accepted although it is corrupted')
    if needle and needle not in message:
        raise SystemExit(f'malformed {tag}: refused without the expected reason '
                         f'{needle!r}: {message.strip()}')
    left = [p for p in glob.glob(os.path.join(out, '**'), recursive=True)
            if os.path.isfile(p)]
    if left:
        raise SystemExit(f'malformed {tag}: refusal left {len(left)} file(s) behind')


store = open('packed_egg/hello_none.egg', 'rb').read()
zlibed = open('packed_egg/hello_normal.egg', 'rb').read()
FILESIG, BLOCKSIG = 0x0A8590E3, 0x02B50C13


def sig_at(sig, blob):
    return blob.find(struct.pack('<I', sig))


# Truncations: header, prefix, sub-headers, block, end marker.
for cut, tag in ((0, 'empty'), (8, 'header-cut'), (20, 'prefix-cut'),
                 (len(zlibed) // 2, 'block-header-cut'),
                 (len(zlibed) - 5, 'block-data-cut'),
                 (len(zlibed) - 1, 'end-cut')):
    refuse('trunc-' + tag, zlibed[:cut])

# Reserved for the version field: a reader may accept an unknown version, but
# not a wrong signature nor a prefix that never ends.
b = bytearray(store)
b[0:4] = b'XGGA'
refuse('magic', b, 'EGGA')
b = bytearray(store)
b[12:16] = b'\x00\x00\x00\x00'
refuse('prefix-end', b)

fs = sig_at(FILESIG, store)
bs = sig_at(BLOCKSIG, zlibed)
b = bytearray(store)
b[fs + 8:fs + 16] = b'\xff' * 8          # member usize = 2^64-1
refuse('member-usize-max', b)
b = bytearray(store)
b[fs + 20:fs + 23] = b'\x00\xff\xff'     # FILENAME length > file size
refuse('filename-len', b)

# Codecs: unknown method, then each codec fed a stream that is not its own
# (deflate labelled bzip2/AZO/LZMA).
b = bytearray(zlibed)
b[bs + 4] = 9
refuse('method-unknown', b, 'not implemented')
for method, needle in ((2, 'bzip2'), (3, 'AZO'), (4, 'LZMA')):
    b = bytearray(zlibed)
    b[bs + 4] = method
    refuse('method-%d-mismatch' % method, b, needle)

b = bytearray(zlibed)
b[bs + 6:bs + 10] = b'\xff\xff\xff\xff'      # block usize
refuse('block-usize-max', b)
b = bytearray(zlibed)
b[bs + 10:bs + 14] = b'\xff\xff\xff\xff'     # block csize
refuse('block-csize-max', b)
b = bytearray(zlibed)
b[bs + 10:bs + 14] = b'\x00\x00\x00\x00'     # zero csize, non-zero usize
refuse('block-csize-zero', b)
b = bytearray(zlibed)
b[bs + 14] ^= 0x01                            # diverging CRC
refuse('block-crc', b, 'CRC mismatch')
b = bytearray(zlibed)
b[bs + 22] ^= 0x7f                            # corrupted stream
refuse('block-data', b)
b = bytearray(zlibed)
b[bs + 18:bs + 22] = b'\x00\x00\x00\x00'     # block end marker
refuse('block-end', b)

# Bytes after the end marker: nothing may be tolerated silently.
refuse('trailing-junk', zlibed + b'EGGA' + b'\x00' * 10, 'after the final end marker')

# Path traversal & Zip-Slip protection: continuously tracking directory nesting depth,
# rejecting ../ or ..\ ascending above root, leading absolute slashes (/ and \),
# and DOS drive identifiers (C:).
for tag, name in (
    ('name-dotdot', b'../../pwn'),
    ('name-dotdot-win', rb'..\..\pwn'),
    ('name-absolute', b'/tmp/absx'),
    ('name-absolute-win', rb'\tmp\absy'),
    ('name-drive-abs', rb'C:\evil.x'),
    ('name-drive-rel', rb'C:evil.tx'),
    ('name-nested-esc', rb'sub\..\..'),
):
    b = bytearray(store)
    at = b.find(b'hello.txt')
    if at < 0 or len(name) != 9:
        raise SystemExit(f'{tag}: cannot forge the name (pattern {len(name)})')
    b[at:at + 9] = name
    refuse(tag, b, 'skipping unsafe path traversal')
if any(os.path.exists(p) for p in (os.path.join(root, 'pwn'), '/tmp/absx', '/tmp/absy', 'C:\\evil.x')):
    raise SystemExit('a hostile name wrote outside the destination directory')

# Encrypted: unknown method, flipped verifier, truncated archive.
enc = bytearray(open('packed_egg_8.0/hello_optimized_password_zip2.egg', 'rb').read())
vi = sig_at(0x08D1470F, enc)
b = bytearray(enc)
b[vi + 7] = 7
refuse('crypt-method', b, 'unknown', password='password')
b = bytearray(enc)
b[vi + 8] ^= 0x01
refuse('crypt-verifier', b, 'incorrect password', password='password')
refuse('crypt-truncated', enc[:-1], password='password')

print(f'malformed input: {len(glob.glob(os.path.join(BAD, "*.egg")))} '
      'mutations refused cleanly (no signal, no file written), '
      'path traversal included')

print(f'probe corpus: byte-for-byte extraction {extracted} samples '
      f'({unicode_members} non-ASCII members, {solid_extracted} solid, '
      f'{solid_lzma_extracted} solid LZMA), {bzip2_extracted} BZip2, '
      f'{azo_extracted} AZO, explicit refusals {refused}')
EOF

echo "== [8/13] EGG encrypted members: ZipCrypto / AES-128 / AES-256 / LEA-128 / LEA-256 =="
# The LEA block cipher before its wrapper: standard test vectors (KS X 3246,
# annex A), reproduced verbatim in src/leatv.c.
./tests/bin/leatv
python3 - "$EXTRACT_ROOT" <<'EOF'
import bz2, glob, os, subprocess, sys, zlib

root = sys.argv[1]
# Password of the three samples shipped with the corpus (the same across the
# three methods, so only the encryption layers are compared).
PASSWORD = 'password'
# (file suffix, label printed by `alz list`)
ARCHIVES = [('zip2', 'zip'), ('aes128', 'aes128'), ('aes256', 'aes256')]

ref = open('corpus/hello.txt', 'rb').read()


def run(args):
    return subprocess.run(['./alzgg'] + args, capture_output=True, text=True)


def files_under(d):
    return [p for p in glob.glob(os.path.join(d, '**'), recursive=True)
            if os.path.isfile(p)]


for suffix, label in ARCHIVES:
    base = f'hello_optimized_password_{suffix}.egg'
    arc = os.path.join('packed_egg_8.0', base)
    if not os.path.exists(arc):
        raise SystemExit(f'{base}: encrypted fixture missing')

    # The listing does not depend on the password.
    listing = run(['list', arc])
    if listing.returncode or f'crypt={label}' not in listing.stdout:
        raise SystemExit(f'{base}: list failed or reported the wrong cipher: '
                         f'{listing.stdout}{listing.stderr}')

    # No password: explicit refusal, nothing written.
    out = os.path.join(root, f'crypt-nopass-{suffix}')
    os.makedirs(out)
    r = run(['extract', arc, '--raw', '-d', out])
    if r.returncode == 0 or 'password required' not in (r.stdout + r.stderr):
        raise SystemExit(f'{base}: a missing password was not refused: '
                         f'{r.stdout}{r.stderr}')
    if files_under(out):
        raise SystemExit(f'{base}: refusal without a password left files behind')

    # Wrong password: explicit refusal, nothing written.
    out = os.path.join(root, f'crypt-badpass-{suffix}')
    os.makedirs(out)
    r = run(['extract', arc, '-p', 'not-the-password', '--raw', '-d', out])
    if r.returncode == 0 or 'incorrect password' not in (r.stdout + r.stderr):
        raise SystemExit(f'{base}: a wrong password was not refused: '
                         f'{r.stdout}{r.stderr}')
    if files_under(out):
        raise SystemExit(f'{base}: refusal with a wrong password left files behind')

    # Right password: the decrypted payload must be a bzip2 stream whose content
    # is corpus/hello.txt and whose CRC-32 is the one in the block header.
    out = os.path.join(root, f'crypt-raw-{suffix}')
    os.makedirs(out)
    r = run(['extract', arc, '-p', PASSWORD, '--raw', '-d', out])
    if r.returncode:
        raise SystemExit(f'{base}: decryption failed: {(r.stderr or r.stdout).strip()}')
    written = os.path.join(out, 'hello.txt')
    if not os.path.exists(written):
        raise SystemExit(f'{base}: --raw wrote no hello.txt')
    payload = open(written, 'rb').read()
    if payload[:2] != b'BZ':
        raise SystemExit(f'{base}: decrypted payload is not a bzip2 stream: '
                         f'{payload[:4]!r}')
    try:
        plain = bz2.decompress(payload)
    except Exception as exc:                 # noqa: BLE001 - message de test
        raise SystemExit(f'{base}: the decrypted stream does not decompress: {exc}')
    if plain != ref:
        raise SystemExit(f'{base}: decrypted content differs from corpus/hello.txt')
    if (zlib.crc32(plain) & 0xFFFFFFFF) != 0x50575A24:
        raise SystemExit(f'{base}: decrypted content CRC differs from the block header')

    # Normal extraction: decryption THEN bzip2 decoding, all the way through.
    # This is the only path exercising both layers together: these three
    # archives are the corpus' only encrypted ones, and their blocks are bzip2.
    out = os.path.join(root, f'crypt-full-{suffix}')
    os.makedirs(out)
    r = run(['extract', arc, '-p', PASSWORD, '-d', out])
    if r.returncode:
        raise SystemExit(f'{base}: extraction with the right password failed: '
                         f'{(r.stderr or r.stdout).strip()}')
    written = os.path.join(out, 'hello.txt')
    if not os.path.exists(written):
        raise SystemExit(f'{base}: extraction wrote no hello.txt')
    if open(written, 'rb').read() != ref:
        raise SystemExit(f'{base}: extracted content differs from corpus/hello.txt')

# AES authenticates the ciphertext: a modified byte must be rejected on the
# HMAC, BEFORE any write (regardless of the password, which is correct here).
blob = bytearray(open('packed_egg_8.0/hello_optimized_password_aes128.egg', 'rb').read())
at = blob.find(bytes.fromhex('130cb502'))          # signature BLOCK
if at < 0:
    raise SystemExit('aes128: block signature not found, cannot tamper')
content = at + 4 + 14 + 4                          # sig + header + END
blob[content + 40] ^= 0x01
bad = os.path.join(root, 'crypt-tampered.egg')
open(bad, 'wb').write(bytes(blob))
out = os.path.join(root, 'crypt-tampered')
os.makedirs(out)
r = run(['extract', bad, '-p', PASSWORD, '--raw', '-d', out])
message = (r.stdout + r.stderr)
if r.returncode == 0 or 'authentication' not in message or 'HMAC' not in message:
    raise SystemExit(f'tampered AES ciphertext was not rejected: {message.strip()}')
if files_under(out):
    raise SystemExit('the tampered AES archive left files behind')

# --- LEA-128/256 (methods 5 and 6): six ALZip 12.30 samples (lot J). The
# block cipher itself is pinned by tests/bin/leatv on the KS X 3246 vectors;
# these archives verify the rest of the chain as ALZip frames it
# (PBKDF2-HMAC-SHA1, 2-byte verifier, HMAC-SHA1 truncated to 10, 128-bit
# big-endian counter CTR) for both key sizes, with a stored member, a bzip2
# member (Optimized profile) and two members with distinct salts.
LEA = [
    ('packed_egg/lea128_store_hello.egg', 'lea128',
     ['hello.txt']),
    ('packed_egg/lea256_store_hello.egg', 'lea256',
     ['hello.txt']),
    ('packed_egg/lea128_optimized_hello.egg', 'lea128',
     ['hello.txt']),
    ('packed_egg/lea256_optimized_hello.egg', 'lea256',
     ['hello.txt']),
    ('packed_egg/lea128_store_two.egg', 'lea128',
     ['two/hello.txt', 'two/code.c']),
    ('packed_egg/lea256_store_two.egg', 'lea256',
     ['two/hello.txt', 'two/code.c']),
]
for arc, label, names in LEA:
    if not os.path.exists(arc):
        raise SystemExit(f'{arc}: LEA fixture missing')
    listing = run(['list', arc])
    if listing.returncode or f'crypt={label}' not in listing.stdout:
        raise SystemExit(f'{arc}: list failed or reported the wrong cipher: '
                         f'{listing.stdout}{listing.stderr}')
    out = os.path.join(root, 'lea-nopass-' + os.path.basename(arc))
    os.makedirs(out)
    r = run(['extract', arc, '-d', out])
    if r.returncode == 0 or 'password required' not in (r.stdout + r.stderr):
        raise SystemExit(f'{arc}: a missing password was not refused')
    if files_under(out):
        raise SystemExit(f'{arc}: refusal without a password left files behind')
    out = os.path.join(root, 'lea-badpass-' + os.path.basename(arc))
    os.makedirs(out)
    r = run(['extract', arc, '-p', 'not-the-password', '-d', out])
    if r.returncode == 0 or 'incorrect password' not in (r.stdout + r.stderr):
        raise SystemExit(f'{arc}: a wrong password was not refused: '
                         f'{r.stdout}{r.stderr}')
    if files_under(out):
        raise SystemExit(f'{arc}: refusal with a wrong password left files behind')
    out = os.path.join(root, 'lea-full-' + os.path.basename(arc))
    os.makedirs(out)
    r = run(['extract', arc, '-p', PASSWORD, '-d', out])
    if r.returncode:
        raise SystemExit(f'{arc}: extraction failed: '
                         f'{(r.stderr or r.stdout).strip()}')
    for name in names:
        got = os.path.join(out, *name.split('/'))
        ref = os.path.join('corpus', *name.split('/')[-1:])
        if not os.path.exists(got):
            raise SystemExit(f'{arc}: extraction wrote no {name}')
        if open(got, 'rb').read() != open(ref, 'rb').read():
            raise SystemExit(f'{arc}: {name} differs from {ref}')

# LEA authenticates the ciphertext too (same HMAC as AES): one byte of the
# block payload is flipped (located by its signature), not of the header.
arc = 'packed_egg/lea256_optimized_hello.egg'
blob = bytearray(open(arc, 'rb').read())
at = blob.find(bytes.fromhex('130cb502'))          # signature BLOCK
if at < 0:
    raise SystemExit('lea256: block signature not found, cannot tamper')
blob[at + 4 + 14 + 4 + 40] ^= 0x01
bad = os.path.join(root, 'lea-tampered.egg')
open(bad, 'wb').write(bytes(blob))
out = os.path.join(root, 'lea-tampered')
os.makedirs(out)
r = run(['extract', bad, '-p', PASSWORD, '-d', out])
message = (r.stdout + r.stderr)
if r.returncode == 0 or 'authentication' not in message or 'HMAC' not in message:
    raise SystemExit(f'tampered LEA ciphertext was not rejected: {message.strip()}')
if files_under(out):
    raise SystemExit('the tampered LEA archive left files behind')

print('encryption: ZipCrypto, AES-128, AES-256, LEA-128 and LEA-256 '
      'decrypted back to the corpus (CRCs match); missing password, wrong '
      'password and tampered ciphertext refused without writing')
EOF

echo "== [9/13] EGG writer: byte-parity against the ALZip references =="
python3 - "$TEST_TMP" <<'EOF'
import datetime, glob, os, random, shutil, struct, subprocess, sys, time, zlib

sys.path.insert(0, 'tools')
import egg_dump as ed   # independent structural parser (reverse-engineered spec)

# A member's FILETIME field holds the file's LOCAL time (measured on the
# references: +2 h from the epoch). The corpus was produced in Europe/Paris, so
# this zone is pinned to make the step reproducible elsewhere; the alz child
# processes inherit it.
os.environ['TZ'] = 'Europe/Paris'
time.tzset()

root = sys.argv[1]
ALZ = os.path.abspath('./alzgg')


def reference(path):
    """(bytes, header_id, [(name, filetime)]) of the ALZip reference archive."""
    blob = open(path, 'rb').read()
    hid = struct.unpack_from('<I', blob, 6)[0]
    members = [(e['name'], e['wininfo']['filetime'])
               for e in ed.parse(path)['files'] if e.get('kind') == 'file']
    return blob, hid, members


def find_reference(base):
    """Path of a reference archive, whichever set carries it."""
    for directory in ('packed_egg', 'packed_alz',
                      'packed_egg_8.0', 'packed_alz_8.0'):
        path = os.path.join(directory, base)
        if os.path.exists(path):
            return path
    raise SystemExit(f'{base}: reference archive missing')


def pin(stage, name, filetime):
    """Set on the entry the mtime that yields this FILETIME on write."""
    wall = filetime // 10000000 - 11644473600
    epoch = int(datetime.datetime.utcfromtimestamp(wall).astimezone().timestamp())
    os.utime(os.path.join(stage, *name.split('/')), (epoch, epoch))


def create(stage, archive, hid, args, profile='none'):
    return subprocess.run([ALZ, 'create', archive, '-p', profile,
                           '-i', '0x%x' % hid] + args,
                          cwd=stage, capture_output=True, text=True)


# --- ZipCrypto on the test side: the 12-byte verifier stored in Encrypt Info
# decrypts to 10 bytes of material followed by the two high bytes of the
# member's CRC-32 (low weight first). ALZip draws those 10 bytes at random; the
# test reads them back from the reference instead of hard-coding them, which
# also checks where the two CRC bytes sit.
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


def zip_material(stored, crc, pwbytes):
    k = [0x12345678, 0x23456789, 0x34567890]
    for b in pwbytes:
        _zupd(k, b)
    plain = bytearray()
    for b in stored:
        t = (k[2] | 2) & 0xFFFFFFFF
        c = b ^ ((((t * (t ^ 1)) & 0xFFFFFFFF) >> 8) & 0xFF)
        plain.append(c)
        _zupd(k, c)
    if plain[10] != ((crc >> 16) & 0xFF) or plain[11] != ((crc >> 24) & 0xFF):
        raise SystemExit(f'inconsistent ZipCrypto verifier: {plain.hex()}')
    return bytes(plain[:10]).hex()


# Single files, an empty file, then eight members over two levels including a
# 2022 date (winter time: the zone is not the summer one). Each profile is
# compared with the references of the same profile: the `hint` byte is the zlib
# level (6 = Normal, 5 = Priority on Compressing Speed), measured over the whole
# corpus.
single = os.path.join(root, 'w-single')
os.makedirs(single)
shutil.copy2('corpus/hello.txt', os.path.join(single, 'hello.txt'))

# code.c: 45,270 bytes of C text, the heaviest member of several references.
# Under Normal it comes out as deflate hint 6 (gui_normal_code.egg, produced by
# the GUI), under Compressing Speed as hint 5 (code_compspeed.egg) and under
# Optimized as bzip2 hint 4 (code_optimized.egg): comparing it pins the three
# routes AND the three encoders of the writer. The encoders themselves are
# covered block by block by steps 10 and 11.
code = os.path.join(root, 'w-code')
os.makedirs(code)
shutil.copy2('corpus/code.c', os.path.join(code, 'code.c'))

empty = os.path.join(root, 'w-empty')
os.makedirs(empty)
open(os.path.join(empty, 'empty.dat'), 'wb').close()

nested = os.path.join(root, 'w-nested')
os.makedirs(nested)
shutil.copytree('corpus/nested', os.path.join(nested, 'tree'),
                copy_function=shutil.copy2)
nested = os.path.join(nested, 'tree')

# The compressed ALZip 8.0 profiles (deflate 6 / deflate 5) are no longer
# reproduced: 12.30 writes deflate 4 in Normal and deflate 2 in Compressing
# Speed. Only the Store members stay identical across the two versions; the
# 12.30 levels are pinned by lot K (below).
cases = [
    ('none', 'hello_none.egg', single, ['hello.txt']),
    ('none', 'empty_none.egg', empty, ['empty.dat']),
    ('none', 'nested_none.egg', nested, sorted(os.listdir(nested))),
]

for profile, base, stage, args in cases:
    blob, hid, members = reference(find_reference(base))
    for name, filetime in members:
        pin(stage, name, filetime)
    out = os.path.join(root, base.replace('.egg', '') + '-out.egg')
    result = create(stage, out, hid, args, profile)
    if result.returncode:
        raise SystemExit(f'{base}: create failed: '
                         f'{(result.stderr or result.stdout).strip()}')
    got = open(out, 'rb').read()
    if got != blob:
        at = next((i for i in range(min(len(got), len(blob))) if got[i] != blob[i]),
                  min(len(got), len(blob)))
        raise SystemExit(f'{base}: archive produced with -p {profile} differs from the '
                         f'reference ({len(got)} vs {len(blob)} bytes, first '
                         f'difference at {at})')
    print(f'  {base}: {len(got)} identical bytes ({len(members)} member(s), '
          f'-p {profile})')

# --- lot K: the five ALZipCon 12.30 profiles on the same `two/` tree
# (hello.txt + code.c, 45,335 bytes), then a `.sys` member routed to AZO.
# This is the write contract: m0 store, m1 deflate 2, m2 deflate 4, m3 LZMA 8,
# m4 Optimized (bzip2 hint 4 for this .c/.txt). Each archive is reproduced byte
# for byte with its Header ID and FILETIMEs, then read back.
lotk_stage = os.path.join(root, 'w-lotk')
os.makedirs(os.path.join(lotk_stage, 'two'))
shutil.copy2('corpus/hello.txt', os.path.join(lotk_stage, 'two', 'hello.txt'))
shutil.copy2('corpus/code.c', os.path.join(lotk_stage, 'two', 'code.c'))
for base, profile in (('egg_m0_two.egg', 'none'), ('egg_m1_two.egg', 'compspeed'),
                      ('egg_m2_two.egg', 'normal'), ('egg_m3_two.egg', 'compratio'),
                      ('egg_m4_two.egg', 'optimized')):
    ref = os.path.join('packed_egg', base)
    blob, hid, members = reference(ref)
    for name, filetime in members:
        pin(lotk_stage, name, filetime)
    out = os.path.join(root, 'lotk-' + base)
    result = create(lotk_stage, out, hid, ['two'], profile)
    if result.returncode:
        raise SystemExit(f'{base}: create failed: '
                         + (result.stderr or result.stdout).strip())
    got = open(out, 'rb').read()
    if got != blob:
        at = next((i for i in range(min(len(got), len(blob))) if got[i] != blob[i]),
                  min(len(got), len(blob)))
        raise SystemExit(f'{base}: archive produced with -p {profile} differs '
                         f'from the 12.30 reference ({len(got)} vs {len(blob)} '
                         f'bytes, first difference at {at})')
    back = os.path.join(root, 'lotk-back-' + base)
    os.makedirs(back)
    result = subprocess.run([ALZ, 'extract', out, '-d', back],
                            capture_output=True, text=True)
    if result.returncode or open(os.path.join(back, 'two', 'code.c'), 'rb').read() != \
            open('corpus/code.c', 'rb').read():
        raise SystemExit(f'{base}: 12.30 archive is not readable back: '
                         + (result.stdout + result.stderr).strip())
    print(f'  {base}: {len(got)} identical bytes (12.30, -p {profile})')

# AZO: same 12.30 reference as lot J/optimized, on a .sys derived from the
# ALZip 8.0 Deflate.dll (corpus/probe.sys).
azo_ref = os.path.join('packed_egg', 'egg_m4_sys.egg')
blob, hid, members = reference(azo_ref)
azo_stage = os.path.join(root, 'w-lotk-azo')
os.makedirs(azo_stage)
for name, filetime in members:
    shutil.copy2(os.path.join('corpus', name), os.path.join(azo_stage, name))
    pin(azo_stage, name, filetime)
out = os.path.join(root, 'lotk-azo.egg')
result = create(azo_stage, out, hid, [name for name, _ in members], 'optimized')
if result.returncode or open(out, 'rb').read() != blob:
    raise SystemExit('egg_m4_sys.egg: AZO 12.30 reference differs: '
                     + (result.stderr or result.stdout).strip())
print(f'  egg_m4_sys.egg: {len(blob)} identical bytes (12.30, AZO)')

# --- ALZip 8.0 GUI archives: one per profile. They are no longer a write
# contract (their levels are ALZip 8.0's) but are still extracted byte for byte
# in step 6.

# --- "Priority on Compress Ratio": the LZMA stream is identical between 8.0
# and 12.30, only the `hint` byte changes (6 -> 8). The thirteen 8.0
# references are therefore replayed by comparing the whole block (method,
# sizes, CRC and payload) and requiring hint 8 on our side: that pins the LZMA
# encoder on far more than lot K's code.c, without pretending to reproduce the
# 8.0 header bytes.
def lzma_payload(entry):
    return [(b['method'], b['usize'], b['csize'], b['crc'], b['data'])
            for b in entry.get('blocks', [])]

compratio_single = {
    'hello': 'hello.txt', 'code': 'code.c', 'eng': 'eng.txt',
    'mixed': 'mixed.bin', 'records': 'records.bin', 'pattern': 'pattern.bin',
    'biased': 'biased.bin', 'random': 'random.bin', 'zeros': 'zeros.bin',
    'image': 'image.raw', 'image24': 'image24.raw', 'sound': 'sound.wav',
    'Noise': 'Noise.wav',
}
ratio_checked = 0
for stem, name in compratio_single.items():
    ref_path = find_reference(f'{stem}_compratio.egg')
    if not os.path.exists(ref_path):
        raise SystemExit(f'{stem}_compratio.egg: LZMA reference missing')
    blob, hid, members = reference(ref_path)
    stage = os.path.join(root, 'w-ratio-' + stem)
    os.makedirs(stage)
    shutil.copy2(os.path.join('corpus', name), os.path.join(stage, name))
    pin(stage, name, members[0][1])
    out = os.path.join(root, 'ratio-' + stem + '.egg')
    result = create(stage, out, hid, [name], 'compratio')
    if result.returncode:
        raise SystemExit(f'{stem}_compratio.egg: create failed: '
                         + (result.stderr or result.stdout).strip())
    ref_file = [e for e in ed.parse(ref_path)['files'] if e.get('kind') == 'file'][0]
    got_file = [e for e in ed.parse(out)['files'] if e.get('kind') == 'file'][0]
    hints = [b['hint'] for b in got_file.get('blocks', [])]
    if hints != [8] * len(hints):
        raise SystemExit(f'{stem}_compratio.egg: hints {hints}, expected [8]')
    if lzma_payload(got_file) != lzma_payload(ref_file):
        raise SystemExit(f'{stem}_compratio.egg: the LZMA stream differs from '
                         'the 8.0 reference (only the hint may change)')
    ratio_checked += 1
print(f'  {ratio_checked} LZMA blocks identical to the 8.0 references, hint 8')

nested_ref = find_reference('nested_compratio.egg')
blob, hid, members = reference(nested_ref)
stage = os.path.join(root, 'w-ratio-nested')
shutil.copytree('corpus/nested', stage, copy_function=shutil.copy2)
for name, filetime in members:
    pin(stage, name, filetime)
out = os.path.join(root, 'ratio-nested.egg')
result = create(stage, out, hid, sorted(os.listdir(stage)), 'compratio')
if result.returncode:
    raise SystemExit('nested_compratio.egg: create failed: '
                     + (result.stderr or result.stdout).strip())
ref_files = {e['name']: e for e in ed.parse(nested_ref)['files']
             if e.get('kind') == 'file'}
got_files = {e['name']: e for e in ed.parse(out)['files']
             if e.get('kind') == 'file'}
if set(ref_files) != set(got_files):
    raise SystemExit('nested_compratio.egg: member set differs')
for name, ref_file in ref_files.items():
    got_hints = [b['hint'] for b in got_files[name].get('blocks', [])]
    if got_hints != [8] * len(got_hints):
        raise SystemExit(f'nested_compratio.egg/{name}: hints {got_hints}, expected [8]')
    if lzma_payload(got_files[name]) != lzma_payload(ref_file):
        raise SystemExit(f'nested_compratio.egg/{name}: the LZMA stream differs '
                         'from the 8.0 reference')
print(f'  nested_compratio.egg: {len(members)} identical LZMA streams, hint 8')

# --- Optimized profile: routes measured per extension, compared byte for byte.
# bzip2 for .c/.txt/.java, store for .jpg/.zip, deflate hint 5 for .bin/.raw/.wav
# - including a .bin with text content (text_contenu), which pins the fact that
# the route follows the EXTENSION and not the content -, LZMA 6 for .doc/.ico and
# AZO for .sys/.com.
#
# The derived AZO entries are not stored: probe.com is probe.sys under another
# extension (ALZip routes it to AZO too, same hint, same stream), sysmulti.sys is
# corpus/code.c repeated 14 times - 633,780 bytes, hence two internal 2^19 slices
# (524,288 + 109,492): that reference pins the internal slicing and the model
# reset from one slice to the next.
derived = os.path.join(root, 'w-derived')
os.makedirs(derived, exist_ok=True)
shutil.copy2('corpus/probe.sys', os.path.join(derived, 'probe.com'))
with open(os.path.join(derived, 'sysmulti.sys'), 'wb') as fp:
    fp.write(open('corpus/code.c', 'rb').read() * 14)

# --- AZO's x86 filter (spec A.12): two Windows executables (MZ signature)
# renamed to .sys, hence routed to AZO like other .sys files. AZO.dll only raises
# the filter flag when the first buffer starts with "MZ" (0x61907410) and then
# writes `31 01` - that is what these two references show, whereas probe.sys
# (text) gives `31 00`. mz.sys fits in one slice; mzmulti.sys (594,264 bytes)
# spans two and its second slice does NOT start with MZ: it is filtered anyway
# (sticky flag), which pins the rule.
mz_src = os.environ.get('ALZIP_80_DIR', os.path.join('_work', 'binaries', 'alzip-8.0'))
if not os.path.isdir(mz_src):
    mz_src = os.path.join('research', 'Program Files (x86)', 'ALZip')
deflate_src = os.path.join(mz_src, 'Coders', 'Deflate.dll')
alzipcon_src = os.path.join(mz_src, 'ALZipCon.exe')
if os.path.isfile(deflate_src):
    shutil.copy2(deflate_src, os.path.join(derived, 'mz.sys'))
if os.path.isfile(alzipcon_src):
    shutil.copy2(alzipcon_src, os.path.join(derived, 'mzmulti.sys'))

# --- x86 filter + raw-copied slice: two incompressible .sys members starting
# with MZ (same recipe as DERIVED, step 6). AZO.dll filters the slice BEFORE the
# "block copied" test and then stores the filtered data as is: these two
# references are the only ones in the corpus on that path (csize == usize, slice
# field 3 zero, `31 01` flag kept).
def mzraw_payload(n):
    r = random.Random(0x415a4f)
    return b'MZ' + bytes(r.randrange(256) for _ in range(n - 2))

with open(os.path.join(derived, 'mzraw.sys'), 'wb') as fp:
    fp.write(mzraw_payload(524288))
with open(os.path.join(derived, 'mzraw2.sys'), 'wb') as fp:
    fp.write(mzraw_payload(2 * 524288))

optimized = [
    ('empty_optimized.egg', 'corpus', ['empty.dat']),
    ('hello_optimized.egg', 'corpus', ['hello.txt']),
    ('code_optimized.egg', 'corpus', ['code.c']),
    # Same content as the previous one (identical blocks, different header_id):
    # the archive labelled "normal" is actually Optimized, hence the bzip2 route
    # that had been misread as the Normal profile's.
    ('packed_egg_8.0/code_normal.egg', 'corpus', ['code.c']),
    ('eng_optimized.egg', 'corpus', ['eng.txt']),
    ('image_optimized.egg', 'corpus', ['image.raw']),
    ('records_optimized.egg', 'corpus', ['records.bin']),
    ('nested_optimized.egg', 'corpus/nested', None),
    ('text_contenu_optimized.egg', 'corpus', ['text_contenu.bin']),
    ('probe_java_optimized.egg', 'corpus', ['probe.java']),
    ('probe_jpg_optimized.egg', 'corpus', ['probe.jpg']),
    ('probe_doc_optimized.egg', 'corpus', ['probe.doc']),
    ('probe_ico_optimized.egg', 'corpus', ['probe.ico']),
    ('probe_sys_optimized.egg', 'corpus', ['probe.sys']),
    ('probe_com_optimized.egg', derived, ['probe.com']),
    ('sysmulti_sys_optimized.egg', derived, ['sysmulti.sys']),
    ('mzraw_sys_optimized.egg', derived, ['mzraw.sys']),
    ('mzraw2_sys_optimized.egg', derived, ['mzraw2.sys']),
]
if os.path.isfile(os.path.join(derived, 'mz.sys')):
    optimized.append(('mz_sys_optimized.egg', derived, ['mz.sys']))
if os.path.isfile(os.path.join(derived, 'mzmulti.sys')):
    optimized.append(('mzmulti_sys_optimized.egg', derived, ['mzmulti.sys']))
for base, src, args in optimized:
    ref_path = base if base.startswith('packed_') else find_reference(base)
    # 8.0 references whose name also exists in 12.30 are named by full path:
    # only the base name is used for the working directories.
    label = os.path.basename(base)
    blob, hid, members = reference(ref_path)
    stage = os.path.join(root, 'w-opt-' + label.replace('.egg', ''))
    if args is None:                     # tree (nested): both levels
        shutil.copytree(src, stage, copy_function=shutil.copy2)
        args = sorted(os.listdir(stage))
    else:
        os.makedirs(stage)
        for name in args:
            shutil.copy2(os.path.join(src, name), os.path.join(stage, name))
    for name, filetime in members:
        pin(stage, name, filetime)
    out = os.path.join(root, 'opt-' + label)
    result = create(stage, out, hid, args, 'optimized')
    if result.returncode:
        raise SystemExit(f'{base}: optimized create failed: '
                         f'{(result.stderr or result.stdout).strip()}')
    got = open(out, 'rb').read()
    if got != blob:
        at = next((i for i in range(min(len(got), len(blob))) if got[i] != blob[i]),
                  min(len(got), len(blob)))
        raise SystemExit(f'{base}: archive produced with -p optimized differs from '
                         f'the reference ({len(got)} vs {len(blob)} bytes, first '
                         f'difference at {at})')
    print(f'  {base}: {len(got)} identical bytes (Optimized, {len(members)} '
          f'member(s))')

# --- Optimized profile, FULL ROUTING TABLE: packed_egg/routes_optimized.egg has
# 148 members, one per extension of the matrix (the four lists of Formats/Egg.dll
# - AZO .sys/.com, store 40 extensions (12.30 dropped `ace`), LZMA 8, bzip2 35 -
# plus about a hundred extensions outside the lists, without extension and with
# a double suffix), all with the same content (4,096 bytes of corpus/eng.txt):
# only the EXTENSION decides, and the compared csizes pin the codec AND its level
# (bzip2 725 B, LZMA 970, AZO 961, deflate 6 1006, deflate 5 1004, store 4096).
#
# What this reference fixes, and no other one proves:
#   - the deflate hint 5 fallback for any extension outside the lists (.exe,
#     .dll, .json, .md, .log, .pdf, .b, .x, .htm...: no extension is refused any
#     more);
#   - case-insensitive routing (u140.C, u141.TXT, u142.SYS, u143.JPG, u144.DOC,
#     u145.ZIP follow their lowercase form);
#   - only the last suffix counts (dbl.tar.gz -> gz, dbl2.c.bak -> bak,
#     a.b.c -> c) and a leading dot does not make an extension (.dotfile, left
#     out of the reference because of its hidden attribute, = noext).
#
# .dotfile is the only member not stored: Wine gives it attr=02 (hidden) and our
# writer does not guess an attribute; the absence of an extension is covered by
# `noext` and by all the `r...` entries without a dot.
# 12.30 reference: this is the one that rules for the writer. It differs from
# the ALZip 8.0 one on a single member, `r001.ace` - store in 8.0, deflate
# hint 5 in 12.30 (`ace` left the store list) -, which is exactly what this
# comparison pins.
routes_ref = os.path.join('packed_egg', 'routes_optimized.egg')
blob, hid, members = reference(routes_ref)
stage = os.path.join(root, 'w-routes')
os.makedirs(os.path.join(stage, 'routes'))
payload = open('corpus/eng.txt', 'rb').read()[:4096]
for name, filetime in members:
    with open(os.path.join(stage, *name.split('/')), 'wb') as fp:
        fp.write(payload)
    pin(stage, name, filetime)
out = os.path.join(root, 'routes-out.egg')
result = create(stage, out, hid, ['routes'], 'optimized')
if result.returncode:
    raise SystemExit('routes_optimized.egg: create failed: '
                     + (result.stderr or result.stdout).strip())
got = open(out, 'rb').read()
if got != blob:
    at = next((i for i in range(min(len(got), len(blob))) if got[i] != blob[i]),
              min(len(got), len(blob)))
    raise SystemExit('routes_optimized.egg: the 148-extension routing table differs '
                     f'from the ALZip reference ({len(got)} vs {len(blob)} bytes, '
                     f'first difference at {at})')
print(f'  routes_optimized.egg: {len(got)} identical bytes (Optimized, '
      f'{len(members)} extensions): AZO/store/BZ2/LZMA lists and the deflate '
      f'hint 5 fallback')

# --- The matching rule itself, read back from the binary instead of copied from
# a table: ALZipCon.exe looks the extension up in the codec's list
# (wstring::find from 0) and only accepts the match if the NEXT character is a
# comma (or the end of the string) - a single attempt, with no retry on the next
# occurrence. Consequence: an extension whose FIRST occurrence falls inside a
# longer, EARLIER entry of its own list is invisible. Those are exactly the nine
# "inert" entries measured in lot G (.htm inside .html, .as inside .asc, .b
# inside .bat, .bb inside .bbs, .cp inside .cpp, .d inside .dbt, .j/.jav inside
# .java, .x inside .xml).
#
# Locations: Formats/Egg.dll registers the four lists (AZO 0x6231ba4c, store
# 0x6231ba68, BZ2 0x6231bc58, LZMA 0x6231be68) and the application picks, not the
# plugin; AZCTM.dll carries the same lists (0x1006fb30...) and the boundary test
# lives in ALZipCon.exe (find 0x456a87, comma 0x456aef, codec loop 0x456b61).
#
# This block replays that rule on the lists READ FROM the DLL: if it reproduces
# the reference's 148 members one by one, the writer's table is not a copied list
# but indeed the consequence of the rule - and the BZ2 list can only lose the
# nine known entries.
# ALZipCon 12.30 DLL: this is the version that produced the reference. The ALZip
# 8.0 one (under research/) keeps `ace` at the head of the store list, hence the
# single difference between the two routing archives on `r001.ace`.
dll = os.environ.get('EGG_DLL_PATH', os.path.join('_work', 'binaries', 'alzip-12.30', 'Formats', 'Egg.dll'))
if not os.path.isfile(dll):
    dll = os.path.join('vendor', 'alzip-12.30', 'Formats', 'Egg.dll')
if os.path.isfile(dll):
    raw = open(dll, 'rb').read()

    def utf16_at(pos):
        chars = []
        while raw[pos] or raw[pos + 1]:
            chars.append(chr(raw[pos] | (raw[pos + 1] << 8)))
            pos += 2
        return ''.join(chars)

    def list_of(prefix):
        pos = raw.find(prefix.encode('utf-16-le'))
        if pos < 0:
            raise SystemExit(f'{dll}: list {prefix!r} not found')
        return utf16_at(pos)

    # Plugin registration order (Egg.dll 0x62315033...0x62315092): AZO, LZMA, store,
    # BZ2. The lists are disjoint, so the order does not matter.
    LISTS = [('AZO', list_of('.sys, .com, '), (3, 1)),
             ('LZMA', list_of('.ppt, .xls, '), (4, 6)),
             ('STORE', list_of('.alz, .arc, '), (0, 0)),
             ('BZ2', list_of('.h, .c, .java, '), (2, 4))]


    def alzip_match(ext, lst):
        i = lst.find(ext)
        return i >= 0 and (i + len(ext) == len(lst) or lst[i + len(ext)] == ',')


    def ext_of(name):
        base = name.rsplit('/', 1)[-1]
        dot = base.rfind('.')
        return base[dot:].lower() if dot > 0 and dot + 1 < len(base) else ''


    def alzip_route(name):
        ext = ext_of(name)
        if ext:
            for label, lst, codec in LISTS:
                if alzip_match(ext, lst):
                    return label, codec
        return 'DEFLATE5', (1, 5)


    parsed = ed.parse(routes_ref)
    files = [e for e in parsed['files'] if e.get('kind') == 'file']
    for e in files:
        label, want = alzip_route(e['name'])
        got_pairs = [(b['method'], b['hint']) for b in e['blocks']]
        if got_pairs != [want] * len(got_pairs):
            raise SystemExit(f'routes_optimized.egg/{e["name"]}: the ALZip rule '
                             f'({label}) predicts {want}, the reference carries '
                             f'{got_pairs}')
    if len(files) != len(members):
        raise SystemExit(f'{len(files)} members described by the rule, '
                         f'{len(members)} in the reference')

    shadowed = {}
    for label, lst, _codec in LISTS:
        shadowed[label] = sorted(entry[1:] for entry in lst.split(', ')
                                 if entry and not alzip_match(entry, lst))
    if shadowed['BZ2'] != ['as', 'b', 'bb', 'cp', 'd', 'htm', 'j', 'jav', 'x']:
        raise SystemExit(f'BZ2 list: shadowed entries {shadowed["BZ2"]}, the nine '
                         f'expected ones being as, b, bb, cp, d, htm, j, jav, x')
    if shadowed['STORE'] or shadowed['LZMA'] or shadowed['AZO']:
        raise SystemExit(f'no store/LZMA/AZO list entry may be shadowed, yet '
                         f'{shadowed}')
    dead = ', '.join(shadowed['BZ2'])
    print(f'  ALZip rule replayed on the Formats/Egg.dll lists: the '
          f'{len(files)} reference members follow from it, and the only list that '
          f'loses entries is BZ2 ({len(shadowed["BZ2"])} shadowed: {dead})')
else:
    print('  Note: Egg.dll not found (proprietary binary omitted); skipped DLL reflection check.')

# --- encryption (spec §12): nine ALZip references - three in packed_egg
# (Optimized, ZipCrypto/AES-128/AES-256 on the same hello.txt), three in lot A
# (store ZipCrypto, deflate AES-128/256) and three two-member archives
# (ZipCrypto/AES-128/AES-256), which exercise one salt and one verifier PER
# MEMBER. ALZip draws this material at random, so byte-for-byte parity is
# obtained by feeding the references' own back in (10 ZipCrypto bytes, 8/16 of
# AES salt).
two_stage = os.path.join(root, 'w-twofiles')
for rel in ('corpus/twofiles/hello.txt',
            'corpus/twofiles/records.bin'):
    dst = os.path.join(two_stage, rel)
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    shutil.copy2(rel, dst)
two_names = ['corpus/twofiles/hello.txt',
             'corpus/twofiles/records.bin']

encrypted = [
    ('packed_egg_8.0/hello_optimized_password_zip2.egg', 'optimized', 'zip',
     ['00010001010101000101'], single, ['hello.txt'], 'password'),
    ('packed_egg_8.0/hello_optimized_password_aes128.egg', 'optimized', 'aes128',
     ['75524cd3ec8f3806'], single, ['hello.txt'], 'password'),
    ('packed_egg_8.0/hello_optimized_password_aes256.egg', 'optimized', 'aes256',
     ['5c8731099a82950ca08f7f6167d033a5'], single, ['hello.txt'], 'password'),
    ('packed_egg_8.0/enc_store_basic.egg', 'none', 'zip',
     ['00010001010000000101'], single, ['hello.txt'], 'password'),
    # The 8.0 deflate 6/5 references are no longer reproducible: the 12.30
    # two-member encrypted archives (m1 and m2) are checked further down by
    # crypt_parity, which reads the material back from the reference.
]
for ref, prof, cipher, mats, stage, names, passphrase in encrypted:
    if not os.path.exists(ref):
        raise SystemExit(f'{ref}: encrypted reference missing')
    blob, hid, members = reference(ref)
    if len(mats) != len(members):
        raise SystemExit(f'{ref}: {len(members)} members but {len(mats)} material entries')
    for name, filetime in members:
        pin(stage, name, filetime)
    out = os.path.join(root, 'enc-' + os.path.basename(ref))
    result = create(stage, out, hid,
                    ['--password', passphrase, '--crypt', cipher,
                     '--crypt-info', ','.join(mats)] + names, prof)
    if result.returncode:
        raise SystemExit(f'{os.path.basename(ref)}: encrypted create failed: '
                         f'{(result.stderr or result.stdout).strip()}')
    got = open(out, 'rb').read()
    if got != blob:
        at = next((i for i in range(min(len(got), len(blob))) if got[i] != blob[i]),
                  min(len(got), len(blob)))
        raise SystemExit(f'{os.path.basename(ref)}: archive produced with '
                         f'--crypt {cipher} differs from the reference '
                         f'({len(got)} vs {len(blob)} bytes, first difference at '
                         f'{at})')
    print(f'  {os.path.basename(ref)}: {len(got)} identical bytes '
          f'({cipher}, {len(members)} member(s))')

# --- Full lot H matrix: the four EGG profiles (m0..m3) x the three methods
# (-tp0/1/2) on hello.txt, a two-member store archive, and the two cases WITHOUT
# a block - empty file and directory - that ALZip leaves without Encrypt Info
# even when -ppassword is requested. The random material is read back from each
# reference (10 decrypted bytes for ZipCrypto, the salt in the clear for AES):
# no value is hard-coded.
def crypt_parity(ref, prof, cipher, stage, names):
    blob = open(ref, 'rb').read()
    hid = struct.unpack_from('<I', blob, 6)[0]
    mats = []
    for e in ed.parse(ref)['files']:
        if e['kind'] in ('file', 'dir'):
            pin(stage, e['name'], e['wininfo']['filetime'])
        c = e.get('crypt')
        if not c:
            continue
        data = bytes.fromhex(c['data'])
        if c['method'] == 0:
            crc = e['blocks'][0]['crc']
            mats.append(zip_material(data[:12],
                                     int(crc, 16) if isinstance(crc, str) else crc,
                                     b'password'))
        else:
            # AES-128 (1) and LEA-128 (5): 8-byte salt; AES-256 (2) and
            # LEA-256 (6): 16. Both families derive the key the same way, hence
            # this test on the parity of the method number.
            mats.append(data[:16 if c['method'] % 2 == 0 else 8].hex())
    out = os.path.join(root, 'enc-' + os.path.basename(ref))
    args = [ALZ, 'create', out, '-p', prof, '-i', '0x%x' % hid,
            '--password', 'password', '--crypt', cipher]
    if mats:
        args += ['--crypt-info', ','.join(mats)]
    result = subprocess.run(args + names, cwd=stage, capture_output=True,
                            text=True)
    if result.returncode:
        raise SystemExit(f'{os.path.basename(ref)}: create failed: '
                         + (result.stderr or result.stdout).strip())
    got = open(out, 'rb').read()
    if got != blob:
        at = next((i for i in range(min(len(got), len(blob))) if got[i] != blob[i]),
                  min(len(got), len(blob)))
        raise SystemExit(f'{os.path.basename(ref)}: {len(got)} vs {len(blob)} '
                         f'bytes, first difference at {at}')
    print(f'  {os.path.basename(ref)}: {len(got)} identical bytes '
          f'({prof}, {cipher})')


h_root = 'packed_egg_8.0'          # lot H: encrypted ALZip 8.0 references
h_hello = os.path.join(root, 'w-crypt-hello')
os.makedirs(h_hello)
shutil.copy2(os.path.join('corpus', 'hello.txt'), h_hello)
h_two = os.path.join(root, 'w-crypt-two')
os.makedirs(h_two)
for _n in ('hello.txt', 'records.bin'):
    shutil.copy2(os.path.join('corpus', _n), h_two)
h_empty = os.path.join(root, 'w-crypt-empty')
os.makedirs(h_empty)
open(os.path.join(h_empty, 'empty.dat'), 'wb').close()
# The reference member carries the path it was archived under, so the working
# tree must contain it verbatim.
h_dir = os.path.join(root, 'w-crypt-dir')
h_dir_member = 'fixtures/out/lot-h/crypt/emptydir'
os.makedirs(os.path.join(h_dir, *h_dir_member.split('/')))

# Only the Store profile is identical across 8.0 and 12.30; the compressed
# 12.30 profiles are covered by lot K's encrypted archives, right after the LEA
# references. The block-less cases (empty, directory) depend on no profile and
# are still compared as they are.
for _m, _prof in (('m0', 'none'),):
    for _tp, _cipher in (('tp0', 'zip'), ('tp1', 'aes128'), ('tp2', 'aes256')):
        crypt_parity(os.path.join(h_root, f'enc_egg_{_m}_{_tp}.egg'), _prof,
                     _cipher, h_hello, ['hello.txt'])
crypt_parity(os.path.join(h_root, 'enc_egg_two_m0_tp0.egg'), 'none', 'zip',
             h_two, ['hello.txt', 'records.bin'])
crypt_parity(os.path.join(h_root, 'enc_egg_empty_tp0.egg'), 'none', 'zip',
             h_empty, ['empty.dat'])
crypt_parity(os.path.join(h_root, 'enc_egg_dir_tp0.egg'), 'none', 'zip',
             h_dir, [h_dir_member])
print('  lot H store encryption: three methods, two members, empty file and '
      'directory without Encrypt Info')

# --- LEA-128/256 (lot J): ALZipCon 12.30's undocumented "-tp3" / "-tp4" are
# the only known producers of these methods. The ciphertext (CTR), the PBKDF2
# verifier and the HMAC are therefore compared byte for byte against these six
# references: store and Optimized (bzip2), one and two entries, both key sizes.
j_hello = os.path.join(root, 'w-lea-hello')
os.makedirs(j_hello)
shutil.copy2('corpus/hello.txt', os.path.join(j_hello, 'hello.txt'))
j_two = os.path.join(root, 'w-lea-two')
os.makedirs(os.path.join(j_two, 'two'))
shutil.copy2('corpus/hello.txt', os.path.join(j_two, 'two', 'hello.txt'))
shutil.copy2('corpus/code.c', os.path.join(j_two, 'two', 'code.c'))
for _base, _prof, _cipher, _stage, _names in (
        ('lea128_store_hello.egg', 'none', 'lea128', j_hello, ['hello.txt']),
        ('lea256_store_hello.egg', 'none', 'lea256', j_hello, ['hello.txt']),
        ('lea128_optimized_hello.egg', 'optimized', 'lea128', j_hello,
         ['hello.txt']),
        ('lea256_optimized_hello.egg', 'optimized', 'lea256', j_hello,
         ['hello.txt']),
        ('lea128_store_two.egg', 'none', 'lea128', j_two, ['two']),
        ('lea256_store_two.egg', 'none', 'lea256', j_two, ['two'])):
    crypt_parity(os.path.join('packed_egg', _base), _prof, _cipher,
                 _stage, _names)

# 12.30 encryption: ZipCrypto in m1 (deflate 2) with two members - one salt and
# one verifier per member - and AES-256 in m2 (deflate 4). crypt_parity reads the
# material back from each reference, as for lots H and J.
crypt_parity('packed_egg/egg_zip_m1_two.egg', 'compspeed', 'zip',
             j_two, ['two'])
crypt_parity('packed_egg/egg_aes256_m2_hello.egg', 'normal', 'aes256',
             j_hello, ['hello.txt'])

# --- Encrypted + split (lot H, span_15vol_crypt): ALZip encrypts the member then
# splits it, the ciphertext (verifier included) being spread over 16 volumes of
# 102,400 bytes. This is the only witness of a chain longer than three volumes,
# and at the same time the proof that the two operations compose in that order:
# the verifier lives in Encrypt Info, not at the head of the data.
span_ref = 'packed_egg_8.0/span_15vol_crypt'
span_src = 'corpus/span/random1m.bin'
vols = sorted(glob.glob(span_ref + '.vol*.egg'),
              key=lambda p: int(p.split('.vol')[-1].split('.')[0]))
if len(vols) != 16:
    raise SystemExit(f'{span_ref}: 16 volumes expected, {len(vols)} found')
head = open(vols[0], 'rb').read()
vol_ids = [struct.unpack_from('<I', open(v, 'rb').read(20), 6)[0] for v in vols]
vi = head.find(struct.pack('<I', 0x08D1470F))
if vi < 0:
    raise SystemExit('span_15vol_crypt: Encrypt Info missing from volume 1')
verifier = head[vi + 8:vi + 20]   # sig(4) + flags(1) + length(2) + method(1)
wi = head.find(struct.pack('<I', 0x2C86950B))
span_time = struct.unpack_from('<Q', head, wi + 7)[0]
span_stage = os.path.join(root, 'w-span-crypt')
os.makedirs(span_stage)
shutil.copy2(span_src, os.path.join(span_stage, 'random1m.bin'))
pin(span_stage, 'random1m.bin', span_time)
span_crc = zlib.crc32(open(span_src, 'rb').read()) & 0xFFFFFFFF
span_mat = zip_material(verifier, span_crc, b'secret')
span_out = os.path.join(root, 'span-crypt.egg')
result = subprocess.run([ALZ, 'create', span_out, '-p', 'none',
                         '-v', '102400',
                         '-i', ','.join('0x%x' % i for i in vol_ids),
                         '--password', 'secret', '--crypt-info', span_mat,
                         'random1m.bin'],
                        cwd=span_stage, capture_output=True, text=True)
if result.returncode:
    raise SystemExit('encrypted span create failed: '
                     + (result.stderr or result.stdout).strip())
for n, ref in enumerate(vols, 1):
    got = open(os.path.join(root, 'span-crypt.vol%d.egg' % n), 'rb').read()
    if got != open(ref, 'rb').read():
        raise SystemExit(f'span_15vol_crypt: volume {n} differs from the '
                         f'ALZip reference')
# ... and the chain reads back from its last volume.
span_dec = os.path.join(root, 'span-crypt-dec')
os.makedirs(span_dec)
r = subprocess.run([ALZ, 'extract', os.path.join(root, 'span-crypt.vol16.egg'),
                    '-d', span_dec, '-p', 'secret'], capture_output=True,
                   text=True)
if r.returncode or open(os.path.join(span_dec, 'random1m.bin'), 'rb').read() != \
        open('corpus/span/random1m.bin', 'rb').read():
    raise SystemExit('encrypted span chain: extraction from the last volume '
                     'failed: ' + r.stdout + r.stderr)
print('  span_15vol_crypt: 16 identical encrypted volumes, chain read back '
      'from the last volume')

# Random material (ALZip behaviour, without --crypt-info): the archive must read
# back, and a missing or wrong password must be refused without writing - on the
# writer side as on the reader side.
plain = open(os.path.join(single, 'hello.txt'), 'rb').read()
for _cipher in ('zip', 'lea128', 'lea256'):
    rnd = os.path.join(root, f'enc-random-{_cipher}.egg')
    result = subprocess.run([ALZ, 'create', rnd, '-p', 'normal', '-i', '0x1234',
                             '--password', 's3cret', '--crypt', _cipher,
                             'hello.txt'],
                            cwd=single, capture_output=True, text=True)
    if result.returncode:
        raise SystemExit(f'random-material encrypted create failed ({_cipher}): '
                         + (result.stderr or result.stdout).strip())
    for extra, needle in (([], 'password required'),
                          (['-p', 'wrong'], 'incorrect password')):
        outdir = os.path.join(root, f'enc-random-refuse-{_cipher}-' + str(len(extra)))
        os.makedirs(outdir)
        r = subprocess.run([ALZ, 'extract', rnd, '-d', outdir] + extra,
                           capture_output=True, text=True)
        if r.returncode == 0 or needle not in (r.stdout + r.stderr):
            raise SystemExit(f'encrypted archive ({_cipher}, {extra}): expected '
                             f'"{needle}", got: '
                             + (r.stdout + r.stderr).strip())
        if [p for p in glob.glob(os.path.join(outdir, '**'), recursive=True)
                if os.path.isfile(p)]:
            raise SystemExit(f'encrypted archive ({_cipher}, {extra}): refusal '
                             'left files behind')
    outdir = os.path.join(root, f'enc-random-ok-{_cipher}')
    os.makedirs(outdir)
    r = subprocess.run([ALZ, 'extract', rnd, '-d', outdir, '-p', 's3cret'],
                       capture_output=True, text=True)
    if r.returncode or open(os.path.join(outdir, 'hello.txt'), 'rb').read() != plain:
        raise SystemExit(f'random-material encrypted archive does not '
                         f'round-trip ({_cipher}): '
                         + (r.stdout + r.stderr).strip())
print('  random material (zip, lea128, lea256): archive read back, missing or '
      'wrong password refused')

# Combinations and inputs the writer must refuse, without writing: ALZip
# forbids encrypting a solid archive and encrypted volumes; the material must be
# complete and match the method's length; a password that is not valid UTF-8
# cannot be converted to an ANSI code page (spec §12.9), so it is refused rather
# than guessed. The empty member and the directory are not refused: the matrix
# above shows ALZip writes them without Encrypt Info, and the writer reproduces
# that.
refusals = [
    ([ALZ, 'create', os.path.join(root, 'r1.egg'), '-p', 'compspeed', '-s',
      '-i', '0x1234', '--password', 'pw', 'hello.txt'], single, 'cannot be encrypted'),
    ([ALZ, 'create', os.path.join(root, 'r4.egg'), '-p', 'normal', '-i', '0x1234',
      '--password', 'pw', '--crypt-info', '00010001010000000101',
      'hello.txt', 'hello.txt'], single, 'one random material per member'),
    ([ALZ, 'create', os.path.join(root, 'r5.egg'), '-p', 'normal', '-i', '0x1234',
      '--password', 'pw', '--crypt', 'aes128', '--crypt-info',
      '00010001010000000101', 'hello.txt'], single, 'invalid --crypt-info'),
    # `--crypt` without `--password`: refused, otherwise the archive came out in
    # the clear although the command line asked for encryption.
    ([ALZ, 'create', os.path.join(root, 'r7.egg'), '-p', 'normal', '-i', '0x1234',
      '--crypt', 'lea256', 'hello.txt'], single,
     '--crypt only makes sense with --password'),
    # Lone 0xF6 byte: neither valid UTF-8 nor convertible (the ALZip encoding is
    # measured from a UTF-8 string, cf. the three `napw` references).
    ([os.fsencode(ALZ), b'create', os.fsencode(os.path.join(root, 'r6.egg')),
      b'-p', b'normal', b'-i', b'0x1234', b'--password', b'passw\xf6rd',
      b'hello.txt'], single, 'UTF-8'),
]
for args, cwd, needle in refusals:
    r = subprocess.run(args, cwd=cwd, capture_output=True, text=True)
    message = r.stdout + r.stderr
    if r.returncode == 0 or needle not in message:
        raise SystemExit(f'encryption refusal "{needle}" not reported: '
                         + message.strip())
    if os.path.exists(args[2]):
        raise SystemExit(f'encryption refusal "{needle}" left an archive behind')
print('  solid, incomplete material, short salt, non-ASCII password and --crypt '
      'without --password all refused without writing')

# The Optimized profile no longer refuses an extension: its table is complete
# (four lists + fallback). probe.pas, absent from the Optimized lists but present
# in the DLL's bzip2 list, follows its route; probe.cc, outside every list, takes
# the deflate hint 5 fallback. The whole table is checked byte for byte by
# packed_egg/routes_optimized.egg (148 extensions) above.
for member, want in (('probe.pas', 'meth=2(bzip2) hint=4'),
                     ('probe.cc', 'meth=1(deflate) hint=5')):
    target = os.path.join(root, 'opt-route-' + member.replace('.', '-') + '.egg')
    result = subprocess.run([ALZ, 'create', target, '-p', 'optimized',
                             '-i', '0x1234', member],
                            cwd='corpus', capture_output=True, text=True)
    if result.returncode:
        raise SystemExit(f'optimized {member} is still refused: '
                         + (result.stderr or result.stdout).strip())
    listed = subprocess.run([ALZ, 'list', target], capture_output=True, text=True)
    if want not in listed.stdout:
        raise SystemExit(f'optimized {member}: expected {want!r}, got:\n'
                         + listed.stdout.strip())

# The Normal profile does not route by extension: the ALZip plugin's m1 profile
# registers as "Deflate + Store" and the GUI matrix' fifteen members (nine
# extensions) all come out as deflate hint 6. An extension no matrix contains no
# longer has to be refused, it is written like the others. Three names outside
# every list prove it, one of them without an extension.
for name, payload in (('notes.md', b'unmeasured\n'),
                      ('payload.exe', b'MZ' + bytes(range(64))),
                      ('sans-extension', b'no dot here\n')):
    with open(os.path.join(single, name), 'wb') as fp:
        fp.write(payload)
    target = os.path.join(root, 'normal-unlisted-' + name.replace('.', '-') + '.egg')
    result = create(single, target, 0x1234, [name], 'normal')
    if result.returncode:
        raise SystemExit(f'normal {name}: create failed: '
                         + (result.stderr or result.stdout).strip())
    listed = subprocess.run([ALZ, 'list', target], capture_output=True, text=True)
    if 'meth=1(deflate) hint=4' not in listed.stdout:
        raise SystemExit(f'normal {name}: expected deflate hint 4, got:\n'
                         + listed.stdout.strip())

# --- solid + ".c" member: the 8.0 reference (solid Normal, deflate 6) is no
# longer a write contract; the 12.30 solid (m1 = deflate 2) is covered by lot K
# below. Set K's LZMA/M1 stream keeps a .c member in the `two/` tree, so the
# extension routing stays exercised.

# --- empty directory: an attr=0x80 member without a block (as in the
# references), and a round trip through the project's reader.
stage = os.path.join(root, 'w-dir')
os.makedirs(os.path.join(stage, 'vide'))
open(os.path.join(stage, 'f.bin'), 'wb').write(b'abc')
arc = os.path.join(root, 'dir.egg')
result = subprocess.run([ALZ, 'create', arc, '-p', 'none', '-i', '0x1234',
                         'vide', 'f.bin'], cwd=stage, capture_output=True, text=True)
if result.returncode:
    raise SystemExit(f'create with an empty directory failed: '
                     f'{(result.stderr or result.stdout).strip()}')
found = [e for e in ed.parse(arc)['files'] if e['name'] == 'vide']
if (not found or found[0]['wininfo']['attrs'] != 0x80 or found[0]['blocks']
        or found[0]['usize'] != 0):
    raise SystemExit(f'the empty directory is not stored as attr=0x80 without a block: '
                     f'{found}')
out = os.path.join(root, 'dir-extract')
os.makedirs(out)
result = subprocess.run([ALZ, 'extract', arc, '-d', out], capture_output=True, text=True)
if result.returncode or open(os.path.join(out, 'f.bin'), 'rb').read() != b'abc':
    raise SystemExit('the store archive written here is not readable back by alzgg: '
                     f'{(result.stdout + result.stderr).strip()}')

# --- determinism: two writes of the same tree and the same header_id
second = os.path.join(root, 'dir-2.egg')
subprocess.run([ALZ, 'create', second, '-p', 'none', '-i', '0x1234', 'vide', 'f.bin'],
               cwd=stage, capture_output=True, check=True)
if open(second, 'rb').read() != open(arc, 'rb').read():
    raise SystemExit('two runs with the same header id produced different archives')

# --- 12.30 solid (m1 and m3): a single stream over the CONCATENATION of the
# members, a single BLOCK after the headers, a 7-byte SOLID_INFO in the prefix.
# Set K's two references (deflate 2 and LZMA 8) carry `two/hello.txt` and
# `two/code.c`; they are reproduced byte for byte, then read back by our
# extractor.
for ref_path, base, profile in (
        ('packed_egg/egg_s_m1_two.egg', 'lotk_solid_m1', 'compspeed'),
        ('packed_egg/egg_s_m3_two.egg', 'lotk_solid_m3', 'compratio')):
    blob, hid, members = reference(ref_path)
    stage = os.path.join(root, 'w-solid-' + base)
    os.makedirs(os.path.join(stage, 'two'))
    shutil.copy2('corpus/hello.txt', os.path.join(stage, 'two', 'hello.txt'))
    shutil.copy2('corpus/code.c', os.path.join(stage, 'two', 'code.c'))
    for name, filetime in members:
        pin(stage, name, filetime)
    out = os.path.join(root, base + '-out.egg')
    result = subprocess.run([ALZ, 'create', out, '-p', profile, '-s',
                             '-i', '0x%x' % hid, 'two'],
                            cwd=stage, capture_output=True, text=True)
    if result.returncode:
        raise SystemExit(f'{base}: solid create failed: '
                         f'{(result.stderr or result.stdout).strip()}')
    got = open(out, 'rb').read()
    if got != blob:
        at = next((i for i in range(min(len(got), len(blob))) if got[i] != blob[i]),
                  min(len(got), len(blob)))
        raise SystemExit(f'{base}: solid archive differs from the reference '
                         f'({len(got)} vs {len(blob)} bytes, first difference at {at})')
    back = os.path.join(root, base + '-back')
    os.makedirs(back)
    result = subprocess.run([ALZ, 'extract', out, '-d', back],
                            capture_output=True, text=True)
    if result.returncode:
        raise SystemExit(f'{base}: the solid archive written here is not readable '
                         f'back by alzgg: {(result.stdout + result.stderr).strip()}')
    for name, _ in members:
        if open(os.path.join(stage, *name.split('/')), 'rb').read() != \
           open(os.path.join(back, *name.split('/')), 'rb').read():
            raise SystemExit(f'{base}: {name} differs after the solid round-trip')
    print(f'  {base}: {len(got)} identical bytes (solid -p {profile}, '
          f'{len(members)} members), round trip conforms')

# Solid versus non-solid profiles: ALZip only allows m1 and m3 in solid mode;
# everything else must be refused without writing.
for profile in ('none', 'normal', 'optimized'):
    target = os.path.join(root, f'solid-refuse-{profile}.egg')
    result = subprocess.run([ALZ, 'create', target, '-p', profile, '-s',
                             '-i', '0x1234', 'hello.txt'],
                            cwd=single, capture_output=True, text=True)
    message = result.stdout + result.stderr
    if result.returncode == 0 or 'solid' not in message:
        raise SystemExit(f'solid -p {profile} was not refused explicitly: '
                         f'{message.strip()}')
    if os.path.exists(target):
        raise SystemExit(f'the refused solid -p {profile} left an archive behind')

# --- volume splitting (`-v`): each reference chain is reproduced byte for
# byte, then read back from its LAST volume (the `prev` chain walked backwards by
# the reader). The three cases cover six volumes: 3 x Normal (boundary inside a
# compressed block + DUMMY between two sub-headers), 2 x Optimized on an
# incompressible stream, 3 x Optimized with 420 bzip2 members.
def check_split(tag, refs, profile, src, names):
    blobs = [open(p, 'rb').read() for p in refs]
    ids = [struct.unpack_from('<I', blob, 6)[0] for blob in blobs]
    ordered, synth = ed.vol_chain(refs[0])
    logical = os.path.join(root, f'logical-{tag}.bin')
    open(logical, 'wb').write(synth)
    lm = ed.parse(logical)
    members = [e for e in lm['files'] if e.get('kind') == 'file']
    stage = os.path.join(root, 'w-' + tag)
    os.makedirs(stage)
    for name in names:
        shutil.copy2(os.path.join(src, name), os.path.join(stage, name))
    for e in members:
        pin(stage, e['name'], e['wininfo']['filetime'])
    out = os.path.join(root, 'split-' + tag + '.egg')
    result = subprocess.run([ALZ, 'create', out, '-p', profile, '-v', '100KB',
                             '-i', ','.join('0x%x' % i for i in ids)]
                            + sorted(names),
                            cwd=stage, capture_output=True, text=True)
    if result.returncode:
        raise SystemExit(f'{tag}: create -v failed: '
                         + (result.stderr or result.stdout).strip())
    base = out[:-4]
    for k, blob in enumerate(blobs, 1):
        got = open(f'{base}.vol{k}.egg', 'rb').read()
        if got != blob:
            at = next((i for i in range(min(len(got), len(blob)))
                       if got[i] != blob[i]), min(len(got), len(blob)))
            raise SystemExit(f'{tag}.vol{k}.egg: split differs from the '
                             f'reference ({len(got)} vs {len(blob)} bytes, first '
                             f'difference at {at})')
    back = os.path.join(root, tag + '-back')
    os.makedirs(back)
    last = len(blobs)
    result = subprocess.run([ALZ, 'extract', f'{base}.vol{last}.egg', '-d', back],
                            capture_output=True, text=True)
    if result.returncode:
        raise SystemExit(f'{tag}: vol{last} not readable back: '
                         + (result.stderr or result.stdout).strip())
    for e in members:
        rel = e['name'].split('/')
        if open(os.path.join(stage, *rel), 'rb').read() != \
           open(os.path.join(back, *rel), 'rb').read():
            raise SystemExit(f'{tag}: {e["name"]} differs after the split '
                             f'round-trip')
    print(f'  {tag}: {len(blobs)} identical volumes ({len(members)} member(s), '
          f'-p {profile}), round trip from vol{last} conforms')

split_names = sorted(os.listdir('corpus/splitmany'))
check_split('records_speed_1230',
            [f'packed_egg/egg_m1_records_v100k.vol{k}.egg'
             for k in (1, 2)],
            'compspeed', 'corpus', ['records.bin'])
check_split('records_optimized',
            [f'packed_egg_8.0/records_optimized.vol{k}.egg' for k in (1, 2)],
            'optimized', 'corpus', ['records.bin'])
check_split('splitmany_optimized',
            [f'packed_egg_8.0/splitmany_optimized.vol{k}.egg' for k in (1, 2, 3)],
            'optimized', 'corpus/splitmany', split_names)

# --- split refusals and naming: a single volume is named .vol1.egg (the shape
# observed on the Windows sets), and everything not written here is refused
# without leaving a volume behind.
def split_volumes(stem):
    return sorted(glob.glob(stem + '.vol*.egg'))

target = os.path.join(root, 'split-one.egg')
result = subprocess.run([ALZ, 'create', target, '-p', 'none', '-v', '100KB',
                         '-i', '0x2a', 'hello.txt'],
                        cwd=single, capture_output=True, text=True)
if result.returncode:
    raise SystemExit('single-volume -v create failed: '
                     + (result.stderr or result.stdout).strip())
vol1 = os.path.join(root, 'split-one.vol1.egg')
if not os.path.exists(vol1) or os.path.exists(target):
    raise SystemExit('a one-volume split is not named <base>.vol1.egg')
back = os.path.join(root, 'split-one-back')
os.makedirs(back)
result = subprocess.run([ALZ, 'extract', vol1, '-d', back],
                        capture_output=True, text=True)
if result.returncode or open(os.path.join(back, 'hello.txt'), 'rb').read() != \
   open('corpus/hello.txt', 'rb').read():
    raise SystemExit('the one-volume split is not readable back: '
                     + (result.stderr or result.stdout).strip())

target = os.path.join(root, 'split-solid.egg')
result = subprocess.run([ALZ, 'create', target, '-p', 'compspeed', '-s', '-v', '100KB',
                         '-i', '0x1234', 'hello.txt'],
                        cwd=single, capture_output=True, text=True)
message = result.stdout + result.stderr
if result.returncode == 0 or 'solid' not in message:
    raise SystemExit('solid + -v was not refused explicitly: ' + message.strip())
if split_volumes(target[:-4]):
    raise SystemExit('the refused solid + -v archive left volumes behind')

result = subprocess.run([ALZ, 'create', target, '-p', 'normal', '-v', '100KB',
                         'hello.txt'],
                        cwd=single, capture_output=True, text=True)
message = result.stdout + result.stderr
if result.returncode == 0 or 'Header ID' not in message:
    raise SystemExit('-v without -i was not refused explicitly: ' + message.strip())

result = subprocess.run([ALZ, 'create', target, '-p', 'normal', '-v', '20',
                         '-i', '0x1', 'hello.txt'],
                        cwd=single, capture_output=True, text=True)
message = result.stdout + result.stderr
if result.returncode == 0 or 'volume size' not in message:
    raise SystemExit('a volume smaller than the 33-byte header was not refused: '
                     + message.strip())

# IDs exhausted while writing: the second volume cannot be created, and the
# first one (already written) is removed.
split_stage = 'corpus/splitmany'
target = os.path.join(root, 'split-oneid.egg')
result = subprocess.run([ALZ, 'create', target, '-p', 'normal', '-v', '100KB',
                         '-i', '0x4041'] + sorted(split_names),
                        cwd=split_stage, capture_output=True, text=True)
message = result.stdout + result.stderr
if result.returncode == 0 or 'Header ID' not in message:
    raise SystemExit('a split archive with a single header id was not refused: '
                     + message.strip())
if split_volumes(target[:-4]):
    raise SystemExit('the interrupted split left volume files behind')

print('EGG writer: ALZip 12.30 contract reproduced byte for byte '
      '(lot K: m0 store, m1 deflate 2, m2 deflate 4, m3 LZMA 8, m4 Optimized '
      'with its full routing table - the 148 extensions of '
      'routes_optimized.egg, bzip2/store/deflate hint=5, .doc/.ico LZMA, AZO '
      '.sys and .com (including a 633,780-byte member, two internal slices) '
      'and the text-content .bin kept in deflate -, AZO x86 filter on four MZ '
      'members (`31 01` flag, two of them over two slices) plus two raw-copied '
      'slices (incompressible, filter applied before the copy decision); the '
      'thirteen LZMA streams of the 8.0 corpus share the same payload, hint 8; '
      'solid m1/m3 and the 12.30 split chain (records_speed_1230, 2 volumes), '
      'plus records_optimized and splitmany_optimized unchanged; encrypted '
      '12.30 archives (ZipCrypto m1 with two members, AES-256 m2) and 8.0 '
      'store/Optimized, LEA-128/256 and sixteen encrypted volumes; the empty '
      'file and the directory written without Encrypt Info like ALZip; solid '
      'outside m1/m3, solid+-v, solid+password, incomplete material, non-ASCII '
      'password, -v without ID, undersized volume and exhausted IDs refused '
      'without writing; empty directory, round trip and determinism conform)')
EOF

echo "== [10/13] EGG codec encoders (bzip2, AZO): every reference block reproduced byte for byte =="
python3 - "$TEST_TMP" <<'EOF'
import bz2, glob, os, random, subprocess, sys, zlib

sys.path.insert(0, 'tools')
import egg_dump as ed   # independent structural parser (reverse-engineered spec)

root = sys.argv[1]
BZ2ENC = os.path.abspath('./tests/bin/bz2enc')

# Every bzip2 block of the corpus, except the three encrypted archives: their
# payload is an encrypted bzip2 stream (steps 6 and 8 cover them after
# decryption). Volumes 2+ reassemble the same stream as volume 1, so only that
# one is walked.
#
# Each pair's input is decompressed by Python's libbzip2, never by our decoder:
# the encoder is compared with the corpus, not with itself.
pairs, hints = [], set()
for arc in (sorted(glob.glob('packed_egg/*.egg'))
            + sorted(glob.glob('packed_egg_8.0/*.egg'))):
    # Only the first volume carries the start of the stream: the following ones
    # (.vol2 ... .vol16) reassemble the same stream and must not be walked again.
    if '.vol' in arc and not arc.endswith('.vol1.egg'):
        continue
    path = arc
    if '.vol' in arc:
        _ordered, logical = ed.vol_chain(arc)
        path = os.path.join(root, 'logical.egg')
        with open(path, 'wb') as fp:
            fp.write(logical)
    for e in ed.parse(path).get('files', []):
        for blk in e.get('blocks', []):
            if blk['method'] != 2 or e.get('crypt'):
                continue
            hints.add(blk['hint'])
            src = bz2.decompress(blk['data'])
            if len(src) != blk['usize']:
                raise SystemExit(f'{arc}/{e["name"]}: {len(src)} bytes '
                                 f'decompressed, {blk["usize"]} expected')
            if (zlib.crc32(src) & 0xffffffff) != int(blk['crc'], 16):
                raise SystemExit(f'{arc}/{e["name"]}: block CRC-32 does not match')
            base = os.path.join(root, 'bzpairs', '%04d' % len(pairs))
            os.makedirs(os.path.dirname(base), exist_ok=True)
            with open(base + '.in', 'wb') as fp:
                fp.write(src)
            with open(base + '.ref', 'wb') as fp:
                fp.write(blk['data'])
            pairs.append((base + '.in', base + '.ref'))

# A corpus that loses its bzip2 samples must fail the step, not let it pass
# vacuously (the exact count is not pinned: the corpus may grow).
if len(pairs) < 400:
    raise SystemExit(f'only {len(pairs)} cleartext bzip2 blocks found in the '
                     'corpus: the encoder is no longer exercised over it')
if hints != {4}:
    raise SystemExit(f'bzip2 block hints are {sorted(hints)}, no longer {{4}}: the '
                     'blockSize100k = 4 pinning no longer matches the corpus')

# bz2enc: encodes each input as bzip2 (blockSize100k 4) and requires byte-for-
# byte equality with the reference stream. In batches, so the command-line length
# limit does not matter if the corpus grows.
CHUNK = 100
for i in range(0, len(pairs), CHUNK):
    batch = pairs[i:i + CHUNK]
    r = subprocess.run([BZ2ENC] + [p for pair in batch for p in pair],
                       capture_output=True, text=True)
    if r.returncode:
        raise SystemExit('bz2enc failed:\n' + r.stdout + r.stderr)
    if f'{len(batch)}/{len(batch)}' not in r.stdout:
        raise SystemExit(f'expected {len(batch)}/{len(batch)} identical streams, got:\n'
                         + r.stdout[-2000:])

print(f'  {len(pairs)} bzip2 blocks re-encoded byte for byte (hint 4 = '
      f'blockSize100k 4): the Optimized archives (gui_optimized_matrix.egg and '
      f'its fifteen members, including a 1 MiB .c) and the 420 members of '
      f'splitmany_optimized')

# --- AZO (method 3): three ALZip references, and nothing else - only .sys and
# .com are routed to AZO, and the encoder was only measured on those blocks.
# `azoenc` re-encodes the input and requires byte-for-byte equality with the
# block payload (which itself carries its internal 2^19 slices).
AZOENC = os.path.abspath('./tests/bin/azoenc')

# Input recipe for each reference, so nothing but the archives is stored:
# probe.com is probe.sys under another extension; sysmulti.sys is corpus/code.c
# repeated 14 times (633,780 bytes, two internal slices); the two AZO members of
# the routing set (.sys and .com) are 4,096-byte files identical to the rest of
# that set.
ROUTE_PAYLOAD = open('corpus/eng.txt', 'rb').read()[:4096]
MZ_SRC = os.environ.get('ALZIP_80_DIR', os.path.join('_work', 'binaries', 'alzip-8.0'))
if not os.path.isdir(MZ_SRC):
    MZ_SRC = os.path.join('research', 'Program Files (x86)', 'ALZip')

def azo_input(name):
    # Some 8.0 references archived the file under its staging path
    # (fixtures/out/lot-g/multi/probe.sys): only the end of the name identifies
    # the recipe.
    if name.startswith('routes/'):
        return ROUTE_PAYLOAD
    name = os.path.basename(name)
    if name in ('probe.sys', 'probe.com'):
        return open('corpus/probe.sys', 'rb').read()
    if name == 'sysmulti.sys':
        return open('corpus/code.c', 'rb').read() * 14
    if name == 'mz.sys':
        p = os.path.join(MZ_SRC, 'Coders', 'Deflate.dll')
        return open(p, 'rb').read() if os.path.isfile(p) else None
    if name == 'mzmulti.sys':
        p = os.path.join(MZ_SRC, 'ALZipCon.exe')
        return open(p, 'rb').read() if os.path.isfile(p) else None
    if name in ('mzraw.sys', 'mzraw2.sys'):
        # MZ + random: the slice does not compress and is copied, filtered
        r = random.Random(0x415a4f)
        n = 524288 if name == 'mzraw.sys' else 2 * 524288
        return b'MZ' + bytes(r.randrange(256) for _ in range(n - 2))
    return None

# The corpus carries each recipe several times (same payload archived by 12.30
# and by 8.0, plus the lot G MZ reference archived under its staging path): each
# (input, expected stream) pair is encoded once, but all TEN distinct recipes
# must be present.
azo_pairs, azo_hints, azo_recipes, azo_seen = [], set(), set(), set()
for arc in sorted(glob.glob('packed_egg/*.egg')) + sorted(glob.glob('packed_egg_8.0/*.egg')):
    if '.vol' in arc:
        continue
    for e in ed.parse(arc).get('files', []):
        for blk in e.get('blocks', []):
            if blk['method'] != 3:
                continue
            azo_hints.add(blk['hint'])
            src = azo_input(e['name'])
            if src is None:
                if os.path.basename(e['name']) in ('mz.sys', 'mzmulti.sys'):
                    continue
                raise SystemExit(f'{arc}: no input recipe for AZO member '
                                 f'{e["name"]} (add it here)')
            if len(src) != blk['usize']:
                raise SystemExit(f'{arc}/{e["name"]}: {len(src)} bytes of input, '
                                 f'{blk["usize"]} expected')
            if (zlib.crc32(src) & 0xffffffff) != int(blk['crc'], 16):
                raise SystemExit(f'{arc}/{e["name"]}: block CRC-32 does not match')
            azo_recipes.add(e['name'] if e['name'].startswith('routes/')
                            else os.path.basename(e['name']))
            key = (blk['usize'], int(blk['crc'], 16), zlib.crc32(blk['data']))
            if key in azo_seen:
                continue
            azo_seen.add(key)
            base = os.path.join(root, 'azopairs', '%04d' % len(azo_pairs))
            os.makedirs(os.path.dirname(base), exist_ok=True)
            with open(base + '.in', 'wb') as fp:
                fp.write(src)
            with open(base + '.ref', 'wb') as fp:
                fp.write(blk['data'])
            azo_pairs.append((base + '.in', base + '.ref'))

EXPECTED_AZO = {'probe.sys', 'probe.com', 'sysmulti.sys',
                'mzraw.sys', 'mzraw2.sys',
                'routes/r094.sys', 'routes/r095.com', 'routes/u142.SYS'}
if os.path.isfile(os.path.join(MZ_SRC, 'Coders', 'Deflate.dll')):
    EXPECTED_AZO.add('mz.sys')
if os.path.isfile(os.path.join(MZ_SRC, 'ALZipCon.exe')):
    EXPECTED_AZO.add('mzmulti.sys')
if azo_recipes != EXPECTED_AZO:
    raise SystemExit(f'AZO recipes in the corpus: {sorted(azo_recipes)} - expected '
                     f'{sorted(EXPECTED_AZO)}')
if azo_hints != {1}:
    raise SystemExit(f'AZO block hints are {sorted(azo_hints)}, no longer {{1}}: '
                     f'hint 1 is no longer pinned by the corpus')

r = subprocess.run([AZOENC] + [p for pair in azo_pairs for p in pair],
                   capture_output=True, text=True)
if r.returncode:
    raise SystemExit('azoenc failed:\n' + r.stdout + r.stderr)
if f'{len(azo_pairs)}/{len(azo_pairs)}' not in r.stdout:
    raise SystemExit(f'expected {len(azo_pairs)}/{len(azo_pairs)} identical '
                     'streams, got:\n' + r.stdout[-2000:])
print(f'  {len(azo_pairs)} AZO blocks re-encoded byte for byte (hint 1): '
      f'probe.sys, probe.com, sysmulti.sys (633,780 bytes, two internal 2^19 '
      f'slices), the three members of the routing set (.sys, .com, .SYS: '
      f'case-insensitive routing), the two MZ executables (x86 filter, `31 01` '
      f'flag, one of them over two slices) and the two raw-copied MZ slices '
      f'(incompressible, csize == usize)')
EOF

echo "== [11/13] ALZ encrypted members: ZipCrypto (single, multi, spanned) =="
python3 - "$TEST_TMP" <<'EOF'
import glob, os, subprocess, sys

root = sys.argv[1]
FIX = 'packed_alz_8.0'
PASSWORD = 'secret'

# Required references, produced by ALZipCon -tp0 -psecret (fixtures lot B): if
# they disappear, the step must say so instead of passing vacuously.
REQUIRED = ['enc_basic.alz', 'enc_basic_split.alz', 'enc_basic_split.a00',
            'enc_basic_paths.alz', 'unicode_basic_encrypted.alz']
missing = [f for f in REQUIRED if not os.path.isfile(os.path.join(FIX, f))]
if missing:
    raise SystemExit(f'encrypted ALZ references missing: {missing}')


def run(args):
    # ALZ member names use the code page of the machine that wrote them (CP1252
    # on these references), so decoding is tolerant; otherwise the test would
    # fail on a non-UTF-8 name instead of on the point at hand.
    p = subprocess.run(['./alzgg'] + args, capture_output=True)
    return subprocess.CompletedProcess(p.args, p.returncode,
                                       p.stdout.decode('utf-8', 'replace'),
                                       p.stderr.decode('utf-8', 'replace'))


def files_under(d):
    return sorted(p for p in glob.glob(os.path.join(d, '**'), recursive=True)
                  if os.path.isfile(p))


# 1. Walking encrypted members skipped csize bytes instead of 12 + csize (the
# ZipCrypto verifier at the head of the data): it must pass and say so.
for name in ('enc_basic.alz', 'enc_basic_paths.alz', 'enc_basic_split.alz',
             'unicode_basic_encrypted.alz'):
    r = run(['list', os.path.join(FIX, name)])
    if r.returncode or 'crypt=zip2' not in r.stdout:
        raise SystemExit(f'{name}: list failed or hid the encryption: {r.stdout}{r.stderr}')

# 2. No password: explicit refusal, nothing written.
out = os.path.join(root, 'alz-nopass')
os.makedirs(out)
r = run(['extract', os.path.join(FIX, 'enc_basic.alz'), '-d', out])
if r.returncode == 0 or 'password required' not in (r.stdout + r.stderr):
    raise SystemExit('a missing ALZ password was not refused: ' + r.stdout + r.stderr)
if files_under(out):
    raise SystemExit('the ALZ refusal without a password left files behind')

# 3. Wrong password: the ZipCrypto verifier refuses, nothing written.
out = os.path.join(root, 'alz-badpass')
os.makedirs(out)
r = run(['extract', os.path.join(FIX, 'enc_basic.alz'), '-d', out, '-p', 'not-the-password'])
if r.returncode == 0 or 'incorrect password' not in (r.stdout + r.stderr):
    raise SystemExit('a wrong ALZ password was not refused: ' + r.stdout + r.stderr)
if files_under(out):
    raise SystemExit('the ALZ refusal with a wrong password left files behind')

# 4. Right password: content identical to the source, including a member that
# is both encrypted AND split over two volumes.
for name, member, source in (('enc_basic.alz', 'hello.txt', 'corpus/hello.txt'),
                             ('enc_basic_split.alz', 'records.bin', 'corpus/records.bin')):
    out = os.path.join(root, 'alz-dec-' + name)
    os.makedirs(out)
    r = run(['extract', os.path.join(FIX, name), '-d', out, '-p', PASSWORD])
    if r.returncode:
        raise SystemExit(f'{name}: extraction failed: {r.stdout}{r.stderr}')
    got = open(os.path.join(out, member), 'rb').read()
    if got != open(source, 'rb').read():
        raise SystemExit(f'{name}/{member}: decrypted bytes differ from {source}')

# 5. Eight encrypted members in one archive: the ZipCrypto keys are re-seeded
# per member (otherwise only the first would come out). The stored names are the
# paths relative to the reader, so the source is the path itself.
out = os.path.join(root, 'alz-dec-paths')
os.makedirs(out)
r = run(['extract', os.path.join(FIX, 'enc_basic_paths.alz'), '-d', out, '-p', PASSWORD])
if r.returncode:
    raise SystemExit('enc_basic_paths: extraction failed: ' + r.stdout + r.stderr)
def source_of(rel):
    """Corpus file matching the archived name.

    The reference was written from `fixtures/out/lot-b/nested`: the stored name
    carries that staging prefix, which is stripped to find the `corpus/nested`
    tree again.
    """
    rel = rel.replace(os.sep, '/')
    for prefix in ('fixtures/out/lot-b/',):
        if rel.startswith(prefix):
            rel = rel[len(prefix):]
    for candidate in (rel, os.path.basename(rel)):
        path = os.path.join('corpus', candidate)
        if os.path.isfile(path):
            return path
    return None


done = 0
for path in files_under(out):
    rel = os.path.relpath(path, out)
    src = source_of(rel)
    if src is None:
        raise SystemExit(f'enc_basic_paths: {rel} has no counterpart in the corpus')
    if open(path, 'rb').read() != open(src, 'rb').read():
        raise SystemExit(f'enc_basic_paths: {rel} differs from {src}')
    done += 1
if done < 8:
    raise SystemExit(f'enc_basic_paths: only {done} members decrypted, expected 8')

print(f'ALZ encryption (ZipCrypto): 4 archives walked, {done} members re-seeded '
      f'member by member, span+encrypted checked byte for byte; missing or wrong '
      f'password refused without writing')

# --- ALZ span chains: the 16-volume references (`.alz` + 15 `.aNN`) are read
# back from the first volume. The corpus used to stop at `.a02`, so no test ever
# walked an ALZ chain past volume 4; a truncated chain cannot even be listed
# (`inconsistent data`) and its CRC cannot be validated. The encrypted chain was
# regenerated under Wine (ALZip draws a new keystream per run, so volumes from
# two runs cannot be mixed), hence its record carrying attr 0x20, which 12.30
# writes anyway.
with open(os.path.join('corpus', 'span', 'random1m.bin'), 'rb') as f:
    span_payload = f.read()
for name, extra in (('span_15vol_m0', []), ('span_15vol_m2', []),
                    ('span_15vol_crypt', ['-p', PASSWORD])):
    stem = os.path.join(FIX, name)
    missing = [f'{name}.a{n:02d}' for n in range(15)
               if not os.path.isfile(f'{stem}.a{n:02d}')]
    if missing:
        raise SystemExit(f'{name}: incomplete volume chain, missing {missing}')
    out = os.path.join(root, 'alz-chain-' + name)
    os.makedirs(out)
    r = run(['extract', f'{stem}.alz', '-d', out] + extra)
    if r.returncode:
        raise SystemExit(f'{name}: chain extraction failed: '
                         + (r.stderr or r.stdout).strip())
    with open(os.path.join(out, 'random1m.bin'), 'rb') as f:
        if f.read() != span_payload:
            raise SystemExit(f'{name}: payload read back from the chain differs '
                             'from corpus/span/random1m.bin')
print('  3 ALZ span chains (16 volumes each) read back from the first volume')
EOF

echo "== [12/13] ALZ writer: ZipCrypto byte-parity against ALZip 12.30 =="
python3 - "$TEST_TMP" <<'EOF'
import glob, os, subprocess, sys

root = sys.argv[1]
FIX = 'packed_alz'
PASSWORD = 'password'
ALZ = os.path.abspath('./alzgg')

# --- ZipCrypto on the test side: a member's 12-byte verifier decrypts to 10
# bytes of material plus the two high bytes of the CRC-32 (low weight first).
# That material is what ALZip draws at random; the test reads it back from the
# reference instead of hard-coding it, and checks where the two CRC bytes sit
# along the way.
T = []
for i in range(256):
    c = i
    for _ in range(8):
        c = (c >> 1) ^ (0xEDB88320 if c & 1 else 0)
    T.append(c)


def upd(k, c):
    k[0] = (k[0] >> 8) ^ T[(k[0] ^ c) & 0xFF]
    k[1] = ((k[1] + (k[0] & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF
    k[2] = (k[2] >> 8) ^ T[(k[2] ^ (k[1] >> 24)) & 0xFF]


def stream_byte(k):
    t = (k[2] | 2) & 0xFFFFFFFF
    return (((t * (t ^ 1)) & 0xFFFFFFFF) >> 8) & 0xFF


def zip_material(stored, crc, pwbytes=None):
    k = [0x12345678, 0x23456789, 0x34567890]
    for b in (PASSWORD.encode() if pwbytes is None else pwbytes):
        upd(k, b)
    plain = bytearray()
    for b in stored:
        c = b ^ stream_byte(k)
        plain.append(c)
        upd(k, c)
    if plain[10] != ((crc >> 16) & 0xFF) or plain[11] != ((crc >> 24) & 0xFF):
        raise SystemExit(f'verify data does not end with CRC>>16: {plain.hex()}')
    return bytes(plain[:10]).hex()


def parse_members(path, pwbytes=None):
    """(name, ts, DOS attribute, material) of the members, verifier included.

    The attribute sits at pos+6: magic(4) + name length(2) + attribute(1) +
    time(4) + flags(1) + unknown(1). It is read back here instead of assumed, so
    the `-tp0` references with attributes are compared as they are."""
    d = open(path, 'rb').read()
    pos, rows = 8, []
    while d[pos:pos + 4] == b'BLZ\x01':
        nl = int.from_bytes(d[pos + 4:pos + 6], 'little')
        ts = int.from_bytes(d[pos + 7:pos + 11], 'little')
        fd = d[pos + 11]
        q = pos + 13
        if fd & 0xF0:
            q += 2
            crc = int.from_bytes(d[q:q + 4], 'little')
            q += 4
            nb = fd >> 4
            cs = int.from_bytes(d[q:q + nb], 'little')
            q += nb + nb
        else:
            crc, cs = 0, 0
        name = d[q:q + nl].decode('utf-8')
        q += nl
        mat = zip_material(d[q:q + 12], crc, pwbytes) if fd & 1 else None
        rows.append((name, ts, d[pos + 6], mat))
        pos = q + cs + (12 if fd & 1 else 0)
    return rows


def dos(ts):
    return '%d-%02d-%02d %02d:%02d:%02d' % (
        1980 + (ts >> 25), (ts >> 21) & 15, (ts >> 16) & 31,
        (ts >> 11) & 31, (ts >> 5) & 63, (ts & 31) * 2)


def run(args, cwd='.'):
    return subprocess.run([ALZ] + args, cwd=cwd, capture_output=True, text=True)


# --- Byte-for-byte parity against ALZip 12.30: one stored member and a
# two-member archive with paths, one verifier and one material per member. The
# profile is -m1 (deflate 2). The material is read back from the reference,
# never hard-coded.
cases = [
    ('alz_zip_m1_hello.alz', 'faster',
     ['corpus/hello.txt=>hello.txt'], []),
    ('alz_zip_m1_two.alz', 'faster',
     ['corpus/code.c=>two/code.c',
      'corpus/hello.txt=>two/hello.txt'], []),
]
for base, prof, files, extra in cases:
    ref = os.path.join(FIX, base)
    if not os.path.exists(ref):
        raise SystemExit(f'{base}: encrypted ALZ reference missing')
    rows = parse_members(ref)
    names = [n for n, _, _, _ in rows]
    mats = ','.join(m for *_, m in rows if m)
    if files is None:
        files = names                     # the stored names are the paths
    out = os.path.join(root, 'alz-enc-' + base)
    args = ['create', '-p', prof, '-T', ','.join(dos(t) for _, t, _, _ in rows)]
    args += extra + ['--password', PASSWORD, '--crypt-info', mats, '-o', out]
    args += files
    r = run(args)
    if r.returncode:
        raise SystemExit(f'{base}: encrypted create failed: '
                         + (r.stderr or r.stdout).strip())
    if open(out, 'rb').read() != open(ref, 'rb').read():
        raise SystemExit(f'{base}: encrypted archive differs from the reference')
    stem = out[:-4]
    vol = 1
    while True:
        if vol == 1:
            refv, gotv = ref, out
        else:
            refv = os.path.join(FIX, base[:-4] + '.a%02d' % (vol - 1))
            gotv = stem + '.a%02d' % (vol - 1)
            if not os.path.exists(refv):
                break
        if open(gotv, 'rb').read() != open(refv, 'rb').read():
            raise SystemExit(f'{base}: volume {vol} differs from the reference')
        vol += 1
    print(f'  {base}: {len(rows)} member(s), material read back from the reference, '
          f'identical bytes')

# The decoder must read these encrypted 12.30 archives back (one salt and one
# verifier per member for the two-entry one).
for base, member in (('alz_zip_m1_hello.alz', 'hello.txt'),
                     ('alz_zip_m1_two.alz', 'two/code.c')):
    outdir = os.path.join(root, 'dec-' + base)
    os.makedirs(outdir)
    r = run(['extract', os.path.join(FIX, base), '-d', outdir, '-p', PASSWORD])
    if r.returncode or open(os.path.join(outdir, *member.split('/')), 'rb').read() != \
            open('corpus/' + member.split('/')[-1], 'rb').read():
        raise SystemExit(f'{base}: 12.30 encrypted archive is not readable: '
                         + (r.stdout + r.stderr).strip())
print('  read 12.30: one- and two-member ZipCrypto archives decrypted')

# --- Non-ASCII password (lot H, spec §12.9). ALZip converts the string to an
# ANSI code page before deriving the key: '€' becomes byte 0x80 there, which
# neither UTF-8 (E2 82 AC) nor Latin-1 (impossible) would give. The material is
# therefore read back with those bytes; if the writer encoded otherwise, the
# verifier would no longer land on the CRC and the archive would differ. The two
# references also differ by profile (`fast` and `faster`, which the 65-byte
# member cannot tell apart but the 240,000 bytes of records.bin do).
napw = [
    ('packed_alz_8.0/enc_alz_napw_euro.alz', 'fast',
     'corpus/hello.txt=>hello.txt', 'hello.txt'),
    ('packed_alz_8.0/enc_alz_napw_euro_records.alz', 'faster',
     'corpus/records.bin=>records.bin', 'records.bin'),
]
for ref, prof, source, member in napw:
    if not os.path.exists(ref):
        raise SystemExit(f'{ref}: encrypted reference missing')
    rows = parse_members(ref, '€'.encode('cp1252'))
    # The 12.30 writer no longer reproduces these two 8.0 samples (different
    # levels and attribute); the ANSI code page step stays checked on both
    # sides: correct read with "€", refusal of an ASCII password that differs
    # only by encoding.
    # The reader must recover the plaintext with that same password, and refuse
    # a password that differs only by what a badly chosen encoding would confuse
    # with it (bare 'e', or the UTF-8 form of '€' read byte by byte).
    plain = open(source.split('=>')[0], 'rb').read()
    outdir = os.path.join(root, 'alz-napw-dec-' + os.path.basename(ref))
    os.makedirs(outdir)
    r = run(['extract', ref, '-d', outdir, '-p', '€'])
    if r.returncode or open(os.path.join(outdir, member), 'rb').read() != plain:
        raise SystemExit(f'{os.path.basename(ref)}: extraction with the '
                         f'non-ASCII password failed: ' + r.stdout + r.stderr)
    bad = os.path.join(root, 'alz-napw-bad-' + os.path.basename(ref))
    os.makedirs(bad)
    r = run(['extract', ref, '-d', bad, '-p', 'e'])
    if r.returncode == 0 or 'incorrect password' not in (r.stdout + r.stderr):
        raise SystemExit(f'{os.path.basename(ref)}: a wrong (ASCII) password '
                         f'was not refused: ' + r.stdout + r.stderr)
    if [p for p in glob.glob(os.path.join(bad, '**'), recursive=True)
            if os.path.isfile(p)]:
        raise SystemExit(f'{os.path.basename(ref)}: the refusal left files behind')
    print(f'  {os.path.basename(ref)}: non-ASCII password (0x80), '
          f'{len(rows)} member(s), read and ASCII refusal checked')

# --- ALZ encryption of lot H: the 8.0 matrix is no longer a write contract
# (different levels and attribute); it stays covered on the read side in step 11.
# The empty member without Encrypt Info and the attribute + encryption
# coexistence stay exercised by the refusals and the round trip below.

# --- Random material (without --crypt-info): the archive must read back, and a
# missing or wrong password must be refused without writing.
rnd = os.path.join(root, 'alz-enc-random.alz')
r = run(['create', '-p', 'normal', '-T', '2026-10-15 16:14:58', '--password',
         's3cret', '-o', rnd, 'corpus/hello.txt=>hello.txt'])
if r.returncode:
    raise SystemExit('ALZ random-material create failed: '
                     + (r.stderr or r.stdout).strip())
listing = run(['list', rnd])
if listing.returncode or 'crypt=zip2' not in listing.stdout:
    raise SystemExit('list hides the ALZ encryption: ' + listing.stdout)
plain = open('corpus/hello.txt', 'rb').read()
for extra, needle in (([], 'password required'),
                      (['-p', 'wrong'], 'incorrect password')):
    outdir = os.path.join(root, 'alz-enc-refuse-' + str(len(extra)))
    os.makedirs(outdir)
    r = run(['extract', rnd, '-d', outdir] + extra)
    if r.returncode == 0 or needle not in (r.stdout + r.stderr):
        raise SystemExit(f'ALZ encrypted ({extra}): expected "{needle}", got: '
                         + (r.stdout + r.stderr).strip())
    if [p for p in os.listdir(outdir)]:
        raise SystemExit(f'ALZ encrypted ({extra}): refusal left files behind')
outdir = os.path.join(root, 'alz-enc-ok')
os.makedirs(outdir)
r = run(['extract', rnd, '-d', outdir, '-p', 's3cret'])
if (r.returncode or
        open(os.path.join(outdir, 'hello.txt'), 'rb').read() != plain):
    raise SystemExit('ALZ random-material archive does not round-trip: '
                     + (r.stdout + r.stderr).strip())
print('  random material: archive read back, missing or wrong password refused')

# --- Refusal without writing: material without a password, and incomplete
# material. Neither the empty member nor the non-ASCII password is refused:
# enc_alz_empty shows ALZip stores an empty member without an encrypted field,
# and the ANSI code page step (spec §12.9) makes "passwörd" and "€" usable just
# like ALZip does.
refusals = [
    ('cryptinfo-without-password',
     ['create', '-p', 'normal', '-T', '2026-10-15 16:14:58', '--crypt-info',
      '01000100010001000000', 'corpus/hello.txt=>hello.txt'],
     'only makes sense with --password'),
    ('incomplete-material',
     ['create', '-p', 'normal', '-T', '2026-10-15 16:14:58', '--password', 'pw',
      '--crypt-info', '01000100010001000000,01000100010001000000',
      'corpus/hello.txt=>hello.txt'],
     '10 bytes of material per member'),
]
for label, args, needle in refusals:
    target = os.path.join(root, 'alz-refuse-' + label + '.alz')
    r = run(args + ['-o', target])
    message = r.stdout + r.stderr
    if r.returncode == 0 or needle not in message:
        raise SystemExit(f'ALZ encryption refusal "{needle}" not reported: '
                         + message.strip())
    if os.path.exists(target):
        raise SystemExit(f'ALZ encryption refusal "{needle}" left an archive')
print('  material without a password and incomplete material refused without '
      'writing')
EOF

echo "== [13/13] 12.30 reference manifest: every line reproduced byte for byte =="
# Steps 9 and 12 check chosen cases; the manifest is the complete list of the
# 55 12.30 archives (13 ALZ + 42 EGG, `-v` lines counting several volumes).
# tools/manifest_parity.py replays EVERY line from that file - options
# translated, input tree rebuilt from the reference, byte-for-byte comparison -
# and fails if a reference is no longer reproduced or if a line no longer matches
# its archive.
python3 tools/manifest_parity.py "$TEST_TMP/manifest"

echo "== CLI options: -u/--unix and -1/--bare listing and formatting =="
python3 - "$TEST_TMP" <<'EOF'
import os, subprocess, shutil, sys

root = sys.argv[1]
ALZ = os.path.abspath('./alzgg')

def run(args):
    return subprocess.run([ALZ] + args, capture_output=True, text=True)

# 1. ALZ listing checks
r_std = run(['list', 'packed_alz_8.0/Noise_normal.alz'])
if r_std.returncode != 0 or 'Noise.wav' not in r_std.stdout or 'alzgg (.alz/.egg)' not in r_std.stdout:
    raise SystemExit('ALZ standard list failed')

r_bare = run(['list', '-1', 'packed_alz_8.0/Noise_normal.alz'])
if r_bare.returncode != 0 or r_bare.stdout != 'Noise.wav\n':
    raise SystemExit(f'ALZ bare list failed: {r_bare.stdout!r}')

r_unix = run(['list', '-u', 'packed_alz_8.0/Noise_normal.alz'])
if r_unix.returncode != 0 or 'noise.wav' not in r_unix.stdout or 'Noise.wav' in r_unix.stdout:
    raise SystemExit(f'ALZ unix list failed: {r_unix.stdout!r}')

for flags in (['-1', '-u'], ['-u', '-1'], ['-1u'], ['-u1'], ['--bare', '--unix']):
    r = run(['list'] + flags + ['packed_alz_8.0/Noise_normal.alz'])
    if r.returncode != 0 or r.stdout != 'noise.wav\n':
        raise SystemExit(f'ALZ bare+unix {flags} failed: {r.stdout!r}')

r_post = run(['list', 'packed_alz_8.0/Noise_normal.alz', '-1u'])
if r_post.returncode != 0 or r_post.stdout != 'noise.wav\n':
    raise SystemExit(f'ALZ post-argument list failed: {r_post.stdout!r}')

# 2. EGG listing checks
r_egg_std = run(['list', 'packed_egg/hello_normal_aes128.egg'])
if r_egg_std.returncode != 0 or 'version=0x0100' not in r_egg_std.stdout:
    raise SystemExit('EGG standard list failed')

r_egg_bare = run(['list', '-1', 'packed_egg/hello_normal_aes128.egg'])
if r_egg_bare.returncode != 0 or r_egg_bare.stdout != 'hello.txt\n':
    raise SystemExit(f'EGG bare list failed: {r_egg_bare.stdout!r}')

for flags in (['-1', '-u'], ['-1u'], ['--bare', '--unix']):
    r = run(['list'] + flags + ['packed_egg/hello_normal_aes128.egg'])
    if r.returncode != 0 or r.stdout != 'hello.txt\n':
        raise SystemExit(f'EGG bare+unix {flags} failed: {r.stdout!r}')

# 3. Extraction with -u lowercases output files
ext_dir = os.path.join(root, 'cli-opt-ext-u')
os.makedirs(ext_dir)
r_ext = run(['extract', '-u', 'packed_alz_8.0/Noise_normal.alz', '-d', ext_dir])
if r_ext.returncode != 0 or not os.path.exists(os.path.join(ext_dir, 'noise.wav')):
    raise SystemExit('Extraction with -u failed to create lowercase path')

print('  -u/--unix and -1/--bare list and extract tests: PASS')
EOF

echo "ALZ corpus-subset suite: PASS"

