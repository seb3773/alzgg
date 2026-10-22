#!/usr/bin/env python3
"""Survey of the bzip2 encoder parameters, on the reference EGG blocks.

For every method-2 (bzip2) block of the corpus — packed_egg/ and
corpus_probe/ — the payload is decompressed with the bz2 module (Python's
libbzip2, independent of this project) and recompressed at each blockSize100k
(the module's compresslevel) to see which one reproduces ALZip's stream byte for
byte. Blocks of the three encrypted archives are left aside: their payload is an
encrypted bzip2 stream, readable only after decryption (steps 6 and 8 of
tests/run_tests.sh take care of that).

The bz2 module does not set workFactor; src/bz2enc.c (the vendored 1.0.5
library) exhausts that parameter in the test suite.

Output: one summary per hint, and any differences. The script is read-only; it
serves as a trace of how the setting was established.
"""
import bz2
import glob
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import egg_dump as ed


def cleartext_blocks(path):
    """(name, hint, usize, payload) for each UNENCRYPTED bzip2 block."""
    tmp = None
    if '.vol' in path:
        _ordered, synth = ed.vol_chain(path)
        tmp = path + '.logical'
        with open(tmp, 'wb') as fp:
            fp.write(synth)
        path = tmp
    try:
        parsed = ed.parse(path)
    except Exception:
        return []
    finally:
        if tmp:
            os.unlink(tmp)
    out = []
    for entry in parsed.get('files', []):
        if entry.get('crypt'):
            continue
        for blk in entry.get('blocks', []):
            if blk['method'] == 2:
                out.append((entry['name'], blk['hint'], blk['usize'], blk['data']))
    return out


def matched_levels(src, payload):
    return [lvl for lvl in range(1, 10)
            if bz2.compress(src, compresslevel=lvl) == payload]


def main():
    archives = sorted(glob.glob('packed_egg/*.egg')) + \
               sorted(glob.glob('corpus_probe/*.egg'))
    total, skipped_vols, failures = 0, 0, []
    per_hint = {}
    for arc in archives:
        if arc.endswith(('.vol2.egg', '.vol3.egg')):
            skipped_vols += 1        # same stream as volume 1, reassembled by it
            continue
        for name, hint, usize, payload in cleartext_blocks(arc):
            total += 1
            per_hint.setdefault(hint, 0)
            per_hint[hint] += 1
            try:
                src = bz2.decompress(payload)
            except OSError as exc:
                failures.append(f'{arc} {name}: undecodable stream ({exc})')
                continue
            if len(src) != usize:
                failures.append(f'{arc} {name}: {len(src)} bytes, {usize} expected')
                continue
            levels = matched_levels(src, payload)
            if levels != [hint]:
                failures.append(f'{arc} {name}: exact blockSize100k {levels}, '
                                f'block hint {hint}')
    print(f'{total} plain bzip2 blocks, hints {per_hint}'
          f' ({skipped_vols} volume files ignored: they reassemble the '
          f'same stream)')
    if failures:
        print(f'{len(failures)} mismatches:')
        for f in failures[:20]:
            print('  FAIL', f)
        return 1
    print('each stream is reproduced by exactly one blockSize100k, the one of the '
          'hint du bloc')
    return 0


if __name__ == '__main__':
    sys.exit(main())
