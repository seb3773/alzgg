#!/usr/bin/env python3
"""Compare the archives regenerated under Wine with their checked-in references.

`fixtures/build-fixtures.py` writes new 8.0 archives, but ALZip randomises the
Header ID (and the crypto material of an encrypted member), Wine adds
FILE_ATTRIBUTE_ARCHIVE to ALZ records, and the staging mtime differs between two
runs. A byte comparison therefore cannot be the acceptance test; this tool
compares what the format promises instead, member by member:

  * name (the staging prefix `fixtures/out/...` is ignored, the base name is the
    key), uncompressed size, CRC-32, container method / block hint, and the DOS
    attributes with the Wine-only 0x20 bit cleared.

EGG archives are parsed with `tools/egg_dump.py`, the independent structural
parser. ALZ archives are listed with `./alzgg` (the C reader): its `list` output
already follows the volume chain, so an `.alz` is compared as a whole and its
`.aNN` volumes are skipped here. Archives above 1 GiB (the `huge` group) are
skipped too: `make heavy` compares those; this tool is the cheap check for every
regenerated reference.

    tools/fixture_parity.py               # fixtures/out against packed_*_8.0
    tools/fixture_parity.py --out DIR     # another staging directory
"""
import argparse
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / 'tools'))
import egg_dump

REFERENCES = {'egg': REPO / 'packed_egg_8.0', 'alz': REPO / 'packed_alz_8.0'}
ALZ_LINE = re.compile(
    r'^(?P<name>.+?) meth=(?P<meth>\d+) csize=(?P<csize>\d+) '
    r'usize=(?P<usize>\d+) crc=(?P<crc>[0-9a-fA-F]+) fd=(?P<fd>[0-9a-fA-F]+) '
    r'attr=(?P<attr>[0-9a-fA-F]+)')


def egg_members(path):
    parsed = egg_dump.parse(str(path))
    return [{
        'name': entry['name'].replace('\\', '/'),
        'usize': entry['usize'],
        'attr': entry.get('attr', 0) & ~0x20,
        'blocks': [(block['method'], block.get('hint'), block['usize'],
                    block['crc']) for block in entry.get('blocks', [])],
    } for entry in parsed['files']]


def alz_members(path):
    result = subprocess.run([str(REPO / 'alzgg'), 'list', str(path)],
                            capture_output=True)
    if result.returncode:
        raise ValueError('alzgg list failed: '
                         + result.stderr.decode('utf-8', 'replace').strip())
    members = []
    # ALZ member names use the code page of the machine that wrote them (CP1252
    # here): decode tolerantly, the bytes are what matters for the comparison.
    for line in result.stdout.decode('utf-8', 'replace').splitlines():
        if not line.strip() or line.startswith(('END ', 'alzgg', '(based on', 'pure C', 'https://')):
            continue
        match = ALZ_LINE.match(line)
        if not match:
            raise ValueError(f'unparsed alz line: {line!r}')
        members.append({
            'name': match['name'].replace('\\', '/'),
            'usize': int(match['usize']),
            'crc': match['crc'].lower(),
            'method': int(match['meth']),
            'attr': int(match['attr'], 16) & ~0x20,
        })
    return members


def compare(reference, generated, kind):
    want = egg_members(reference) if kind == 'egg' else alz_members(reference)
    got = egg_members(generated) if kind == 'egg' else alz_members(generated)
    if len(want) != len(got):
        return f'member count {len(want)} -> {len(got)}'
    # Names carry the staging path, which depends on --out: key on the base name
    # plus the size (two members can share a base name in different trees).
    def keys(members):
        out = {}
        for member in members:
            key = (member['name'].rsplit('/', 1)[-1], member['usize'])
            out.setdefault(key, []).append(member)
        return out
    ref_keys, gen_keys = keys(want), keys(got)
    if set(ref_keys) != set(gen_keys):
        only_ref = sorted(set(ref_keys) - set(gen_keys))[:3]
        only_gen = sorted(set(gen_keys) - set(ref_keys))[:3]
        return f'members differ: only reference {only_ref}, only generated {only_gen}'
    for key, ref_members in ref_keys.items():
        ref, gen = ref_members[0], gen_keys[key][0]
        if kind == 'egg':
            if ref['blocks'] != gen['blocks']:
                return f'{key[0]}: blocks {ref["blocks"]} != {gen["blocks"]}'
        elif (ref['method'], ref['crc']) != (gen['method'], gen['crc']):
            return (f'{key[0]}: method/CRC {ref["method"]}/{ref["crc"]} != '
                    f'{gen["method"]}/{gen["crc"]}')
        if ref['attr'] != gen['attr']:
            return f'{key[0]}: attr {ref["attr"]:02x} != {gen["attr"]:02x}'
    return None


def main(argv=None):
    parser = argparse.ArgumentParser(
        description='Compare regenerated 8.0 fixtures with packed_*_8.0/.')
    parser.add_argument('--out', default='fixtures/out',
                        help='staging directory (default: fixtures/out)')
    parser.add_argument('--quiet', action='store_true',
                        help='print only differences and the summary')
    args = parser.parse_args(argv)
    staging = (REPO / args.out).resolve()
    if not staging.is_dir():
        raise SystemExit(f'no staging directory: {staging}')

    same = different = missing = skipped = 0
    for generated in sorted(staging.rglob('*')):
        if not generated.is_file() or generated.suffix not in ('.egg', '.alz'):
            continue
        # A volume is a fragment of the chain compared through its `.alz`.
        if '.vol' in generated.name or re.fullmatch(r'\.a\d+', generated.suffix):
            skipped += 1
            continue
        if generated.stat().st_size > (1 << 30):
            if not args.quiet:
                print(f'SKIP {generated.name}: above 1 GiB, make heavy covers it')
            skipped += 1
            continue
        kind = generated.suffix[1:]
        reference = REFERENCES[kind] / generated.name
        if not reference.exists():
            missing += 1
            print(f'MISSING {generated.name}: no reference in {REFERENCES[kind].name}/')
            continue
        try:
            problem = compare(reference, generated, kind)
        except (OSError, ValueError, KeyError, TypeError) as exc:
            problem = str(exc)
        if problem:
            different += 1
            print(f'DIFF {generated.name}: {problem}')
        else:
            same += 1
            if not args.quiet:
                print(f'identical: {generated.name}')

    print(f'\nidentical={same} different={different} missing_reference={missing} '
          f'skipped={skipped}')
    return 0 if different == 0 and missing == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
