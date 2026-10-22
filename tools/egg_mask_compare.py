#!/usr/bin/env python3
"""Compare a regenerated EGG archive with its checked-in reference.

ALZip randomises two things that a fresh oracle run cannot reproduce:

  * the 4-byte Header ID at file offset 6 (drawn per archive by ALZip, see
    FORMAT-EGG.md §2) ;
  * the encryption material of every member, which is its whole point.

The comparison therefore zeroes the Header ID and each Encrypt Info `data`
blob (found byte-for-byte, from tools/egg_dump.py's parse) in both archives and
then requires the rest to be identical. Member FILETIMEs are masked as well:
they record the *staging* mtime of the input, which a regeneration cannot
reproduce (the reference lot was staged from a different copy). Attributes,
block framing, codec hints and payloads are not masked.

The helper does not handle split volumes: a volume fragment is not a parseable
EGG stream, so tools/egg_dump.py refuses it. Regeneration scripts compare those
by extraction instead.

    egg_mask_compare.py REFERENCE.egg GENERATED.egg
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import egg_dump

HEADER_ID_OFFSET = 6
HEADER_ID_SIZE = 4


def randomised_blobs(path):
    """Random material and FILETIMEs, as they appear on disk."""
    blobs = []
    for entry in egg_dump.parse(path)['files']:
        crypt = entry.get('crypt')
        if crypt and crypt['data']:
            blobs.append(bytes.fromhex(crypt['data']))
        wininfo = entry.get('wininfo')
        if wininfo:
            blobs.append(wininfo['filetime'].to_bytes(8, 'little'))
    return blobs


def masked(path):
    with open(path, 'rb') as f:
        data = bytearray(f.read())
    if len(data) < HEADER_ID_OFFSET + HEADER_ID_SIZE:
        raise ValueError(f'{path}: too short for an EGG header')
    data[HEADER_ID_OFFSET:HEADER_ID_OFFSET + HEADER_ID_SIZE] = b'\0' * HEADER_ID_SIZE
    for needle in randomised_blobs(path):
        at = data.find(needle)
        while at >= 0:
            data[at:at + len(needle)] = b'\0' * len(needle)
            at = data.find(needle, at + len(needle))
    return data


def header_id_masked(path):
    """Isolated volume: Header ID + Split Info chain identifiers (which ALZip
    also draws); nothing else is random in a volume."""
    with open(path, 'rb') as f:
        data = bytearray(f.read())
    if len(data) < HEADER_ID_OFFSET + HEADER_ID_SIZE:
        raise ValueError(f'{path}: too short for an EGG header')
    data[HEADER_ID_OFFSET:HEADER_ID_OFFSET + HEADER_ID_SIZE] = b'\0' * HEADER_ID_SIZE
    split = data.find(egg_dump.SPLIT.to_bytes(4, 'little'), 0, 64)
    if split >= 0:
        _flags, size, start = egg_dump._ef(data, split + 4)
        if start + size <= len(data):
            data[start:start + size] = b'\0' * size
    return data


def main(argv):
    if len(argv) not in (3, 4) or (len(argv) == 4 and argv[1] != '--volume'):
        print('usage: egg_mask_compare.py [--volume] reference.egg generated.egg',
              file=sys.stderr)
        return 2
    if len(argv) == 4:
        mask = header_id_masked
        ref_path, gen_path = argv[2], argv[3]
    else:
        mask = masked
        ref_path, gen_path = argv[1], argv[2]
    try:
        ref = mask(ref_path)
        got = mask(gen_path)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f'EGG DIFF: {exc}', file=sys.stderr)
        return 1
    if len(ref) != len(got):
        print(f'EGG DIFF: {os.path.basename(ref_path)}: {len(got)} bytes '
              f'generated for {len(ref)} expected', file=sys.stderr)
        return 1
    for index, (a, b) in enumerate(zip(ref, got)):
        if a != b:
            print(f'EGG DIFF: {os.path.basename(ref_path)}: first difference '
                  f'at offset 0x{index:x} ({a:02x} != {b:02x})', file=sys.stderr)
            return 1
    print(f'IDENTICAL except Header ID, FILETIMEs and encryption material: '
          f'{os.path.basename(ref_path)}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv))
