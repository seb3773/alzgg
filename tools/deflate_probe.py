#!/usr/bin/env python3
"""Compare ALZip deflate streams with zlib compress at levels 1..9.

Usage: python3 tools/deflate_probe.py [packed_corpus/*.alz]
"""
import glob, os, struct, sys, zlib, collections

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import header_dump as hd

def logical_stream(path):
    """Concatenated data region across all volumes of `path`."""
    base = path[:-4]
    vblobs = []
    for vname in [path] + [f'{base}.a{i:02d}' for i in range(0, 999)]:
        if not os.path.exists(vname):
            break
        vblobs.append(open(vname, 'rb').read())
    out = bytearray()
    first = True
    for i, blob in enumerate(vblobs):
        a = 0 if first else 8
        out += blob[a:len(blob) - 16]
        first = False
    # NOTE: for vol0 the data region starts after the file headers; caller
    # must offset accordingly (hd.read_member_data is the precise tool).
    return bytes(out)

def matches(a, b):
    n = min(len(a), len(b))
    i = 0
    while i < n and a[i] == b[i]:
        i += 1
    return i

count = 0
for path in sorted(glob.glob('packed_corpus/*.alz')):
    (p, vol, entries), = hd.parse(path)
    if not isinstance(entries, list):
        continue
    for name, info in entries:
        if info is None or name in ('END',) or info.get('method') != 2:
            continue
        raw = hd.read_member_data(path, info['hdr_pos'])
        data = raw
        try:
            out = zlib.decompressobj(-15).decompress(data)
            crc_ok = ((zlib.crc32(out) & 0xffffffff) == (info['crc'] or 0)
                      and len(out) == (info['usize'] or 0))
        except Exception as e:
            print(f'{os.path.basename(path):28s} {name:20s} inflate ERROR {e}')
            continue
        hits = []
        for lvl in range(1, 10):
            for strat, sname in ((0, 'def'), (1, 'filt'), (2, 'huff'), (3, 'rle'), (4, 'fix')):
                c = zlib.compressobj(lvl, zlib.DEFLATED, -15, 7, strat)
                st = c.compress(out) + c.flush()
                m = matches(st, data)
                if m == len(data):
                    hits.append(f'EXACT lvl={lvl} {sname}')
                elif m >= 64:
                    hits.append(f'{m}/{len(data)} lvl={lvl} {sname}')
        verdict = '; '.join(hits) if hits else 'no zlib variant matches first 64+ bytes'
        count += 1
        print(f'{os.path.basename(path):28s} {name:20s} crc_ok={crc_ok} {verdict}')
print(f'--- {count} deflate members checked')
