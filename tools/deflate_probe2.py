#!/usr/bin/env python3
"""Grid-search zlib (windowBits 8..15, memLevel 1..9, levels, strategies)
against representative ALZip streams that failed the level-only probe."""
import os, sys, zlib
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import header_dump as hd

targets = [
    ('packed_corpus/Noise_fast.alz',        'Noise.wav'),
    ('packed_corpus/sound_fast.alz',        'sound.wav'),
    ('packed_corpus/records_fast.alz',      'records.bin'),
    ('packed_corpus/random_fast.alz',       'random.bin'),
    ('packed_corpus/image24_fast.alz',      'image24.raw'),
    ('packed_corpus/image_faster.alz',      'image.raw'),
    ('packed_corpus/biased_normal.alz',     'biased.bin'),
]

def matches(a, b):
    n = min(len(a), len(b)); i = 0
    while i < n and a[i] == b[i]: i += 1
    return i

for arc, name in targets:
    (p, vol, entries), = hd.parse(arc)
    info = next(i for n, i in entries if n == name and i)
    data = hd.read_member_data(arc, info['hdr_pos'])
    out = zlib.decompressobj(-15).decompress(data)
    best = []
    for wb in range(9, 16):
        for ml in range(1, 10):
            for lvl in (1, 2, 3, 4, 5, 6):
                c = zlib.compressobj(lvl, zlib.DEFLATED, -wb, ml, 0)
                st = c.compress(out) + c.flush()
                m = matches(st, data)
                if m == len(data):
                    best.append((wb, ml, lvl, 'EXACT'))
                    break  # exact found for this wb; try other wb too
        # also try wbits without memLevel spread when exact found
    # report best prefix match config
    if not best:
        # find config with longest common prefix for hint
        cfg, mx = None, 0
        for wb in (9, 10, 11, 12, 13, 14, 15):
            for ml in (1, 2, 3, 4, 5, 6, 7, 8, 9):
                for lvl in (1, 2, 3, 4, 5, 6):
                    c = zlib.compressobj(lvl, zlib.DEFLATED, -wb, ml, 0)
                    st = c.compress(out) + c.flush()
                    m = matches(st, data)
                    if m > mx:
                        mx, cfg = m, (wb, ml, lvl)
        print(f'{os.path.basename(arc):26s} {name:15s} NO EXACT; best prefix cfg wb={cfg[0]} ml={cfg[1]} lvl={cfg[2]} -> {mx}/{len(data)}')
    else:
        for b in best:
            print(f'{os.path.basename(arc):26s} {name:15s} EXACT wb=-{b[0]} memLevel={b[1]} lvl={b[2]}')
