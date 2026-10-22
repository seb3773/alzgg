#!/usr/bin/env python3
"""Verify the hypothesis for the whole packed corpus:
  profile faster -> zlib deflate (wb=-15, memLevel=8, level=1)
  profile fast   -> same,  level=2
  profile normal -> same,  level=4
  profile none   -> method 0 store (expected exception: image24?)
Also flags stream-vs-stream equality across profiles.
"""
import glob, os, sys, zlib
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import header_dump as hd

def matches(a, b):
    n = min(len(a), len(b)); i = 0
    while i < n and a[i] == b[i]: i += 1
    return i

PROFILE = {
    'faster': 1, 'fast': 2, 'normal': 4,
}

fails, ok, skipped = [], 0, 0
streams = {}   # (member, profile) -> stream bytes to compare across profiles
lvl_of = {}
for path in sorted(glob.glob('packed_corpus/*.alz')):
    arc = os.path.basename(path)
    (p, vol, entries), = hd.parse(path)
    if not isinstance(entries, list):
        continue
    prof = next((px for px in PROFILE if f'_{px}.alz' in arc), None)
    level = PROFILE.get(prof)
    for name, info in entries:
        if info is None or name in ('END',):
            continue
        key = (name, prof)
        if info.get('method') == 0:
            streams[key] = hd.read_member_data(path, info['hdr_pos'])
            lvl_of[key] = 0
            continue
        if info.get('method') != 2:
            skipped += 1
            continue
        data = hd.read_member_data(path, info['hdr_pos'])
        out = zlib.decompressobj(-15).decompress(data, info['usize'] or 0)
        if level is None:   # unknown profile (e.g. *_none with deflate): detect
            level = next((lv for lv in (1, 2, 4) if
                          (lambda c: c.compress(out) + c.flush())(
                              zlib.compressobj(lv, zlib.DEFLATED, -15, 8, 0)) == data), None)
            if level is None:
                fails.append(f'{arc} {name}: no candidate level matches')
                continue
        c = zlib.compressobj(level, zlib.DEFLATED, -15, 8, 0)
        st = c.compress(out) + c.flush()
        streams[key] = st
        lvl_of[key] = level
        if st != data:
            fails.append(f'{arc} {name}: len {len(st)} vs {len(data)}, prefix {matches(st,data)}/{len(data)}')
        else:
            ok += 1
        # CRC check too
        if (zlib.crc32(out) & 0xffffffff) != (info['crc'] or 0):
            fails.append(f'{arc} {name}: CRC mismatch after inflate')

print(f'exact matches: {ok}, fails: {len(fails)}, non-deflate skipped: {skipped}')
for f in fails[:20]:
    print('  FAIL', f)

print('--- cross-profile stream equality (same member) ---')
members = sorted({m for (m, pr) in streams})
for m in members:
    vals = {}
    for pr in ('none', 'faster', 'fast', 'normal'):
        k = (m, pr)
        if k in streams:
            vals.setdefault(streams[k], []).append(pr)
    if len(vals) > 1:
        parts = [f"{pr}({lvl_of[(m,pr)]})" for s, prs in vals.items() for pr in prs]
        print(f'  {m:20s} differs: {" ".join(parts)}')
    else:
        prs = [pr for s, plist in vals.items() for pr in plist]
        print(f'  {m:20s} IDENTICAL all profiles: {", ".join(sorted(prs))} lvl={sorted({lvl_of[(m, p)] for p in prs if (m, p) in lvl_of})}')
