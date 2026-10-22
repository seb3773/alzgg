#!/usr/bin/env python3
"""Survey of the routing by file type, archive by archive.

For every archive of packed_egg/ and corpus_probe/, the members are listed with
the method of each of their blocks (0 store, 1 deflate, 2 bzip2, 3 AZO, 4 lzma),
together with hint and sizes. Used to establish the "which file type takes which
codec" rule of the Normal / Priority-on-Ratio / Optimized profiles, without
guessing it.
"""
import glob
import os
import re
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import egg_dump as ed

PROFILE_RE = re.compile(r'_(none|normal|compspeed|compratio|optimized|faster|fast)'
                        r'(?:_solid)?(?:_password)?')


def members(path):
    tmp = None
    if '.vol' in path:
        _o, synth = ed.vol_chain(path)
        fd, tmp = tempfile.mkstemp(suffix='.egg')
        with os.fdopen(fd, 'wb') as fp:
            fp.write(synth)
        path = tmp
    try:
        r = ed.parse(path)
    except Exception as exc:
        return None, str(exc)
    finally:
        if tmp:
            os.unlink(tmp)
    out = []
    for e in r.get('files', []):
        out.append((e.get('name'), [(b['method'], b['hint'], b['usize'], b['csize'])
                                    for b in e.get('blocks', [])]))
    return out, None


def profile_of(arc):
    m = PROFILE_RE.search(os.path.basename(arc))
    return m.group(1) if m else '?'


def main():
    only = sys.argv[1] if len(sys.argv) > 1 else None
    archives = sorted(glob.glob('packed_egg/*.egg')) + \
               sorted(glob.glob('corpus_probe/*.egg'))
    for arc in archives:
        base = os.path.basename(arc)
        if arc.endswith(('.vol2.egg', '.vol3.egg')):
            continue
        if only and only not in base:
            continue
        mems, err = members(arc)
        if mems is None:
            print(f'{base:44s} FAIL {err}')
            continue
        prof = profile_of(arc)
        print(f'\n== {base}  profil={prof}  {len(mems)} membres')
        show = mems if len(mems) <= 12 else mems[:6] + [('…', [])] + mems[-3:]
        for name, blks in show:
            if not blks:
                print(f'   {str(name):36s} (aucun bloc)')
                continue
            desc = ', '.join(f'm{m}.hint{h} {u}->{c}' for m, h, u, c in blks)
            print(f'   {str(name):36s} {desc}')


if __name__ == '__main__':
    main()
