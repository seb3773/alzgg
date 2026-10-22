"""Dump EGG (.egg) archive structure.

Reverse/architecture per CC0 spec https://github.com/alkegi/docs/blob/master/egg.md
All integers LE. Signatures are 4-byte little-endian on disk:
  EGGA        0x41474745  EGG archive header (14 bytes: ver16, headerID32, reserved32)
  0x24F5A262  Split Info (extra field, 8 bytes prev/next volume IDs)
  0x24E5A060  Solid Info (extra field, 0 bytes)
  0x0A8590E3  File header (no extra field: fileID32, usize64) = 16 bytes
  0x0A8591AC  Filename (extra field: flags1, size16) + [locale16] + [parentID32] + name
  0x2C86950B  Windows File Info (extra field, 9 bytes: FILETIME64, attrs8)
  0x08D1470F  Encrypt Info (extra field; method1 + method-specific data)
  0x02B50C13  Block header (no extra field: method1, hint1, usize32, csize32, crc32)
              then End Marker, then csize bytes data
  0x08E28222  End marker: terminates prefix section, file subheaders, each block, archive
Extra field prefix: flags byte (1) + size (UInt16 if flags bit0==0, else UInt32) = 3 or 5 bytes.
"""
import struct, sys, os

MAGIC = 0x41474745
FILE_HDR = 0x0A8590E3
FILENAME = 0x0A8591AC
COMMENT = 0x04C63672
WININFO = 0x2C86950B
POSIXINFO = 0x1EE922E5
ENCRYPT = 0x08D1470F
BLOCK = 0x02B50C13
SPLIT = 0x24F5A262
SOLID = 0x24E5A060
GENC = 0x08D144A8
SKIP = 0xFFFF0000
DUMMY = 0x07463307
END = 0x08E28222

SIG_NAMES = {
    MAGIC: 'EGG_HDR', SPLIT: 'SPLIT_INFO', SOLID: 'SOLID_INFO', GENC: 'GLOBAL_CRYPT',
    FILE_HDR: 'FILE_HDR', FILENAME: 'FILENAME', COMMENT: 'COMMENT', WININFO: 'WIN_INFO',
    POSIXINFO: 'POSIX_INFO', ENCRYPT: 'ENCRYPT', BLOCK: 'BLOCK', DUMMY: 'DUMMY',
    SKIP: 'SKIP', END: 'END_MARKER',
}
METHODS = {0: 'store', 1: 'deflate', 2: 'bzip2', 3: 'AZO', 4: 'lzma'}
CRYPT_METHODS = {0: 'zip', 1: 'aes128', 2: 'aes256', 5: 'lea128', 6: 'lea256'}


class Fail(Exception):
    pass


def _ef(blob, pos):
    """Extra field: returns (flags, size, new_pos). Size UInt16 if flags bit0==0 else UInt32."""
    if len(blob) < pos + 3:
        raise Fail(f'extra field truncated @{pos:#x}')
    flags = blob[pos]
    pos2 = pos + 1
    if flags & 0x01:
        if len(blob) < pos2 + 4:
            raise Fail(f'extra field (32) truncated @{pos:#x}')
        size = int.from_bytes(blob[pos2:pos2 + 4], 'little')
        return flags, size, pos2 + 4
    size = int.from_bytes(blob[pos2:pos2 + 2], 'little')
    return flags, size, pos2 + 2


def _skipef(blob, pos):
    flags, size, np = _ef(blob, pos)
    return np + size


def _sig(blob, pos):
    if len(blob) < pos + 4:
        return None
    return int.from_bytes(blob[pos:pos + 4], 'little')


def _prefix_end(blob):
    """Volume: (egg_hdr_dict, payload_start, split_prev, split_next, solid)"""
    ver, hid, resv = struct.unpack_from('<HII', blob, 4)
    pos = 14
    prev = nxt = None
    solid = False
    while True:
        sig = _sig(blob, pos)
        if sig == END:
            pos += 4
            break
        if sig == SPLIT:
            f, sz, p2 = _ef(blob, pos + 4)
            prev, nxt = struct.unpack_from('<II', blob, p2)
            pos = p2 + sz
        elif sig == SOLID:
            f, sz, p2 = _ef(blob, pos + 4)
            solid = True
            pos = p2 + sz
        elif sig in (GENC, SKIP, DUMMY):
            pos = _skipef(blob, pos + 4)
        else:
            return None
    return {'ver': ver, 'hid': hid, 'resv': resv, 'payload': pos,
            'prev': prev, 'next': nxt, 'solid': solid}


def vol_chain(path):
    """Follow the split chain from `path` (single volume OK).
    Returns pair (list of (fname, info, blob), logical_blob)."""
    base = os.path.dirname(os.path.abspath(path))
    stems = {os.path.basename(path)}
    # discover candidate siblings sharing stem before .volN.egg
    stem0 = os.path.basename(path)
    for ext in ('.vol1.egg', '.vol2.egg', '.vol3.egg'):
        if stem0.endswith(ext):
            stem0 = stem0[: -len(ext)]
    import glob as g
    cands = sorted(g.glob(os.path.join(base, stem0 + '*.egg')))
    first = open(path, 'rb').read()
    info0 = _prefix_end(first)
    if info0 is None:
        return [(path, None, first)], None
    chain = []
    seen = {}
    for cand in cands:
        blob = open(cand, 'rb').read()
        inf = _prefix_end(blob)
        if inf:
            chain.append((os.path.basename(cand), inf, blob))
    # order by ID linkage starting at prev==None(first volume)
    cur = [c for c in chain if c[1]['prev'] in (None, 0)]
    ordered = []
    if cur:
        ordered.append(cur[0])
        while ordered[-1][1]['next']:
            nxt_id = ordered[-1][1]['next']
            m = [c for c in chain if c[1]['hid'] == nxt_id and c not in ordered]
            if not m:
                break
            ordered.append(m[0])
    else:
        ordered = [c for c in chain if os.path.basename(c[0]) == os.path.basename(path)]
        if not ordered:
            ordered = chain[:1]
    # logical stream: concat payload regions, every volume to EOF (the final
    # volume keeps its own trailing END record, read as shared by parse())
    parts = []
    for name, inf, blob in ordered:
        parts.append(blob[inf['payload']:])
    synth = b'\x45\x47\x47\x41' + struct.pack('<HII', ordered[0][1]['ver'],
                                              ordered[0][1]['hid'], 0) + b''.join(parts)
    return ordered, synth


def parse(path):
    """-> {header:..., prefix:[], files:[{...blocks:[]}], tail_ok:bool}"""
    blob = open(path, 'rb').read()
    out = {'path': path, 'problems': []}
    if len(blob) < 14 or int.from_bytes(blob[:4], 'little') != MAGIC:
        out['problems'].append('not EGG')
        return out
    ver, hid, resv = struct.unpack_from('<HII', blob, 4)
    out['version'] = hex(ver)
    out['header_id'] = hid
    out['reserved'] = resv

    # prefix section
    pos = 14
    found = []
    while True:
        sig = _sig(blob, pos)
        if sig is None:
            raise Fail('EOF in prefix section')
        outp = pos
        if sig == END:
            pos += 4
            break
        if sig == FILE_HDR:  # empty prefix section (split logical stream)
            break
        if sig in (SPLIT,):
            if int.from_bytes(blob[pos + 4 + 2:pos + 4 + 2], 'little') != 0x0:  # placeholder
                pass
            f, sz, p2 = _ef(blob, outp + 4)
            prev, nxt = struct.unpack_from('<II', blob, p2)
            found.append(('SPLIT_INFO', {'prev_id': prev, 'next_id': nxt}))
            pos = p2 + sz
        elif sig in (SOLID, SKIP, GENC, DUMMY):
            if sig == DUMMY:
                f, sz, p2 = _ef(blob, outp + 4)
                found.append(('DUMMY', {'size': sz}))
                pos = p2 + sz
            else:
                pos = _skipef(blob, outp + 4)
                found.append((SIG_NAMES.get(sig, hex(sig)), None))
        else:
            raise Fail(f'unexpected {SIG_NAMES.get(sig, hex(sig))} in prefix @${outp:x}')
    out['prefix'] = found

    # files
    files = []
    while True:
        sig = _sig(blob, pos)
        if sig is None:
            out['problems'].append('EOF before final end marker')
            break
        if sig == END:
            pos += 4
            if _sig(blob, pos) is not None:
                out['problems'].append(f'data after final end marker @${pos:#x}')
            break
        if sig != FILE_HDR:
            # archive-level comment
            if sig == COMMENT:
                pos0 = pos
                pos = _skipef(blob, pos + 4)
                text = blob[pos0 + 7:pos]
                files.append({'kind': 'archive_comment', 'text': text.decode('utf-8', 'replace')})
                continue
            raise Fail(f'unexpected {SIG_NAMES.get(sig, hex(sig))} where file header expected @${pos:#x}')

        file_id, usize = struct.unpack_from('<IQ', blob, pos + 4)
        pos += 16
        e = {'kind': 'file', 'file_id': file_id, 'usize': usize,
             'name': None, 'wininfo': None, 'crypt': None, 'comments': [], 'blocks': []}
        # subheaders
        while True:
            sig = _sig(blob, pos)
            if sig in (None, END):
                if sig == END:
                    pos += 4
                break
            if sig == FILENAME:
                f, sz, p2 = _ef(blob, pos + 4)
                q = p2
                locale = None
                if f & 0x08:
                    locale = int.from_bytes(blob[q:q + 2], 'little')
                    q += 2
                parent = None
                if f & 0x10:
                    parent = int.from_bytes(blob[q:q + 4], 'little')
                    q += 4
                e['fnext'] = sz
                e['fn_flags'] = f
                e['fn_locale'] = locale
                e['fn_parent'] = parent
                e['name'] = blob[q:p2 + sz].decode('utf-8', 'replace')
                pos = p2 + sz
            elif sig == COMMENT:
                pos0 = pos
                pos = _skipef(blob, pos + 4)
                e['comments'].append(blob[pos0 + 7:pos].decode('utf-8', 'replace'))
            elif sig == WININFO:
                f, sz, p2 = _ef(blob, pos + 4)
                if sz == 9:
                    ft, attrs = struct.unpack_from('<QB', blob, p2)
                    e['wininfo'] = {'filetime': ft, 'attrs': attrs}
                pos = p2 + sz
            elif sig == ENCRYPT:
                f, sz, p2 = _ef(blob, pos + 4)
                method = blob[p2]
                e['crypt'] = {'method': method, 'name': CRYPT_METHODS.get(method, method),
                              'data': blob[p2 + 1:p2 + sz].hex(), 'declared_size': sz}
                pos = p2 + sz
            elif sig == POSIXINFO or sig == DUMMY:
                pos = _skipef(blob, pos + 4)
            elif sig == FILENAME:
                pass
            else:
                raise Fail(f'unexpected {SIG_NAMES.get(sig, hex(sig))} in file subheaders @${pos:#x}')
        # blocks
        while True:
            sig = _sig(blob, pos)
            if sig is None:
                out['problems'].append('EOF in blocks')
                break
            if sig in (COMMENT, FILE_HDR, END):
                break
            if sig in (ENCRYPT, DUMMY):  # seen in some writers between blocks
                pos = _skipef(blob, pos + 4)
                continue
            if sig != BLOCK:
                raise Fail(
                    f'unexpected {SIG_NAMES.get(sig, hex(sig))} in blocks @${pos:#x}')
            meth, hint, bus, bcs, bcrc = struct.unpack_from('<BBIII', blob, pos + 4)
            mpos = pos + 18
            if _sig(blob, mpos) != END:
                raise Fail(f'missing end marker after block header @${mpos:#x}')
            mpos += 4
            data = blob[mpos:mpos + bcs]
            if len(data) < bcs:
                raise Fail(f'block data truncated (need {bcs}, have {len(data)}) @${mpos:#x}')
            e['blocks'].append({
                'method': meth, 'method_name': METHODS.get(meth, meth), 'hint': hint,
                'usize': bus, 'csize': bcs, 'crc': f'{bcrc:08x}',
                'data': data})
            pos = mpos + bcs
        files.append(e)
    out['files'] = files
    return out


def _main():
    for path in sys.argv[1:]:
        is_split = '.vol' in path
        if is_split:
            ordered, synth = vol_chain(path)
            print(f"== SPLIT {os.path.basename(path)}  volumes=["
                  f"{', '.join(n for n, i, b in ordered)}] ")
            for n, i, b in ordered:
                print(f"   vol {n}: id={i['hid']:#010x} prev={i['prev']} next={i['next']} "
                      f"payload@${i['payload']:#x} size={len(b)}")
            blob_tmp = '/tmp/_egg_logical.bin'
            open(blob_tmp, 'wb').write(synth)
            path = blob_tmp
        if '.vol' not in path:
            pass
        try:
            r = parse(path)
        except Fail as exc:
            print(f'== {os.path.basename(path)}  FAIL: {exc}')
            continue
        n = os.path.basename(path)
        print(f"== {n}  ver={r['version']} header_id={r['header_id']:#010x} "
              f"problems={r['problems'] or 'none'}")
        for kind, info in r.get('prefix', []):
            print(f'   prefix {kind} {info if info is not None else ""}')
        for e in r['files']:
            if e['kind'] == 'archive_comment':
                print(f"   [archive comment] {e['text']!r}")
                continue
            win = e.get('wininfo')
            w = (f" win={win['filetime']},attr={win['attrs']:#x}" if win else '')
            c = f" crypt={e['crypt']['name']}({e['crypt']['declared_size']},{e['crypt']['data']})" if e['crypt'] else ''
            loc = f" locale={e['fn_locale']}" if e.get('fn_locale') is not None else ''
            par = f" parent={e['fn_parent']}" if e.get('fn_parent') is not None else ''
            fl = f" fnflags={e['fn_flags']:#x}" if 'fn_flags' in e else ''
            print(f"   file#{e['file_id']} '{e['name']}' usize={e['usize']}{fl}{loc}{par}{w}{c}")
            for b in e['blocks']:
                prev = b['data'][:16].hex()
                print(f"      block {b['method_name']:8s} hint={b['hint']} "
                      f"usize={b['usize']:>9} csize={b['csize']:>8} crc={b['crc']} head='{prev}'")


if __name__ == '__main__':
    _main()
