"""Dump ALZip (.alz) container/header fields.

Archive header (8 bytes each volume):
  0..3  magic 'ALZ\\x01'
  4..5  unknown (observed 0a 00)
  6     volume number (0=.alz, 1=.a00, 2=.a01...)
  7     reserved (observed zero)
  == vol==0: file headers follow at offset 8
  == vol!=0: compressed data follows directly
File header ('BLZ\\x01'):
  0..3  magic
  4..5  filename length (LE)
  6     attributes (bit0 RO, bit1 hidden, bit4 dir, bit5 file)
  7..10 timestamp (DOS format)
  11    flags: bit0=encrypted, bit3=data-descriptor(unalz), bits4-7 size-field size
        (0x10/0x20/0x40/0x80 = 1/2/4/8 bytes)
  12    unknown2
  -- only if bits4-7 != 0 --
  13    compression method (0=store,1=bzip2,2=deflate,3=obfuscated deflate)
  14    unknown3
  15..18 crc32 LE
  19..19+nb-1    compressed size LE
  ...            uncompressed size LE
  then filename bytes
  then compressed data
End ('CLZ\\x01'): 4 magic + 8 zero + magic2 ('CLZ\\x02' final / 'CLZ\\x03' not final)
"""
import struct, glob, os, sys


def parse(path):
    """Returns list of (path, vol, entries); entries = list of (name, info)
    name in ('END', 'UNKNOWN magic ...', 'SHORT READ ...') or file name."""
    with open(path, 'rb') as f:
        head = f.read(8)
        if len(head) < 8 or head[:4] != b'ALZ\x01':
            return [(path, None, 'NOT ALZ')]
        vol = head[6]
        unknown = head[4:6]
        reserved = head[7]
        if reserved != 0:
            return [(path, vol, f'non-zero reserved byte={reserved:#x}')]
        if vol != 0:
            return [(path, vol, f'data-only volume, unknown={unknown.hex()}')]
        blob = open(path, 'rb').read()
        pos = 8
        entries = []
        while True:
            if blob[pos:pos+4] == b'CLZ\x01':
                tail = blob[pos:pos+16]
                entries.append(('END', {'tail': tail.hex(), 'end_pos': pos}))
                break
            if blob[pos:pos+4] != b'BLZ\x01':
                entries.append((f'UNKNOWN magic {blob[pos:pos+6].hex()} @${pos:x}', None))
                break
            if len(blob) < pos + 15:
                entries.append((f'SHORT READ @{pos+4:x}', None))
                break
            fnl, attr, ts, fd, unk2 = struct.unpack_from('<HBIBB', blob, pos + 4)
            hdr = 13          # name offset without optional fields
            comp = crc = cs = us = unk3 = None
            if fd & 0xF0:
                nb = fd >> 4        # size-field byte count (unalz: fd/0x10)
                comp, unk3 = blob[pos+13], blob[pos+14]
                crc = int.from_bytes(blob[pos+15:pos+19], 'little')
                cs = int.from_bytes(blob[pos+19:pos+19+nb], 'little')
                us = int.from_bytes(blob[pos+19+nb:pos+19+2*nb], 'little')
                hdr = 19 + 2 * nb
            name = blob[pos+hdr:pos+hdr+fnl]
            data_off = pos + hdr + fnl
            entries.append((name.decode('cp437', 'replace'),
                            {'attr': attr, 'time': ts, 'fd': fd, 'unk2': unk2,
                             'method': comp, 'unk3': unk3, 'crc': crc,
                             'csize': cs, 'usize': us, 'data_off': data_off,
                             'hdr_pos': pos}))
            pos = data_off + (cs if cs is not None else 0)
        return [(path, vol, entries)]


def read_member_data(path, hdr_pos):
    """Reconstructs the full data stream of the member whose header lies at
    hdr_pos in `path`, concatenating continuation volumes (.a00, .a01...)."""
    # volumes list
    base = path[:-4]
    vblobs = []
    for vname in [path] + [f'{base}.a{i:02d}' for i in range(0, 999)]:
        if not os.path.exists(vname):
            break
        vblobs.append(open(vname, 'rb').read())
    r = parse(path)
    (p, vol, entries), = r
    info = next((inf for nm, inf in entries if inf and nm not in ('END',)
                 and inf.get('hdr_pos') == hdr_pos), None)
    if info is None:
        return None
    data_off = info['data_off']
    cs = info['csize']
    if cs is None:
        return b''
    blob0 = vblobs[0]
    logical = bytearray(blob0[data_off:len(blob0) - 16])
    for blob in vblobs[1:]:
        logical += blob[8:len(blob) - 16]
    return bytes(logical[:cs])


METHOD_NAMES = {None: '-', 0: 'store', 1: 'bzip2', 2: 'deflate', 3: 'deflate3?'}


def _cli():
    for path in sorted(sys.argv[1:]) or sorted(glob.glob('packed_corpus/*.alz')):
        for (p, vol, entries) in parse(path):
            if entries == 'NOT ALZ':
                print(f'{os.path.basename(p):26s} NOT ALZ')
                continue
            if isinstance(entries, str):  # data-only volume
                print(f'{os.path.basename(p):26s} vol={vol}  {entries}')
                continue
            print(f'== {os.path.basename(p)}  vol={vol}')
            for name, info in entries:
                if info is None:
                    print(f'   {name}')
                elif name == 'END':
                    print(f'   END @${info["end_pos"]:x}  tail={info["tail"]}')
                else:
                    i = info
                    print(f"   '{name}' meth={METHOD_NAMES.get(i['method'], i['method'])} "
                          f"csize={i['csize']} usize={i['usize']} crc={(i['crc'] or 0):08x} "
                          f"attr={i['attr']:02x} fd={i['fd']:02x} u2={i['unk2']:02x} "
                          f"u3={(i['unk3'] or 0):02x} ts={i['time']:08x} hdr@${i['hdr_pos']:x} "
                          f"data@${i['data_off']:x}")


if __name__ == '__main__':
    _cli()
