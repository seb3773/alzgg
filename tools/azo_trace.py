#!/usr/bin/env python3
"""Trace of the AZO parser (EGG method 3): decodes a block and prints the symbol
stream (literals, fresh matches, reuses) as ALZip wrote it. Used to compare our
encoder's parser with the reference one.

Usage:
  python3 tools/azo_trace.py archive.egg            # every AZO block
  python3 tools/azo_trace.py archive.egg --limit 60 # print only the first 60
                                                     # symbols
  python3 tools/azo_trace.py --payload blob.bin --usize N   # raw AZO payload

The decoder is an independent transcription of src/egg_azo.c (same models, same
MRU lists, same tables), instrumented to log the decisions.
"""
import argparse
import struct
import sys

MASK = 0xFFFFFFFF
MSB = 0x80000000
SMSB = 0x40000000


class Bits:
    def __init__(self, data):
        self.data = data
        self.pos = 0
        self.cur = 0
        self.bits = 0

    def bit(self):
        if not self.bits:
            self.cur = self.data[self.pos] if self.pos < len(self.data) else 0
            self.pos += 1
            self.bits = 8
        self.bits -= 1
        return (self.cur >> self.bits) & 1


class Dec:
    def __init__(self, data):
        self.inp = Bits(data)
        self.low = 0
        self.up = MASK
        self.tag = 0
        for _ in range(32):
            self.tag = ((self.tag << 1) | self.inp.bit()) & MASK

    def rescale(self):
        while (self.low & MSB) == (self.up & MSB):
            b = self.inp.bit()
            self.tag = ((self.tag << 1) & MASK) | b
            self.low = (self.low << 1) & MASK
            self.up = ((self.up << 1) & MASK) | 1
        while (self.low & SMSB) and not (self.up & SMSB):
            b = self.inp.bit()
            self.tag = (((self.tag << 1) | b) ^ MSB) & MASK
            self.low = (self.low << 1) & (MASK >> 1)
            self.up = ((self.up << 1) | 1 | MSB) & MASK

    def bool(self, cum, total_bit):
        t = ((self.up - self.low) + 1) >> total_bit
        v = (self.tag - self.low) // t
        if v >= cum:
            self.low += t * cum
            self.rescale()
            return 1
        self.up = self.low + t * cum - 1
        self.rescale()
        return 0

    def uniform(self, total_bit):
        t = ((self.up - self.low) + 1) >> total_bit
        v = (self.tag - self.low) // t
        self.up = self.low + t * (v + 1) - 1
        self.low = self.low + t * v
        self.rescale()
        return v


class Ebp:
    def __init__(self, bit_n):
        self.bit_n = bit_n
        self.prob = [512] * (1 << bit_n)

    def decode(self, d):
        value = 0
        pre = 1
        for i in range(self.bit_n - 1, -1, -1):
            bit = d.bool(self.prob[pre], 10)
            if bit:
                self.prob[pre] -= self.prob[pre] >> 4
            else:
                self.prob[pre] += (1024 - self.prob[pre]) >> 4
            if bit:
                value |= 1 << i
            pre = (pre << 1) | bit
        return value

    def update(self, value):
        pre = 1
        for i in range(self.bit_n - 1, -1, -1):
            bit = (value >> i) & 1
            if bit:
                self.prob[pre] -= self.prob[pre] >> 4
            else:
                self.prob[pre] += (1024 - self.prob[pre]) >> 4
            pre = (pre << 1) | bit


class BoolState:
    def __init__(self):
        self.prob = [2048] * 256
        self.state = 0

    def decode(self, d):
        bit = d.bool(self.prob[self.state], 12)
        if bit:
            self.prob[self.state] -= self.prob[self.state] >> 6
        else:
            self.prob[self.state] += (4096 - self.prob[self.state]) >> 6
        self.state = ((self.state << 1) | bit) & 0xFF
        return bit


class Pp:
    """PredictProb: two models (fine/coarse) + lucky counter."""

    def __init__(self, nfine, bit_n, shift):
        self.fine = [Ebp(bit_n) for _ in range(nfine)]
        self.coarse = [Ebp(bit_n) for _ in range(nfine >> shift)]
        self.lucky = [0] * nfine
        self.shift = shift

    def decode(self, d, pre, bit_n):
        m1 = self.fine[pre]
        m2 = self.coarse[pre >> self.shift]
        if self.lucky[pre] >= 0:
            value = m1.decode(d)
            m2.update(value)
        else:
            value = m2.decode(d)
            m1.update(value)
        prod1 = prod2 = 1
        node = 1
        for i in range(bit_n - 1, -1, -1):
            p1 = m1.prob[node]
            p2 = m2.prob[node]
            v = (value >> i) & 1
            if (prod1 | prod2) & ((1024 - 1) << (32 - 10)):
                prod1 >>= 10
                prod2 >>= 10
            prod1 *= (1024 - p1) if v else p1
            prod2 *= (1024 - p2) if v else p2
            node = (node << 1) | v
        r = (prod1 > prod2) - (prod1 < prod2)
        if r > 0:
            self.lucky[pre] += 1
        elif r < 0:
            self.lucky[pre] -= 1
        return value


def ilog2(v):
    n = 0
    while v >> 1:
        v >>= 1
        n += 1
    return n


def build_tables():
    len_extra = [0 if i < 32 else (i - 32) // 8 for i in range(128)]
    dist_extra = [0 if i < 16 else (i - 16) // 4 for i in range(128)]
    len_base = [0] * 128
    dist_base = [0] * 128
    len_base[0] = 2
    dist_base[0] = 1
    for i in range(1, 128):
        len_base[i] = len_base[i - 1] + (1 << len_extra[i - 1])
        dist_base[i] = dist_base[i - 1] + (1 << dist_extra[i - 1])
    return len_base, len_extra, dist_base, dist_extra


LEN_BASE, LEN_EXTRA, DIST_BASE, DIST_EXTRA = build_tables()


def dist_code(value):
    v = value - 1
    if v < 16:
        return v
    v -= 16
    extra = ilog2(v // 4 + 1)
    return 16 + extra * 4 + (v - ((1 << extra) - 1) * 4) // (1 << extra)


def trace_block(payload, usize, limit, out):
    d = Dec(payload)
    match_flag = BoolState()
    reuse_flag = BoolState()
    short_reuse = BoolState()
    short_dist = BoolState()
    idx_short = Ebp(1)
    idx_long = Ebp(7)
    dist_short = Ebp(1)
    dist_long = Ebp(7)
    alpha = Pp(256, 8, 5)
    lengths = Pp(128, 7, 4)
    len_rep = [2 + i for i in range(128)]
    pos_rep = [0] * 128
    dist_rep = [1, 2]
    match_rep = [0, 1]
    hist = [len_rep, pos_rep, dist_rep, match_rep]

    def take(idx, hi):
        v = hist[hi][idx]
        for i in range(idx, 0, -1):
            hist[hi][i] = hist[hi][i - 1]
        hist[hi][0] = v
        return v

    def add(v, hi):
        for i in range(len(hist[hi]) - 1, 0, -1):
            hist[hi][i] = hist[hi][i - 1]
        hist[hi][0] = v

    data = bytearray(usize)
    nsym = 0
    if usize == 0:
        return data
    data[0] = alpha.decode(d, 0, 8)
    nsym += 1
    out.write('L 0 %02x\n' % data[0])
    i = 1
    while i < usize:
        if not match_flag.decode(d):
            data[i] = alpha.decode(d, data[i - 1], 8)
            if nsym < limit:
                out.write('L %d %02x\n' % (i, data[i]))
            i += 1
            nsym += 1
            continue
        if reuse_flag.decode(d):
            if short_reuse.decode(d):
                hidx = take(idx_short.decode(d), 3)
            else:
                hidx = idx_long.decode(d)
                add(hidx, 3)
            length = take(hidx, 0)
            distance = i - take(hidx, 1)
            kind = 'R'
        else:
            if short_dist.decode(d):
                distance = take(dist_short.decode(d), 2)
            else:
                code = dist_long.decode(d)
                distance = DIST_BASE[code]
                if DIST_EXTRA[code]:
                    distance += d.uniform(DIST_EXTRA[code])
                add(distance, 2)
            code = dist_code(distance)
            lcode = lengths.decode(d, code, 7)
            length = LEN_BASE[lcode]
            if LEN_EXTRA[lcode]:
                length += d.uniform(LEN_EXTRA[lcode])
            add(length, 0)
            add(i, 1)
            kind = 'M'
        if distance == 0 or distance > i:
            raise SystemExit('distance invalide @%d: %d' % (i, distance))
        if nsym < limit:
            out.write('%s %d idx=%d len=%d dist=%d\n'
                      % (kind, i, hidx if kind == 'R' else -1, length, distance))
        if length > usize - i:
            length = usize - i
        while length:
            data[i] = data[i - distance]
            i += 1
            length -= 1
        nsym += 1
    return data


def payloads_from_egg(path):
    blob = open(path, 'rb').read()
    sig = bytes.fromhex('130cb502')     # BLOCK
    end = bytes.fromhex('2282e208')     # marqueur de fin
    res = []
    pos = 0
    while True:
        j = blob.find(sig, pos)
        if j < 0:
            break
        if blob[j + 18:j + 22] == end:
            meth = blob[j + 4]
            usize = struct.unpack_from('<I', blob, j + 6)[0]
            csize = struct.unpack_from('<I', blob, j + 10)[0]
            if meth == 3:
                res.append((usize, blob[j + 22:j + 22 + csize]))
            pos = j + 22 + csize
        else:
            pos = j + 4
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('archive', nargs='?')
    ap.add_argument('--payload')
    ap.add_argument('--usize', type=int)
    ap.add_argument('--limit', type=int, default=80)
    args = ap.parse_args()

    todo = []
    if args.payload:
        todo.append((args.usize, open(args.payload, 'rb').read()))
    else:
        todo = payloads_from_egg(args.archive)

    for n, (usize, payload) in enumerate(todo):
        if len(payload) < 2 or payload[0:1] != b'1':
            continue
        flags = payload[1]
        pos = 2
        print('== bloc AZO #%d : usize=%d csize=%d flags=%d'
              % (n, usize, len(payload), flags))
        out = sys.stdout
        total = 0
        while pos + 12 <= len(payload):
            bus, bcs, chk = struct.unpack_from('>III', payload, pos)
            pos += 12
            if not bus and not bcs:
                break
            assert (bus ^ bcs) == chk
            if bcs == bus:
                print('  bloc brut %d octets' % bus)
                pos += bcs
                total += bus
                continue
            trace_block(payload[pos:pos + bcs], bus, args.limit, out)
            pos += bcs
            total += bus
        print('  -> %d bytes decoded' % total)


if __name__ == '__main__':
    main()
