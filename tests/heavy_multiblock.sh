#!/bin/sh
# HEAVY check, outside `make test`: an encrypted EGG member above 3 GiB, hence
# split into TWO blocks under a single continuous encryption context.
#
# The corpus has only one reference for this case: `huge_enc_zip.egg` (lot H,
# 5 GiB of zeros under ZipCrypto), 3 GiB + 2 GiB, with the same two CRCs as the
# plain `-m0` `huge_store_5g.egg`. It weighs 5 GiB, hence a separate script
# rather than a `make test` step:
#
#   make heavy            # or: sh tests/heavy_multiblock.sh
#
# What the script requires, in both directions:
#   1. the reader extracts the 5 GiB back (the ZipCrypto check is deferred, the
#      verifier carrying the CRC of the WHOLE member and not of the first block);
#   2. the writer rebuilds the archive byte for byte from the same random
#      material, read back from the reference;
#   3. a wrong password is refused.
set -e

# Paths are relative to the repository root: move there, wherever the script is
# launched from.
cd "$(dirname "$0")/.."

ref=packed_egg_8.0/huge_enc_zip.egg
src=corpus/huge/zero5g.bin

if [ ! -f "$ref" ] || [ ! -f "$src" ]; then
    echo "heavy multiblock: SKIP — $ref or $src missing"
    echo "  (fixtures/build-fixtures.py --only h produces them; --skip-huge omits the 5 GiB)"
    exit 0
fi

command -v python3 >/dev/null 2>&1 || {
    echo "heavy multiblock: python3 is required" >&2
    exit 1
}
[ -x ./alzgg ] || make -s alzgg
[ -x ./alzgg ] || {
    echo "heavy multiblock: ./alzgg not found" >&2
    exit 1
}

work=$(mktemp -d "${ALZIP_HEAVY_WORK:-./heavy-work}.XXXXXX")
trap 'rm -rf "$work"' EXIT INT TERM
echo "heavy multiblock: working in $work (~15 GiB temporary)"

# --- Header, FILETIME and random material read back from the reference. The
# ZipCrypto verifier (12 bytes in Encrypt Info) decrypts into 10 bytes of
# material + the two high bytes of the member CRC, low byte first: the last two
# bytes are therefore checked here, against the CRC of a member the script does
# not decompress yet.
python3 - "$ref" "$src" "$work" <<'PY'
import os, struct, sys, zlib

ref, src, work = sys.argv[1:4]
head = open(ref, 'rb').read(4096)
if head[:4] != b'EGGA':
    raise SystemExit(f'{ref}: EGGA signature missing')
hid = struct.unpack_from('<I', head, 6)[0]
vi = head.find(struct.pack('<I', 0x08D1470F))
if vi < 0:
    raise SystemExit("Encrypt Info missing: the reference is not encrypted")
method = head[vi + 7]
stored = head[vi + 8:vi + 20]
wi = head.find(struct.pack('<I', 0x2C86950B))
filetime = struct.unpack_from('<Q', head, wi + 7)[0]

# CRC-32 of the whole member (5 GiB of zeros here, but we really compute it).
crc = 0
with open(src, 'rb') as f:
    while True:
        b = f.read(1 << 24)
        if not b:
            break
        crc = zlib.crc32(b, crc)
crc &= 0xFFFFFFFF

T = []
for i in range(256):
    c = i
    for _ in range(8):
        c = (c >> 1) ^ (0xEDB88320 if c & 1 else 0)
    T.append(c)


def upd(k, c):
    k[0] = (k[0] >> 8) ^ T[(k[0] ^ c) & 0xFF]
    k[1] = ((k[1] + (k[0] & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF
    k[2] = (k[2] >> 8) ^ T[(k[2] ^ (k[1] >> 24)) & 0xFF]


k = [0x12345678, 0x23456789, 0x34567890]
for b in b'password':
    upd(k, b)
plain = bytearray()
for b in stored:
    t = (k[2] | 2) & 0xFFFFFFFF
    c = b ^ ((((t * (t ^ 1)) & 0xFFFFFFFF) >> 8) & 0xFF)
    plain.append(c)
    upd(k, c)
if plain[10] != ((crc >> 16) & 0xFF) or plain[11] != ((crc >> 24) & 0xFF):
    raise SystemExit('the verifier does not carry the whole-member CRC: '
                     + plain.hex())
if method != 0:
    raise SystemExit(f'method {method}: this script expects ZipCrypto')
open(os.path.join(work, 'material'), 'w').write(bytes(plain[:10]).hex())
open(os.path.join(work, 'header'), 'w').write('%08x %d\n' % (hid, filetime))
print(f'  header read back: header_id {hid:#x}, verifier on the whole CRC '
      f'{crc:08x}')
PY

read -r hid filetime < "$work/header"
material=$(cat "$work/material")

# --- 1. Reader: the 5 GiB come out, deferred check included.
mkdir "$work/out"
if ! ./alzgg extract "$ref" -d "$work/out" -p password; then
    echo "heavy multiblock: FAIL — extraction refused" >&2
    exit 1
fi
if ! cmp -s "$src" "$work/out/zero5g.bin"; then
    echo "heavy multiblock: FAIL — extracted content differs from $src" >&2
    exit 1
fi
rm -rf "$work/out"
echo "  read: 5 GiB extracted again, deferred ZipCrypto check consistent"

# --- 2. Writer: byte-for-byte rebuild, same material, same FILETIME.
python3 - "$src" "$filetime" <<'PY'
import datetime, os, sys
wall = int(sys.argv[2]) // 10000000 - 11644473600
epoch = int(datetime.datetime.utcfromtimestamp(wall).astimezone().timestamp())
os.utime(sys.argv[1], (epoch, epoch))
PY
alz=$(pwd)/alzgg
work_abs=$(cd "$work" && pwd)
if ! (cd "$(dirname "$src")" && "$alz" create "$work_abs/rebuilt.egg" \
        -p none -i "0x$hid" --password password --crypt zip \
        --crypt-info "$material" zero5g.bin) >"$work/create.log" 2>&1; then
    cat "$work/create.log" >&2
    echo "heavy multiblock: FAIL — encrypted creation refused" >&2
    exit 1
fi
if ! cmp -s "$ref" "$work/rebuilt.egg"; then
    echo "heavy multiblock: FAIL — rebuilt archive differs from $ref" >&2
    exit 1
fi
echo "  write: 5 368 709 263 identical bytes to the ALZip reference"

# --- 3. A wrong password is refused.
mkdir "$work/bad"
if ./alzgg extract "$ref" -d "$work/bad" -p wrong >"$work/bad.log" 2>&1; then
    echo "heavy multiblock: FAIL — a wrong password was accepted" >&2
    exit 1
fi
echo "  refusal: wrong password rejected (" \
     "$(sed -n '1p' "$work/bad.log") )"

echo "heavy multiblock: PASS"
