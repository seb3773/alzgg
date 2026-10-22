#!/usr/bin/env python3
"""Compare two ALZ archives byte-for-byte, masking only BLZ DOS timestamps.

This is the exact-output oracle used by the ALZ corpus tests. It validates the
volume framing and walks each logical archive stream so member headers/data can
continue across volumes. Any archive byte difference outside the four timestamp
bytes in each file header is a failure.
"""
import glob
import os
import re
import sys

ARCHIVE_MAGIC = b'ALZ\x01'
FILE_MAGIC = b'BLZ\x01'
END_MAGIC = b'CLZ\x01'
FINAL_MAGIC = b'CLZ\x02'
NONFINAL_MAGIC = b'CLZ\x03'


class ArchiveError(Exception):
    pass


def load_volumes(path):
    if not os.path.isfile(path):
        raise ArchiveError(f'missing archive: {path}')
    base = path[:-4] if path.endswith('.alz') else path
    indexed = {}
    for candidate in glob.glob(base + '.a*'):
        match = re.fullmatch(re.escape(base) + r'\.a(\d+)', candidate)
        if match:
            indexed[int(match.group(1))] = candidate
    expected = 0
    paths = [path]
    while expected in indexed:
        paths.append(indexed[expected])
        expected += 1
    extra = sorted(indexed.keys() - set(range(expected)))
    if extra:
        raise ArchiveError(f'volume sequence has a gap before indices {extra}: {path}')

    blobs = []
    for index, volume_path in enumerate(paths):
        with open(volume_path, 'rb') as f:
            blob = f.read()
        if len(blob) < 24:
            raise ArchiveError(f'volume too short: {volume_path}')
        if blob[:4] != ARCHIVE_MAGIC:
            raise ArchiveError(f'bad archive magic: {volume_path}')
        volume_number = blob[6]
        # The archive header numbers the first volume 0, then .a00=1, .a01=2.
        if volume_number != index:
            raise ArchiveError(
                f'volume header byte 6 is {volume_number}, expected {index}: {volume_path}')
        if blob[7] != 0:
            raise ArchiveError(f'archive header reserved byte 7 is non-zero: {volume_path}')
        if blob[-16:-12] != END_MAGIC:
            raise ArchiveError(f'missing END record: {volume_path}')
        expected_end = FINAL_MAGIC if index == len(paths) - 1 else NONFINAL_MAGIC
        if blob[-4:] != expected_end:
            raise ArchiveError(f'wrong final/non-final END marker: {volume_path}')
        blobs.append(blob)
    return paths, blobs


def parse_timestamp_offsets(blobs):
    """Walk file records and return timestamp byte offsets for each volume."""
    timestamps = [[] for _ in blobs]
    volume_index = 0
    pos = 8
    # The ALZ header length is 8. Volume data may continue at offset 8 in the
    # next volume; the 16-byte END is always reserved at each volume's tail.
    data_ends = [len(blob) - 16 for blob in blobs]

    def next_volume():
        nonlocal volume_index, pos
        if volume_index + 1 >= len(blobs):
            return False
        volume_index += 1
        pos = 8
        return True

    def require_in_volume(size, what):
        if pos + size > data_ends[volume_index]:
            raise ArchiveError(
                f'{what} crosses volume boundary at volume {volume_index}, offset {pos}')

    def skip_member_data(size):
        nonlocal pos
        remaining = size
        while remaining:
            available = data_ends[volume_index] - pos
            if available <= 0:
                if not next_volume():
                    raise ArchiveError('member data continues beyond final volume')
                continue
            take = min(available, remaining)
            pos += take
            remaining -= take

    while True:
        if pos >= data_ends[volume_index]:
            if next_volume():
                continue
            break
        available = data_ends[volume_index] - pos
        if available < 4:
            raise ArchiveError(f'truncated record magic in volume {volume_index}, offset {pos}')

        magic = blobs[volume_index][pos:pos + 4]
        if magic == END_MAGIC:
            if volume_index != len(blobs) - 1:
                raise ArchiveError(f'END record encountered before final volume at index {volume_index}')
            if pos + 16 != len(blobs[volume_index]):
                raise ArchiveError(f'END record is not the final 16 bytes in volume {volume_index}')
            break
        if magic == FILE_MAGIC:
            record_pos = pos
            pos += 4
            require_in_volume(9, 'fixed file header')
            name_len = int.from_bytes(blobs[volume_index][pos:pos + 2], 'little')
            # attr (1), DOS timestamp (4), fd (1), unknown2 (1)
            timestamps[volume_index].append(record_pos + 7)
            fd = blobs[volume_index][pos + 7]
            pos += 9
            csize = 0
            if fd & 0xF0:
                size_width = fd >> 4
                require_in_volume(6 + 2 * size_width, 'optional sizes')
                csize = int.from_bytes(blobs[volume_index][pos + 6:pos + 6 + size_width], 'little')
                pos += 6 + 2 * size_width
            require_in_volume(name_len, 'filename')
            pos += name_len
            skip_member_data(csize)
            continue

        raise ArchiveError(
            f'unexpected record {magic.hex()} in volume {volume_index} at offset {pos}')

    return timestamps


def masked(blob, offsets):
    data = bytearray(blob)
    for offset in offsets:
        if offset < 0 or offset + 4 > len(data):
            raise ArchiveError(f'invalid timestamp offset: {offset}')
        data[offset:offset + 4] = b'\x00' * 4
    return data


def compare(ref, generated):
    ref_paths, ref_blobs = load_volumes(ref)
    gen_paths, gen_blobs = load_volumes(generated)
    if len(ref_blobs) != len(gen_blobs):
        raise ArchiveError(f'volume count differs: {len(ref_blobs)} != {len(gen_blobs)}')

    ref_timestamps = parse_timestamp_offsets(ref_blobs)
    gen_timestamps = parse_timestamp_offsets(gen_blobs)
    if [len(x) for x in ref_timestamps] != [len(x) for x in gen_timestamps]:
        raise ArchiveError('file-header count per volume differs')

    for index, (ref_blob, gen_blob) in enumerate(zip(ref_blobs, gen_blobs)):
        if len(ref_blob) != len(gen_blob):
            raise ArchiveError(
                f'volume {index} byte length differs: {len(ref_blob)} != {len(gen_blob)}')
        r = masked(ref_blob, ref_timestamps[index])
        g = masked(gen_blob, gen_timestamps[index])
        if r != g:
            mismatch = next(i for i, (a, b) in enumerate(zip(r, g)) if a != b)
            raise ArchiveError(
                f'volume {index} differs at byte offset 0x{mismatch:x}: '
                f'{r[mismatch]:02x} != {g[mismatch]:02x}')
    return len(ref_blobs)


def main(argv):
    if len(argv) != 3:
        print('usage: archive_compare.py reference.alz generated.alz', file=sys.stderr)
        return 2
    try:
        volumes = compare(argv[1], argv[2])
    except (ArchiveError, OSError, ValueError) as exc:
        print(f'ARCHIVE DIFF: {exc}', file=sys.stderr)
        return 1
    print(f'IDENTICAL outside DOS timestamps ({volumes} volume(s)): {os.path.basename(argv[1])}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv))
