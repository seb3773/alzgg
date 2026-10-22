#!/bin/sh
# Regenerates the ALZip 12.30 reference corpus (lot K, FIXTURES.md) with
# the install located in `_work/binaries/alzip-12.30` and compares it to the archives
# versioned under `packed_egg/` (EGG) and `packed_alz/` (ALZ). Development only:
# wine and the 12.30 install are required, nothing here is called by `make test`.
#
#   fixtures/lot-k.sh                    # regenerates into out/lot-k-regen and compares
#   LOTK_WORK=/other/path fixtures/lot-k.sh
#
# Encrypted archives cannot be compared byte for byte: ALZip draws their
# material (salt, IV, ZipCrypto headers) at random. They are therefore decrypted
# on both sides and compared member by member. For the others, only the EGG
# Header ID (4 random bytes at offset 6) and the ALZ DOS timestamps are masked —
# entry timestamps come from the original files, copied with their mtime.
set -e

repo=$(cd "$(dirname "$0")/.." && pwd)
cd "$repo"
work=${LOTK_WORK:-$repo/out/lot-k-regen}
stage=$work/stage
out=$work/out
refs_egg=$repo/packed_egg
refs_alz=$repo/packed_alz
oracle=$repo/tools/alz_oracle.sh
alz=$repo/alzgg

[ -x "$alz" ] || { echo "$0: $alz missing (run make)" >&2; exit 1; }
[ -x "$oracle" ] || { echo "$0: $oracle missing" >&2; exit 1; }
[ -d "$refs_egg" ] || { echo "$0: references missing: $refs_egg" >&2; exit 1; }
[ -d "$refs_alz" ] || { echo "$0: references missing: $refs_alz" >&2; exit 1; }

# The references are split by container: ALZ archives (and their `.a00`
# volumes) live in packed_alz/, everything EGG in packed_egg/.
ref_file() {
    case $1 in
        *.alz|*.a00) printf '%s/%s\n' "$refs_alz" "$1" ;;
        *)           printf '%s/%s\n' "$refs_egg" "$1" ;;
    esac
}

rm -rf "$work"
mkdir -p "$stage/two" "$out"
cp -p corpus/hello.txt corpus/code.c "$stage/two/"
cp -p corpus/hello.txt corpus/code.c corpus/records.bin corpus/biased.bin \
      corpus/random.bin "$stage/"
cp -p corpus/probe.sys "$stage/"

fail=0

extract_all() { # archive destination [password]
    mkdir -p "$2"
    if [ -n "$3" ]; then
        "$alz" extract "$1" -d "$2" -p "$3" >/dev/null
    else
        "$alz" extract "$1" -d "$2" >/dev/null
    fi
}

compare_extracted() { # reference generated [password]
    rm -rf "$work/x-ref" "$work/x-gen"
    extract_all "$1" "$work/x-ref" "$3"
    extract_all "$2" "$work/x-gen" "$3"
    # `alz list` prints the Header ID and the timestamps, which regeneration does
    # not reproduce (random Header ID, staging mtime): strip them before
    # comparing the two listings.
    if diff -r "$work/x-ref" "$work/x-gen" >/dev/null &&
       [ "$("$alz" list "$1" | sed 's/header_id=[0-9a-f]*//; s/time=[0-9]*//; s/ts=[0-9a-f]*//')" = \
         "$("$alz" list "$2" | sed 's/header_id=[0-9a-f]*//; s/time=[0-9]*//; s/ts=[0-9a-f]*//')" ];
    then
        echo "  $(basename "$1"): identical members (content and listing)"
    else
        echo "  $(basename "$1"): CONTENT DIFFERS" >&2
        fail=1
    fi
}

compare_alz() { # reference generated
    if python3 tools/archive_compare.py "$1" "$2" >/dev/null; then
        echo "  $(basename "$1"): identical apart from DOS timestamps"
    else
        echo "  $(basename "$1"): ARCHIVE DIFFERS" >&2
        python3 tools/archive_compare.py "$1" "$2" >&2 || true
        fail=1
    fi
}

compare_egg() { # reference generated
    if python3 tools/egg_mask_compare.py "$1" "$2" >/dev/null; then
        echo "  $(basename "$1"): identical apart from Header ID and FILETIMEs"
    else
        echo "  $(basename "$1"): ARCHIVE DIFFERS" >&2
        python3 tools/egg_mask_compare.py "$1" "$2" >&2 || true
        fail=1
    fi
}

# reference name | ALZipCon options | input
while IFS='|' read -r ref opts input; do
    [ -n "$ref" ] || continue
    gen=$out/$ref
    case $ref in
        *.vol1.egg) gen=$out/${ref%.vol1.egg}.egg ;;
    esac

    echo "== $ref ($opts $input)"
    "$oracle" "$gen" $opts "$stage/$input" >/dev/null

    # Random material (encryption) and volume chains: a volume fragment is not a
    # parseable EGG stream, so compare through extraction.
    case $ref in
        *_zip_*|*_aes*|*_lea*)
            compare_extracted "$(ref_file "$ref")" "$gen" password
            continue ;;
        *.vol1.egg)
            base=${ref%.vol1.egg}
            # The chain is read back from its first volume; each volume carries
            # its own Header ID, the only variable byte compared here.
            compare_extracted "$(ref_file "$base.vol1.egg")" "$out/$base.vol1.egg"
            if python3 tools/egg_mask_compare.py --volume \
                   "$(ref_file "$base.vol2.egg")" "$out/$base.vol2.egg" >/dev/null; then
                echo "  $base.vol2.egg: identical apart from volume identifiers"
            else
                echo "  $base.vol2.egg: VOLUME DIFFERS" >&2
                python3 tools/egg_mask_compare.py --volume \
                    "$(ref_file "$base.vol2.egg")" "$out/$base.vol2.egg" >&2 || true
                fail=1
            fi
            continue ;;
    esac

    case $ref in
        *.alz|*.a00) compare_alz "$(ref_file "$ref")" "$gen" ;;
        *) compare_egg "$(ref_file "$ref")" "$gen" ;;
    esac
done <<'EOF'
egg_m0_two.egg|-m0|two
egg_m1_two.egg|-m1|two
egg_m2_two.egg|-m2|two
egg_m3_two.egg|-m3|two
egg_m4_two.egg|-m4|two
egg_s_m1_two.egg|-s -m1|two
egg_s_m3_two.egg|-s -m3|two
egg_m4_sys.egg|-m4|probe.sys
egg_zip_m0_hello.egg|-m0 -tp0 -ppassword|hello.txt
egg_zip_m1_two.egg|-m1 -tp0 -ppassword|two
egg_aes256_m2_hello.egg|-m2 -tp2 -ppassword|hello.txt
egg_m1_records_v100k.vol1.egg|-m1 -v100KB|records.bin
alz_m0_hello.alz|-m0|hello.txt
alz_m1_biased_v100k.alz|-m1|biased.bin
alz_m1_code.alz|-m1|code.c
alz_m2_code.alz|-m2|code.c
alz_m0_random_v100k.alz|-m0 -v100KB|random.bin
alz_zip_m1_hello.alz|-m1 -tp0 -ppassword|hello.txt
alz_zip_m1_two.alz|-m1 -tp0 -ppassword|two
EOF

if [ "$fail" -ne 0 ]; then
    echo "lot K: at least one archive differs (generated in $out)" >&2
    exit 1
fi
echo "lot K: all 22 reference archives are reproduced by ALZipCon 12.30"
