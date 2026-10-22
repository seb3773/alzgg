#!/bin/sh
# Local ALZip oracle (development aid, outside `make test`).
#
#   tools/alz_oracle.sh [-r 8] [--work DIR] OUTPUT [OPTIONS…] ENTRIES…
#
# OUTPUT is the archive name passed to ALZipCon (`-a` is added by the script).
# With `-v`, ALZip appends `.vol1.egg` / `.a00` itself: pass the stem
# (`…_v100k.egg`), not a volume name. OPTIONS are forwarded as they are
# (`-m1`, `-s`, `-v100KB`, `-tp0`, `-ppassword`, …); the ENTRIES that follow
# are copied into a work area under their own base name — that name is what the
# archive stores and what decides routing by extension. Two entries with the
# same base name are rejected rather than silently overwritten.
#
# Default reference: ALZip 12.30 (`_work/binaries/alzip-12.30`, console install
# placed locally). `-r 8` switches to the 8.0.0.18 install in `_work/binaries/alzip-8.0`,
# which remains the reference of the 8.0 corpus — for reading, and for
# regenerating its own archives (the project writer follows the 12.30 scale).
#
# The Wine prefix, the install copy and the entry area live under
# `out/oracle-<ref>` (never in /tmp); `--work` moves them.
#
# Examples:
#   tools/alz_oracle.sh /tmp/x.egg -m2 corpus/hello.txt
#   tools/alz_oracle.sh packed_egg/egg_m1_two.egg -m1 out/lot-k-stage/two
set -e

repo=$(cd "$(dirname "$0")/.." && pwd)
ref=12
work=

usage() {
    sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//' >&2
    exit 2
}

while [ $# -gt 0 ]; do
    case "$1" in
        -r|--ref)  [ $# -ge 2 ] || usage; ref=$2; shift 2 ;;
        --work)    [ $# -ge 2 ] || usage; work=$2; shift 2 ;;
        -h|--help) usage ;;
        --)        shift; break ;;
        *)         break ;;
    esac
done

[ $# -ge 2 ] || usage
out=$1
shift

opts=
while [ $# -gt 0 ]; do
    case "$1" in
        --) shift; break ;;
        -*) opts="$opts $1"; shift ;;
        *)  break ;;
    esac
done
[ $# -ge 1 ] || usage

case $ref in
    12)
        inst="${ALZIP_1230_DIR:-$repo/_work/binaries/alzip-12.30}"
        [ -d "$inst" ] || inst="$repo/vendor/alzip-12.30"
        ;;
    8)
        inst="${ALZIP_80_DIR:-$repo/_work/binaries/alzip-8.0}"
        [ -d "$inst" ] || inst="$repo/research/Program Files (x86)/ALZip"
        ;;
    *)  echo "$0: unknown reference '$ref' (12 or 8)" >&2; exit 2 ;;
esac
[ -d "$inst" ] || {
    echo "$0: reference install not found: $inst" >&2
    exit 1
}
command -v wine >/dev/null 2>&1 || {
    echo "$0: wine is required (development oracle only)" >&2
    exit 1
}

work=${work:-$repo/out/oracle-$ref}
prefix=$work/prefix
stage=$work/stage
outdir=$work/out

mkdir -p "$work"
if [ ! -f "$work/install/.copied" ]; then
    rm -rf "$work/install"
    cp -R "$inst" "$work/install"
    : > "$work/install/.copied"
fi

rm -rf "$stage" "$outdir"
mkdir -p "$stage" "$outdir"

list=
for src in "$@"; do
    base=$(basename "$src")
    [ -e "$stage/$base" ] && {
        echo "$0: duplicate base name: $base" >&2
        exit 2
    }
    if [ -d "$src" ]; then cp -Rp "$src" "$stage/$base"; else cp -p "$src" "$stage/$base"; fi
    win=$(printf 'Z:%s' "$stage/$base" | sed 's#/#\\#g')
    list=${list:+$list,}$win
done

mkdir -p "$(dirname "$out")"
win_out=$(printf 'Z:%s' "$outdir/$(basename "$out")" | sed 's#/#\\#g')

cd "$work/install"
set +e
env -u LD_PRELOAD WINEPREFIX="$prefix" WINEDEBUG=-all \
    WINEDLLOVERRIDES="mscoree,mshtml=" timeout 600 \
    wine ALZipCon.exe -a $opts "$list" "$win_out" >"$work/log.txt" 2>&1
set -e

copied=0
for f in "$outdir"/*; do
    [ -e "$f" ] || continue
    base=$(basename "$f")
    cp "$f" "$(dirname "$out")/$base"
    echo "$(dirname "$out")/$base"
    copied=1
done

[ "$copied" -eq 1 ] || {
    echo "$0: ALZipCon produced nothing (see $work/log.txt)" >&2
    tail -5 "$work/log.txt" >&2 || true
    exit 1
}
