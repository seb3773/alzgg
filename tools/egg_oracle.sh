#!/bin/sh
# Local ALZip oracle (development aid, outside `make test`).
#
#   tools/egg_oracle.sh PROFILE OUT.egg ENTRY...
#
# PROFILE is ALZipCon's `-m` value: 0 (none), 1 (normal), 3 (ratio),
# 4 (optimized). The entries are copied into the Wine prefix under their own
# base name — that name is what the archive stores, and it is what decides
# routing by extension, which `alz create` must reproduce — then passed in a
# single invocation, in the order given.
#
# This script stays wired to the 8.0.0.18 install (`_work/binaries/alzip-8.0`), the reference
# of the historical corpus; for the 12.30 write reference, use
# `tools/alz_oracle.sh` (install under `_work/binaries/alzip-12.30`).
#
# The Wine prefix lives in /tmp/azowine (EGG_ORACLE_WORK moves it).
set -e

if [ $# -lt 3 ]; then
    echo "usage: $0 PROFILE OUT.egg ENTRY..." >&2
    exit 2
fi

prof=$1
out=$2
shift 2
repo=$(cd "$(dirname "$0")/.." && pwd)
alzip="${ALZIP_80_DIR:-$repo/_work/binaries/alzip-8.0}"
[ -d "$alzip" ] || alzip="$repo/research/Program Files (x86)/ALZip"
work=${EGG_ORACLE_WORK:-/tmp/azowine}

command -v wine >/dev/null 2>&1 || {
    echo "$0: wine is required (development oracle only)" >&2
    exit 1
}
[ -d "$alzip" ] || {
    echo "$0: reference copy not found: $alzip" >&2
    exit 1
}

rm -rf "$work/stage"
rm -f "$work/out.egg"
mkdir -p "$work/stage"
[ -d "$work/alzip" ] || cp -r "$alzip" "$work/alzip"

# Names are kept as they are; two entries with the same base name in different
# directories would be a conflict, so we reject it rather than let Wine
# silently overwrite one entry.
list=
for src in "$@"; do
    base=$(basename "$src")
    [ -e "$work/stage/$base" ] && {
        echo "$0: duplicate base name: $base" >&2
        exit 2
    }
    # A directory is accepted: it is the only measured way to get a
    # multi-member archive from this build (`-a` rejects a comma-separated list
    # under Wine, and adding to an existing archive fails too).
    if [ -d "$src" ]; then cp -r "$src" "$work/stage/$base"; else cp "$src" "$work/stage/$base"; fi
    win=$(printf 'Z:%s' "$work/stage/$base" | sed 's#/#\\#g')
    if [ -z "$list" ]; then list=$win; else list=$list,$win; fi
done

cd "$work/alzip"
win_out=$(printf 'Z:%s' "$work/out.egg" | sed 's#/#\\#g')
win_in=$list

WINEPREFIX="$work/prefix" WINEDEBUG=-all timeout 300 wine ALZipCon.exe \
    -a -m"$prof" "$win_in" "$win_out" >"$work/log.txt" 2>&1 || true

[ -f "$work/out.egg" ] || {
    echo "$0: ALZipCon produced nothing (see $work/log.txt)" >&2
    exit 1
}
mv "$work/out.egg" "$out"
echo "$out"
