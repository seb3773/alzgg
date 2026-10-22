#!/bin/sh
# Generates the 12.30 references described by `fixtures/corpus-12.30.manifest`.
#
#   fixtures/build-12.30.sh [--out DIR]
#
# Each manifest line is an ALZipCon 12.30 invocation through
# `tools/alz_oracle.sh` (install under `_work/binaries/alzip-12.30`, Wine prefix
# under `out/`). The special inputs are staged here:
#   two/     hello.txt + code.c
#   meta/    the lot D files (attributes and dates)
#   unicode/ the non-ASCII tree of corpus_probe (moved into corpus/ eventually)
#   routes/  the 148 names of the routing matrix, 4 096 bytes each
# The `probe.*` files (AZO/LZMA) still come from corpus_probe/ until the source
# consolidation is done.
#
# The default output is `out/corpus-12.30/`; the volume names are the ones
# ALZip appends (`.vol1.egg`, `.a00`) for the lines with `-v`.
set -e

repo=$(cd "$(dirname "$0")/.." && pwd)
cd "$repo"
out=$repo/out/corpus-12.30
case ${1:-} in
    --out) [ $# -ge 2 ] || { echo "$0: --out expects a directory" >&2; exit 2; }
           out=$2; shift 2 ;;
    '')    ;;
    *)     echo "$0: unknown argument '$1'" >&2; exit 2 ;;
esac
manifest=$repo/fixtures/corpus-12.30.manifest
oracle=$repo/tools/alz_oracle.sh
stage=$out/stage

[ -x "$oracle" ] || { echo "$0: $oracle missing" >&2; exit 1; }
[ -f "$manifest" ] || { echo "$0: $manifest missing" >&2; exit 1; }

rm -rf "$out"
mkdir -p "$stage/two" "$stage/meta" "$stage/routes"
cp -p corpus/hello.txt corpus/code.c "$stage/two/"
cp -Rp corpus/meta/. "$stage/meta/"
cp -Rp corpus/unicode "$stage/unicode"
# `probe.com` is the same payload as `probe.sys` under another extension
# (AZO route).
cp -p corpus/probe.sys "$stage/probe.com"

# The routing-matrix names are read back from the archive that describes them
# (no name is copied by hand), and each member gets the first 4 096 bytes of
# corpus/eng.txt, like the reference.
python3 - "$stage/routes" <<'PY'
import os, sys
sys.path.insert(0, 'tools')
import egg_dump

dest = sys.argv[1]
content = open('corpus/eng.txt', 'rb').read()[:4096]
for entry in egg_dump.parse('packed_egg_8.0/routes_optimized.egg')['files']:
    if entry.get('kind') != 'file':
        continue
    # Reference members carry the `routes/` prefix (the staged directory); we
    # strip it here, ALZip puts it back when archiving `stage/routes`.
    name = entry['name']
    if name.startswith('routes/'):
        name = name[len('routes/'):]
    path = os.path.join(dest, name)
    os.makedirs(os.path.dirname(path) or dest, exist_ok=True)
    with open(path, 'wb') as f:
        f.write(content)
print(f'{len(os.listdir(dest))} routing members staged')
PY

produced=0
failed=
while IFS='|' read -r dest opts inputs; do
    case $dest in ''|'#'*) continue ;; esac
    mkdir -p "$out/$(dirname "$dest")"
    # A `-v` line names its FIRST volume (`.vol1.egg`), but ALZipCon appends the
    # volume suffix itself: it must receive the stem, not the volume name.
    case $dest in
        *.vol1.egg) gen=$out/${dest%.vol1.egg}.egg ;;
        *)          gen=$out/$dest ;;
    esac

    args=
    for input in $inputs; do
        case $input in
            two|meta|unicode|routes) path=$stage/$input ;;
            corpus/probe.com)        path=$stage/probe.com ;;
            corpus/probe.*)          path=corpus/${input#corpus/} ;;
            *)                       path=$repo/$input ;;
        esac
        [ -e "$path" ] || { echo "missing: $path" >&2; exit 1; }
        args="$args $path"
    done

    if "$oracle" "$gen" $opts $args >/dev/null; then
        produced=$((produced + 1))
    else
        failed="$failed $dest"
    fi
done < "$manifest"

[ -z "$failed" ] || {
    echo "failures:$failed" >&2
    exit 1
}
echo "12.30: $produced entries generated in $out"
