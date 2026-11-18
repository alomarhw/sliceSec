#!/bin/bash
# Points-to regression tests: each case's facts (Andersen, --tsv) must equal its expected.tsv exactly.
# Usage: tests/regression/run.sh [path/to/srcptr] [path/to/srcml]
here="$(cd "$(dirname "$0")" && pwd)"; ptr="${1:-srcptr}"; srcml="${2:-srcml}"; work="$(mktemp -d)"; trap 'rm -r "$work"' EXIT
failed=0
for case in "$here"/*/; do
    name="$(basename "$case")"
    (cd "$case" && "$srcml" --position *.c -o "$work/$name.xml") || { echo "FAIL $name: srcml"; failed=1; continue; }
    "$ptr" -i "$work/$name.xml" -a --tsv | awk -F'\t' 'NF>=8 {print $2"\t"$3"\t"$6"\t"$7}' | sort > "$work/$name.got"
    grep -v '^#' "$case/expected.tsv" | sort > "$work/$name.want"
    if diff -q "$work/$name.want" "$work/$name.got" >/dev/null; then echo "$name: $(wc -l < "$work/$name.want" | tr -d ' ') facts pass"
    else echo "FAIL $name"; diff "$work/$name.want" "$work/$name.got"; failed=1; fi
done
exit $failed
