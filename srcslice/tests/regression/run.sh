#!/bin/bash
# Regression tests: slice each case with srcSlice and compare against its expected.tsv.
# Usage: tests/regression/run.sh [path/to/srcSlice] [path/to/srcml]
here="$(cd "$(dirname "$0")" && pwd)"
slicer="${1:-srcSlice}"
srcml="${2:-srcml}"
work="$(mktemp -d)"
trap 'rm -r "$work"' EXIT
failed=0
for case in "$here"/*/; do
    name="$(basename "$case")"
    (cd "$case" && "$srcml" --position src -o "$work/$name.xml") || { echo "FAIL $name: srcml"; failed=1; continue; }
    result="$(python3 "$here/check.py" "$slicer" "$work/$name.xml" "$case/expected.tsv")"
    echo "$name: $(echo "$result" | tail -1)"
    echo "$result" | grep '^FAIL' && failed=1
done
exit $failed
