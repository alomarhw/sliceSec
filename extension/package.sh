#!/bin/sh
# Package the extension with the analysis package inside (backend/slicesec), so installing the .vsix needs no
# pip install. srcML and the enhanced srcSlice must still be on PATH (see the top-level README).
set -e
cd "$(dirname "$0")"
rm -rf backend && mkdir backend
cp -R ../slicesec/slicesec backend/slicesec
find backend -name __pycache__ -prune -exec rm -rf {} +
version=$(node -p "require('./package.json').version")
npx --yes @vscode/vsce@3.2.1 package --no-dependencies -o "slicesec-$version.vsix"
rm -rf backend
