#!/bin/sh
# cfingerd 1.4.3 (CVE-2001-0609) and the Debian security fix, from snapshot.debian.org, checked by SHA-1.
set -e
cd "$(dirname "$0")"
curl -s -o cfingerd_1.4.3.orig.tar.gz https://snapshot.debian.org/file/47f19ecf667331a480d1c29b546ab0b02dc9008f
curl -s -o cfingerd_1.4.3-1.1.diff.gz https://snapshot.debian.org/file/30a4a306db919ad8461ef16457be3f341d9f353f
echo "47f19ecf667331a480d1c29b546ab0b02dc9008f  cfingerd_1.4.3.orig.tar.gz" | shasum -c -
echo "30a4a306db919ad8461ef16457be3f341d9f353f  cfingerd_1.4.3-1.1.diff.gz" | shasum -c -
rm -rf vulnerable fixed && mkdir vulnerable fixed
tar -xzf cfingerd_1.4.3.orig.tar.gz -C vulnerable
tar -xzf cfingerd_1.4.3.orig.tar.gz -C fixed
gunzip -c cfingerd_1.4.3-1.1.diff.gz | (cd fixed/cfingerd-1.4.3 && patch -p1 -s)
