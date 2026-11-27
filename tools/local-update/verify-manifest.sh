#!/bin/sh
set -eu
export LC_ALL=C
test "$#" = 3 || exit 78
dir=$1
key=$2
floor=$3
for f in manifest.txt manifest.sig tachyon; do
    test -f "$dir/$f" && test ! -L "$dir/$f" || exit 78
done
test -f "$key" && test ! -L "$key" || exit 78
test "$(wc -c <"$dir/manifest.txt")" -le 2048 || exit 78
test "$(wc -c <"$dir/manifest.sig")" -le 2048 || exit 78
usign -V -p "$key" -m "$dir/manifest.txt" -x "$dir/manifest.sig" >/dev/null 2>&1 || exit 78
# A fixed ordered schema avoids eval, sourcing, URL injection, and duplicate fields.
awk -v floor="$floor" '
BEGIN { ok=1; if (floor !~ /^(0|[1-9][0-9]*)$/ || length(floor)>9) ok=0 }
NR==1 { if ($0!="schema=1") ok=0 }
NR==2 { if ($0!="channel=stable") ok=0 }
NR==3 { if ($0!="arch=aarch64-musl") ok=0 }
NR==4 { s=substr($0,10); if ($0 !~ /^sequence=[1-9][0-9]*$/ || length(s)>9 || s+0<=floor+0) ok=0 }
NR==5 { s=substr($0,17); if ($0 !~ /^upstream_commit=[0-9a-f]+$/ || length(s)!=40) ok=0 }
NR==6 { s=substr($0,16); if ($0 !~ /^adapter_commit=[0-9a-f]+$/ || length(s)!=40) ok=0 }
NR==7 { s=substr($0,8); if ($0 !~ /^sha256=[0-9a-f]+$/ || length(s)!=64) ok=0 }
NR==8 { s=substr($0,7); if ($0 !~ /^bytes=[1-9][0-9]*$/ || length(s)>8 || s+0>16777216) ok=0 }
END { if (NR!=8 || !ok) exit 78 }
' "$dir/manifest.txt" || exit 78
hash=$(sed -n '7s/^sha256=//p' "$dir/manifest.txt")
bytes=$(sed -n '8s/^bytes=//p' "$dir/manifest.txt")
test "$(wc -c <"$dir/tachyon")" -eq "$bytes" || exit 78
test "$(sha256sum "$dir/tachyon" | cut -d' ' -f1)" = "$hash" || exit 78
echo VERIFIED_MANIFEST_AND_PAYLOAD_ONLY
