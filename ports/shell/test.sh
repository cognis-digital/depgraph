#!/usr/bin/env sh
# Smoke test for the shell port. Asserts on real output. Exit 0 = pass.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
SH="$HERE/depgraph.sh"
fail=0

req="$(mktemp)"
cat > "$req" <<'EOF'
requests==2.28.0
pillow==8.4.0
reqests==2.31.0
numpy
cryptography==42.0.0
EOF

out="$(sh "$SH" "$req")"
rm -f "$req"

assert_contains() {
  printf '%s\n' "$out" | grep -q "$1" || { echo "FAIL: expected /$1/"; fail=1; }
}

# pillow 8.4.0 is CRITICAL -> grade F
assert_contains "F     pillow"
# requests 2.28.0 is vulnerable (CVE-2023-32681)
assert_contains "CVE-2023-32681"
# reqests is a typosquat of requests
assert_contains "typosquat: reqests"
# numpy unpinned
assert_contains "unpinned: numpy"
# cryptography clean -> grade A
assert_contains "A     cryptography"
# project rollup line present
assert_contains "project: "

# fixed version must NOT be flagged as vuln
req2="$(mktemp)"
echo "requests==2.31.0" > "$req2"
out2="$(sh "$SH" "$req2")"
rm -f "$req2"
if printf '%s\n' "$out2" | grep -q "CVE-2023-32681"; then
  echo "FAIL: fixed requests 2.31.0 should not be flagged"; fail=1
fi

if [ "$fail" -eq 0 ]; then
  echo "ok - shell port smoke test passed"
else
  echo "shell port test FAILED"; exit 1
fi
