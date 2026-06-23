#!/usr/bin/env bash
# Run every language port's smoke test. Skips a port if its toolchain is absent.
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if command -v node >/dev/null 2>&1; then
  node ports/javascript/test.js
else
  echo "node: skipped (not installed)"
fi

if command -v go >/dev/null 2>&1; then
  ( cd ports/go && go test ./... )
else
  echo "go: skipped (not installed)"
fi

if command -v cargo >/dev/null 2>&1; then
  ( cd ports/rust && cargo test )
else
  echo "rust: skipped (not installed)"
fi

sh ports/shell/test.sh
