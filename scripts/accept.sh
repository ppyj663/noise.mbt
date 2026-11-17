#!/usr/bin/env bash
# Re-run the library, optional TCP, and optional oracle checks on the
# current MoonBit toolchain. Exit non-zero on failure. This script does
# not run or rewrite bench/results.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

section() { printf '\n== %s ==\n' "$1"; }

fail() {
  printf 'FAIL  %s\n' "$1" >&2
  exit 1
}

section "toolchain"
command -v moon >/dev/null || fail "moon not on PATH"
command -v moonc >/dev/null || fail "moonc not on PATH"
printf 'moon=%s\n' "$(command -v moon)"
printf 'moonc=%s\n' "$(command -v moonc)"
if [ -n "${MOONC_OVERRIDE:-}" ]; then
  printf 'MOONC_OVERRIDE=%s\n' "$MOONC_OVERRIDE"
fi
moon version --all

section "library"
moon update
moon check --deny-warn --target native
moon test --target native
moon fmt --check
moon info
moon run --target native example
moon run --target native example/pipe

moon_home="${MOON_HOME:-$HOME/.moon}"
section "tcp"
if [ -d "$moon_home/lib/core/async" ]; then
  moon -C example/tcp update
  moon -C example/tcp check --deny-warn --target native
  moon -C example/tcp test --target native --package ppyj663/noise-tcp-example
  moon -C example/tcp run --target native .
else
  printf 'SKIP  %s/lib/core/async is not present (library-only toolchain)\n' "$moon_home"
fi

section "oracle"
py=""
if [ -n "${NOISE_ORACLE_PYTHON:-}" ]; then
  py="$NOISE_ORACLE_PYTHON"
elif command -v python3 >/dev/null; then
  py="python3"
elif command -v python >/dev/null; then
  py="python"
fi

if [ -n "$py" ] && "$py" -c "import cryptography" >/dev/null 2>&1; then
  "$py" scripts/fallback_oracle.py --check
else
  echo "SKIP  Python cryptography is not available"
fi

section "done"
echo "acceptance passed"
