#!/usr/bin/env bash
# Reproducible local benchmark. Does not set a pass/fail threshold.
# Each measured item prints 2 warmup lines, 9 sample lines, and 1 summary line.
set -eu
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
out="${1:-bench/results}"
mkdir -p "$out"
source_hash="$(
  {
    git ls-files
    git ls-files --others --exclude-standard
  } | sort -u | grep -v '^bench/results/' | while read -r path; do
    if [ -f "$path" ]; then
      sha256sum "$path"
    fi
  done | sha256sum | awk '{print $1}'
)"
moon run --target native --release bench > "$out/samples.jsonl"
{
  echo "{"
  echo "  \"commit\": \"$(git rev-parse HEAD)\","
  if [ -n "$(git status --porcelain)" ]; then dirty=true; else dirty=false; fi
  echo "  \"dirty\": $dirty,"
  echo "  \"date_utc\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\","
  echo "  \"moon\": \"$(moon version | head -1)\","
  echo "  \"moonc\": \"$(moon version --all | awk '/^moonc /{print; exit}')\","
  echo "  \"target\": \"native\","
  echo "  \"optimize\": \"release\","
  echo "  \"os\": \"$(uname -srm)\","
  echo "  \"cpu\": \"$(awk -F: '/model name/{print $2; exit}' /proc/cpuinfo | sed 's/^ //')\","
  echo "  \"clock\": \"moonbitlang/core/bench monotonic_clock, microseconds\","
  echo "  \"warmup\": 2,"
  echo "  \"samples\": 9,"
  echo "  \"source_tree_sha256\": \"$source_hash\","
  echo "  \"patch_sha256\": \"recorded in the verification log after the patch is sealed\","
  echo "  \"keys\": \"fixed labels hashed with SHA-256; not for production\""
  echo "}"
} > "$out/meta.json"
echo "wrote $out/samples.jsonl and $out/meta.json"
wc -c "$out/samples.jsonl"
awk -F'"kind":"' '{print $2}' "$out/samples.jsonl" | awk -F'"' '{print $1}' | sort | uniq -c
