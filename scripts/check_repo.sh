#!/usr/bin/env bash
# Local OSC2026 repository self-check. Does not publish or contact GitHub
# beyond reading the already configured remote.
set -u

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

fail=0
warn=0

ok() { printf 'PASS  %s\n' "$1"; }
bad() { printf 'FAIL  %s\n' "$1"; fail=$((fail + 1)); }
note() { printf 'WARN  %s\n' "$1"; warn=$((warn + 1)); }

echo "== structure =="
if git ls-files | grep -E '(^|/)_build/|(^|/)\.mooncakes/|pkg\.generated\.mbti' >/dev/null; then
  bad "tracked build cache or generated interface"
else
  ok "no tracked _build, .mooncakes, or pkg.generated.mbti"
fi
for f in README.md LICENSE moon.mod moon.pkg source-attribution.md CHANGELOG.md .gitignore .github/workflows/ci.yml example/main.mbt; do
  if [ -f "$f" ]; then
    ok "present $f"
  else
    bad "missing $f"
  fi
done

echo "== license =="
if grep -q "Apache License" LICENSE && grep -q 'license = "Apache-2.0"' moon.mod; then
  ok "root LICENSE and moon.mod both say Apache-2.0"
else
  bad "LICENSE and moon.mod disagree or are not Apache-2.0"
fi

echo "== readme and attribution =="
for needle in "snow" "mooncry" "Apache-2.0" "Cacophony" "moon test" "moon run example"; do
  if grep -q "$needle" README.md; then
    ok "README mentions $needle"
  else
    bad "README missing $needle"
  fi
done
for needle in "github.com/mcginty/snow" "Apache-2.0 OR MIT" "cc06b/mooncry" "centromere/cacophony" "Unlicense" "RFC 7693"; do
  if grep -q "$needle" source-attribution.md; then
    ok "source-attribution mentions $needle"
  else
    bad "source-attribution missing $needle"
  fi
done

echo "== commits =="
count="$(git rev-list --count HEAD)"
echo "     commits on HEAD: $count"
authors="$(git log --format='%an <%ae>' | sort | uniq)"
printf '%s\n' "$authors" | sed 's/^/     /'
if git log --format='%b' | grep -qi 'Co-authored-by:'; then
  bad "commit message contains Co-authored-by"
else
  ok "no Co-authored-by trailers"
fi
if [ "$count" -lt 10 ]; then
  note "fewer than 10 commits; the charter sample asks for 10-20 effective commits"
fi

echo "== remote default branch =="
if git rev-parse --abbrev-ref origin/HEAD >/dev/null 2>&1; then
  default="$(git rev-parse --abbrev-ref origin/HEAD)"
  default="${default#origin/}"
  echo "     origin HEAD: $default"
  if git merge-base --is-ancestor HEAD "origin/$default" 2>/dev/null; then
    ok "HEAD is contained in origin/$default"
  else
    bad "HEAD is not on the remote default branch origin/$default"
  fi
else
  note "origin/HEAD is not set; run git remote show origin"
fi

echo "== MoonBit source scale =="
python3 - << 'PY'
import subprocess
files = [p for p in subprocess.check_output(["git", "ls-files", "*.mbt"], text=True).split() if p]
def classify(path):
    if path == "vectors_data.mbt":
        return "embedded-vectors"
    if path.endswith("_wbtest.mbt") or path.endswith("_test.mbt"):
        return "test"
    if path.startswith("example/"):
        return "example"
    return "impl"
counts = {k: [0, 0] for k in ("impl", "test", "example", "embedded-vectors")}
for path in files:
    kind = classify(path)
    for line in open(path, encoding="utf-8"):
        counts[kind][0] += 1
        stripped = line.strip()
        if stripped and not stripped.startswith("///") and not stripped.startswith("//"):
            counts[kind][1] += 1
print("     kind                 raw  effective")
total_raw = total_eff = 0
for kind in ("impl", "test", "example", "embedded-vectors"):
    raw, eff = counts[kind]
    total_raw += raw
    total_eff += eff
    print(f"     {kind:20} {raw:5} {eff:5}")
print(f"     {'total':20} {total_raw:5} {total_eff:5}")
impl_eff = counts["impl"][1]
print(f"     implementation effective lines: {impl_eff}")
print("     charter reference range: 4000-10000 effective MoonBit lines")
if impl_eff < 4000:
    print("     NOTE: below the 4k reference; the charter treats this as a range, not a hard cutoff")
PY

echo "== summary =="
echo "fail=$fail warn=$warn"
exit "$fail"
