#!/bin/sh
# Live demo: build a third-party program (the Solana Foundation Anchor escrow in demo/escrow-anchor,
# unmodified) and check it with `tokenscope sbf-run` against the specs in demo/specs.
#
# usage: scripts/run-live-demo.sh [path-to-tokenscope]     (default: target/release/tokenscope)
# Requires cargo-build-sbf 4.5.0 and platform-tools v1.58 (see scripts/build-programs.sh).
# Every spec in demo/specs must report findings (exit 1), the rule IDs found must equal
# demo/expected-findings.txt, and every control run in demo/control (no transfer fee) must pass all
# its checks (exit 0); any other outcome is a regression and exits non-zero.
# Output: target/demo/escrow.so and target/demo/results/<spec>.{txt,sarif}.
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
BIN=${1:-"$ROOT/target/release/tokenscope"}
[ -x "$BIN" ] || [ ! -x "$BIN.exe" ] || BIN="$BIN.exe"
[ -x "$BIN" ] || { echo "binary not found: $BIN" >&2; exit 2; }
PT="${TOKENSCOPE_PLATFORM_TOOLS:-$HOME/.cache/solana/v1.58/platform-tools}"
[ -x "$PT/rust/bin/rustc" ] || { echo "platform-tools not found at $PT (see docs/toolchain.md)" >&2; exit 2; }
OUT="$ROOT/target/demo"
mkdir -p "$OUT/results"
unset RUSTFLAGS

(cd "$ROOT/demo/escrow-anchor/programs/escrow" && \
  PATH="$PT/rust/bin:$PATH" RUSTC="$PT/rust/bin/rustc" \
  cargo-build-sbf --no-rustup-override --skip-tools-install --tools-version v1.58 \
    --sbf-out-dir "$OUT" >&2)
echo "built $OUT/escrow.so"

# Spec paths (elf_path, source locations) are relative to the repository root.
cd "$ROOT"
: >"$OUT/found.txt"
for spec in demo/specs/*.json; do
  name=$(basename "$spec" .json)
  set +e
  "$BIN" sbf-run --spec "$spec" --format text --sarif "$OUT/results/$name.sarif" >"$OUT/results/$name.txt"
  rc=$?
  set -e
  echo "== $name (exit $rc)"
  cat "$OUT/results/$name.txt"
  [ "$rc" -eq 1 ] || { echo "expected findings (exit 1) from $spec, got exit $rc" >&2; exit 1; }
  grep -E '^[A-Z0-9-]+ \[(error|warning|note)\]' "$OUT/results/$name.txt" | cut -d' ' -f1 >>"$OUT/found.txt"
done

# Control runs: same program and calls with plain mints (no transfer fee). Every check must hold,
# so a finding here means TokenScope flags a correct flow.
for spec in demo/control/*.json; do
  name=$(basename "$spec" .json)
  set +e
  "$BIN" sbf-run --spec "$spec" --format text --sarif "$OUT/results/$name.sarif" >"$OUT/results/$name.txt"
  rc=$?
  set -e
  echo "== control $name (exit $rc)"
  cat "$OUT/results/$name.txt"
  [ "$rc" -eq 0 ] || { echo "control run $spec must pass every check, got exit $rc" >&2; exit 1; }
done

LC_ALL=C sort "$OUT/found.txt" >"$OUT/found.sorted.txt"
if diff -u "$ROOT/demo/expected-findings.txt" "$OUT/found.sorted.txt"; then
  echo "live demo: TokenScope reported exactly the expected findings ($(wc -l <"$OUT/found.sorted.txt" | tr -d ' '))"
else
  echo "live demo: findings differ from demo/expected-findings.txt" >&2
  exit 1
fi
