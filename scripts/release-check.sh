#!/bin/sh
# Exercise every `tokenscope` command and documented exit code against a built binary.
#
# usage: scripts/release-check.sh [path-to-tokenscope]     (default: target/release/tokenscope)
# Needs the programs built (scripts/build-programs.sh). Exits non-zero if any check fails.
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
BIN=${1:-"$ROOT/target/release/tokenscope"}
[ -x "$BIN" ] || [ ! -x "$BIN.exe" ] || BIN="$BIN.exe"
[ -x "$BIN" ] || { echo "binary not found: $BIN" >&2; exit 2; }
export TOKENSCOPE_PROGRAM_DIR=${TOKENSCOPE_PROGRAM_DIR:-"$ROOT/target/sbf-programs"}
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
FAIL=0; N=0

expect() { # expect <code> <description> -- <args...>
  want=$1; desc=$2; shift 3
  N=$((N+1))
  "$BIN" "$@" >"$W/out" 2>"$W/err"; got=$?
  if [ "$got" -eq "$want" ]; then echo "[ok]   exit $got  $desc"; else
    echo "[FAIL] exit $got (want $want)  $desc"; head -c 400 "$W/err"; FAIL=$((FAIL+1)); fi
}
expect_either() { # expect_either "<code> <code>" <description> -- <args...>
  want=$1; desc=$2; shift 3
  N=$((N+1))
  "$BIN" "$@" >"$W/out" 2>"$W/err"; got=$?
  case " $want " in *" $got "*) echo "[ok]   exit $got  $desc (either of: $want)";; *)
    echo "[FAIL] exit $got (want one of: $want)  $desc"; head -c 400 "$W/err"; FAIL=$((FAIL+1));; esac
}
contains() { # contains <file> <text> <description>
  N=$((N+1))
  if grep -q -- "$2" "$1"; then echo "[ok]   output contains '$2'  ($3)"; else echo "[FAIL] output lacks '$2'  ($3)"; FAIL=$((FAIL+1)); fi
}

echo "binary: $BIN ($("$BIN" --version))"
expect 0 "doctor" -- doctor;                                     contains "$W/out" "environment OK" doctor
expect 0 "inspect" -- inspect;                                   contains "$W/out" "INV-CUST-001" inspect
expect 0 "inspect one target" -- inspect --target demo-escrow-corrected
expect 2 "inspect unknown target" -- inspect --target nope
expect 0 "--help" -- --help
expect 0 "--version" -- --version
expect 2 "unknown subcommand" -- frobnicate
expect 2 "run without target" -- run

expect 0 "run corrected, core suite" -- run --target demo-escrow-corrected --count 0 --out "$W/o1"
expect 1 "run vulnerable, core suite (violations)" -- run --target demo-escrow-vulnerable --count 0 --out "$W/o2"
V=$(ls "$W/o2" | head -1)
expect 1 "run both flavors" -- run --target demo-escrow --count 0 --out "$W/o3"
expect 1 "run extensions suite (custody finding)" -- run --target demo-escrow-corrected --suite extensions --count 0 --out "$W/o4"
expect_either "0 1" "run guided strategy (a batch need not contain a violation)" -- run --target demo-escrow-vulnerable --no-suite --count 6 --strategy guided --out "$W/o5"
expect 0 "run extended strategy, corrected, 1 scenario" -- run --target demo-escrow-corrected --no-suite --count 1 --strategy extended --seed 4 --out "$W/o6"
expect 0 "run stateful strategy, corrected, 1 scenario" -- run --target demo-escrow-corrected --no-suite --count 1 --strategy stateful --seed 5 --out "$W/o6s"
expect 2 "run with bad suite" -- run --target demo-escrow-vulnerable --suite nope
expect 2 "run with nothing to run" -- run --target demo-escrow-vulnerable --no-suite --count 0

printf '{"schema_version":1,"target":"demo-escrow-corrected","seed":1,"generated":2,"suite":"none"}' >"$W/cfg.json"
expect 0 "run --config" -- run --config "$W/cfg.json" --out "$W/o8"
printf '{not json' >"$W/bad.json"
expect 2 "run --config malformed" -- run --config "$W/bad.json"

F=$(ls "$W/o2/$V/findings" | head -1); S=$(ls "$W/o2/$V/scenarios" | head -1)
expect 1 "replay a violating scenario" -- replay "$W/o2/$V/scenarios/$S"
expect 2 "replay missing file" -- replay "$W/nope.json"
expect 0 "minimize a finding" -- minimize "$W/o2/$V/findings/$F" --out "$W/min.json"
expect 2 "minimize malformed finding" -- minimize "$W/bad.json"
expect 0 "report json" -- report "$V" --format json --out "$W/o2";   contains "$W/out" '"totals"' "report json"
expect 0 "report text" -- report "$V" --format text --out "$W/o2";   contains "$W/out" "invariant violations" "report text"
expect 0 "report markdown" -- report "$V" --format markdown --out "$W/o2"; contains "$W/out" "# TokenScope Campaign Report" "report markdown"
expect 0 "report sarif" -- report "$V" --format sarif --out "$W/o2"; contains "$W/out" '"$schema"' "report sarif"
expect 2 "report unknown id" -- report cp_0000000000000000 --out "$W/o2"
expect 2 "report invalid id" -- report "../etc/passwd" --out "$W/o2"

CORP="$ROOT/fixtures/corpus"
expect 0 "corpus list" -- corpus list --corpus "$CORP"
expect 0 "corpus replay --all" -- corpus replay --all --corpus "$CORP"
expect 0 "corpus add (temp corpus)" -- corpus add "$ROOT/fixtures/scenarios/fee-loss-min-vulnerable.json" --description "release check" --corpus "$W/corpus"
expect 0 "corpus replay one" -- corpus replay "$(ls "$W/corpus" | head -1 | sed 's/\.json$//')" --corpus "$W/corpus"
sed 's/"outcome": "invariant_violation"/"outcome": "pass"/' "$W/corpus/$(ls "$W/corpus" | head -1)" >"$W/tampered.json"
mkdir "$W/tcorpus" && cp "$W/tampered.json" "$W/tcorpus/$(ls "$W/corpus" | head -1)"
expect 4 "corpus replay detects a regression" -- corpus replay --all --corpus "$W/tcorpus"
expect 2 "corpus replay unknown case" -- corpus replay rc_unknown --corpus "$CORP"
expect 2 "corpus replay on an empty corpus" -- corpus replay --all --corpus "$W/empty"

expect 0 "tui --snapshot dashboard" -- tui --snapshot dashboard --target demo-escrow-corrected
expect 0 "tui --snapshot findings (vulnerable)" -- tui --snapshot findings --target demo-escrow-vulnerable; contains "$W/out" "INV-ACCT-001" "tui findings"
expect 2 "tui --snapshot unknown screen" -- tui --snapshot nonsense
expect 2 "tui with both flavors" -- tui --target demo-escrow --snapshot help

# Generic SBF specs: elf_path is relative to the repository root.
cd "$ROOT"
EX="examples/generic-sbf"
expect 1 "sbf-run vulnerable example (check fails)" -- sbf-run --spec "$EX/escrow-vulnerable.json" --format text --sarif "$W/sbf.sarif"
contains "$W/out" "INV-ACCT-001" "sbf-run finding"
contains "$W/sbf.sarif" '"version": "2.1.0"' "sbf-run sarif"
expect 0 "sbf-run corrected example" -- sbf-run --spec "$EX/escrow-corrected.json"
contains "$W/out" '"findings": \[\]' "sbf-run json output"
expect 2 "sbf-run unknown format" -- sbf-run --spec "$EX/escrow-corrected.json" --format xml
expect 2 "sbf-run missing spec" -- sbf-run --spec "$W/nope.json"
expect 2 "sbf-run malformed spec" -- sbf-run --spec "$W/bad.json"
sed 's#target/sbf-programs/demo_escrow_corrected.so#target/sbf-programs/missing.so#' "$EX/escrow-corrected.json" >"$W/noelf.json"
expect 3 "sbf-run with a missing program" -- sbf-run --spec "$W/noelf.json"
N=$((N+1)); printf '{"op":"shutdown","id":1}\n' | "$BIN" sbf-session >"$W/out" 2>"$W/err"; got=$?
if [ "$got" -eq 0 ] && grep -q '"ok":true' "$W/out"; then echo "[ok]   exit 0  sbf-session shutdown"; else echo "[FAIL] exit $got  sbf-session shutdown"; FAIL=$((FAIL+1)); fi

# Setup-error exit code needs the program directory override, run it explicitly.
N=$((N+1)); TOKENSCOPE_PROGRAM_DIR=/nonexistent "$BIN" run --target demo-escrow-corrected --no-suite --count 1 --out "$W/o9" >"$W/out" 2>"$W/err"; got=$?
if [ "$got" -eq 3 ]; then echo "[ok]   exit 3  run with missing programs (explicit override)"; else echo "[FAIL] exit $got (want 3)  missing programs"; FAIL=$((FAIL+1)); fi
N=$((N+1)); TOKENSCOPE_PROGRAM_DIR=/nonexistent "$BIN" doctor >"$W/out" 2>&1; got=$?
if [ "$got" -eq 3 ]; then echo "[ok]   exit 3  doctor with missing programs"; else echo "[FAIL] exit $got (want 3)  doctor"; FAIL=$((FAIL+1)); fi

echo "$((N-FAIL))/$N checks passed"
[ "$FAIL" -eq 0 ]
