# Fuzzing

Targets (`fuzz/fuzz_targets/`), each a thin libFuzzer wrapper around a body in
`crates/tokenscope-fuzz-harness`:

| Target | Component | Input | Checks |
|---|---|---|---|
| `parse_scenario` | scenario parser | bytes as JSON | accepted input validates, round-trips, stable ID |
| `parse_finding` | finding parser | JSON | validates, round-trips |
| `parse_campaign` | campaign parser + report rendering | JSON | report consistent with campaign; JSON/text render; round-trips |
| `parse_corpus_case` | corpus-case parser | JSON | validates, round-trips |
| `evaluate_trace` | invariant engine on arbitrary traces | JSON trace | no panic; findings only from violations |
| `shrink_scenario` | shrinker | JSON scenario + synthetic predicate | result valid, satisfies predicate, never larger |
| `reference_model_scenario` | `TokenReferenceModel` (`tokenscope-model`) | JSON scenario | balance bounds, fee ceiling, atomic rollback |
| `replay_scenario` | real SVM execution (`--features engine`) | JSON scenario | outcome self-consistent; **not run here** (see below) |

Seeds are real engine output (`cargo run -p tokenscope-fuzz-harness --example make_seeds`) plus
regression inputs found by fuzzing (`regression-*.json`).

## Running

* Standard (nightly): `cargo +nightly fuzz run <target>` from the repository root.
* Stable compiler (what was used here, since nightly was not installable in the sandbox):
  `scripts/fuzz.sh <target> [seconds]`. It builds with the same SanitizerCoverage flags
  `cargo fuzz` uses, **without AddressSanitizer** (nightly only), and runs libFuzzer.

## Is this coverage-guided?

Yes for the parser, shrinker and invariant targets: libFuzzer reads SanitizerCoverage edge counters
and trace-compare data from the instrumented binary and uses them to select and mutate inputs
(visible as growing `cov:` / `ft:` / `corp:` in its output). It is **not** a claim about the escrow
programs themselves: no target fuzzes the on-chain code, and `scenarios::generate_guided` is
guided by *input-space* dimensions, not code coverage.

## Results actually obtained (stable compiler, no ASan, 1 vCPU, short runs)

| Target | Seconds | Executions | Edge cov (start -> end) | Corpus (start -> end) | Crashes |
|---|---|---|---|---|---|
| `parse_scenario` | 40 | 9,590,969 | 705 -> 2,291 | 23 -> 2,673 | 0 |
| `parse_finding` | 30 | 5,183,507 | 522 -> 2,291 | 6 -> 2,668 | 0 |
| `parse_campaign` | 30 | 2,442,987 | 1,229 -> 3,481 | 1 -> 2,451 | 0 |
| `parse_corpus_case` | 30 | 6,757,629 | 464 -> 1,951 | 2 -> 2,605 | 0 |
| `evaluate_trace` (after fix) | 75 | 7,918,816 | 720 -> 2,427 | 5 -> 2,959 | 0 |
| `shrink_scenario` | 30 | 7,314,932 | 539 -> 2,014 | 22 -> 2,653 | 0 |

These are minutes, not hours; they show the targets work and found one bug, not that the
components are free of bugs.

**Bug found:** the first `evaluate_trace` run crashed after ~98 thousand executions: `evaluate`
returned each step's self-reported `index` and `findings` used it to index the step list, so a
trace whose `index` fields did not match positions panicked (`index out of bounds`). Fixed by using
the step position and bounds-checked lookup; the crashing input is committed as
`corpus/evaluate_trace/regression-step-index-out-of-bounds.json` with unit tests.

`replay_scenario` executes the real SVM (about 15 scenarios/s), and an instrumented build of the
whole Agave tree was not attempted in the sandbox's disk budget, so it has **not** been fuzzed;
its body is exercised on stable by `crates/tokenscope-fuzz-harness/tests/targets.rs`.
