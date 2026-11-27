# Architecture

## Data flow

```
Scenario (JSON, validated)
   |  tokenscope-core::Engine::run_scenario
   v
Target adapter (tokenscope-adapter)  --builds-->  instructions + accounts
   |  uses tokenscope-executor::Harness (Mollusk SVM, real system + Token-2022 + target ELF)
   v
ExecutionTrace  (real before/after Snapshots, step statuses, program logs, compute units)
   |  tokenscope-invariants::{evaluate, classify, findings}
   v
RunRecord { outcome, findings }  ->  Campaign  ->  Report / TUI / corpus / shrinker
```

Setup problems (invalid scenario, unknown target, missing program ELF, harness failure) stop at the
adapter and become `OutcomeClass::SetupError`; they never reach the invariant engine and never
produce findings.

## Crates

| Crate | Responsibility | Depends on |
|---|---|---|
| `tokenscope-model` | Serializable, validated types: `Scenario`, `Action`, `ExecutionTrace`, `Finding`, `Campaign`, `CorpusCase`, `OutcomeClass`, `RawAccount`, `RawSnapshot`; content-derived IDs; schema versioning | serde, sha2, thiserror |
| `tokenscope-executor` | `Harness`: creates Token-2022 mints/accounts via real instructions (`MintPlan` / `MintExt` for fee, hook, default state, pausable, permanent delegate, non-transferable, close authority, interest-bearing, scaled UI), loads program ELFs (escrow, demo hook), executes with unlimited log capture, decodes real account state (frozen, paused, delegate, CPI Guard, hook counter) | mollusk-svm, spl-token-2022-interface |
| `tokenscope-adapter` | `TargetAdapter` trait (`AdapterCapabilities`, `AdapterVersion`) and `EscrowAdapter`: deploys programs, creates accounts, builds instructions, records snapshots | executor, model |
| `tokenscope-invariants` | Pure functions over traces with `InvariantLevel` classification (`GlobalSvm`, `Token2022`, `TargetSpecific`, `Custom`); core (6) and `--extended` (13) catalogs via `InvariantRegistry`; finding construction | model |
| `tokenscope-scenarios` | Core, extension, and mint-profile suites; seeded generators (`random`, `extended`, `stateful`), boundary exploration, deterministic mutation, dimension tracking and guided selection | model |
| `tokenscope-shrinker` | Generic bounded deterministic minimizer driven by a failure predicate | model |
| `tokenscope-core` | `Engine` (run, replay, minimize, campaign) and the on-disk corpus | adapter, invariants, shrinker |
| `tokenscope-report` | Versioned JSON, text, Markdown, and SARIF 2.1.0 reports; artifact files | model |
| `tokenscope-cli` | `tokenscope` binary; exit codes; no dependency on the TUI for its own commands | all of the above, `tokenscope-tui` for `tui` |
| `tokenscope-tui` | Ratatui interface: pure `App` state, worker-thread `runner`, `ui` rendering, terminal `driver` | core, report, invariants |
| `tokenscope-fuzz-harness` | Bodies of the libFuzzer targets (`fuzz/`), also run on stable by tests | all of the above (core behind the `engine` feature) |
| `programs/demo-escrow` | On-chain demo (pinocchio), separate lockfile, built by `scripts/build-programs.sh` | pinocchio 0.11.2 |
| `programs/demo-forwarder` | CPI forwarder fixture (invoke_with_slice), same build script | pinocchio 0.11.2 |
| `programs/demo-hook` | Transfer-hook fixture (counter, reject flag), same build script | pinocchio 0.11.2 |

Design rules:

* Execution logic never lives in rendering code; the TUI's `App` is pure and tested without a terminal.
* Reports, CLI output and the TUI are views of the same `Campaign` value (no timestamps in persisted
  data), which is why they cannot disagree.
* Ground truth is executed account state. The fee formula appears only in tests, as an independent
  cross-check.

## Decisions

* **Mollusk over LiteSVM for real Token-2022 execution**: TokenScope executes on-chain programs directly at the instruction level using Mollusk SVM. This eliminates transaction fee, signature, and blockhash plumbing, provides deterministic instruction-level failure atomicity, inspects raw program return codes explicitly, and uses the verified mainnet Token-2022 ELF bundled by `mollusk-svm-programs-token-2022`.
* **Native escrow with pinocchio**, no Anchor: smallest dependency surface.
* **Program kept out of the host workspace**: different toolchain (platform-tools Rust), own lockfile.
* **Scenario/finding IDs are content hashes** so artifacts are self-verifying and dedupe naturally.
* **Shrinker is generic** over a predicate: it is unit/property-tested without the SVM and driven by
  real execution in `tokenscope-core`.
* **Guided generation is input-space guided**: it tracks coverage of scenario dimensions (fee class, amount class,
  action kind, extension, pairs), never of program code; fuzz targets use real libFuzzer coverage feedback.
* **Suites are split** (`core` fee accounting, `extensions`, `profiles`, plus `all` = `core`+`extensions` and
  `full` = `core`+`extensions`+`profiles`) so the original demonstration stays unchanged and the
  permanent-delegate finding on both flavors is explicit.
* **Single failure atomicity model**: Mollusk's context persists state only for successful
  instructions, matching Solana transaction semantics for the single-instruction steps used here.

## Extension points

A new target needs: an adapter (setup, instruction builders, snapshot decoding), scenario
templates, and invariants over its trace type. The current `ExecutionTrace`/`Snapshot` types are
escrow-shaped; generalizing them is future work and is deliberately not pre-built.
