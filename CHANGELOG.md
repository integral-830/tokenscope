# Changelog

All notable changes to TokenScope are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
* **Extended invariants (`--extended`, 13 total):**
  * Added 3 DeFi/math invariants (`INV-ZERO-001` dust/zero truncation, `INV-DILUT-001` asset-to-liability dilution, `INV-SYMM-001` asymmetric vault drains) and 4 Token-2022 policy invariants (`INV-PAUSE-001`, `INV-FREEZE-001`, `INV-CPI-001`, `INV-HOOK-001`).
  * Added `extended_catalog()`, `InvariantRegistry::with_extended_invariants()`, `Engine::with_extended_invariants()`, and `--extended` CLI flag across `inspect`, `run`, `replay`, `minimize`, `tui`, and `RunConfig`.
* **Combined mint profiles (`--suite profiles` / `--suite full`):**
  * Added 5 multi-extension mint profile scenarios (`mint_profile_suite`) testing composite RWA interactions (`TransferFeeConfig`, `Pausable`, `DefaultAccountState`, `PermanentDelegate`, `CpiGuard`, `TransferHook`).
* **Interactive TUI extended mode:**
  * Added `--extended` flag and `x` hotkey to toggle between 6 core and 13 extended invariants live in `tokenscope-tui`.
  * Updated `Dashboard`, `Scenarios`, `Token`, `Invariants`, `Reports`, and `Help` screens to render mint extensions, active registry evaluations/levels, and Markdown/SARIF artifact paths.

## [0.1.0] - 2026-11-19

### Added

#### Round 3: Extension Operations and Runtime Semantics
* **Transfer fee operations and epoch mechanics:**
  * Added `transfer_checked_with_fee_ix` instruction builder for exact fee verification (`FeeMismatch` 32).
  * Added instruction builders for `harvest_withheld_to_mint_ix`, `withdraw_withheld_from_mint_ix`, `withdraw_withheld_from_accounts_ix`, and `set_transfer_fee_ix`.
  * Added `warp_to_epoch` and `epoch` helpers in `Harness` for testing epoch-delayed fee transitions (2-epoch lag).
  * Added `mint_withheld` account inspection helper to track withheld fee tokens on mint accounts.
  * Added 6 integration tests in `crates/tokenscope-executor/tests/transfer_fee.rs` verifying fee collection, fee rate updates, and withheld token conservation.
* **Multisig authority management:**
  * Added `create_multisig` instruction and `multisig()` state decoder supporting $M$-of-$N$ threshold signers.
  * Added `transfer_checked_multisig_ix` supporting multiple signer seeds and accounts.
  * Documented and verified on-chain runtime behavior: client builders reject $M > N$ and $M=0$, but the on-chain runtime accepts $M > N$, permanently locking funds.
  * Added 6 integration tests in `crates/tokenscope-executor/tests/ext_multisig.rs`.
* **Required transfer memos and atomic rollback:**
  * Integrated SPL Memo program (`mollusk-svm-programs-memo = "=0.16.2"`).
  * Added `execute_transaction_logged` and `execute_transaction` in `Harness` for multi-instruction transaction execution with atomic rollback.
  * Added `token_memo_transfer` and `memo_transfer_instructions` scenario builders.
  * Documented and verified runtime behavior: transfers without memo fail with custom error 36 (`0x24`), an empty memo string `""` fully satisfies the requirement, and later failures in the transaction roll back state changes atomically.
  * Added 6 integration tests in `crates/tokenscope-executor/tests/ext_memo_transfer.rs`.
* **CPI forwarder and CPI Guard restrictions:**
  * Added `programs/demo-forwarder` Pinocchio native SBF program forwarding instructions via CPI (`invoke_with_slice`).
  * Added forwarder integration helpers `demo_forwarder_program_id`, `forward_instruction`, and `install_demo_forwarder`.
  * Added `owner` field to `TokenAccountView` for authority tracking.
  * Added 8 integration tests in `crates/tokenscope-executor/tests/ext_cpi_forwarder.rs` verifying that CPI Guard blocks owner-signed transfers (42), burns (43), approvals (45), closing to third parties (44), and authority changes (46) inside CPI, blocks changing CPI Guard settings inside CPI (41), but permits delegate transfers inside CPI.
* **Pointer extensions lifecycle and authority:**
  * Added `MetadataPointer`, `GroupPointer`, and `GroupMemberPointer` variants to `MintExt`.
  * Added `PointerView` struct and readers `mint_metadata_pointer`, `mint_group_pointer`, and `mint_group_member_pointer`.
  * Added instruction builders `update_metadata_pointer_ix`, `update_group_pointer_ix`, and `update_group_member_pointer_ix`.
  * Added 10 integration tests in `crates/tokenscope-executor/tests/ext_pointers.rs` verifying initialization, authority updates, clearing to `None`, rejection of unauthorized updates (`OwnerMismatch` 4), rejection of immutable pointer updates (`NoAuthorityExists` 29), and coexistence of all three pointers.
* **Independent reference model and differential testing:**
  * Added pure `TokenReferenceModel` in `tokenscope-model` modeling expected fee calculations, ceiling division, caps, pause, freeze, and atomic rollbacks.
  * Added differential testing suite in `tokenscope-adapter/tests/reference_differential.rs` verifying full agreement with real Mollusk SVM execution and proving divergence on vulnerable escrow.
* **Audit-grade reporting formats:**
  * Added Markdown campaign audit reports (`--format markdown`) and SARIF 2.1.0 output (`--format sarif`) for code scanning and CI integrations.
* **Target adapter architecture:**
  * Added stable `TargetAdapter` trait in `tokenscope-adapter` decoupling program deployment and trace capture from the engine.
  * Implemented `TargetAdapter` for `EscrowAdapter` and re-exported via `tokenscope-core`.
  * Added `run_scenario_with_adapter` and `run_campaign_with_adapter` in `Engine`, verified with a custom target acceptance test.
* **Extensible invariant engine:**
  * Added `Invariant` trait and dynamic `InvariantRegistry` in `tokenscope-invariants` allowing registration and evaluation of custom invariants alongside built-ins.
  * Maintained full backward compatibility for free functions `evaluate()` and `catalog()`, re-exported via `tokenscope-core`.
* **Stateful model-based scenario generation:**
  * Added `generate_stateful` generator in `tokenscope-scenarios` driving action selection from `TokenReferenceModel` simulated state.
  * Added `--strategy stateful` option to CLI (`tokenscope run`) and configuration files.
  * Added property-based determinism and validity test in `tokenscope-scenarios`.
* **Reference model fuzzing:**
  * Added `reference_model_scenario` fuzz target in `tokenscope-fuzz-harness` and `fuzz/` verifying pure state machine transitions, fee ceilings, and atomic rollback on arbitrary inputs.
  * Added seed corpus and stable compiler mutation tests in `tokenscope-fuzz-harness/tests/targets.rs`.
* **Release verification and CI hardening:**
  * Added automated clean-room verification for workspace crates, ensuring tree hash integrity, clippy compliance, and deterministic test outputs.
  * Verified reproducible test passes across all 11 workspace crates and native SBF programs.

#### Round 2: Hooks, State, Invariants, and Fuzzing
* Added transfer-hook fixture program `programs/demo-hook` for atomic transfer validation and rejection.
* Added support and verification for `DefaultAccountState`, `Pausable`, `PermanentDelegate`, and extension compatibility constraints.
* Added dimension-guided scenario generation and boundary exploration in `tokenscope-scenarios`.
* Added 6 libFuzzer targets in `crates/tokenscope-fuzz-harness` and `fuzz/`.
* Added reproducible benchmark suite across scenario generation, SVM lifecycle, invariant checks, and shrinking in `docs/benchmarks.md`.

#### Round 1: Core Architecture and Demo
* Scaffolded 11 workspace crates with `tokenscope-model`, `tokenscope-executor`, `tokenscope-adapter`, `tokenscope-invariants`, `tokenscope-scenarios`, `tokenscope-core`, `tokenscope-shrinker`, `tokenscope-report`, `tokenscope-cli`, `tokenscope-tui`, and `tokenscope-fuzz-harness`.
* Implemented native SBF escrow demo (`programs/demo-escrow`) with vulnerable and corrected flavors.
* Implemented 6 core invariants (`INV-ACCT-001`, `INV-SOLV-001`, `INV-ATOM-001`, `INV-CONS-001`, `INV-AUTH-001`, `INV-CUST-001`).
* Implemented bounded deterministic shrinker with gap-halving candidates.
* Implemented 9-screen Ratatui TUI with headless snapshot testing and safe terminal restoration on exit/signals.
* Implemented CLI with stable exit codes (0, 1, 2, 3, 4).
