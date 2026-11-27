# Dependency, `unsafe` and resource-limit review

Performed on the commit that adds this file, with the tools named below. Findings that are
accepted risks are listed explicitly; nothing is waved through silently.

## Inventory

* Host workspace: **465** crate dependencies (`cargo audit` count for `Cargo.lock`). The size comes
  almost entirely from `mollusk-svm` (the Agave runtime) and `ratatui`.
* On-chain programs (`programs/demo-escrow`, `programs/demo-hook`): 25 and 21 crates (pinocchio and
  its tiny dependency set). Fuzz package: 367 crates (libFuzzer + the harness).
* Direct dependencies of first-party crates are intentionally few: `serde`, `serde_json`, `sha2`,
  `thiserror`, `clap`, `ratatui`, `signal-hook` (unix, already in the tree via crossterm),
  `proptest`/`tempfile` (tests only), and the Mollusk / Token-2022 interface crates.
* Duplicate versions exist for several Solana crates (for example `solana-pubkey` 3.x and 4.x)
  because the Token-2022 interface crate and Mollusk sit on different minor lines. This is
  an upstream split, not something TokenScope can unify.

## Licenses

`cargo metadata` license fields were inspected for all packages. No GPL-family, AGPL or BUSL
license applies to a dependency except the *option* of LGPL in the multi-licensed `r-efi` (the MIT
or Apache option is used). Four `mollusk-svm*` crates have an empty `license` field because they
ship a `LICENSE` file instead; those files were read and are Apache-2.0. RTK (a development tool,
not a dependency) is not part of this inventory.

## `unsafe`

* First-party host crates: `unsafe_code = "forbid"` (workspace lint); `grep` finds no `unsafe` in
  `crates/` or `fuzz/`.
* On-chain programs: `unsafe_code = "deny"` because pinocchio's `entrypoint!` macro expands to
  unsafe code; the program source itself contains no `unsafe` block.
* Third-party crates (Agave, Mollusk, ratatui, ...) contain `unsafe`; it was not audited here.

## Vulnerability scan (`cargo audit` 0.22.2, advisory DB of 1,395 advisories fetched 2026-10-30)

| Lockfile | Result |
|---|---|
| `Cargo.lock` | 1 vulnerability (accepted, below) + 4 "unmaintained" warnings |
| `programs/demo-escrow/Cargo.lock`, `programs/demo-hook/Cargo.lock` | clean |
| `fuzz/Cargo.lock` | 3 "unmaintained" warnings, no vulnerabilities |

**RUSTSEC-2026-0387, `crypto-bigint` 0.5.5 (timing variability in constant-time operations).**
Dependency path: `k256` -> `solana-secp256k1-recover` -> `solana-syscalls` -> `mollusk-svm` ->
`tokenscope-executor`. It matters for secret-dependent arithmetic (key operations). TokenScope
holds no keys or secrets, never invokes secp256k1 recovery, and the escrow and hook programs do
not use it. A fix requires `crypto-bigint >= 0.7.6`, which `k256 0.13` (pinned by Agave) does not
allow, so this cannot be resolved here. Accepted and recorded in `.cargo/audit.toml`; re-check on
each Mollusk/Agave update.

Unmaintained warnings (all transitive via Agave/Mollusk, none a known vulnerability): `bincode`
1.3.3 (RUSTSEC-2025-0141), `derivative` 2.2.0 (RUSTSEC-2024-0388), `libsecp256k1` 0.7.2
(RUSTSEC-2025-0161), `paste` 1.0.15 (RUSTSEC-2024-0436).

## Resource limits and malformed input

| Input / work | Limit | Enforced in | Tested |
|---|---|---|---|
| JSON document size (scenario, finding, campaign, trace, corpus case, run config) | 32 MiB, checked from metadata and while reading | `tokenscope_core::read_document` (CLI + corpus) | `oversized_inputs_and_limits_are_rejected_with_usage_errors` |
| JSON nesting | serde_json recursion limit (128) | serde_json | `deeply_nested_json_is_rejected_not_a_stack_overflow` |
| Actions per scenario | 64 | `Scenario::validate` | model unit tests |
| Mint extensions per scenario | 8 | `Scenario::validate` | `too_many_extensions_are_rejected` |
| Scenario name | 128 bytes | `Scenario::validate` | model unit tests |
| Generated scenarios per run | 10,000 | CLI | CLI tests |
| Shrink attempts | 100,000 (default 300) | CLI + shrinker budget | CLI + shrinker tests |
| TUI activity log | 200 lines | `App::push_activity` | - |
| Compute per instruction | Mollusk's compute budget | Mollusk | - |

Parsers are property-tested with arbitrary and mutated input, and fuzzed with libFuzzer
(`fuzz/README.md`); that fuzzing found one real panic (fixed).

## Failure handling

Setup problems, rejected instructions, invariant violations and suspected vulnerabilities are
distinct outcome classes; harness problems never become findings. All command failures map to
documented exit codes (`scripts/release-check.sh` checks 49 of them on the release binary). The TUI
restores the terminal on quit, error, panic, SIGTERM and SIGHUP (`scripts/check-tui-terminal.py`);
SIGKILL cannot be handled.
