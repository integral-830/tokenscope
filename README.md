<p align="center">
  <img src="assets/tokenscope-logo.svg" alt="TokenScope Logo" width="100%" />
</p>

<p align="center">
  <a href="https://github.com/integral-830/tokenscope/actions/workflows/ci.yml"><img src="https://github.com/integral-830/tokenscope/actions/workflows/ci.yml/badge.svg" alt="CI" /></a>
  <a href="https://github.com/integral-830/tokenscope/actions/workflows/tokenscope-audit.yml"><img src="https://github.com/integral-830/tokenscope/actions/workflows/tokenscope-audit.yml/badge.svg" alt="Security Audit" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue.svg" alt="License: Apache-2.0" /></a>
  <a href="docs/toolchain.md"><img src="https://img.shields.io/badge/rust-1.99.0%2B-orange.svg" alt="Rust 1.99.0+" /></a>
  <a href="docs/supported-extensions.md"><img src="https://img.shields.io/badge/solana-Token--2022-14F195.svg?logo=solana&logoColor=white" alt="Solana Token-2022" /></a>
  <a href="https://github.com/integral-830/tokenscope"><img src="https://img.shields.io/badge/tests-271%20passing-brightgreen.svg" alt="Tests: 271 passing" /></a>
  <a href="docs/architecture.md"><img src="https://img.shields.io/badge/engine-Mollusk%20SVM-9945FF.svg" alt="Mollusk SVM" /></a>
  <a href="FORMAT.md"><img src="https://img.shields.io/badge/security-SARIF%202.1.0-blueviolet.svg" alt="SARIF 2.1.0" /></a>
</p>

# TokenScope

TokenScope is a Rust framework for **adversarial testing of Solana Token-2022 integrations**. It
executes real programs in a real Solana Virtual Machine (the Mollusk SVM with the real Token-2022
program), checks explicit invariants against *decoded on-chain account state*, minimizes failures,
and writes reproducible findings.

```
Target adapter -> Scenarios -> Real SVM execution -> Invariant checking -> Shrinking -> Findings
```

> **Status:** version 0.1.0. One target (a demo escrow), 13 invariants (6 core, 7 `--extended`), and 271 passing workspace
> tests. Token-2022 behavior verified by executable tests: transfer fees (including epoch delays,
> `TransferCheckedWithFee`, harvest and withdraw), freeze/thaw, DefaultAccountState, Pausable,
> transfer hooks (fixture hook), CPI Guard (direct and CPI forwarder fixture), delegates, permanent
> delegate, multisig authorities (threshold signing and on-chain quirks), required transfer memos
> with atomic rollback, pointer extensions (MetadataPointer, GroupPointer, GroupMemberPointer), and
> extension compatibility. See [Limitations](#limitations) and
> [docs/supported-extensions.md](docs/supported-extensions.md) before relying on any result.
> TokenScope does not detect vulnerabilities in general, and an invariant violation is **not**
> proof of exploitability. It provides deterministic fuzzing and invariant checking over real SBF bytecodes.

## The demonstration

Token-2022 transfer fees mean the amount a program *sends* is not the amount that *arrives*. The
demo escrow ships in two flavors built from one source (`programs/demo-escrow`):

* **vulnerable** credits the nominal deposit amount;
* **corrected** (`--features corrected`) credits the vault's real balance change.

With a 2% fee, depositing 1,000 credits 1,000 on the vulnerable escrow while the vault holds 980
(20 withheld by Token-2022). The same scenario passes on the corrected escrow.

```text
$ tokenscope run --target demo-escrow-vulnerable --count 0     # exit code 1
executed 14 | pass 4 | execution failures 2 | invariant violations 8 | setup errors 0 | findings 16
...
fd_eb4facd442285199 INV-ACCT-001 [Medium] target=demo-escrow-vulnerable scenario=sc_3573a0f4384e7945 seed=0
  observed: step 0: deposit of 1000 credited 1000 but the vault received 980 (withheld fee delta 20)

$ tokenscope run --target demo-escrow-corrected --count 0      # exit code 0
executed 14 | pass 12 | execution failures 2 | invariant violations 0 | setup errors 0 | findings 0
```

Full walkthrough with replay and minimization: [docs/demo.md](docs/demo.md).

## Showcase Video and Demo

https://github.com/user-attachments/assets/9d5a5c23-4715-4365-a486-77e84d1d793d

> **Video Walkthrough:** [assets/tokenscope-showcase.mp4](assets/tokenscope-showcase.mp4) (02:50 runtime, strictly under the 3-minute hackathon limit).
> Features real Mollusk SVM execution against un-mocked Token-2022 bytecodes, invariant detection on Pinocchio escrow, deterministic failure minimization, and the live Ratatui TUI dashboard.

### Interface & Execution Screenshots

<p align="center">
  <img src="assets/screenshot-1-tui.png" alt="TokenScope Interactive TUI Dashboard" width="100%" />
</p>

<p align="center">
  <img src="assets/screenshot-2-cli-run.png" alt="CLI Execution: Invariant Detection" width="49%" />
  <img src="assets/screenshot-3-sarif-report.png" alt="SARIF 2.1.0 Security Gate" width="49%" />
</p>

## Solana Ecosystem Integration

TokenScope integrates directly with low-level Solana execution primitives to test programs against genuine on-chain conditions without mocks or heuristics:

### Why Solana?

Solana's Token-2022 program (Token Extensions) represents a paradigm shift from monolithic smart contracts to protocol-level composable token behaviors. However, extensions such as transfer fees, transfer hooks, permanent delegates, and CPI guards introduce subtle composability hazards:
* **Nominal vs Received Assumptions:** Off-chain unit tests and transaction mocks often assume nominal amounts equal received balances, failing to detect transfer fee shortfalls.
* **Client vs Runtime Divergence:** Client-side instruction builders mask on-chain runtime acceptance quirks (such as multisig $M > N$ fund locks).
* **EVM-Centric Tool Blindspots:** Conventional audit tools cannot execute Solana SBF/BPF bytecodes or model CPI account-resolution constraints.

TokenScope solves this by providing a native, deterministic SVM testing framework purpose-built for the Solana runtime.

### How is Token-2022 Uniquely Tested?

1. **In-Process Solana Virtual Machine (Mollusk SVM):**
   Executes un-mocked SBF programs using the Mollusk execution harness. It loads the official mainnet-dump ELF bytecode of the Solana Token-2022 program (`mollusk-svm-programs-token-2022`), testing contracts against genuine Solana runtime behavior.
2. **Comprehensive Token-2022 Extension Coverage:**
   Systematically explores state transitions across complex Solana extensions:
   * **Transfer Fees:** Verifies nominal vs. received balance deltas, epoch fee transitions (2-epoch lag), and withholding logic.
   * **CPI Guard:** Enforces cross-program invocation boundaries, ensuring untrusted programs cannot hijack owner-authorized transfers.
   * **Transfer Hooks:** Resolves required extra account metadata across cross-program invocations.
   * **Authorities & Policies:** Validates Permanent Delegates, DefaultAccountState, Pausable, and Multisig threshold logic.
3. **Native SBF On-Chain Reference Targets (Pinocchio):**
   Includes production-grade on-chain escrow and hook programs written in native Rust with Pinocchio 0.11.2 (zero-dependency SBF), compiling directly to `sbf` ELF shared objects.
4. **Live Solana Devnet Deployments:**
   Reference contracts are compiled with Solana platform-tools v1.58 and deployed on Solana Devnet:
   * Hardened Reference Escrow: [`AcYw1BmDMimEN7Simi8urSatz9YRvJrBBBwyD5mvwWUj`](https://explorer.solana.com/address/AcYw1BmDMimEN7Simi8urSatz9YRvJrBBBwyD5mvwWUj?cluster=devnet)
   * Vulnerability Sandbox: [`BYNHabimxQiTqDbRwvjMxvdQsHZfEq2Em8A1BcMah258`](https://explorer.solana.com/address/BYNHabimxQiTqDbRwvjMxvdQsHZfEq2Em8A1BcMah258?cluster=devnet)
5. **Decoded Account State Invariants:**
   Instead of tracking transaction receipts, TokenScope decodes raw Solana account data directly after each instruction step to verify economic invariants (solvency, custody, balance consistency).

## Devnet Deployments

* **Target Programs (Pinocchio):** Built from source via `./scripts/build-programs.sh`:
  * `demo-escrow-corrected`: `target/sbf-programs/demo_escrow_corrected.so`
    * Devnet Program ID: [`AcYw1BmDMimEN7Simi8urSatz9YRvJrBBBwyD5mvwWUj`](https://explorer.solana.com/address/AcYw1BmDMimEN7Simi8urSatz9YRvJrBBBwyD5mvwWUj?cluster=devnet)
  * `demo-escrow-vulnerable`: `target/sbf-programs/demo_escrow_vulnerable.so`
    * Devnet Program ID: [`BYNHabimxQiTqDbRwvjMxvdQsHZfEq2Em8A1BcMah258`](https://explorer.solana.com/address/BYNHabimxQiTqDbRwvjMxvdQsHZfEq2Em8A1BcMah258?cluster=devnet) (*educational exploit sandbox*)
  * `demo-hook`: `target/sbf-programs/demo_hook.so`

> [!IMPORTANT]
> **Security & Deployment Notice:** `demo-escrow-corrected` is the production-hardened reference implementation. `demo-escrow-vulnerable` is an intentional defect sandbox for TokenScope invariant verification; per [SECURITY.md](SECURITY.md), it must never be funded with mainnet assets.




## Installation & CI/CD Integration

### 1-Line CLI Install

Install the TokenScope CLI binary directly from source:

```bash
cargo install --git https://github.com/integral-830/tokenscope tokenscope-cli --locked
```

### GitHub Actions Workflow (Zero-Config Security Gate)

Add TokenScope to any Solana repository (`.github/workflows/tokenscope.yml`) to run Token-2022 invariant verification on pull requests with native SARIF 2.1.0 alerts in the GitHub Security tab:

```yaml
name: TokenScope Token-2022 Security Gate
on: [push, pull_request]

jobs:
  tokenscope:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - name: Install TokenScope
        run: cargo install --git https://github.com/integral-830/tokenscope tokenscope-cli --locked
      - name: Run Token-2022 Invariant Suite
        run: tokenscope run --target demo-escrow-corrected --count 50 --strategy stateful --out audit-results || true
      - name: Generate SARIF Security Report
        run: |
          CAMPAIGN_ID=$(ls -td audit-results/cp_* | head -n 1 | xargs -n 1 basename)
          tokenscope report "$CAMPAIGN_ID" --format sarif --out audit-results > audit-results/tokenscope.sarif
      - name: Upload SARIF to GitHub Security Tab
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: audit-results/tokenscope.sarif
```

## Quick start

Requirements: Rust 1.99.0 (MSRV 1.97), and for building the on-chain demo programs
`cargo-build-sbf` 4.5.0 plus Solana platform-tools **v1.58**
(see [docs/toolchain.md](docs/toolchain.md) for exact, verified installation steps).

```sh
./scripts/build-programs.sh          # builds both escrow flavors from source into target/sbf-programs/
cargo build --release -p tokenscope-cli
export PATH="$PWD/target/release:$PATH"

tokenscope doctor                    # verifies programs, bundled Token-2022 and real execution
tokenscope inspect                   # targets, accounts, instructions, invariants
tokenscope run --target demo-escrow  # runs both flavors; exit 1 because the vulnerable one violates
tokenscope tui                       # interactive UI
cargo test --workspace               # all tests (needs the built programs)
```

## Commands

| Command | Purpose | Exit codes |
|---|---|---|
| `doctor` | verify the environment, incl. a real fee transfer | 0 ok, 3 problem |
| `inspect [--target T] [--extended]` | show target configuration and invariants | 0 |
| `run --target T --seed N [--count N] [--suite core\|extensions\|profiles\|all\|full\|none] [--strategy random\|extended\|guided\|stateful] [--extended] [--out DIR]` / `run --config FILE` | run a campaign, write artifacts | 0 no violations, 1 violations, 2 bad input, 3 setup error |
| `replay <scenario-file> [--extended]` | re-run one scenario | 0 / 1 / 2 / 3 |
| `minimize <finding-file> [--out F] [--max-attempts N] [--extended]` | shrink a finding's scenario | 0, 2, 4 not reproducible |
| `report <campaign-id> [--format json\|text\|markdown\|sarif]` | print or export a campaign report | 0, 2 |
| `corpus list \| replay <id>\|--all \| add <scenario> --description ...` | regression corpus | 0, 2, 3, 4 mismatch |
| `tui [--suite S] [--extended] [--snapshot SCREEN]` | interactive UI (or print one screen headlessly) | 0, 2, 3 |
| `completion <shell>` | generate shell autocompletion (`bash`, `zsh`, `fish`, `powershell`, `elvish`) | 0 |

Targets: `demo-escrow-vulnerable`, `demo-escrow-corrected`, or `demo-escrow` (both).

Suites: `core` (the original 14 fee-accounting scenarios; default), `extensions` (10 extension, authorization and
boundary scenarios), `profiles` (5 combined realistic Token-2022 mint profile scenarios), `all` (`core` + `extensions`,
24 scenarios), `full` (`core` + `extensions` + `profiles`, 29 scenarios), `none`. Passing `--extended` enables
all 13 invariants (`INV-ACCT/SOLV/ATOM/CONS/AUTH/CUST-001` plus `INV-ZERO/DILUT/SYMM/PAUSE/FREEZE/CPI/HOOK-001`). Note that
the corrected escrow still reports a custody finding in the `extensions` and `profiles` suites (`permanent-delegate-drains-vault`,
`profile-rwa-regulated-mint`): neither flavor checks the mint's extensions. Under `--extended`, `fee-100pct-consumes-deposit`
and `profile-micro-fee-dust-truncation` also trigger `INV-ZERO-001`.
Strategies: `random` (seeded fee scenarios), `extended` (extension-aware templates), `guided` (mutates the
suites and the regression corpus and keeps only scenarios that add a new *input-space* cell; it is not
guided by program coverage), and `stateful` (model-based state-machine generation driven by `TokenReferenceModel`).

## Repository layout

`crates/tokenscope-{model,executor,adapter,invariants,scenarios,shrinker,core,report,cli,tui,fuzz-harness}`,
`programs/demo-{escrow,hook,forwarder}`, `fixtures/` (scenarios and the regression corpus), `scripts/`, `docs/`.
Architecture: [docs/architecture.md](docs/architecture.md).

## Execution boundaries and security model

TokenScope models the Solana execution environment with explicit boundaries:

1. **In-process Mollusk SVM vs live validator:**
   * TokenScope executes un-mocked SBF BPF program bytecodes directly in-memory via the Mollusk SVM harness (`43.2 us` per instruction).
   * This design prioritizes invariant fuzzing throughput (over 23,000 instructions per second on a single CPU core) rather than full network simulation (Gossip, Tower BFT, RPC latency, or priority fee auctions).
   * Transaction-level atomicity and multi-instruction rollback are exercised via `execute_transaction_logged`, while cryptographic Ed25519 signature verification is abstracted to `is_signer` checks.

2. **Supported Token-2022 extensions:**
   * `TransferFeeConfig` and `TransferFeeAmount`: Ceiling division math, withheld fee tracking on recipient accounts and mint, 2-epoch delay (`warp_to_epoch`), and permissionless harvest.
   * `CpiGuard`: Strict caller validation rejecting owner-signed `Transfer`, `Burn`, `CloseAccount`, and `SetAuthority` at `stack_height > 1`, while permitting `DelegateTransfer`.
   * `MemoTransfer`: SPL memo requirement enforcement and full multi-instruction atomic rollback.
   * `Multisig`: On-chain threshold enforcement ($M \le N$) and runtime quirk verification ($M > N$ permanently locking funds).
   * `Pointers`: `MetadataPointer`, `GroupPointer`, and `GroupMemberPointer` authority update lifecycle and immutability lock (`authority = None`).
   * `DefaultAccountState`, `Pausable`, and `PermanentDelegate`.

3. **Roadmap v2 boundaries (deliberately scoped out):**
   * *Confidential Transfers (ZK ElGamal):* Requires twisted ElGamal proof generation and the `ZkTokenProof` system program, which would slow down in-memory SVM fuzzing by orders of magnitude.
   * *Dynamic `ExtraAccountMetaList` Resolution:* Transfer hooks currently execute against explicit validation fixtures rather than resolving dynamic third-party account lists via `spl-tlv-account-resolution`.
   * *TokenMetadata TLV Payloads:* Pointers to metadata accounts are verified, but internal Metaplex Borsh/TLV schemas are not parsed.

4. **CI/CD Security Automation:**
   * TokenScope natively emits OASIS SARIF 2.1.0 reports (`--format sarif`), integrating directly into GitHub Code Scanning and Pull Request security gates via `.github/workflows/tokenscope-audit.yml`.

## Limitations

* One target program (the demo escrow). Token-2022 coverage is listed with its limits in
  [docs/supported-extensions.md](docs/supported-extensions.md); confidential transfers and production
  TokenMetadata account data are **not covered**. Pointer extensions, multisig authorities, required
  transfer memos, and CPI Guard restrictions are verified by dedicated executable test suites. The
  transfer-hook tests use a fixture hook program, not a production one.
* Authorization is modeled as the depositor-signature, account-identity and initialization checks
  (`INV-AUTH-001`); other authority paths are not exercised.
* Scenario generation is seeded pseudo-random or *input-space*-guided; it never observes program coverage.
  The libFuzzer targets (`fuzz/`) are coverage-guided but fuzz the tool's parsers, shrinker and invariant
  engine, not the on-chain programs; the real-SVM `replay_scenario` target has not been fuzzed.
* Fuzzing ran for minutes on the stable compiler without AddressSanitizer; benchmarks come from one shared VM.
* `cargo audit` reports one advisory reachable only via Mollusk's Agave dependency (accepted and justified in
  [docs/dependency-review.md](docs/dependency-review.md)). All CI workflows run automatically in GitHub Actions.
* Token-2022 is the mainnet-snapshot ELF bundled by `mollusk-svm-programs-token-2022` 0.16.2; it
  may differ from other Token-2022 builds.
* Execution is instruction-level (no signature verification, fees or blockhash); see
  [docs/architecture.md](docs/architecture.md).
* An invariant violation shows a property failing on observed state, not that funds can be stolen.

## Verification scripts

| Script | Purpose |
|---|---|
| `scripts/build-programs.sh` | build escrow (two flavors), demo hook and CPI forwarder from source |
| `scripts/release-check.sh [bin]` | exercise every command and exit code on a built binary (49 checks) |
| `scripts/check-tui-terminal.py` | verify terminal restoration on quit, error, panic, SIGTERM, SIGHUP (pty) |
| `scripts/fuzz.sh <target> [s]` | libFuzzer run on the stable compiler ([fuzz/README.md](fuzz/README.md)) |
| `cargo run --release -p tokenscope-core --example bench` | benchmarks ([docs/benchmarks.md](docs/benchmarks.md)) |

## License

Apache-2.0 (see `LICENSE`).
