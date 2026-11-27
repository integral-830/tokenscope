# Invariants

Each invariant is a pure function over one step of an `ExecutionTrace`
(`crates/tokenscope-invariants`). A verdict is **held**, **violated** or **not applicable**
(preconditions unmet; never evidence of a bug). Setup errors never reach this stage.

Severity attached to findings is advisory and always carries a rationale; no finding is promoted
to `suspected_vulnerability` automatically.

## INV-ACCT-001: deposit credit equals amount received

* **Precondition:** the step is a deposit, it succeeded, and the vault is a Token-2022 account read
  from real account data.
* **Expected:** `delta(escrow_recorded) == delta(vault_amount)`.
* **Legitimate exceptions:** none in P0 (the demo escrow charges no fee of its own).
* **Detects:** crediting the nominal amount when a transfer fee reduces what arrives.
* **Does not prove:** how the over-credit can be exploited.

## INV-SOLV-001: recorded liability does not exceed vault assets

* **Precondition:** the step succeeded.
* **Expected:** `escrow_recorded <= vault_amount` after the step.
* **Exceptions:** transient states inside one instruction are not observed.
* **Observation:** on the vulnerable escrow a later withdrawal of the over-credited balance fails
  (locked funds), shown by `fee-2pct-deposit-withdraw`.

## INV-ATOM-001: failed instructions leave no partial state

* **Precondition:** the step failed.
* **Expected:** every observed quantity equals its value before the step.
* **Exceptions:** lamport fees and compute use are not observed.
* **Note:** Mollusk does not persist failed instructions, so this holds structurally for the demo
  escrow; the invariant exists to catch regressions and future multi-instruction targets, and is
  unit-tested against synthetic partial-state traces.

## INV-CONS-001: deposit conserves tokens under transfer-fee semantics

* **Precondition:** the step is a deposit and succeeded.
* **Expected:** `depositor_debit == amount && delta(vault_amount) + delta(vault_withheld) == amount`.
* **Exceptions:** a missing transfer-fee extension counts as `withheld = 0`.
* **Expected result:** holds for *both* escrow flavors, because the fee is accounted for; it
  guards the harness's own observations.

## INV-AUTH-001: adversarial operations are rejected and change nothing

* **Precondition:** the step's action is one the escrow must reject (`Action::expects_rejection`):
  `UnauthorizedWithdraw` (an attacker signs in the depositor's position), `MismatchedDeposit` /
  `MismatchedWithdraw` (substituted mint, vault, token program or vault authority) and `ReinitEscrow`.
* **Expected:** the step fails, every observed quantity is unchanged, and the attacker's balance does not increase.
* **Exceptions:** only the depositor-signature, account-identity and initialization checks are modeled; other
  authority paths (delegates, forged PDAs) are not exercised.
* **Classification note:** rejection is the desired outcome, so a failed must-reject step does not make a
  run an execution failure.
* **Result today:** holds on both flavors; detection of a *successful* attack is covered by unit tests on
  synthetic traces.

## INV-CUST-001: the vault only shrinks through an authorized withdrawal

* **Precondition:** the step succeeded and its action is not the depositor's `Withdraw`.
* **Expected:** `vault_amount_after >= vault_amount_before`.
* **Exceptions:** `Withdraw` is the authorized path; interest-bearing or scaled amounts are not modeled
  (raw token amounts only).
* **Detects:** custody-assumption breaks such as a `PermanentDelegate` drain. Severity rationale says
  this is an integration-assumption failure caused by the mint's configuration, not necessarily a program bug.
* **Result today:** fires on **both** flavors for `permanent-delegate-drains-vault`, together with
  `INV-SOLV-001` (recorded balance exceeds the vault afterwards).

## Extended invariants (`--extended`)

Enabling `--extended` on `inspect`, `run`, `replay`, or `minimize` (or `Engine::with_extended_invariants()` in Rust) evaluates seven additional invariants alongside the six core checks (13 total):

### INV-ZERO-001: non-zero operation does not truncate to zero value

* **Precondition:** the step succeeded (`StepStatus::Ok`) with a non-zero input (`Deposit { amount > 0 }` or `Withdraw` when `escrow_recorded > 0`).
* **Expected:** `delta(escrow_recorded) > 0 && delta(vault_amount) > 0` for deposits; `delta(destination_balance) > 0` for non-zero withdrawals.
* **Detects:** 100% transfer fees or ceiling rounding truncating small deposits to zero credit (fires even on `demo-escrow-corrected` for `fee-100pct-consumes-deposit`, `fee-rounds-up-tiny-deposit`, and `profile-micro-fee-dust-truncation`).

### INV-DILUT-001: asset-to-liability exchange rate does not decrease

* **Precondition:** the step succeeded and recorded liability before and after the step is non-zero.
* **Expected:** `vault_amount_after * recorded_before >= vault_amount_before * recorded_after`.
* **Detects:** share or liability dilution across deposits, redemptions, and fee accruals.

### INV-SYMM-001: symmetric state-reducing operations maintain equivalent clamps

* **Precondition:** the step succeeded and `escrow_recorded` decreased.
* **Expected:** vault reduction never exceeds liability reduction (`vault_before - vault_after <= recorded_before - recorded_after`).
* **Detects:** asymmetric withdrawal or drain paths draining more real tokens than recorded liabilities retired.

### INV-PAUSE-001: paused mint rejects token transfers without state mutation

* **Precondition:** `before.mint_paused == Some(true)` and the step attempts token movement (`Deposit { amount > 0 }`, `Withdraw` with balance/drain, `DelegateTransfer { amount > 0 }`, or `PermanentDelegateDrain { amount > 0 }`).
* **Expected:** the step fails atomically (`before == after`).
* **Exceptions:** `ApproveDelegate`, `FreezeAccount`, `Pause`, and `Resume` remain callable per Token-2022 `Pausable` semantics.

### INV-FREEZE-001: frozen account cannot transfer or receive tokens

* **Precondition:** `depositor_source` is frozen (`Deposit`/`DelegateTransfer`) or `vault` is frozen (`Deposit`/`Withdraw`/`PermanentDelegateDrain`).
* **Expected:** the step fails atomically (`before == after`).
* **Exceptions:** withdrawals to a separate thawed `withdraw_destination` succeed when only `depositor_source` is frozen and `vault` is thawed.

### INV-CPI-001: CPI Guard blocks owner-signed CPI transfers

* **Precondition:** `before.source_cpi_guard == true` and the step is a non-zero `Deposit` via the escrow's CPI.
* **Expected:** the step fails atomically (`before == after`).
* **Exceptions:** top-level instructions and approved delegate transfers remain allowed per Token-2022 `CpiGuard` semantics.

### INV-HOOK-001: TransferHook mint invokes hook on transfer and reverts on failure

* **Precondition:** `hook_invocations` is `Some(_)` on both `before` and `after` (a `TransferHook` mint).
* **Expected:** successful non-zero token transfers increment `hook_invocations`; failed or non-transfer instructions leave `hook_invocations` unchanged.

## Invariant classification levels

Invariants are tiered by scope via `InvariantLevel`:

* **`GlobalSvm`:** Fundamental SVM invariants (e.g., failure atomicity `INV-ATOM-001`).
* **`Token2022`:** Extension-specific token rules (e.g., fee conservation `INV-CONS-001`, custody `INV-CUST-001`).
* **`TargetSpecific`:** Application-level accounting and state rules (e.g., escrow balance tracking `INV-ACCT-001`, solvency `INV-SOLV-001`).
* **`Custom`:** User-defined or protocol-specific rules.

## Adding an invariant

State id, `InvariantLevel`, preconditions, expected behavior and exceptions in `InvariantDef`; implement a
`fn(&StepRecord) -> Verdict` (or the `Invariant` trait) and register it in `InvariantRegistry` (using
`with_extended_invariants()` / `extended_catalog()` or `catalog()`, plus `severity_for` if non-default
severity is needed); add held/violated/not-applicable unit tests with synthetic traces; document it here.
