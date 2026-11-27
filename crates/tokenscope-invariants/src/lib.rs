//! Invariant engine.
//!
//! Each invariant has an identifier, preconditions, an expected behavior, and documented
//! legitimate exceptions (see `docs/invariants.md`). Invariants are pure functions over an
//! [`ExecutionTrace`]; they never execute programs and never edit state.
//!
//! A verdict of [`Verdict::NotApplicable`] means the preconditions were not met, which is never
//! evidence of a bug. Setup problems never reach this crate: the adapter reports them separately.

use tokenscope_model::{
    Action, ExecutionTrace, Finding, OutcomeClass, Reproduction, SCHEMA_VERSION, Scenario,
    Severity, Snapshot, StateDelta, StepRecord, StepStatus,
};

/// Documentation of one invariant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvariantDef {
    /// Stable identifier, e.g. `INV-ACCT-001`.
    pub id: &'static str,
    /// Short name.
    pub name: &'static str,
    /// What the property states.
    pub description: &'static str,
    /// Conditions under which the invariant is evaluated.
    pub preconditions: &'static [&'static str],
    /// Required behavior.
    pub expected: &'static str,
    /// Cases deliberately not treated as violations.
    pub exceptions: &'static [&'static str],
    /// Invariant level in the hierarchy.
    pub level: InvariantLevel,
}

/// Classification of invariants by their scope in the verification hierarchy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvariantLevel {
    /// Global Solana VM invariants (lamport conservation, signer privileges, read-only).
    GlobalSvm,
    /// Token-2022 program invariants (transfer fees, freeze, CPI guard).
    Token2022,
    /// Target-program-specific invariants (escrow accounting, solvency).
    TargetSpecific,
    /// Developer-defined custom invariants.
    Custom,
}

/// Transfer accounting: credit equals actual receipt.
pub const ACCT_001: InvariantDef = InvariantDef {
    id: "INV-ACCT-001",
    name: "Deposit credit equals amount received",
    description: "After a successful deposit, the escrow's recorded balance must increase by exactly the amount the vault actually received.",
    preconditions: &[
        "the step is a deposit",
        "the step succeeded",
        "the vault is a Token-2022 account observed from real account data",
    ],
    expected: "delta(escrow_recorded) == delta(vault_amount)",
    exceptions: &[
        "none in P0: the demo escrow has no fee of its own and no other path credits the vault",
    ],
    level: InvariantLevel::TargetSpecific,
};

/// Solvency: liabilities never exceed assets.
pub const SOLV_001: InvariantDef = InvariantDef {
    id: "INV-SOLV-001",
    name: "Recorded liability does not exceed vault assets",
    description: "After every successful step, the amount the escrow owes the depositor must not exceed the vault's token balance.",
    preconditions: &["the step succeeded"],
    expected: "escrow_recorded <= vault_amount",
    exceptions: &["transient states inside a single instruction are not observed"],
    level: InvariantLevel::TargetSpecific,
};

/// Failure atomicity.
pub const ATOM_001: InvariantDef = InvariantDef {
    id: "INV-ATOM-001",
    name: "Failed instructions leave no partial state",
    description: "If an instruction fails, every observed quantity must equal its value before the instruction.",
    preconditions: &["the step failed"],
    expected: "after == before for all observed quantities",
    exceptions: &["lamport fees and compute use are not observed"],
    level: InvariantLevel::GlobalSvm,
};

/// Conservation under documented transfer-fee semantics.
pub const CONS_001: InvariantDef = InvariantDef {
    id: "INV-CONS-001",
    name: "Deposit conserves tokens under transfer-fee semantics",
    description: "On a successful deposit of `amount`, the depositor is debited exactly `amount`, and the vault's balance gain plus its withheld-fee gain equals `amount`.",
    preconditions: &["the step is a deposit", "the step succeeded"],
    expected: "depositor_debit == amount && delta(vault_amount) + delta(vault_withheld) == amount",
    exceptions: &["a missing transfer-fee extension counts as withheld = 0"],
    level: InvariantLevel::Token2022,
};

/// Authorization: unauthorized actors cause no prohibited transition.
pub const AUTH_001: InvariantDef = InvariantDef {
    id: "INV-AUTH-001",
    name: "Adversarial operations are rejected and change nothing",
    description: "An operation that must be rejected (a withdrawal signed by a non-depositor, a deposit or withdrawal with a substituted mint, vault, token program or vault authority, or re-initialization of the escrow) must fail, must leave every observed quantity unchanged, and must not credit the attacker.",
    preconditions: &[
        "the step's action is one the escrow is required to reject (Action::expects_rejection)",
    ],
    expected: "step failed && after == before && attacker_balance unchanged",
    exceptions: &[
        "only the depositor-signature, account-identity and initialization checks are modeled; other authority paths (delegates, forged PDAs) are not exercised",
    ],
    level: InvariantLevel::TargetSpecific,
};

/// Custody: only the depositor's withdrawal may reduce the vault.
pub const CUST_001: InvariantDef = InvariantDef {
    id: "INV-CUST-001",
    name: "The vault only shrinks through an authorized withdrawal",
    description: "A successful step other than the depositor's Withdraw must not decrease the vault's token balance. This encodes the escrow's assumption that only its PDA can move vault tokens; mint extensions such as PermanentDelegate break that assumption.",
    preconditions: &["the step succeeded", "the step's action is not Withdraw"],
    expected: "vault_amount_after >= vault_amount_before",
    exceptions: &[
        "Withdraw by the depositor is the authorized path and is excluded",
        "interest-bearing or scaled amounts are not modeled; only raw token amounts are compared",
    ],
    level: InvariantLevel::Token2022,
};

/// Truncation and zero-rounding: non-zero inputs must not yield zero tokens or zero credits.
pub const ZERO_001: InvariantDef = InvariantDef {
    id: "INV-ZERO-001",
    name: "Non-zero operation does not truncate to zero value",
    description: "A successful step with a non-zero input amount must not result in 0 tokens credited, transferred, or received, which leads to share burning with zero payout or unbacked state mutations.",
    preconditions: &["the step succeeded", "the step has a non-zero input amount"],
    expected: "delta(credited_or_transferred) > 0",
    exceptions: &["steps that are intentionally zero-amount no-ops"],
    level: InvariantLevel::TargetSpecific,
};

/// Share dilution: the ratio of vault assets to recorded liabilities must never decrease.
pub const DILUT_001: InvariantDef = InvariantDef {
    id: "INV-DILUT-001",
    name: "Asset-to-liability exchange rate does not decrease",
    description: "After every successful step, the ratio of vault assets to recorded liabilities must not decrease, ensuring existing participants are never diluted.",
    preconditions: &["the step succeeded", "prior recorded liability is positive"],
    expected: "vault_amount_after * recorded_before >= vault_amount_before * recorded_after",
    exceptions: &["authorized admin fee extractions with explicit governance parameters"],
    level: InvariantLevel::TargetSpecific,
};

/// Symmetric path safety: parallel state-reducing methods must maintain equivalent balance clamp rules.
pub const SYMM_001: InvariantDef = InvariantDef {
    id: "INV-SYMM-001",
    name: "Symmetric state-reducing operations maintain equivalent clamps",
    description: "Any reduction in recorded liabilities must not exceed the reduction in real vault holdings, preventing one-sided bounds clamps and desynchronized accounting.",
    preconditions: &["the step succeeded", "recorded liabilities decreased"],
    expected: "delta(vault_amount) matches or bounds delta(escrow_recorded)",
    exceptions: &["none: symmetric operations must adhere to conservative bounds"],
    level: InvariantLevel::TargetSpecific,
};

/// Pausable enforcement: paused mints reject token movement and mutate no state.
pub const PAUSE_001: InvariantDef = InvariantDef {
    id: "INV-PAUSE-001",
    name: "Paused mint rejects token transfers without state mutation",
    description: "While a Pausable mint is paused, deposits, withdrawals, delegate transfers, and permanent-delegate drains must fail atomically without moving tokens or altering state.",
    preconditions: &[
        "the mint's paused flag before the step is true",
        "the step is a deposit, withdraw, delegate transfer, or permanent-delegate drain",
    ],
    expected: "step fails and before == after",
    exceptions: &[
        "ApproveDelegate, FreezeAccount, Pause, and Resume remain callable per Token-2022 semantics",
    ],
    level: InvariantLevel::Token2022,
};

/// Freeze enforcement: frozen token accounts reject transfers involving them.
pub const FREEZE_001: InvariantDef = InvariantDef {
    id: "INV-FREEZE-001",
    name: "Frozen account cannot transfer or receive tokens",
    description: "Transfers sourcing from or targeting a frozen depositor source or frozen vault must fail atomically without moving tokens or updating escrow accounting.",
    preconditions: &[
        "depositor_source is frozen (for deposit or delegate transfer) OR vault is frozen (for deposit, withdraw, or permanent-delegate drain)",
    ],
    expected: "step fails and before == after",
    exceptions: &[
        "withdrawals to withdraw_destination remain valid when only depositor_source is frozen and vault is thawed",
    ],
    level: InvariantLevel::Token2022,
};

/// CPI Guard enforcement: owner-signed CPI transfers from a guarded source are blocked.
pub const CPI_001: InvariantDef = InvariantDef {
    id: "INV-CPI-001",
    name: "CPI Guard blocks owner-signed CPI transfers",
    description: "When CPI Guard is enabled on the depositor source account, non-zero owner-signed deposits through an escrow CPI must be rejected with zero state mutation.",
    preconditions: &[
        "source_cpi_guard is true before the step",
        "the step is a non-zero Deposit through the escrow CPI",
    ],
    expected: "step fails and before == after",
    exceptions: &["direct owner instructions and approved delegate transfers remain allowed"],
    level: InvariantLevel::Token2022,
};

/// Transfer Hook integrity: active TransferHook mints execute hooks on successful transfers and never increment on failure.
pub const HOOK_001: InvariantDef = InvariantDef {
    id: "INV-HOOK-001",
    name: "TransferHook mint invokes hook on transfer and reverts on failure",
    description: "On mints with TransferHook enabled, successful non-zero token movements must invoke the hook (hook_invocations increases), and failed or non-transfer steps must leave hook_invocations unchanged.",
    preconditions: &["the mint has a configured TransferHook observer (hook_invocations is Some)"],
    expected: "hook_invocations increases on successful non-zero transfers and is unchanged otherwise",
    exceptions: &["zero-amount no-ops that return before invoking token transfer"],
    level: InvariantLevel::Token2022,
};

/// All invariants implemented by this crate (core set).
pub fn catalog() -> [InvariantDef; 6] {
    [ACCT_001, SOLV_001, ATOM_001, CONS_001, AUTH_001, CUST_001]
}

/// Extended catalog of all 13 invariants (core 6 + advanced DeFi & Token-2022 policy invariants).
pub fn extended_catalog() -> [InvariantDef; 13] {
    [
        ACCT_001, SOLV_001, ATOM_001, CONS_001, AUTH_001, CUST_001, ZERO_001, DILUT_001, SYMM_001,
        PAUSE_001, FREEZE_001, CPI_001, HOOK_001,
    ]
}

/// Result of evaluating one invariant on one step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// The invariant held.
    Held,
    /// The invariant did not hold.
    Violated {
        /// Observed behavior description.
        observed: String,
    },
    /// Preconditions were not met; not evidence either way.
    NotApplicable,
}

/// One invariant evaluated on one step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evaluation {
    /// Invariant identifier.
    pub invariant_id: &'static str,
    /// Position of the step within the trace (not the step's self-reported `index`).
    pub step_index: usize,
    /// Outcome.
    pub verdict: Verdict,
}

fn d(after: u64, before: u64) -> i128 {
    i128::from(after) - i128::from(before)
}

fn acct_001(step: &StepRecord) -> Verdict {
    let (Action::Deposit { amount }, StepStatus::Ok) = (step.action, &step.status) else {
        return Verdict::NotApplicable;
    };
    let credit = d(step.after.escrow_recorded, step.before.escrow_recorded);
    let received = d(step.after.vault_amount, step.before.vault_amount);
    if credit == received {
        Verdict::Held
    } else {
        Verdict::Violated {
            observed: format!(
                "deposit of {amount} credited {credit} but the vault received {received} (withheld fee delta {})",
                d(
                    step.after.vault_withheld.unwrap_or(0),
                    step.before.vault_withheld.unwrap_or(0)
                )
            ),
        }
    }
}

fn solv_001(step: &StepRecord) -> Verdict {
    if step.status != StepStatus::Ok {
        return Verdict::NotApplicable;
    }
    let s = &step.after;
    if s.escrow_recorded <= s.vault_amount {
        Verdict::Held
    } else {
        Verdict::Violated {
            observed: format!(
                "escrow records {} owed but the vault holds {}: shortfall of {}",
                s.escrow_recorded,
                s.vault_amount,
                s.escrow_recorded - s.vault_amount
            ),
        }
    }
}

fn atom_001(step: &StepRecord) -> Verdict {
    if !matches!(step.status, StepStatus::Failed { .. }) {
        return Verdict::NotApplicable;
    }
    if step.before == step.after {
        Verdict::Held
    } else {
        Verdict::Violated {
            observed: format!(
                "failed step changed state: before={:?} after={:?}",
                step.before, step.after
            ),
        }
    }
}

fn cons_001(step: &StepRecord) -> Verdict {
    let (Action::Deposit { amount }, StepStatus::Ok) = (step.action, &step.status) else {
        return Verdict::NotApplicable;
    };
    let debit = d(step.before.depositor_balance, step.after.depositor_balance);
    let gain = d(step.after.vault_amount, step.before.vault_amount);
    let withheld = d(
        step.after.vault_withheld.unwrap_or(0),
        step.before.vault_withheld.unwrap_or(0),
    );
    if debit == i128::from(amount) && gain + withheld == i128::from(amount) {
        Verdict::Held
    } else {
        Verdict::Violated {
            observed: format!(
                "deposit of {amount}: depositor debited {debit}, vault gained {gain}, withheld gained {withheld}"
            ),
        }
    }
}

fn auth_001(step: &StepRecord) -> Verdict {
    if !step.action.expects_rejection() {
        return Verdict::NotApplicable;
    }
    if step.status == StepStatus::Ok {
        return Verdict::Violated {
            observed: format!(
                "{:?} succeeded but must be rejected: attacker balance {} -> {}, vault {} -> {}, recorded {} -> {}",
                step.action,
                step.before.attacker_balance,
                step.after.attacker_balance,
                step.before.vault_amount,
                step.after.vault_amount,
                step.before.escrow_recorded,
                step.after.escrow_recorded
            ),
        };
    }
    if step.before != step.after {
        return Verdict::Violated {
            observed: format!(
                "rejected {:?} still changed state: before={:?} after={:?}",
                step.action, step.before, step.after
            ),
        };
    }
    Verdict::Held
}

fn cust_001(step: &StepRecord) -> Verdict {
    if step.status != StepStatus::Ok || step.action == Action::Withdraw {
        return Verdict::NotApplicable;
    }
    if step.after.vault_amount >= step.before.vault_amount {
        Verdict::Held
    } else {
        Verdict::Violated {
            observed: format!(
                "{:?} reduced the vault from {} to {} without an authorized withdrawal (issuer balance {} -> {})",
                step.action,
                step.before.vault_amount,
                step.after.vault_amount,
                step.before.issuer_balance,
                step.after.issuer_balance
            ),
        }
    }
}

fn zero_001(step: &StepRecord) -> Verdict {
    if step.status != StepStatus::Ok {
        return Verdict::NotApplicable;
    }
    match step.action {
        Action::Deposit { amount } if amount > 0 => {
            let credit = d(step.after.escrow_recorded, step.before.escrow_recorded);
            let vault_gain = d(step.after.vault_amount, step.before.vault_amount);
            if credit <= 0 || vault_gain <= 0 {
                Verdict::Violated {
                    observed: format!(
                        "non-zero deposit of {amount} resulted in credit {credit} and vault gain {vault_gain}"
                    ),
                }
            } else {
                Verdict::Held
            }
        }
        Action::Withdraw if step.before.escrow_recorded > 0 => {
            let payout = d(
                step.after.destination_balance,
                step.before.destination_balance,
            );
            if payout <= 0 {
                Verdict::Violated {
                    observed: format!(
                        "withdrawal against {} recorded owed resulted in 0 destination payout",
                        step.before.escrow_recorded
                    ),
                }
            } else {
                Verdict::Held
            }
        }
        _ => Verdict::NotApplicable,
    }
}

fn dilut_001(step: &StepRecord) -> Verdict {
    if step.status != StepStatus::Ok {
        return Verdict::NotApplicable;
    }
    let b = &step.before;
    let a = &step.after;
    if b.escrow_recorded == 0 || a.escrow_recorded == 0 {
        return Verdict::NotApplicable;
    }
    // Check if vault_after / recorded_after >= vault_before / recorded_before
    // <=> vault_after * recorded_before >= vault_before * recorded_after
    let lhs = u128::from(a.vault_amount) * u128::from(b.escrow_recorded);
    let rhs = u128::from(b.vault_amount) * u128::from(a.escrow_recorded);
    if lhs >= rhs {
        Verdict::Held
    } else {
        Verdict::Violated {
            observed: format!(
                "exchange rate diluted: before={}/{} ({:.6}), after={}/{} ({:.6})",
                b.vault_amount,
                b.escrow_recorded,
                b.vault_amount as f64 / b.escrow_recorded as f64,
                a.vault_amount,
                a.escrow_recorded,
                a.vault_amount as f64 / a.escrow_recorded as f64
            ),
        }
    }
}

fn symm_001(step: &StepRecord) -> Verdict {
    if step.status != StepStatus::Ok {
        return Verdict::NotApplicable;
    }
    let b = &step.before;
    let a = &step.after;
    if a.escrow_recorded >= b.escrow_recorded {
        return Verdict::NotApplicable;
    }
    let liability_reduction = b.escrow_recorded - a.escrow_recorded;
    let vault_reduction = b.vault_amount.saturating_sub(a.vault_amount);
    if vault_reduction > liability_reduction {
        Verdict::Violated {
            observed: format!(
                "asymmetric drain: vault reduced by {vault_reduction} but recorded liability reduced by only {liability_reduction}"
            ),
        }
    } else {
        Verdict::Held
    }
}

fn pause_001(step: &StepRecord) -> Verdict {
    if step.before.mint_paused != Some(true) {
        return Verdict::NotApplicable;
    }
    let blocked_op = match step.action {
        Action::Deposit { amount }
        | Action::DelegateTransfer { amount }
        | Action::PermanentDelegateDrain { amount } => amount > 0,
        Action::Withdraw => {
            step.before.escrow_recorded > 0 || step.after.vault_amount < step.before.vault_amount
        }
        _ => false,
    };
    if !blocked_op {
        return Verdict::NotApplicable;
    }
    if step.status == StepStatus::Ok {
        Verdict::Violated {
            observed: format!(
                "{:?} succeeded while mint was paused (vault {} -> {}, recorded {} -> {})",
                step.action,
                step.before.vault_amount,
                step.after.vault_amount,
                step.before.escrow_recorded,
                step.after.escrow_recorded
            ),
        }
    } else if step.before != step.after {
        Verdict::Violated {
            observed: format!(
                "paused {:?} mutated state despite rejection: before={:?} after={:?}",
                step.action, step.before, step.after
            ),
        }
    } else {
        Verdict::Held
    }
}

fn freeze_001(step: &StepRecord) -> Verdict {
    let blocked_op = match step.action {
        Action::Deposit { amount } if amount > 0 => {
            step.before.depositor_frozen || step.before.vault_frozen
        }
        Action::DelegateTransfer { amount } if amount > 0 => step.before.depositor_frozen,
        Action::Withdraw => {
            step.before.vault_frozen
                && (step.before.escrow_recorded > 0
                    || step.after.vault_amount < step.before.vault_amount)
        }
        Action::PermanentDelegateDrain { amount } if amount > 0 => step.before.vault_frozen,
        _ => false,
    };
    if !blocked_op {
        return Verdict::NotApplicable;
    }
    if step.status == StepStatus::Ok {
        Verdict::Violated {
            observed: format!(
                "{:?} succeeded with frozen account (depositor_frozen={}, vault_frozen={}): vault {} -> {}",
                step.action,
                step.before.depositor_frozen,
                step.before.vault_frozen,
                step.before.vault_amount,
                step.after.vault_amount
            ),
        }
    } else if step.before != step.after {
        Verdict::Violated {
            observed: format!(
                "frozen {:?} mutated state despite rejection: before={:?} after={:?}",
                step.action, step.before, step.after
            ),
        }
    } else {
        Verdict::Held
    }
}

fn cpi_001(step: &StepRecord) -> Verdict {
    if !step.before.source_cpi_guard {
        return Verdict::NotApplicable;
    }
    let Action::Deposit { amount } = step.action else {
        return Verdict::NotApplicable;
    };
    if amount == 0 {
        return Verdict::NotApplicable;
    }
    if step.status == StepStatus::Ok {
        Verdict::Violated {
            observed: format!(
                "owner-signed CPI Deposit({amount}) succeeded while CPI Guard was enabled on source (vault {} -> {}, depositor {} -> {})",
                step.before.vault_amount,
                step.after.vault_amount,
                step.before.depositor_balance,
                step.after.depositor_balance
            ),
        }
    } else if step.before != step.after {
        Verdict::Violated {
            observed: format!(
                "CPI-guarded Deposit({amount}) mutated state despite rejection: before={:?} after={:?}",
                step.before, step.after
            ),
        }
    } else {
        Verdict::Held
    }
}

fn hook_001(step: &StepRecord) -> Verdict {
    let (Some(before_hooks), Some(after_hooks)) =
        (step.before.hook_invocations, step.after.hook_invocations)
    else {
        return Verdict::NotApplicable;
    };
    if matches!(step.status, StepStatus::Failed { .. }) {
        return if after_hooks != before_hooks {
            Verdict::Violated {
                observed: format!(
                    "failed step {:?} mutated hook_invocations from {before_hooks} to {after_hooks}",
                    step.action
                ),
            }
        } else {
            Verdict::Held
        };
    }
    let expects_hook = match step.action {
        Action::Deposit { amount }
        | Action::DelegateTransfer { amount }
        | Action::PermanentDelegateDrain { amount } => amount > 0,
        Action::Withdraw => {
            step.before.escrow_recorded > 0 || step.after.vault_amount < step.before.vault_amount
        }
        _ => false,
    };
    if expects_hook {
        if after_hooks > before_hooks {
            Verdict::Held
        } else {
            Verdict::Violated {
                observed: format!(
                    "TransferHook mint completed {:?} without invoking transfer hook (hook_invocations stayed at {after_hooks})",
                    step.action
                ),
            }
        }
    } else if after_hooks != before_hooks {
        Verdict::Violated {
            observed: format!(
                "non-transfer step {:?} unexpectedly changed hook_invocations from {before_hooks} to {after_hooks}",
                step.action
            ),
        }
    } else {
        Verdict::NotApplicable
    }
}

/// Trait for an invariant implementation.
pub trait Invariant: Send + Sync {
    /// Invariant definition metadata.
    fn def(&self) -> InvariantDef;
    /// Evaluate the invariant against a single step.
    fn evaluate(&self, step: &StepRecord) -> Verdict;
}

/// A wrapper around a function pointer and definition implementing [`Invariant`].
#[derive(Clone, Copy)]
pub struct FnInvariant {
    def: InvariantDef,
    check: fn(&StepRecord) -> Verdict,
}

impl FnInvariant {
    /// Create a new invariant from a definition and evaluation function.
    pub const fn new(def: InvariantDef, check: fn(&StepRecord) -> Verdict) -> Self {
        Self { def, check }
    }
}

impl Invariant for FnInvariant {
    fn def(&self) -> InvariantDef {
        self.def
    }

    fn evaluate(&self, step: &StepRecord) -> Verdict {
        (self.check)(step)
    }
}

/// Dynamic registry of invariants to evaluate against execution traces.
pub struct InvariantRegistry {
    invariants: Vec<Box<dyn Invariant>>,
}

impl Default for InvariantRegistry {
    fn default() -> Self {
        Self {
            invariants: vec![
                Box::new(FnInvariant::new(ACCT_001, acct_001)),
                Box::new(FnInvariant::new(SOLV_001, solv_001)),
                Box::new(FnInvariant::new(ATOM_001, atom_001)),
                Box::new(FnInvariant::new(CONS_001, cons_001)),
                Box::new(FnInvariant::new(AUTH_001, auth_001)),
                Box::new(FnInvariant::new(CUST_001, cust_001)),
            ],
        }
    }
}

impl InvariantRegistry {
    /// Create a registry with all 13 invariants (core 6 + ZERO/DILUT/SYMM + PAUSE/FREEZE/CPI/HOOK).
    pub fn with_extended_invariants() -> Self {
        let mut reg = Self::default();
        reg.register(FnInvariant::new(ZERO_001, zero_001));
        reg.register(FnInvariant::new(DILUT_001, dilut_001));
        reg.register(FnInvariant::new(SYMM_001, symm_001));
        reg.register(FnInvariant::new(PAUSE_001, pause_001));
        reg.register(FnInvariant::new(FREEZE_001, freeze_001));
        reg.register(FnInvariant::new(CPI_001, cpi_001));
        reg.register(FnInvariant::new(HOOK_001, hook_001));
        reg
    }

    /// Create an empty registry with no invariants.
    pub fn empty() -> Self {
        Self {
            invariants: Vec::new(),
        }
    }

    /// Register a new invariant.
    pub fn register(&mut self, invariant: impl Invariant + 'static) {
        self.invariants.push(Box::new(invariant));
    }

    /// List all registered invariant definitions.
    pub fn catalog(&self) -> Vec<InvariantDef> {
        self.invariants.iter().map(|i| i.def()).collect()
    }

    /// Number of registered invariants.
    pub fn len(&self) -> usize {
        self.invariants.len()
    }

    /// Whether the registry has no invariants.
    pub fn is_empty(&self) -> bool {
        self.invariants.is_empty()
    }

    /// Evaluate all registered invariants on every step of `trace`.
    pub fn evaluate(&self, trace: &ExecutionTrace) -> Vec<Evaluation> {
        let mut out = Vec::new();
        for (position, step) in trace.steps.iter().enumerate() {
            for inv in &self.invariants {
                let def = inv.def();
                out.push(Evaluation {
                    invariant_id: def.id,
                    step_index: position,
                    verdict: inv.evaluate(step),
                });
            }
        }
        out
    }

    /// Build findings from evaluations using this registry's registered invariant definitions.
    pub fn findings(
        &self,
        scenario: &Scenario,
        trace: &ExecutionTrace,
        evaluations: &[Evaluation],
    ) -> Vec<Finding> {
        let cat = self.catalog();
        findings_with_catalog(scenario, trace, evaluations, &cat)
    }
}

/// Evaluate every invariant on every step of `trace`, in step then catalog order.
pub fn evaluate(trace: &ExecutionTrace) -> Vec<Evaluation> {
    InvariantRegistry::default().evaluate(trace)
}

/// Run-level classification from evaluations and step statuses. `SetupError` is decided earlier
/// (the adapter returns an error) and never produced here.
pub fn classify(trace: &ExecutionTrace, evaluations: &[Evaluation]) -> OutcomeClass {
    if evaluations
        .iter()
        .any(|e| matches!(e.verdict, Verdict::Violated { .. }))
    {
        OutcomeClass::InvariantViolation
    } else if trace
        .steps
        .iter()
        .any(|s| matches!(s.status, StepStatus::Failed { .. }) && !s.action.expects_rejection())
    {
        OutcomeClass::ExecutionFailure
    } else {
        OutcomeClass::Pass
    }
}

fn delta(label: &str, account: &str, before: u64, after: u64) -> StateDelta {
    StateDelta {
        label: label.into(),
        account: account.into(),
        before,
        after,
    }
}

fn evidence(trace: &ExecutionTrace, before: &Snapshot, after: &Snapshot) -> Vec<StateDelta> {
    let acct = |l: &str| trace.address_of(l).unwrap_or("unknown").to_string();
    let mut v = vec![
        delta(
            "escrow_recorded",
            &acct("escrow_state"),
            before.escrow_recorded,
            after.escrow_recorded,
        ),
        delta(
            "vault_amount",
            &acct("vault"),
            before.vault_amount,
            after.vault_amount,
        ),
        delta(
            "depositor_balance",
            &acct("depositor_source"),
            before.depositor_balance,
            after.depositor_balance,
        ),
    ];
    if before.vault_withheld.is_some() || after.vault_withheld.is_some() {
        v.push(delta(
            "vault_withheld",
            &acct("vault"),
            before.vault_withheld.unwrap_or(0),
            after.vault_withheld.unwrap_or(0),
        ));
    }
    v
}

fn severity_for(id: &str) -> (Severity, &'static str) {
    match id {
        "INV-SOLV-001" => (
            Severity::High,
            "Recorded liabilities exceed vault assets, so honoring the record can fail or drain other users' funds. Exploitability by an attacker is not established by this check.",
        ),
        "INV-ACCT-001" => (
            Severity::Medium,
            "The escrow over- or under-credits relative to tokens actually held. Impact depends on how credits are later redeemed; this check alone does not prove exploitability.",
        ),
        "INV-CUST-001" => (
            Severity::High,
            "Tokens left the vault without the escrow's authorization. This is an integration-assumption failure caused by the mint's configuration (for example a permanent delegate), not necessarily a program bug; whether it is exploitable depends on who controls that authority.",
        ),
        "INV-AUTH-001" => (
            Severity::High,
            "An actor other than the depositor was able to act on the escrow. Severity is advisory; confirm the signer model before treating this as exploitable.",
        ),
        "INV-CONS-001" => (
            Severity::Medium,
            "Tokens are not conserved under the documented fee semantics, which suggests an accounting error in the observation or the program.",
        ),
        "INV-ZERO-001" => (
            Severity::High,
            "Non-zero user action resulted in 0 tokens transferred or credited, causing loss of user funds due to rounding truncation.",
        ),
        "INV-DILUT-001" => (
            Severity::High,
            "Asset-to-liability exchange rate decreased, diluting existing depositors' claims and enabling liquidity extraction.",
        ),
        "INV-SYMM-001" => (
            Severity::High,
            "Asymmetric state reduction observed: vault assets decreased faster than recorded liabilities.",
        ),
        "INV-PAUSE-001" => (
            Severity::High,
            "A token movement succeeded or mutated state while the Pausable mint was paused, bypassing mint-level emergency halt controls.",
        ),
        "INV-FREEZE-001" => (
            Severity::High,
            "A token transfer succeeded or mutated state while the source or vault account was frozen, bypassing Token-2022 freeze enforcement.",
        ),
        "INV-CPI-001" => (
            Severity::High,
            "An owner-signed CPI deposit bypassed CPI Guard protection on the depositor source account.",
        ),
        "INV-HOOK-001" => (
            Severity::High,
            "A TransferHook mint failed to invoke its hook on transfer or leaked hook state on a failed instruction.",
        ),
        _ => (
            Severity::Low,
            "A failed instruction left partial state, which can be exploitable depending on the program; severity is advisory.",
        ),
    }
}

/// Build one [`Finding`] per violated invariant (using its first violating step) in `trace`.
/// Findings always have class [`OutcomeClass::InvariantViolation`]; promotion to a suspected
/// vulnerability is a human decision.
pub fn findings(
    scenario: &Scenario,
    trace: &ExecutionTrace,
    evaluations: &[Evaluation],
) -> Vec<Finding> {
    findings_with_catalog(scenario, trace, evaluations, &catalog())
}

/// Build findings looking up invariant definitions in a provided catalog slice.
pub fn findings_with_catalog(
    scenario: &Scenario,
    trace: &ExecutionTrace,
    evaluations: &[Evaluation],
    defs: &[InvariantDef],
) -> Vec<Finding> {
    let mut seen = Vec::<&'static str>::new();
    let mut out = Vec::new();
    for e in evaluations {
        let Verdict::Violated { observed } = &e.verdict else {
            continue;
        };
        if seen.contains(&e.invariant_id) {
            continue;
        }
        seen.push(e.invariant_id);
        let Some(step) = trace.steps.get(e.step_index) else {
            continue;
        };
        let def = defs.iter().find(|d| d.id == e.invariant_id);
        let expected_desc = match def {
            Some(d) => format!("{} ({})", d.expected, d.name),
            None => format!("custom invariant {}", e.invariant_id),
        };
        let (severity, rationale) = severity_for(e.invariant_id);
        let scenario_id = scenario.id();
        out.push(Finding {
            schema_version: SCHEMA_VERSION,
            id: Finding::compute_id(&scenario.target, &scenario_id, e.invariant_id),
            target: scenario.target.clone(),
            scenario_id: scenario_id.clone(),
            seed: scenario.seed,
            invariant_id: e.invariant_id.into(),
            class: OutcomeClass::InvariantViolation,
            expected: expected_desc,
            observed: format!("step {}: {observed}", e.step_index),
            deltas: evidence(trace, &step.before, &step.after),
            logs: step.logs.clone(),
            severity,
            severity_rationale: rationale.into(),
            reproduction: Reproduction {
                command: format!("tokenscope replay {scenario_id}.json"),
                scenario: scenario.clone(),
            },
            minimized: None,
        });
    }
    out
}

#[cfg(test)]
mod tests;
