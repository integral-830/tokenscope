//! Scenario generation.
//!
//! * [`builtin_suite`] is a fixed, hand-written set covering transfer fees, rounding, boundaries
//!   and failure cases.
//! * [`generate`] derives scenarios from a seed with a small, documented PRNG (SplitMix64), so
//!   the same seed always yields the same scenarios on every platform.

use tokenscope_model::{
    Action, MAX_ACTIONS, MintExtension, MintSpec, Mismatch, SCHEMA_VERSION, Scenario,
    TransferFeeParams,
};

mod dimensions;
mod guided;
mod stateful;

pub use dimensions::{
    AMOUNT_CLASSES, Coverage, FEE_CLASSES, amount_class, cells, fee_class, universe,
};
pub use guided::{
    BOUNDARY_BPS, BOUNDARY_MAX_FEE, GuidedBatch, boundary_scenarios, generate_extended,
    generate_guided, mutate, rounding_boundaries,
};
pub use stateful::generate_stateful;

/// SplitMix64 pseudo-random generator (Steele, Lea, Flood 2014). Deterministic and portable.
#[derive(Debug, Clone)]
pub struct SplitMix64(u64);

impl SplitMix64 {
    /// Create a generator from a seed.
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }

    /// Next 64 random bits.
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform-ish value in `0..bound` (`bound > 0`; modulo bias is irrelevant for test generation).
    pub fn below(&mut self, bound: u64) -> u64 {
        self.next_u64() % bound
    }
}

fn base(
    name: &str,
    target: &str,
    fee: Option<(u16, u64)>,
    balance: u64,
    actions: Vec<Action>,
) -> Scenario {
    Scenario {
        schema_version: SCHEMA_VERSION,
        name: name.into(),
        seed: 0,
        target: target.into(),
        mint: MintSpec {
            decimals: 6,
            transfer_fee: fee.map(|(basis_points, maximum_fee)| TransferFeeParams {
                basis_points,
                maximum_fee,
            }),
        },
        initial_balance: balance,
        extensions: vec![],
        actions,
    }
}

fn ext(
    name: &str,
    target: &str,
    fee: Option<(u16, u64)>,
    extensions: Vec<MintExtension>,
    balance: u64,
    actions: Vec<Action>,
) -> Scenario {
    Scenario {
        extensions,
        ..base(name, target, fee, balance, actions)
    }
}

fn dep(amount: u64) -> Action {
    Action::Deposit { amount }
}

/// The fixed scenario suite for `target`.
pub fn builtin_suite(target: &str) -> Vec<Scenario> {
    let t = target;
    let max = u64::MAX;
    vec![
        base("control-no-fee", t, None, 10_000, vec![dep(1_000)]),
        base(
            "fee-2pct-deposit",
            t,
            Some((200, max)),
            10_000,
            vec![dep(1_000)],
        ),
        base(
            "fee-2pct-deposit-withdraw",
            t,
            Some((200, max)),
            10_000,
            vec![dep(1_000), Action::Withdraw],
        ),
        base(
            "fee-rounds-up-tiny-deposit",
            t,
            Some((1, max)),
            100,
            vec![dep(1)],
        ),
        base(
            "fee-capped-by-maximum",
            t,
            Some((1_000, 10)),
            100_000,
            vec![dep(50_000)],
        ),
        base(
            "fee-100pct-consumes-deposit",
            t,
            Some((10_000, max)),
            1_000,
            vec![dep(500)],
        ),
        base(
            "zero-amount-deposit",
            t,
            Some((500, max)),
            100,
            vec![dep(0)],
        ),
        base(
            "two-deposits-accumulate",
            t,
            Some((300, max)),
            10_000,
            vec![dep(1_000), dep(2_000)],
        ),
        base(
            "large-amount",
            t,
            Some((50, max)),
            2_000_000_000_000_000,
            vec![dep(1_000_000_000_000_000)],
        ),
        base(
            "failure-insufficient-funds",
            t,
            Some((200, max)),
            10,
            vec![dep(1_000)],
        ),
        base(
            "frozen-source-deposit-rejected",
            t,
            Some((200, max)),
            10_000,
            vec![Action::FreezeDepositor, dep(1_000)],
        ),
        base(
            "freeze-thaw-then-deposit",
            t,
            Some((200, max)),
            10_000,
            vec![Action::FreezeDepositor, Action::ThawDepositor, dep(1_000)],
        ),
        base(
            "unauthorized-withdraw-rejected",
            t,
            None,
            10_000,
            vec![dep(1_000), Action::UnauthorizedWithdraw],
        ),
        base(
            "withdraw-with-nothing-recorded",
            t,
            Some((200, max)),
            10,
            vec![Action::Withdraw],
        ),
    ]
}

/// Which built-in scenarios a campaign runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuiteSelection {
    /// No built-in scenarios (only generated ones).
    None,
    /// The original fee-accounting suite ([`builtin_suite`]).
    Core,
    /// Extension, authorization and boundary scenarios ([`extension_suite`]).
    Extensions,
    /// Combined realistic Token-2022 mint profile scenarios ([`mint_profile_suite`]).
    Profiles,
    /// Core and extension suites (24 scenarios, backward-compatible default).
    All,
    /// Core, extension, and combined mint profile suites.
    Full,
}

impl SuiteSelection {
    /// Parse `none | core | extensions | profiles | all | full`.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "none" => Some(Self::None),
            "core" => Some(Self::Core),
            "extensions" => Some(Self::Extensions),
            "profiles" => Some(Self::Profiles),
            "all" => Some(Self::All),
            "full" => Some(Self::Full),
            _ => Option::None,
        }
    }

    /// The selected scenarios for `target`.
    pub fn scenarios(self, target: &str) -> Vec<Scenario> {
        let mut v = Vec::new();
        if matches!(self, Self::Core | Self::All | Self::Full) {
            v.extend(builtin_suite(target));
        }
        if matches!(self, Self::Extensions | Self::All | Self::Full) {
            v.extend(extension_suite(target));
        }
        if matches!(self, Self::Profiles | Self::Full) {
            v.extend(mint_profile_suite(target));
        }
        v
    }
}

/// Combined realistic Token-2022 mint profile scenarios exercising multi-extension interactions
/// (e.g., regulated RWA mints combining TransferFee + Pausable + DefaultAccountState + PermanentDelegate).
pub fn mint_profile_suite(target: &str) -> Vec<Scenario> {
    let t = target;
    let max = u64::MAX;
    vec![
        ext(
            "profile-rwa-regulated-mint",
            t,
            Some((25, 10_000)),
            vec![
                MintExtension::Pausable,
                MintExtension::DefaultAccountState { frozen: true },
                MintExtension::PermanentDelegate,
            ],
            100_000,
            vec![
                dep(1_000),
                Action::ThawVault,
                Action::Pause,
                dep(1_000),
                Action::Resume,
                dep(10_000),
                Action::PermanentDelegateDrain { amount: 2_000 },
            ],
        ),
        ext(
            "profile-cpi-guarded-pausable-fee",
            t,
            Some((200, max)),
            vec![MintExtension::Pausable],
            20_000,
            vec![
                Action::EnableCpiGuard,
                Action::ApproveDelegate { amount: 1_000 },
                dep(2_000),
                Action::DelegateTransfer { amount: 500 },
                Action::Pause,
                Action::DelegateTransfer { amount: 200 },
                Action::Resume,
                Action::DisableCpiGuard,
                dep(2_000),
                Action::Withdraw,
            ],
        ),
        ext(
            "profile-hooked-rwa-pause-freeze",
            t,
            Some((50, max)),
            vec![
                MintExtension::TransferHook,
                MintExtension::Pausable,
                MintExtension::DefaultAccountState { frozen: true },
            ],
            10_000,
            vec![
                dep(1_000),
                Action::ThawVault,
                Action::Pause,
                dep(1_000),
                Action::Resume,
                dep(1_000),
            ],
        ),
        ext(
            "profile-micro-fee-dust-truncation",
            t,
            Some((100, max)),
            vec![MintExtension::Pausable],
            10_000,
            vec![dep(500), dep(1)],
        ),
        ext(
            "profile-freeze-source-allows-withdraw-dest",
            t,
            None,
            vec![MintExtension::Pausable],
            10_000,
            vec![
                dep(1_000),
                Action::FreezeDepositor,
                dep(500),
                Action::Withdraw,
                Action::ThawDepositor,
            ],
        ),
    ]
}

/// Extension, authorization and boundary scenarios. Note that `permanent-delegate-drains-vault`
/// is a finding on *both* escrow flavors: neither checks the mint's extensions.
pub fn extension_suite(target: &str) -> Vec<Scenario> {
    let t = target;
    let max = u64::MAX;
    vec![
        ext(
            "pausable-deposit-gated",
            t,
            None,
            vec![MintExtension::Pausable],
            10_000,
            vec![Action::Pause, dep(1_000), Action::Resume, dep(1_000)],
        ),
        base(
            "cpi-guard-blocks-escrow-deposit",
            t,
            None,
            10_000,
            vec![
                Action::EnableCpiGuard,
                dep(1_000),
                Action::DisableCpiGuard,
                dep(1_000),
            ],
        ),
        ext(
            "default-frozen-vault-blocks-deposit",
            t,
            None,
            vec![MintExtension::DefaultAccountState { frozen: true }],
            10_000,
            vec![dep(1_000), Action::ThawVault, dep(1_000)],
        ),
        ext(
            "permanent-delegate-drains-vault",
            t,
            None,
            vec![MintExtension::PermanentDelegate],
            10_000,
            vec![dep(1_000), Action::PermanentDelegateDrain { amount: 500 }],
        ),
        base(
            "delegate-allowance-lifecycle",
            t,
            None,
            10_000,
            vec![
                Action::ApproveDelegate { amount: 300 },
                Action::DelegateTransfer { amount: 200 },
                Action::DelegateTransfer { amount: 200 },
                Action::RevokeDelegate,
            ],
        ),
        ext(
            "transfer-hook-mint-unsupported-by-escrow",
            t,
            None,
            vec![MintExtension::TransferHook],
            10_000,
            vec![dep(1_000)],
        ),
        base(
            "mismatched-accounts-rejected",
            t,
            None,
            10_000,
            vec![
                dep(1_000),
                Action::MismatchedDeposit {
                    mismatch: Mismatch::WrongMint,
                    amount: 5,
                },
                Action::MismatchedDeposit {
                    mismatch: Mismatch::WrongVault,
                    amount: 5,
                },
                Action::MismatchedDeposit {
                    mismatch: Mismatch::WrongTokenProgram,
                    amount: 5,
                },
                Action::MismatchedWithdraw {
                    mismatch: Mismatch::WrongMint,
                },
                Action::MismatchedWithdraw {
                    mismatch: Mismatch::WrongVault,
                },
                Action::MismatchedWithdraw {
                    mismatch: Mismatch::WrongTokenProgram,
                },
                Action::MismatchedWithdraw {
                    mismatch: Mismatch::WrongAuthority,
                },
                Action::ReinitEscrow,
            ],
        ),
        base(
            "repeated-withdrawals",
            t,
            None,
            10_000,
            vec![dep(1_000), Action::Withdraw, Action::Withdraw],
        ),
        base(
            "u64-max-deposit-no-fee",
            t,
            None,
            u64::MAX,
            vec![dep(u64::MAX), Action::Withdraw],
        ),
        base(
            "u64-max-deposit-with-fee",
            t,
            Some((100, max)),
            u64::MAX,
            vec![dep(u64::MAX)],
        ),
    ]
}

/// Generate `count` scenarios for `target` from `seed`. Scenario `i` records the seed it was
/// derived from (`seed` mixed with `i`), so it can be regenerated independently.
pub fn generate(seed: u64, count: usize, target: &str) -> Vec<Scenario> {
    (0..count as u64)
        .map(|i| {
            generate_one(
                seed.wrapping_add(i.wrapping_mul(0xA24B_AED4_963E_E407)),
                i,
                target,
            )
        })
        .collect()
}

fn generate_one(seed: u64, index: u64, target: &str) -> Scenario {
    let mut rng = SplitMix64::new(seed);
    let fee = match rng.below(4) {
        0 => None,
        1 => Some((rng.below(10_001) as u16, u64::MAX)),
        2 => Some((rng.below(10_001) as u16, 1 + rng.below(1_000))),
        _ => Some((1 + rng.below(50) as u16, u64::MAX)),
    };
    let balance = 1 + rng.below(1_000_000);
    let n_actions = 1 + rng.below(4) as usize;
    let mut actions = Vec::with_capacity(n_actions);
    for _ in 0..n_actions.min(MAX_ACTIONS) {
        if rng.below(5) == 0 {
            actions.push(Action::Withdraw);
        } else {
            let amount = match rng.below(4) {
                0 => rng.below(4),
                1 => 1 + rng.below(100),
                _ => rng.below(balance / 2 + 1),
            };
            actions.push(dep(amount));
        }
    }
    let mut s = base(&format!("generated-{index}"), target, fee, balance, actions);
    s.seed = seed;
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splitmix_matches_reference_vector() {
        // First outputs of SplitMix64 seeded with 0 (reference implementation values).
        let mut r = SplitMix64::new(0);
        assert_eq!(r.next_u64(), 0xE220_A839_7B1D_CDAF);
        assert_eq!(r.next_u64(), 0x6E78_9E6A_A1B9_65F4);
    }

    #[test]
    fn builtin_suite_is_valid_and_uniquely_identified() {
        let suite = builtin_suite("demo-escrow-vulnerable");
        assert!(suite.len() >= 10);
        let mut ids: Vec<_> = suite.iter().map(Scenario::id).collect();
        for s in &suite {
            s.validate().unwrap();
        }
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), suite.len());
    }

    #[test]
    fn same_seed_same_scenarios_different_seed_differs() {
        let a = generate(42, 20, "t");
        assert_eq!(a, generate(42, 20, "t"));
        assert_ne!(a, generate(43, 20, "t"));
    }

    #[test]
    fn generated_scenarios_are_valid_and_regenerable_from_recorded_seed() {
        for (i, s) in generate(7, 50, "t").iter().enumerate() {
            s.validate().unwrap();
            assert_eq!(&generate_one(s.seed, i as u64, "t"), s);
        }
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn every_seed_generates_valid_deterministic_scenarios(seed in any::<u64>(), count in 1usize..8) {
            let a = generate(seed, count, "demo-escrow-vulnerable");
            prop_assert_eq!(a.len(), count);
            for s in &a { prop_assert!(s.validate().is_ok()); }
            prop_assert_eq!(a, generate(seed, count, "demo-escrow-vulnerable"));
        }

        #[test]
        fn stateful_generation_is_valid_and_deterministic(seed in any::<u64>(), count in 1usize..8) {
            let a = generate_stateful(seed, count, "demo-escrow-vulnerable");
            prop_assert_eq!(a.len(), count);
            for s in &a { prop_assert!(s.validate().is_ok()); }
            prop_assert_eq!(a, generate_stateful(seed, count, "demo-escrow-vulnerable"));
        }
    }
}

#[cfg(test)]
mod suite_tests {
    use super::*;

    #[test]
    fn suites_are_valid_disjoint_and_selectable() {
        let core = builtin_suite("t");
        let ext = extension_suite("t");
        let profiles = mint_profile_suite("t");
        assert_eq!(
            core.len(),
            14,
            "the original suite is unchanged (IDs depend on it)"
        );
        assert_eq!(ext.len(), 10);
        assert_eq!(profiles.len(), 5);
        let mut ids: Vec<_> = core
            .iter()
            .chain(&ext)
            .chain(&profiles)
            .map(Scenario::id)
            .collect();
        for s in core.iter().chain(&ext).chain(&profiles) {
            s.validate().unwrap();
        }
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), 29, "no duplicate scenarios across suites");
        assert_eq!(SuiteSelection::All.scenarios("t").len(), 24);
        assert_eq!(SuiteSelection::Full.scenarios("t").len(), 29);
        assert_eq!(SuiteSelection::Core.scenarios("t"), core);
        assert_eq!(SuiteSelection::Extensions.scenarios("t"), ext);
        assert_eq!(SuiteSelection::Profiles.scenarios("t"), profiles);
        assert!(SuiteSelection::None.scenarios("t").is_empty());
        assert_eq!(SuiteSelection::parse("all"), Some(SuiteSelection::All));
        assert_eq!(
            SuiteSelection::parse("profiles"),
            Some(SuiteSelection::Profiles)
        );
        assert_eq!(SuiteSelection::parse("full"), Some(SuiteSelection::Full));
        assert_eq!(SuiteSelection::parse("everything"), None);
    }
}
