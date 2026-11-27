//! Generic Solana SBF target adapter and interactive stateful SVM session.
//!
//! Loads arbitrary compiled `.so` SBF programs into Mollusk (`tokenscope_executor::Harness`),
//! provisions Token-2022 mints, PDAs, and program/system accounts from declarative specs, and
//! observes objective account deltas (`RawSnapshot`, lamports, SPL balances, watched byte offsets,
//! and authority slots) without hardcoding protocol-specific logic.

use std::{
    collections::{BTreeMap, HashMap},
    path::PathBuf,
    str::FromStr,
};

use serde::{Deserialize, Serialize};
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use tokenscope_executor::{
    AccountInspection, ExecError, Harness, MintExt, MintPlan, SvmSnapshot, derive_address,
    sha256_hex,
};
use tokenscope_model::{MintExtension, RawSnapshot, Scenario, StepStatus};

use crate::{
    AdapterCapabilities, AdapterVersion, TargetAdapter,
    generic_checks::{CheckFinding, CheckSpec, evaluate_checks},
};

/// Extra companion ELF program to load alongside the primary target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtraProgramSpec {
    /// Logical label used when referencing this program in calls or PDAs.
    pub label: String,
    /// Optional explicit Base58 program ID; deterministically derived if omitted.
    #[serde(default)]
    pub program_id: Option<String>,
    /// Filesystem path to the compiled `.so` SBF ELF.
    pub elf_path: PathBuf,
}

/// Declarative Token-2022 mint provisioning specification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MintSetupSpec {
    /// Logical mint label referenced by token accounts.
    pub label: String,
    /// Token decimals.
    #[serde(default = "default_decimals")]
    pub decimals: u8,
    /// Optional transfer-fee basis points (Token-2022 `TransferFeeConfig`).
    #[serde(default)]
    pub transfer_fee_bp: Option<u16>,
    /// Optional transfer-fee maximum cap in base units.
    #[serde(default)]
    pub maximum_fee: Option<u64>,
    /// Enable the `Pausable` Token-2022 mint extension.
    #[serde(default)]
    pub pausable: bool,
    /// Enable the `DefaultAccountState` Token-2022 mint extension.
    #[serde(default)]
    pub default_frozen: Option<bool>,
    /// Optional label or pubkey of a `PermanentDelegate` extension.
    #[serde(default)]
    pub permanent_delegate: Option<String>,
    /// Optional label or pubkey of a `TransferHook` program (`demo-hook` compatible).
    #[serde(default)]
    pub hook_program_label: Option<String>,
}

fn default_decimals() -> u8 {
    6
}

/// Single seed component for declarative PDA resolution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SeedSpec {
    /// Literal UTF-8 string seed (e.g. `"escrow"`).
    Utf8 {
        /// UTF-8 seed bytes.
        value: String,
    },
    /// Raw hex-encoded seed bytes.
    Hex {
        /// Hex-encoded bytes.
        hex: String,
    },
    /// 32-byte public key of another resolved account or program label.
    Account {
        /// Account or program label already defined earlier in the spec.
        label: String,
    },
}

/// Objective byte-offset watcher for an unsigned 64-bit little-endian counter in raw account data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct U64FieldSpec {
    /// Field name recorded in state deltas (e.g. `escrow_recorded`, `total_shares`).
    pub name: String,
    /// Byte offset where the 8-byte little-endian integer starts.
    pub offset: usize,
    /// Economic classification: `liability`, `reserve`, `shares`, or `state`.
    #[serde(default = "default_field_kind")]
    pub kind: String,
    /// Optional asset label when `kind` maps to a value flow (`liability`/`reserve`/`shares`).
    #[serde(default)]
    pub asset: Option<String>,
}

fn default_field_kind() -> String {
    "state".to_string()
}

/// Declarative account setup entry for a generic SBF session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountSetupSpec {
    /// Logical label (also used in call account lists).
    pub label: String,
    /// Economic role (`attacker`, `user`, `depositor`, `vault`, `protocol`, `admin`, `fee_recipient`).
    #[serde(default = "default_role")]
    pub role: String,
    /// Provisioning kind: `system`, `program_owned`, `pda`, or `token`.
    #[serde(default = "default_acct_kind")]
    pub kind: String,
    /// Mint label for `token` accounts.
    #[serde(default)]
    pub mint: Option<String>,
    /// Owner label/pubkey (`system` by default for `system`, primary target for `program_owned`, authority for `token`).
    #[serde(default)]
    pub owner_label: Option<String>,
    /// For `token` accounts: create it at the owner's associated token account address
    /// (programs using `associated_token::` constraints verify the address).
    #[serde(default)]
    pub associated: bool,
    /// Initial SPL token amount minted into this `token` account.
    #[serde(default)]
    pub initial_amount: Option<u64>,
    /// Explicit lamport balance (defaults to rent-exempt minimum or funded system balance).
    #[serde(default)]
    pub lamports: Option<u64>,
    /// Account data byte length for `program_owned`/`pda` accounts.
    #[serde(default)]
    pub space: Option<usize>,
    /// Optional initial account bytes in hex (zero-padded up to `space`).
    #[serde(default)]
    pub data_hex: Option<String>,
    /// Optional PDA derivation seeds (`kind == "pda"`).
    #[serde(default)]
    pub pda_seeds: Vec<SeedSpec>,
    /// Program label whose ID derives the PDA (defaults to primary target program).
    #[serde(default)]
    pub pda_program_label: Option<String>,
    /// Generic 64-bit integer watchers inside this account's byte buffer.
    #[serde(default)]
    pub u64_fields: Vec<U64FieldSpec>,
    /// Byte offsets storing 32-byte authority pubkeys watched for unauthorized mutations.
    #[serde(default)]
    pub authority_offsets: Vec<usize>,
}

fn default_role() -> String {
    "protocol".to_string()
}

fn default_acct_kind() -> String {
    "system".to_string()
}

/// Reference to one account inside a single SBF instruction invocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SbfAccountMetaSpec {
    /// Resolved account or program label (or `"payer"`, `"token2022"`, `"system"`, `"target"`).
    #[serde(default)]
    pub label: String,
    /// Optional explicit Base58 pubkey override.
    #[serde(default)]
    pub pubkey: Option<String>,
    /// Whether this account signs the instruction.
    #[serde(default)]
    pub is_signer: bool,
    /// Whether this account is marked writable.
    #[serde(default)]
    pub is_writable: bool,
}

/// Generic SBF instruction invocation specification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SbfCallSpec {
    /// Program label (default: primary target program, `"token2022"`, `"system"`, or extra program label).
    #[serde(default)]
    pub program_label: Option<String>,
    /// Raw instruction payload bytes in hex (e.g. `01e803000000000000` for `[1, 1000u64 LE]`).
    #[serde(default)]
    pub data_hex: String,
    /// Ordered account metas passed to the instruction.
    #[serde(default)]
    pub accounts: Vec<SbfAccountMetaSpec>,
    /// Caller account label for normalized trace metadata.
    #[serde(default)]
    pub caller_label: Option<String>,
    /// Caller economic role (`attacker`, `user`, `depositor`, `admin`).
    #[serde(default)]
    pub caller_role: Option<String>,
    /// Logical entrypoint function name for normalized trace metadata.
    #[serde(default)]
    pub fn_name: Option<String>,
}

/// Complete configuration for provisioning a [`GenericSbfSession`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenericSbfConfig {
    /// Target identifier.
    pub target_id: String,
    /// Optional explicit Base58 program ID (derived from `target_id` if omitted).
    #[serde(default)]
    pub program_id: Option<String>,
    /// Primary compiled `.so` SBF ELF path.
    pub elf_path: PathBuf,
    /// Companion ELF programs to load in the same Mollusk instance.
    #[serde(default)]
    pub extra_programs: Vec<ExtraProgramSpec>,
    /// Mints to provision before creating token accounts.
    #[serde(default)]
    pub mints: Vec<MintSetupSpec>,
    /// Accounts to provision and track for raw/token/field diffs.
    #[serde(default)]
    pub accounts: Vec<AccountSetupSpec>,
    /// Optional initial instructions executed after account provisioning (e.g. `init`).
    #[serde(default)]
    pub setup_calls: Vec<SbfCallSpec>,
}

/// Normalized balance/accounting flow emitted from real SVM account diffs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedValueFlow {
    /// Asset identifier (mint label, `"SOL"`, or watched token asset).
    pub asset: String,
    /// Account label.
    pub account: String,
    /// Account economic role.
    pub role: String,
    /// Logical owner label (or Base58 pubkey) owning this account on-chain.
    #[serde(default)]
    pub owner: String,
    /// Quantity before the step.
    pub before: i128,
    /// Quantity after the step.
    pub after: i128,
    /// Delta (`after - before`).
    pub delta: i128,
    /// Flow classification (`balance`, `supply`, `liability`, `reserve`, `shares`, `fee`).
    pub kind: String,
}

/// Normalized state/byte delta emitted from real SVM account diffs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedStateDelta {
    /// Watched field name or `raw_data_digest`.
    pub var_name: String,
    /// Owning account label.
    pub contract: String,
    /// String/integer representation before the step.
    pub before: serde_json::Value,
    /// String/integer representation after the step.
    pub after: serde_json::Value,
}

/// Normalized authority/pubkey mutation observed during a call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedPrivilegeChange {
    /// Subject identifier (`<account>@<offset>` or `<account>.owner`).
    pub subject: String,
    /// Action tag (`authority_change`, `token_owner_change`, `delegate_change`).
    pub action: String,
    /// Caller label.
    pub actor: String,
    /// Caller role.
    pub actor_role: String,
    /// Account label whose authority slot changed.
    pub target: String,
    /// Human-readable `before -> after` detail.
    pub detail: String,
}

/// Normalized outcome of executing one [`SbfCallSpec`] or multi-instruction sequence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SbfCallObservation {
    /// `"ok"` when the instruction succeeded, `"reverted"` when rejected.
    pub status: String,
    /// Error message when rejected.
    pub revert_reason: String,
    /// Compute units consumed.
    pub compute_units: u64,
    /// Runtime log lines emitted.
    pub logs: Vec<String>,
    /// Objective balance/supply/liability/reserve deltas across tracked accounts.
    pub value_flows: Vec<ObservedValueFlow>,
    /// Watched byte fields and raw data digests that changed.
    pub state_deltas: Vec<ObservedStateDelta>,
    /// Observed authority pubkey or token ownership mutations.
    pub privilege_changes: Vec<ObservedPrivilegeChange>,
    /// Optional raw SVM snapshot before execution.
    pub raw_before: RawSnapshot,
    /// Optional raw SVM snapshot after execution.
    pub raw_after: RawSnapshot,
}

/// Spec accepted by `tokenscope sbf-run` and [`GenericSbfAdapter`] for batch trace execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenericBatchSpec {
    /// Generic program + mint + account provisioning configuration.
    pub config: GenericSbfConfig,
    /// Scenario descriptor used for metadata and identification.
    #[serde(default)]
    pub scenario: Option<Scenario>,
    /// Sequence of SBF instructions to execute after `config.setup_calls`.
    #[serde(default)]
    pub calls: Vec<SbfCallSpec>,
    /// Declarative checks evaluated against the observed steps.
    #[serde(default)]
    pub checks: Vec<CheckSpec>,
}

/// Persistent interactive Mollusk SVM session over arbitrary compiled SBF `.so` programs.
pub struct GenericSbfSession {
    config: GenericSbfConfig,
    harness: Harness,
    target_program_id: Pubkey,
    programs: HashMap<String, Pubkey>,
    accounts: HashMap<String, Pubkey>,
    account_specs: Vec<AccountSetupSpec>,
    mint_specs: HashMap<String, MintSetupSpec>,
    snapshots: BTreeMap<u64, SvmSnapshot>,
    next_snap_id: u64,
}

fn decode_hex(raw: &str) -> Result<Vec<u8>, ExecError> {
    let s = raw.trim().strip_prefix("0x").unwrap_or(raw.trim());
    if !s.len().is_multiple_of(2) {
        return Err(ExecError::Setup {
            step: "decode-hex".into(),
            detail: format!("odd hex length {}", s.len()),
        });
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for chunk in s.as_bytes().as_chunks::<2>().0 {
        let pair = std::str::from_utf8(chunk).map_err(|e| ExecError::Setup {
            step: "decode-hex".into(),
            detail: e.to_string(),
        })?;
        let byte = u8::from_str_radix(pair, 16).map_err(|e| ExecError::Setup {
            step: "decode-hex".into(),
            detail: format!("invalid hex `{pair}`: {e}"),
        })?;
        out.push(byte);
    }
    Ok(out)
}

fn parse_or_derive(explicit: Option<&str>, label: &str) -> Result<Pubkey, ExecError> {
    match explicit {
        Some(s) if !s.trim().is_empty() => {
            Pubkey::from_str(s.trim()).map_err(|e| ExecError::Setup {
                step: "parse-pubkey".into(),
                detail: format!("invalid pubkey `{s}` for `{label}`: {e}"),
            })
        }
        _ => Ok(derive_address(label)),
    }
}

/// Empty counterpart of `present` for an account that does not exist on the other side of a call:
/// zero lamports, zero-filled data of the same length, and a zero token balance (with zero withheld
/// fees when the present side tracks them).
fn absent_like(present: &AccountInspection) -> AccountInspection {
    AccountInspection {
        owner: present.owner,
        lamports: 0,
        executable: false,
        data: vec![0; present.data.len()],
        token: present
            .token
            .map(|t| tokenscope_executor::TokenAccountView {
                amount: 0,
                withheld: t.withheld.map(|_| 0),
                delegate: None,
                delegated_amount: 0,
                frozen: false,
                owner: t.owner,
            }),
        mint_supply: None,
        mint_paused: None,
    }
}

fn read_u64_le(data: &[u8], offset: usize) -> Option<u64> {
    let slice = data.get(offset..offset.checked_add(8)?)?;
    let mut buf = [0u8; 8];
    buf.copy_from_slice(slice);
    Some(u64::from_le_bytes(buf))
}

fn read_pubkey32(data: &[u8], offset: usize) -> Option<Pubkey> {
    let slice = data.get(offset..offset.checked_add(32)?)?;
    let mut buf = [0u8; 32];
    buf.copy_from_slice(slice);
    Some(Pubkey::new_from_array(buf))
}

impl GenericSbfSession {
    /// Provision a fresh Mollusk VM from `config`, load ELFs, create mints/accounts, and run `setup_calls`.
    pub fn deploy(config: GenericSbfConfig) -> Result<Self, ExecError> {
        let mut h = Harness::new();
        let target_program_id = parse_or_derive(
            config.program_id.as_deref(),
            &format!("program/{}", config.target_id),
        )?;
        let elf = std::fs::read(&config.elf_path).map_err(|e| ExecError::Setup {
            step: "load-program".into(),
            detail: format!("{}: {e}", config.elf_path.display()),
        })?;
        h.load_program(&target_program_id, &elf);
        h.load_associated_token_program();

        let mut programs: HashMap<String, Pubkey> = HashMap::new();
        programs.insert("target".to_string(), target_program_id);
        programs.insert(config.target_id.clone(), target_program_id);
        programs.insert("token2022".to_string(), spl_token_2022_interface::id());
        programs.insert("system".to_string(), solana_system_interface::program::ID);
        programs.insert(
            "associated_token".to_string(),
            Harness::associated_token_program_id(),
        );

        for ep in &config.extra_programs {
            let pid = parse_or_derive(ep.program_id.as_deref(), &format!("program/{}", ep.label))?;
            let extra_elf = std::fs::read(&ep.elf_path).map_err(|e| ExecError::Setup {
                step: "load-extra-program".into(),
                detail: format!("{}: {e}", ep.elf_path.display()),
            })?;
            h.load_program(&pid, &extra_elf);
            programs.insert(ep.label.clone(), pid);
        }

        let mut accounts: HashMap<String, Pubkey> = HashMap::new();
        accounts.insert("payer".to_string(), h.payer());
        accounts.insert("target".to_string(), target_program_id);
        accounts.insert("token2022".to_string(), spl_token_2022_interface::id());
        accounts.insert("system".to_string(), solana_system_interface::program::ID);
        for (lbl, pid) in &programs {
            accounts.entry(lbl.clone()).or_insert(*pid);
        }

        // Pre-seed system addresses referenced by mint extensions or PDAs cleanly in two passes
        let mut mint_specs: HashMap<String, MintSetupSpec> = HashMap::new();
        for ms in &config.mints {
            let mut exts = Vec::new();
            if let Some(bp) = ms.transfer_fee_bp {
                exts.push(MintExt::TransferFee {
                    basis_points: bp,
                    maximum_fee: ms.maximum_fee.unwrap_or(u64::MAX),
                });
            }
            if ms.pausable {
                exts.push(MintExt::Pausable);
            }
            if let Some(frozen) = ms.default_frozen {
                exts.push(MintExt::DefaultAccountState { frozen });
            }
            if let Some(del_lbl) = &ms.permanent_delegate {
                let del_pk = parse_or_derive(None, &format!("account/{del_lbl}"))?;
                accounts.entry(del_lbl.clone()).or_insert(del_pk);
                exts.push(MintExt::PermanentDelegate { delegate: del_pk });
            }
            if let Some(hook_lbl) = &ms.hook_program_label {
                let hook_pid = programs
                    .get(hook_lbl)
                    .copied()
                    .ok_or_else(|| ExecError::Setup {
                        step: "mint-hook".into(),
                        detail: format!("unknown hook program label `{hook_lbl}`"),
                    })?;
                exts.push(MintExt::TransferHook {
                    program_id: hook_pid,
                });
            }
            let mint_pk = h.create_mint_ext(&ms.label, &MintPlan::new(ms.decimals, exts))?;
            accounts.insert(ms.label.clone(), mint_pk);
            mint_specs.insert(ms.label.clone(), ms.clone());
        }

        let mut account_specs = Vec::with_capacity(config.accounts.len());
        for acct in &config.accounts {
            let pk = match acct.kind.as_str() {
                "pda" => {
                    let pid = match acct.pda_program_label.as_deref() {
                        Some(lbl) => {
                            programs.get(lbl).copied().ok_or_else(|| ExecError::Setup {
                                step: "pda-program".into(),
                                detail: format!("unknown PDA program `{lbl}`"),
                            })?
                        }
                        None => target_program_id,
                    };
                    let mut raw_seeds: Vec<Vec<u8>> = Vec::with_capacity(acct.pda_seeds.len());
                    for seed in &acct.pda_seeds {
                        match seed {
                            SeedSpec::Utf8 { value } => raw_seeds.push(value.as_bytes().to_vec()),
                            SeedSpec::Hex { hex } => raw_seeds.push(decode_hex(hex)?),
                            SeedSpec::Account { label } => {
                                let dep = accounts.get(label).copied().ok_or_else(|| {
                                    ExecError::Setup {
                                        step: "pda-seed-account".into(),
                                        detail: format!(
                                            "PDA `{}` references `{label}` before it was defined",
                                            acct.label
                                        ),
                                    }
                                })?;
                                raw_seeds.push(dep.as_ref().to_vec());
                            }
                        }
                    }
                    let slices: Vec<&[u8]> = raw_seeds.iter().map(Vec::as_slice).collect();
                    let (pda, _) = Pubkey::find_program_address(&slices, &pid);
                    if acct.space.is_some() || acct.data_hex.is_some() || acct.owner_label.is_some()
                    {
                        let owner_pk = match acct.owner_label.as_deref() {
                            Some(lbl) => programs
                                .get(lbl)
                                .copied()
                                .or_else(|| accounts.get(lbl).copied())
                                .ok_or_else(|| ExecError::Setup {
                                    step: "pda-owner".into(),
                                    detail: format!(
                                        "unknown owner `{lbl}` for PDA `{}`",
                                        acct.label
                                    ),
                                })?,
                            None => pid,
                        };
                        let mut buf = match acct.data_hex.as_deref() {
                            Some(hx) => decode_hex(hx)?,
                            None => Vec::new(),
                        };
                        let target_len = acct.space.unwrap_or(buf.len());
                        if buf.len() < target_len {
                            buf.resize(target_len, 0);
                        }
                        h.set_account(&pda, &owner_pk, &buf, acct.lamports, false);
                    }
                    pda
                }
                "token" => {
                    let mint_lbl = acct.mint.as_deref().ok_or_else(|| ExecError::Setup {
                        step: "token-account".into(),
                        detail: format!("token account `{}` missing `mint`", acct.label),
                    })?;
                    let mint_pk =
                        accounts
                            .get(mint_lbl)
                            .copied()
                            .ok_or_else(|| ExecError::Setup {
                                step: "token-account".into(),
                                detail: format!("unknown mint `{mint_lbl}` for `{}`", acct.label),
                            })?;
                    let owner_pk = match acct.owner_label.as_deref() {
                        Some(lbl) => accounts
                            .get(lbl)
                            .copied()
                            .unwrap_or_else(|| derive_address(&format!("account/{lbl}"))),
                        None => h.payer(),
                    };
                    let ta_pk = if acct.associated {
                        let ata = Harness::associated_token_address(&owner_pk, &mint_pk);
                        h.create_token_account_at(&ata, &mint_pk, &owner_pk)?
                    } else {
                        h.create_token_account(&acct.label, &mint_pk, &owner_pk)?
                    };
                    if let Some(amt) = acct.initial_amount.filter(|v| *v > 0) {
                        h.mint_to(&mint_pk, &ta_pk, amt)?;
                    }
                    if let Some(ms) = mint_specs.get(mint_lbl)
                        && ms.default_frozen == Some(true)
                        && acct.role != "vault"
                    {
                        h.execute(&h.freeze_ix(&ta_pk, &mint_pk, false)?)?;
                    }
                    ta_pk
                }
                "program_owned" => {
                    let owner_pk = match acct.owner_label.as_deref() {
                        Some(lbl) => programs
                            .get(lbl)
                            .copied()
                            .or_else(|| accounts.get(lbl).copied())
                            .ok_or_else(|| ExecError::Setup {
                                step: "program-owned-owner".into(),
                                detail: format!("unknown owner `{lbl}` for `{}`", acct.label),
                            })?,
                        None => target_program_id,
                    };
                    let mut buf = match acct.data_hex.as_deref() {
                        Some(hx) => decode_hex(hx)?,
                        None => Vec::new(),
                    };
                    let space = acct.space.unwrap_or(buf.len());
                    if buf.len() < space {
                        buf.resize(space, 0);
                    }
                    let pk = derive_address(&format!("account/{}", acct.label));
                    h.set_account(&pk, &owner_pk, &buf, acct.lamports, false);
                    pk
                }
                _ => {
                    // System account (wallets, signers, attackers, depositor EOA)
                    let pk = accounts
                        .get(&acct.label)
                        .copied()
                        .unwrap_or_else(|| derive_address(&format!("account/{}", acct.label)));
                    let mut buf = match acct.data_hex.as_deref() {
                        Some(hx) => decode_hex(hx)?,
                        None => Vec::new(),
                    };
                    let space = acct.space.unwrap_or(buf.len());
                    if buf.len() < space {
                        buf.resize(space, 0);
                    }
                    let lam = acct.lamports.unwrap_or(1_000_000_000);
                    h.set_account(
                        &pk,
                        &solana_system_interface::program::ID,
                        &buf,
                        Some(lam),
                        false,
                    );
                    pk
                }
            };
            accounts.insert(acct.label.clone(), pk);
            account_specs.push(acct.clone());
        }

        let mut sess = Self {
            config: config.clone(),
            harness: h,
            target_program_id,
            programs,
            accounts,
            account_specs,
            mint_specs,
            snapshots: BTreeMap::new(),
            next_snap_id: 1,
        };
        for setup_call in &config.setup_calls {
            let obs = sess.call(setup_call)?;
            if obs.status != "ok" {
                return Err(ExecError::Setup {
                    step: "setup-call".into(),
                    detail: format!("{}; logs={:?}", obs.revert_reason, obs.logs),
                });
            }
        }
        Ok(sess)
    }

    /// Return resolved `{ label -> Base58 address }` mapping.
    pub fn resolved_accounts(&self) -> HashMap<String, String> {
        self.accounts
            .iter()
            .map(|(k, v)| (k.clone(), v.to_string()))
            .collect()
    }

    /// Capture raw & decoded balances across all tracked accounts right now.
    pub fn raw_snapshot(&self) -> RawSnapshot {
        let tracked: Vec<(&str, Pubkey)> = self
            .account_specs
            .iter()
            .filter_map(|s| {
                self.accounts
                    .get(&s.label)
                    .map(|pk| (s.label.as_str(), *pk))
            })
            .collect();
        self.harness.raw_snapshot(&tracked)
    }

    /// Inspect a single account by label.
    pub fn inspect_label(&self, label: &str) -> Option<AccountInspection> {
        let pk = self.accounts.get(label)?;
        self.harness.inspect_account(pk)
    }

    /// Inspect an account, treating a zero-lamport account as nonexistent: the runtime garbage
    /// collects it, and a program that closed it (`close = ...`) left only an empty shell.
    fn live_account(&self, pk: &Pubkey) -> Option<AccountInspection> {
        self.harness
            .inspect_account(pk)
            .filter(|acct| acct.lamports > 0)
    }

    /// Capture a deterministic checkpoint identifier.
    pub fn snapshot(&mut self) -> u64 {
        let id = self.next_snap_id;
        self.next_snap_id += 1;
        self.snapshots.insert(id, self.harness.snapshot_state());
        id
    }

    /// Rewind VM accounts and clock sysvar to `snapshot_id`.
    pub fn restore(&mut self, snapshot_id: u64) -> Result<(), ExecError> {
        let snap = self
            .snapshots
            .get(&snapshot_id)
            .cloned()
            .ok_or_else(|| ExecError::Setup {
                step: "restore".into(),
                detail: format!("unknown snapshot id {snapshot_id}"),
            })?;
        self.harness.restore_state(&snap);
        Ok(())
    }

    /// Advance Mollusk clock slot and unix timestamp.
    pub fn advance_time(&mut self, slots: u64, seconds: i64) {
        self.harness.advance_clock(slots, seconds);
    }

    fn resolve_program_id(&self, label: Option<&str>) -> Result<Pubkey, ExecError> {
        match label {
            None => Ok(self.target_program_id),
            Some(l) if l.trim().is_empty() => Ok(self.target_program_id),
            Some(l) => self
                .programs
                .get(l)
                .copied()
                .or_else(|| Pubkey::from_str(l).ok())
                .ok_or_else(|| ExecError::Setup {
                    step: "resolve-program".into(),
                    detail: format!("unknown program `{l}`"),
                }),
        }
    }

    fn resolve_meta(&self, meta: &SbfAccountMetaSpec) -> Result<AccountMeta, ExecError> {
        let pk = if let Some(raw_pk) = meta.pubkey.as_deref().filter(|s| !s.trim().is_empty()) {
            Pubkey::from_str(raw_pk.trim()).map_err(|e| ExecError::Setup {
                step: "resolve-account-pubkey".into(),
                detail: format!("invalid pubkey `{raw_pk}`: {e}"),
            })?
        } else {
            self.accounts
                .get(&meta.label)
                .copied()
                .ok_or_else(|| ExecError::Setup {
                    step: "resolve-account-label".into(),
                    detail: format!("unknown account label `{}`", meta.label),
                })?
        };
        Ok(if meta.is_writable {
            AccountMeta::new(pk, meta.is_signer)
        } else {
            AccountMeta::new_readonly(pk, meta.is_signer)
        })
    }

    fn build_instruction(&self, call: &SbfCallSpec) -> Result<Instruction, ExecError> {
        let program_id = self.resolve_program_id(call.program_label.as_deref())?;
        let data = decode_hex(&call.data_hex)?;
        let mut accounts = Vec::with_capacity(call.accounts.len());
        for m in &call.accounts {
            accounts.push(self.resolve_meta(m)?);
        }
        Ok(Instruction {
            program_id,
            accounts,
            data,
        })
    }

    /// Execute one SBF instruction in the live SVM and capture objective before/after deltas.
    pub fn call(&mut self, call: &SbfCallSpec) -> Result<SbfCallObservation, ExecError> {
        self.call_many(std::slice::from_ref(call))
    }

    /// Execute a sequence of instructions (single instruction if len==1, atomic tx if len>1).
    pub fn call_many(&mut self, calls: &[SbfCallSpec]) -> Result<SbfCallObservation, ExecError> {
        if calls.is_empty() {
            return Err(ExecError::Setup {
                step: "call".into(),
                detail: "at least one instruction is required".into(),
            });
        }
        let mut ixs = Vec::with_capacity(calls.len());
        for c in calls {
            ixs.push(self.build_instruction(c)?);
        }
        let caller_label = calls[0]
            .caller_label
            .clone()
            .unwrap_or_else(|| "attacker".to_string());
        let caller_role = calls[0]
            .caller_role
            .clone()
            .unwrap_or_else(|| "attacker".to_string());

        let tracked: Vec<(&str, Pubkey)> = self
            .account_specs
            .iter()
            .filter_map(|s| {
                self.accounts
                    .get(&s.label)
                    .map(|pk| (s.label.as_str(), *pk))
            })
            .collect();
        let before_ins: Vec<Option<AccountInspection>> = tracked
            .iter()
            .map(|(_, pk)| self.live_account(pk))
            .collect();
        let mint_supplies_before: Vec<(String, Option<u64>)> = self
            .mint_specs
            .keys()
            .map(|mlbl| {
                let sup = self
                    .accounts
                    .get(mlbl)
                    .and_then(|mpk| self.harness.inspect_account(mpk))
                    .and_then(|ins| ins.mint_supply);
                (mlbl.clone(), sup)
            })
            .collect();
        let raw_before = self.harness.raw_snapshot(&tracked);

        let report = if ixs.len() == 1 {
            self.harness.execute_logged(&ixs[0])
        } else {
            self.harness.execute_transaction_logged(&ixs)
        };

        let after_ins: Vec<Option<AccountInspection>> = tracked
            .iter()
            .map(|(_, pk)| self.live_account(pk))
            .collect();
        let raw_after = self.harness.raw_snapshot(&tracked);

        let mut value_flows = Vec::new();
        let mut state_deltas = Vec::new();
        let mut privilege_changes = Vec::new();

        for (idx, spec) in self.account_specs.iter().enumerate() {
            // An account the call created (or closed) is compared against an empty account of the
            // same shape, so vaults opened and closed inside one instruction still show their flows.
            let (b_owned, a_owned);
            let (b, a) = match (
                before_ins.get(idx).and_then(Option::as_ref),
                after_ins.get(idx).and_then(Option::as_ref),
            ) {
                (Some(b), Some(a)) => (b, a),
                (None, Some(a)) => {
                    b_owned = absent_like(a);
                    (&b_owned, a)
                }
                (Some(b), None) => {
                    a_owned = absent_like(b);
                    (b, &a_owned)
                }
                (None, None) => continue,
            };

            if let (Some(bt), Some(at)) = (b.token, a.token) {
                let asset = spec.mint.clone().unwrap_or_else(|| "SPL_TOKEN".to_string());
                let owner_lbl = self
                    .accounts
                    .iter()
                    .find(|(_, pk)| **pk == at.owner)
                    .map(|(k, _)| k.clone())
                    .unwrap_or_else(|| {
                        spec.owner_label
                            .clone()
                            .unwrap_or_else(|| at.owner.to_string())
                    });
                value_flows.push(ObservedValueFlow {
                    asset: asset.clone(),
                    account: spec.label.clone(),
                    role: spec.role.clone(),
                    owner: owner_lbl.clone(),
                    before: i128::from(bt.amount),
                    after: i128::from(at.amount),
                    delta: i128::from(at.amount) - i128::from(bt.amount),
                    kind: "balance".to_string(),
                });
                if let (Some(bw), Some(aw)) = (bt.withheld, at.withheld)
                    && bw != aw
                {
                    value_flows.push(ObservedValueFlow {
                        asset: asset.clone(),
                        account: spec.label.clone(),
                        role: "fee_recipient".to_string(),
                        owner: owner_lbl,
                        before: i128::from(bw),
                        after: i128::from(aw),
                        delta: i128::from(aw) - i128::from(bw),
                        kind: "fee".to_string(),
                    });
                }
                if bt.owner != at.owner {
                    privilege_changes.push(ObservedPrivilegeChange {
                        subject: format!("{}.owner", spec.label),
                        action: "token_owner_change".to_string(),
                        actor: caller_label.clone(),
                        actor_role: caller_role.clone(),
                        target: spec.label.clone(),
                        detail: format!("{} -> {}", bt.owner, at.owner),
                    });
                }
                if bt.delegate != at.delegate {
                    privilege_changes.push(ObservedPrivilegeChange {
                        subject: format!("{}.delegate", spec.label),
                        action: "delegate_change".to_string(),
                        actor: caller_label.clone(),
                        actor_role: caller_role.clone(),
                        target: spec.label.clone(),
                        detail: format!("{:?} -> {:?}", bt.delegate, at.delegate),
                    });
                }
            }

            if (b.lamports != a.lamports) && spec.label != "payer" {
                value_flows.push(ObservedValueFlow {
                    asset: "SOL".to_string(),
                    account: spec.label.clone(),
                    role: spec.role.clone(),
                    owner: spec.label.clone(),
                    before: i128::from(b.lamports),
                    after: i128::from(a.lamports),
                    delta: i128::from(a.lamports) - i128::from(b.lamports),
                    kind: "balance".to_string(),
                });
            }

            let mut watched_changed = false;
            for f in &spec.u64_fields {
                if let (Some(vb), Some(va)) = (
                    read_u64_le(&b.data, f.offset),
                    read_u64_le(&a.data, f.offset),
                ) {
                    let flow_kind = f.kind.as_str();
                    if matches!(flow_kind, "liability" | "reserve" | "shares") {
                        let default_asset = self
                            .mint_specs
                            .keys()
                            .next()
                            .cloned()
                            .unwrap_or_else(|| "SPL_TOKEN".to_string());
                        value_flows.push(ObservedValueFlow {
                            asset: f.asset.clone().unwrap_or(default_asset),
                            account: spec.label.clone(),
                            role: spec.role.clone(),
                            owner: spec.label.clone(),
                            before: i128::from(vb),
                            after: i128::from(va),
                            delta: i128::from(va) - i128::from(vb),
                            kind: flow_kind.to_string(),
                        });
                    }
                    if vb != va {
                        watched_changed = true;
                        state_deltas.push(ObservedStateDelta {
                            var_name: f.name.clone(),
                            contract: spec.label.clone(),
                            before: serde_json::json!(vb),
                            after: serde_json::json!(va),
                        });
                    }
                }
            }

            for &off in &spec.authority_offsets {
                if let (Some(pb), Some(pa)) =
                    (read_pubkey32(&b.data, off), read_pubkey32(&a.data, off))
                    && pb != pa
                {
                    watched_changed = true;
                    privilege_changes.push(ObservedPrivilegeChange {
                        subject: format!("{}@{}", spec.label, off),
                        action: "authority_change".to_string(),
                        actor: caller_label.clone(),
                        actor_role: caller_role.clone(),
                        target: spec.label.clone(),
                        detail: format!("{pb} -> {pa}"),
                    });
                }
            }

            if b.data != a.data && !watched_changed {
                state_deltas.push(ObservedStateDelta {
                    var_name: "raw_data_digest".to_string(),
                    contract: spec.label.clone(),
                    before: serde_json::json!(sha256_hex(&b.data)),
                    after: serde_json::json!(sha256_hex(&a.data)),
                });
            }
        }

        // Track mint supply transitions across configured mints
        for (mlbl, sup_b_opt) in &mint_supplies_before {
            if let Some(sb) = sup_b_opt
                && let Some(mpk) = self.accounts.get(mlbl)
                && let Some(sa) = self
                    .harness
                    .inspect_account(mpk)
                    .and_then(|ins| ins.mint_supply)
                && *sb != sa
            {
                value_flows.push(ObservedValueFlow {
                    asset: mlbl.clone(),
                    account: mlbl.clone(),
                    role: "protocol".to_string(),
                    owner: mlbl.clone(),
                    before: i128::from(*sb),
                    after: i128::from(sa),
                    delta: i128::from(sa) - i128::from(*sb),
                    kind: "supply".to_string(),
                });
            }
        }

        Ok(SbfCallObservation {
            status: if report.error.is_none() {
                "ok".to_string()
            } else {
                "reverted".to_string()
            },
            revert_reason: report.error.unwrap_or_default(),
            compute_units: report.compute_units,
            logs: report.logs,
            value_flows,
            state_deltas,
            privilege_changes,
            raw_before,
            raw_after,
        })
    }

    /// Return the underlying [`GenericSbfConfig`].
    pub fn config(&self) -> &GenericSbfConfig {
        &self.config
    }
}

/// Interactive stdio JSON-RPC request packet accepted by `tokenscope sbf-session`.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum SbfRpcRequest {
    /// Provision or reset the SVM session from `config`.
    Deploy {
        /// Request ID echoed in response.
        id: u64,
        /// Full provisioning spec.
        config: GenericSbfConfig,
    },
    /// Execute one SBF instruction (or atomic sequence if `calls` provided).
    Call {
        /// Request ID echoed in response.
        id: u64,
        /// Single call payload.
        call: Option<SbfCallSpec>,
        /// Multi-instruction atomic transaction payload.
        #[serde(default)]
        calls: Vec<SbfCallSpec>,
    },
    /// Read raw/decoded account state by label.
    ReadAccount {
        /// Request ID echoed in response.
        id: u64,
        /// Account label.
        label: String,
    },
    /// Advance slot and clock timestamp.
    AdvanceTime {
        /// Request ID echoed in response.
        id: u64,
        /// Slots to warp ahead.
        #[serde(default = "default_one_u64")]
        blocks: u64,
        /// Seconds to add to `clock.unix_timestamp`.
        #[serde(default)]
        seconds: i64,
    },
    /// Capture deterministic SVM checkpoint.
    Snapshot {
        /// Request ID echoed in response.
        id: u64,
    },
    /// Restore previously captured checkpoint.
    Restore {
        /// Request ID echoed in response.
        id: u64,
        /// Checkpoint ID returned by `snapshot`.
        snapshot_id: u64,
    },
    /// Cleanly exit the worker loop.
    Shutdown {
        /// Request ID echoed in response.
        id: u64,
    },
}

fn default_one_u64() -> u64 {
    1
}

/// Stateful dispatcher handling interactive JSON-RPC commands over a live [`GenericSbfSession`].
#[derive(Default)]
pub struct SbfRpcHandler {
    session: Option<GenericSbfSession>,
}

impl SbfRpcHandler {
    /// Create an uninitialized RPC handler awaiting `deploy`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Process one [`SbfRpcRequest`]; returns `(response_json, should_exit)`.
    pub fn handle(&mut self, req: SbfRpcRequest) -> (serde_json::Value, bool) {
        match req {
            SbfRpcRequest::Deploy { id, config } => match GenericSbfSession::deploy(config) {
                Ok(sess) => {
                    let resolved = sess.resolved_accounts();
                    let raw = sess.raw_snapshot();
                    self.session = Some(sess);
                    (
                        serde_json::json!({
                            "id": id,
                            "ok": true,
                            "result": {
                                "accounts": resolved,
                                "raw_initial": raw,
                            }
                        }),
                        false,
                    )
                }
                Err(e) => (
                    serde_json::json!({
                        "id": id,
                        "ok": false,
                        "error": e.to_string(),
                    }),
                    false,
                ),
            },
            SbfRpcRequest::Call { id, call, calls } => {
                let Some(sess) = self.session.as_mut() else {
                    return (
                        serde_json::json!({ "id": id, "ok": false, "error": "session not deployed" }),
                        false,
                    );
                };
                let seq = if !calls.is_empty() {
                    calls
                } else if let Some(c) = call {
                    vec![c]
                } else {
                    vec![]
                };
                match sess.call_many(&seq) {
                    Ok(obs) => (
                        serde_json::json!({ "id": id, "ok": true, "result": obs }),
                        false,
                    ),
                    Err(e) => (
                        serde_json::json!({ "id": id, "ok": false, "error": e.to_string() }),
                        false,
                    ),
                }
            }
            SbfRpcRequest::ReadAccount { id, label } => {
                let Some(sess) = self.session.as_ref() else {
                    return (
                        serde_json::json!({ "id": id, "ok": false, "error": "session not deployed" }),
                        false,
                    );
                };
                match sess.inspect_label(&label) {
                    Some(ins) => (
                        serde_json::json!({
                            "id": id,
                            "ok": true,
                            "result": {
                                "owner": ins.owner.to_string(),
                                "lamports": ins.lamports,
                                "data_hex": ins.data.iter().map(|b| format!("{b:02x}")).collect::<String>(),
                                "token_amount": ins.token.map(|t| t.amount),
                                "token_withheld": ins.token.and_then(|t| t.withheld),
                                "token_owner": ins.token.map(|t| t.owner.to_string()),
                                "mint_supply": ins.mint_supply,
                                "mint_paused": ins.mint_paused,
                            }
                        }),
                        false,
                    ),
                    None => (
                        serde_json::json!({ "id": id, "ok": false, "error": format!("unknown account `{label}`") }),
                        false,
                    ),
                }
            }
            SbfRpcRequest::AdvanceTime {
                id,
                blocks,
                seconds,
            } => {
                let Some(sess) = self.session.as_mut() else {
                    return (
                        serde_json::json!({ "id": id, "ok": false, "error": "session not deployed" }),
                        false,
                    );
                };
                sess.advance_time(blocks, seconds);
                (
                    serde_json::json!({ "id": id, "ok": true, "result": {} }),
                    false,
                )
            }
            SbfRpcRequest::Snapshot { id } => {
                let Some(sess) = self.session.as_mut() else {
                    return (
                        serde_json::json!({ "id": id, "ok": false, "error": "session not deployed" }),
                        false,
                    );
                };
                let snap_id = sess.snapshot();
                (
                    serde_json::json!({ "id": id, "ok": true, "result": { "snapshot_id": snap_id } }),
                    false,
                )
            }
            SbfRpcRequest::Restore { id, snapshot_id } => {
                let Some(sess) = self.session.as_mut() else {
                    return (
                        serde_json::json!({ "id": id, "ok": false, "error": "session not deployed" }),
                        false,
                    );
                };
                match sess.restore(snapshot_id) {
                    Ok(()) => (
                        serde_json::json!({ "id": id, "ok": true, "result": {} }),
                        false,
                    ),
                    Err(e) => (
                        serde_json::json!({ "id": id, "ok": false, "error": e.to_string() }),
                        false,
                    ),
                }
            }
            SbfRpcRequest::Shutdown { id } => (
                serde_json::json!({ "id": id, "ok": true, "result": {} }),
                true,
            ),
        }
    }
}

/// [`TargetAdapter`] implementation executing arbitrary `.so` ELF batch specs in Mollusk.
pub struct GenericSbfAdapter {
    batch: GenericBatchSpec,
}

impl GenericSbfAdapter {
    /// Wrap a [`GenericBatchSpec`] into a [`TargetAdapter`].
    pub fn new(batch: GenericBatchSpec) -> Self {
        Self { batch }
    }

    /// Execute `self.batch` cleanly, producing raw observations paired with optional [`Scenario`].
    pub fn execute_batch(&self) -> Result<GenericBatchOutput, ExecError> {
        let mut sess = GenericSbfSession::deploy(self.batch.config.clone())?;
        let raw_initial = sess.raw_snapshot();
        let accounts = sess.resolved_accounts();
        let mut steps = Vec::with_capacity(self.batch.calls.len());
        for c in &self.batch.calls {
            steps.push(sess.call(c)?);
        }
        let findings = evaluate_checks(&self.batch.checks, &self.batch.calls, &steps);
        Ok(GenericBatchOutput {
            target_id: self.batch.config.target_id.clone(),
            accounts,
            raw_initial,
            steps,
            findings,
        })
    }
}

/// Result returned by [`GenericSbfAdapter::execute_batch`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenericBatchOutput {
    /// Target program ID / label.
    pub target_id: String,
    /// Resolved `{ label -> Pubkey }` map.
    pub accounts: HashMap<String, String>,
    /// Initial raw account state after provisioning and `setup_calls`.
    pub raw_initial: RawSnapshot,
    /// Per-call observed diffs and raw snapshots.
    pub steps: Vec<SbfCallObservation>,
    /// Failed checks declared in the batch spec.
    #[serde(default)]
    pub findings: Vec<CheckFinding>,
}

impl TargetAdapter for GenericSbfAdapter {
    fn target_id(&self) -> &str {
        &self.batch.config.target_id
    }

    fn run(&self, scenario: &Scenario) -> Result<tokenscope_model::ExecutionTrace, ExecError> {
        scenario.validate().map_err(|e| ExecError::Setup {
            step: "validate-scenario".into(),
            detail: e.to_string(),
        })?;
        let out = self.execute_batch()?;
        let accounts = out
            .accounts
            .iter()
            .map(|(l, a)| tokenscope_model::AccountRef {
                label: l.clone(),
                address: a.clone(),
            })
            .collect();
        let mut trace = tokenscope_model::ExecutionTrace::new(
            scenario.id(),
            self.batch.config.target_id.clone(),
            tokenscope_model::Snapshot::default(),
            accounts,
        );
        trace.raw_initial = Some(out.raw_initial);
        for (index, (obs, act)) in out
            .steps
            .into_iter()
            .zip(scenario.actions.iter())
            .enumerate()
        {
            trace.steps.push(tokenscope_model::StepRecord {
                index,
                action: *act,
                before: tokenscope_model::Snapshot::default(),
                after: tokenscope_model::Snapshot::default(),
                status: if obs.status == "ok" {
                    StepStatus::Ok
                } else {
                    StepStatus::Failed {
                        error: obs.revert_reason,
                    }
                },
                logs: obs.logs,
                compute_units: obs.compute_units,
                raw_before: Some(obs.raw_before),
                raw_after: Some(obs.raw_after),
            });
        }
        Ok(trace)
    }

    fn version(&self) -> AdapterVersion {
        AdapterVersion {
            name: "GenericSbfAdapter".to_string(),
            version: "0.1.0".to_string(),
            schema_version: tokenscope_model::SCHEMA_VERSION,
        }
    }

    fn capabilities(&self) -> AdapterCapabilities {
        AdapterCapabilities {
            raw_state_capture: true,
            multi_instruction: true,
            cpi_tracing: false,
            multi_program: true,
            custom_decoders: true,
        }
    }

    fn description(&self) -> &str {
        "Target-agnostic Mollusk SBF ELF adapter with RawSnapshot, SPL, and offset field observation"
    }
}

/// Convert [`tokenscope_model::MintExtension`] helper list cleanly for tests.
pub fn extension_names(exts: &[MintExtension]) -> Vec<&'static str> {
    exts.iter()
        .map(|e| match e {
            MintExtension::DefaultAccountState { .. } => "default_account_state",
            MintExtension::Pausable => "pausable",
            MintExtension::PermanentDelegate => "permanent_delegate",
            MintExtension::TransferHook => "transfer_hook",
        })
        .collect()
}
