//! Stateful Token-2022 execution environment.

use std::{cell::RefCell, collections::HashMap, rc::Rc};

use mollusk_svm::{
    Mollusk, MolluskContext, program::loader_keys::LOADER_V3, result::ProgramResult,
};
use sha2::{Digest, Sha256};
use solana_account::Account;
use solana_instruction::Instruction;
use solana_pubkey::Pubkey;
use solana_svm_log_collector::LogCollector;
use spl_token_2022_interface::{
    extension::{
        BaseStateWithExtensions, ExtensionType, StateWithExtensions, account_len,
        group_member_pointer, group_pointer, metadata_pointer,
        transfer_fee::{TransferFeeAmount, TransferFeeConfig, instruction as fee_ix},
    },
    instruction as token_ix,
    state::{Account as TokenAccount, AccountState, Mint},
};
use tokenscope_model::{MintSpec, RawAccount, RawSnapshot};

use crate::ExecError;

const LEGACY_SPL_TOKEN_ID: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";

/// Deterministic SVM checkpoint containing the account store and clock state.
#[derive(Clone)]
pub struct SvmSnapshot {
    store: HashMap<Pubkey, Account>,
    slot: u64,
    unix_timestamp: i64,
}

/// Decoded generic inspection of one Solana account in the active store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountInspection {
    /// Program owning this account.
    pub owner: Pubkey,
    /// Lamport balance.
    pub lamports: u64,
    /// Executable flag.
    pub executable: bool,
    /// Raw account bytes.
    pub data: Vec<u8>,
    /// Decoded Token / Token-2022 account fields when unpackable.
    pub token: Option<TokenAccountView>,
    /// Decoded Mint total supply when unpackable.
    pub mint_supply: Option<u64>,
    /// Decoded Pausable mint flag when unpackable.
    pub mint_paused: Option<bool>,
}

/// Deterministically derive an address from a label (reproducible runs need stable addresses).
pub fn derive_address(label: &str) -> Pubkey {
    let digest = Sha256::digest(format!("tokenscope/address/{label}"));
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&digest);
    Pubkey::new_from_array(bytes)
}

/// Decoded view of a Token-2022 token account (read from real account data).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenAccountView {
    /// Owner of the token account.
    pub owner: Pubkey,
    /// Spendable token balance.
    pub amount: u64,
    /// Fee amount withheld on this account by the transfer-fee extension, if present.
    pub withheld: Option<u64>,
    /// Whether the account is frozen.
    pub frozen: bool,
    /// Approved delegate, if any.
    pub delegate: Option<Pubkey>,
    /// Remaining amount the delegate may spend.
    pub delegated_amount: u64,
}

/// Decoded view of a mint pointer extension (metadata, group, or group member).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PointerView {
    /// Authority that can update the pointer, or `None` if immutable.
    pub authority: Option<Pubkey>,
    /// Address the pointer directs to, or `None` if unset.
    pub address: Option<Pubkey>,
}

/// Execution environment holding a Mollusk SVM and its persistent account store.
pub struct Harness {
    ctx: MolluskContext<HashMap<Pubkey, Account>>,
    payer: Pubkey,
    logs: Rc<RefCell<LogCollector>>,
}

/// Outcome of executing one instruction, including captured logs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecReport {
    /// `None` on success, otherwise the runtime error text.
    pub error: Option<String>,
    /// Log lines emitted by this instruction.
    pub logs: Vec<String>,
    /// Compute units consumed.
    pub compute_units: u64,
}

impl Harness {
    /// Create an environment with the system program and Token-2022 loaded and a funded payer.
    pub fn new() -> Self {
        let mut mollusk = Mollusk::default();
        // Mollusk installs a debug-level logger by default. Silence it unless the user opted in
        // via RUST_LOG; execution logs are captured explicitly through `LogCollector` instead.
        if std::env::var_os("RUST_LOG").is_none() {
            log::set_max_level(log::LevelFilter::Off);
        }
        // The default collector silently stops recording after 10 KB, which would drop the logs of
        // later steps in a long-lived harness. A harness lives for one scenario, so no limit.
        let logs = LogCollector::new_ref_with_limit(None);
        mollusk.logger = Some(Rc::clone(&logs));
        mollusk_svm_programs_token_2022::add_program(&mut mollusk);
        let payer = derive_address("payer");
        let mut store = HashMap::new();
        store.insert(
            payer,
            Account::new(10_000_000_000, 0, &solana_system_interface::program::ID),
        );
        Self {
            ctx: mollusk.with_context(store),
            payer,
            logs,
        }
    }

    /// The funded fee payer / default authority.
    pub fn payer(&self) -> Pubkey {
        self.payer
    }

    /// Access to the underlying Mollusk context (for target program registration).
    pub fn context(&self) -> &MolluskContext<HashMap<Pubkey, Account>> {
        &self.ctx
    }

    /// Mutable access to the underlying Mollusk (for target program registration).
    pub fn mollusk_mut(&mut self) -> &mut Mollusk {
        &mut self.ctx.mollusk
    }

    /// Register a program ELF under the upgradeable loader (as deployed programs are).
    pub fn load_program(&mut self, program_id: &Pubkey, elf: &[u8]) {
        self.ctx
            .mollusk
            .add_program_with_loader_and_elf(program_id, &LOADER_V3, elf);
    }

    /// Register the bundled SPL Associated Token Account program (mainnet ELF) at its canonical
    /// address, for target programs that create associated token accounts through CPI.
    pub fn load_associated_token_program(&mut self) {
        mollusk_svm_programs_token::associated_token::add_program(&mut self.ctx.mollusk);
    }

    /// Canonical address of the SPL Associated Token Account program.
    pub fn associated_token_program_id() -> Pubkey {
        mollusk_svm_programs_token::associated_token::ID
    }

    /// Associated Token-2022 account address for `owner` and `mint`.
    pub fn associated_token_address(owner: &Pubkey, mint: &Pubkey) -> Pubkey {
        Pubkey::find_program_address(
            &[
                owner.as_ref(),
                spl_token_2022_interface::id().as_ref(),
                mint.as_ref(),
            ],
            &Self::associated_token_program_id(),
        )
        .0
    }

    /// Execute one instruction and report errors, logs and compute usage. State persists only
    /// when the instruction succeeds.
    pub fn execute_logged(&self, ix: &Instruction) -> ExecReport {
        let start = self.logs.borrow().get_recorded_content().len();
        let result = self.ctx.process_instruction(ix);
        let logs = self.logs.borrow().get_recorded_content()[start..].to_vec();
        let error = match result.program_result {
            ProgramResult::Success => None,
            other => Some(format!("{other:?}")),
        };
        ExecReport {
            error,
            logs,
            compute_units: result.compute_units_consumed,
        }
    }

    /// Execute one instruction, persisting state on success (failed instructions leave state intact).
    pub fn execute(&self, ix: &Instruction) -> Result<(), ExecError> {
        match self.execute_logged(ix).error {
            None => Ok(()),
            Some(e) => Err(ExecError::Instruction(e)),
        }
    }

    /// Execute multiple instructions atomically as a single transaction and report errors, logs
    /// and compute usage. State persists only when the entire transaction succeeds.
    pub fn execute_transaction_logged(&self, instructions: &[Instruction]) -> ExecReport {
        let start = self.logs.borrow().get_recorded_content().len();
        let result = self
            .ctx
            .process_transaction_instructions(instructions, Some(&self.payer));
        let logs = self.logs.borrow().get_recorded_content()[start..].to_vec();
        let error = if result.program_result.is_ok() {
            None
        } else {
            Some(format!("{:?}", result.program_result))
        };
        ExecReport {
            error,
            logs,
            compute_units: result.compute_units_consumed,
        }
    }

    /// Execute multiple instructions atomically as a single transaction, persisting state on success.
    pub fn execute_transaction(&self, instructions: &[Instruction]) -> Result<(), ExecError> {
        match self.execute_transaction_logged(instructions).error {
            None => Ok(()),
            Some(e) => Err(ExecError::Instruction(e)),
        }
    }

    /// Create an account at a caller-chosen address (for example a PDA, which the harness may
    /// create directly because Mollusk does not verify signatures).
    pub fn create_owned_account_at(
        &self,
        address: &Pubkey,
        space: usize,
        owner: &Pubkey,
    ) -> Result<(), ExecError> {
        let ix = solana_system_interface::instruction::create_account(
            &self.payer,
            address,
            self.rent_for(space),
            space as u64,
            owner,
        );
        self.setup("create-account-at", &[ix])
    }

    /// Create an account owned by `owner` with `space` bytes, rent-exempt, funded by the payer.
    pub fn create_owned_account(
        &self,
        label: &str,
        space: usize,
        owner: &Pubkey,
    ) -> Result<Pubkey, ExecError> {
        let address = derive_address(&format!("account/{label}"));
        let ix = solana_system_interface::instruction::create_account(
            &self.payer,
            &address,
            self.rent_for(space),
            space as u64,
            owner,
        );
        self.setup("create-account", &[ix])?;
        Ok(address)
    }

    fn setup(&self, step: &str, ixs: &[Instruction]) -> Result<(), ExecError> {
        for ix in ixs {
            self.execute(ix).map_err(|e| ExecError::Setup {
                step: step.into(),
                detail: e.to_string(),
            })?;
        }
        Ok(())
    }

    /// Rent-exempt minimum balance for `space` bytes.
    pub fn rent_exempt_balance(&self, space: usize) -> u64 {
        self.rent_for(space)
    }

    fn rent_for(&self, space: usize) -> u64 {
        self.ctx.mollusk.sysvars.rent.minimum_balance(space)
    }

    /// Create and initialize a Token-2022 mint via real instructions, with an optional
    /// `TransferFeeConfig`. Returns the mint address.
    pub fn create_mint(&self, label: &str, spec: &MintSpec) -> Result<Pubkey, ExecError> {
        let mint = derive_address(&format!("mint/{label}"));
        let token = spl_token_2022_interface::id();
        let mut exts = Vec::new();
        if spec.transfer_fee.is_some() {
            exts.push(ExtensionType::TransferFeeConfig);
        }
        let space = ExtensionType::try_calculate_account_len::<Mint>(&exts).map_err(|e| {
            ExecError::Setup {
                step: "mint-size".into(),
                detail: e.to_string(),
            }
        })?;
        let mut ixs = vec![solana_system_interface::instruction::create_account(
            &self.payer,
            &mint,
            self.rent_for(space),
            space as u64,
            &token,
        )];
        if let Some(fee) = spec.transfer_fee {
            ixs.push(
                fee_ix::initialize_transfer_fee_config(
                    &token,
                    &mint,
                    Some(&self.payer),
                    Some(&self.payer),
                    fee.basis_points,
                    fee.maximum_fee,
                )
                .map_err(|e| ExecError::Setup {
                    step: "fee-config-ix".into(),
                    detail: e.to_string(),
                })?,
            );
        }
        ixs.push(
            token_ix::initialize_mint2(
                &token,
                &mint,
                &self.payer,
                Some(&self.payer),
                spec.decimals,
            )
            .map_err(|e| ExecError::Setup {
                step: "init-mint-ix".into(),
                detail: e.to_string(),
            })?,
        );
        self.setup("create-mint", &ixs)?;
        Ok(mint)
    }

    /// Create and initialize a Token-2022 token account for `mint` owned by `owner`.
    pub fn create_token_account(
        &self,
        label: &str,
        mint: &Pubkey,
        owner: &Pubkey,
    ) -> Result<Pubkey, ExecError> {
        let account = derive_address(&format!("token-account/{label}"));
        self.create_token_account_at(&account, mint, owner)
    }

    /// Create and initialize a Token-2022 token account at an explicit `account` address (for
    /// example the owner's associated token account, which programs verify by address).
    pub fn create_token_account_at(
        &self,
        account: &Pubkey,
        mint: &Pubkey,
        owner: &Pubkey,
    ) -> Result<Pubkey, ExecError> {
        let account = *account;
        let token = spl_token_2022_interface::id();
        let mint_data = self.account(mint)?.data;
        let space = account_len::try_calculate_account_len_from_mint_data(&mint_data, &[])
            .map_err(|e| ExecError::Setup {
                step: "account-size".into(),
                detail: e.to_string(),
            })?;
        let ixs = [
            solana_system_interface::instruction::create_account(
                &self.payer,
                &account,
                self.rent_for(space),
                space as u64,
                &token,
            ),
            token_ix::initialize_account3(&token, &account, mint, owner).map_err(|e| {
                ExecError::Setup {
                    step: "init-account-ix".into(),
                    detail: e.to_string(),
                }
            })?,
        ];
        self.setup("create-token-account", &ixs)?;
        Ok(account)
    }

    /// Create and initialize a Token-2022 multisig account.
    pub fn create_multisig(
        &self,
        label: &str,
        signers: &[&Pubkey],
        m: u8,
    ) -> Result<Pubkey, ExecError> {
        use solana_program_pack::Pack;
        let multisig = derive_address(&format!("multisig/{label}"));
        let token = spl_token_2022_interface::id();
        let space = spl_token_2022_interface::state::Multisig::LEN;
        let ixs = [
            solana_system_interface::instruction::create_account(
                &self.payer,
                &multisig,
                self.rent_for(space),
                space as u64,
                &token,
            ),
            token_ix::initialize_multisig2(&token, &multisig, signers, m).map_err(|e| {
                ExecError::Setup {
                    step: "init-multisig-ix".into(),
                    detail: e.to_string(),
                }
            })?,
        ];
        self.setup("create-multisig", &ixs)?;
        Ok(multisig)
    }

    /// Mint `amount` tokens to `destination` using the mint authority (the payer).
    pub fn mint_to(
        &self,
        mint: &Pubkey,
        destination: &Pubkey,
        amount: u64,
    ) -> Result<(), ExecError> {
        let token = spl_token_2022_interface::id();
        let ix = token_ix::mint_to(&token, mint, destination, &self.payer, &[], amount).map_err(
            |e| ExecError::Setup {
                step: "mint-to-ix".into(),
                detail: e.to_string(),
            },
        )?;
        self.setup("mint-to", &[ix])
    }

    /// Build a `FreezeAccount` or `ThawAccount` instruction signed by the mint's freeze authority
    /// (the harness payer).
    pub fn freeze_ix(
        &self,
        account: &Pubkey,
        mint: &Pubkey,
        freeze: bool,
    ) -> Result<Instruction, ExecError> {
        let token = spl_token_2022_interface::id();
        let ix = if freeze {
            token_ix::freeze_account(&token, account, mint, &self.payer, &[])
        } else {
            token_ix::thaw_account(&token, account, mint, &self.payer, &[])
        };
        ix.map_err(|e| ExecError::Setup {
            step: "freeze-ix".into(),
            detail: e.to_string(),
        })
    }

    /// Build a `TransferChecked` instruction (does not execute it).
    pub fn transfer_checked_ix(
        &self,
        source: &Pubkey,
        mint: &Pubkey,
        destination: &Pubkey,
        authority: &Pubkey,
        amount: u64,
        decimals: u8,
    ) -> Result<Instruction, ExecError> {
        token_ix::transfer_checked(
            &spl_token_2022_interface::id(),
            source,
            mint,
            destination,
            authority,
            &[],
            amount,
            decimals,
        )
        .map_err(|e| ExecError::Setup {
            step: "transfer-ix".into(),
            detail: e.to_string(),
        })
    }

    /// Build a `TransferChecked` instruction signed by a multisig's individual signers.
    #[allow(clippy::too_many_arguments)]
    pub fn transfer_checked_multisig_ix(
        &self,
        source: &Pubkey,
        mint: &Pubkey,
        destination: &Pubkey,
        multisig: &Pubkey,
        signers: &[&Pubkey],
        amount: u64,
        decimals: u8,
    ) -> Result<Instruction, ExecError> {
        token_ix::transfer_checked(
            &spl_token_2022_interface::id(),
            source,
            mint,
            destination,
            multisig,
            signers,
            amount,
            decimals,
        )
        .map_err(|e| ExecError::Setup {
            step: "transfer-multisig-ix".into(),
            detail: e.to_string(),
        })
    }

    /// Build a `TransferCheckedWithFee` instruction (does not execute it).
    #[allow(clippy::too_many_arguments)]
    pub fn transfer_checked_with_fee_ix(
        &self,
        source: &Pubkey,
        mint: &Pubkey,
        destination: &Pubkey,
        authority: &Pubkey,
        amount: u64,
        decimals: u8,
        fee: u64,
    ) -> Result<Instruction, ExecError> {
        fee_ix::transfer_checked_with_fee(
            &spl_token_2022_interface::id(),
            source,
            mint,
            destination,
            authority,
            &[],
            amount,
            decimals,
            fee,
        )
        .map_err(|e| ExecError::Setup {
            step: "transfer-checked-with-fee-ix".into(),
            detail: e.to_string(),
        })
    }

    /// Build a `HarvestWithheldTokensToMint` instruction.
    pub fn harvest_withheld_to_mint_ix(
        &self,
        mint: &Pubkey,
        sources: &[&Pubkey],
    ) -> Result<Instruction, ExecError> {
        fee_ix::harvest_withheld_tokens_to_mint(&spl_token_2022_interface::id(), mint, sources)
            .map_err(|e| ExecError::Setup {
                step: "harvest-withheld-to-mint-ix".into(),
                detail: e.to_string(),
            })
    }

    /// Build a `WithdrawWithheldTokensFromMint` instruction signed by `authority`.
    pub fn withdraw_withheld_from_mint_ix(
        &self,
        mint: &Pubkey,
        destination: &Pubkey,
        authority: &Pubkey,
    ) -> Result<Instruction, ExecError> {
        fee_ix::withdraw_withheld_tokens_from_mint(
            &spl_token_2022_interface::id(),
            mint,
            destination,
            authority,
            &[],
        )
        .map_err(|e| ExecError::Setup {
            step: "withdraw-withheld-from-mint-ix".into(),
            detail: e.to_string(),
        })
    }

    /// Build a `WithdrawWithheldTokensFromAccounts` instruction signed by `authority`.
    pub fn withdraw_withheld_from_accounts_ix(
        &self,
        mint: &Pubkey,
        destination: &Pubkey,
        authority: &Pubkey,
        sources: &[&Pubkey],
    ) -> Result<Instruction, ExecError> {
        fee_ix::withdraw_withheld_tokens_from_accounts(
            &spl_token_2022_interface::id(),
            mint,
            destination,
            authority,
            &[],
            sources,
        )
        .map_err(|e| ExecError::Setup {
            step: "withdraw-withheld-from-accounts-ix".into(),
            detail: e.to_string(),
        })
    }

    /// Build a `SetTransferFee` instruction signed by the fee config authority.
    pub fn set_transfer_fee_ix(
        &self,
        mint: &Pubkey,
        authority: &Pubkey,
        transfer_fee_basis_points: u16,
        maximum_fee: u64,
    ) -> Result<Instruction, ExecError> {
        fee_ix::set_transfer_fee(
            &spl_token_2022_interface::id(),
            mint,
            authority,
            &[],
            transfer_fee_basis_points,
            maximum_fee,
        )
        .map_err(|e| ExecError::Setup {
            step: "set-transfer-fee-ix".into(),
            detail: e.to_string(),
        })
    }

    fn account(&self, address: &Pubkey) -> Result<Account, ExecError> {
        self.ctx
            .account_store
            .borrow()
            .get(address)
            .cloned()
            .ok_or_else(|| ExecError::MissingAccount(address.to_string()))
    }

    /// Decode a token account from its real on-chain data.
    pub fn token_account(&self, address: &Pubkey) -> Result<TokenAccountView, ExecError> {
        let acct = self.account(address)?;
        let state = StateWithExtensions::<TokenAccount>::unpack(&acct.data).map_err(|e| {
            ExecError::Decode {
                account: address.to_string(),
                detail: e.to_string(),
            }
        })?;
        let withheld = state
            .get_extension::<TransferFeeAmount>()
            .ok()
            .map(|e| u64::from(e.withheld_amount));
        Ok(TokenAccountView {
            owner: state.base.owner,
            amount: state.base.amount,
            withheld,
            frozen: state.base.state == AccountState::Frozen,
            delegate: Option::<Pubkey>::from(state.base.delegate),
            delegated_amount: state.base.delegated_amount,
        })
    }

    /// Decode a multisig account from its real on-chain data.
    pub fn multisig(
        &self,
        address: &Pubkey,
    ) -> Result<spl_token_2022_interface::state::Multisig, ExecError> {
        use solana_program_pack::Pack;
        let acct = self.account(address)?;
        spl_token_2022_interface::state::Multisig::unpack_from_slice(&acct.data).map_err(|e| {
            ExecError::Decode {
                account: address.to_string(),
                detail: e.to_string(),
            }
        })
    }

    /// Read the mint's current transfer-fee parameters, if configured (real mint data).
    pub fn mint_fee_params(
        &self,
        mint: &Pubkey,
        epoch: u64,
    ) -> Result<Option<(u16, u64)>, ExecError> {
        let acct = self.account(mint)?;
        let state =
            StateWithExtensions::<Mint>::unpack(&acct.data).map_err(|e| ExecError::Decode {
                account: mint.to_string(),
                detail: e.to_string(),
            })?;
        Ok(state.get_extension::<TransferFeeConfig>().ok().map(|c| {
            let f = c.get_epoch_fee(epoch);
            (
                u16::from(f.transfer_fee_basis_points),
                u64::from(f.maximum_fee),
            )
        }))
    }

    /// Read the withheld transfer fees accumulated on a mint (real mint account data).
    pub fn mint_withheld(&self, mint: &Pubkey) -> Result<Option<u64>, ExecError> {
        let acct = self.account(mint)?;
        let state =
            StateWithExtensions::<Mint>::unpack(&acct.data).map_err(|e| ExecError::Decode {
                account: mint.to_string(),
                detail: e.to_string(),
            })?;
        Ok(state
            .get_extension::<TransferFeeConfig>()
            .ok()
            .map(|c| u64::from(c.withheld_amount)))
    }

    /// Read the `MetadataPointer` extension state on `mint` (`None` when extension is absent).
    pub fn mint_metadata_pointer(&self, mint: &Pubkey) -> Result<Option<PointerView>, ExecError> {
        let acct = self.account(mint)?;
        let state =
            StateWithExtensions::<Mint>::unpack(&acct.data).map_err(|e| ExecError::Decode {
                account: mint.to_string(),
                detail: e.to_string(),
            })?;
        Ok(state
            .get_extension::<metadata_pointer::MetadataPointer>()
            .ok()
            .map(|p| PointerView {
                authority: p
                    .authority
                    .get()
                    .map(|a| Pubkey::new_from_array(a.to_bytes())),
                address: p
                    .metadata_address
                    .get()
                    .map(|a| Pubkey::new_from_array(a.to_bytes())),
            }))
    }

    /// Read the `GroupPointer` extension state on `mint` (`None` when extension is absent).
    pub fn mint_group_pointer(&self, mint: &Pubkey) -> Result<Option<PointerView>, ExecError> {
        let acct = self.account(mint)?;
        let state =
            StateWithExtensions::<Mint>::unpack(&acct.data).map_err(|e| ExecError::Decode {
                account: mint.to_string(),
                detail: e.to_string(),
            })?;
        Ok(state
            .get_extension::<group_pointer::GroupPointer>()
            .ok()
            .map(|p| PointerView {
                authority: p
                    .authority
                    .get()
                    .map(|a| Pubkey::new_from_array(a.to_bytes())),
                address: p
                    .group_address
                    .get()
                    .map(|a| Pubkey::new_from_array(a.to_bytes())),
            }))
    }

    /// Read the `GroupMemberPointer` extension state on `mint` (`None` when extension is absent).
    pub fn mint_group_member_pointer(
        &self,
        mint: &Pubkey,
    ) -> Result<Option<PointerView>, ExecError> {
        let acct = self.account(mint)?;
        let state =
            StateWithExtensions::<Mint>::unpack(&acct.data).map_err(|e| ExecError::Decode {
                account: mint.to_string(),
                detail: e.to_string(),
            })?;
        Ok(state
            .get_extension::<group_member_pointer::GroupMemberPointer>()
            .ok()
            .map(|p| PointerView {
                authority: p
                    .authority
                    .get()
                    .map(|a| Pubkey::new_from_array(a.to_bytes())),
                address: p
                    .member_address
                    .get()
                    .map(|a| Pubkey::new_from_array(a.to_bytes())),
            }))
    }

    /// Instruction to update the metadata pointer on `mint`.
    pub fn update_metadata_pointer_ix(
        &self,
        mint: &Pubkey,
        authority: &Pubkey,
        metadata_address: Option<Pubkey>,
    ) -> Result<Instruction, ExecError> {
        let token = spl_token_2022_interface::id();
        metadata_pointer::instruction::update(&token, mint, authority, &[], metadata_address)
            .map_err(|e| ExecError::Setup {
                step: "update-metadata-pointer-ix".into(),
                detail: e.to_string(),
            })
    }

    /// Instruction to update the group pointer on `mint`.
    pub fn update_group_pointer_ix(
        &self,
        mint: &Pubkey,
        authority: &Pubkey,
        group_address: Option<Pubkey>,
    ) -> Result<Instruction, ExecError> {
        let token = spl_token_2022_interface::id();
        group_pointer::instruction::update(&token, mint, authority, &[], group_address).map_err(
            |e| ExecError::Setup {
                step: "update-group-pointer-ix".into(),
                detail: e.to_string(),
            },
        )
    }

    /// Instruction to update the group member pointer on `mint`.
    pub fn update_group_member_pointer_ix(
        &self,
        mint: &Pubkey,
        authority: &Pubkey,
        member_address: Option<Pubkey>,
    ) -> Result<Instruction, ExecError> {
        let token = spl_token_2022_interface::id();
        group_member_pointer::instruction::update(&token, mint, authority, &[], member_address)
            .map_err(|e| ExecError::Setup {
                step: "update-group-member-pointer-ix".into(),
                detail: e.to_string(),
            })
    }

    /// Advance the harness clock to the first slot of the given epoch.
    pub fn warp_to_epoch(&mut self, epoch: u64) {
        let slot = self
            .ctx
            .mollusk
            .sysvars
            .epoch_schedule
            .get_first_slot_in_epoch(epoch);
        self.ctx.mollusk.warp_to_slot(slot);
    }

    /// Current epoch according to the harness clock sysvar.
    pub fn epoch(&self) -> u64 {
        self.ctx.mollusk.sysvars.clock.epoch
    }

    /// Extension types present on a mint, decoded from real account data.
    pub fn mint_extension_types(&self, mint: &Pubkey) -> Result<Vec<ExtensionType>, ExecError> {
        let acct = self.account(mint)?;
        let state =
            StateWithExtensions::<Mint>::unpack(&acct.data).map_err(|e| ExecError::Decode {
                account: mint.to_string(),
                detail: e.to_string(),
            })?;
        state.get_extension_types().map_err(|e| ExecError::Decode {
            account: mint.to_string(),
            detail: e.to_string(),
        })
    }

    /// Extension types present on a token account, decoded from real account data.
    pub fn token_account_extension_types(
        &self,
        address: &Pubkey,
    ) -> Result<Vec<ExtensionType>, ExecError> {
        let acct = self.account(address)?;
        let state = StateWithExtensions::<TokenAccount>::unpack(&acct.data).map_err(|e| {
            ExecError::Decode {
                account: address.to_string(),
                detail: e.to_string(),
            }
        })?;
        state.get_extension_types().map_err(|e| ExecError::Decode {
            account: address.to_string(),
            detail: e.to_string(),
        })
    }

    /// Whether CPI Guard is enabled on a token account (`None` when the account has no
    /// `CpiGuard` extension), decoded from real account data.
    pub fn token_cpi_guard(&self, address: &Pubkey) -> Result<Option<bool>, ExecError> {
        let acct = self.account(address)?;
        let state = StateWithExtensions::<TokenAccount>::unpack(&acct.data).map_err(|e| {
            ExecError::Decode {
                account: address.to_string(),
                detail: e.to_string(),
            }
        })?;
        Ok(state
            .get_extension::<spl_token_2022_interface::extension::cpi_guard::CpiGuard>()
            .ok()
            .map(|c| bool::from(c.lock_cpi)))
    }

    /// The top-level instructions that enable or disable CPI Guard on `account`. Enabling first
    /// reallocates the account for the `CpiGuard` extension when it is missing (the owner signs
    /// both). Disabling must also be a top-level instruction: the program rejects it inside a CPI.
    pub fn cpi_guard_instructions(
        &self,
        account: &Pubkey,
        owner: &Pubkey,
        enable: bool,
    ) -> Result<Vec<Instruction>, ExecError> {
        use spl_token_2022_interface::extension::cpi_guard;
        let token = spl_token_2022_interface::id();
        fn map(e: impl ToString) -> ExecError {
            ExecError::Setup {
                step: "cpi-guard-ix".into(),
                detail: e.to_string(),
            }
        }
        let mut out = Vec::new();
        if enable && self.token_cpi_guard(account)?.is_none() {
            out.push(
                token_ix::reallocate(
                    &token,
                    account,
                    &self.payer,
                    owner,
                    &[],
                    &[ExtensionType::CpiGuard],
                )
                .map_err(map)?,
            );
        }
        out.push(
            if enable {
                cpi_guard::instruction::enable_cpi_guard(&token, account, owner, &[])
            } else {
                cpi_guard::instruction::disable_cpi_guard(&token, account, owner, &[])
            }
            .map_err(map)?,
        );
        Ok(out)
    }

    /// Whether required transfer memos are enabled on a token account (`None` without extension),
    /// decoded from real account data.
    pub fn token_memo_transfer(&self, address: &Pubkey) -> Result<Option<bool>, ExecError> {
        let acct = self.account(address)?;
        let state = StateWithExtensions::<TokenAccount>::unpack(&acct.data).map_err(|e| {
            ExecError::Decode {
                account: address.to_string(),
                detail: e.to_string(),
            }
        })?;
        Ok(state
            .get_extension::<spl_token_2022_interface::extension::memo_transfer::MemoTransfer>()
            .ok()
            .map(|m| bool::from(m.require_incoming_transfer_memos)))
    }

    /// The instructions that enable or disable required transfer memos on `account`. Enabling first
    /// reallocates the account for the `MemoTransfer` extension when it is missing.
    pub fn memo_transfer_instructions(
        &self,
        account: &Pubkey,
        owner: &Pubkey,
        enable: bool,
    ) -> Result<Vec<Instruction>, ExecError> {
        use spl_token_2022_interface::extension::memo_transfer;
        let token = spl_token_2022_interface::id();
        fn map(e: impl ToString) -> ExecError {
            ExecError::Setup {
                step: "memo-transfer-ix".into(),
                detail: e.to_string(),
            }
        }
        let mut out = Vec::new();
        if enable && self.token_memo_transfer(account)?.is_none() {
            out.push(
                token_ix::reallocate(
                    &token,
                    account,
                    &self.payer,
                    owner,
                    &[],
                    &[ExtensionType::MemoTransfer],
                )
                .map_err(map)?,
            );
        }
        out.push(
            if enable {
                memo_transfer::instruction::enable_required_transfer_memos(
                    &token,
                    account,
                    owner,
                    &[],
                )
            } else {
                memo_transfer::instruction::disable_required_transfer_memos(
                    &token,
                    account,
                    owner,
                    &[],
                )
            }
            .map_err(map)?,
        );
        Ok(out)
    }

    /// Total supply of a mint, decoded from real account data.
    pub fn mint_supply(&self, mint: &Pubkey) -> Result<u64, ExecError> {
        let acct = self.account(mint)?;
        StateWithExtensions::<Mint>::unpack(&acct.data)
            .map(|s| s.base.supply)
            .map_err(|e| ExecError::Decode {
                account: mint.to_string(),
                detail: e.to_string(),
            })
    }

    /// Whether a `Pausable` mint is currently paused (`None` without the extension).
    pub fn mint_paused(&self, mint: &Pubkey) -> Result<Option<bool>, ExecError> {
        let acct = self.account(mint)?;
        let state =
            StateWithExtensions::<Mint>::unpack(&acct.data).map_err(|e| ExecError::Decode {
                account: mint.to_string(),
                detail: e.to_string(),
            })?;
        Ok(state
            .get_extension::<spl_token_2022_interface::extension::pausable::PausableConfig>()
            .ok()
            .map(|c| bool::from(c.paused)))
    }

    /// Raw account bytes (for evidence capture and tests).
    pub fn raw_account(&self, address: &Pubkey) -> Result<Account, ExecError> {
        self.account(address)
    }

    /// Insert or replace an account directly in the backing SVM store.
    pub fn set_account(
        &self,
        address: &Pubkey,
        owner: &Pubkey,
        data: &[u8],
        lamports: Option<u64>,
        executable: bool,
    ) {
        let lam = lamports.unwrap_or_else(|| self.rent_for(data.len()));
        let acct = Account {
            lamports: lam,
            data: data.to_vec(),
            owner: *owner,
            executable,
            rent_epoch: 0,
        };
        self.ctx.account_store.borrow_mut().insert(*address, acct);
    }

    /// Snapshot the full account store and current clock sysvar.
    pub fn snapshot_state(&self) -> SvmSnapshot {
        SvmSnapshot {
            store: self.ctx.account_store.borrow().clone(),
            slot: self.ctx.mollusk.sysvars.clock.slot,
            unix_timestamp: self.ctx.mollusk.sysvars.clock.unix_timestamp,
        }
    }

    /// Restore the full account store and clock sysvar from a prior snapshot.
    pub fn restore_state(&mut self, snap: &SvmSnapshot) {
        *self.ctx.account_store.borrow_mut() = snap.store.clone();
        self.ctx.mollusk.warp_to_slot(snap.slot);
        self.ctx.mollusk.sysvars.clock.unix_timestamp = snap.unix_timestamp;
    }

    /// Advance Mollusk clock slot and unix timestamp.
    pub fn advance_clock(&mut self, slots: u64, seconds: i64) {
        let next_slot = self.ctx.mollusk.sysvars.clock.slot.saturating_add(slots);
        self.ctx.mollusk.warp_to_slot(next_slot);
        self.ctx.mollusk.sysvars.clock.unix_timestamp = self
            .ctx
            .mollusk
            .sysvars
            .clock
            .unix_timestamp
            .saturating_add(seconds);
    }

    /// Inspect an account's owner, lamports, raw bytes, and SPL Token / Mint state if applicable.
    pub fn inspect_account(&self, address: &Pubkey) -> Option<AccountInspection> {
        let acct = self.ctx.account_store.borrow().get(address).cloned()?;
        let is_token_prog = acct.owner == spl_token_2022_interface::id()
            || acct.owner.to_string() == LEGACY_SPL_TOKEN_ID;
        let token = if is_token_prog {
            StateWithExtensions::<TokenAccount>::unpack(&acct.data)
                .ok()
                .map(|state| {
                    let withheld = state
                        .get_extension::<TransferFeeAmount>()
                        .ok()
                        .map(|e| u64::from(e.withheld_amount));
                    TokenAccountView {
                        owner: state.base.owner,
                        amount: state.base.amount,
                        withheld,
                        frozen: state.base.state == AccountState::Frozen,
                        delegate: Option::<Pubkey>::from(state.base.delegate),
                        delegated_amount: state.base.delegated_amount,
                    }
                })
        } else {
            None
        };
        let (mint_supply, mint_paused) = if is_token_prog {
            match StateWithExtensions::<Mint>::unpack(&acct.data) {
                Ok(state) => {
                    let paused = state
                        .get_extension::<spl_token_2022_interface::extension::pausable::PausableConfig>()
                        .ok()
                        .map(|c| bool::from(c.paused));
                    (Some(state.base.supply), paused)
                }
                Err(_) => (None, None),
            }
        } else {
            (None, None)
        };
        Some(AccountInspection {
            owner: acct.owner,
            lamports: acct.lamports,
            executable: acct.executable,
            data: acct.data,
            token,
            mint_supply,
            mint_paused,
        })
    }

    /// Capture a target-agnostic [`RawSnapshot`] across tracked `(label, pubkey)` accounts.
    pub fn raw_snapshot(&self, tracked: &[(&str, Pubkey)]) -> RawSnapshot {
        let store = self.ctx.account_store.borrow();
        let mut accounts = Vec::with_capacity(tracked.len());
        let mut total_lamports = 0u64;
        for (_, addr) in tracked {
            if let Some(acct) = store.get(addr) {
                total_lamports = total_lamports.saturating_add(acct.lamports);
                let data_hex: String = acct.data.iter().map(|b| format!("{b:02x}")).collect();
                accounts.push(RawAccount {
                    address: addr.to_string(),
                    owner: acct.owner.to_string(),
                    lamports: acct.lamports,
                    executable: acct.executable,
                    data_len: acct.data.len(),
                    data_hex,
                });
            }
        }
        RawSnapshot {
            accounts,
            total_lamports,
        }
    }
}

impl Default for Harness {
    fn default() -> Self {
        Self::new()
    }
}

/// Lowercase hex SHA-256 of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// SHA-256 of the bundled Token-2022 program ELF used for every execution.
pub fn token_2022_elf_sha256() -> String {
    sha256_hex(mollusk_svm_programs_token_2022::ELF)
}

/// End-to-end environment check used by `tokenscope doctor`: executes a real 1,000-unit
/// `TransferChecked` on a 200 bp fee mint and verifies the decoded balances against the documented
/// fee formula. Returns a one-line description on success.
pub fn self_check() -> Result<String, ExecError> {
    use tokenscope_model::TransferFeeParams;
    let spec = MintSpec {
        decimals: 6,
        transfer_fee: Some(TransferFeeParams {
            basis_points: 200,
            maximum_fee: u64::MAX,
        }),
    };
    let h = Harness::new();
    let (alice, bob) = (derive_address("alice"), derive_address("bob"));
    let mint = h.create_mint("check", &spec)?;
    let src = h.create_token_account("src", &mint, &alice)?;
    let dst = h.create_token_account("dst", &mint, &bob)?;
    h.mint_to(&mint, &src, 10_000)?;
    h.execute(&h.transfer_checked_ix(&src, &mint, &dst, &alice, 1_000, 6)?)?;
    let d = h.token_account(&dst)?;
    let fee = (1_000u64 * 200).div_ceil(10_000);
    if d.amount == 1_000 - fee && d.withheld == Some(fee) {
        Ok(format!(
            "1000 @ 200bp delivered {} with {} withheld",
            d.amount, fee
        ))
    } else {
        Err(ExecError::Setup {
            step: "self-check".into(),
            detail: format!("unexpected destination state {d:?}"),
        })
    }
}
