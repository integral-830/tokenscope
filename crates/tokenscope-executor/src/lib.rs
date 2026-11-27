//! Real SVM execution harness.
//!
//! Every state change in this crate is produced by executing real programs (the system program
//! and the Token-2022 program ELF bundled with `mollusk-svm-programs-token-2022`) inside the
//! Mollusk SVM. Balances are never edited by hand; observations decode actual account data.

mod error;
mod extensions;
mod forwarder;
mod harness;
mod hook;

pub use error::ExecError;
pub use extensions::{MintExt, MintPlan};
pub use forwarder::{demo_forwarder_program_id, forward_instruction};
pub use harness::{
    AccountInspection, ExecReport, Harness, PointerView, SvmSnapshot, TokenAccountView,
    derive_address, self_check, sha256_hex, token_2022_elf_sha256,
};
pub use hook::{EXECUTE_DISCRIMINATOR, HookCounter, HookFixture, demo_hook_program_id};
